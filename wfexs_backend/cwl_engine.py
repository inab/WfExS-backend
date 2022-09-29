#!/usr/bin/env python
# -*- coding: utf-8 -*-

# Copyright 2020-2022 Barcelona Supercomputing Center (BSC), Spain
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
from __future__ import absolute_import

import json
import logging
import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import venv

from typing import cast, Any, List, Mapping, MutableMapping
from typing import MutableSequence, Optional, Sequence, Set, Tuple, Union

import jsonpath_ng  # type: ignore[import]
import jsonpath_ng.ext  # type: ignore[import]
import yaml

from .common import (
    AbsPath,
    AnyPath,
    ContentKind,
    ContainerTaggedName,
    ContainerType,
    EngineLocalConfig,
    EngineMode,
    EnginePath,
    EngineVersion,
    ExitVal,
    ExpectedOutput,
    Fingerprint,
    LocalWorkflow,
    MaterializedContent,
    MaterializedInput,
    MaterializedOutput,
    MaterializedWorkflowEngine,
    RelPath,
    SymbolicParamName,
    URIType,
    WorkflowEngineVersionStr,
    WorkflowType,
)

from .engine import WORKDIR_STDOUT_FILE, WORKDIR_STDERR_FILE, STATS_DAG_DOT_FILE
from .engine import WorkflowEngine, WorkflowEngineException

from .utils.contents import CWLClass2WfExS


# Next methods are borrowed from
# https://github.com/common-workflow-language/cwltool/blob/5bdb3d3dd47d8d1b3a1685220b4b6ce0f94c055e/cwltool/singularity.py#L83
def _normalize_image_id(string: str) -> RelPath:
    return cast(RelPath, string.replace("/", "_") + ".img")


def _normalize_sif_id(string: str) -> RelPath:
    return cast(RelPath, string.replace("/", "_") + ".sif")


ExecInputVal = Union[
    bool,
    int,
    float,
    str,
    MutableMapping[str, Any],
    MutableSequence[bool],
    MutableSequence[int],
    MutableSequence[float],
    MutableSequence[str],
    MutableSequence[MutableMapping[str, Any]],
]


class CWLWorkflowEngine(WorkflowEngine):
    CWLTOOL_PYTHON_PACKAGE = "cwltool"
    CWL_UTILS_PYTHON_PACKAGE = "cwl-utils"
    SCHEMA_SALAD_PYTHON_PACKAGE = "schema-salad"

    CWL_REPO = "https://github.com/common-workflow-language/"
    CWLTOOL_REPO = CWL_REPO + CWLTOOL_PYTHON_PACKAGE
    CWL_UTILS_REPO = CWL_REPO + CWL_UTILS_PYTHON_PACKAGE

    DEFAULT_CWLTOOL_VERSION = cast(EngineVersion, "3.1.20220913185150")

    DEVEL_CWLTOOL_PACKAGE = f"git+{CWLTOOL_REPO}.git"
    # Set this constant to something meaningful only when a hotfix
    # between releases is needed
    # DEVEL_CWLTOOL_VERSION = 'ed9dd4c3472e940a52dfe90049895f470bfd7329'
    DEVEL_CWLTOOL_VERSION = None

    # DEFAULT_CWL_UTILS_VERSION = 'v0.10'
    # DEFAULT_SCHEMA_SALAD_VERSION = '8.2.20211116214159'

    PODMAN_CWLTOOL_VERSION = cast(EngineVersion, "3.1.20210921111717")
    NO_WRAPPER_CWLTOOL_VERSION = cast(EngineVersion, "3.1.20210921111717")
    CWLTOOL_MAX_PYVER: List[Tuple[Optional[int], Optional[int], EngineVersion]] = [
        (3, None, NO_WRAPPER_CWLTOOL_VERSION),
        (3, 6, cast(EngineVersion, "3.1.20220116183622")),
        (None, None, DEFAULT_CWLTOOL_VERSION),
    ]

    NODEJS_WRAPPER = "nodejs_wrapper.bash"

    NODEJS_CONTAINER_TAG = cast(ContainerTaggedName, "docker.io/node:slim")
    OPERATIONAL_CONTAINER_TAGS = [NODEJS_CONTAINER_TAG]

    ENGINE_NAME = "cwl"

    SUPPORTED_CONTAINER_TYPES = {
        ContainerType.NoContainer,
        ContainerType.Singularity,
        ContainerType.Docker,
        ContainerType.Podman,
    }

    SUPPORTED_SECURE_EXEC_CONTAINER_TYPES = {
        ContainerType.NoContainer,
        ContainerType.Singularity,
        #    ContainerType.Podman,
    }

    def __init__(
        self,
        cacheDir: Optional[AnyPath] = None,
        workflow_config: Optional[Mapping[str, Any]] = None,
        local_config: Optional[EngineLocalConfig] = None,
        engineTweaksDir: Optional[AnyPath] = None,
        cacheWorkflowDir: Optional[AnyPath] = None,
        cacheWorkflowInputsDir: Optional[AnyPath] = None,
        workDir: Optional[AnyPath] = None,
        outputsDir: Optional[AnyPath] = None,
        outputMetaDir: Optional[AnyPath] = None,
        intermediateDir: Optional[AnyPath] = None,
        tempDir: Optional[AnyPath] = None,
        secure_exec: bool = False,
        allowOther: bool = False,
        config_directory: Optional[AnyPath] = None,
    ):

        super().__init__(
            cacheDir=cacheDir,
            workflow_config=workflow_config,
            local_config=local_config,
            engineTweaksDir=engineTweaksDir,
            cacheWorkflowDir=cacheWorkflowDir,
            cacheWorkflowInputsDir=cacheWorkflowInputsDir,
            workDir=workDir,
            outputsDir=outputsDir,
            intermediateDir=intermediateDir,
            outputMetaDir=outputMetaDir,
            tempDir=tempDir,
            secure_exec=secure_exec,
            allowOther=allowOther,
            config_directory=config_directory,
        )

        # Getting a fixed version of the engine
        toolsSect = local_config.get("tools", {}) if local_config else {}
        engineConf = toolsSect.get(self.ENGINE_NAME, {})
        workflowEngineConf = (
            workflow_config.get(self.ENGINE_NAME, {}) if workflow_config else {}
        )

        default_cwl_version = self.DEFAULT_CWLTOOL_VERSION
        pymatched = False
        for pyver_maj, pyver_min, matched_cwl_version in self.CWLTOOL_MAX_PYVER:
            if pyver_maj == sys.version_info.major:
                if pyver_min is None:
                    # This one is temporary, until it finds something better
                    default_cwl_version = matched_cwl_version
                elif pyver_min == sys.version_info.minor:
                    # If perfect match, use it!
                    default_cwl_version = matched_cwl_version
                    pymatched = True
                    break
            else:
                default_cwl_version = matched_cwl_version
                break

        # These are the requested versions
        requested_cwl_version = workflowEngineConf.get("version")
        if requested_cwl_version is None:
            requested_cwl_version = engineConf.get("version")

        if (requested_cwl_version is None) or (
            pymatched and requested_cwl_version > default_cwl_version
        ):
            cwl_version = default_cwl_version
        else:
            cwl_version = requested_cwl_version

        self.logger.debug(
            f"cwltool version: requested {requested_cwl_version} used {cwl_version}"
        )

        self.cwl_version = cwl_version

        # Setting up packed directory
        self.cacheWorkflowPackDir = os.path.join(self.cacheWorkflowDir, "wf-pack")
        os.makedirs(self.cacheWorkflowPackDir, exist_ok=True)

    @classmethod
    def MyWorkflowType(cls) -> WorkflowType:
        return WorkflowType(
            engineName=cls.ENGINE_NAME,
            shortname="cwl",
            name="Common Workflow Language",
            clazz=cls,
            uriMatch=[re.compile(r"^https://w3id\.org/cwl/")],
            uriTemplate=cast(URIType, r"https://w3id.org/cwl/{}/"),
            url=cast(URIType, "https://www.commonwl.org/"),
            trs_descriptor="CWL",
            rocrate_programming_language="#cwl",
        )

    @classmethod
    def SupportedContainerTypes(cls) -> Set[ContainerType]:
        return cls.SUPPORTED_CONTAINER_TYPES

    @classmethod
    def SupportedSecureExecContainerTypes(cls) -> Set[ContainerType]:
        return cls.SUPPORTED_SECURE_EXEC_CONTAINER_TYPES

    def identifyWorkflow(
        self, localWf: LocalWorkflow, engineVer: Optional[EngineVersion] = None
    ) -> Union[Tuple[EngineVersion, LocalWorkflow], Tuple[None, None]]:
        """
        This method should return the effective engine version needed
        to run it when this workflow engine recognizes the workflow type
        """
        cwlPath = localWf.dir
        if localWf.relPath is not None:
            cwlPath = cast(AbsPath, os.path.join(cwlPath, localWf.relPath))

        # Is this a yaml?
        cwlVersion = None
        try:
            with open(cwlPath, mode="r", encoding="utf-8") as pCWL:
                wf_yaml = yaml.safe_load(pCWL)  # parse possible CWL
                cwlVersion = wf_yaml.get("cwlVersion")
        except Exception as e:
            self.logger.warning(
                "Unable to process CWL entrypoint {} {}".format(cwlPath, e)
            )

        if cwlVersion is None:
            return None, None

        newLocalWf = LocalWorkflow(
            dir=localWf.dir,
            relPath=localWf.relPath,
            effectiveCheckout=localWf.effectiveCheckout,
            langVersion=cwlVersion,
        )

        # TODO: Check best version of the engine
        if localWf.relPath is not None:
            engineVer = self.cwl_version

        if engineVer is None:
            engineVer = self.cwl_version

        return engineVer, newLocalWf

    def materializeEngineVersion(
        self, engineVersion: EngineVersion
    ) -> Tuple[EngineVersion, EnginePath, Fingerprint]:
        """
        Method to ensure the required engine version is materialized
        It should raise an exception when the exact version is unavailable,
        and no replacement could be fetched
        """
        if self.engine_mode != EngineMode.Local:
            raise WorkflowEngineException(
                "Unsupported engine mode {} for {} engine".format(
                    self.engine_mode, self.ENGINE_NAME
                )
            )

        if self.DEVEL_CWLTOOL_VERSION is not None:
            cwltoolPackage = self.DEVEL_CWLTOOL_PACKAGE
            cwltoolMatchOp = "@"
            engineVersion = self.DEVEL_CWLTOOL_VERSION
        else:
            cwltoolPackage = self.CWLTOOL_PYTHON_PACKAGE
            cwltoolMatchOp = "=="

        # A version directory is needed
        cwl_install_dir = os.path.join(self.weCacheDir, engineVersion)

        # Creating the virtual environment needed to separate CWL code
        # from workflow execution backend
        if not os.path.isdir(cwl_install_dir):
            venv.create(cwl_install_dir, with_pip=True)

        # Let's be sure the nodejs wrapper, needed by cwltool versions
        # prior to 3.1.20210921111717 is in place
        # installWrapper = engineVersion < self.NO_WRAPPER_CWLTOOL_VERSION

        # But there are still some issues in Computerome, so we are
        # installing the wrapper in any case, meanwhile the issue is
        # triaged and fixed.
        installWrapper = True
        if engineVersion < self.NO_WRAPPER_CWLTOOL_VERSION:
            node_wrapper_source_path = os.path.join(
                self.payloadsDir, self.NODEJS_WRAPPER
            )
            node_wrapper_inst_path = os.path.join(cwl_install_dir, "bin", "node")
            if not os.path.isfile(node_wrapper_inst_path):
                shutil.copy2(node_wrapper_source_path, node_wrapper_inst_path)

            # Assuring it has the permissions
            if not os.access(node_wrapper_inst_path, os.X_OK):
                os.chmod(node_wrapper_inst_path, stat.S_IREAD | stat.S_IEXEC)

            # And the symlink from nodejs to node
            nodejs_wrapper_inst_path = os.path.join(cwl_install_dir, "bin", "nodejs")
            if not os.path.islink(nodejs_wrapper_inst_path):
                os.symlink("node", nodejs_wrapper_inst_path)

        # Now, time to run it
        instEnv = dict(os.environ)

        with tempfile.NamedTemporaryFile() as cwl_install_stdout:
            with tempfile.NamedTemporaryFile() as cwl_install_stderr:
                retVal = subprocess.Popen(
                    ". '{0}'/bin/activate && pip install --upgrade pip wheel ; pip install {1}{2}{3}".format(
                        cwl_install_dir,
                        cwltoolPackage,
                        cwltoolMatchOp,
                        engineVersion,
                        # Commented out, as WfExS is not currently using cwl-utils
                        #    self.SCHEMA_SALAD_PYTHON_PACKAGE, self.DEFAULT_SCHEMA_SALAD_VERSION,
                        #    self.CWL_UTILS_PYTHON_PACKAGE, self.DEFAULT_CWL_UTILS_VERSION,
                    ),
                    stdout=cwl_install_stdout,
                    stderr=cwl_install_stderr,
                    cwd=cwl_install_dir,
                    shell=True,
                    env=instEnv,
                ).wait()

                # Proper error handling
                if retVal != 0:
                    # Reading the output and error for the report
                    with open(cwl_install_stdout.name, "r") as c_stF:
                        cwl_install_stdout_v = c_stF.read()
                    with open(cwl_install_stderr.name, "r") as c_stF:
                        cwl_install_stderr_v = c_stF.read()

                    errstr = "Could not install CWL {} . Retval {}\n======\nSTDOUT\n======\n{}\n======\nSTDERR\n======\n{}".format(
                        engineVersion,
                        retVal,
                        cwl_install_stdout_v,
                        cwl_install_stderr_v,
                    )
                    raise WorkflowEngineException(errstr)

        # TODO

        return (
            engineVersion,
            cast(EnginePath, cwl_install_dir),
            cast(Fingerprint, engineVersion),
        )

    def _get_engine_version_str(
        self, matWfEng: MaterializedWorkflowEngine
    ) -> WorkflowEngineVersionStr:
        assert (
            matWfEng.instance == self
        ), "The workflow engine instance does not match!!!!"

        # CWLWorkflowEngine directory is needed
        cwl_install_dir = matWfEng.engine_path

        # Execute cwltool --version
        with tempfile.NamedTemporaryFile() as cwl_version_stderr:
            # Writing straight to the file
            with subprocess.Popen(
                ". '{0}'/bin/activate && cwltool --version".format(cwl_install_dir),
                stdout=subprocess.PIPE,
                stderr=cwl_version_stderr,
                cwd=cwl_install_dir,
                shell=True,
            ) as vP:
                engine_ver: str = ""
                if vP.stdout is not None:
                    engine_ver = vP.stdout.read().decode("utf-8", errors="continue")
                    self.logger.debug(f"{cwl_install_dir} version => {engine_ver}")

                retval = vP.wait()

            # Proper error handling
            if retval != 0:
                # Reading the output and error for the report
                with open(cwl_version_stderr.name, "r") as c_stF:
                    cwl_version_stderr_v = c_stF.read()

                errstr = "Could not get version running cwltool --version from {}. Retval {}\n======\nSTDOUT\n======\n{}\n======\nSTDERR\n======\n{}".format(
                    cwl_install_dir, retval, engine_ver, cwl_version_stderr_v
                )
                raise WorkflowEngineException(errstr)

            pref_ver = os.path.join(cwl_install_dir, "bin") + "/"
            if engine_ver.startswith(pref_ver):
                engine_ver = engine_ver[len(pref_ver) :]

            return cast(WorkflowEngineVersionStr, engine_ver.strip())

    def materializeWorkflow(
        self, matWorkflowEngine: MaterializedWorkflowEngine, offline: bool = False
    ) -> Tuple[MaterializedWorkflowEngine, List[ContainerTaggedName]]:
        """
        Method to ensure the workflow has been materialized. It returns the
        localWorkflow directory, as well as the list of containers.

        For Nextflow it is usually a no-op, but for CWL it requires resolution.
        """
        localWf = matWorkflowEngine.workflow
        localWorkflowDir = localWf.dir

        assert (
            localWf.relPath is not None
        ), "CWL workflows should have a relative file path"

        if os.path.isabs(localWf.relPath):
            localWorkflowFile = cast(AbsPath, localWf.relPath)
        else:
            localWorkflowFile = cast(
                AbsPath, os.path.join(localWorkflowDir, localWf.relPath)
            )
        engineVersion = matWorkflowEngine.version
        # CWLWorkflowEngine directory is needed
        cwl_install_dir = matWorkflowEngine.engine_path

        if not os.path.isfile(localWorkflowFile):
            raise WorkflowEngineException(
                "CWL workflow {} has not been materialized.".format(localWorkflowFile)
            )

        # Extract hashes directories from localWorkflow
        (
            localWorkflowUsedHashes_head,
            localWorkflowUsedHashes_tail,
        ) = localWorkflowDir.split("/")[-2:]

        # Setting up workflow packed name
        localWorkflowPackedName = (
            os.path.join(localWorkflowUsedHashes_head, localWorkflowUsedHashes_tail)
            + ".cwl"
        ).replace("/", "_")
        packedLocalWorkflowFile = os.path.join(
            self.cacheWorkflowPackDir, localWorkflowPackedName
        )

        # TODO: check whether the repo is newer than the packed file

        if (
            not os.path.isfile(packedLocalWorkflowFile)
            or os.path.getsize(packedLocalWorkflowFile) == 0
        ):
            if offline:
                raise WorkflowEngineException(
                    "Cannot allow to materialize packed CWL workflow in offline mode. Risk to access external content."
                )

            # Execute cwltool --pack
            with open(packedLocalWorkflowFile, mode="wb") as packedH:
                with tempfile.NamedTemporaryFile() as cwl_pack_stderr:
                    # Writing straight to the file
                    retVal = subprocess.Popen(
                        ". '{0}'/bin/activate && cwltool --no-doc-cache --pack {1}".format(
                            cwl_install_dir, localWorkflowFile
                        ),
                        stdout=packedH,
                        stderr=cwl_pack_stderr,
                        cwd=cwl_install_dir,
                        shell=True,
                    ).wait()

                    # Proper error handling
                    if retVal != 0:
                        # Reading the output and error for the report
                        with open(cwl_pack_stderr.name, "r") as c_stF:
                            cwl_pack_stderr_v = c_stF.read()

                        errstr = "Could not pack CWL running cwltool --pack {}. Retval {}\n======\nSTDERR\n======\n{}".format(
                            engineVersion, retVal, cwl_pack_stderr_v
                        )
                        raise WorkflowEngineException(errstr)

        containerTags = set()

        # Getting the identifiers
        cwlVersion = None
        with open(packedLocalWorkflowFile, encoding="utf-8") as pLWH:
            wf_yaml = yaml.safe_load(pLWH)  # parse packed CWL
            cwlVersion = wf_yaml.get("cwlVersion", "v1.0")
            dockerExprParser = jsonpath_ng.ext.parse(
                '$."$graph" .. hints | requirements [?class = "DockerRequirement"][*]'
            )
            for match in dockerExprParser.find(wf_yaml):
                dockerPullId = match.value.get("dockerPull")

                # Fallback to dockerImageId if dockerPull was not set
                # https://www.commonwl.org/v1.0/CommandLineTool.html#DockerRequirement
                if dockerPullId is None:
                    dockerPullId = match.value.get("dockerImageId")

                # TODO: treat other cases like dockerImport or dockerLoad?

                containerTags.add(dockerPullId)

        newLocalWf = LocalWorkflow(
            dir=localWf.dir,
            relPath=cast(RelPath, packedLocalWorkflowFile),
            effectiveCheckout=localWf.effectiveCheckout,
            langVersion=cwlVersion,
        )
        newWfEngine = MaterializedWorkflowEngine(
            instance=matWorkflowEngine.instance,
            version=engineVersion,
            fingerprint=matWorkflowEngine.fingerprint,
            engine_path=cwl_install_dir,
            workflow=newLocalWf,
        )
        return newWfEngine, list(containerTags)

    def sideContainers(self) -> List[ContainerTaggedName]:
        """
        Containers needed by the engine to work
        """
        return self.OPERATIONAL_CONTAINER_TAGS

    def simpleContainerFileName(self, imageUrl: URIType) -> RelPath:
        """
        This method was borrowed from
        https://github.com/common-workflow-language/cwltool/blob/5bdb3d3dd47d8d1b3a1685220b4b6ce0f94c055e/cwltool/singularity.py#L107
        """
        # match = re.search(
        #    pattern=r"([a-z]*://)", string=imageUrl
        # )
        img_name = _normalize_image_id(imageUrl)
        # candidates.append(img_name)
        # sif_name = _normalize_sif_id(dockerRequirement["dockerPull"])
        # candidates.append(sif_name)

        return img_name

    @staticmethod
    def generateDotWorkflow(
        matWfEng: MaterializedWorkflowEngine, dagFile: AbsPath
    ) -> None:
        localWf = matWfEng.workflow

        assert (
            localWf.relPath is not None
        ), "CWL workflows should have a relative file path"

        if os.path.isabs(localWf.relPath):
            localWorkflowFile = cast(AbsPath, localWf.relPath)
        else:
            localWorkflowFile = cast(
                AbsPath, os.path.join(localWf.dir, localWf.relPath)
            )
        engineVersion = matWfEng.version
        cwl_install_dir = matWfEng.engine_path
        # Execute cwltool --print-dot
        with open(dagFile, mode="wb") as packedH:
            with tempfile.NamedTemporaryFile() as cwl_dot_stderr:
                # Writing straight to the file
                retVal = subprocess.Popen(
                    ". '{0}'/bin/activate && cwltool --print-dot {1}".format(
                        cwl_install_dir, localWorkflowFile
                    ),
                    stdout=packedH,
                    stderr=cwl_dot_stderr,
                    cwd=cwl_install_dir,
                    shell=True,
                ).wait()

                # Proper error handling
                if retVal != 0:
                    # Reading the output and error for the report
                    cwl_dot_stderr.seek(0)
                    cwl_dot_stderr_v = cwl_dot_stderr.read().decode(
                        "utf-8", errors="ignore"
                    )

                    errstr = "Could not generate CWL representation in dot format using cwltool --print-dot {}. Retval {}\n======\nSTDERR\n======\n{}".format(
                        engineVersion, retVal, cwl_dot_stderr_v
                    )
                    raise WorkflowEngineException(errstr)

    def launchWorkflow(
        self,
        matWfEng: MaterializedWorkflowEngine,
        matInputs: Sequence[MaterializedInput],
        outputs: Sequence[ExpectedOutput],
    ) -> Tuple[ExitVal, Sequence[MaterializedInput], Sequence[MaterializedOutput]]:
        """
        Method to execute the workflow
        """
        localWf = matWfEng.workflow

        assert (
            localWf.relPath is not None
        ), "CWL workflows should have a relative file path"

        if os.path.isabs(localWf.relPath):
            localWorkflowFile = cast(AbsPath, localWf.relPath)
        else:
            localWorkflowFile = cast(
                AbsPath, os.path.join(localWf.dir, localWf.relPath)
            )
        engineVersion = matWfEng.version
        dagFile = cast(AbsPath, os.path.join(self.outputStatsDir, STATS_DAG_DOT_FILE))

        if os.path.exists(localWorkflowFile):
            # CWLWorkflowEngine directory is needed
            cwl_install_dir = matWfEng.engine_path

            # First, generate the graphical representation of the workflow
            self.generateDotWorkflow(matWfEng, dagFile)

            # Then, all the preparations
            cwl_dict_inputs = dict()
            with open(localWorkflowFile, "r") as cwl_file:
                cwl_yaml = yaml.safe_load(cwl_file)  # convert packed CWL to YAML

                # As the workflow has been packed, the #main element appears
                io_parser = jsonpath_ng.ext.parse('$."$graph"[?class = "Workflow"]')

                workflows = dict()
                first_workflow = None
                for match in io_parser.find(cwl_yaml):
                    wf = match.value
                    wfId = wf.get("id")
                    wfIdPrefix = "" if wfId is None else wfId + "/"

                    wf_cwl_yaml_inputs = wf.get("inputs", [])
                    wf_cwl_yaml_outputs = wf.get("outputs", [])

                    workflow = (
                        wfId,
                        wfIdPrefix,
                        wf_cwl_yaml_inputs,
                        wf_cwl_yaml_outputs,
                    )
                    workflows[wfId] = workflow
                    if first_workflow is None:
                        first_workflow = workflow

                # Now, deciding
                if first_workflow is None:
                    raise WorkflowEngineException(
                        f"FIXME?: No workflow was found in {localWorkflowFile}"
                    )
                elif len(workflows) > 1 and "#main" in workflows:
                    # TODO: have a look at cwltool code and more workflows,
                    # to be sure this heuristic is valid
                    workflow = workflows["#main"]
                else:
                    workflow = first_workflow

                wfId, wfIdPrefix, cwl_yaml_inputs, cwl_yaml_outputs = workflow

                # Setting packed CWL inputs (id, type)
                for (
                    cwl_yaml_input
                ) in cwl_yaml_inputs:  # clean string of packed CWL inputs
                    cwl_yaml_input_id = str(cwl_yaml_input["id"])
                    # Validating
                    if cwl_yaml_input_id.startswith(wfIdPrefix):
                        inputId = cwl_yaml_input_id[len(wfIdPrefix) :]
                    elif cwl_yaml_input_id[0] == "#":
                        inputId = cwl_yaml_input_id[1:]
                    else:
                        inputId = cwl_yaml_input_id

                    if inputId not in cwl_dict_inputs:
                        cwl_dict_inputs[inputId] = cwl_yaml_input

            # TODO change the hardcoded filename
            inputsFileName = "inputdeclarations.yaml"
            yamlFile = cast(AnyPath, os.path.join(self.workDir, inputsFileName))

            try:
                # Create YAML file
                augmentedInputs = self.createYAMLFile(
                    matInputs, cwl_dict_inputs, yamlFile
                )
                if os.path.isfile(yamlFile):
                    # Execute workflow
                    stdoutFilename = os.path.join(
                        self.outputMetaDir, WORKDIR_STDOUT_FILE
                    )
                    stderrFilename = os.path.join(
                        self.outputMetaDir, WORKDIR_STDERR_FILE
                    )

                    # As the stdout contains the description of the outputs
                    # which is parsed to identify them
                    # we have to overwrite it every time we are running
                    # the workflow
                    with open(stdoutFilename, mode="wb+") as cwl_yaml_stdout:
                        with open(stderrFilename, mode="ab+") as cwl_yaml_stderr:
                            intermediateDir = self.intermediateDir + "/"
                            outputDir = self.outputsDir + "/"

                            # This is needed to isolate execution environment
                            # and teach cwltool where to find the cached images
                            instEnv = dict()
                            # These variables are needed to have the installation working
                            # so external commands like singularity or docker can be found
                            for envKey in ("LD_LIBRARY_PATH", "PATH"):
                                valToSet = os.environ.get(envKey)
                                if valToSet is not None:
                                    instEnv[envKey] = valToSet
                            instEnv.update(self.container_factory.environment)

                            debugFlag = ""
                            if self.logger.getEffectiveLevel() <= logging.DEBUG:
                                debugFlag = "--debug --leave-tmpdir"
                            elif self.logger.getEffectiveLevel() <= logging.INFO:
                                debugFlag = "--verbose --rm-tmpdir"
                            else:
                                debugFlag = "--rm-tmpdir"

                            if (
                                self.container_factory.containerType
                                == ContainerType.Singularity
                            ):
                                assert (
                                    matWfEng.containers_path is not None
                                ), "The containers path should exist"

                                cmdTemplate = "cwltool --outdir {0} {4} --strict --no-doc-cache --disable-pull --singularity --tmp-outdir-prefix={1} --tmpdir-prefix={1} {2} {3}"
                                instEnv[
                                    "CWL_SINGULARITY_CACHE"
                                ] = matWfEng.containers_path
                                instEnv["SINGULARITY_CONTAIN"] = "1"
                                instEnv["APPTAINER_CONTAIN"] = "1"
                                if self.writable_containers:
                                    instEnv["SINGULARITY_WRITABLE"] = "1"
                                    instEnv["APPTAINER_WRITABLE"] = "1"
                            elif (
                                self.container_factory.containerType
                                == ContainerType.Docker
                            ):
                                cmdTemplate = "cwltool --outdir {0} {4} --strict --no-doc-cache --disable-pull --tmp-outdir-prefix={1} --tmpdir-prefix={1} {2} {3}"
                            elif (
                                self.container_factory.containerType
                                == ContainerType.Podman
                            ):
                                if engineVersion < self.PODMAN_CWLTOOL_VERSION:
                                    if self.container_factory.supportsFeature("userns"):
                                        instEnv["PODMAN_USERNS"] = "keep-id"
                                    cmdTemplate = (
                                        "cwltool --outdir {0} {4} --strict --no-doc-cache --disable-pull '--user-space-docker-cmd="
                                        + self.container_factory.command
                                        + "' --tmp-outdir-prefix={1} --tmpdir-prefix={1} {2} {3}"
                                    )
                                else:
                                    cmdTemplate = "cwltool --outdir {0} {4} --strict --no-doc-cache --disable-pull --podman --tmp-outdir-prefix={1} --tmpdir-prefix={1} {2} {3}"
                            elif (
                                self.container_factory.containerType
                                == ContainerType.NoContainer
                            ):
                                cmdTemplate = "cwltool --outdir {0} {4} --strict --no-doc-cache --no-container --tmp-outdir-prefix={1} --tmpdir-prefix={1} {2} {3}"
                            else:
                                raise WorkflowEngineException(
                                    "FATAL ERROR: Unsupported container factory {}".format(
                                        self.container_factory.ContainerType()
                                    )
                                )

                            cmd = cmdTemplate.format(
                                outputDir,
                                intermediateDir,
                                localWorkflowFile,
                                yamlFile,
                                debugFlag,
                            )
                            self.logger.debug("Command => {}".format(cmd))

                            retVal = subprocess.Popen(
                                ". '{0}'/bin/activate && {1}".format(
                                    cwl_install_dir, cmd
                                ),
                                stdout=cwl_yaml_stdout,
                                stderr=cwl_yaml_stderr,
                                cwd=self.workDir,
                                shell=True,
                                env=instEnv,
                            ).wait()

                            cwl_yaml_stdout.seek(0)
                            cwl_yaml_stdout_v = cwl_yaml_stdout.read().decode(
                                "utf-8", "ignore"
                            )
                            # Proper error handling
                            try:
                                outputsMapping = json.loads(cwl_yaml_stdout_v)
                                cwl_yaml_stderr_v = ""
                            except json.JSONDecodeError as e:
                                outputsMapping = None
                                cwl_yaml_stderr_v = (
                                    "Output cwltool JSON decode error: {}".format(e.msg)
                                )

                            if retVal > 125:
                                # Reading the error for the report
                                cwl_yaml_stderr.seek(0)
                                cwl_yaml_stderr_v += cwl_yaml_stderr.read().decode(
                                    "utf-8", "ignore"
                                )

                                errstr = "[CWL] Failed running cwltool {}. Retval {}\n======\nSTDOUT\n======\n{}\n======\nSTDERR\n======\n{}".format(
                                    engineVersion,
                                    retVal,
                                    cwl_yaml_stdout_v,
                                    cwl_yaml_stderr_v,
                                )
                                raise WorkflowEngineException(errstr)

                            # Reading the output for the report
                            matOutputs = self.identifyMaterializedOutputs(
                                matInputs, outputs, self.outputsDir, outputsMapping
                            )
                else:
                    retVal = -1
                    matOutputs = []

                # FIXME: create augmentedInputs properly
                return cast(ExitVal, retVal), matInputs, matOutputs

            except WorkflowEngineException as wfex:
                raise wfex
            except Exception as error:
                raise WorkflowEngineException(
                    "ERROR: cannot execute the workflow {}, {}".format(
                        localWorkflowFile, error
                    )
                )
        else:
            raise WorkflowEngineException(
                "CWL workflow {} has not been successfully materialized and packed for their execution".format(
                    localWorkflowFile
                )
            )

    def createYAMLFile(
        self,
        matInputs: Sequence[MaterializedInput],
        cwlInputs: Mapping[str, Any],
        filename: AnyPath,
    ) -> Mapping[SymbolicParamName, ExecInputVal]:
        """
        Method to create a YAML file that describes the execution inputs of the workflow
        needed for their execution. Return parsed inputs.
        """
        try:
            execInputs = self.executionInputs(matInputs, cwlInputs)
            if len(execInputs) != 0:
                with open(filename, mode="w+", encoding="utf-8") as yaml_file:
                    yaml.dump(
                        execInputs,
                        yaml_file,
                        allow_unicode=True,
                        default_flow_style=False,
                        sort_keys=False,
                    )
                return execInputs

            else:
                raise WorkflowEngineException("Dict of execution inputs is empty")

        except IOError as error:
            raise WorkflowEngineException(
                "ERROR: cannot create YAML file {}, {}".format(filename, error)
            )

    def executionInputs(
        self, matInputs: Sequence[MaterializedInput], cwlInputs: Mapping[str, Any]
    ) -> Mapping[SymbolicParamName, ExecInputVal]:
        """
        Setting execution inputs needed to execute the workflow
        """
        if len(matInputs) == 0:  # Is list of materialized inputs empty?
            raise WorkflowEngineException("FATAL ERROR: Execution with no inputs")

        if len(cwlInputs) == 0:  # Is list of declared inputs empty?
            raise WorkflowEngineException(
                "FATAL ERROR: Workflow with no declared inputs"
            )

        execInputs: MutableMapping[SymbolicParamName, ExecInputVal] = dict()
        for matInput in matInputs:
            if isinstance(matInput, MaterializedInput):  # input is a MaterializedInput
                # numberOfInputs = len(matInput.values)  # number of inputs inside a MaterializedInput
                for input_value in matInput.values:
                    name = matInput.name
                    value_types = cwlInputs.get(name, {}).get("type")
                    if value_types is None:
                        raise WorkflowEngineException(
                            "ERROR: input {} not available in workflow".format(name)
                        )

                    if not isinstance(value_types, list):
                        value_types = [value_types]

                    value = input_value
                    for value_type in value_types:
                        classType = None
                        if isinstance(value_type, str):
                            classType = value_type
                            value_type = {"type": classType}
                        elif isinstance(value_type, dict):
                            classType = value_type["type"]
                        else:
                            self.logger.debug(
                                "FIXME? value_type of class {}".format(
                                    value_type.__class__.__name__
                                )
                            )
                            continue

                        isArray = False
                        if classType == "null":
                            if value is not None:
                                continue
                        elif classType == "array":
                            isArray = True
                            classType = value_type.get("items")
                            if classType is None:
                                raise WorkflowEngineException(
                                    "ERROR: Ill formed array input type for {} in workflow definition: {}".format(
                                        name, value_type
                                    )
                                )
                        # else: # the other types are managed below

                        if isinstance(
                            value, MaterializedContent
                        ):  # value of an input contains MaterializedContent
                            if value.kind in (ContentKind.Directory, ContentKind.File):
                                if not os.path.exists(value.local):
                                    self.logger.warning(
                                        "Input {} is not materialized".format(name)
                                    )
                                value_local = value.local

                                eInput: MutableMapping[str, Any] = {
                                    "class": classType,
                                    "location": value_local,
                                }
                                if matInput.secondaryInputs is not None:
                                    eInput["secondaryFiles"] = [
                                        {
                                            "class": list(CWLClass2WfExS.keys())[
                                                list(CWLClass2WfExS.values()).index(
                                                    secInput.kind
                                                )
                                            ],
                                            "location": secInput.local,
                                        }
                                        for secInput in matInput.secondaryInputs
                                    ]
                                if isArray:
                                    the_arr = execInputs.setdefault(
                                        name,
                                        cast(
                                            MutableSequence[MutableMapping[str, Any]],
                                            [],
                                        ),
                                    )
                                    assert isinstance(the_arr, list)
                                    the_arr.append(eInput)
                                    # FIXME: secondary parameters in an array of inputs?!?!?
                                elif name in execInputs:
                                    raise WorkflowEngineException(
                                        "ERROR: Input {} is not array, but it received more than one value".format(
                                            name
                                        )
                                    )
                                else:
                                    execInputs[name] = eInput
                            else:  # The error now is managed outside
                                # FIXME: do something better for other kinds
                                #
                                # raise WorkflowEngineException(
                                #     "ERROR: Input {} has values of type {} this code does not know how to handle".format(
                                #         name, value.kind))
                                continue
                        elif isArray:
                            # FIXME: apply additional validations
                            the_arr_v = execInputs.setdefault(
                                name, cast(ExecInputVal, [])
                            )
                            assert isinstance(the_arr_v, list)
                            the_arr_v.append(value)
                        else:
                            # FIXME: apply additional validations
                            execInputs[name] = value
                        break
                    else:
                        # If we reach this, no value was set up
                        raise WorkflowEngineException(
                            "ERROR: Input {} has value types {} for value of type {}, and this code does not know how to handle it (check types)".format(
                                name,
                                value_types,
                                value.kind
                                if isinstance(value, MaterializedContent)
                                else value.__class__.__name__,
                            )
                        )

        return execInputs
