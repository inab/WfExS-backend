#!/usr/bin/env python
# -*- coding: utf-8 -*-

# SPDX-License-Identifier: Apache-2.0
# Copyright 2020-2024 Barcelona Supercomputing Center (BSC), Spain
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

import copy
import datetime
import json
import logging
import os
import pathlib
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import venv

from typing import (
    cast,
    TYPE_CHECKING,
)

from ..common import (
    ContainerTaggedName,
    ContainerType,
    ContentKind,
    EngineMode,
    ExecutionStatus,
    LocalWorkflow,
    MaterializedContent,
    MaterializedInput,
)

if TYPE_CHECKING:
    import pathlib
    from typing import (
        Any,
        Iterator,
        Mapping,
        MutableMapping,
        MutableSequence,
        Optional,
        Sequence,
        Set,
        Tuple,
        Type,
        Union,
    )

    from typing_extensions import (
        TypeAlias,
    )

    from ..common import (
        AbsPath,
        AnyPath,
        EngineVersion,
        ExitVal,
        ExpectedOutput,
        Fingerprint,
        MaterializedOutput,
        ProgsMapping,
        RelPath,
        SymbolicName,
        SymbolicParamName,
        URIType,
    )

    from ..container_factories import (
        ContainerFactory,
    )

    from ..fetchers import (
        RemoteRepo,
    )

    ExecInputVal: TypeAlias = Union[
        bool,
        int,
        float,
        str,
        None,
        MutableMapping[str, Any],
        MutableSequence[bool],
        MutableSequence[int],
        MutableSequence[float],
        MutableSequence[str],
        MutableSequence[MutableMapping[str, Any]],
    ]

    from jsonpath_ng.jsonpath import JSONVal

    from . import (
        EngineLocalConfig,
        EnginePath,
        WorkflowEngineVersionStr,
    )


import jsonpath_ng
import jsonpath_ng.ext
import psutil
import yaml

from . import (
    DEFAULT_PRIORITY,
    MaterializedWorkflowEngine,
    StagedExecution,
    STATS_DAG_DOT_FILE,
    WORKDIR_STATS_RELDIR,
    WORKDIR_STDOUT_FILE,
    WORKDIR_STDERR_FILE,
    WorkflowEngine,
    WorkflowEngineException,
    WorkflowEngineInstallException,
    WorkflowType,
)

from ..container_factories.no_container import (
    NoContainerFactory,
)

from ..utils.contents import (
    CWLClass2WfExS,
    link_or_copy,
)


# Next methods are borrowed from
# https://github.com/common-workflow-language/cwltool/blob/5bdb3d3dd47d8d1b3a1685220b4b6ce0f94c055e/cwltool/singularity.py#L83
def _normalize_image_id(string: "str") -> "RelPath":
    return cast("RelPath", string.replace("/", "_") + ".img")


def _normalize_sif_id(string: "str") -> "RelPath":
    return cast("RelPath", string.replace("/", "_") + ".sif")


class CWLWorkflowEngine(WorkflowEngine):
    CWLTOOL_PYTHON_PACKAGE = "cwltool"
    CWL_UTILS_PYTHON_PACKAGE = "cwl-utils"
    SCHEMA_SALAD_PYTHON_PACKAGE = "schema-salad"

    CWL_REPO = "https://github.com/common-workflow-language/"
    CWLTOOL_REPO = CWL_REPO + CWLTOOL_PYTHON_PACKAGE
    # DEVEL_CWLTOOL_REPO = "https://github.com/jmfernandez/" + CWLTOOL_PYTHON_PACKAGE
    DEVEL_CWLTOOL_REPO = CWLTOOL_REPO
    CWL_UTILS_REPO = CWL_REPO + CWL_UTILS_PYTHON_PACKAGE

    DEFAULT_CWLTOOL_VERSION = cast("EngineVersion", "3.1.20240708091337")

    # DEVEL_CWLTOOL_PACKAGE = f"git+{CWLTOOL_REPO}.git"
    DEVEL_CWLTOOL_PACKAGE = f"git+{DEVEL_CWLTOOL_REPO}.git"
    # Set this constant to something meaningful only when a hotfix
    # between releases is needed
    # DEVEL_CWLTOOL_VERSION = "509ffb9d6802c837ec2a818b799ef4c332c34d04"
    DEVEL_CWLTOOL_VERSION = None

    # DEFAULT_CWL_UTILS_VERSION = 'v0.10'
    # DEFAULT_SCHEMA_SALAD_VERSION = '8.2.20211116214159'

    PODMAN_CWLTOOL_VERSION = cast("EngineVersion", "3.1.20210921111717")
    NO_WRAPPER_CWLTOOL_VERSION = cast("EngineVersion", "3.1.20210921111717")
    CWLTOOL_MAX_PYVER: "Sequence[Tuple[Optional[int], Optional[int], EngineVersion]]" = [
        (3, None, NO_WRAPPER_CWLTOOL_VERSION),
        (3, 6, cast("EngineVersion", "3.1.20220116183622")),
        (None, None, DEFAULT_CWLTOOL_VERSION),
    ]

    INPUT_DECLARATIONS_FILENAME = "inputdeclarations.yaml"

    NODEJS_WRAPPER = "nodejs_wrapper.bash"

    NODEJS_CONTAINER_TAG = ContainerTaggedName(
        origTaggedName="docker.io/node:slim",
        type=ContainerType.Docker,
    )
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
        container_factory_clazz: "Type[ContainerFactory]" = NoContainerFactory,
        cacheDir: "Optional[pathlib.Path]" = None,
        engine_config: "Optional[EngineLocalConfig]" = None,
        progs_mapping: "Optional[ProgsMapping]" = None,
        engineTweaksDir: "Optional[pathlib.Path]" = None,
        cacheWorkflowDir: "Optional[pathlib.Path]" = None,
        cacheWorkflowInputsDir: "Optional[pathlib.Path]" = None,
        workDir: "Optional[pathlib.Path]" = None,
        outputsDir: "Optional[pathlib.Path]" = None,
        outputMetaDir: "Optional[pathlib.Path]" = None,
        intermediateDir: "Optional[pathlib.Path]" = None,
        tempDir: "Optional[pathlib.Path]" = None,
        stagedContainersDir: "Optional[pathlib.Path]" = None,
        secure_exec: "bool" = False,
        allowOther: "bool" = False,
        config_directory: "Optional[pathlib.Path]" = None,
        writable_containers: "bool" = False,
    ):
        super().__init__(
            container_factory_clazz=container_factory_clazz,
            cacheDir=cacheDir,
            engine_config=engine_config,
            progs_mapping=progs_mapping,
            engineTweaksDir=engineTweaksDir,
            cacheWorkflowDir=cacheWorkflowDir,
            cacheWorkflowInputsDir=cacheWorkflowInputsDir,
            workDir=workDir,
            outputsDir=outputsDir,
            intermediateDir=intermediateDir,
            outputMetaDir=outputMetaDir,
            tempDir=tempDir,
            stagedContainersDir=stagedContainersDir,
            secure_exec=secure_exec,
            allowOther=allowOther,
            config_directory=config_directory,
            writable_containers=writable_containers,
        )

        # Obtaining the full path to Java
        self.python_cmd = self.progs_mapping.get(
            cast("SymbolicName", "python"), sys.executable
        )

        pymatched = False
        if self.DEVEL_CWLTOOL_VERSION is not None:
            default_cwltool_version = cast(
                "EngineVersion",
                self.DEVEL_CWLTOOL_PACKAGE + "@" + self.DEVEL_CWLTOOL_VERSION,
            )
        else:
            default_cwltool_version = self.DEFAULT_CWLTOOL_VERSION

            for pyver_maj, pyver_min, matched_cwltool_version in self.CWLTOOL_MAX_PYVER:
                if pyver_maj == sys.version_info.major:
                    if pyver_min is None:
                        # This one is temporary, until it finds something better
                        default_cwltool_version = matched_cwltool_version
                    elif pyver_min == sys.version_info.minor:
                        # If perfect match, use it!
                        default_cwltool_version = matched_cwltool_version
                        pymatched = True
                        break
                else:
                    default_cwltool_version = matched_cwltool_version
                    break

        # These are the requested versions
        requested_cwltool_version = self.engine_config.get("version")

        if (requested_cwltool_version is None) or (
            pymatched and requested_cwltool_version > default_cwltool_version
        ):
            cwltool_version = default_cwltool_version
        else:
            cwltool_version = requested_cwltool_version

        self.logger.debug(
            f"cwltool version: requested {requested_cwltool_version} used {cwltool_version}"
        )

        self.cwltool_version = cwltool_version

        # Setting up packed directory
        self.cacheWorkflowPackDir = self.cacheWorkflowDir / "wf-pack"
        self.cacheWorkflowPackDir.mkdir(parents=True, exist_ok=True)

    @classmethod
    def MyWorkflowType(cls) -> "WorkflowType":
        # As of https://about.workflowhub.eu/Workflow-RO-Crate/ ,
        # the rocrate_programming_language should be next
        return WorkflowType(
            engineName=cls.ENGINE_NAME,
            shortname="cwl",
            name="Common Workflow Language",
            clazz=cls,
            uriMatch=[re.compile(r"^https://w3id\.org/cwl/")],
            uriTemplate=cast("URIType", r"https://w3id.org/cwl/{}/"),
            url=cast("URIType", "https://www.commonwl.org/"),
            trs_descriptor="CWL",
            rocrate_programming_language="https://w3id.org/workflowhub/workflow-ro-crate#cwl",
            priority=DEFAULT_PRIORITY + 10,
        )

    @classmethod
    def HasExplicitOutputs(cls) -> "bool":
        # CWL has a clear separation between inputs and outputs
        return True

    @classmethod
    def SupportedContainerTypes(cls) -> "Set[ContainerType]":
        return cls.SUPPORTED_CONTAINER_TYPES

    @classmethod
    def SupportedSecureExecContainerTypes(cls) -> "Set[ContainerType]":
        return cls.SUPPORTED_SECURE_EXEC_CONTAINER_TYPES

    @property
    def engine_url(self) -> "URIType":
        return cast("URIType", "https://pypi.org/project/cwltool/")

    def identifyWorkflow(
        self, localWf: "LocalWorkflow", engineVer: "Optional[EngineVersion]" = None
    ) -> "Union[Tuple[EngineVersion, LocalWorkflow], Tuple[None, None]]":
        """
        This method should return the effective engine version needed
        to run it when this workflow engine recognizes the workflow type
        """
        cwlPath = localWf.dir
        if localWf.relPath is not None:
            cwlPath = cwlPath / localWf.relPath

        if cwlPath.is_dir():
            self.logger.warning("CWL entrypoint cannot be a directory")
            return None, None

        # Is this a yaml?
        cwlVersion = None
        try:
            with cwlPath.open(mode="r", encoding="utf-8") as pCWL:
                wf_yaml = yaml.safe_load(pCWL)  # parse possible CWL
                cwlVersion = wf_yaml.get("cwlVersion")
        except Exception as e:
            self.logger.warning(
                "Unable to process CWL entrypoint {} {}".format(cwlPath, e)
            )

        if cwlVersion is None:
            return None, None

        # TODO: select the minimum cwltool version based on cwlVersion
        # TODO: Check best version of the engine
        if engineVer is None:
            engineVer = self.cwltool_version

        newLocalWf = LocalWorkflow(
            dir=localWf.dir,
            relPath=localWf.relPath,
            effectiveCheckout=localWf.effectiveCheckout,
            langVersion=cwlVersion,
            relPathFiles=[cast("RelPath", localWf.relPath)],
        )

        # call cwltool --print-deps --relative-deps cwd
        # and parse its contents in order to get either relative paths
        # or URLs
        newLocalWf = self._enrichWorkflowDeps(newLocalWf, engineVer)

        return engineVer, newLocalWf

    def materializeEngineVersion(
        self, engineVersion: "EngineVersion"
    ) -> "Tuple[EngineVersion, pathlib.Path, Fingerprint]":
        """
        Method to ensure the required engine version is materialized
        It should raise an exception when the exact version is unavailable,
        and no replacement could be fetched
        """
        if self.engine_mode == EngineMode.Local:
            return self._materializeEngineVersionLocal(engineVersion)

        raise WorkflowEngineException(
            "Unsupported engine mode {} for {} engine".format(
                self.engine_mode, self.ENGINE_NAME
            )
        )

    def _materializeEngineVersionLocal(
        self,
        engineVersion: "EngineVersion",
        search_other: "bool" = True,
    ) -> "Tuple[EngineVersion, pathlib.Path, Fingerprint]":
        """
        Method to ensure the required engine version is materialized
        It should raise an exception when the exact version is unavailable,
        and no replacement could be fetched
        """

        if engineVersion.startswith(self.DEVEL_CWLTOOL_PACKAGE + "@"):
            cwltoolPackage = self.DEVEL_CWLTOOL_PACKAGE
            cwltoolMatchOp = "@"
            inst_engineVersion = engineVersion[len(self.DEVEL_CWLTOOL_PACKAGE) + 1 :]
        elif engineVersion.startswith("git+https") and "@" in engineVersion:
            # This is for foreign development versions of cwltool
            at_place = engineVersion.find("@")
            cwltoolPackage = engineVersion[0:at_place]
            cwltoolMatchOp = "@"
            inst_engineVersion = engineVersion[at_place + 1 :]
        else:
            cwltoolPackage = self.CWLTOOL_PYTHON_PACKAGE
            cwltoolMatchOp = "=="
            inst_engineVersion = engineVersion

        # Now, time to run it
        instEnv = dict(os.environ)

        python_executable = self.python_cmd
        # A version directory is needed, also based on the python version
        python_version_major = 0
        python_version_minor = 0
        if python_executable is None or python_executable == sys.executable:
            python_version_major = sys.version_info.major
            python_version_minor = sys.version_info.minor
        else:
            with tempfile.NamedTemporaryFile() as cwltool_vers_stdout:
                with tempfile.NamedTemporaryFile() as cwltool_vers_stderr:
                    retval_vers = subprocess.Popen(
                        [
                            python_executable,
                            "-c",
                            "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')",
                        ],
                        stdout=cwltool_vers_stdout,
                        stderr=cwltool_vers_stderr,
                        stdin=subprocess.DEVNULL,
                        env=instEnv,
                    ).wait()
                    with open(cwltool_vers_stdout.name, "r") as c_stF:
                        cwltool_vers_stdout_v = c_stF.read()
                    vers = cwltool_vers_stdout_v.split("\n")[0].split(".")
                    if retval_vers == 0 and len(vers) >= 2:
                        try:
                            python_version_major = int(vers[0])
                            python_version_minor = int(vers[1])
                        except:
                            errstr = f"Could not parse python version using {python_executable}"
                            self.logger.error(errstr)
                            raise WorkflowEngineInstallException(errstr)
                    else:
                        # Reading the output and error for the report
                        with open(cwltool_vers_stderr.name, "r") as c_stF:
                            cwltool_vers_stderr_v = c_stF.read()

                        errstr = f"""\
Could not get python version using {python_executable}. Retval {retval_vers}
======
STDOUT
======
{cwltool_vers_stdout_v}
======
STDERR
======
{cwltool_vers_stderr_v}
"""
                        # Cleanup
                        self.logger.error(errstr)
                        raise WorkflowEngineInstallException(errstr)

        cwltool_install_dir = (
            self.weCacheDir
            / f"python-{python_version_major}.{python_version_minor}_{inst_engineVersion}"
        )

        # Creating the virtual environment needed to separate CWL code
        # from workflow execution backend
        do_install = True
        if not cwltool_install_dir.is_dir():
            if python_executable is None:
                venv.create(cwltool_install_dir, with_pip=True)
            else:
                with tempfile.NamedTemporaryFile() as cwltool_venv_stdout:
                    with tempfile.NamedTemporaryFile() as cwltool_venv_stderr:
                        retval_venv = subprocess.Popen(
                            [
                                python_executable,
                                "-mvenv",
                                cwltool_install_dir.as_posix(),
                            ],
                            stdout=cwltool_venv_stdout,
                            stderr=cwltool_venv_stderr,
                            stdin=subprocess.DEVNULL,
                            env=instEnv,
                        ).wait()
                        if retval_venv != 0:
                            # Reading the output and error for the report
                            with open(cwltool_venv_stdout.name, "r") as c_stF:
                                cwltool_venv_stdout_v = c_stF.read()
                            with open(cwltool_venv_stderr.name, "r") as c_stF:
                                cwltool_venv_stderr_v = c_stF.read()

                            errstr = f"""\
Could not create environment at {cwltool_install_dir} using {python_executable}. Retval {retval_venv}
======
STDOUT
======
{cwltool_venv_stdout_v}
======
STDERR
======
{cwltool_venv_stderr_v}
"""
                            # Cleanup
                            if cwltool_install_dir.is_dir():
                                shutil.rmtree(cwltool_install_dir)
                                errstr += f"\n(partial directory {cwltool_install_dir} was removed)"
                            self.logger.error(errstr)
                            raise WorkflowEngineInstallException(errstr)

        else:
            # Check the installation is up and running
            # creating a "fake" MaterializedWorkflowEngine
            # with even "faker" LocalWorkflow
            installed_engineVersion_str = self.__get_engine_version_str_local(
                MaterializedWorkflowEngine(
                    instance=self,
                    workflow=LocalWorkflow(
                        dir=pathlib.Path("/"),
                        relPath=None,
                        effectiveCheckout=None,
                    ),
                    version=cast("EngineVersion", ""),
                    fingerprint="",
                    engine_path=cwltool_install_dir,
                )
            )

            r_sp = installed_engineVersion_str.rfind(" ")
            if r_sp != -1:
                installed_engineVersion = installed_engineVersion_str[r_sp + 1 :]
            else:
                installed_engineVersion = installed_engineVersion_str

            do_install = inst_engineVersion != installed_engineVersion
            if do_install:
                self.logger.debug(
                    f"cwltool mismatch {inst_engineVersion} vs {installed_engineVersion}"
                )

        if do_install:
            # Let's be sure the nodejs wrapper, needed by cwltool versions
            # prior to 3.1.20210921111717 is in place
            # installWrapper = engineVersion < self.NO_WRAPPER_CWLTOOL_VERSION

            # But there are still some issues in Computerome, so we are
            # installing the wrapper in any case, meanwhile the issue is
            # triaged and fixed.
            installWrapper = True
            if inst_engineVersion < self.NO_WRAPPER_CWLTOOL_VERSION:
                node_wrapper_source_path = self.payloadsDir / self.NODEJS_WRAPPER
                node_wrapper_inst_path = cwltool_install_dir / "bin" / "node"
                if not node_wrapper_inst_path.is_file():
                    shutil.copy2(node_wrapper_source_path, node_wrapper_inst_path)

                # Assuring it has the permissions
                if not os.access(node_wrapper_inst_path, os.X_OK):
                    node_wrapper_inst_path.chmod(stat.S_IREAD | stat.S_IEXEC)

                # And the symlink from nodejs to node
                nodejs_wrapper_inst_path = cwltool_install_dir / "bin" / "nodejs"
                if not nodejs_wrapper_inst_path.is_symlink():
                    os.symlink("node", nodejs_wrapper_inst_path)

            with tempfile.NamedTemporaryFile() as cwltool_install_stdout:
                with tempfile.NamedTemporaryFile() as cwltool_install_stderr:
                    retVal = subprocess.Popen(
                        [
                            f"{cwltool_install_dir}/bin/pip",
                            "install",
                            "--upgrade",
                            "pip",
                            "wheel",
                        ],
                        stdout=cwltool_install_stdout,
                        stderr=cwltool_install_stderr,
                        stdin=subprocess.DEVNULL,
                        cwd=cwltool_install_dir,
                        env=instEnv,
                    ).wait()

                    # Proper error handling
                    if retVal != 0:
                        # Reading the output and error for the report
                        with open(cwltool_install_stdout.name, "r") as c_stF:
                            cwltool_install_stdout_v = c_stF.read()
                        with open(cwltool_install_stderr.name, "r") as c_stF:
                            cwltool_install_stderr_v = c_stF.read()

                        errstr = "Could not upgrade pip. Retval {}\n======\nSTDOUT\n======\n{}\n======\nSTDERR\n======\n{}".format(
                            retVal,
                            cwltool_install_stdout_v,
                            cwltool_install_stderr_v,
                        )
                        # Cleanup
                        shutil.rmtree(cwltool_install_dir)
                        errstr += f"\n(directory {cwltool_install_dir} was removed)"
                        raise WorkflowEngineException(errstr)

                    retVal = subprocess.Popen(
                        [
                            f"{cwltool_install_dir}/bin/pip",
                            "install",
                            cwltoolPackage + cwltoolMatchOp + inst_engineVersion,
                            # Due https://github.com/common-workflow-language/cwltool/issues/2027
                            # we are downgrading here the pydot version
                            "pydot<3.0.0",
                        ],
                        # Commented out, as WfExS is not currently using cwl-utils
                        #    self.SCHEMA_SALAD_PYTHON_PACKAGE, self.DEFAULT_SCHEMA_SALAD_VERSION,
                        #    self.CWL_UTILS_PYTHON_PACKAGE, self.DEFAULT_CWL_UTILS_VERSION,
                        stdout=cwltool_install_stdout,
                        stderr=cwltool_install_stderr,
                        stdin=subprocess.DEVNULL,
                        cwd=cwltool_install_dir,
                        env=instEnv,
                    ).wait()

                    # Proper error handling
                    if retVal != 0:
                        # Reading the output and error for the report
                        with open(cwltool_install_stdout.name, "r") as c_stF:
                            cwltool_install_stdout_v = c_stF.read()
                        with open(cwltool_install_stderr.name, "r") as c_stF:
                            cwltool_install_stderr_v = c_stF.read()

                        # Is the proposed version unavailable?
                        if (
                            search_other
                            and cwltoolMatchOp == "=="
                            and "ERROR: Ignored the following versions"
                            in cwltool_install_stderr_v
                        ):
                            with tempfile.NamedTemporaryFile() as cwltool_index_stdout:
                                with tempfile.NamedTemporaryFile() as cwltool_index_stderr:
                                    retval_index = subprocess.Popen(
                                        [
                                            f"{cwltool_install_dir}/bin/pip",
                                            "index",
                                            "versions",
                                            cwltoolPackage,
                                        ],
                                        # Commented out, as WfExS is not currently using cwl-utils
                                        #    self.SCHEMA_SALAD_PYTHON_PACKAGE, self.DEFAULT_SCHEMA_SALAD_VERSION,
                                        #    self.CWL_UTILS_PYTHON_PACKAGE, self.DEFAULT_CWL_UTILS_VERSION,
                                        stdout=cwltool_index_stdout,
                                        stderr=cwltool_index_stderr,
                                        stdin=subprocess.DEVNULL,
                                        cwd=cwltool_install_dir,
                                        env=instEnv,
                                    ).wait()

                                    # Cleanup
                                    shutil.rmtree(cwltool_install_dir)

                                    if retval_index == 0:
                                        with open(
                                            cwltool_index_stdout.name, mode="r"
                                        ) as c_stF:
                                            for rep_line in c_stF:
                                                aver = "Available versions: "
                                                if rep_line.startswith(aver):
                                                    for version in rep_line[
                                                        len(aver) :
                                                    ].split(", "):
                                                        try:
                                                            return self._materializeEngineVersionLocal(
                                                                cast(
                                                                    "EngineVersion",
                                                                    version,
                                                                ),
                                                                search_other=False,
                                                            )
                                                        except:
                                                            self.logger.warning(
                                                                f"Unable to install cwltool {version}"
                                                            )

                        # Cleanup
                        shutil.rmtree(cwltool_install_dir)

                        # Reading the output and error for the report
                        with open(cwltool_install_stdout.name, "r") as c_stF:
                            cwltool_install_stdout_v = c_stF.read()
                        with open(cwltool_install_stderr.name, "r") as c_stF:
                            cwltool_install_stderr_v = c_stF.read()

                        errstr = "Could not install CWL {} . Retval {}\n======\nSTDOUT\n======\n{}\n======\nSTDERR\n======\n{}".format(
                            engineVersion,
                            retVal,
                            cwltool_install_stdout_v,
                            cwltool_install_stderr_v,
                        )
                        errstr += f"\n(directory {cwltool_install_dir} was removed)"
                        raise WorkflowEngineInstallException(errstr)

            # TODO

        return (
            engineVersion,
            cwltool_install_dir,
            cast("Fingerprint", engineVersion),
        )

    def _get_engine_version_str(
        self, matWfEng: "MaterializedWorkflowEngine"
    ) -> "WorkflowEngineVersionStr":
        assert (
            matWfEng.instance == self
        ), "The workflow engine instance does not match!!!!"

        if self.engine_mode == EngineMode.Local:
            return self.__get_engine_version_str_local(matWfEng)

        raise WorkflowEngineException(
            "Unsupported engine mode {} for {} engine".format(
                self.engine_mode, self.ENGINE_NAME
            )
        )

    def __get_engine_version_str_local(
        self, matWfEng: "MaterializedWorkflowEngine"
    ) -> "WorkflowEngineVersionStr":
        # CWLWorkflowEngine directory is needed
        cwltool_install_dir = matWfEng.engine_path

        # Execute cwltool --version
        with tempfile.NamedTemporaryFile() as cwltool_version_stderr:
            # Writing straight to the file
            with subprocess.Popen(
                [f"{cwltool_install_dir}/bin/cwltool", "--version"],
                stdout=subprocess.PIPE,
                stderr=cwltool_version_stderr,
                stdin=subprocess.DEVNULL,
                cwd=cwltool_install_dir,
            ) as vP:
                engine_ver: "str" = ""
                if vP.stdout is not None:
                    engine_ver = vP.stdout.read().decode("utf-8", errors="continue")
                    self.logger.debug(f"{cwltool_install_dir} version => {engine_ver}")

                retval = vP.wait()

            # Proper error handling
            if retval != 0:
                # Reading the output and error for the report
                with open(cwltool_version_stderr.name, "r") as c_stF:
                    cwltool_version_stderr_v = c_stF.read()

                errstr = "Could not get version running cwltool --version from {}. Retval {}\n======\nSTDOUT\n======\n{}\n======\nSTDERR\n======\n{}".format(
                    cwltool_install_dir, retval, engine_ver, cwltool_version_stderr_v
                )
                raise WorkflowEngineException(errstr)

            pref_ver = os.path.join(cwltool_install_dir, "bin") + "/"
            if engine_ver.startswith(pref_ver):
                engine_ver = engine_ver[len(pref_ver) :]

            return cast("WorkflowEngineVersionStr", engine_ver.strip())

    def _enrichWorkflowDeps(
        self, localWf: "LocalWorkflow", engineVer: "EngineVersion"
    ) -> "LocalWorkflow":
        # CWLWorkflowEngine directory is needed
        _, cwltool_install_dir, _ = self.materializeEngineVersion(engineVer)

        assert localWf.relPath
        # Execute cwltool --print-deps
        printed_deps_str = ""
        with tempfile.NamedTemporaryFile() as cwltool_printdeps_stderr:
            # Writing straight to the file
            with subprocess.Popen(
                [
                    f"{cwltool_install_dir}/bin/cwltool",
                    "--print-deps",
                    "--relative-deps",
                    "cwd",
                    localWf.relPath,
                ],
                stdout=subprocess.PIPE,
                stderr=cwltool_printdeps_stderr,
                stdin=subprocess.DEVNULL,
                cwd=localWf.dir,
            ) as pP:
                if pP.stdout is not None:
                    printed_deps_str = pP.stdout.read().decode(
                        "utf-8", errors="continue"
                    )
                    self.logger.debug(
                        f"{cwltool_install_dir} --print-deps => {printed_deps_str}"
                    )

                retval = pP.wait()

            # Proper error handling
            if retval != 0:
                # Reading the output and error for the report
                with open(cwltool_printdeps_stderr.name, "r") as c_stF:
                    cwltool_printdeps_stderr_v = c_stF.read()

                errstr = f"""Could not get workflow dependencies running cwltool --print-deps from {localWf.dir} {localWf.relPath} with {cwltool_install_dir}. Retval {retval}
======
STDOUT
======
{printed_deps_str}
======
STDERR
======
{cwltool_printdeps_stderr_v}"""
                raise WorkflowEngineException(errstr)

        # Is this a correct JSON?
        try:
            printed_deps = json.loads(printed_deps_str)
        except json.JSONDecodeError as e:
            raise WorkflowEngineException(
                f"Dependencies are not in correct JSON\n{printed_deps_str}"
            ) from e

        # Now, let's parse them
        relPaths: "MutableSequence[Union[RelPath, URIType]]" = []
        new_nodes = [printed_deps]
        while len(new_nodes) > 0:
            the_nodes = new_nodes
            new_nodes = []
            for the_node in the_nodes:
                clazz_name = the_node.get("class")
                if clazz_name == "File":
                    # Save this location
                    relPaths.append(the_node.get("location"))
                elif clazz_name == "Directory":
                    # More nodes to inspect
                    listing = the_node.get("listing")
                    if isinstance(listing, list):
                        new_nodes.extend(listing)

                # Secondary files for the next loop
                sec_files = the_node.get("secondaryFiles")
                if isinstance(sec_files, list):
                    # More nodes to inspect
                    new_nodes.extend(sec_files)

        if len(relPaths) > 0:
            return localWf._replace(relPathFiles=relPaths)
        else:
            return localWf

    def materializeWorkflow(
        self,
        matWorkflowEngine: "MaterializedWorkflowEngine",
        consolidatedWorkflowDir: "pathlib.Path",
        offline: "bool" = False,
        profiles: "Optional[Sequence[str]]" = None,
        context_inputs: "Sequence[MaterializedInput]" = [],
        context_environment: "Sequence[MaterializedInput]" = [],
        remote_repo: "Optional[RemoteRepo]" = None,
    ) -> "Tuple[MaterializedWorkflowEngine, Sequence[ContainerTaggedName]]":
        """
        Method to ensure the workflow has been materialized. In the case
        of CWL, it returns a new materialized workflow engine, which points
        to a newly genereated LocalWorkflow instance pointing to the
        consolidated workflow. Also, it returns the list of containers.
        """
        localWf = matWorkflowEngine.workflow
        localWorkflowDir = localWf.dir
        consolidatedWorkflowPath = pathlib.Path(consolidatedWorkflowDir)

        assert (
            localWf.relPath is not None
        ), "CWL workflows should have a relative file path"

        if os.path.isabs(localWf.relPath):
            localWorkflowFile = pathlib.Path(localWf.relPath)
        else:
            localWorkflowFile = localWorkflowDir / localWf.relPath
        engineVersion = matWorkflowEngine.version
        # CWLWorkflowEngine directory is needed
        cwltool_install_dir = matWorkflowEngine.engine_path

        if not localWorkflowFile.is_file():
            raise WorkflowEngineException(
                f"CWL workflow {localWorkflowFile} has not been materialized (not a file)."
            )

        # Extract hashes directories from localWorkflow
        (
            localWorkflowUsedHashes_head,
            localWorkflowUsedHashes_tail,
        ) = localWorkflowDir.parts[-2:]

        # Setting up workflow packed name
        localWorkflowPackedName = (
            os.path.join(localWorkflowUsedHashes_head, localWorkflowUsedHashes_tail)
            + ".cwl"
        ).replace("/", "_")

        # TODO: check whether the repo is newer than the packed file

        consolidatedPackedWorkflowFile = (
            consolidatedWorkflowPath / localWorkflowPackedName
        )
        if (
            not consolidatedPackedWorkflowFile.is_file()
            or os.path.getsize(consolidatedPackedWorkflowFile) == 0
        ):
            packedLocalWorkflowFile = (
                pathlib.Path(self.cacheWorkflowPackDir) / localWorkflowPackedName
            )
            if (
                not packedLocalWorkflowFile.is_file()
                or os.path.getsize(packedLocalWorkflowFile) == 0
            ):
                if offline:
                    raise WorkflowEngineException(
                        "Cannot allow to materialize packed CWL workflow in offline mode. Risk to access external content."
                    )

                # Execute cwltool --pack
                with packedLocalWorkflowFile.open(mode="wb") as packedH:
                    with tempfile.NamedTemporaryFile() as cwltool_pack_stderr:
                        # Writing straight to the file
                        retVal = subprocess.Popen(
                            [
                                f"{cwltool_install_dir}/bin/cwltool",
                                "--no-doc-cache",
                                "--pack",
                                localWorkflowFile.as_posix(),
                            ],
                            stdout=packedH,
                            stderr=cwltool_pack_stderr,
                            stdin=subprocess.DEVNULL,
                            cwd=cwltool_install_dir,
                        ).wait()

                        # Proper error handling
                        if retVal != 0:
                            # Reading the output and error for the report
                            with open(cwltool_pack_stderr.name, "r") as c_stF:
                                cwltool_pack_stderr_v = c_stF.read()

                            errstr = "Could not pack CWL running cwltool --pack {}. Retval {}\n======\nSTDERR\n======\n{}".format(
                                engineVersion, retVal, cwltool_pack_stderr_v
                            )
                            raise WorkflowEngineException(errstr)

                # Last, deploy a copy of this packed workflow in the working directory
            link_or_copy(packedLocalWorkflowFile, consolidatedPackedWorkflowFile)

        containerTags: "Set[str]" = set()

        # Getting the identifiers
        cwlVersion = None
        # TODO: collect conda hints
        with consolidatedPackedWorkflowFile.open(mode="r", encoding="utf-8") as pLWH:
            wf_yaml = yaml.safe_load(pLWH)  # parse packed CWL
            cwlVersion = wf_yaml.get("cwlVersion", "v1.0")
            dockerExprParser = jsonpath_ng.ext.parse(
                '$."$graph" .. hints | requirements [?class = "DockerRequirement"][*]'
            )
            for match in dockerExprParser.find(wf_yaml):
                match_value = cast("Mapping[str, JSONVal]", match.value)
                dockerPullId: "Optional[str]" = cast(
                    "Optional[str]", match_value.get("dockerPull")
                )

                # Fallback to dockerImageId if dockerPull was not set
                # https://www.commonwl.org/v1.0/CommandLineTool.html#DockerRequirement
                if dockerPullId is None:
                    dockerPullId = cast(
                        "Optional[str]", match_value.get("dockerImageId")
                    )

                # TODO: treat other cases like dockerImport or dockerLoad?
                if dockerPullId is not None:
                    containerTags.add(dockerPullId)

        newLocalWf = LocalWorkflow(
            dir=consolidatedWorkflowPath,
            relPath=cast("RelPath", localWorkflowPackedName),
            effectiveCheckout=localWf.effectiveCheckout,
            langVersion=cwlVersion,
            # No file should be needed
            relPathFiles=[],
        )
        newWfEngine = MaterializedWorkflowEngine(
            instance=matWorkflowEngine.instance,
            version=engineVersion,
            fingerprint=matWorkflowEngine.fingerprint,
            engine_path=cwltool_install_dir,
            workflow=newLocalWf,
        )

        list_of_containers: "MutableSequence[ContainerTaggedName]" = []
        for containerTag in containerTags:
            container_type = ContainerType.Docker
            if containerTag.startswith("http:") or containerTag.startswith("https:"):
                container_type = ContainerType.Singularity

            putative_container_tag = ContainerTaggedName(
                origTaggedName=containerTag,
                type=container_type,
            )

            if putative_container_tag not in list_of_containers:
                list_of_containers.append(putative_container_tag)

        return newWfEngine, list_of_containers

    def sideContainers(self) -> "Sequence[ContainerTaggedName]":
        """
        Containers needed by the engine to work
        """
        return self.OPERATIONAL_CONTAINER_TAGS

    def simpleContainerFileName(self, imageUrl: "URIType") -> "Sequence[RelPath]":
        """
        This method was borrowed from
        https://github.com/common-workflow-language/cwltool/blob/5bdb3d3dd47d8d1b3a1685220b4b6ce0f94c055e/cwltool/singularity.py#L107
        """
        # match = re.search(
        #    pattern=r"([a-z]*://)", string=imageUrl
        # )
        candidates: "MutableSequence[RelPath]" = [_normalize_image_id(imageUrl)]
        # Next block could be needed in a darker future where either one
        # or another file naming style is used depending on some
        # obscure reason
        # if self.container_factory.containerType == ContainerType.Singularity:
        #     candidates.append(_normalize_sif_id(imageUrl))

        return candidates

    @staticmethod
    def generateDotWorkflow(
        matWfEng: "MaterializedWorkflowEngine", dagFile: "pathlib.Path"
    ) -> None:
        localWf = matWfEng.workflow

        assert (
            localWf.relPath is not None
        ), "CWL workflows should have a relative file path"

        # As the engine should be materialized by parameter
        # no call to materializeEngineVersion is needed

        if os.path.isabs(localWf.relPath):
            localWorkflowFile = pathlib.Path(localWf.relPath)
        else:
            localWorkflowFile = localWf.dir / localWf.relPath
        engineVersion = matWfEng.version
        cwltool_install_dir = str(matWfEng.engine_path)
        # Execute cwltool --print-dot
        with dagFile.open(mode="wb") as packedH:
            with tempfile.NamedTemporaryFile() as cwltool_dot_stderr:
                # Writing straight to the file
                retVal = subprocess.Popen(
                    [
                        f"{cwltool_install_dir}/bin/cwltool",
                        "--print-dot",
                        "--debug",
                        localWorkflowFile,
                    ],
                    stdout=packedH,
                    stderr=cwltool_dot_stderr,
                    stdin=subprocess.DEVNULL,
                    cwd=cwltool_install_dir,
                ).wait()

                # Proper error handling
                if retVal != 0:
                    # Reading the output and error for the report
                    cwltool_dot_stderr.seek(0)
                    cwltool_dot_stderr_v = cwltool_dot_stderr.read().decode(
                        "utf-8", errors="ignore"
                    )

                    errstr = "Could not generate CWL representation in dot format using cwltool --print-dot {}. Retval {}\n======\nSTDERR\n======\n{}".format(
                        engineVersion, retVal, cwltool_dot_stderr_v
                    )
                    raise WorkflowEngineException(errstr)

    def launchWorkflow(
        self,
        matWfEng: "MaterializedWorkflowEngine",
        matInputs: "Sequence[MaterializedInput]",
        matEnvironment: "Sequence[MaterializedInput]",
        outputs: "Sequence[ExpectedOutput]",
        profiles: "Optional[Sequence[str]]" = None,
    ) -> "Iterator[StagedExecution]":
        """
        Method to execute the workflow
        """
        # TODO: implement usage of materialized environment variables
        localWf = matWfEng.workflow

        assert (
            localWf.relPath is not None
        ), "CWL workflows should have a relative file path"

        if os.path.isabs(localWf.relPath):
            localWorkflowFile = pathlib.Path(localWf.relPath)
        else:
            localWorkflowFile = localWf.dir / localWf.relPath
        engineVersion = matWfEng.version

        (
            outputDirPostfix,
            intermediateDir,
            outputsDir,
            outputMetaDir,
        ) = self.create_job_directories()
        outputStatsDir = outputMetaDir / WORKDIR_STATS_RELDIR
        outputStatsDir.mkdir(parents=True, exist_ok=True)

        dagFile = outputStatsDir / STATS_DAG_DOT_FILE

        queued = datetime.datetime.fromtimestamp(
            psutil.Process(os.getpid()).create_time()
        ).astimezone()
        yield StagedExecution(
            status=ExecutionStatus.Queued,
            job_id=str(os.getpid()),
            exitVal=cast("ExitVal", -1),
            augmentedInputs=[],
            # TODO: store the augmentedEnvironment instead
            # of the materialized one
            environment=matEnvironment,
            matCheckOutputs=[],
            outputsDir=outputsDir,
            queued=queued,
            started=datetime.datetime.min,
            ended=datetime.datetime.min,
            logfile=[],
        )

        if localWorkflowFile.exists():
            # CWLWorkflowEngine directory is needed
            cwltool_install_dir = matWfEng.engine_path

            # First, generate the graphical representation of the workflow
            self.generateDotWorkflow(matWfEng, dagFile)

            # Then, all the preparations
            cwl_dict_inputs: "MutableMapping[SymbolicParamName, Any]" = dict()
            with localWorkflowFile.open(mode="r") as cwl_file:
                cwl_yaml = yaml.safe_load(cwl_file)  # convert packed CWL to YAML

                # As the workflow has been packed, the #main element appears
                io_parser = jsonpath_ng.ext.parse('$."$graph"[?class = "Workflow"]')

                workflows = dict()
                first_workflow = None
                for match in io_parser.find(cwl_yaml):
                    wf = cast("Mapping[str, JSONVal]", match.value)
                    wfId = cast("Optional[str]", wf.get("id"))
                    wfIdPrefix = "" if wfId is None else wfId + "/"

                    wf_cwl_yaml_inputs = cast(
                        "Sequence[Mapping[str, JSONVal]]", wf.get("inputs", [])
                    )
                    wf_cwl_yaml_outputs = cast(
                        "Sequence[Mapping[str, JSONVal]]", wf.get("outputs", [])
                    )

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
                        cwl_dict_inputs[
                            cast("SymbolicParamName", inputId)
                        ] = cwl_yaml_input

            # Create augmentedInputs properly
            augmentedInputs = self.augmentCWLInputs(matInputs, cwl_dict_inputs)

            inputsFileName = outputMetaDir / self.INPUT_DECLARATIONS_FILENAME

            try:
                # Create YAML file
                cwlizedInputs = self.createYAMLFile(
                    matInputs, cwl_dict_inputs, inputsFileName
                )
                if os.path.isfile(inputsFileName):
                    # Execute workflow
                    stdoutFilename = outputMetaDir / WORKDIR_STDOUT_FILE
                    stderrFilename = outputMetaDir / WORKDIR_STDERR_FILE

                    # As the stdout contains the description of the outputs
                    # which is parsed to identify them
                    # we have to overwrite it every time we are running
                    # the workflow
                    with stdoutFilename.open(mode="wb+") as cwl_yaml_stdout:
                        with stderrFilename.open(mode="ab+") as cwl_yaml_stderr:
                            jobIntermediateDir = intermediateDir.as_posix() + "/"
                            outputDir = outputsDir.as_posix() + "/"

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
                                debugFlags = [
                                    "--debug",
                                    "--leave-tmpdir",
                                ]
                            elif self.logger.getEffectiveLevel() <= logging.INFO:
                                debugFlags = [
                                    "--verbose",
                                    "--rm-tmpdir",
                                ]
                            else:
                                debugFlags = [
                                    "--rm-tmpdir",
                                ]

                            # The command-line
                            cmd_arr = [
                                f"{cwltool_install_dir}/bin/cwltool",
                                *debugFlags,
                                "--outdir=" + outputDir,
                                "--tmp-outdir-prefix=" + jobIntermediateDir,
                                "--tmpdir-prefix=" + jobIntermediateDir,
                                "--strict",
                                "--no-doc-cache",
                            ]

                            if (
                                self.container_factory.containerType
                                == ContainerType.Singularity
                            ):
                                assert (
                                    matWfEng.containers_path is not None
                                ), "The containers path should exist"

                                cmd_arr.extend(
                                    [
                                        "--disable-pull",
                                        "--singularity",
                                    ]
                                )
                                instEnv[
                                    "CWL_SINGULARITY_CACHE"
                                ] = matWfEng.containers_path.as_posix()
                                instEnv["SINGULARITY_CONTAIN"] = "1"
                                instEnv["APPTAINER_CONTAIN"] = "1"
                                if self.writable_containers:
                                    instEnv["SINGULARITY_WRITABLE"] = "1"
                                    instEnv["APPTAINER_WRITABLE"] = "1"
                            elif (
                                self.container_factory.containerType
                                == ContainerType.Docker
                            ):
                                cmd_arr.extend(
                                    [
                                        "--disable-pull",
                                    ]
                                )
                            elif (
                                self.container_factory.containerType
                                == ContainerType.Podman
                            ):
                                if engineVersion < self.PODMAN_CWLTOOL_VERSION:
                                    if self.container_factory.supportsFeature("userns"):
                                        instEnv["PODMAN_USERNS"] = "keep-id"
                                    cmd_arr.extend(
                                        [
                                            "--disable-pull",
                                            "--user-space-docker-cmd="
                                            + self.container_factory.command,
                                        ]
                                    )
                                else:
                                    cmd_arr.extend(
                                        [
                                            "--disable-pull",
                                            "--podman",
                                        ]
                                    )
                            elif (
                                self.container_factory.containerType
                                == ContainerType.NoContainer
                            ):
                                cmd_arr.extend(
                                    [
                                        "--no-container",
                                    ]
                                )
                            else:
                                raise WorkflowEngineException(
                                    "FATAL ERROR: Unsupported container factory {}".format(
                                        self.container_factory.ContainerType()
                                    )
                                )

                            # Now, the environment variables to include
                            bindable_paths: "MutableSequence[pathlib.Path]" = []
                            for mat_env in matEnvironment:
                                if (
                                    mat_env.values is not None
                                    and len(mat_env.values) > 0
                                ):
                                    cmd_arr.append(
                                        "--preserve-environment=" + mat_env.name
                                    )
                                    env_vals: "MutableSequence[str]" = []
                                    for mat_val in mat_env.values:
                                        if isinstance(mat_val, MaterializedContent):
                                            the_local = (
                                                mat_val.local
                                                if mat_val.extrapolated_local is None
                                                else mat_val.extrapolated_local
                                            )
                                            bindable_paths.append(the_local)
                                            env_vals.append(the_local.as_posix())
                                        else:
                                            env_vals.append(str(mat_val))
                                    # Now, assign it
                                    instEnv[mat_env.name] = ":".join(env_vals)

                            if (
                                self.container_factory.containerType
                                != ContainerType.NoContainer
                            ):
                                # TODO: Teach cwltool to bind the paths
                                pass

                            # Last, the workflow to run and the yaml with the inputs
                            cmd_arr.extend(
                                [
                                    localWorkflowFile.as_posix(),
                                    inputsFileName.as_posix(),
                                ]
                            )
                            self.logger.debug("Command => {}".format(" ".join(cmd_arr)))

                            started = datetime.datetime.now().astimezone()
                            yield StagedExecution(
                                status=ExecutionStatus.Running,
                                job_id=str(os.getpid()),
                                exitVal=cast("ExitVal", -1),
                                augmentedInputs=augmentedInputs,
                                # TODO: store the augmentedEnvironment instead
                                # of the materialized one
                                environment=matEnvironment,
                                matCheckOutputs=[],
                                outputsDir=outputsDir,
                                queued=queued,
                                started=started,
                                ended=datetime.datetime.min,
                                diagram=dagFile,
                                logfile=[
                                    stdoutFilename,
                                    stderrFilename,
                                ],
                            )

                            retVal = subprocess.Popen(
                                cmd_arr,
                                stdout=cwl_yaml_stdout,
                                stderr=cwl_yaml_stderr,
                                stdin=subprocess.DEVNULL,
                                cwd=self.workDir,
                                env=instEnv,
                            ).wait()
                            ended = datetime.datetime.now(datetime.timezone.utc)

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

                            if retVal > 0:
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
                                matInputs, outputs, outputsDir, outputsMapping
                            )

                    yield StagedExecution(
                        status=ExecutionStatus.Finished,
                        exitVal=cast("ExitVal", retVal),
                        augmentedInputs=augmentedInputs,
                        # TODO: store the augmentedEnvironment instead
                        # of the materialized one
                        environment=matEnvironment,
                        matCheckOutputs=matOutputs,
                        outputsDir=outputsDir,
                        queued=queued,
                        started=started,
                        ended=ended,
                        diagram=dagFile,
                        logfile=[
                            stdoutFilename,
                            stderrFilename,
                        ],
                    )
                else:
                    yield StagedExecution(
                        status=ExecutionStatus.Died,
                        exitVal=cast("ExitVal", -1),
                        augmentedInputs=augmentedInputs,
                        # TODO: store the augmentedEnvironment instead
                        # of the materialized one
                        environment=matEnvironment,
                        matCheckOutputs=[],
                        outputsDir=outputsDir,
                        queued=queued,
                        started=started,
                        ended=datetime.datetime.now().astimezone(),
                        diagram=dagFile,
                        logfile=[],
                    )

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
        matInputs: "Sequence[MaterializedInput]",
        cwlInputs: "Mapping[SymbolicParamName, Any]",
        filename: "pathlib.Path",
    ) -> "Mapping[SymbolicParamName, ExecInputVal]":
        """
        Method to create a YAML file that describes the execution inputs of the workflow
        needed for their execution. Return parsed inputs.
        """
        try:
            execInputs = self.executionInputs(matInputs, cwlInputs)
            if len(execInputs) != 0:
                with filename.open(mode="w+", encoding="utf-8") as yaml_file:
                    yaml.safe_dump(
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

    def augmentCWLInputs(
        self,
        matInputs: "Sequence[MaterializedInput]",
        cwlInputs: "Mapping[SymbolicParamName, Any]",
    ) -> "Sequence[MaterializedInput]":
        """
        Generate additional MaterializedInput for the implicit params.
        """
        matHash: "Mapping[SymbolicParamName, MaterializedInput]" = {
            mat_input.name: mat_input for mat_input in matInputs
        }
        augmented_inputs = cast("MutableSequence[MaterializedInput]", [])
        for input_name, cwl_input in cwlInputs.items():
            aug_input = matHash.get(input_name)
            if aug_input is None:
                if "default" in cwl_input:
                    val = cwl_input["default"]

                    # TODO: handle complex default values, like file paths
                    # TODO: can default values have secondary inputs?
                    aug_values = val if isinstance(val, list) else [val]
                    aug_input = MaterializedInput(
                        name=input_name,
                        values=aug_values,
                        autoFilled=False,
                        implicit=True,
                    )

            if aug_input is not None:
                augmented_inputs.append(aug_input)

        return augmented_inputs

    def executionInputs(
        self,
        matInputs: "Sequence[MaterializedInput]",
        cwlInputs: "Mapping[SymbolicParamName, Any]",
    ) -> "Mapping[SymbolicParamName, ExecInputVal]":
        """
        Setting execution inputs needed to execute the workflow
        """
        if len(matInputs) == 0:  # Is list of materialized inputs empty?
            raise WorkflowEngineException("FATAL ERROR: Execution with no inputs")

        if len(cwlInputs) == 0:  # Is list of declared inputs empty?
            raise WorkflowEngineException(
                "FATAL ERROR: Workflow with no declared inputs"
            )

        execInputs: "MutableMapping[SymbolicParamName, ExecInputVal]" = dict()
        for matInput in matInputs:
            if isinstance(matInput, MaterializedInput):  # input is a MaterializedInput
                # numberOfInputs = len(matInput.values)  # number of inputs inside a MaterializedInput
                name = matInput.name
                value_types = cwlInputs.get(name, {}).get("type")
                if value_types is None:
                    raise WorkflowEngineException(
                        f"ERROR: input {name} not available in workflow"
                    )

                if not isinstance(value_types, list):
                    value_types = [value_types]

                the_values = matInput.values if matInput.values is not None else [None]
                for input_value in the_values:
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
                            if value.kind in (
                                ContentKind.Directory,
                                ContentKind.File,
                                ContentKind.ContentWithURIs,
                            ):
                                if not value.local.exists():
                                    self.logger.warning(
                                        "Input {} is not materialized".format(name)
                                    )
                                value_local = (
                                    value.local
                                    if value.extrapolated_local is None
                                    else value.extrapolated_local
                                ).as_posix()

                                eInput: "MutableMapping[str, Any]" = {
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
                                            "location": secInput.local.as_posix(),
                                        }
                                        for secInput in matInput.secondaryInputs
                                    ]
                                if isArray:
                                    the_arr = execInputs.setdefault(
                                        name,
                                        cast(
                                            "MutableSequence[MutableMapping[str, Any]]",
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
                                name, cast("ExecInputVal", [])
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
