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
import functools
import itertools
import json
import logging
import os
import pathlib
import platform
import re
import shutil
import subprocess
import sys
import tempfile
import yaml

from typing import (
    cast,
    TYPE_CHECKING,
)

from ..common import (
    ContainerTaggedName,
    ContainerType,
    ContentKind,
    DEFAULT_JAVA_CMD,
    EngineMode,
    LocalWorkflow,
    MaterializedContent,
    MaterializedInput,
    StagedExecution,
)

if TYPE_CHECKING:
    from typing import (
        Any,
        IO,
        Mapping,
        MutableMapping,
        MutableSequence,
        Optional,
        Pattern,
        Sequence,
        Set,
        Tuple,
        Type,
        Union,
    )

    from typing_extensions import Final

    from ..common import (
        AbsPath,
        AnyPath,
        EngineMode,
        EngineVersion,
        ExitVal,
        ExpectedOutput,
        Fingerprint,
        MaterializedOutput,
        RelPath,
        SymbolicParamName,
        URIType,
    )

    from ..container_factories import (
        ContainerFactory,
    )

    from ..utils.groovy_parsing import (
        ContextAssignments,
        NfInclude,
        NfIncludeConfig,
        NfProcess,
        NfWorkflow,
    )

    from . import (
        EngineLocalConfig,
        EnginePath,
        WorkflowEngineVersionStr,
    )

from . import WorkflowEngine, WorkflowEngineException
from . import (
    MaterializedWorkflowEngine,
    STATS_DAG_DOT_FILE,
    WORKDIR_STATS_RELDIR,
    WORKDIR_STDOUT_FILE,
    WORKDIR_STDERR_FILE,
    WorkflowType,
)

from ..container_factories.no_container import (
    NoContainerFactory,
)

from ..fetchers.http import fetchClassicURL
from ..utils.contents import (
    copy2_nofollow,
)
from ..utils.groovy_parsing import (
    analyze_nf_content,
    ERROR_PROCESS_NAME,
)

# A default name for the static bash
DEFAULT_STATIC_BASH_CMDS = [
    "bash.static",
    f"bash-{platform.system().lower()}-{platform.machine()}",
]

DEFAULT_STATIC_PS_CMDS = [
    "ps.static",
    f"ps-{platform.system().lower()}-{platform.machine()}",
]


@functools.lru_cache()
def _tzstring() -> "str":
    try:
        with open("/etc/timezone", "r") as tzreader:
            tzstring = tzreader.readline().rstrip()
    except:
        # The default for the worst case
        tzstring = "Europe/Madrid"

    return tzstring


class NextflowWorkflowEngine(WorkflowEngine):
    NEXTFLOW_REPO = "https://github.com/nextflow-io/nextflow"
    DEFAULT_NEXTFLOW_VERSION = cast("EngineVersion", "19.04.1")
    DEFAULT_NEXTFLOW_VERSION_WITH_PODMAN = cast("EngineVersion", "20.01.0")
    DEFAULT_NEXTFLOW_VERSION_20_04 = cast("EngineVersion", "20.04.1")
    DEFAULT_NEXTFLOW_DOCKER_IMAGE = "nextflow/nextflow"

    DEFAULT_NEXTFLOW_ENTRYPOINT = "main.nf"
    NEXTFLOW_CONFIG_FILENAME = "nextflow.config"
    TROJAN_CONFIG_FILENAME = "force-params-with-trojan.config"
    INPUT_DECLARATIONS_FILENAME = "inputdeclarations.yaml"

    NEXTFLOW_IO = cast("URIType", "https://www.nextflow.io/")

    DEFAULT_MAX_RETRIES = 5
    DEFAULT_MAX_CPUS = 4

    ENGINE_NAME = "nextflow"

    SUPPORTED_CONTAINER_TYPES = {
        ContainerType.NoContainer,
        ContainerType.Singularity,
        ContainerType.Docker,
        ContainerType.Podman,
    }

    SUPPORTED_SECURE_EXEC_CONTAINER_TYPES = {
        ContainerType.NoContainer,
        ContainerType.Singularity,
        #   ContainerType.Podman,
    }

    def __init__(
        self,
        container_factory_clazz: "Type[ContainerFactory]" = NoContainerFactory,
        cacheDir: "Optional[AnyPath]" = None,
        workflow_config: "Optional[Mapping[str, Any]]" = None,
        local_config: "Optional[EngineLocalConfig]" = None,
        engineTweaksDir: "Optional[AnyPath]" = None,
        cacheWorkflowDir: "Optional[AnyPath]" = None,
        cacheWorkflowInputsDir: "Optional[AnyPath]" = None,
        workDir: "Optional[AnyPath]" = None,
        outputsDir: "Optional[AnyPath]" = None,
        outputMetaDir: "Optional[AnyPath]" = None,
        intermediateDir: "Optional[AnyPath]" = None,
        tempDir: "Optional[AnyPath]" = None,
        stagedContainersDir: "Optional[AnyPath]" = None,
        secure_exec: "bool" = False,
        allowOther: "bool" = False,
        config_directory: "Optional[AnyPath]" = None,
    ):
        super().__init__(
            container_factory_clazz=container_factory_clazz,
            cacheDir=cacheDir,
            workflow_config=workflow_config,
            local_config=local_config,
            engineTweaksDir=engineTweaksDir,
            cacheWorkflowDir=cacheWorkflowDir,
            cacheWorkflowInputsDir=cacheWorkflowInputsDir,
            workDir=workDir,
            outputsDir=outputsDir,
            intermediateDir=intermediateDir,
            tempDir=tempDir,
            stagedContainersDir=stagedContainersDir,
            outputMetaDir=outputMetaDir,
            secure_exec=secure_exec,
            allowOther=allowOther,
            config_directory=config_directory,
        )

        toolsSect = local_config.get("tools", {}) if local_config else {}
        # Obtaining the full path to Java
        self.java_cmd = toolsSect.get("javaCommand", DEFAULT_JAVA_CMD)
        abs_java_cmd = shutil.which(self.java_cmd)
        if abs_java_cmd is None:
            self.logger.critical(
                f"Java command {self.java_cmd}, needed by Nextflow, was not found"
            )
        else:
            self.java_cmd = abs_java_cmd

        # Obtaining the full path to static bash
        staticBashPaths = []
        stBash = toolsSect.get("staticBashCommand")
        if stBash is not None:
            staticBashPaths.append(stBash)
        staticBashPaths.extend(DEFAULT_STATIC_BASH_CMDS)

        for static_bash_cmd in staticBashPaths:
            self.static_bash_cmd = shutil.which(static_bash_cmd)
            if self.static_bash_cmd is not None:
                break

        if self.static_bash_cmd is None:
            self.logger.warning(
                f"Static bash command is not available (looked for {staticBashPaths}). It could be needed for some images"
            )

        # Obtaining the full path to static ps
        staticPsPaths = []
        stPs = toolsSect.get("staticPsCommand")
        if stPs is not None:
            staticPsPaths.append(stPs)
        staticPsPaths.extend(DEFAULT_STATIC_PS_CMDS)

        for static_ps_cmd in staticPsPaths:
            self.static_ps_cmd = shutil.which(static_ps_cmd)
            if self.static_ps_cmd is not None:
                break

        if self.static_ps_cmd is None:
            self.logger.warning(
                f"Static ps command is not available (looked for {staticPsPaths}). It could be needed for some images"
            )

        # Deciding whether to unset JAVA_HOME
        wfexs_dirname = os.path.dirname(os.path.abspath(sys.argv[0]))
        self.unset_java_home = (
            os.path.commonpath([self.java_cmd, wfexs_dirname]) == wfexs_dirname
        )

        engineConf = copy.deepcopy(toolsSect.get(self.ENGINE_NAME, {}))
        workflowEngineConf = (
            workflow_config.get(self.ENGINE_NAME, {}) if workflow_config else {}
        )
        engineConf.update(workflowEngineConf)

        self.nxf_image = engineConf.get(
            "dockerImage", self.DEFAULT_NEXTFLOW_DOCKER_IMAGE
        )
        nxf_version = engineConf.get("version")
        if nxf_version is None:
            if self.container_factory.containerType == ContainerType.Podman:
                default_nextflow_version = self.DEFAULT_NEXTFLOW_VERSION_WITH_PODMAN
            else:
                default_nextflow_version = self.DEFAULT_NEXTFLOW_VERSION
            nxf_version = engineConf.get("version", default_nextflow_version)
        elif (
            self.container_factory.containerType == ContainerType.Podman
            and nxf_version < self.DEFAULT_NEXTFLOW_VERSION_WITH_PODMAN
        ):
            nxf_version = self.DEFAULT_NEXTFLOW_VERSION_WITH_PODMAN
        self.nxf_version = nxf_version
        self.max_retries = engineConf.get("maxRetries", self.DEFAULT_MAX_RETRIES)
        self.max_cpus = engineConf.get("maxProcesses", self.DEFAULT_MAX_CPUS)

        # The profile to force, in case it cannot be guessed
        nxf_profile: "Union[str, Sequence[str]]" = engineConf.get("profile", [])
        self.nxf_profile: "Sequence[str]"
        if isinstance(nxf_profile, list):
            self.nxf_profile = nxf_profile
        elif isinstance(nxf_profile, str):
            split_by_comma = re.compile(r"[ \t]*,[ \t]*")
            self.nxf_profile = split_by_comma.split(nxf_profile)
        else:
            # It should not happen
            self.nxf_profile = [str(nxf_profile)]

        # Setting the assets directory
        self.nxf_assets = os.path.join(self.engineTweaksDir, "assets")
        os.makedirs(self.nxf_assets, exist_ok=True)

        # Setting up packed directory
        self.groovy_cache_dir = os.path.join(
            self.cacheWorkflowDir, "groovy-parsing-cache"
        )
        os.makedirs(self.groovy_cache_dir, exist_ok=True)

    @classmethod
    def MyWorkflowType(cls) -> "WorkflowType":
        # As of https://about.workflowhub.eu/Workflow-RO-Crate/ ,
        # the rocrate_programming_language should be next
        return WorkflowType(
            engineName=cls.ENGINE_NAME,
            shortname="nextflow",
            name="Nextflow",
            clazz=cls,
            uriMatch=[cls.NEXTFLOW_IO],
            uriTemplate=cls.NEXTFLOW_IO,
            url=cls.NEXTFLOW_IO,
            trs_descriptor="NFL",
            rocrate_programming_language="https://w3id.org/workflowhub/workflow-ro-crate#nextflow",
        )

    @classmethod
    def HasExplicitOutputs(cls) -> "bool":
        # Nextflow only has params
        return False

    @classmethod
    def SupportedContainerTypes(cls) -> "Set[ContainerType]":
        return cls.SUPPORTED_CONTAINER_TYPES

    @classmethod
    def SupportedSecureExecContainerTypes(cls) -> "Set[ContainerType]":
        return cls.SUPPORTED_SECURE_EXEC_CONTAINER_TYPES

    @property
    def engine_url(self) -> "URIType":
        return self.NEXTFLOW_IO

    NXF_VER_PAT: "Pattern[str]" = re.compile(r"!?[>=]*([^ ]+)")

    def identifyWorkflow(
        self, localWf: "LocalWorkflow", engineVer: "Optional[EngineVersion]" = None
    ) -> "Union[Tuple[EngineVersion, LocalWorkflow], Tuple[None, None]]":
        """
        This method should return the effective engine version needed
        to run it when this workflow engine recognizes the workflow type
        """

        nfPath = localWf.dir
        if localWf.relPath is not None:
            nfPath = nfPath / localWf.relPath

        nfDir: "pathlib.Path"
        # If it is a directory, we have to assume there should be a nextflow.config
        firstPath = None
        if nfPath.is_dir():
            nfDir = nfPath
        elif nfPath.is_file():
            # Does it exist?
            nfDir = nfPath.parent
            # We don't know yet which is
            firstPath = nfPath
        else:
            # Giving up
            raise WorkflowEngineException(
                f"Could not find {nfPath} in Nextflow workflow directory"
            )

        # Trying with the defaults
        if firstPath is None:
            firstPath = nfDir / self.NEXTFLOW_CONFIG_FILENAME

            # Does it exist?
            if not firstPath.is_file():
                firstPath = nfDir / self.DEFAULT_NEXTFLOW_ENTRYPOINT

                if not firstPath.is_file():
                    # Giving up
                    raise WorkflowEngineException(
                        f"Could not find neither {self.NEXTFLOW_CONFIG_FILENAME} nor {self.DEFAULT_NEXTFLOW_ENTRYPOINT} in Nextflow workflow directory {nfDir}"
                    )
                    # return None, None

        # Guessing what we got here is a nextflow.config
        # or a Nexflow file
        processes: "Sequence[NfProcess]"
        includes: "Sequence[NfInclude]"
        workflows: "Sequence[NfWorkflow]"
        includeconfigs: "Sequence[NfIncludeConfig]"
        interesting_assignments: "ContextAssignments"

        nfConfig: "Optional[pathlib.Path]" = None
        candidateNf: "Optional[RelPath]" = None
        candidateConfig: "Optional[RelPath]" = None
        newNxfConfigs: "MutableSequence[pathlib.Path]" = []
        only_names = ["manifest", "nextflow"]
        absoluteCandidateNf: "Optional[pathlib.Path]" = None
        # First, are we dealing with a config or a nextflow file?
        with open(firstPath, mode="rt", encoding="utf-8") as nfH:
            firstPathContent = nfH.read()
            try:
                (
                    _,
                    processes,
                    includes,
                    workflows,
                    includeconfigs,
                    interesting_assignments,
                ) = analyze_nf_content(
                    firstPathContent,
                    only_names=only_names,
                    cache_dir=self.groovy_cache_dir,
                )
            except Exception as e:
                errstr = f"Failed to parse initial file {os.path.relpath(firstPath, nfDir)} with groovy parser"
                self.logger.exception(errstr)
                raise WorkflowEngineException(errstr) from e

            some_process = False
            for a_process in processes:
                if a_process.name != ERROR_PROCESS_NAME:
                    some_process = True
                    break
            if isinstance(interesting_assignments.get("manifest"), dict):
                # This is a nextflow config
                nfConfig = firstPath
                newNxfConfigs.append(firstPath)
            elif some_process or len(includes) > 0 or len(workflows) > 0:
                # It is a nextflow file, but it could be one different from the one at the nextflow.config
                absoluteCandidateNf = firstPath
            else:
                # This might be a nextflow config
                nfConfig = firstPath
                newNxfConfigs.append(firstPath)

        # Did we loaded a nextflow config file?
        if nfConfig is None:
            possibleNfConfig = nfDir / self.NEXTFLOW_CONFIG_FILENAME
            # Only include what it is reachable
            if possibleNfConfig.is_file():
                newNxfConfigs.append(possibleNfConfig)
            else:
                self.logger.debug(
                    f"No default configuration file for workflow at {nfDir}"
                )

        # Let's record all the configuration files
        nxfScripts: "MutableSequence[RelPath]" = []
        absolutePutativeCandidateNf: "Optional[pathlib.Path]" = None
        minimalEngineVer = None
        kw_20_04_Pat: "Optional[Pattern[str]]" = re.compile(
            r"\$(?:(?:launchDir|moduleDir|projectDir)|\{(?:launchDir|moduleDir|projectDir)\})"
        )
        while len(newNxfConfigs) > 0:
            nextNewNxfConfigs: "MutableSequence[pathlib.Path]" = []
            for newNxfConfig in newNxfConfigs:
                # Do not read twice
                relNewNxfConfig = cast(
                    "RelPath", newNxfConfig.relative_to(nfDir).as_posix()
                )
                if relNewNxfConfig in nxfScripts:
                    continue

                nxfScripts.append(relNewNxfConfig)
                with newNxfConfig.open(mode="rt", encoding="utf-8") as nfH:
                    newNxfConfigContent = nfH.read()
                    try:
                        (
                            _,
                            _,
                            _,
                            _,
                            includeconfigs,
                            interesting_assignments,
                        ) = analyze_nf_content(
                            newNxfConfigContent,
                            only_names=only_names,
                            cache_dir=self.groovy_cache_dir,
                        )
                    except Exception as e:
                        errstr = f"Failed to parse configuration file {relNewNxfConfig} with groovy parser"
                        self.logger.exception(errstr)
                        raise WorkflowEngineException(errstr) from e

                    # Register the main one
                    if nfConfig is None:
                        nfConfig = newNxfConfig

                    # This is easier to be detected through pattern matching
                    if kw_20_04_Pat is not None:
                        matched = kw_20_04_Pat.search(newNxfConfigContent)
                        if matched:
                            if self.nxf_version <= self.DEFAULT_NEXTFLOW_VERSION_20_04:
                                minimalEngineVer = self.DEFAULT_NEXTFLOW_VERSION_20_04
                            else:
                                minimalEngineVer = self.nxf_version
                            kw_20_04_Pat = None

                    # Time to resolve these
                    nfConfigDir = newNxfConfig.parent
                    # But first, check the manifest availability
                    # to obtain the entrypoint
                    manifest = interesting_assignments.get("manifest")
                    if isinstance(manifest, dict):
                        putativeCandidateNfVals = manifest.get("mainScript")
                        if putativeCandidateNfVals is not None:
                            for putativeCandidateNfVal in putativeCandidateNfVals:
                                putativeCandidateNf = putativeCandidateNfVal[1]
                                possibleAbsolutePutativeCandidateNf = (
                                    nfConfigDir / putativeCandidateNf
                                ).resolve(strict=False)
                                if possibleAbsolutePutativeCandidateNf.is_file():
                                    absolutePutativeCandidateNf = (
                                        possibleAbsolutePutativeCandidateNf
                                    )
                                else:
                                    self.logger.warning(
                                        f"Candidate entrypoint {putativeCandidateNf} from manifest at {relNewNxfConfig} not found"
                                    )

                        # And now, the minimal version
                        putativeEngineVerVals = manifest.get("nextflowVersion")
                        if putativeEngineVerVals is not None:
                            for putativeEngineVerVal in putativeEngineVerVals:
                                matched = self.NXF_VER_PAT.search(
                                    putativeEngineVerVal[1]
                                )
                                if matched:
                                    if engineVer is None or engineVer <= matched.group(
                                        1
                                    ):
                                        engineVer = cast(
                                            "EngineVersion", matched.group(1)
                                        )
                                    else:
                                        self.logger.info(
                                            f"Manifest reports version {matched.group(1)}, but version {engineVer} was requested"
                                        )
                                    break
                                else:
                                    self.logger.debug(
                                        f"Discarded {putativeEngineVerVal[1]} as a valid version string from {relNewNxfConfig}"
                                    )

                    # And register all the included config files which are reachable
                    for includeconfig in includeconfigs:
                        relIncludePath = includeconfig.path
                        absIncludePath = (nfConfigDir / relIncludePath).resolve(
                            strict=False
                        )
                        if absIncludePath.is_file():
                            nextNewNxfConfigs.append(absIncludePath)
                        else:
                            self.logger.warning(
                                f"Nextflow config file {relIncludePath} included from {relNewNxfConfig} not found"
                            )
            # Next round
            newNxfConfigs = nextNewNxfConfigs

        if nfConfig is None and absoluteCandidateNf is None:
            # Neither config nor entrypoint, giving up
            raise WorkflowEngineException(
                f"Could not find neither neither config nor entrypoint in Nextflow workflow directory {nfDir}, giving up"
            )
            # return None, None

        if absoluteCandidateNf is None:
            if absolutePutativeCandidateNf is None:
                # Giving up
                raise WorkflowEngineException(
                    f"Could not find mainScript or {self.DEFAULT_NEXTFLOW_ENTRYPOINT} in Nextflow workflow directory {nfDir}"
                )
                # return None, None
            # We have the entrypoint
            entrypoint = absolutePutativeCandidateNf
        elif (
            absolutePutativeCandidateNf is not None
            and absoluteCandidateNf != absolutePutativeCandidateNf
        ):
            raise WorkflowEngineException(
                "Nextflow mainScript in manifest {} differs from the one requested {}".format(
                    os.path.relpath(absolutePutativeCandidateNf, nfDir),
                    os.path.relpath(absoluteCandidateNf, nfDir),
                )
            )
        else:
            entrypoint = absoluteCandidateNf

        # Setting a default engineVer
        if (minimalEngineVer is not None) and (
            (engineVer is None) or engineVer < minimalEngineVer
        ):
            engineVer = minimalEngineVer

        if engineVer is None:
            engineVer = self.nxf_version
        elif (
            self.container_factory.containerType == ContainerType.Podman
            and engineVer < self.DEFAULT_NEXTFLOW_VERSION_WITH_PODMAN
        ):
            engineVer = self.DEFAULT_NEXTFLOW_VERSION_WITH_PODMAN

        # Subworkflow / submodule include detection
        newNxfScripts: "MutableSequence[pathlib.Path]" = [entrypoint]
        only_names = ["nextflow"]
        while len(newNxfScripts) > 0:
            nextNxfScripts: "MutableSequence[pathlib.Path]" = []
            for nxfScript in newNxfScripts:
                relNxfScript = cast("RelPath", os.path.relpath(nxfScript, nfDir))
                # Avoid loops
                if relNxfScript in nxfScripts:
                    continue

                self.logger.debug(f"Initial parsing {relNxfScript}")
                nxfScripts.append(relNxfScript)
                with open(nxfScript, mode="rt", encoding="utf-8") as nH:
                    content = nH.read()
                    try:
                        (
                            _,
                            processes,
                            includes,
                            workflows,
                            _,
                            interesting_assignments,
                        ) = analyze_nf_content(
                            content,
                            only_names=only_names,
                            cache_dir=self.groovy_cache_dir,
                        )
                    except Exception as e:
                        errstr = f"Failed to parse Nextflow file {relNxfScript} with groovy parser"
                        self.logger.exception(errstr)
                        raise WorkflowEngineException(errstr) from e

                    # Register all the included files which are reachable
                    nxfScriptDir = nxfScript.parent
                    for include in includes:
                        relIncludePath = include.path
                        if not relIncludePath.endswith(".nf"):
                            relIncludePath += ".nf"
                        absIncludePath = (nxfScriptDir / relIncludePath).resolve(
                            strict=False
                        )
                        if absIncludePath.is_file():
                            nextNxfScripts.append(absIncludePath)
                        else:
                            self.logger.warning(
                                f"Nextflow file {relIncludePath} included from {relNxfScript} not found"
                            )

                    # And register the templates from each
                    # the processes
                    for processDecl in processes:
                        for relTemplatePath in processDecl.templates:
                            # Now, let's try finding it
                            local_template = (
                                nxfScriptDir / "templates" / relTemplatePath
                            )
                            if not local_template.is_file():
                                local_template = nfDir / "templates" / relTemplatePath

                            # And now let's save it!
                            if local_template.is_file():
                                abs_local_template = local_template.resolve(
                                    strict=False
                                )
                                rel_local_template = cast(
                                    "RelPath",
                                    local_template.relative_to(nfDir).as_posix(),
                                )
                                nxfScripts.append(rel_local_template)
                            else:
                                self.logger.warning(
                                    f"Nextflow template {relTemplatePath} included from {relNxfScript} not found"
                                )

            newNxfScripts = nextNxfScripts

        candidateNf = cast("RelPath", os.path.relpath(entrypoint, nfDir))

        # Last, as there is no safe way to learn about other needed
        # files and directories, just include all the ones which are not
        # hidden. In previous iterations the code was looking for bin,
        # templates, lib and nextflow_schema.json , in part based on
        # https://training.nextflow.io/advanced/structure/
        # But real life workflows were using local files and directories
        # relative to the workflow directory, from custom locations.
        for child in nfDir.iterdir():
            if child.name.startswith("."):
                continue
            if child.name not in nxfScripts:
                nxfScripts.append(cast("RelPath", child.name))

        # The engine version should be used to create the id of the workflow language
        return engineVer, LocalWorkflow(
            dir=nfDir,
            relPath=candidateNf,
            effectiveCheckout=localWf.effectiveCheckout,
            langVersion=engineVer,
            relPathFiles=nxfScripts,
        )

    def materializeEngineVersion(
        self, engineVersion: "EngineVersion"
    ) -> "Tuple[EngineVersion, EnginePath, Fingerprint]":
        """
        Method to ensure the required engine version is materialized
        It should raise an exception when the exact version is unavailable,
        and no replacement could be fetched
        """

        nextflow_install_dir = cast(
            "EnginePath", os.path.join(self.weCacheDir, engineVersion)
        )
        retval, nxf_install_stdout_v, nxf_install_stderr_v = self.runNextflowCommand(
            engineVersion, ["info"], nextflow_path=nextflow_install_dir
        )
        if retval != 0:
            errstr = "Could not install Nextflow {} . Retval {}\n======\nSTDOUT\n======\n{}\n======\nSTDERR\n======\n{}".format(
                engineVersion, retval, nxf_install_stdout_v, nxf_install_stderr_v
            )
            raise WorkflowEngineException(errstr)

        # Getting the version label
        verPat = re.compile(r"Version: +(.*)$")
        assert nxf_install_stdout_v is not None
        verMatch = verPat.search(nxf_install_stdout_v)

        engineFingerprint = verMatch.group(1) if verMatch else ""

        return (
            engineVersion,
            nextflow_install_dir,
            cast("Fingerprint", engineFingerprint),
        )

    def runNextflowCommand(
        self,
        nextflow_version: "EngineVersion",
        commandLine: "Sequence[str]",
        containers_path: "Optional[AnyPath]" = None,
        workdir: "Optional[pathlib.Path]" = None,
        intermediateDir: "Optional[pathlib.Path]" = None,
        nextflow_path: "Optional[EnginePath]" = None,
        stdoutFilename: "Optional[AbsPath]" = None,
        stderrFilename: "Optional[AbsPath]" = None,
        runEnv: "Optional[Mapping[str, str]]" = None,
    ) -> "Tuple[ExitVal, Optional[str], Optional[str]]":
        self.logger.debug("Command => nextflow " + " ".join(commandLine))

        if containers_path is None:
            containers_path = cast(
                "AnyPath", self.container_factory.cacheDir.as_posix()
            )
        if self.engine_mode == EngineMode.Docker:
            (
                retval,
                nxf_run_stdout_v,
                nxf_run_stderr_v,
            ) = self.runNextflowCommandInDocker(
                nextflow_version,
                commandLine,
                containers_path=containers_path,
                workdir=workdir,
                intermediateDir=intermediateDir,
                stdoutFilename=stdoutFilename,
                stderrFilename=stderrFilename,
                runEnv=runEnv,
            )
        elif self.engine_mode == EngineMode.Local:
            retval, nxf_run_stdout_v, nxf_run_stderr_v = self.runLocalNextflowCommand(
                nextflow_version,
                commandLine,
                containers_path=containers_path,
                workdir=workdir,
                intermediateDir=intermediateDir,
                nextflow_install_dir=nextflow_path,
                stdoutFilename=stdoutFilename,
                stderrFilename=stderrFilename,
                runEnv=runEnv,
            )
        else:
            raise WorkflowEngineException(
                "Unsupported engine mode {} for {} engine".format(
                    self.engine_mode, self.ENGINE_NAME
                )
            )

        return retval, nxf_run_stdout_v, nxf_run_stderr_v

    def runLocalNextflowCommand(
        self,
        nextflow_version: "EngineVersion",
        commandLine: "Sequence[str]",
        containers_path: "AnyPath",
        workdir: "Optional[pathlib.Path]" = None,
        intermediateDir: "Optional[pathlib.Path]" = None,
        nextflow_install_dir: "Optional[EnginePath]" = None,
        stdoutFilename: "Optional[AbsPath]" = None,
        stderrFilename: "Optional[AbsPath]" = None,
        runEnv: "Optional[Mapping[str, str]]" = None,
    ) -> "Tuple[ExitVal, Optional[str], Optional[str]]":
        if nextflow_install_dir is None:
            nextflow_install_dir = cast(
                "EnginePath", os.path.join(self.weCacheDir, nextflow_version)
            )
        cachedScript = cast("AbsPath", os.path.join(nextflow_install_dir, "nextflow"))
        if not os.path.exists(cachedScript):
            os.makedirs(nextflow_install_dir, exist_ok=True)
            nextflow_script_url = cast(
                "URIType",
                "https://github.com/nextflow-io/nextflow/releases/download/v{0}/nextflow-{0}-all".format(
                    nextflow_version
                ),
            )
            self.logger.info(
                "Downloading Nextflow {}: {} => {}".format(
                    nextflow_version, nextflow_script_url, cachedScript
                )
            )
            fetchClassicURL(nextflow_script_url, cachedScript)

        # Checking the installer has execution permissions
        if not os.access(cachedScript, os.R_OK | os.X_OK):
            os.chmod(cachedScript, 0o555)

        # Now, time to run it
        NXF_HOME = os.path.join(nextflow_install_dir, ".nextflow")
        instEnv = dict(os.environ if runEnv is None else runEnv)
        instEnv["NXF_HOME"] = NXF_HOME
        # Needed for newer nextflow versions, so older workflows do not misbehave
        instEnv["NXF_DEFAULT_DSL"] = "1"
        instEnv["JAVA_CMD"] = self.java_cmd
        if self.unset_java_home:
            instEnv.pop("NXF_JAVA_HOME", None)
            instEnv.pop("JAVA_HOME", None)

        jobIntermediateDir = (
            intermediateDir if intermediateDir is not None else self.intermediateDir
        )
        instEnv["NXF_WORK"] = (
            workdir if workdir is not None else jobIntermediateDir
        ).as_posix()
        instEnv["NXF_ASSETS"] = self.nxf_assets
        if self.logger.getEffectiveLevel() <= logging.DEBUG:
            instEnv["NXF_DEBUG"] = "1"
        #    instEnv['NXF_DEBUG'] = '2'
        # elif self.logger.getEffectiveLevel() <= logging.INFO:
        #    instEnv['NXF_DEBUG'] = '1'

        # FIXME: Should we set NXF_TEMP???
        instEnv["NXF_TEMP"] = self.tempDir
        instEnv["TMPDIR"] = self.tempDir

        # This is needed to have Nextflow using the cached contents
        if self.container_factory.containerType == ContainerType.Singularity:
            # See https://github.com/nextflow-io/nextflow/commit/91e9ee7c3c2ed4e63559339ae1a1d2c7d5f25953
            if nextflow_version >= "21.09.0-edge":
                env_sing_key = "NXF_SINGULARITY_LIBRARYDIR"
            else:
                env_sing_key = "NXF_SINGULARITY_CACHEDIR"

            instEnv[env_sing_key] = containers_path

        # This is done only once
        retval = 0
        nxf_run_stdout_v = None
        nxf_run_stderr_v = None
        if not os.path.isdir(NXF_HOME):
            for tries in range(2):
                with tempfile.NamedTemporaryFile() as nxf_install_stdout:
                    with tempfile.NamedTemporaryFile() as nxf_install_stderr:
                        retval = subprocess.Popen(
                            [cachedScript, "-version"],
                            stdout=nxf_install_stdout,
                            stderr=nxf_install_stderr,
                            cwd=nextflow_install_dir,
                            env=instEnv,
                        ).wait()

                        if retval == 0:
                            break

                        # Reading the output and error for the report
                        if os.path.exists(nxf_install_stdout.name):
                            with open(nxf_install_stdout.name, "r") as c_stF:
                                nxf_run_stdout_v = c_stF.read()
                        else:
                            nxf_run_stdout_v = ""

                        if os.path.exists(nxf_install_stderr.name):
                            with open(nxf_install_stderr.name, "r") as c_stF:
                                nxf_run_stderr_v = c_stF.read()
                        else:
                            nxf_run_stderr_v = ""

        # And now the command is run
        if retval == 0 and isinstance(commandLine, list) and len(commandLine) > 0:
            # Needed to tie Nextflow short
            instEnv["NXF_OFFLINE"] = "true"

            nxf_run_stdout: "IO[bytes]"
            nxf_run_stderr: "IO[bytes]"
            try:
                if stdoutFilename is None:
                    nxf_run_stdout = tempfile.NamedTemporaryFile()
                    stdoutFilename = cast("AbsPath", nxf_run_stdout.name)
                else:
                    nxf_run_stdout = open(stdoutFilename, mode="ab+")

                if stderrFilename is None:
                    nxf_run_stderr = tempfile.NamedTemporaryFile()
                    stderrFilename = cast("AbsPath", nxf_run_stderr.name)
                else:
                    nxf_run_stderr = open(stderrFilename, mode="ab+")

                retval = subprocess.Popen(
                    [cachedScript, *commandLine],
                    stdout=nxf_run_stdout,
                    stderr=nxf_run_stderr,
                    cwd=nextflow_install_dir if workdir is None else workdir,
                    env=instEnv,
                ).wait()
            finally:
                # Reading the output and error for the report
                if nxf_run_stdout is not None:
                    nxf_run_stdout.seek(0)
                    nxf_run_stdout_v_b = nxf_run_stdout.read()
                    nxf_run_stdout_v = nxf_run_stdout_v_b.decode("utf-8", "ignore")
                    nxf_run_stdout.close()
                if nxf_run_stderr is not None:
                    nxf_run_stderr.seek(0)
                    nxf_run_stderr_v_b = nxf_run_stderr.read()
                    nxf_run_stderr_v = nxf_run_stderr_v_b.decode("utf-8", "ignore")
                    nxf_run_stderr.close()

        return cast("ExitVal", retval), nxf_run_stdout_v, nxf_run_stderr_v

    def runNextflowCommandInDocker(
        self,
        nextflow_version: "EngineVersion",
        commandLine: "Sequence[str]",
        containers_path: "AnyPath",
        workdir: "Optional[pathlib.Path]" = None,
        intermediateDir: "Optional[pathlib.Path]" = None,
        stdoutFilename: "Optional[AbsPath]" = None,
        stderrFilename: "Optional[AbsPath]" = None,
        runEnv: "Optional[Mapping[str, str]]" = None,
    ) -> "Tuple[ExitVal, Optional[str], Optional[str]]":
        # Now, we have to assure the nextflow image is already here
        docker_tag = self.nxf_image + ":" + nextflow_version
        checkimage_params = [
            self.docker_cmd,
            "images",
            "--format",
            "{{.ID}}\t{{.Tag}}",
            docker_tag,
        ]

        retval = 0
        nxf_run_stdout_v = None
        nxf_run_stderr_v = None
        with tempfile.NamedTemporaryFile() as checkimage_stdout:
            with tempfile.NamedTemporaryFile() as checkimage_stderr:
                retval = subprocess.call(
                    checkimage_params,
                    stdout=checkimage_stdout,
                    stderr=checkimage_stderr,
                )

                if retval != 0:
                    # Reading the output and error for the report
                    with open(checkimage_stdout.name, "r") as c_stF:
                        nxf_run_stdout_v = c_stF.read()
                    with open(checkimage_stderr.name, "r") as c_stF:
                        nxf_run_stderr_v = c_stF.read()

                    errstr = "ERROR: Nextflow Engine failed while checking Nextflow image (retval {}). Tag: {}\n======\nSTDOUT\n======\n{}\n======\nSTDERR\n======\n{}".format(
                        retval, docker_tag, nxf_run_stdout_v, nxf_run_stderr_v
                    )

                    nxf_run_stderr_v = errstr

            do_pull_image = os.path.getsize(checkimage_stdout.name) == 0

        if retval == 0 and do_pull_image:
            # The image is not here yet
            pullimage_params = [self.docker_cmd, "pull", docker_tag]
            with tempfile.NamedTemporaryFile() as pullimage_stdout:
                with tempfile.NamedTemporaryFile() as pullimage_stderr:
                    retval = subprocess.call(
                        pullimage_params,
                        stdout=pullimage_stdout,
                        stderr=pullimage_stderr,
                    )
                    if retval != 0:
                        # Reading the output and error for the report
                        with open(pullimage_stdout.name, "r") as c_stF:
                            nxf_run_stdout_v = c_stF.read()
                        with open(pullimage_stderr.name, "r") as c_stF:
                            nxf_run_stderr_v = c_stF.read()

                        # It failed!
                        errstr = "ERROR: Nextflow Engine failed while pulling Nextflow image (retval {}). Tag: {}\n======\nSTDOUT\n======\n{}\n======\nSTDERR\n======\n{}".format(
                            retval, docker_tag, nxf_run_stdout_v, nxf_run_stderr_v
                        )

                        nxf_run_stderr_v = errstr

        if retval == 0 and isinstance(commandLine, list) and len(commandLine) > 0:
            # TODO: run it!!!!
            nxf_run_stdout_v = ""

            try:
                if workdir is None:
                    workdir = (
                        self.workDir.absolute()
                        if not self.workDir.is_absolute()
                        else self.workDir
                    )
                else:
                    workdir.mkdir(parents=True, exist_ok=True)
            except Exception as error:
                raise WorkflowEngineException(
                    "ERROR: Unable to create nextflow working directory. Error: "
                    + str(error)
                )

            # Value needed to compose the Nextflow docker call
            uid = str(os.getuid())
            gid = str(os.getgid())

            # Timezone is needed to get logs properly timed
            tzstring = _tzstring()

            # FIXME: should it be something more restrictive?
            homedir = os.path.expanduser("~")

            nextflow_install_dir = os.path.join(self.weCacheDir, nextflow_version)
            nxf_home = os.path.join(nextflow_install_dir, ".nextflow")
            nxf_assets_dir = self.nxf_assets
            try:
                # Directories required by Nextflow in a Docker
                os.makedirs(nxf_assets_dir, exist_ok=True)
            except Exception as error:
                raise WorkflowEngineException(
                    "ERROR: Unable to create nextflow assets directory. Error: "
                    + str(error)
                )

            # The fixed parameters
            nextflow_cmd_pre_vol = [
                self.docker_cmd,
                "run",
                "--rm",
                "--net",
                "host",
                "-e",
                "USER",
                "-e",
                "NXF_DEBUG",
                "-e",
                "TZ=" + tzstring,
                "-e",
                "HOME=" + homedir,
                "-e",
                "NXF_ASSETS=" + nxf_assets_dir,
                "-e",
                "NXF_USRMAP=" + uid,
                # "-e", "NXF_DOCKER_OPTS=-u "+uid+":"+gid+" -e HOME="+homedir+" -e TZ="+tzstring+" -v "+workdir+":"+workdir+":rw,rprivate,z -v "+project_path+":"+project_path+":rw,rprivate,z",
                "-e",
                "NXF_DOCKER_OPTS=-u "
                + uid
                + ":"
                + gid
                + " -e HOME="
                + homedir
                + " -e TZ="
                + tzstring
                + " -v "
                + workdir.as_posix()
                + ":"
                + workdir.as_posix()
                + ":rw,rprivate,z",
                "-v",
                "/var/run/docker.sock:/var/run/docker.sock:rw,rprivate,z",
            ]

            validation_cmd_post_vol = ["-w", workdir, docker_tag, "nextflow"]
            validation_cmd_post_vol.extend(commandLine)

            validation_cmd_post_vol_resume = [*validation_cmd_post_vol, "-resume"]

            # This one will be filled in by the volume parameters passed to docker
            # docker_vol_params = []

            # This one will be filled in by the volume meta declarations, used
            # to generate the volume parameters
            volumes = [
                (homedir + "/", "ro,rprivate,z"),
                #    (nxf_assets_dir,"rprivate,z"),
                (workdir.as_posix() + "/", "rw,rprivate,z"),
                #    (project_path+'/',"rw,rprivate,z"),
                #    (repo_dir+'/',"ro,rprivate,z")
            ]
            #
            ## These are the parameters, including input and output files and directories
            #
            ## Parameters which are not input or output files are in the configuration
            # variable_params = [
            ##    ('challenges_ids',challenges_ids),
            ##    ('participant_id',participant_id)
            # ]
            # for conf_key in self.configuration.keys():
            #    if conf_key not in self.MASKED_KEYS:
            #        variable_params.append((conf_key,self.configuration[conf_key]))
            #
            #
            # variable_infile_params = [
            #    ('input',input_loc),
            #    ('goldstandard_dir',goldstandard_dir_loc),
            #    ('public_ref_dir',public_ref_dir_loc),
            #    ('assess_dir',assess_dir_loc)
            # ]
            #
            # variable_outfile_params = [
            #    ('statsdir',stats_loc+'/'),
            #    ('outdir',results_loc+'/'),
            #    ('otherdir',other_loc+'/')
            # ]
            #
            ## The list of populable outputs
            # variable_outfile_params.extend(self.populable_outputs.items())
            #
            ## Preparing the RO volumes
            # for ro_loc_id,ro_loc_val in variable_infile_params:
            #    if os.path.exists(ro_loc_val):
            #        if ro_loc_val.endswith('/') and os.path.isfile(ro_loc_val):
            #            ro_loc_val = ro_loc_val[:-1]
            #        elif not ro_loc_val.endswith('/') and os.path.isdir(ro_loc_val):
            #            ro_loc_val += '/'
            #    volumes.append((ro_loc_val,"ro,rprivate,z"))
            #    variable_params.append((ro_loc_id,ro_loc_val))
            #
            ## Preparing the RW volumes
            # for rw_loc_id,rw_loc_val in variable_outfile_params:
            #    # We can skip integrating subpaths of project_path
            #    if os.path.commonprefix([os.path.normpath(rw_loc_val),project_path]) != project_path:
            #        if os.path.exists(rw_loc_val):
            #            if rw_loc_val.endswith('/') and os.path.isfile(rw_loc_val):
            #                rw_loc_val = rw_loc_val[:-1]
            #            elif not rw_loc_val.endswith('/') and os.path.isdir(rw_loc_val):
            #                rw_loc_val += '/'
            #        elif rw_loc_val.endswith('/'):
            #            # Forcing the creation of the directory
            #            try:
            #                os.makedirs(rw_loc_val)
            #            except:
            #                pass
            #        else:
            #            # Forcing the creation of the file
            #            # so docker does not create it as a directory
            #            with open(rw_loc_val,mode="a") as pop_output_h:
            #                logger.debug("Pre-created empty output file (ownership purposes) "+rw_loc_val)
            #                pass
            #
            #        volumes.append((rw_loc_val,"rprivate,z"))
            #
            #    variable_params.append((rw_loc_id,rw_loc_val))
            #
            # Assembling the command line
            validation_params = []
            validation_params.extend(nextflow_cmd_pre_vol)

            for volume_dir, volume_mode in volumes:
                validation_params.append("-v")
                validation_params.append(
                    volume_dir + ":" + volume_dir + ":" + volume_mode
                )

            validation_params_resume = [*validation_params]

            validation_params.extend(validation_cmd_post_vol)
            validation_params_resume.extend(validation_cmd_post_vol_resume)
            #
            ## Last, but not the least important
            # validation_params_flags = []
            # for param_id,param_val in variable_params:
            #    validation_params_flags.append("--" + param_id)
            #    validation_params_flags.append(param_val)
            #
            # validation_params.extend(validation_params_flags)
            # validation_params_resume.extend(validation_params_flags)
            #
            # Retries system was introduced because an insidious
            # bug happens sometimes
            # https://forums.docker.com/t/any-known-problems-with-symlinks-on-bind-mounts/32138
            retries = self.max_retries
            retval = -1
            validation_params_cmd = validation_params

            run_stdout: "IO[bytes]"
            run_stderr: "IO[bytes]"
            try:
                if stdoutFilename is None:
                    run_stdout = tempfile.NamedTemporaryFile()
                    stdoutFilename = cast("AbsPath", run_stdout.name)
                else:
                    run_stdout = open(stdoutFilename, mode="ab+")

                if stderrFilename is None:
                    run_stderr = tempfile.NamedTemporaryFile()
                    stderrFilename = cast("AbsPath", run_stderr.name)
                else:
                    run_stderr = open(stderrFilename, mode="ab+")

                while retries > 0 and retval != 0:
                    self.logger.debug('"' + '" "'.join(validation_params_cmd) + '"')
                    run_stdout.flush()
                    run_stderr.flush()

                    retval = subprocess.call(
                        validation_params_cmd, stdout=run_stdout, stderr=run_stderr
                    )
                    if retval != 0:
                        retries -= 1
                        self.logger.debug(
                            "\nFailed with {} , left {} tries\n".format(retval, retries)
                        )
                        validation_params_cmd = validation_params_resume
            finally:
                # Reading the output and error for the report
                if run_stdout is not None:
                    run_stdout.seek(0)
                    nxf_run_stdout_v_b = run_stdout.read()
                    nxf_run_stdout_v = nxf_run_stdout_v_b.decode("utf-8", "ignore")
                    run_stdout.close()
                if run_stderr is not None:
                    run_stderr.seek(0)
                    nxf_run_stderr_v_b = run_stderr.read()
                    nxf_run_stderr_v = nxf_run_stderr_v_b.decode("utf-8", "ignore")
                    run_stderr.close()

            # Last evaluation
            if retval != 0:
                # It failed!
                errstr = "ERROR: Nextflow Engine failed while executing Nextflow workflow (retval {})\n======\nSTDOUT\n======\n{}\n======\nSTDERR\n======\n{}".format(
                    retval, nxf_run_stdout_v, nxf_run_stderr_v
                )

                nxf_run_stderr_v = errstr

        return cast("ExitVal", retval), nxf_run_stdout_v, nxf_run_stderr_v

    def _get_engine_version_str(
        self, matWfEng: "MaterializedWorkflowEngine"
    ) -> "WorkflowEngineVersionStr":
        assert (
            matWfEng.instance == self
        ), "The workflow engine instance does not match!!!!"

        retval, engine_ver, nxf_version_stderr_v = self.runNextflowCommand(
            matWfEng.version,
            ["-v"],
            workdir=pathlib.Path(matWfEng.engine_path),
            nextflow_path=matWfEng.engine_path,
        )

        if retval != 0:
            errstr = "Could not get version running nextflow -v from {}. Retval {}\n======\nSTDOUT\n======\n{}\n======\nSTDERR\n======\n{}".format(
                matWfEng.engine_path, retval, engine_ver, nxf_version_stderr_v
            )
            raise WorkflowEngineException(errstr)

        if engine_ver is None:
            engine_ver = ""

        return cast("WorkflowEngineVersionStr", engine_ver.strip())

    # Pattern for searching for process\..*container = ['"]([^'"]+)['"] in dumped config
    ContConfigPat: "Pattern[str]" = re.compile(
        r"process\..*container = '(.+)'$", flags=re.MULTILINE
    )

    # Pattern for searching for (docker|podman)\.registry = ['"]([^'"]+)['"] in dumped config
    RegistryPat: "Pattern[str]" = re.compile(
        r"(docker|podman)\.registry = '(.+)'$", flags=re.MULTILINE
    )

    C_URL_REGEX: "Final[Pattern[str]]" = re.compile(
        r"https?:\/\/(www\.)?[-a-zA-Z0-9@:%._\+~#=]{1,256}\.[a-zA-Z0-9()]{1,6}\b([-a-zA-Z0-9()@:%_\+.~#?&//=]*)"
    )

    C_DOCKER_REGEX: "Final[Pattern[str]]" = re.compile(
        r"(?:docker://)?(?:(?=[^:\/]{1,253})(?!-)[a-zA-Z0-9-]{1,63}(?<!-)(?:\.(?!-)[a-zA-Z0-9-]{1,63}(?<!-))*(?::[0-9]{1,5})?/)?((?![._-])(?:[a-z0-9._-]*)(?<![._-])(?:/(?![._-])[a-z0-9._-]*(?<![._-]))*)(?::(?![.-])[a-zA-Z0-9_.-]{1,128})?"
    )

    # Pattern to search dsl enabling
    DSLEnablePat: "Final[Pattern[str]]" = re.compile(
        r"^\s*nextflow\.enable\.dsl\s*=\s*([1-9])"
    )

    def _genDockSingContainerTaggedName(
        self,
        container_tag: "str",
        registries: "Mapping[ContainerType, str]",
    ) -> "Optional[ContainerTaggedName]":
        this_container_url = None
        this_container_docker = None
        url_match = self.C_URL_REGEX.search(container_tag)
        if url_match:
            this_container_url = url_match[0]
            self.logger.debug(f"Found URL container {this_container_url}")

        docker_match = self.C_DOCKER_REGEX.search(container_tag)
        if docker_match is not None and docker_match[0] != "singularity":
            this_container_docker = docker_match[0]
            self.logger.debug(f"Found Docker container {this_container_docker}")

        if this_container_url is not None:
            return ContainerTaggedName(
                origTaggedName=this_container_url,
                type=ContainerType.Singularity,
            )
        elif this_container_docker is not None:
            return ContainerTaggedName(
                origTaggedName=this_container_docker,
                type=ContainerType.Docker,
                registries=registries if registries else None,
            )

        self.logger.error(
            f"Cannot parse container string {container_tag}\n\n:warning: Skipping this container image.."
        )

        return None

    def materializeWorkflow(
        self,
        matWorkflowEngine: "MaterializedWorkflowEngine",
        consolidatedWorkflowDir: "AbsPath",
        offline: "bool" = False,
        profiles: "Optional[Sequence[str]]" = None,
    ) -> "Tuple[MaterializedWorkflowEngine, Sequence[ContainerTaggedName]]":
        """
        Method to ensure the workflow has been materialized. In the case
        of Nextflow, it returns the input matWorkflowEngine after the checks,
        as well as the list of containers
        """

        # Default nextflow profile is 'standard'
        # parse
        # nextflow config -flat
        localWf = matWorkflowEngine.workflow
        nxf_params = ["config", "-flat"]
        if profiles is None:
            profiles = self.nxf_profile
        if profiles:
            nxf_params.extend(["-profile", ",".join(profiles)])
        else:
            nxf_params.extend(["-show-profiles"])
        nxf_params.append(localWf.dir.as_posix())

        flat_retval, flat_stdout, flat_stderr = self.runNextflowCommand(
            matWorkflowEngine.version,
            nxf_params,
            workdir=localWf.dir,
            nextflow_path=matWorkflowEngine.engine_path,
        )

        if flat_retval != 0:
            errstr = """Could not obtain the flat workflow config Nextflow (fingerprint {}) . Retval {}
======
STDOUT
======
{}

======
STDERR
======
{}""".format(
                matWorkflowEngine.fingerprint, flat_retval, flat_stdout, flat_stderr
            )
            raise WorkflowEngineException(errstr)

        # searching for process\..*container = ['"]([^'"]+)['"]
        containerTags: "MutableSequence[ContainerTaggedName]" = []
        containerTagsConda: "MutableSequence[ContainerTaggedName]" = []
        containerTagSet: "Set[str]" = set()
        assert flat_stdout is not None
        self.logger.debug(f"nextflow config -flat {localWf.dir} => {flat_stdout}")

        # We need to learn the registries before getting the tags
        container_registries: "MutableMapping[ContainerType, str]" = {}
        for regMatch in self.RegistryPat.finditer(flat_stdout):
            try:
                container_registries[ContainerType(regMatch[1])] = regMatch[2]
            except:
                self.logger.debug(f"Failed to assign registry {regMatch[1]}")

        for contMatch in self.ContConfigPat.finditer(flat_stdout):
            # Discarding local path cases
            if contMatch[1][0] != "/" and contMatch[1] not in containerTagSet:
                containerTagSet.add(contMatch[1])
                tagged_container = self._genDockSingContainerTaggedName(
                    contMatch[1], container_registries
                )
                if (tagged_container is not None) and (
                    tagged_container not in containerTags
                ):
                    containerTags.append(tagged_container)

        # Early DSL2 detection
        dslVer: "Optional[str]" = None
        for dslMatch in self.DSLEnablePat.finditer(flat_stdout):
            dslVer = dslMatch.group(1)
            # Only first declaration should be allowed
            break

        # and main workflow for
        # container ['"]([^'"]+)['"]
        assert localWf.relPath is not None
        wfEntrypoint = (
            localWf.relPath
            if os.path.isabs(localWf.relPath)
            else os.path.join(localWf.dir, localWf.relPath)
        )

        # Subworkflow / submodule include detection
        nfDir = matWorkflowEngine.workflow.dir
        assert matWorkflowEngine.workflow.relPathFiles is not None
        for relNxfScript in matWorkflowEngine.workflow.relPathFiles:
            # Skipping templates and other elements
            if not relNxfScript.endswith(".nf"):
                continue

            nxfScript = (nfDir / relNxfScript).resolve(strict=False)
            # If it is an special directory, skip it!
            if nxfScript.is_dir():
                continue

            self.logger.debug(f"Searching container declarations at {relNxfScript}")
            with nxfScript.open(mode="rt", encoding="utf-8") as wfH:
                # This is needed for multi-line pattern matching
                content = wfH.read()

                try:
                    (
                        _,
                        processes,
                        includes,
                        workflows,
                        _,
                        interesting_assignments,
                    ) = analyze_nf_content(content, cache_dir=self.groovy_cache_dir)
                except Exception as e:
                    errstr = f"Failed to parse Nextflow file {relNxfScript} with groovy parser"
                    self.logger.exception(errstr)
                    raise WorkflowEngineException(errstr) from e

                for processDecl in processes:
                    # Docker and Singularity
                    for container_tag in processDecl.containers:
                        if container_tag not in containerTagSet:
                            containerTagSet.add(container_tag)
                            tagged_container = self._genDockSingContainerTaggedName(
                                container_tag, container_registries
                            )
                            if (tagged_container is not None) and (
                                tagged_container not in containerTags
                            ):
                                containerTags.append(tagged_container)
                    # Conda
                    for conda_tag in processDecl.condas:
                        if conda_tag not in containerTagSet:
                            containerTagSet.add(conda_tag)
                            containerTagsConda.append(
                                ContainerTaggedName(
                                    origTaggedName=conda_tag,
                                    type=ContainerType.Conda,
                                )
                            )

                # Matching at least one DSL declaration
                if dslVer is None:
                    nextFl = interesting_assignments.get("nextflow")
                    if isinstance(nextFl, dict):
                        nextEnb = nextFl.get("enable")
                        if isinstance(nextEnb, dict):
                            dslVerVal = nextEnb.get("dsl")
                            if isinstance(dslVerVal, list):
                                dslVer = dslVerVal[0][1]

        # Join both lists
        if len(containerTagsConda) > 0:
            containerTags.extend(containerTagsConda)
        return matWorkflowEngine, containerTags

    def simpleContainerFileName(self, imageUrl: "URIType") -> "RelPath":
        """
        This method was borrowed from
        https://github.com/nextflow-io/nextflow/blob/539a22b68c114c94eaf4a88ea8d26b7bfe2d0c39/modules/nextflow/src/main/groovy/nextflow/container/SingularityCache.groovy#L80
        and translated to Python
        """
        p = imageUrl.find("://")
        name = imageUrl[p + 3 :] if p != -1 else imageUrl
        extension = ".img"
        if ".sif:" in name:
            extension = ".sif"
            name = name.replace(".sif:", "-")
        elif name.endswith(".sif"):
            extension = ".sif"
            name = name[:-4]

        name = name.replace(":", "-").replace("/", "-")

        return cast("RelPath", name + extension)

    def structureAsNXFParams(
        self, matInputs: "Sequence[MaterializedInput]", outputsDir: "pathlib.Path"
    ) -> "Mapping[str, Any]":
        nxpParams: "MutableMapping[str, Any]" = {}

        for matInput in matInputs:
            node = nxpParams
            splittedPath = matInput.name.split(".")
            for step in splittedPath[:-1]:
                node = node.setdefault(step, {})

            nxfValues: "MutableSequence[Union[str, int, float]]" = []

            for value in matInput.values:
                if isinstance(value, MaterializedContent):
                    if value.kind in (
                        ContentKind.Directory,
                        ContentKind.File,
                        ContentKind.ContentWithURIs,
                    ):
                        if not value.local.exists():
                            self.logger.warning(
                                "Input {} has values which are not materialized".format(
                                    matInput.name
                                )
                            )
                        # Use the extrapolated local file containing paths
                        # instead of the original one containing URLs
                        nxfValues.append(
                            value.local.as_posix()
                            if value.extrapolated_local is None
                            else value.extrapolated_local.as_posix()
                        )
                    else:
                        raise WorkflowEngineException(
                            "ERROR: Input {} has values of type {} this code does not know how to handle".format(
                                matInput.name, value.kind
                            )
                        )
                elif matInput.autoFilled:
                    # This is needed to correct paths for different executions
                    assert isinstance(value, str)
                    if os.path.isabs(value):
                        rel_path = os.path.relpath(value, self.outputsDir)
                    else:
                        rel_path = value
                    nxfValues.append(os.path.join(outputsDir, rel_path))
                else:
                    nxfValues.append(value)

            node[splittedPath[-1]] = nxfValues if len(nxfValues) != 1 else nxfValues[0]

        return nxpParams

    def augmentNextflowInputs(
        self,
        matHash: "Mapping[SymbolicParamName, MaterializedInput]",
        allExecutionParams: "Mapping[str, Any]",
        prefix: "str" = "",
    ) -> "Sequence[MaterializedInput]":
        """
        Generate additional MaterializedInput for the implicit params.
        """
        augmentedInputs = cast("MutableSequence[MaterializedInput]", [])
        for key, val in allExecutionParams.items():
            linearKey = cast("SymbolicParamName", prefix + key)
            if isinstance(val, dict):
                newAugmentedInputs = self.augmentNextflowInputs(
                    matHash, val, prefix=linearKey + "."
                )
                augmentedInputs.extend(newAugmentedInputs)
            else:
                augmentedInput = matHash.get(linearKey)
                if augmentedInput is None:
                    # Time to create a new materialized input
                    theValues = val if isinstance(val, list) else [val]
                    augmentedInput = MaterializedInput(
                        name=cast("SymbolicParamName", key),
                        values=theValues,
                        implicit=True,
                    )
                elif augmentedInput.autoFilled:
                    # Time to update an existing materialized input
                    theValues = val if isinstance(val, list) else [val]
                    augmentedInput = MaterializedInput(
                        name=augmentedInput.name, values=theValues, autoFilled=True
                    )

                augmentedInputs.append(augmentedInput)

        return augmentedInputs

    def launchWorkflow(
        self,
        matWfEng: "MaterializedWorkflowEngine",
        matInputs: "Sequence[MaterializedInput]",
        matEnvironment: "Sequence[MaterializedInput]",
        outputs: "Sequence[ExpectedOutput]",
        profiles: "Optional[Sequence[str]]" = None,
    ) -> "StagedExecution":
        # TODO: implement usage of materialized environment variables
        if len(matInputs) == 0:  # Is list of materialized inputs empty?
            raise WorkflowEngineException("FATAL ERROR: Execution with no inputs")

        localWf = matWfEng.workflow
        # Some needed assumptions
        assert localWf.relPath is not None
        assert isinstance(localWf.relPathFiles, list) and len(localWf.relPathFiles) > 0

        # These declarations provide a separate metadata directory for
        # each one of the executions of Nextflow
        (
            outputDirPostfix,
            intermediateDir,
            outputsDir,
            outputMetaDir,
        ) = self.create_job_directories()
        outputStatsDir = outputMetaDir / WORKDIR_STATS_RELDIR
        outputStatsDir.mkdir(parents=True, exist_ok=True)

        timelineFile = outputStatsDir / "timeline.html"
        reportFile = outputStatsDir / "report.html"
        traceFile = outputStatsDir / "trace.tsv"
        dagFile = outputStatsDir / STATS_DAG_DOT_FILE

        # Custom variables setup
        runEnv = dict(os.environ)
        optStaticBinsMonkeyPatch = ""
        optWritable = None

        # The list of environment variables to be whitelisted
        runEnv["TZ"] = _tzstring()
        envWhitelist = [
            "TZ",
        ]
        runEnv.update(self.container_factory.environment)
        envWhitelist.extend(self.container_factory.environment.keys())

        # This is needed for containers potentially without ps command
        if self.container_factory.containerType in (
            ContainerType.Singularity,
            ContainerType.Docker,
            ContainerType.Podman,
        ):
            if self.container_factory.containerType == ContainerType.Singularity:
                volFlag = "-B"
            else:
                volFlag = "-v"

            if self.static_ps_cmd is not None:
                # We are placing the patched ps command into /usr/local/bin
                # because /bin/ps could already exist, and being a symlink
                # to /bin/busybox, leading to a massive failure
                optStaticBinsMonkeyPatch += (
                    f" {volFlag} {self.static_ps_cmd}:/usr/local/bin/ps:ro"
                )

        if self.container_factory.containerType == ContainerType.Singularity:
            if self.static_bash_cmd is not None:
                optStaticBinsMonkeyPatch += (
                    f" {volFlag} {self.static_bash_cmd}:/bin/bash:ro"
                )

            if self.writable_containers:
                optWritable = "--writable-tmpfs"
            elif self.container_factory.supportsFeature("userns"):
                optWritable = "--userns"
            else:
                optWritable = "--pid"
        elif self.container_factory.containerType == ContainerType.Podman:
            if self.container_factory.supportsFeature("userns"):
                optWritable = "--userns=keep-id"
            else:
                optWritable = ""

        # Environment variables have to be processed before we are reaching next lines
        # Now, the environment variables to include
        bindable_paths: "MutableSequence[pathlib.Path]" = []
        for mat_env in matEnvironment:
            if len(mat_env.values) > 0:
                envWhitelist.append(mat_env.name)
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
                runEnv[mat_env.name] = ":".join(env_vals)

        if self.container_factory.containerType != ContainerType.NoContainer:
            # Teach the container solution to bind the paths being used
            # by the exposed environment variables
            for bindable_path in bindable_paths:
                optStaticBinsMonkeyPatch += (
                    f" {volFlag} {bindable_path}:{bindable_path}:ro"
                )

        # Corner cases of single file workflows with no nextflow.config file
        originalConfFile: "Optional[pathlib.Path]"
        if localWf.relPath != localWf.relPathFiles[0]:
            originalConfFile = localWf.dir / localWf.relPathFiles[0]

            # Copying the workflow directory, so an additional file
            # can be included without changing the original one
            wDir = outputMetaDir / "nxf_trojan"
            shutil.copytree(localWf.dir, wDir, copy_function=copy2_nofollow)

            forceParamsConfFile = wDir / self.TROJAN_CONFIG_FILENAME
        else:
            wDir = localWf.dir
            # Configuration file generated by WfExS to override what it is needed
            forceParamsConfFile = outputMetaDir / self.TROJAN_CONFIG_FILENAME

            originalConfFile = None

        # File where all the gathered parameters are going to be stored
        allParamsFile = os.path.join(outputMetaDir, "all-params.json")

        with forceParamsConfFile.open(mode="w", encoding="utf-8") as fPC:
            # First of all, we have to replicate the contents of the
            # original nextflow.config, so their original methods are not out
            # of context
            if originalConfFile is not None:
                with originalConfFile.open(mode="r", encoding="utf-8") as oH:
                    shutil.copyfileobj(oH, fPC)

                print("\n", file=fPC)

            if self.container_factory.containerType == ContainerType.Singularity:
                print(
                    f"""
docker.enabled = false
podman.enabled = false
singularity.enabled = true
singularity.envWhitelist = '{','.join(envWhitelist)}'
singularity.runOptions = '{volFlag} {self.cacheWorkflowInputsDir}:{self.cacheWorkflowInputsDir}:ro {optWritable} {optStaticBinsMonkeyPatch}'
singularity.autoMounts = true
""",
                    file=fPC,
                )
            elif self.container_factory.containerType == ContainerType.Docker:
                print(
                    f"""
singularity.enabled = false
podman.enabled = false
docker.enabled = true
docker.envWhitelist = '{','.join(envWhitelist)}'
docker.runOptions = '{volFlag} {self.cacheWorkflowInputsDir}:{self.cacheWorkflowInputsDir}:ro,Z {optStaticBinsMonkeyPatch}'
docker.fixOwnership = true
""",
                    file=fPC,
                )
            elif self.container_factory.containerType == ContainerType.Podman:
                print(
                    f"""
singularity.enabled = false
docker.enabled = false
podman.enabled = true
podman.envWhitelist = '{','.join(envWhitelist)}'
podman.runOptions = '{volFlag} {self.cacheWorkflowInputsDir}:{self.cacheWorkflowInputsDir}:ro,Z {optWritable}'
""",
                    file=fPC,
                )
            elif self.container_factory.containerType == ContainerType.NoContainer:
                print(
                    f"""
docker.enabled = false
singularity.enabled = false
podman.enabled = false
""",
                    file=fPC,
                )

            # Trace fields are detailed at
            # https://www.nextflow.io/docs/latest/tracing.html#trace-fields
            print(
                f"""
timeline {{
	enabled = true
	file = "{timelineFile}"
}}
		
report {{
	enabled = true
	file = "{reportFile}"
}}

trace {{
	enabled = true
	file = "{traceFile}"
    fields = 'task_id,process,tag,name,status,exit,module,container,cpus,time,disk,memory,attempt,submit,start,complete,duration,realtime,%cpu,%mem,rss,vmem,peak_rss,peak_vmem,rchar,wchar,syscr,syscw,read_bytes,write_bytes,env,script,error_action'
    raw = true
    sep = '\0\t\0'
}}

dag {{
	enabled = true
	file = "{dagFile}"
}}
""",
                file=fPC,
            )

            if self.max_cpus is not None:
                print(
                    f"""
executor.cpus={self.max_cpus}
""",
                    file=fPC,
                )

            # Last, the trojan horse in the configuration file for input parameter
            # provenance, which only works when this is done after loading the original nextflow.config
            print(
                """

import groovy.json.JsonOutput
def wfexs_allParams()
{{
    new File('{0}').write(JsonOutput.toJson(params))
}}

wfexs_allParams()
""".format(
                    allParamsFile
                ),
                file=fPC,
            )

        inputsFileName = outputMetaDir / self.INPUT_DECLARATIONS_FILENAME

        nxpParams = self.structureAsNXFParams(matInputs, outputsDir)
        if len(nxpParams) != 0:
            try:
                with inputsFileName.open(mode="w+", encoding="utf-8") as yF:
                    yaml.safe_dump(nxpParams, yF)
            except IOError as error:
                raise WorkflowEngineException(
                    "ERROR: cannot create input declarations file {}, {}".format(
                        inputsFileName, error
                    )
                )
        else:
            raise WorkflowEngineException("No parameter was specified! Bailing out")

        runName = "WfExS-run_" + datetime.datetime.now().strftime("%Y%m%dT%H%M%S")

        nxf_params = [
            "-log",
            (outputStatsDir / "log.txt").as_posix(),
            "-C",
            forceParamsConfFile.as_posix(),
            "run",
            "-name",
            runName,
            "-offline",
            "-w",
            intermediateDir.as_posix(),
            "-params-file",
            inputsFileName.as_posix(),
        ]

        profile_input: "Optional[MaterializedInput]" = None
        if profiles is None:
            profiles = self.nxf_profile
        if profiles:
            profile_input = MaterializedInput(
                name=cast("SymbolicParamName", "-profile"),
                values=[",".join(profiles)],
            )
            nxf_params.extend(
                [profile_input.name, cast("str", profile_input.values[0])]
            )

        # Using the copy of the original workflow
        nxf_params.append(wDir.as_posix())

        stdoutFilename = cast(
            "AbsPath", os.path.join(outputMetaDir, WORKDIR_STDOUT_FILE)
        )
        stderrFilename = cast(
            "AbsPath", os.path.join(outputMetaDir, WORKDIR_STDERR_FILE)
        )

        started = datetime.datetime.now(datetime.timezone.utc)
        launch_retval, launch_stdout, launch_stderr = self.runNextflowCommand(
            matWfEng.version,
            nxf_params,
            containers_path=matWfEng.containers_path,
            workdir=outputsDir,
            intermediateDir=intermediateDir,
            nextflow_path=matWfEng.engine_path,
            stdoutFilename=stdoutFilename,
            stderrFilename=stderrFilename,
            runEnv=runEnv,
        )
        ended = datetime.datetime.now(datetime.timezone.utc)

        self.logger.debug(launch_retval)
        self.logger.debug(launch_stdout)
        self.logger.debug(launch_stderr)

        # Creating the augmented inputs
        if os.path.isfile(allParamsFile):
            matHash = {}
            for matInput in matInputs:
                matHash[matInput.name] = matInput

            with open(allParamsFile, mode="r", encoding="utf-8") as aPF:
                allExecutionParams = json.load(aPF)

            augmentedInputs = self.augmentNextflowInputs(matHash, allExecutionParams)
        else:
            augmentedInputs = matInputs

        # And it is wise to also preserve the used profiles
        if profile_input is not None:
            augmentedInputs = [profile_input, *augmentedInputs]

        # Creating the materialized outputs
        matOutputs = self.identifyMaterializedOutputs(matInputs, outputs, outputsDir)

        relOutputsDir = cast("RelPath", os.path.relpath(outputsDir, self.workDir))
        return StagedExecution(
            exitVal=launch_retval,
            augmentedInputs=augmentedInputs,
            matCheckOutputs=matOutputs,
            outputsDir=relOutputsDir,
            started=started,
            ended=ended,
            # TODO: store the augmentedEnvironment instead
            # of the materialized one
            environment=matEnvironment,
            diagram=cast("RelPath", os.path.relpath(dagFile, self.workDir)),
            logfile=[
                cast("RelPath", os.path.relpath(stdoutFilename, self.workDir)),
                cast("RelPath", os.path.relpath(stderrFilename, self.workDir)),
            ],
            profiles=profiles,
        )
