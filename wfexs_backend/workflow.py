#!/usr/bin/env python
# -*- coding: utf-8 -*-

# Copyright 2020-2023 Barcelona Supercomputing Center (BSC), Spain
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

import atexit
import copy
import datetime
import inspect
import json
import logging
import os
import pathlib
import platform
import shutil
import subprocess
import sys
import tempfile
import threading
import time

from typing import (
    cast,
    Pattern,
    TYPE_CHECKING,
)

from .common import (
    StagedExecution,
)

if TYPE_CHECKING:
    from typing import (
        Any,
        Iterable,
        Mapping,
        MutableMapping,
        MutableSequence,
        Optional,
        Sequence,
        Tuple,
        Type,
        Union,
    )

    from typing_extensions import (
        Final,
        Literal,
        TypedDict,
    )

    from .common import (
        AbsPath,
        AbstractWorkflowEngineType,
        AnyContent,
        AnyPath,
        ContainerEngineVersionStr,
        ContainerOperatingSystem,
        EngineVersion,
        ExitVal,
        ExportActionBlock,
        MaterializedOutput,
        MutableParamsBlock,
        OutputsBlock,
        ParamsBlock,
        PlaceHoldersBlock,
        ProcessorArchitecture,
        RelPath,
        RepoTag,
        RepoURL,
        SecurityContextConfig,
        SecurityContextConfigBlock,
        SymbolicName,
        SymbolicParamName,
        SymbolicOutputName,
        TRS_Workflow_Descriptor,
        WfExSInstanceId,
        WorkflowConfigBlock,
        WorkflowEngineVersionStr,
        WorkflowMetaConfigBlock,
        WorkflowType,
        WritableSecurityContextConfig,
        WritableWorkflowMetaConfigBlock,
        URIType,
    )

    Sch_PlainURI = URIType

    Sch_LicensedURI = TypedDict(
        "Sch_LicensedURI",
        {
            "uri": str,
            "licences": Sequence[Sch_PlainURI],
            "attributions": Sequence[Any],
            "security-context": str,
        },
        total=False,
    )

    Sch_InputURI_Elem = Union[Sch_PlainURI, Sch_LicensedURI]
    Sch_InputURI_Fetchable = Union[Sch_InputURI_Elem, Sequence[Sch_InputURI_Elem]]
    Sch_InputURI = Union[Sch_InputURI_Fetchable, Sequence[Sequence[Sch_InputURI_Elem]]]

    Sch_Param = TypedDict(
        "Sch_Param",
        {
            "c-l-a-s-s": str,
            "url": Sch_InputURI,
            "secondary-urls": Sch_InputURI,
            "preferred-name": Union[Literal[False], str],
            "relative-dir": Union[Literal[False], str],
            "security-context": str,
            "globExplode": str,
            "autoFill": bool,
            "autoPrefix": bool,
        },
        total=False,
    )

    WFVersionId = Union[str, int]
    WorkflowId = Union[str, int]

import urllib.parse

from .ro_crate import (
    addInputsResearchObject,
    addOutputsResearchObject,
    addExpectedOutputsResearchObject,
    create_workflow_crate,
    add_execution_to_crate,
)
import bagit  # type: ignore[import]

from . import common as common_defs_module

# We have preference for the C based loader and dumper, but the code
# should fallback to default implementations when C ones are not present

import yaml

YAMLLoader: "Type[Union[yaml.Loader, yaml.CLoader]]"
YAMLDumper: "Type[Union[yaml.Dumper, yaml.CDumper]]"
try:
    from yaml import CLoader as YAMLLoader, CDumper as YAMLDumper
except ImportError:
    from yaml import Loader as YAMLLoader, Dumper as YAMLDumper

from .common import (
    AbstractWfExSException,
    Attribution,
    CacheType,
    ContentKind,
    DefaultNoLicenceTuple,
    ExpectedOutput,
    ExportItem,
    ExportItemType,
    ExportAction,
    GeneratedContent,
    GeneratedDirectoryContent,
    IdentifiedWorkflow,
    LicensedURI,
    LocalWorkflow,
    MarshallingStatus,
    MaterializedContent,
    MaterializedInput,
    MaterializedExportAction,
    MaterializedWorkflowEngine,
    RemoteRepo,
    StagedSetup,
)

from .encrypted_fs import ENCRYPTED_FS_MOUNT_IMPLEMENTATIONS

from .engine import (
    WorkflowEngine,
    WorkflowEngineException,
    WORKDIR_CONTAINERS_RELDIR,
    WORKDIR_ENGINE_TWEAKS_RELDIR,
    WORKDIR_INPUTS_RELDIR,
    WORKDIR_INTERMEDIATE_RELDIR,
    WORKDIR_MARSHALLED_EXECUTE_FILE,
    WORKDIR_MARSHALLED_EXPORT_FILE,
    WORKDIR_MARSHALLED_STAGE_FILE,
    WORKDIR_META_RELDIR,
    WORKDIR_OUTPUTS_RELDIR,
    WORKDIR_PASSPHRASE_FILE,
    WORKDIR_WORKFLOW_META_FILE,
    WORKDIR_WORKFLOW_RELDIR,
)

from .utils.contents import link_or_copy
from .utils.marshalling_handling import marshall_namedtuple, unmarshall_namedtuple
from .utils.misc import config_validate

from .fetchers.git import guess_repo_params
from .fetchers.trs_files import (
    TRS_SCHEME_PREFIX,
    INTERNAL_TRS_SCHEME_PREFIX,
)

from .nextflow_engine import NextflowWorkflowEngine
from .cwl_engine import CWLWorkflowEngine

if TYPE_CHECKING:
    from .wfexs_backend import WfExSBackend

# The list of classes to be taken into account
# CWL detection is before, as Nextflow one is
# a bit lax (only detects a couple of too common
# keywords)
WORKFLOW_ENGINE_CLASSES: "Sequence[Type[WorkflowEngine]]" = [
    CWLWorkflowEngine,
    NextflowWorkflowEngine,
]


def _wakeupEncDir(
    cond: "threading.Condition", workDir: "AbsPath", logger: "logging.Logger"
) -> None:
    """
    This method periodically checks whether the directory is still available
    """
    cond.acquire()
    try:
        while not cond.wait(60):
            os.path.isdir(workDir)
    except:
        logger.exception("Wakeup thread failed!")
    finally:
        cond.release()


class WFException(AbstractWfExSException):
    pass


class ExportActionException(AbstractWfExSException):
    pass


class WF:
    """
    Workflow enaction class
    """

    TRS_TOOL_FILES_FILE: "Final[RelPath]" = cast("RelPath", "trs_tool_files.json")

    SECURITY_CONTEXT_SCHEMA: "Final[RelPath]" = cast("RelPath", "security-context.json")
    STAGE_DEFINITION_SCHEMA: "Final[RelPath]" = cast("RelPath", "stage-definition.json")
    EXPORT_ACTIONS_SCHEMA: "Final[RelPath]" = cast("RelPath", "export-actions.json")

    STAGED_CRATE_FILE: "Final[RelPath]" = cast("RelPath", "staged.crate")
    EXECUTION_CRATE_FILE: "Final[RelPath]" = cast("RelPath", "execution.crate")

    DEFAULT_TRS_ENDPOINT: "Final[str]" = (
        "https://dev.workflowhub.eu/ga4gh/trs/v2/"  # root of GA4GH TRS API
    )
    TRS_TOOLS_PATH: "Final[str]" = "tools/"

    WORKFLOW_ENGINES: "Final[Sequence[WorkflowType]]" = list(
        map(lambda clazz: clazz.MyWorkflowType(), WORKFLOW_ENGINE_CLASSES)
    )

    RECOGNIZED_TRS_DESCRIPTORS: "Final[Mapping[TRS_Workflow_Descriptor, WorkflowType]]" = dict(
        map(lambda t: (t.trs_descriptor, t), WORKFLOW_ENGINES)
    )

    def __init__(
        self,
        wfexs: "WfExSBackend",
        workflow_id: "Optional[WorkflowId]" = None,
        version_id: "Optional[WFVersionId]" = None,
        descriptor_type: "Optional[TRS_Workflow_Descriptor]" = None,
        trs_endpoint: "str" = DEFAULT_TRS_ENDPOINT,
        params: "Optional[ParamsBlock]" = None,
        outputs: "Optional[OutputsBlock]" = None,
        placeholders: "Optional[PlaceHoldersBlock]" = None,
        default_actions: "Optional[Sequence[ExportActionBlock]]" = None,
        workflow_config: "Optional[WorkflowConfigBlock]" = None,
        creds_config: "Optional[SecurityContextConfigBlock]" = None,
        instanceId: "Optional[WfExSInstanceId]" = None,
        nickname: "Optional[str]" = None,
        creation: "Optional[datetime.datetime]" = None,
        rawWorkDir: "Optional[AnyPath]" = None,
        paranoid_mode: "Optional[bool]" = None,
        fail_ok: "bool" = False,
    ):
        """
        Init function

        :param wfexs: A WfExSBackend instance
        :param workflow_id: A unique identifier of the workflow. Although it is an integer in WorkflowHub,
        we cannot assume it is so in all the GA4GH TRS implementations which are exposing workflows.
        :param version_id: An identifier of the workflow version. Although it is an integer in
        WorkflowHub, we cannot assume the format of the version id, as it could follow semantic
        versioning, providing an UUID, etc.
        :param descriptor_type: The type of descriptor that represents this version of the workflow
        (e.g. CWL, WDL, NFL, or GALAXY). It is optional, so it is guessed from the calls to the API.
        :param trs_endpoint: The TRS endpoint used to find the workflow.
        :param params: Optional params for the workflow execution.
        :param outputs:
        :param workflow_config: Tweaks for workflow enactment, like some overrides
        :param creds_config: Dictionary with the different credential contexts, only used to fetch fresh contents
        :param instanceId: The instance id of this working directory
        :param nickname: The nickname of this working directory
        :param creation: The creation timestamp
        :param rawWorkDir: Raw working directory
        :param paranoid_mode: Should we enable paranoid mode for this workflow?
        :type wfexs: WfExSBackend
        :type workflow_id: str
        :type version_id: str
        :type descriptor_type: str
        :type trs_endpoint: str
        :type params: dict
        :type outputs: dict
        :type workflow_config: dict
        :type creds_config: SecurityContextConfigBlock
        :type instanceId: str
        :type creation datetime.datetime
        :type rawWorkDir: str
        :type paranoid_mode: bool
        :type fail_ok: bool
        """
        if wfexs is None:
            raise WFException("Unable to initialize, no WfExSBackend instance provided")

        # Getting a logger focused on specific classes
        self.logger = logging.getLogger(
            dict(inspect.getmembers(self))["__module__"]
            + "::"
            + self.__class__.__name__
        )

        self.wfexs = wfexs
        self.encWorkDir: "Optional[AbsPath]" = None
        self.workDir: "Optional[AbsPath]" = None

        if isinstance(paranoid_mode, bool):
            self.paranoidMode = paranoid_mode
        else:
            self.paranoidMode = self.wfexs.getDefaultParanoidMode()

        if not isinstance(workflow_config, dict):
            workflow_config = {}

        self.outputs: "Optional[Sequence[ExpectedOutput]]"
        self.default_actions: "Optional[Sequence[ExportAction]]"
        self.trs_endpoint: "Optional[str]"
        self.version_id: "Optional[WFVersionId]"
        self.descriptor_type: "Optional[TRS_Workflow_Descriptor]"
        self.id: "Optional[Union[str, int]]"
        if workflow_id is not None:
            workflow_meta: "WritableWorkflowMetaConfigBlock" = {
                "workflow_id": workflow_id
            }
            if version_id is not None:
                workflow_meta["version"] = version_id
            if nickname is not None:
                workflow_meta["nickname"] = nickname
            if descriptor_type is not None:
                descriptor = self.RECOGNIZED_TRS_DESCRIPTORS.get(descriptor_type)
                if descriptor is not None:
                    workflow_meta["workflow_type"] = descriptor.shortname
                else:
                    workflow_meta["workflow_type"] = descriptor_type
            if trs_endpoint is not None:
                workflow_meta["trs_endpoint"] = trs_endpoint
            if workflow_config is not None:
                workflow_meta["workflow_config"] = workflow_config
            if params is not None:
                workflow_meta["params"] = params
            if outputs is not None:
                workflow_meta["outputs"] = outputs
            if placeholders is not None:
                workflow_meta["placeholders"] = placeholders

            valErrors = config_validate(workflow_meta, self.STAGE_DEFINITION_SCHEMA)
            if len(valErrors) > 0:
                errstr = f"ERROR in workflow staging definition block: {valErrors}"
                self.logger.error(errstr)
                raise WFException(errstr)

            if not isinstance(creds_config, dict):
                creds_config = {}

            valErrors = config_validate(creds_config, self.SECURITY_CONTEXT_SCHEMA)
            if len(valErrors) > 0:
                errstr = f"ERROR in security context block: {valErrors}"
                self.logger.error(errstr)
                raise WFException(errstr)

            if not isinstance(params, dict):
                params = {}

            if not isinstance(outputs, dict):
                outputs = {}

            if not isinstance(placeholders, dict):
                placeholders = {}

            # Workflow-specific
            self.workflow_config = workflow_config
            self.creds_config = creds_config

            self.id = str(workflow_id)
            self.version_id = str(version_id)
            self.descriptor_type = descriptor_type
            self.params = params
            self.placeholders = placeholders
            self.formatted_params = self.formatParams(params)
            self.outputs = self.parseExpectedOutputs(outputs)
            self.default_actions = self.parseExportActions(
                [] if default_actions is None else default_actions
            )

            # The endpoint should always end with a slash
            if isinstance(trs_endpoint, str):
                if trs_endpoint[-1] != "/":
                    trs_endpoint += "/"

                # Removing the tools suffix, which appeared in first WfExS iterations
                if trs_endpoint.endswith("/" + self.TRS_TOOLS_PATH):
                    trs_endpoint = trs_endpoint[0 : -len(self.TRS_TOOLS_PATH)]

            self.trs_endpoint = trs_endpoint
        else:
            self.trs_endpoint = None
            self.id = None
            self.version_id = None
            self.descriptor_type = None

        if instanceId is not None:
            self.instanceId = instanceId

        if creation is None:
            self.workdir_creation = datetime.datetime.now(tz=datetime.timezone.utc)
        else:
            self.workdir_creation = creation

        self.encfs_type = None
        self.encfsCond = None
        self.encfsThread = None
        self.fusermount_cmd = cast("AnyPath", "")
        self.encfs_idleMinutes = None
        self.doUnmount = False

        checkSecure = True
        if rawWorkDir is None:
            if instanceId is None:
                (
                    self.instanceId,
                    self.nickname,
                    self.workdir_creation,
                    self.rawWorkDir,
                ) = self.wfexs.createRawWorkDir(nickname_prefix=nickname)
                checkSecure = False
            else:
                (
                    self.instanceId,
                    self.nickname,
                    self.workdir_creation,
                    self.rawWorkDir,
                ) = self.wfexs.getOrCreateRawWorkDirFromInstanceId(
                    instanceId, nickname=nickname, create_ok=False
                )
        else:
            self.rawWorkDir = cast("AbsPath", os.path.abspath(rawWorkDir))
            if instanceId is None:
                (
                    self.instanceId,
                    self.nickname,
                    self.workdir_creation,
                    _,
                ) = self.wfexs.parseOrCreateRawWorkDir(
                    self.rawWorkDir, nickname=nickname, create_ok=False
                )
            else:
                self.nickname = nickname if nickname is not None else instanceId

        # TODO: enforce restrictive permissions on each raw working directory
        self.allowOther = False

        if checkSecure:
            passphraseFile = os.path.join(self.rawWorkDir, WORKDIR_PASSPHRASE_FILE)
            self.secure = os.path.exists(passphraseFile)
        else:
            self.secure = workflow_config.get("secure", True)

        doSecureWorkDir = self.secure or self.paranoidMode

        was_setup = self.setupWorkdir(doSecureWorkDir, fail_ok=fail_ok)

        self.configMarshalled: "Optional[Union[bool, datetime.datetime]]" = None
        self.inputsDir: "Optional[AbsPath]"
        self.intermediateDir: "Optional[AbsPath]"
        self.outputsDir: "Optional[AbsPath]"
        self.engineTweaksDir: "Optional[AbsPath]"
        self.metaDir: "Optional[AbsPath]"
        self.workflowDir: "Optional[AbsPath]"
        self.containersDir: "Optional[AbsPath]"
        if was_setup:
            assert (
                self.workDir is not None
            ), "Workdir has to be already defined at this point"
            # This directory will hold either symbolic links to the cached
            # inputs, or the inputs properly post-processed (decompressed,
            # decrypted, etc....)
            self.inputsDir = cast(
                "AbsPath", os.path.join(self.workDir, WORKDIR_INPUTS_RELDIR)
            )
            os.makedirs(self.inputsDir, exist_ok=True)
            # This directory should hold intermediate workflow steps results
            self.intermediateDir = cast(
                "AbsPath", os.path.join(self.workDir, WORKDIR_INTERMEDIATE_RELDIR)
            )
            os.makedirs(self.intermediateDir, exist_ok=True)
            # This directory will hold the final workflow results, which could
            # be either symbolic links to the intermediate results directory
            # or newly generated content
            self.outputsDir = cast(
                "AbsPath", os.path.join(self.workDir, WORKDIR_OUTPUTS_RELDIR)
            )
            os.makedirs(self.outputsDir, exist_ok=True)
            # This directory is here for those files which are created in order
            # to tweak or patch workflow executions
            self.engineTweaksDir = cast(
                "AbsPath", os.path.join(self.workDir, WORKDIR_ENGINE_TWEAKS_RELDIR)
            )
            os.makedirs(self.engineTweaksDir, exist_ok=True)
            # This directory will hold metadata related to the execution
            self.metaDir = cast(
                "AbsPath", os.path.join(self.workDir, WORKDIR_META_RELDIR)
            )
            # This directory will hold a copy of the workflow
            self.workflowDir = cast(
                "AbsPath", os.path.join(self.workDir, WORKDIR_WORKFLOW_RELDIR)
            )
            # This directory will hold either a hardlink or a copy of the containers
            self.containersDir = cast(
                "AbsPath", os.path.join(self.workDir, WORKDIR_CONTAINERS_RELDIR)
            )

            # This is true when the working directory already exists
            if checkSecure:
                if not os.path.isdir(self.metaDir):
                    self.configMarshalled = False
                    errstr = "Staged working directory {} is incomplete".format(
                        self.workDir
                    )
                    self.logger.exception(errstr)
                    if not fail_ok:
                        raise WFException(errstr)
                    self.workflow_config = None
                    is_damaged = True
                else:
                    # In order to be able to build next paths to call
                    unmarshalled = self.unmarshallConfig(fail_ok=fail_ok)
                    # One of the worst scenarios
                    is_damaged = not unmarshalled
                    if is_damaged:
                        self.workflow_config = None
                        # self.marshallConfig(overwrite=False)
            else:
                os.makedirs(self.metaDir, exist_ok=True)
                self.marshallConfig(overwrite=True)
                is_damaged = False
        else:
            self.configMarshalled = False
            is_damaged = True
            self.inputsDir = None
            self.intermediateDir = None
            self.outputsDir = None
            self.engineTweaksDir = None
            self.metaDir = None
            self.workflowDir = None
            self.containersDir = None

        self.stagedSetup = StagedSetup(
            instance_id=self.instanceId,
            nickname=self.nickname,
            creation=self.workdir_creation,
            workflow_config=self.workflow_config,
            raw_work_dir=self.rawWorkDir,
            work_dir=self.workDir,
            workflow_dir=self.workflowDir,
            inputs_dir=self.inputsDir,
            outputs_dir=self.outputsDir,
            intermediate_dir=self.intermediateDir,
            engine_tweaks_dir=self.engineTweaksDir,
            meta_dir=self.metaDir,
            temp_dir=self.tempDir,
            secure_exec=self.secure or self.paranoidMode,
            allow_other=self.allowOther,
            is_encrypted=doSecureWorkDir,
            is_damaged=is_damaged,
        )

        self.repoURL: "Optional[RepoURL]" = None
        self.repoTag: "Optional[RepoTag]" = None
        self.repoRelPath: "Optional[RelPath]" = None
        self.repoDir: "Optional[AbsPath]" = None
        self.repoEffectiveCheckout: "Optional[RepoTag]" = None
        self.engine: "Optional[AbstractWorkflowEngineType]" = None
        self.engineVer: "Optional[EngineVersion]" = None
        self.engineDesc: "Optional[WorkflowType]" = None

        self.materializedParams: "Optional[Sequence[MaterializedInput]]" = None
        self.localWorkflow: "Optional[LocalWorkflow]" = None
        self.materializedEngine: "Optional[MaterializedWorkflowEngine]" = None
        self.containerEngineVersion: "Optional[ContainerEngineVersionStr]" = None
        self.workflowEngineVersion: "Optional[WorkflowEngineVersionStr]" = None

        self.containerEngineOs: "Optional[ContainerOperatingSystem]" = None
        self.arch: "Optional[ProcessorArchitecture]" = None

        self.stagedExecutions: "Optional[MutableSequence[StagedExecution]]" = None
        self.cacheROCrateFilename: "Optional[AbsPath]" = None

        self.runExportActions: "Optional[MutableSequence[MaterializedExportAction]]" = (
            None
        )

        self.stageMarshalled: "Optional[Union[bool, datetime.datetime]]" = None
        self.executionMarshalled: "Optional[Union[bool, datetime.datetime]]" = None
        self.exportMarshalled: "Optional[Union[bool, datetime.datetime]]" = None

    FUSE_SYSTEM_CONF = "/etc/fuse.conf"

    def getPID(self) -> "Optional[str]":
        """
        It provides the most permanent workflow id it can generate from
        the details in the YAML
        """
        the_pid: "Optional[str]"
        if self.id is not None:
            the_pid = str(self.id)
            parsedRepoURL = urllib.parse.urlparse(the_pid)

            # If it is not an URI / CURIE
            if parsedRepoURL.scheme == "":
                if (self.trs_endpoint is not None) and len(self.trs_endpoint) > 0:
                    parsedTRSURL = urllib.parse.urlparse(self.trs_endpoint)
                    trs_steps: "Sequence[str]" = parsedTRSURL.path.split("/")
                    pid_steps = ["", urllib.parse.quote(the_pid, safe="")]

                    if self.version_id is not None:
                        pid_steps.append(
                            urllib.parse.quote(str(self.version_id), safe="")
                        )

                    the_pid = urllib.parse.urlunparse(
                        urllib.parse.ParseResult(
                            scheme=TRS_SCHEME_PREFIX,
                            netloc=parsedTRSURL.netloc,
                            path="/".join(pid_steps),
                            params="",
                            query="",
                            fragment="",
                        )
                    )
                else:
                    self.logger.debug("trs_endpoint was not provided")
                    the_pid = None
        else:
            the_pid = None

        return the_pid

    def setupWorkdir(self, doSecureWorkDir: "bool", fail_ok: "bool" = False) -> "bool":
        uniqueRawWorkDir = self.rawWorkDir

        allowOther = False
        uniqueEncWorkDir: "Optional[AbsPath]"
        uniqueWorkDir: "AbsPath"
        if doSecureWorkDir:
            # We need to detect whether fuse has enabled user_allow_other
            # the only way I know is parsing /etc/fuse.conf
            if not self.paranoidMode and os.path.exists(self.FUSE_SYSTEM_CONF):
                with open(self.FUSE_SYSTEM_CONF, mode="r") as fsc:
                    for line in fsc:
                        if line.startswith("user_allow_other"):
                            allowOther = True
                            break
                    self.logger.debug(f"FUSE has user_allow_other: {allowOther}")

            uniqueEncWorkDir = cast("AbsPath", os.path.join(uniqueRawWorkDir, ".crypt"))
            uniqueWorkDir = cast("AbsPath", os.path.join(uniqueRawWorkDir, "work"))

            # The directories should exist before calling encryption FS mount
            os.makedirs(uniqueEncWorkDir, exist_ok=True)
            os.makedirs(uniqueWorkDir, exist_ok=True)

            # This is the passphrase needed to decrypt the filesystem
            passphraseFile = cast(
                "AbsPath", os.path.join(uniqueRawWorkDir, WORKDIR_PASSPHRASE_FILE)
            )

            if os.path.exists(passphraseFile):
                (
                    encfs_type,
                    encfs_cmd,
                    securePassphrase,
                ) = self.wfexs.readSecuredPassphrase(passphraseFile)
            else:
                (
                    encfs_type,
                    encfs_cmd,
                    securePassphrase,
                ) = self.wfexs.generateSecuredPassphrase(passphraseFile)

            self.encfs_type = encfs_type

            (
                self.fusermount_cmd,
                self.encfs_idleMinutes,
            ) = self.wfexs.getFusermountParams()
            # Warn/fail earlier
            if os.path.ismount(uniqueWorkDir):
                # raise WFException("Destination mount point {} is already in use")
                self.logger.warning(
                    "Destination mount point {} is already in use".format(uniqueWorkDir)
                )
                was_setup = True
            else:
                # DANGER!
                # We are removing leftovers in work directory
                with os.scandir(uniqueWorkDir) as uwi:
                    for entry in uwi:
                        # Tainted, not empty directory. Moving...
                        if entry.name not in (".", ".."):
                            self.logger.warning(
                                f"Destination mount point {uniqueWorkDir} is tainted. Moving..."
                            )
                            shutil.move(
                                uniqueWorkDir,
                                uniqueWorkDir + "_tainted_" + str(time.time()),
                            )
                            os.makedirs(uniqueWorkDir, exist_ok=True)
                            break

                # We are going to unmount what we have mounted
                self.doUnmount = True

                # Now, time to mount the encrypted FS
                try:
                    ENCRYPTED_FS_MOUNT_IMPLEMENTATIONS[encfs_type](
                        encfs_cmd,
                        self.encfs_idleMinutes,
                        uniqueEncWorkDir,
                        uniqueWorkDir,
                        uniqueRawWorkDir,
                        securePassphrase,
                        allowOther,
                    )
                except Exception as e:
                    errmsg = f"Cannot FUSE mount {uniqueWorkDir} with {encfs_cmd}"
                    self.logger.exception(errmsg)
                    if not fail_ok:
                        raise WFException(errmsg) from e
                    was_setup = False
                else:
                    was_setup = True
                    # and start the thread which keeps the mount working
                    self.encfsCond = threading.Condition()
                    self.encfsThread = threading.Thread(
                        target=_wakeupEncDir,
                        args=(self.encfsCond, uniqueWorkDir, self.logger),
                        daemon=True,
                    )
                    self.encfsThread.start()

            # self.encfsPassphrase = securePassphrase
            del securePassphrase
        else:
            uniqueEncWorkDir = None
            uniqueWorkDir = uniqueRawWorkDir
            was_setup = True

        # The temporary directory is in the raw working directory as
        # some container engine could fail
        uniqueTempDir = cast("AbsPath", os.path.join(uniqueRawWorkDir, ".TEMP"))
        os.makedirs(uniqueTempDir, exist_ok=True)
        os.chmod(uniqueTempDir, 0o1777)

        # Setting up working directories, one per instance
        self.encWorkDir = uniqueEncWorkDir
        self.workDir = uniqueWorkDir
        self.tempDir = uniqueTempDir
        self.allowOther = allowOther

        return was_setup

    def unmountWorkdir(self) -> None:
        if self.doUnmount and (self.encWorkDir is not None):
            if self.encfsCond is not None:
                self.encfsCond.acquire()
                self.encfsCond.notify()
                self.encfsThread = None
                self.encfsCond = None
            # Only unmount if it is needed
            assert self.workDir is not None
            if os.path.ismount(self.workDir):
                with tempfile.NamedTemporaryFile() as encfs_umount_stdout, tempfile.NamedTemporaryFile() as encfs_umount_stderr:
                    fusermountCommand: "Sequence[str]" = [
                        self.fusermount_cmd,
                        "-u",  # Umount the directory
                        "-z",  # Even if it is not possible to umount it now, hide the mount point
                        self.workDir,
                    ]

                    retval = subprocess.Popen(
                        fusermountCommand,
                        stdout=encfs_umount_stdout,
                        stderr=encfs_umount_stderr,
                    ).wait()

                    if retval != 0:
                        with open(encfs_umount_stdout.name, mode="r") as c_stF:
                            encfs_umount_stdout_v = c_stF.read()
                        with open(encfs_umount_stderr.name, mode="r") as c_stF:
                            encfs_umount_stderr_v = c_stF.read()

                        errstr = "Could not umount {} (retval {})\nCommand: {}\n======\nSTDOUT\n======\n{}\n======\nSTDERR\n======\n{}".format(
                            self.encfs_type,
                            retval,
                            " ".join(fusermountCommand),
                            encfs_umount_stdout_v,
                            encfs_umount_stderr_v,
                        )
                        raise WFException(errstr)

            # This is needed to avoid double work
            self.doUnmount = False
            self.encWorkDir = None
            self.workDir = None

    def cleanup(self) -> None:
        self.unmountWorkdir()

    def getStagedSetup(self) -> "StagedSetup":
        return self.stagedSetup

    def getMarshallingStatus(self, reread_stats: "bool" = False) -> "MarshallingStatus":
        if reread_stats:
            self.unmarshallExecute(offline=True, fail_ok=True)
            self.unmarshallExport(offline=True, fail_ok=True)

        return MarshallingStatus(
            config=self.configMarshalled,
            stage=self.stageMarshalled,
            execution=self.executionMarshalled,
            export=self.exportMarshalled,
        )

    def enableParanoidMode(self) -> None:
        self.paranoidMode = True

    @classmethod
    def FromWorkDir(
        cls,
        wfexs: "WfExSBackend",
        workflowWorkingDirectory: "Union[RelPath, AbsPath]",
        fail_ok: "bool" = False,
    ) -> "WF":
        """
        This class method requires an existing staged working directory
        """

        if wfexs is None:
            raise WFException("Unable to initialize, no WfExSBackend instance provided")

        instanceId, nickname, creation, rawWorkDir = wfexs.normalizeRawWorkingDirectory(
            workflowWorkingDirectory
        )

        return cls(
            wfexs,
            instanceId=instanceId,
            nickname=nickname,
            rawWorkDir=rawWorkDir,
            creation=creation,
            fail_ok=fail_ok,
        )

    @classmethod
    def ReadSecurityContextFile(
        cls, securityContextsConfigFilename: "AnyPath"
    ) -> "SecurityContextConfigBlock":
        with open(securityContextsConfigFilename, mode="r", encoding="utf-8") as scf:
            creds_config = unmarshall_namedtuple(yaml.safe_load(scf))

        return cast("SecurityContextConfigBlock", creds_config)

    @classmethod
    def FromFiles(
        cls,
        wfexs: "WfExSBackend",
        workflowMetaFilename: "AnyPath",
        securityContextsConfigFilename: "Optional[AnyPath]" = None,
        nickname_prefix: "Optional[str]" = None,
        paranoidMode: "bool" = False,
    ) -> "WF":
        """
        This class method creates a new staged working directory
        """

        with open(workflowMetaFilename, mode="r", encoding="utf-8") as wcf:
            workflow_meta = unmarshall_namedtuple(yaml.safe_load(wcf))

        # Should we prepend the nickname prefix?
        if nickname_prefix is not None:
            workflow_meta["nickname"] = nickname_prefix + workflow_meta.get(
                "nickname", ""
            )

        # Last, try loading the security contexts credentials file
        if securityContextsConfigFilename and os.path.exists(
            securityContextsConfigFilename
        ):
            creds_config = cls.ReadSecurityContextFile(securityContextsConfigFilename)
        else:
            creds_config = {}

        return cls.FromDescription(
            wfexs, workflow_meta, creds_config, paranoidMode=paranoidMode
        )

    @classmethod
    def FromDescription(
        cls,
        wfexs: "WfExSBackend",
        workflow_meta: "WorkflowMetaConfigBlock",
        creds_config: "Optional[SecurityContextConfigBlock]" = None,
        paranoidMode: "bool" = False,
    ) -> "WF":
        """
        This class method might create a new staged working directory

        :param wfexs: WfExSBackend instance
        :param workflow_meta: The configuration describing both the workflow
        and the inputs to use when it is being instantiated.
        :param creds_config: Dictionary with the different credential contexts (to be implemented)
        :param paranoidMode:
        :type wfexs: WfExSBackend
        :type workflow_meta: dict
        :type creds_config: SecurityContextConfigBlock
        :type paranoidMode: bool
        :return: Workflow configuration
        """

        # The preserved paranoid mode must be honoured
        preserved_paranoid_mode = workflow_meta.get("paranoid_mode")
        if preserved_paranoid_mode is not None:
            paranoidMode = preserved_paranoid_mode

        return cls(
            wfexs,
            workflow_meta["workflow_id"],
            workflow_meta.get("version"),
            descriptor_type=workflow_meta.get("workflow_type"),
            trs_endpoint=workflow_meta.get("trs_endpoint", cls.DEFAULT_TRS_ENDPOINT),
            params=workflow_meta.get("params", {}),
            outputs=workflow_meta.get("outputs", {}),
            placeholders=workflow_meta.get("placeholders", {}),
            default_actions=workflow_meta.get("default_actions"),
            workflow_config=workflow_meta.get("workflow_config"),
            nickname=workflow_meta.get("nickname"),
            creds_config=creds_config,
            paranoid_mode=paranoidMode,
        )

    @classmethod
    def FromForm(
        cls,
        wfexs: "WfExSBackend",
        workflow_meta: "WorkflowMetaConfigBlock",
        paranoidMode: "bool" = False,
    ) -> "WF":  # VRE
        """

        :param wfexs: WfExSBackend instance
        :param workflow_meta: The configuration describing both the workflow
        and the inputs to use when it is being instantiated.
        :param paranoidMode:
        :type workflow_meta: dict
        :type paranoidMode: bool
        :return: Workflow configuration
        """

        return cls(
            wfexs,
            workflow_meta["workflow_id"],
            workflow_meta.get("version"),
            descriptor_type=workflow_meta.get("workflow_type"),
            trs_endpoint=workflow_meta.get("trs_endpoint", cls.DEFAULT_TRS_ENDPOINT),
            params=workflow_meta.get("params", {}),
            placeholders=workflow_meta.get("placeholders", {}),
            default_actions=workflow_meta.get("default_actions"),
            workflow_config=workflow_meta.get("workflow_config"),
            nickname=workflow_meta.get("nickname"),
            paranoid_mode=paranoidMode,
        )

    def fetchWorkflow(
        self,
        workflow_id: "WorkflowId",
        version_id: "Optional[WFVersionId]",
        trs_endpoint: "Optional[str]",
        descriptor_type: "Optional[TRS_Workflow_Descriptor]",
        offline: "bool" = False,
        ignoreCache: "bool" = False,
    ) -> None:
        """
        Fetch the whole workflow description based on the data obtained
        from the TRS where it is being published.

        If the workflow id is an URL, it is supposed to be a git repository,
        and the version will represent either the branch, tag or specific commit.
        So, the whole TRS fetching machinery is bypassed.workflowDir
        """

        assert self.metaDir is not None

        repoDir, repo, engineDesc, repoEffectiveCheckout = self.wfexs.cacheWorkflow(
            workflow_id=workflow_id,
            version_id=version_id,
            trs_endpoint=trs_endpoint,
            descriptor_type=descriptor_type,
            ignoreCache=ignoreCache,
            offline=offline,
            meta_dir=self.metaDir,
        )
        self.repoURL = repo.repo_url
        self.repoTag = repo.tag
        self.repoRelPath = repo.rel_path

        # Workflow Language version cannot be assumed here yet
        # A copy of the workflows is kept
        assert self.workflowDir is not None, "The workflow directory should be defined"
        if os.path.isdir(self.workflowDir):
            shutil.rmtree(self.workflowDir)
        # force_copy is needed to isolate the copy of the workflow
        # so local modifications in a working directory does not
        # poison the cached workflow
        link_or_copy(repoDir, self.workflowDir, force_copy=True)
        # We cannot know yet the dependencies
        localWorkflow = LocalWorkflow(
            dir=self.workflowDir,
            relPath=self.repoRelPath,
            effectiveCheckout=repoEffectiveCheckout,
        )
        self.logger.info(
            "materialized workflow repository (checkout {}): {}".format(
                repoEffectiveCheckout, self.workflowDir
            )
        )

        if self.repoRelPath is not None:
            if not os.path.exists(os.path.join(self.workflowDir, self.repoRelPath)):
                raise WFException(
                    "Relative path {} cannot be found in materialized workflow repository {}".format(
                        self.repoRelPath, self.workflowDir
                    )
                )
        # A valid engine must be identified from the fetched content
        # TODO: decide whether to force some specific version
        if engineDesc is None:
            for engineDesc in self.WORKFLOW_ENGINES:
                self.logger.debug("Testing engine " + engineDesc.trs_descriptor)
                engine = self.wfexs.instantiateEngine(engineDesc, self.stagedSetup)

                try:
                    engineVer, candidateLocalWorkflow = engine.identifyWorkflow(
                        localWorkflow
                    )
                    self.logger.debug(
                        "Tested engine {} {}".format(
                            engineDesc.trs_descriptor, engineVer
                        )
                    )
                    if engineVer is not None:
                        break
                except WorkflowEngineException:
                    # TODO: store the exceptions, to be shown if no workflow is recognized
                    pass
            else:
                raise WFException(
                    "No engine recognized a workflow at {}".format(self.repoURL)
                )
        else:
            self.logger.debug("Fixed engine " + engineDesc.trs_descriptor)
            engine = self.wfexs.instantiateEngine(engineDesc, self.stagedSetup)
            engineVer, candidateLocalWorkflow = engine.identifyWorkflow(localWorkflow)
            if engineVer is None:
                raise WFException(
                    "Engine {} did not recognize a workflow at {}".format(
                        engine.workflowType.engineName, self.repoURL
                    )
                )

        self.repoDir = repoDir
        self.repoEffectiveCheckout = repoEffectiveCheckout
        self.engineDesc = engineDesc
        self.engine = engine
        self.engineVer = engineVer
        self.localWorkflow = candidateLocalWorkflow

    def setupEngine(self, offline: "bool" = False, ignoreCache: "bool" = False) -> None:
        # The engine is populated by self.fetchWorkflow()
        if self.engine is None:
            assert self.id is not None
            self.fetchWorkflow(
                self.id,
                self.version_id,
                self.trs_endpoint,
                self.descriptor_type,
                offline=offline,
                ignoreCache=ignoreCache,
            )

        assert (
            self.engine is not None
        ), "Workflow engine not properly identified or set up"

        if self.materializedEngine is None:
            assert self.localWorkflow is not None
            localWorkflow = self.localWorkflow
        else:
            localWorkflow = self.materializedEngine.workflow

        matWfEngV2 = self.engine.materializeEngine(localWorkflow, self.engineVer)

        # At this point, there can be uninitialized elements
        if matWfEngV2 is not None:
            engine_version_str = WorkflowEngine.GetEngineVersion(matWfEngV2)
            self.workflowEngineVersion = engine_version_str
            if self.materializedEngine is not None:
                matWfEngV2 = MaterializedWorkflowEngine(
                    instance=matWfEngV2.instance,
                    version=matWfEngV2.version,
                    fingerprint=matWfEngV2.fingerprint,
                    engine_path=matWfEngV2.engine_path,
                    workflow=matWfEngV2.workflow,
                    containers_path=self.materializedEngine.containers_path,
                    containers=self.materializedEngine.containers,
                    operational_containers=self.materializedEngine.operational_containers,
                )
        self.materializedEngine = matWfEngV2

    def materializeWorkflowAndContainers(
        self, offline: "bool" = False, ignoreCache: "bool" = False
    ) -> None:
        if self.materializedEngine is None:
            self.setupEngine(offline=offline, ignoreCache=ignoreCache)

        assert (
            self.materializedEngine is not None
        ), "The materialized workflow engine should be available at this point"

        # This information is badly needed for provenance
        if self.materializedEngine.containers is None:
            assert (
                self.containersDir is not None
            ), "The destination directory should be available here"
            if not offline:
                os.makedirs(self.containersDir, exist_ok=True)
            (
                self.materializedEngine,
                self.containerEngineVersion,
                self.containerEngineOs,
                self.arch,
            ) = WorkflowEngine.MaterializeWorkflowAndContainers(
                self.materializedEngine, self.containersDir, offline=offline
            )

    def injectInputs(
        self,
        paths: "Sequence[AnyPath]",
        workflowInputs_destdir: "Optional[AbsPath]" = None,
        workflowInputs_cacheDir: "Optional[Union[AbsPath, CacheType]]" = None,
        lastInput: "int" = 0,
    ) -> int:
        if workflowInputs_destdir is None:
            workflowInputs_destdir = self.inputsDir
        if workflowInputs_cacheDir is None:
            workflowInputs_cacheDir = CacheType.Input

        cacheable = not self.paranoidMode
        # The storage dir depends on whether it can be cached or not
        storeDir = workflowInputs_cacheDir if cacheable else workflowInputs_destdir
        if storeDir is None:
            raise WFException(
                "Cannot inject inputs as the store directory is undefined"
            )

        assert workflowInputs_destdir is not None

        for path in paths:
            # We are sending the context name thinking in the future,
            # as it could contain potential hints for authenticated access
            fileuri = urllib.parse.urlunparse(
                ("file", "", os.path.abspath(path), "", "", "")
            )
            matContent = self.wfexs.downloadContent(
                cast("URIType", fileuri),
                dest=storeDir,
                ignoreCache=not cacheable,
                registerInCache=cacheable,
            )

            # Now, time to create the symbolic link
            lastInput += 1

            prettyLocal = os.path.join(
                workflowInputs_destdir, matContent.prettyFilename
            )

            # As Nextflow has some issues when two inputs of a process
            # have the same basename, harden by default
            hardenPrettyLocal = True
            # hardenPrettyLocal = False
            # if os.path.islink(prettyLocal):
            #     oldLocal = os.readlink(prettyLocal)
            #
            #     hardenPrettyLocal = oldLocal != matContent.local
            # elif os.path.exists(prettyLocal):
            #     hardenPrettyLocal = True

            if hardenPrettyLocal:
                # Trying to avoid collisions on input naming
                prettyLocal = os.path.join(
                    workflowInputs_destdir,
                    str(lastInput) + "_" + matContent.prettyFilename,
                )

            if not os.path.exists(prettyLocal):
                os.symlink(matContent.local, prettyLocal)

        return lastInput

    def materializeInputs(
        self, offline: "bool" = False, ignoreCache: "bool" = False, lastInput: "int" = 0
    ) -> None:
        assert (
            self.inputsDir is not None
        ), "The working directory should not be corrupted beyond basic usage"
        assert self.formatted_params is not None

        theParams, numInputs = self.fetchInputs(
            self.formatted_params,
            workflowInputs_destdir=self.inputsDir,
            offline=offline,
            ignoreCache=ignoreCache,
            lastInput=lastInput,
        )
        self.materializedParams = theParams

    def getContext(
        self, remote_file: "str", contextName: "Optional[str]"
    ) -> "Optional[SecurityContextConfig]":
        secContext = None
        if contextName is not None:
            secContext = self.creds_config.get(contextName)
            if secContext is None:
                raise WFException(
                    "No security context {} is available, needed by {}".format(
                        contextName, remote_file
                    )
                )

        return secContext

    def buildLicensedURI(
        self,
        remote_file_f: "Sch_InputURI_Fetchable",
        contextName: "Optional[str]" = None,
        licences: "Tuple[URIType, ...]" = DefaultNoLicenceTuple,
        attributions: "Sequence[Attribution]" = [],
    ) -> "Union[LicensedURI, Sequence[LicensedURI]]":
        if isinstance(remote_file_f, list):
            retvals = []
            for remote_url in remote_file_f:
                retval = self.buildLicensedURI(
                    remote_url,
                    contextName=contextName,
                    licences=licences,
                    attributions=attributions,
                )
                if isinstance(retval, list):
                    retvals.extend(retval)
                else:
                    retvals.append(retval)

            return retvals

        if isinstance(remote_file_f, dict):
            remote_file = remote_file_f
            # The value of the attributes is superseded
            remote_url = remote_file["uri"]
            licences_l = remote_file.get("licences")
            if isinstance(licences_l, list):
                licences = tuple(licences_l)
            contextName = remote_file.get("security-context", contextName)

            # Reconstruction of the attributions
            rawAttributions = remote_file.get("attributions")
            parsed_attributions = Attribution.ParseRawAttributions(
                remote_file.get("attributions")
            )
            # Only overwrite in this case
            if len(parsed_attributions) > 0:
                attributions = parsed_attributions
        else:
            remote_url = remote_file_f

        secContext = None
        if contextName is not None:
            secContext = self.creds_config.get(contextName)
            if secContext is None:
                raise WFException(
                    "No security context {} is available, needed by {}".format(
                        contextName, remote_file_f
                    )
                )

        return LicensedURI(
            uri=remote_url,
            licences=licences,
            attributions=attributions,
            secContext=secContext,
        )

    def _fetchRemoteFile(
        self,
        remote_file: "Sch_InputURI_Fetchable",
        contextName: "Optional[str]",
        offline: "bool",
        storeDir: "Union[AbsPath, CacheType]",
        cacheable: "bool",
        inputDestDir: "AbsPath",
        globExplode: "Optional[str]",
        prefix: "str" = "",
        hardenPrettyLocal: "bool" = False,
        prettyRelname: "Optional[RelPath]" = None,
        ignoreCache: "bool" = False,
    ) -> "Sequence[MaterializedContent]":
        # Embedding the context
        alt_remote_file = self.buildLicensedURI(remote_file, contextName=contextName)
        matContent = self.wfexs.downloadContent(
            alt_remote_file,
            dest=storeDir,
            offline=offline,
            ignoreCache=ignoreCache or not cacheable,
            registerInCache=cacheable,
        )

        # Now, time to create the link
        if prettyRelname is None:
            prettyRelname = matContent.prettyFilename

        prettyLocal = cast("AbsPath", os.path.join(inputDestDir, prettyRelname))

        # Protection against misbehaviours which could hijack the
        # execution environment
        realPrettyLocal = os.path.realpath(prettyLocal)
        realInputDestDir = os.path.realpath(inputDestDir)
        if not realPrettyLocal.startswith(realInputDestDir):
            prettyRelname = cast("RelPath", os.path.basename(realPrettyLocal))
            prettyLocal = cast("AbsPath", os.path.join(inputDestDir, prettyRelname))

        # Checking whether local name hardening is needed
        if not hardenPrettyLocal:
            if os.path.islink(prettyLocal):
                oldLocal = os.readlink(prettyLocal)

                hardenPrettyLocal = oldLocal != matContent.local
            elif os.path.exists(prettyLocal):
                hardenPrettyLocal = True

        if hardenPrettyLocal:
            # Trying to avoid collisions on input naming
            prettyLocal = cast(
                "AbsPath", os.path.join(inputDestDir, prefix + prettyRelname)
            )

        if not os.path.exists(prettyLocal):
            # We are either hardlinking or copying here
            link_or_copy(matContent.local, prettyLocal)

        remote_pairs = []
        if globExplode is not None:
            prettyLocalPath = pathlib.Path(prettyLocal)
            matParse = urllib.parse.urlparse(matContent.licensed_uri.uri)
            for exp in prettyLocalPath.glob(globExplode):
                relPath = exp.relative_to(prettyLocalPath)
                relName = cast("RelPath", str(relPath))
                relExpPath = matParse.path
                if relExpPath[-1] != "/":
                    relExpPath += "/"
                relExpPath += "/".join(
                    map(lambda part: urllib.parse.quote_plus(part), relPath.parts)
                )
                expUri = urllib.parse.urlunparse(
                    (
                        matParse.scheme,
                        matParse.netloc,
                        relExpPath,
                        matParse.params,
                        matParse.query,
                        matParse.fragment,
                    )
                )

                # TODO: enrich outputs to add licensing features?
                lic_expUri = LicensedURI(
                    uri=cast("URIType", expUri),
                    licences=matContent.licensed_uri.licences,
                )
                remote_pairs.append(
                    MaterializedContent(
                        local=cast("AbsPath", str(exp)),
                        licensed_uri=lic_expUri,
                        prettyFilename=relName,
                        metadata_array=matContent.metadata_array,
                        kind=ContentKind.Directory
                        if exp.is_dir()
                        else ContentKind.File,
                    )
                )
        else:
            remote_pair = MaterializedContent(
                local=prettyLocal,
                licensed_uri=matContent.licensed_uri,
                prettyFilename=prettyRelname,
                kind=matContent.kind,
                metadata_array=matContent.metadata_array,
            )
            remote_pairs.append(remote_pair)

        return remote_pairs

    def _formatStringFromPlaceHolders(self, the_string: "str") -> "str":
        assert self.params is not None

        i_l_the_string = the_string.find("{")
        i_r_the_string = the_string.find("}")
        if (
            i_l_the_string != -1
            and i_r_the_string != -1
            and i_l_the_string < i_r_the_string
        ):
            try:
                the_string = the_string.format(**self.placeholders)
            except:
                # Ignore failures
                self.logger.warning(
                    f"Failed to format (revise placeholders): {the_string}"
                )
        return the_string

    def _formatInputURIFromPlaceHolders(
        self, input_uri: "Sch_InputURI"
    ) -> "Sch_InputURI":
        some_formatted = False

        return_input_uri: "Sch_InputURI"
        if isinstance(input_uri, list):
            return_input_uri = []
            for i_uri in input_uri:
                return_i_uri = self._formatInputURIFromPlaceHolders(i_uri)
                return_input_uri.append(return_i_uri)  # type: ignore[arg-type]
                if return_i_uri != i_uri:
                    some_formatted = True
        elif isinstance(input_uri, dict):
            i_uri = input_uri["uri"]
            return_i_uri = cast("URIType", self._formatStringFromPlaceHolders(i_uri))
            some_formatted = return_i_uri != i_uri
            if some_formatted:
                return_input_uri = copy.copy(input_uri)
                return_input_uri["uri"] = return_i_uri
            else:
                return_input_uri = input_uri
        else:
            return_input_uri = cast(
                "URIType", self._formatStringFromPlaceHolders(cast("str", input_uri))
            )
            some_formatted = return_input_uri != input_uri

        return return_input_uri if some_formatted else input_uri

    def formatParams(
        self, params: "Optional[ParamsBlock]", prefix: "str" = ""
    ) -> "Optional[ParamsBlock]":
        if params is None:
            return params

        formatted_params: "MutableParamsBlock" = dict()
        some_formatted = False
        for key, raw_inputs in params.items():
            # We are here for the
            linearKey = prefix + key
            if isinstance(raw_inputs, dict):
                inputs = cast("Sch_Param", raw_inputs)
                inputClass = inputs.get("c-l-a-s-s")
                if inputClass is not None:
                    if inputClass in ("File", "Directory"):  # input files
                        if inputClass == "Directory":
                            # We have to autofill this with the outputs directory,
                            # so results are properly stored (without escaping the jail)
                            if inputs.get("autoFill", False):
                                formatted_params[key] = inputs
                                continue

                            globExplode = inputs.get("globExplode")
                        elif inputClass == "File" and inputs.get("autoFill", False):
                            formatted_params[key] = inputs
                            continue

                        was_formatted = False

                        remote_files: "Optional[Sch_InputURI]" = inputs.get("url")
                        if remote_files is not None:
                            formatted_remote_files = (
                                self._formatInputURIFromPlaceHolders(remote_files)
                            )
                            if remote_files != formatted_remote_files:
                                was_formatted = True
                        else:
                            formatted_remote_files = None

                        secondary_remote_files: "Optional[Sch_InputURI]" = inputs.get(
                            "secondary-urls"
                        )
                        if secondary_remote_files is not None:
                            formatted_secondary_remote_files = (
                                self._formatInputURIFromPlaceHolders(
                                    secondary_remote_files
                                )
                            )
                            if (
                                secondary_remote_files
                                != formatted_secondary_remote_files
                            ):
                                was_formatted = True
                        else:
                            formatted_secondary_remote_files = None

                        preferred_name_conf = inputs.get("preferred-name")
                        formatted_preferred_name_conf: "Optional[Union[str, Literal[False]]]"
                        if isinstance(preferred_name_conf, str):
                            formatted_preferred_name_conf = (
                                self._formatStringFromPlaceHolders(preferred_name_conf)
                            )
                            if preferred_name_conf != formatted_preferred_name_conf:
                                was_formatted = True
                        else:
                            formatted_preferred_name_conf = preferred_name_conf

                        reldir_conf = inputs.get("relative-dir")
                        formatted_reldir_conf: "Optional[Union[str, Literal[False]]]"
                        if isinstance(reldir_conf, str):
                            formatted_reldir_conf = self._formatStringFromPlaceHolders(
                                reldir_conf
                            )
                            if reldir_conf != formatted_reldir_conf:
                                was_formatted = True
                        else:
                            formatted_reldir_conf = reldir_conf

                        # Something has to be changed
                        if was_formatted:
                            some_formatted = True
                            formatted_inputs = copy.copy(inputs)
                            if "url" in inputs:
                                assert formatted_remote_files is not None
                                formatted_inputs["url"] = formatted_remote_files
                            if "secondary-urls" in inputs:
                                assert formatted_secondary_remote_files is not None
                                formatted_inputs[
                                    "secondary-urls"
                                ] = formatted_secondary_remote_files
                            if "preferred-name" in inputs:
                                assert formatted_preferred_name_conf is not None
                                formatted_inputs[
                                    "preferred-name"
                                ] = formatted_preferred_name_conf
                            if "relative-dir" in inputs:
                                assert formatted_reldir_conf is not None
                                formatted_inputs["relative-dir"] = formatted_reldir_conf
                        else:
                            formatted_inputs = inputs

                        formatted_params[key] = formatted_inputs

                    else:
                        raise WFException(
                            'Unrecognized input class "{}", attached to "{}"'.format(
                                inputClass, linearKey
                            )
                        )
                else:
                    # possible nested files
                    formatted_inputs_nested = self.formatParams(
                        cast("ParamsBlock", inputs), prefix=linearKey + "."
                    )
                    if inputs != formatted_inputs_nested:
                        some_formatted = True
                    formatted_params[key] = formatted_inputs_nested
            elif isinstance(raw_inputs, list):
                if len(raw_inputs) > 0 and isinstance(raw_inputs[0], str):
                    formatted_inputs_l = []
                    did_change = False
                    for raw_input in raw_inputs:
                        formatted_input = self._formatStringFromPlaceHolders(raw_input)
                        formatted_inputs_l.append(formatted_input)
                        if formatted_input != raw_input:
                            did_change = True
                            some_formatted = True

                    formatted_params[key] = (
                        formatted_inputs_l if did_change else raw_inputs
                    )
                else:
                    formatted_params[key] = raw_inputs
            elif isinstance(raw_inputs, str):
                formatted_input = self._formatStringFromPlaceHolders(raw_inputs)
                formatted_params[key] = formatted_input
                if raw_inputs != formatted_input:
                    some_formatted = True
            else:
                formatted_params[key] = raw_inputs

        return formatted_params if some_formatted else params

    def fetchInputs(
        self,
        params: "Union[ParamsBlock, Sequence[Mapping[str, Any]]]",
        workflowInputs_destdir: "AbsPath",
        prefix: "str" = "",
        lastInput: "int" = 0,
        offline: "bool" = False,
        ignoreCache: "bool" = False,
    ) -> "Tuple[Sequence[MaterializedInput], int]":
        """
        Fetch the input files for the workflow execution.
        All the inputs must be URLs or CURIEs from identifiers.org / n2t.net.

        :param params: Optional params for the workflow execution.
        :param workflowInputs_destdir:
        :param prefix:
        :param lastInput:
        :param offline:
        :type params: dict
        :type prefix: str
        """
        assert (
            self.outputsDir is not None
        ), "Working directory should not be corrupted beyond basic usage"

        theInputs = []

        paramsIter = params.items() if isinstance(params, dict) else enumerate(params)
        for key, inputs in paramsIter:
            # We are here for the
            linearKey = prefix + key
            if isinstance(inputs, dict):
                inputClass = inputs.get("c-l-a-s-s")
                if inputClass is not None:
                    if inputClass in ("File", "Directory"):  # input files
                        inputDestDir = workflowInputs_destdir
                        globExplode = None

                        path_tokens = linearKey.split(".")
                        # Filling in the defaults
                        assert len(path_tokens) >= 1
                        if len(path_tokens) >= 1:
                            pretty_relname = path_tokens[-1]
                            if len(path_tokens) > 1:
                                relative_dir = os.path.join(*path_tokens[0:-1])
                            else:
                                relative_dir = None
                        else:
                            pretty_relname = None
                            relative_dir = None

                        if inputClass == "Directory":
                            # We have to autofill this with the outputs directory,
                            # so results are properly stored (without escaping the jail)
                            if inputs.get("autoFill", False):
                                if inputs.get("autoPrefix", True):
                                    autoFilledDir = os.path.join(
                                        self.outputsDir, *path_tokens
                                    )
                                else:
                                    autoFilledDir = self.outputsDir

                                theInputs.append(
                                    MaterializedInput(
                                        linearKey, [autoFilledDir], autoFilled=True
                                    )
                                )
                                continue

                            globExplode = inputs.get("globExplode")
                        elif inputClass == "File" and inputs.get("autoFill", False):
                            # We have to autofill this with the outputs directory,
                            # so results are properly stored (without escaping the jail)
                            autoFilledFile = os.path.join(self.outputsDir, path_tokens)
                            autoFilledDir = os.path.dirname(autoFilledFile)
                            # This is needed to assure the path exists
                            if autoFilledDir != self.outputsDir:
                                os.makedirs(autoFilledDir, exist_ok=True)

                            theInputs.append(
                                MaterializedInput(
                                    linearKey, [autoFilledFile], autoFilled=True
                                )
                            )
                            continue

                        remote_files: "Optional[Sch_InputURI]" = inputs.get("url")
                        # It has to exist
                        if remote_files is not None:
                            # We are sending the context name thinking in the future,
                            # as it could contain potential hints for authenticated access
                            contextName = inputs.get("security-context")

                            secondary_remote_files: "Optional[Sch_InputURI]" = (
                                inputs.get("secondary-urls")
                            )
                            preferred_name_conf = inputs.get("preferred-name")
                            if isinstance(preferred_name_conf, str):
                                pretty_relname = preferred_name_conf
                            elif not preferred_name_conf:
                                # Remove the pre-computed relative dir
                                pretty_relname = None

                            cacheable = (
                                not self.paranoidMode
                                if inputs.get("cache", True)
                                else False
                            )

                            # Setting up the relative dir preference
                            reldir_conf = inputs.get("relative-dir")
                            if isinstance(reldir_conf, str):
                                relative_dir = reldir_conf
                            elif not reldir_conf:
                                # Remove the pre-computed relative dir
                                relative_dir = None

                            if relative_dir is not None:
                                newInputDestDir = os.path.realpath(
                                    os.path.join(inputDestDir, relative_dir)
                                )
                                if newInputDestDir.startswith(
                                    os.path.realpath(inputDestDir)
                                ):
                                    inputDestDir = cast("AbsPath", newInputDestDir)

                            # The storage dir depends on whether it can be cached or not
                            storeDir: "Union[CacheType, AbsPath]" = (
                                CacheType.Input if cacheable else workflowInputs_destdir
                            )

                            remote_files_f: "Sequence[Sch_InputURI_Fetchable]"
                            if isinstance(
                                remote_files, list
                            ):  # more than one input file
                                remote_files_f = remote_files
                            else:
                                remote_files_f = [
                                    cast("Sch_InputURI_Fetchable", remote_files)
                                ]

                            remote_pairs: "MutableSequence[MaterializedContent]" = []
                            for remote_file in remote_files_f:
                                lastInput += 1
                                t_remote_pairs = self._fetchRemoteFile(
                                    remote_file,
                                    contextName,
                                    offline,
                                    storeDir,
                                    cacheable,
                                    inputDestDir,
                                    globExplode,
                                    prefix=str(lastInput) + "_",
                                    prettyRelname=pretty_relname,
                                    ignoreCache=ignoreCache,
                                )
                                remote_pairs.extend(t_remote_pairs)

                            secondary_remote_pairs: "Optional[MutableSequence[MaterializedContent]]"
                            if secondary_remote_files is not None:
                                secondary_remote_files_f: "Sequence[Sch_InputURI_Fetchable]"
                                if isinstance(
                                    secondary_remote_files, list
                                ):  # more than one input file
                                    secondary_remote_files_f = secondary_remote_files
                                else:
                                    secondary_remote_files_f = [
                                        cast(
                                            "Sch_InputURI_Fetchable",
                                            secondary_remote_files,
                                        )
                                    ]

                                secondary_remote_pairs = []
                                for secondary_remote_file in secondary_remote_files_f:
                                    # The last fetched content prefix is the one used
                                    # for all the secondaries
                                    t_secondary_remote_pairs = self._fetchRemoteFile(
                                        secondary_remote_file,
                                        contextName,
                                        offline,
                                        storeDir,
                                        cacheable,
                                        inputDestDir,
                                        globExplode,
                                        prefix=str(lastInput) + "_",
                                        ignoreCache=ignoreCache,
                                    )
                                    secondary_remote_pairs.extend(
                                        t_secondary_remote_pairs
                                    )
                            else:
                                secondary_remote_pairs = None

                            theInputs.append(
                                MaterializedInput(
                                    name=linearKey,
                                    values=remote_pairs,
                                    secondaryInputs=secondary_remote_pairs,
                                )
                            )
                        else:
                            if inputClass == "File":
                                # Empty input, i.e. empty file
                                inputDestPath = cast(
                                    "AbsPath",
                                    os.path.join(inputDestDir, *linearKey.split(".")),
                                )
                                os.makedirs(
                                    os.path.dirname(inputDestPath), exist_ok=True
                                )
                                # Creating the empty file
                                with open(inputDestPath, mode="wb") as idH:
                                    pass
                                contentKind = ContentKind.File
                            else:
                                inputDestPath = inputDestDir
                                contentKind = ContentKind.Directory

                            theInputs.append(
                                MaterializedInput(
                                    name=linearKey,
                                    values=[
                                        MaterializedContent(
                                            local=inputDestPath,
                                            licensed_uri=LicensedURI(
                                                uri=cast("URIType", "data:,")
                                            ),
                                            prettyFilename=cast(
                                                "RelPath",
                                                os.path.basename(inputDestPath),
                                            ),
                                            kind=contentKind,
                                        )
                                    ],
                                )
                            )
                    else:
                        raise WFException(
                            'Unrecognized input class "{}", attached to "{}"'.format(
                                inputClass, linearKey
                            )
                        )
                else:
                    # possible nested files
                    newInputsAndParams, lastInput = self.fetchInputs(
                        inputs,
                        workflowInputs_destdir=workflowInputs_destdir,
                        prefix=linearKey + ".",
                        lastInput=lastInput,
                        offline=offline,
                        ignoreCache=ignoreCache,
                    )
                    theInputs.extend(newInputsAndParams)
            else:
                if not isinstance(inputs, list):
                    inputs = [inputs]
                theInputs.append(MaterializedInput(linearKey, inputs))

        return theInputs, lastInput

    def stageWorkDir(
        self, offline: "bool" = False, ignoreCache: "bool" = False
    ) -> "StagedSetup":
        """
        This method is here to simplify the understanding of the needed steps
        """
        # This method is called from within setupEngine
        # self.fetchWorkflow(self.id, self.version_id, self.trs_endpoint, self.descriptor_type)
        # This method is called from within materializeWorkflowAndContainers
        # self.setupEngine(offline=offline)
        self.materializeWorkflowAndContainers(offline=offline, ignoreCache=ignoreCache)
        self.materializeInputs(offline=offline, ignoreCache=ignoreCache)
        self.marshallStage()

        return self.getStagedSetup()

    def workdirToBagit(self) -> "bagit.Bag":
        """
        BEWARE: This is a destructive step! So, once run, there is no back!
        """
        return bagit.make_bag(self.workDir)

    DefaultCardinality = "1"
    CardinalityMapping = {
        "1": (1, 1),
        "?": (0, 1),
        "*": (0, sys.maxsize),
        "+": (1, sys.maxsize),
    }

    OutputClassMapping = {
        ContentKind.File.name: ContentKind.File,
        ContentKind.Directory.name: ContentKind.Directory,
        ContentKind.Value.name: ContentKind.Value,
    }

    def parseExpectedOutputs(
        self, outputs: "Union[Sequence[Any], Mapping[str, Any]]"
    ) -> "Sequence[ExpectedOutput]":
        expectedOutputs = []

        # TODO: implement parsing of outputs
        outputsIter = (
            outputs.items() if isinstance(outputs, dict) else enumerate(outputs)
        )

        for outputKey, outputDesc in outputsIter:
            # The glob pattern
            patS = outputDesc.get("glob")
            if patS is not None:
                if len(patS) == 0:
                    patS = None

            # Fill from this input
            fillFrom = outputDesc.get("fillFrom")

            # Parsing the cardinality
            cardS = outputDesc.get("cardinality")
            cardinality = None
            if cardS is not None:
                if isinstance(cardS, int):
                    if cardS < 1:
                        cardinality = (0, 1)
                    else:
                        cardinality = (cardS, cardS)
                elif isinstance(cardS, list):
                    cardinality = (int(cardS[0]), int(cardS[1]))
                else:
                    cardinality = self.CardinalityMapping.get(cardS)

            if cardinality is None:
                cardinality = self.CardinalityMapping[self.DefaultCardinality]

            eOutput = ExpectedOutput(
                name=outputKey,
                kind=self.OutputClassMapping.get(
                    outputDesc.get("c-l-a-s-s"), ContentKind.File
                ),
                preferredFilename=outputDesc.get("preferredName"),
                cardinality=cardinality,
                fillFrom=fillFrom,
                glob=patS,
            )
            expectedOutputs.append(eOutput)

        return expectedOutputs

    def parseExportActions(
        self, raw_actions: "Sequence[Mapping[str, Any]]"
    ) -> "Sequence[ExportAction]":
        assert self.outputs is not None

        o_raw_actions = {"exports": raw_actions}
        valErrors = config_validate(o_raw_actions, self.EXPORT_ACTIONS_SCHEMA)
        if len(valErrors) > 0:
            errstr = f"ERROR in export actions definition block: {valErrors}"
            self.logger.error(errstr)
            raise WFException(errstr)

        actions: "MutableSequence[ExportAction]" = []
        for actionDesc in raw_actions:
            actionId = cast("SymbolicName", actionDesc["id"])
            pluginId = cast("SymbolicName", actionDesc["plugin"])

            whatToExport = []
            for encoded_name in actionDesc["what"]:
                colPos = encoded_name.find(":")
                rColPos = encoded_name.rfind(":")
                assert colPos >= 0

                # Directives like:
                # * "working-directory"
                # * "stage-rocrate"
                # * "provenance-rocrate"
                if colPos == 0:
                    assert rColPos > colPos

                    if encoded_name[-1] != ":":
                        raise WFException(
                            f"Unexpected element to export {encoded_name}"
                        )
                    rawItemType = encoded_name[1:rColPos]
                    blockName = encoded_name[rColPos + 1 :]
                    whatName = None
                else:
                    rawItemType = encoded_name[0:colPos]
                    blockName = encoded_name[colPos + 1 : rColPos]
                    whatName = encoded_name[rColPos + 1 :]
                    assert len(whatName) > 0

                whatToExport.append(
                    ExportItem(
                        type=ExportItemType(rawItemType), block=blockName, name=whatName
                    )
                )

            action = ExportAction(
                action_id=actionId,
                plugin_id=pluginId,
                what=whatToExport,
                context_name=actionDesc.get("security-context"),
                setup=actionDesc.get("setup"),
                preferred_scheme=actionDesc.get("preferred-scheme"),
                preferred_id=actionDesc.get("preferred-pid"),
            )
            actions.append(action)

        return actions

    def executeWorkflow(self, offline: "bool" = False) -> "ExitVal":
        self.unmarshallStage(offline=offline)
        self.unmarshallExecute(offline=offline, fail_ok=True)

        assert self.materializedEngine is not None
        assert self.materializedParams is not None
        assert self.outputs is not None

        if self.stagedExecutions is None:
            self.stagedExecutions = []

        stagedExec = WorkflowEngine.ExecuteWorkflow(
            self.materializedEngine, self.materializedParams, self.outputs
        )

        self.stagedExecutions.append(stagedExec)

        self.logger.debug(stagedExec.exitVal)
        self.logger.debug(stagedExec.started)
        self.logger.debug(stagedExec.ended)
        self.logger.debug(stagedExec.augmentedInputs)
        self.logger.debug(stagedExec.matCheckOutputs)

        # Store serialized version of exitVal, augmentedInputs and matCheckOutputs
        self.marshallExecute(overwrite=True)

        # And last, report the exit value
        return stagedExec.exitVal

    def listMaterializedExportActions(self) -> "Sequence[MaterializedExportAction]":
        """
        This method should return the pids generated from the contents
        """
        self.unmarshallExport(offline=True)

        assert self.runExportActions is not None

        return self.runExportActions

    def exportResultsFromFiles(
        self,
        exportActionsFile: "Optional[AnyPath]" = None,
        securityContextFile: "Optional[AnyPath]" = None,
        action_ids: "Sequence[SymbolicName]" = [],
        fail_ok: "bool" = False,
    ) -> "Tuple[Sequence[MaterializedExportAction], Sequence[Tuple[ExportAction, Exception]]]":
        if exportActionsFile is not None:
            with open(exportActionsFile, mode="r", encoding="utf-8") as eaf:
                raw_actions = unmarshall_namedtuple(yaml.safe_load(eaf))

            actions = self.parseExportActions(raw_actions["exports"])
        else:
            actions = None

        if securityContextFile is not None:
            creds_config = self.ReadSecurityContextFile(securityContextFile)

            valErrors = config_validate(creds_config, self.SECURITY_CONTEXT_SCHEMA)
            if len(valErrors) > 0:
                errstr = f"ERROR in security context block: {valErrors}"
                self.logger.error(errstr)
                raise WFException(errstr)
        else:
            creds_config = None

        return self.exportResults(actions, creds_config, action_ids, fail_ok=fail_ok)

    def exportResults(
        self,
        actions: "Optional[Sequence[ExportAction]]" = None,
        creds_config: "Optional[SecurityContextConfigBlock]" = None,
        action_ids: "Sequence[SymbolicName]" = [],
        fail_ok: "bool" = False,
    ) -> "Tuple[Sequence[MaterializedExportAction], Sequence[Tuple[ExportAction, Exception]]]":
        # The precondition
        if self.unmarshallExport(offline=True, fail_ok=True) is None:
            # TODO
            raise WFException("FIXME")
        # We might to export the previously failed execution
        self.unmarshallExecute(offline=True, fail_ok=True)

        # If actions is None, then try using default ones
        matActions: "MutableSequence[MaterializedExportAction]" = []
        actionErrors: "MutableSequence[Tuple[ExportAction, Exception]]" = []
        if actions is None:
            actions = self.default_actions

            # Corner case
            if actions is None:
                return matActions, actionErrors

        filtered_actions: "Sequence[ExportAction]"
        if len(action_ids) > 0:
            action_ids_set = set(action_ids)
            filtered_actions = list(
                filter(lambda action: action.action_id in action_ids_set, actions)
            )
        else:
            filtered_actions = actions

        # First, let's check all the requested actions are viable
        for action in filtered_actions:
            try:
                # check the export items are available
                elems = self.locateExportItems(action.what)

                # check the security context is available
                a_setup_block: "Optional[WritableSecurityContextConfig]"
                if action.setup is not None:
                    # Clone it
                    a_setup_block = cast(
                        "WritableSecurityContextConfig", copy.copy(action.setup)
                    )
                else:
                    a_setup_block = None

                if action.context_name is None:
                    pass
                elif creds_config is not None:
                    setup_block = creds_config.get(action.context_name)
                    if setup_block is None:
                        raise ExportActionException(
                            f"No configuration found for context {action.context_name} (action {action.action_id})"
                        )
                    # Merging both setup blocks
                    if a_setup_block is None:
                        a_setup_block = cast(
                            "WritableSecurityContextConfig", copy.copy(setup_block)
                        )
                    else:
                        a_setup_block.update(setup_block)
                else:
                    raise ExportActionException(
                        f"Missing security context block with requested context {action.context_name} (action {action.action_id})"
                    )

                # check whether plugin is available
                export_p = self.wfexs.instantiateExportPlugin(
                    self, action.plugin_id, a_setup_block
                )

                # Export the contents and obtain a PID
                new_pids = export_p.push(
                    elems,
                    preferred_scheme=action.preferred_scheme,
                    preferred_id=action.preferred_id,
                )

                # Last, register the PID
                matAction = MaterializedExportAction(
                    action=action, elems=elems, pids=new_pids
                )

                matActions.append(matAction)
            except Exception as e:
                self.logger.exception(
                    f"Export action {action.action_id} (plugin {action.plugin_id}) failed"
                )
                actionErrors.append((action, e))

        if len(actionErrors) > 0:
            errmsg = "There were errors in actions {0}, skipping:\n{1}".format(
                ",".join(map(lambda err: err[0].action_id, actionErrors)),
                "\n".join(map(lambda err: str(err[1]), actionErrors)),
            )

            self.logger.error(errmsg)
            if not fail_ok:
                raise ExportActionException(errmsg)

        # Last, save the metadata we have gathered
        if self.runExportActions is None:
            self.runExportActions = list(matActions)
        else:
            self.runExportActions.extend(matActions)

        # And record them
        self.marshallExport(overwrite=len(matActions) > 0)

        return matActions, actionErrors

    def marshallConfig(
        self, overwrite: "bool" = False
    ) -> "Union[bool, datetime.datetime]":
        assert (
            self.metaDir is not None
        ), "Working directory should not be corrupted beyond basic usage"
        # The seed should have be already written

        # Now, the config itself
        if overwrite or (self.configMarshalled is None):
            workflow_meta_filename = os.path.join(
                self.metaDir, WORKDIR_WORKFLOW_META_FILE
            )
            if (
                overwrite
                or not os.path.exists(workflow_meta_filename)
                or os.path.getsize(workflow_meta_filename) == 0
            ):
                with open(workflow_meta_filename, mode="w", encoding="utf-8") as wmF:
                    workflow_meta: "MutableMapping[str, Any]" = {
                        "workflow_id": self.id,
                        "paranoid_mode": self.paranoidMode,
                    }
                    if self.nickname is not None:
                        workflow_meta["nickname"] = self.nickname
                    if self.version_id is not None:
                        workflow_meta["version"] = self.version_id
                    if self.descriptor_type is not None:
                        workflow_meta["workflow_type"] = self.descriptor_type
                    if self.trs_endpoint is not None:
                        workflow_meta["trs_endpoint"] = self.trs_endpoint
                    if self.workflow_config is not None:
                        workflow_meta["workflow_config"] = self.workflow_config
                    if self.params is not None:
                        workflow_meta["params"] = self.params
                    if self.placeholders is not None:
                        workflow_meta["placeholders"] = self.placeholders
                    if self.outputs is not None:
                        outputs = {output.name: output for output in self.outputs}
                        workflow_meta["outputs"] = outputs
                    if self.default_actions is not None:
                        workflow_meta["default_actions"] = self.default_actions

                    yaml.dump(
                        marshall_namedtuple(workflow_meta), wmF, Dumper=YAMLDumper
                    )

            # This has been commented-out, as credentials should NEVER be kept!!!
            #
            # creds_file = os.path.join(self.metaDir, WORKDIR_SECURITY_CONTEXT_FILE)
            # if overwrite or not os.path.exists(creds_file):
            #     with open(creds_file, mode='w', encoding='utf-8') as crF:
            #         yaml.dump(marshall_namedtuple(self.creds_config), crF, Dumper=YAMLDumper)

            self.configMarshalled = datetime.datetime.fromtimestamp(
                os.path.getctime(workflow_meta_filename), tz=datetime.timezone.utc
            )

        return self.configMarshalled

    def unmarshallConfig(
        self, fail_ok: "bool" = False
    ) -> "Optional[Union[bool, datetime.datetime]]":
        assert (
            self.metaDir is not None
        ), "Working directory should not be corrupted beyond basic usage"

        if self.configMarshalled is None:
            config_unmarshalled = True
            workflow_meta_filename = os.path.join(
                self.metaDir, WORKDIR_WORKFLOW_META_FILE
            )
            # If the file does not exist, fail fast
            if not os.path.isfile(workflow_meta_filename):
                self.logger.debug(
                    f"Marshalled config file {workflow_meta_filename} does not exist"
                )
                return False

            workflow_meta = None
            try:
                with open(workflow_meta_filename, mode="r", encoding="utf-8") as wcf:
                    workflow_meta = unmarshall_namedtuple(yaml.safe_load(wcf))

                    # If the file decodes to None, fail fast
                    if workflow_meta is None:
                        self.logger.error(
                            f"Marshalled config file {workflow_meta_filename} is empty"
                        )
                        return False

                    # Fixes
                    if ("workflow_type" in workflow_meta) and workflow_meta[
                        "workflow_type"
                    ] is None:
                        del workflow_meta["workflow_type"]

                    self.id = workflow_meta["workflow_id"]
                    self.paranoidMode = workflow_meta["paranoid_mode"]
                    self.nickname = workflow_meta.get("nickname", self.instanceId)
                    self.version_id = workflow_meta.get("version")
                    self.descriptor_type = workflow_meta.get("workflow_type")
                    self.trs_endpoint = workflow_meta.get("trs_endpoint")
                    self.workflow_config = workflow_meta.get("workflow_config")
                    self.params = workflow_meta.get("params")
                    self.placeholders = workflow_meta.get("placeholders")
                    self.formatted_params = self.formatParams(self.params)

                    outputsM = workflow_meta.get("outputs")
                    if isinstance(outputsM, dict):
                        outputs = list(outputsM.values())
                        if len(outputs) == 0 or isinstance(outputs[0], ExpectedOutput):
                            self.outputs = outputs
                        else:
                            self.outputs = self.parseExpectedOutputs(outputsM)
                    else:
                        self.outputs = None

                    defaultActionsM = workflow_meta.get("default_actions")
                    if isinstance(defaultActionsM, dict):
                        default_actions = list(defaultActionsM.values())
                        if len(default_actions) == 0 or isinstance(
                            default_actions[0], ExportAction
                        ):
                            self.default_actions = default_actions
                        else:
                            self.default_actions = self.parseExportActions(
                                default_actions
                            )
                    else:
                        self.default_actions = None
            except IOError as ioe:
                config_unmarshalled = False
                self.logger.debug(
                    "Marshalled config file {} I/O errors".format(
                        workflow_meta_filename
                    )
                )
                if not fail_ok:
                    raise WFException("ERROR opening/reading config file") from ioe
            except TypeError as te:
                config_unmarshalled = False
                self.logger.debug(
                    "Marshalled config file {} unmarshalling errors".format(
                        workflow_meta_filename
                    )
                )
                if not fail_ok:
                    raise WFException("ERROR unmarshalling config file") from te
            except Exception as e:
                config_unmarshalled = False
                self.logger.debug(
                    "Marshalled config file {} misc errors".format(
                        workflow_meta_filename
                    )
                )
                if not fail_ok:
                    raise WFException("ERROR processing config file") from e

            if workflow_meta is not None:
                valErrors = config_validate(workflow_meta, self.STAGE_DEFINITION_SCHEMA)
                if len(valErrors) > 0:
                    config_unmarshalled = False
                    errstr = f"ERROR in workflow staging definition block {workflow_meta_filename}: {valErrors}"
                    self.logger.error(errstr)
                    if not fail_ok:
                        raise WFException(errstr)

                # This has been commented-out, as credentials should NEVER be kept!!!
                #
                # creds_file = os.path.join(self.metaDir, WORKDIR_SECURITY_CONTEXT_FILE)
                # if os.path.exists(creds_file):
                #     with open(creds_file, mode="r", encoding="utf-8") as scf:
                #         self.creds_config = unmarshall_namedtuple(yaml.safe_load(scf, Loader=YAMLLoader))
                # else:
                #     self.creds_config = {}
                #
                # valErrors = config_validate(self.creds_config, self.SECURITY_CONTEXT_SCHEMA)
                # if len(valErrors) > 0:
                #     config_unmarshalled = False
                #     errstr = f'ERROR in security context block {creds_file}: {valErrors}'
                #     self.logger.error(errstr)
                #     if not fail_ok:
                #         raise WFException(errstr)
                self.creds_config = dict()

                self.configMarshalled = datetime.datetime.fromtimestamp(
                    os.path.getctime(workflow_meta_filename), tz=datetime.timezone.utc
                )

        return self.configMarshalled

    def marshallStage(
        self, exist_ok: "bool" = True, overwrite: "bool" = False
    ) -> "Optional[Union[bool, datetime.datetime]]":
        if overwrite or (self.stageMarshalled is None):
            # Do not even try
            if self.marshallConfig(overwrite=overwrite) is None:
                return None

            assert (
                self.metaDir is not None
            ), "The metadata directory should be available"

            marshalled_stage_file = os.path.join(
                self.metaDir, WORKDIR_MARSHALLED_STAGE_FILE
            )
            stageAlreadyMarshalled = False
            if os.path.exists(marshalled_stage_file):
                errmsg = "Marshalled stage file {} already exists".format(
                    marshalled_stage_file
                )
                if not overwrite and not exist_ok:
                    raise WFException(errmsg)
                self.logger.debug(errmsg)
                stageAlreadyMarshalled = True

            if not stageAlreadyMarshalled or overwrite:
                assert (
                    self.materializedEngine is not None
                ), "The engine should have already been materialized at this point"
                stage = {
                    "repoURL": self.repoURL,
                    "repoTag": self.repoTag,
                    "repoRelPath": self.repoRelPath,
                    "repoEffectiveCheckout": self.repoEffectiveCheckout,
                    "engineDesc": self.engineDesc,
                    "engineVer": self.engineVer,
                    "materializedEngine": self.materializedEngine,
                    "containers": self.materializedEngine.containers,
                    "containerEngineVersion": self.containerEngineVersion,
                    "containerEngineOs": self.containerEngineOs,
                    "arch": self.arch,
                    "workflowEngineVersion": self.workflowEngineVersion,
                    "materializedParams": self.materializedParams
                    # TODO: check nothing essential was left
                }

                self.logger.debug(
                    "Creating marshalled stage file {}".format(marshalled_stage_file)
                )
                with open(marshalled_stage_file, mode="w", encoding="utf-8") as msF:
                    marshalled_stage = marshall_namedtuple(stage)
                    yaml.dump(marshalled_stage, msF, Dumper=YAMLDumper)

            self.stageMarshalled = datetime.datetime.fromtimestamp(
                os.path.getctime(marshalled_stage_file), tz=datetime.timezone.utc
            )
        elif not exist_ok:
            raise WFException(f"Marshalled stage file already exists")

        return self.stageMarshalled

    def unmarshallStage(
        self, offline: "bool" = False, fail_ok: "bool" = False
    ) -> "Optional[Union[bool, datetime.datetime]]":
        if self.stageMarshalled is None:
            # If basic state does not work, even do not try
            retval = self.unmarshallConfig(fail_ok=fail_ok)
            if not retval:
                return None

            assert (
                self.metaDir is not None
            ), "The metadata directory should be available"

            marshalled_stage_file = os.path.join(
                self.metaDir, WORKDIR_MARSHALLED_STAGE_FILE
            )
            if not os.path.exists(marshalled_stage_file):
                errmsg = f"Marshalled stage file {marshalled_stage_file} does not exists. Stage state was not stored"
                self.logger.debug(errmsg)
                self.stageMarshalled = False
                if fail_ok:
                    return self.stageMarshalled
                raise WFException(errmsg)

            self.logger.debug(
                "Parsing marshalled stage state file {}".format(marshalled_stage_file)
            )
            try:
                # These symbols are needed to properly deserialize the yaml
                with open(marshalled_stage_file, mode="r", encoding="utf-8") as msF:
                    marshalled_stage = yaml.load(msF, Loader=YAMLLoader)

                    combined_globals = copy.copy(common_defs_module.__dict__)
                    combined_globals.update(globals())
                    stage = unmarshall_namedtuple(marshalled_stage, combined_globals)
                    self.repoURL = stage["repoURL"]
                    self.repoTag = stage["repoTag"]
                    self.repoRelPath = stage["repoRelPath"]
                    self.repoEffectiveCheckout = stage["repoEffectiveCheckout"]
                    self.engineDesc = stage["engineDesc"]
                    self.engineVer = stage["engineVer"]
                    self.materializedEngine = stage["materializedEngine"]
                    self.materializedParams = stage["materializedParams"]
                    self.containerEngineVersion = stage.get("containerEngineVersion")
                    self.containerEngineOs = stage.get("containerEngineOs")
                    if self.containerEngineOs is None:
                        self.containerEngineOs = cast(
                            "ContainerOperatingSystem", platform.system().lower()
                        )
                    self.arch = stage.get("arch")
                    if self.arch is None:
                        self.arch = cast("ProcessorArchitecture", platform.machine())
                    self.workflowEngineVersion = stage.get("workflowEngineVersion")

                    # This is needed to properly set up the materializedEngine
                    self.setupEngine(offline=True)
            except Exception as e:
                errmsg = "Error while unmarshalling content from stage state file {}. Reason: {}".format(
                    marshalled_stage_file, e
                )
                self.logger.debug(errmsg)
                self.stageMarshalled = False
                if fail_ok:
                    return self.stageMarshalled
                raise WFException(errmsg) from e

            self.stageMarshalled = datetime.datetime.fromtimestamp(
                os.path.getctime(marshalled_stage_file), tz=datetime.timezone.utc
            )

        return self.stageMarshalled

    def marshallExecute(
        self, exist_ok: "bool" = True, overwrite: "bool" = False
    ) -> "Optional[Union[bool, datetime.datetime]]":
        if overwrite or (self.executionMarshalled is None):
            if self.marshallStage(exist_ok=exist_ok, overwrite=overwrite) is None:
                return None

            assert (
                self.metaDir is not None
            ), "The metadata directory should be available"

            assert self.stagedExecutions is not None

            marshalled_execution_file = os.path.join(
                self.metaDir, WORKDIR_MARSHALLED_EXECUTE_FILE
            )
            executionAlreadyMarshalled = False
            if os.path.exists(marshalled_execution_file):
                errmsg = "Marshalled execution file {} already exists".format(
                    marshalled_execution_file
                )
                if not overwrite and not exist_ok:
                    raise WFException(errmsg)
                self.logger.debug(errmsg)
                executionAlreadyMarshalled = True

            if not executionAlreadyMarshalled or overwrite:
                executions = []
                for stagedExec in self.stagedExecutions:
                    execution = {
                        "outputsDir": stagedExec.outputsDir,
                        "exitVal": stagedExec.exitVal,
                        "augmentedInputs": stagedExec.augmentedInputs,
                        "matCheckOutputs": stagedExec.matCheckOutputs,
                        "started": stagedExec.started,
                        "ended": stagedExec.ended,
                        # TODO: check nothing essential was left
                    }
                    executions.append(execution)

                self.logger.debug(
                    "Creating marshalled execution file {}".format(
                        marshalled_execution_file
                    )
                )
                with open(marshalled_execution_file, mode="w", encoding="utf-8") as msF:
                    yaml.dump(marshall_namedtuple(executions), msF, Dumper=YAMLDumper)

            self.executionMarshalled = datetime.datetime.fromtimestamp(
                os.path.getctime(marshalled_execution_file), tz=datetime.timezone.utc
            )
        elif not exist_ok:
            raise WFException("Marshalled execution file already exists")

        return self.executionMarshalled

    def unmarshallExecute(
        self, offline: "bool" = True, fail_ok: "bool" = False
    ) -> "Optional[Union[bool, datetime.datetime]]":
        if self.executionMarshalled is None:
            # If stage state is not properly prepared, even do not try
            retval = self.unmarshallStage(offline=offline, fail_ok=fail_ok)
            if not retval:
                return None

            assert (
                self.metaDir is not None
            ), "The metadata directory should be available"

            marshalled_execution_file = os.path.join(
                self.metaDir, WORKDIR_MARSHALLED_EXECUTE_FILE
            )
            if not os.path.exists(marshalled_execution_file):
                errmsg = f"Marshalled execution file {marshalled_execution_file} does not exists. Execution state was not stored"
                self.logger.debug(errmsg)
                self.executionMarshalled = False
                if fail_ok:
                    return self.executionMarshalled
                raise WFException(errmsg)

            self.logger.debug(
                "Parsing marshalled execution state file {}".format(
                    marshalled_execution_file
                )
            )

            executionMarshalled = datetime.datetime.fromtimestamp(
                os.path.getctime(marshalled_execution_file), tz=datetime.timezone.utc
            )
            try:
                with open(marshalled_execution_file, mode="r", encoding="utf-8") as meF:
                    marshalled_execution = yaml.load(meF, Loader=YAMLLoader)
                    combined_globals = copy.copy(common_defs_module.__dict__)
                    combined_globals.update(globals())
                    execution_read = unmarshall_namedtuple(
                        marshalled_execution, combined_globals
                    )

                    if isinstance(execution_read, dict):
                        executions = [execution_read]
                    else:
                        executions = execution_read

                    self.stagedExecutions = []
                    for execution in executions:
                        stagedExec = StagedExecution(
                            exitVal=execution["exitVal"],
                            augmentedInputs=execution["augmentedInputs"],
                            matCheckOutputs=execution["matCheckOutputs"],
                            outputsDir=execution.get(
                                "outputsDir", WORKDIR_OUTPUTS_RELDIR
                            ),
                            started=execution.get("started", executionMarshalled),
                            ended=execution.get("ended", executionMarshalled),
                        )
                        self.stagedExecutions.append(stagedExec)
            except Exception as e:
                errmsg = "Error while unmarshalling content from execution state file {}. Reason: {}".format(
                    marshalled_execution_file, e
                )
                self.logger.debug(errmsg)
                self.executionMarshalled = False
                if fail_ok:
                    return self.executionMarshalled
                raise WFException(errmsg) from e

            self.executionMarshalled = datetime.datetime.fromtimestamp(
                os.path.getctime(marshalled_execution_file), tz=datetime.timezone.utc
            )

        return self.executionMarshalled

    def marshallExport(
        self, exist_ok: "bool" = True, overwrite: "bool" = False
    ) -> "Optional[Union[bool, datetime.datetime]]":
        if overwrite or (self.exportMarshalled is None):
            # Do not even try saving the state
            if self.marshallStage(exist_ok=exist_ok, overwrite=overwrite) is None:
                return None

            assert (
                self.metaDir is not None
            ), "The metadata directory should be available"

            marshalled_export_file = os.path.join(
                self.metaDir, WORKDIR_MARSHALLED_EXPORT_FILE
            )
            exportAlreadyMarshalled = False
            if os.path.exists(marshalled_export_file):
                errmsg = "Marshalled export results file {} already exists".format(
                    marshalled_export_file
                )
                if not overwrite and not exist_ok:
                    raise WFException(errmsg)
                self.logger.debug(errmsg)
                exportAlreadyMarshalled = True

            if not exportAlreadyMarshalled or overwrite:
                if self.runExportActions is None:
                    self.runExportActions = []

                self.logger.debug(
                    "Creating marshalled export results file {}".format(
                        marshalled_export_file
                    )
                )
                with open(marshalled_export_file, mode="w", encoding="utf-8") as msF:
                    yaml.dump(
                        marshall_namedtuple(self.runExportActions),
                        msF,
                        Dumper=YAMLDumper,
                    )

            self.exportMarshalled = datetime.datetime.fromtimestamp(
                os.path.getctime(marshalled_export_file), tz=datetime.timezone.utc
            )
        elif not exist_ok:
            raise WFException("Marshalled export results file already exists")

        return self.exportMarshalled

    def unmarshallExport(
        self, offline: "bool" = True, fail_ok: "bool" = False
    ) -> "Optional[Union[bool, datetime.datetime]]":
        if self.exportMarshalled is None:
            # If state does not work, even do not try
            retval = self.unmarshallStage(offline=offline, fail_ok=fail_ok)
            if not retval:
                return None

            assert (
                self.metaDir is not None
            ), "The metadata directory should be available"

            marshalled_export_file = os.path.join(
                self.metaDir, WORKDIR_MARSHALLED_EXPORT_FILE
            )
            if not os.path.exists(marshalled_export_file):
                errmsg = f"Marshalled export results file {marshalled_export_file} does not exists. Export results state was not stored"
                self.logger.debug(errmsg)
                self.exportMarshalled = False
                if fail_ok:
                    return self.exportMarshalled
                raise WFException(errmsg)

            self.logger.debug(
                "Parsing marshalled export results state file {}".format(
                    marshalled_export_file
                )
            )
            try:
                with open(marshalled_export_file, mode="r", encoding="utf-8") as meF:
                    marshalled_export = yaml.load(meF, Loader=YAMLLoader)
                    combined_globals = copy.copy(common_defs_module.__dict__)
                    combined_globals.update(globals())
                    self.runExportActions = unmarshall_namedtuple(
                        marshalled_export, combined_globals
                    )

            except Exception as e:
                errmsg = f"Error while unmarshalling content from export results state file {marshalled_export_file}. Reason: {e}"
                self.logger.debug(e)
                self.exportMarshalled = False
                if fail_ok:
                    return self.exportMarshalled
                raise WFException(errmsg) from e

            self.exportMarshalled = datetime.datetime.fromtimestamp(
                os.path.getctime(marshalled_export_file), tz=datetime.timezone.utc
            )

        return self.exportMarshalled

    def locateExportItems(
        self, items: "Sequence[ExportItem]"
    ) -> "Sequence[AnyContent]":
        """
        The located paths in the contents should be relative to the working directory
        """
        retval: "MutableSequence[AnyContent]" = []

        materializedParamsDict: "Mapping[SymbolicParamName, MaterializedInput]" = dict()
        for item in items:
            if item.type == ExportItemType.Param:
                if not isinstance(self.getMarshallingStatus().stage, datetime.datetime):
                    raise WFException(
                        f"Cannot export inputs from {self.stagedSetup.instance_id} until the workflow has been properly staged"
                    )

                assert self.materializedParams is not None
                assert self.stagedSetup.inputs_dir is not None
                if item.name is not None:
                    if not materializedParamsDict:
                        materializedParamsDict = dict(
                            map(lambda mp: (mp.name, mp), self.materializedParams)
                        )
                    materializedParam = materializedParamsDict.get(
                        cast("SymbolicParamName", item.name)
                    )
                    if materializedParam is None:
                        raise KeyError(
                            f"Param {item.name} to be exported does not exist"
                        )
                    retval.extend(
                        cast(
                            "Iterable[MaterializedContent]",
                            filter(
                                lambda mpc: isinstance(mpc, MaterializedContent),
                                materializedParam.values,
                            ),
                        )
                    )
                    if materializedParam.secondaryInputs:
                        retval.extend(materializedParam.secondaryInputs)
                else:
                    # The whole input directory
                    prettyFilename = cast(
                        "RelPath", os.path.basename(self.stagedSetup.inputs_dir)
                    )
                    retval.append(
                        MaterializedContent(
                            local=self.stagedSetup.inputs_dir,
                            licensed_uri=LicensedURI(
                                uri=cast(
                                    "URIType",
                                    "wfexs:"
                                    + self.stagedSetup.instance_id
                                    + "/"
                                    + prettyFilename,
                                )
                            ),
                            prettyFilename=prettyFilename,
                            kind=ContentKind.Directory,
                        )
                    )
            elif item.type == ExportItemType.Output:
                if not isinstance(
                    self.getMarshallingStatus().execution, datetime.datetime
                ):
                    raise WFException(
                        f"Cannot export outputs from {self.stagedSetup.instance_id} until the workflow has been executed at least once"
                    )

                assert (
                    isinstance(self.stagedExecutions, list)
                    and len(self.stagedExecutions) > 0
                )
                assert self.stagedSetup.outputs_dir is not None
                # TODO: select which of the executions export
                stagedExec = self.stagedExecutions[-1]
                # if item.block:
                #    for p_stagedExec in self.stagedExecutions:
                #        if

                if item.name is not None and len(item.name) > 0:
                    matCheckOutput: "Optional[MaterializedOutput]" = None
                    for cand_matCheckOutput in stagedExec.matCheckOutputs:
                        if cand_matCheckOutput.name == item.name:
                            matCheckOutput = cand_matCheckOutput
                            break
                    if matCheckOutput is None:
                        raise KeyError(
                            f"Output {item.name} to be exported does not exist"
                        )
                    retval.extend(
                        cast(
                            "Iterable[Union[GeneratedContent, GeneratedDirectoryContent]]",
                            filter(
                                lambda aoc: isinstance(
                                    aoc, (GeneratedContent, GeneratedDirectoryContent)
                                ),
                                matCheckOutput.values,
                            ),
                        )
                    )
                else:
                    assert self.stagedSetup.work_dir is not None
                    # The whole output directory
                    prettyFilename = cast("RelPath", stagedExec.outputsDir)
                    retval.append(
                        MaterializedContent(
                            local=cast(
                                "AbsPath",
                                os.path.join(
                                    self.stagedSetup.work_dir, stagedExec.outputsDir
                                ),
                            ),
                            licensed_uri=LicensedURI(
                                uri=cast(
                                    "URIType",
                                    "wfexs:"
                                    + self.stagedSetup.instance_id
                                    + "/"
                                    + prettyFilename,
                                )
                            ),
                            prettyFilename=prettyFilename,
                            kind=ContentKind.Directory,
                        )
                    )
            elif item.type == ExportItemType.WorkingDirectory:
                # The whole working directory
                retval.append(
                    MaterializedContent(
                        local=cast("AbsPath", self.stagedSetup.work_dir),
                        licensed_uri=LicensedURI(
                            uri=cast("URIType", "wfexs:" + self.stagedSetup.instance_id)
                        ),
                        prettyFilename=prettyFilename,
                        kind=ContentKind.Directory,
                    )
                )
            elif item.type in (
                ExportItemType.StageCrate,
                ExportItemType.ProvenanceCrate,
            ):
                if item.block not in ("", "full"):
                    raise KeyError(
                        f"'{item.block}' is not a valid variant for {item.type.value}"
                    )

                if item.type == ExportItemType.StageCrate:
                    if not isinstance(
                        self.getMarshallingStatus().stage, datetime.datetime
                    ):
                        raise WFException(
                            f"Cannot export the prospective provenance crate from {self.stagedSetup.instance_id} until the workflow has been properly staged"
                        )

                    create_rocrate = self.createStageResearchObject
                    rocrate_prefix = f"wfexs_stage_{item.block}_crate"
                    pretty_relname = self.STAGED_CRATE_FILE
                elif item.type == ExportItemType.ProvenanceCrate:
                    if not isinstance(
                        self.getMarshallingStatus().execution, datetime.datetime
                    ):
                        raise WFException(
                            f"Cannot export the restrospective provenance crate from {self.stagedSetup.instance_id} until the workflow has been executed at least once"
                        )

                    create_rocrate = self.createResultsResearchObject
                    rocrate_prefix = f"wfexs_prov_{item.block}_crate"
                    pretty_relname = self.EXECUTION_CRATE_FILE
                else:
                    raise LookupError(
                        f"Unexpected '{item.block}' variant for {item.type.value}"
                    )

                # Now, let's generate it
                temp_handle, temp_rocrate_file = tempfile.mkstemp(
                    prefix=rocrate_prefix, suffix=".zip"
                )
                os.close(temp_handle)
                atexit.register(os.unlink, temp_rocrate_file)
                create_rocrate(
                    filename=cast("AbsPath", temp_rocrate_file),
                    doMaterializedROCrate=item.block == "full",
                )
                retval.append(
                    MaterializedContent(
                        local=cast("AbsPath", temp_rocrate_file),
                        licensed_uri=LicensedURI(
                            uri=cast(
                                "URIType",
                                "wfexs:"
                                + self.stagedSetup.instance_id
                                + "/"
                                + pretty_relname,
                            )
                        ),
                        prettyFilename=pretty_relname,
                        kind=ContentKind.File,
                    )
                )

            else:
                # TODO
                raise LookupError(f"Unimplemented management of item type {item.type}")

        return retval

    def createStageResearchObject(
        self,
        filename: "Optional[AnyPath]" = None,
        doMaterializedROCrate: "bool" = False,
    ) -> "AnyPath":
        """
        Create RO-crate from stage provenance.
        """
        # TODO: implement deserialization
        self.unmarshallStage(offline=True, fail_ok=True)

        assert self.localWorkflow is not None
        assert self.materializedEngine is not None
        assert self.repoURL is not None
        assert self.repoTag is not None
        assert self.materializedParams is not None
        assert self.stagedSetup.work_dir is not None
        assert self.stagedSetup.inputs_dir is not None
        assert self.stagedSetup.outputs_dir is not None

        wf_file = create_workflow_crate(
            self.repoURL,
            self.repoTag,
            self.localWorkflow,
            self.materializedEngine,
            self.workflowEngineVersion,
            self.containerEngineVersion,
            self.containerEngineOs,
            self.arch,
            work_dir=self.stagedSetup.work_dir,
            do_attach=doMaterializedROCrate,
        )
        wfCrate = wf_file.crate

        addInputsResearchObject(
            wf_file,
            self.materializedParams,
            work_dir=self.stagedSetup.work_dir,
            do_attach=doMaterializedROCrate,
        )
        if self.outputs is not None:
            addExpectedOutputsResearchObject(wf_file, self.outputs)

        # Save RO-crate as execution.crate.zip
        if filename is None:
            assert self.outputsDir is not None
            filename = cast(
                "AnyPath", os.path.join(self.outputsDir, self.STAGED_CRATE_FILE)
            )
        wfCrate.write_zip(filename)

        self.logger.info("Staged RO-Crate created: {}".format(filename))

        return filename

    def createResultsResearchObject(
        self,
        filename: "Optional[AnyPath]" = None,
        doMaterializedROCrate: "bool" = False,
    ) -> "AnyPath":
        """
        Create RO-crate from stage provenance.
        """
        # TODO: implement deserialization
        self.unmarshallExecute(offline=True, fail_ok=True)

        assert self.localWorkflow is not None
        assert self.materializedEngine is not None
        assert self.repoURL is not None
        assert self.repoTag is not None
        assert self.stagedSetup.work_dir is not None
        assert (
            isinstance(self.stagedExecutions, list) and len(self.stagedExecutions) > 0
        )

        wf_file = create_workflow_crate(
            self.repoURL,
            self.repoTag,
            self.localWorkflow,
            self.materializedEngine,
            self.workflowEngineVersion,
            self.containerEngineVersion,
            self.containerEngineOs,
            self.arch,
            work_dir=self.stagedSetup.work_dir,
            do_attach=doMaterializedROCrate,
        )
        wfCrate = wf_file.crate

        for stagedExec in self.stagedExecutions:
            add_execution_to_crate(
                wf_file,
                stagedSetup=self.stagedSetup,
                stagedExec=stagedExec,
                do_attach=doMaterializedROCrate,
            )

        # Save RO-crate as execution.crate.zip
        if filename is None:
            assert self.outputsDir is not None
            filename = cast(
                "AnyPath", os.path.join(self.outputsDir, self.EXECUTION_CRATE_FILE)
            )

        wfCrate.write_zip(filename)

        self.logger.info("Execution RO-Crate created: {}".format(filename))

        return filename
