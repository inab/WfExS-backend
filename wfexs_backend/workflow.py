#!/usr/bin/env python
# -*- coding: utf-8 -*-

# SPDX-License-Identifier: Apache-2.0
# Copyright 2020-2025 Barcelona Supercomputing Center (BSC), Spain
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
import dataclasses
import datetime
import inspect
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
import threading
import time
import warnings
import zipfile

import psutil
from RWFileLock import RWFileLock

from typing import (
    cast,
    Dict,
    NamedTuple,
    # This one might be needed for proper unmarshalling
    Pattern,
    TYPE_CHECKING,
    TypeVar,
)

from .common import (
    ContainerType,
    ContentWithURIsDesc,
    CratableItem,
    DEFAULT_CONTAINER_TYPE,
    ExecutionStatus,
    NoCratableItem,
    ResolvedORCID,
)

from .fetchers import (
    FetcherException,
    # Next ones are needed for correct unmarshalling
    RemoteRepo,
    RepoGuessFlavor,
    RepoType,
)

from .utils.orcid import (
    validate_orcid,
)

if TYPE_CHECKING:
    from os import (
        PathLike,
    )

    from typing import (
        Any,
        ClassVar,
        IO,
        Iterable,
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
        Final,
        Literal,
        TypeAlias,
        TypedDict,
        TypeGuard,
        Required,
        NotRequired,
    )

    from .common import (
        AbsPath,
        AnyContent,
        AnyPath,
        EngineVersion,
        ExitVal,
        GlobPattern,
        LicenceDescription,
        MaterializedOutput,
        RelPath,
        RepoTag,
        RepoURL,
        SecurityContextConfig,
        SymbolicName,
        SymbolicParamName,
        SymbolicOutputName,
        TRS_Workflow_Descriptor,
        WfExSInstanceId,
        WritableSecurityContextConfig,
        URIType,
        URIWithMetadata,
    )

    from .container_factories import (
        ContainerEngineVersionStr,
        ContainerOperatingSystem,
        ProcessorArchitecture,
    )

    from .encrypted_fs import (
        EncryptedFSType,
    )

    from .workflow_engines import (
        AbstractWorkflowEngineType,
        WorkflowEngineVersionStr,
    )

    from .pushers import (
        AbstractExportPlugin,
    )

    from .utils.licences import (
        LicenceMatcher,
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

    # Remember to change this if the JSON schema is changed
    Sch_Tabular = TypedDict(
        "Sch_Tabular",
        {
            "uri-columns": Required[Sequence[int]],
            "row-sep": NotRequired[str],
            "column-sep": Required[str],
            "header-rows": NotRequired[int],
        },
    )

    # Remember to change this if the JSON schema is changed
    Sch_Param = TypedDict(
        "Sch_Param",
        {
            "c-l-a-s-s": str,
            "value": Union[str, Sequence[str]],
            "tabular": Sch_Tabular,
            "url": Sch_InputURI,
            "secondary-urls": Sch_InputURI,
            "preferred-name": Union[Literal[False], str],
            "relative-dir": Union[Literal[False], str],
            "security-context": str,
            "disclosable": bool,
            "cacheable": bool,
            "clonable": bool,
            "globExplode": str,
            "autoFill": bool,
            "autoPrefix": bool,
        },
        total=False,
    )

    # Remember to change this if the JSON schema is changed
    Sch_Output = TypedDict(
        "Sch_Output",
        {
            "c-l-a-s-s": str,
            "cardinality": Union[str, int, Sequence[int]],
            "preferredName": str,
            "fillFrom": str,
            "glob": str,
            "syntheticOutput": bool,
        },
        total=False,
    )

    WFVersionId: TypeAlias = Union[str, int]
    WorkflowId: TypeAlias = Union[str, int]

    ExportActionBlock: TypeAlias = Mapping[str, Any]

    MutableParamsBlock: TypeAlias = MutableMapping[str, Any]
    ParamsBlock: TypeAlias = Mapping[str, Any]

    PlaceHoldersBlock: TypeAlias = Mapping[str, Union[int, float, str]]

    EnvironmentBlock: TypeAlias = Mapping[str, Any]

    MutableOutputsBlock: TypeAlias = MutableMapping[str, Any]
    OutputsBlock: TypeAlias = Mapping[str, Any]

    WorkflowConfigBlock: TypeAlias = Mapping[str, Any]

    WorkflowMetaConfigBlock: TypeAlias = Mapping[str, Any]
    WritableWorkflowMetaConfigBlock: TypeAlias = MutableMapping[str, Any]


import urllib.parse

# This is needed to assure yaml.safe_load unmarshalls gives no error
from .container_factories import (
    Container,
)
from .workflow_engines import (
    StagedExecution,
    WorkflowType,
)

from .pushers import (
    ExportPluginException,
)

from .pushers.abstract_contexted_export import (
    AbstractContextedExportPlugin,
)

from .ro_crate import (
    WorkflowRunROCrate,
)
from .utils.rocrate import (
    ContentWithURIsMIMEs,
    ReadROCrateMetadata,
    ReproducibilityLevel,
)

from .security_context import (
    SecurityContextVault,
)
import bagit

from . import __url__ as wfexs_backend_url
from . import __official_name__ as wfexs_backend_name
from . import get_WfExS_version_str

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
    ExportItemType,
    GeneratedContent,
    GeneratedDirectoryContent,
    LicensedURI,
    LocalWorkflow,
    MarshallingStatus,
    MaterializedContent,
    MaterializedInput,
    StagedSetup,
)

from .encrypted_fs import ENCRYPTED_FS_MOUNT_IMPLEMENTATIONS

from .workflow_engines import (
    MaterializedWorkflowEngine,
    STATS_DAG_DOT_FILE,
    WorkflowEngine,
    WorkflowEngineException,
    WorkflowEngineInstallException,
    WORKDIR_CONSOLIDATED_WORKFLOW_RELDIR,
    WORKDIR_CONTAINERS_RELDIR,
    WORKDIR_ENGINE_TWEAKS_RELDIR,
    WORKDIR_INPUTS_RELDIR,
    WORKDIR_EXTRAPOLATED_INPUTS_RELDIR,
    WORKDIR_INTERMEDIATE_RELDIR,
    WORKDIR_MARSHALLED_EXECUTE_FILE,
    WORKDIR_MARSHALLED_EXPORT_FILE,
    WORKDIR_MARSHALLED_STAGE_FILE,
    WORKDIR_META_RELDIR,
    WORKDIR_OUTPUTS_RELDIR,
    WORKDIR_PASSPHRASE_FILE,
    WORKDIR_STATS_RELDIR,
    WORKDIR_STDERR_FILE,
    WORKDIR_STDOUT_FILE,
    WORKDIR_WORKFLOW_META_FILE,
    WORKDIR_WORKFLOW_RELDIR,
)

from .utils.contents import (
    bin2dataurl,
    link_or_copy,
    link_or_copy_pathlib,
    link_or_symlink_pathlib,
)
from .utils.marshalling_handling import marshall_namedtuple, unmarshall_namedtuple
from .utils.misc import (
    config_validate,
    get_maximum_file_descriptors,
    is_uri,
)
from .utils.zipfile_path import path_relative_to

from .fetchers.trs_files import (
    GA4GHTRSFetcher,
)

if TYPE_CHECKING:
    from .wfexs_backend import WfExSBackend

# This code needs exception groups
if sys.version_info[:2] < (3, 11):
    from exceptiongroup import ExceptionGroup


# Related export namedtuples
class ExportItem(NamedTuple):
    type: "ExportItemType"
    block: "Optional[str]" = None
    name: "Optional[Union[SymbolicParamName, SymbolicOutputName]]" = None


# The description of an export action
class ExportAction(NamedTuple):
    action_id: "SymbolicName"
    plugin_id: "SymbolicName"
    what: "Sequence[ExportItem]"
    context_name: "Optional[SymbolicName]"
    setup: "Optional[SecurityContextConfig]"
    preferred_scheme: "Optional[str]"
    preferred_id: "Optional[str]"
    licences: "Sequence[str]" = []
    title: "Optional[str]" = None
    description: "Optional[str]" = None
    custom_metadata: "Optional[Mapping[str, Any]]" = None
    community_custom_metadata: "Optional[Mapping[str, Any]]" = None


class MaterializedExportAction(NamedTuple):
    """
    The description of an export action which was materialized, so
    a permanent identifier was obtained, along with some metadata
    """

    action: "ExportAction"
    elems: "Sequence[AnyContent]"
    pids: "Sequence[URIWithMetadata]"
    when: "datetime.datetime" = datetime.datetime.now().astimezone()


KT = TypeVar("KT")
VT = TypeVar("VT")


class DefaultMissing(Dict[KT, VT]):
    """
    This is inspired in the example available at
    https://docs.python.org/3/library/stdtypes.html#str.format_map
    """

    def __missing__(self, key: KT) -> VT:
        return cast(VT, key)


def _wakeupEncDir(
    cond: "threading.Condition", workDir: "pathlib.Path", logger: "logging.Logger"
) -> None:
    """
    This method periodically checks whether the directory is still available
    """
    cond.acquire()
    try:
        while not cond.wait(60) and workDir.is_dir():
            pass
    except:
        logger.exception("Wakeup thread failed!")
    finally:
        cond.release()


class WFException(AbstractWfExSException):
    pass


class ExportActionException(AbstractWfExSException):
    pass


class WFWarning(UserWarning):
    pass


class WF:
    """
    Workflow enaction class
    """

    TRS_TOOL_FILES_FILE: "Final[RelPath]" = cast("RelPath", "trs_tool_files.json")

    STAGE_DEFINITION_SCHEMA: "Final[RelPath]" = cast("RelPath", "stage-definition.json")
    EXPORT_ACTIONS_SCHEMA: "Final[RelPath]" = cast("RelPath", "export-actions.json")

    STAGED_CRATE_FILE: "Final[RelPath]" = cast("RelPath", "staged.ro-crate.zip")
    EXECUTION_CRATE_FILE: "Final[RelPath]" = cast("RelPath", "execution.ro-crate.zip")

    DEFAULT_TRS_ENDPOINT: "Final[str]" = (
        "https://dev.workflowhub.eu/ga4gh/trs/v2/"  # root of GA4GH TRS API
    )

    def __init__(
        self,
        wfexs: "WfExSBackend",
        workflow_id: "Optional[WorkflowId]" = None,
        version_id: "Optional[WFVersionId]" = None,
        descriptor_type: "Optional[TRS_Workflow_Descriptor]" = None,
        trs_endpoint: "Optional[str]" = None,
        prefer_upstream_source: "Optional[bool]" = None,
        params: "Optional[ParamsBlock]" = None,
        enabled_profiles: "Optional[Sequence[str]]" = None,
        environment: "Optional[EnvironmentBlock]" = None,
        outputs: "Optional[OutputsBlock]" = None,
        placeholders: "Optional[PlaceHoldersBlock]" = None,
        default_actions: "Optional[Sequence[ExportActionBlock]]" = None,
        workflow_config: "Optional[WorkflowConfigBlock]" = None,
        vault: "Optional[SecurityContextVault]" = None,
        instanceId: "Optional[WfExSInstanceId]" = None,
        nickname: "Optional[str]" = None,
        orcids: "Sequence[str]" = [],
        creation: "Optional[datetime.datetime]" = None,
        rawWorkDir: "Optional[pathlib.Path]" = None,
        paranoid_mode: "Optional[bool]" = None,
        public_key_filenames: "Sequence[pathlib.Path]" = [],
        private_key_filename: "Optional[pathlib.Path]" = None,
        private_key_passphrase: "Optional[str]" = None,
        fail_ok: "bool" = False,
        cached_repo: "Optional[Tuple[RemoteRepo, WorkflowType]]" = None,
        cached_workflow: "Optional[LocalWorkflow]" = None,
        cached_inputs: "Optional[Sequence[MaterializedInput]]" = None,
        cached_environment: "Optional[Sequence[MaterializedInput]]" = None,
        preferred_containers: "Sequence[Container]" = [],
        preferred_operational_containers: "Sequence[Container]" = [],
        reproducibility_level: "ReproducibilityLevel" = ReproducibilityLevel.Minimal,
        strict_reproducibility_level: "bool" = False,
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
        It can be either the short name of the workflow engine, or the name used by GA4GH TRS.
        :param trs_endpoint: The TRS endpoint used to find the workflow.
        :param params: Optional params for the workflow execution.
        :param outputs:
        :param workflow_config: Tweaks for workflow enactment, like some overrides
        :param vault: Dictionary with the different credential contexts, only used to fetch fresh contents
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
        :type vault: SecurityContextVault
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

        # These internal variables are needed for imports.
        # They are not preserved in the marshalled staging state, so
        # their effects are only in the initial session
        self.cached_repo = cached_repo
        self.cached_workflow = cached_workflow
        self.cached_inputs = cached_inputs
        self.cached_environment = cached_environment
        self.preferred_containers = copy.copy(preferred_containers)
        self.preferred_operational_containers = copy.copy(
            preferred_operational_containers
        )
        self.reproducibility_level = reproducibility_level
        self.strict_reproducibility_level = strict_reproducibility_level

        self.encWorkDir: "Optional[pathlib.Path]" = None
        self.workDir: "Optional[pathlib.Path]" = None

        if isinstance(paranoid_mode, bool):
            self.paranoidMode = paranoid_mode
        else:
            self.paranoidMode = self.wfexs.getDefaultParanoidMode()

        if not isinstance(workflow_config, dict):
            workflow_config = dict()

        # The container type first is looked up at the workflow configuration
        # and later at the local configuration
        container_type_str = workflow_config.get("containerType")
        if container_type_str is None:
            self.explicit_container_type = False
            container_type_str = self.wfexs.local_config.get("tools", dict()).get(
                "containerType", DEFAULT_CONTAINER_TYPE.value
            )
            workflow_config["containerType"] = container_type_str
        else:
            self.explicit_container_type = True
        # This property should mutate after unmarshalling the config
        self.container_type_str = container_type_str

        self.enabled_profiles: "Optional[Sequence[str]]" = None
        self.expected_outputs: "Optional[Sequence[ExpectedOutput]]" = None
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
                descriptor = self.wfexs.RECOGNIZED_TRS_DESCRIPTORS.get(descriptor_type)
                if descriptor is None:
                    descriptor = self.wfexs.RECOGNIZED_SHORTNAME_DESCRIPTORS.get(
                        descriptor_type
                    )

                if descriptor is not None:
                    workflow_meta["workflow_type"] = descriptor.shortname
                else:
                    self.logger.warning(
                        f"This instance of WfExS backend does not recognize workflows of type {descriptor_type}"
                    )
                    workflow_meta["workflow_type"] = descriptor_type
            if trs_endpoint is not None:
                workflow_meta["trs_endpoint"] = trs_endpoint
            if prefer_upstream_source is not None:
                workflow_meta["prefer_upstream_source"] = prefer_upstream_source
            if workflow_config is not None:
                workflow_meta["workflow_config"] = workflow_config
            if params is not None:
                workflow_meta["params"] = params
            if enabled_profiles is not None:
                workflow_meta["profile"] = enabled_profiles
            if outputs is not None:
                workflow_meta["outputs"] = outputs
            if placeholders is not None:
                workflow_meta["placeholders"] = placeholders

            valErrors = config_validate(workflow_meta, self.STAGE_DEFINITION_SCHEMA)
            if len(valErrors) > 0:
                errstr = f"ERROR in workflow staging definition block: {valErrors}"
                self.logger.error(errstr)
                raise WFException(errstr)

            # Processing the input creds_config
            if not isinstance(vault, SecurityContextVault):
                vault = SecurityContextVault()

            if not isinstance(params, dict):
                params = dict()

            if not isinstance(outputs, dict):
                outputs = dict()

            if not isinstance(placeholders, dict):
                placeholders = dict()

            # Workflow-specific
            self.workflow_config = workflow_config

            self.vault = vault

            self.id = str(workflow_id) if workflow_id is not None else None
            self.version_id = str(version_id) if version_id is not None else None
            self.descriptor_type = descriptor_type
            self.prefer_upstream_source = (
                prefer_upstream_source if prefer_upstream_source is not None else True
            )
            self.params = params
            self.enabled_profiles = enabled_profiles
            self.environment = environment
            self.placeholders = placeholders
            self.formatted_params, self.outputs_to_inject = self.formatParams(params)
            assert self.outputs_to_inject is not None
            self.formatted_environment, _ = self.formatParams(environment)
            self.outputs = outputs
            self.default_actions = self.parseExportActions(
                [] if default_actions is None else default_actions
            )

            # We are assuming here the provided TRS endpoint is right
            # The endpoint should always end with a slash
            if isinstance(trs_endpoint, str):
                if trs_endpoint[-1] != "/":
                    trs_endpoint += "/"

            self.trs_endpoint = trs_endpoint
        else:
            self.trs_endpoint = None
            self.id = None
            self.version_id = None
            self.descriptor_type = None
            self.prefer_upstream_source = True

        if instanceId is not None:
            self.instanceId = instanceId

        if creation is None:
            self.workdir_creation = datetime.datetime.now(tz=datetime.timezone.utc)
        else:
            self.workdir_creation = creation

        self.encfs_type: "Optional[EncryptedFSType]" = None
        self.encfsCond: "Optional[threading.Condition]" = None
        self.encfsThread: "Optional[threading.Thread]" = None
        self.fusermount_cmd = cast("AnyPath", "")
        self.encfs_idleMinutes: "Optional[int]" = None
        self.doUnmount = False

        checkSecure = True
        if rawWorkDir is None:
            if instanceId is None:
                (
                    self.instanceId,
                    self.nickname,
                    self.workdir_creation,
                    self.orcids,
                    self.rawWorkDir,
                ) = self.wfexs.createRawWorkDir(nickname_prefix=nickname, orcids=orcids)
                checkSecure = False
            else:
                (
                    self.instanceId,
                    self.nickname,
                    self.workdir_creation,
                    self.orcids,
                    self.rawWorkDir,
                ) = self.wfexs.getOrCreateRawWorkDirFromInstanceId(
                    instanceId, nickname=nickname, create_ok=False
                )
        else:
            self.rawWorkDir = rawWorkDir.absolute()
            if instanceId is None:
                (
                    self.instanceId,
                    self.nickname,
                    self.workdir_creation,
                    self.orcids,
                    _,
                ) = self.wfexs.parseOrCreateRawWorkDir(
                    self.rawWorkDir, nickname=nickname, create_ok=False
                )
            else:
                self.nickname = nickname if nickname is not None else instanceId
                # FIXME: This is not correct
                self.orcids = orcids

        # TODO: enforce restrictive permissions on each raw working directory
        self.allowOther = False

        if checkSecure:
            workdir_passphrase_file = self.rawWorkDir / WORKDIR_PASSPHRASE_FILE
            self.secure = workdir_passphrase_file.exists()
        else:
            self.secure = (len(public_key_filenames) > 0) or workflow_config.get(
                "secure", True
            )

        doSecureWorkDir = self.secure or self.paranoidMode

        self.tempDir: "pathlib.Path"
        was_setup, self.tempDir = self.setupWorkdir(
            doSecureWorkDir,
            fail_ok=fail_ok,
            public_key_filenames=public_key_filenames,
            private_key_filename=private_key_filename,
            private_key_passphrase=private_key_passphrase,
        )

        self.configMarshalled: "Optional[Union[bool, datetime.datetime]]" = None
        self.inputsDir: "Optional[pathlib.Path]"
        self.extrapolatedInputsDir: "Optional[pathlib.Path]"
        self.intermediateDir: "Optional[pathlib.Path]"
        self.outputsDir: "Optional[pathlib.Path]"
        self.engineTweaksDir: "Optional[pathlib.Path]"
        self.metaDir: "Optional[pathlib.Path]"
        self.workflowDir: "Optional[pathlib.Path]"
        self.consolidatedWorkflowDir: "Optional[pathlib.Path]"
        self.containersDir: "Optional[pathlib.Path]"
        if was_setup:
            assert (
                self.workDir is not None
            ), "Workdir has to be already defined at this point"
            # This directory will hold either hard links to the cached
            # inputs, or the inputs properly pre-processed (decompressed,
            # decrypted, etc....) before a possible extrapolation.
            # These are the inputs used for RO-Crate building
            self.inputsDir = self.workDir / WORKDIR_INPUTS_RELDIR
            self.inputsDir.mkdir(parents=True, exist_ok=True)
            # This directory will hold either hard links to the inputs directory,
            # or the inputs after a possible extrapolation
            self.extrapolatedInputsDir = (
                self.workDir / WORKDIR_EXTRAPOLATED_INPUTS_RELDIR
            )
            self.extrapolatedInputsDir.mkdir(parents=True, exist_ok=True)
            # This directory should hold intermediate workflow steps results
            self.intermediateDir = self.workDir / WORKDIR_INTERMEDIATE_RELDIR
            self.intermediateDir.mkdir(parents=True, exist_ok=True)
            # This directory will hold the final workflow results, which could
            # be either symbolic links to the intermediate results directory
            # or newly generated content
            self.outputsDir = self.workDir / WORKDIR_OUTPUTS_RELDIR
            self.outputsDir.mkdir(parents=True, exist_ok=True)
            # This directory is here for those files which are created in order
            # to tweak or patch workflow executions
            self.engineTweaksDir = self.workDir / WORKDIR_ENGINE_TWEAKS_RELDIR
            self.engineTweaksDir.mkdir(exist_ok=True)
            # This directory will hold metadata related to the execution
            self.metaDir = self.workDir / WORKDIR_META_RELDIR
            # This directory will hold a copy of the workflow
            self.workflowDir = self.workDir / WORKDIR_WORKFLOW_RELDIR
            # This directory will hold a copy of the consolidated workflow
            self.consolidatedWorkflowDir = (
                self.workDir / WORKDIR_CONSOLIDATED_WORKFLOW_RELDIR
            )
            # This directory will hold either a hardlink or a copy of the containers
            self.containersDir = self.workDir / WORKDIR_CONTAINERS_RELDIR

            # This is true when the working directory already exists
            if checkSecure:
                if not self.metaDir.is_dir():
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
                # This check has to be done before the marshalling of the config
                # in order to avoid very ill stage directories
                try:
                    container_type = ContainerType(self.container_type_str)
                except ValueError as ve:
                    errstr = f"Unable to initialize, {self.container_type_str} (explicitly set: {'yes' if self.explicit_container_type else 'no'}) is not a valid container type"
                    self.logger.error(errstr)
                    raise WFException(errstr) from ve
                # As it is a new deployment, forget the concern about
                # the container type
                self.explicit_container_type = True

                self.metaDir.mkdir(parents=True, exist_ok=True)
                self.marshallConfig(overwrite=True)
                is_damaged = False
        else:
            self.configMarshalled = False
            is_damaged = True
            self.inputsDir = None
            self.extrapolatedInputsDir = None
            self.intermediateDir = None
            self.outputsDir = None
            self.engineTweaksDir = None
            self.metaDir = None
            self.workflowDir = None
            self.consolidatedWorkflowDir = None
            self.containersDir = None

        # Now it is the moment to check. It could happen that the
        # working directory comes from a version where a new container
        # type is supported, but not in this one
        try:
            container_type = ContainerType(self.container_type_str)
        except ValueError as ve:
            errstr = f"Unable to initialize, {self.container_type_str} (explicitly set: {'yes' if self.explicit_container_type else 'no'}) is not a valid container type"
            self.logger.error(errstr)
            raise WFException(errstr) from ve

        self.staged_setup = StagedSetup(
            instance_id=self.instanceId,
            container_type=container_type,
            nickname=self.nickname,
            creation=self.workdir_creation,
            workflow_config=self.workflow_config,
            raw_work_dir=self.rawWorkDir,
            work_dir=self.workDir,
            workflow_dir=self.workflowDir,
            consolidated_workflow_dir=self.consolidatedWorkflowDir,
            inputs_dir=self.inputsDir,
            extrapolated_inputs_dir=self.extrapolatedInputsDir,
            outputs_dir=self.outputsDir,
            intermediate_dir=self.intermediateDir,
            containers_dir=self.containersDir,
            engine_tweaks_dir=self.engineTweaksDir,
            meta_dir=self.metaDir,
            temp_dir=self.tempDir,
            secure_exec=self.secure or self.paranoidMode,
            allow_other=self.allowOther,
            is_encrypted=doSecureWorkDir,
            is_damaged=is_damaged,
        )

        self.remote_repo: "Optional[RemoteRepo]" = None
        self.repoURL: "Optional[RepoURL]" = None
        self.repoTag: "Optional[RepoTag]" = None
        self.repoRelPath: "Optional[RelPath]" = None
        self.repoEffectiveCheckout: "Optional[RepoTag]" = None
        self.engine: "Optional[AbstractWorkflowEngineType]" = None
        self.engineVer: "Optional[EngineVersion]" = None
        self.engineDesc: "Optional[WorkflowType]" = None

        self.materializedParams: "Optional[Sequence[MaterializedInput]]" = None
        self.materializedEnvironment: "Optional[Sequence[MaterializedInput]]" = None
        self.localWorkflow: "Optional[LocalWorkflow]" = None
        self.materializedEngine: "Optional[MaterializedWorkflowEngine]" = None
        self.containerEngineVersion: "Optional[ContainerEngineVersionStr]" = None
        self.workflowEngineVersion: "Optional[WorkflowEngineVersionStr]" = None

        self.containerEngineOs: "Optional[ContainerOperatingSystem]" = None
        self.arch: "Optional[ProcessorArchitecture]" = None

        self.stagedExecutions: "Optional[MutableSequence[StagedExecution]]" = None

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
                            scheme=GA4GHTRSFetcher.TRS_SCHEME_PREFIX,
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

    def setupWorkdir(
        self,
        doSecureWorkDir: "bool",
        fail_ok: "bool" = False,
        public_key_filenames: "Sequence[pathlib.Path]" = [],
        private_key_filename: "Optional[pathlib.Path]" = None,
        private_key_passphrase: "Optional[str]" = None,
    ) -> "Tuple[bool, pathlib.Path]":
        uniqueRawWorkDir = self.rawWorkDir

        allowOther = False
        uniqueEncWorkDir: "Optional[pathlib.Path]"
        uniqueWorkDir: "pathlib.Path"
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

            uniqueEncWorkDir = uniqueRawWorkDir / ".crypt"
            uniqueWorkDir = uniqueRawWorkDir / "work"

            # The directories should exist before calling encryption FS mount
            uniqueEncWorkDir.mkdir(parents=True, exist_ok=True)
            uniqueWorkDir.mkdir(parents=True, exist_ok=True)

            # This is the passphrase needed to decrypt the filesystem
            workdir_passphrase_file = uniqueRawWorkDir / WORKDIR_PASSPHRASE_FILE

            used_public_key_filenames: "Sequence[pathlib.Path]"
            if workdir_passphrase_file.exists():
                (
                    encfs_type,
                    encfs_cmd,
                    secureWorkdirPassphrase,
                ) = self.wfexs.readSecuredWorkdirPassphrase(
                    workdir_passphrase_file,
                    private_key_filename=private_key_filename,
                    private_key_passphrase=private_key_passphrase,
                )
                used_public_key_filenames = []
            else:
                (
                    encfs_type,
                    encfs_cmd,
                    secureWorkdirPassphrase,
                    used_public_key_filenames,
                ) = self.wfexs.generateSecuredWorkdirPassphrase(
                    workdir_passphrase_file,
                    private_key_filename=private_key_filename,
                    private_key_passphrase=private_key_passphrase,
                    public_key_filenames=public_key_filenames,
                )

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
                                uniqueWorkDir.as_posix(),
                                uniqueWorkDir.with_name(
                                    uniqueWorkDir.name + "_tainted_" + str(time.time())
                                ).as_posix(),
                            )
                            uniqueWorkDir.mkdir(parents=True, exist_ok=True)
                            break

                # We are going to unmount what we have mounted
                self.doUnmount = True

                # Now, time to mount the encrypted FS
                try:
                    ENCRYPTED_FS_MOUNT_IMPLEMENTATIONS[encfs_type](
                        pathlib.Path(encfs_cmd),
                        self.encfs_idleMinutes,
                        uniqueEncWorkDir,
                        uniqueWorkDir,
                        uniqueRawWorkDir,
                        secureWorkdirPassphrase,
                        allowOther,
                    )
                except Exception as e:
                    errmsg = f"Cannot FUSE mount {uniqueWorkDir} with {encfs_cmd}"
                    self.logger.exception(errmsg)
                    if not fail_ok:
                        raise WFException(errmsg) from e
                    was_setup = False
                else:
                    # IMPORTANT: There can be a race condition in some containerised
                    # scenarios where the FUSE mount process goes to background, but
                    # mounting itself has not finished. This check helps
                    # both to detect and to avoid that corner case.
                    if not os.path.ismount(uniqueWorkDir):
                        errmsg = f"Corner case: cannot keep mounted FUSE mount {uniqueWorkDir} with {encfs_cmd}"
                        self.logger.exception(errmsg)
                        if not fail_ok:
                            raise WFException(errmsg)
                        was_setup = False

                    was_setup = True
                    # and start the thread which keeps the mount working
                    self.encfsCond = threading.Condition()
                    self.encfsThread = threading.Thread(
                        target=_wakeupEncDir,
                        args=(self.encfsCond, uniqueWorkDir, self.logger),
                        daemon=True,
                    )
                    self.encfsThread.start()

                    # Time to transfer the public keys
                    # to be used later in the lifecycle
                    if len(used_public_key_filenames) > 0:
                        base_keys_dir = uniqueWorkDir / "meta" / "public_keys"
                        base_keys_dir.mkdir(parents=True, exist_ok=True)
                        key_fns: "MutableSequence[str]" = []
                        manifest = {
                            "creation": datetime.datetime.now().astimezone(),
                            "keys": key_fns,
                        }
                        for i_key, key_fn in enumerate(used_public_key_filenames):
                            dest_fn_basename = f"key_{i_key}.c4gh.public"
                            dest_fn = base_keys_dir / dest_fn_basename
                            shutil.copyfile(key_fn, dest_fn)
                            key_fns.append(dest_fn_basename)

                        # Last, manifest
                        with (base_keys_dir / "manifest.json").open(
                            mode="wt",
                            encoding="utf-8",
                        ) as mF:
                            json.dump(manifest, mF, sort_keys=True)

            # self.encfsPassphrase = secureWorkdirPassphrase
            del secureWorkdirPassphrase
        else:
            uniqueEncWorkDir = None
            uniqueWorkDir = uniqueRawWorkDir
            was_setup = True

        # The temporary directory is in the raw working directory as
        # some container engine could fail
        uniqueTempDir = uniqueRawWorkDir / ".TEMP"
        uniqueTempDir.mkdir(parents=True, exist_ok=True)
        uniqueTempDir.chmod(0o1777)

        # Setting up working directories, one per instance
        self.encWorkDir = uniqueEncWorkDir
        self.workDir = uniqueWorkDir
        self.allowOther = allowOther

        return was_setup, uniqueTempDir

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
                        self.workDir.as_posix(),
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
        return self.staged_setup

    def getMarshallingStatus(self, reread_stats: "bool" = False) -> "MarshallingStatus":
        if reread_stats:
            self.unmarshallExecute(offline=True, fail_ok=True)
            self.unmarshallExport(offline=True, fail_ok=True)

        return MarshallingStatus(
            pid=self.getPID(),
            workflow_type=self.engineDesc.engineName
            if self.engineDesc is not None
            else None,
            container_type=self.engine.getConfiguredContainerType()
            if self.engine is not None
            else None,
            config=self.configMarshalled,
            stage=self.stageMarshalled,
            execution=self.executionMarshalled,
            export=self.exportMarshalled,
            execution_stats=list(
                map(
                    lambda r: (
                        r.outputsDir.name,
                        r.status,
                        r.queued,
                        r.started,
                        r.ended,
                        r.exitVal,
                    ),
                    self.stagedExecutions,
                )
            )
            if self.stagedExecutions is not None
            else [],
            export_stamps=list(map(lambda ea: ea.when, self.runExportActions))
            if self.runExportActions is not None
            else [],
        )

    def getMaterializedWorkflow(self) -> "Optional[LocalWorkflow]":
        return (
            self.localWorkflow
            if self.materializedEngine is None
            else self.materializedEngine.workflow
        )

    def getMaterializedContainers(self) -> "Sequence[Container]":
        containers: "Sequence[Container]" = []
        if self.materializedEngine is not None:
            if self.materializedEngine.containers is not None:
                containers = self.materializedEngine.containers

        return containers

    def enableParanoidMode(self) -> None:
        self.paranoidMode = True

    @staticmethod
    def __read_yaml_config(
        filename: "pathlib.Path",
    ) -> "WritableWorkflowMetaConfigBlock":
        with filename.open(mode="r", encoding="utf-8") as wcf:
            config_dirname = filename.resolve().parent
            workflow_meta = unmarshall_namedtuple(
                yaml.safe_load(wcf), workdir=config_dirname
            )

        return cast("WritableWorkflowMetaConfigBlock", workflow_meta)

    @classmethod
    def __merge_params_from_file(
        cls,
        wfexs: "WfExSBackend",
        base_workflow_meta: "WorkflowMetaConfigBlock",
        replaced_parameters_filename: "pathlib.Path",
    ) -> "Tuple[WritableWorkflowMetaConfigBlock, Mapping[str, Set[str]]]":
        transferrable_keys = ("params", "environment")
        new_params_meta = cls.__read_yaml_config(replaced_parameters_filename)

        if (
            not isinstance(base_workflow_meta, dict)
            or "params" not in base_workflow_meta
        ):
            raise WFException(
                "Base workflow metadata does not have the proper WfExS parameters structure"
            )

        if not isinstance(new_params_meta, dict) or "params" not in new_params_meta:
            raise WFException(
                f"Loaded {replaced_parameters_filename} does not have the proper WfExS parameters structure"
            )

        # Now, trim everything but what it is allowed
        existing_keys = set(new_params_meta.keys())
        for t_key in transferrable_keys:
            if t_key in existing_keys:
                existing_keys.remove(t_key)

        if len(existing_keys) > 0:
            for key in existing_keys:
                del new_params_meta[key]

        # This key is needed to pass the validation
        new_params_meta["workflow_id"] = "dummy"
        # Let's check!
        if wfexs.validateConfigFiles(new_params_meta) > 0:
            raise WFException(
                f"Loaded WfExS parameters from {replaced_parameters_filename} fails (have a look at the log messages for details)"
            )

        # Last, merge
        workflow_meta = copy.deepcopy(base_workflow_meta)
        transferred_items: "MutableMapping[str, Set[str]]" = dict()
        for t_key in transferrable_keys:
            if t_key in new_params_meta:
                workflow_meta.setdefault(t_key, {}).update(new_params_meta[t_key])
                transferred_items[t_key] = set(new_params_meta[t_key].keys())

        return workflow_meta, transferred_items

    @classmethod
    def FromWorkDir(
        cls,
        wfexs: "WfExSBackend",
        workflowWorkingDirectory: "pathlib.Path",
        private_key_filename: "Optional[pathlib.Path]" = None,
        private_key_passphrase: "Optional[str]" = None,
        fail_ok: "bool" = False,
    ) -> "WF":
        """
        This class method requires an existing staged working directory
        """

        if wfexs is None:
            raise WFException("Unable to initialize, no WfExSBackend instance provided")

        (
            instanceId,
            nickname,
            creation,
            orcids,
            rawWorkDir,
        ) = wfexs.normalizeRawWorkingDirectory(workflowWorkingDirectory)

        return cls(
            wfexs,
            instanceId=instanceId,
            nickname=nickname,
            rawWorkDir=rawWorkDir,
            creation=creation,
            # orcids=orcids,  # Do we need to propagate this here?
            private_key_filename=private_key_filename,
            private_key_passphrase=private_key_passphrase,
            fail_ok=fail_ok,
        )

    @classmethod
    def TryWorkflowURI(
        cls,
        wfexs: "WfExSBackend",
        workflow_uri: "str",
        securityContextsConfigFilename: "Optional[pathlib.Path]" = None,
        nickname_prefix: "Optional[str]" = None,
    ) -> "WF":
        """
        This class method creates a new staged working directory
        """

        workflow_meta = {
            "workflow_id": workflow_uri,
            "workflow_config": {"secure": False},
            "params": {},
        }

        return cls.FromStagedRecipe(
            wfexs,
            workflow_meta,
            securityContextsConfigFilename=securityContextsConfigFilename,
            nickname_prefix=nickname_prefix,
            reproducibility_level=ReproducibilityLevel.Minimal,
        )

    @classmethod
    def FromFiles(
        cls,
        wfexs: "WfExSBackend",
        workflowMetaFilename: "pathlib.Path",
        securityContextsConfigFilename: "Optional[pathlib.Path]" = None,
        nickname_prefix: "Optional[str]" = None,
        orcids: "Sequence[str]" = [],
        public_key_filenames: "Sequence[pathlib.Path]" = [],
        private_key_filename: "Optional[pathlib.Path]" = None,
        private_key_passphrase: "Optional[str]" = None,
        paranoidMode: "bool" = False,
    ) -> "WF":
        """
        This class method creates a new staged working directory
        """

        workflow_meta = cls.__read_yaml_config(workflowMetaFilename)

        return cls.FromStagedRecipe(
            wfexs,
            workflow_meta,
            securityContextsConfigFilename=securityContextsConfigFilename,
            nickname_prefix=nickname_prefix,
            orcids=orcids,
            public_key_filenames=public_key_filenames,
            private_key_filename=private_key_filename,
            private_key_passphrase=private_key_passphrase,
            paranoidMode=paranoidMode,
            reproducibility_level=ReproducibilityLevel.Minimal,
        )

    @classmethod
    def FromStagedRecipe(
        cls,
        wfexs: "WfExSBackend",
        workflow_meta: "WritableWorkflowMetaConfigBlock",
        securityContextsConfigFilename: "Optional[pathlib.Path]" = None,
        nickname_prefix: "Optional[str]" = None,
        orcids: "Sequence[str]" = [],
        public_key_filenames: "Sequence[pathlib.Path]" = [],
        private_key_filename: "Optional[pathlib.Path]" = None,
        private_key_passphrase: "Optional[str]" = None,
        paranoidMode: "bool" = False,
        cached_repo: "Optional[Tuple[RemoteRepo, WorkflowType]]" = None,
        cached_workflow: "Optional[LocalWorkflow]" = None,
        cached_inputs: "Optional[Sequence[MaterializedInput]]" = None,
        cached_environment: "Optional[Sequence[MaterializedInput]]" = None,
        preferred_containers: "Sequence[Container]" = [],
        preferred_operational_containers: "Sequence[Container]" = [],
        reproducibility_level: "ReproducibilityLevel" = ReproducibilityLevel.Metadata,
        strict_reproducibility_level: "bool" = False,
    ) -> "WF":
        """
        This class method creates a new staged working directory
        """

        # Should we prepend the nickname prefix?
        if nickname_prefix is not None:
            workflow_meta["nickname"] = nickname_prefix + workflow_meta.get(
                "nickname", ""
            )

        # Last, try loading the security contexts credentials file
        if securityContextsConfigFilename:
            if securityContextsConfigFilename.exists():
                vault = SecurityContextVault.FromFile(securityContextsConfigFilename)
            else:
                raise WFException(
                    f"Security context file {securityContextsConfigFilename} is not reachable"
                )
        else:
            vault = SecurityContextVault()

        return cls.FromDescription(
            wfexs,
            workflow_meta,
            vault,
            paranoidMode=paranoidMode,
            orcids=orcids,
            public_key_filenames=public_key_filenames,
            private_key_filename=private_key_filename,
            private_key_passphrase=private_key_passphrase,
            cached_repo=cached_repo,
            cached_workflow=cached_workflow,
            cached_inputs=cached_inputs,
            cached_environment=cached_environment,
            preferred_containers=preferred_containers,
            preferred_operational_containers=preferred_operational_containers,
            reproducibility_level=reproducibility_level,
            strict_reproducibility_level=strict_reproducibility_level,
        )

    @classmethod
    def FromPreviousInstanceDeclaration(
        cls,
        wfexs: "WfExSBackend",
        wfInstance: "WF",
        securityContextsConfigFilename: "Optional[pathlib.Path]" = None,
        replaced_parameters_filename: "Optional[pathlib.Path]" = None,
        nickname_prefix: "Optional[str]" = None,
        orcids: "Sequence[str]" = [],
        public_key_filenames: "Sequence[pathlib.Path]" = [],
        private_key_filename: "Optional[pathlib.Path]" = None,
        private_key_passphrase: "Optional[str]" = None,
        secure: "bool" = True,
        paranoidMode: "bool" = False,
        reproducibility_level: "ReproducibilityLevel" = ReproducibilityLevel.Metadata,
        strict_reproducibility_level: "bool" = False,
    ) -> "WF":
        """
        This class method creates a new staged working directory
        based on the declaration of an existing one
        """

        # The workflow information can be incomplete without this step.
        # was_staged = wfInstance.unmarshallStage(offline=True, fail_ok=True, do_full_setup=False)
        # if not isinstance(was_staged, datetime.datetime):
        #    raise WFException(f"Staged working directory from {wfInstance} was not properly staged")
        # Now we should be able to get the configuration file
        workflow_meta = copy.deepcopy(wfInstance.staging_recipe)

        if replaced_parameters_filename is not None:
            workflow_meta, replaced_items = cls.__merge_params_from_file(
                wfexs, workflow_meta, replaced_parameters_filename
            )
        else:
            replaced_items = dict()

        # Now, some postprocessing...
        cached_inputs: "Optional[Sequence[MaterializedInput]]" = None
        cached_environment: "Optional[Sequence[MaterializedInput]]" = None
        the_containers: "Sequence[Container]" = []
        the_operational_containers: "Sequence[Container]" = []
        cached_workflow: "Optional[LocalWorkflow]" = None
        cached_repo: "Optional[Tuple[RemoteRepo, WorkflowType]]" = None
        if reproducibility_level >= ReproducibilityLevel.Full:
            if wfInstance.materializedParams is not None:
                cached_inputs = copy.copy(wfInstance.materializedParams)

                # Let's invalidate several params
                # as several parameters could be replaced
                replaced_inputs = replaced_items.get("params")
                if (
                    replaced_inputs is not None
                    and isinstance(cached_inputs, list)
                    and len(cached_inputs) > 0
                ):
                    # This is overcomplicated to pass checks in python 3.7 mypy
                    def filter_cached_inputs(
                        m_i: "MaterializedInput",
                    ) -> "TypeGuard[bool]":
                        assert replaced_inputs is not None
                        return m_i.name not in replaced_inputs

                    new_cached_inputs = list(
                        filter(filter_cached_inputs, cached_inputs)
                    )
                    if len(new_cached_inputs) < len(cached_inputs):
                        cached_inputs = cast(
                            "Sequence[MaterializedInput]", new_cached_inputs
                        )

            if wfInstance.materializedEnvironment is not None:
                cached_environment = copy.copy(wfInstance.materializedEnvironment)

                # Let's invalidate several environment variables
                # as several parameters could be replaced
                replaced_environment = replaced_items.get("environment")
                if (
                    replaced_environment is not None
                    and isinstance(cached_environment, list)
                    and len(cached_environment) > 0
                ):
                    # This is overcomplicated to pass checks in python 3.7 mypy
                    def filter_cached_environment(
                        m_i: "MaterializedInput",
                    ) -> "TypeGuard[bool]":
                        assert replaced_environment is not None
                        return m_i.name not in replaced_environment

                    new_cached_environment = list(
                        filter(filter_cached_environment, cached_environment)
                    )
                    if len(new_cached_environment) < len(cached_environment):
                        cached_environment = cast(
                            "Sequence[MaterializedInput]", new_cached_environment
                        )

            if wfInstance.materializedEngine is not None:
                if wfInstance.materializedEngine.containers is not None:
                    the_containers = wfInstance.materializedEngine.containers
                if wfInstance.materializedEngine.operational_containers is not None:
                    the_operational_containers = (
                        wfInstance.materializedEngine.operational_containers
                    )

        if reproducibility_level >= ReproducibilityLevel.Metadata:
            if wfInstance.remote_repo is not None and wfInstance.engineDesc is not None:
                cached_repo = (wfInstance.remote_repo, wfInstance.engineDesc)

            cached_workflow = wfInstance.getMaterializedWorkflow()

        # We have to reset the inherited paranoid mode and nickname
        for k_name in ("nickname", "paranoid_mode"):
            if k_name in workflow_meta:
                del workflow_meta[k_name]

        # We also have to reset the secure mode
        workflow_meta.setdefault("workflow_config", {})["secure"] = secure

        return cls.FromStagedRecipe(
            wfexs,
            workflow_meta,
            securityContextsConfigFilename=securityContextsConfigFilename,
            nickname_prefix=nickname_prefix,
            orcids=orcids,
            public_key_filenames=public_key_filenames,
            private_key_filename=private_key_filename,
            private_key_passphrase=private_key_passphrase,
            paranoidMode=paranoidMode,
            cached_repo=cached_repo,
            cached_workflow=cached_workflow,
            cached_inputs=cached_inputs,
            cached_environment=cached_environment,
            preferred_containers=the_containers,
            reproducibility_level=reproducibility_level,
            strict_reproducibility_level=strict_reproducibility_level,
        )

    @staticmethod
    def _transferInputs(
        payload_dir: "pathlib.Path",
        inputs_dir: "pathlib.Path",
        cached_inputs: "Sequence[MaterializedInput]",
    ) -> "Sequence[MaterializedInput]":
        new_cached_inputs = []
        for cached_input in cached_inputs:
            new_cached_input = cached_input
            if len(new_cached_input.values) > 0 and isinstance(
                new_cached_input.values[0], MaterializedContent
            ):
                new_values: "MutableSequence[MaterializedContent]" = []
                for value in cast(
                    "Sequence[MaterializedContent]", new_cached_input.values
                ):
                    source_file = payload_dir / value.local
                    dest_file = inputs_dir / path_relative_to(source_file, payload_dir)
                    new_value = value._replace(
                        local=dest_file,
                    )
                    new_values.append(new_value)

                new_cached_input = new_cached_input._replace(values=new_values)

            if (
                new_cached_input.secondaryInputs is not None
                and len(new_cached_input.secondaryInputs) > 0
                and isinstance(new_cached_input.secondaryInputs[0], MaterializedContent)
            ):
                new_secondaryInputs: "MutableSequence[MaterializedContent]" = []
                for secondaryInput in new_cached_input.secondaryInputs:
                    source_file = payload_dir / secondaryInput.local
                    dest_file = inputs_dir / path_relative_to(source_file, payload_dir)
                    new_secondaryInput = secondaryInput._replace(
                        local=dest_file,
                    )
                    new_secondaryInputs.append(new_secondaryInput)

                new_cached_input = new_cached_input._replace(
                    secondaryInputs=new_secondaryInputs
                )

            new_cached_inputs.append(new_cached_input)

        return new_cached_inputs

    @classmethod
    def FromPreviousROCrate(
        cls,
        wfexs: "WfExSBackend",
        workflowROCrateFilename: "pathlib.Path",
        public_name: "str",  # Mainly used for provenance and exceptions
        securityContextsConfigFilename: "Optional[pathlib.Path]" = None,
        replaced_parameters_filename: "Optional[pathlib.Path]" = None,
        nickname_prefix: "Optional[str]" = None,
        orcids: "Sequence[str]" = [],
        public_key_filenames: "Sequence[pathlib.Path]" = [],
        private_key_filename: "Optional[pathlib.Path]" = None,
        private_key_passphrase: "Optional[str]" = None,
        secure: "bool" = True,
        paranoidMode: "bool" = False,
        reproducibility_level: "ReproducibilityLevel" = ReproducibilityLevel.Metadata,
        strict_reproducibility_level: "bool" = False,
        retrospective_first: "bool" = True,
    ) -> "WF":
        """
        This class method creates a new staged working directory
        based on the declaration of an existing one
        """

        jsonld_obj, payload_dir = ReadROCrateMetadata(
            workflowROCrateFilename, public_name
        )

        (
            repo,
            workflow_type,
            container_type,
            params,
            profiles,
            environment,
            outputs,
            cached_workflow,
            the_containers,
            cached_inputs,
            cached_environment,
        ) = wfexs.rocrate_toolbox.generateWorkflowMetaFromJSONLD(
            jsonld_obj,
            public_name,
            reproducibility_level=reproducibility_level,
            strict_reproducibility_level=strict_reproducibility_level,
            retrospective_first=retrospective_first,
            payload_dir=payload_dir,
        )

        workflow_pid = wfexs.gen_workflow_pid(repo)
        logging.debug(
            f"Repo {repo} workflow type {workflow_type} container factory {container_type}"
        )
        workflow_meta: "WritableWorkflowMetaConfigBlock" = {
            "workflow_id": workflow_pid,
            "workflow_type": workflow_type.shortname,
            "environment": environment,
            "params": params,
            "outputs": outputs,
            "workflow_config": {
                "secure": secure,
            },
        }
        if profiles is not None:
            workflow_meta["profile"] = profiles
        if container_type is not None:
            workflow_meta["workflow_config"]["containerType"] = container_type.value

        logging.debug(f"{json.dumps(workflow_meta, indent=4)}")

        if replaced_parameters_filename is not None:
            workflow_meta, replaced_items = cls.__merge_params_from_file(
                wfexs, workflow_meta, replaced_parameters_filename
            )
        else:
            replaced_items = dict()

        # Last, be sure that what it has been generated is correct
        if wfexs.validateConfigFiles(workflow_meta, securityContextsConfigFilename) > 0:
            raise WFException(
                f"Generated WfExS description from {public_name} fails (have a look at the log messages for details)"
            )

        # Now, some postprocessing...
        if (
            reproducibility_level >= ReproducibilityLevel.Full
            and payload_dir is not None
        ):
            # Let's invalidate several params and environment
            # as several parameters could be replaced
            replaced_inputs = replaced_items.get("params")
            if (
                replaced_inputs is not None
                and isinstance(cached_inputs, list)
                and len(cached_inputs) > 0
            ):
                # This is overcomplicated to pass checks in python 3.7 mypy
                def filter_cached_inputs(m_i: "MaterializedInput") -> "TypeGuard[bool]":
                    assert replaced_inputs is not None
                    return m_i.name not in replaced_inputs

                new_cached_inputs = list(filter(filter_cached_inputs, cached_inputs))
                if len(new_cached_inputs) < len(cached_inputs):
                    cached_inputs = cast(
                        "Sequence[MaterializedInput]", new_cached_inputs
                    )

            replaced_environment = replaced_items.get("environment")
            if (
                replaced_environment is not None
                and isinstance(cached_environment, list)
                and len(cached_environment) > 0
            ):
                # This is overcomplicated to pass checks in python 3.7 mypy
                def filter_cached_environment(
                    m_i: "MaterializedInput",
                ) -> "TypeGuard[bool]":
                    assert replaced_environment is not None
                    return m_i.name not in replaced_environment

                new_cached_environment = list(
                    filter(
                        filter_cached_environment,
                        cast("Sequence[MaterializedInput]", cached_environment),
                    )
                )
                if len(new_cached_environment) < len(cached_environment):
                    cached_environment = cast(
                        "Sequence[MaterializedInput]", new_cached_environment
                    )

        return cls.FromStagedRecipe(
            wfexs,
            workflow_meta,
            securityContextsConfigFilename=securityContextsConfigFilename,
            nickname_prefix=nickname_prefix,
            orcids=orcids,
            public_key_filenames=public_key_filenames,
            private_key_filename=private_key_filename,
            private_key_passphrase=private_key_passphrase,
            paranoidMode=paranoidMode,
            cached_repo=(repo, workflow_type),
            cached_workflow=cached_workflow,
            cached_inputs=cached_inputs,
            cached_environment=cached_environment,
            preferred_containers=the_containers,
            # TODO: preferred_operational_containers are not rescued (yet!)
            reproducibility_level=reproducibility_level,
            strict_reproducibility_level=strict_reproducibility_level,
        )

    @classmethod
    def FromDescription(
        cls,
        wfexs: "WfExSBackend",
        workflow_meta: "WorkflowMetaConfigBlock",
        vault: "SecurityContextVault",
        orcids: "Sequence[str]" = [],
        public_key_filenames: "Sequence[pathlib.Path]" = [],
        private_key_filename: "Optional[pathlib.Path]" = None,
        private_key_passphrase: "Optional[str]" = None,
        paranoidMode: "bool" = False,
        cached_repo: "Optional[Tuple[RemoteRepo, WorkflowType]]" = None,
        cached_workflow: "Optional[LocalWorkflow]" = None,
        cached_inputs: "Optional[Sequence[MaterializedInput]]" = None,
        cached_environment: "Optional[Sequence[MaterializedInput]]" = None,
        preferred_containers: "Sequence[Container]" = [],
        preferred_operational_containers: "Sequence[Container]" = [],
        reproducibility_level: "ReproducibilityLevel" = ReproducibilityLevel.Metadata,
        strict_reproducibility_level: "bool" = False,
    ) -> "WF":
        """
        This class method might create a new staged working directory

        :param wfexs: WfExSBackend instance
        :param workflow_meta: The configuration describing both the workflow
        and the inputs to use when it is being instantiated.
        :param paranoidMode:
        :type wfexs: WfExSBackend
        :type workflow_meta: dict
        :type paranoidMode: bool
        :return: Workflow configuration
        """

        # The preserved paranoid mode must be honoured
        preserved_paranoid_mode = workflow_meta.get("paranoid_mode")
        if preserved_paranoid_mode is not None:
            paranoidMode = preserved_paranoid_mode

        profiles: "Optional[Union[str, Sequence[str]]]" = workflow_meta.get("profile")
        enabled_profiles: "Optional[Sequence[str]]" = None
        if profiles is not None:
            if isinstance(profiles, list):
                enabled_profiles = profiles
            elif isinstance(profiles, str):
                split_by_comma = re.compile(r"[ \t]*,[ \t]*")
                enabled_profiles = split_by_comma.split(profiles)
            else:
                # It should not happen
                enabled_profiles = [str(profiles)]

        parsed_workflow_id = urllib.parse.urlparse(workflow_meta["workflow_id"])
        if parsed_workflow_id.scheme != "":
            trs_endpoint = workflow_meta.get("trs_endpoint")
        else:
            trs_endpoint = workflow_meta.get("trs_endpoint", cls.DEFAULT_TRS_ENDPOINT)

        return cls(
            wfexs,
            workflow_meta["workflow_id"],
            workflow_meta.get("version"),
            descriptor_type=workflow_meta.get("workflow_type"),
            trs_endpoint=trs_endpoint,
            prefer_upstream_source=workflow_meta.get("prefer_upstream_source"),
            params=workflow_meta.get("params", dict()),
            enabled_profiles=enabled_profiles,
            environment=workflow_meta.get("environment", dict()),
            outputs=workflow_meta.get("outputs", dict()),
            placeholders=workflow_meta.get("placeholders", dict()),
            default_actions=workflow_meta.get("default_actions"),
            workflow_config=workflow_meta.get("workflow_config"),
            nickname=workflow_meta.get("nickname"),
            orcids=orcids,
            vault=vault,
            public_key_filenames=public_key_filenames,
            private_key_filename=private_key_filename,
            private_key_passphrase=private_key_passphrase,
            paranoid_mode=paranoidMode,
            cached_repo=cached_repo,
            cached_workflow=cached_workflow,
            cached_inputs=cached_inputs,
            cached_environment=cached_environment,
            preferred_containers=preferred_containers,
            preferred_operational_containers=preferred_operational_containers,
            reproducibility_level=reproducibility_level,
            strict_reproducibility_level=strict_reproducibility_level,
        )

    @classmethod
    def FromForm(
        cls,
        wfexs: "WfExSBackend",
        workflow_meta: "WorkflowMetaConfigBlock",
        orcids: "Sequence[str]" = [],
        public_key_filenames: "Sequence[pathlib.Path]" = [],
        private_key_filename: "Optional[pathlib.Path]" = None,
        private_key_passphrase: "Optional[str]" = None,
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

        profiles: "Optional[Union[str, Sequence[str]]]" = workflow_meta.get("profile")
        enabled_profiles: "Optional[Sequence[str]]" = None
        if profiles is not None:
            if isinstance(profiles, list):
                enabled_profiles = profiles
            elif isinstance(profiles, str):
                split_by_comma = re.compile(r"[ \t]*,[ \t]*")
                enabled_profiles = split_by_comma.split(profiles)
            else:
                # It should not happen
                enabled_profiles = [str(profiles)]

        parsed_workflow_id = urllib.parse.urlparse(workflow_meta["workflow_id"])
        if parsed_workflow_id.scheme != "":
            trs_endpoint = workflow_meta.get("trs_endpoint")
        else:
            trs_endpoint = workflow_meta.get("trs_endpoint", cls.DEFAULT_TRS_ENDPOINT)

        return cls(
            wfexs,
            workflow_meta["workflow_id"],
            workflow_meta.get("version"),
            descriptor_type=workflow_meta.get("workflow_type"),
            trs_endpoint=trs_endpoint,
            prefer_upstream_source=workflow_meta.get("prefer_upstream_source"),
            params=workflow_meta.get("params", dict()),
            enabled_profiles=enabled_profiles,
            environment=workflow_meta.get("environment", dict()),
            placeholders=workflow_meta.get("placeholders", dict()),
            default_actions=workflow_meta.get("default_actions"),
            workflow_config=workflow_meta.get("workflow_config"),
            nickname=workflow_meta.get("nickname"),
            orcids=orcids,
            public_key_filenames=public_key_filenames,
            private_key_filename=private_key_filename,
            private_key_passphrase=private_key_passphrase,
            paranoid_mode=paranoidMode,
        )

    def fetchWorkflow(
        self,
        workflow_id: "WorkflowId",
        version_id: "Optional[WFVersionId]",
        trs_endpoint: "Optional[str]",
        descriptor_type: "Optional[TRS_Workflow_Descriptor]",
        prefer_upstream_source: "bool" = True,
        offline: "bool" = False,
        ignoreCache: "bool" = False,
        injectable_repo: "Optional[Tuple[RemoteRepo, WorkflowType]]" = None,
        injectable_workflow: "Optional[LocalWorkflow]" = None,
    ) -> None:
        """
        Fetch the whole workflow description based on the data obtained
        from the TRS where it is being published.

        If the workflow id is an URL, it is supposed to be a repository (git, swh, ...),
        and the version will represent either the branch, tag or specific commit.
        So, the whole TRS fetching machinery is bypassed.
        """

        assert self.metaDir is not None
        assert self.workflowDir is not None, "The workflow directory should be defined"
        workflow_dir = pathlib.Path(self.workflowDir)

        repoDir: "Optional[pathlib.Path]" = None
        injected_workflow: "Optional[LocalWorkflow]" = None
        rel_path_files: "Optional[Sequence[Union[RelPath, URIType]]]" = None
        # Materialize the workflow, even if it was already materialized
        if self.remote_repo is None or ignoreCache:
            repoEffectiveCheckout: "Optional[RepoTag]"
            # Injectable repo info is a precondition for injectable local workflow
            if injectable_repo is not None:
                repo, self.engineDesc = injectable_repo

                parsedRepoURL = urllib.parse.urlparse(repo.repo_url)
                assert (
                    len(parsedRepoURL.scheme) > 0
                ), f"Repository id {repo.repo_url} should be a parsable URI"

                if not ignoreCache and injectable_workflow is not None:
                    # Injectable repo info is a precondition for injectable local workflow
                    repoEffectiveCheckout = repo.checkout
                    repoDir = injectable_workflow.dir
                    injected_workflow = injectable_workflow
                    issue_warning = False
                    rel_path_files = injected_workflow.relPathFiles
                    if repo.rel_path is not None:
                        if (
                            injected_workflow.relPath is not None
                            and repo.rel_path.endswith(injected_workflow.relPath)
                        ):
                            if (
                                injected_workflow.relPathFiles is not None
                                and repo.rel_path != injected_workflow.relPath
                            ):
                                repo_rel_prefix = repo.rel_path[
                                    0 : -len(injected_workflow.relPath)
                                ]
                                rel_path_files = []
                                for rel_path_file in injected_workflow.relPathFiles:
                                    # Do not prefix URLs
                                    if is_uri(rel_path_file):
                                        rel_path_files.append(rel_path_file)
                                    else:
                                        rel_path_files.append(
                                            cast(
                                                "RelPath",
                                                repo_rel_prefix + rel_path_file,
                                            )
                                        )
                        elif repo.rel_path != injected_workflow.relPath:
                            issue_warning = True
                    elif injected_workflow.relPath is not None:
                        issue_warning = True

                    if issue_warning:
                        self.logger.warning(
                            f"Injected workflow has a different relPath from the injected repo"
                        )
                else:
                    (
                        repoDir,
                        materialized_repo,
                        workflow_type,
                        downstream_repos,
                    ) = self.wfexs.doMaterializeRepo(
                        repo,
                        prefer_upstream_source=prefer_upstream_source,
                        doUpdate=ignoreCache,
                        # registerInCache=True,
                        offline=offline,
                    )
                    assert len(downstream_repos) > 0
                    repo = materialized_repo.repo
                    repoEffectiveCheckout = repo.get_checkout()
            else:
                (
                    repoDir,
                    repo,
                    self.engineDesc,
                    repoEffectiveCheckout,
                ) = self.wfexs.cacheWorkflow(
                    workflow_id=workflow_id,
                    version_id=version_id,
                    trs_endpoint=trs_endpoint,
                    prefer_upstream_source=prefer_upstream_source,
                    descriptor_type=descriptor_type,
                    ignoreCache=ignoreCache,
                    offline=offline,
                    meta_dir=self.metaDir,
                )

            self.remote_repo = repo
            # These are kept for compatibility
            self.repoURL = repo.repo_url
            self.repoTag = repo.tag
            self.repoRelPath = repo.rel_path
            self.repoEffectiveCheckout = repoEffectiveCheckout

            # Workflow Language version cannot be assumed here yet
            # A copy of the workflows is kept
            if workflow_dir.is_dir():
                shutil.rmtree(workflow_dir)
            # force_copy is needed to isolate the copy of the workflow
            # so local modifications in a working directory does not
            # poison the cached workflow
            if injected_workflow is not None:
                if (
                    injected_workflow.relPath is not None
                    and len(injected_workflow.relPath) > 0
                ):
                    assert repo.rel_path is not None
                    link_or_copy_pathlib(
                        injected_workflow.dir / injected_workflow.relPath,
                        workflow_dir / repo.rel_path,
                        force_copy=True,
                        preserve_attrs=True,
                    )

                if rel_path_files is not None:
                    assert injected_workflow.relPathFiles is not None
                    for inj, dest_inj in zip(
                        injected_workflow.relPathFiles, rel_path_files
                    ):
                        # Do not try copying URLs
                        if not is_uri(inj):
                            link_or_copy_pathlib(
                                injected_workflow.dir / inj,
                                workflow_dir / dest_inj,
                                force_copy=True,
                                preserve_attrs=True,
                            )
            elif repoDir.is_dir():
                link_or_copy_pathlib(repoDir, workflow_dir, force_copy=True)
            else:
                workflow_dir.mkdir(parents=True, exist_ok=True)
                if self.repoRelPath is None:
                    self.repoRelPath = cast("RelPath", "workflow.entrypoint")
                link_or_copy_pathlib(
                    repoDir,
                    workflow_dir / self.repoRelPath,
                    force_copy=True,
                )

        # We cannot know yet the dependencies
        localWorkflow = LocalWorkflow(
            dir=workflow_dir,
            relPath=self.repoRelPath,
            effectiveCheckout=self.repoEffectiveCheckout,
            relPathFiles=rel_path_files,
        )
        self.logger.info(
            "materialized workflow repository (checkout {}): {}".format(
                self.repoEffectiveCheckout, localWorkflow.dir
            )
        )

        if localWorkflow.relPath is not None:
            if not (localWorkflow.dir / localWorkflow.relPath).exists():
                raise WFException(
                    "Relative path {} cannot be found in materialized workflow repository {}".format(
                        localWorkflow.relPath, localWorkflow.dir
                    )
                )
        # A valid engine must be identified from the fetched content
        # TODO: decide whether to force some specific version
        if self.engineDesc is None:
            for engineDesc in self.wfexs.WORKFLOW_ENGINES:
                self.logger.debug("Testing engine " + engineDesc.trs_descriptor)
                engine = self.wfexs.instantiateEngine(engineDesc, self.staged_setup)

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
                        self.engineDesc = engineDesc
                        break
                except WorkflowEngineInstallException:
                    self.logger.exception(
                        f"Engine {engineDesc.trs_descriptor} could not be installed. Reason:"
                    )
                    raise
                except WorkflowEngineException:
                    # TODO: store the exceptions, to be shown if no workflow is recognized
                    self.logger.exception(
                        f"Engine {engineDesc.trs_descriptor} did not recognize the workflow as a valid one. Reason:"
                    )
            else:
                raise WFException(
                    f"No engine recognized a valid workflow at {self.repoURL} ({localWorkflow})"
                )
        else:
            self.logger.debug("Fixed engine " + self.engineDesc.trs_descriptor)
            engine = self.wfexs.instantiateEngine(self.engineDesc, self.staged_setup)
            engineVer, candidateLocalWorkflow = engine.identifyWorkflow(localWorkflow)
            if engineVer is None:
                raise WFException(
                    "Engine {} did not recognize a workflow at {}".format(
                        engine.workflowType.engineName, self.repoURL
                    )
                )

        enabled_profiles: "Optional[Sequence[str]]" = None
        if self.enabled_profiles is not None:
            enabled_profiles = self.enabled_profiles
        elif (
            self.staged_setup.workflow_config is not None
            and self.engineDesc is not None
        ):
            profiles: "Optional[Union[str, Sequence[str]]]" = (
                self.staged_setup.workflow_config.get(
                    self.engineDesc.engineName, {}
                ).get("profile")
            )
            if profiles is not None:
                if isinstance(profiles, list):
                    enabled_profiles = profiles
                elif isinstance(profiles, str):
                    split_by_comma = re.compile(r"[ \t]*,[ \t]*")
                    enabled_profiles = split_by_comma.split(profiles)
                else:
                    # It should not happen
                    enabled_profiles = [str(profiles)]

                # Backward <=> forward compatibility
                self.enabled_profiles = enabled_profiles

        self.engine = engine
        self.engineVer = engineVer
        self.localWorkflow = candidateLocalWorkflow

    def setupEngine(
        self,
        offline: "bool" = False,
        ignoreCache: "bool" = False,
        initial_engine_version: "Optional[EngineVersion]" = None,
        injectable_repo: "Optional[Tuple[RemoteRepo, WorkflowType]]" = None,
        injectable_workflow: "Optional[LocalWorkflow]" = None,
    ) -> None:
        # The engine is populated by self.fetchWorkflow()
        if self.engine is None:
            assert self.id is not None
            self.fetchWorkflow(
                self.id,
                self.version_id,
                self.trs_endpoint,
                self.descriptor_type,
                prefer_upstream_source=self.prefer_upstream_source,
                offline=offline,
                ignoreCache=ignoreCache,
                injectable_repo=injectable_repo,
                injectable_workflow=injectable_workflow,
            )

        assert (
            self.engine is not None
        ), "Workflow engine not properly identified or set up"

        # Process outputs now we have an engine
        if isinstance(self.outputs, dict):
            assert self.outputs_to_inject is not None
            outputs = list(self.outputs.values())
            if (len(outputs) == 0 and len(self.outputs_to_inject) == 0) or (
                len(outputs) > 0 and isinstance(outputs[0], ExpectedOutput)
            ):
                self.expected_outputs = outputs
            else:
                self.expected_outputs = self.parseExpectedOutputs(
                    self.outputs_to_inject,
                    self.outputs,
                    default_synthetic_output=not self.engine.HasExplicitOutputs(),
                )
        else:
            self.expected_outputs = None

        engine_version: "Optional[EngineVersion]"
        if self.materializedEngine is None:
            assert self.localWorkflow is not None
            localWorkflow = self.localWorkflow
            do_identify = True
            if initial_engine_version is not None:
                engine_version = initial_engine_version
            else:
                engine_version = self.engineVer
        else:
            localWorkflow = self.materializedEngine.workflow
            engine_version = self.materializedEngine.version
            do_identify = False

        # This is to avoid double initialization
        matWfEngV2 = self.engine.materializeEngine(
            localWorkflow,
            engineVersion=engine_version,
            do_identify=do_identify,
        )

        # At this point, there can be uninitialized elements
        if matWfEngV2 is not None:
            # We have to assure the reused version is the right one
            self.engineVer = matWfEngV2.version
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
        if matWfEngV2 is not None:
            self.logger.info(
                f"Engine {matWfEngV2.instance.__class__.__name__} version {matWfEngV2.version} being used"
            )
        else:
            self.logger.warning("No engine was selected (it may fail later)")

    def materializeWorkflowAndContainers(
        self,
        offline: "bool" = False,
        ignoreCache: "bool" = False,
        injectable_repo: "Optional[Tuple[RemoteRepo, WorkflowType]]" = None,
        injectable_workflow: "Optional[LocalWorkflow]" = None,
        injectable_containers: "Sequence[Container]" = [],
        injectable_operational_containers: "Sequence[Container]" = [],
        context_inputs: "Sequence[MaterializedInput]" = [],
        context_environment: "Sequence[MaterializedInput]" = [],
    ) -> None:
        if self.materializedEngine is None:
            # Only inject on first try
            self.setupEngine(
                offline=offline,
                initial_engine_version=self.engineVer,
                ignoreCache=ignoreCache,
                injectable_repo=injectable_repo,
                injectable_workflow=injectable_workflow,
            )

        assert (
            self.materializedEngine is not None
        ), "The materialized workflow engine should be available at this point"

        # This information is badly needed for provenance
        if self.materializedEngine.containers is None:
            assert (
                self.containersDir is not None
            ), "The destination directory should be available here"
            assert (
                self.consolidatedWorkflowDir is not None
            ), "The consolidated workflow directory should be available here"
            if not offline:
                self.containersDir.mkdir(parents=True, exist_ok=True)
            (
                self.materializedEngine,
                self.containerEngineVersion,
                self.containerEngineOs,
                self.arch,
            ) = WorkflowEngine.MaterializeWorkflowAndContainers(
                self.materializedEngine,
                self.containersDir,
                self.consolidatedWorkflowDir,
                offline=offline,
                injectable_containers=injectable_containers,
                injectable_operational_containers=injectable_operational_containers,
                profiles=self.enabled_profiles,
                context_inputs=context_inputs,
                context_environment=context_environment,
            )

    def materializeInputs(
        self,
        formatted_params: "Union[ParamsBlock, Sequence[Mapping[str, Any]]]",
        offline: "bool" = False,
        ignoreCache: "bool" = False,
        injectable_inputs: "Optional[Sequence[MaterializedInput]]" = None,
        lastInput: "int" = 0,
    ) -> "Sequence[MaterializedInput]":
        assert (
            self.inputsDir is not None
        ), "The working directory should not be corrupted beyond basic usage"
        assert (
            self.extrapolatedInputsDir is not None
        ), "The working directory should not be corrupted beyond basic usage"

        injectable_inputs_dict: "Mapping[str, MaterializedInput]"
        if injectable_inputs is not None and not ignoreCache:
            injectable_inputs_dict = {
                injectable_input.name: injectable_input
                for injectable_input in injectable_inputs
            }
        else:
            # Ignore injected inputs salvaged from elsewhere
            injectable_inputs_dict = dict()

        theParams, numInputs, the_failed_uris = self.fetchInputs(
            formatted_params,
            workflowInputs_destdir=self.inputsDir,
            workflowExtrapolatedInputs_destdir=self.extrapolatedInputsDir,
            offline=offline,
            ignoreCache=ignoreCache,
            injectable_inputs_dict=injectable_inputs_dict,
            lastInput=lastInput,
        )

        if len(the_failed_uris) > 0:
            self.logger.error(
                "Next URIs could not be downloaded. Maybe some kind of authentication is needed."
            )
            for failed_uri in the_failed_uris:
                self.logger.error(f"-> {failed_uri}")

            raise WFException(
                f"{len(the_failed_uris)} URIs could not be fetched. See log for details"
            )

        return theParams

    def _buildLicensedURI(
        self,
        remote_file_f: "Sch_InputURI_Fetchable",
        contextName: "Optional[str]" = None,
        licences: "Tuple[URIType, ...]" = DefaultNoLicenceTuple,
        attributions: "Sequence[Attribution]" = [],
    ) -> "Tuple[Union[LicensedURI, Sequence[LicensedURI]], bool]":
        was_simple = False
        if isinstance(remote_file_f, list):
            retvals = []
            for remote_url in remote_file_f:
                retval, this_was_simple = self._buildLicensedURI(
                    remote_url,
                    contextName=contextName,
                    licences=licences,
                    attributions=attributions,
                )
                was_simple |= this_was_simple
                if isinstance(retval, list):
                    retvals.extend(retval)
                else:
                    retvals.append(retval)

            return retvals, was_simple

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
            was_simple = True
            remote_url = remote_file_f

        secContext = self.vault.getContext(remote_url, contextName)

        return (
            LicensedURI(
                uri=remote_url,
                licences=licences,
                attributions=attributions,
                secContext=secContext,
            ),
            was_simple,
        )

    def _fetchRemoteFile(
        self,
        remote_file: "Sch_InputURI_Fetchable",
        contextName: "Optional[str]",
        offline: "bool",
        storeDir: "Union[pathlib.Path, CacheType]",
        cacheable: "bool",
        inputDestDir: "pathlib.Path",
        globExplode: "Optional[str]",
        prefix: "str" = "",
        hardenPrettyLocal: "bool" = False,
        prettyRelname: "Optional[RelPath]" = None,
        ignoreCache: "bool" = False,
        cloneToStore: "bool" = True,
    ) -> "Sequence[MaterializedContent]":
        # Embedding the context
        alt_remote_file, alt_is_plain = self._buildLicensedURI(
            remote_file, contextName=contextName
        )
        # Trying to preserve what it is returned by the cache
        # unless we are explicitly feeding a licence
        matContent = self.wfexs.downloadContent(
            alt_remote_file,
            dest=storeDir,
            offline=offline,
            vault=self.vault,
            ignoreCache=ignoreCache,
            registerInCache=cacheable,
            keep_cache_licence=alt_is_plain,
            default_clonable=cloneToStore,
        )

        # Now, time to create the link
        if prettyRelname is None:
            prettyRelname = matContent.prettyFilename

        prettyLocal = inputDestDir / prettyRelname

        # Protection against misbehaviours which could hijack the
        # execution environment
        realPrettyLocal = prettyLocal.resolve()
        realInputDestDir = inputDestDir.resolve()
        # Path.is_relative_to was introduced in Python 3.9
        # if not realPrettyLocal.is_relative_to(realInputDestDir):
        common_path = pathlib.Path(
            os.path.commonpath([realPrettyLocal, realInputDestDir])
        )
        if realInputDestDir != common_path:
            prettyRelname = cast("RelPath", realPrettyLocal.name)
            prettyLocal = inputDestDir / prettyRelname

        # Checking whether local name hardening is needed
        if not hardenPrettyLocal:
            if prettyLocal.is_symlink():
                # Path.readlink was added in Python 3.9
                oldLocal = pathlib.Path(os.readlink(prettyLocal))

                hardenPrettyLocal = oldLocal != matContent.local
            elif prettyLocal.exists():
                hardenPrettyLocal = True

        if hardenPrettyLocal:
            # Trying to avoid collisions on input naming
            prettyLocal = inputDestDir / (prefix + prettyRelname)

        if not prettyLocal.exists():
            # Are we allowed to make a copy of the input in the working directory?
            if matContent.clonable:
                # We are either hardlinking or copying here
                link_or_copy_pathlib(matContent.local, prettyLocal)
            else:
                # We are either hardlinking or symlinking here
                link_or_symlink_pathlib(matContent.local, prettyLocal)

        remote_pairs = []
        if globExplode is not None:
            prettyLocalPath = prettyLocal
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
                        local=exp,
                        licensed_uri=lic_expUri,
                        prettyFilename=relName,
                        metadata_array=matContent.metadata_array,
                        kind=ContentKind.Directory
                        if exp.is_dir()
                        else ContentKind.File,
                        # Lazy evaluation of fingerprint,
                        # so do not compute it here
                    )
                )
        else:
            remote_pair = MaterializedContent(
                local=prettyLocal,
                licensed_uri=matContent.licensed_uri,
                prettyFilename=prettyRelname,
                kind=matContent.kind,
                metadata_array=matContent.metadata_array,
                fingerprint=matContent.fingerprint,
            )
            remote_pairs.append(remote_pair)

        return remote_pairs

    def _formatStringFromPlaceHolders(
        self, the_string: "str", placeholders: "Optional[PlaceHoldersBlock]" = None
    ) -> "str":
        # Default placeholders are workflow level ones
        if placeholders is None:
            placeholders = self.placeholders

        i_l_the_string = the_string.find("{")
        i_r_the_string = the_string.find("}")
        if (
            i_l_the_string != -1
            and i_r_the_string != -1
            and i_l_the_string < i_r_the_string
        ):
            try:
                """
                This is inspired in the example available at
                https://docs.python.org/3/library/stdtypes.html#str.format_map
                """
                the_string = the_string.format_map(DefaultMissing(placeholders))
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
    ) -> "Tuple[Optional[ParamsBlock] , Optional[Sequence[Sch_Output]]]":
        if params is None:
            return None, None

        outputs_to_inject: "MutableSequence[Sch_Output]" = []
        formatted_params: "MutableParamsBlock" = dict()
        some_formatted = False
        for key, raw_inputs in params.items():
            # We are here for the
            linearKey = prefix + key
            if isinstance(raw_inputs, dict):
                inputs = cast("Sch_Param", raw_inputs)
                inputClass = inputs.get("c-l-a-s-s")
                if inputClass is not None:
                    if inputClass not in (
                        ContentKind.File.name,
                        ContentKind.Directory.name,
                        ContentKind.Value.name,
                        ContentKind.ContentWithURIs.name,
                    ):
                        raise WFException(
                            'Unrecognized input class "{}", attached to "{}"'.format(
                                inputClass, linearKey
                            )
                        )

                    prefrel_formatted = False
                    formatted_preferred_name_conf: "Optional[Union[str, Literal[False]]]" = (
                        None
                    )
                    formatted_reldir_conf: "Optional[Union[str, Literal[False]]]" = None
                    if inputClass in (
                        ContentKind.File.name,
                        ContentKind.Directory.name,
                        ContentKind.ContentWithURIs.name,
                    ):
                        # These parameters can be used both for input placement tuning
                        # as well for output placement
                        preferred_name_conf = inputs.get("preferred-name")
                        if isinstance(preferred_name_conf, str):
                            formatted_preferred_name_conf = (
                                self._formatStringFromPlaceHolders(preferred_name_conf)
                            )
                            if preferred_name_conf != formatted_preferred_name_conf:
                                prefrel_formatted = True
                        else:
                            formatted_preferred_name_conf = preferred_name_conf

                        reldir_conf = inputs.get("relative-dir")
                        if isinstance(reldir_conf, str):
                            formatted_reldir_conf = self._formatStringFromPlaceHolders(
                                reldir_conf
                            )
                            if reldir_conf != formatted_reldir_conf:
                                prefrel_formatted = True
                        else:
                            formatted_reldir_conf = reldir_conf

                    if inputClass in (
                        ContentKind.File.name,
                        ContentKind.Directory.name,
                    ):
                        # input files
                        # We have to autofill this with the outputs directory,
                        # so results are properly stored (without escaping the jail)
                        if inputs.get("autoFill", False):
                            if prefrel_formatted:
                                some_formatted = True
                                formatted_inputs = copy.copy(inputs)
                                if formatted_preferred_name_conf is not None:
                                    formatted_inputs[
                                        "preferred-name"
                                    ] = formatted_preferred_name_conf
                                if formatted_reldir_conf is not None:
                                    formatted_inputs[
                                        "relative-dir"
                                    ] = formatted_reldir_conf
                            else:
                                formatted_inputs = inputs
                            formatted_params[key] = formatted_inputs

                            # Inject as an output
                            outputs_to_inject.append(
                                {
                                    "c-l-a-s-s": inputClass,
                                    "cardinality": 1,
                                    "fillFrom": linearKey,
                                    "syntheticOutput": False,
                                }
                            )
                            continue

                        if inputClass == ContentKind.Directory.name:
                            globExplode = inputs.get("globExplode")

                    # Processing url and secondary-urls
                    if ("url" in inputs) and (
                        inputClass
                        in (
                            ContentKind.File.name,
                            ContentKind.Directory.name,
                            ContentKind.ContentWithURIs.name,
                        )
                    ):
                        # input files
                        was_formatted = prefrel_formatted

                        remote_files: "Sch_InputURI" = inputs["url"]
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

                        # Something has to be changed
                        if was_formatted:
                            some_formatted = True
                            formatted_inputs = copy.copy(inputs)
                            assert formatted_remote_files is not None
                            formatted_inputs["url"] = formatted_remote_files
                            if "secondary-urls" in inputs:
                                assert formatted_secondary_remote_files is not None
                                formatted_inputs[
                                    "secondary-urls"
                                ] = formatted_secondary_remote_files
                            if formatted_preferred_name_conf is not None:
                                formatted_inputs[
                                    "preferred-name"
                                ] = formatted_preferred_name_conf
                            if formatted_reldir_conf is not None:
                                formatted_inputs["relative-dir"] = formatted_reldir_conf
                        else:
                            formatted_inputs = inputs

                        formatted_params[key] = formatted_inputs

                    # Processing value contents
                    if ("value" in inputs) and (
                        inputClass
                        in (
                            ContentKind.File.name,
                            ContentKind.Value.name,
                            ContentKind.ContentWithURIs.name,
                        )
                    ):
                        # It could have been fixed by previous step
                        val_inputs: "Union[str, Sequence[str]]"
                        if key in formatted_params:
                            val_inputs = formatted_params[key]["value"]
                        else:
                            val_inputs = inputs["value"]

                        formatted_val_inputs = val_inputs
                        if isinstance(val_inputs, list):
                            if len(val_inputs) > 0 and isinstance(val_inputs[0], str):
                                formatted_inputs_l = []
                                did_change = False
                                for val_input in val_inputs:
                                    formatted_input = (
                                        self._formatStringFromPlaceHolders(val_input)
                                    )
                                    formatted_inputs_l.append(formatted_input)
                                    if formatted_input != val_input:
                                        did_change = True
                                        some_formatted = True

                                if did_change:
                                    formatted_val_inputs = formatted_inputs_l
                        elif isinstance(val_inputs, str):
                            formatted_input = self._formatStringFromPlaceHolders(
                                val_inputs
                            )
                            if val_inputs != formatted_input:
                                formatted_val_inputs = formatted_input

                        # Last, copy only when needed
                        if formatted_val_inputs != val_inputs:
                            formatted_inputs = copy.copy(
                                formatted_params[key]
                                if key in formatted_params
                                else inputs
                            )
                            formatted_inputs["value"] = formatted_val_inputs

                            formatted_params[key] = formatted_inputs
                        elif key not in formatted_params:
                            formatted_params[key] = inputs

                else:
                    # possible nested files
                    (
                        formatted_inputs_nested,
                        child_outputs_to_inject,
                    ) = self.formatParams(
                        cast("ParamsBlock", inputs), prefix=linearKey + "."
                    )
                    if inputs != formatted_inputs_nested:
                        some_formatted = True
                    formatted_params[key] = formatted_inputs_nested
                    # Propagate the outputs to inject
                    if isinstance(child_outputs_to_inject, list):
                        outputs_to_inject.extend(child_outputs_to_inject)
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

        return formatted_params if some_formatted else params, outputs_to_inject

    def _fetchContentWithURIs(
        self,
        inputs: "ParamsBlock",
        linearKey: "SymbolicParamName",
        workflowInputs_destdir: "pathlib.Path",
        workflowExtrapolatedInputs_destdir: "pathlib.Path",
        lastInput: "int" = 0,
        offline: "bool" = False,
        ignoreCache: "bool" = False,
        cloneToStore: "bool" = True,
    ) -> "Tuple[Sequence[MaterializedInput], int, Sequence[str]]":
        # Current code for ContentWithURIs is only implemented for
        # tabular contents
        config_key = "tabular"

        tabconf = inputs.get(config_key)
        encoding_format = ContentWithURIsMIMEs.get(config_key)
        if not isinstance(tabconf, dict) or not isinstance(encoding_format, str):
            raise WFException(
                f"Content with uris {linearKey} must have a declaration of these types: {', '.join(ContentWithURIsMIMEs.keys())}"
            )

        t_newline: "str" = (
            tabconf.get("row-sep", "\\n").encode("utf-8").decode("unicode-escape")
        )
        t_skiplines: "int" = tabconf.get("header-rows", 0)
        t_split = tabconf["column-sep"].encode("utf-8").decode("unicode-escape")
        t_uri_cols: "Sequence[int]" = tabconf["uri-columns"]

        inputDestDir = pathlib.Path(workflowInputs_destdir)
        extrapolatedInputDestDir = pathlib.Path(workflowExtrapolatedInputs_destdir)

        path_tokens = linearKey.split(".")
        # Filling in the defaults
        assert len(path_tokens) >= 1
        pretty_relname: "Optional[RelPath]" = cast("RelPath", path_tokens[-1])
        if len(path_tokens) > 1:
            relative_dir = os.path.join(*path_tokens[0:-1])
        else:
            relative_dir = None

        remote_files: "Optional[Sch_InputURI]" = inputs.get("url")
        inline_values: "Optional[Union[str, Sequence[str]]]" = inputs.get("value")
        # It has to exist
        assert (remote_files is not None) or (inline_values is not None)

        secondary_remote_files: "Sch_InputURI" = []

        # We are sending the context name thinking in the future,
        # as it could contain potential hints for authenticated access
        contextName = inputs.get("security-context")
        # This is only for the paranoid mode
        cacheable = inputs.get("cacheable", True)
        if self.paranoidMode:
            ignoreCache = False

        if not cacheable and not cloneToStore:
            self.logger.warning(
                "Current staging scenario can lead to unexpected errors in case of cache miss, as neither caching nor cloning are allowed"
            )

        if remote_files is not None:
            this_ignoreCache = ignoreCache
        else:
            this_ignoreCache = True

        preferred_name_conf = cast("Optional[RelPath]", inputs.get("preferred-name"))
        if isinstance(preferred_name_conf, str):
            pretty_relname = preferred_name_conf

        # Setting up the relative dir preference
        reldir_conf = inputs.get("relative-dir")
        if isinstance(reldir_conf, str):
            relative_dir = reldir_conf
        elif not reldir_conf:
            # Remove the pre-computed relative dir
            relative_dir = None

        if relative_dir is not None:
            newInputDestDir = (inputDestDir / relative_dir).resolve()
            # Path.is_relative_to was introduced in Python 3.9
            # if newInputDestDir.is_relative_to(inputDestDir):
            common_path = pathlib.Path(
                os.path.commonpath([newInputDestDir, inputDestDir])
            )
            if common_path == inputDestDir:
                inputDestDir = newInputDestDir
                extrapolatedInputDestDir = (
                    extrapolatedInputDestDir / relative_dir
                ).resolve()

        # The storage dir depends on whether it can be cloned or not
        storeDir: "Union[CacheType, pathlib.Path]" = (
            CacheType.Input if cacheable else workflowInputs_destdir
        )

        remote_files_f: "Sequence[Sch_InputURI_Fetchable]"
        if remote_files is not None:
            if isinstance(remote_files, list):  # more than one input file
                remote_files_f = remote_files
            else:
                remote_files_f = [cast("Sch_InputURI_Fetchable", remote_files)]
        else:
            inline_values_l: "Sequence[str]"
            if isinstance(inline_values, list):
                # more than one inline content
                inline_values_l = inline_values
            else:
                inline_values_l = [cast("str", inline_values)]

            remote_files_f = [
                # The storage dir is always the input
                # Let's use the trick of translating the content into a data URL
                bin2dataurl(inline_value.encode("utf-8"))
                for inline_value in inline_values_l
            ]

        # Fetch and process the files with the URIs to be processed
        theNewInputs: "MutableSequence[MaterializedInput]" = []
        the_failed_uris: "MutableSequence[str]" = []
        for remote_file in remote_files_f:
            lastInput += 1
            try:
                t_remote_pairs = self._fetchRemoteFile(
                    remote_file,
                    contextName,
                    offline,
                    storeDir,
                    cacheable=cacheable,
                    inputDestDir=inputDestDir,
                    globExplode=None,
                    prefix=str(lastInput) + "_",
                    prettyRelname=pretty_relname,
                    ignoreCache=this_ignoreCache,
                    cloneToStore=cloneToStore,
                )
            except:
                self.logger.exception(
                    f"Error while fetching primary content with URIs {remote_file}"
                )
                the_failed_uris.append(remote_file)

            # Time to process each file
            these_secondary_uris: "Set[str]" = set()
            remote_pairs: "MutableSequence[MaterializedContent]" = []
            for t_remote_pair in t_remote_pairs:
                remote_pairs.append(t_remote_pair)

                with t_remote_pair.local.open(
                    mode="rt",
                    encoding="utf-8",
                    newline=t_newline,
                ) as tH:
                    skiplines = t_skiplines
                    for line in tH:
                        # Skipping first header lines
                        if skiplines > 0:
                            skiplines -= 1
                            continue

                        # Removing the newline, as it can ruin everything
                        if line.endswith(t_newline):
                            line = line[: -len(t_newline)]

                        cols = line.split(t_split, -1)
                        for t_uri_col in t_uri_cols:
                            if t_uri_col < len(cols) and len(cols[t_uri_col]) > 0:
                                # Should we check whether it is a URI?
                                these_secondary_uris.add(cols[t_uri_col])

            secondary_remote_pairs: "Optional[MutableSequence[MaterializedContent]]"
            if len(these_secondary_uris) > 0:
                secondary_uri_mapping: "MutableMapping[str, pathlib.Path]" = dict()
                secondary_remote_pairs = []
                # Fetch each gathered URI
                for secondary_remote_file in these_secondary_uris:
                    # The last fetched content prefix is the one used
                    # for all the secondaries
                    try:
                        t_secondary_remote_pairs = self._fetchRemoteFile(
                            cast("URIType", secondary_remote_file),
                            contextName,
                            offline,
                            storeDir,
                            cacheable,
                            inputDestDir,
                            globExplode=None,
                            prefix=str(lastInput) + "_",
                            ignoreCache=this_ignoreCache,
                            cloneToStore=cloneToStore,
                        )
                    except:
                        self.logger.exception(
                            f"Error while fetching secondary content with URIs {secondary_remote_file}"
                        )
                        the_failed_uris.append(secondary_remote_file)

                    # Rescuing the correspondence to be used later
                    for t_secondary_remote_pair in t_secondary_remote_pairs:
                        secondary_remote_pairs.append(t_secondary_remote_pair)
                        if (
                            t_secondary_remote_pair.licensed_uri.uri
                            in these_secondary_uris
                        ):
                            mapping_key = t_secondary_remote_pair.licensed_uri.uri
                        else:
                            mapping_key = cast("URIType", secondary_remote_file)

                        secondary_uri_mapping[
                            mapping_key
                        ] = t_secondary_remote_pair.local

                # Now, reopen each file to replace URLs by paths
                for i_remote_pair, remote_pair in enumerate(remote_pairs):
                    extrapolated_local = extrapolatedInputDestDir / os.path.relpath(
                        remote_pair.local, inputDestDir
                    )
                    with remote_pair.local.open(
                        mode="rt",
                        encoding="utf-8",
                        newline=t_newline,
                    ) as tH:
                        with extrapolated_local.open(
                            mode="wt",
                            encoding="utf-8",
                            newline=t_newline,
                        ) as tW:
                            skiplines = t_skiplines
                            for line in tH:
                                # Skipping first header lines
                                if skiplines > 0:
                                    tW.write(line)
                                    skiplines -= 1
                                    continue

                                if line.endswith(t_newline):
                                    line = line[: -len(t_newline)]

                                cols = line.split(t_split, -1)
                                # Patching each column
                                fixed_row = False
                                for t_uri_col in t_uri_cols:
                                    if (
                                        t_uri_col < len(cols)
                                        and len(cols[t_uri_col]) > 0
                                    ):
                                        # Should we check whether it is a URI?
                                        cols[t_uri_col] = secondary_uri_mapping[
                                            cols[t_uri_col]
                                        ].as_posix()
                                        fixed_row = True

                                if fixed_row:
                                    print(t_split.join(cols), file=tW)
                                else:
                                    print(line, file=tW)

                    # Last, fix it
                    remote_pairs[i_remote_pair] = remote_pair._replace(
                        kind=ContentKind.ContentWithURIs,
                        extrapolated_local=extrapolated_local,
                    )
            else:
                secondary_remote_pairs = None

            # If more than one URI is provided, due some limitations more
            # than one MaterializedInput instance is emitted associated to
            # the very same linearKey. Each one of them will be represented
            # as a collection in the generated Workflow Run RO-Crate
            theNewInputs.append(
                MaterializedInput(
                    name=linearKey,
                    values=remote_pairs,
                    secondaryInputs=secondary_remote_pairs,
                    contentWithURIs=ContentWithURIsDesc(
                        encodingFormat=encoding_format,
                        setup={
                            "headerRows": t_skiplines,
                            "rowSep": t_newline,
                            "columnSep": t_split,
                            "uriColumns": t_uri_cols,
                        },
                    ),
                    disclosable=inputs.get("disclosable", True),
                )
            )

        return theNewInputs, lastInput, the_failed_uris

    def _injectContent(
        self,
        injectable_content: "Sequence[MaterializedContent]",
        dest_path: "pathlib.Path",
        pretty_relname: "Optional[str]",
        last_input: "int" = 1,
    ) -> "Tuple[MutableSequence[MaterializedContent], int]":
        injected_content: "MutableSequence[MaterializedContent]" = []
        for injectable in injectable_content:
            # Detecting naming collisions
            pretty_filename = injectable.prettyFilename
            pretty_rel = pathlib.Path(pretty_filename)
            dest_content = dest_path / pretty_rel
            if dest_content.exists() and pretty_relname is not None:
                dest_content = dest_path / pretty_relname

            # Stay here while collisions happen
            while dest_content.exists():
                prefix = str(last_input) + "_"
                dest_content = dest_path / pretty_rel.with_name(
                    prefix + pretty_rel.name
                )
                last_input += 1

            # Transfer it
            dest_content.parent.mkdir(parents=True, exist_ok=True)
            link_or_copy_pathlib(injectable.local, dest_content, force_copy=True)
            # Second, record it
            injected_content.append(
                MaterializedContent(
                    local=dest_content,
                    licensed_uri=injectable.licensed_uri,
                    prettyFilename=pretty_filename,
                    kind=injectable.kind,
                    metadata_array=injectable.metadata_array,
                    fingerprint=injectable.fingerprint,
                )
            )

        return injected_content, last_input

    def fetchInputs(
        self,
        params: "Union[ParamsBlock, Sequence[ParamsBlock]]",
        workflowInputs_destdir: "pathlib.Path",
        workflowExtrapolatedInputs_destdir: "pathlib.Path",
        prefix: "str" = "",
        injectable_inputs_dict: "Mapping[str, MaterializedInput]" = {},
        lastInput: "int" = 0,
        offline: "bool" = False,
        ignoreCache: "bool" = False,
    ) -> "Tuple[Sequence[MaterializedInput], int, Sequence[str]]":
        """
        Fetch the input files for the workflow execution.
        All the inputs must be URLs or CURIEs from identifiers.org / n2t.net.

        :param params: Optional params for the workflow execution.
        :param workflowInputs_destdir:
        :param workflowExtrapolatedInputs_destdir:
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

        the_failed_uris: "MutableSequence[str]" = []

        paramsIter: "Iterable[Tuple[Union[str, int], Any]]" = (
            params.items() if isinstance(params, dict) else enumerate(params)
        )
        for key, inputs in paramsIter:
            # We are here for the
            linearKey = cast("SymbolicParamName", prefix + str(key))
            if isinstance(inputs, dict):
                inputClass = inputs.get("c-l-a-s-s")
                if inputClass is not None:
                    clonable = inputs.get("clonable", True)
                    if inputClass in (
                        ContentKind.File.name,
                        ContentKind.Directory.name,
                    ):  # input files
                        inputDestDir = pathlib.Path(workflowInputs_destdir)
                        globExplode = None

                        path_tokens = linearKey.split(".")
                        # Filling in the defaults
                        assert len(path_tokens) >= 1
                        pretty_relname: "Optional[RelPath]" = cast(
                            "RelPath", path_tokens[-1]
                        )
                        if len(path_tokens) > 1:
                            relative_dir = os.path.join(*path_tokens[0:-1])
                        else:
                            relative_dir = None

                        if inputClass == ContentKind.Directory.name:
                            # We have to autofill this with the outputs directory,
                            # so results are properly stored (without escaping the jail)
                            if inputs.get("autoFill", False):
                                relative_dir = inputs.get("relative-dir")
                                preferred_name = inputs.get("preferred-name")
                                auto_prefix = inputs.get("autoPrefix", True)
                                if (
                                    relative_dir is not None
                                    or preferred_name is not None
                                ):
                                    auto_prefix = True

                                if auto_prefix:
                                    if relative_dir is not None:
                                        rel_auto_filled = relative_dir
                                    else:
                                        rel_auto_filled = ""
                                    if preferred_name is not None:
                                        the_tokens = [preferred_name]
                                    else:
                                        the_tokens = path_tokens
                                    # We cannot use an absolute path because
                                    # each run has its own output directory!!!
                                    autoFilledDir = os.path.join(
                                        rel_auto_filled, *the_tokens
                                    )
                                else:
                                    autoFilledDir = ""

                                theInputs.append(
                                    MaterializedInput(
                                        name=linearKey,
                                        values=[autoFilledDir],
                                        autoFilled=True,
                                        # What it is autofilled is probably
                                        # an output, so it should not be
                                        # automatically disclosable
                                        disclosable=False,
                                    )
                                )
                                continue

                            globExplode = inputs.get("globExplode")
                        elif inputClass == ContentKind.File.name and inputs.get(
                            "autoFill", False
                        ):
                            relative_dir = inputs.get("relative-dir")
                            preferred_name = inputs.get("preferred-name")
                            if relative_dir is not None:
                                rel_auto_filled = relative_dir
                            else:
                                rel_auto_filled = ""
                            if preferred_name is not None:
                                the_tokens = [preferred_name]
                            else:
                                the_tokens = path_tokens

                            # We have to autofill this with the outputs directory,
                            # so results are properly stored (without escaping the jail)
                            autoFilledFile = pathlib.Path(
                                self.outputsDir, rel_auto_filled, *the_tokens
                            )
                            autoFilledDir = autoFilledFile.parent
                            # This is needed to assure the path exists
                            if not autoFilledDir.samefile(self.outputsDir):
                                autoFilledDir.mkdir(parents=True, exist_ok=True)

                            theInputs.append(
                                MaterializedInput(
                                    name=linearKey,
                                    # TODO: do it in a more elegant way
                                    values=[autoFilledFile.as_posix()],
                                    autoFilled=True,
                                    # What it is autofilled is probably
                                    # an output, so it should not be
                                    # automatically disclosable
                                    disclosable=False,
                                )
                            )
                            continue

                        remote_files: "Optional[Sch_InputURI]" = inputs.get("url")
                        inline_values: "Optional[Union[str, Sequence[str]]]" = (
                            inputs.get("value")
                        )
                        # It has to exist
                        if remote_files is not None or (
                            inputClass == ContentKind.File.name
                            and (inline_values is not None)
                        ):
                            secondary_remote_files: "Optional[Sch_InputURI]"
                            if remote_files is not None:
                                # We are sending the context name thinking in the future,
                                # as it could contain potential hints for authenticated access
                                contextName = inputs.get("security-context")

                                secondary_remote_files = inputs.get("secondary-urls")
                                cacheable = inputs.get("cacheable", True)
                                this_ignoreCache = (
                                    False if self.paranoidMode else ignoreCache
                                )
                            else:
                                contextName = None
                                secondary_remote_files = None
                                cacheable = False
                                this_ignoreCache = True

                            preferred_name_conf = inputs.get("preferred-name")
                            if isinstance(preferred_name_conf, str):
                                pretty_relname = cast("RelPath", preferred_name_conf)
                            elif not preferred_name_conf:
                                # Remove the pre-computed relative dir
                                pretty_relname = None

                            # Setting up the relative dir preference
                            reldir_conf = inputs.get("relative-dir")
                            if isinstance(reldir_conf, str):
                                relative_dir = reldir_conf
                            elif not reldir_conf:
                                # Remove the pre-computed relative dir
                                relative_dir = None

                            if relative_dir is not None:
                                newInputDestDir = (
                                    inputDestDir / relative_dir
                                ).resolve()
                                if newInputDestDir.relative_to(inputDestDir):
                                    inputDestDir = newInputDestDir

                            remote_pairs: "MutableSequence[MaterializedContent]" = []
                            secondary_remote_pairs: "Optional[MutableSequence[MaterializedContent]]" = (
                                None
                            )

                            injectable_input = injectable_inputs_dict.get(linearKey)
                            if (
                                injectable_input is not None
                                and len(injectable_input.values) > 0
                            ):
                                # Input being injected
                                remote_pairs, lastInput = self._injectContent(
                                    cast(
                                        "Sequence[MaterializedContent]",
                                        injectable_input.values,
                                    ),
                                    inputDestDir,
                                    last_input=lastInput,
                                    pretty_relname=pretty_relname,
                                )

                            if len(remote_pairs) == 0:
                                # No injected content
                                # The storage dir depends on whether it can be cached or not
                                storeDir: "Union[CacheType, pathlib.Path]" = (
                                    CacheType.Input
                                    if cacheable
                                    else workflowInputs_destdir
                                )

                                remote_files_f: "Sequence[Sch_InputURI_Fetchable]"
                                if remote_files is not None:
                                    if isinstance(
                                        remote_files, list
                                    ):  # more than one input file
                                        remote_files_f = remote_files
                                    else:
                                        remote_files_f = [
                                            cast("Sch_InputURI_Fetchable", remote_files)
                                        ]
                                else:
                                    inline_values_l: "Sequence[str]"
                                    if isinstance(inline_values, list):
                                        # more than one inline content
                                        inline_values_l = inline_values
                                    else:
                                        inline_values_l = [cast("str", inline_values)]

                                    remote_files_f = [
                                        # The storage dir is always the input
                                        # Let's use the trick of translating the content into a data URL
                                        bin2dataurl(inline_value.encode("utf-8"))
                                        for inline_value in inline_values_l
                                    ]

                                for remote_file in remote_files_f:
                                    lastInput += 1
                                    try:
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
                                            ignoreCache=this_ignoreCache,
                                            cloneToStore=clonable,
                                        )
                                        remote_pairs.extend(t_remote_pairs)
                                    except:
                                        self.logger.exception(
                                            f"Error while fetching primary URI {remote_file}"
                                        )
                                        the_failed_uris.append(remote_file)

                                if (remote_files is not None) and (
                                    secondary_remote_files is not None
                                ):
                                    secondary_remote_files_f: "Sequence[Sch_InputURI_Fetchable]"
                                    if isinstance(
                                        secondary_remote_files, list
                                    ):  # more than one input file
                                        secondary_remote_files_f = (
                                            secondary_remote_files
                                        )
                                    else:
                                        secondary_remote_files_f = [
                                            cast(
                                                "Sch_InputURI_Fetchable",
                                                secondary_remote_files,
                                            )
                                        ]

                                    secondary_remote_pairs = []
                                    for (
                                        secondary_remote_file
                                    ) in secondary_remote_files_f:
                                        # The last fetched content prefix is the one used
                                        # for all the secondaries
                                        try:
                                            t_secondary_remote_pairs = (
                                                self._fetchRemoteFile(
                                                    secondary_remote_file,
                                                    contextName,
                                                    offline,
                                                    storeDir,
                                                    cacheable,
                                                    inputDestDir,
                                                    globExplode,
                                                    prefix=str(lastInput) + "_",
                                                    ignoreCache=this_ignoreCache,
                                                    cloneToStore=clonable,
                                                )
                                            )
                                            secondary_remote_pairs.extend(
                                                t_secondary_remote_pairs
                                            )
                                        except:
                                            self.logger.exception(
                                                f"Error while fetching secondary URI {secondary_remote_file}"
                                            )
                                            the_failed_uris.append(
                                                secondary_remote_file
                                            )

                            theInputs.append(
                                MaterializedInput(
                                    name=linearKey,
                                    values=remote_pairs,
                                    secondaryInputs=secondary_remote_pairs,
                                    disclosable=inputs.get("disclosable", True),
                                )
                            )
                        else:
                            if inputClass == ContentKind.File.name:
                                # Empty input, i.e. empty file
                                inputDestPath = inputDestDir.joinpath(
                                    *linearKey.split(".")
                                )
                                inputDestPath.parent.mkdir(parents=True, exist_ok=True)
                                # Creating the empty file
                                inputDestPath.touch()
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
                                                inputDestPath.name,
                                            ),
                                            kind=contentKind,
                                        )
                                    ],
                                    disclosable=inputs.get("disclosable", True),
                                )
                            )

                    elif inputClass == ContentKind.ContentWithURIs.name:
                        this_ignoreCache = False if self.paranoidMode else ignoreCache
                        (
                            theNewInputs,
                            lastInput,
                            new_failed_uris,
                        ) = self._fetchContentWithURIs(
                            inputs,
                            linearKey,
                            workflowInputs_destdir,
                            workflowExtrapolatedInputs_destdir,
                            lastInput=lastInput,
                            offline=offline,
                            ignoreCache=this_ignoreCache,
                            cloneToStore=clonable,
                        )
                        theInputs.extend(theNewInputs)
                        the_failed_uris.extend(new_failed_uris)
                    elif inputClass == ContentKind.Value.name:
                        input_val = inputs.get("value")
                        if input_val is None:
                            raise WFException(f"Value {linearKey} cannot be null")

                        if not isinstance(input_val, list):
                            input_val = [input_val]
                        theInputs.append(
                            MaterializedInput(
                                name=linearKey,
                                values=input_val,
                                disclosable=inputs.get("disclosable", True),
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
                    newInputsAndParams, lastInput, new_failed_uris = self.fetchInputs(
                        inputs,
                        workflowInputs_destdir=workflowInputs_destdir,
                        workflowExtrapolatedInputs_destdir=workflowExtrapolatedInputs_destdir,
                        prefix=linearKey + ".",
                        lastInput=lastInput,
                        injectable_inputs_dict=injectable_inputs_dict,
                        offline=offline,
                        ignoreCache=ignoreCache,
                    )
                    theInputs.extend(newInputsAndParams)
                    the_failed_uris.extend(new_failed_uris)
            else:
                if not isinstance(inputs, list):
                    inputs = [inputs]
                theInputs.append(
                    MaterializedInput(
                        name=linearKey,
                        values=inputs,
                        disclosable=True,
                    )
                )

        return theInputs, lastInput, the_failed_uris

    def tryStageWorkflow(
        self, offline: "bool" = False, ignoreCache: "bool" = False
    ) -> "StagedSetup":
        """
        This method is here to try materializing and identifying a workflow
        """

        # Inputs should be materialized before materializing the workflow itself
        # because some workflow systems could need them in order to describe
        # some its internal details.
        #
        # But as we are trying to materialize a bare workflow, no input
        # is going to be provided

        # This method is called from within setupEngine
        # self.fetchWorkflow(self.id, self.version_id, self.trs_endpoint, self.descriptor_type)
        # This method is called from within materializeWorkflowAndContainers
        # self.setupEngine(offline=offline)
        self.materializeWorkflowAndContainers(
            offline=offline,
            ignoreCache=ignoreCache,
        )

        self.marshallStage()

        return self.getStagedSetup()

    def stageWorkDir(
        self, offline: "bool" = False, ignoreCache: "bool" = False
    ) -> "StagedSetup":
        """
        This method is here to simplify the understanding of the needed steps
        """

        # Inputs are materialized before materializing the workflow itself
        # because some workflow systems could need them in order to describe
        # some its internal details.
        assert self.formatted_params is not None
        self.materializedParams = self.materializeInputs(
            self.formatted_params,
            offline=offline,
            ignoreCache=ignoreCache,
            injectable_inputs=self.cached_inputs
            if self.reproducibility_level >= ReproducibilityLevel.Metadata
            else None,
        )

        assert self.formatted_environment is not None
        self.materializedEnvironment = self.materializeInputs(
            self.formatted_environment,
            offline=offline,
            ignoreCache=ignoreCache,
            injectable_inputs=self.cached_environment
            if self.reproducibility_level >= ReproducibilityLevel.Metadata
            else None,
        )

        # This method is called from within setupEngine
        # self.fetchWorkflow(self.id, self.version_id, self.trs_endpoint, self.descriptor_type)
        # This method is called from within materializeWorkflowAndContainers
        # self.setupEngine(offline=offline)
        self.materializeWorkflowAndContainers(
            offline=offline,
            ignoreCache=ignoreCache,
            injectable_repo=self.cached_repo
            if self.reproducibility_level >= ReproducibilityLevel.Metadata
            else None,
            injectable_workflow=self.cached_workflow
            if self.reproducibility_level >= ReproducibilityLevel.Full
            else None,
            injectable_containers=self.preferred_containers
            if self.reproducibility_level >= ReproducibilityLevel.Metadata
            else [],
            injectable_operational_containers=self.preferred_operational_containers
            if self.reproducibility_level >= ReproducibilityLevel.Metadata
            else [],
            context_inputs=self.materializedParams,
            context_environment=self.materializedEnvironment,
        )

        self.marshallStage()

        return self.getStagedSetup()

    def workdirToBagit(self) -> "bagit.Bag":
        """
        BEWARE: This is a destructive step! So, once run, there is no back!
        """
        assert self.workDir is not None
        return bagit.make_bag(self.workDir.as_posix())

    DefaultCardinality = "1"
    CardinalityMapping: "Mapping[str, Tuple[int, int]]" = {
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
        self,
        outputs_to_inject: "Sequence[Sch_Output]",
        outputs: "Union[Sequence[Sch_Output], Mapping[str, Sch_Output]]",
        default_synthetic_output: "bool",
    ) -> "Sequence[ExpectedOutput]":
        expectedOutputs = []
        known_outputs: "Set[str]" = set()

        outputs_to_process: "MutableSequence[Tuple[str, Sch_Output]]" = []
        for output_to_inject in outputs_to_inject:
            fill_from = output_to_inject.get("fillFrom")
            assert isinstance(fill_from, str)
            if fill_from not in known_outputs:
                known_outputs.add(fill_from)
                outputs_to_process.append((fill_from, output_to_inject))

        # TODO: implement parsing of outputs
        outputsIter = cast(
            "Iterable[Tuple[Union[str, int], Sch_Output]]",
            outputs.items() if isinstance(outputs, dict) else enumerate(outputs),
        )

        for outputKey, outputDesc in outputsIter:
            # Skip already injected
            outputKeyStr = str(outputKey)
            if outputKeyStr not in known_outputs:
                known_outputs.add(outputKeyStr)
                outputs_to_process.append((outputKeyStr, outputDesc))

        for output_name, outputDesc in outputs_to_process:
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
                elif isinstance(cardS, str):
                    cardinality = self.CardinalityMapping.get(cardS)
                else:
                    raise WFException("Unimplemented corner case")

            if cardinality is None:
                cardinality = self.CardinalityMapping[self.DefaultCardinality]

            outputDescClass = outputDesc.get("c-l-a-s-s")
            eOutput = ExpectedOutput(
                name=cast("SymbolicOutputName", output_name),
                kind=ContentKind.File
                if outputDescClass is None
                else self.OutputClassMapping.get(outputDescClass, ContentKind.File),
                preferredFilename=cast(
                    "Optional[RelPath]", outputDesc.get("preferredName")
                ),
                cardinality=cardinality,
                fillFrom=cast("Optional[SymbolicParamName]", fillFrom),
                glob=cast("Optional[GlobPattern]", patS),
                syntheticOutput=outputDesc.get(
                    "syntheticOutput", default_synthetic_output
                ),
            )
            expectedOutputs.append(eOutput)

        return expectedOutputs

    def parseExportActions(
        self, raw_actions: "Sequence[ExportActionBlock]"
    ) -> "Sequence[ExportAction]":
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
                licences=actionDesc.get("licences", []),
                title=actionDesc.get("title"),
                description=actionDesc.get("description"),
                custom_metadata=actionDesc.get("custom-metadata"),
                community_custom_metadata=actionDesc.get("community-custom-metadata"),
            )
            actions.append(action)

        return actions

    def executeWorkflow(self, offline: "bool" = False) -> "StagedExecution":
        self.unmarshallStage(offline=offline)
        self.unmarshallExecute(offline=offline, fail_ok=True)

        assert self.materializedEngine is not None
        assert self.materializedParams is not None
        assert self.materializedEnvironment is not None
        assert self.expected_outputs is not None
        assert self.outputsDir is not None

        if self.stagedExecutions is None:
            self.stagedExecutions = []

        # First, the job tries to add itself to the list ASAP
        job_id = os.getpid()
        queued = datetime.datetime.fromtimestamp(
            psutil.Process(job_id).create_time()
        ).astimezone()
        initial_staged_exec = StagedExecution(
            exitVal=cast("ExitVal", -1),
            augmentedInputs=[],
            matCheckOutputs=[],
            outputsDir=self.outputsDir,
            queued=queued,
            started=datetime.datetime.min,
            ended=datetime.datetime.min,
            status=ExecutionStatus.Queued,
            job_id=str(job_id),
        )
        self.marshallExecute(initial_staged_exec)

        # Now, execute the job in foreground
        for staged_exec in WorkflowEngine.ExecuteWorkflow(
            self.materializedEngine,
            self.materializedParams,
            self.materializedEnvironment,
            self.expected_outputs,
            self.enabled_profiles,
        ):
            self.logger.debug(staged_exec.exitVal)
            self.logger.debug(staged_exec.started)
            self.logger.debug(staged_exec.ended)
            self.logger.debug(staged_exec.augmentedInputs)
            self.logger.debug(staged_exec.matCheckOutputs)

            # TODO: store only the last update
            # Store serialized version of exitVal, augmentedInputs and matCheckOutputs
            self.marshallExecute(staged_exec)

        # And last, report the last staged execution
        return staged_exec

    def queueExecution(self, offline: "bool" = False) -> "str":
        self.unmarshallStage(offline=offline)
        self.unmarshallExecute(offline=offline, fail_ok=True)

        assert self.materializedEngine is not None
        assert self.materializedParams is not None
        assert self.materializedEnvironment is not None
        assert self.expected_outputs is not None
        assert self.outputsDir is not None

        if self.stagedExecutions is None:
            self.stagedExecutions = []

        # And once deployed, let's run the workflow in background!
        job_id = os.fork()
        if job_id == 0:
            os.setsid()
            os.closerange(0, get_maximum_file_descriptors())

            # This is the child
            # First, the child tries to add itself to the list ASAP
            job_id = os.getpid()
            queued = datetime.datetime.fromtimestamp(
                psutil.Process(job_id).create_time()
            ).astimezone()
            initial_staged_exec = StagedExecution(
                exitVal=cast("ExitVal", -1),
                augmentedInputs=[],
                matCheckOutputs=[],
                outputsDir=self.outputsDir,
                queued=queued,
                started=datetime.datetime.min,
                ended=datetime.datetime.min,
                status=ExecutionStatus.Queued,
                job_id=str(job_id),
            )
            self.marshallExecute(initial_staged_exec)

            # Then, listen to the events
            # with daemon.DaemonContext(detach_process=False) as dc:
            for staged_exec in WorkflowEngine.ExecuteWorkflow(
                self.materializedEngine,
                self.materializedParams,
                self.materializedEnvironment,
                self.expected_outputs,
                self.enabled_profiles,
            ):
                # TODO: store only the last update
                # Store serialized version of exitVal, augmentedInputs and matCheckOutputs
                self.marshallExecute(staged_exec)
        elif job_id > 0:
            # This is the parent
            # As a redundancy, add the child to the list
            queued = datetime.datetime.fromtimestamp(
                psutil.Process(job_id).create_time()
            ).astimezone()
            initial_staged_exec = StagedExecution(
                exitVal=cast("ExitVal", -1),
                augmentedInputs=[],
                matCheckOutputs=[],
                outputsDir=self.outputsDir,
                queued=queued,
                started=datetime.datetime.min,
                ended=datetime.datetime.min,
                status=ExecutionStatus.Queued,
                job_id=str(job_id),
            )
            self.marshallExecute(initial_staged_exec)
            return str(job_id)

        raise WFException(
            f"Unable to create a background jobs for {self.instanceId} ({self.nickname})"
        )

    def listMaterializedExportActions(self) -> "Sequence[MaterializedExportAction]":
        """
        This method should return the pids generated from the contents
        """
        self.unmarshallExport(offline=True)

        assert self.runExportActions is not None

        return self.runExportActions

    def exportResultsFromFiles(
        self,
        exportActionsFile: "Optional[pathlib.Path]" = None,
        securityContextFile: "Optional[pathlib.Path]" = None,
        action_ids: "Sequence[SymbolicName]" = [],
        fail_ok: "bool" = False,
    ) -> "Tuple[Sequence[MaterializedExportAction], Sequence[Tuple[ExportAction, Exception]]]":
        if exportActionsFile is not None:
            with exportActionsFile.open(mode="r", encoding="utf-8") as eaf:
                raw_actions = unmarshall_namedtuple(
                    yaml.safe_load(eaf), workdir=self.workDir
                )

            actions = self.parseExportActions(raw_actions["exports"])
        else:
            actions = None

        if securityContextFile is not None:
            vault = SecurityContextVault.FromFile(securityContextFile)
        else:
            vault = SecurityContextVault()

        return self.exportResults(actions, vault, action_ids, fail_ok=fail_ok)

    def _curate_orcid_list(
        self, orcids: "Sequence[str]", fail_ok: "bool" = True
    ) -> "Sequence[ResolvedORCID]":
        failed_orcids: "MutableSequence[str]" = []
        val_orcids: "MutableSequence[ResolvedORCID]" = []
        for orcid in orcids:
            # validate ORCID asking for its public metadata
            try:
                resolved_orcid = validate_orcid(orcid)
                if resolved_orcid is not None:
                    val_orcids.append(resolved_orcid)
                else:
                    self.logger.error(
                        f"ORCID {orcid} was discarded because it could not be resolved"
                    )
                    failed_orcids.append(orcid)

            except FetcherException as fe:
                self.logger.exception(f"Error resolving ORCID {orcid}")
                failed_orcids.append(orcid)

        if len(failed_orcids) > 0 and not fail_ok:
            raise WFException(
                f"{len(failed_orcids)} of {len(orcids)} ORCIDs were not valid: {', '.join(failed_orcids)}"
            )

        return val_orcids

    def _instantiate_export_plugin(
        self,
        action: "ExportAction",
        sec_context: "Optional[SecurityContextConfig]",
        default_licences: "Sequence[LicenceDescription]",
        default_orcids: "Sequence[ResolvedORCID]",
        default_preferred_id: "Optional[str]",
    ) -> "AbstractExportPlugin":
        """
        This method instantiates an stateful export plugin. Although the
        licences, ORCIDs and preferred ids are not used at the beginning,
        they are supplied as default values to the implementation, in case
        it is able to do something meaningful with them.
        Licence list should be curated outside this method.
        """

        _export_plugin_clazz = self.wfexs.getExportPluginClass(action.plugin_id)
        if _export_plugin_clazz is None:
            raise KeyError(f"Unavailable plugin {action.plugin_id}")

        staged_setup = self.getStagedSetup()

        if staged_setup.work_dir is None:
            raise ValueError(
                f"Staged setup from {staged_setup.instance_id} is corrupted"
            )

        if staged_setup.is_damaged:
            raise ValueError(f"Staged setup from {staged_setup.instance_id} is damaged")

        export_p = _export_plugin_clazz(
            refdir=staged_setup.work_dir,
            setup_block=sec_context,
            default_licences=default_licences,
            default_orcids=default_orcids,
            default_preferred_id=default_preferred_id,
        )

        # Context-based export plugins need this initialization
        if isinstance(export_p, AbstractContextedExportPlugin):
            export_p.set_wfexs_context(self.wfexs, self.getStagedSetup().temp_dir)

        return export_p

    def exportResults(
        self,
        actions: "Optional[Sequence[ExportAction]]" = None,
        vault: "Optional[SecurityContextVault]" = None,
        action_ids: "Sequence[SymbolicName]" = [],
        fail_ok: "bool" = False,
        op_licences: "Sequence[str]" = [],
        op_orcids: "Sequence[str]" = [],
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
        verstr = get_WfExS_version_str()
        for action in filtered_actions:
            try:
                # check the export items are available
                the_licences = (
                    action.licences if len(action.licences) > 0 else op_licences
                )
                the_orcids = cast("MutableSequence[str]", copy.copy(self.orcids))
                for op_orcid in op_orcids:
                    if op_orcid not in the_orcids:
                        the_orcids.append(op_orcid)

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
                elif vault is not None:
                    # TODO: rework this
                    setup_block = vault.getContext("", action.context_name)
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
                # TODO: Should we include mechanism to reuse a PID
                # already used in a previous export?
                preferred_id: "Optional[str]" = None
                if action.preferred_id is not None:
                    if action.preferred_scheme is not None:
                        preferred_id = (
                            action.preferred_scheme + ":" + action.preferred_id
                        )
                    else:
                        preferred_id = action.preferred_id

                expanded_licences = self.wfexs.curate_licence_list(the_licences)
                curated_orcids = self._curate_orcid_list(the_orcids)

                export_p = self._instantiate_export_plugin(
                    action=action,
                    sec_context=a_setup_block,
                    default_licences=expanded_licences,
                    default_orcids=curated_orcids,
                    default_preferred_id=preferred_id,
                )

                # This booked pid could differ from the preferred one
                # as it could not be reused due some constraints.
                # Also, we need to know the internal_pid associated to
                # the booked one, so we can handle drafts
                booked_entry = export_p.book_pid(
                    licences=expanded_licences,
                    resolved_orcids=curated_orcids,
                    preferred_id=preferred_id,
                    initially_required_metadata=action.custom_metadata,
                    initially_required_community_specific_metadata=action.community_custom_metadata,
                )

                if booked_entry is None:
                    raise ExportActionException(
                        f"Unable to book a PID for dataset export using export plugin with id {action.plugin_id}"
                    )

                elems = self.locateExportItems(
                    action.what,
                    licences=expanded_licences,
                    resolved_orcids=curated_orcids,
                    crate_pid=booked_entry.pid,
                )

                placeholders: "Mapping[str, str]" = {
                    "instance_id": self.staged_setup.instance_id,
                    "nickname": self.staged_setup.nickname
                    if self.staged_setup.nickname is not None
                    else self.staged_setup.instance_id,
                    "wfexs_verstr": verstr,
                    "wfexs_backend_name": wfexs_backend_name,
                    "wfexs_backend_url": wfexs_backend_url,
                }

                if action.title is None:
                    title = "Dataset pushed from staged WfExS working directory {instance_id} ({nickname})"
                else:
                    title = action.title
                title = self._formatStringFromPlaceHolders(title, placeholders)

                if action.description is None:
                    description = """\
This dataset has been created and uploaded using {wfexs_backend_name} {wfexs_verstr},
whose sources are available at {wfexs_backend_url}.

The contents come from staged WfExS working directory {instance_id} ({nickname}).
This is an enumeration of the types of collected contents:

"""
                    for e_item in action.what:
                        description += f" * {e_item.name} ({e_item.type.value})\n"
                else:
                    description = action.description
                description = self._formatStringFromPlaceHolders(
                    description, placeholders
                )

                # Export the contents and obtain a PID
                new_pids = export_p.push(
                    elems,
                    title=title,
                    description=description,
                    licences=expanded_licences,
                    resolved_orcids=curated_orcids,
                    preferred_id=booked_entry.draft_id,
                    metadata=action.custom_metadata,
                    community_specific_metadata=action.community_custom_metadata,
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
        self.marshallExport(matActions)

        return matActions, actionErrors

    @property
    def staging_recipe(self) -> "WritableWorkflowMetaConfigBlock":
        workflow_meta: "WritableWorkflowMetaConfigBlock" = {
            "workflow_id": self.id,
            "prefer_upstream_source": self.prefer_upstream_source,
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
        if self.enabled_profiles is not None:
            workflow_meta["profile"] = self.enabled_profiles
        if self.environment is not None:
            workflow_meta["environment"] = self.environment
        if self.placeholders is not None:
            workflow_meta["placeholders"] = self.placeholders
        if self.outputs is not None:
            workflow_meta["outputs"] = self.outputs
        if self.default_actions is not None:
            workflow_meta["default_actions"] = self.default_actions

        return cast(
            "WritableWorkflowMetaConfigBlock",
            marshall_namedtuple(workflow_meta, workdir=self.workDir),
        )

    def marshallConfig(
        self, overwrite: "bool" = False
    ) -> "Union[bool, datetime.datetime]":
        assert (
            self.metaDir is not None
        ), "Working directory should not be corrupted beyond basic usage"
        # The seed should have be already written

        # Now, the config itself
        if overwrite or (self.configMarshalled is None):
            workflow_meta_filename = self.metaDir / WORKDIR_WORKFLOW_META_FILE
            if (
                overwrite
                or not workflow_meta_filename.exists()
                or os.path.getsize(workflow_meta_filename) == 0
            ):
                staging_recipe = self.staging_recipe
                with workflow_meta_filename.open(mode="w", encoding="utf-8") as wmF:
                    wmlock = RWFileLock(wmF)
                    with wmlock.exclusive_lock():
                        yaml.dump(staging_recipe, wmF, Dumper=YAMLDumper)

            self.configMarshalled = datetime.datetime.fromtimestamp(
                os.path.getctime(workflow_meta_filename)
            ).astimezone()

        return self.configMarshalled

    def __get_combined_globals(self) -> "Mapping[str, Any]":
        """
        This method is needed since workflow engines and container factories
        are dynamically loaded.
        """
        combined_globals = copy.copy(common_defs_module.__dict__)
        combined_globals.update(globals())
        combined_globals.update(
            [
                (workflow_engine.__name__, workflow_engine)
                for workflow_engine in self.wfexs.listWorkflowEngineClasses()
            ]
        )

        return combined_globals

    def unmarshallConfig(
        self, fail_ok: "bool" = False
    ) -> "Optional[Union[bool, datetime.datetime]]":
        assert (
            self.metaDir is not None
        ), "Working directory should not be corrupted beyond basic usage"

        if self.configMarshalled is None:
            config_unmarshalled = True
            workflow_meta_filename = self.metaDir / WORKDIR_WORKFLOW_META_FILE
            # If the file does not exist, fail fast
            if (
                not workflow_meta_filename.is_file()
                or os.stat(workflow_meta_filename).st_size == 0
            ):
                self.logger.debug(
                    f"Marshalled config file {workflow_meta_filename} does not exist or is empty"
                )
                return False

            workflow_meta = None
            try:
                with workflow_meta_filename.open(mode="r", encoding="utf-8") as wcf:
                    rmlock = RWFileLock(wcf)
                    with rmlock.shared_blocking_lock():
                        workflow_meta = unmarshall_namedtuple(
                            yaml.safe_load(wcf), workdir=self.workDir
                        )

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
                    self.prefer_upstream_source = workflow_meta.get(
                        "prefer_upstream_source", True
                    )
                    self.workflow_config = workflow_meta.get("workflow_config")
                    self.params = workflow_meta.get("params")
                    profiles: "Optional[Union[str, Sequence[str]]]" = workflow_meta.get(
                        "profile"
                    )
                    enabled_profiles: "Optional[Sequence[str]]" = None
                    if profiles is not None:
                        if isinstance(profiles, list):
                            enabled_profiles = profiles
                        elif isinstance(profiles, str):
                            split_by_comma = re.compile(r"[ \t]*,[ \t]*")
                            enabled_profiles = split_by_comma.split(profiles)
                        else:
                            # It should not happen
                            enabled_profiles = [str(profiles)]

                    self.enabled_profiles = enabled_profiles
                    self.environment = workflow_meta.get("environment")
                    self.placeholders = workflow_meta.get("placeholders")
                    self.outputs = workflow_meta.get("outputs")
                    self.formatted_params, self.outputs_to_inject = self.formatParams(
                        self.params
                    )
                    assert self.outputs_to_inject is not None
                    self.formatted_environment, _ = self.formatParams(self.environment)

                    # The right moment to rescue this?
                    if isinstance(self.workflow_config, dict):
                        container_type_str = self.workflow_config.get("containerType")
                        if container_type_str is not None:
                            self.explicit_container_type = True
                            self.container_type_str = container_type_str

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
                self.logger.log(
                    logging.WARNING if fail_ok else logging.ERROR,
                    "Marshalled config file {} I/O errors".format(
                        workflow_meta_filename
                    ),
                )
                if not fail_ok:
                    raise WFException("ERROR opening/reading config file") from ioe
            except TypeError as te:
                config_unmarshalled = False
                self.logger.log(
                    logging.WARNING if fail_ok else logging.ERROR,
                    "Marshalled config file {} unmarshalling errors".format(
                        workflow_meta_filename
                    ),
                )
                if not fail_ok:
                    raise WFException("ERROR unmarshalling config file") from te
            except Exception as e:
                config_unmarshalled = False
                self.logger.exception(
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

                self.vault = SecurityContextVault()

                self.configMarshalled = datetime.datetime.fromtimestamp(
                    os.path.getctime(workflow_meta_filename)
                ).astimezone()

        return self.configMarshalled

    def marshallStage(
        self, exist_ok: "bool" = True, overwrite: "bool" = False
    ) -> "Optional[Union[bool, datetime.datetime]]":
        if overwrite or (self.stageMarshalled is None):
            # Do not even try
            if self.marshallConfig() is None:
                return None

            assert (
                self.metaDir is not None
            ), "The metadata directory should be available"

            marshalled_stage_file = self.metaDir / WORKDIR_MARSHALLED_STAGE_FILE
            stageAlreadyMarshalled = False
            if marshalled_stage_file.exists():
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
                    "remote_repo": self.remote_repo,
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
                    "materializedParams": self.materializedParams,
                    "materializedEnvironment": self.materializedEnvironment,
                    # TODO: check nothing essential was left
                }

                self.logger.debug(
                    "Creating marshalled stage file {}".format(marshalled_stage_file)
                )
                with marshalled_stage_file.open(mode="w", encoding="utf-8") as msF:
                    marshalled_stage = marshall_namedtuple(stage, workdir=self.workDir)
                    swlock = RWFileLock(msF)
                    with swlock.exclusive_lock():
                        yaml.dump(marshalled_stage, msF, Dumper=YAMLDumper)

            self.stageMarshalled = datetime.datetime.fromtimestamp(
                os.path.getctime(marshalled_stage_file)
            ).astimezone()
        elif not exist_ok:
            raise WFException(f"Marshalled stage file already exists")

        return self.stageMarshalled

    def unmarshallStage(
        self,
        offline: "bool" = False,
        fail_ok: "bool" = False,
        do_full_setup: "bool" = True,
    ) -> "Optional[Union[bool, datetime.datetime]]":
        if self.stageMarshalled is None:
            # If basic state does not work, even do not try
            retval = self.unmarshallConfig(fail_ok=fail_ok)
            if not retval:
                return None

            assert (
                self.metaDir is not None
            ), "The metadata directory should be available"

            marshalled_stage_file = self.metaDir / WORKDIR_MARSHALLED_STAGE_FILE
            if not marshalled_stage_file.exists():
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
                with marshalled_stage_file.open(mode="r", encoding="utf-8") as msF:
                    srlock = RWFileLock(msF)
                    with srlock.shared_blocking_lock():
                        marshalled_stage = yaml.load(msF, Loader=YAMLLoader)

                    combined_globals = self.__get_combined_globals()
                    stage = unmarshall_namedtuple(
                        marshalled_stage,
                        myglobals=combined_globals,
                        workdir=self.workDir,
                    )
                    self.remote_repo = stage.get("remote_repo")
                    # This one takes precedence
                    if self.remote_repo is not None:
                        self.repoURL = self.remote_repo.repo_url
                        self.repoTag = self.remote_repo.tag
                        self.repoRelPath = self.remote_repo.rel_path
                    else:
                        self.repoURL = stage["repoURL"]
                        self.repoTag = stage["repoTag"]
                        self.repoRelPath = stage["repoRelPath"]
                        assert self.repoURL is not None
                        self.remote_repo = RemoteRepo(
                            repo_url=self.repoURL,
                            tag=self.repoTag,
                            rel_path=self.repoRelPath,
                        )
                    self.repoEffectiveCheckout = stage["repoEffectiveCheckout"]
                    self.engineDesc = stage["engineDesc"]
                    self.engineVer = stage["engineVer"]
                    self.materializedEngine = stage["materializedEngine"]
                    if (
                        self.materializedEngine is not None
                        and stage["containers"] is not None
                        and self.materializedEngine.containers is None
                    ):
                        self.materializedEngine = self.materializedEngine._replace(
                            containers=stage["containers"]
                        )
                    self.materializedParams = stage["materializedParams"]
                    self.materializedEnvironment = stage.get(
                        "materializedEnvironment", []
                    )

                    # Trying to identify the right container type
                    # for old staged directories
                    if (
                        not self.explicit_container_type
                        and self.materializedEngine is not None
                    ):
                        guessed_container_type: "ContainerType"
                        if (
                            self.materializedEngine.containers is None
                            or len(self.materializedEngine.containers) == 0
                        ):
                            if (
                                self.materializedEngine.operational_containers is None
                                or len(self.materializedEngine.operational_containers)
                                == 0
                            ):
                                guessed_container_type = ContainerType.NoContainer
                            else:
                                guessed_container_type = (
                                    self.materializedEngine.operational_containers[
                                        0
                                    ].type
                                )
                        else:
                            guessed_container_type = self.materializedEngine.containers[
                                0
                            ].type

                        self.container_type_str = guessed_container_type.value
                        self.staged_setup = self.staged_setup._replace(
                            container_type=guessed_container_type
                        )

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
                    if do_full_setup:
                        self.setupEngine(offline=True)
                    elif self.engineDesc is not None:
                        enabled_profiles: "Optional[Sequence[str]]" = None
                        if self.enabled_profiles is not None:
                            enabled_profiles = self.enabled_profiles
                        elif self.staged_setup.workflow_config is not None:
                            profiles: "Optional[Union[str, Sequence[str]]]" = (
                                self.staged_setup.workflow_config.get(
                                    self.engineDesc.engineName, {}
                                ).get("profile")
                            )
                            if profiles is not None:
                                if isinstance(profiles, list):
                                    enabled_profiles = profiles
                                elif isinstance(profiles, str):
                                    split_by_comma = re.compile(r"[ \t]*,[ \t]*")
                                    enabled_profiles = split_by_comma.split(profiles)
                                else:
                                    # It should not happen
                                    enabled_profiles = [str(profiles)]

                                # Backward <=> forward compatibility
                                self.enabled_profiles = enabled_profiles

                        self.engine = self.wfexs.instantiateEngine(
                            self.engineDesc, self.staged_setup
                        )

                    # Process outputs now we have an engine
                    if isinstance(self.outputs, dict):
                        assert self.engine is not None
                        assert self.outputs_to_inject is not None
                        outputs = list(self.outputs.values())
                        if (len(outputs) == 0 and len(self.outputs_to_inject) == 0) or (
                            len(outputs) > 0 and isinstance(outputs[0], ExpectedOutput)
                        ):
                            self.expected_outputs = outputs
                        else:
                            self.expected_outputs = self.parseExpectedOutputs(
                                self.outputs_to_inject,
                                self.outputs,
                                default_synthetic_output=not self.engine.HasExplicitOutputs(),
                            )
                    else:
                        self.expected_outputs = None
            except Exception as e:
                errmsg = "Error while unmarshalling content from stage state file {}. Reason: {}".format(
                    marshalled_stage_file, e
                )
                self.stageMarshalled = False
                self.logger.exception(errmsg)
                if fail_ok:
                    self.logger.debug(errmsg)
                    return self.stageMarshalled
                self.logger.exception(errmsg)
                raise WFException(errmsg) from e

            # Now, time to save the late changes
            if not self.explicit_container_type and self.materializedEngine is not None:
                self.explicit_container_type = True
                self.workflow_config["containerType"] = self.container_type_str
                self.marshallConfig(overwrite=True)

            self.stageMarshalled = datetime.datetime.fromtimestamp(
                os.path.getctime(marshalled_stage_file)
            ).astimezone()

        return self.stageMarshalled

    def marshallExecute(
        self,
        staged_exec: "StagedExecution",
    ) -> "Optional[Union[bool, datetime.datetime]]":
        if self.marshallStage() is None:
            return None

        assert self.metaDir is not None, "The metadata directory should be available"

        assert self.stagedExecutions is not None

        marshalled_execution_file = self.metaDir / WORKDIR_MARSHALLED_EXECUTE_FILE

        # The file contents must be kept INTACT (or created)!!!
        emF = os.open(marshalled_execution_file, os.O_RDWR | os.O_CREAT, mode=0o666)
        ewlock = RWFileLock(emF)
        with ewlock.exclusive_blocking_lock(), os.fdopen(
            emF, mode="r+", encoding="utf-8"
        ) as msF:
            staged_executions: "MutableSequence[StagedExecution]" = []
            creation_timestamp = datetime.datetime.fromtimestamp(
                os.fstat(emF).st_ctime
            ).astimezone()
            if os.fstat(emF).st_size > 0:
                try:
                    (
                        staged_executions,
                        creation_timestamp,
                    ) = self._unmarshallExecuteFH(msF, os.fstat(emF).st_ctime)
                except:
                    self.logger.error(
                        f"Unable to unmarshall executions metadata file {marshalled_execution_file}"
                    )

            # Overwrite previous versions of the very same staged execution
            for candidate_stage_pos, candidate_stage in enumerate(staged_executions):
                if (
                    candidate_stage.outputsDir == self.outputsDir
                    and candidate_stage.job_id == staged_exec.job_id
                ) or (
                    candidate_stage.outputsDir != self.outputsDir
                    and staged_exec.outputsDir != self.outputsDir
                    and candidate_stage.outputsDir == staged_exec.outputsDir
                ):
                    staged_executions[candidate_stage_pos] = staged_exec
                    break
            else:
                staged_executions.append(staged_exec)

            # And now, store!
            executions = []
            for stagedExec in staged_executions:
                execution = {
                    "exitVal": stagedExec.exitVal,
                    "augmentedInputs": stagedExec.augmentedInputs,
                    "matCheckOutputs": stagedExec.matCheckOutputs,
                    "outputsDir": stagedExec.outputsDir,
                    "started": stagedExec.started,
                    "ended": stagedExec.ended,
                    "environment": stagedExec.environment,
                    "outputMetaDir": stagedExec.outputMetaDir,
                    "diagram": stagedExec.diagram,
                    "logfile": stagedExec.logfile,
                    "profiles": stagedExec.profiles,
                    "queued": stagedExec.queued,
                    "status": stagedExec.status,
                    "job_id": stagedExec.job_id,
                }
                executions.append(execution)

            self.logger.debug(
                "Writing marshalled execution file {}".format(marshalled_execution_file)
            )

            msF.seek(0)
            yaml.dump(
                marshall_namedtuple(executions, workdir=self.workDir),
                msF,
                Dumper=YAMLDumper,
            )
            # Last, remove possible last bytes
            msF.truncate(msF.tell())

        self.executionMarshalled = creation_timestamp
        self.stagedExecutions = staged_executions

        return self.executionMarshalled

    def unmarshallExecute(
        self, offline: "bool" = True, fail_ok: "bool" = False
    ) -> "Tuple[Optional[Union[bool, datetime.datetime]], Sequence[StagedExecution]]":
        # If stage state is not properly prepared, even do not try
        retval = self.unmarshallStage(offline=offline, fail_ok=fail_ok)
        if not retval:
            return None, []

        assert self.metaDir is not None, "The metadata directory should be available"

        marshalled_execution_file = self.metaDir / WORKDIR_MARSHALLED_EXECUTE_FILE
        if not marshalled_execution_file.exists():
            errmsg = f"Marshalled execution file {marshalled_execution_file} does not exist. Execution state was not stored"
            self.logger.debug(errmsg)
            self.executionMarshalled = False
            if fail_ok:
                return self.executionMarshalled, []
            raise WFException(errmsg)

        self.logger.debug(
            "Parsing marshalled execution state file {}".format(
                marshalled_execution_file
            )
        )

        try:
            with marshalled_execution_file.open(mode="r", encoding="utf-8") as meF:
                erlock = RWFileLock(meF)
                with erlock.shared_blocking_lock():
                    (
                        self.stagedExecutions,
                        creation_timestamp,
                    ) = self._unmarshallExecuteFH(meF)
                self.executionMarshalled = creation_timestamp

                return self.executionMarshalled, self.stagedExecutions
        except Exception as e:
            errmsg = "Error while unmarshalling content from execution state file {}. Reason: {}".format(
                marshalled_execution_file, e
            )
            self.executionMarshalled = False
            if fail_ok:
                self.logger.exception(errmsg)
                return self.executionMarshalled, []
            self.logger.exception(errmsg)
            raise WFException(errmsg) from e

    def _unmarshallExecuteFH(
        self, meF: "IO[str]", creation_time: "Optional[float]" = None
    ) -> "Tuple[MutableSequence[StagedExecution], datetime.datetime]":
        """
        Internal method used to unmarshall staged executions metadata.

        :param meF: open file (or similar), with fileno method
        :param creation_time: when the marshalled execution file was created, measured in number of seconds since epoch
        :returns: The list of unmarshalled, staged executions
        """
        assert self.workDir is not None
        assert self.metaDir is not None, "The metadata directory should be available"

        if creation_time is None:
            creation_time = os.fstat(meF.fileno()).st_ctime

        # The default
        creation_timestamp = datetime.datetime.fromtimestamp(creation_time).astimezone()

        marshalled_execution = yaml.load(meF, Loader=YAMLLoader)
        combined_globals = self.__get_combined_globals()
        execution_read = unmarshall_namedtuple(
            marshalled_execution,
            myglobals=combined_globals,
            workdir=self.workDir,
        )

        if isinstance(execution_read, dict):
            executions = [execution_read]
        else:
            executions = execution_read

        staged_executions: "MutableSequence[StagedExecution]" = []
        for execution in cast("Sequence[Mapping[str, Any]]", executions):
            execution = StagedExecution._mapping_fixes(execution, self.workDir)

            # We might need to learn where the metadata of this
            # specific execution is living
            default_outputs_dir = self.workDir / WORKDIR_OUTPUTS_RELDIR
            outputsDir = execution.get("outputsDir", default_outputs_dir)
            jobOutputMetaDir = execution.get("outputMetaDir")
            if jobOutputMetaDir is None:
                absOutputMetaDir = self.metaDir / WORKDIR_OUTPUTS_RELDIR
                if not outputsDir.samefile(default_outputs_dir):
                    jobOutputMetaDir = self.metaDir / outputsDir.relative_to(
                        self.workDir
                    )
                else:
                    jobOutputMetaDir = absOutputMetaDir
            else:
                absOutputMetaDir = jobOutputMetaDir

            # For backward compatibility, let's find the
            # logfiles and generated charts
            logfiles: "Optional[MutableSequence[pathlib.Path]]" = execution.get(
                "logfile"
            )
            if logfiles is None:
                candidate_logfiles_str = [
                    WORKDIR_STDOUT_FILE,
                    WORKDIR_STDERR_FILE,
                    cast("RelPath", "log.txt"),
                ]

                logfiles = []
                for logfname in candidate_logfiles_str:
                    logfile = pathlib.Path(logfname)
                    if not logfile.is_absolute():
                        logfile = self.workDir / logfname

                    if not logfile.exists():
                        logfile = jobOutputMetaDir / logfname

                    if not logfile.exists() and jobOutputMetaDir != absOutputMetaDir:
                        logfile = absOutputMetaDir / logfname

                    if logfile.exists():
                        logfiles.append(logfile)

            diagram: "Optional[pathlib.Path]" = execution.get("diagram")
            if diagram is not None:
                if not diagram.is_absolute():
                    diagram = (self.workDir / diagram).resolve()
            else:
                putative_diagram = (
                    jobOutputMetaDir / WORKDIR_STATS_RELDIR / STATS_DAG_DOT_FILE
                )

                if not putative_diagram.exists() and not jobOutputMetaDir.samefile(
                    absOutputMetaDir
                ):
                    putative_diagram = (
                        absOutputMetaDir / WORKDIR_STATS_RELDIR / STATS_DAG_DOT_FILE
                    )

                if putative_diagram.exists():
                    diagram = putative_diagram

            profiles: "Optional[Sequence[str]]" = execution.get("profiles")
            # Backward <=> forward compatibility
            if profiles is None:
                profiles = self.enabled_profiles

            job_status = cast(
                "ExecutionStatus",
                execution.get("status", ExecutionStatus.Finished),
            )

            # Let's check how "alive" are the processes
            if job_status in (ExecutionStatus.Queued, ExecutionStatus.Running):
                try:
                    job_id = int(execution.get("job_id", ""))
                    queued_proc = datetime.datetime.fromtimestamp(
                        psutil.Process(job_id).create_time()
                    ).astimezone()

                    queued = execution.get("queued", datetime.datetime.min)
                    if queued_proc != queued:
                        job_status = ExecutionStatus.Died
                except (psutil.NoSuchProcess, ValueError, TypeError):
                    job_status = ExecutionStatus.Died

            stagedExec = StagedExecution(
                exitVal=execution["exitVal"],
                augmentedInputs=execution["augmentedInputs"],
                matCheckOutputs=execution["matCheckOutputs"],
                outputsDir=outputsDir,
                started=execution.get("started", creation_timestamp),
                ended=execution.get("ended", creation_timestamp),
                environment=execution.get("environment", []),
                outputMetaDir=absOutputMetaDir,
                diagram=diagram,
                logfile=logfiles,
                profiles=profiles,
                queued=execution.get("queued", datetime.datetime.min),
                status=job_status,
                job_id=execution.get("job_id"),
            )
            staged_executions.append(stagedExec)

        return staged_executions, creation_timestamp

    def marshallExport(
        self, new_mat_actions: "Sequence[MaterializedExportAction]"
    ) -> "Optional[Union[bool, datetime.datetime]]":
        # Do not even try saving the state
        if self.marshallStage() is None:
            return None

        assert self.metaDir is not None, "The metadata directory should be available"

        marshalled_export_file = self.metaDir / WORKDIR_MARSHALLED_EXPORT_FILE

        # The file contents must be kept INTACT (or created)!!!
        emF = os.open(marshalled_export_file, os.O_RDWR | os.O_CREAT, mode=0o666)
        ewlock = RWFileLock(emF)
        with ewlock.exclusive_blocking_lock(), os.fdopen(
            emF, mode="r+", encoding="utf-8"
        ) as msF:
            run_export_actions: "MutableSequence[MaterializedExportAction]" = []
            creation_timestamp = datetime.datetime.fromtimestamp(
                os.fstat(emF).st_ctime
            ).astimezone()
            if os.fstat(emF).st_size > 0:
                try:
                    (
                        run_export_actions,
                        creation_timestamp,
                    ) = self._unmarshallExportFH(msF, os.fstat(emF).st_ctime)
                except:
                    self.logger.error(
                        f"Unable to unmarshall exports metadata file {marshalled_export_file}"
                    )

            run_export_actions.extend(new_mat_actions)

            self.logger.debug(
                "Writing marshalled export results file {}".format(
                    marshalled_export_file
                )
            )
            msF.seek(0)
            yaml.dump(
                marshall_namedtuple(run_export_actions, workdir=self.workDir),
                msF,
                Dumper=YAMLDumper,
            )
            # Last, remove possible last bytes
            msF.truncate(msF.tell())

        self.exportMarshalled = creation_timestamp
        self.runExportActions = run_export_actions

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

            marshalled_export_file = self.metaDir / WORKDIR_MARSHALLED_EXPORT_FILE
            if not marshalled_export_file.exists():
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
                with marshalled_export_file.open(mode="r", encoding="utf-8") as meF:
                    erlock = RWFileLock(meF)
                    with erlock.shared_blocking_lock():
                        (
                            self.runExportActions,
                            self.exportMarshalled,
                        ) = self._unmarshallExportFH(meF)

            except Exception as e:
                errmsg = f"Error while unmarshalling content from export results state file {marshalled_export_file}. Reason: {e}"
                self.exportMarshalled = False
                if fail_ok:
                    self.logger.debug(errmsg)
                    return self.exportMarshalled
                else:
                    self.logger.exception(errmsg)
                raise WFException(errmsg) from e

        return self.exportMarshalled

    def _unmarshallExportFH(
        self, meF: "IO[str]", creation_time: "Optional[float]" = None
    ) -> "Tuple[MutableSequence[MaterializedExportAction], datetime.datetime]":
        if creation_time is None:
            creation_time = os.fstat(meF.fileno()).st_ctime

        # The default
        creation_timestamp = datetime.datetime.fromtimestamp(creation_time).astimezone()

        marshalled_export = yaml.load(meF, Loader=YAMLLoader)
        combined_globals = self.__get_combined_globals()
        run_export_actions = unmarshall_namedtuple(
            marshalled_export,
            myglobals=combined_globals,
            workdir=self.workDir,
        )

        return run_export_actions, creation_timestamp

    ExportROCrate2Payloads: "Final[Mapping[str, CratableItem]]" = {
        "": NoCratableItem,
        "inputs": CratableItem.Inputs,
        "outputs": CratableItem.Outputs,
        "workflow": CratableItem.Workflow,
        "containers": CratableItem.Containers,
        "prospective": CratableItem.ProspectiveProvenance,
        "full": CratableItem.RetrospectiveProvenance,
    }

    def locateExportItems(
        self,
        items: "Sequence[ExportItem]",
        licences: "Sequence[LicenceDescription]" = [],
        resolved_orcids: "Sequence[ResolvedORCID]" = [],
        crate_pid: "Optional[str]" = None,
    ) -> "Sequence[AnyContent]":
        """
        The located paths in the contents should be relative to the working directory
        """
        retval: "MutableSequence[AnyContent]" = []

        materializedParamsDict: "Mapping[SymbolicParamName, MaterializedInput]" = dict()
        materializedEnvironmentDict: "Mapping[SymbolicParamName, MaterializedInput]" = (
            dict()
        )
        for item in items:
            if item.type == ExportItemType.Param:
                if not isinstance(self.getMarshallingStatus().stage, datetime.datetime):
                    raise WFException(
                        f"Cannot export inputs from {self.staged_setup.instance_id} until the workflow has been properly staged"
                    )

                assert self.materializedParams is not None
                assert self.staged_setup.inputs_dir is not None
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
                    if not materializedParam.disclosable:
                        raise PermissionError(
                            f"Param {item.name} contents have export restrictions"
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
                    # The whole input directory, which can contain files
                    # and / or directories references from environment
                    # variables
                    prettyFilename = cast("RelPath", self.staged_setup.inputs_dir.name)
                    retval.append(
                        MaterializedContent(
                            local=self.staged_setup.inputs_dir,
                            licensed_uri=LicensedURI(
                                uri=cast(
                                    "URIType",
                                    "wfexs:"
                                    + self.staged_setup.instance_id
                                    + "/"
                                    + prettyFilename,
                                )
                            ),
                            prettyFilename=prettyFilename,
                            kind=ContentKind.Directory,
                        )
                    )
            elif item.type == ExportItemType.Environment:
                if not isinstance(self.getMarshallingStatus().stage, datetime.datetime):
                    raise WFException(
                        f"Cannot export environment from {self.staged_setup.instance_id} until the workflow has been properly staged"
                    )

                assert self.materializedEnvironment is not None
                assert self.staged_setup.inputs_dir is not None
                if item.name is not None:
                    if not materializedEnvironmentDict:
                        materializedEnvironmentDict = dict(
                            map(lambda mp: (mp.name, mp), self.materializedEnvironment)
                        )
                    materializedEnvVar = materializedEnvironmentDict.get(
                        cast("SymbolicParamName", item.name)
                    )
                    if materializedEnvVar is None:
                        raise KeyError(
                            f"Environment variable {item.name} to be exported does not exist"
                        )
                    if not materializedEnvVar.disclosable:
                        raise PermissionError(
                            f"Environment variable {item.name} contents have export restrictions"
                        )
                    retval.extend(
                        cast(
                            "Iterable[MaterializedContent]",
                            filter(
                                lambda mpc: isinstance(mpc, MaterializedContent),
                                materializedEnvVar.values,
                            ),
                        )
                    )
                else:
                    raise NotImplementedError(
                        "Exporting the files and directories associated to the whole set of environment variables is not implemented yet"
                    )
            elif item.type == ExportItemType.Output:
                if not isinstance(
                    self.getMarshallingStatus().execution, datetime.datetime
                ):
                    raise WFException(
                        f"Cannot export outputs from {self.staged_setup.instance_id} until the workflow has been executed at least once"
                    )

                assert (
                    isinstance(self.stagedExecutions, list)
                    and len(self.stagedExecutions) > 0
                )
                assert self.staged_setup.outputs_dir is not None
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
                    assert self.staged_setup.work_dir is not None
                    # The whole output directory
                    prettyFilename = cast("RelPath", stagedExec.outputsDir)
                    retval.append(
                        MaterializedContent(
                            local=pathlib.Path(self.staged_setup.work_dir)
                            / stagedExec.outputsDir,
                            licensed_uri=LicensedURI(
                                uri=cast(
                                    "URIType",
                                    "wfexs:"
                                    + self.staged_setup.instance_id
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
                assert self.staged_setup.work_dir is not None
                retval.append(
                    MaterializedContent(
                        local=pathlib.Path(self.staged_setup.work_dir),
                        licensed_uri=LicensedURI(
                            uri=cast(
                                "URIType", "wfexs:" + self.staged_setup.instance_id
                            )
                        ),
                        prettyFilename=prettyFilename,
                        kind=ContentKind.Directory,
                    )
                )
            elif item.type in (
                ExportItemType.StageCrate,
                ExportItemType.ProvenanceCrate,
            ):
                assert item.block is not None
                item_blocks = item.block.split(",")
                payloads_param = NoCratableItem
                for item_block in item_blocks:
                    if item_block not in self.ExportROCrate2Payloads:
                        raise KeyError(
                            f"'{item_block}' is not a valid variant for {item.type.value} ('"
                            + "', '".join(self.ExportROCrate2Payloads.keys())
                            + "')"
                        )
                    payloads_param |= self.ExportROCrate2Payloads[item_block]

                if item.type == ExportItemType.StageCrate:
                    if not isinstance(
                        self.getMarshallingStatus().stage, datetime.datetime
                    ):
                        raise WFException(
                            f"Cannot export the prospective provenance crate from {self.staged_setup.instance_id} until the workflow has been properly staged"
                        )

                    create_rocrate = self.createStageResearchObject
                    rocrate_prefix = f"wfexs_stage_{item.block}_crate"
                    pretty_relname = self.STAGED_CRATE_FILE
                elif item.type == ExportItemType.ProvenanceCrate:
                    if not isinstance(
                        self.getMarshallingStatus().execution, datetime.datetime
                    ):
                        raise WFException(
                            f"Cannot export the restrospective provenance crate from {self.staged_setup.instance_id} until the workflow has been executed at least once"
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
                temp_rocrate_path = pathlib.Path(temp_rocrate_file)

                create_rocrate(
                    filename=temp_rocrate_path,
                    payloads=payloads_param,
                    licences=licences,
                    resolved_orcids=resolved_orcids,
                    crate_pid=crate_pid,
                )
                retval.append(
                    MaterializedContent(
                        local=temp_rocrate_path,
                        licensed_uri=LicensedURI(
                            uri=cast(
                                "URIType",
                                "wfexs:"
                                + self.staged_setup.instance_id
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
        filename: "Optional[pathlib.Path]" = None,
        payloads: "CratableItem" = NoCratableItem,
        licences: "Sequence[LicenceDescription]" = [],
        resolved_orcids: "Sequence[ResolvedORCID]" = [],
        crate_pid: "Optional[str]" = None,
    ) -> "pathlib.Path":
        """
        Create RO-crate from stage provenance.
        """
        # TODO: implement RO-Crate deserialization
        self.unmarshallStage(offline=True, fail_ok=True)

        assert self.localWorkflow is not None
        assert self.materializedEngine is not None
        assert self.remote_repo is not None
        assert self.remote_repo.tag is not None or self.remote_repo.repo_type in (
            RepoType.Raw,
            None,
        )
        assert self.materializedParams is not None
        assert self.materializedEnvironment is not None
        assert self.staged_setup.work_dir is not None
        assert self.staged_setup.inputs_dir is not None
        assert self.staged_setup.outputs_dir is not None

        the_orcid_ids = set(
            map(lambda resolved_orcid: resolved_orcid.orcid, resolved_orcids)
        )
        raw_orcids: "MutableSequence[str]" = []
        for raw_orcid in self.orcids:
            if raw_orcid not in the_orcid_ids:
                raw_orcids.append(raw_orcid)
        the_orcids: "Sequence[ResolvedORCID]"
        if len(raw_orcids) > 0:
            the_orcids = [
                *self._curate_orcid_list(raw_orcids, fail_ok=False),
                *resolved_orcids,
            ]
        else:
            the_orcids = resolved_orcids
        wrroc = WorkflowRunROCrate(
            self.remote_repo,
            self.getPID(),
            self.localWorkflow,
            self.materializedEngine,
            self.workflowEngineVersion,
            self.containerEngineVersion,
            self.containerEngineOs,
            self.arch,
            staged_setup=self.staged_setup,
            payloads=payloads,
            licences=licences,
            orcids=the_orcids,
            progs=self.wfexs.progs,
            tempdir=self.tempDir,
            scheme_desc=self.wfexs.describeFetchableSchemes(),
            crate_pid=crate_pid,
        )

        wrroc.addStagedWorkflowDetails(
            self.materializedParams,
            self.materializedEnvironment,
            self.expected_outputs,
            profiles=self.enabled_profiles,
        )

        # Save RO-crate as execution.crate.zip
        if filename is None:
            assert self.outputsDir is not None
            filename = self.outputsDir / self.STAGED_CRATE_FILE
        wrroc.writeWRROC(filename)

        self.logger.info("Staged RO-Crate created: {}".format(filename))

        return filename

    def createResultsResearchObject(
        self,
        filename: "Optional[pathlib.Path]" = None,
        payloads: "CratableItem" = NoCratableItem,
        licences: "Sequence[LicenceDescription]" = [],
        resolved_orcids: "Sequence[ResolvedORCID]" = [],
        crate_pid: "Optional[str]" = None,
    ) -> "pathlib.Path":
        """
        Create RO-crate from stage provenance.
        """
        self.unmarshallExecute(offline=True, fail_ok=True)

        assert self.localWorkflow is not None
        assert self.materializedEngine is not None
        assert self.remote_repo is not None
        assert self.remote_repo.tag is not None or self.remote_repo.repo_type in (
            RepoType.Raw,
            None,
        )
        assert self.staged_setup.work_dir is not None
        assert (
            isinstance(self.stagedExecutions, list) and len(self.stagedExecutions) > 0
        )

        the_orcid_ids = set(
            map(lambda resolved_orcid: resolved_orcid.orcid, resolved_orcids)
        )
        raw_orcids: "MutableSequence[str]" = []
        for raw_orcid in self.orcids:
            if raw_orcid not in the_orcid_ids:
                raw_orcids.append(raw_orcid)
        the_orcids: "Sequence[ResolvedORCID]"
        if len(raw_orcids) > 0:
            the_orcids = [
                *self._curate_orcid_list(raw_orcids, fail_ok=False),
                *resolved_orcids,
            ]
        else:
            the_orcids = resolved_orcids
        wrroc = WorkflowRunROCrate(
            self.remote_repo,
            self.getPID(),
            self.localWorkflow,
            self.materializedEngine,
            self.workflowEngineVersion,
            self.containerEngineVersion,
            self.containerEngineOs,
            self.arch,
            staged_setup=self.staged_setup,
            payloads=payloads,
            licences=licences,
            orcids=the_orcids,
            progs=self.wfexs.progs,
            tempdir=self.tempDir,
            scheme_desc=self.wfexs.describeFetchableSchemes(),
            crate_pid=crate_pid,
        )

        for stagedExec in self.stagedExecutions:
            wrroc.addWorkflowExecution(
                stagedExec=stagedExec,
                expected_outputs=self.expected_outputs,
            )

        # Save RO-crate as execution.crate.zip
        if filename is None:
            assert self.outputsDir is not None
            filename = self.outputsDir / self.EXECUTION_CRATE_FILE

        wrroc.writeWRROC(filename)

        self.logger.info("Execution RO-Crate created: {}".format(filename))

        return filename
