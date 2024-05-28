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

import atexit
import copy
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

from typing import (
    cast,
    Dict,
    NamedTuple,
    Pattern,
    TYPE_CHECKING,
    TypeVar,
)

from .common import (
    ContainerType,
    CratableItem,
    DEFAULT_CONTAINER_TYPE,
    NoCratableItem,
    NoLicenceDescription,
    ResolvedORCID,
    StagedExecution,
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
    from typing import (
        Any,
        ClassVar,
        Iterable,
        Iterator,
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

    from typing_extensions import (
        Final,
        Literal,
        TypeAlias,
        TypedDict,
        Required,
        NotRequired,
    )

    from .common import (
        AbsPath,
        AnyContent,
        AnyPath,
        EngineVersion,
        ExitVal,
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
from .utils.licences import (
    AcceptableLicenceSchemes,
    LicenceMatcherSingleton,
)
from .utils.rocrate import (
    ReadROCrateMetadata,
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

# This is needed to keep backward compatibility
# with ancient working directories
Container.RegisterYAMLConstructor(YAMLLoader)

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
)
from .utils.marshalling_handling import marshall_namedtuple, unmarshall_namedtuple
from .utils.misc import config_validate

from .fetchers.trs_files import (
    TRS_SCHEME_PREFIX,
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
    when: "datetime.datetime" = datetime.datetime.now(
        tz=datetime.timezone.utc
    ).astimezone()


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
    TRS_TOOLS_PATH: "Final[str]" = "tools/"

    def __init__(
        self,
        wfexs: "WfExSBackend",
        workflow_id: "Optional[WorkflowId]" = None,
        version_id: "Optional[WFVersionId]" = None,
        descriptor_type: "Optional[TRS_Workflow_Descriptor]" = None,
        trs_endpoint: "str" = DEFAULT_TRS_ENDPOINT,
        params: "Optional[ParamsBlock]" = None,
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
        rawWorkDir: "Optional[AnyPath]" = None,
        paranoid_mode: "Optional[bool]" = None,
        public_key_filenames: "Sequence[AnyPath]" = [],
        private_key_filename: "Optional[AnyPath]" = None,
        private_key_passphrase: "Optional[str]" = None,
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
        self.encWorkDir: "Optional[AbsPath]" = None
        self.workDir: "Optional[AbsPath]" = None

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
            self.params = params
            self.environment = environment
            self.placeholders = placeholders
            self.formatted_params, self.outputs_to_inject = self.formatParams(params)
            assert self.outputs_to_inject is not None
            self.formatted_environment, _ = self.formatParams(environment)
            self.outputs = outputs
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
            self.rawWorkDir = cast("AbsPath", os.path.abspath(rawWorkDir))
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
            workdir_passphrase_file = os.path.join(
                self.rawWorkDir, WORKDIR_PASSPHRASE_FILE
            )
            self.secure = os.path.exists(workdir_passphrase_file)
        else:
            self.secure = (len(public_key_filenames) > 0) or workflow_config.get(
                "secure", True
            )

        doSecureWorkDir = self.secure or self.paranoidMode

        self.tempDir: "AbsPath"
        was_setup, self.tempDir = self.setupWorkdir(
            doSecureWorkDir,
            fail_ok=fail_ok,
            public_key_filenames=public_key_filenames,
            private_key_filename=private_key_filename,
            private_key_passphrase=private_key_passphrase,
        )

        self.configMarshalled: "Optional[Union[bool, datetime.datetime]]" = None
        self.inputsDir: "Optional[AbsPath]"
        self.extrapolatedInputsDir: "Optional[AbsPath]"
        self.intermediateDir: "Optional[AbsPath]"
        self.outputsDir: "Optional[AbsPath]"
        self.engineTweaksDir: "Optional[AbsPath]"
        self.metaDir: "Optional[AbsPath]"
        self.workflowDir: "Optional[AbsPath]"
        self.consolidatedWorkflowDir: "Optional[AbsPath]"
        self.containersDir: "Optional[AbsPath]"
        if was_setup:
            assert (
                self.workDir is not None
            ), "Workdir has to be already defined at this point"
            # This directory will hold either hard links to the cached
            # inputs, or the inputs properly pre-processed (decompressed,
            # decrypted, etc....) before a possible extrapolation.
            # These are the inputs used for RO-Crate building
            self.inputsDir = cast(
                "AbsPath", os.path.join(self.workDir, WORKDIR_INPUTS_RELDIR)
            )
            os.makedirs(self.inputsDir, exist_ok=True)
            # This directory will hold either hard links to the inputs directory,
            # or the inputs after a possible extrapolation
            self.extrapolatedInputsDir = cast(
                "AbsPath",
                os.path.join(self.workDir, WORKDIR_EXTRAPOLATED_INPUTS_RELDIR),
            )
            os.makedirs(self.extrapolatedInputsDir, exist_ok=True)
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
            # This directory will hold a copy of the consolidated workflow
            self.consolidatedWorkflowDir = cast(
                "AbsPath",
                os.path.join(self.workDir, WORKDIR_CONSOLIDATED_WORKFLOW_RELDIR),
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

                os.makedirs(self.metaDir, exist_ok=True)
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

    def setupWorkdir(
        self,
        doSecureWorkDir: "bool",
        fail_ok: "bool" = False,
        public_key_filenames: "Sequence[AnyPath]" = [],
        private_key_filename: "Optional[AnyPath]" = None,
        private_key_passphrase: "Optional[str]" = None,
    ) -> "Tuple[bool, AbsPath]":
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
            workdir_passphrase_file = cast(
                "AbsPath", os.path.join(uniqueRawWorkDir, WORKDIR_PASSPHRASE_FILE)
            )

            used_public_key_filenames: "Sequence[AnyPath]"
            if os.path.exists(workdir_passphrase_file):
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
                        base_keys_dir = os.path.join(
                            uniqueWorkDir, "meta", "public_keys"
                        )
                        os.makedirs(base_keys_dir, exist_ok=True)
                        key_fns: "MutableSequence[str]" = []
                        manifest = {
                            "creation": datetime.datetime.now(
                                tz=datetime.timezone.utc
                            ).astimezone(),
                            "keys": key_fns,
                        }
                        for i_key, key_fn in enumerate(used_public_key_filenames):
                            dest_fn_basename = f"key_{i_key}.c4gh.public"
                            dest_fn = os.path.join(base_keys_dir, dest_fn_basename)
                            shutil.copyfile(key_fn, dest_fn)
                            key_fns.append(dest_fn_basename)

                        # Last, manifest
                        with open(
                            os.path.join(base_keys_dir, "manifest.json"),
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
        uniqueTempDir = cast("AbsPath", os.path.join(uniqueRawWorkDir, ".TEMP"))
        os.makedirs(uniqueTempDir, exist_ok=True)
        os.chmod(uniqueTempDir, 0o1777)

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
                map(lambda r: (r.started, r.ended, r.exitVal), self.stagedExecutions)
            )
            if self.stagedExecutions is not None
            else [],
            export_stamps=list(map(lambda ea: ea.when, self.runExportActions))
            if self.runExportActions is not None
            else [],
        )

    def enableParanoidMode(self) -> None:
        self.paranoidMode = True

    @staticmethod
    def __read_yaml_config(filename: "AnyPath") -> "WritableWorkflowMetaConfigBlock":
        with open(filename, mode="r", encoding="utf-8") as wcf:
            workflow_meta = unmarshall_namedtuple(yaml.safe_load(wcf))

        return cast("WritableWorkflowMetaConfigBlock", workflow_meta)

    @classmethod
    def __merge_params_from_file(
        cls,
        wfexs: "WfExSBackend",
        base_workflow_meta: "WorkflowMetaConfigBlock",
        replaced_parameters_filename: "AnyPath",
    ) -> "WritableWorkflowMetaConfigBlock":
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
        existing_keys.remove("params")
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
        workflow_meta["params"].update(new_params_meta["params"])

        return workflow_meta

    @classmethod
    def FromWorkDir(
        cls,
        wfexs: "WfExSBackend",
        workflowWorkingDirectory: "AnyPath",
        private_key_filename: "Optional[AnyPath]" = None,
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
    def FromFiles(
        cls,
        wfexs: "WfExSBackend",
        workflowMetaFilename: "AnyPath",
        securityContextsConfigFilename: "Optional[AnyPath]" = None,
        nickname_prefix: "Optional[str]" = None,
        orcids: "Sequence[str]" = [],
        public_key_filenames: "Sequence[AnyPath]" = [],
        private_key_filename: "Optional[AnyPath]" = None,
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
        )

    @classmethod
    def FromStagedRecipe(
        cls,
        wfexs: "WfExSBackend",
        workflow_meta: "WritableWorkflowMetaConfigBlock",
        securityContextsConfigFilename: "Optional[AnyPath]" = None,
        nickname_prefix: "Optional[str]" = None,
        orcids: "Sequence[str]" = [],
        public_key_filenames: "Sequence[AnyPath]" = [],
        private_key_filename: "Optional[AnyPath]" = None,
        private_key_passphrase: "Optional[str]" = None,
        paranoidMode: "bool" = False,
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
            if os.path.exists(securityContextsConfigFilename):
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
        )

    @classmethod
    def FromPreviousInstanceDeclaration(
        cls,
        wfexs: "WfExSBackend",
        wfInstance: "WF",
        securityContextsConfigFilename: "Optional[AnyPath]" = None,
        replaced_parameters_filename: "Optional[AnyPath]" = None,
        nickname_prefix: "Optional[str]" = None,
        orcids: "Sequence[str]" = [],
        public_key_filenames: "Sequence[AnyPath]" = [],
        private_key_filename: "Optional[AnyPath]" = None,
        private_key_passphrase: "Optional[str]" = None,
        secure: "bool" = True,
        paranoidMode: "bool" = False,
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
            workflow_meta = cls.__merge_params_from_file(
                wfexs, workflow_meta, replaced_parameters_filename
            )

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
        )

    @classmethod
    def FromPreviousROCrate(
        cls,
        wfexs: "WfExSBackend",
        workflowROCrateFilename: "AnyPath",
        public_name: "str",  # Mainly used for provenance and exceptions
        securityContextsConfigFilename: "Optional[AnyPath]" = None,
        replaced_parameters_filename: "Optional[AnyPath]" = None,
        nickname_prefix: "Optional[str]" = None,
        orcids: "Sequence[str]" = [],
        public_key_filenames: "Sequence[AnyPath]" = [],
        private_key_filename: "Optional[AnyPath]" = None,
        private_key_passphrase: "Optional[str]" = None,
        secure: "bool" = True,
        paranoidMode: "bool" = False,
    ) -> "WF":
        """
        This class method creates a new staged working directory
        based on the declaration of an existing one
        """

        jsonld_obj = ReadROCrateMetadata(workflowROCrateFilename, public_name)

        (
            repo,
            workflow_type,
            container_type,
            the_containers,
            params,
            environment,
            outputs,
        ) = wfexs.rocrate_toolbox.generateWorkflowMetaFromJSONLD(
            jsonld_obj, public_name
        )
        workflow_pid = wfexs.gen_workflow_pid(repo)
        logging.debug(
            f"Repo {repo} workflow type {workflow_type} container factory {container_type}"
        )
        logging.debug(f"Containers {the_containers}")
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
        if container_type is not None:
            workflow_meta["workflow_config"]["containerType"] = container_type.value

        logging.debug(f"{json.dumps(workflow_meta, indent=4)}")

        if replaced_parameters_filename is not None:
            workflow_meta = cls.__merge_params_from_file(
                wfexs, workflow_meta, replaced_parameters_filename
            )

        # Last, be sure that what it has been generated is correct
        if wfexs.validateConfigFiles(workflow_meta, securityContextsConfigFilename) > 0:
            raise WFException(
                f"Generated WfExS description from {public_name} fails (have a look at the log messages for details)"
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
        )

    @classmethod
    def FromDescription(
        cls,
        wfexs: "WfExSBackend",
        workflow_meta: "WorkflowMetaConfigBlock",
        vault: "SecurityContextVault",
        orcids: "Sequence[str]" = [],
        public_key_filenames: "Sequence[AnyPath]" = [],
        private_key_filename: "Optional[AnyPath]" = None,
        private_key_passphrase: "Optional[str]" = None,
        paranoidMode: "bool" = False,
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

        return cls(
            wfexs,
            workflow_meta["workflow_id"],
            workflow_meta.get("version"),
            descriptor_type=workflow_meta.get("workflow_type"),
            trs_endpoint=workflow_meta.get("trs_endpoint", cls.DEFAULT_TRS_ENDPOINT),
            params=workflow_meta.get("params", dict()),
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
        )

    @classmethod
    def FromForm(
        cls,
        wfexs: "WfExSBackend",
        workflow_meta: "WorkflowMetaConfigBlock",
        orcids: "Sequence[str]" = [],
        public_key_filenames: "Sequence[AnyPath]" = [],
        private_key_filename: "Optional[AnyPath]" = None,
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

        return cls(
            wfexs,
            workflow_meta["workflow_id"],
            workflow_meta.get("version"),
            descriptor_type=workflow_meta.get("workflow_type"),
            trs_endpoint=workflow_meta.get("trs_endpoint", cls.DEFAULT_TRS_ENDPOINT),
            params=workflow_meta.get("params", dict()),
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
        offline: "bool" = False,
        ignoreCache: "bool" = False,
    ) -> None:
        """
        Fetch the whole workflow description based on the data obtained
        from the TRS where it is being published.

        If the workflow id is an URL, it is supposed to be a repository (git, swh, ...),
        and the version will represent either the branch, tag or specific commit.
        So, the whole TRS fetching machinery is bypassed.
        """

        assert self.metaDir is not None
        assert self.workflowDir is not None

        repoDir: "Optional[AbsPath]" = None
        if self.remote_repo is None or ignoreCache:
            (
                repoDir,
                repo,
                self.engineDesc,
                repoEffectiveCheckout,
            ) = self.wfexs.cacheWorkflow(
                workflow_id=workflow_id,
                version_id=version_id,
                trs_endpoint=trs_endpoint,
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
            assert (
                self.workflowDir is not None
            ), "The workflow directory should be defined"
            if os.path.isdir(self.workflowDir):
                shutil.rmtree(self.workflowDir)
            # force_copy is needed to isolate the copy of the workflow
            # so local modifications in a working directory does not
            # poison the cached workflow
            if os.path.isdir(repoDir):
                link_or_copy(repoDir, self.workflowDir, force_copy=True)
            else:
                os.makedirs(self.workflowDir, exist_ok=True)
                if self.repoRelPath is None:
                    self.repoRelPath = cast("RelPath", "workflow.entrypoint")
                link_or_copy(
                    repoDir,
                    cast("AbsPath", os.path.join(self.workflowDir, self.repoRelPath)),
                    force_copy=True,
                )

        # We cannot know yet the dependencies
        localWorkflow = LocalWorkflow(
            dir=self.workflowDir,
            relPath=self.repoRelPath,
            effectiveCheckout=self.repoEffectiveCheckout,
        )
        self.logger.info(
            "materialized workflow repository (checkout {}): {}".format(
                self.repoEffectiveCheckout, self.workflowDir
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
                except WorkflowEngineException:
                    # TODO: store the exceptions, to be shown if no workflow is recognized
                    self.logger.exception(
                        f"Engine {engineDesc.trs_descriptor} did not recognize the workflow as a valid one. Reason:"
                    )
            else:
                raise WFException(
                    "No engine recognized a valid workflow at {}".format(self.repoURL)
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

        self.engine = engine
        self.engineVer = engineVer
        self.localWorkflow = candidateLocalWorkflow

    def setupEngine(
        self,
        offline: "bool" = False,
        ignoreCache: "bool" = False,
        initial_engine_version: "Optional[EngineVersion]" = None,
    ) -> None:
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
            if self.engineVer is not None:
                engine_version = self.engineVer
            else:
                engine_version = initial_engine_version
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
            assert (
                self.consolidatedWorkflowDir is not None
            ), "The consolidated workflow directory should be available here"
            if not offline:
                os.makedirs(self.containersDir, exist_ok=True)
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
            )

    # DEPRECATED?
    def injectInputs(
        self,
        paths: "Sequence[AnyPath]",
        workflowInputs_destdir: "Optional[AbsPath]" = None,
        workflowInputs_cacheDir: "Optional[Union[AbsPath, CacheType]]" = None,
        lastInput: "int" = 0,
    ) -> int:
        warnings.warn(
            "injectInputs is being deprecated", PendingDeprecationWarning, stacklevel=2
        )
        if workflowInputs_destdir is None:
            assert self.inputsDir is not None
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

        for path in paths:
            # We are sending the context name thinking in the future,
            # as it could contain potential hints for authenticated access
            fileuri = urllib.parse.urlunparse(
                ("file", "", os.path.abspath(path), "", "", "")
            )
            matContent = self.wfexs.downloadContent(
                LicensedURI(
                    uri=cast("URIType", fileuri),
                ),
                vault=self.vault,
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
        self,
        formatted_params: "Union[ParamsBlock, Sequence[Mapping[str, Any]]]",
        offline: "bool" = False,
        ignoreCache: "bool" = False,
        lastInput: "int" = 0,
    ) -> "Sequence[MaterializedInput]":
        assert (
            self.inputsDir is not None
        ), "The working directory should not be corrupted beyond basic usage"
        assert (
            self.extrapolatedInputsDir is not None
        ), "The working directory should not be corrupted beyond basic usage"

        theParams, numInputs, the_failed_uris = self.fetchInputs(
            formatted_params,
            workflowInputs_destdir=self.inputsDir,
            workflowExtrapolatedInputs_destdir=self.extrapolatedInputsDir,
            offline=offline,
            ignoreCache=ignoreCache,
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
            ignoreCache=ignoreCache or not cacheable,
            registerInCache=cacheable,
            keep_cache_licence=alt_is_plain,
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
        workflowInputs_destdir: "AbsPath",
        workflowExtrapolatedInputs_destdir: "AbsPath",
        lastInput: "int" = 0,
        offline: "bool" = False,
        ignoreCache: "bool" = False,
    ) -> "Tuple[Sequence[MaterializedInput], int, Sequence[str]]":
        tabconf = inputs.get("tabular")
        if not isinstance(tabconf, dict):
            raise WFException(
                f"Content with uris {linearKey} must have 'tabular' declaration"
            )

        t_newline: "str" = (
            tabconf.get("row-sep", "\\n").encode("utf-8").decode("unicode-escape")
        )
        t_skiplines: "int" = tabconf.get("header-rows", 0)
        t_split = tabconf["column-sep"].encode("utf-8").decode("unicode-escape")
        t_uri_cols: "Sequence[int]" = tabconf["uri-columns"]

        inputDestDir = workflowInputs_destdir
        extrapolatedInputDestDir = workflowExtrapolatedInputs_destdir

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
        cacheable = not self.paranoidMode if inputs.get("cache", True) else False
        if remote_files is not None:
            this_cacheable = cacheable
            this_ignoreCache = ignoreCache
        else:
            this_cacheable = False
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
            newInputDestDir = os.path.realpath(os.path.join(inputDestDir, relative_dir))
            if newInputDestDir.startswith(os.path.realpath(inputDestDir)):
                inputDestDir = cast("AbsPath", newInputDestDir)
                extrapolatedInputDestDir = cast(
                    "AbsPath",
                    os.path.realpath(
                        os.path.join(extrapolatedInputDestDir, relative_dir)
                    ),
                )

        # The storage dir depends on whether it can be cached or not
        storeDir: "Union[CacheType, AbsPath]" = (
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
                    cacheable,
                    inputDestDir,
                    globExplode=None,
                    prefix=str(lastInput) + "_",
                    prettyRelname=pretty_relname,
                    ignoreCache=this_ignoreCache,
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

                with open(
                    t_remote_pair.local, mode="rt", encoding="utf-8", newline=t_newline
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
                secondary_uri_mapping: "MutableMapping[str, str]" = dict()
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
                            ignoreCache=ignoreCache,
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
                            secondary_uri_mapping[
                                t_secondary_remote_pair.licensed_uri.uri
                            ] = t_secondary_remote_pair.local

                # Now, reopen each file to replace URLs by paths
                for i_remote_pair, remote_pair in enumerate(remote_pairs):
                    extrapolated_local = os.path.join(
                        extrapolatedInputDestDir,
                        os.path.relpath(remote_pair.local, inputDestDir),
                    )
                    with open(
                        remote_pair.local,
                        mode="rt",
                        encoding="utf-8",
                        newline=t_newline,
                    ) as tH:
                        with open(
                            extrapolated_local,
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
                                        ]
                                        fixed_row = True

                                if fixed_row:
                                    print(t_split.join(cols), file=tW)
                                else:
                                    print(line, file=tW)

                    # Last, fix it
                    remote_pairs[i_remote_pair] = remote_pair._replace(
                        kind=ContentKind.ContentWithURIs,
                        extrapolated_local=cast("AbsPath", extrapolated_local),
                    )
            else:
                secondary_remote_pairs = None

            theNewInputs.append(
                MaterializedInput(
                    name=linearKey,
                    values=remote_pairs,
                    secondaryInputs=secondary_remote_pairs,
                )
            )

        return theNewInputs, lastInput, the_failed_uris

    def fetchInputs(
        self,
        params: "Union[ParamsBlock, Sequence[ParamsBlock]]",
        workflowInputs_destdir: "AbsPath",
        workflowExtrapolatedInputs_destdir: "AbsPath",
        prefix: "str" = "",
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

        paramsIter = params.items() if isinstance(params, dict) else enumerate(params)
        for key, inputs in paramsIter:
            # We are here for the
            linearKey = prefix + key
            if isinstance(inputs, dict):
                inputClass = inputs.get("c-l-a-s-s")
                if inputClass is not None:
                    if inputClass in (
                        ContentKind.File.name,
                        ContentKind.Directory.name,
                    ):  # input files
                        inputDestDir = workflowInputs_destdir
                        globExplode = None

                        path_tokens = linearKey.split(".")
                        # Filling in the defaults
                        assert len(path_tokens) >= 1
                        pretty_relname = path_tokens[-1]
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
                            autoFilledFile = os.path.join(
                                self.outputsDir, rel_auto_filled, *the_tokens
                            )
                            autoFilledDir = os.path.dirname(autoFilledFile)
                            # This is needed to assure the path exists
                            if autoFilledDir != self.outputsDir:
                                os.makedirs(autoFilledDir, exist_ok=True)

                            theInputs.append(
                                MaterializedInput(
                                    name=linearKey,
                                    values=[autoFilledFile],
                                    autoFilled=True,
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
                                cacheable = (
                                    not self.paranoidMode
                                    if inputs.get("cache", True)
                                    else False
                                )
                                this_ignoreCache = ignoreCache
                            else:
                                contextName = None
                                secondary_remote_files = None
                                cacheable = False
                                this_ignoreCache = True

                            preferred_name_conf = inputs.get("preferred-name")
                            if isinstance(preferred_name_conf, str):
                                pretty_relname = preferred_name_conf
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

                            remote_pairs: "MutableSequence[MaterializedContent]" = []
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
                                    )
                                    remote_pairs.extend(t_remote_pairs)
                                except:
                                    self.logger.exception(
                                        f"Error while fetching primary URI {remote_file}"
                                    )
                                    the_failed_uris.append(remote_file)

                            secondary_remote_pairs: "Optional[MutableSequence[MaterializedContent]]"
                            if (remote_files is not None) and (
                                secondary_remote_files is not None
                            ):
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
                                                ignoreCache=ignoreCache,
                                            )
                                        )
                                        secondary_remote_pairs.extend(
                                            t_secondary_remote_pairs
                                        )
                                    except:
                                        self.logger.exception(
                                            f"Error while fetching secondary URI {secondary_remote_file}"
                                        )
                                        the_failed_uris.append(secondary_remote_file)

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
                            if inputClass == ContentKind.File.name:
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

                    elif inputClass == ContentKind.ContentWithURIs.name:
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
                            ignoreCache=ignoreCache,
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
                    )
                )

        return theInputs, lastInput, the_failed_uris

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

        assert self.formatted_params is not None
        self.materializedParams = self.materializeInputs(
            self.formatted_params, offline=offline, ignoreCache=ignoreCache
        )

        assert self.formatted_environment is not None
        self.materializedEnvironment = self.materializeInputs(
            self.formatted_environment, offline=offline, ignoreCache=ignoreCache
        )

        self.marshallStage()

        return self.getStagedSetup()

    def workdirToBagit(self) -> "bagit.Bag":
        """
        BEWARE: This is a destructive step! So, once run, there is no back!
        """
        assert self.workDir is not None
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
        self,
        outputs_to_inject: "Sequence[Sch_Output]",
        outputs: "Union[Sequence[Sch_Output], Mapping[str, Sch_Output]]",
        default_synthetic_output: "bool",
    ) -> "Sequence[ExpectedOutput]":
        expectedOutputs = []
        known_outputs: "Set[str]" = set()

        outputs_to_process = []
        for output_to_inject in outputs_to_inject:
            fill_from = output_to_inject.get("fillFrom")
            assert isinstance(fill_from, str)
            if fill_from not in known_outputs:
                known_outputs.add(fill_from)
                outputs_to_process.append((fill_from, output_to_inject))

        # TODO: implement parsing of outputs
        outputsIter = (
            outputs.items() if isinstance(outputs, dict) else enumerate(outputs)
        )

        for outputKey, outputDesc in outputsIter:
            # Skip already injected
            if str(outputKey) not in known_outputs:
                known_outputs.add(outputKey)
                outputs_to_process.append((str(outputKey), outputDesc))

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
                else:
                    cardinality = self.CardinalityMapping.get(cardS)

            if cardinality is None:
                cardinality = self.CardinalityMapping[self.DefaultCardinality]

            eOutput = ExpectedOutput(
                name=cast("SymbolicOutputName", output_name),
                kind=self.OutputClassMapping.get(
                    outputDesc.get("c-l-a-s-s"), ContentKind.File
                ),
                preferredFilename=outputDesc.get("preferredName"),
                cardinality=cardinality,
                fillFrom=fillFrom,
                glob=patS,
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

    def executeWorkflow(self, offline: "bool" = False) -> "ExitVal":
        self.unmarshallStage(offline=offline)
        self.unmarshallExecute(offline=offline, fail_ok=True)

        assert self.materializedEngine is not None
        assert self.materializedParams is not None
        assert self.materializedEnvironment is not None
        assert self.expected_outputs is not None

        if self.stagedExecutions is None:
            self.stagedExecutions = []

        stagedExec = WorkflowEngine.ExecuteWorkflow(
            self.materializedEngine,
            self.materializedParams,
            self.materializedEnvironment,
            self.expected_outputs,
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
            vault = SecurityContextVault.FromFile(securityContextFile)
        else:
            vault = SecurityContextVault()

        return self.exportResults(actions, vault, action_ids, fail_ok=fail_ok)

    def _curate_licence_list(
        self, licences: "Sequence[str]"
    ) -> "Sequence[LicenceDescription]":
        # As these licences can be in short format, resolve them to URIs
        expanded_licences: "MutableSequence[LicenceDescription]" = []
        if len(licences) == 0:
            expanded_licences.append(NoLicenceDescription)
        else:
            licence_matcher = self.GetLicenceMatcher()
            rejected_licences: "MutableSequence[str]" = []
            for lic in licences:
                matched_licence = licence_matcher.matchLicence(lic)
                if matched_licence is None:
                    rejected_licences.append(lic)
                else:
                    expanded_licences.append(matched_licence)

            if len(rejected_licences) > 0:
                raise WFException(
                    f"Unsupported license URI scheme(s) or Workflow RO-Crate short license(s): {', '.join(rejected_licences)}"
                )

        return expanded_licences

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

                expanded_licences = self._curate_licence_list(the_licences)
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
        self.marshallExport(overwrite=len(matActions) > 0)

        return matActions, actionErrors

    @property
    def staging_recipe(self) -> "WritableWorkflowMetaConfigBlock":
        workflow_meta: "WritableWorkflowMetaConfigBlock" = {
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
        if self.environment is not None:
            workflow_meta["environment"] = self.environment
        if self.placeholders is not None:
            workflow_meta["placeholders"] = self.placeholders
        if self.outputs is not None:
            workflow_meta["outputs"] = self.outputs
        if self.default_actions is not None:
            workflow_meta["default_actions"] = self.default_actions

        return cast(
            "WritableWorkflowMetaConfigBlock", marshall_namedtuple(workflow_meta)
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
            workflow_meta_filename = os.path.join(
                self.metaDir, WORKDIR_WORKFLOW_META_FILE
            )
            if (
                overwrite
                or not os.path.exists(workflow_meta_filename)
                or os.path.getsize(workflow_meta_filename) == 0
            ):
                staging_recipe = self.staging_recipe
                with open(workflow_meta_filename, mode="w", encoding="utf-8") as wmF:
                    yaml.dump(staging_recipe, wmF, Dumper=YAMLDumper)

            self.configMarshalled = datetime.datetime.fromtimestamp(
                os.path.getctime(workflow_meta_filename), tz=datetime.timezone.utc
            )

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
            workflow_meta_filename = os.path.join(
                self.metaDir, WORKDIR_WORKFLOW_META_FILE
            )
            # If the file does not exist, fail fast
            if (
                not os.path.isfile(workflow_meta_filename)
                or os.stat(workflow_meta_filename).st_size == 0
            ):
                self.logger.debug(
                    f"Marshalled config file {workflow_meta_filename} does not exist or is empty"
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

                    combined_globals = self.__get_combined_globals()
                    stage = unmarshall_namedtuple(marshalled_stage, combined_globals)
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
                    combined_globals = self.__get_combined_globals()
                    execution_read = unmarshall_namedtuple(
                        marshalled_execution, combined_globals
                    )

                    if isinstance(execution_read, dict):
                        executions = [execution_read]
                    else:
                        executions = execution_read

                    self.stagedExecutions = []
                    for execution in executions:
                        # We might need to learn where the metadata of this
                        # specific execution is living
                        outputsDir = execution.get("outputsDir", WORKDIR_OUTPUTS_RELDIR)
                        absOutputMetaDir = os.path.join(
                            self.metaDir, WORKDIR_OUTPUTS_RELDIR
                        )
                        if absOutputMetaDir != WORKDIR_OUTPUTS_RELDIR:
                            jobOutputMetaDir = os.path.join(
                                absOutputMetaDir, os.path.basename(outputsDir)
                            )
                        else:
                            jobOutputMetaDir = absOutputMetaDir

                        # For backward compatibility, let's find the
                        # logfiles and generated charts
                        logfile: "Optional[MutableSequence[RelPath]]" = execution.get(
                            "logfile"
                        )
                        if not isinstance(logfile, list) or len(logfile) == 0:
                            logfile = []
                            for logfname in (
                                WORKDIR_STDOUT_FILE,
                                WORKDIR_STDERR_FILE,
                                "log.txt",
                            ):
                                putative_fname = os.path.join(
                                    jobOutputMetaDir, logfname
                                )
                                if os.path.exists(putative_fname):
                                    logfile.append(
                                        cast(
                                            "RelPath",
                                            os.path.relpath(
                                                putative_fname, self.workDir
                                            ),
                                        )
                                    )
                                    continue

                                if jobOutputMetaDir != absOutputMetaDir:
                                    putative_fname = os.path.join(
                                        absOutputMetaDir, logfname
                                    )
                                    if os.path.exists(putative_fname):
                                        logfile.append(
                                            cast(
                                                "RelPath",
                                                os.path.relpath(
                                                    putative_fname, self.workDir
                                                ),
                                            )
                                        )

                        diagram: "Optional[RelPath]" = execution.get("diagram")
                        if diagram is None:
                            putative_diagram = os.path.join(
                                jobOutputMetaDir,
                                WORKDIR_STATS_RELDIR,
                                STATS_DAG_DOT_FILE,
                            )

                            if os.path.exists(putative_diagram):
                                diagram = cast(
                                    "RelPath",
                                    os.path.relpath(putative_diagram, self.workDir),
                                )
                            elif jobOutputMetaDir != absOutputMetaDir:
                                putative_diagram = os.path.join(
                                    absOutputMetaDir,
                                    WORKDIR_STATS_RELDIR,
                                    STATS_DAG_DOT_FILE,
                                )
                                if os.path.exists(putative_diagram):
                                    diagram = cast(
                                        "RelPath",
                                        os.path.relpath(putative_diagram, self.workDir),
                                    )

                        stagedExec = StagedExecution(
                            exitVal=execution["exitVal"],
                            augmentedInputs=execution["augmentedInputs"],
                            matCheckOutputs=execution["matCheckOutputs"],
                            outputsDir=outputsDir,
                            started=execution.get("started", executionMarshalled),
                            ended=execution.get("ended", executionMarshalled),
                            logfile=logfile,
                            diagram=diagram,
                        )
                        self.stagedExecutions.append(stagedExec)
            except Exception as e:
                errmsg = "Error while unmarshalling content from execution state file {}. Reason: {}".format(
                    marshalled_execution_file, e
                )
                self.executionMarshalled = False
                if fail_ok:
                    self.logger.debug(errmsg)
                    return self.executionMarshalled
                self.logger.exception(errmsg)
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
                    combined_globals = self.__get_combined_globals()
                    self.runExportActions = unmarshall_namedtuple(
                        marshalled_export, combined_globals
                    )

            except Exception as e:
                errmsg = f"Error while unmarshalling content from export results state file {marshalled_export_file}. Reason: {e}"
                self.exportMarshalled = False
                if fail_ok:
                    self.logger.debug(errmsg)
                    return self.exportMarshalled
                else:
                    self.logger.exception(errmsg)
                raise WFException(errmsg) from e

            self.exportMarshalled = datetime.datetime.fromtimestamp(
                os.path.getctime(marshalled_export_file), tz=datetime.timezone.utc
            )

        return self.exportMarshalled

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
                    prettyFilename = cast(
                        "RelPath", os.path.basename(self.staged_setup.inputs_dir)
                    )
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
                            local=cast(
                                "AbsPath",
                                os.path.join(
                                    self.staged_setup.work_dir, stagedExec.outputsDir
                                ),
                            ),
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
                retval.append(
                    MaterializedContent(
                        local=cast("AbsPath", self.staged_setup.work_dir),
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

                create_rocrate(
                    filename=cast("AbsPath", temp_rocrate_file),
                    payloads=payloads_param,
                    licences=licences,
                    resolved_orcids=resolved_orcids,
                    crate_pid=crate_pid,
                )
                retval.append(
                    MaterializedContent(
                        local=cast("AbsPath", temp_rocrate_file),
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
        filename: "Optional[AnyPath]" = None,
        payloads: "CratableItem" = NoCratableItem,
        licences: "Sequence[LicenceDescription]" = [],
        resolved_orcids: "Sequence[ResolvedORCID]" = [],
        crate_pid: "Optional[str]" = None,
    ) -> "AnyPath":
        """
        Create RO-crate from stage provenance.
        """
        # TODO: implement RO-Crate deserialization
        self.unmarshallStage(offline=True, fail_ok=True)

        assert self.localWorkflow is not None
        assert self.materializedEngine is not None
        assert self.remote_repo is not None
        assert self.remote_repo.tag is not None
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
        )

        # Save RO-crate as execution.crate.zip
        if filename is None:
            assert self.outputsDir is not None
            filename = cast(
                "AnyPath", os.path.join(self.outputsDir, self.STAGED_CRATE_FILE)
            )
        wrroc.writeWRROC(filename)

        self.logger.info("Staged RO-Crate created: {}".format(filename))

        return filename

    def createResultsResearchObject(
        self,
        filename: "Optional[AnyPath]" = None,
        payloads: "CratableItem" = NoCratableItem,
        licences: "Sequence[LicenceDescription]" = [],
        resolved_orcids: "Sequence[ResolvedORCID]" = [],
        crate_pid: "Optional[str]" = None,
    ) -> "AnyPath":
        """
        Create RO-crate from stage provenance.
        """
        self.unmarshallExecute(offline=True, fail_ok=True)

        assert self.localWorkflow is not None
        assert self.materializedEngine is not None
        assert self.remote_repo is not None
        assert self.remote_repo.tag is not None
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
            )

        # Save RO-crate as execution.crate.zip
        if filename is None:
            assert self.outputsDir is not None
            filename = cast(
                "AnyPath", os.path.join(self.outputsDir, self.EXECUTION_CRATE_FILE)
            )

        wrroc.writeWRROC(filename)

        self.logger.info("Execution RO-Crate created: {}".format(filename))

        return filename

    _LicenceMatcher: "ClassVar[Optional[LicenceMatcher]]" = None

    @classmethod
    def GetLicenceMatcher(cls) -> "LicenceMatcher":
        if cls._LicenceMatcher is None:
            cls._LicenceMatcher = LicenceMatcherSingleton()
            assert cls._LicenceMatcher is not None

        return cls._LicenceMatcher
