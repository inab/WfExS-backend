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

import abc
import copy
from dataclasses import dataclass
import datetime
import enum
import os
import pathlib
from typing import (
    cast,
    NamedTuple,
    TYPE_CHECKING,
)

if TYPE_CHECKING:
    from typing import (
        Any,
        Callable,
        List,
        Mapping,
        MutableMapping,
        MutableSequence,
        NewType,
        Optional,
        Pattern,
        Sequence,
        Set,
        Tuple,
        Type,
        Union,
    )

    # pylint: disable-next=unused-import
    from typing import (
        Iterator,
    )

    from typing_extensions import (
        Final,
        TypeAlias,
        TypedDict,
    )


# Patching default context in order to load CA certificates from certifi
import certifi
import ssl


def create_augmented_context(
    purpose: "ssl.Purpose" = ssl.Purpose.SERVER_AUTH,
    *,
    cafile: "Optional[str]" = None,
    capath: "Optional[str]" = None,
    cadata: "Optional[Union[str, bytes]]" = None,
) -> "ssl.SSLContext":
    context = ssl.create_default_context(
        purpose=purpose, cafile=cafile, capath=capath, cadata=cadata
    )

    context.load_verify_locations(cafile=certifi.where())

    return context


if ssl._create_default_https_context != create_augmented_context:
    ssl._create_default_https_context = create_augmented_context

if TYPE_CHECKING:
    # Abstraction of names
    SymbolicName = NewType("SymbolicName", str)
    # This is a relative path
    RelPath = NewType("RelPath", str)
    # This is an absolute path
    AbsPath = NewType("AbsPath", str)
    # This is either a relative or an absolute path
    AnyPath: TypeAlias = Union[RelPath, AbsPath]

    PathlibLike: TypeAlias = pathlib.Path
    PathLikePath: TypeAlias = Union[str, os.PathLike[str]]


DEFAULT_DOCKER_CMD = cast("SymbolicName", "docker")
DEFAULT_SINGULARITY_CMD = cast("SymbolicName", "singularity")
DEFAULT_APPTAINER_CMD = cast("SymbolicName", "apptainer")
DEFAULT_PODMAN_CMD = cast("SymbolicName", "podman")
DEFAULT_JAVA_CMD = cast("SymbolicName", "java")
DEFAULT_FUSERMOUNT_CMD = cast("SymbolicName", "fusermount")
DEFAULT_DOT_CMD = cast("SymbolicName", "dot")

if TYPE_CHECKING:
    ProgsMapping: TypeAlias = MutableMapping[SymbolicName, AnyPath]

DEFAULT_PROGS: "ProgsMapping" = {
    DEFAULT_DOCKER_CMD: cast("RelPath", DEFAULT_DOCKER_CMD),
    DEFAULT_SINGULARITY_CMD: cast("RelPath", DEFAULT_SINGULARITY_CMD),
    DEFAULT_APPTAINER_CMD: cast("RelPath", DEFAULT_APPTAINER_CMD),
    DEFAULT_PODMAN_CMD: cast("RelPath", DEFAULT_PODMAN_CMD),
    DEFAULT_JAVA_CMD: cast("RelPath", DEFAULT_JAVA_CMD),
    DEFAULT_FUSERMOUNT_CMD: cast("RelPath", DEFAULT_FUSERMOUNT_CMD),
    DEFAULT_DOT_CMD: cast("RelPath", DEFAULT_DOT_CMD),
}


class EngineMode(enum.Enum):
    Local = "local"
    Docker = "docker"


DEFAULT_ENGINE_MODE = EngineMode.Local

if TYPE_CHECKING:
    WfExSInstanceId = NewType("WfExSInstanceId", str)

    # Abstraction of input params and output names
    SymbolicParamName = NewType("SymbolicParamName", SymbolicName)
    SymbolicOutputName = NewType("SymbolicOutputName", SymbolicName)

    URIType = NewType("URIType", str)
    # The URL of a git repository containing at least one workflow
    RepoURL = NewType("RepoURL", URIType)
    # The tag, branch or hash of a workflow in a git repository
    RepoTag = NewType("RepoTag", str)

    # This is a workflow engine version
    EngineVersion = NewType("EngineVersion", str)

    # This is a workflow language version
    WFLangVersion = NewType("WFLangVersion", str)

    # This represents a fingerprint from an installation, a docker image, etc...
    # It should follow next format
    # {0}={1}
    # where {0} is the name of the digest (sha256, for instance)
    # and {1} is the base64 encoding of the binary digest
    Fingerprint = NewType("Fingerprint", str)

    # Exit value from any kind of execution
    ExitVal = NewType("ExitVal", int)

    SecurityContextConfig: TypeAlias = Mapping[str, Any]
    WritableSecurityContextConfig: TypeAlias = MutableMapping[str, Any]


## BEWARE!!!! The names of these keys MUST NOT CHANGE
## as they match the names appearing at the stage-definitions.json
class ContentKind(enum.Enum):
    File = "file"
    Directory = "dir"
    Value = "val"
    ContentWithURIs = "luris"


class ContainerType(enum.Enum):
    Singularity = "singularity"
    Apptainer = "singularity"
    Docker = "docker"
    UDocker = "udocker"
    Podman = "podman"
    Conda = "conda"
    NoContainer = "none"


# The tagged name of a container
@dataclass
class ContainerTaggedName:
    """
    origTaggedName: Symbolic name or identifier of the container
        (including tag) which appears in the workflow.
    type: Compatible container type with this symbolic name
        Container factories have to decide whether they bear with it.
    registries: an optional mapping from container type to registry,
    to be used by different container materialization solutions.
    """

    origTaggedName: "str"
    type: "ContainerType"
    registries: "Optional[Mapping[ContainerType, str]]" = None


class AttributionRole(enum.Enum):
    """
    The valid roles come from CASRAI CRediT, and can be visited through
    http://credit.niso.org/contributor-roles/{term}/
    """

    Conceptualization = "conceptualization"
    DataCuration = "data-curation"
    FormalAnalysis = "formal-analysis"
    FundingAcquisition = "funding-acquisition"
    Investigation = "investigation"
    Methodology = "methodology"
    ProjectAdministration = "project-administration"
    Resources = "resources"
    Software = "software"
    Supervision = "supervision"
    Validation = "validation"
    Visualization = "visualization"
    WritingOriginalDraft = "writing-original-draft"
    WritingReviewEditing = "writing-review-editing"


class Attribution(NamedTuple):
    # Author
    name: "str"
    # A unique way to represent this author, either through her/his
    # ORCID or another permanent, representative link
    pid: "URIType"
    roles: "Sequence[AttributionRole]" = []

    @classmethod
    def ParseRawAttribution(cls, rawAttribution: "Mapping[str, Any]") -> "Attribution":
        return cls(
            name=rawAttribution["name"],
            pid=rawAttribution["pid"],
            roles=[AttributionRole(rawRole) for rawRole in rawAttribution["roles"]],
        )

    @classmethod
    def ParseRawAttributions(
        cls, rawAttributions: "Optional[Sequence[Mapping[str, Any]]]"
    ) -> "Sequence[Attribution]":
        attributions = []
        if isinstance(rawAttributions, list):
            for rawAttribution in rawAttributions:
                attributions.append(cls.ParseRawAttribution(rawAttribution))

        return attributions


NoLicenceShort: "Final[str]" = "notspecified"
NoLicence: "Final[URIType]" = cast(
    "URIType", "https://choosealicense.com/no-permission/"
)
DefaultNoLicenceTuple: "Tuple[URIType, ...]" = (NoLicence,)


class LicenceDescription(NamedTuple):
    """
    This tuple is used to describe licences
    """

    short: "str"
    uris: "Sequence[URIType]"
    description: "str"
    is_spdx: "bool" = True

    def get_uri(self) -> "URIType":
        if self.is_spdx:
            return cast("URIType", f"https://spdx.org/licenses/{self.short}")
        elif len(self.uris) > 0:
            return self.uris[0]
        # TODO: cover the case of custom licences
        # where text is available, but it is not in any URL
        else:
            return NoLicence


# According to Workflow RO-Crate, this is the term for no license (or not specified)
NoLicenceDescription: "Final[LicenceDescription]" = LicenceDescription(
    short=NoLicenceShort,
    uris=[NoLicence],
    description="No license - no permission to use unless the owner grants a licence",
    is_spdx=False,
)

CC_BY_40_LICENCE: "Final[str]" = "CC-BY-4.0"
CC_BY_40_LicenceDescription: "Final[LicenceDescription]" = LicenceDescription(
    short=CC_BY_40_LICENCE,
    uris=[cast("URIType", "https://creativecommons.org/licenses/by/4.0/")],
    description="Creative Commons Attribution 4.0 International",
)


class MemberPattern(NamedTuple):
    glob: "str"
    place_at: "Optional[RelPath]"


class LicensedURI(NamedTuple):
    """
    uri: The uri
    licence: The licence associated to the dataset behind this URI
    attributions: The attributions associated to the dataset pointed
    out by this URI
    secContext: The optional, security context to use when the uri
    has to be accessed. This is useful for use cases like DRS, where
    it can provide the authentication metadata
    """

    uri: "URIType"
    # One or more licence URLs, either from a repository, or a site like
    # choosealicense.com or spdx.org/licenses/
    licences: "Tuple[Union[URIType, LicenceDescription], ...]" = DefaultNoLicenceTuple
    attributions: "Sequence[Attribution]" = []
    secContext: "Optional[SecurityContextConfig]" = None
    members: "Sequence[MemberPattern]" = []


if TYPE_CHECKING:
    AnyURI: TypeAlias = Union[URIType, LicensedURI]

    class ORCIDPublicRecord(TypedDict):
        title: Optional[str]
        displayName: Optional[str]
        names: Optional[Mapping[str, Any]]
        biography: Optional[Any]
        otherNames: Optional[Mapping[str, Any]]
        countries: Optional[Mapping[str, Any]]
        keyword: Optional[Mapping[str, Any]]
        emails: Optional[Mapping[str, Any]]
        externalIdentifier: Optional[Mapping[str, Any]]
        website: Optional[Mapping[str, Any]]
        lastModifiedTime: Optional[int]


class URIWithMetadata(NamedTuple):
    """
    uri: The uri, which can be either a raw or an annotated one
    metadata: A dictionary with the metadata associated to that URI.
    preferredName: A pretty way to name this resource. Workflow
        execution can decide whether to honour it or not
    """

    uri: "URIType"
    metadata: "Mapping[str, Any]"
    preferredName: "Optional[RelPath]" = None


class ResolvedORCID(NamedTuple):
    """
    A resolved ORCID

    orcid: The resolved ORCID id
    url: The URL of the ORCID profile
    record: The fetched, public ORCID record
    record_fetch_metadata: Metadata about the resolution process
    """

    orcid: "str"
    url: "URIType"
    record: "ORCIDPublicRecord"
    record_fetch_metadata: "Sequence[URIWithMetadata]"


class MaterializedContent(NamedTuple):
    """
    local: Local absolute path of the content which was materialized. It
      can be either a path in the cached inputs directory, or an absolute
      path in the inputs directory of the execution
    licensed_uri: Either an URL or a CURIE of the content which was materialized,
      needed for the provenance
    prettyFilename: The preferred filename to use in the inputs directory
      of the execution environment
    kind: The kind of content, either file, directory, value or something more complex.
    fingerprint: If it is available, propagate the computed fingerprint
      from the cache.
    clonable: If it is true, copies of this materialized content can be
      performed. Otherwise, content should remain in the original place
      represented by "local".
    reference_uri: This is needed to refer the fetched dataset source of
      this content.
    reference_kind: This is needed to declare whether the fetched dataset
      was materialized either as a File or as a Directory.
    """

    local: "PathlibLike"
    licensed_uri: "LicensedURI"
    prettyFilename: "RelPath"
    kind: "ContentKind" = ContentKind.File
    metadata_array: "Optional[Sequence[URIWithMetadata]]" = None
    extrapolated_local: "Optional[PathlibLike]" = None
    fingerprint: "Optional[Fingerprint]" = None
    clonable: "bool" = True
    reference_uri: "Optional[LicensedURI]" = None
    reference_kind: "Optional[ContentKind]" = None
    reference_size: "Optional[int]" = None
    reference_mime: "Optional[str]" = None
    reference_fingerprint: "Optional[Fingerprint]" = None

    @classmethod
    def _mapping_fixes(
        cls, orig: "Mapping[str, Any]", workdir: "Optional[pathlib.Path]"
    ) -> "Mapping[str, Any]":
        dest = cast("MutableMapping[str, Any]", copy.copy(orig))
        dest["local"] = pathlib.Path(orig["local"])
        if workdir is not None and not dest["local"].is_absolute():
            dest["local"] = (workdir / dest["local"]).resolve()

        extra = orig.get("extrapolated_local")
        if extra is not None:
            dest["extrapolated_local"] = pathlib.Path(extra)
            if workdir is not None and not dest["extrapolated_local"].is_absolute():
                dest["extrapolated_local"] = (
                    workdir / dest["extrapolated_local"]
                ).resolve()

        return dest

    @classmethod
    def _key_fixes(cls) -> "Mapping[str, str]":
        return {"uri": "licensed_uri"}


if TYPE_CHECKING:
    MaterializedInputValues: TypeAlias = Union[
        Sequence[bool],
        Sequence[str],
        Sequence[int],
        Sequence[float],
        None,
        Sequence[MaterializedContent],
    ]


if TYPE_CHECKING:

    class ContentWithURIsSetup(TypedDict):
        """
        headerRows: Number of header rows
        rowSep: Line separator
        columnSep: Expression used to break a line into its column values
        uriColumns: The 0-based numbers of the columns containing URIs to be fetched
        """

        headerRows: "int"
        rowSep: "str"
        columnSep: "str"
        uriColumns: "Sequence[int]"


class ContentWithURIsDesc(NamedTuple):
    """
    encodingFormat: the kind of content with URIs (currently implemented is text/csv => tabular)
    setup: The dictionary describing the setup
    """

    encodingFormat: "str"
    setup: "ContentWithURIsSetup"


class MaterializedInput(NamedTuple):
    """
    name: Name of the input
    values: list of associated values, which can be literal ones or
      instances from MaterializedContent
    """

    name: "SymbolicParamName"
    values: "MaterializedInputValues"
    secondaryInputs: "Optional[Sequence[MaterializedContent]]" = None
    autoFilled: "bool" = False
    implicit: "bool" = False
    contentWithURIs: "Optional[ContentWithURIsDesc]" = None
    disclosable: "bool" = True

    @staticmethod
    def path_tokens_2_linear_key(path_tokens: "Sequence[str]") -> "SymbolicParamName":
        """
        Translating a structured key into a linear input name, usable as key
        """
        return cast(
            "SymbolicParamName",
            ".".join(map(lambda p: "'" + p + "'" if "." in p else p, path_tokens)),
        )

    @staticmethod
    def linear_key_2_path_tokens(linear_key: "str") -> "Tuple[str, ...]":
        """
        Translating an input name into a structured key,
        removing quotes whenever it is needed
        """
        path_tokens: "MutableSequence[str]" = []

        token: "str" = ""
        for path_token in linear_key.split("."):
            if len(token) > 0:
                token += "." + path_token
            elif len(path_token) > 1 and path_token[0] == "'":
                token = path_token[1:]
            else:
                path_tokens.append(path_token)

            if len(token) > 1 and token[-1] == "'":
                path_tokens.append(token[0:-1])
                token = ""

        # This one should never happen
        if len(token) > 0:
            path_tokens.append(token)

        return tuple(path_tokens)


if TYPE_CHECKING:
    GlobPattern = NewType("GlobPattern", str)


class ExpectedOutput(NamedTuple):
    """
    name: Name of the output. If the workflow engine allows using
      symbolic names attached to the outputs, this name must match that.
      Otherwise, a matching pattern must be defined.
    kind: The kind of output. Either an atomic value.
    preferredFilename: Relative "pretty" name which is going to be used
      to export the file to external storage.
    cardinality: Whether it is expected to be optional, a single value or
      multiple ones.
    glob: When the workflow engine does not use symbolic
      names to label the outputs, this is the filename pattern to capture the
      local path, based on the output / working directory.
    syntheticOutput: It is true for outputs which do not really exist
    either as parameter or explicit outputs.
    """

    name: "SymbolicOutputName"
    kind: "ContentKind"
    preferredFilename: "Optional[RelPath]"
    cardinality: "Tuple[int, int]"
    fillFrom: "Optional[SymbolicParamName]" = None
    glob: "Optional[GlobPattern]" = None
    syntheticOutput: "Optional[bool]" = None

    def _marshall(self) -> "MutableMapping[str, Any]":
        mD: "MutableMapping[str, Any]" = {
            "c-l-a-s-s": self.kind.name,
            "cardinality": list(self.cardinality),
        }

        if self.preferredFilename is not None:
            mD["preferredName"] = self.preferredFilename
        if self.glob is not None:
            mD["glob"] = self.glob
        if self.fillFrom is not None:
            mD["fillFrom"] = self.fillFrom
        if self.syntheticOutput is not None:
            mD["syntheticOutput"] = self.syntheticOutput

        return mD

    @classmethod
    def _unmarshall(cls, **obj: "Any") -> "ExpectedOutput":
        return cls(
            name=obj["name"],
            kind=ContentKind(obj["c-l-a-s-s"])
            if "c-l-a-s-s" in obj
            else ContentKind.File,
            preferredFilename=obj.get("preferredName"),
            fillFrom=obj.get("fillFrom"),
            glob=obj.get("glob"),
            cardinality=cast("Tuple[int, int]", tuple(obj["cardinality"])),
            syntheticOutput=cast("Optional[bool]", obj.get("syntheticOutput")),
        )


@dataclass
class AbstractGeneratedContent(abc.ABC):
    """
    local: Local absolute path of the content which was generated. It
      is an absolute path in the outputs directory of the execution.
    uri: A putative URL or a CURIE of the content which was generated,
      needed for the provenance and upload matters.
    signature: Computed checksum from the file
    preferredFilename: The preferred relative filename to use when it is
      uploaded from the computational environment
    """

    local: "PathlibLike"
    signature: "Optional[Fingerprint]" = None
    uri: "Optional[LicensedURI]" = None
    preferredFilename: "Optional[RelPath]" = None

    @classmethod
    def _mapping_fixes(
        cls, orig: "Mapping[str, Any]", workdir: "Optional[pathlib.Path]"
    ) -> "Mapping[str, Any]":
        dest = cast("MutableMapping[str, Any]", copy.copy(orig))
        dest["local"] = pathlib.Path(orig["local"])
        if workdir is not None and not dest["local"].is_absolute():
            dest["local"] = (workdir / dest["local"]).resolve()

        return dest


@dataclass
class GeneratedContent(AbstractGeneratedContent):
    """
    local: Local absolute path of the content which was generated. It
      is an absolute path in the outputs directory of the execution.
    uri: A putative URL or a CURIE of the content which was generated,
      needed for the provenance and upload matters.
    signature: Computed checksum from the file
    preferredFilename: The preferred relative filename to use when it is
      uploaded from the computational environment
    """

    # This was done because it is not possible to refer to itself
    secondaryFiles: "Optional[Sequence[AbstractGeneratedContent]]" = None


@dataclass
class GeneratedDirectoryContent(AbstractGeneratedContent):
    """
    local: Local absolute path of the content which was generated. It
      is an absolute path in the outputs directory of the execution.
    uri: A putative URL or a CURIE of the content which was generated,
      needed for the provenance and upload matters.
    values: The list of contents of the directory, which are either
      GeneratedContent or GeneratedDirectoryContent
    signature: Optional computed checksum from the directory
    preferredFilename: The preferred relative filename to use when it is
      uploaded from the computational environment
    """

    values: "Optional[Sequence[AbstractGeneratedContent]]" = (
        None  # It should be List[Union[GeneratedContent, GeneratedDirectoryContent]]
    )
    secondaryFiles: "Optional[Sequence[AbstractGeneratedContent]]" = None


if TYPE_CHECKING:
    AnyContent: TypeAlias = Union[MaterializedContent, AbstractGeneratedContent]


class MaterializedOutput(NamedTuple):
    """
    name: Name of the output. It should be a public identifier whenever it is possible
    expectedCardinality: Whether it was expected to be optional, a single value or
      multiple ones.
    local: Local absolute path of the output
    prettyFilename: Relative "pretty" name to be used in provenance
    """

    name: "SymbolicOutputName"
    kind: "ContentKind"
    expectedCardinality: "Tuple[int, int]"
    values: "Union[Sequence[bool], Sequence[str], Sequence[int], Sequence[float], None, Sequence[AbstractGeneratedContent]]"
    syntheticOutput: "Optional[bool]" = None
    filledFrom: "Optional[str]" = None
    glob: "Optional[GlobPattern]" = None


class LocalWorkflow(NamedTuple):
    """
    dir: The path to the directory where the checkout was applied
    relPath: Inside the checkout, the relative path to the workflow definition
    effectiveCheckout: hex hash of the materialized checkout
    langVersion: workflow language version / revision
    relPathFiles: files and directories composing the workflow, which can
    be either local or remote ones (i.e. CWL)
    """

    dir: "PathlibLike"
    relPath: "Optional[RelPath]"
    effectiveCheckout: "Optional[RepoTag]"
    langVersion: "Optional[Union[EngineVersion, WFLangVersion]]" = None
    relPathFiles: "Optional[Sequence[Union[RelPath, URIType]]]" = None

    @classmethod
    def _mapping_fixes(
        cls, orig: "Mapping[str, Any]", workdir: "Optional[pathlib.Path]"
    ) -> "Mapping[str, Any]":
        dest = cast("MutableMapping[str, Any]", copy.copy(orig))
        dest["dir"] = pathlib.Path(orig["dir"])
        if workdir is not None and not dest["dir"].is_absolute():
            dest["dir"] = (workdir / dest["dir"]).resolve()

        return dest


if TYPE_CHECKING:
    TRS_Workflow_Descriptor: TypeAlias = str


class StagedSetup(NamedTuple):
    instance_id: "WfExSInstanceId"
    container_type: "ContainerType"
    nickname: "Optional[str]"
    creation: "datetime.datetime"
    workflow_config: "Optional[Mapping[str, Any]]"
    engine_tweaks_dir: "Optional[pathlib.Path]"
    raw_work_dir: "pathlib.Path"
    work_dir: "Optional[pathlib.Path]"
    workflow_dir: "Optional[pathlib.Path]"
    consolidated_workflow_dir: "Optional[pathlib.Path]"
    inputs_dir: "Optional[pathlib.Path]"
    extrapolated_inputs_dir: "Optional[pathlib.Path]"
    outputs_dir: "Optional[pathlib.Path]"
    intermediate_dir: "Optional[pathlib.Path]"
    containers_dir: "Optional[pathlib.Path]"
    meta_dir: "Optional[pathlib.Path]"
    temp_dir: "pathlib.Path"
    secure_exec: "bool"
    allow_other: "bool"
    is_encrypted: "bool"
    is_damaged: "bool"


class ExecutionStatus(enum.Enum):
    """
    The status of a workflow execution
    """

    Queued = "queued"
    Running = "running"
    Finished = "finished"
    Died = "died"


class MarshallingStatus(NamedTuple):
    pid: "Optional[str]"
    workflow_type: "Optional[str]"
    container_type: "Optional[ContainerType]"
    config: "Optional[Union[bool, datetime.datetime]]"
    stage: "Optional[Union[bool, datetime.datetime]]"
    execution: "Optional[Union[bool, datetime.datetime]]"
    export: "Optional[Union[bool, datetime.datetime]]"
    execution_stats: "Optional[Sequence[Tuple[str, ExecutionStatus, Optional[datetime.datetime], datetime.datetime, datetime.datetime, ExitVal]]]"
    export_stamps: "Optional[Sequence[datetime.datetime]]"

    def __repr__(self) -> "str":
        return f"""\
* Workflow PID: {self.pid}
* Workflow type: {self.workflow_type}
* Container type: {'none' if self.container_type is None else self.container_type.value}
* Marshalling date status:
  - config: {"(never done)" if self.config is None  else  self.config.isoformat()  if isinstance(self.config, datetime.datetime)  else  "(failed/not done yet)"}
  - stage: {"(never done)" if self.stage is None  else  self.stage.isoformat()  if isinstance(self.stage, datetime.datetime)  else  "(failed/not done yet)"}
  - execution: {"(never done)" if self.execution is None  else  self.execution.isoformat()  if isinstance(self.execution, datetime.datetime)  else  "(failed/not done yet)"}
  - export: {"(never done)" if self.export is None  else  self.export.isoformat()  if isinstance(self.export, datetime.datetime)  else  "(failed/not done yet)"}
* Execution stats:
{'  (none)' if self.execution_stats is None or len(self.execution_stats) == 0 else chr(10).join(map(lambda ss: ' - Job ' + ss[0] + '. Status: ' + ss[1].value + ' (queued ' + (ss[2].isoformat() if ss[2] is not None else '(unknown)') + ' , started ' + ss[3].isoformat() + ' , ended ' + ss[4].isoformat() + ' ) (exit ' + str(ss[5]) + ')', self.execution_stats))}
* Exported at:
{'  (none)' if self.export_stamps is None or len(self.export_stamps) == 0 else chr(10).join(map(lambda ea: '  - ' + ea.isoformat(), self.export_stamps))}\
"""


DEFAULT_CONTAINER_TYPE = ContainerType.Singularity

# Postfix of metadata files (generated by the instances)
META_JSON_POSTFIX: "Final[str]" = "_meta.json"


class AbstractWfExSException(Exception):
    pass


# Adapted from https://gist.github.com/ptmcg/23ba6e42d51711da44ba1216c53af4ea
# in order to show the value instead of the class name
import argparse


class ArgTypeMixin(enum.Enum):
    @classmethod
    def argtype(cls, s: "str") -> "enum.Enum":
        try:
            return cls(s)
        except:
            raise argparse.ArgumentTypeError(f"{s!r} is not a valid {cls.__name__}")

    def __str__(self) -> "str":
        return str(self.value)


class StrDocEnum(str, ArgTypeMixin):
    # Learnt from https://docs.python.org/3.11/howto/enum.html#when-to-use-new-vs-init
    description: str

    def __new__(cls, value: "Any", description: "str" = "") -> "StrDocEnum":
        obj = str.__new__(cls, value)
        obj._value_ = value
        obj.description = description

        return obj

    def __str__(self) -> "str":
        return str(self.value)


class ArgsDefaultWithRawHelpFormatter(argparse.ArgumentDefaultsHelpFormatter):
    # Conditionally treat descriptions as raw
    def _split_lines(self, text: "str", width: "int") -> "List[str]":
        """
        Formats the given text by splitting the lines at '\n'.
        Overrides argparse.HelpFormatter._split_lines function.

        :param text: help text passed by ArgumentParser.HelpFormatter
        :param width: console width passed by argparse.HelpFormatter
        :return: argparse.HelpFormatter._split_lines function
        with new split text argument.
        """
        if text.startswith("raw|"):
            return text[4:].splitlines()
        return super()._split_lines(text, width)


# These cache types are needed to return the right paths
# from an WF instance
class CacheType(StrDocEnum):
    Input = ("input", "Cached or injected inputs")
    ROCrate = ("ro-crate", "Cached RO-Crates (usually from WorkflowHub)")
    TRS = ("ga4gh-trs", "Cached files from tools described at GA4GH TRS repositories")
    Workflow = ("workflow", "Cached workflows, which come from a git repository")


class ExportItemType(enum.Enum):
    """
    Types of items which can be exported as such
    """

    Param = "param"
    Environment = "envvar"
    Output = "output"
    WorkingDirectory = "working-directory"
    StageCrate = "stage-rocrate"
    ProvenanceCrate = "provenance-rocrate"


class CratableItem(enum.IntFlag):
    """
    What can be materialized in the RO-Crate
    """

    Workflow = enum.auto()
    Containers = enum.auto()
    Inputs = enum.auto()
    Outputs = enum.auto()
    ProspectiveProvenance = Workflow | Containers | Inputs
    RetrospectiveProvenance = ProspectiveProvenance | Outputs


NoCratableItem = CratableItem(0)
