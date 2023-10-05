#!/usr/bin/env python
# -*- coding: utf-8 -*-

# SPDX-License-Identifier: Apache-2.0
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

import abc
from dataclasses import dataclass
import datetime
import enum
import os
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
    # This is also an absolute path
    EnginePath = NewType("EnginePath", AbsPath)

    # This is a container engine version
    ContainerEngineVersionStr = NewType("ContainerEngineVersionStr", str)
    WorkflowEngineVersionStr = NewType("WorkflowEngineVersionStr", str)
    ContainerOperatingSystem = NewType("ContainerOperatingSystem", str)
    ProcessorArchitecture = NewType("ProcessorArchitecture", str)

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
    SecurityContextConfigBlock: TypeAlias = Mapping[str, SecurityContextConfig]

    # TODO: study using TypedDict
    LocalConfig: TypeAlias = Mapping[str, Any]
    ContainerLocalConfig: TypeAlias = Mapping[str, Any]
    EngineLocalConfig: TypeAlias = Mapping[str, Any]
    WorkflowConfigBlock: TypeAlias = Mapping[str, Any]
    WorkflowMetaConfigBlock: TypeAlias = Mapping[str, Any]
    WritableWorkflowMetaConfigBlock: TypeAlias = MutableMapping[str, Any]
    WfExSConfigBlock: TypeAlias = Mapping[str, Any]
    WritableWfExSConfigBlock: TypeAlias = MutableMapping[str, Any]
    ExportActionBlock: TypeAlias = Mapping[str, Any]
    ParamsBlock: TypeAlias = Mapping[str, Any]
    EnvironmentBlock: TypeAlias = Mapping[str, Any]
    MutableParamsBlock: TypeAlias = MutableMapping[str, Any]
    OutputsBlock: TypeAlias = Mapping[str, Any]
    PlaceHoldersBlock: TypeAlias = Mapping[str, Union[int, float, str]]

    # As each workflow engine can have its own naming convention, leave them to
    # provide it
    ContainerFileNamingMethod: TypeAlias = Callable[[URIType], RelPath]


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


# Licences
AcceptableLicenceSchemes: "Final[Set[str]]" = {
    "ftp",
    "http",
    "https",
    "data",
}
NoLicence: "Final[URIType]" = cast(
    "URIType", "https://choosealicense.com/no-permission/"
)
DefaultNoLicenceTuple: "Tuple[URIType, ...]" = (NoLicence,)

# According to Workflow RO-Crate, this is the term for no license (or not specified)
NoLicenceShort: "Final[str]" = "notspecified"

# The correspondence from short Workflow RO-Crate licences and their URIs
# taken from https://about.workflowhub.eu/Workflow-RO-Crate/#supported-licenses
ROCrateShortLicences: "Final[Mapping[str, str]]" = {
    "AFL-3.0": "https://opensource.org/licenses/AFL-3.0",  # - Academic Free License 3.0
    "APL-1.0": "https://opensource.org/licenses/APL-1.0",  # - Adaptive Public License 1.0
    "Apache-1.1": "https://opensource.org/licenses/Apache-1.1",  # - Apache Software License 1.1
    "Apache-2.0": "https://opensource.org/licenses/Apache-2.0",  # - Apache Software License 2.0
    "APSL-2.0": "https://opensource.org/licenses/APSL-2.0",  # - Apple Public Source License 2.0
    "Artistic-2.0": "https://opensource.org/licenses/Artistic-2.0",  # - Artistic License 2.0
    "AAL": "https://opensource.org/licenses/AAL",  # - Attribution Assurance Licenses
    "BSD-2-Clause": "https://opensource.org/licenses/BSD-2-Clause",  # - BSD 2-Clause “Simplified” or “FreeBSD” License (BSD-2-Clause)
    "BSD-3-Clause": "https://opensource.org/licenses/BSD-3-Clause",  # - BSD 3-Clause “New” or “Revised” License (BSD-3-Clause)
    "BitTorrent-1.1": "https://spdx.org/licenses/BitTorrent-1.1",  # - BitTorrent Open Source License 1.1
    "BSL-1.0": "https://opensource.org/licenses/BSL-1.0",  # - Boost Software License 1.0
    "CC0-1.0": "https://creativecommons.org/publicdomain/zero/1.0/",  # - CC0 1.0
    "CNRI-Python": "https://opensource.org/licenses/CNRI-Python",  # - CNRI Python License
    "CUA-OPL-1.0": "https://opensource.org/licenses/CUA-OPL-1.0",  # - CUA Office Public License 1.0
    "CECILL-2.1": "https://opensource.org/licenses/CECILL-2.1",  # - CeCILL License 2.1
    "CDDL-1.0": "https://opensource.org/licenses/CDDL-1.0",  # - Common Development and Distribution License 1.0
    "CPAL-1.0": "https://opensource.org/licenses/CPAL-1.0",  # - Common Public Attribution License 1.0
    "CATOSL-1.1": "https://opensource.org/licenses/CATOSL-1.1",  # - Computer Associates Trusted Open Source License 1.1 (CATOSL-1.1)
    "EUDatagrid": "https://opensource.org/licenses/EUDatagrid",  # - EU DataGrid Software License
    "EPL-1.0": "https://opensource.org/licenses/EPL-1.0",  # - Eclipse Public License 1.0
    "ECL-2.0": "https://opensource.org/licenses/ECL-2.0",  # - Educational Community License 2.0
    "EFL-2.0": "https://opensource.org/licenses/EFL-2.0",  # - Eiffel Forum License 2.0
    "Entessa": "https://opensource.org/licenses/Entessa",  # - Entessa Public License
    "EUPL-1.1": "https://opensource.org/licenses/EUPL-1.1",  # - European Union Public License 1.1
    "Fair": "https://opensource.org/licenses/Fair",  # - Fair License
    "Frameworx-1.0": "https://opensource.org/licenses/Frameworx-1.0",  # - Frameworx License 1.0
    "AGPL-3.0": "https://opensource.org/licenses/AGPL-3.0",  # - GNU Affero General Public License v3
    "GPL-2.0": "https://opensource.org/licenses/GPL-2.0",  # - GNU General Public License 2.0
    "GPL-3.0": "https://opensource.org/licenses/GPL-3.0",  # - GNU General Public License 3.0
    "LGPL-2.1": "https://opensource.org/licenses/LGPL-2.1",  # - GNU Lesser General Public License 2.1
    "LGPL-3.0": "https://opensource.org/licenses/LGPL-3.0",  # - GNU Lesser General Public License 3.0
    "HPND": "https://opensource.org/licenses/HPND",  # - Historical Permission Notice and Disclaimer
    "IPL-1.0": "https://opensource.org/licenses/IPL-1.0",  # - IBM Public License 1.0
    "IPA": "https://opensource.org/licenses/IPA",  # - IPA Font License
    "ISC": "https://opensource.org/licenses/ISC",  # - ISC License
    "Intel": "https://opensource.org/licenses/Intel",  # - Intel Open Source License
    "LPPL-1.3c": "https://opensource.org/licenses/LPPL-1.3c",  # - LaTeX Project Public License 1.3c
    "LPL-1.0": "https://opensource.org/licenses/LPL-1.0",  # - Lucent Public License (“Plan9”) 1.0
    "LPL-1.02": "https://opensource.org/licenses/LPL-1.02",  # - Lucent Public License 1.02
    "MIT": "https://opensource.org/licenses/MIT",  # - MIT License
    "mitre": "https://opensource.org/licenses/CVW",  # - MITRE Collaborative Virtual Workspace License (CVW License)
    "MS-PL": "https://opensource.org/licenses/MS-PL",  # - Microsoft Public License
    "MS-RL": "https://opensource.org/licenses/MS-RL",  # - Microsoft Reciprocal License
    "MirOS": "https://opensource.org/licenses/MirOS",  # - MirOS Licence
    "Motosoto": "https://opensource.org/licenses/Motosoto",  # - Motosoto License
    "MPL-1.0": "https://opensource.org/licenses/MPL-1.0",  # - Mozilla Public License 1.0
    "MPL-1.1": "https://opensource.org/licenses/MPL-1.1",  # - Mozilla Public License 1.1
    "MPL-2.0": "https://opensource.org/licenses/MPL-2.0",  # - Mozilla Public License 2.0
    "Multics": "https://opensource.org/licenses/Multics",  # - Multics License
    "NASA-1.3": "https://opensource.org/licenses/NASA-1.3",  # - NASA Open Source Agreement 1.3
    "NTP": "https://opensource.org/licenses/NTP",  # - NTP License
    "Naumen": "https://opensource.org/licenses/Naumen",  # - Naumen Public License
    "NGPL": "https://opensource.org/licenses/NGPL",  # - Nethack General Public License
    "Nokia": "https://opensource.org/licenses/Nokia",  # - Nokia Open Source License
    "NPOSL-3.0": "https://opensource.org/licenses/NPOSL-3.0",  # - Non-Profit Open Software License 3.0
    "OCLC-2.0": "https://opensource.org/licenses/OCLC-2.0",  # - OCLC Research Public License 2.0
    "OFL-1.1": "https://opensource.org/licenses/OFL-1.1",  # - Open Font License 1.1
    "OGL-UK-1.0": "https://www.nationalarchives.gov.uk/doc/open-government-licence/version/1/",  # - Open Government Licence 1.0 (United Kingdom)
    "OGL-UK-2.0": "https://www.nationalarchives.gov.uk/doc/open-government-licence/version/2/",  # - Open Government Licence 2.0 (United Kingdom)
    "OGL-UK-3.0": "https://www.nationalarchives.gov.uk/doc/open-government-licence/version/3/",  # - Open Government Licence 3.0 (United Kingdom)
    "OGTSL": "https://opensource.org/licenses/OGTSL",  # - Open Group Test Suite License
    "OSL-3.0": "https://opensource.org/licenses/OSL-3.0",  # - Open Software License 3.0
    "PHP-3.0": "https://opensource.org/licenses/PHP-3.0",  # - PHP License 3.0
    "PostgreSQL": "https://opensource.org/licenses/PostgreSQL",  # - PostgreSQL License
    "Python-2.0": "https://opensource.org/licenses/Python-2.0",  # - Python License 2.0
    "QPL-1.0": "https://opensource.org/licenses/QPL-1.0",  # - Q Public License 1.0
    "RPSL-1.0": "https://opensource.org/licenses/RPSL-1.0",  # - RealNetworks Public Source License 1.0
    "RPL-1.5": "https://opensource.org/licenses/RPL-1.5",  # - Reciprocal Public License 1.5
    "RSCPL": "https://opensource.org/licenses/RSCPL",  # - Ricoh Source Code Public License
    "SimPL-2.0": "https://opensource.org/licenses/SimPL-2.0",  # - Simple Public License 2.0
    "Sleepycat": "https://opensource.org/licenses/Sleepycat",  # - Sleepycat License
    "SISSL": "https://opensource.org/licenses/SISSL",  # - Sun Industry Standards Source License 1.1
    "SPL-1.0": "https://opensource.org/licenses/SPL-1.0",  # - Sun Public License 1.0
    "Watcom-1.0": "https://opensource.org/licenses/Watcom-1.0",  # - Sybase Open Watcom Public License 1.0
    "NCSA": "https://opensource.org/licenses/NCSA",  # - University of Illinois/NCSA Open Source License
    "Unlicense": "https://unlicense.org/",  # - Unlicense
    "VSL-1.0": "https://opensource.org/licenses/VSL-1.0",  # - Vovida Software License 1.0
    "W3C": "https://opensource.org/licenses/W3C",  # - W3C License
    "Xnet": "https://opensource.org/licenses/Xnet",  # - X.Net License
    "ZPL-2.0": "https://opensource.org/licenses/ZPL-2.0",  # - Zope Public License 2.0
    "WXwindows": "https://opensource.org/licenses/WXwindows",  # - wxWindows Library License
    "Zlib": "https://opensource.org/licenses/Zlib",  # - zlib/libpng license
    NoLicenceShort: NoLicence,  # - No license - no permission to use unless the owner grants a licence
}


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
    licences: "Tuple[URIType, ...]" = DefaultNoLicenceTuple
    attributions: "Sequence[Attribution]" = []
    secContext: "Optional[SecurityContextConfig]" = None


if TYPE_CHECKING:
    AnyURI: TypeAlias = Union[URIType, LicensedURI]


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


class MaterializedContent(NamedTuple):
    """
    local: Local absolute path of the content which was materialized. It
      can be either a path in the cached inputs directory, or an absolute
      path in the inputs directory of the execution
    licensed_uri: Either an URL or a CURIE of the content which was materialized,
      needed for the provenance
    prettyFilename: The preferred filename to use in the inputs directory
      of the execution environment
    fingerprint: If it is available, propagate the computed fingerprint
      from the cache.
    """

    local: "AbsPath"
    licensed_uri: "LicensedURI"
    prettyFilename: "RelPath"
    kind: "ContentKind" = ContentKind.File
    metadata_array: "Optional[Sequence[URIWithMetadata]]" = None
    extrapolated_local: "Optional[AbsPath]" = None
    fingerprint: "Optional[Fingerprint]" = None

    @classmethod
    def _key_fixes(cls) -> "Mapping[str, str]":
        return {"uri": "licensed_uri"}


if TYPE_CHECKING:
    MaterializedInputValues: TypeAlias = Union[
        Sequence[bool],
        Sequence[str],
        Sequence[int],
        Sequence[float],
        Sequence[MaterializedContent],
    ]


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
    """

    name: "SymbolicOutputName"
    kind: "ContentKind"
    preferredFilename: "Optional[RelPath]"
    cardinality: "Tuple[int, int]"
    fillFrom: "Optional[SymbolicParamName]" = None
    glob: "Optional[GlobPattern]" = None

    def _marshall(self) -> "MutableMapping[str, Any]":
        mD = {
            "c-l-a-s-s": self.kind.name,
            "cardinality": list(self.cardinality),
        }

        if self.preferredFilename is not None:
            mD["preferredName"] = self.preferredFilename
        if self.glob is not None:
            mD["glob"] = self.glob
        if self.fillFrom is not None:
            mD["fillFrom"] = self.fillFrom

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

    local: "AnyPath"
    signature: "Optional[Fingerprint]" = None
    uri: "Optional[LicensedURI]" = None
    preferredFilename: "Optional[RelPath]" = None


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
    values: "Union[Sequence[bool], Sequence[str], Sequence[int], Sequence[float], Sequence[AbstractGeneratedContent]]"


class LocalWorkflow(NamedTuple):
    """
    dir: The path to the directory where the checkout was applied
    relPath: Inside the checkout, the relative path to the workflow definition
    effectiveCheckout: hex hash of the materialized checkout
    langVersion: workflow language version / revision
    relPathFiles: files composing the workflow, which can be either local
    or remote ones (i.e. CWL)
    """

    dir: "AbsPath"
    relPath: "Optional[RelPath]"
    effectiveCheckout: "Optional[RepoTag]"
    langVersion: "Optional[Union[EngineVersion, WFLangVersion]]" = None
    relPathFiles: "Optional[Sequence[Union[RelPath, URIType]]]" = None


# This skeleton is here only for type mapping reasons
class AbstractWorkflowEngineType(abc.ABC):
    @classmethod
    @abc.abstractmethod
    def MyWorkflowType(cls) -> "WorkflowType":
        pass

    @property
    def workflowType(self) -> "WorkflowType":
        return self.MyWorkflowType()

    @abc.abstractmethod
    def getConfiguredContainerType(self) -> "ContainerType":
        pass

    @property
    def configuredContainerType(self) -> "ContainerType":
        return self.getConfiguredContainerType()

    @property
    @abc.abstractmethod
    def engine_url(self) -> "URIType":
        pass

    @abc.abstractmethod
    def _get_engine_version_str(
        self, matWfEng: "MaterializedWorkflowEngine"
    ) -> "WorkflowEngineVersionStr":
        """
        It must return a string in the form of
        "{symbolic engine name} {version}"
        """
        pass

    @abc.abstractmethod
    def sideContainers(self) -> "Sequence[ContainerTaggedName]":
        pass

    @abc.abstractmethod
    def materialize_containers(
        self,
        listOfContainerTags: "Sequence[ContainerTaggedName]",
        containersDir: "AnyPath",
        offline: "bool" = False,
    ) -> "Tuple[ContainerEngineVersionStr, Sequence[Container], ContainerOperatingSystem, ProcessorArchitecture]":
        pass

    @abc.abstractmethod
    def deploy_containers(
        self,
        containers_list: "Sequence[Container]",
        containersDir: "Optional[AnyPath]" = None,
        force: "bool" = False,
    ) -> "Sequence[Container]":
        pass

    @property
    @abc.abstractmethod
    def staged_containers_dir(self) -> "AnyPath":
        pass

    @abc.abstractmethod
    def materializeEngine(
        self, localWf: "LocalWorkflow", engineVersion: "Optional[EngineVersion]" = None
    ) -> "Optional[MaterializedWorkflowEngine]":
        pass

    @abc.abstractmethod
    def identifyWorkflow(
        self, localWf: "LocalWorkflow", engineVer: "Optional[EngineVersion]" = None
    ) -> "Union[Tuple[EngineVersion, LocalWorkflow], Tuple[None, None]]":
        """
        This method should return the effective engine version needed
        to run it when this workflow engine recognizes the workflow type
        """
        pass

    @abc.abstractmethod
    def materializeWorkflow(
        self,
        matWorfklowEngine: "MaterializedWorkflowEngine",
        consolidatedWorkflowDir: "AbsPath",
        offline: "bool" = False,
    ) -> "Tuple[MaterializedWorkflowEngine, Sequence[ContainerTaggedName]]":
        """
        Method to ensure the workflow has been materialized. It returns a
        possibly updated materialized workflow engine, as well as the list of containers

        For Nextflow it is usually a no-op, but for CWL it requires resolution
        """

        pass

    @abc.abstractmethod
    def launchWorkflow(
        self,
        matWfEng: "MaterializedWorkflowEngine",
        inputs: "Sequence[MaterializedInput]",
        environment: "Sequence[MaterializedInput]",
        outputs: "Sequence[ExpectedOutput]",
    ) -> "StagedExecution":
        pass

    @classmethod
    @abc.abstractmethod
    def FromStagedSetup(
        cls,
        staged_setup: "StagedSetup",
        cache_dir: "Optional[AnyPath]" = None,
        cache_workflow_dir: "Optional[AnyPath]" = None,
        cache_workflow_inputs_dir: "Optional[AnyPath]" = None,
        local_config: "Optional[EngineLocalConfig]" = None,
        config_directory: "Optional[AnyPath]" = None,
    ) -> "AbstractWorkflowEngineType":
        pass


if TYPE_CHECKING:
    TRS_Workflow_Descriptor: TypeAlias = str


class WorkflowType(NamedTuple):
    """
    engineName: symbolic name of the engine
    shortname: short name used in the WfExS-backend configuration files
    for the workflow language
    name: Textual representation of the workflow language
    clazz: Class implementing the engine invocation
    uriMatch: The URI patterns used in RO-Crate to identify the workflow type
    uriTemplate: The URI template to be used when RO-Crate ComputerLanguage is generated
    url: The URL used in RO-Crate to represent the workflow language
    trs_descriptor: The string used in GA4GH TRSv2 specification to define this workflow type
    rocrate_programming_language: Traditional internal id in RO-Crate implementations used for this workflow type (to be deprecated)
    """

    engineName: "str"
    shortname: "str"
    name: "str"
    clazz: "Type[AbstractWorkflowEngineType]"
    uriMatch: "Sequence[Union[Pattern[str], URIType]]"
    uriTemplate: "URIType"
    url: "URIType"
    trs_descriptor: "TRS_Workflow_Descriptor"
    rocrate_programming_language: "str"

    @classmethod
    def _value_fixes(cls) -> "Mapping[str, Optional[str]]":
        return {"shortname": "trs_descriptor"}


class RepoType(enum.Enum):
    Git = "git"
    Raw = "raw"
    Other = "other"
    SoftwareHeritage = "swh"
    TRS = "trs"

    @classmethod
    def _undeprecate_table(cls) -> "Mapping[str, str]":
        # These fixes are needed to map deprecated values
        # to the most approximate ones
        return {
            "github": "git",
            "gitlab": "git",
            "bitbucket": "git",
        }


class RepoGuessFlavor(enum.Enum):
    GitHub = "github"
    GitLab = "gitlab"
    BitBucket = "bitbucket"


class RemoteRepo(NamedTuple):
    """
    Remote repository description
    """

    repo_url: "RepoURL"
    tag: "Optional[RepoTag]" = None
    rel_path: "Optional[RelPath]" = None
    repo_type: "Optional[RepoType]" = None
    web_url: "Optional[URIType]" = None
    guess_flavor: "Optional[RepoGuessFlavor]" = None


class StagedSetup(NamedTuple):
    instance_id: "WfExSInstanceId"
    container_type: "ContainerType"
    nickname: "Optional[str]"
    creation: "datetime.datetime"
    workflow_config: "Optional[Mapping[str, Any]]"
    engine_tweaks_dir: "Optional[AbsPath]"
    raw_work_dir: "AbsPath"
    work_dir: "Optional[AbsPath]"
    workflow_dir: "Optional[AbsPath]"
    consolidated_workflow_dir: "Optional[AbsPath]"
    inputs_dir: "Optional[AbsPath]"
    extrapolated_inputs_dir: "Optional[AbsPath]"
    outputs_dir: "Optional[AbsPath]"
    intermediate_dir: "Optional[AbsPath]"
    containers_dir: "Optional[AbsPath]"
    meta_dir: "Optional[AbsPath]"
    temp_dir: "AbsPath"
    secure_exec: "bool"
    allow_other: "bool"
    is_encrypted: "bool"
    is_damaged: "bool"


class MarshallingStatus(NamedTuple):
    pid: "Optional[str]"
    workflow_type: "Optional[str]"
    container_type: "Optional[ContainerType]"
    config: "Optional[Union[bool, datetime.datetime]]"
    stage: "Optional[Union[bool, datetime.datetime]]"
    execution: "Optional[Union[bool, datetime.datetime]]"
    export: "Optional[Union[bool, datetime.datetime]]"
    execution_stats: "Optional[Sequence[Tuple[datetime.datetime, datetime.datetime, ExitVal]]]"
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
{'  (none)' if self.execution_stats is None or len(self.execution_stats) == 0 else chr(10).join(map(lambda ss: '  - Started ' + ss[0].isoformat() + ' , ended ' + ss[1].isoformat() + ' (exit ' + str(ss[2]) + ')', self.execution_stats))}
* Exported at:
{'  (none)' if self.export_stamps is None or len(self.export_stamps) == 0 else chr(10).join(map(lambda ea: '  - ' + ea.isoformat(), self.export_stamps))}\
"""


DEFAULT_CONTAINER_TYPE = ContainerType.Singularity


@dataclass
class Container(ContainerTaggedName):
    """
    origTaggedName: Symbolic name or identifier of the container
        (including tag) which appears in the workflow.
    type: Container type
    registries:
    taggedName: Symbolic name or identifier of the container (including tag)
    localPath: The full local path to the container file (it can be None)
    signature: Signature (aka file fingerprint) of the container
        (sha256 or similar). It could be None outside Singularity solutions.
    fingerprint: Server fingerprint of the container.
        Mainly from docker registries.
    metadataLocalPath: The full local path to the container metadata file (it can be None)
    """

    taggedName: "URIType" = cast("URIType", "")
    architecture: "Optional[ProcessorArchitecture]" = None
    operatingSystem: "Optional[ContainerOperatingSystem]" = None
    localPath: "Optional[AbsPath]" = None
    signature: "Optional[Fingerprint]" = None
    fingerprint: "Optional[Fingerprint]" = None
    metadataLocalPath: "Optional[AbsPath]" = None


class MaterializedWorkflowEngine(NamedTuple):
    """
    instance: Instance of the workflow engine
    version: Version of the engine to be used
    fingerprint: Fingerprint of the engine to be used (it could be the version)
    engine_path: Absolute path to the fetched engine
    workflow: Instance of LocalWorkflow
    containers_path: Where the containers are going to be available for offline-execute
    containers: List of Container instances (needed by workflow)
    operational_containers: List of Container instances (needed by engine)
    """

    instance: "AbstractWorkflowEngineType"
    version: "EngineVersion"
    fingerprint: "Union[Fingerprint, str]"
    engine_path: "EnginePath"
    workflow: "LocalWorkflow"
    containers_path: "Optional[AbsPath]" = None
    containers: "Optional[Sequence[Container]]" = None
    operational_containers: "Optional[Sequence[Container]]" = None


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


class StagedExecution(NamedTuple):
    """
    The description of the execution of a workflow, giving the relative directory of the output
    """

    exitVal: "ExitVal"
    augmentedInputs: "Sequence[MaterializedInput]"
    matCheckOutputs: "Sequence[MaterializedOutput]"
    outputsDir: "RelPath"
    started: "datetime.datetime"
    ended: "datetime.datetime"
    environment: "Sequence[MaterializedInput]" = []
    outputMetaDir: "Optional[RelPath]" = None
    diagram: "Optional[RelPath]" = None
    logfile: "Sequence[RelPath]" = []


# Next method has been borrowed from FlowMaps
def scantree(path: "AnyPath") -> "Iterator[os.DirEntry[str]]":
    """Recursively yield DirEntry objects for given directory."""

    hasDirs = False
    for entry in os.scandir(path):
        # We are avoiding to enter in loops around '.' and '..'
        if entry.is_dir(follow_symlinks=False):
            if entry.name[0] != ".":
                hasDirs = True
        else:
            yield entry

    # We are leaving the dirs to the end
    if hasDirs:
        for entry in os.scandir(path):
            # We are avoiding to enter in loops around '.' and '..'
            if entry.is_dir(follow_symlinks=False) and entry.name[0] != ".":
                yield entry
                yield from scantree(cast("AbsPath", entry.path))
