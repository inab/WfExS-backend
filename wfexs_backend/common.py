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

import abc
import datetime
import enum
import os
from typing import cast, Any, Callable, Dict, List, Mapping, NamedTuple
from typing import NewType, Optional, Pattern, Sequence, Tuple, Type, Union
from typing import Iterator, MutableMapping, TYPE_CHECKING

if TYPE_CHECKING:
    from rocrate.model.computerlanguage import ComputerLanguage # type: ignore[import]


# Patching default context in order to load CA certificates from certifi
import certifi
import ssl

def create_augmented_context(purpose: ssl.Purpose = ssl.Purpose.SERVER_AUTH, *, cafile: Optional[str] = None, capath: Optional[str] = None, cadata: Optional[Union[str, bytes]] = None) -> ssl.SSLContext:
    context = ssl.create_default_context(purpose=purpose, cafile=cafile, capath=capath, cadata=cadata)
    
    context.load_verify_locations(cafile=certifi.where())
    
    return context

if ssl._create_default_https_context != create_augmented_context:
    ssl._create_default_https_context = create_augmented_context

# Abstraction of names
SymbolicName = NewType('SymbolicName', str)
# This is a relative path
RelPath = NewType('RelPath', str)
# This is an absolute path
AbsPath = NewType('AbsPath', str)

DEFAULT_GIT_CMD = cast(SymbolicName, 'git')
DEFAULT_DOCKER_CMD = cast(SymbolicName, 'docker')
DEFAULT_SINGULARITY_CMD = cast(SymbolicName, 'singularity')
DEFAULT_PODMAN_CMD = cast(SymbolicName, 'podman')
DEFAULT_JAVA_CMD = cast(SymbolicName, 'java')
DEFAULT_FUSERMOUNT_CMD = cast(SymbolicName, 'fusermount')

DEFAULT_PROGS : Dict[SymbolicName, Union[RelPath, AbsPath]] = {
    DEFAULT_GIT_CMD: cast(RelPath, DEFAULT_GIT_CMD),
    DEFAULT_DOCKER_CMD: cast(RelPath, DEFAULT_DOCKER_CMD),
    DEFAULT_SINGULARITY_CMD: cast(RelPath, DEFAULT_SINGULARITY_CMD),
    DEFAULT_PODMAN_CMD: cast(RelPath, DEFAULT_PODMAN_CMD),
    DEFAULT_JAVA_CMD: cast(RelPath, DEFAULT_JAVA_CMD),
    DEFAULT_FUSERMOUNT_CMD: cast(RelPath, DEFAULT_FUSERMOUNT_CMD),
}


class EngineMode(enum.Enum):
    Local = 'local'
    Docker = 'docker'


DEFAULT_ENGINE_MODE = EngineMode.Local

WfExSInstanceId = NewType('WfExSInstanceId', str)

# Abstraction of input params and output names
SymbolicParamName = NewType('SymbolicParamName', SymbolicName)
SymbolicOutputName = NewType('SymbolicOutputName', SymbolicName)

# The tagged name of a container
ContainerTaggedName = NewType('ContainerTaggedName', str)

URIType = NewType('URIType', str)
# The URL of a git repository containing at least one workflow
RepoURL = NewType('RepoURL', URIType)
# The tag, branch or hash of a workflow in a git repository
RepoTag = NewType('RepoTag', str)
# This is also an absolute path
EnginePath = NewType('EnginePath', AbsPath)

# This is a workflow engine version
EngineVersion = NewType('EngineVersion', str)

# This is a workflow language version
WFLangVersion = NewType('WFLangVersion', str)

# This represents a fingerprint from an installation, a docker image, etc...
# It should follow next format
# {0}={1}
# where {0} is the name of the digest (sha256, for instance)
# and {1} is the base64 encoding of the binary digest
Fingerprint = NewType('Fingerprint', str)

# Exit value from any kind of execution
ExitVal = NewType('ExitVal', int)

SecurityContextConfig = Dict[str, Any]
SecurityContextConfigBlock = MutableMapping[str, SecurityContextConfig]

# As each workflow engine can have its own naming convention, leave them to
# provide it
ContainerFileNamingMethod = Callable[[URIType], RelPath]


## BEWARE!!!! The names of these keys MUST NOT CHANGE
class ContentKind(enum.Enum):
    File = 'file'
    Directory = 'dir'
    Value = 'val'

class AttributionRole(enum.Enum):
    """
    The valid roles come from CASRAI CRediT, and can be visited through
    http://credit.niso.org/contributor-roles/{term}/
    """
    Conceptualization = 'conceptualization'
    DataCuration = 'data-curation'
    FormalAnalysis = 'formal-analysis'
    FundingAcquisition = 'funding-acquisition'
    Investigation = 'investigation'
    Methodology = 'methodology'
    ProjectAdministration = 'project-administration'
    Resources = 'resources'
    Software = 'software'
    Supervision = 'supervision'
    Validation = 'validation'
    Visualization = 'visualization'
    WritingOriginalDraft = 'writing-original-draft'
    WritingReviewEditing = 'writing-review-editing'

class Attribution(NamedTuple):
    # Author
    name: str
    # A unique way to represent this author, either through her/his
    # ORCID or another permanent, representative link
    pid: URIType
    roles: Sequence[AttributionRole] = []
    
    @classmethod
    def ParseRawAttribution(cls, rawAttribution: Mapping[str, Any]) -> "Attribution":
        return cls(
            name=rawAttribution['name'],
            pid=rawAttribution['pid'],
            roles=[ AttributionRole(rawRole) for rawRole in rawAttribution['roles'] ]
        )
    
    @classmethod
    def ParseRawAttributions(cls, rawAttributions: Optional[Sequence[Mapping[str, Any]]]) -> "Sequence[Attribution]":
        attributions = []
        if isinstance(rawAttributions, list):
            for rawAttribution in rawAttributions:
                attributions.append(cls.ParseRawAttribution(rawAttribution))
        
        return attributions
        

NoLicence : URIType = cast(URIType, 'https://choosealicense.com/no-permission/')
DefaultNoLicenceTuple : Tuple[URIType, ...] = (NoLicence, )

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
    uri: URIType
    # One or more licence URLs, either from a repository, or a site like
    # choosealicense.com or spdx.org/licenses/
    licences: Tuple[URIType, ...] = DefaultNoLicenceTuple
    attributions: Sequence[Attribution] = []
    secContext: Optional[SecurityContextConfig] = None

AnyURI = Union[URIType,LicensedURI]

class URIWithMetadata(NamedTuple):
    """
    uri: The uri, which can be either a raw or an annotated one
    metadata: A dictionary with the metadata associated to that URI.
    preferredName: A pretty way to name this resource. Workflow
        execution can decide whether to honour it or not
    """
    uri: URIType
    metadata: Mapping[str,Any]
    preferredName: Optional[RelPath] = None

class MaterializedContent(NamedTuple):
    """
    local: Local absolute path of the content which was materialized. It
      can be either a path in the cached inputs directory, or an absolute
      path in the inputs directory of the execution
    uri: Either an URL or a CURIE of the content which was materialized,
      needed for the provenance
    prettyFilename: The preferred filename to use in the inputs directory
      of the execution environment
    """
    local: AbsPath
    licensed_uri: LicensedURI
    prettyFilename: RelPath
    kind: ContentKind = ContentKind.File
    metadata_array: Optional[Sequence[URIWithMetadata]] = None

ProtocolFetcherReturn = Tuple[Union[AnyURI, ContentKind, Sequence[AnyURI]], Sequence[URIWithMetadata], Optional[Tuple[URIType, ...]]]
ProtocolFetcher = Callable[[URIType, AbsPath, Optional[SecurityContextConfig]], ProtocolFetcherReturn]


class MaterializedInput(NamedTuple):
    """
    name: Name of the input
    values: list of associated values, which can be literal ones or
      instances from MaterializedContent
    """
    name: SymbolicParamName
    values: Union[Sequence[bool], Sequence[str], Sequence[int], Sequence[float], Sequence[MaterializedContent]]
    secondaryInputs: Optional[Sequence[MaterializedContent]] = None


GlobPattern = NewType('GlobPattern', str)


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
    name: SymbolicOutputName
    kind: ContentKind
    preferredFilename: Optional[RelPath]
    cardinality: Tuple[int, int]
    fillFrom: Optional[SymbolicParamName] = None
    glob: Optional[GlobPattern] = None
    
    def _marshall(self) -> MutableMapping[str, Any]:
        mD = {
            'c-l-a-s-s': self.kind.name,
            'cardinality': list(self.cardinality),
        }
        
        if self.preferredFilename is not None:
            mD['preferredName'] = self.preferredFilename
        if self.glob is not None:
            mD['glob'] = self.glob
        if self.fillFrom is not None:
            mD['fillFrom'] = self.fillFrom
        
        return mD
    
    @classmethod
    def _unmarshall(cls, **obj: Any) -> "ExpectedOutput":
        return cls(
            name=obj['name'],
            kind=ContentKind(obj['c-l-a-s-s'])  if 'c-l-a-s-s' in obj  else  ContentKind.File,
            preferredFilename=obj.get('preferredName'),
            fillFrom=obj.get('fillFrom'),
            glob=obj.get('glob'),
            cardinality=cast(Tuple[int, int], tuple(obj['cardinality']))
        )


class AbstractGeneratedContent(object):
    pass

class GeneratedContent(AbstractGeneratedContent, NamedTuple):
    """
    local: Local absolute path of the content which was generated. It
      is an absolute path in the outputs directory of the execution.
    uri: A putative URL or a CURIE of the content which was generated,
      needed for the provenance and upload matters.
    signature: Computed checksum from the file
    preferredFilename: The preferred relative filename to use when it is
      uploaded from the computational environment
    """
    local: AbsPath
    signature: Fingerprint
    uri: Optional[LicensedURI] = None
    preferredFilename: Optional[RelPath] = None
    secondaryFiles: Optional[Sequence[AbstractGeneratedContent]] = None


class GeneratedDirectoryContent(AbstractGeneratedContent, NamedTuple):
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
    local: AbsPath
    values: Sequence[AbstractGeneratedContent]  # It should be List[Union[GeneratedContent, GeneratedDirectoryContent]]
    uri: Optional[LicensedURI] = None
    preferredFilename: Optional[RelPath] = None
    signature: Optional[Fingerprint] = None
    secondaryFiles: Optional[Sequence[AbstractGeneratedContent]] = None


class MaterializedOutput(NamedTuple):
    """
    name: Name of the output. It should be a public identifier whenever it is possible
    expectedCardinality: Whether it was expected to be optional, a single value or
      multiple ones.
    local: Local absolute path of the output
    prettyFilename: Relative "pretty" name to be used in provenance
    """
    name: SymbolicOutputName
    kind: ContentKind
    expectedCardinality: Tuple[int, int]
    values: Union[Sequence[bool], Sequence[str], Sequence[int], Sequence[float], Sequence[AbstractGeneratedContent]]


class LocalWorkflow(NamedTuple):
    """
    dir: The path to the directory where the checkout was applied
    relPath: Inside the checkout, the relative path to the workflow definition
    effectiveCheckout: hex hash of the materialized checkout
    langVersion: workflow language version / revision
    """
    dir: AbsPath
    relPath: Optional[RelPath]
    effectiveCheckout: Optional[RepoTag]
    langVersion: Optional[Union[EngineVersion, WFLangVersion]] = None


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
    def sideContainers(self) -> Sequence[ContainerTaggedName]:
        pass
    
    def materializeContainers(self, listOfContainerTags: Sequence[ContainerTaggedName], containersDir: Union[RelPath, AbsPath], offline: bool = False) -> "Sequence[Container]":
        pass
    
    @abc.abstractmethod
    def materializeEngine(self, localWf: LocalWorkflow,
                          engineVersion: Optional[EngineVersion] = None) -> "Optional[MaterializedWorkflowEngine]":
        pass
    
    @abc.abstractmethod
    def identifyWorkflow(self, localWf: LocalWorkflow, engineVer: Optional[EngineVersion] = None) -> Union[Tuple[EngineVersion, LocalWorkflow], Tuple[None, None]]:
        """
        This method should return the effective engine version needed
        to run it when this workflow engine recognizes the workflow type
        """
        pass
    
    @abc.abstractmethod
    def materializeWorkflow(self, matWorfklowEngine: "MaterializedWorkflowEngine", offline: bool = False) -> "Tuple[MaterializedWorkflowEngine, Sequence[ContainerTaggedName]]":
        """
        Method to ensure the workflow has been materialized. It returns the 
        localWorkflow directory, as well as the list of containers
        
        For Nextflow it is usually a no-op, but for CWL it requires resolution
        """

        pass
    
    @abc.abstractmethod
    def launchWorkflow(self, matWfEng: "MaterializedWorkflowEngine", inputs: Sequence[MaterializedInput],
                       outputs: Sequence[ExpectedOutput]) -> Tuple[ExitVal, Sequence[MaterializedInput], Sequence[MaterializedOutput]]:
        pass
    
    @classmethod
    @abc.abstractmethod
    def FromStagedSetup(cls,
            staged_setup: "StagedSetup",
            cache_dir: Optional[Union[RelPath, AbsPath]] = None,
            cache_workflow_dir: Optional[Union[RelPath, AbsPath]] = None,
            cache_workflow_inputs_dir: Optional[Union[RelPath, AbsPath]] = None,
            local_config: Optional[Mapping[str, Any]] = None,
            config_directory: Optional[Union[RelPath, AbsPath]] = None
    ) -> "AbstractWorkflowEngineType":
        pass
    
    @abc.abstractmethod
    def getEmptyCrateAndComputerLanguage(self, langVersion: Optional[Union[EngineVersion, WFLangVersion]]) -> "ComputerLanguage":
        pass

TRS_Workflow_Descriptor = str


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
    engineName: str
    shortname: str
    name: str
    clazz: Type[AbstractWorkflowEngineType]
    uriMatch: Sequence[Union[Pattern[str], URIType]]
    uriTemplate: URIType
    url: URIType
    trs_descriptor: TRS_Workflow_Descriptor
    rocrate_programming_language: str


class RemoteRepo(NamedTuple):
    """
    Remote repository description
    """
    repo_url: RepoURL
    tag: Optional[RepoTag] = None
    rel_path: Optional[RelPath] = None

class IdentifiedWorkflow(NamedTuple):
    """
    workflow_type: The identified workflow type
    """
    workflow_type: WorkflowType
    remote_repo: RemoteRepo

class StagedSetup(NamedTuple):
    instance_id: WfExSInstanceId
    nickname: Optional[str]
    creation: datetime.datetime
    workflow_config: Optional[Mapping[str, Any]]
    engine_tweaks_dir: Optional[AbsPath]
    raw_work_dir: AbsPath
    work_dir: Optional[AbsPath]
    workflow_dir: Optional[AbsPath]
    inputs_dir: Optional[AbsPath]
    outputs_dir: Optional[AbsPath]
    intermediate_dir: Optional[AbsPath]
    meta_dir: Optional[AbsPath]
    temp_dir: AbsPath
    secure_exec: bool
    allow_other: bool
    is_encrypted: bool
    is_damaged: bool

import datetime
class MarshallingStatus(NamedTuple):
    config: Optional[Union[bool, datetime.datetime]]
    stage: Optional[Union[bool, datetime.datetime]]
    execution: Optional[Union[bool, datetime.datetime]]
    export: Optional[Union[bool, datetime.datetime]]
    
    def __repr__(self) -> str:
        return f"""Marshalling date status:
- config: {"(never done)" if self.config is None  else  self.config.isoformat()  if isinstance(self.config, datetime.datetime)  else  "(failed/not done yet)"}
- stage: {"(never done)" if self.stage is None  else  self.stage.isoformat()  if isinstance(self.stage, datetime.datetime)  else  "(failed/not done yet)"}
- execution: {"(never done)" if self.execution is None  else  self.execution.isoformat()  if isinstance(self.execution, datetime.datetime)  else  "(failed/not done yet)"}
- export: {"(never done)" if self.export is None  else  self.export.isoformat()  if isinstance(self.export, datetime.datetime)  else  "(failed/not done yet)"}
"""

class ContainerType(enum.Enum):
    Singularity = 'singularity'
    Docker = 'docker'
    UDocker = 'udocker'
    Podman = 'podman'
    NoContainer = 'none'


DEFAULT_CONTAINER_TYPE = ContainerType.Singularity


class Container(NamedTuple):
    """
    origTaggedName: Symbolic name or identifier of the container
        (including tag) which appears in the workflow.
    taggedName: Symbolic name or identifier of the container (including tag)
    type: Container type
    localPath: The full local path to the container file (it can be None)
    signature: Signature (aka file fingerprint) of the container
        (sha256 or similar). It could be None outside Singularity solutions.
    fingerprint: Server fingerprint of the container.
        Mainly from docker registries.
    """
    origTaggedName: str
    taggedName: URIType
    type: ContainerType
    localPath: Optional[AbsPath] = None
    signature: Optional[Fingerprint] = None
    fingerprint: Optional[Fingerprint] = None


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
    instance: AbstractWorkflowEngineType
    version: EngineVersion
    fingerprint: Union[Fingerprint, str]
    engine_path: EnginePath
    workflow: LocalWorkflow
    containers_path: Optional[AbsPath] = None
    containers: Optional[Sequence[Container]] = None
    operational_containers: Optional[Sequence[Container]] = None


class AbstractWfExSException(Exception):
    pass


# Adapted from https://gist.github.com/ptmcg/23ba6e42d51711da44ba1216c53af4ea
# in order to show the value instead of the class name
import argparse
class ArgTypeMixin(enum.Enum):
    @classmethod
    def argtype(cls, s: str) -> enum.Enum:
        try:
            return cls(s)
        except:
            raise argparse.ArgumentTypeError(
                f"{s!r} is not a valid {cls.__name__}")
    
    def __str__(self) -> str:
        return str(self.value)

class StrDocEnum(str, ArgTypeMixin, enum.Enum):
    # Learnt from https://docs.python.org/3.11/howto/enum.html#when-to-use-new-vs-init
    description: str
    def __new__(cls, value: Any, description: str = '') -> "StrDocEnum":
        obj = str.__new__(cls, value)
        obj._value_ = value
        obj.description = description
        
        return obj
    
    def __str__(self) -> str:
        return str(self.value)

class ArgsDefaultWithRawHelpFormatter(argparse.ArgumentDefaultsHelpFormatter):
    # Conditionally treat descriptions as raw
    def _split_lines(self, text: str, width: int) -> List[str]:
        """
        Formats the given text by splitting the lines at '\n'.
        Overrides argparse.HelpFormatter._split_lines function.

        :param text: help text passed by ArgumentParser.HelpFormatter
        :param width: console width passed by argparse.HelpFormatter
        :return: argparse.HelpFormatter._split_lines function
        with new split text argument.
        """
        if text.startswith('raw|'):
            return text[4:].splitlines()
        return super()._split_lines(text, width)


# These cache types are needed to return the right paths
# from an WF instance
class CacheType(StrDocEnum):
    Input = ('input', 'Cached or injected inputs')
    ROCrate = ('ro-crate', 'Cached RO-Crates (usually from WorkflowHub)')
    TRS = ('ga4gh-trs', 'Cached files from tools described at GA4GH TRS repositories')
    Workflow = ('workflow', 'Cached workflows, which come from a git repository')


# Next method has been borrowed from FlowMaps
def scantree(path: Union[RelPath, AbsPath]) -> "Iterator[os.DirEntry[str]]":
    """Recursively yield DirEntry objects for given directory."""

    hasDirs = False
    for entry in os.scandir(path):
        # We are avoiding to enter in loops around '.' and '..'
        if entry.is_dir(follow_symlinks=False):
            if entry.name[0] != '.':
                hasDirs = True
        else:
            yield entry

    # We are leaving the dirs to the end
    if hasDirs:
        for entry in os.scandir(path):
            # We are avoiding to enter in loops around '.' and '..'
            if entry.is_dir(follow_symlinks=False) and entry.name[0] != '.':
                yield entry
                yield from scantree(cast(AbsPath, entry.path))
