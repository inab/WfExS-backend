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
import enum
import os
from typing import Any, Callable, List, Mapping, NamedTuple
from typing import NewType, Optional, Pattern, Tuple, Type, Union


# Patching default context in order to load CA certificates from certifi
import certifi
import ssl

def create_augmented_context(purpose=ssl.Purpose.SERVER_AUTH, *, cafile=None, capath=None, cadata=None):
    context = ssl.create_default_context(purpose=purpose, cafile=cafile, capath=capath, cadata=cadata)
    
    context.load_verify_locations(cafile=certifi.where())
    
    return context

if ssl._create_default_https_context != create_augmented_context:
    ssl._create_default_https_context = create_augmented_context



DEFAULT_GIT_CMD = 'git'
DEFAULT_DOCKER_CMD = 'docker'
DEFAULT_SINGULARITY_CMD = 'singularity'
DEFAULT_PODMAN_CMD = 'podman'
DEFAULT_JAVA_CMD = 'java'
DEFAULT_FUSERMOUNT_CMD = 'fusermount'

DEFAULT_PROGS = {
    DEFAULT_GIT_CMD: DEFAULT_GIT_CMD,
    DEFAULT_DOCKER_CMD: DEFAULT_DOCKER_CMD,
    DEFAULT_SINGULARITY_CMD: DEFAULT_SINGULARITY_CMD,
    DEFAULT_PODMAN_CMD: DEFAULT_PODMAN_CMD,
    DEFAULT_JAVA_CMD: DEFAULT_JAVA_CMD,
    DEFAULT_FUSERMOUNT_CMD: DEFAULT_FUSERMOUNT_CMD,
}


class EngineMode(enum.Enum):
    Local = 'local'
    Docker = 'docker'


DEFAULT_ENGINE_MODE = EngineMode.Local

WfExSInstanceId = NewType('WfExSInstanceId', str)

# Abstraction of input params and output names
SymbolicName = NewType('SymbolicName', str)
SymbolicParamName = NewType('SymbolicParamName', SymbolicName)
SymbolicOutputName = NewType('SymbolicOutputName', SymbolicName)

# The tagged name of a container
ContainerTaggedName = NewType('ContainerTaggedName', str)

URIType = NewType('URIType', str)
# The URL of a git repository containing at least one workflow
RepoURL = NewType('RepoURL', URIType)
# The tag, branch or hash of a workflow in a git repository
RepoTag = NewType('RepoTag', str)
# This is a relative path
RelPath = NewType('RelPath', str)
# This is an absolute path
AbsPath = NewType('AbsPath', str)
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

SecurityContextConfig = Mapping[str, Any]

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
    roles: List[AttributionRole] = []

NoPermissionLicence = 'https://choosealicense.com/no-permission/'

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
    # A licence URL, either from a repository, or a site like
    # choosealicense.com or spdx.org/licenses/
    licence: URIType = NoPermissionLicence
    attributions: List[Attribution] = []
    secContext: Optional[SecurityContextConfig] = None

AnyURI = Union[URIType,LicensedURI]

class URIWithMetadata(NamedTuple):
    """
    uri: The uri, which can be either a raw or an annotated one
    metadata: A dictionary with the metadata associated to that URI.
    preferredName: A pretty way to name this resource. Workflow
        execution can decide whether to honour it or not
    """
    uri: AnyURI
    metadata: Mapping[str,Any]
    preferredName: RelPath = None

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
    uri: AnyURI
    prettyFilename: RelPath
    kind: ContentKind = ContentKind.File
    metadata_array: Optional[List[URIWithMetadata]] = None

ProtocolFetcher = Callable[[URIType, AbsPath, Optional[SecurityContextConfig]], Tuple[Union[AnyURI, ContentKind, List[AnyURI]], List[URIWithMetadata]]]


class MaterializedInput(NamedTuple):
    """
    name: Name of the input
    values: list of associated values, which can be literal ones or
      instances from MaterializedContent
    """
    name: SymbolicParamName
    values: List[Union[bool, str, int, float, MaterializedContent]]


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
    preferredFilename: RelPath
    cardinality: Tuple[int, int]
    fillFrom: Optional[SymbolicParamName] = None
    glob: Optional[GlobPattern] = None
    
    def _marshall(self):
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
    def _unmarshall(cls, **obj):
        return cls(
            name=obj['name'],
            kind=ContentKind(obj['c-l-a-s-s'])  if 'c-l-a-s-s' in obj  else  ContentKind.File,
            preferredFilename=obj.get('preferredName'),
            fillFrom=obj.get('fillFrom'),
            glob=obj.get('glob'),
            cardinality=tuple(obj['cardinality'])
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
    values: List[AbstractGeneratedContent]  # It should be List[Union[GeneratedContent, GeneratedDirectoryContent]]
    uri: Optional[LicensedURI] = None
    preferredFilename: Optional[RelPath] = None
    signature: Optional[Fingerprint] = None


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
    values: List[Union[bool, str, int, float, GeneratedContent, GeneratedDirectoryContent]]


class LocalWorkflow(NamedTuple):
    """
    dir: The path to the directory where the checkout was applied
    relPath: Inside the checkout, the relative path to the workflow definition
    effectiveCheckout: hex hash of the materialized checkout
    langVersion: workflow language version / revision
    """
    dir: AbsPath
    relPath: RelPath
    effectiveCheckout: RepoTag
    langVersion: WFLangVersion = None


# This skeleton is here only for type mapping reasons
class AbstractWorkflowEngineType(abc.ABC):
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
    uriMatch: List[Union[Pattern, URIType]]
    uriTemplate: URIType
    url: URIType
    trs_descriptor: TRS_Workflow_Descriptor
    rocrate_programming_language: str


class StagedSetup(NamedTuple):
    instance_id: WfExSInstanceId
    nickname: str
    workflow_config: Mapping
    engine_tweaks_dir: AbsPath
    work_dir: AbsPath
    inputs_dir: AbsPath
    outputs_dir: AbsPath
    intermediate_dir: AbsPath
    meta_dir: AbsPath
    temp_dir: AbsPath
    secure_exec:bool
    allow_other:bool

class MaterializedWorkflowEngine(NamedTuple):
    """
    instance: Instance of the workflow engine
    version: Version of the engine to be used
    fingerprint: Fingerprint of the engine to be used (it could be the version)
    engine_path: Absolute path to the fetched engine
    workflow: Instance of LocalWorkflow
    """
    instance: AbstractWorkflowEngineType
    version: str
    fingerprint: Union[Fingerprint, str]
    engine_path: EnginePath
    workflow: LocalWorkflow


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
    localPath: AbsPath = None
    signature: Fingerprint = None
    fingerprint: Fingerprint = None


class WFException(Exception):
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

    def __str__(self):
        return str(self.value)

# These cache types are needed to return the right paths
# from an WF instance
class CacheType(ArgTypeMixin, enum.Enum):
    Input = 'input'
    ROCrate = 'ro-crate'
    TRS = 'ga4gh-trs'
    Workflow = 'workflow'


# Next method has been borrowed from FlowMaps
def scantree(path):
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
                yield from scantree(entry.path)
