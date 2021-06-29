#!/usr/bin/env python
# -*- coding: utf-8 -*-

# Copyright 2020-2021 Barcelona Supercomputing Center (BSC), Spain
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
import base64
import enum
import functools
import hashlib
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


class EngineMode(enum.Enum):
    Local = 'local'
    Docker = 'docker'


DEFAULT_ENGINE_MODE = EngineMode.Local

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


class ContentKind(enum.Enum):
    File = 'file'
    Directory = 'dir'
    Value = 'val'


class URIWithMetadata(NamedTuple):
    """
    uri: The uri
    metadata: A dictionary with the metadata associated to that URI.
    """
    uri: URIType
    metadata: Mapping[str,Any]

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
    uri: URIType
    prettyFilename: RelPath
    kind: ContentKind = ContentKind.File
    metadata_array: Optional[List[URIWithMetadata]] = None

ProtocolFetcher = Callable[[URIType, AbsPath, Optional[SecurityContextConfig]], Tuple[Union[URIType, ContentKind], List[URIWithMetadata]]]


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
    glob: GlobPattern


class GeneratedContent(NamedTuple):
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
    uri: URIType = None
    preferredFilename: RelPath = None


class GeneratedDirectoryContent(NamedTuple):
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
    values: List[Any]  # It should be List[Union[GeneratedContent, GeneratedDirectoryContent]]
    uri: URIType = None
    preferredFilename: RelPath = None


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
    name: Textual representation of the workflow language
    clazz: Class implementing the engine invocation
    uriMatch: The URI patterns used in RO-Crate to identify the workflow type
    uriTemplate: The URI template to be used when RO-Crate ComputerLanguage is generated
    url: The URL used in RO-Crate to represent the workflow language
    trs_descriptor: The string used in GA4GH TRSv2 specification to define this workflow type
    rocrate_programming_language: Traditional internal id in RO-Crate implementations used for this workflow type (to be deprecated)
    """
    engineName: str
    name: str
    clazz: Type[AbstractWorkflowEngineType]
    uriMatch: List[Union[Pattern, URIType]]
    uriTemplate: URIType
    url: URIType
    trs_descriptor: TRS_Workflow_Descriptor
    rocrate_programming_language: str


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


# Next methods have been borrowed from FlowMaps
DEFAULT_DIGEST_ALGORITHM = 'sha256'
DEFAULT_DIGEST_BUFFER_SIZE = 65536

def stringifyDigest(digestAlgorithm, digest:bytes) -> Union[Fingerprint, bytes]:
    return '{0}={1}'.format(digestAlgorithm, str(base64.standard_b64encode(digest), 'iso-8859-1'))

def stringifyFilenameDigest(digestAlgorithm, digest:bytes) -> Union[Fingerprint, bytes]:
    return '{0}~{1}'.format(digestAlgorithm, str(base64.urlsafe_b64encode(digest), 'iso-8859-1'))

def nullProcessDigest(digestAlgorithm, digest:bytes) -> Union[Fingerprint, bytes]:
    return digest

from rfc6920.methods import generate_nih_from_digest

def nihDigest(digestAlgorithm, digest: bytes) -> Union[Fingerprint, bytes]:
    return generate_nih_from_digest(digest, algo=digestAlgorithm)

def ComputeDigestFromFileLike(filelike, digestAlgorithm=DEFAULT_DIGEST_ALGORITHM, bufferSize: int = DEFAULT_DIGEST_BUFFER_SIZE, repMethod=stringifyDigest) -> Fingerprint:
    """
    Accessory method used to compute the digest of an input file-like object
    """
    h = hashlib.new(digestAlgorithm)
    buf = filelike.read(bufferSize)
    while len(buf) > 0:
        h.update(buf)
        buf = filelike.read(bufferSize)

    return repMethod(digestAlgorithm, h.digest())


@functools.lru_cache(maxsize=32)
def ComputeDigestFromFile(filename: Union[AbsPath, RelPath], digestAlgorithm=DEFAULT_DIGEST_ALGORITHM, bufferSize: int = DEFAULT_DIGEST_BUFFER_SIZE, repMethod=stringifyDigest) -> Fingerprint:
    """
    Accessory method used to compute the digest of an input file
    """
    with open(filename, mode='rb') as f:
        return ComputeDigestFromFileLike(f, digestAlgorithm, bufferSize, repMethod)

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

def ComputeDigestFromDirectory(dirname: Union[AbsPath, RelPath], digestAlgorithm=DEFAULT_DIGEST_ALGORITHM, bufferSize: int = DEFAULT_DIGEST_BUFFER_SIZE, repMethod=stringifyDigest) -> Fingerprint:
    """
    Accessory method used to compute the digest of an input directory,
    based on the names and digest of the files in the directory
    """
    cEntries = [ ]
    # First, gather and compute all the files
    for entry in scantree(dirname):
        if entry.is_file():
            cEntries.append(
                (
                    os.path.relpath(entry.path, dirname).encode('utf-8'),
                    ComputeDigestFromFile(entry.path, repMethod=nullProcessDigest)
                )
            )
    
    # Second, sort by the relative path, bytes encoded in utf-8
    cEntries.sort(key=lambda e: e[0])
    
    # Third, digest compute
    h = hashlib.new(digestAlgorithm)
    for cRelPathB , cDigest in cEntries:
        h.update(cRelPathB)
        h.update(cDigest)
    
    return repMethod(digestAlgorithm, h.digest())

def GetGeneratedDirectoryContent(thePath: AbsPath, uri: URIType = None, preferredFilename: RelPath = None) -> GeneratedDirectoryContent:
    """
    """
    theValues = []
    with os.scandir(thePath) as itEntries:
        for entry in itEntries:
            # Hidden files are skipped by default
            if not entry.name.startswith('.'):
                theValue = None
                if entry.is_file():
                    theValue = GeneratedContent(
                        local=entry.path,
                        # uri=None, 
                        signature=ComputeDigestFromFile(entry.path, repMethod=nihDigest)
                    )
                elif entry.is_dir():
                    theValue = GetGeneratedDirectoryContent(entry.path)

                if theValue is not None:
                    theValues.append(theValue)

    return GeneratedDirectoryContent(
        local=thePath,
        uri=uri,
        preferredFilename=preferredFilename,
        values=theValues
    )


CWLClass2WfExS = {
    'Directory': ContentKind.Directory,
    'File': ContentKind.File
    # '???': ContentKind.Value
}


def CWLDesc2Content(cwlDescs: Union[Mapping[str, Any], List[Mapping[str, Any]]], logger, expectedOutput: ExpectedOutput = None) -> List[Union[bool, str, int, float, GeneratedContent, GeneratedDirectoryContent]]:
    """
    """
    matValues = []

    if not isinstance(cwlDescs, list):
        cwlDescs = [cwlDescs]
    
    for cwlDesc in cwlDescs:
        foundKind = CWLClass2WfExS.get(cwlDesc['class'])
        if (expectedOutput is not None) and foundKind != expectedOutput.kind:
            logger.warning("For output {} obtained kind does not match ({} vs {})".format(expectedOutput.name, expectedOutput.kind, foundKind))
        
        matValue = None
        if foundKind == ContentKind.Directory:
            theValues = CWLDesc2Content(cwlDesc['listing'], logger=logger)
            matValue = GeneratedDirectoryContent(
                local=cwlDesc['path'],
                # TODO: Generate URIs when it is advised
                # uri=None
                preferredFilename=None if expectedOutput is None else expectedOutput.preferredFilename,
                values=theValues
            )
        elif foundKind == ContentKind.File:
            matValue = GeneratedContent(
                local=cwlDesc['path'],
                signature=ComputeDigestFromFile(cwlDesc['path'], repMethod=nihDigest)
            )
        
        if matValue is not None:
            matValues.append(matValue)
            
            # What to do with auxiliary/secondary files?
            secondaryFiles = cwlDesc.get('secondaryFiles', [])
            if len(secondaryFiles) > 0:
                matValues.extend(CWLDesc2Content(secondaryFiles, logger))

    return matValues