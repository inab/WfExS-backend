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
import shutil
import enum
from collections import namedtuple
from urllib import request, parse

from typing import Callable, List, Mapping, NamedTuple, NewType, Pattern, Type, Union

import base64
import hashlib
import functools

DEFAULT_GIT_CMD = 'git'
DEFAULT_DOCKER_CMD = 'docker'
DEFAULT_SINGULARITY_CMD = 'singularity'
DEFAULT_PODMAN_CMD = 'podman'
DEFAULT_JAVA_CMD = 'java'


class EngineMode(enum.Enum):
    Local = 'local'
    Docker = 'docker'


DEFAULT_ENGINE_MODE = EngineMode.Local

# Abstraction of input params and output names
SymbolicName = NewType('SymbolicName',str)
SymbolicParamName = NewType('SymbolicParamName',SymbolicName)
SymbolicOutputName = NewType('SymbolicOutputName',SymbolicName)

# The tagged name of a container
ContainerTaggedName = NewType('ContainerTaggedName',str)

URIType = NewType('URIType',str)
# The URL of a git repository containing at least one workflow
RepoURL = NewType('RepoURL',URIType)
# The tag, branch or hash of a workflow in a git repository
RepoTag = NewType('RepoTag',str)
# This is a relative path
RelPath = NewType('RelPath',str)
# This is an absolute path
AbsPath = NewType('AbsPath',str)
# This is also an absolute path
EnginePath = NewType('EnginePath',AbsPath)

# This is a workflow engine version
EngineVersion = NewType('EngineVersion',str)

# This represents a fingerprint from an installation, a docker image, etc...
# It should follow next format
# {0}={1}
# where {0} is the name of the digest (sha256, for instance)
# and {1} is the base64 encoding of the binary digest
Fingerprint = NewType('Fingerprint',str)

# Exit value from any kind of execution
ExitVal = NewType('ExitVal',int)

SecurityContextConfig = Mapping[str,object]

# As each workflow engine can have its own naming convention, leave them to
# provide it
ContainerFileNamingMethod = Callable[[URIType],RelPath]

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


class MaterializedInput(NamedTuple):
    """
    name: Name of the input
    values: list of associated values, which can be literal ones or
      instances from MaterializedContent
    """
    name: SymbolicParamName
    values: List[Union[bool,str,int,float,MaterializedContent]]

class ExpectedOutput(NamedTuple):
    """
    name: Name of the output
    isImplicit: if it is true, this output is implicit, so no parameter
      must be set
    prettyFilename: Relative "pretty" name to be used in input directory
      when the workflow is being launched
    glob: When the output is implicit, the filename pattern to capture the
      local path, based on the output / working directory
    """
    name: SymbolicOutputName
    isImplicit: bool
    prettyFilename: RelPath
    glob: Pattern

class MaterializedOutput(NamedTuple):
    """
    name: Name of the output
    local: Local absolute path of the output
    prettyFilename: Relative "pretty" name to be used in provenance
    signature: Computed sha256 from the file
    """
    name: SymbolicOutputName
    local: AbsPath
    prettyFilename: RelPath
    signature: Fingerprint

class LocalWorkflow(NamedTuple):
    """
    dir: The path to the directory where the checkout was applied
    relPath: Inside the checkout, the relative path to the workflow definition
    effectiveCheckout: hex hash of the materialized checkout
    """
    dir: AbsPath
    relPath: RelPath
    effectiveCheckout: RepoTag

# This skeleton is here only for type mapping reasons
class AbstractWorkflowEngineType(abc.ABC):
    pass

TRS_Workflow_Descriptor = str

class WorkflowType(NamedTuple):
    """
    engineName: symbolic name of the engine
    clazz: Class implementing the engine invocation
    uri: The URI used in RO-Crate to identify the workflow type
    trs_descriptor: The string used in GA4GH TRSv2 specification to define this workflow type
    rocrate_programming_language: Traditional internal id in RO-Crate implementations used for this workflow type (to be deprecated)
    """
    engineName: str
    clazz: Type[AbstractWorkflowEngineType]
    uri: URIType
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
    fingerprint: Union[Fingerprint,str]
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
    taggedName: Symbolic name or identifier of the container (including tag)
    signature: Signature (aka fingerprint) of the container (sha256 or similar)
    type: Container type
    localPath: The full local path to the container file (it can be null)
    """
    taggedName: str
    signature: Fingerprint
    type: ContainerType
    localPath: AbsPath

class WFException(Exception):
    pass

def fetchClassicURL(remote_file:URIType, cachedFilename:AbsPath, secContext:SecurityContextConfig=None) -> None:
    """
    Method to fetch contents from http, https and ftp

    :param remote_file:
    :param cachedFilename:
    :param secContext:
    """
    try:
        if isinstance(secContext, dict):
            username = secContext.get('username')
            password = secContext.get('password')
            if username is not None:
                if password is None:
                    password = ''

                # Time to set up user and password in URL
                parsedInputURL = parse.urlparse(remote_file)

                netloc = parse.quote(username, safe='') + ':' + parse.quote(password,
                                                                            safe='') + '@' + parsedInputURL.hostname
                if parsedInputURL.port is not None:
                    netloc += ':' + str(parsedInputURL.port)

                # Now the credentials are properly set up
                remote_file = parse.urlunparse((parsedInputURL.scheme, netloc, parsedInputURL.path,
                                                parsedInputURL.params, parsedInputURL.query, parsedInputURL.fragment))
        with request.urlopen(remote_file) as url_response, open(cachedFilename, 'wb') as download_file:
            shutil.copyfileobj(url_response, download_file)
    except Exception as e:
        raise WFException("Cannot download content from {} to {}: {}".format(remote_file, cachedFilename, e))

# Next methods have been borrowed from FlowMaps
DEFAULT_DIGEST_ALGORITHM = 'sha256'
DEFAULT_DIGET_BUFFER_SIZE = 65536
def ComputeDigestFromFileLike(filelike, digestAlgorithm=DEFAULT_DIGEST_ALGORITHM, bufferSize:int=DEFAULT_DIGET_BUFFER_SIZE) -> Fingerprint:
    """
    Accessory method used to compute the digest of an input file-like object
    """

    h = hashlib.new(digestAlgorithm)
    buf = filelike.read(bufferSize)
    while len(buf) > 0:
            h.update(buf)
            buf = filelike.read(bufferSize)

    return '{0}={1}'.format(digestAlgorithm,str(base64.standard_b64encode(h.digest()),'iso-8859-1'))

@functools.lru_cache(maxsize=32)
def ComputeDigestFromFile(filename:Union[AbsPath,RelPath], digestAlgorithm=DEFAULT_DIGEST_ALGORITHM, bufferSize:int=DEFAULT_DIGET_BUFFER_SIZE) -> Fingerprint:
    """
    Accessory method used to compute the digest of an input file
    """
    
    with open(filename, mode='rb') as f:
        return ComputeDigestFromFileLike(f, digestAlgorithm, bufferSize)