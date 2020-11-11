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

import shutil
import enum
from collections import namedtuple
from urllib import request, parse

DEFAULT_GIT_CMD = 'git'
DEFAULT_DOCKER_CMD = 'docker'
DEFAULT_SINGULARITY_CMD = 'singularity'
DEFAULT_JAVA_CMD = 'java'


class EngineMode(enum.Enum):
    Local = 'local'
    Docker = 'docker'


DEFAULT_ENGINE_MODE = EngineMode.Local

MaterializedContent = namedtuple('MaterializedContent', ['local', 'uri', 'prettyFilename'])
MaterializedInput = namedtuple('MaterializedInput', ['name', 'values'])

LocalWorkflow = namedtuple('LocalWorkflow', ['dir', 'relPath', 'effectiveCheckout'])
WorkflowType = namedtuple('WorkflowType', ['engineName', 'clazz', 'uri', 'trs_descriptor', 'rocrate_programming_language'])
MaterializedWorkflowEngine = namedtuple('MaterializedWorkflowEngine',
                                        ['instance', 'version', 'fingerprint', 'workflow'])
# Instance of the workflow engine
# Version of the engine to be used
# Fingerprint of the engine to be used (it could be the version)
# Instance of LocalWorkflow

class ContainerType(enum.Enum):
    Singularity = 'singularity'
    Docker = 'docker'

Container = namedtuple('Container', ['name', 'tag', 'signature', 'type'])
# Symbolic name or identifier of the container
# Symbolic name or identifier of the tag
# Signature (aka fingerprint) of the container (sha256 or similar)
# Container type

# The URL of a git repository containing at least one workflow
RepoURL = str
# The tag, branch or hash of a workflow in a git repository
RepoTag = str
# This is a relative path
RelPath = str
# This is an absolute path
AbsPath = str

# This is a workflow engine version
EngineVersion = str
# This represents a fingerprint from an installation, a docker image, etc...
Fingerprint = str

class WFException(Exception):
    pass

def fetchClassicURL(remote_file, cachedFilename, secContext=None) -> None:
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
