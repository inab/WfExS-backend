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

from collections import namedtuple

MaterializedContent = namedtuple('MaterializedContent', ['local', 'uri', 'prettyFilename'])
MaterializedInput = namedtuple('MaterializedInput', ['name', 'values'])

LocalWorkflow = namedtuple('LocalWorkflow', ['dir', 'relPath','effectiveCheckout'])
WorkflowType = namedtuple('WorkflowType', ['engine', 'clazz', 'uri','trs_descriptor','rocrate_programming_language'])
MaterializedWorkflowEngine = namedtuple('MaterializedWorkflowEngine', ['instance', 'version', 'fingerprint','workflow'])

Container = namedtuple('Container', ['name', 'tag', 'signature', 'type'])
# Symbolic name or identifier of the container
# Symbolic name or identifier of the tag
# Signature of the container (sha256 or similar)
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