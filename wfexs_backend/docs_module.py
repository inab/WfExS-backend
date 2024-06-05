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

from .wfexs_backend import WfExSBackend
from typing import TYPE_CHECKING

from .utils.licences import LicenceMatcherSingleton

if TYPE_CHECKING:
    from typing import (
        Sequence,
        Tuple,
    )

    from .common import (
        ContainerType,
        LicenceDescription,
    )

    from .workflow_engines import (
        WorkflowType,
    )


def list_containers() -> "Sequence[ContainerType]":
    wfBackend = WfExSBackend()
    return wfBackend.listImplementedContainerTypes()


def list_export_plugins() -> "Sequence[str]":
    wfBackend = WfExSBackend()
    return wfBackend.listExportPluginNames()


def list_fetchers() -> "Sequence[Tuple[str, str, int]]":
    wfBackend = WfExSBackend()
    return wfBackend.describeFetchableSchemes()


def list_licences() -> "Sequence[LicenceDescription]":
    licence_matcher = LicenceMatcherSingleton()
    return licence_matcher.describeDocumentedLicences()


def list_workflow_engines() -> "Sequence[WorkflowType]":
    wfBackend = WfExSBackend()
    return wfBackend.WORKFLOW_ENGINES
