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

import pytest

from tests.util import (
    MarkDetails,
)

MARKERS = [
    MarkDetails(
        acronym="Zenodo",
        name="zenodo_params",
        param="zenodo_config_filename",
        option="--zenodo-config",
        param_description="This parameter provides the Zenodo config filename for the tests involving authentication",
        mark_description="mark test to run only when a configuration file with Zenodo credentials is provided",
    ),
    MarkDetails(
        acronym="B2SHARE",
        name="b2share_params",
        param="b2share_config_filename",
        option="--b2share-config",
        param_description="This parameter provides the B2SHARE config filename for the tests involving authentication",
        mark_description="mark test to run only when a configuration file with B2SHARE credentials is provided",
    ),
    MarkDetails(
        acronym="Dataverse",
        name="dataverse_params",
        param="dataverse_config_filename",
        option="--dataverse-config",
        param_description="This parameter provides the Dataverse config filename for the tests involving authentication",
        mark_description="mark test to run only when a configuration file with Dataverse credentials is provided",
    ),
]
