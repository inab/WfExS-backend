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


def pytest_addoption(parser: "pytest.Parser") -> "None":
    parser.addoption(
        "--zenodo-config",
        dest="zenodo_config_filename",
        action="store",
        help="This flag enables Zenodo config filename",
    )

    parser.addoption(
        "--b2share-config",
        dest="b2share_config_filename",
        action="store",
        help="This flag enables B2SHARE config filename",
    )
