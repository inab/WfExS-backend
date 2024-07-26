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
import pathlib

from tests.pushers.marks import (
    MARKERS,
)

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from py.path.local import LocalPath  # type: ignore[import]


def pytest_addoption(parser: "pytest.Parser") -> "None":
    for mark_details in MARKERS:
        parser.addoption(
            mark_details.option,
            dest=mark_details.param,
            action="store",
            help=mark_details.param_description,
        )


@pytest.fixture
def tmppath(tmpdir: "LocalPath") -> "pathlib.Path":
    return pathlib.Path(tmpdir)
