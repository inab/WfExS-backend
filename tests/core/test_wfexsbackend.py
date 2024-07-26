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
import logging
import pathlib

from typing import (
    cast,
    TYPE_CHECKING,
)

if TYPE_CHECKING:
    from typing import (
        Tuple,
    )
    from wfexs_backend.wfexs_backend import (
        WfExSConfigBlock,
    )

from wfexs_backend.wfexs_backend import WfExSBackend


@pytest.mark.filterwarnings("ignore:.*:pytest.PytestReturnNotNoneWarning")
def test_wfexsbackend_bootstrap(
    tmppath: "pathlib.Path",
) -> "Tuple[WfExSConfigBlock, pathlib.Path]":
    bootstrap_ok, test_local_config, config_directory = WfExSBackend.bootstrap_config(
        local_config_ro={
            "cacheDir": "CACHE",
            "workDir": "WORKDIRS",
        },
        config_directory=tmppath,
        key_prefix="crypt4gh",
    )
    assert bootstrap_ok
    assert config_directory.is_dir()
    assert (tmppath / "WORKDIRS").is_dir()
    assert not (tmppath / "CACHE").exists()

    return test_local_config, config_directory


@pytest.mark.filterwarnings("ignore:.*:pytest.PytestReturnNotNoneWarning")
def test_wfexsbackend_init(tmppath: "pathlib.Path") -> "WfExSBackend":
    test_local_config, config_directory = test_wfexsbackend_bootstrap(tmppath)

    wfexs = WfExSBackend(
        local_config=test_local_config,
        config_directory=config_directory,
    )

    assert (tmppath / "CACHE").is_dir()
    assert wfexs is not None

    return wfexs


def test_wfexsbackend_list_container_factories(tmppath: "pathlib.Path") -> "None":
    wfBackend = test_wfexsbackend_init(tmppath)

    assert len(wfBackend.listImplementedContainerTypes()) > 0


def test_wfexsbackend_list_export_plugins(tmppath: "pathlib.Path") -> "None":
    wfBackend = test_wfexsbackend_init(tmppath)

    assert len(wfBackend.listExportPluginNames()) > 0


def test_wfexsbackend_list_fetchable_schemes(tmppath: "pathlib.Path") -> "None":
    wfBackend = test_wfexsbackend_init(tmppath)

    assert len(wfBackend.describeFetchableSchemes()) > 0


def test_wfexsbackend_list_workflow_engines(tmppath: "pathlib.Path") -> "None":
    wfBackend = test_wfexsbackend_init(tmppath)

    assert len(wfBackend.WORKFLOW_ENGINES) > 0
