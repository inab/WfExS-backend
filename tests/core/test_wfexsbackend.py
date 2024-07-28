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
import atexit
import logging
import os
import pathlib

from typing import (
    cast,
    TYPE_CHECKING,
)

if TYPE_CHECKING:
    from typing import (
        Optional,
        Tuple,
    )
    from wfexs_backend.wfexs_backend import (
        WfExSConfigBlock,
    )

from wfexs_backend.wfexs_backend import WfExSBackend
from wfexs_backend.workflow import WF

from tests.util import get_path

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)


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


WORKFLOW_TESTBED = pytest.mark.parametrize(
    ["stage_file", "context_file"],
    [
        ("test-hello-cwl.wfex.stage", None),
        ("test-hello-cwl-secure.wfex.stage", None),
    ],
)


@pytest.mark.filterwarnings("ignore:.*:pytest.PytestReturnNotNoneWarning")
@WORKFLOW_TESTBED
def test_wfexsbackend_stage(
    tmppath: "pathlib.Path", stage_file: "str", context_file: "Optional[str]"
) -> "WF":
    wfBackend = test_wfexsbackend_init(tmppath)

    stage_def_path = pathlib.Path(get_path(os.path.join("data", stage_file)))
    assert stage_def_path.is_file(), f"Test file {stage_def_path} is not available"

    context_def_path: "Optional[pathlib.Path]"
    if context_file is not None:
        context_def_path = pathlib.Path(get_path(os.path.join("data", context_file)))
        assert (
            context_def_path.is_file()
        ), f"Context file {context_def_path}, paired with {stage_def_path}, is not available"
    else:
        context_def_path = None

    wfInstance = wfBackend.fromFiles(
        stage_def_path,
        context_def_path,
    )

    atexit.register(wfInstance.cleanup)
    return wfInstance
