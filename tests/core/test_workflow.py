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
import datetime
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

from tests.core.test_wfexsbackend import (
    test_wfexsbackend_stage,
    WORKFLOW_TESTBED,
)
from wfexs_backend.workflow import WF

from tests.util import get_path

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)


@pytest.mark.filterwarnings("ignore:.*:pytest.PytestReturnNotNoneWarning")
@WORKFLOW_TESTBED
def test_workflow_stage(
    tmppath: "pathlib.Path", stage_file: "str", context_file: "Optional[str]"
) -> "WF":
    wfInstance = test_wfexsbackend_stage(tmppath, stage_file, context_file)

    wfSetup = wfInstance.getStagedSetup()
    stagedSetup = wfInstance.stageWorkDir()
    logger.info(
        "Instance {} (nickname '{}') is {} ready".format(
            wfSetup.instance_id,
            wfSetup.nickname,
            "NOT" if stagedSetup.is_damaged else "now",
        )
    )

    assert not stagedSetup.is_damaged
    assert isinstance(wfInstance.stageMarshalled, datetime.datetime)

    return wfInstance


@pytest.mark.filterwarnings("ignore:.*:pytest.PytestReturnNotNoneWarning")
@WORKFLOW_TESTBED
def test_workflow_offline_exec(
    tmppath: "pathlib.Path", stage_file: "str", context_file: "Optional[str]"
) -> "WF":
    wfInstance = test_workflow_stage(tmppath, stage_file, context_file)
    staged_exec = wfInstance.executeWorkflow(offline=True)

    assert staged_exec.exitVal == 0

    return wfInstance
