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
import inspect
import logging
import os
import pathlib
import time

from typing import (
    cast,
    TYPE_CHECKING,
)

if TYPE_CHECKING:
    from typing import (
        Optional,
        Sequence,
        Tuple,
    )
    from wfexs_backend.wfexs_backend import (
        WfExSConfigBlock,
    )

from tests.core.test_wfexsbackend import (
    test_wfexsbackend_stage,
    WORKFLOW_TESTBED,
)
from wfexs_backend.common import ExecutionStatus
from wfexs_backend.workflow import WF

from tests.util import get_path

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)


@pytest.mark.filterwarnings("ignore:.*:pytest.PytestReturnNotNoneWarning")
@WORKFLOW_TESTBED
def test_workflow_stage(
    tmppath: "pathlib.Path",
    stage_file: "str",
    context_file: "Optional[str]",
    should_fail: "Optional[Sequence[str]]",
) -> "WF":
    wfInstance = test_wfexsbackend_stage(tmppath, stage_file, context_file, should_fail)

    try:
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

    except:
        if should_fail is None or inspect.currentframe().f_code.co_name not in should_fail:  # type: ignore[union-attr]
            raise
    else:
        if should_fail is not None and inspect.currentframe().f_code.co_name in should_fail:  # type: ignore[union-attr]
            raise AssertionError(f"Method {inspect.currentframe().f_code.co_name} should have failed with stage file {stage_file} and context file {context_file}")  # type: ignore[union-attr]

    return wfInstance


@pytest.mark.filterwarnings("ignore:.*:pytest.PytestReturnNotNoneWarning")
@WORKFLOW_TESTBED
def test_workflow_offline_exec(
    tmppath: "pathlib.Path",
    stage_file: "str",
    context_file: "Optional[str]",
    should_fail: "Optional[Sequence[str]]",
) -> "WF":
    wfInstance = test_workflow_stage(tmppath, stage_file, context_file, should_fail)

    try:
        staged_exec = wfInstance.executeWorkflow(offline=True)

        assert staged_exec.status == ExecutionStatus.Finished
        assert staged_exec.exitVal == 0
    except:
        if should_fail is None or inspect.currentframe().f_code.co_name not in should_fail:  # type: ignore[union-attr]
            raise
    else:
        if should_fail is not None and inspect.currentframe().f_code.co_name in should_fail:  # type: ignore[union-attr]
            raise AssertionError(f"Method {inspect.currentframe().f_code.co_name} should have failed with stage file {stage_file} and context file {context_file}")  # type: ignore[union-attr]

    return wfInstance


PARALLEL_WORKFLOW_TESTBED = pytest.mark.parametrize(
    ["stage_file", "context_file", "should_fail"],
    [
        ("test-sleephello-cwl-singularity.wfex.stage", None, None),
    ],
)

NUM_PARALLEL = 4


@PARALLEL_WORKFLOW_TESTBED
def test_workflow_multiple_executions(
    tmppath: "pathlib.Path",
    stage_file: "str",
    context_file: "Optional[str]",
    should_fail: "Optional[Sequence[str]]",
) -> "None":
    wfInstance = test_workflow_stage(tmppath, stage_file, context_file, should_fail)

    try:
        for numstep in range(NUM_PARALLEL):
            staged_exec = wfInstance.executeWorkflow(offline=True)

            assert staged_exec.status == ExecutionStatus.Finished
            assert staged_exec.exitVal == 0

        creation_time, executions = wfInstance.unmarshallExecute()
        assert (
            len(executions) == NUM_PARALLEL
        ), f"Inconsistent number of registered executions (got {len(executions)}, expected {NUM_PARALLEL})"
    except:
        if should_fail is None or inspect.currentframe().f_code.co_name not in should_fail:  # type: ignore[union-attr]
            raise
    else:
        if should_fail is not None and inspect.currentframe().f_code.co_name in should_fail:  # type: ignore[union-attr]
            raise AssertionError(f"Method {inspect.currentframe().f_code.co_name} should have failed with stage file {stage_file} and context file {context_file}")  # type: ignore[union-attr]


@PARALLEL_WORKFLOW_TESTBED
def test_workflow_parallel_executions(
    tmppath: "pathlib.Path",
    stage_file: "str",
    context_file: "Optional[str]",
    should_fail: "Optional[Sequence[str]]",
) -> "None":
    wfInstance = test_workflow_stage(tmppath, stage_file, context_file, should_fail)

    try:
        job_ids = []
        for numstep in range(NUM_PARALLEL):
            job_id = wfInstance.queueExecution(offline=True)
            job_ids.append(job_id)

        # Wait for a second
        time.sleep(1)
        creation_time, executions = wfInstance.unmarshallExecute(offline=True)
        assert (
            len(list(filter(lambda ex: ex.job_id in job_ids, executions)))
            == NUM_PARALLEL
        ), f"Some jobs are missing (recorded {job_ids})"
        assert (
            len(executions) == NUM_PARALLEL
        ), f"Inconsistent initial number of registered executions (got {len(executions)}, expected {NUM_PARALLEL})"
        # Wait for 10 seconds
        time.sleep(10)
        creation_time, executions = wfInstance.unmarshallExecute(offline=True)
        assert (
            len(
                list(
                    filter(
                        lambda ex: ex.status != ExecutionStatus.Died
                        and (
                            ex.status
                            not in (ExecutionStatus.Queued, ExecutionStatus.Running)
                            or ex.job_id in job_ids
                        ),
                        executions,
                    )
                )
            )
            == NUM_PARALLEL
        ), f"Some jobs are missing (recorded {job_ids})"
        assert (
            len(executions) == NUM_PARALLEL
        ), f"Inconsistent initial number of registered executions (got {len(executions)}, expected {NUM_PARALLEL})"
    except:
        if should_fail is None or inspect.currentframe().f_code.co_name not in should_fail:  # type: ignore[union-attr]
            raise
    else:
        if should_fail is not None and inspect.currentframe().f_code.co_name in should_fail:  # type: ignore[union-attr]
            raise AssertionError(f"Method {inspect.currentframe().f_code.co_name} should have failed with stage file {stage_file} and context file {context_file}")  # type: ignore[union-attr]
