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

from pathlib import Path

from typing import (
    cast,
    TYPE_CHECKING,
)

if TYPE_CHECKING:
    from wfexs_backend.common import (
        RelPath,
        RepoTag,
        RepoURL,
        URIType,
    )

from wfexs_backend.fetchers import (
    RemoteRepo,
    RepoGuessFlavor,
    RepoType,
)
from wfexs_backend.fetchers.git import GitFetcher

WfExS_basedir = Path(__file__).parent.parent
WfExS_basedir_file_uri = WfExS_basedir.as_uri()
WfExS_git_basedir = WfExS_basedir / ".git"
WfExS_git_basedir_file_uri = WfExS_git_basedir.as_uri()


@pytest.mark.parametrize(
    ["url", "expected"],
    [
        (
            "https://github.com/inab/WfExS-backend.git",
            RemoteRepo(
                repo_url=cast("RepoURL", "https://github.com/inab/WfExS-backend.git"),
                tag=cast("RepoTag", "main"),
                guess_flavor=RepoGuessFlavor.GitHub,
                repo_type=RepoType.Git,
            ),
        ),
        (
            "git+https://github.com/inab/WfExS-backend.git",
            RemoteRepo(
                repo_url=cast("RepoURL", "https://github.com/inab/WfExS-backend.git"),
                tag=cast("RepoTag", "main"),
                repo_type=RepoType.Git,
            ),
        ),
        (
            "https://github.com/inab/WfExS-backend.git@0.1.2",
            RemoteRepo(
                repo_url=cast("RepoURL", "https://github.com/inab/WfExS-backend.git"),
                repo_type=RepoType.Git,
                tag=cast("RepoTag", "0.1.2"),
            ),
        ),
        (
            "https://github.com/inab/WfExS-backend.git#subdirectory=workflow_examples/ipc/cosifer_test1_cwl.wfex.stage",
            RemoteRepo(
                repo_url=cast("RepoURL", "https://github.com/inab/WfExS-backend.git"),
                repo_type=RepoType.Git,
                tag=cast("RepoTag", "main"),
                rel_path=cast(
                    "RelPath", "workflow_examples/ipc/cosifer_test1_cwl.wfex.stage"
                ),
            ),
        ),
        (
            "ssh://git@github.com:inab/WfExS-backend.git",
            RemoteRepo(
                repo_url=cast("RepoURL", "ssh://git@github.com/inab/WfExS-backend.git"),
                tag=cast("RepoTag", "main"),
                repo_type=RepoType.Git,
            ),
        ),
        (
            "git+ssh://git@github.com:inab/WfExS-backend.git",
            RemoteRepo(
                repo_url=cast("RepoURL", "ssh://git@github.com/inab/WfExS-backend.git"),
                tag=cast("RepoTag", "main"),
                repo_type=RepoType.Git,
            ),
        ),
        (
            "ssh://git@github.com:inab/WfExS-backend.git@0.1.2",
            RemoteRepo(
                repo_url=cast("RepoURL", "ssh://git@github.com/inab/WfExS-backend.git"),
                repo_type=RepoType.Git,
                tag=cast("RepoTag", "0.1.2"),
            ),
        ),
        (
            "ssh://git@github.com:inab/WfExS-backend.git#subdirectory=workflow_examples/ipc/cosifer_test1_cwl.wfex.stage",
            RemoteRepo(
                repo_url=cast("RepoURL", "ssh://git@github.com/inab/WfExS-backend.git"),
                repo_type=RepoType.Git,
                tag=cast("RepoTag", "main"),
                rel_path=cast(
                    "RelPath", "workflow_examples/ipc/cosifer_test1_cwl.wfex.stage"
                ),
            ),
        ),
        (
            WfExS_git_basedir_file_uri,
            RemoteRepo(
                repo_url=cast("RepoURL", WfExS_git_basedir_file_uri),
                repo_type=RepoType.Git,
            ),
        ),
        (
            "git+" + WfExS_git_basedir_file_uri,
            RemoteRepo(
                repo_url=cast("RepoURL", WfExS_git_basedir_file_uri),
                repo_type=RepoType.Git,
            ),
        ),
        (
            WfExS_git_basedir_file_uri + "@0.1.2",
            RemoteRepo(
                repo_url=cast("RepoURL", WfExS_git_basedir_file_uri),
                repo_type=RepoType.Git,
                tag=cast("RepoTag", "0.1.2"),
            ),
        ),
        (
            WfExS_git_basedir_file_uri
            + "#subdirectory=workflow_examples/ipc/cosifer_test1_cwl.wfex.stage",
            RemoteRepo(
                repo_url=cast("RepoURL", WfExS_git_basedir_file_uri),
                repo_type=RepoType.Git,
                rel_path=cast(
                    "RelPath", "workflow_examples/ipc/cosifer_test1_cwl.wfex.stage"
                ),
            ),
        ),
        (
            "github.com/inab/WfExS-backend.git",
            None,
        ),
        (
            "git@github.com:inab/WfExS-backend.git",
            RemoteRepo(
                repo_url=cast("RepoURL", "ssh://git@github.com/inab/WfExS-backend.git"),
                tag=cast("RepoTag", "main"),
                repo_type=RepoType.Git,
            ),
        ),
        (
            "ssh://git@github.com:inab/WfExS-backend",
            RemoteRepo(
                repo_url=cast("RepoURL", "ssh://git@github.com/inab/WfExS-backend"),
                tag=cast("RepoTag", "main"),
                repo_type=RepoType.Git,
            ),
        ),
        (
            "https://github.com/inab/WfExS-backend",
            RemoteRepo(
                repo_url=cast("RepoURL", "https://github.com/inab/WfExS-backend"),
                guess_flavor=RepoGuessFlavor.GitHub,
                repo_type=RepoType.Git,
                tag=cast("RepoTag", "main"),
            ),
        ),
        (
            WfExS_basedir_file_uri,
            RemoteRepo(
                repo_url=cast("RepoURL", WfExS_basedir_file_uri),
                repo_type=RepoType.Git,
            ),
        ),
    ],
)
def test_guess_git_repo_params(url: "str", expected: "RemoteRepo") -> "None":
    logger = logging.Logger("name")
    output = GitFetcher.GuessRepoParams(cast("URIType", url), logger=logger)

    # When no tag is given, ignore what it was discovered
    if output is not None and expected is not None and expected.tag is None:
        output = output._replace(tag=None)
    assert output == expected
