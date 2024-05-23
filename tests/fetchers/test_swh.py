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
    from typing import (
        Optional,
    )

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
from wfexs_backend.fetchers.swh import SoftwareHeritageFetcher

WfExS_basedir = Path(__file__).parent.parent
WfExS_basedir_file_uri = WfExS_basedir.as_uri()
WfExS_git_basedir = WfExS_basedir / ".git"
WfExS_git_basedir_file_uri = WfExS_git_basedir.as_uri()

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

SWH_TESTBED = pytest.mark.parametrize(
    ["url", "remote_repo", "repo_pid"],
    [
        (
            "swh:1:dir:6b1abfafa9baf6ffbe2ab1da2b036ed3ae8879a9;origin=https://github.com/inab/Wetlab2Variations;visit=swh:1:snp:4f8cb5f83b5a0b8d9d629e8cfcb979bba0b6b325;anchor=swh:1:rev:31348ed533961f84cf348bf1af660ad9de6f870c;path=/nextflow/",
            RemoteRepo(
                repo_url=cast(
                    "RepoURL",
                    "swh:1:dir:6b1abfafa9baf6ffbe2ab1da2b036ed3ae8879a9;origin=https://github.com/inab/Wetlab2Variations;visit=swh:1:snp:4f8cb5f83b5a0b8d9d629e8cfcb979bba0b6b325;anchor=swh:1:rev:31348ed533961f84cf348bf1af660ad9de6f870c;path=/nextflow/",
                ),
                tag=cast(
                    "RepoTag", "swh:1:dir:6b1abfafa9baf6ffbe2ab1da2b036ed3ae8879a9"
                ),
                repo_type=RepoType.SoftwareHeritage,
            ),
            "swh:1:dir:6b1abfafa9baf6ffbe2ab1da2b036ed3ae8879a9;origin=https://github.com/inab/Wetlab2Variations;visit=swh:1:snp:4f8cb5f83b5a0b8d9d629e8cfcb979bba0b6b325;anchor=swh:1:rev:31348ed533961f84cf348bf1af660ad9de6f870c;path=/nextflow/",
        ),
        (
            "swh:1:cnt:deb7365914c0fdf51fd0a4e9a75b4afe7f8d93f7;origin=https://github.com/inab/Wetlab2Variations;visit=swh:1:snp:4f8cb5f83b5a0b8d9d629e8cfcb979bba0b6b325;anchor=swh:1:rev:31348ed533961f84cf348bf1af660ad9de6f870c;path=/nextflow/nextflow.nf",
            RemoteRepo(
                repo_url=cast(
                    "RepoURL",
                    "swh:1:cnt:deb7365914c0fdf51fd0a4e9a75b4afe7f8d93f7;origin=https://github.com/inab/Wetlab2Variations;visit=swh:1:snp:4f8cb5f83b5a0b8d9d629e8cfcb979bba0b6b325;anchor=swh:1:rev:31348ed533961f84cf348bf1af660ad9de6f870c;path=/nextflow/nextflow.nf",
                ),
                tag=cast(
                    "RepoTag", "swh:1:cnt:deb7365914c0fdf51fd0a4e9a75b4afe7f8d93f7"
                ),
                repo_type=RepoType.SoftwareHeritage,
            ),
            "swh:1:cnt:deb7365914c0fdf51fd0a4e9a75b4afe7f8d93f7;origin=https://github.com/inab/Wetlab2Variations;visit=swh:1:snp:4f8cb5f83b5a0b8d9d629e8cfcb979bba0b6b325;anchor=swh:1:rev:31348ed533961f84cf348bf1af660ad9de6f870c;path=/nextflow/nextflow.nf",
        ),
        (
            "swh:1:rev:31348ed533961f84cf348bf1af660ad9de6f870c",
            RemoteRepo(
                repo_url=cast(
                    "RepoURL", "swh:1:rev:31348ed533961f84cf348bf1af660ad9de6f870c"
                ),
                tag=cast(
                    "RepoTag", "swh:1:rev:31348ed533961f84cf348bf1af660ad9de6f870c"
                ),
                repo_type=RepoType.SoftwareHeritage,
            ),
            "swh:1:rev:31348ed533961f84cf348bf1af660ad9de6f870c",
        ),
        (
            "swh:1:snp:4f8cb5f83b5a0b8d9d629e8cfcb979bba0b6b325",
            RemoteRepo(
                repo_url=cast(
                    "RepoURL", "swh:1:snp:4f8cb5f83b5a0b8d9d629e8cfcb979bba0b6b325"
                ),
                tag=cast(
                    "RepoTag", "swh:1:snp:4f8cb5f83b5a0b8d9d629e8cfcb979bba0b6b325"
                ),
                repo_type=RepoType.SoftwareHeritage,
            ),
            "swh:1:snp:4f8cb5f83b5a0b8d9d629e8cfcb979bba0b6b325",
        ),
    ],
)


@SWH_TESTBED
def test_guess_swh_repo_params(
    url: "str", remote_repo: "Optional[RemoteRepo]", repo_pid: "Optional[str]"
) -> "None":
    output = SoftwareHeritageFetcher.GuessRepoParams(
        cast("URIType", url), logger=logger
    )

    # When no web url is given, ignore what it was discovered
    if output is not None and remote_repo is not None:
        if remote_repo.web_url is None:
            output = output._replace(web_url=None)
        # For now, patch this
        if remote_repo.checkout is None:
            output = output._replace(checkout=None)
    assert output == remote_repo


@SWH_TESTBED
def test_build_swh_pid_from_repo(
    url: "str", remote_repo: "Optional[RemoteRepo]", repo_pid: "Optional[str]"
) -> "None":
    if remote_repo is None:
        pytest.skip("Skipped test because no remote repo was provided")
    else:
        fetcher = SoftwareHeritageFetcher({})
        output = fetcher.build_pid_from_repo(remote_repo)

        assert output == repo_pid
