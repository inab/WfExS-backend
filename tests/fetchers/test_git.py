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
        Type,
        Union,
    )

    from wfexs_backend.common import (
        RelPath,
        RepoTag,
        RepoURL,
        URIType,
    )

from wfexs_backend.scheme_catalog import (
    SchemeCatalog,
)

from wfexs_backend.fetchers import (
    RemoteRepo,
    RepoGuessException,
    RepoGuessFlavor,
    RepoType,
)

from wfexs_backend.fetchers.http import HTTPFetcher

from wfexs_backend.fetchers.git import GitFetcher

import wfexs_backend

WfExS_basedir = Path(wfexs_backend.__file__).parent.parent
WfExS_basedir_file_uri = WfExS_basedir.as_uri()
WfExS_git_basedir = WfExS_basedir / ".git"
WfExS_git_basedir_file_uri = WfExS_git_basedir.as_uri()

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

GIT_TESTBED = pytest.mark.parametrize(
    ["url", "remote_repo_or_exception_class", "repo_pid"],
    [
        (
            "https://github.com/inab/WfExS-backend.git",
            RemoteRepo(
                repo_url=cast("RepoURL", "https://github.com/inab/WfExS-backend.git"),
                tag=cast("RepoTag", "main"),
                guess_flavor=RepoGuessFlavor.GitHub,
                repo_type=RepoType.Git,
            ),
            "git+https://github.com/inab/WfExS-backend.git@main",
        ),
        (
            "git+https://github.com/inab/WfExS-backend.git",
            RemoteRepo(
                repo_url=cast("RepoURL", "https://github.com/inab/WfExS-backend.git"),
                tag=cast("RepoTag", "main"),
                repo_type=RepoType.Git,
            ),
            "git+https://github.com/inab/WfExS-backend.git@main",
        ),
        (
            "https://github.com/inab/WfExS-backend.git@0.2.0",
            RemoteRepo(
                repo_url=cast("RepoURL", "https://github.com/inab/WfExS-backend.git"),
                repo_type=RepoType.Git,
                tag=cast("RepoTag", "0.2.0"),
                checkout=cast("RepoTag", "906f48308c62e78bff2057fd60862d08707df6b7"),
            ),
            "git+https://github.com/inab/WfExS-backend.git@906f48308c62e78bff2057fd60862d08707df6b7",
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
            "git+https://github.com/inab/WfExS-backend.git@main#subdirectory=workflow_examples/ipc/cosifer_test1_cwl.wfex.stage",
        ),
        (
            "ssh://git@github.com:inab/WfExS-backend.git",
            RemoteRepo(
                repo_url=cast("RepoURL", "ssh://git@github.com/inab/WfExS-backend.git"),
                tag=cast("RepoTag", "main"),
                repo_type=RepoType.Git,
            ),
            "git+ssh://git@github.com:inab/WfExS-backend.git@main",
        ),
        (
            "git+ssh://git@github.com:inab/WfExS-backend.git",
            RemoteRepo(
                repo_url=cast("RepoURL", "ssh://git@github.com/inab/WfExS-backend.git"),
                tag=cast("RepoTag", "main"),
                repo_type=RepoType.Git,
            ),
            "git+ssh://git@github.com:inab/WfExS-backend.git@main",
        ),
        (
            # This tag does not exists!
            "ssh://git@github.com:inab/WfExS-backend.git@0.1.2",
            RepoGuessException,
            "git+ssh://git@github.com:inab/WfExS-backend.git@0.1.2",
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
            "git+ssh://git@github.com:inab/WfExS-backend.git@main#subdirectory=workflow_examples/ipc/cosifer_test1_cwl.wfex.stage",
        ),
        (
            WfExS_git_basedir_file_uri,
            RemoteRepo(
                repo_url=cast("RepoURL", WfExS_git_basedir_file_uri),
                repo_type=RepoType.Git,
            ),
            "git+" + WfExS_git_basedir_file_uri,
        ),
        (
            "git+" + WfExS_git_basedir_file_uri,
            RemoteRepo(
                repo_url=cast("RepoURL", WfExS_git_basedir_file_uri),
                repo_type=RepoType.Git,
            ),
            "git+" + WfExS_git_basedir_file_uri,
        ),
        (
            # This tag does not exists!
            WfExS_git_basedir_file_uri + "@0.1.2",
            RepoGuessException,
            "git+" + WfExS_git_basedir_file_uri + "@0.1.2",
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
            "git+"
            + WfExS_git_basedir_file_uri
            + "#subdirectory=workflow_examples/ipc/cosifer_test1_cwl.wfex.stage",
        ),
        (
            "github.com/inab/WfExS-backend.git",
            None,
            None,
        ),
        (
            "git@github.com:inab/WfExS-backend.git",
            RemoteRepo(
                repo_url=cast("RepoURL", "ssh://git@github.com/inab/WfExS-backend.git"),
                tag=cast("RepoTag", "main"),
                repo_type=RepoType.Git,
            ),
            "git+ssh://git@github.com:inab/WfExS-backend.git@main",
        ),
        (
            "ssh://git@github.com:inab/WfExS-backend",
            RemoteRepo(
                repo_url=cast("RepoURL", "ssh://git@github.com/inab/WfExS-backend"),
                tag=cast("RepoTag", "main"),
                repo_type=RepoType.Git,
            ),
            "git+ssh://git@github.com:inab/WfExS-backend.git@main",
        ),
        (
            "https://github.com/inab/WfExS-backend",
            RemoteRepo(
                repo_url=cast("RepoURL", "https://github.com/inab/WfExS-backend"),
                guess_flavor=RepoGuessFlavor.GitHub,
                repo_type=RepoType.Git,
                tag=cast("RepoTag", "main"),
            ),
            "git+https://github.com/inab/WfExS-backend.git@main",
        ),
        (
            WfExS_basedir_file_uri,
            RemoteRepo(
                repo_url=cast("RepoURL", WfExS_basedir_file_uri),
                repo_type=RepoType.Git,
            ),
            "git+" + WfExS_basedir_file_uri,
        ),
        (
            "github:inab/ipc_workflows/cosifer-20210322/cosifer/cwl/cosifer-workflow.cwl",
            RemoteRepo(
                repo_url=cast("RepoURL", "https://github.com/inab/ipc_workflows"),
                guess_flavor=RepoGuessFlavor.GitHub,
                repo_type=RepoType.Git,
                tag=cast("RepoTag", "cosifer-20210322"),
                rel_path=cast("RelPath", "cosifer/cwl/cosifer-workflow.cwl"),
            ),
            "git+https://github.com/inab/ipc_workflows.git@cosifer-20210322#subdirectory=cosifer/cwl/cosifer-workflow.cwl",
        ),
    ],
)


@GIT_TESTBED
def test_guess_git_repo_params(
    url: "str",
    remote_repo_or_exception_class: "Optional[Union[RemoteRepo, Type[Exception]]]",
    repo_pid: "Optional[str]",
) -> "None":
    if (
        isinstance(remote_repo_or_exception_class, RemoteRepo)
        or remote_repo_or_exception_class is None
    ):
        output = GitFetcher.GuessRepoParams(cast("URIType", url), logger=logger)

        # When no tag is given, ignore what it was discovered
        if output is not None and remote_repo_or_exception_class is not None:
            if remote_repo_or_exception_class.tag is None:
                output = output._replace(tag=None)
            # For now, patch this
            if remote_repo_or_exception_class.checkout is not None:
                output = output._replace(
                    checkout=remote_repo_or_exception_class.checkout
                )
        assert output == remote_repo_or_exception_class

    else:
        with pytest.raises(remote_repo_or_exception_class):
            output = GitFetcher.GuessRepoParams(cast("URIType", url), logger=logger)


@GIT_TESTBED
def test_build_git_pid_from_repo(
    url: "str",
    remote_repo_or_exception_class: "Optional[Union[RemoteRepo, Type[Exception]]]",
    repo_pid: "Optional[str]",
) -> "None":
    if remote_repo_or_exception_class is None or not isinstance(
        remote_repo_or_exception_class, RemoteRepo
    ):
        pytest.skip("Skipped test because no remote repo was provided")
    else:
        scheme_catalog = SchemeCatalog(
            scheme_handlers=HTTPFetcher.GetSchemeHandlers(),
        )

        fetcher = GitFetcher(scheme_catalog, progs={})
        output = fetcher.build_pid_from_repo(remote_repo_or_exception_class)

        assert output == repo_pid
