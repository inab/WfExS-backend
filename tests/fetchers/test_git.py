import pytest
import logging
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

from wfexs_backend.common import RemoteRepo, RepoType
from wfexs_backend.fetchers.git import guess_git_repo_params


@pytest.mark.parametrize(
    ["url", "expected"],
    [
        (
            "https://github.com/inab/WfExS-backend.git",
            RemoteRepo(
                repo_url=cast("RepoURL", "https://github.com/inab/WfExS-backend.git"),
                repo_type=RepoType.Git,
            ),
        ),
        (
            "git+https://github.com/inab/WfExS-backend.git",
            RemoteRepo(
                repo_url=cast("RepoURL", "https://github.com/inab/WfExS-backend.git"),
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
                rel_path=cast(
                    "RelPath", "workflow_examples/ipc/cosifer_test1_cwl.wfex.stage"
                ),
            ),
        ),
        (
            "ssh://git@github.com:inab/WfExS-backend.git",
            RemoteRepo(
                repo_url=cast("RepoURL", "git@github.com:inab/WfExS-backend.git"),
                repo_type=RepoType.Git,
            ),
        ),
        (
            "git+ssh://git@github.com:inab/WfExS-backend.git",
            RemoteRepo(
                repo_url=cast("RepoURL", "git@github.com:inab/WfExS-backend.git"),
                repo_type=RepoType.Git,
            ),
        ),
        (
            "ssh://git@github.com:inab/WfExS-backend.git@0.1.2",
            RemoteRepo(
                repo_url=cast("RepoURL", "git@github.com:inab/WfExS-backend.git"),
                repo_type=RepoType.Git,
                tag=cast("RepoTag", "0.1.2"),
            ),
        ),
        (
            "ssh://git@github.com:inab/WfExS-backend.git#subdirectory=workflow_examples/ipc/cosifer_test1_cwl.wfex.stage",
            RemoteRepo(
                repo_url=cast("RepoURL", "git@github.com:inab/WfExS-backend.git"),
                repo_type=RepoType.Git,
                rel_path=cast(
                    "RelPath", "workflow_examples/ipc/cosifer_test1_cwl.wfex.stage"
                ),
            ),
        ),
        (
            "file:///inab/WfExS-backend/.git",
            RemoteRepo(
                repo_url=cast("RepoURL", "file:///inab/WfExS-backend/.git"),
                repo_type=RepoType.Git,
            ),
        ),
        (
            "git+file:///inab/WfExS-backend/.git",
            RemoteRepo(
                repo_url=cast("RepoURL", "file:///inab/WfExS-backend/.git"),
                repo_type=RepoType.Git,
            ),
        ),
        (
            "file:///inab/WfExS-backend/.git@0.1.2",
            RemoteRepo(
                repo_url=cast("RepoURL", "file:///inab/WfExS-backend/.git"),
                repo_type=RepoType.Git,
                tag=cast("RepoTag", "0.1.2"),
            ),
        ),
        (
            "file:///inab/WfExS-backend/.git#subdirectory=workflow_examples/ipc/cosifer_test1_cwl.wfex.stage",
            RemoteRepo(
                repo_url=cast("RepoURL", "file:///inab/WfExS-backend/.git"),
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
            None,
        ),
        (
            "ssh://git@github.com:inab/WfExS-backend",
            RemoteRepo(
                repo_url=cast("RepoURL", "git@github.com:inab/WfExS-backend"),
                repo_type=RepoType.Git,
            ),
        ),
        (
            "https://github.com/inab/WfExS-backend",
            RemoteRepo(
                repo_url=cast("RepoURL", "https://github.com/inab/WfExS-backend"),
                repo_type=RepoType.Git,
            ),
        ),
        (
            "file:///inab/WfExS-backend",
            RemoteRepo(
                repo_url=cast("RepoURL", "file:///inab/WfExS-backend"),
                repo_type=RepoType.Git,
            ),
        ),
    ],
)
def test_guess_git_repo_params(url: "str", expected: "RemoteRepo") -> "None":
    logger = logging.Logger("name")
    output = guess_git_repo_params(cast("URIType", url), logger=logger)
    assert output == expected
