#!/usr/bin/env python
# -*- coding: utf-8 -*-

# SPDX-License-Identifier: Apache-2.0
# Copyright 2020-2023 Barcelona Supercomputing Center (BSC), Spain
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

__author__ = "José M. Fernández <https://orcid.org/0000-0002-4806-5140>, Laura Rodriguez-Navas <https://orcid.org/0000-0003-4929-1219>, Adrián Muñoz-Cívico <https://orcid.org/0000-0001-7517-5065>, Paula Iborra <https://orcid.org/0000-0003-0504-3029>"
__copyright__ = "© 2020-2023 Barcelona Supercomputing Center (BSC), ES"
__license__ = "Apache 2.0"

# https://www.python.org/dev/peps/pep-0396/
__version__ = "0.10.2"
__url__ = "https://github.com/inab/WfExS-backend"
__official_name__ = "WfExS-backend"

from typing import (
    cast,
    TYPE_CHECKING,
)

if TYPE_CHECKING:
    from typing import (
        MutableMapping,
        Optional,
        Sequence,
        Tuple,
    )


def describeGitRepo(repo: "str") -> "Tuple[str, str, str]":
    """Describe the repository version.

    Args:
    projdir: git repository root
    Returns: a string description of the current git revision

    Examples: "gabcdefh", "v0.1" or "v0.1-5-gabcdefh".
    """
    import datetime
    import dulwich.objects
    import dulwich.porcelain
    import time

    if TYPE_CHECKING:
        import dulwich.repo
        import dulwich.walk

    active_branch = dulwich.porcelain.active_branch(repo)  # type: ignore[no-untyped-call]
    active_branch_decode = active_branch.decode("utf-8", errors="ignore")
    # Get the repository
    r: "dulwich.repo.Repo"
    with dulwich.porcelain.open_repo_closing(repo) as r:  # type: ignore[no-untyped-call]
        # Get a list of all tags
        refs = r.get_refs()
        tags: "MutableMapping[str, Tuple[datetime.datetime, str]]" = {}
        for keyb, value in refs.items():
            key = keyb.decode()
            obj = r.get_object(value)
            if "tags" not in key:
                continue

            _, tag = key.rsplit("/", 1)

            try:
                if isinstance(obj, dulwich.objects.Commit):
                    commit = obj
                elif isinstance(obj, dulwich.objects.Tag):
                    commit_o = obj.object
                    commit = cast("dulwich.objects.Commit", r.get_object(commit_o[1]))
                else:
                    continue
            except AttributeError:
                continue
            tags[tag] = (
                datetime.datetime(*time.gmtime(commit.commit_time)[:6]),
                commit.id.decode("ascii"),
            )

        sorted_tags: "Sequence[Tuple[str, Tuple[datetime.datetime, str]]]" = sorted(
            tags.items(), key=lambda tag: (tag[1][0], tag[0]), reverse=True
        )

        # Get the latest commit
        latest_commit_id_decode = r[r.head()].id.decode("ascii")

        # If there are no tags, return the current commit
        if len(sorted_tags) == 0:
            return (
                "g{}".format(r[r.head()].id.decode("ascii")[:7]),
                latest_commit_id_decode,
                active_branch_decode,
            )

        # We're now 0 commits from the top
        commit_count = 0

        # Walk through all commits
        walker: "dulwich.walk.Walker"
        walker = r.get_walker()  # type: ignore[no-untyped-call]
        skipFirst = True
        for entry in walker:
            # Check if tag
            commit_id = entry.commit.id.decode("ascii")
            for sorted_tag in sorted_tags:
                tag_name = sorted_tag[0]
                tag_commit = sorted_tag[1][1]
                if commit_id == tag_commit:
                    if commit_count == 0:
                        return tag_name, latest_commit_id_decode, active_branch_decode
                    else:
                        return (
                            "{}-{}-g{}".format(
                                tag_name,
                                commit_count,
                                latest_commit_id_decode[:7],
                            ),
                            latest_commit_id_decode,
                            active_branch_decode,
                        )

            commit_count += 1

        # Return plain commit if no parent tag can be found
        return (
            "g{}".format(latest_commit_id_decode[:7]),
            latest_commit_id_decode,
            active_branch_decode,
        )


# It returns something similar to 'git describe --tags'
def get_WfExS_version() -> "Tuple[str, Optional[str], Optional[str]]":
    import os
    import sys
    import dulwich.errors

    vertuple: "Tuple[str, Optional[str], Optional[str]]"
    vertuple = __version__, None, None
    executable = os.path.basename(sys.argv[0])
    # try:

    if executable.startswith("WfExS-"):
        wfexs_dirname = os.path.dirname(os.path.abspath(sys.argv[0]))

        try:
            vertuple = describeGitRepo(wfexs_dirname)
        except dulwich.errors.NotGitRepository as de:
            # This can happen when WfExS-backend is installed using pip
            pass

    return vertuple


def get_WfExS_version_str() -> "str":
    wfexs_version = get_WfExS_version()

    verstr = wfexs_version[0]
    if wfexs_version[1] is not None:
        verstr += " (" + wfexs_version[1]
        if wfexs_version[2] is not None:
            verstr += ", branch " + wfexs_version[2]
        verstr += ")"
    elif wfexs_version[2] is not None:
        verstr += " (branch " + wfexs_version[2] + ")"

    return verstr
