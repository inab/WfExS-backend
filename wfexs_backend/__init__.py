#!/usr/bin/env python
# -*- coding: utf-8 -*-

# Copyright 2020-2022 Barcelona Supercomputing Center (BSC), Spain
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

__author__ = 'Laura Rodriguez-Navas <https://orcid.org/0000-0003-4929-1219>, José M. Fernández <https://orcid.org/0000-0002-4806-5140>'
__copyright__ = '© 2020-2022 Barcelona Supercomputing Center (BSC), ES'
__license__ = 'Apache 2.0'

# https://www.python.org/dev/peps/pep-0396/
__version__ = '0.5.3'

def describeGitRepo(repo):
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

    # Get the repository
    with dulwich.porcelain.open_repo_closing(repo) as r:
        # Get a list of all tags
        refs = r.get_refs()
        tags = {}
        for key, value in refs.items():
            key = key.decode()
            obj = r.get_object(value)
            if u"tags" not in key:
                continue

            _, tag = key.rsplit(u"/", 1)

            try:
                if isinstance(obj, dulwich.objects.Commit):
                    commit = obj
                else:
                    commit = obj.object
                    commit = r.get_object(commit[1])
            except AttributeError:
                continue
            tags[tag] = [
                datetime.datetime(*time.gmtime(commit.commit_time)[:6]),
                commit.id.decode("ascii"),
            ]

        sorted_tags = sorted(tags.items(), key=lambda tag: tag[1][0], reverse=True)

        # Get the latest commit
        latest_commit_id_decode = r[r.head()].id.decode("ascii")

        # If there are no tags, return the current commit
        if len(sorted_tags) == 0:
            return "g{}".format(r[r.head()].id.decode("ascii")[:7]), latest_commit_id_decode

        # We're now 0 commits from the top
        commit_count = 0

        # Walk through all commits
        walker = r.get_walker()
        skipFirst = True
        for entry in walker:
            # Check if tag
            commit_id = entry.commit.id.decode("ascii")
            for tag in sorted_tags:
                tag_name = tag[0]
                tag_commit = tag[1][1]
                if commit_id == tag_commit:
                    if commit_count == 0:
                        return tag_name, latest_commit_id_decode
                    else:
                        return "{}-{}-g{}".format(
                            tag_name,
                            commit_count,
                            latest_commit_id_decode[:7],
                        ), latest_commit_id_decode

            commit_count += 1

        # Return plain commit if no parent tag can be found
        return "g{}".format(latest_commit_id_decode[:7]), latest_commit_id_decode

# It returns something similar to 'git describe --tags'
def get_WfExS_version():
    import os
    import sys
    import dulwich.errors

    vertuple = __version__ , None
    executable = os.path.basename(sys.argv[0])
    #try:
    
    if executable.startswith('WfExS-'):
        wfexs_dirname = os.path.dirname(os.path.abspath(sys.argv[0]))
        
        try:
            vertuple = describeGitRepo(wfexs_dirname)
        except dulwich.errors.NotGitRepository as de:
            # This can happen when WfExS-backend is installed using pip
            pass
    
    return vertuple
