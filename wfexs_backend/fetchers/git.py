#!/usr/bin/env python
# -*- coding: utf-8 -*-

# Copyright 2020-2021 Barcelona Supercomputing Center (BSC), Spain
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

import atexit
import hashlib
import os
import shutil
import subprocess
import tempfile
from typing import Mapping, Optional
from urllib import parse

from . import AbstractStatefulFetcher
from ..common import *

class GitFetcher(AbstractStatefulFetcher):
    def __init__(self, progs: Mapping[SymbolicName, AbsPath]):
        super().__init__(progs=progs)
        
        self.git_cmd = self.progs.get(DEFAULT_GIT_CMD, DEFAULT_GIT_CMD)

    def doMaterializeRepo(self, repoURL, repoTag: Optional[RepoTag] = None, repo_tag_destdir: Optional[AbsPath] = None, base_repo_destdir: Optional[AbsPath] = None, doUpdate: Optional[bool] = True) -> Tuple[AbsPath, RepoTag]:
        """

        :param repoURL:
        :param repoTag:
        :param doUpdate:
        :return:
        """

        # Assure directory exists before next step
        if repo_tag_destdir is None:
            if base_repo_destdir is None:
                repo_tag_destdir = tempfile.mkdtemp(prefix='wfexs', suffix='.git')
                atexit.register(shutil.rmtree, repo_tag_destdir)
            else:
                repo_hashed_id = hashlib.sha1(repoURL.encode('utf-8')).hexdigest()
                repo_destdir = os.path.join(base_repo_destdir, repo_hashed_id)
                # repo_destdir = os.path.join(self.cacheWorkflowDir, repo_hashed_id)
                
                if not os.path.exists(repo_destdir):
                    try:
                        os.makedirs(repo_destdir)
                    except IOError:
                        errstr = "ERROR: Unable to create intermediate directories for repo {}. ".format(repoURL)
                        raise WFException(errstr)

                repo_hashed_tag_id = hashlib.sha1(b'' if repoTag is None else repoTag.encode('utf-8')).hexdigest()
                repo_tag_destdir = os.path.join(repo_destdir, repo_hashed_tag_id)
        
        self.logger.debug(f'Repo dir {repo_tag_destdir}')
        
        # We are assuming that, if the directory does exist, it contains the repo
        doRepoUpdate = True
        if not os.path.exists(os.path.join(repo_tag_destdir, '.git')):
            # Try cloning the repository without initial checkout
            if repoTag is not None:
                gitclone_params = [
                    self.git_cmd, 'clone', '-n', '--recurse-submodules', repoURL, repo_tag_destdir
                ]

                # Now, checkout the specific commit
                gitcheckout_params = [
                    self.git_cmd, 'checkout', repoTag
                ]
            else:
                # We know nothing about the tag, or checkout
                gitclone_params = [
                    self.git_cmd, 'clone', '--recurse-submodules', repoURL, repo_tag_destdir
                ]

                gitcheckout_params = None
        elif doUpdate:
            gitclone_params = None
            gitcheckout_params = [
                self.git_cmd, 'pull', '--recurse-submodules'
            ]
            if repoTag is not None:
                gitcheckout_params.extend(['origin', repoTag])
        else:
            doRepoUpdate = False

        if doRepoUpdate:
            with tempfile.NamedTemporaryFile() as git_stdout, tempfile.NamedTemporaryFile() as git_stderr:

                # First, (bare) clone
                retval = 0
                if gitclone_params is not None:
                    self.logger.debug(f'Running "{" ".join(gitclone_params)}"')
                    retval = subprocess.call(gitclone_params, stdout=git_stdout, stderr=git_stderr)
                # Then, checkout (which can be optional)
                if retval == 0 and (gitcheckout_params is not None):
                    self.logger.debug(f'Running "{" ".join(gitcheckout_params)}"')
                    retval = subprocess.Popen(gitcheckout_params, stdout=git_stdout, stderr=git_stderr,
                                              cwd=repo_tag_destdir).wait()
                # Last, submodule preparation
                if retval == 0:
                    # Last, initialize submodules
                    gitsubmodule_params = [
                        self.git_cmd, 'submodule', 'update', '--init', '--recursive'
                    ]

                    self.logger.debug(f'Running "{" ".join(gitsubmodule_params)}"')
                    retval = subprocess.Popen(gitsubmodule_params, stdout=git_stdout, stderr=git_stderr,
                                              cwd=repo_tag_destdir).wait()

                # Proper error handling
                if retval != 0:
                    # Reading the output and error for the report
                    with open(git_stdout.name, "r") as c_stF:
                        git_stdout_v = c_stF.read()
                    with open(git_stderr.name, "r") as c_stF:
                        git_stderr_v = c_stF.read()

                    errstr = "ERROR: Unable to pull '{}' (tag '{}'). Retval {}\n======\nSTDOUT\n======\n{}\n======\nSTDERR\n======\n{}".format(
                        repoURL, repoTag, retval, git_stdout_v, git_stderr_v)
                    raise WFException(errstr)

        # Last, we have to obtain the effective checkout
        gitrevparse_params = [
            self.git_cmd, 'rev-parse', '--verify', 'HEAD'
        ]

        self.logger.debug(f'Running "{" ".join(gitrevparse_params)}"')
        with subprocess.Popen(gitrevparse_params, stdout=subprocess.PIPE, encoding='iso-8859-1',
                              cwd=repo_tag_destdir) as revproc:
            repo_effective_checkout = revproc.stdout.read().rstrip()

        return repo_tag_destdir, repo_effective_checkout


    def fetch(self, remote_file:URIType, cachedFilename:AbsPath, secContext:Optional[SecurityContextConfig]=None) -> Tuple[Union[URIType, ContentKind], List[URIWithMetadata]]:
        parsedInputURL = parse.urlparse(remote_file)
        
        # These are the usual URIs which can be understood by pip
        # See https://pip.pypa.io/en/stable/cli/pip_install/#git
        if not parsedInputURL.scheme.startswith('git+') and parsedInputURL.scheme != 'git':
            raise WFException()
            
        # Getting the scheme git is going to understand
        if len(parsedInputURL.scheme) > 3:
            gitScheme = parsedInputURL.scheme[4:]
        else:
            gitScheme = parsedInputURL.scheme

        # Getting the tag or branch
        if '@' in parsedInputURL.path:
            gitPath, repoTag = parsedInputURL.path.split('@', 1)
        else:
            gitPath = parsedInputURL.path
            repoTag = None

        # Getting the repoRelPath (if available)
        if len(parsedInputURL.fragment) > 0:
            frag_qs = parse.parse_qs(parsedInputURL.fragment)
            subDirArr = frag_qs.get('subdirectory', [])
            if len(subDirArr) > 0:
                repoRelPath = subDirArr[0]
        else:
            repoRelPath = None

        # Now, reassemble the repoURL, to be used by git client
        repoURL = parse.urlunparse((gitScheme, parsedInputURL.netloc, gitPath, '', '', ''))
        
        repo_tag_destdir , repo_effective_checkout = self.doMaterializeRepo(repoURL, repoTag=repoTag)
        
        if repoRelPath is not None:
            cachedContentPath = os.path.join(repo_tag_destdir, repoRelPath)
            preferredName = repoRelPath.split('/')[-1]
        else:
            cachedContentPath = repo_tag_destdir
            preferredName = None
        
        if os.path.isdir(cachedContentPath):
            kind = ContentKind.Directory
        elif os.path.isfile(cachedContentPath):
            kind = ContentKind.File
        else:
            raise WFException(f"Remote {remote_file} is neither a file nor a directory (does it exist?)")
        
        shutil.move(cachedContentPath, cachedFilename)
        
        return kind, [
            URIWithMetadata(
                uri=remote_file,
                metadata={
                    'repo': repoURL,
                    'tag': repoTag,
                    'relpath': repoRelPath
                },
                preferredName=preferredName
            )
        ]
        

# These are de-facto schemes supported by pip and git client
SCHEME_HANDLERS = {
    'git': GitFetcher,
    'git+https': GitFetcher,
    'git+http': GitFetcher,
}
