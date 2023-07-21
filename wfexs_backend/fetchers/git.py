#!/usr/bin/env python
# -*- coding: utf-8 -*-

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

import atexit
import hashlib
import os
import shutil
import subprocess
import tempfile
from typing import (
    cast,
    TYPE_CHECKING,
)

if TYPE_CHECKING:
    import logging

    from typing import (
        Any,
        Mapping,
        MutableMapping,
        MutableSequence,
        Optional,
        Tuple,
        Type,
        Union,
        Sequence,
    )

    from typing_extensions import (
        Final,
    )

    from ..common import (
        AbsPath,
        AnyPath,
        ProgsMapping,
        RelPath,
        RepoTag,
        RepoURL,
        SecurityContextConfig,
        SymbolicName,
        URIType,
    )

    from . import (
        AbstractStatefulFetcher,
        RepoDesc,
    )


from urllib import parse, request

import dulwich.porcelain
import git

from . import (
    AbstractRepoFetcher,
    FetcherException,
    RepoGuessException,
)

from ..common import (
    ContentKind,
    ProtocolFetcherReturn,
    RemoteRepo,
    RepoType,
    URIWithMetadata,
)

from ..utils.contents import link_or_copy

GITHUB_SCHEME = "github"
GITHUB_NETLOC = "github.com"


class GitFetcher(AbstractRepoFetcher):
    GIT_PROTO: "Final[str]" = "git"
    GIT_PROTO_PREFIX: "Final[str]" = GIT_PROTO + "+"
    DEFAULT_GIT_CMD: "Final[SymbolicName]" = cast("SymbolicName", "git")

    def __init__(
        self, progs: "ProgsMapping", setup_block: "Optional[Mapping[str, Any]]" = None
    ):
        super().__init__(progs=progs, setup_block=setup_block)

        self.git_cmd = self.progs.get(
            self.DEFAULT_GIT_CMD, cast("RelPath", self.DEFAULT_GIT_CMD)
        )

    @classmethod
    def GetSchemeHandlers(cls) -> "Mapping[str, Type[AbstractStatefulFetcher]]":
        # These are de-facto schemes supported by pip and git client
        return {
            cls.GIT_PROTO: cls,
            cls.GIT_PROTO_PREFIX + "https": cls,
            cls.GIT_PROTO_PREFIX + "http": cls,
        }

    @classmethod
    def GetNeededPrograms(cls) -> "Sequence[SymbolicName]":
        return (cls.DEFAULT_GIT_CMD,)

    def doMaterializeRepo(
        self,
        repoURL: "RepoURL",
        repoTag: "Optional[RepoTag]" = None,
        repo_tag_destdir: "Optional[AbsPath]" = None,
        base_repo_destdir: "Optional[AbsPath]" = None,
        doUpdate: "Optional[bool]" = True,
    ) -> "Tuple[AbsPath, RepoDesc, Sequence[URIWithMetadata]]":
        """

        :param repoURL: The URL to the repository.
        :param repoTag: The tag or branch to checkout.
        By default, checkout the repository's default branch.
        :param doUpdate:
        :return:
        """

        # Assure directory exists before next step
        if repo_tag_destdir is None:
            if base_repo_destdir is None:
                repo_tag_destdir = cast(
                    "AbsPath", tempfile.mkdtemp(prefix="wfexs", suffix=".git")
                )
                atexit.register(shutil.rmtree, repo_tag_destdir)
            else:
                repo_hashed_id = hashlib.sha1(repoURL.encode("utf-8")).hexdigest()
                repo_destdir = os.path.join(base_repo_destdir, repo_hashed_id)
                # repo_destdir = os.path.join(self.cacheWorkflowDir, repo_hashed_id)

                if not os.path.exists(repo_destdir):
                    try:
                        os.makedirs(repo_destdir)
                    except IOError:
                        errstr = "ERROR: Unable to create intermediate directories for repo {}. ".format(
                            repoURL
                        )
                        raise FetcherException(errstr)

                repo_hashed_tag_id = hashlib.sha1(
                    b"" if repoTag is None else repoTag.encode("utf-8")
                ).hexdigest()
                repo_tag_destdir = cast(
                    "AbsPath", os.path.join(repo_destdir, repo_hashed_tag_id)
                )

        self.logger.debug(f"Repo dir {repo_tag_destdir}")

        # We are assuming that, if the directory does exist, it contains the repo
        doRepoUpdate = True
        if not os.path.exists(os.path.join(repo_tag_destdir, ".git")):
            # Try cloning the repository without initial checkout
            if repoTag is not None:
                gitclone_params = [
                    self.git_cmd,
                    "clone",
                    "-n",
                    "--recurse-submodules",
                    repoURL,
                    repo_tag_destdir,
                ]

                # Now, checkout the specific commit
                gitcheckout_params = [self.git_cmd, "checkout", repoTag]
            else:
                # We know nothing about the tag, or checkout
                gitclone_params = [
                    self.git_cmd,
                    "clone",
                    "--recurse-submodules",
                    repoURL,
                    repo_tag_destdir,
                ]

                gitcheckout_params = None
        elif doUpdate:
            gitclone_params = None
            gitcheckout_params = [self.git_cmd, "pull", "--recurse-submodules"]
            if repoTag is not None:
                gitcheckout_params.extend(["origin", repoTag])
        else:
            doRepoUpdate = False

        if doRepoUpdate:
            with tempfile.NamedTemporaryFile() as git_stdout, tempfile.NamedTemporaryFile() as git_stderr:
                # First, (bare) clone
                retval = 0
                if gitclone_params is not None:
                    self.logger.debug(f'Running "{" ".join(gitclone_params)}"')
                    retval = subprocess.call(
                        gitclone_params, stdout=git_stdout, stderr=git_stderr
                    )
                # Then, checkout (which can be optional)
                if retval == 0 and (gitcheckout_params is not None):
                    self.logger.debug(f'Running "{" ".join(gitcheckout_params)}"')
                    retval = subprocess.Popen(
                        gitcheckout_params,
                        stdout=git_stdout,
                        stderr=git_stderr,
                        cwd=repo_tag_destdir,
                    ).wait()
                # Last, submodule preparation
                if retval == 0:
                    # Last, initialize submodules
                    gitsubmodule_params = [
                        self.git_cmd,
                        "submodule",
                        "update",
                        "--init",
                        "--recursive",
                    ]

                    self.logger.debug(f'Running "{" ".join(gitsubmodule_params)}"')
                    retval = subprocess.Popen(
                        gitsubmodule_params,
                        stdout=git_stdout,
                        stderr=git_stderr,
                        cwd=repo_tag_destdir,
                    ).wait()

                # Proper error handling
                if retval != 0:
                    # Reading the output and error for the report
                    with open(git_stdout.name, "r") as c_stF:
                        git_stdout_v = c_stF.read()
                    with open(git_stderr.name, "r") as c_stF:
                        git_stderr_v = c_stF.read()

                    errstr = "ERROR: Unable to pull '{}' (tag '{}'). Retval {}\n======\nSTDOUT\n======\n{}\n======\nSTDERR\n======\n{}".format(
                        repoURL, repoTag, retval, git_stdout_v, git_stderr_v
                    )
                    raise FetcherException(errstr)

        # Last, we have to obtain the effective checkout
        gitrevparse_params = [self.git_cmd, "rev-parse", "--verify", "HEAD"]

        self.logger.debug(f'Running "{" ".join(gitrevparse_params)}"')
        with subprocess.Popen(
            gitrevparse_params,
            stdout=subprocess.PIPE,
            encoding="iso-8859-1",
            cwd=repo_tag_destdir,
        ) as revproc:
            if revproc.stdout is not None:
                repo_effective_checkout = cast(
                    "RepoTag", revproc.stdout.read().rstrip()
                )

        repo_desc: "RepoDesc" = {
            "repo": repoURL,
            "tag": repoTag,
            "checkout": repo_effective_checkout,
        }

        return (
            repo_tag_destdir,
            repo_desc,
            [],
        )

    def fetch(
        self,
        remote_file: "URIType",
        cachedFilename: "AbsPath",
        secContext: "Optional[SecurityContextConfig]" = None,
    ) -> "ProtocolFetcherReturn":
        parsedInputURL = parse.urlparse(remote_file)

        # These are the usual URIs which can be understood by pip
        # See https://pip.pypa.io/en/stable/cli/pip_install/#git
        if parsedInputURL.scheme not in self.GetSchemeHandlers():
            raise FetcherException(f"FIXME: Unhandled scheme {parsedInputURL.scheme}")

        # Getting the scheme git is going to understand
        if len(parsedInputURL.scheme) >= len(self.GIT_PROTO_PREFIX):
            gitScheme = parsedInputURL.scheme[len(self.GIT_PROTO_PREFIX) :]
        else:
            gitScheme = parsedInputURL.scheme

        # Getting the tag or branch
        repoTag: "Optional[RepoTag]"
        if "@" in parsedInputURL.path:
            gitPath, repoTag = cast(
                "Tuple[str, RepoTag]", tuple(parsedInputURL.path.split("@", 1))
            )
        else:
            gitPath = parsedInputURL.path
            repoTag = None

        # Getting the repoRelPath (if available)
        if len(parsedInputURL.fragment) > 0:
            frag_qs = parse.parse_qs(parsedInputURL.fragment)
            subDirArr = frag_qs.get("subdirectory", [])
            if len(subDirArr) > 0:
                repoRelPath = subDirArr[0]
        else:
            repoRelPath = None

        # Now, reassemble the repoURL, to be used by git client
        repoURL = cast(
            "RepoURL",
            parse.urlunparse((gitScheme, parsedInputURL.netloc, gitPath, "", "", "")),
        )

        repo_tag_destdir, repo_desc, metadata_array = self.doMaterializeRepo(
            repoURL, repoTag=repoTag
        )
        repo_desc["relpath"] = cast("RelPath", repoRelPath)

        preferredName: "Optional[RelPath]"
        if repoRelPath is not None:
            cachedContentPath = os.path.join(repo_tag_destdir, repoRelPath)
            preferredName = cast("RelPath", repoRelPath.split("/")[-1])
        else:
            cachedContentPath = repo_tag_destdir
            preferredName = None

        if os.path.isdir(cachedContentPath):
            kind = ContentKind.Directory
        elif os.path.isfile(cachedContentPath):
            kind = ContentKind.File
        else:
            raise FetcherException(
                f"Remote {remote_file} is neither a file nor a directory (does it exist?)"
            )

        # shutil.move(cachedContentPath, cachedFilename)
        link_or_copy(cast("AnyPath", cachedContentPath), cachedFilename)

        augmented_metadata_array = [
            URIWithMetadata(
                uri=remote_file, metadata=repo_desc, preferredName=preferredName
            ),
            *metadata_array,
        ]
        return ProtocolFetcherReturn(
            kind_or_resolved=kind,
            metadata_array=augmented_metadata_array,
            # TODO: Identify licences in git repositories??
            licences=None,
        )


HEAD_LABEL = b"HEAD"
REFS_HEADS_PREFIX = b"refs/heads/"
REFS_TAGS_PREFIX = b"refs/tags/"
GIT_SCHEMES = ["https", "git+https", "ssh", "git+ssh", "file", "git+file"]


def guess_git_repo_params(
    wf_url: "Union[URIType, parse.ParseResult]",
    logger: "logging.Logger",
    fail_ok: "bool" = False,
) -> "Optional[RemoteRepo]":
    """Extract the parameters for a git repo from the given URL. If an invalid URL is passed,
    this function returns `None`.
    
    The acceptable form for the URL can be found [here](https://pip.pypa.io/en/stable/topics/vcs-support/#git).

    :param wf_url: The URL to the repo.
    :param logger: A `logging.Logger` instance for debugging purposes.
    :param fail_ok: _description_, defaults to False. Deprecated, ignored.
    :return: A `RemoteRepo` instance containing parameters of the git repo or `None`
    if no repo was found.
    """
    repoURL = None
    repoTag = None
    repoRelPath = None
    repoType: "Optional[RepoType]" = RepoType.Git

    # Deciding which is the input
    if isinstance(wf_url, parse.ParseResult):
        parsed_wf_url = wf_url
    else:
        parsed_wf_url = parse.urlparse(wf_url)

    # Return None if no scheme in URL. Can't choose how to proceed
    if not parsed_wf_url.scheme:
        logger.debug(
            f"No scheme in repo URL. Choices are: {', '.join(GIT_SCHEMES)}"
        )
        return None
    
    # Return None if no scheme in URL. Can't choose how to proceed
    if not ".git" in parsed_wf_url.path:
        logger.debug(
            f"URL does not seem to point to a git repo."
        )
        return None

    # Getting the scheme git is going to understand
    git_scheme = parsed_wf_url.scheme.removeprefix("git+")

    # Getting the tag or branch
    gitPath = parsed_wf_url.path
    if "@" in parsed_wf_url.path:
        gitPath, repoTag = parsed_wf_url.path.split("@", 1)

    # Getting the repoRelPath (if available)
    if parsed_wf_url.fragment:
        frag_qs = parse.parse_qs(parsed_wf_url.fragment)
        subDirArr = frag_qs.get("subdirectory", [])
        if subDirArr:
            repoRelPath = subDirArr[0]

    # Now, reassemble the repoURL
    if git_scheme == "ssh":
        repoURL = parsed_wf_url.netloc + gitPath
    else:
        repoURL = parse.urlunparse((git_scheme, parsed_wf_url.netloc, gitPath, "", "", ""))

    logger.debug(
        "From {} was derived (type {}) {} {} {}".format(
            wf_url, repoType, repoURL, repoTag, repoRelPath
        )
    )

    return RemoteRepo(
        repo_url=cast("RepoURL", repoURL),
        tag=cast("Optional[RepoTag]", repoTag),
        rel_path=cast("Optional[RelPath]", repoRelPath),
        repo_type=repoType,
    )
