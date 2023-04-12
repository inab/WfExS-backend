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
        Optional,
        Tuple,
        Type,
        Union,
        Sequence,
    )

    from typing_extensions import Final

    from ..common import (
        AbsPath,
        AnyPath,
        ProgsMapping,
        ProtocolFetcherReturn,
        RelPath,
        RepoTag,
        RepoURL,
        SecurityContextConfig,
        SymbolicName,
        URIType,
    )


from urllib import parse, request

import dulwich.porcelain

from . import AbstractStatefulFetcher, FetcherException

from ..common import (
    ContentKind,
    RemoteRepo,
    RepoType,
    URIWithMetadata,
)

from ..utils.contents import link_or_copy

GITHUB_SCHEME = "github"
GITHUB_NETLOC = "github.com"


class GitGuessException(FetcherException):
    pass


class GitFetcher(AbstractStatefulFetcher):
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
    ) -> "Tuple[AbsPath, RepoTag, MutableMapping[str, Union[RepoURL, Optional[RepoTag], RelPath, AbsPath]]]":
        """

        :param repoURL:
        :param repoTag:
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

        metadata: "MutableMapping[str, Union[RepoURL, Optional[RepoTag], RelPath, AbsPath]]" = {
            "repo": repoURL,
            "tag": repoTag,
            "checkout": repo_effective_checkout,
        }

        return repo_tag_destdir, repo_effective_checkout, metadata

    def find_repo_in_uri(
        self, remote_file: "URIType"
    ) -> "Tuple[Optional[RepoType], Optional[URIType], Optional[Sequence[str]]]":
        """
        This method helps identifying the repo root and repo type from an URL
        """

        parsedInputURL = parse.urlparse(remote_file)
        sp_path = parsedInputURL.path.split("/")

        shortest_pre_path: "Optional[URIType]" = None
        longest_post_path: "Optional[Sequence[str]]" = None
        repo_type: "Optional[RepoType]" = None
        for pos in range(len(sp_path), 0, -1):
            pre_path = "/".join(sp_path[:pos])
            if pre_path == "":
                pre_path = "/"
            remote_uri_anc = parse.urlunparse(parsedInputURL._replace(path=pre_path))

            git_lsremote_params = [self.git_cmd, "ls-remote", remote_uri_anc]

            retval = subprocess.call(
                git_lsremote_params,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )

            # It is considered a git repo!
            if retval == 0:
                shortest_pre_path = cast("URIType", pre_path)
                longest_post_path = sp_path[pos:]
                if repo_type is None:
                    # Metadata is all we really need
                    req = request.Request(remote_uri_anc, method="HEAD")
                    try:
                        with request.urlopen(req) as resp:
                            # Is it gitlab?
                            if list(
                                filter(
                                    lambda c: "gitlab" in c,
                                    resp.headers.get_all("Set-Cookie"),
                                )
                            ):
                                repo_type = RepoType.GitLab
                            elif list(
                                filter(
                                    lambda c: GITHUB_NETLOC in c,
                                    resp.headers.get_all("Set-Cookie"),
                                )
                            ):
                                repo_type = RepoType.GitHub
                            elif list(
                                filter(
                                    lambda c: "bitbucket" in c,
                                    resp.headers.get_all("X-View-Name"),
                                )
                            ):
                                repo_type = RepoType.BitBucket
                            else:
                                repo_type = RepoType.Other
                    except Exception as e:
                        pass

        return repo_type, shortest_pre_path, longest_post_path

    def fetch(
        self,
        remote_file: "URIType",
        cachedFilename: "AbsPath",
        secContext: "Optional[SecurityContextConfig]" = None,
    ) -> "ProtocolFetcherReturn":
        parsedInputURL = parse.urlparse(remote_file)

        # These are the usual URIs which can be understood by pip
        # See https://pip.pypa.io/en/stable/cli/pip_install/#git
        if (
            not parsedInputURL.scheme.startswith(self.GIT_PROTO_PREFIX)
            and parsedInputURL.scheme != self.GIT_PROTO
        ):
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

        repo_tag_destdir, repo_effective_checkout, metadata = self.doMaterializeRepo(
            repoURL, repoTag=repoTag
        )
        metadata["relpath"] = cast("RelPath", repoRelPath)

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

        return (
            kind,
            [
                URIWithMetadata(
                    uri=remote_file, metadata=metadata, preferredName=preferredName
                )
            ],
            None,
        )


HEAD_LABEL = b"HEAD"
REFS_HEADS_PREFIX = b"refs/heads/"


def get_git_default_branch(
    repoURL: "str", git_cmd: "str" = GitFetcher.DEFAULT_GIT_CMD
) -> "RepoTag":
    remote_refs_dict: "Mapping[bytes, bytes]"
    remote_refs_dict = dulwich.porcelain.ls_remote(repoURL)
    head_remote_ref = remote_refs_dict[HEAD_LABEL]
    b_default_repo_tag: "Optional[str]" = None
    for remote_label, remote_ref in remote_refs_dict.items():
        if remote_ref == head_remote_ref and remote_label.startswith(REFS_HEADS_PREFIX):
            b_default_repo_tag = remote_label[len(REFS_HEADS_PREFIX) :].decode(
                "utf-8", errors="continue"
            )
            break

    # b_default_repo_tag: "Optional[Any]"
    # with tempfile.NamedTemporaryFile() as db_err, subprocess.Popen(
    #    [git_cmd,'ls-remote','--symref',repoURL,'HEAD'],
    #    stdout=subprocess.PIPE,
    #    stderr=db_err
    # ) as db_sp:
    #    if db_sp.stdout is not None:
    #        b_default_repo_tag = db_sp.stdout.read()
    #    db_retval = db_sp.wait()
    #
    #    if db_retval != 0:
    #        with open(db_err.name, "r") as errH:
    #            db_err_v = errH.read()
    #
    #        raise GitGuessException(f"Exit val {db_retval} while getting default branch name from {repoURL}: {db_err_v}")

    if b_default_repo_tag is None:
        raise GitGuessException(
            f"No tag was obtained while getting default branch name from {repoURL}"
        )

    return cast("RepoTag", b_default_repo_tag)


def guess_repo_params(
    wf_url: "Union[URIType, parse.ParseResult]",
    logger: "logging.Logger",
    fail_ok: "bool" = False,
) -> "Optional[RemoteRepo]":
    repoURL = None
    repoTag = None
    repoRelPath = None
    repoType: "Optional[RepoType]" = None

    # Deciding which is the input
    if isinstance(wf_url, parse.ParseResult):
        parsed_wf_url = wf_url
    else:
        parsed_wf_url = parse.urlparse(wf_url)

    # These are the usual URIs which can be understood by pip
    # See https://pip.pypa.io/en/stable/cli/pip_install/#git
    if (
        parsed_wf_url.scheme.startswith(GitFetcher.GIT_PROTO_PREFIX)
        or parsed_wf_url.scheme == GitFetcher.GIT_PROTO
    ):
        # Getting the scheme git is going to understand
        if len(parsed_wf_url.scheme) >= len(GitFetcher.GIT_PROTO_PREFIX):
            gitScheme = parsed_wf_url.scheme[len(GitFetcher.GIT_PROTO_PREFIX) :]
        else:
            gitScheme = parsed_wf_url.scheme

        # Getting the tag or branch
        if "@" in parsed_wf_url.path:
            gitPath, repoTag = parsed_wf_url.path.split("@", 1)
        else:
            gitPath = parsed_wf_url.path

        # Getting the repoRelPath (if available)
        if len(parsed_wf_url.fragment) > 0:
            frag_qs = parse.parse_qs(parsed_wf_url.fragment)
            subDirArr = frag_qs.get("subdirectory", [])
            if len(subDirArr) > 0:
                repoRelPath = subDirArr[0]

        # Now, reassemble the repoURL
        repoURL = parse.urlunparse(
            (gitScheme, parsed_wf_url.netloc, gitPath, "", "", "")
        )
        if repoTag is None:
            repoTag = get_git_default_branch(repoURL)
        repoType = RepoType.Raw

    elif parsed_wf_url.scheme == GITHUB_SCHEME:
        repoType = RepoType.GitHub

        gh_path_split = parsed_wf_url.path.split("/")
        gh_path = "/".join(gh_path_split[:2])
        gh_post_path = gh_path_split[2:]
        if len(gh_post_path) > 0:
            repoTag = gh_post_path[0]
            if len(gh_post_path) > 1:
                repoRelPath = "/".join(gh_post_path[1:])

        repoURL = parse.urlunparse(
            parse.ParseResult(
                scheme="https",
                netloc=GITHUB_NETLOC,
                path=gh_path,
                params="",
                query="",
                fragment="",
            )
        )
        if repoTag is None:
            repoTag = get_git_default_branch(repoURL)

    # TODO handling other popular cases, like bitbucket
    elif parsed_wf_url.netloc == GITHUB_NETLOC:
        wf_path = parsed_wf_url.path.split("/")

        if len(wf_path) >= 3:
            repoGitPath = wf_path[:3]
            if not repoGitPath[-1].endswith(".git"):
                repoGitPath[-1] += ".git"

            # Rebuilding repo git path
            repoURL = parse.urlunparse(
                (
                    parsed_wf_url.scheme,
                    parsed_wf_url.netloc,
                    "/".join(repoGitPath),
                    "",
                    "",
                    "",
                )
            )

            # And now, guessing the tag and the relative path
            if len(wf_path) >= 5 and (wf_path[3] in ("blob", "tree")):
                repoTag = wf_path[4]

                if len(wf_path) >= 6:
                    repoRelPath = "/".join(wf_path[5:])
            else:
                repoTag = get_git_default_branch(repoURL)
        repoType = RepoType.GitHub
    elif parsed_wf_url.netloc == "raw.githubusercontent.com":
        wf_path = parsed_wf_url.path.split("/")
        if len(wf_path) >= 3:
            # Rebuilding it
            repoGitPath = wf_path[:3]
            repoGitPath[-1] += ".git"

            # Rebuilding repo git path
            repoURL = parse.urlunparse(
                ("https", GITHUB_NETLOC, "/".join(repoGitPath), "", "", "")
            )

            # And now, guessing the tag/checkout and the relative path
            if len(wf_path) >= 4:
                repoTag = wf_path[3]

                if len(wf_path) >= 5:
                    repoRelPath = "/".join(wf_path[4:])
            else:
                repoTag = get_git_default_branch(repoURL)
        repoType = RepoType.GitHub
    elif not fail_ok:
        raise FetcherException(
            "FIXME: Unsupported http(s) git repository {}".format(wf_url)
        )

    logger.debug(
        "From {} was derived {} {} {}".format(wf_url, repoURL, repoTag, repoRelPath)
    )

    if repoURL is None:
        return None

    return RemoteRepo(
        repo_url=cast("RepoURL", repoURL),
        tag=cast("Optional[RepoTag]", repoTag),
        rel_path=cast("Optional[RelPath]", repoRelPath),
        repo_type=repoType,
    )


# See above
SCHEME_HANDLERS: "Mapping[str, Type[AbstractStatefulFetcher]]" = (
    GitFetcher.GetSchemeHandlers()
)
