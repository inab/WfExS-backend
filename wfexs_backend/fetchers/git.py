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

from . import (
    AbstractRepoFetcher,
    DocumentedStatefulProtocolFetcher,
    FetcherException,
    ProtocolFetcherReturn,
    RepoGuessException,
)

from ..common import (
    ContentKind,
    RemoteRepo,
    RepoGuessFlavor,
    RepoType,
    URIWithMetadata,
)

from ..utils.contents import link_or_copy

GITHUB_NETLOC = "github.com"


class GitFetcher(AbstractRepoFetcher):
    GIT_PROTO: "Final[str]" = "git"
    GIT_PROTO_PREFIX: "Final[str]" = GIT_PROTO + "+"
    GITHUB_SCHEME: "Final[str]" = "github"
    DEFAULT_GIT_CMD: "Final[SymbolicName]" = cast("SymbolicName", "git")

    def __init__(
        self, progs: "ProgsMapping", setup_block: "Optional[Mapping[str, Any]]" = None
    ):
        super().__init__(progs=progs, setup_block=setup_block)

        self.git_cmd = self.progs.get(
            self.DEFAULT_GIT_CMD, cast("RelPath", self.DEFAULT_GIT_CMD)
        )

    @classmethod
    def GetSchemeHandlers(cls) -> "Mapping[str, DocumentedStatefulProtocolFetcher]":
        # These are de-facto schemes supported by pip and git client
        dspf = DocumentedStatefulProtocolFetcher(
            fetcher_class=cls,
            priority=cls.PRIORITY,
        )
        return {
            cls.GIT_PROTO: dspf,
            cls.GIT_PROTO_PREFIX + "file": dspf,
            cls.GIT_PROTO_PREFIX + "https": dspf,
            cls.GIT_PROTO_PREFIX + "http": dspf,
            cls.GIT_PROTO_PREFIX + "ssh": dspf,
            cls.GITHUB_SCHEME: dspf,
        }

    @property
    def description(self) -> "str":
        return "'git' scheme and pseudo-schemes 'git+file', 'git+https', 'git+ssh' (based on https://pip.pypa.io/en/stable/topics/vcs-support/) and 'github' are managed by using git command line, applying minimal transformations in the URI."

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

        if parsedInputURL.scheme == self.GITHUB_SCHEME:
            gh_path_split = parsedInputURL.path.split("/")
            gh_path_gh = [
                gh_path_split[0],
            ]
            fragment = ""
            if len(gh_path_split) > 2:
                gh_path_gh.append(gh_path_split[1] + f".git@{gh_path_split[2]}")
                if len(gh_path_split) > 3:
                    fragment = f"subdirectory={'/'.join(gh_path_split[3:])}"
            else:
                gh_path_gh.append(gh_path_split[1] + ".git")

            redir_url = parse.urlunparse(
                parse.ParseResult(
                    scheme=self.GIT_PROTO_PREFIX + "https",
                    netloc=GITHUB_NETLOC,
                    path="/".join(gh_path_gh),
                    params="",
                    query="",
                    fragment=fragment,
                )
            )
            return ProtocolFetcherReturn(
                kind_or_resolved=cast("URIType", redir_url),
                metadata_array=[],
            )

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
GIT_SCHEMES = ["https", "git", "ssh", "file"]


def guess_git_repo_params(
    wf_url: "Union[URIType, parse.ParseResult]",
    logger: "logging.Logger",
    fail_ok: "bool" = False,
) -> "Optional[RemoteRepo]":
    repoURL = None
    repoTag = None
    repoRelPath = None
    repoType: "Optional[RepoType]" = None
    guessedRepoFlavor: "Optional[RepoGuessFlavor]" = None
    web_url: "Optional[URIType]" = None

    # Deciding which is the input
    if isinstance(wf_url, parse.ParseResult):
        parsed_wf_url = wf_url
    else:
        parsed_wf_url = parse.urlparse(wf_url)

    # These are the usual URIs which can be understood by pip
    # See https://pip.pypa.io/en/stable/cli/pip_install/#git
    found_params: "Optional[Tuple[RemoteRepo, Sequence[str], Sequence[RepoTag]]]" = None
    try:
        if parsed_wf_url.scheme == GitFetcher.GITHUB_SCHEME:
            repoType = RepoType.Git
            guessedRepoFlavor = RepoGuessFlavor.GitHub

            gh_path_split = parsed_wf_url.path.split("/")
            gh_path = "/".join(gh_path_split[:2])
            gh_post_path = list(map(parse.unquote_plus, gh_path_split[2:]))
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
            found_params = find_git_repo_in_uri(cast("URIType", repoURL))

        elif (
            parsed_wf_url.scheme in ("http", "https")
            and parsed_wf_url.netloc == GITHUB_NETLOC
            and "@" not in parsed_wf_url.path
            and parsed_wf_url.fragment == ""
        ):
            found_params = find_git_repo_in_uri(parsed_wf_url)
            repoURL = found_params[0].repo_url
            repoType = RepoType.Git
            guessedRepoFlavor = RepoGuessFlavor.GitHub

            # And now, guessing the tag and the relative path
            # WARNING! This code can have problems with tags which contain slashes
            wf_path = found_params[1]
            repo_branches_tags = found_params[2]
            if len(wf_path) > 1 and (wf_path[0] in ("blob", "tree")):
                wf_path_tag = list(map(parse.unquote_plus, wf_path[1:]))

                tag_relpath = "/".join(wf_path_tag)
                for repo_branch_tag in repo_branches_tags:
                    if repo_branch_tag == tag_relpath or tag_relpath.startswith(
                        repo_branch_tag + "/"
                    ):
                        repoTag = repo_branch_tag
                        if len(tag_relpath) > len(repo_branch_tag):
                            tag_relpath = tag_relpath[len(repo_branch_tag) + 1 :]
                            if len(tag_relpath) > 0:
                                repoRelPath = tag_relpath
                        break
                else:
                    # Fallback
                    repoTag = wf_path_tag[0]
                    if len(wf_path_tag) > 0:
                        repoRelPath = "/".join(wf_path_tag[1:])
        elif (
            parsed_wf_url.scheme in ("http", "https")
            and parsed_wf_url.netloc == "raw.githubusercontent.com"
        ):
            repoType = RepoType.Git
            guessedRepoFlavor = RepoGuessFlavor.GitHub
            wf_path = list(map(parse.unquote_plus, parsed_wf_url.path.split("/")))
            if len(wf_path) >= 3:
                # Rebuilding it
                repoGitPath = wf_path[:3]
                repoGitPath[-1] += ".git"

                # Rebuilding repo git path
                repoURL = parse.urlunparse(
                    ("https", GITHUB_NETLOC, "/".join(repoGitPath), "", "", "")
                )

                # And now, guessing the tag/checkout and the relative path
                # WARNING! This code can have problems with tags which contain slashes
                found_params = find_git_repo_in_uri(cast("URIType", repoURL))
                if len(wf_path) >= 4:
                    repo_branches_tags = found_params[2]
                    # Validate against existing branch and tag names
                    tag_relpath = "/".join(wf_path[3:])
                    for repo_branch_tag in repo_branches_tags:
                        if repo_branch_tag == tag_relpath or tag_relpath.startswith(
                            repo_branch_tag + "/"
                        ):
                            repoTag = repo_branch_tag
                            if len(tag_relpath) > len(repo_branch_tag):
                                tag_relpath = tag_relpath[len(repo_branch_tag) + 1 :]
                                if len(tag_relpath) > 0:
                                    repoRelPath = tag_relpath
                            break
                    else:
                        # Fallback
                        repoTag = wf_path[3]
                        if len(wf_path) > 4:
                            repoRelPath = "/".join(wf_path[4:])
        elif (
            parsed_wf_url.scheme == ""
            or (parsed_wf_url.scheme in GitFetcher.GetSchemeHandlers())
            or (parsed_wf_url.scheme in GIT_SCHEMES)
        ):
            if parsed_wf_url.scheme == "":
                # It could be a checkout uri in the form of 'git@github.com:inab/WfExS-backend.git'
                if (
                    parsed_wf_url.netloc == ""
                    and ("@" in parsed_wf_url.path)
                    and (":" in parsed_wf_url.path)
                ):
                    gitScheme = "ssh"
                    parsed_wf_url = parse.urlparse(
                        f"{gitScheme}://"
                        + parse.urlunparse(parsed_wf_url).replace(":", "/")
                    )
                else:
                    logger.debug(
                        f"No scheme in repo URL. Choices are: {', '.join(GIT_SCHEMES)}"
                    )
                    return None
            # Getting the scheme git is going to understand
            elif parsed_wf_url.scheme.startswith(GitFetcher.GIT_PROTO_PREFIX):
                gitScheme = parsed_wf_url.scheme[len(GitFetcher.GIT_PROTO_PREFIX) :]
                denorm_parsed_wf_url = parsed_wf_url._replace(scheme=gitScheme)
                parsed_wf_url = parse.urlparse(parse.urlunparse(denorm_parsed_wf_url))
            else:
                gitScheme = parsed_wf_url.scheme

            if gitScheme not in GIT_SCHEMES:
                logger.debug(
                    f"Unknown scheme {gitScheme} in repo URL. Choices are: {', '.join(GIT_SCHEMES)}"
                )
                return None

            # Beware ssh protocol!!!! I has a corner case with URLs like
            # ssh://git@github.com:inab/WfExS-backend.git'
            if parsed_wf_url.scheme == "ssh" and ":" in parsed_wf_url.netloc:
                new_netloc = parsed_wf_url.netloc
                # Translating it to something better
                colon_pos = new_netloc.rfind(":")
                new_netloc = new_netloc[:colon_pos] + "/" + new_netloc[colon_pos + 1 :]
                denorm_parsed_wf_url = parsed_wf_url._replace(netloc=new_netloc)
                parsed_wf_url = parse.urlparse(parse.urlunparse(denorm_parsed_wf_url))

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
            found_params = find_git_repo_in_uri(cast("URIType", repoURL))
            guessedRepoFlavor = found_params[0].guess_flavor
        # TODO handling other popular cases, like bitbucket
        else:
            found_params = find_git_repo_in_uri(parsed_wf_url)

    except RepoGuessException as gge:
        if not fail_ok:
            import traceback

            traceback.print_exc()
            raise FetcherException(
                f"FIXME: Unsupported http(s) git repository {wf_url} (see cascade exception)"
            ) from gge

    if found_params is not None:
        if repoTag is None:
            repoTag = found_params[0].tag
        repoType = found_params[0].repo_type
        if guessedRepoFlavor is None:
            guessedRepoFlavor = found_params[0].guess_flavor
    elif not fail_ok:
        raise FetcherException(
            f"FIXME: Unsupported git repository {wf_url}. (Is it really a git repo???)"
        )

    logger.debug(
        "From {} was derived (type {}, flavor {}) {} {} {}".format(
            wf_url, repoType, guessedRepoFlavor, repoURL, repoTag, repoRelPath
        )
    )

    if repoURL is None:
        return None

    #    if repoType == RepoType.GitHub:
    #        wf_entrypoint_path = [
    #
    #        ]
    #        web_url = urllib.parse.urlunparse(
    #            (
    #                "https",
    #                "raw.githubusercontent.com",
    #                "/".join(wf_entrypoint_path),
    #                "",
    #                "",
    #                "",
    #            )
    #        )

    return RemoteRepo(
        repo_url=cast("RepoURL", repoURL),
        tag=cast("Optional[RepoTag]", repoTag),
        rel_path=cast("Optional[RelPath]", repoRelPath),
        repo_type=repoType,
        guess_flavor=guessedRepoFlavor,
        web_url=web_url,
    )


def find_git_repo_in_uri(
    remote_file: "Union[URIType, parse.ParseResult]",
) -> "Tuple[RemoteRepo, Sequence[str], Sequence[RepoTag]]":
    if isinstance(remote_file, parse.ParseResult):
        parsedInputURL = remote_file
    else:
        parsedInputURL = parse.urlparse(remote_file)
    sp_path = parsedInputURL.path.split("/")

    shortest_pre_path: "Optional[URIType]" = None
    longest_post_path: "Optional[Sequence[str]]" = None
    repo_type: "Optional[RepoType]" = None
    guessed_repo_flavor: "Optional[RepoGuessFlavor]" = None
    the_remote_uri: "Optional[str]" = None
    b_default_repo_tag: "Optional[str]" = None
    repo_branches: "Optional[MutableSequence[RepoTag]]" = None
    for pos in range(len(sp_path), 0, -1):
        pre_path = "/".join(sp_path[:pos])
        if pre_path == "":
            pre_path = "/"
        remote_uri_anc = parse.urlunparse(parsedInputURL._replace(path=pre_path))

        remote_refs_dict: "Mapping[bytes, bytes]"
        try:
            # Dulwich works both with file, ssh, git and http(s) protocols
            remote_refs_dict = dulwich.porcelain.ls_remote(remote_uri_anc)
            repo_type = RepoType.Git
        except (
            dulwich.errors.NotGitRepository,
            dulwich.errors.GitProtocolError,
        ) as ngr:
            # Skip and continue
            continue

        the_remote_uri = remote_uri_anc

        head_remote_ref = remote_refs_dict[HEAD_LABEL]
        repo_branches = []
        b_default_repo_tag = None
        for remote_label, remote_ref in remote_refs_dict.items():
            if remote_label.startswith(REFS_HEADS_PREFIX):
                b_repo_tag = remote_label[len(REFS_HEADS_PREFIX) :].decode(
                    "utf-8", errors="continue"
                )
                repo_branches.append(cast("RepoTag", b_repo_tag))
                if b_default_repo_tag is None and remote_ref == head_remote_ref:
                    b_default_repo_tag = b_repo_tag

        # It is considered a git repo!
        shortest_pre_path = cast("URIType", pre_path)
        longest_post_path = sp_path[pos:]
        if repo_type is None:
            # Metadata is all we really need
            repo_type = RepoType.Raw
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
                        repo_type = RepoType.Git
                        guessed_repo_flavor = RepoGuessFlavor.GitLab
                    elif list(
                        filter(
                            lambda c: GITHUB_NETLOC in c,
                            resp.headers.get_all("Set-Cookie"),
                        )
                    ):
                        repo_type = RepoType.Git
                        guessed_repo_flavor = RepoGuessFlavor.GitHub
                    elif list(
                        filter(
                            lambda c: "bitbucket" in c,
                            resp.headers.get_all("X-View-Name"),
                        )
                    ):
                        repo_type = RepoType.Git
                        guessed_repo_flavor = RepoGuessFlavor.BitBucket
            except Exception as e:
                pass

    if repo_type is None:
        raise RepoGuessException(f"Unable to identify {remote_file} as a git repo")

    if b_default_repo_tag is None:
        raise RepoGuessException(
            f"No tag was obtained while getting default branch name from {remote_file}"
        )

    assert longest_post_path is not None
    assert repo_branches is not None

    repo = RemoteRepo(
        repo_url=cast("RepoURL", the_remote_uri),
        tag=cast("RepoTag", b_default_repo_tag),
        repo_type=repo_type,
        guess_flavor=guessed_repo_flavor,
    )
    return repo, longest_post_path, repo_branches
