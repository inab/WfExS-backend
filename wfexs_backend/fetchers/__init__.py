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

from __future__ import absolute_import

import abc
import enum
import logging

from typing import (
    cast,
    NamedTuple,
    TYPE_CHECKING,
)

if TYPE_CHECKING:
    from typing import (
        Any,
        Callable,
        ClassVar,
        Iterable,
        IO,
        Mapping,
        MutableMapping,
        MutableSequence,
        Optional,
        Sequence,
        Tuple,
        Type,
        TypeVar,
        Union,
    )

    from typing_extensions import (
        Final,
        NotRequired,
        Required,
        TypeAlias,
        TypedDict,
    )

    from ..common import (
        AbsPath,
        AnyURI,
        ContentKind,
        ProgsMapping,
        RelPath,
        RepoURL,
        RepoTag,
        SecurityContextConfig,
        SymbolicName,
        URIType,
        URIWithMetadata,
    )

    class RepoDesc(TypedDict):
        repo: Required[RepoURL]
        tag: Required[Optional[RepoTag]]
        checkout: Required[RepoTag]
        relpath: NotRequired[RelPath]
        repotype: NotRequired[str]


class ProtocolFetcherReturn(NamedTuple):
    kind_or_resolved: "Union[AnyURI, ContentKind, Sequence[AnyURI]]"
    metadata_array: "Sequence[URIWithMetadata]"
    licences: "Optional[Tuple[URIType, ...]]" = None


if TYPE_CHECKING:
    from mypy_extensions import DefaultNamedArg

    ProtocolFetcher: TypeAlias = Callable[
        [
            URIType,
            AbsPath,
            DefaultNamedArg(Optional[SecurityContextConfig], "secContext"),
        ],
        ProtocolFetcherReturn,
    ]

from urllib import parse

from ..common import (
    AbstractWfExSException,
)


# Default priority
DEFAULT_PRIORITY: "Final[int]" = 0


class DocumentedProtocolFetcher(NamedTuple):
    fetcher: "ProtocolFetcher"
    description: "str"
    priority: "int" = DEFAULT_PRIORITY


class DocumentedStatefulProtocolFetcher(NamedTuple):
    fetcher_class: "Type[AbstractStatefulFetcher]"
    description: "Optional[str]" = None
    priority: "int" = DEFAULT_PRIORITY


class FetcherException(AbstractWfExSException):
    code: "Optional[Union[str, int]]"
    reason: "Optional[str]"

    def __init__(
        self,
        msg: "str",
        code: "Optional[Union[str, int]]" = None,
        reason: "Optional[str]" = None,
    ):
        super().__init__(msg)
        self.code = code
        self.reason = reason


class InvalidFetcherException(FetcherException):
    pass


class FetcherInstanceException(FetcherException):
    pass


class AbstractStatefulFetcher(abc.ABC):
    """
    Abstract class to model stateful fetchers
    """

    # Default priority
    PRIORITY: "ClassVar[int]" = DEFAULT_PRIORITY

    # Is this implementation enabled?
    ENABLED: "ClassVar[bool]" = True

    def __init__(
        self,
        progs: "ProgsMapping" = dict(),
        setup_block: "Optional[Mapping[str, Any]]" = None,
    ):
        import inspect

        self.logger = logging.getLogger(
            dict(inspect.getmembers(self))["__module__"]
            + "::"
            + self.__class__.__name__
        )
        # This is used to resolve program names
        self.progs = progs
        self.setup_block = setup_block if isinstance(setup_block, dict) else dict()

    @abc.abstractmethod
    def fetch(
        self,
        remote_file: "URIType",
        cachedFilename: "AbsPath",
        secContext: "Optional[SecurityContextConfig]" = None,
    ) -> "ProtocolFetcherReturn":
        """
        This is the method to be implemented by the stateful fetcher
        """
        pass

    @property
    @abc.abstractmethod
    def description(self) -> "str":
        """
        Description of this URI handler
        """
        pass

    @classmethod
    @abc.abstractmethod
    def GetSchemeHandlers(cls) -> "Mapping[str, DocumentedStatefulProtocolFetcher]":
        return dict()

    @classmethod
    @abc.abstractmethod
    def GetNeededPrograms(cls) -> "Sequence[SymbolicName]":
        return tuple()

    @staticmethod
    def ParseAndRemoveCredentials(
        remote_file: "URIType",
    ) -> "Tuple[parse.ParseResult, URIType]":
        parsedInputURL = parse.urlparse(remote_file)
        if parsedInputURL.username is not None:
            assert parsedInputURL.hostname is not None
            netloc = parsedInputURL.hostname
            if parsedInputURL.port is not None:
                netloc += ":" + str(parsedInputURL.port)
            # Now the credentials are properly removed
            remote_file = cast(
                "URIType",
                parse.urlunparse(
                    (
                        parsedInputURL.scheme,
                        netloc,
                        parsedInputURL.path,
                        parsedInputURL.params,
                        parsedInputURL.query,
                        parsedInputURL.fragment,
                    )
                ),
            )

        return parsedInputURL, remote_file


if TYPE_CHECKING:
    StatefulFetcher = TypeVar("StatefulFetcher", bound=AbstractStatefulFetcher)


class RepoGuessException(FetcherException):
    pass


class RepoType(enum.Enum):
    Git = "git"
    Raw = "raw"
    Other = "other"
    SoftwareHeritage = "swh"
    TRS = "trs"

    @classmethod
    def _undeprecate_table(cls) -> "Mapping[str, str]":
        # These fixes are needed to map deprecated values
        # to the most approximate ones
        return {
            "github": "git",
            "gitlab": "git",
            "bitbucket": "git",
        }


class RepoGuessFlavor(enum.Enum):
    GitHub = "github"
    GitLab = "gitlab"
    BitBucket = "bitbucket"


class RemoteRepo(NamedTuple):
    """
    Remote repository description
    """

    repo_url: "RepoURL"
    tag: "Optional[RepoTag]" = None
    rel_path: "Optional[RelPath]" = None
    repo_type: "Optional[RepoType]" = None
    web_url: "Optional[URIType]" = None
    guess_flavor: "Optional[RepoGuessFlavor]" = None
    checkout: "Optional[RepoTag]" = None

    def gen_repo_desc(self) -> "Optional[RepoDesc]":
        retval: "RepoDesc" = {
            "repo": self.repo_url,
            "tag": self.tag,
            "checkout": self.get_checkout(),
        }

        if self.repo_type is not None:
            retval["repotype"] = self.repo_type.value

        return retval

    def get_checkout(self) -> "RepoTag":
        return (
            self.checkout
            if self.checkout is not None
            else self.tag
            if self.tag is not None
            else cast("RepoTag", "")
        )


class AbstractRepoFetcher(AbstractStatefulFetcher):
    PRIORITY: "ClassVar[int]" = DEFAULT_PRIORITY + 10

    @abc.abstractmethod
    def materialize_repo(
        self,
        repoURL: "RepoURL",
        repoTag: "Optional[RepoTag]" = None,
        repo_tag_destdir: "Optional[AbsPath]" = None,
        base_repo_destdir: "Optional[AbsPath]" = None,
        doUpdate: "Optional[bool]" = True,
    ) -> "Tuple[AbsPath, RemoteRepo, Sequence[URIWithMetadata]]":
        pass

    @abc.abstractmethod
    def build_pid_from_repo(self, remote_repo: "RemoteRepo") -> "Optional[str]":
        """
        This method is required to generate a PID which usually
        represents an element (usually a workflow) in a repository.
        If the fetcher does not recognize the type of repo, it should
        return None
        """
        pass

    @classmethod
    @abc.abstractmethod
    def GuessRepoParams(
        cls,
        orig_wf_url: "Union[URIType, parse.ParseResult]",
        logger: "Optional[logging.Logger]" = None,
        fail_ok: "bool" = False,
    ) -> "Optional[RemoteRepo]":
        pass


if TYPE_CHECKING:
    RepoFetcher = TypeVar("RepoFetcher", bound=AbstractRepoFetcher)


class AbstractStatefulStreamingFetcher(AbstractStatefulFetcher):
    def fetch(
        self,
        remote_file: "URIType",
        cachedFilename: "AbsPath",
        secContext: "Optional[SecurityContextConfig]" = None,
    ) -> "ProtocolFetcherReturn":
        with open(cachedFilename, mode="wb") as dS:
            return self.streamfetch(remote_file, dS, secContext=secContext)

    @abc.abstractmethod
    def streamfetch(
        self,
        remote_file: "URIType",
        dest_stream: "IO[bytes]",
        secContext: "Optional[SecurityContextConfig]" = None,
    ) -> "ProtocolFetcherReturn":
        """
        This is the method to be implemented by the stateful streaming fetcher
        which can receive as destination either a file
        """
        pass
