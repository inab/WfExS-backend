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

from __future__ import absolute_import

import abc
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


class AbstractRepoFetcher(AbstractStatefulFetcher):
    PRIORITY: "ClassVar[int]" = DEFAULT_PRIORITY + 10

    @abc.abstractmethod
    def doMaterializeRepo(
        self,
        repoURL: "RepoURL",
        repoTag: "Optional[RepoTag]" = None,
        repo_tag_destdir: "Optional[AbsPath]" = None,
        base_repo_destdir: "Optional[AbsPath]" = None,
        doUpdate: "Optional[bool]" = True,
    ) -> "Tuple[AbsPath, RepoDesc, Sequence[URIWithMetadata]]":
        pass


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
