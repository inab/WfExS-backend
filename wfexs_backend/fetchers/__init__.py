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

from __future__ import absolute_import

import abc
import logging
import os

from typing import (
    cast,
    TYPE_CHECKING,
)

if TYPE_CHECKING:
    from typing import (
        Any,
        Callable,
        Iterable,
        IO,
        Mapping,
        MutableMapping,
        MutableSequence,
        Optional,
        Sequence,
        Tuple,
        Type,
        Union,
    )

    from typing_extensions import (
        NotRequired,
        Required,
        TypedDict,
    )

    from ..common import (
        AbsPath,
        ProgsMapping,
        ProtocolFetcher,
        ProtocolFetcherReturn,
        RelPath,
        RepoURL,
        RepoTag,
        SecurityContextConfig,
        SymbolicName,
        URIType,
    )

    class RepoDesc(TypedDict):
        repo: Required[RepoURL]
        tag: Required[Optional[RepoTag]]
        checkout: Required[RepoTag]
        relpath: NotRequired[RelPath]


from urllib import parse

from ..common import (
    AbstractWfExSException,
    ContentKind,
    URIWithMetadata,
)

from ..utils.contents import link_or_copy


class FetcherException(AbstractWfExSException):
    pass


class InvalidFetcherException(FetcherException):
    pass


class FetcherInstanceException(FetcherException):
    pass


class AbstractStatefulFetcher(abc.ABC):
    """
    Abstract class to model stateful fetchers
    """

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

    @classmethod
    @abc.abstractmethod
    def GetSchemeHandlers(cls) -> "Mapping[str, Type[AbstractStatefulFetcher]]":
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


class AbstractRepoFetcher(AbstractStatefulFetcher):
    @abc.abstractmethod
    def doMaterializeRepo(
        self,
        repoURL: "RepoURL",
        repoTag: "Optional[RepoTag]" = None,
        repo_tag_destdir: "Optional[AbsPath]" = None,
        base_repo_destdir: "Optional[AbsPath]" = None,
        doUpdate: "Optional[bool]" = True,
    ) -> "Tuple[AbsPath, RepoTag, RepoDesc]":
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


def fetchFile(
    remote_file: "URIType",
    cachedFilename: "AbsPath",
    secContext: "Optional[SecurityContextConfig]" = None,
) -> "ProtocolFetcherReturn":
    """
    Method to fetch contents from local contents, optionally impersonating
    the original CURIE (useful for cache exports)

    :param remote_file:
    :param cachedFilename: Destination filename for the fetched content
    :param secContext: The security context containing the credentials
    """

    parsedInputURL = parse.urlparse(remote_file)
    localPath = cast("AbsPath", parsedInputURL.path)
    if not os.path.exists(localPath):
        raise FetcherException("Local path {} is not available".format(localPath))

    kind = None
    if os.path.isdir(localPath):
        kind = ContentKind.Directory
    elif os.path.isfile(localPath):
        kind = ContentKind.File
    else:
        raise FetcherException(
            "Local path {} is neither a file nor a directory".format(localPath)
        )
    # Efficient linking of data
    force_copy = parsedInputURL.fragment == "copy"
    metadata = {}
    the_remote_file = remote_file
    # Only impersonate under very specific conditions
    if parsedInputURL.query:
        qP = parse.parse_qs(parsedInputURL.query)
        new_remote_file = qP.get("inject_as")
        if new_remote_file:
            nP = parse.urlparse(new_remote_file[0])
            if nP.scheme:
                the_remote_file = cast("URIType", new_remote_file[0])
                force_copy = True
                metadata["injected"] = True
                metadata["impersonated"] = True
    link_or_copy(localPath, cachedFilename, force_copy=force_copy)

    return kind, [URIWithMetadata(the_remote_file, metadata)], None


DEFAULT_SCHEME_HANDLERS: "Mapping[str, ProtocolFetcher]" = {
    "file": fetchFile,
}
