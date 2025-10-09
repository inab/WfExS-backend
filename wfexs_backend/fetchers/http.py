#!/usr/bin/env python
# -*- coding: utf-8 -*-

# SPDX-License-Identifier: Apache-2.0
# Copyright 2020-2025 Barcelona Supercomputing Center (BSC), Spain
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
import http.client
import os
import shutil
import string

from typing import (
    cast,
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
        Union,
    )

    from typing_extensions import (
        Final,
    )

    from _typeshed import SupportsRead
    from ssl import SSLContext
    from mypy_extensions import DefaultNamedArg

    from ..common import (
        AbsPath,
        PathLikePath,
        ProgsMapping,
        RelPath,
        RepoURL,
        RepoTag,
        SecurityContextConfig,
        SymbolicName,
        URIType,
    )

import urllib.error
import urllib.parse
import urllib.request

from . import (
    AbstractStatefulFetcher,
    AbstractStatefulStreamingFetcher,
    DocumentedProtocolFetcher,
    DocumentedStatefulProtocolFetcher,
    FetcherException,
    ProtocolFetcherReturn,
)

from ..common import (
    ContentKind,
    URIWithMetadata,
)

from ..utils.misc import (
    build_http_opener,
    get_opener_with_auth,
)


class HTTPFetcher(AbstractStatefulStreamingFetcher):
    PRIORITY: "ClassVar[int]" = 20
    HTTP_PROTO: "Final[str]" = "http"
    HTTPS_PROTO: "Final[str]" = "https"

    @classmethod
    def GetSchemeHandlers(cls) -> "Mapping[str, DocumentedStatefulProtocolFetcher]":
        # These are de-facto schemes supported by pip and git client
        return {
            cls.HTTP_PROTO: DocumentedStatefulProtocolFetcher(
                fetcher_class=cls,
                description="HTTP download URLs",
                priority=cls.PRIORITY,
            ),
            cls.HTTPS_PROTO: DocumentedStatefulProtocolFetcher(
                fetcher_class=cls,
                description="HTTPS download URLs",
                priority=cls.PRIORITY,
            ),
        }

    @property
    def description(self) -> "str":
        return "HTTP and HTTPS download URLs"

    @classmethod
    def GetNeededPrograms(cls) -> "Sequence[SymbolicName]":
        return tuple()

    def streamfetch(
        self,
        remote_file: "URIType",
        dest_stream: "IO[bytes]",
        secContext: "Optional[SecurityContextConfig]" = None,
        explicit_redirects: "bool" = False,
    ) -> "ProtocolFetcherReturn":
        """
        Method to fetch contents from http and https.
        This is the method to be implemented by the stateful streaming fetcher
        which can receive as destination a byte stream

        :param remote_file:
        :param dest_stream:
        :param secContext:
        """

        # This is needed to remove possible embedded credentials,
        # which should not be stored in the cache
        orig_remote_file = remote_file
        parsedInputURL, remote_file = self.ParseAndRemoveCredentials(orig_remote_file)
        # Now the credentials are properly removed from remote_file
        # we get them from the parsed url
        username = parsedInputURL.username
        password = parsedInputURL.password

        if isinstance(secContext, dict):
            headers = secContext.get("headers", {}).copy()
            token = secContext.get("token")
            token_header = secContext.get("token_header")
            username = secContext.get("username", username)
            password = secContext.get("password", password)

            method = secContext.get("method")
            data = secContext.get("data")
        else:
            headers = {}
            method = None
            data = None
            token = None
            token_header = None

        # Callable[[Union[str, Request], Union[bytes, SupportsRead[bytes], Iterable[bytes], None], Optional[float]], Any]
        # Callable[[Union[str, Request], Optional[Union[bytes, SupportsRead[bytes], Iterable[bytes], None]], Optional[float], DefaultNamedArg(Optional[str], 'cafile'), DefaultNamedArg(Optional[str], 'capath'), DefaultNamedArg(bool, 'cadefault'), DefaultNamedArg(Optional[SSLContext], 'context')], Any]
        opener: "Union[Callable[[Union[str, urllib.request.Request], Union[bytes, SupportsRead[bytes], Iterable[bytes], None], Optional[float]], Any], Callable[[Union[str, urllib.request.Request], Optional[Union[bytes, SupportsRead[bytes], Iterable[bytes]]], Optional[float], DefaultNamedArg(Optional[str], 'cafile'), DefaultNamedArg(Optional[str], 'capath'), DefaultNamedArg(bool, 'cadefault'), DefaultNamedArg(Optional[SSLContext], 'context')], Any]]"
        opener = build_http_opener(implicit_redirect=not explicit_redirects).open
        if token is not None:
            if token_header is not None:
                headers[token_header] = token
            else:
                headers["Authorization"] = f"Bearer {token}"
        elif username is not None:
            if password is None:
                password = ""

            opener = get_opener_with_auth(
                remote_file,
                username,
                password,
                implicit_redirect=not explicit_redirects,
            ).open

            # # Time to set up user and password in URL
            # parsedInputURL = urllib.parse.urlparse(remote_file)
            #
            # netloc = urllib.parse.quote(username, safe='') + ':' + urllib.parse.quote(password,
            #                                                             safe='') + '@' + parsedInputURL.hostname
            # if parsedInputURL.port is not None:
            #     netloc += ':' + str(parsedInputURL.port)
            #
            # # Now the credentials are properly set up
            # remote_file = cast("URIType", urllib.parse.urlunparse((parsedInputURL.scheme, netloc, parsedInputURL.path,
            #                                 parsedInputURL.params, parsedInputURL.query, parsedInputURL.fragment)))

        uri_with_metadata = None
        req_remote = urllib.request.Request(
            remote_file, headers=headers, data=data, method=method
        )
        try:
            with opener(req_remote) as url_response:
                uri_with_metadata = URIWithMetadata(
                    uri=url_response.url, metadata=dict(url_response.headers.items())
                )

                while True:
                    try:
                        # Try getting it
                        shutil.copyfileobj(url_response, dest_stream)
                    except http.client.IncompleteRead as icread:
                        dest_stream.write(icread.partial)
                        # Restarting the copy
                        continue
                    break

        except urllib.error.HTTPError as he:
            if he.code > 300 or he.code < 400:
                # This code is inspired on the implementation
                # of urllib.request.HTTPRedirectHandler.http_error_302
                redirect_url: "Optional[str]" = None
                if "Location" in he.headers:
                    redirect_url = he.headers["Location"]
                elif "URI" in he.headers:
                    redirect_url = he.headers["URI"]

                if redirect_url is not None:
                    # fix a possible malformed URL
                    urlparts = urllib.parse.urlparse(redirect_url)

                    # For security reasons we don't allow redirection to anything other
                    # than http, https or ftp.

                    if urlparts.scheme not in ("http", "https", "ftp", ""):
                        raise FetcherException(
                            f"Redirection from '{he.filename}' to url '{redirect_url}' is not allowed",
                        ) from he

                    if not urlparts.path and urlparts.netloc:
                        urlparts = urlparts._replace(path="/")
                    redirect_url = urllib.parse.urlunparse(urlparts)

                    # http.client.parse_headers() decodes as ISO-8859-1.  Recover the
                    # original bytes and percent-encode non-ASCII bytes, and any special
                    # characters such as the space.
                    redirect_url = urllib.parse.quote(
                        redirect_url,
                        encoding="iso-8859-1",
                        safe=string.punctuation,
                    )
                    redirect_url = urllib.parse.urljoin(
                        req_remote.full_url, redirect_url
                    )

                    uri_with_metadata = URIWithMetadata(
                        uri=cast("URIType", he.filename),
                        metadata=dict(he.headers.items()),
                    )
                    return ProtocolFetcherReturn(
                        kind_or_resolved=cast("URIType", redirect_url),
                        metadata_array=[uri_with_metadata],
                    )
            raise FetcherException(
                "Error fetching {} ({}): {} {}\n{}".format(
                    orig_remote_file,
                    he.filename,
                    he.code,
                    he.reason,
                    he.read().decode(),
                ),
                code=he.code,
                reason=he.reason,
            ) from he

        return ProtocolFetcherReturn(
            kind_or_resolved=ContentKind.File,
            metadata_array=[uri_with_metadata],
        )
