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
import http.client

import shutil

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

    from _typeshed import SupportsRead
    from ssl import SSLContext
    from mypy_extensions import DefaultNamedArg

    from ..common import (
        AbsPath,
        ProgsMapping,
        ProtocolFetcher,
        RelPath,
        RepoURL,
        RepoTag,
        SecurityContextConfig,
        SymbolicName,
        URIType,
    )

from urllib import request, parse
import urllib.error

from . import (
    AbstractStatefulFetcher,
    FetcherException,
)

from ..common import (
    ContentKind,
    ProtocolFetcherReturn,
    URIWithMetadata,
)


def get_opener_with_auth(
    top_level_url: "str", username: "str", password: "str"
) -> "request.OpenerDirector":
    """
    Taken from https://stackoverflow.com/a/44239906
    """

    # create a password manager
    password_mgr = request.HTTPPasswordMgrWithPriorAuth()

    # Add the username and password.
    # If we knew the realm, we could use it instead of None.
    password_mgr.add_password(
        None, top_level_url, username, password, is_authenticated=True
    )

    handler = request.HTTPBasicAuthHandler(password_mgr)

    # create "opener" (OpenerDirector instance)
    return request.build_opener(handler)


def fetchClassicURL(
    remote_file: "URIType",
    cachedFilename: "Union[AbsPath, IO[bytes]]",
    secContext: "Optional[SecurityContextConfig]" = None,
) -> "ProtocolFetcherReturn":
    """
    Method to fetch contents from http, https and ftp

    :param remote_file:
    :param cachedFilename:
    :param secContext:
    """

    # This is needed to remove possible embedded credentials,
    # which should not be stored in the cache
    orig_remote_file = remote_file
    parsedInputURL, remote_file = AbstractStatefulFetcher.ParseAndRemoveCredentials(
        orig_remote_file
    )
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
    opener: "Union[Callable[[Union[str, request.Request], Union[bytes, SupportsRead[bytes], Iterable[bytes], None], Optional[float]], Any], Callable[[Union[str, request.Request], Optional[Union[bytes, SupportsRead[bytes], Iterable[bytes]]], Optional[float], DefaultNamedArg(Optional[str], 'cafile'), DefaultNamedArg(Optional[str], 'capath'), DefaultNamedArg(bool, 'cadefault'), DefaultNamedArg(Optional[SSLContext], 'context')], Any]]"
    opener = request.urlopen
    if token is not None:
        if token_header is not None:
            headers[token_header] = token
        else:
            headers["Authorization"] = f"Bearer {token}"
    elif username is not None:
        if password is None:
            password = ""

        opener = get_opener_with_auth(remote_file, username, password).open

        # # Time to set up user and password in URL
        # parsedInputURL = parse.urlparse(remote_file)
        #
        # netloc = parse.quote(username, safe='') + ':' + parse.quote(password,
        #                                                             safe='') + '@' + parsedInputURL.hostname
        # if parsedInputURL.port is not None:
        #     netloc += ':' + str(parsedInputURL.port)
        #
        # # Now the credentials are properly set up
        # remote_file = cast("URIType", parse.urlunparse((parsedInputURL.scheme, netloc, parsedInputURL.path,
        #                                 parsedInputURL.params, parsedInputURL.query, parsedInputURL.fragment)))

    # Preparing where it is going to be written
    download_file: "IO[bytes]"
    if isinstance(cachedFilename, str):
        download_file = open(cachedFilename, "wb")
    else:
        download_file = cachedFilename

    uri_with_metadata = None
    try:
        req_remote = request.Request(
            remote_file, headers=headers, data=data, method=method
        )
        with opener(req_remote) as url_response:
            uri_with_metadata = URIWithMetadata(
                uri=url_response.url, metadata=dict(url_response.headers.items())
            )

            while True:
                try:
                    # Try getting it
                    shutil.copyfileobj(url_response, download_file)
                except http.client.IncompleteRead as icread:
                    download_file.write(icread.partial)
                    # Restarting the copy
                    continue
                break

    except urllib.error.HTTPError as he:
        raise FetcherException(
            "Error fetching {} : {} {}\n{}".format(
                orig_remote_file, he.code, he.reason, he.read().decode()
            )
        ) from he
    finally:
        # Closing files opened by this code
        if download_file != cachedFilename:
            download_file.close()

    return ProtocolFetcherReturn(
        kind_or_resolved=ContentKind.File,
        metadata_array=[uri_with_metadata],
    )


SCHEME_HANDLERS: "Mapping[str, ProtocolFetcher]" = {
    "http": fetchClassicURL,
    "https": fetchClassicURL,
}
