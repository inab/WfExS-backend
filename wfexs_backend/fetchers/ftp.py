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
        RelPath,
        RepoURL,
        RepoTag,
        SecurityContextConfig,
        SymbolicName,
        URIType,
    )

    class FTPConnBlock(TypedDict):
        HOST: "str"
        PORT: "NotRequired[int]"
        USER: "NotRequired[str]"
        PASSWORD: "NotRequired[str]"


from . import AbstractStatefulFetcher
from ..common import (
    ContentKind,
    ProtocolFetcherReturn,
    URIWithMetadata,
)

from ..utils.ftp_downloader import FTPDownloader


def fetchFTPURL(
    remote_file: "URIType",
    cachedFilename: "AbsPath",
    secContext: "Optional[SecurityContextConfig]" = None,
) -> "ProtocolFetcherReturn":
    """
    Method to fetch contents from ftp

    :param remote_file:
    :param cachedFilename:
    :param secContext:
    """

    orig_remote_file = remote_file
    parsedInputURL, remote_file = AbstractStatefulFetcher.ParseAndRemoveCredentials(
        orig_remote_file
    )
    # Now the credentials are properly removed from remote_file
    # we get them from the parsed url
    username = parsedInputURL.username
    password = parsedInputURL.password

    kind = None
    assert parsedInputURL.hostname is not None
    connParams: "FTPConnBlock" = {
        "HOST": parsedInputURL.hostname,
    }
    if parsedInputURL.port is not None:
        connParams["PORT"] = parsedInputURL.port

    if isinstance(secContext, dict):
        # There could be some corner cases where an empty
        # dictionary, or a dictionary without the needed keys
        # has been provided
        username = secContext.get("username", username)
        password = secContext.get("password", password)

    # Setting credentials only when it is set
    if username is not None:
        connParams["USER"] = username
        connParams["PASSWORD"] = password if password is not None else ""

    ftp_client = FTPDownloader(**connParams)
    retval = ftp_client.download(
        download_path=parsedInputURL.path, upload_path=cachedFilename
    )
    if isinstance(retval, list):
        kind = ContentKind.Directory
    else:
        kind = ContentKind.File

    return ProtocolFetcherReturn(
        kind_or_resolved=kind,
        metadata_array=[URIWithMetadata(remote_file, {})],
    )


SCHEME_HANDLERS: "Mapping[str, ProtocolFetcher]" = {
    "ftp": fetchFTPURL,
}
