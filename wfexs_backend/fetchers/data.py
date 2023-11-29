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

import os

import data_url

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

    from ..common import (
        AbsPath,
        ProgsMapping,
        RelPath,
        RepoURL,
        RepoTag,
        SecurityContextConfig,
        SymbolicName,
        URIType,
    )

from urllib import parse

from . import (
    DocumentedProtocolFetcher,
    FetcherException,
    ProtocolFetcherReturn,
)

from ..common import (
    ContentKind,
    URIWithMetadata,
)

DATA_SCHEME = "data"


def deserializeDataURI(
    remote_file: "URIType",
    cachedFilename: "AbsPath",
    secContext: "Optional[SecurityContextConfig]" = None,
) -> "ProtocolFetcherReturn":
    """
    Method to deserialize data urls

    :param remote_file:
    :param cachedFilename: Destination filename for the fetched content
    :param secContext: The security context containing the credentials
    """

    parsedInputURL = parse.urlparse(remote_file)
    if parsedInputURL.scheme != DATA_SCHEME:
        raise FetcherException(f"FIXME: Unhandled scheme {parsedInputURL.scheme}")

    with open(cachedFilename, mode="wb") as oH:
        data_url_obj = data_url.DataURL.from_url(remote_file)

        if isinstance(data_url_obj.data, str):
            the_string = parse.unquote_plus(data_url_obj.data)
            oH.write(the_string.encode("utf-8"))
        else:
            oH.write(data_url_obj.data)

    return ProtocolFetcherReturn(
        kind_or_resolved=ContentKind.File,
        metadata_array=[
            URIWithMetadata(
                uri=remote_file,
                metadata={},
            )
        ],
    )


SCHEME_HANDLERS: "Mapping[str, DocumentedProtocolFetcher]" = {
    DATA_SCHEME: DocumentedProtocolFetcher(
        fetcher=deserializeDataURI,
        description="'data' scheme is used to embed very small payloads, as it is described at https://datatracker.ietf.org/doc/html/rfc2397",
        priority=20,
    ),
}
