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
        ProtocolFetcher,
        RelPath,
        RepoURL,
        RepoTag,
        SecurityContextConfig,
        SymbolicName,
        URIType,
    )

from urllib import parse

from . import FetcherException

from ..common import (
    ContentKind,
    ProtocolFetcherReturn,
    URIWithMetadata,
)

from ..utils.contents import link_or_copy


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

    return ProtocolFetcherReturn(
        kind_or_resolved=kind,
        metadata_array=[
            URIWithMetadata(
                uri=the_remote_file,
                metadata=metadata,
                preferredName=cast("RelPath", os.path.basename(localPath)),
            )
        ],
    )


SCHEME_HANDLERS: "Mapping[str, ProtocolFetcher]" = {
    "file": fetchFile,
}
