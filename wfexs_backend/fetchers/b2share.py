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

import base64
import io
import json
import os

from typing import (
    cast,
    TYPE_CHECKING,
)

from urllib import parse

from . import FetcherException
from .http import fetchClassicURL

from ..common import (
    ContentKind,
    ProtocolFetcherReturn,
    URIWithMetadata,
)

if TYPE_CHECKING:
    from typing import (
        Mapping,
        Optional,
    )

    from ..common import (
        AbsPath,
        ProtocolFetcher,
        SecurityContextConfig,
        URIType,
    )

# See https://eudat.eu/services/userdoc/b2share-http-rest-api#get-specific-record
B2SHARE_SCHEME = "b2share"
B2SHARE_RECORD_REST = "https://b2share.eudat.eu/api/records/"


def fetchB2SHARE(
    remote_file: "URIType",
    cachedFilename: "AbsPath",
    secContext: "Optional[SecurityContextConfig]" = None,
) -> "ProtocolFetcherReturn":
    """
    Method to fetch files from B2SHARE datasets.
    It is quite similar to Zenodo.

    :param remote_file:
    :param cachedFilename: Destination filename for the fetched content
    :param secContext: The security context containing the credentials
    """

    # TODO: implement support for access_token through security context

    # Dealing with an odd behaviour from urlparse
    for det in ("/", "?", "#"):
        if det in remote_file:
            parsedInputURL = parse.urlparse(remote_file)
            break
    else:
        parsedInputURL = parse.urlparse(remote_file + "#")
    parsed_steps = parsedInputURL.path.split("/")

    if len(parsed_steps) < 1 or parsed_steps[0] == "":
        raise FetcherException(
            f"{remote_file} is not a valid {B2SHARE_SCHEME} CURIE. It should start with something like {B2SHARE_SCHEME}:record_id"
        )

    b2share_id = parsed_steps[0]

    metadata_url = cast("URIType", parse.urljoin(B2SHARE_RECORD_REST, b2share_id))

    gathered_meta = {"fetched": metadata_url}
    metadata_array = [URIWithMetadata(remote_file, gathered_meta)]
    try:
        metaio = io.BytesIO()
        _, metametaio, _ = fetchClassicURL(metadata_url, metaio)
        metadata = json.loads(metaio.getvalue().decode("utf-8"))
        gathered_meta["payload"] = metadata
        metadata_array.extend(metametaio)
    except FetcherException as fe:
        raise FetcherException(
            f"Error fetching B2SHARE metadata for {b2share_id} : {fe.code} {fe.reason}"
        ) from fe

    if not isinstance(metadata, dict) or (metadata.get("created") is None):
        raise FetcherException(
            f"B2SHARE metadata for {b2share_id} is inconsistent: {metadata}"
        )

    license_block = metadata.get("metadata", {}).get("license", {})
    licence_url = license_block.get("license_uri")
    # When no URL, then the text should suffice
    if licence_url is None:
        licence_url = license_block.get("license")
    if licence_url is None:
        licence_url = license_block.get("license_identifier")
    if licence_url is None:
        raise FetcherException(
            f"B2SHARE licence metadata needed to describe {b2share_id} is inconsistent: {metadata}"
        )

    # Let's select the contents
    kind: "Optional[ContentKind]" = None
    the_possible_files = metadata.get("files", [])
    if len(parsed_steps) == 1:
        the_files = the_possible_files
        kind = ContentKind.Directory
    else:
        the_files = []
        prefix = "/".join(parsed_steps[1:])
        # Adjusting this properly
        if prefix[-1] == "/":
            prefix_slash = prefix
            prefix = prefix[0:-1]
        else:
            prefix_slash = prefix + "/"

        for the_file in the_possible_files:
            key = the_file.get("key")
            if key is None:
                continue

            the_link = the_file.get("ePIC_PID")
            if the_link is None:
                continue

            if key == prefix:
                the_files.append(the_file)
                kind = ContentKind.File
                break
            elif key.startswith(prefix_slash):
                the_files.append(the_file)
                kind = ContentKind.Directory

    if kind is None:
        raise FetcherException(
            f"{remote_file} does not match contents from B2SHARE entry {b2share_id} (or entry has no associated file)"
        )

    # Now, let's materialize the files
    try:
        if kind == ContentKind.Directory:
            os.makedirs(cachedFilename, exist_ok=True)
            for the_file in the_files:
                relpath = the_file["key"]
                last_slash = relpath.rfind("/")
                if last_slash != -1:
                    the_file_local_dir = os.path.join(
                        cachedFilename, relpath[0:last_slash]
                    )
                    os.makedirs(the_file_local_dir, exist_ok=True)

                the_file_local_path = cast(
                    "AbsPath", os.path.join(cachedFilename, relpath)
                )
                _, metacont, _ = fetchClassicURL(
                    the_file["ePIC_PID"], the_file_local_path
                )
                metadata_array.extend(metacont)
        else:
            _, metacont, _ = fetchClassicURL(the_files[0]["ePIC_PID"], cachedFilename)
            metadata_array.extend(metacont)
    except FetcherException as fe:
        raise FetcherException(
            f"Error fetching B2SHARE entry contents for {b2share_id} : {fe.code} {fe.reason}"
        ) from fe

    return ProtocolFetcherReturn(
        kind_or_resolved=kind,
        metadata_array=metadata_array,
        licences=(cast("URIType", licence_url),),
    )


# These are schemes from identifiers.org
SCHEME_HANDLERS: "Mapping[str, ProtocolFetcher]" = {
    B2SHARE_SCHEME: fetchB2SHARE,
}
