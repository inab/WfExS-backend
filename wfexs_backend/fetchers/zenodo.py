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

from . import (
    DocumentedProtocolFetcher,
    FetcherException,
    ProtocolFetcherReturn,
)
from .http import fetchClassicURL

from ..common import (
    ContentKind,
    URIWithMetadata,
)

if TYPE_CHECKING:
    from typing import (
        Mapping,
        Optional,
    )

    from ..common import (
        AbsPath,
        SecurityContextConfig,
        URIType,
    )

# See https://developers.zenodo.org/#retrieve37
ZENODO_SCHEME = "zenodo"
ZENODO_RECORD_REST = "https://zenodo.org/api/records/"
ZENODO_LICENSE_REST = "https://zenodo.org/api/licenses/"


def fetchZenodo(
    remote_file: "URIType",
    cachedFilename: "AbsPath",
    secContext: "Optional[SecurityContextConfig]" = None,
) -> "ProtocolFetcherReturn":
    """
    Method to fetch files from Zenodo datasets.

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
            f"{remote_file} is not a valid {ZENODO_SCHEME} CURIE. It should start with something like {ZENODO_SCHEME}:record_id"
        )

    zenodo_id = parsed_steps[0]

    metadata_url = cast("URIType", parse.urljoin(ZENODO_RECORD_REST, zenodo_id))

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
            f"Error fetching Zenodo metadata for {zenodo_id} : {fe.code} {fe.reason}"
        ) from fe

    if not isinstance(metadata, dict) or (metadata.get("conceptdoi") is None):
        raise FetcherException(
            f"Zenodo metadata for {zenodo_id} is inconsistent: {metadata}"
        )

    zenodo_lic_id = metadata.get("metadata", {}).get("license", {}).get("id")
    if zenodo_lic_id is None:
        raise FetcherException(
            f"Zenodo metadata for {zenodo_id} is inconsistent: {metadata}"
        )

    # Let's identify the licence of the contents
    licence_meta_url = cast(
        "URIType", parse.urljoin(ZENODO_LICENSE_REST, zenodo_lic_id)
    )

    gathered_l_meta = {"fetched": licence_meta_url}
    metadata_array.append(URIWithMetadata(remote_file, gathered_l_meta))
    try:
        metaio = io.BytesIO()
        _, metametalicio, _ = fetchClassicURL(licence_meta_url, metaio)
        l_metadata = json.loads(metaio.getvalue().decode("utf-8"))
        gathered_l_meta["payload"] = l_metadata
        metadata_array.extend(metametalicio)
    except FetcherException as fe:
        raise FetcherException(
            f"Error fetching Zenodo licence metadata {zenodo_lic_id} for {zenodo_id} : {fe.code} {fe.reason}"
        ) from fe

    licence_url = l_metadata.get("metadata", {}).get("url")
    if licence_url is None:
        raise FetcherException(
            f"Zenodo licence metadata {zenodo_lic_id} needed to describe {zenodo_id} is inconsistent: {l_metadata}"
        )

    # When no URL, then the text should suffice
    if licence_url == "":
        licence_url = l_metadata["metadata"].get("title", zenodo_lic_id)

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

            the_link = the_file.get("links", {}).get("self")
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
            f"{remote_file} does not match contents from Zenodo entry {zenodo_id} (or entry has no associated file)"
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
                    the_file["links"]["self"], the_file_local_path
                )
                metadata_array.extend(metacont)
        else:
            _, metacont, _ = fetchClassicURL(
                the_files[0]["links"]["self"], cachedFilename
            )
            metadata_array.extend(metacont)
    except FetcherException as fe:
        raise FetcherException(
            f"Error fetching Zenodo entry contents for {zenodo_id} : {fe.code} {fe.reason}"
        ) from fe

    return ProtocolFetcherReturn(
        kind_or_resolved=kind,
        metadata_array=metadata_array,
        licences=(cast("URIType", licence_url),),
    )


# These are schemes from identifiers.org
SCHEME_HANDLERS: "Mapping[str, DocumentedProtocolFetcher]" = {
    ZENODO_SCHEME: DocumentedProtocolFetcher(
        fetcher=fetchZenodo,
        description="CURIEs following this scheme can be translated to a downloadable dataset, using APIs described at https://developers.zenodo.org/",
    ),
}
