#!/usr/bin/env python
# -*- coding: utf-8 -*-

# Copyright 2020-2022 Barcelona Supercomputing Center (BSC), Spain
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
import urllib.error

from . import fetchClassicURL, FetcherException

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
        ProtocolFetcher,
        ProtocolFetcherReturn,
        SecurityContextConfig,
        URIType,
    )

# See https://developer.osf.io/#tag/Nodes
OSF_IO_SCHEME = "osf.io"
OSF_IO_RECORD_REST = "https://api.osf.io/v2/nodes/"


def fetchOSFIO(
    remote_file: "URIType",
    cachedFilename: "AbsPath",
    secContext: "Optional[SecurityContextConfig]" = None,
) -> "ProtocolFetcherReturn":
    """
    Method to fetch files from osf.io datasets.

    :param remote_file:
    :param cachedFilename: Destination filename for the fetched content
    :param secContext: The security context containing the credentials
    """

    # TODO: implement support for access_token through security context

    # Dealing with an odd behaviour from urlparse
    for det in ("/", "?", "#"):
        if det in remote_file:
            parsedInputURL = urllib.parse.urlparse(remote_file)
            break
    else:
        parsedInputURL = urllib.parse.urlparse(remote_file + "#")
    parsed_steps = parsedInputURL.path.split("/")

    if len(parsed_steps) < 1 or parsed_steps[0] == "":
        raise FetcherException(
            f"{remote_file} is not a valid {OSF_IO_SCHEME} CURIE. It should start with something like {OSF_IO_SCHEME}:record_id"
        )

    osf_io_id = parsed_steps[0]

    metadata_url = cast("URIType", parse.urljoin(OSF_IO_RECORD_REST, osf_io_id))

    gathered_meta = {"fetched": metadata_url}
    metadata_array = [URIWithMetadata(remote_file, gathered_meta)]
    try:
        metaio = io.BytesIO()
        _, metametaio, _ = fetchClassicURL(metadata_url, metaio)
        metadata = json.loads(metaio.getvalue().decode("utf-8"))
        gathered_meta["payload"] = metadata
        metadata_array.extend(metametaio)
    except urllib.error.HTTPError as he:
        raise FetcherException(
            f"Error fetching osf.io metadata for {osf_io_id} : {he.code} {he.reason}"
        )

    if not isinstance(metadata, dict) or (metadata.get("data") is None):
        raise FetcherException(
            f"osf.io metadata for {osf_io_id} is inconsistent: {metadata}"
        )

    rel_block = metadata.get("data", {}).get("relationships", {})

    if rel_block is None:
        raise FetcherException(
            f"osf.io relationships metadata for {osf_io_id} is inconsistent: {metadata}"
        )

    # Let's identify the licence of the contents
    osf_io_lic_link = (
        rel_block.get("license", {}).get("links", {}).get("related", {}).get("href")
    )
    if osf_io_lic_link is None:
        raise FetcherException(
            f"osf.io license link for {osf_io_id} is missing: {metadata}"
        )

    gathered_l_meta = {"fetched": osf_io_lic_link}
    metadata_array.append(URIWithMetadata(remote_file, gathered_l_meta))
    try:
        metaio = io.BytesIO()
        _, metametalicio, _ = fetchClassicURL(osf_io_lic_link, metaio)
        l_metadata = json.loads(metaio.getvalue().decode("utf-8"))
        gathered_l_meta["payload"] = l_metadata
        metadata_array.extend(metametalicio)
    except urllib.error.HTTPError as he:
        raise FetcherException(
            f"Error fetching osf.io licence metadata {osf_io_lic_link} for {osf_io_id} : {he.code} {he.reason}"
        )

    licence_url = l_metadata.get("data", {}).get("attributes", {}).get("url")
    # When no URL, then the name should suffice
    if licence_url is None:
        licence_url = l_metadata.get("data", {}).get("attributes", {}).get("name")
    # When no name, then the text should suffice
    if licence_url is None:
        licence_url = l_metadata.get("data", {}).get("attributes", {}).get("text")

    if licence_url is None:
        raise FetcherException(
            f"osf.io licence metadata {osf_io_lic_link} needed to describe {osf_io_id} is inconsistent: {l_metadata}"
        )

    # Let's fetch the metadata of the contents
    osf_io_files_meta_link = (
        rel_block.get("files", {}).get("links", {}).get("related", {}).get("href")
    )
    if osf_io_files_meta_link is None:
        raise FetcherException(
            f"osf.io files metadata link for {osf_io_id} is missing: {metadata}"
        )

    gathered_fm_meta = {"fetched": osf_io_files_meta_link}
    metadata_array.append(URIWithMetadata(remote_file, gathered_fm_meta))
    try:
        metaio = io.BytesIO()
        _, metametafmio, _ = fetchClassicURL(osf_io_files_meta_link, metaio)
        fm_metadata = json.loads(metaio.getvalue().decode("utf-8"))
        gathered_fm_meta["payload"] = fm_metadata
        metadata_array.extend(metametafmio)
    except urllib.error.HTTPError as he:
        raise FetcherException(
            f"Error fetching osf.io files metadata {osf_io_files_meta_link} for {osf_io_id} : {he.code} {he.reason}"
        )

    # Let's fetch the list of the contents
    prov_block = fm_metadata.get("data", [])
    # TODO: manage the alternate storage providers of the data
    for store_block in prov_block:
        if store_block.get("type") == "files":
            possible_osf_io_store_link = (
                store_block.get("relationships", {})
                .get("files", {})
                .get("links", {})
                .get("related", {})
                .get("href")
            )
            if possible_osf_io_store_link is not None:
                osf_io_store_link = possible_osf_io_store_link
                break
    else:
        raise FetcherException(
            f"osf.io is not publishing where the files are for {osf_io_id} (or it is under controlled access): {fm_metadata}"
        )

    gathered_s_meta = {"fetched": osf_io_store_link}
    metadata_array.append(URIWithMetadata(remote_file, gathered_s_meta))
    try:
        metaio = io.BytesIO()
        _, metametasio, _ = fetchClassicURL(osf_io_store_link, metaio)
        s_metadata = json.loads(metaio.getvalue().decode("utf-8"))
        gathered_s_meta["payload"] = s_metadata
        metadata_array.extend(metametasio)
    except urllib.error.HTTPError as he:
        raise FetcherException(
            f"Error fetching osf.io stored files metadata {osf_io_store_link} for {osf_io_id} : {he.code} {he.reason}"
        )

    # Let's select the contents
    kind: "Optional[ContentKind]" = None
    the_possible_files = s_metadata.get("data", [])

    prefix = "/".join(parsed_steps[1:])
    # Adjusting this properly
    if len(parsed_steps) == 1:
        # Not used
        prefix_slash = ""
    elif prefix[-1] == "/":
        prefix_slash = prefix
        prefix = prefix[0:-1]
    else:
        prefix_slash = prefix + "/"

    the_files = []
    for the_file in the_possible_files:
        if the_file.get("type") != "files":
            continue

        osf_kind = the_file.get("attributes", {}).get("kind")
        if osf_kind != "file":
            continue

        key = the_file.get("attributes", {}).get("materialized_path").lstrip("/")

        the_link = the_file.get("links", {}).get("download")
        if the_link is None:
            continue

        if len(parsed_steps) == 1:
            the_files.append(the_file)
            kind = ContentKind.Directory
        elif key == prefix:
            the_files.append(the_file)
            kind = ContentKind.File
            break
        elif key.startswith(prefix_slash):
            the_files.append(the_file)
            kind = ContentKind.Directory

    # Now, let's materialize the files
    try:
        if kind == ContentKind.Directory:
            os.makedirs(cachedFilename, exist_ok=True)
            for the_file in the_files:
                relpath = the_file["attributes"]["materialized_path"].lstrip("/")
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
                    the_file["links"]["download"], the_file_local_path
                )
                metadata_array.extend(metacont)
        elif kind == ContentKind.File:
            _, metacont, _ = fetchClassicURL(
                the_files[0]["links"]["download"], cachedFilename
            )
            metadata_array.extend(metacont)
        else:
            raise FetcherException(
                f"{remote_file} does not match contents from osf.io entry {osf_io_id} (or entry has no associated file)"
            )
    except urllib.error.HTTPError as he:
        raise FetcherException(
            f"Error fetching Zenodo entry contents for {osf_io_id} : {he.code} {he.reason}"
        )

    return kind, metadata_array, (cast("URIType", licence_url),)


# These are schemes from identifiers.org
SCHEME_HANDLERS: "Mapping[str, ProtocolFetcher]" = {
    OSF_IO_SCHEME: fetchOSFIO,
}
