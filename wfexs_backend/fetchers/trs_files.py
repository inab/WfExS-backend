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

import io
import json
import os

from typing import (
    cast,
    Mapping,
    Optional,
)

from urllib import parse
import urllib.error

from . import fetchClassicURL, FetcherException

from ..common import (
    AbsPath,
    ContentKind,
    ProtocolFetcher,
    ProtocolFetcherReturn,
    SecurityContextConfig,
    URIType,
    URIWithMetadata,
)


INTERNAL_TRS_SCHEME_PREFIX = "wfexs.trs.files"

TRS_FILES_SUFFIX = "/files"
TRS_DESCRIPTOR_INFIX = "/descriptor/"


def fetchTRSFiles(
    remote_file: URIType,
    cachedFilename: AbsPath,
    secContext: Optional[SecurityContextConfig] = None,
) -> ProtocolFetcherReturn:
    """
    Method to download contents from TRS files related to a tool

    :param remote_file:
    :param cachedFilename: Destination filename for the fetched content
    :param secContext: The security context containing the credentials
    """

    parsedInputURL = parse.urlparse(remote_file)
    embedded_remote_file = parsedInputURL.path

    if not embedded_remote_file.endswith(TRS_FILES_SUFFIX):
        metadata_url = cast(URIType, embedded_remote_file + TRS_FILES_SUFFIX)
    else:
        metadata_url = cast(URIType, embedded_remote_file)
        descriptor_base_url = (
            embedded_remote_file[0 : -len(TRS_FILES_SUFFIX)] + TRS_DESCRIPTOR_INFIX
        )

    topMeta = {
        "fetched": metadata_url,
        "payload": None,
        "workflow_entrypoint": None,
        "remote_workflow_entrypoint": None,
    }
    metadata_array = [URIWithMetadata(remote_file, topMeta)]
    metaio = None
    try:
        metaio = io.BytesIO()
        _, metametaio, _ = fetchClassicURL(metadata_url, metaio)
        metadata = json.loads(metaio.getvalue().decode("utf-8"))
        topMeta["payload"] = metadata
        metadata_array.extend(metametaio)

        metaio = None
    except urllib.error.HTTPError as he:
        raise FetcherException(
            "Error fetching or processing TRS files metadata for {} : {} {}".format(
                remote_file, he.code, he.reason
            )
        ) from he

    os.makedirs(cachedFilename, exist_ok=True)
    absdirs = set()
    emptyWorkflow = True
    for file_desc in metadata:
        file_rel_path = file_desc.get("path")
        if file_rel_path is not None:
            emptyWorkflow = False

            file_url = cast(URIType, descriptor_base_url + file_rel_path)
            absfile = cast(AbsPath, os.path.join(cachedFilename, file_rel_path))

            # Intermediate path creation
            reldir = os.path.dirname(file_rel_path)
            if len(reldir) > 0:
                absdir = os.path.join(cachedFilename, reldir)
                if absdir not in absdirs:
                    absdirs.add(absdir)
                    os.makedirs(absdir, exist_ok=True)

            # it is fetched twice, one for the metadata,
            if file_desc.get("file_type") == "PRIMARY_DESCRIPTOR":
                descriptorMeta = io.BytesIO()
                _, metaprimary, _ = fetchClassicURL(file_url, descriptorMeta)
                metadata_array.extend(metaprimary)

                # This metadata can help a lot to get the workflow repo
                metadataPD = json.loads(descriptorMeta.getvalue().decode("utf-8"))
                topMeta["workflow_entrypoint"] = file_rel_path
                topMeta["remote_workflow_entrypoint"] = metadataPD.get("url")

                del descriptorMeta
                del metadataPD

            # and another for the raw content (in case no workflow repo is identified)
            _, metaelem, _ = fetchClassicURL(
                file_url, absfile, {"headers": {"Accept": "text/plain"}}
            )
            metadata_array.extend(metaelem)

    if emptyWorkflow:
        raise FetcherException(
            "Error processing TRS files for {} : no file was found.\n{}".format(
                remote_file, metadata
            )
        )

    return ContentKind.Directory, metadata_array, None


# These are schemes from identifiers.org
SCHEME_HANDLERS: Mapping[str, ProtocolFetcher] = {
    INTERNAL_TRS_SCHEME_PREFIX: fetchTRSFiles,
}
