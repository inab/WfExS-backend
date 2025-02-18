#!/usr/bin/env python
# -*- coding: utf-8 -*-

# SPDX-License-Identifier: Apache-2.0
# Copyright 2020-2024 Barcelona Supercomputing Center (BSC), Spain
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
from .http import HTTPFetcher

from ..common import (
    URIWithMetadata,
)

if TYPE_CHECKING:
    from typing import (
        Mapping,
        Optional,
    )

    from ..common import (
        AbsPath,
        PathLikePath,
        SecurityContextConfig,
        URIType,
    )

# See https://www.doi.org/factsheets/DOIProxy.html#rest-api
DOI_SCHEME = "doi"
DOI_RA_REST = "https://doi.org/doiRA/"
DOI_HANDLE_REST = "https://doi.org/api/handles/"

ZENODO_RECORD_PREFIX = "/record/"
ZENODO_NEW_RECORD_PREFIX = "/doi/10.5281/zenodo."
B2SHARE_RECORD_PREFIX = "/records/"
OSF_IO_RECORD_PREFIX = "/"
WORKFLOWHUB_RECORD_PREFIX = "/workflows/"


def fetchDOI(
    remote_file: "URIType",
    cachedFilename: "PathLikePath",
    secContext: "Optional[SecurityContextConfig]" = None,
) -> "ProtocolFetcherReturn":
    """
    Method to resolve URIs from DOI.
    In the future, it will differentiate among different DOI providers
    in order to delegate the resolution on specific implementations
    like the ones from Zenodo, OSF, Datacite or B2SHARE.

    :param remote_file:
    :param cachedFilename: Destination filename for the fetched content
    :param secContext: The security context containing the credentials
    """

    parsedInputURL = parse.urlparse(remote_file)
    parsed_steps = parsedInputURL.path.split("/")

    if len(parsed_steps) < 2 or parsed_steps[0] == "":
        raise FetcherException(
            f"{remote_file} is not a valid {DOI_SCHEME} CURIE. It should start with something like {DOI_SCHEME}:prefix/suffix"
        )

    doi_id = parsedInputURL.path

    metadata_ra_url = cast("URIType", parse.urljoin(DOI_RA_REST, doi_id))

    gathered_ra_meta = {"fetched": metadata_ra_url}
    metadata_array = [URIWithMetadata(remote_file, gathered_ra_meta)]
    http_fetcher = HTTPFetcher()
    try:
        metaio = io.BytesIO()
        _, metametaraio, _ = http_fetcher.streamfetch(metadata_ra_url, metaio)
        metadata_ra = json.loads(metaio.getvalue().decode("utf-8"))
        gathered_ra_meta["payload"] = metadata_ra
        metadata_array.extend(metametaraio)
    except FetcherException as fe:
        raise FetcherException(
            f"Error fetching DOI RA metadata for {doi_id} : {fe.code} {fe.reason}"
        ) from fe

    if (
        not isinstance(metadata_ra, list)
        or len(metadata_ra) == 0
        or not isinstance(metadata_ra[0], dict)
        or (metadata_ra[0].get("RA") is None)
    ):
        raise FetcherException(f"DOI {doi_id} does not exist: {metadata_ra}")

    metadata_url = cast("URIType", parse.urljoin(DOI_HANDLE_REST, doi_id))

    gathered_meta = {"fetched": metadata_url}
    metadata_array.append(URIWithMetadata(remote_file, gathered_meta))
    try:
        metaio = io.BytesIO()
        _, metametaio, _ = http_fetcher.streamfetch(metadata_url, metaio)
        metadata = json.loads(metaio.getvalue().decode("utf-8"))
        gathered_meta["payload"] = metadata
        metadata_array.extend(metametaio)
    except FetcherException as fe:
        raise FetcherException(
            f"Error fetching DOI metadata for {doi_id} : {fe.code} {fe.reason}"
        )

    doi_resolved_url: "Optional[str]" = None
    try:
        # https://www.doi.org/factsheets/DOIProxy.html#rest-api
        for value_block in metadata["values"]:
            data_block = value_block.get("data")
            if value_block.get("type") == "URL" and isinstance(data_block, dict):
                data_format = data_block.get("format")
                data_value = data_block.get("value")
                if data_value is not None:
                    # If "format"="string", "value" is a string,
                    #    representing the data as a UTF-8 string.
                    # If "format"="base64", "value" is a string, with a
                    #    BASE64 encoding of the data.
                    # If "format"="hex", "value" is a string, with a hex
                    #    encoding of the data.
                    # If "format"="admin", "value" is an object,
                    #    representing an HS_ADMIN value, with properties
                    #    "handle" (a string), "index" (an integer), and
                    #    "permissions" (a string, representing the
                    #    bitmask of permissions).
                    # If "format"="vlist", "value" is an list of objects,
                    #    representing an HS_VLIST value; each object in
                    #    the list has properties "handle" (a string) and
                    #    "index" (an integer).
                    # If "format"="site", "value" is an object,
                    #    representing an HS_SITE value. As the structure
                    #    of this object is complicated and generally of
                    #    limited technical interest it is currently
                    #    omitted from this documentation.
                    if data_format not in ("string", "base64", "hex"):
                        # Skip what we cannot manage
                        continue

                    if data_format == "base64":
                        data_value = base64.standard_b64decode(data_value).decode(
                            "utf-8", errors="ignore"
                        )
                    elif data_format == "hex":
                        data_value = bytes.fromhex(data_value).decode(
                            "utf-8", errors="ignore"
                        )
                    doi_resolved_url = data_value
                    break

        if doi_resolved_url is None:
            raise ValueError(f"Unable to properly resolve {doi_id}: {metadata}")
    except Exception as e:
        raise FetcherException(f"Error processing DOI metadata for {doi_id} : {e}")

    # TODO: identify other cases, like OSF
    doi_resolved_parsed = parse.urlparse(doi_resolved_url)
    if doi_resolved_parsed.scheme in ("http", "https"):
        # If it is from zenodo, let's delegate on zenodo pseudo-CURIE
        append_fragment = False
        if (
            doi_resolved_parsed.netloc == "zenodo.org"
            and doi_resolved_parsed.path.startswith(ZENODO_RECORD_PREFIX)
        ):
            doi_resolved_url = (
                "zenodo:" + doi_resolved_parsed.path[len(ZENODO_RECORD_PREFIX) :]
            )
            append_fragment = True
        elif (
            doi_resolved_parsed.netloc == "zenodo.org"
            and doi_resolved_parsed.path.startswith(ZENODO_NEW_RECORD_PREFIX)
        ):
            doi_resolved_url = (
                "zenodo:" + doi_resolved_parsed.path[len(ZENODO_NEW_RECORD_PREFIX) :]
            )
            append_fragment = True
        elif (
            doi_resolved_parsed.netloc == "b2share.eudat.eu"
            and doi_resolved_parsed.path.startswith(B2SHARE_RECORD_PREFIX)
        ):
            doi_resolved_url = (
                "b2share:" + doi_resolved_parsed.path[len(B2SHARE_RECORD_PREFIX) :]
            )
            append_fragment = True
        elif (
            doi_resolved_parsed.netloc == "osf.io"
            and doi_resolved_parsed.path.startswith(OSF_IO_RECORD_PREFIX)
        ):
            doi_resolved_url = (
                "osf.io:"
                + doi_resolved_parsed.path[len(OSF_IO_RECORD_PREFIX) :].split("/")[0]
            )
            append_fragment = True
        elif (
            doi_resolved_parsed.netloc == "workflowhub.eu"
            and doi_resolved_parsed.path.startswith(WORKFLOWHUB_RECORD_PREFIX)
        ):
            doi_resolved_url = (
                "trs://"
                + doi_resolved_parsed.netloc
                + "/"
                + doi_resolved_parsed.path[len(WORKFLOWHUB_RECORD_PREFIX) :]
            )
            if doi_resolved_parsed.query != "":
                query_d = parse.parse_qs(doi_resolved_parsed.query)
                version_a = query_d.get("version", [])
                if len(version_a) > 0:
                    doi_resolved_url += "/" + parse.quote(version_a[0], safe="")

        if append_fragment and len(parsedInputURL.fragment) > 0:
            doi_resolved_url += "/" + parsedInputURL.fragment

    return ProtocolFetcherReturn(
        kind_or_resolved=cast("URIType", doi_resolved_url),
        metadata_array=metadata_array,
    )


# These are schemes from identifiers.org
SCHEME_HANDLERS: "Mapping[str, DocumentedProtocolFetcher]" = {
    DOI_SCHEME: DocumentedProtocolFetcher(
        fetcher=fetchDOI,
        description="DOIs resolve to web sites. A subset of the different DOI providers also point to datasets, like the ones from Zenodo, B2SHARE or osf.io. Fetcher implementing DOI support either delegates on other specialized fetchers or delegates the download of the resolved URL.",
    ),
}
