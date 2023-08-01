#!/usr/bin/env python3
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

import io
import json

from typing import (
    cast,
    TYPE_CHECKING,
)

if TYPE_CHECKING:
    from typing import (
        Mapping,
        MutableSequence,
        Optional,
        Tuple,
    )

    from ..common import (
        AbsPath,
        ProtocolFetcher,
        SecurityContextConfig,
        URIType,
    )

from urllib import parse
import urllib.error

# We have preference for the C based loader and dumper, but the code
# should fallback to default implementations when C ones are not present
import yaml

from . import FetcherException
from .http import fetchClassicURL

from ..common import (
    LicensedURI,
    ProtocolFetcherReturn,
    URIWithMetadata,
)

DRS_SCHEME = "drs"
N2T_NET_SERVICE = "https://n2t.net/"


def query_n2t(
    scheme: "str",
    the_id: "str",
    remote_file: "URIType",
    metadata_array: "MutableSequence[URIWithMetadata]" = [],
) -> "Tuple[URIType, MutableSequence[URIWithMetadata]]":
    query_url = cast("URIType", N2T_NET_SERVICE + scheme + ":")
    gathered_meta = {"fetched": query_url}

    n2t_io = io.BytesIO()
    _, meta_n2t_io, _ = fetchClassicURL(query_url, n2t_io)
    answer = yaml.safe_load(n2t_io.getvalue().decode("utf-8"))

    gathered_meta["payload"] = answer
    metadata_array.append(URIWithMetadata(remote_file, gathered_meta))
    metadata_array.extend(meta_n2t_io)

    if not isinstance(answer, dict):
        raise FetcherException(
            f"Unexpected answer for n2t.net query about {remote_file} ({scheme})"
        )

    ans = answer.get("scheme")
    if ans is None:
        raise FetcherException(
            f"No answer for n2t.net query about {remote_file} ({scheme})"
        )

    a_type = ans.get("type")
    if a_type == "synonym":
        for_ans = ans.get("for")
        if for_ans is None:
            raise FetcherException(
                f"Ill-formed synonym answer for n2t.net query about {remote_file} ({scheme})"
            )
        return query_n2t(for_ans, the_id, remote_file, metadata_array)

    if a_type != "scheme":
        raise FetcherException(
            f'Unknown "{a_type}" answer for n2t.net query about {remote_file} ({scheme})'
        )

    redir_pat = ans.get("redirect")
    if redir_pat is None:
        raise FetcherException(
            f"Ill-formed redirect answer for n2t.net query about {remote_file} ({scheme})"
        )

    return cast("URIType", redir_pat.replace("$id", the_id)), metadata_array


def downloadContentFromDRS(
    remote_file: "URIType",
    cachedFilename: "AbsPath",
    secContext: "Optional[SecurityContextConfig]" = None,
) -> "ProtocolFetcherReturn":
    upperSecContext = dict()

    parsedInputURL = parse.urlparse(remote_file)

    # Complaining about unknown schemes
    if parsedInputURL.scheme != DRS_SCHEME:
        raise FetcherException(
            f"Unexpected scheme {parsedInputURL.scheme}, expected {DRS_SCHEME}"
        )

    retURL: "MutableSequence[LicensedURI]" = []
    metadata_array: "MutableSequence[URIWithMetadata]" = []

    # Detecting compact version of DRS
    # https://ga4gh.github.io/data-repository-service-schemas/preview/release/drs-1.1.0/docs/#_appendix_compact_identifier_based_uris
    colon_index = parsedInputURL.netloc.find(":")
    if colon_index != -1 and parsedInputURL.path == "":
        # As the element on the right side of ':' could not be an integer
        # it has to be obtained through the traditional way
        scheme = parsedInputURL.netloc[0:colon_index]
        the_id = parsedInputURL.netloc[colon_index + 1 :]

        # Now, the query to n2t.net
        redirect_url, metadata_array = query_n2t(scheme, the_id, remote_file)

        retURL.append(LicensedURI(uri=redirect_url))
    else:
        # Computing the path prefix
        path_tokens = parsedInputURL.path.split("/")
        object_id = path_tokens[-1]
        path_tokens[-1] = ""
        ga4gh_path_prefix = "/".join(path_tokens) + "ga4gh/drs/v1/"

        token = None
        token_header = None
        username = None
        password = None

        # Setting up the credentials
        netloc = parsedInputURL.hostname
        if netloc is None:
            netloc = ""
        headers = dict()
        if isinstance(secContext, dict):
            headers = secContext.get("headers", {})
            token = secContext.get("token")
            token_header = secContext.get("token_header")
            username = secContext.get("username")
            password = secContext.get("password")

            if token is not None:
                upperSecContext["token"] = token
                if token_header is not None:
                    upperSecContext["token_header"] = token_header
            elif username is not None:
                if password is None:
                    password = ""
                upperSecContext["username"] = username
                upperSecContext["password"] = password

            upperSecContext["headers"] = headers

        scheme = "https"
        if parsedInputURL.port is not None:
            netloc += ":" + str(parsedInputURL.port)
            if parsedInputURL.port == 80:
                scheme = "http"

        # And the service prefix
        drs_service_prefix = parse.urlunparse(
            (scheme, netloc, ga4gh_path_prefix, "", "", "")
        )

        # Now, get the object metadata
        object_metadata_url = cast(
            "URIType", drs_service_prefix + "objects/" + object_id
        )

        gathered_meta = {"fetched": object_metadata_url}
        metadata = None
        try:
            metaio = io.BytesIO()
            _, metametaio, _ = fetchClassicURL(
                object_metadata_url, metaio, secContext=upperSecContext
            )
            object_metadata = json.loads(metaio.getvalue().decode("utf-8"))
            # Gathering the preferred name
            preferredName = object_metadata.get("name")

            gathered_meta["payload"] = object_metadata
            metadata_array.append(
                URIWithMetadata(remote_file, gathered_meta, preferredName)
            )
            metadata_array.extend(metametaio)
        except urllib.error.HTTPError as he:
            raise FetcherException(
                "Error fetching DRS metadata for {} : {} {}".format(
                    remote_file, he.code, he.reason
                )
            ) from he

        # With the metadata, let's compose the URL to be returned
        # (which could not be cached)
        for access_method in object_metadata.get("access_methods", []):
            object_url = access_method.get("access_url")
            access_id = access_method.get("access_id")
            customSecContext = None
            if (object_url is None) and (access_id is not None):
                object_access_metadata_url = cast(
                    "URIType",
                    object_metadata_url + "/access/" + parse.quote(access_id, safe=""),
                )

                try:
                    metaaccio = io.BytesIO()
                    _, metametaaccio, _ = fetchClassicURL(
                        object_access_metadata_url,
                        metaaccio,
                        secContext=upperSecContext,
                    )
                    object_access_metadata = json.loads(
                        metaaccio.getvalue().decode("utf-8")
                    )
                except urllib.error.HTTPError as he:
                    raise FetcherException(
                        "Error fetching DRS access link {} for {} : {} {}".format(
                            access_id, remote_file, he.code, he.reason
                        )
                    ) from he

                object_url = object_access_metadata.get("url")
                object_headers = object_access_metadata.get("headers")

                if isinstance(object_headers, dict):
                    customSecContext = {"headers": object_headers}

            if object_url is not None:
                lic_uri = LicensedURI(uri=object_url, secContext=customSecContext)
                retURL.append(lic_uri)

    return ProtocolFetcherReturn(
        kind_or_resolved=retURL,
        metadata_array=metadata_array,
    )


SCHEME_HANDLERS: "Mapping[str, ProtocolFetcher]" = {
    DRS_SCHEME: downloadContentFromDRS,
}
