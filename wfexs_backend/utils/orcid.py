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

import io
import json
import re
from typing import (
    cast,
    TYPE_CHECKING,
)
import urllib.parse

if TYPE_CHECKING:
    from typing import (
        Any,
        Optional,
        Pattern,
        Mapping,
        Sequence,
        Tuple,
    )

    from typing_extensions import (
        Final,
    )

    from ..common import (
        ORCIDPublicRecord,
        URIType,
        URIWithMetadata,
    )


from ..common import (
    ResolvedORCID,
)
from ..fetchers.http import HTTPFetcher
from ..fetchers import FetcherException

ORCID_HOST: "Final[str]" = "orcid.org"
ORCID_PATTERN: "Final[Pattern[str]]" = re.compile(r"^0\d{3}-\d{4}-\d{4}-\d{3}(?:\d|X)$")
ORCID_CURIE: "Final[str]" = "orcid"
ORCID_URL_PREFIX: "Final[str]" = f"https://{ORCID_HOST}"


def validate_orcid(
    orcid_or_url: "str",
) -> "Optional[ResolvedORCID]":
    """
    This method validates the input possible orcid. When it is a valid one
    it returns the ORCID in short form, the URL of the ORCID profile,
    the public record and the gathered metadata from the HTTP REST call
    """

    parsed_as_url = urllib.parse.urlparse(orcid_or_url)
    # Is a bare ORCID?
    possible_orcid: "str"
    if parsed_as_url.scheme == "":
        possible_orcid = orcid_or_url
    elif parsed_as_url.scheme in ("http", "https"):
        if parsed_as_url.netloc != ORCID_HOST:
            raise FetcherException(
                f"Unexpected host {parsed_as_url.netloc} for an ORCID"
            )
        tokenized_path = parsed_as_url.path.split("/")
        if len(tokenized_path) >= 1 and len(tokenized_path[0]) > 0:
            possible_orcid = tokenized_path[0]
        elif len(tokenized_path) >= 2 and len(tokenized_path[1]) > 0:
            possible_orcid = tokenized_path[1]
        else:
            raise FetcherException(f"Unable to extract ORCID from {orcid_or_url}")
    elif parsed_as_url.scheme == ORCID_CURIE:
        possible_orcid = parsed_as_url.path
    else:
        raise FetcherException(f"Unexpected scheme {parsed_as_url.scheme} for an ORCID")

    if ORCID_PATTERN.match(possible_orcid):
        public_record_b = io.BytesIO()
        public_orcid_url = cast("URIType", f"{ORCID_URL_PREFIX}/{possible_orcid}")
        # If there is any issue fetching, next call should raise an exception
        _, meta_public_record, _ = HTTPFetcher().streamfetch(
            cast("URIType", f"{public_orcid_url}/public-record.json"), public_record_b
        )
        try:
            public_record = cast(
                "ORCIDPublicRecord",
                json.loads(public_record_b.getvalue().decode("utf-8")),
            )

            return (
                None
                if not isinstance(public_record, dict)
                or public_record.get("lastModifiedTime") is None
                else ResolvedORCID(
                    orcid=possible_orcid,
                    url=public_orcid_url,
                    record=public_record,
                    record_fetch_metadata=meta_public_record,
                )
            )
        except json.JSONDecodeError as jde:
            raise FetcherException(
                f"Unable to properly decode public record from {possible_orcid}"
            ) from jde
    else:
        raise FetcherException(
            f"'{possible_orcid}' is not a valid ORCID, as it does not match the expected pattern"
        )
