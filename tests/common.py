#!/usr/bin/env python3
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

from typing import (
    cast,
    TYPE_CHECKING,
)

if TYPE_CHECKING:
    from wfexs_backend.common import (
        URIType,
    )

from wfexs_backend.common import (
    ResolvedORCID,
)

TEST_ORCID = ResolvedORCID(
    orcid="0000-0002-4806-5140",
    url=cast("URIType", ""),
    record={
        "title": None,
        "displayName": "Fernández, José Mª",
        "names": None,
        "biography": None,
        "otherNames": None,
        "countries": None,
        "keyword": None,
        "emails": None,
        "externalIdentifier": None,
        "website": None,
        "lastModifiedTime": None,
    },
    record_fetch_metadata=[],
)
