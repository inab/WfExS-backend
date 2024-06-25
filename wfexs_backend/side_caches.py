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

import logging
from typing import TYPE_CHECKING

from rocrate.model.metadata import (
    LegacyMetadata,
    Metadata,
)

from .utils.licences import LicenceMatcherSingleton
from .utils.passphrase_wrapper import WfExSPassGenSingleton
from .utils.pyld_caching import pyld_cache_initialize

if TYPE_CHECKING:
    from typing import (
        Sequence,
    )


def populate_side_caches() -> "None":
    """
    This method populates some side caches which are used in several parts
    of WfExS-backend code. They are residing at specific subdirectories
    from XDG_CACHE_DIR, and they are:

    * The lists of words used to generate random passphrases,
    * Most common JSON-LD contexts.
    * The list of licences from SPDX.
    """

    # First, the list of words
    logging.info("Populating passphrase generator cache (lists of words)")
    pw = WfExSPassGenSingleton()
    pw.initialize()

    # Then, most common JSON-LD contexts.
    logging.info(
        "Populating common JSON-LD contexts cache (needed for offline JSON-LD parsing)"
    )
    pyld_cache_initialize(
        [
            LegacyMetadata.PROFILE + "/context",
            Metadata.PROFILE + "/context",
            "https://w3id.org/ro/terms/workflow-run",
        ]
    )

    # Last, the list of licences
    logging.info("Populating list of licences cache (list fetched from SPDX)")
    lm = LicenceMatcherSingleton()
