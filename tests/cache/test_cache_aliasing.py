#!/usr/bin/env python
# -*- coding: utf-8 -*-

# SPDX-License-Identifier: Apache-2.0
# Copyright 2020-2026 Barcelona Supercomputing Center (BSC), Spain
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

# This test was written to track issues documented at https://github.com/inab/WfExS-backend/issues/288

import pytest

import filecmp
import logging
import os
import pathlib

from typing import (
    cast,
    TYPE_CHECKING,
)

if TYPE_CHECKING:
    # from wfexs_backend.workflow import WF
    from wfexs_backend.common import (
        URIType,
    )

from tests.core.test_wfexsbackend import (
    # This is needed to avoid re-running tests due the name starting with test_
    test_wfexsbackend_init as wfexs_backend_init,
)

from tests.util import get_path

from wfexs_backend.common import CacheType
import wfexs_backend.utils.digests

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

SAMPLE_DATA_FILE_1 = "lorem-ipsum-5-paragraphs.txt"
SAMPLE_DATA_FILE_2 = "lorem-ipsum-3-paragraphs.txt"


@pytest.mark.filterwarnings("ignore:.*:pytest.PytestReturnNotNoneWarning")
def test_cache_file(
    tmppath: "pathlib.Path",
) -> "None":
    wfBackend = wfexs_backend_init(tmppath)

    sample_path_1 = pathlib.Path(get_path(os.path.join("data", SAMPLE_DATA_FILE_1)))
    sample_path_2 = pathlib.Path(get_path(os.path.join("data", SAMPLE_DATA_FILE_2)))

    tmp_path = tmppath / "cached-content.txt"

    # The tmp path holds a copy of the first file
    sample_path_1.copy(tmp_path)
    with tmp_path.open(mode="rb") as tH:
        fingerprint_1 = wfexs_backend.utils.digests.ComputeDigestFromFileLike(
            tH,
            repMethod=wfexs_backend.utils.digests.hexDigest,
        )
        logger.info(f"Initial fingerprint {fingerprint_1!r}")

    # First, register the sample content in the cache
    cached_content = wfBackend.cacheFetch(
        cast("URIType", tmp_path.as_uri()),
        cacheType=CacheType.Input,
        offline=False,
    )

    # Now, check
    assert filecmp.cmp(tmp_path, cached_content.path)

    # Now, overwrite the contents at tmp path
    sample_path_2.copy(tmp_path)
    with tmp_path.open(mode="rb") as tH:
        fingerprint_2 = wfexs_backend.utils.digests.ComputeDigestFromFileLike(
            tH,
            repMethod=wfexs_backend.utils.digests.hexDigest,
        )
        logger.info(f"Updated fingerprint {fingerprint_2!r}")

    assert fingerprint_1 != fingerprint_2

    # fetched_dir = tmppath / "DOWN"

    ## Now, get both the cache handler and the path
    cH, cPath = wfBackend.getCacheHandler(CacheType.Input)
    cached_content_2 = cH.fetch(
        cast("URIType", tmp_path.as_uri()),
        offline=False,
        cache_dir=cPath,
    )

    # cached_content_2 = wfBackend.cacheFetch(
    #    cast("URIType", tmp_path.as_uri()),
    #    cacheType=CacheType.Input,
    #    offline=False,
    # )

    # Now, check again
    logger.info(f"Path to downloaded content {cached_content_2.path.as_posix()}")
    assert filecmp.cmp(tmp_path, cached_content_2.path)

    ## Now, fetch
