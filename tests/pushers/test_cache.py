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

import pytest
import logging

from pathlib import Path

import os
import sys
import urllib.error

import pytest

from wfexs_backend.common import (
    CacheType,
    GeneratedContent,
)

from wfexs_backend.pushers import ExportPluginException
from wfexs_backend.pushers.cache_export import CacheExportPlugin

from wfexs_backend.wfexs_backend import WfExSBackend

from typing import (
    cast,
    TYPE_CHECKING,
)

if TYPE_CHECKING:
    from wfexs_backend.common import (
        AbsPath,
        SecurityContextConfig,
        URIType,
    )

from tests.util import get_path

from wfexs_backend.common import (
    CC_BY_40_LicenceDescription,
    NoLicenceDescription,
)

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)


def test_cache_basic() -> "None":
    """
    Check cache export plugin instantiation
    """
    CacheExportPlugin(cast("AbsPath", "/"), setup_block={})


def test_cache_book_pid_noparam_fail() -> "None":
    """
    Check cache plugin cannot "book" without a hint
    """
    cep = CacheExportPlugin(cast("AbsPath", "/"), setup_block={})
    with pytest.raises(ValueError):
        cep.book_pid()


def test_cache_book_pid_nouri_fail() -> "None":
    """
    Check cache plugin cannot "book" a preferred id which is not an URI
    """

    cep = CacheExportPlugin(cast("AbsPath", "/"), setup_block={})
    with pytest.raises(ValueError):
        cep.book_pid("nonamespace")


def test_cache_book_pid() -> "None":
    """
    Check cache plugin "books" an URI
    """

    cep = CacheExportPlugin(cast("AbsPath", "/"), setup_block={})
    pid = "the:test"
    booked_pid = cep.book_pid(pid)
    assert booked_pid is not None
    assert pid == booked_pid.pid


def test_cache_push_nocontext_fail() -> "None":
    """
    Check cache plugin complains about no contextualized instance
    """

    cep = CacheExportPlugin(cast("AbsPath", "/"), setup_block={})
    with pytest.raises(ValueError):
        cep.push([])


def test_cache_push(tmpdir) -> "None":  # type: ignore[no-untyped-def]
    """
    Check cache plugin complains about no contextualized instance
    """

    naive_path = get_path(os.path.join("data", "naive_file.txt"))
    assert os.path.isfile(naive_path), f"Test file {naive_path} is not available"

    # First, instantiate WfExS backend
    temppath = tmpdir.mkdir("TEMP")

    bootstrap_ok, test_local_config = WfExSBackend.bootstrap(
        local_config_ro={
            "cacheDir": "CACHE",
            "workDir": "WORKDIRS",
        },
        config_directory=tmpdir.strpath,
        key_prefix="crypt4gh",
    )
    wfexs = WfExSBackend(
        local_config=test_local_config,
        config_directory=tmpdir.strpath,
    )

    # Second, instantiate the cache plugin
    cep = CacheExportPlugin(
        cast("AbsPath", os.path.dirname(naive_path)),
        setup_block={},
    )

    cep.set_wfexs_context(wfexs, tempdir=temppath.strpath)

    # Third, "book" a PID
    booked_entry = cep.book_pid("the:test")
    assert booked_entry is not None

    # Fourth, push file into the cache
    pushed_contents = cep.push(
        items=[
            GeneratedContent(local=cast("AbsPath", naive_path)),
        ],
        preferred_id=booked_entry.draft_id,
        licences=[
            CC_BY_40_LicenceDescription,
            NoLicenceDescription,
        ],
    )

    # Fifth, check
    # cH, cPath = wfexs.getCacheHandler(CacheType.Input)
    logger.info(
        wfexs.cacheFetch(
            cast("URIType", "the:test"), cacheType=CacheType.Input, offline=True
        )
    )
