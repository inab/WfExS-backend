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

import copy
import datetime
import logging

from pathlib import Path

import os
import sys
import urllib.error

import pytest

from wfexs_backend.pushers import ExportPluginException
from wfexs_backend.pushers.dataverse_export import DataversePublisher

from typing import (
    cast,
    TYPE_CHECKING,
)

if TYPE_CHECKING:
    from typing import (
        Any,
        MutableMapping,
        MutableSequence,
    )
    from wfexs_backend.common import (
        AbsPath,
        SecurityContextConfig,
    )
    from pytest_param_files import (  # type: ignore[import]
        ParamTestData,
    )

from tests.util import get_path


dataverse_params = pytest.mark.dataverse_params()

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)


@pytest.mark.dependency
def test_dataverse_basic_fail_noapiprefix() -> "None":
    """
    Check Dataverse plugin complains about missing api-prefix parameter
    """
    with pytest.raises(ExportPluginException):
        DataversePublisher(cast("AbsPath", "/"), setup_block={"token": ""})


@pytest.mark.dependency
def test_dataverse_basic_fail_notoken() -> "None":
    """
    Check Dataverse plugin complains about missing token parameter
    """
    with pytest.raises(ExportPluginException):
        dep = DataversePublisher(
            cast("AbsPath", "/"), setup_block={"api-prefix": "example.org"}
        )


basic_deps = [
    test_dataverse_basic_fail_noapiprefix.__name__,
    test_dataverse_basic_fail_notoken.__name__,
]


@pytest.mark.dependency(depends=basic_deps, collect=True)
@dataverse_params
def test_dataverse_basic(file_params: "ParamTestData") -> "None":
    """Basic parsing test."""
    # assert isinstance(file_params.line, int)
    # assert isinstance(file_params.title, str)
    assert isinstance(
        file_params.extra.get("token"), str
    ), "This test needs a valid Dataverse user token"
    assert isinstance(
        file_params.extra.get("api-prefix"), str
    ), "This test needs to know the Dataverse service API prefix"
    assert isinstance(
        file_params.extra.get("dataverse-id"), str
    ), "This test needs a valid Dataverse id where to create new datasets"
    # assert isinstance(file_params.description, str)
    # assert isinstance(file_params.content, str)
    # assert isinstance(file_params.expected, str)

    setup_block: "SecurityContextConfig" = {
        "token": file_params.extra["token"],
        "api-prefix": file_params.extra["api-prefix"],
        "dataverse-id": file_params.extra["dataverse-id"],
    }
    dep = DataversePublisher(cast("AbsPath", "/tofill"), setup_block=setup_block)
    # assert file_params.expected.rstrip() == "Other"
    # file_params.assert_expected("Other", rstrip=True)


@pytest.mark.dependency(depends=basic_deps, collect=True)
@dataverse_params
def test_dataverse_get_pid_metadata(file_params: "ParamTestData") -> "None":
    assert isinstance(
        file_params.extra.get("token"), str
    ), "This test needs a valid Dataverse user token"
    assert isinstance(
        file_params.extra.get("api-prefix"), str
    ), "This test needs to know the Dataverse service API prefix"
    assert isinstance(
        file_params.extra.get("owned_existing_pid"), str
    ), "This test needs a Dataverse PID owned by the user in the service living under the api-prefix parameter"
    assert isinstance(
        file_params.extra.get("dataverse-id"), str
    ), "This test needs a valid Dataverse id where to create new datasets"

    setup_block: "SecurityContextConfig" = {
        "token": file_params.extra["token"],
        "api-prefix": file_params.extra["api-prefix"],
        "dataverse-id": file_params.extra["dataverse-id"],
    }
    dep = DataversePublisher(cast("AbsPath", "/tofill"), setup_block=setup_block)
    existing_pid = file_params.extra["owned_existing_pid"]

    pid_metadata = dep.get_pid_metadata(existing_pid)
    logger.info(pid_metadata)
    assert pid_metadata is not None, f"No metadata was obtained for {existing_pid}"


@pytest.mark.dependency(depends=basic_deps, collect=True)
@dataverse_params
def test_dataverse_book_new_pid(file_params: "ParamTestData") -> "None":
    assert isinstance(
        file_params.extra.get("token"), str
    ), "This test needs a valid Dataverse user token"
    assert isinstance(
        file_params.extra.get("api-prefix"), str
    ), "This test needs to know the Dataverse service API prefix"
    assert isinstance(
        file_params.extra.get("dataverse-id"), str
    ), "This test needs a valid Dataverse id where to create new datasets"

    setup_block: "SecurityContextConfig" = {
        "token": file_params.extra["token"],
        "api-prefix": file_params.extra["api-prefix"],
        "dataverse-id": file_params.extra["dataverse-id"],
    }
    dep = DataversePublisher(cast("AbsPath", "/tofill"), setup_block=setup_block)

    booked_entry = None
    try:
        booked_entry = dep.book_pid()
        assert booked_entry is not None
        logger.info(f"Booked PID is {booked_entry.pid}")
    except urllib.error.HTTPError as he:
        irbytes = he.read()
        logger.error(f"Error {he.url} {he.code} {he.reason} . Server report:")
        logger.error(irbytes.decode())
        raise he
    finally:
        if booked_entry is not None:
            dep.discard_booked_pid(booked_entry)


@pytest.mark.dependency(
    depends=[
        test_dataverse_book_new_pid.__name__,
    ],
    collect=True,
)
@dataverse_params
def test_dataverse_book_draft_pid(file_params: "ParamTestData") -> "None":
    assert isinstance(
        file_params.extra.get("token"), str
    ), "This test needs a valid Dataverse user token"
    assert isinstance(
        file_params.extra.get("api-prefix"), str
    ), "This test needs to know the Dataverse service API prefix"
    assert isinstance(
        file_params.extra.get("dataverse-id"), str
    ), "This test needs a valid Dataverse id where to create new datasets"

    setup_block: "SecurityContextConfig" = {
        "token": file_params.extra["token"],
        "api-prefix": file_params.extra["api-prefix"],
        "dataverse-id": file_params.extra["dataverse-id"],
    }
    dep = DataversePublisher(cast("AbsPath", "/tofill"), setup_block=setup_block)

    booked_entry = None
    booked_entry_take2 = None
    try:
        booked_entry = dep.book_pid()
        logger.info(booked_entry)
        assert booked_entry is not None
        booked_entry_take2 = dep.book_pid(booked_entry.draft_id)
        logger.info(booked_entry_take2)
        assert booked_entry_take2 is not None
        assert (
            booked_entry.pid == booked_entry_take2.pid
        ), f"Booked PIDs do not match {booked_entry.pid} vs {booked_entry_take2.pid}"
    except urllib.error.HTTPError as he:
        irbytes = he.read()
        logger.error(f"Error {he.url} {he.code} {he.reason} . Server report:")
        logger.error(irbytes.decode())
        raise he
    finally:
        if booked_entry is not None:
            dep.discard_booked_pid(booked_entry)
        if booked_entry_take2 is not None and (
            booked_entry is None or booked_entry_take2.draft_id != booked_entry.draft_id
        ):
            dep.discard_booked_pid(booked_entry_take2)


@pytest.mark.dependency(
    depends=[
        test_dataverse_book_new_pid.__name__,
    ],
    collect=True,
)
@dataverse_params
def test_dataverse_book_new_version_pid(file_params: "ParamTestData") -> "None":
    assert isinstance(
        file_params.extra.get("token"), str
    ), "This test needs a valid Dataverse user token"
    assert isinstance(
        file_params.extra.get("api-prefix"), str
    ), "This test needs to know the Dataverse service API prefix"
    assert isinstance(
        file_params.extra.get("dataverse-id"), str
    ), "This test needs a valid Dataverse id where to create new datasets"
    assert isinstance(
        file_params.extra.get("owned_existing_pid"), str
    ), "This test needs a Dataverse PID owned by the user"

    setup_block: "SecurityContextConfig" = {
        "token": file_params.extra["token"],
        "api-prefix": file_params.extra["api-prefix"],
        "dataverse-id": file_params.extra["dataverse-id"],
    }
    dep = DataversePublisher(
        cast("AbsPath", "/tofill"),
        setup_block=setup_block,
        preferred_id=file_params.extra["owned_existing_pid"],
    )

    booked_entry = None
    try:
        booked_entry = dep.book_pid()
        logger.info(booked_entry)
        assert booked_entry is not None
    except urllib.error.HTTPError as he:
        irbytes = he.read()
        logger.error(f"Error {he.url} {he.code} {he.reason} . Server report:")
        logger.error(irbytes.decode())
        raise he
    finally:
        if booked_entry is not None:
            dep.discard_booked_pid(booked_entry)


@pytest.mark.dependency(
    depends=[
        test_dataverse_book_new_pid.__name__,
    ],
    collect=True,
)
@dataverse_params
def test_dataverse_upload_file_to_draft(file_params: "ParamTestData") -> "None":
    assert isinstance(
        file_params.extra.get("token"), str
    ), "This test needs a valid Dataverse user token"
    assert isinstance(
        file_params.extra.get("api-prefix"), str
    ), "This test needs to know the Dataverse service API prefix"
    assert isinstance(
        file_params.extra.get("dataverse-id"), str
    ), "This test needs a valid Dataverse id where to create new datasets"

    naive_path = get_path(os.path.join("data", "naive_file.txt"))
    assert os.path.isfile(naive_path), f"Test file {naive_path} is not available"

    setup_block: "SecurityContextConfig" = {
        "token": file_params.extra["token"],
        "api-prefix": file_params.extra["api-prefix"],
        "dataverse-id": file_params.extra["dataverse-id"],
    }
    dep = DataversePublisher(
        cast("AbsPath", os.path.join(os.path.dirname(__file__), "data")),
        setup_block=setup_block,
    )

    booked_entry = None
    try:
        booked_entry = dep.book_pid()
        assert booked_entry is not None
        assert booked_entry.metadata is not None
        uploaded_file_meta = dep.upload_file_to_draft(
            booked_entry,
            filename=naive_path,
            remote_filename=None,
        )
        logger.info(uploaded_file_meta)
        assert uploaded_file_meta.get("key") == os.path.basename(naive_path)
        assert uploaded_file_meta.get("size") == os.path.getsize(naive_path)
    except urllib.error.HTTPError as he:
        irbytes = he.read()
        logger.error(f"Error {he.url} {he.code} {he.reason} . Server report:")
        logger.error(irbytes.decode())
        raise he
    finally:
        if booked_entry is not None:
            dep.discard_booked_pid(booked_entry)


STREAM_FILENAME = "remote/streamfile.txt"


@pytest.mark.dependency(
    depends=[
        test_dataverse_book_new_pid.__name__,
    ],
    collect=True,
)
@dataverse_params
def test_dataverse_upload_stream_to_draft(file_params: "ParamTestData") -> "None":
    assert isinstance(
        file_params.extra.get("token"), str
    ), "This test needs a valid Dataverse user token"
    assert isinstance(
        file_params.extra.get("api-prefix"), str
    ), "This test needs to know the Dataverse service API prefix"
    assert isinstance(
        file_params.extra.get("dataverse-id"), str
    ), "This test needs a valid Dataverse id where to create new datasets"

    naive_path = get_path(os.path.join("data", "naive_file.txt"))
    assert os.path.isfile(naive_path), f"Test file {naive_path} is not available"
    naive_path_size = os.path.getsize(naive_path)

    setup_block: "SecurityContextConfig" = {
        "token": file_params.extra["token"],
        "api-prefix": file_params.extra["api-prefix"],
        "dataverse-id": file_params.extra["dataverse-id"],
    }
    dep = DataversePublisher(cast("AbsPath", "/tofill"), setup_block=setup_block)

    booked_entry = None
    try:
        booked_entry = dep.book_pid()
        assert booked_entry is not None
        assert booked_entry.metadata is not None
        with open(naive_path, mode="rb") as nH:
            uploaded_file_meta = dep.upload_file_to_draft(
                booked_entry,
                filename=nH,
                remote_filename=STREAM_FILENAME,
                content_size=naive_path_size,
            )
        logger.info(uploaded_file_meta)
        assert uploaded_file_meta.get("key") == STREAM_FILENAME
        assert uploaded_file_meta.get("size") == naive_path_size
    except urllib.error.HTTPError as he:
        irbytes = he.read()
        logger.error(f"Error {he.url} {he.code} {he.reason} . Server report:")
        logger.error(irbytes.decode())
        raise he
    finally:
        if booked_entry is not None:
            dep.discard_booked_pid(booked_entry)


@pytest.mark.dependency(
    depends=[
        test_dataverse_book_new_pid.__name__,
    ],
    collect=True,
)
@dataverse_params
def test_dataverse_update_record_metadata(file_params: "ParamTestData") -> "None":
    assert isinstance(
        file_params.extra.get("token"), str
    ), "This test needs a valid Dataverse user token"
    assert isinstance(
        file_params.extra.get("api-prefix"), str
    ), "This test needs to know the Dataverse service API prefix"
    assert isinstance(
        file_params.extra.get("dataverse-id"), str
    ), "This test needs a valid Dataverse id where to create new datasets"

    setup_block: "SecurityContextConfig" = {
        "token": file_params.extra["token"],
        "api-prefix": file_params.extra["api-prefix"],
        "dataverse-id": file_params.extra["dataverse-id"],
    }
    dep = DataversePublisher(cast("AbsPath", "/tofill"), setup_block=setup_block)

    booked_entry = None
    try:
        booked_entry = dep.book_pid()
        assert booked_entry is not None
        assert booked_entry.metadata is not None
        logger.info(f"Booked PID is {booked_entry.pid}")

        # TO BE DONE
        entry_metadata: "MutableMapping[str, Any]" = {}
        entry_metadata["titles"][0]["title"] += (
            " at " + datetime.datetime.utcnow().isoformat()
        )
        entry_metadata["descriptions"][0]["description"] += (
            " at " + datetime.datetime.utcnow().isoformat()
        )

        updated_meta = dep.update_record_metadata(booked_entry, entry_metadata)
        logger.info(updated_meta)
        # assert entry_metadata["metadata"]["title"] == updated_meta.get("metadata", {}).get("title")
        # assert entry_metadata["metadata"]["upload_type"] == updated_meta.get("metadata", {}).get("upload_type")
    except urllib.error.HTTPError as he:
        irbytes = he.read()
        logger.error(f"Error {he.url} {he.code} {he.reason} . Server report:")
        logger.error(irbytes.decode())
        raise he
    finally:
        if booked_entry is not None:
            dep.discard_booked_pid(booked_entry)


@pytest.mark.dependency(
    depends=[
        test_dataverse_upload_file_to_draft.__name__,
        test_dataverse_update_record_metadata.__name__,
    ],
    collect=True,
)
@dataverse_params
def test_dataverse_publish_new_pid(file_params: "ParamTestData") -> "None":
    assert isinstance(
        file_params.extra.get("token"), str
    ), "This test needs a valid Dataverse user token"
    assert isinstance(
        file_params.extra.get("api-prefix"), str
    ), "This test needs to know the Dataverse service API prefix"
    assert isinstance(
        file_params.extra.get("dataverse-id"), str
    ), "This test needs a valid Dataverse id where to create new datasets"

    setup_block: "SecurityContextConfig" = {
        "token": file_params.extra["token"],
        "api-prefix": file_params.extra["api-prefix"],
        "dataverse-id": file_params.extra["dataverse-id"],
    }
    dep = DataversePublisher(cast("AbsPath", "/tofill"), setup_block=setup_block)

    booked_entry = None
    try:
        booked_entry = dep.book_pid()
        assert booked_entry is not None
        assert booked_entry.metadata is not None
        logger.info(f"Booked PID is {booked_entry.pid}")

        # TO BE DONE
        entry_metadata: "MutableMapping[str, Any]" = {}
        entry_metadata["titles"][0]["title"] += (
            " at " + datetime.datetime.utcnow().isoformat()
        )
        entry_metadata["descriptions"][0]["description"] += (
            " at " + datetime.datetime.utcnow().isoformat()
        )

        updated_meta = dep.update_record_metadata(booked_entry, entry_metadata)
        logger.info(updated_meta)
        # assert entry_metadata["metadata"]["title"] == updated_meta.get("metadata", {}).get("title")
        # assert entry_metadata["metadata"]["upload_type"] == updated_meta.get("metadata", {}).get("upload_type")
        published_meta = dep.publish_draft_record(booked_entry)
        logger.info(published_meta)
    except urllib.error.HTTPError as he:
        irbytes = he.read()
        logger.error(f"Error {he.url} {he.code} {he.reason} . Server report:")
        logger.error(irbytes.decode())
        raise he
    finally:
        if booked_entry is not None:
            dep.discard_booked_pid(booked_entry)
