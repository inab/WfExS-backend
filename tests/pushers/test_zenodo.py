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

import datetime
import logging

import pathlib

import os
import sys
import urllib.error

import pytest

from wfexs_backend.pushers import ExportPluginException
from wfexs_backend.pushers.zenodo_export import ZenodoExportPlugin

from typing import (
    cast,
    TYPE_CHECKING,
)

if TYPE_CHECKING:
    from wfexs_backend.common import (
        AbsPath,
        SecurityContextConfig,
    )
    from pytest_param_files import (  # type: ignore[import]
        ParamTestData,
    )

from tests.common import (
    TEST_ORCID,
)

from tests.util import (
    get_path,
)

from wfexs_backend.common import (
    CC_BY_40_LicenceDescription,
    NoLicenceDescription,
)


# def pytest_generate_tests(metafunc):
#    if "stringinput" in metafunc.fixturenames:
#        metafunc.parametrize("stringinput", metafunc.config.getoption("stringinput"))

# if "PYTEST_WFEXS_ZENODO" in os.environ:
#    zenodo_params = pytest.mark.param_file(os.environ.get("PYTEST_WFEXS_ZENODO", ""), fmt="yaml")
# else:
#    zenodo_params = pytest.mark.skip("No configuration file through PYTEST_WFEXS_ZENODO available for this batch of Zenodo tests")
zenodo_params = pytest.mark.zenodo_params()


logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)


# @pytest.mark.xfail(raises=ExportPluginException, reason="Check Zenodo plugin complains about missing token parameter")
@pytest.mark.dependency
def test_zenodo_basic_fail_nosandbox() -> "None":
    """
    Check Zenodo plugin complains about missing sandbox parameter
    """
    with pytest.raises(ExportPluginException):
        ZenodoExportPlugin(pathlib.Path("/"), setup_block={"token": ""})


# @pytest.mark.xfail(raises=ExportPluginException, reason="Check Zenodo plugin complains about missing sandbox parameter")
@pytest.mark.dependency
def test_zenodo_basic_fail_notoken() -> "None":
    """
    Check Zenodo plugin complains about missing token parameter
    """
    with pytest.raises(ExportPluginException):
        zep = ZenodoExportPlugin(pathlib.Path("/"), setup_block={"sandbox": True})


basic_deps = [
    test_zenodo_basic_fail_nosandbox.__name__,
    test_zenodo_basic_fail_notoken.__name__,
]


@pytest.mark.dependency(depends=basic_deps, collect=True)
@zenodo_params
def test_zenodo_basic(file_params: "ParamTestData") -> "None":
    """Basic parsing test."""
    # assert isinstance(file_params.line, int)
    # assert isinstance(file_params.title, str)
    assert isinstance(
        file_params.extra.get("token"), str
    ), "This test needs a valid Zenodo user token"
    assert isinstance(
        file_params.extra.get("sandbox"), bool
    ), "This test needs to know whether to run against sandbox or production"
    # assert isinstance(file_params.description, str)
    # assert isinstance(file_params.content, str)
    # assert isinstance(file_params.expected, str)

    setup_block: "SecurityContextConfig" = {
        "token": file_params.extra["token"],
        "sandbox": file_params.extra["sandbox"],
    }
    zep = ZenodoExportPlugin(pathlib.Path("/tofill"), setup_block=setup_block)
    # assert file_params.expected.rstrip() == "Other"
    # file_params.assert_expected("Other", rstrip=True)


@pytest.mark.dependency(depends=basic_deps, collect=True)
@zenodo_params
def test_zenodo_get_pid_metadata(file_params: "ParamTestData") -> "None":
    assert isinstance(
        file_params.extra.get("token"), str
    ), "This test needs a valid Zenodo user token"
    assert isinstance(
        file_params.extra.get("sandbox"), bool
    ), "This test needs to know whether to run against sandbox or production"
    assert isinstance(
        file_params.extra.get("owned_existing_pid"), str
    ), "This test needs a Zenodo PID owned by the user"

    setup_block: "SecurityContextConfig" = {
        "token": file_params.extra["token"],
        "sandbox": file_params.extra["sandbox"],
    }
    zep = ZenodoExportPlugin(pathlib.Path("/tofill"), setup_block=setup_block)
    existing_pid = file_params.extra["owned_existing_pid"]

    pid_metadata = zep.get_pid_metadata(existing_pid)
    logger.info(pid_metadata)
    assert pid_metadata is not None, f"No metadata was obtained for {existing_pid}"


@pytest.mark.dependency(depends=basic_deps, collect=True)
@zenodo_params
def test_zenodo_book_new_pid(file_params: "ParamTestData") -> "None":
    assert isinstance(
        file_params.extra.get("token"), str
    ), "This test needs a valid Zenodo user token"
    assert isinstance(
        file_params.extra.get("sandbox"), bool
    ), "This test needs to know whether to run against sandbox or production"

    setup_block: "SecurityContextConfig" = {
        "token": file_params.extra["token"],
        "sandbox": file_params.extra["sandbox"],
    }
    zep = ZenodoExportPlugin(pathlib.Path("/tofill"), setup_block=setup_block)

    booked_entry = None
    try:
        booked_entry = zep.book_pid()
        assert booked_entry is not None
        logger.info(f"Booked PID is {booked_entry.pid}")
    except urllib.error.HTTPError as he:
        irbytes = he.read()
        logger.error(f"Error {he.url} {he.code} {he.reason} . Server report:")
        logger.error(irbytes.decode())
        raise he
    finally:
        if booked_entry is not None:
            zep.discard_booked_pid(booked_entry)


@pytest.mark.dependency(
    depends=[
        test_zenodo_book_new_pid.__name__,
    ],
    collect=True,
)
@zenodo_params
def test_zenodo_book_draft_pid(file_params: "ParamTestData") -> "None":
    assert isinstance(
        file_params.extra.get("token"), str
    ), "This test needs a valid Zenodo user token"
    assert isinstance(
        file_params.extra.get("sandbox"), bool
    ), "This test needs to know whether to run against sandbox or production"

    setup_block: "SecurityContextConfig" = {
        "token": file_params.extra["token"],
        "sandbox": file_params.extra["sandbox"],
    }
    zep = ZenodoExportPlugin(pathlib.Path("/tofill"), setup_block=setup_block)

    booked_entry = None
    booked_entry_take2 = None
    try:
        booked_entry = zep.book_pid()
        logger.info(booked_entry)
        assert booked_entry is not None
        booked_entry_take2 = zep.book_pid(booked_entry.draft_id)
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
            zep.discard_booked_pid(booked_entry)
        if booked_entry_take2 is not None and (
            booked_entry is None or booked_entry_take2.draft_id != booked_entry.draft_id
        ):
            zep.discard_booked_pid(booked_entry_take2)


@pytest.mark.dependency(
    depends=[
        test_zenodo_book_new_pid.__name__,
    ],
    collect=True,
)
@zenodo_params
def test_zenodo_book_new_version_pid(file_params: "ParamTestData") -> "None":
    assert isinstance(
        file_params.extra.get("token"), str
    ), "This test needs a valid Zenodo user token"
    assert isinstance(
        file_params.extra.get("sandbox"), bool
    ), "This test needs to know whether to run against sandbox or production"
    assert isinstance(
        file_params.extra.get("owned_existing_pid"), str
    ), "This test needs a Zenodo PID owned by the user"

    setup_block: "SecurityContextConfig" = {
        "token": file_params.extra["token"],
        "sandbox": file_params.extra["sandbox"],
    }
    zep = ZenodoExportPlugin(
        pathlib.Path("/tofill"),
        setup_block=setup_block,
        default_preferred_id=file_params.extra["owned_existing_pid"],
    )

    booked_entry = None
    try:
        booked_entry = zep.book_pid()
        logger.info(booked_entry)
        assert booked_entry is not None
    except urllib.error.HTTPError as he:
        irbytes = he.read()
        logger.error(f"Error {he.url} {he.code} {he.reason} . Server report:")
        logger.error(irbytes.decode())
        raise he
    finally:
        if booked_entry is not None:
            zep.discard_booked_pid(booked_entry)


@pytest.mark.dependency(
    depends=[
        test_zenodo_book_new_pid.__name__,
    ],
    collect=True,
)
@zenodo_params
def test_zenodo_upload_file_to_draft(file_params: "ParamTestData") -> "None":
    assert isinstance(
        file_params.extra.get("token"), str
    ), "This test needs a valid Zenodo user token"
    assert isinstance(
        file_params.extra.get("sandbox"), bool
    ), "This test needs to know whether to run against sandbox or production"

    naive_path = get_path(os.path.join("data", "naive_file.txt"))
    assert os.path.isfile(naive_path), f"Test file {naive_path} is not available"

    setup_block: "SecurityContextConfig" = {
        "token": file_params.extra["token"],
        "sandbox": file_params.extra["sandbox"],
    }
    zep = ZenodoExportPlugin(
        pathlib.Path(__file__).parent / "data",
        setup_block=setup_block,
    )

    booked_entry = None
    try:
        booked_entry = zep.book_pid()
        assert booked_entry is not None
        assert booked_entry.metadata is not None
        uploaded_file_meta = zep.upload_file_to_draft(
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
            zep.discard_booked_pid(booked_entry)


STREAM_FILENAME = "remote/streamfile.txt"


@pytest.mark.dependency(
    depends=[
        test_zenodo_book_new_pid.__name__,
    ],
    collect=True,
)
@zenodo_params
def test_zenodo_upload_stream_to_draft(file_params: "ParamTestData") -> "None":
    assert isinstance(
        file_params.extra.get("token"), str
    ), "This test needs a valid Zenodo user token"
    assert isinstance(
        file_params.extra.get("sandbox"), bool
    ), "This test needs to know whether to run against sandbox or production"

    naive_path = get_path(os.path.join("data", "naive_file.txt"))
    assert os.path.isfile(naive_path), f"Test file {naive_path} is not available"
    naive_path_size = os.path.getsize(naive_path)

    path_sep = "____"
    setup_block: "SecurityContextConfig" = {
        "token": file_params.extra["token"],
        "sandbox": file_params.extra["sandbox"],
        "path_sep": path_sep,
    }
    zep = ZenodoExportPlugin(pathlib.Path("/tofill"), setup_block=setup_block)

    booked_entry = None
    try:
        booked_entry = zep.book_pid()
        assert booked_entry is not None
        assert booked_entry.metadata is not None
        with open(naive_path, mode="rb") as nH:
            uploaded_file_meta = zep.upload_file_to_draft(
                booked_entry,
                filename=nH,
                remote_filename=STREAM_FILENAME,
                content_size=naive_path_size,
            )
        logger.info(uploaded_file_meta)
        assert uploaded_file_meta.get("key") == STREAM_FILENAME.replace("/", path_sep)
        assert uploaded_file_meta.get("size") == naive_path_size
    except urllib.error.HTTPError as he:
        irbytes = he.read()
        logger.error(f"Error {he.url} {he.code} {he.reason} . Server report:")
        logger.error(irbytes.decode())
        raise he
    finally:
        if booked_entry is not None:
            zep.discard_booked_pid(booked_entry)


@pytest.mark.dependency(
    depends=[
        test_zenodo_book_new_pid.__name__,
    ],
    collect=True,
)
@zenodo_params
def test_zenodo_update_record_metadata_raw(file_params: "ParamTestData") -> "None":
    assert isinstance(
        file_params.extra.get("token"), str
    ), "This test needs a valid Zenodo user token"
    assert isinstance(
        file_params.extra.get("sandbox"), bool
    ), "This test needs to know whether to run against sandbox or production"

    setup_block: "SecurityContextConfig" = {
        "token": file_params.extra["token"],
        "sandbox": file_params.extra["sandbox"],
    }
    zep = ZenodoExportPlugin(pathlib.Path("/tofill"), setup_block=setup_block)

    booked_entry = None
    try:
        booked_entry = zep.book_pid()
        assert booked_entry is not None
        assert booked_entry.metadata is not None
        logger.info(f"Booked PID is {booked_entry.pid}")
        entry_metadata = {
            "title": "My test upload",
            "upload_type": "dataset",
            "description": "This is my test upload",
            "creators": [
                {
                    "name": "Doe, John",
                    "affiliation": "Zenodo",
                }
            ],
        }
        updated_meta = zep.update_record_metadata(booked_entry, entry_metadata)
        logger.info(updated_meta)
        assert entry_metadata["title"] == updated_meta.get("metadata", {}).get("title")
        assert entry_metadata["upload_type"] == updated_meta.get("metadata", {}).get(
            "upload_type"
        )
    except urllib.error.HTTPError as he:
        irbytes = he.read()
        logger.error(f"Error {he.url} {he.code} {he.reason} . Server report:")
        logger.error(irbytes.decode())
        raise he
    finally:
        if booked_entry is not None:
            zep.discard_booked_pid(booked_entry)


@pytest.mark.dependency(
    depends=[
        test_zenodo_book_new_pid.__name__,
    ],
    collect=True,
)
@zenodo_params
def test_zenodo_update_record_metadata_facets(file_params: "ParamTestData") -> "None":
    assert isinstance(
        file_params.extra.get("token"), str
    ), "This test needs a valid Zenodo user token"
    assert isinstance(
        file_params.extra.get("sandbox"), bool
    ), "This test needs to know whether to run against sandbox or production"

    setup_block: "SecurityContextConfig" = {
        "token": file_params.extra["token"],
        "sandbox": file_params.extra["sandbox"],
    }
    zep = ZenodoExportPlugin(pathlib.Path("/tofill"), setup_block=setup_block)

    booked_entry = None
    try:
        test_upload_type = "dataset"
        booked_entry = zep.book_pid(
            initially_required_metadata={
                "upload_type": test_upload_type,
            },
        )
        assert booked_entry is not None
        assert booked_entry.metadata is not None
        logger.info(f"Booked PID is {booked_entry.pid}")
        test_title = "My test upload"
        test_description = "This is my test upload"
        updated_meta = zep.update_record_metadata(
            booked_entry,
            title=test_title,
            description=test_description,
            resolved_orcids=[
                TEST_ORCID,
            ],
            licences=[
                CC_BY_40_LicenceDescription,
            ],
        )
        logger.info(updated_meta)
        assert test_title == updated_meta.get("metadata", {}).get("title")
        assert test_upload_type == updated_meta.get("metadata", {}).get("upload_type")
    except urllib.error.HTTPError as he:
        irbytes = he.read()
        logger.error(f"Error {he.url} {he.code} {he.reason} . Server report:")
        logger.error(irbytes.decode())
        raise he
    finally:
        if booked_entry is not None:
            zep.discard_booked_pid(booked_entry)


@pytest.mark.dependency(
    depends=[
        test_zenodo_upload_file_to_draft.__name__,
        test_zenodo_update_record_metadata_raw.__name__,
    ],
    collect=True,
)
@zenodo_params
def test_zenodo_publish_new_pid(file_params: "ParamTestData") -> "None":
    assert isinstance(
        file_params.extra.get("token"), str
    ), "This test needs a valid Zenodo user token"
    assert isinstance(
        file_params.extra.get("sandbox"), bool
    ), "This test needs to know whether to run against sandbox or production"

    naive_path = get_path(os.path.join("data", "naive_file.txt"))
    assert os.path.isfile(naive_path), f"Test file {naive_path} is not available"

    setup_block: "SecurityContextConfig" = {
        "token": file_params.extra["token"],
        "sandbox": file_params.extra["sandbox"],
    }
    zep = ZenodoExportPlugin(
        pathlib.Path(__file__).parent / "data",
        setup_block=setup_block,
    )

    booked_entry = None
    published_meta = None
    try:
        booked_entry = zep.book_pid()
        assert booked_entry is not None
        assert booked_entry.metadata is not None
        logger.info(f"Booked PID is {booked_entry.pid}")

        uploaded_file_meta = zep.upload_file_to_draft(
            booked_entry,
            filename=naive_path,
            remote_filename=None,
        )
        logger.info(uploaded_file_meta)

        entry_metadata = {
            "title": "My test upload at " + datetime.datetime.utcnow().isoformat(),
            "upload_type": "dataset",
            "description": "This is my test upload at "
            + datetime.datetime.utcnow().isoformat(),
        }
        updated_meta = zep.update_record_metadata(
            booked_entry,
            metadata=entry_metadata,
            resolved_orcids=[
                TEST_ORCID,
            ],
            licences=[
                CC_BY_40_LicenceDescription,
                NoLicenceDescription,
            ],
        )
        logger.info(updated_meta)
        assert entry_metadata["title"] == updated_meta.get("metadata", {}).get("title")
        assert entry_metadata["upload_type"] == updated_meta.get("metadata", {}).get(
            "upload_type"
        )

        published_meta = zep.publish_draft_record(booked_entry)
        logger.info(published_meta)
    except urllib.error.HTTPError as he:
        irbytes = he.read()
        logger.error(f"Error {he.url} {he.code} {he.reason} . Server report:")
        logger.error(irbytes.decode())
        raise he
    finally:
        if booked_entry is not None and published_meta is None:
            zep.discard_booked_pid(booked_entry)
