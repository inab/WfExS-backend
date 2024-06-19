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

import os
import pathlib
import sys
import urllib.error

from wfexs_backend.pushers import ExportPluginException
from wfexs_backend.pushers.nextcloud_export import NextcloudExportPlugin

from typing import (
    cast,
    TYPE_CHECKING,
)

if TYPE_CHECKING:
    from wfexs_backend.common import (
        AbsPath,
        RelPath,
        SecurityContextConfig,
    )
    from pytest_param_files import (  # type: ignore[import]
        ParamTestData,
    )

from tests.common import (
    TEST_ORCID,
)

from tests.util import get_path

from wfexs_backend.common import (
    CC_BY_40_LicenceDescription,
    GeneratedContent,
    NoLicenceDescription,
)


nextcloud_params = pytest.mark.nextcloud_params()

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)


@pytest.mark.dependency
def test_nextcloud_basic_fail_noapiprefix() -> "None":
    """
    Check Nextcloud plugin complains about missing server parameter
    """
    with pytest.raises(ExportPluginException):
        NextcloudExportPlugin(
            cast("AbsPath", "/"),
            setup_block={"base-directory": "/", "user": "", "token": ""},
        )


@pytest.mark.dependency
def test_nextcloud_basic_fail_nobasedir() -> "None":
    """
    Check Nextcloud plugin complains about missing base-directory parameter
    """
    with pytest.raises(ExportPluginException):
        NextcloudExportPlugin(
            cast("AbsPath", "/"),
            setup_block={"api-prefix": "", "user": "", "token": ""},
        )


@pytest.mark.dependency
def test_nextcloud_basic_fail_nouser() -> "None":
    """
    Check Nextcloud plugin complains about missing user parameter
    """
    with pytest.raises(ExportPluginException):
        nep = NextcloudExportPlugin(
            cast("AbsPath", "/"),
            setup_block={"api-prefix": "", "base-directory": "/", "token": ""},
        )


@pytest.mark.dependency
def test_nextcloud_basic_fail_notoken() -> "None":
    """
    Check Nextcloud plugin complains about missing token parameter
    """
    with pytest.raises(ExportPluginException):
        nep = NextcloudExportPlugin(
            cast("AbsPath", "/"),
            setup_block={"api-prefix": "", "base-directory": "/", "user": ""},
        )


basic_deps = [
    test_nextcloud_basic_fail_noapiprefix.__name__,
    test_nextcloud_basic_fail_nobasedir.__name__,
    test_nextcloud_basic_fail_notoken.__name__,
    test_nextcloud_basic_fail_nouser.__name__,
]


@pytest.mark.dependency(depends=basic_deps, collect=True)
@nextcloud_params
def test_nextcloud_basic(file_params: "ParamTestData") -> "None":
    """Basic parsing test."""
    assert isinstance(
        file_params.extra.get("user"), str
    ), "This test needs a valid Nextcloud user"
    assert isinstance(
        file_params.extra.get("token"), str
    ), "This test needs a valid Nextcloud application token"
    assert isinstance(
        file_params.extra.get("api-prefix"), str
    ), "This test needs to know the Nextcloud service API prefix"
    assert isinstance(
        file_params.extra.get("base-directory"), str
    ), "This test needs to know the base directory for all the new directories"

    setup_block: "SecurityContextConfig" = {
        "user": file_params.extra["user"],
        "token": file_params.extra["token"],
        "api-prefix": file_params.extra["api-prefix"],
        "base-directory": file_params.extra["base-directory"],
    }
    nep = NextcloudExportPlugin(cast("AbsPath", "/tofill"), setup_block=setup_block)
    # assert file_params.expected.rstrip() == "Other"
    # file_params.assert_expected("Other", rstrip=True)


@pytest.mark.dependency(depends=basic_deps, collect=True)
@nextcloud_params
def test_nextcloud_get_pid_metadata(file_params: "ParamTestData") -> "None":
    assert isinstance(
        file_params.extra.get("user"), str
    ), "This test needs a valid Nextcloud user"
    assert isinstance(
        file_params.extra.get("token"), str
    ), "This test needs a valid Nextcloud application token"
    assert isinstance(
        file_params.extra.get("api-prefix"), str
    ), "This test needs to know the Nextcloud service API prefix"
    assert isinstance(
        file_params.extra.get("base-directory"), str
    ), "This test needs to know the base directory for all the new directories"
    assert isinstance(
        file_params.extra.get("owned_existing_pid"), str
    ), "This test needs a Nextcloud PID owned by the user"

    setup_block: "SecurityContextConfig" = {
        "user": file_params.extra["user"],
        "token": file_params.extra["token"],
        "api-prefix": file_params.extra["api-prefix"],
        "base-directory": file_params.extra["base-directory"],
    }
    nep = NextcloudExportPlugin(cast("AbsPath", "/tofill"), setup_block=setup_block)
    existing_pid = file_params.extra["owned_existing_pid"]

    pid_metadata = nep.get_pid_metadata(existing_pid)
    logger.info(pid_metadata)
    assert pid_metadata is not None, f"No metadata was obtained for {existing_pid}"


@pytest.mark.dependency(depends=basic_deps, collect=True)
@nextcloud_params
def test_nextcloud_book_new_pid(file_params: "ParamTestData") -> "None":
    assert isinstance(
        file_params.extra.get("user"), str
    ), "This test needs a valid Nextcloud user"
    assert isinstance(
        file_params.extra.get("token"), str
    ), "This test needs a valid Nextcloud application token"
    assert isinstance(
        file_params.extra.get("api-prefix"), str
    ), "This test needs to know the Nextcloud service API prefix"
    assert isinstance(
        file_params.extra.get("base-directory"), str
    ), "This test needs to know the base directory for all the new directories"

    setup_block: "SecurityContextConfig" = {
        "user": file_params.extra["user"],
        "token": file_params.extra["token"],
        "api-prefix": file_params.extra["api-prefix"],
        "base-directory": file_params.extra["base-directory"],
    }
    nep = NextcloudExportPlugin(cast("AbsPath", "/tofill"), setup_block=setup_block)

    booked_entry = None
    try:
        booked_entry = nep.book_pid()
        assert booked_entry is not None
        logger.info(f"Booked PID is {booked_entry.draft_id} {booked_entry.pid}")
    except urllib.error.HTTPError as he:
        irbytes = he.read()
        logger.error(f"Error {he.url} {he.code} {he.reason} . Server report:")
        logger.error(irbytes.decode())
        raise he
    finally:
        if booked_entry is not None:
            nep.discard_booked_pid(booked_entry)


@pytest.mark.dependency(
    depends=[
        test_nextcloud_book_new_pid.__name__,
    ],
    collect=True,
)
@nextcloud_params
def test_nextcloud_book_draft_pid(file_params: "ParamTestData") -> "None":
    assert isinstance(
        file_params.extra.get("user"), str
    ), "This test needs a valid Nextcloud user"
    assert isinstance(
        file_params.extra.get("token"), str
    ), "This test needs a valid Nextcloud application token"
    assert isinstance(
        file_params.extra.get("api-prefix"), str
    ), "This test needs to know the Nextcloud service API prefix"
    assert isinstance(
        file_params.extra.get("base-directory"), str
    ), "This test needs to know the base directory for all the new directories"

    setup_block: "SecurityContextConfig" = {
        "user": file_params.extra["user"],
        "token": file_params.extra["token"],
        "api-prefix": file_params.extra["api-prefix"],
        "base-directory": file_params.extra["base-directory"],
    }
    nep = NextcloudExportPlugin(cast("AbsPath", "/tofill"), setup_block=setup_block)

    booked_entry = None
    booked_entry_take2 = None
    try:
        booked_entry = nep.book_pid()
        logger.info(booked_entry)
        assert booked_entry is not None
        booked_entry_take2 = nep.book_pid(booked_entry.draft_id)
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
            nep.discard_booked_pid(booked_entry)
        if booked_entry_take2 is not None and (
            booked_entry is None or booked_entry_take2.draft_id != booked_entry.draft_id
        ):
            nep.discard_booked_pid(booked_entry_take2)


@pytest.mark.dependency(
    depends=[
        test_nextcloud_book_new_pid.__name__,
    ],
    collect=True,
)
@nextcloud_params
def test_nextcloud_book_new_version_pid(file_params: "ParamTestData") -> "None":
    assert isinstance(
        file_params.extra.get("user"), str
    ), "This test needs a valid Nextcloud user"
    assert isinstance(
        file_params.extra.get("token"), str
    ), "This test needs a valid Nextcloud application token"
    assert isinstance(
        file_params.extra.get("api-prefix"), str
    ), "This test needs to know the Nextcloud service API prefix"
    assert isinstance(
        file_params.extra.get("base-directory"), str
    ), "This test needs to know the base directory for all the new directories"
    assert isinstance(
        file_params.extra.get("owned_existing_pid"), str
    ), "This test needs a Nextcloud PID owned by the user"

    setup_block: "SecurityContextConfig" = {
        "user": file_params.extra["user"],
        "token": file_params.extra["token"],
        "api-prefix": file_params.extra["api-prefix"],
        "base-directory": file_params.extra["base-directory"],
    }

    nep = NextcloudExportPlugin(
        cast("AbsPath", "/tofill"),
        setup_block=setup_block,
        default_preferred_id=file_params.extra["owned_existing_pid"],
    )

    orig_booked_entry = None
    booked_entry = None
    try:
        orig_booked_entry = nep.get_pid_draftentry(
            file_params.extra["owned_existing_pid"]
        )
        assert orig_booked_entry is not None
        booked_entry = nep.book_pid()
        logger.info(booked_entry)
        assert booked_entry is not None
    except urllib.error.HTTPError as he:
        irbytes = he.read()
        logger.error(f"Error {he.url} {he.code} {he.reason} . Server report:")
        logger.error(irbytes.decode())
        raise he
    finally:
        if booked_entry is not None and (
            orig_booked_entry is None
            or orig_booked_entry.draft_id != booked_entry.draft_id
        ):
            nep.discard_booked_pid(booked_entry)


@pytest.mark.dependency(
    depends=[
        test_nextcloud_book_new_pid.__name__,
    ],
    collect=True,
)
@nextcloud_params
def test_nextcloud_upload_file_to_draft(file_params: "ParamTestData") -> "None":
    assert isinstance(
        file_params.extra.get("user"), str
    ), "This test needs a valid Nextcloud user"
    assert isinstance(
        file_params.extra.get("token"), str
    ), "This test needs a valid Nextcloud application token"
    assert isinstance(
        file_params.extra.get("api-prefix"), str
    ), "This test needs to know the Nextcloud service API prefix"
    assert isinstance(
        file_params.extra.get("base-directory"), str
    ), "This test needs to know the base directory for all the new directories"

    naive_path = get_path(os.path.join("data", "naive_file.txt"))
    assert os.path.isfile(naive_path), f"Test file {naive_path} is not available"

    setup_block: "SecurityContextConfig" = {
        "user": file_params.extra["user"],
        "token": file_params.extra["token"],
        "api-prefix": file_params.extra["api-prefix"],
        "base-directory": file_params.extra["base-directory"],
    }
    nep = NextcloudExportPlugin(
        cast("AbsPath", os.path.dirname(naive_path)),
        setup_block=setup_block,
    )

    booked_entry = None
    try:
        booked_entry = nep.book_pid()
        assert booked_entry is not None
        assert booked_entry.metadata is not None
        uploaded_file_meta = nep.upload_file_to_draft(
            booked_entry,
            filename=naive_path,
            remote_filename=None,
        )
        logger.info(uploaded_file_meta)
        remote_path = uploaded_file_meta.get("remote_path")
        assert remote_path is not None
        assert remote_path.startswith(file_params.extra["base-directory"])
        remote_relpath = uploaded_file_meta.get("remote_relpath")
        assert remote_relpath is not None
        assert remote_path.endswith(remote_relpath)
    except urllib.error.HTTPError as he:
        irbytes = he.read()
        logger.error(f"Error {he.url} {he.code} {he.reason} . Server report:")
        logger.error(irbytes.decode())
        raise he
    finally:
        if booked_entry is not None:
            nep.discard_booked_pid(booked_entry)


STREAM_FILENAME = "remote/streamfile.txt"


@pytest.mark.dependency(
    depends=[
        test_nextcloud_book_new_pid.__name__,
    ],
    collect=True,
)
@nextcloud_params
def test_nextcloud_upload_stream_to_draft(file_params: "ParamTestData") -> "None":
    assert isinstance(
        file_params.extra.get("user"), str
    ), "This test needs a valid Nextcloud user"
    assert isinstance(
        file_params.extra.get("token"), str
    ), "This test needs a valid Nextcloud application token"
    assert isinstance(
        file_params.extra.get("api-prefix"), str
    ), "This test needs to know the Nextcloud service API prefix"
    assert isinstance(
        file_params.extra.get("base-directory"), str
    ), "This test needs to know the base directory for all the new directories"

    naive_path = get_path(os.path.join("data", "naive_file.txt"))
    assert os.path.isfile(naive_path), f"Test file {naive_path} is not available"
    naive_path_size = os.path.getsize(naive_path)

    setup_block: "SecurityContextConfig" = {
        "user": file_params.extra["user"],
        "token": file_params.extra["token"],
        "api-prefix": file_params.extra["api-prefix"],
        "base-directory": file_params.extra["base-directory"],
    }
    nep = NextcloudExportPlugin(cast("AbsPath", "/tofill"), setup_block=setup_block)

    booked_entry = None
    try:
        booked_entry = nep.book_pid()
        assert booked_entry is not None
        assert booked_entry.metadata is not None
        with open(naive_path, mode="rb") as nH:
            uploaded_file_meta = nep.upload_file_to_draft(
                booked_entry,
                filename=nH,
                remote_filename=STREAM_FILENAME,
                content_size=naive_path_size,
            )
        logger.info(uploaded_file_meta)
        remote_path = uploaded_file_meta.get("remote_path")
        assert remote_path is not None
        assert remote_path.startswith(file_params.extra["base-directory"])
        remote_relpath = uploaded_file_meta.get("remote_relpath")
        assert remote_relpath is not None
        assert remote_path.endswith(remote_relpath)
    except urllib.error.HTTPError as he:
        irbytes = he.read()
        logger.error(f"Error {he.url} {he.code} {he.reason} . Server report:")
        logger.error(irbytes.decode())
        raise he
    finally:
        if booked_entry is not None:
            nep.discard_booked_pid(booked_entry)


# @pytest.mark.dependency(
#    depends=[
#        test_nextcloud_book_new_pid.__name__,
#    ],
#    collect=True,
# )
@pytest.mark.skip
@nextcloud_params
def test_nextcloud_update_record_metadata_raw(file_params: "ParamTestData") -> "None":
    assert isinstance(
        file_params.extra.get("user"), str
    ), "This test needs a valid Nextcloud user"
    assert isinstance(
        file_params.extra.get("token"), str
    ), "This test needs a valid Nextcloud application token"
    assert isinstance(
        file_params.extra.get("api-prefix"), str
    ), "This test needs to know the Nextcloud service API prefix"
    assert isinstance(
        file_params.extra.get("base-directory"), str
    ), "This test needs to know the base directory for all the new directories"

    setup_block: "SecurityContextConfig" = {
        "user": file_params.extra["user"],
        "token": file_params.extra["token"],
        "api-prefix": file_params.extra["api-prefix"],
        "base-directory": file_params.extra["base-directory"],
    }
    nep = NextcloudExportPlugin(cast("AbsPath", "/tofill"), setup_block=setup_block)

    booked_entry = None
    try:
        booked_entry = nep.book_pid()
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
        updated_meta = nep.update_record_metadata(booked_entry, entry_metadata)
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
            nep.discard_booked_pid(booked_entry)


# @pytest.mark.dependency(
#    depends=[
#        test_nextcloud_book_new_pid.__name__,
#    ],
#    collect=True,
# )
@pytest.mark.skip
@nextcloud_params
def test_nextcloud_update_record_metadata_facets(
    file_params: "ParamTestData",
) -> "None":
    assert isinstance(
        file_params.extra.get("user"), str
    ), "This test needs a valid Nextcloud user"
    assert isinstance(
        file_params.extra.get("token"), str
    ), "This test needs a valid Nextcloud application token"
    assert isinstance(
        file_params.extra.get("api-prefix"), str
    ), "This test needs to know the Nextcloud service API prefix"
    assert isinstance(
        file_params.extra.get("base-directory"), str
    ), "This test needs to know the base directory for all the new directories"

    setup_block: "SecurityContextConfig" = {
        "user": file_params.extra["user"],
        "token": file_params.extra["token"],
        "api-prefix": file_params.extra["api-prefix"],
        "base-directory": file_params.extra["base-directory"],
    }
    nep = NextcloudExportPlugin(cast("AbsPath", "/tofill"), setup_block=setup_block)

    booked_entry = None
    try:
        test_upload_type = "dataset"
        booked_entry = nep.book_pid(
            initially_required_metadata={
                "upload_type": test_upload_type,
            },
        )
        assert booked_entry is not None
        assert booked_entry.metadata is not None
        logger.info(f"Booked PID is {booked_entry.pid}")
        test_title = "My test upload"
        test_description = "This is my test upload"
        updated_meta = nep.update_record_metadata(
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
            nep.discard_booked_pid(booked_entry)


@pytest.mark.dependency(
    depends=[
        test_nextcloud_upload_file_to_draft.__name__,
        #        test_nextcloud_update_record_metadata_raw.__name__,
    ],
    collect=True,
)
@nextcloud_params
def test_nextcloud_publish_new_pid(file_params: "ParamTestData") -> "None":
    assert isinstance(
        file_params.extra.get("user"), str
    ), "This test needs a valid Nextcloud user"
    assert isinstance(
        file_params.extra.get("token"), str
    ), "This test needs a valid Nextcloud application token"
    assert isinstance(
        file_params.extra.get("api-prefix"), str
    ), "This test needs to know the Nextcloud service API prefix"
    assert isinstance(
        file_params.extra.get("base-directory"), str
    ), "This test needs to know the base directory for all the new directories"

    naive_path = get_path(os.path.join("data", "naive_file.txt"))
    assert os.path.isfile(naive_path), f"Test file {naive_path} is not available"

    setup_block: "SecurityContextConfig" = {
        "user": file_params.extra["user"],
        "token": file_params.extra["token"],
        "api-prefix": file_params.extra["api-prefix"],
        "base-directory": file_params.extra["base-directory"],
    }
    nep = NextcloudExportPlugin(
        cast("AbsPath", os.path.join(os.path.dirname(__file__), "data")),
        setup_block=setup_block,
    )

    booked_entry = None
    published_meta = None
    try:
        booked_entry = nep.book_pid()
        assert booked_entry is not None
        assert booked_entry.metadata is not None
        logger.info(f"Booked PID is {booked_entry.pid}")

        uploaded_file_meta = nep.upload_file_to_draft(
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
        updated_meta = nep.update_record_metadata(
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

        published_meta = nep.publish_draft_record(booked_entry)
        logger.info(published_meta)
    except urllib.error.HTTPError as he:
        irbytes = he.read()
        logger.error(f"Error {he.url} {he.code} {he.reason} . Server report:")
        logger.error(irbytes.decode())
        raise he
    finally:
        if booked_entry is not None and published_meta is None:
            nep.discard_booked_pid(booked_entry)


@pytest.mark.dependency(
    depends=[
        test_nextcloud_publish_new_pid.__name__,
    ],
    collect=True,
)
@nextcloud_params
def test_nextcloud_push(file_params: "ParamTestData") -> "None":
    assert isinstance(
        file_params.extra.get("user"), str
    ), "This test needs a valid Nextcloud user"
    assert isinstance(
        file_params.extra.get("token"), str
    ), "This test needs a valid Nextcloud application token"
    assert isinstance(
        file_params.extra.get("api-prefix"), str
    ), "This test needs to know the Nextcloud service API prefix"
    assert isinstance(
        file_params.extra.get("base-directory"), str
    ), "This test needs to know the base directory for all the new directories"

    naive_path = get_path(os.path.join("data", "naive_file.txt"))
    assert os.path.isfile(naive_path), f"Test file {naive_path} is not available"

    setup_block: "SecurityContextConfig" = {
        "user": file_params.extra["user"],
        "token": file_params.extra["token"],
        "api-prefix": file_params.extra["api-prefix"],
        "base-directory": file_params.extra["base-directory"],
    }
    nep = NextcloudExportPlugin(
        cast("AbsPath", os.path.join(os.path.dirname(__file__), "data")),
        setup_block=setup_block,
    )

    booked_entry = None
    published_meta = None
    try:
        entry_metadata = {
            "title": "My test upload at " + datetime.datetime.utcnow().isoformat(),
            "upload_type": "dataset",
            "description": "This is my test upload at "
            + datetime.datetime.utcnow().isoformat(),
        }

        booked_entry = nep.book_pid()
        assert booked_entry is not None

        pushed_entries = nep.push(
            preferred_id=booked_entry.draft_id,
            items=[
                GeneratedContent(
                    local=pathlib.Path(naive_path),
                ),
                GeneratedContent(
                    local=pathlib.Path(naive_path),
                    preferredFilename=cast("RelPath", STREAM_FILENAME),
                ),
            ],
            metadata=entry_metadata,
            resolved_orcids=[
                TEST_ORCID,
            ],
            licences=[
                CC_BY_40_LicenceDescription,
                NoLicenceDescription,
            ],
        )
        assert pushed_entries is not None
        assert booked_entry.metadata is not None
        logger.info(f"Booked PID is {booked_entry.pid}")
    except urllib.error.HTTPError as he:
        irbytes = he.read()
        logger.error(f"Error {he.url} {he.code} {he.reason} . Server report:")
        logger.error(irbytes.decode())
        raise he
    finally:
        if booked_entry is not None:
            nep.discard_booked_pid(booked_entry)
