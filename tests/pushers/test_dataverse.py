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
import json
import logging

import pathlib

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
        Mapping,
        MutableMapping,
        MutableSequence,
        Set,
    )
    from wfexs_backend.common import (
        AbsPath,
        SecurityContextConfig,
        URIType,
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

dataverse_params = pytest.mark.dataverse_params()

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)


@pytest.mark.dependency
def test_dataverse_basic_fail_noapiprefix() -> "None":
    """
    Check Dataverse plugin complains about missing api-prefix parameter
    """
    with pytest.raises(ExportPluginException):
        DataversePublisher(pathlib.Path("/"), setup_block={"token": ""})


@pytest.mark.dependency
def test_dataverse_basic_fail_notoken() -> "None":
    """
    Check Dataverse plugin complains about missing token parameter
    """
    with pytest.raises(ExportPluginException):
        dep = DataversePublisher(
            pathlib.Path("/"), setup_block={"api-prefix": "example.org"}
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
    dep = DataversePublisher(pathlib.Path("/tofill"), setup_block=setup_block)
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
    dep = DataversePublisher(pathlib.Path("/tofill"), setup_block=setup_block)
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
    dep = DataversePublisher(pathlib.Path("/tofill"), setup_block=setup_block)

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
    dep = DataversePublisher(pathlib.Path("/tofill"), setup_block=setup_block)

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
        pathlib.Path("/tofill"),
        setup_block=setup_block,
        default_preferred_id=file_params.extra["owned_existing_pid"],
    )

    orig_booked_entry = None
    booked_entry = None
    try:
        orig_booked_entry = dep.get_pid_draftentry(
            file_params.extra["owned_existing_pid"]
        )
        logger.info(orig_booked_entry)
        assert orig_booked_entry is not None
        assert orig_booked_entry.metadata is not None
        assert orig_booked_entry.metadata.get("versionState") != "DRAFT"

        booked_entry = dep.book_pid()
        logger.info(booked_entry)
        assert booked_entry is not None
        assert booked_entry.metadata is not None
        assert booked_entry.metadata.get("versionState") == "DRAFT"

        assert orig_booked_entry.metadata.get("id") != booked_entry.metadata.get(
            "id"
        ), f"Internal booked PIDs do match {orig_booked_entry.metadata.get('id')} vs {booked_entry.metadata.get('id')}"
    except urllib.error.HTTPError as he:
        irbytes = he.read()
        logger.error(f"Error {he.url} {he.code} {he.reason} . Server report:")
        logger.error(irbytes.decode())
        raise he
    finally:
        if booked_entry is not None:
            logger.info(f"Discarding draft from {booked_entry.draft_id}")
            dep.discard_booked_pid(booked_entry)
        elif (
            orig_booked_entry is not None
            and orig_booked_entry.metadata is not None
            and orig_booked_entry.metadata.get("versionState") != "DRAFT"
        ):
            logger.info(f"Discarding draft from {orig_booked_entry.draft_id}")
            dep.discard_booked_pid(orig_booked_entry)


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
        pathlib.Path(__file__).parent / "data",
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
        assert uploaded_file_meta.get("data", {}).get("files", [])[0]["dataFile"].get(
            "filename"
        ) == os.path.basename(naive_path)
        assert uploaded_file_meta.get("data", {}).get("files", [])[0]["dataFile"].get(
            "filesize"
        ) == os.path.getsize(naive_path)
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
    dep = DataversePublisher(pathlib.Path("/tofill"), setup_block=setup_block)

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
        basename = (
            uploaded_file_meta.get("data", {})
            .get("files", [])[0]["dataFile"]
            .get("filename")
        )
        dirname = (
            uploaded_file_meta.get("data", {}).get("files", [])[0].get("directoryLabel")
        )
        filename = basename if dirname is None else dirname + "/" + basename
        assert filename == STREAM_FILENAME
        assert (
            uploaded_file_meta.get("data", {})
            .get("files", [])[0]["dataFile"]
            .get("filesize")
            == naive_path_size
        )
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
def test_dataverse_update_record_metadata_raw(file_params: "ParamTestData") -> "None":
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
    dep = DataversePublisher(pathlib.Path("/tofill"), setup_block=setup_block)

    booked_entry = None
    try:
        booked_entry = dep.book_pid()
        assert booked_entry is not None
        assert booked_entry.metadata is not None
        logger.info(f"Booked PID is {booked_entry.pid}")
        entry_metadata: "MutableMapping[str, Any]" = cast(
            "MutableMapping[str, Any]",
            copy.deepcopy(booked_entry.metadata),
        )

        field_checks: "MutableMapping[str, Mapping[str, Any]]" = dict()
        for field in (
            entry_metadata.get("metadataBlocks", {})
            .get("citation", {})
            .get("fields", [])
        ):
            if isinstance(field, dict):
                typeName = field.get("typeName")
                if typeName == "title":
                    field_checks[typeName] = field
                    field["value"] = (
                        "My test upload updated at "
                        + datetime.datetime.utcnow().isoformat()
                    )
                elif typeName == "author":
                    field_checks[typeName] = field
                    field["value"] = [
                        {
                            "authorName": {
                                "typeName": "authorName",
                                "multiple": False,
                                "typeClass": "primitive",
                                "value": "Doe, John",
                            }
                        }
                    ]
                elif typeName == "dsDescription":
                    field_checks[typeName] = field
                    field["value"] = [
                        {
                            "dsDescriptionValue": {
                                "typeName": "dsDescriptionValue",
                                "multiple": False,
                                "typeClass": "primitive",
                                "value": "This is my test upload description updated at "
                                + datetime.datetime.utcnow().isoformat(),
                            }
                        }
                    ]
                elif typeName == "subject":
                    field_checks[typeName] = field
                    field["value"] = [
                        "Computer and Information Science",
                    ]

        # logger.info(json.dumps(entry_metadata, indent=4))
        updated_meta = dep.update_record_metadata(
            booked_entry,
            metadata=entry_metadata,
        )
        logger.info(updated_meta)
        checked_types: "Set[str]" = set()
        for field in (
            updated_meta.get("metadataBlocks", {}).get("citation", {}).get("fields", [])
        ):
            typeName = field.get("typeName")
            field_check = field_checks.get(typeName)
            if field_check is not None:
                checked_types.add(typeName)
                assert (
                    field == field_check
                ), f"Metadata inconsistencies in field {typeName}"

        assert checked_types == set(
            field_checks.keys()
        ), "Some of the changed keys were not found"
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
def test_dataverse_update_record_metadata_facets(
    file_params: "ParamTestData",
) -> "None":
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
    dep = DataversePublisher(pathlib.Path("/tofill"), setup_block=setup_block)

    booked_entry = None
    try:
        booked_entry = dep.book_pid()
        assert booked_entry is not None
        assert booked_entry.metadata is not None
        logger.info(f"Booked PID is {booked_entry.pid}")
        entry_metadata: "MutableMapping[str, Any]" = cast(
            "MutableMapping[str, Any]",
            copy.deepcopy(booked_entry.metadata),
        )

        field_checks: "MutableMapping[str, Mapping[str, Any]]" = dict()
        for field in (
            entry_metadata.get("metadataBlocks", {})
            .get("citation", {})
            .get("fields", [])
        ):
            if isinstance(field, dict):
                typeName = field.get("typeName")
                if typeName == "subject":
                    field_checks[typeName] = field
                    field["value"] = [
                        "Computer and Information Science",
                    ]

        # logger.info(json.dumps(entry_metadata, indent=4))
        updated_meta = dep.update_record_metadata(
            booked_entry,
            metadata=entry_metadata,
            title="My test upload updated at " + datetime.datetime.utcnow().isoformat(),
            description="This is my test upload description updated at "
            + datetime.datetime.utcnow().isoformat(),
            resolved_orcids=[
                TEST_ORCID,
            ],
            licences=[
                CC_BY_40_LicenceDescription,
            ],
        )
        logger.info(updated_meta)
        checked_types: "Set[str]" = set()
        for field in (
            updated_meta.get("metadataBlocks", {}).get("citation", {}).get("fields", [])
        ):
            typeName = field.get("typeName")
            field_check = field_checks.get(typeName)
            if field_check is not None:
                checked_types.add(typeName)
                assert (
                    field == field_check
                ), f"Metadata inconsistencies in field {typeName}"

        assert checked_types == set(
            field_checks.keys()
        ), "Some of the changed keys were not found"
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
        # test_dataverse_upload_file_to_draft.__name__,
        test_dataverse_update_record_metadata_raw.__name__,
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
    dep = DataversePublisher(pathlib.Path("/tofill"), setup_block=setup_block)

    booked_entry = None
    published_meta = None
    try:
        booked_entry = dep.book_pid()
        assert booked_entry is not None
        assert booked_entry.metadata is not None
        logger.info(f"Booked PID is {booked_entry.pid}")

        entry_metadata: "MutableMapping[str, Any]" = cast(
            "MutableMapping[str, Any]",
            copy.deepcopy(booked_entry.metadata),
        )

        field_checks: "MutableMapping[str, Mapping[str, Any]]" = dict()
        for field in (
            entry_metadata.get("metadataBlocks", {})
            .get("citation", {})
            .get("fields", [])
        ):
            if isinstance(field, dict):
                typeName = field.get("typeName")
                if typeName == "title":
                    field_checks[typeName] = field
                    field["value"] = (
                        "My test published entry updated at "
                        + datetime.datetime.utcnow().isoformat()
                    )
                elif typeName == "author":
                    field_checks[typeName] = field
                    field["value"] = [
                        {
                            "authorName": {
                                "typeName": "authorName",
                                "multiple": False,
                                "typeClass": "primitive",
                                "value": "Doe, John",
                            }
                        }
                    ]
                elif typeName == "dsDescription":
                    field_checks[typeName] = field
                    field["value"] = [
                        {
                            "dsDescriptionValue": {
                                "typeName": "dsDescriptionValue",
                                "multiple": False,
                                "typeClass": "primitive",
                                "value": "This is my test published entry description updated at "
                                + datetime.datetime.utcnow().isoformat(),
                            }
                        }
                    ]
                elif typeName == "subject":
                    field_checks[typeName] = field
                    field["value"] = [
                        "Computer and Information Science",
                    ]

        # logger.info(json.dumps(entry_metadata, indent=4))
        updated_meta = dep.update_record_metadata(
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
        # checked_types: "Set[str]" = set()
        # for field in (
        #     updated_meta.get("metadataBlocks", {}).get("citation", {}).get("fields", [])
        # ):
        #     typeName = field.get("typeName")
        #     field_check = field_checks.get(typeName)
        #     if field_check is not None:
        #         checked_types.add(typeName)
        #         assert (
        #             field == field_check
        #         ), f"Metadata inconsistencies in field {typeName}"
        #
        # assert checked_types == set(
        #     field_checks.keys()
        # ), "Some of the changed keys were not found"

        published_meta = dep.publish_draft_record(booked_entry)
        logger.info(published_meta)
    except urllib.error.HTTPError as he:
        irbytes = he.read()
        logger.error(f"Error {he.url} {he.code} {he.reason} . Server report:")
        logger.error(irbytes.decode())
        raise he
    finally:
        if booked_entry is not None and published_meta is None:
            dep.discard_booked_pid(booked_entry)
