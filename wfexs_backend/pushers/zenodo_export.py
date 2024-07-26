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

import copy
import datetime

# import http.cookiejar
import json
import logging
import os
from typing import (
    cast,
    NamedTuple,
    TYPE_CHECKING,
)
import urllib.error
import urllib.parse
import urllib.request
import uuid

from ..common import (
    MaterializedContent,
    URIWithMetadata,
)

if TYPE_CHECKING:
    import pathlib
    from typing import (
        Any,
        ClassVar,
        IO,
        Mapping,
        MutableMapping,
        MutableSet,
        Optional,
        Sequence,
        Set,
        Tuple,
        Union,
    )

    from typing_extensions import (
        Final,
    )

    from ..common import (
        AbsPath,
        AnyContent,
        LicenceDescription,
        RelPath,
        ResolvedORCID,
        SecurityContextConfig,
        SymbolicName,
        URIType,
    )

    from ..workflow import WF

from . import (
    DraftEntry,
    ExportPluginException,
)

from .abstract_token_sandboxed_export import (
    AbstractTokenSandboxedExportPlugin,
)


class ZenodoExportPlugin(AbstractTokenSandboxedExportPlugin):
    """
    Class to model exporting results to Zenodo
    """

    PLUGIN_NAME: "ClassVar[SymbolicName]" = cast("SymbolicName", "zenodo")

    # Is this implementation ready?
    ENABLED: "ClassVar[bool]" = True

    ZENODO_PREFIX: "Final[str]" = "https://zenodo.org"
    SANDBOX_ZENODO_PREFIX: "Final[str]" = "https://sandbox.zenodo.org"

    DEFAULT_REMOTE_PATH_SEPARATOR: "Final[str]" = "__"

    def __init__(
        self,
        refdir: "pathlib.Path",
        setup_block: "Optional[SecurityContextConfig]" = None,
        default_licences: "Sequence[LicenceDescription]" = [],
        default_orcids: "Sequence[ResolvedORCID]" = [],
        default_preferred_id: "Optional[str]" = None,
    ):
        super().__init__(
            refdir=refdir,
            setup_block=setup_block,
            default_licences=default_licences,
            default_orcids=default_orcids,
            default_preferred_id=default_preferred_id,
        )

        self.path_sep = self.setup_block.get(
            "path_sep", self.DEFAULT_REMOTE_PATH_SEPARATOR
        )
        if "/" in self.path_sep:
            raise ValueError("Path separator used in Zenodo file uploads cannot be '/'")

        self.zenodo_prefix = (
            self.SANDBOX_ZENODO_PREFIX if self.sandbox else self.ZENODO_PREFIX
        )
        self.deposit_api_prefix = self.api_prefix + "deposit/"
        self.depositions_api_prefix = self.deposit_api_prefix + "depositions"
        self.records_api_prefix = self.api_prefix + "records"

        # self._shared_cookie_jar = http.cookiejar.CookieJar()
        # cookieproc = urllib.request.HTTPCookieProcessor(self._shared_cookie_jar)
        # self.cookie_opener = urllib.request.build_opener(cookieproc).open
        #
        # firstreq = urllib.request.Request(
        #    url=self.deposit_api_prefix + "depositions",
        #    headers={
        #        "Accept": "application/json",
        #        **self._gen_headers()
        #    },
        #    method="GET",
        # )
        # with urllib.request.urlopen(firstreq) as eH:
        #    pass

    def get_api_prefix(self) -> "str":
        zenodo_prefix = (
            self.SANDBOX_ZENODO_PREFIX if self.sandbox else self.ZENODO_PREFIX
        )
        return zenodo_prefix + "/api/"

    def _gen_headers(self) -> "MutableMapping[str, str]":
        return {
            "Authorization": f"Bearer {self.api_token}",
            "Referer": self.zenodo_prefix,
        }

    def book_pid(
        self,
        preferred_id: "Optional[str]" = None,
        initially_required_metadata: "Optional[Mapping[str, Any]]" = None,
        initially_required_community_specific_metadata: "Optional[Mapping[str, Any]]" = None,
        title: "Optional[str]" = None,
        description: "Optional[str]" = None,
        licences: "Sequence[LicenceDescription]" = [],
        resolved_orcids: "Sequence[ResolvedORCID]" = [],
    ) -> "Optional[DraftEntry]":
        draft_id, pid, draft_metadata = self._book_pid_internal(
            preferred_id=preferred_id,
            initially_required_metadata=initially_required_metadata,
            title=title,
            description=description,
            licences=licences,
            resolved_orcids=resolved_orcids,
        )
        if draft_id is None:
            return None

        return DraftEntry(
            draft_id=draft_id,
            pid=cast("str", pid),
            metadata=draft_metadata,
            raw_metadata=draft_metadata,
        )

    def _book_pid_internal(
        self,
        preferred_id: "Optional[str]" = None,
        initially_required_metadata: "Optional[Mapping[str, Any]]" = None,
        title: "Optional[str]" = None,
        description: "Optional[str]" = None,
        licences: "Sequence[LicenceDescription]" = [],
        resolved_orcids: "Sequence[ResolvedORCID]" = [],
    ) -> "Tuple[Optional[str], Optional[str], Optional[Mapping[str, Any]]]":
        """
        We are booking a new PID, in case the default
        preferred id is None or an invalid one
        """
        if preferred_id is None:
            preferred_id = self.default_preferred_id

        booked_meta: "Optional[Mapping[str, Any]]" = None
        fill_in_new_entry = True
        newentry_url: "Optional[str]" = None
        if preferred_id is not None:
            booked_meta = self.get_pid_metadata(preferred_id)
            if booked_meta is not None:
                # TODO: check whether the entry is still a draft
                booked_id = booked_meta.get("id")
                # Booked
                if booked_id is not None:
                    fill_in_new_entry = False
                    # Submitted
                    if booked_meta.get("submitted", False):
                        # Built the request url for new version
                        newentry_url = (
                            booked_meta["links"]["latest_draft"] + "/actions/newversion"
                        )
                    else:
                        preferred_id = str(booked_id)
                else:
                    self.logger.info(
                        f"Discarding pre-booked {preferred_id} Zenodo entry id reusage"
                    )
            else:
                self.logger.info(
                    f"Discarding pre-booked {preferred_id} Zenodo entry id reusage"
                )

        if fill_in_new_entry:
            # Book new entry
            newentry_url = self.depositions_api_prefix

        if newentry_url is not None:
            # Setting up the initial metadata
            initial_metadata_entry = {}
            modifiable_metadata: "Optional[MutableMapping[str, Any]]" = None
            if (
                initially_required_metadata is not None
                and len(initially_required_metadata) > 0
            ):
                modifiable_metadata = cast(
                    "MutableMapping[str, Any]",
                    copy.deepcopy(initially_required_metadata),
                )

            if len(licences) == 0 and len(self.default_licences) > 0:
                licences = self.default_licences

            if len(resolved_orcids) == 0 and len(self.default_orcids) > 0:
                resolved_orcids = self.default_orcids

            if modifiable_metadata is None:
                # A dataset is being uploaded
                modifiable_metadata = {}

            if modifiable_metadata.get("upload_type") is None:
                modifiable_metadata["upload_type"] = "dataset"

            if (
                title is not None
                or description is not None
                or len(licences) > 0
                or len(resolved_orcids) > 0
            ):
                if title is not None:
                    modifiable_metadata["title"] = title

                if description is not None:
                    modifiable_metadata["description"] = description

                if len(licences) > 0:
                    # Zenodo has a severe restriction in its REST API
                    # Only first licence is include due a severe limitation
                    # of REST API
                    # modifiable_metadata["license"] = [
                    #     {
                    #         "id": licence.short
                    #     }
                    #     for licence in licences
                    # ]
                    modifiable_metadata["license"] = {"id": licences[0].short}
                    if len(licences) > 1:
                        self.logger.warning(
                            f"Only the first licence was attached to record due Zenodo technical limitations"
                        )

                if len(resolved_orcids) > 0:
                    creators = [
                        {
                            "name": resolved_orcid.record["displayName"],
                            "orcid": resolved_orcid.orcid,
                        }
                        for resolved_orcid in resolved_orcids
                    ]
                    modifiable_metadata["creators"] = creators

            if modifiable_metadata is not None:
                initial_metadata_entry["metadata"] = modifiable_metadata

            req = urllib.request.Request(
                url=newentry_url,
                data=json.dumps(initial_metadata_entry).encode("utf-8"),
                headers={"Content-Type": "application/json", **self._gen_headers()},
            )
            try:
                with urllib.request.urlopen(req) as bH:
                    booked_meta = json.load(bH)
                    assert booked_meta is not None
                    booked_id = booked_meta.get("id")
                    if booked_id is not None:
                        preferred_id = str(booked_id)
            except urllib.error.HTTPError as he:
                errmsg = f"{self._customized_book_pid_error_string} using {newentry_url}. Server response: {he.read().decode('utf-8')}"
                self.logger.exception(errmsg)
                # for cookie in self._shared_cookie_jar:
                #    self.logger.error(f"Cookie: {cookie.name}, {cookie.value}")
                raise ExportPluginException(errmsg) from he

        # At this point, new entry has been booked
        internal_id: "Optional[str]" = None
        if booked_meta is not None:
            prereserve_doi = booked_meta.get("metadata", {}).get("prereserve_doi", {})
            if prereserve_doi:
                preferred_id = "doi:" + prereserve_doi["doi"]
                internal_id = str(prereserve_doi["recid"])

        # It should be the doi
        return internal_id, preferred_id, booked_meta

    @property
    def _customized_book_pid_error_string(self) -> "str":
        """
        This method can be overridden to provide more context
        """
        return "Unable to book a Zenodo entry"

    def discard_booked_pid(self, pid_or_draft: "Union[str, DraftEntry]") -> "bool":
        if isinstance(pid_or_draft, DraftEntry):
            pid = pid_or_draft.draft_id
        else:
            pid = pid_or_draft

        discard_link: "Optional[str]" = None
        booked_meta = self.get_pid_metadata(pid)
        if booked_meta is not None:
            # TODO: check whether the entry is still a draft
            booked_id = booked_meta.get("id")
            # Booked
            if booked_id is not None:
                fill_in_new_entry = False
                # Submitted
                if not booked_meta.get("submitted", False):
                    discard_link = booked_meta.get("links", {}).get("discard")
            else:
                self.logger.debug(f"Ineligible {pid} Zenodo entry")
        else:
            self.logger.debug(f"Unable to find {pid} Zenodo entry id")

        # Last, release!
        if discard_link is not None:
            discardreq = urllib.request.Request(
                url=discard_link,
                headers={"Content-Type": "application/json", **self._gen_headers()},
                method="POST",
            )
            try:
                with urllib.request.urlopen(discardreq) as pH:
                    return True
            except Exception as e:
                self.logger.exception(f"Failed to discard entry {pid}")
                raise ExportPluginException(f"Failed to discard entry {pid}") from e

        return False

    def get_pid_metadata(self, pid: "str") -> "Optional[Mapping[str, Any]]":
        # Was the preferred_id already booked?
        # Requesting from the server
        if pid.isnumeric():
            req = urllib.request.Request(
                url=self.depositions_api_prefix + "/" + pid,
                headers={"Accept": "application/json", **self._gen_headers()},
            )
            try:
                with urllib.request.urlopen(req) as bH:
                    retval = json.load(bH)
                    return cast("Mapping[str, Any]", retval)
            except:
                self.logger.exception(f"Unable to fetch info about {pid} Zenodo entry")

        else:
            # Preparing for the search
            if pid.startswith("doi:"):
                pid = pid[len("doi:") :]
            curated_pid = '"' + pid.replace('"', '\\"') + '"'
            query = {
                "q": f"conceptdoi:{curated_pid} doi:{curated_pid} recid:{curated_pid}",
                #            "q": f'recid:{curated_pid}',
                "status": "draft",
            }

            req = urllib.request.Request(
                url=self.records_api_prefix
                + "?"
                + urllib.parse.urlencode(query, encoding="utf-8"),
                headers={"Accept": "application/json", **self._gen_headers()},
            )
            # req = urllib.request.Request(
            #    url=self.deposit_api_prefix + "depositions/" + urllib.parse.quote(pid, safe=""),
            #    headers={
            #        "Accept": "application/json",
            #        **self._gen_headers()
            #    },
            # )
            try:
                with urllib.request.urlopen(req) as bH:
                    retval = json.load(bH)
                    if (
                        isinstance(retval, dict)
                        and len(retval.get("hits", {}).get("hits", [])) > 0
                    ):
                        return cast("Mapping[str, Any]", retval["hits"]["hits"][0])
            except:
                self.logger.exception(f"Unable to fetch info about {pid} Zenodo entry")

        return None

    def get_file_bucket_prefix(
        self,
        draft_entry: "DraftEntry",
    ) -> "str":
        """
        This is an accessory method which is used to build upload paths
        """
        assert draft_entry.metadata is not None
        upload_bucket_prefix = cast(
            "Optional[str]", draft_entry.metadata.get("links", {}).get("bucket")
        )
        assert upload_bucket_prefix is not None
        upload_bucket_prefix += "/"

        return upload_bucket_prefix

    def upload_file_to_draft(
        self,
        draft_entry: "DraftEntry",
        filename: "Union[str, IO[bytes]]",
        remote_filename: "Optional[str]",
        content_size: "Optional[int]" = None,
    ) -> "Mapping[str, Any]":
        upload_bucket_prefix = self.get_file_bucket_prefix(draft_entry)

        pH: "IO[bytes]"
        if isinstance(filename, str):
            pH = open(filename, mode="rb")
            content_size = os.stat(filename).st_size
            if remote_filename is None:
                remote_filename = os.path.relpath(filename, self.refdir)

            mesg = "file " + filename
        else:
            assert isinstance(
                remote_filename, str
            ), "When filename is a data stream, remote_filename must be declared"
            assert (
                content_size is not None
            ), "When filename is a data stream, content_size must be declared"
            pH = filename
            mesg = "stream"

        # As Zenodo (as of 2024-03-04) https://github.com/zenodo/zenodo/issues/1089
        # the remote filename cannot represent nested directories.
        # So, let's substitute the directory separator
        remote_filename = remote_filename.replace("/", self.path_sep)

        self.logger.info(
            f"Uploading {mesg} to {upload_bucket_prefix + urllib.parse.quote(remote_filename)}"
        )

        try:
            putreq = urllib.request.Request(
                url=upload_bucket_prefix + urllib.parse.quote(remote_filename),
                data=pH,
                method="PUT",
                headers={
                    # The content type must be always this, to avoid a 415
                    "Content-Type": "application/octet-stream",
                    "Content-Length": str(content_size),
                    **self._gen_headers(),
                },
            )
            with urllib.request.urlopen(putreq) as pr:
                upload_response = cast("Mapping[str, Any]", json.load(pr))
        except urllib.error.HTTPError as he:
            self.logger.error(
                f"There was some problem uploading {remote_filename} to {upload_bucket_prefix}. Server response: {he.read().decode('utf-8')}"
            )
            raise
        finally:
            if pH != filename:
                pH.close()

        return upload_response

    def update_record_metadata(
        self,
        draft_entry: "DraftEntry",
        metadata: "Optional[Mapping[str, Any]]" = None,
        community_specific_metadata: "Optional[Mapping[str, Any]]" = None,
        title: "Optional[str]" = None,
        description: "Optional[str]" = None,
        licences: "Sequence[LicenceDescription]" = [],
        resolved_orcids: "Sequence[ResolvedORCID]" = [],
    ) -> "Mapping[str, Any]":
        assert draft_entry.metadata is not None
        record = draft_entry.metadata

        modifiable_metadata = cast("Optional[MutableMapping[str, Any]]", metadata)

        if (
            title is not None
            or description is not None
            or len(licences) > 0
            or len(resolved_orcids) > 0
        ):
            if metadata is None:
                # In this case, we need the metadata as it is, in order to avoid
                # "forgetting" already set metadata
                fetched_metadata = self.get_pid_metadata(draft_entry.draft_id)
                if fetched_metadata is None:
                    raise ExportPluginException(
                        f"Zenodo draft/entry {draft_entry.draft_id} is unavailable"
                    )
                else:
                    modifiable_metadata = fetched_metadata.get("metadata", {})
                    assert modifiable_metadata is not None
            else:
                modifiable_metadata = cast(
                    "MutableMapping[str, Any]", copy.copy(metadata)
                )

            if title is not None:
                modifiable_metadata["title"] = title

            if description is not None:
                modifiable_metadata["description"] = description

            if len(licences) > 0:
                # Only first licence is include due a severe limitation
                # of REST API
                # modifiable_metadata["license"] = [
                #     {
                #         "id": licence.short
                #     }
                #     for licence in licences
                # ]
                modifiable_metadata["license"] = {"id": licences[0].short}
                if len(licences) > 1:
                    self.logger.warning(
                        f"Only the first licence was attached to record {draft_entry.pid} due Zenodo technical limitations"
                    )

            if len(resolved_orcids) > 0:
                creators = [
                    {
                        "name": resolved_orcid.record["displayName"],
                        "orcid": resolved_orcid.orcid,
                    }
                    for resolved_orcid in resolved_orcids
                ]
                modifiable_metadata["creators"] = creators

        # This might not be needed
        if modifiable_metadata is not None:
            metareq = urllib.request.Request(
                url=record.get("links", {}).get("self"),
                data=json.dumps({"metadata": modifiable_metadata}).encode("utf-8"),
                headers={"Content-Type": "application/json", **self._gen_headers()},
                method="PUT",
            )
            try:
                with urllib.request.urlopen(metareq) as mH:
                    meta_update = cast("Mapping[str, Any]", json.load(mH))
            except:
                raise ExportPluginException("Failed to update metadata")
        else:
            meta_update = {}

        return meta_update

    def publish_draft_record(self, draft_entry: "DraftEntry") -> "Mapping[str, Any]":
        assert draft_entry.metadata is not None
        draft_record = draft_entry.metadata

        pubreq = urllib.request.Request(
            url=draft_record.get("links", {}).get("publish"),
            headers={"Content-Type": "application/json", **self._gen_headers()},
            method="POST",
        )
        try:
            with urllib.request.urlopen(pubreq) as pH:
                pub_update = cast("Mapping[str, Any]", json.load(pH))
        except urllib.error.HTTPError as he:
            self.logger.error(
                f"There was some problem publishing {draft_entry.pid}. Server response: {he.read().decode('utf-8')}"
            )
            raise ExportPluginException(
                f"Failed to publish entry {draft_entry.pid}"
            ) from he
        except Exception as e:
            raise ExportPluginException(
                f"Unexpected failure publishing entry {draft_entry.pid}"
            ) from e

        return pub_update
