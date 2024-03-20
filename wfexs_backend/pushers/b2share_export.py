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
import functools
import json
import os
import re
from typing import (
    cast,
    TYPE_CHECKING,
)
import urllib.error
import urllib.parse
import urllib.request
import uuid

import jsonschema.validators
import jsonpointer

from ..common import (
    MaterializedContent,
    URIWithMetadata,
)

if TYPE_CHECKING:
    from typing import (
        Any,
        ClassVar,
        IO,
        Mapping,
        MutableMapping,
        MutableSequence,
        Optional,
        Sequence,
        Set,
        Tuple,
        Type,
        Union,
    )

    from jsonschema.exceptions import ValidationError

    from typing_extensions import (
        Final,
    )

    from ..common import (
        AbsPath,
        AnyContent,
        RelPath,
        SecurityContextConfig,
        SymbolicName,
        URIType,
    )

from . import (
    DraftEntry,
    ExportPluginException,
)

from .abstract_token_sandboxed_export import (
    AbstractTokenSandboxedExportPlugin,
)


# These are the supported JSON Schema validators
INTROSPECT_VALIDATOR_MAPPER: "Mapping[str, Type[jsonschema.validators._Validator]]" = {
    j_valid.META_SCHEMA["$schema"]: cast(
        "Type[jsonschema.validators._Validator]", j_valid
    )
    for j_valid in filter(
        lambda j_val: hasattr(j_val, "META_SCHEMA")
        and isinstance(j_val.META_SCHEMA, dict),
        jsonschema.validators.__dict__.values(),
    )
}


class B2SHAREPublisher(AbstractTokenSandboxedExportPlugin):
    """
    See https://eudat.eu/services/userdoc/b2share-http-rest-api
    """

    PLUGIN_NAME: "ClassVar[SymbolicName]" = cast("SymbolicName", "b2share")

    # Is this implementation ready?
    ENABLED: "ClassVar[bool]" = False

    B2SHARE_API_PREFIX: "Final[str]" = "https://b2share.eudat.eu/api/"
    SANDBOX_B2SHARE_API_PREFIX: "Final[str]" = "https://trng-b2share.eudat.eu/api/"

    B2SHARE_DOI_PREFIX: "Final[str]" = "10.23728/b2share."
    SANDBOX_B2SHARE_DOI_PREFIX: "Final[str]" = "XXXX/b2share."

    DEFAULT_B2SHARE_COMMUNITY: "Final[str]" = "EUDAT"

    BANNED_SCHEMA_KEYS: "Final[Sequence[str]]" = [
        "$future_doi",
        "owners",
    ]

    def __init__(
        self,
        refdir: "AbsPath",
        setup_block: "Optional[SecurityContextConfig]" = None,
        licences: "Sequence[URIType]" = [],
        orcids: "Sequence[str]" = [],
        preferred_id: "Optional[str]" = None,
    ):
        super().__init__(
            refdir=refdir,
            setup_block=setup_block,
            licences=licences,
            orcids=orcids,
            preferred_id=preferred_id,
        )

        if self.sandbox:
            self.api_prefix = self.SANDBOX_B2SHARE_API_PREFIX
            self.b2share_doi_prefix = self.SANDBOX_B2SHARE_DOI_PREFIX
        else:
            self.api_prefix = self.B2SHARE_API_PREFIX
            self.b2share_doi_prefix = self.B2SHARE_DOI_PREFIX

        community_id_or_name = cast(
            "Optional[str]", self.setup_block.get("community_id")
        )
        community_metadata = self.get_community_metadata(community_id_or_name)
        if community_metadata is None:
            # Worst case, no resolution, it will fail in the near future
            errmsg = f"Unable to fetch metadata about community {community_id_or_name} from {self.api_prefix}. Does it exist?"
            self.logger.fatal(errmsg)
            raise KeyError(errmsg)
        else:
            self.community_metadata = community_metadata
            self.community_id = cast("str", community_metadata["id"])

    def get_community_metadata(
        self, community_id_or_name: "Optional[str]"
    ) -> "Optional[Mapping[str, Any]]":
        if community_id_or_name is None:
            community_id_or_name = self.DEFAULT_B2SHARE_COMMUNITY

        # Fetch this metadata just once
        req = urllib.request.Request(self._get_community_api_prefix(""))
        with urllib.request.urlopen(req) as res:
            hits = cast("Mapping[str, Any]", json.load(res))
            for community in hits.get("hits", {}).get("hits", []):
                community_metadata = cast("Mapping[str, Any]", community)
                if (
                    community_metadata.get("id") == community_id_or_name
                    or community_metadata.get("name") == community_id_or_name
                ):
                    return community_metadata

        return None

    def _get_community_api_prefix(self, community_id: "str") -> "str":
        return self.api_prefix + f"communities/{urllib.parse.quote_plus(community_id)}"

    def _get_community_metadata(self, community_id: "str") -> "Mapping[str, Any]":
        """
        DEPRECATED
        """
        req = urllib.request.Request(self._get_community_api_prefix(community_id))
        with urllib.request.urlopen(req) as res:
            return cast("Mapping[str, Any]", json.load(res))

    @staticmethod
    @functools.lru_cache
    def __fetch_schema(
        schema_url: "str",
    ) -> "Tuple[str, Mapping[str, Any]]":
        req = urllib.request.Request(schema_url)
        with urllib.request.urlopen(req) as res:
            community_metadata_schema = json.load(res)
            # We are keeping only what we are interested in
            parsed_url = urllib.parse.urlparse(schema_url)
            if parsed_url.fragment:
                community_metadata_schema_json = jsonpointer.resolve_pointer(
                    community_metadata_schema, parsed_url.fragment
                )
            else:
                community_metadata_schema_json = community_metadata_schema

            # Is it inline?
            jsonschema_meta_id = community_metadata_schema_json.get("$schema")
            if jsonschema_meta_id is None:
                jsonschema_meta_id = community_metadata_schema_json.get(
                    "draft_json_schema", {}
                ).get(
                    "$schema", jsonschema.validators.Draft4Validator.META_SCHEMA["id"]
                )

            return jsonschema_meta_id, community_metadata_schema_json

    def _get_community_schema(
        self, community_id: "str"
    ) -> "Optional[Tuple[str, Mapping[str, Any], str, Optional[str]]]":
        """
        It fetches the community schema
        """
        community_metadata: "Optional[Mapping[str, Any]]"
        if community_id == self.community_id:
            community_metadata = self.community_metadata
        else:
            community_metadata = self.get_community_metadata(community_id)
            if community_metadata is None:
                raise KeyError(
                    f"Unable to fetch metadata about community {community_id}"
                )

        community_specific_uuid = community_metadata.get("schema", {}).get(
            "block_schema_id"
        )

        # Now, let's build the schema URL
        schema_url = community_metadata["links"].get("block_schema")
        if schema_url is None:
            return None

        jsonschema_meta_id, community_metadata_schema_json = self.__fetch_schema(
            schema_url
        )

        return (
            jsonschema_meta_id,
            community_metadata_schema_json,
            schema_url,
            community_specific_uuid,
        )

    def _get_entries_schema(
        self, community_id: "str"
    ) -> "Tuple[str, Mapping[str, Any], str]":
        """
        It fetches the community schema
        """
        community_metadata: "Optional[Mapping[str, Any]]"
        if community_id == self.community_id:
            community_metadata = self.community_metadata
        else:
            community_metadata = self.get_community_metadata(community_id)
            if community_metadata is None:
                raise KeyError(
                    f"Unable to fetch metadata about community {community_id}"
                )

        # Now, let's build the schema URL
        schema_url = community_metadata["links"]["schema"]
        jsonschema_meta_id, entries_metadata_schema_json = self.__fetch_schema(
            schema_url
        )

        return jsonschema_meta_id, entries_metadata_schema_json, schema_url

    def _validate_community_schema(
        self,
        community_id: "str",
        community_specific_metadata: "Mapping[str, Any]",
    ) -> "Optional[str]":
        got_schema = self._get_community_schema(community_id)
        if got_schema is None:
            return None

        (
            jsonschema_meta_id,
            community_metadata_schema_json,
            community_schema_url,
            community_specific_uuid,
        ) = got_schema

        validator = INTROSPECT_VALIDATOR_MAPPER.get(jsonschema_meta_id)
        if validator is None:
            raise ExportPluginException(
                f"Unsupported JSON Schema validation based on {jsonschema_meta_id}"
            )
        reported_errors = False
        for se in validator(community_metadata_schema_json).iter_errors(
            community_specific_metadata
        ):
            if not reported_errors:
                self.logger.error(
                    f"B2SHARE community {community_specific_uuid} validation errors."
                )
                self.logger.error(f"\tSchema is at {community_schema_url}")
                self.logger.error("\tMetadata:")
                self.logger.error(json.dumps(community_specific_metadata, indent=4))
                reported_errors = True

                self.logger.error(
                    "\t\tPath: {0} . Message: {1}".format(
                        "/" + "/".join(map(lambda e: str(e), se.path)),
                        se.message,
                    )
                )

        if reported_errors:
            raise ExportPluginException(
                f"B2SHARE community {community_specific_uuid} specific metadata could not be validated. Inspect log messages.\nSchema is at {community_schema_url}\nMetadata:\n{json.dumps(community_specific_metadata, indent=4)}"
            )

        return community_specific_uuid

    def _validate_entry_schema(
        self,
        community_id: "str",
        entry_metadata: "Mapping[str, Any]",
    ) -> "None":
        (
            jsonschema_meta_id,
            entries_metadata_schema_json,
            entries_schema_url,
        ) = self._get_entries_schema(community_id)

        if any(
            map(
                lambda banned_key: banned_key in entry_metadata, self.BANNED_SCHEMA_KEYS
            )
        ):
            # Removing banned keys
            patched_entry_metadata = cast(
                "MutableMapping[str, Any]", copy.copy(entry_metadata)
            )
            for banned_key in self.BANNED_SCHEMA_KEYS:
                patched_entry_metadata.pop(banned_key, None)
            entry_metadata = patched_entry_metadata

        validator = INTROSPECT_VALIDATOR_MAPPER.get(jsonschema_meta_id)
        if validator is None:
            raise ExportPluginException(
                f"Unsupported JSON Schema validation based on {jsonschema_meta_id}"
            )
        reported_errors = False
        for se in validator(entries_metadata_schema_json).iter_errors(entry_metadata):
            if not reported_errors:
                self.logger.error(f"B2SHARE entry metadata could not be validated.")
                self.logger.error(f"\tSchema is at {entries_schema_url}")
                self.logger.error("\tMetadata:")
                self.logger.error(json.dumps(entry_metadata, indent=4))
                reported_errors = True

                self.logger.error(
                    "\t\tPath: {0} . Message: {1}".format(
                        "/" + "/".join(map(lambda e: str(e), se.path)),
                        se.message,
                    )
                )

        if reported_errors:
            raise ExportPluginException(
                f"B2SHARE entry metadata could not be validated. Inspect log messages.\nSchema is at {entries_schema_url}\nMetadata:\n{json.dumps(entry_metadata, indent=4)}"
            )

    def _get_records_prefix(self) -> "str":
        return self.api_prefix + "records/"

    def _get_query_params(self, include_credentials: "bool", **kwargs: "str") -> "str":
        query_params = {key: value for key, value in kwargs.items()}
        if include_credentials:
            query_params["access_token"] = self.api_token

        return urllib.parse.urlencode(query_params, encoding="utf-8")

    def _create_draft_record(
        self,
        community_specific_metadata: "Optional[Mapping[str, Any]]",
        base_id: "Optional[str]" = None,
        do_validate: "bool" = False,
    ) -> "Mapping[str, Any]":
        if base_id is None:
            base_id = self.preferred_id

        if base_id is not None:
            try:
                base_meta = self.get_pid_metadata(base_id)
                # This corner case happens when the base_id is a draft already
                if base_meta is not None:
                    base_meta.get("metadata", {}).get("")
                    if (
                        base_meta.get("metadata", {}).get("publication_state")
                        == "draft"
                    ):
                        return base_meta
                    # Use the internal id
                    base_id = base_meta["id"]
            except urllib.error.HTTPError as he:
                if he.code != 404:
                    raise he

                # The entry does not exist, so discard this id
                base_id = None

        # CHECK: implement case where the entry already exists, and we want
        # to create a revision. The base id MUST be an internal id in draft mode
        basedkw: "MutableMapping[str, str]" = {}
        if base_id is not None:
            basedkw["version_of"] = base_id

        headers = {
            "Content-Type": "application/json",
        }
        minimal_metadata: "MutableMapping[str, Any]" = {
            "titles": [
                {
                    "title": f"Draft record created at {datetime.datetime.utcnow().isoformat()}"
                }
            ],
            "open_access": True,
        }
        if self.community_id is not None:
            minimal_metadata["community"] = self.community_id
            if do_validate:
                self._validate_entry_schema(self.community_id, minimal_metadata)

            # This one has to be properly initialized
            # even when no specific metadata has to be provided
            minimal_metadata["community_specific"] = {}
            if community_specific_metadata is None:
                community_specific_metadata = {}

            if do_validate:
                community_specific_uuid = self._validate_community_schema(
                    self.community_id,
                    community_specific_metadata,
                )
            else:
                got_schema = self._get_community_schema(self.community_id)
                community_specific_uuid = None if got_schema is None else got_schema[3]

            if community_specific_uuid is not None:
                minimal_metadata["community_specific"][
                    community_specific_uuid
                ] = community_specific_metadata

        req = urllib.request.Request(
            self._get_records_prefix()
            + "?"
            + self._get_query_params(include_credentials=True, **basedkw),
            headers=headers,
            data=json.dumps(minimal_metadata).encode("utf-8"),
        )

        try:
            with urllib.request.urlopen(req) as creares:
                response = json.load(creares)
        except urllib.error.HTTPError as he:
            # This corner case happens when there is a draft already
            if he.code == 400:
                err_payload = json.load(he)
                goto_draft_id = err_payload.get("goto_draft")
                if isinstance(goto_draft_id, str):
                    goto_draft_meta = self.get_pid_metadata(goto_draft_id)
                    if goto_draft_meta is not None:
                        return goto_draft_meta

            raise he

        return cast("Mapping[str, Any]", response)

    INTERNAL_ID_PAT: "Final[re.Pattern[str]]" = re.compile(r"^[0-9a-f]+$")

    def get_pid_metadata(self, pid: "str") -> "Optional[Mapping[str, Any]]":
        headers = {
            "Content-Type": "application/json",
        }
        internal_pid: "Optional[str]" = None
        if self.INTERNAL_ID_PAT.match(pid):
            internal_pid = pid
        elif pid.startswith("doi:" + self.b2share_doi_prefix):
            internal_pid = pid[len("doi:" + self.b2share_doi_prefix) :]

        if internal_pid:
            req = urllib.request.Request(
                self._get_records_prefix()
                + urllib.parse.quote_plus(internal_pid)
                + "?"
                + self._get_query_params(include_credentials=True),
                headers=headers,
            )

            try:
                with urllib.request.urlopen(req) as getmeta:
                    response = json.load(getmeta)
            except urllib.error.HTTPError as he:
                # Is maybe a draft?
                if he.code == 404:
                    reqdraft = urllib.request.Request(
                        self._get_records_prefix()
                        + urllib.parse.quote_plus(internal_pid)
                        + "/draft"
                        + "?"
                        + self._get_query_params(include_credentials=True),
                        headers=headers,
                    )

                    with urllib.request.urlopen(reqdraft) as getmeta:
                        response = json.load(getmeta)
                else:
                    raise he

            return cast("Mapping[str, Any]", response)
        else:
            if pid.startswith("doi:"):
                curated_pid = pid[len("doi:") :]
            else:
                curated_pid = pid
            # TODO: support other cases

            curated_pid = '"' + curated_pid.replace('"', '\\"') + '"'
            query = {
                "q": f"alternate_identifiers.alternate_identifier:{curated_pid}",
            }

            req = urllib.request.Request(
                self._get_records_prefix()
                + "?"
                + self._get_query_params(include_credentials=True, **query),
                headers=headers,
            )

            with urllib.request.urlopen(req) as getmetaS:
                response = json.load(getmetaS)

            try:
                with urllib.request.urlopen(req) as bH:
                    retval = json.load(bH)
                    if (
                        isinstance(retval, dict)
                        and len(retval.get("hits", {}).get("hits", [])) > 0
                    ):
                        return cast("Mapping[str, Any]", retval["hits"]["hits"][0])
            except:
                self.logger.exception(f"Unable to fetch info about {pid} B2SHARE entry")

        return None

    def book_pid(
        self,
        preferred_id: "Optional[str]" = None,
        initially_required_metadata: "Optional[Mapping[str, Any]]" = None,
    ) -> "Optional[DraftEntry]":
        """
        It returns the publisher internal draft id, the public DOI / link, and the draft record representation
        """
        draft_record = self._create_draft_record(
            base_id=preferred_id,
            community_specific_metadata=initially_required_metadata,
        )

        return DraftEntry(
            draft_id=draft_record["id"],
            pid=cast("str", draft_record["metadata"]["$future_doi"]),
            metadata=draft_record,
        )

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
                if booked_meta.get("metadata", {}).get("publication_state") == "draft":
                    discard_link = booked_meta.get("links", {}).get("self")
            else:
                self.logger.debug(f"Ineligible {pid} B2SHARE entry")
        else:
            self.logger.debug(f"Unable to find {pid} B2SHARE entry id")

        # Last, release!
        if discard_link is not None:
            headers = {
                "Content-Type": "application/json",
            }
            discardreq = urllib.request.Request(
                discard_link + "?" + self._get_query_params(include_credentials=True),
                headers=headers,
                method="DELETE",
            )
            try:
                with urllib.request.urlopen(discardreq) as pH:
                    return True
            except Exception as e:
                self.logger.exception(f"Failed to discard entry {pid}")
                raise ExportPluginException(f"Failed to discard entry {pid}") from e

        return False

    def get_file_bucket_prefix(
        self,
        draft_entry: "DraftEntry",
    ) -> "str":
        """
        This is an accessory method which is used to build upload paths
        """
        assert draft_entry.metadata is not None

        return cast("str", draft_entry.metadata["links"]["files"])

    def _get_record_prefix_from_record(self, record: "Mapping[str, Any]") -> "str":
        return cast("str", record["links"]["self"])

    def upload_file_to_draft(
        self,
        draft_entry: "DraftEntry",
        filename: "Union[str, IO[bytes]]",
        remote_filename: "Optional[str]",
        content_size: "Optional[int]" = None,
    ) -> "Mapping[str, Any]":
        """
        It takes as input the draft record representation, a local filename and optionally the remote filename to use
        """
        file_bucket_prefix = self.get_file_bucket_prefix(draft_entry)

        # file_size = os.stat(filename).st_size
        headers = {
            "Accept": "application/json",
            "Content-Type": "application/octet-stream",
            # 	"Content-Length": str(file_size),
        }

        if remote_filename is None:
            assert isinstance(
                filename, str
            ), "When filename is a data stream, remote_filename must be declared"
            remote_filename = os.path.relpath(filename, self.refdir)

        fH: "IO[bytes]"
        if isinstance(filename, str):
            fH = open(filename, mode="rb")
        else:
            fH = filename

        try:
            req = urllib.request.Request(
                file_bucket_prefix
                + "/"
                + urllib.parse.quote_plus(remote_filename)
                + "?"
                + self._get_query_params(include_credentials=True),
                headers=headers,
                data=fH,
                method="PUT",
            )

            with urllib.request.urlopen(req) as answer:
                upload_response = json.load(answer)

            return cast("Mapping[str, Any]", upload_response)
        finally:
            if fH != filename:
                fH.close()

    @staticmethod
    def __update_meta(
        draft_record_metadata: "Mapping[str, Any]",
        metadata: "Mapping[str, Any]",
    ) -> "Mapping[str, Any]":
        """
        Generator of JSON Patch operations
        """
        updated_record_metadata = cast(
            "MutableMapping[str, Any]", copy.deepcopy(draft_record_metadata)
        )
        for key, val in metadata.items():
            if val is None:
                updated_record_metadata.pop(key, None)
            elif key in draft_record_metadata:
                # Is it a list?
                # if isinstance(draft_record_metadata[key], list):
                # 	# Is the value a list itself
                # 	if isinstance(val, list):
                # 		# Let's concatenate
                # 		the_val = val
                # 	else:
                # 		the_val = [ val ]
                #
                # 	for a_idx, a_val in enumerate(the_val, len(draft_record_metadata[key])):
                # 		patch_ops.append({
                # 			"op": "add",
                # 			"path": prefix + key + '/' + str(a_idx),
                # 			"value": a_val,
                # 		})
                # else:
                updated_record_metadata[key] = val
            else:
                updated_record_metadata[key] = val

        return updated_record_metadata

    @staticmethod
    def __patch_ops(
        draft_record_metadata: "Mapping[str, Any]",
        metadata: "Mapping[str, Any]",
        prefix: "str" = "/",
    ) -> "Sequence[Mapping[str, Any]]":
        """
        Generator of JSON Patch operations
        """
        patch_ops: "MutableSequence[Mapping[str, Any]]" = []
        for key, val in metadata.items():
            if val is None:
                patch_ops.append(
                    {
                        "op": "remove",
                        "path": prefix + key,
                    }
                )
            elif key in draft_record_metadata:
                # Is it a list?
                # if isinstance(draft_record_metadata[key], list):
                # 	# Is the value a list itself
                # 	if isinstance(val, list):
                # 		# Let's concatenate
                # 		the_val = val
                # 	else:
                # 		the_val = [ val ]
                #
                # 	for a_idx, a_val in enumerate(the_val, len(draft_record_metadata[key])):
                # 		patch_ops.append({
                # 			"op": "add",
                # 			"path": prefix + key + '/' + str(a_idx),
                # 			"value": a_val,
                # 		})
                # else:
                patch_ops.append(
                    {
                        "op": "replace",
                        "path": prefix + key,
                        "value": val,
                    }
                )
            else:
                patch_ops.append(
                    {
                        "op": "add",
                        "path": prefix + key,
                        "value": val,
                    }
                )

        return patch_ops

    def update_record_metadata(
        self,
        draft_entry: "DraftEntry",
        metadata: "Mapping[str, Any]",
        community_specific_metadata: "Optional[Mapping[str, Any]]" = None,
        do_validate: "bool" = False,
    ) -> "Mapping[str, Any]":
        """
        This method updates the (draft or not) record metadata,
        both the general one, and the specific of the community.
        This one could not make sense for some providers.
        """
        assert draft_entry.metadata is not None
        record = self.get_pid_metadata(draft_entry.draft_id)
        if record is None:
            raise ExportPluginException(
                f"B2SHARE draft/entry {draft_entry.draft_id} is unavailable"
            )

        patch_ops: "MutableSequence[Mapping[str, Any]]"
        # Do not patch when no metadata is provided

        updated_metadata = self.__update_meta(record["metadata"], metadata)
        community_id = cast("Optional[str]", updated_metadata.get("community"))

        if do_validate:
            assert community_id is not None
            # Validate metadata changes
            self._validate_entry_schema(community_id, updated_metadata)

        if metadata:
            metadata_patch_ops = self.__patch_ops(record["metadata"], metadata)
        else:
            metadata_patch_ops = []

        community_metadata_patch_ops: "Sequence[Mapping[str, Any]]" = []
        if community_id is not None:
            got_schema = self._get_community_schema(community_id)
            community_specific_uuid = None if got_schema is None else got_schema[3]

            if community_specific_metadata is None:
                community_specific_metadata = {}
            if community_specific_uuid is not None:
                if do_validate:
                    updated_community_specific_metadata = self.__update_meta(
                        updated_metadata["community_specific"].get(
                            community_specific_uuid, {}
                        ),
                        community_specific_metadata,
                    )
                    self._validate_community_schema(
                        community_id, updated_community_specific_metadata
                    )

                community_metadata_patch_ops = self.__patch_ops(
                    updated_metadata["community_specific"].get(
                        community_specific_uuid, {}
                    ),
                    community_specific_metadata,
                    prefix="/community_specific/" + community_specific_uuid + "/",
                )

        if len(metadata_patch_ops) > 0 or len(community_metadata_patch_ops) > 0:
            record_url = self._get_record_prefix_from_record(record)
            headers = {
                "Content-Type": "application/json-patch+json",
            }
            req = urllib.request.Request(
                record_url + "?" + self._get_query_params(include_credentials=True),
                headers=headers,
                data=json.dumps(
                    [*metadata_patch_ops, *community_metadata_patch_ops]
                ).encode("utf-8"),
                method="PATCH",
            )
            try:
                with urllib.request.urlopen(req) as answer:
                    updated_record = json.load(answer)
            except urllib.error.HTTPError as he:
                self.logger.exception(
                    "PATCH ERROR BODY:\n" + json.dumps(json.load(he.fp), indent=4)
                )
                raise he

            return cast("Mapping[str, Any]", updated_record)
        else:
            return record

    def publish_draft_record(self, draft_entry: "DraftEntry") -> "Mapping[str, Any]":
        """
        This method publishes a draft record
        """
        published_record = self.update_record_metadata(
            draft_entry,
            metadata={
                "publication_state": "submitted",
            },
            do_validate=True,
        )

        return published_record

    def push(
        self,
        items: "Sequence[AnyContent]",
        preferred_id: "Optional[str]" = None,
    ) -> "Sequence[URIWithMetadata]":
        """
        These contents will be included in the B2SHARE share
        """

        if len(items) == 0:
            raise ValueError(
                "This plugin requires at least one element to be processed"
            )

        # We are starting to learn whether we already have a PID
        internal_id = self.preferred_id if preferred_id is None else preferred_id

        booked_entry = self.book_pid(internal_id)

        if preferred_id is None:
            raise ExportPluginException("Unable to book a B2SHARE entry")

        # Now, obtain the metadata, which is needed
        assert booked_entry is not None
        assert booked_entry.metadata is not None

        # Upload
        failed = False
        relitems: "Set[str]" = set()
        for i_item, item in enumerate(items):
            relitem = os.path.relpath(item.local, self.refdir)
            # Outside the relative directory
            if relitem.startswith(os.path.pardir):
                # This is needed to avoid collisions
                prefname: "Optional[RelPath]"
                if isinstance(item, MaterializedContent):
                    prefname = item.prettyFilename
                else:
                    prefname = item.preferredFilename

                if prefname is None:
                    prefname = cast("RelPath", os.path.basename(item.local))

            while prefname in relitems:
                baserelitem = cast(
                    "RelPath", str(i_item) + "_" + os.path.basename(prefname)
                )
                dirrelitem = os.path.dirname(prefname)
                prefname = (
                    cast("RelPath", os.path.join(dirrelitem, baserelitem))
                    if len(dirrelitem) > 0
                    else baserelitem
                )

            assert prefname is not None
            relitem = prefname
            relitems.add(relitem)

            try:
                upload_response = self.upload_file_to_draft(
                    booked_entry, item.local, relitem
                )
            except urllib.error.HTTPError as he:
                failed = True

        if failed:
            file_bucket_prefix = self.get_file_bucket_prefix(booked_entry)
            raise ExportPluginException(
                f"Some contents could not be uploaded to entry {booked_entry.metadata.get('id')}, bucket {file_bucket_prefix}"
            )

        # Add metadata to the entry
        # Publish the entry
        entry_metadata: "Mapping[str, Any]" = {}

        community_specific_metadata: "Mapping[str, Any]" = {}

        # This might not be needed
        meta_update = self.update_record_metadata(
            booked_entry,
            entry_metadata,
            community_specific_metadata=community_specific_metadata,
        )

        # Last, publish!
        pub_update = self.publish_draft_record(booked_entry)

        shared_uris = []
        shared_uris.append(
            URIWithMetadata(
                uri=cast("URIType", booked_entry.pid),
                # TODO: Add meaninful metadata
                metadata=booked_entry.metadata,
            )
        )

        return shared_uris
