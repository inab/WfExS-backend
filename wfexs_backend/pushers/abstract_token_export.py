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

import abc
import logging
import os
from typing import (
    cast,
    NamedTuple,
    TYPE_CHECKING,
)
import urllib.error
import urllib.parse

if TYPE_CHECKING:
    import pathlib
    from typing import (
        Any,
        ClassVar,
        Mapping,
        MutableSequence,
        Optional,
        Sequence,
        Set,
        Tuple,
        Union,
    )

    from typing_extensions import Final

    from ..common import (
        AbsPath,
        AnyContent,
        LicenceDescription,
        MaterializedInput,
        MaterializedOutput,
        RelPath,
        ResolvedORCID,
        SecurityContextConfig,
        SymbolicName,
        URIType,
    )

    from . import (
        DraftEntry,
    )

from . import (
    AbstractDraftedExportPlugin,
    ExportPluginException,
)

from ..common import (
    MaterializedContent,
    URIWithMetadata,
)


class AbstractTokenExportPlugin(AbstractDraftedExportPlugin):
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

        for conf_key in ("token",):
            if conf_key not in self.setup_block:
                raise ExportPluginException(
                    f"Key {conf_key} was not found in security context block"
                )

        self.api_token = self.setup_block["token"]

        for conf_key in ("api-prefix",):
            if conf_key not in self.setup_block:
                raise ExportPluginException(
                    f"Key {conf_key} was not found in setup block"
                )

        self.api_prefix = cast("str", self.setup_block["api-prefix"])
        # Prefix should always end with a slash
        if not self.api_prefix.endswith("/"):
            self.api_prefix += "/"

    @abc.abstractmethod
    def get_file_bucket_prefix(
        self,
        draft_entry: "DraftEntry",
    ) -> "str":
        """
        This is an accessory method which is used to build upload paths
        """
        raise NotImplementedError()

    def get_api_prefix(self) -> "str":
        """
        This method returns the REST API prefix.
        It could be re-implemented
        """
        return self.api_prefix

    def push(
        self,
        items: "Sequence[AnyContent]",
        preferred_id: "Optional[str]" = None,
        title: "Optional[str]" = None,
        description: "Optional[str]" = None,
        licences: "Sequence[LicenceDescription]" = [],
        resolved_orcids: "Sequence[ResolvedORCID]" = [],
        metadata: "Optional[Mapping[str, Any]]" = None,
        community_specific_metadata: "Optional[Mapping[str, Any]]" = None,
    ) -> "Sequence[URIWithMetadata]":
        """
        This is the "reference" implementation, which should work for
        many different implementations
        """

        if len(items) == 0:
            raise ValueError(
                "This plugin requires at least one element to be processed"
            )

        # We are starting to learn whether we already have a PID
        internal_id = (
            self.default_preferred_id if preferred_id is None else preferred_id
        )

        booked_entry = self.book_pid(
            preferred_id=internal_id,
            initially_required_metadata=metadata,
            initially_required_community_specific_metadata=community_specific_metadata,
            title=title,
            description=description,
            licences=licences,
            resolved_orcids=resolved_orcids,
        )

        if booked_entry is None:
            raise ExportPluginException(self._customized_book_pid_error_string)

        # Now, obtain the metadata, which is needed
        assert booked_entry.metadata is not None

        # Upload
        failed = False
        relitems: "Set[str]" = set()
        for i_item, item in enumerate(items):
            # Outside the relative directory
            prefname: "Optional[RelPath]" = None
            if isinstance(item, MaterializedContent):
                prefname = item.prettyFilename
            else:
                prefname = item.preferredFilename

            if prefname is None:
                relitem = os.path.relpath(item.local, self.refdir)
                prefname = cast("RelPath", relitem)

            assert prefname is not None
            # Relative must remain relative!
            prefname = cast("RelPath", prefname.lstrip("/"))

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

            relitems.add(prefname)

            try:
                upload_response = self.upload_file_to_draft(
                    booked_entry, str(item.local), prefname
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
        # This might not be needed
        meta_update = self.update_record_metadata(
            booked_entry,
            metadata=metadata,
            community_specific_metadata=community_specific_metadata,
            title=title,
            description=description,
            licences=licences,
            resolved_orcids=resolved_orcids,
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
