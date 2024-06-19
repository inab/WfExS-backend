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

import os
import pathlib
import shutil
import tempfile
from typing import (
    cast,
    TYPE_CHECKING,
)
import urllib.parse

from ..common import (
    CacheType,
    LicensedURI,
    MaterializedContent,
)

if TYPE_CHECKING:
    from typing import (
        Any,
        ClassVar,
        IO,
        Mapping,
        Optional,
        Sequence,
        Union,
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
        URIWithMetadata,
    )

    from ..workflow import WF

from ..utils.contents import link_or_copy

from . import (
    AbstractExportPlugin,
    DraftEntry,
)
from .abstract_contexted_export import AbstractContextedExportPlugin


class CacheExportPlugin(AbstractContextedExportPlugin):
    """
    Class to model exporting results to WfExS-backend cache
    """

    PLUGIN_NAME = cast("SymbolicName", "cache")

    # Is this implementation ready?
    ENABLED: "ClassVar[bool]" = True

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
        # We are starting to learn whether we already have a PID
        preferred_id = (
            self.default_preferred_id if preferred_id is None else preferred_id
        )
        if (preferred_id is None) or len(preferred_id) == 0:
            raise ValueError("This plugin needs a preferred_id to generate a PID")

        p = urllib.parse.urlparse(preferred_id)
        if p.scheme == "":
            raise ValueError(
                "This plugin needs that the provided preferred_id is a URI (i.e. with a scheme)"
            )

        return DraftEntry(
            draft_id=preferred_id,
            pid=preferred_id,
            metadata=None,
            raw_metadata=None,
        )

    def discard_booked_pid(self, pid_or_draft: "Union[str, DraftEntry]") -> "bool":
        """
        This method is used to release a previously booked PID,
        which has not been published.

        When it returns False, it means that the
        provided id did exist, but it was not a draft
        """

        return False

    def get_pid_metadata(self, pid: "str") -> "Optional[Mapping[str, Any]]":
        """
        This method is used to obtained the metadata associated to a PID,
        in case the destination allows it.
        """

        return None

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
        if self.wfexs is None:
            raise ValueError(
                "This plugin needs to be contextualized with the WfExS instance"
            )

        """
        These contents will be included in the cache
        """
        if len(items) == 0:
            raise ValueError("This plugin needs at least one element to be processed")

        # We are starting to learn whether we already have a PID
        preferred_id = (
            self.default_preferred_id if preferred_id is None else preferred_id
        )
        if (preferred_id is None) or len(preferred_id) == 0:
            raise ValueError("This plugin needs a preferred_id to generate a PID")

        # Create temporary destination directory (if needed)
        tmpdir = None
        source: "Optional[pathlib.Path]" = None
        metadata = None
        try:
            if len(items) > 1:
                tmpdir = tempfile.mkdtemp(dir=self.tempdir, suffix="export")
                source = pathlib.Path(tmpdir)

                # Now, transfer all of them
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
                        relitem = str(i_item) + "_" + prefname
                    dest = cast("AbsPath", os.path.join(tmpdir, relitem))
                    link_or_copy(item.local, dest)
            else:
                source = (
                    items[0].local
                    if isinstance(items[0].local, pathlib.Path)
                    else pathlib.Path(items[0].local)
                )

            # Generated file URI injecting the preferred id an scheme
            uri_to_fetch = LicensedURI(
                uri=cast(
                    "URIType",
                    urllib.parse.urlunparse(
                        urllib.parse.ParseResult(
                            scheme="file",
                            netloc="",
                            path=source.as_posix(),
                            params="",
                            query=urllib.parse.urlencode(
                                {"inject_as": preferred_id},
                                doseq=True,
                            ),
                            fragment="",
                        )
                    ),
                ),
                licences=tuple(licences)
                if len(licences) > 0
                else self.default_licences,
            )

            cached_uri = self.wfexs.cacheFetch(
                uri_to_fetch, CacheType.Input, offline=False, ignoreCache=True
            )
        finally:
            # Removing leftovers
            if tmpdir is not None:
                shutil.rmtree(tmpdir)

        return cached_uri.metadata_array
