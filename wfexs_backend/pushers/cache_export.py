#!/usr/bin/env python
# -*- coding: utf-8 -*-

# Copyright 2020-2022 Barcelona Supercomputing Center (BSC), Spain
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
import shutil
import tempfile
from typing import (
    cast,
    TYPE_CHECKING,
)
import urllib.parse

from ..common import (
    CacheType,
    MaterializedContent,
)

if TYPE_CHECKING:
    from typing import (
        Optional,
        Sequence,
    )

    from ..common import (
        AbsPath,
        AnyContent,
        RelPath,
        SecurityContextConfig,
        SymbolicName,
        URIType,
        URIWithMetadata,
    )

    from ..workflow import WF

from ..utils.contents import link_or_copy

from . import AbstractExportPlugin


class CacheExportPlugin(AbstractExportPlugin):
    """
    Class to model exporting results to WfExS-backend cache
    """

    PLUGIN_NAME = cast("SymbolicName", "cache")

    def __init__(
        self, wfInstance: "WF", setup_block: "Optional[SecurityContextConfig]" = None
    ):
        super().__init__(wfInstance, setup_block)

    def push(
        self,
        items: "Sequence[AnyContent]",
        preferred_scheme: "Optional[str]" = None,
        preferred_id: "Optional[str]" = None,
    ) -> "Sequence[URIWithMetadata]":
        """
        These contents will be included in the cache
        """
        if len(items) == 0:
            raise ValueError("This plugin needs at least one element to be processed")

        if (preferred_scheme is None) or len(preferred_scheme) == 0:
            raise ValueError("This plugin needs a scheme to generate a PID")

        if ":" in preferred_scheme:
            raise ValueError(f"Scheme {preferred_scheme} contains a colon")

        if (preferred_id is None) or len(preferred_id) == 0:
            raise ValueError("This plugin needs a preferred_id to generate a PID")

        # Create temporary destination directory (if needed)
        tmpdir = None
        source = None
        metadata = None
        try:
            if len(items) > 1:
                tmpdir = tempfile.mkdtemp(
                    dir=self.wfInstance.getStagedSetup().temp_dir, suffix="export"
                )
                source = tmpdir

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
                source = items[0].local

            # Generated file URI injecting the preferred id an scheme
            uri_to_fetch = cast(
                "URIType",
                urllib.parse.urlunparse(
                    urllib.parse.ParseResult(
                        scheme="file",
                        netloc="",
                        path=source,
                        params="",
                        query=urllib.parse.urlencode(
                            {"inject_as": f"{preferred_scheme}:{preferred_id}"},
                            doseq=True,
                        ),
                        fragment="",
                    )
                ),
            )

            cached_uri = self.wfInstance.wfexs.cacheFetch(
                uri_to_fetch, CacheType.Input, offline=False, ignoreCache=True
            )
        finally:
            # Removing leftovers
            if tmpdir is not None:
                shutil.rmtree(tmpdir)

        return cached_uri.metadata_array
