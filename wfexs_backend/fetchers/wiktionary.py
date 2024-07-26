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

from typing import (
    TYPE_CHECKING,
)

if TYPE_CHECKING:
    from typing import (
        Any,
        Mapping,
        Optional,
        Sequence,
        Type,
    )

    from typing_extensions import (
        Final,
    )

    from ..common import (
        AbsPath,
        PathLikePath,
        ProgsMapping,
        SecurityContextConfig,
        SymbolicName,
        URIType,
    )

import urllib.parse

from wiktionary_fetcher import store_terms

from ..common import (
    ContentKind,
    URIWithMetadata,
)

from . import (
    AbstractStatefulFetcher,
    DocumentedStatefulProtocolFetcher,
    FetcherException,
    ProtocolFetcherReturn,
)


class WiktionaryFetcher(AbstractStatefulFetcher):
    WIKTIONARY_PROTO: "Final[str]" = "wfexs.wiktionary"

    def __init__(
        self, progs: "ProgsMapping", setup_block: "Optional[Mapping[str, Any]]" = None
    ):
        super().__init__(progs=progs, setup_block=setup_block)

    @classmethod
    def GetSchemeHandlers(cls) -> "Mapping[str, DocumentedStatefulProtocolFetcher]":
        # These are de-facto schemes supported by pip and git client
        return {
            cls.WIKTIONARY_PROTO: DocumentedStatefulProtocolFetcher(
                fetcher_class=cls,
                priority=cls.PRIORITY,
            ),
        }

    @property
    def description(self) -> "str":
        return "Pseudo-scheme used to materialize lists of words from Wiktionary, used for passphrase generation"

    @classmethod
    def GetNeededPrograms(cls) -> "Sequence[SymbolicName]":
        return tuple()

    def fetch(
        self,
        remote_file: "URIType",
        cachedFilename: "PathLikePath",
        secContext: "Optional[SecurityContextConfig]" = None,
    ) -> "ProtocolFetcherReturn":
        parsedInputURL = urllib.parse.urlparse(remote_file)

        if parsedInputURL.scheme != self.WIKTIONARY_PROTO:
            raise FetcherException(
                f"Unhandled scheme {parsedInputURL.scheme}, only understands {self.WIKTIONARY_PROTO}"
            )

        # It is expected that both the language and the terms are represented
        # in the path
        path_comp = parsedInputURL.path.split("/")
        if len(path_comp) < 2:
            raise FetcherException(
                f"Expecting the language and term type to fetch from Wiktionary (e.g. 'English/verbs') but not enough components: {path_comp}"
            )

        lang = path_comp[0]
        term_type = path_comp[1]
        with open(cachedFilename, mode="w", encoding="utf-8") as wH:
            store_terms(lang, term_type, wH)

        # This fetcher generates single files
        kind = ContentKind.File
        # Metadata about the language and fetched term type
        metadata = {
            "lang": lang,
            "terms": term_type,
        }

        return ProtocolFetcherReturn(
            kind_or_resolved=kind,
            metadata_array=[URIWithMetadata(uri=remote_file, metadata=metadata)],
        )
