#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# SPDX-License-Identifier: Apache-2.0
# Copyright 2020-2023 Barcelona Supercomputing Center (BSC), Spain
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
import random
import tempfile
from typing import (
    cast,
    NamedTuple,
    TYPE_CHECKING,
)
import urllib.parse

if TYPE_CHECKING:
    from typing import (
        ClassVar,
        Mapping,
        MutableMapping,
        Optional,
        Sequence,
        Union,
    )

    from typing_extensions import Final

    from ..common import (
        AbsPath,
        URIType,
    )

from funny_passphrase.generator import FunnyPassphraseGenerator
from funny_passphrase.indexer import CompressedIndexedText

import xdg.BaseDirectory  # type: ignore[import]

from ..cache_handler import (
    CacheOfflineException,
    SchemeHandlerCacheHandler,
)
from ..fetchers.http import SCHEME_HANDLERS as HTTP_SCHEME_HANDLERS
from ..fetchers.wiktionary import WiktionaryFetcher


class RemoteWordlistResource(NamedTuple):
    uri: "str"
    substart: "int" = 0
    subend: "Optional[int]" = None


class WfExSPassphraseGenerator(FunnyPassphraseGenerator):
    DEFAULT_PASSPHRASE_LENGTH: "Final[int]" = 6
    WFEXS_PASSPHRASE_SCHEME: "Final[str]" = "wfexs.funny-passphrase"

    DEFAULT_WORD_SETS: "Mapping[str, Sequence[RemoteWordlistResource]]" = {
        "eff-long": [
            RemoteWordlistResource(
                "https://www.eff.org/files/2016/07/18/eff_large_wordlist.txt",
                substart=8,
            )
        ],
        "cain": [
            # https://wiki.skullsecurity.org/index.php/Passwords
            RemoteWordlistResource(
                "http://downloads.skullsecurity.org/passwords/cain.txt.bz2"
            ),
        ],
        "adjectives": [
            RemoteWordlistResource(
                WiktionaryFetcher.WIKTIONARY_PROTO + ":Spanish/adjectives"
            ),
            RemoteWordlistResource(
                WiktionaryFetcher.WIKTIONARY_PROTO + ":Catalan/adjectives"
            ),
            RemoteWordlistResource(
                WiktionaryFetcher.WIKTIONARY_PROTO + ":English/adjectives"
            ),
        ],
        "nouns": [
            RemoteWordlistResource(
                WiktionaryFetcher.WIKTIONARY_PROTO + ":Spanish/nouns"
            ),
            RemoteWordlistResource(
                WiktionaryFetcher.WIKTIONARY_PROTO + ":Catalan/nouns"
            ),
            RemoteWordlistResource(
                WiktionaryFetcher.WIKTIONARY_PROTO + ":English/nouns"
            ),
        ],
    }

    def __init__(
        self,
        cacheHandler: "SchemeHandlerCacheHandler",
        cacheDir: "Optional[AbsPath]" = None,
        word_sets: "Mapping[str, Sequence[RemoteWordlistResource]]" = DEFAULT_WORD_SETS,
    ):
        # The cache is an integral part, as it is where the
        # different components are going to be fetched
        self.cacheHandler = cacheHandler
        self.cacheDir = cacheDir

        cindex_sets = self._materialize_word_sets(word_sets)

        super().__init__(**cindex_sets)

    def _materialize_word_sets(
        self, raw_word_sets: "Mapping[str, Sequence[RemoteWordlistResource]]"
    ) -> "Mapping[str, CompressedIndexedText]":
        """
        Download and index each one of the components of the word sets
        """
        word_sets: "MutableMapping[str, CompressedIndexedText]" = dict()
        for wordlist_tag, word_set_uris in raw_word_sets.items():
            indexed_filenames = []
            for remote_wordlist in word_set_uris:
                word_set_uri = remote_wordlist.uri
                wordlist_internal_uri = cast(
                    "URIType",
                    f'{self.WFEXS_PASSPHRASE_SCHEME}:{urllib.parse.quote(word_set_uri, safe="")}',
                )
                indexed_filename = None
                try:
                    i_cached_content = self.cacheHandler.fetch(
                        wordlist_internal_uri, destdir=self.cacheDir, offline=True
                    )

                    # This if should be superfluous
                    if os.path.exists(i_cached_content.path):
                        indexed_filename = i_cached_content.path
                except CacheOfflineException:
                    pass

                if indexed_filename is None:
                    # Time to fetch the wordlist
                    i_cached_content = self.cacheHandler.fetch(
                        cast("URIType", word_set_uri),
                        destdir=self.cacheDir,
                        offline=False,
                    )

                    # Prepare the compressed index
                    with tempfile.NamedTemporaryFile() as tmp_indexed_filename:
                        CompressedIndexedText.IndexTextFile(
                            i_cached_content.path,
                            tmp_indexed_filename.name,
                            substart=remote_wordlist.substart,
                            subend=remote_wordlist.subend,
                        )
                        # And inject it in the cache
                        indexed_filename, _ = self.cacheHandler.inject(
                            wordlist_internal_uri,
                            destdir=self.cacheDir,
                            tempCachedFilename=cast(
                                "AbsPath", tmp_indexed_filename.name
                            ),
                        )

                assert indexed_filename is not None

                indexed_filenames.append(indexed_filename)

            word_sets[wordlist_tag] = CompressedIndexedText(cfiles=indexed_filenames)

        return word_sets

    def generate_passphrase_random(
        self,
        chosen_wordlist: "Optional[Union[str, int, Sequence[Union[str, int]]]]" = None,
        passphrase_length: "int" = DEFAULT_PASSPHRASE_LENGTH,
    ) -> str:
        """
        This method is needed to hook into the funny passphrase library
        """
        get_random = 1 if chosen_wordlist is None else 0

        wordlists_tags = self.word_set_tags()
        if get_random == 0:
            if not isinstance(chosen_wordlist, list):
                chosen_wordlist = [cast("Union[str, int]", chosen_wordlist)]

            # Validating the wordlist
            for chosen in chosen_wordlist:
                if chosen not in wordlists_tags:
                    get_random = len(chosen_wordlist)
                    break

        if get_random > 0:
            chosen_wordlist = [
                wordlists_tags[random.randrange(len(wordlists_tags))]
                for _ in range(get_random)
            ]

        return self.generate_passphrase(
            num=passphrase_length,
            subset=cast("Sequence[Union[str, int]]", chosen_wordlist),
        )

    def generate_nickname(self) -> str:
        """
        This method generates random nicknames using two specific
        wordlists (if available)
        """
        return (
            self.generate_passphrase_random("adjectives", 1)
            + " "
            + self.generate_passphrase_random("nouns", 1)
        )


class WfExSPassGenSingleton(WfExSPassphraseGenerator):
    __instance: "ClassVar[Optional[WfExSPassphraseGenerator]]" = None

    def __new__(cls) -> "WfExSPassphraseGenerator":  # type: ignore
        if cls.__instance is None:
            cachePath = cast(
                "AbsPath",
                xdg.BaseDirectory.save_cache_path("es.elixir.WfExSPassGenSingleton"),
            )

            # Private cache handler instance
            # with Wiktionary
            cacheHandler = SchemeHandlerCacheHandler(
                cachePath, schemeHandlers=HTTP_SCHEME_HANDLERS
            )
            for scheme, clazz in WiktionaryFetcher.GetSchemeHandlers().items():
                cacheHandler.addSchemeHandler(scheme, clazz)
            cls.__instance = WfExSPassphraseGenerator(cacheHandler)

        return cls.__instance

    def __init__(self) -> None:
        pass
