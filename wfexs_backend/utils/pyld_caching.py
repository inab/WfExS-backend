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
        Callable,
        Mapping,
        Optional,
        Sequence,
    )

import asyncio
import aiohttp
from aiohttp_client_cache.session import CachedSession
from aiohttp_client_cache.backends.sqlite import SQLiteBackend
import os.path
import pyld  # type: ignore[import, import-untyped]
import re
import string
import urllib.parse
import xdg.BaseDirectory


def aiohttp_caching_document_loader(
    cache_file: "str",
    loop: "Optional[asyncio.AbstractEventLoop]" = None,
    secure: "bool" = False,
    **kwargs: "Any",
) -> "Callable[[str, Mapping[str, Mapping[str, str]]], Mapping[str, Any]]":
    """
    This code is based on aiohttp_document_loader from https://raw.githubusercontent.com/digitalbazaar/pyld/2c6b0a65bee700b42c8d0806364f4fc4ebddcc52/lib/pyld/documentloader/aiohttp.py
    """
    """
    Create an Asynchronous document loader using aiohttp.

    :param loop: the event loop used for processing HTTP requests.
    :param secure: require all requests to use HTTPS (default: False).
    :param **kwargs: extra keyword args for the aiohttp request get() call.

    :return: the RemoteDocument loader function.
    """

    if loop is None:
        loop = asyncio.get_event_loop()

    async def async_caching_loader(
        url: "str", headers: "Mapping[str, str]"
    ) -> "Mapping[str, Any]":
        """
        Retrieves JSON-LD at the given URL asynchronously.

        :param url: the URL to retrieve.

        :return: the RemoteDocument.
        """
        try:
            # validate URL
            pieces = urllib.parse.urlparse(url)
            if (
                not all([pieces.scheme, pieces.netloc])
                or pieces.scheme not in ["http", "https"]
                or set(pieces.netloc)
                > set(string.ascii_letters + string.digits + "-.:")
            ):
                raise pyld.jsonld.JsonLdError(
                    "URL could not be dereferenced; "
                    'only "http" and "https" URLs are supported.',
                    "jsonld.InvalidUrl",
                    {"url": url},
                    code="loading document failed",
                )
            if secure and pieces.scheme != "https":
                raise pyld.jsonld.JsonLdError(
                    "URL could not be dereferenced; "
                    "secure mode enabled and "
                    'the URL\'s scheme is not "https".',
                    "jsonld.InvalidUrl",
                    {"url": url},
                    code="loading document failed",
                )
            async with CachedSession(
                cache=SQLiteBackend(cache_file),
                loop=loop,
            ) as session:
                async with session.get(
                    url,
                    headers=headers,
                    **kwargs,
                ) as response:
                    # Allow any content_type in trying to parse json
                    # similar to requests library
                    json_body = await response.json(content_type=None)
                    content_type = response.headers.get("content-type")
                    if not content_type:
                        content_type = "application/octet-stream"
                    doc = {
                        "contentType": content_type,
                        "contextUrl": None,
                        "documentUrl": response.url.human_repr(),
                        "document": json_body,
                    }
                    link_header = response.headers.get("link")
                    if link_header:
                        linked_context = pyld.jsonld.parse_link_header(link_header).get(
                            pyld.jsonld.LINK_HEADER_REL
                        )
                        # only 1 related link header permitted
                        if linked_context and content_type != "application/ld+json":
                            if isinstance(linked_context, list):
                                raise pyld.jsonld.JsonLdError(
                                    "URL could not be dereferenced, "
                                    "it has more than one "
                                    "associated HTTP Link Header.",
                                    "jsonld.LoadDocumentError",
                                    {"url": url},
                                    code="multiple context link headers",
                                )
                            doc["contextUrl"] = linked_context["target"]
                        linked_alternate = pyld.jsonld.parse_link_header(
                            link_header
                        ).get("alternate")
                        # if not JSON-LD, alternate may point there
                        if (
                            linked_alternate
                            and linked_alternate.get("type") == "application/ld+json"
                            and not re.match(
                                r"^application\/(\w*\+)?json$", content_type
                            )
                        ):
                            doc["contentType"] = "application/ld+json"
                            doc["documentUrl"] = pyld.jsonld.prepend_base(
                                url, linked_alternate["target"]
                            )

                    return doc
        except pyld.jsonld.JsonLdError as e:
            raise e
        except Exception as cause:
            raise pyld.jsonld.JsonLdError(
                "Could not retrieve a JSON-LD document from the URL.",
                "jsonld.LoadDocumentError",
                code="loading document failed",
                cause=cause,
            )

    def loader(
        url: "str", options: "Mapping[str, Mapping[str, str]]" = {}
    ) -> "Mapping[str, Any]":
        """
        Retrieves JSON-LD at the given URL.

        :param url: the URL to retrieve.

        :return: the RemoteDocument.
        """
        return loop.run_until_complete(
            async_caching_loader(
                url,
                options.get(
                    "headers",
                    {
                        "Accept": "application/ld+json, application/json",
                    },
                ),
            )
        )

    return loader


def hook_pyld_cache(cache_file: "str") -> "None":
    pyld.jsonld.set_document_loader(
        aiohttp_caching_document_loader(
            cache_file=cache_file,
            timeout=60,
        )
    )


def pyld_cache_initialize(initial_contexts: "Sequence[str]" = []) -> "None":
    """
    This method hooks the caching system to pyld, so context resolution
    does not need to connect to internet.
    And, if the list of initial contexts is not empty, populate the cache
    with them.
    """
    cache_path = xdg.BaseDirectory.save_cache_path("es.elixir.WfExSJSONLD")
    hook_pyld_cache(os.path.join(cache_path, "contexts.db"))

    if len(initial_contexts) > 0:
        mock_jsonld = {
            "@context": initial_contexts,
            "@graph": [],
        }

        # This line should perform the magic
        pyld.jsonld.expand(mock_jsonld, {"keepFreeFloatingNodes": True})
