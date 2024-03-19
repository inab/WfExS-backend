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
from typing import (
    cast,
    NamedTuple,
    TYPE_CHECKING,
)
import urllib.parse

if TYPE_CHECKING:
    from typing import (
        Any,
        ClassVar,
        Mapping,
        MutableSequence,
        Optional,
        Sequence,
        Tuple,
        Union,
    )

    from typing_extensions import Final

    from ..common import (
        AbsPath,
        AnyContent,
        MaterializedInput,
        MaterializedOutput,
        RelPath,
        SecurityContextConfig,
        SymbolicName,
        URIType,
        URIWithMetadata,
    )

from . import (
    AbstractExportPlugin,
    ExportPluginException,
)


class AbstractTokenSandboxedExportPlugin(AbstractExportPlugin):
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

        for conf_key in ("token",):
            if conf_key not in self.setup_block:
                raise ExportPluginException(
                    f"Key {conf_key} was not found in security context block"
                )

        self.api_token = self.setup_block["token"]

        for conf_key in ("sandbox",):
            if conf_key not in self.setup_block:
                raise ExportPluginException(
                    f"Key {conf_key} was not found in setup block"
                )

        self.sandbox = bool(self.setup_block["sandbox"])
