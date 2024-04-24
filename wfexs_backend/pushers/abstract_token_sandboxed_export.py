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
import copy
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
        LicenceDescription,
        MaterializedInput,
        MaterializedOutput,
        RelPath,
        ResolvedORCID,
        SecurityContextConfig,
        SymbolicName,
        URIType,
        URIWithMetadata,
        WritableSecurityContextConfig,
    )

    from . import (
        DraftEntry,
    )

from . import (
    ExportPluginException,
)

from .abstract_token_export import (
    AbstractTokenExportPlugin,
)


class AbstractTokenSandboxedExportPlugin(AbstractTokenExportPlugin):
    def __init__(
        self,
        refdir: "AbsPath",
        setup_block: "Optional[SecurityContextConfig]" = None,
        default_licences: "Sequence[LicenceDescription]" = [],
        default_orcids: "Sequence[ResolvedORCID]" = [],
        default_preferred_id: "Optional[str]" = None,
    ):
        if setup_block is None:
            setup_block = {}
        for conf_key in ("sandbox",):
            if conf_key not in setup_block:
                raise ExportPluginException(
                    f"Key {conf_key} was not found in setup block"
                )

        self.sandbox = bool(setup_block["sandbox"])

        new_setup_block = cast("WritableSecurityContextConfig", copy.copy(setup_block))
        # This code expects the children to implement it
        new_setup_block["api-prefix"] = self.get_api_prefix()

        super().__init__(
            refdir=refdir,
            setup_block=new_setup_block,
            default_licences=default_licences,
            default_orcids=default_orcids,
            default_preferred_id=default_preferred_id,
        )

    @abc.abstractmethod
    def get_api_prefix(self) -> "str":
        """
        This method returns the REST API prefix.
        It could be re-implemented
        """
        raise NotImplementedError()
