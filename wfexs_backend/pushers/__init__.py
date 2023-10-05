#!/usr/bin/env python
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

import abc
import logging
from typing import (
    cast,
    TYPE_CHECKING,
)
import urllib.parse

if TYPE_CHECKING:
    from typing import (
        Any,
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

    from ..workflow import WF

from ..common import (
    AcceptableLicenceSchemes,
    NoLicence,
    ROCrateShortLicences,
)


class ExportPluginException(Exception):
    pass


class AbstractExportPlugin(abc.ABC):
    """
    Abstract class to model stateful export plugins
    """

    PLUGIN_NAME = cast("SymbolicName", "")

    def __init__(
        self,
        wfInstance: "WF",
        setup_block: "Optional[SecurityContextConfig]" = None,
        licences: "Sequence[str]" = [],
        orcids: "Sequence[str]" = [],
    ):
        import inspect

        self.logger = logging.getLogger(
            dict(inspect.getmembers(self))["__module__"]
            + "::"
            + self.__class__.__name__
        )
        # This is used to resolve paths
        self.wfInstance = wfInstance
        self.refdir = wfInstance.getStagedSetup().work_dir
        self.setup_block = setup_block if isinstance(setup_block, dict) else dict()

        # As these licences can be in short format, resolve them to URIs
        expanded_licences: "MutableSequence[URIType]" = []
        if len(licences) == 0:
            expanded_licences.append(NoLicence)
        else:
            rejected_licences: "MutableSequence[str]" = []
            for lic in licences:
                expanded_licence = ROCrateShortLicences.get(lic)
                if expanded_licence is None:
                    if (
                        urllib.parse.urlparse(lic).scheme
                        not in AcceptableLicenceSchemes
                    ):
                        rejected_licences.append(lic)

                    expanded_licence = lic

                expanded_licences.append(cast("URIType", expanded_licence))

            if len(rejected_licences) > 0:
                raise ExportPluginException(
                    f"Unsupported license URI scheme(s) or Workflow RO-Crate short license(s): {', '.join(rejected_licences)}"
                )

        # FIXME: ORCIDs are bypassed (for now)
        expanded_orcids = orcids

        self.licences: "Tuple[URIType, ...]" = tuple(expanded_licences)
        self.orcids: "Tuple[str, ...]" = tuple(expanded_orcids)

    @abc.abstractmethod
    def push(
        self,
        items: "Sequence[AnyContent]",
        preferred_scheme: "Optional[str]" = None,
        preferred_id: "Optional[str]" = None,
    ) -> "Sequence[URIWithMetadata]":
        """
        This is the method to be implemented by the stateful pusher
        """
        pass

    @classmethod
    def PluginName(cls) -> "SymbolicName":
        return cls.PLUGIN_NAME
