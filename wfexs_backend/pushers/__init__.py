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


class ExportPluginException(Exception):
    pass


class AbstractExportPlugin(abc.ABC):
    """
    Abstract class to model stateful export plugins
    """

    PLUGIN_NAME: "ClassVar[SymbolicName]" = cast("SymbolicName", "")
    # Is this implementation enabled?
    ENABLED: "ClassVar[bool]" = True

    def __init__(
        self,
        refdir: "AbsPath",
        setup_block: "Optional[SecurityContextConfig]" = None,
        licences: "Sequence[URIType]" = [],
        orcids: "Sequence[str]" = [],
        preferred_id: "Optional[str]" = None,
    ):
        import inspect

        self.logger = logging.getLogger(
            dict(inspect.getmembers(self))["__module__"]
            + "::"
            + self.__class__.__name__
        )
        # This is used to resolve paths
        self.refdir = refdir
        self.setup_block = setup_block if isinstance(setup_block, dict) else dict()

        # This is the default value for the preferred PID
        # which can be updated through a call to book_pid
        self.preferred_id = preferred_id

        self.licences: "Tuple[URIType, ...]" = tuple(licences)
        self.orcids: "Tuple[str, ...]" = tuple(orcids)

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

    def book_pid(self, preferred_id: "Optional[str]" = None) -> "Optional[str]":
        """
        This method is used to book a new PID,
        in case the destination allows it.

        We can even "suggest" either a new or existing PID.

        When it returns None, it means either
        the destination does not allow booking
        pids, either temporary or permanently
        """

        return self.preferred_id

    @classmethod
    def PluginName(cls) -> "SymbolicName":
        return cls.PLUGIN_NAME
