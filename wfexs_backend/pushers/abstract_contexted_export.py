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
    from os import (
        PathLike,
    )

    from typing import (
        Any,
        Optional,
        Sequence,
        Union,
    )

    from ..common import (
        AbsPath,
        LicenceDescription,
        ResolvedORCID,
        SecurityContextConfig,
        URIType,
    )

    from ..wfexs_backend import WfExSBackend

from . import AbstractExportPlugin


class AbstractContextedExportPlugin(AbstractExportPlugin):
    """
    Abstract class to model stateful export plugins
    which need the workflow context
    """

    def __init__(
        self,
        refdir: "AbsPath",
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
        self.wfexs: "Optional[WfExSBackend]" = None
        self.tempdir: "Optional[Union[str, PathLike[Any]]]" = None

    def set_wfexs_context(
        self,
        wfexs: "WfExSBackend",
        tempdir: "Optional[Union[str, PathLike[Any]]]" = None,
    ) -> "None":
        self.wfexs = wfexs
        self.tempdir = tempdir
