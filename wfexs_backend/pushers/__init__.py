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

import abc
import logging
from typing import Any, Mapping, Optional, Sequence, TYPE_CHECKING, Union
from typing import cast
from typing_extensions import Final

from ..common import AbsPath, RelPath, ExportItem, SymbolicName
from ..common import SecurityContextConfig, URIWithMetadata
from ..common import MaterializedInput, MaterializedOutput
from ..common import AnyContent

if TYPE_CHECKING:
    from ..workflow import WF

class ExportPluginException(Exception):
    pass

class AbstractExportPlugin(abc.ABC):
    """
    Abstract class to model stateful export plugins
    """
    PLUGIN_NAME : SymbolicName = cast(SymbolicName, "")
    def __init__(self, wfInstance: "WF", setup_block: Optional[SecurityContextConfig] = None):
        import inspect
        
        self.logger = logging.getLogger(dict(inspect.getmembers(self))['__module__'] + '::' + self.__class__.__name__)
        # This is used to resolve paths
        self.wfInstance = wfInstance
        self.refdir = wfInstance.getStagedSetup().work_dir
        self.setup_block = setup_block  if isinstance(setup_block, dict)  else dict()
    
    @abc.abstractmethod
    def push(self, items: Sequence[AnyContent], preferred_scheme: Optional[str] = None, preferred_id: Optional[str] = None) -> Sequence[URIWithMetadata]:
        """
        This is the method to be implemented by the stateful pusher
        """
        pass
    
    @classmethod
    def PluginName(cls) -> SymbolicName:
        return cls.PLUGIN_NAME
