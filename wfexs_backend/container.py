#!/usr/bin/env python
# -*- coding: utf-8 -*-

# Copyright 2020-2021 Barcelona Supercomputing Center (BSC), Spain
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
import tempfile
import atexit
import shutil
import abc
import enum

from typing import Dict, List, Tuple
from collections import namedtuple

Container = namedtuple('Container',['name','tag','signature','type'])
# Symbolic name or identifier of the container
# Symbolic name or identifier of the tag
# Signature of the container (sha256 or similar)
# Container type

class ContainerFactory(abc.ABC):
    def __init__(self,cacheDir=None,local_config=dict()):
        """
        Abstract init method
        
        
        """
        self.local_config = local_config
        
        # cacheDir 
        if cacheDir is None:
            cacheDir = local_config.get('cacheDir')
            if cacheDir:
                os.makedirs(cacheDir, exist_ok=True)
            else:
                cacheDir = tempfile.mkdtemp(prefix='wes', suffix='backend')
                # Assuring this temporal directory is removed at the end
                atexit.register(shutil.rmtree, cacheDir)
        
        # But, for materialized containers, we should use a common directory
        self.containersCacheDir = os.path.join(cacheDir,'containers',self.__class__.__name__)
    
    def getListOfContainers(self):
        # TODO
        return []
    
    def materializeContainers(self, containersList = None):
        if containersList is None:
            containersList = self.getListOfContainers()
        
        # TODO
        
        pass
    