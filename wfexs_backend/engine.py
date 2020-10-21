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

WorkflowType = namedtuple('WorkflowType',['name','class','uri'])

Container = namedtuple('Container',['name','tag','signature','type'])
# Symbolic name or identifier of the container
# Symbolic name or identifier of the tag
# Signature of the container (sha256 or similar)
# Container type

class WorkflowEngineException(Exception):
    """
    Exceptions fired by instances of WorkflowEngine
    """
    pass

class WorkflowEngine(abc.ABC):
    def __init__(self,entrypoint,cacheDir=None,workflow_config=dict(),local_config=dict()):
        """
        Abstract init method
        
        
        """
        self.entrypoint = entrypoint
        self.local_config = local_config
        
        # This one may be needed to identify container overrides
        # or specific engine versions
        self.workflow_config = workflow_config
        
        # cacheDir 
        if cacheDir is None:
            cacheDir = local_config.get('cacheDir')
            if cacheDir:
                os.makedirs(cacheDir, exist_ok=True)
            else:
                cacheDir = tempfile.mkdtemp(prefix='wes', suffix='backend')
                # Assuring this temporal directory is removed at the end
                atexit.register(shutil.rmtree, cacheDir)
        
        # We are using as our own caching directory one located at the
        # generic caching directory, with the name of the class
        self.wfCacheDir = os.path.join(cacheDir,self.__class__.__name__)
        
        # But, for materialized containers, we should use a common directory
        self.containersCacheDir = os.path.join(cacheDir,'containers')
    
    @abc.abstractclassmethod
    def WorkflowType(cls) -> WorkflowType:
        pass
    
    @abc.abstractmethod
    def identifyEngineVersion(self) -> str:
        """
        Method which identifies the version of the workflow engine
        """
        pass
    
    def effectiveEngineVersion(self) -> str:
        """
        Method which reports the concrete version of workflow engine in use
        """
    
    @abc.abstractmethod
    def materializeEngine(self):
        """
        Method to ensure the required engine version is materialized
        It should raise an exception when the exact version is unavailable,
        and no replacement could be fetched
        """
        
        pass
    
    @abc.abstractmethod
    def materializeWorkflow(self):
        """
        Method to ensure the workflow has been materialized.
        For Nextflow it is usually a no-op, but for CWL it requires resolution
        """
        
        pass
    
    @abc.abstractmethod
    def getListOfContainers(self) -> List[str]:
        """
        Method to get the list of containers needed by the workflow.
        As the different workflow languages use different ways to
        specify it. It lists the ones listed in the workflow, or
        the overriden ones
        """
        
        pass
    
    @abc.abstractmethod
    def getEffectiveListOfContainers(self) -> List[str]:
        """
        Method to get the list of containers used by the workflow.
        """
        
        pass
    
    def materializeContainers(self):
        # TODO
        
        pass
        