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

from .common import *

from typing import Dict, List, Tuple
from collections import namedtuple

from .container import Container, ContainerFactory
from .singularity_container import SingularityContainerFactory

class WorkflowEngineException(Exception):
    """
    Exceptions fired by instances of WorkflowEngine
    """
    pass


CONTAINER_FACTORY_CLASSES = [
    SingularityContainerFactory,
]

class WorkflowEngine(abc.ABC):
    def __init__(self, cacheDir=None, workflow_config=None, local_config=None, engineTweaksDir=None, cacheWorkflowDir=None):
        """
        Abstract init method

        :param cacheDir:
        :param workflow_config:
            This one may be needed to identify container overrides
            or specific engine versions
        :param local_config:
        :param engineTweaksDir:
        """
        if local_config is None:
            local_config = dict()
        if workflow_config is None:
            workflow_config = dict()
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
                cacheDir = tempfile.mkdtemp(prefix='WfExS', suffix='backend')
                # Assuring this temporal directory is removed at the end
                atexit.register(shutil.rmtree, cacheDir)
        
        # We are using as our own caching directory one located at the
        # generic caching directory, with the name of the class
        self.weCacheDir = os.path.join(cacheDir, self.__class__.__name__)
        
        # Needed for those cases where alternate version of the workflow is generated
        if cacheWorkflowDir is None:
            cacheWorkflowDir = os.path.join(cacheDir, 'wf-cache')
            os.makedirs(cacheWorkflowDir, exist_ok=True)
        self.cacheWorkflowDir = cacheWorkflowDir
        
        
        # engine tweaks directory
        if engineTweaksDir is None:
            engineTweaksDir = tempfile.mkdtemp(prefix='WfExS-tweaks', suffix='backend')
            # Assuring this temporal directory is removed at the end
            atexit.register(shutil.rmtree, engineTweaksDir)
        
        self.engineTweaksDir = engineTweaksDir
        
        # Setting up common properties
        self.docker_cmd = local_config.get('tools', {}).get('dockerCommand', DEFAULT_DOCKER_CMD)
        engine_mode = local_config.get('tools', {}).get('engineMode')
        if engine_mode is None:
            engine_mode = DEFAULT_ENGINE_MODE
        else:
            engine_mode = EngineMode(engine_mode)
        self.engine_mode = engine_mode
        
        container_type = local_config.get('tools', {}).get('containerType')
        if container_type is None:
            container_type = DEFAULT_CONTAINER_TYPE
        else:
            container_type = ContainerType(container_type)
        
        for containerFactory in CONTAINER_FACTORY_CLASSES:
            if containerFactory.ContainerType() == container_type:
                self.container_factory = containerFactory(cacheDir=cacheDir,local_config=local_config)
                break
        else:
            raise WorkflowEngineException("FATAL: No container factory implementation for {}".format(container_type))
    
    @classmethod
    @abc.abstractmethod
    def WorkflowType(cls) -> WorkflowType:
        pass
    
    @property
    def workflowType(self) -> WorkflowType:
        return self.WorkflowType()
    
    @abc.abstractmethod
    def identifyWorkflow(self, localWf: LocalWorkflow, engineVer: EngineVersion = None) -> Tuple[EngineVersion, LocalWorkflow]:
        """
        This method should return the effective engine version needed
        to run it when this workflow engine recognizes the workflow type
        """
        pass

    @abc.abstractmethod
    def materializeEngineVersion(self, engineVersion: EngineVersion) -> Tuple[EngineVersion, Fingerprint]:
        """
        Method to ensure the required engine version is materialized
        It should raise an exception when the exact version is unavailable,
        and no replacement could be fetched
        """

        pass

    def materializeEngine(self, localWf: LocalWorkflow,
                          engineVersion: EngineVersion = None) -> MaterializedWorkflowEngine:
        """
        Method to ensure the required engine version is materialized
        It should raise an exception when the exact version is unavailable,
        and no replacement could be fetched
        """

        # This method can be forced to materialize an specific engine version
        if engineVersion is None:
            # The identification could return an augmented LocalWorkflow instance
            engineVersion, localWf = self.identifyWorkflow(localWf, engineVersion)
            if engineVersion is None:
                return None
        
        # This is needed for those cases where there is no exact match
        # on the available engine version
        engineVersion , engineFingerprint = self.materializeEngineVersion(engineVersion)

        return MaterializedWorkflowEngine(instance=self, version=engineVersion, fingerprint=engineFingerprint,
                                          workflow=localWf)

    @abc.abstractmethod
    def materializeWorkflow(self, matWorfklowEngine: MaterializedWorkflowEngine) -> Tuple[MaterializedWorkflowEngine, List[ContainerTaggedName]]:
        """
        Method to ensure the workflow has been materialized. It returns the 
        localWorkflow directory, as well as the list of containers
        
        For Nextflow it is usually a no-op, but for CWL it requires resolution
        """
        
        pass
    
    def materializeContainers(self, listOfContainerTags: List[ContainerTaggedName]) -> List[Container]:
        return self.container_factory.materializeContainers(listOfContainerTags)
    
    @abc.abstractmethod
    def launchWorkflow(self, localWf: LocalWorkflow, inputs: List[MaterializedInput], outputs):
        pass
    
    @classmethod
    def ExecuteWorkflow(cls, matWfEng: MaterializedWorkflowEngine,inputs: List[MaterializedInput], outputs):
        return matWfEng.instance.launchWorkflow(matWfEng.workflow, inputs, outputs)
    
    @classmethod
    def MaterializeWorkflow(cls, matWfEng: MaterializedWorkflowEngine) -> Tuple[MaterializedWorkflowEngine, List[Container]]:
        matWfEng, listOfContainerTags = matWfEng.instance.materializeWorkflow(matWfEng)
        
        listOfContainers = matWfEng.instance.materializeContainers(listOfContainerTags)
        
        return matWfEng, listOfContainers
        