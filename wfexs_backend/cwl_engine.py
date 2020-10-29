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

from typing import Dict, List, Tuple

from .common import *
from .engine import WorkflowEngine, WorkflowEngineException

class CWLWorkflowEngine(WorkflowEngine):
    CWLTOOL_REPO = 'https://github.com/common-workflow-language/cwltool'
    DEFAULT_CWLTOOL_VERSION = '3.0.20200807132242'
    ENGINE_NAME = 'cwl'
    
    def __init__(self, cacheDir=None, workflow_config=None, local_config=None):
        super().__init__(cacheDir=cacheDir, workflow_config=workflow_config, local_config=local_config)
    
    @classmethod
    def WorkflowType(cls) -> WorkflowType:
        return WorkflowType(
            engine=cls.ENGINE_NAME,
            clazz=cls,
            uri='https://w3id.org/cwl/v1.0/',
            trs_descriptor='CWL',
            rocrate_programming_language='#cwl'
        )
    
    def identifyWorkflow(self, localWf: LocalWorkflow) -> EngineVersion:
        """
        This method should return the effective engine version needed
        to run it when this workflow engine recognizes the workflow type
        """
        
        engineVer = None
        # TODO: Check whether there is a CWL workflow there
        if True:
            engineVer = self.DEFAULT_CWLTOOL_VERSION
        
        return engineVer
    
    def materializeEngineVersion(self, engineVersion: EngineVersion) -> EngineVersion:
        """
        Method to ensure the required engine version is materialized
        It should raise an exception when the exact version is unavailable,
        and no replacement could be fetched
        """
        
        # TODO
        
        return engineVersion
    
    def materializeWorkflow(self, localWf: LocalWorkflow) -> Tuple[LocalWorkflow, List[Container]]:
        """
        Method to ensure the workflow has been materialized. It returns the 
        localWorkflow directory, as well as the list of containers
        
        For Nextflow it is usually a no-op, but for CWL it requires resolution
        """
        
        # TODO
        return localWf, []
    
    def launchWorkflow(self, localWf: LocalWorkflow, inputs: List[MaterializedInput], outputs):
        # TODO
        pass
        