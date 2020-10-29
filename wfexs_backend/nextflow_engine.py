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
import re
import subprocess
import tempfile
from typing import Dict, List, Tuple

from .common import *
from .engine import WorkflowEngine, WorkflowEngineException

class NextflowWorkflowEngine(WorkflowEngine):
    NEXTFLOW_REPO = 'https://github.com/nextflow-io/nextflow'
    DEFAULT_NEXTFLOW_VERSION = '19.04.1'
    DEFAULT_NEXTFLOW_DOCKER_IMAGE = 'nextflow/nextflow'
    
    DEFAULT_MAX_RETRIES=5
    DEFAULT_MAX_CPUS=4
    
    ENGINE_NAME = 'nextflow'
    
    def __init__(self, cacheDir=None, workflow_config=None, local_config=None):
        super().__init__(cacheDir=cacheDir, workflow_config=workflow_config, local_config=local_config)
        
        self.java_cmd = local_config.get('tools',{}).get('javaCommand',DEFAULT_JAVA_CMD)
        
        self.nxf_image = local_config.get(self.ENGINE_NAME,{}).get('dockerImage',self.DEFAULT_NEXTFLOW_DOCKER_IMAGE)
        self.nxf_version = local_config.get(self.ENGINE_NAME,{}).get('version',self.DEFAULT_NEXTFLOW_VERSION)
        self.max_retries = local_config.get(self.ENGINE_NAME,{}).get('maxRetries',self.DEFAULT_MAX_RETRIES)
        self.max_cpus = local_config.get(self.ENGINE_NAME,{}).get('maxCpus',self.DEFAULT_MAX_CPUS)
    
    @classmethod
    def WorkflowType(cls) -> WorkflowType:
        return WorkflowType(
            engine=cls.ENGINE_NAME,
            clazz=cls,
            uri='https://www.nextflow.io/',
            trs_descriptor='NFL',
            rocrate_programming_language='#nextflow'
        )
    
    def identifyWorkflow(self, localWf: LocalWorkflow, engineVer: EngineVersion = None) -> Tuple[EngineVersion,LocalWorkflow]:
        """
        This method should return the effective engine version needed
        to run it when this workflow engine recognizes the workflow type
        """
        
        nfPath = localWf.dir
        if localWf.relPath is not None:
            engineVer = self.nxf_version
            nfPath = os.path.join(nfPath,localWf.relPath)
        
        if os.path.isdir(nfPath):
            nfDir = nfPath
            candidateNf = None
        else:
            nfDir = os.path.dirname(nfPath)
            candidateNf = os.path.basename(nfPath)
        
        nfConfig = os.path.join(nfDir,'nextflow.config')
        verPat = re.compile(r"nextflowVersion *= *['\"][>=]*([^ ]+)['\"]")
        mainPat = re.compile(r"mainScript *= *['\"]([^\"]+)['\"]")
        if engineVer is None:
            engineVer = self.nxf_version
        else:
            # We are deactivating the engine version capture from the config
            verPat = None
        if os.path.isfile(nfConfig):
            # Now, let's guess the nextflow version and mainScript
            with open(nfConfig,"r") as nc_config:
                for line in nc_config:
                    if verPat is not None:
                        matched = verPat.search(line)
                        if matched:
                            engineVer = matched.group(1)
                            verPat = None
                    
                    if mainPat is not None:
                        matched = mainPat.search(line)
                        if matched:
                            putativeCandidateNf = matched.group(1)
                            if candidateNf is not None:
                                if candidateNf != putativeCandidateNf:
                                    # This should be a warning
                                    raise WorkflowEngineException('Nextflow mainScript in manifest {} differs from the one requested {}'.format(putativeCandidateNf,candidateNf))
                            else:
                                candidateNf = putativeCandidateNf
                            mainPat = None
        
        if candidateNf is None:
            # Default case
            candidateNf = 'main.nf'
        
        entrypoint = os.path.join(nfDir,candidateNf)
        # Checking that the workflow entrypoint does exist
        if not os.path.isfile(entrypoint):
            raise WorkflowEngineException('Could not find mainScript {} in Nextflow workflow directory {} '.format(candidateNf,nfDir))
        
        if engineVer is None:
            engineVer = self.nxf_version
        
        return engineVer,LocalWorkflow
    
    def materializeEngineVersion(self, engineVersion: EngineVersion) -> EngineVersion:
        """
        Method to ensure the required engine version is materialized
        It should raise an exception when the exact version is unavailable,
        and no replacement could be fetched
        """
        
        if self.engine_mode == EngineMode.Docker:
            self.materializeEngineInDocker(engineVersion)
        elif self.engine_mode == EngineMode.Local:
            self.materializeEngineLocally(engineVersion)
        
        return engineVersion
    
    def materializeEngineLocally(self,nextflow_version: EngineVersion):
        # TODO
        pass
    
    def materializeEngineInDocker(self,nextflow_version: EngineVersion):
        # Now, we have to assure the nextflow image is already here
        docker_tag = self.nxf_image+':'+nextflow_version
        checkimage_params = [
            self.docker_cmd,"images","--format","{{.ID}}\t{{.Tag}}",docker_tag
        ]
        
        with tempfile.NamedTemporaryFile() as checkimage_stdout:
            with tempfile.NamedTemporaryFile() as checkimage_stderr:
                retval = subprocess.call(checkimage_params,stdout=checkimage_stdout,stderr=checkimage_stderr)

                if retval != 0:
                    # Reading the output and error for the report
                    with open(checkimage_stdout.name,"r") as c_stF:
                        checkimage_stdout_v = c_stF.read()
                    with open(checkimage_stderr.name,"r") as c_stF:
                        checkimage_stderr_v = c_stF.read()
                    
                    errstr = "ERROR: Nextflow Engine failed while checking Nextflow image (retval {}). Tag: {}\n======\nSTDOUT\n======\n{}\n======\nSTDERR\n======\n{}".format(retval,docker_tag,checkimage_stdout_v,checkimage_stderr_v)
                    raise WorkflowEngineException(errstr)
            
            do_pull_image = os.path.getsize(checkimage_stdout.name) == 0
                    
        
        if do_pull_image:
            # The image is not here yet
            pullimage_params = [
                self.docker_cmd,"pull",docker_tag
            ]
            with tempfile.NamedTemporaryFile() as pullimage_stdout:
                with tempfile.NamedTemporaryFile() as pullimage_stderr:
                    retval = subprocess.call(pullimage_params,stdout=pullimage_stdout,stderr=pullimage_stderr)
                    if retval != 0:
                        # Reading the output and error for the report
                        with open(pullimage_stdout.name,"r") as c_stF:
                            pullimage_stdout_v = c_stF.read()
                        with open(pullimage_stderr.name,"r") as c_stF:
                            pullimage_stderr_v = c_stF.read()
                        
                        # It failed!
                        errstr = "ERROR: Nextflow Engine failed while pulling Nextflow image (retval {}). Tag: {}\n======\nSTDOUT\n======\n{}\n======\nSTDERR\n======\n{}".format(retval,docker_tag,pullimage_stdout_v,pullimage_stderr_v)
                        raise WorkflowEngineException(errstr)
        
        return nextflow_version
    
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
    