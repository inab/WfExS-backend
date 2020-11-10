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
from typing import Dict, List, Tuple

import subprocess
import tempfile
import venv

from .common import *
from .engine import WorkflowEngine, WorkflowEngineException


class CWLWorkflowEngine(WorkflowEngine):
    CWLTOOL_PYTHON_PACKAGE = 'cwltool'
    CWL_UTILS_PYTHON_PACKAGE = 'cwl-utils'
    SCHEMA_SALAD_PYTHON_PACKAGE = 'schema-salad'
    CWL_REPO = 'https://github.com/common-workflow-language/'
    CWLTOOL_REPO = CWL_REPO + CWLTOOL_PYTHON_PACKAGE
    CWL_UTILS_REPO = CWLTOOL_REPO + CWL_UTILS_PYTHON_PACKAGE
    DEFAULT_CWLTOOL_VERSION = '3.0.20201026152241'
    DEFAULT_CWL_UTILS_VERSION = '0.7'
    DEFAULT_SCHEMA_SALAD_VERSION = '7.0.20200811075006'
    ENGINE_NAME = 'cwl'

    def __init__(self, cacheDir=None, workflow_config=None, local_config=None, engineTweaksDir=None, cacheWorkflowDir=None):
        super().__init__(cacheDir=cacheDir, workflow_config=workflow_config, local_config=local_config,
                         engineTweaksDir=engineTweaksDir, cacheWorkflowDir=cacheWorkflowDir)

        self.cwl_version = local_config.get(self.ENGINE_NAME, {}).get('version', self.DEFAULT_CWLTOOL_VERSION)
        # Setting up packed directory
        self.cacheWorkflowPackDir = os.path.join(self.cacheWorkflowDir, 'wf-pack')
        os.makedirs(self.cacheWorkflowPackDir, exist_ok=True)

    @classmethod
    def WorkflowType(cls) -> WorkflowType:
        return WorkflowType(
            engineName=cls.ENGINE_NAME,
            clazz=cls,
            uri='https://w3id.org/cwl/v1.0/',
            trs_descriptor='CWL',
            rocrate_programming_language='#cwl'
        )

    def identifyWorkflow(self, localWf: LocalWorkflow, engineVer: EngineVersion = None) -> Tuple[EngineVersion, LocalWorkflow]:
        """
        This method should return the effective engine version needed
        to run it when this workflow engine recognizes the workflow type
        """

        # TODO: Check whether there is a CWL workflow there, and materialize it

        if localWf.relPath is not None:
            engineVer = self.cwl_version

        if engineVer is None:
            engineVer = self.cwl_version

        return engineVer, localWf

    def materializeEngineVersion(self, engineVersion: EngineVersion) -> Tuple[EngineVersion, Fingerprint]:
        """
        Method to ensure the required engine version is materialized
        It should raise an exception when the exact version is unavailable,
        and no replacement could be fetched
        """

        if self.engine_mode != EngineMode.Local:
            raise WorkflowEngineException(
                'Unsupported engine mode {} for {} engine'.format(self.engine_mode, self.ENGINE_NAME))

        # A version directory is needed
        cwl_install_dir = os.path.join(self.weCacheDir, engineVersion)

        # Creating the virtual environment needed to separate CWL code
        # from workflow execution backend
        if not os.path.isdir(cwl_install_dir):
            venv.create(cwl_install_dir, with_pip=True)

        # Now, time to run it
        instEnv = dict(os.environ)

        with tempfile.NamedTemporaryFile() as cwl_install_stdout:
            with tempfile.NamedTemporaryFile() as cwl_install_stderr:
                retval = subprocess.Popen(
                    "source bin/activate ; pip install --upgrade pip wheel ; pip install {}=={}  {}=={}  {}=={}".format(
                        self.SCHEMA_SALAD_PYTHON_PACKAGE, self.DEFAULT_SCHEMA_SALAD_VERSION,
                        self.CWL_UTILS_PYTHON_PACKAGE,
                        self.DEFAULT_CWL_UTILS_VERSION, self.CWLTOOL_PYTHON_PACKAGE, engineVersion),
                    stdout=cwl_install_stdout,
                    stderr=cwl_install_stderr,
                    cwd=cwl_install_dir,
                    shell=True,
                    env=instEnv
                ).wait()

                # Proper error handling
                if retval != 0:
                    # Reading the output and error for the report
                    with open(cwl_install_stdout.name, "r") as c_stF:
                        cwl_install_stdout_v = c_stF.read()
                    with open(cwl_install_stderr.name, "r") as c_stF:
                        cwl_install_stderr_v = c_stF.read()

                    errstr = "Could not install CWL {} . Retval {}\n======\nSTDOUT\n======\n{}\n======\nSTDERR\n======\n{}".format(
                        engineVersion, retval, cwl_install_stdout_v, cwl_install_stderr_v)
                    raise WorkflowEngineException(errstr)
        # TODO

        return engineVersion, None

    def materializeWorkflow(self, matWorkflowEngine: MaterializedWorkflowEngine) -> Tuple[MaterializedWorkflowEngine, List[Container]]:
        """
        Method to ensure the workflow has been materialized. It returns the 
        localWorkflow directory, as well as the list of containers
        
        For Nextflow it is usually a no-op, but for CWL it requires resolution
        """
        localWf = matWorkflowEngine.workflow
        localWorkflowDir = localWf.dir
        if os.path.isabs(localWf.relPath):
            localWorkflowFile = localWf.relPath
        else:
            localWorkflowFile = os.path.join(localWorkflowDir, localWf.relPath)
        engineVersion = matWorkflowEngine.version
        
        if not os.path.isfile(localWorkflowFile):
            raise WorkflowEngineException(
                'CWL workflow {} has not been materialized.'.format(localWorkflowFile))
        
        # Extract hashes directories from localWorkflow
        localWorkflowUsedHashes_head, localWorkflowUsedHashes_tail = localWorkflowDir.split("/")[-2:]

        # Setting up workflow packed name
        localWorkflowPackedName = (os.path.join(localWorkflowUsedHashes_head, localWorkflowUsedHashes_tail) + ".cwl").replace("/", "_")
        packedLocalWorkflowFile = os.path.join(self.cacheWorkflowPackDir, localWorkflowPackedName)
        
        if not os.path.isfile(packedLocalWorkflowFile) or os.path.getsize(packedLocalWorkflowFile) == 0:   # localWorkflow has not been packed
            # Execute cwltool --pack
            # CWLWorkflowEngine directory is needed
            cwl_install_dir = os.path.join(self.weCacheDir, engineVersion)

            with open(packedLocalWorkflowFile,mode='wb') as packedH:
                with tempfile.NamedTemporaryFile() as cwl_pack_stderr:
                    # Writing straight to the file
                    retval = subprocess.Popen(
                        "source bin/activate ; cwltool --no-doc-cache --pack {}".format(localWorkflowFile),
                        stdout=packedH,
                        stderr=cwl_pack_stderr,
                        cwd=cwl_install_dir,
                        shell=True
                    ).wait()

                    # Proper error handling
                    if retval != 0:
                        # Reading the output and error for the report
                        with open(cwl_pack_stderr.name, "r") as c_stF:
                            cwl_pack_stderr_v = c_stF.read()

                        errstr = "Could not pack CWL running cwltool --pack {}. Retval {}\n======\nSTDERR\n======\n{}".format(
                            engineVersion, retval, cwl_pack_stderr_v)
                        raise WorkflowEngineException(errstr)
        
        #  TODO list of containers
        containersList = []
        
        newLocalWf = LocalWorkflow(dir=localWf.dir,relPath=packedLocalWorkflowFile,effectiveCheckout=localWf.effectiveCheckout)
        newWfEngine = MaterializedWorkflowEngine(instance=matWorkflowEngine.instance, version=engineVersion, fingerprint=matWorkflowEngine.fingerprint, workflow=newLocalWf)
        return newWfEngine, containersList

    def launchWorkflow(self, localWf: LocalWorkflow, inputs: List[MaterializedInput], outputs):
        # TODO
        pass
