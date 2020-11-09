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
    CWLTOOL_REPO = 'https://github.com/common-workflow-language/' + CWLTOOL_PYTHON_PACKAGE
    CWL_UTILS_REPO = 'https://github.com/common-workflow-language/' + CWL_UTILS_PYTHON_PACKAGE
    DEFAULT_CWLTOOL_VERSION = '3.0.20201026152241'
    ENGINE_NAME = 'cwl'

    def __init__(self, cacheDir=None, workflow_config=None, local_config=None, engineTweaksDir=None):
        super().__init__(cacheDir=cacheDir, workflow_config=workflow_config, local_config=local_config, engineTweaksDir=engineTweaksDir)
        
        self.cwl_version = local_config.get(self.ENGINE_NAME, {}).get('version', self.DEFAULT_CWLTOOL_VERSION)

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

        cwlPath = localWf.dir
        if localWf.relPath is not None:
            engineVer = self.cwl_version
            cwlPath = os.path.join(cwlPath, localWf.relPath)

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
                    "source bin/activate ; pip install --upgrade pip wheel ; pip install {}=={} {}".format(
                        self.CWLTOOL_PYTHON_PACKAGE, engineVersion, self.CWL_UTILS_PYTHON_PACKAGE),
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

    def materializeWorkflow(self, matWorfklowEngine: MaterializedWorkflowEngine) -> Tuple[MaterializedWorkflowEngine, List[Container]]:
        """
        Method to ensure the workflow has been materialized. It returns the 
        localWorkflow directory, as well as the list of containers
        
        For Nextflow it is usually a no-op, but for CWL it requires resolution
        """

        # TODO
        return matWorfklowEngine, []

    def launchWorkflow(self, localWf: LocalWorkflow, inputs: List[MaterializedInput], outputs):
        # TODO
        pass
