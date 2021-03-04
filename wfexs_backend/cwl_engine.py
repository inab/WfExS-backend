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
import re
import json

import yaml
import jsonpath_ng
import jsonpath_ng.ext

from .common import *
from .engine import WorkflowEngine, WorkflowEngineException
from .container import NoContainerFactory
from .singularity_container import SingularityContainerFactory

# Next methods are borrowed from
# https://github.com/common-workflow-language/cwltool/blob/5bdb3d3dd47d8d1b3a1685220b4b6ce0f94c055e/cwltool/singularity.py#L83
def _normalize_image_id(string: str) -> str:
    return string.replace("/", "_") + ".img"

def _normalize_sif_id(string: str) -> str:
    return string.replace("/", "_") + ".sif"


class CWLWorkflowEngine(WorkflowEngine):
    CWLTOOL_PYTHON_PACKAGE = 'cwltool'
    CWL_UTILS_PYTHON_PACKAGE = 'cwl-utils'
    SCHEMA_SALAD_PYTHON_PACKAGE = 'schema-salad'

    CWL_REPO = 'https://github.com/common-workflow-language/'
    CWLTOOL_REPO = CWL_REPO + CWLTOOL_PYTHON_PACKAGE
    CWL_UTILS_REPO = CWLTOOL_REPO + CWL_UTILS_PYTHON_PACKAGE

    DEFAULT_CWLTOOL_VERSION = '3.0.20210124104916'
    DEFAULT_CWL_UTILS_VERSION = '0.9'
    DEFAULT_SCHEMA_SALAD_VERSION = '7.0.20210124093443'

    ENGINE_NAME = 'cwl'

    def __init__(self,
                 cacheDir=None,
                 workflow_config=None,
                 local_config=None,
                 engineTweaksDir=None,
                 cacheWorkflowDir=None,
                 workDir=None,
                 outputsDir=None,
                 intermediateDir=None
                 ):
        super().__init__(cacheDir=cacheDir, workflow_config=workflow_config, local_config=local_config,
                         engineTweaksDir=engineTweaksDir, cacheWorkflowDir=cacheWorkflowDir,
                         workDir=workDir, outputsDir=outputsDir, intermediateDir=intermediateDir)

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

    def materializeEngineVersion(self, engineVersion: EngineVersion) -> Tuple[EngineVersion, EnginePath, Fingerprint]:
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
                retVal = subprocess.Popen(
                    "source '{0}'/bin/activate ; pip install --upgrade pip wheel ; pip install {1}=={2}  {3}=={4}  {5}=={6}".format(
                        cwl_install_dir,
                        self.SCHEMA_SALAD_PYTHON_PACKAGE, self.DEFAULT_SCHEMA_SALAD_VERSION,
                        self.CWL_UTILS_PYTHON_PACKAGE, self.DEFAULT_CWL_UTILS_VERSION,
                        self.CWLTOOL_PYTHON_PACKAGE, engineVersion),
                    stdout=cwl_install_stdout,
                    stderr=cwl_install_stderr,
                    cwd=cwl_install_dir,
                    shell=True,
                    env=instEnv
                ).wait()

                # Proper error handling
                if retVal != 0:
                    # Reading the output and error for the report
                    with open(cwl_install_stdout.name, "r") as c_stF:
                        cwl_install_stdout_v = c_stF.read()
                    with open(cwl_install_stderr.name, "r") as c_stF:
                        cwl_install_stderr_v = c_stF.read()

                    errstr = "Could not install CWL {} . Retval {}\n======\nSTDOUT\n======\n{}\n======\nSTDERR\n======\n{}".format(
                        engineVersion, retVal, cwl_install_stdout_v, cwl_install_stderr_v)
                    raise WorkflowEngineException(errstr)

        # TODO

        return engineVersion, cwl_install_dir, ""

    def materializeWorkflow(self, matWorkflowEngine: MaterializedWorkflowEngine) -> Tuple[MaterializedWorkflowEngine, List[ContainerTaggedName]]:
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
        # CWLWorkflowEngine directory is needed
        cwl_install_dir = matWorkflowEngine.engine_path

        if not os.path.isfile(localWorkflowFile):
            raise WorkflowEngineException(
                'CWL workflow {} has not been materialized.'.format(localWorkflowFile))

        # Extract hashes directories from localWorkflow
        localWorkflowUsedHashes_head, localWorkflowUsedHashes_tail = localWorkflowDir.split("/")[-2:]

        # Setting up workflow packed name
        localWorkflowPackedName = (
                os.path.join(localWorkflowUsedHashes_head, localWorkflowUsedHashes_tail) + ".cwl").replace("/", "_")
        packedLocalWorkflowFile = os.path.join(self.cacheWorkflowPackDir, localWorkflowPackedName)

        # TODO: check whether the repo is newer than the packed file

        if not os.path.isfile(packedLocalWorkflowFile) or os.path.getsize(packedLocalWorkflowFile) == 0:
            # Execute cwltool --pack
            with open(packedLocalWorkflowFile, mode='wb') as packedH:
                with tempfile.NamedTemporaryFile() as cwl_pack_stderr:
                    # Writing straight to the file
                    retVal = subprocess.Popen(
                        "source '{0}'/bin/activate ; cwltool --no-doc-cache --pack {1}".format(cwl_install_dir,localWorkflowFile),
                        stdout=packedH,
                        stderr=cwl_pack_stderr,
                        cwd=cwl_install_dir,
                        shell=True
                    ).wait()

                    # Proper error handling
                    if retVal != 0:
                        # Reading the output and error for the report
                        with open(cwl_pack_stderr.name, "r") as c_stF:
                            cwl_pack_stderr_v = c_stF.read()

                        errstr = "Could not pack CWL running cwltool --pack {}. Retval {}\n======\nSTDERR\n======\n{}".format(
                            engineVersion, retVal, cwl_pack_stderr_v)
                        raise WorkflowEngineException(errstr)

        containerTags = set()
        
        # Getting the identifiers
        with open(packedLocalWorkflowFile, encoding='utf-8') as pLWH:
            wf_yaml = yaml.safe_load(pLWH)  # parse packed CWL
            dockerExprParser = jsonpath_ng.ext.parse('$."$graph"..requirements[?class = "DockerRequirement"][*]')
            for match in dockerExprParser.find(wf_yaml):
                dockerPullId = match.value.get('dockerPull')
                
                # Fallback to dockerImageId if dockerPull was not set
                # https://www.commonwl.org/v1.0/CommandLineTool.html#DockerRequirement
                if dockerPullId is None:
                    dockerPullId = match.value.get('dockerImageId')
                
                # TODO: treat other cases like dockerImport or dockerLoad?
                
                containerTags.add(dockerPullId)
        
        newLocalWf = LocalWorkflow(dir=localWf.dir, relPath=packedLocalWorkflowFile,
                                   effectiveCheckout=localWf.effectiveCheckout)
        newWfEngine = MaterializedWorkflowEngine(
                            instance=matWorkflowEngine.instance,
                            version=engineVersion,
                            fingerprint=matWorkflowEngine.fingerprint,
                            engine_path=cwl_install_dir,
                            workflow=newLocalWf
                        )
        return newWfEngine, list(containerTags)
    
    def simpleContainerFileName(self, imageUrl: URIType) -> RelPath:
        """
        This method was borrowed from
        https://github.com/common-workflow-language/cwltool/blob/5bdb3d3dd47d8d1b3a1685220b4b6ce0f94c055e/cwltool/singularity.py#L107
        """
        
        #match = re.search(
        #    pattern=r"([a-z]*://)", string=imageUrl
        #)
        img_name = _normalize_image_id(imageUrl)
        #candidates.append(img_name)
        #sif_name = _normalize_sif_id(dockerRequirement["dockerPull"])
        #candidates.append(sif_name)
        
        return img_name
    
    def launchWorkflow(self, matWfEng: MaterializedWorkflowEngine, matInputs: List[MaterializedInput],
                       outputs: List[ExpectedOutput]) -> Tuple[ExitVal, List[MaterializedInput], List[MaterializedOutput]]:
        """
        Method to execute the workflow
        """
        localWf = matWfEng.workflow
        localWorkflowFile = localWf.relPath
        engineVersion = matWfEng.version

        if os.path.exists(localWorkflowFile):
            cwl_dict_inputs = dict()
            with open(localWorkflowFile, "r") as cwl_file:
                cwl_yaml = yaml.safe_load(cwl_file)  # convert packed CWL to YAML
                
                # As the workflow has been packed, the #main element appears
                io_parser = jsonpath_ng.ext.parse('$."$graph"[?class = "Workflow"]')
                cwl_yaml_inputs = None
                cwl_yaml_outputs = None
                wfId = None
                wfIdPrefix = None
                for match in io_parser.find(cwl_yaml):
                    wf = match.value
                    wfId = wf.get('id')
                    wfIdPrefix = ''  if wfId is None  else  wfId + '/'
                    
                    cwl_yaml_inputs = wf.get('inputs',[])
                    cwl_yaml_outputs = wf.get('outputs',[])
                
                # Setting packed CWL inputs (id, type)
                for cwl_yaml_input in cwl_yaml_inputs:  # clean string of packed CWL inputs
                    cwl_yaml_input_id = str(cwl_yaml_input['id'])
                    # Validating
                    if cwl_yaml_input_id.startswith(wfIdPrefix):
                        inputId = cwl_yaml_input_id[len(wfIdPrefix):]
                    else:
                        inputId = cwl_yaml_input_id
                    
                    if inputId not in cwl_dict_inputs:
                        cwl_dict_inputs[inputId] = cwl_yaml_input
            
            # TODO change the hardcoded filename
            inputsFileName = "inputdeclarations.yaml"
            yamlFile = os.path.join(self.workDir, inputsFileName)

            try:
                # Create YAML file
                augmentedInputs = self.createYAMLFile(matInputs, cwl_dict_inputs, yamlFile)
                if os.path.isfile(yamlFile):
                    # CWLWorkflowEngine directory is needed
                    cwl_install_dir = matWfEng.engine_path

                    # Execute workflow
                    with tempfile.NamedTemporaryFile() as cwl_yaml_stdout:
                        with tempfile.NamedTemporaryFile() as cwl_yaml_stderr:
                            intermediateDir = self.intermediateDir + "/"
                            outputDir = self.outputsDir + "/"
                            
                            # This is needed to teach cwltool where to find the cached images
                            instEnv = dict(os.environ)
                            if isinstance(self.container_factory,SingularityContainerFactory):
                                cmdTemplate = "cwltool --outdir {0} --strict --on-error continue --no-doc-cache --disable-pull --singularity --tmp-outdir-prefix={1} --tmpdir-prefix={1} {2} {3}"
                                instEnv['CWL_SINGULARITY_CACHE'] = self.container_factory.cacheDir
                            elif isinstance(self.container_factory,NoContainerFactory):
                                cmdTemplate = "cwltool --outdir {0} --strict --on-error continue --no-doc-cache --no-container --tmp-outdir-prefix={1} --tmpdir-prefix={1} {2} {3}"
                            else:
                                raise WorkflowEngineException("FATAL ERROR: Unsupported container factory {}".format(self.container_factory.ContainerType()))
                            
                            cmd = cmdTemplate.format(outputDir, intermediateDir, localWorkflowFile, yamlFile)

                            retVal = subprocess.Popen("source '{0}'/bin/activate  ; {1}".format(cwl_install_dir,cmd),
                                                      stdout=cwl_yaml_stdout,
                                                      stderr=cwl_yaml_stderr,
                                                      cwd=cwl_install_dir,
                                                      shell=True,
                                                      env=instEnv
                                                      ).wait()
                            
                            # Proper error handling
                            if retVal != 0:
                                # Reading the error for the report
                                with open(cwl_yaml_stderr.name, "r") as c_stF:
                                    cwl_pack_stderr_v = c_stF.read()

                                errstr = "Could not execute CWL running cwltool --pack {}. Retval {}\n======\nSTDERR\n======\n{}".format(
                                    engineVersion, retVal, cwl_pack_stderr_v)
                                raise WorkflowEngineException(errstr)
                            
                            else:
                                # Reading the output for the report
                                with open(cwl_yaml_stdout.name, "r") as c_stT:
                                    cwl_yaml_stdout_v = c_stT.read()
                                    outputs = self.executionOutputs(json.loads(cwl_yaml_stdout_v))
                            
                    return 0, list(augmentedInputs.items()), list(outputs.items())

            except WorkflowEngineException as wfex:
                raise wfex
            except Exception as error:
                raise WorkflowEngineException(
                    "ERROR: cannot execute the workflow {}, {}".format(localWorkflowFile, error)
                )
        else:
            raise WorkflowEngineException(
                'CWL workflow {} has not been successfully materialized and packed for their execution'.format(
                    localWorkflowFile)
            )

    def createYAMLFile(self, matInputs, cwlInputs, filename):
        """
        Method to create a YAML file that describes the execution inputs of the workflow
        needed for their execution. Return parsed inputs.
        """
        try:
            execInputs = self.executionInputs(matInputs, cwlInputs)
            if len(execInputs) != 0:
                with open(filename, mode="w+", encoding="utf-8") as yaml_file:
                    yaml.dump(execInputs, yaml_file, allow_unicode=True, default_flow_style=False, sort_keys=False)
                return execInputs

            else:
                raise WorkflowEngineException(
                    "Dict of execution inputs is empty")

        except IOError as error:
            raise WorkflowEngineException(
                "ERROR: cannot create YAML file {}, {}".format(filename, error))

    @staticmethod
    def executionInputs(matInputs:List[MaterializedInput], cwlInputs):
        """
        Setting execution inputs needed to execute the workflow
        """
        if len(matInputs) == 0:  # Is list of materialized inputs empty?
            raise WorkflowEngineException("FATAL ERROR: Execution with no inputs")
        
        if len(cwlInputs) == 0:  # Is list of declared inputs empty?
            raise WorkflowEngineException("FATAL ERROR: Workflow with no declared inputs")
        
        execInputs = dict()
        for matInput in matInputs:
            if isinstance(matInput, MaterializedInput):  # input is a MaterializedInput
                # numberOfInputs = len(matInput.values)  # number of inputs inside a MaterializedInput
                for input_value in matInput.values:
                    name = matInput.name
                    value_type = cwlInputs.get(name,{}).get('type')
                    if value_type is None:
                        raise WorkflowEngineException("ERROR: input {} not available in workflow".format(name))
                    
                    value = input_value
                    if isinstance(value, MaterializedContent):  # value of an input contains MaterializedContent
                        if os.path.isfile(value.local):
                            value_local = value.local
                            if isinstance(value_type, dict):    # MaterializedContent is a List of File
                                classType = value_type['items']
                                execInputs.setdefault(name,[]).append({"class": classType, "location": value_local})
                            else:   # MaterializedContent is a File
                                classType = value_type
                                execInputs[name] = {"class": classType, "location": value_local}
                        else:
                            raise WorkflowEngineException(
                                "ERROR: Input {} is not materialized".format(name))
                    else:
                        execInputs[name] = value
        
        return execInputs

    @staticmethod
    def executionOutputs(cwlOutputs):
        """
        Setting execution outputs provenance
        """
        execOutputs = dict()

        if len(cwlOutputs.keys()) != 0:  # dict of execution outputs is not empty
            for out_rec in cwlOutputs.keys():
                execOutputs[out_rec] = [{"class": cwlOutputs[out_rec]['class'], "location": cwlOutputs[out_rec]['path']}]
                if "secondaryFiles" in cwlOutputs[out_rec]:
                    secondaryFiles = cwlOutputs[out_rec]['secondaryFiles']
                    for secondaryFile in secondaryFiles:
                        execOutputs[out_rec].append({"class": secondaryFile['class'], "location": secondaryFile['path']})

                # TODO is not a File

            return execOutputs

        else:
            raise WorkflowEngineException("List of execution outputs is empty, {}".format(execOutputs))
