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
import glob
import logging

from .common import *

from typing import Any, Dict, List, Tuple
from collections import namedtuple

from .container import Container, ContainerFactory, NoContainerFactory
from .singularity_container import SingularityContainerFactory

from rocrate.rocrate import ROCrate
from rocrate.model.computerlanguage import ComputerLanguage

# Constants
WORKDIR_INPUTS_RELDIR = 'inputs'
WORKDIR_INTERMEDIATE_RELDIR = 'intermediate'
WORKDIR_META_RELDIR = 'meta'
WORKDIR_STATS_RELDIR = 'stats'
WORKDIR_OUTPUTS_RELDIR = 'outputs'
WORKDIR_ENGINE_TWEAKS_RELDIR = 'engineTweaks'

WORKDIR_STDOUT_FILE = 'stdout.txt'
WORKDIR_STDERR_FILE = 'stderr.txt'

WORKDIR_WORKFLOW_META_FILE = 'workflow_meta.yaml'
WORKDIR_SECURITY_CONTEXT_FILE = 'credentials.yaml'
WORKDIR_PASSPHRASE_FILE = '.passphrase'

STATS_DAG_DOT_FILE = 'dag.dot'

class WorkflowEngineException(Exception):
    """
    Exceptions fired by instances of WorkflowEngine
    """
    pass


CONTAINER_FACTORY_CLASSES = [
    SingularityContainerFactory,
    NoContainerFactory,
]


class WorkflowEngine(AbstractWorkflowEngineType):
    def __init__(self,
                 cacheDir=None,
                 workflow_config=None,
                 local_config=None,
                 engineTweaksDir=None,
                 cacheWorkflowDir=None,
                 workDir=None,
                 outputsDir=None,
                 outputMetaDir=None,
                 intermediateDir=None,
                 config_directory=None
                 ):
        """
        Abstract init method

        :param cacheDir:
        :param workflow_config:
            This one may be needed to identify container overrides
            or specific engine versions
        :param local_config:
        :param engineTweaksDir:
        :param cacheWorkflowDir:
        :param workDir:
        :param outputsDir:
        :param intermediateDir:
        """
        if local_config is None:
            local_config = dict()
        if workflow_config is None:
            workflow_config = dict()
        self.local_config = local_config
        
        if config_directory is None:
            config_directory = os.getcwd()
        self.config_directory = config_directory
        
        # Getting a logger focused on specific classes
        self.logger = logging.getLogger(self.__class__.__name__)
        
        # This one may be needed to identify container overrides
        # or specific engine versions
        self.workflow_config = workflow_config

        # cacheDir 
        if cacheDir is None:
            cacheDir = local_config.get('cacheDir')
        
        if cacheDir is None:
            cacheDir = tempfile.mkdtemp(prefix='WfExS', suffix='backend')
            # Assuring this temporal directory is removed at the end
            atexit.register(shutil.rmtree, cacheDir)
        else:
            if not os.path.isabs(cacheDir):
                cacheDir = os.path.normpath(os.path.join(config_directory,cacheDir))
            # Be sure the directory exists
            os.makedirs(cacheDir, exist_ok=True)

        # We are using as our own caching directory one located at the
        # generic caching directory, with the name of the class
        # This directory will hold software installations, for instance
        self.weCacheDir = os.path.join(cacheDir, self.__class__.__name__)

        # Needed for those cases where alternate version of the workflow is generated
        if cacheWorkflowDir is None:
            cacheWorkflowDir = os.path.join(cacheDir, 'wf-cache')
            os.makedirs(cacheWorkflowDir, exist_ok=True)
        self.cacheWorkflowDir = cacheWorkflowDir

        # Setting up working directories, one per instance
        if workDir is None:
            workDir = tempfile.mkdtemp(prefix='WfExS-exec', suffix='workdir')
            # Assuring this temporal directory is removed at the end
            atexit.register(shutil.rmtree, workDir)
        self.workDir = workDir

        # This directory should hold intermediate workflow steps results
        if intermediateDir is None:
            intermediateDir = os.path.join(workDir, WORKDIR_INTERMEDIATE_RELDIR)
        os.makedirs(intermediateDir, exist_ok=True)
        self.intermediateDir = intermediateDir

        # This directory will hold the final workflow results, which could
        # be either symbolic links to the intermediate results directory
        # or newly generated content
        if outputsDir is None:
            outputsDir = os.path.join(workDir, WORKDIR_OUTPUTS_RELDIR)
        os.makedirs(outputsDir, exist_ok=True)
        self.outputsDir = outputsDir

        # This directory will hold diverse metadata, like execution metadata
        # or newly generated content
        if outputMetaDir is None:
            outputMetaDir = os.path.join(workDir, WORKDIR_META_RELDIR, WORKDIR_OUTPUTS_RELDIR)
        os.makedirs(outputMetaDir, exist_ok=True)
        self.outputMetaDir = outputMetaDir
        
        # This directory will hold stats metadata, as well as the dot representation
        # of the workflow execution
        outputStatsDir = os.path.join(outputMetaDir,WORKDIR_STATS_RELDIR)
        os.makedirs(outputStatsDir, exist_ok=True)
        self.outputStatsDir = outputStatsDir

        # This directory is here for those files which are created in order
        # to tweak or patch workflow executions
        # engine tweaks directory
        if engineTweaksDir is None:
            engineTweaksDir = os.path.join(workDir, WORKDIR_ENGINE_TWEAKS_RELDIR)
        os.makedirs(engineTweaksDir, exist_ok=True)
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
                self.container_factory = containerFactory(cacheDir=cacheDir, local_config=local_config, engine_name=self.__class__.__name__)
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
    
    def getEmptyCrateAndComputerLanguage(self, langVersion: WFLangVersion) -> ComputerLanguage:
        """
        Due the internal synergies between an instance of ComputerLanguage
        and the RO-Crate it is attached to, both of them should be created
        here, just at the same time
        """
        
        wfType = self.workflowType
        crate = ROCrate()
        compLang = ComputerLanguage(crate, identifier=wfType.rocrate_programming_language, properties={
            "name": wfType.name,
            "alternateName": wfType.trs_descriptor,
            "identifier": {
                "@id": wfType.uriTemplate.format(langVersion)
            },
            "url": {
                "@id": wfType.url
            },
            "version": langVersion
        })
        
        return crate , compLang  
    
    @abc.abstractmethod
    def identifyWorkflow(self, localWf: LocalWorkflow, engineVer: EngineVersion = None) -> Tuple[EngineVersion, LocalWorkflow]:
        """
        This method should return the effective engine version needed
        to run it when this workflow engine recognizes the workflow type
        """
        pass

    @abc.abstractmethod
    def materializeEngineVersion(self, engineVersion: EngineVersion) -> Tuple[EngineVersion, EnginePath, Fingerprint]:
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
        engineVersion, enginePath, engineFingerprint = self.materializeEngineVersion(engineVersion)

        return MaterializedWorkflowEngine(instance=self,
                                            version=engineVersion,
                                            fingerprint=engineFingerprint,
                                            engine_path=enginePath,
                                            workflow=localWf
                                        )

    @abc.abstractmethod
    def materializeWorkflow(self, matWorfklowEngine: MaterializedWorkflowEngine) -> Tuple[MaterializedWorkflowEngine, List[ContainerTaggedName]]:
        """
        Method to ensure the workflow has been materialized. It returns the 
        localWorkflow directory, as well as the list of containers
        
        For Nextflow it is usually a no-op, but for CWL it requires resolution
        """

        pass
    
    @abc.abstractmethod
    def simpleContainerFileName(self, imageUrl: URIType) -> RelPath:
        """
        This method must be implemented to tell which names expect the workflow engine
        on its container cache directories when an image is locally materialized
        (currently only useful for Singularity)
        """
        pass
    
    def materializeContainers(self, listOfContainerTags: List[ContainerTaggedName]) -> List[Container]:
        return self.container_factory.materializeContainers(listOfContainerTags, self.simpleContainerFileName)

    @abc.abstractmethod
    def launchWorkflow(self, matWfEng: MaterializedWorkflowEngine, inputs: List[MaterializedInput],
                       outputs: List[ExpectedOutput]) -> Tuple[ExitVal, List[MaterializedInput], List[MaterializedOutput]]:
        pass

    @classmethod
    def ExecuteWorkflow(cls, matWfEng: MaterializedWorkflowEngine, inputs: List[MaterializedInput],
                        outputs: List[ExpectedOutput]) -> Tuple[ExitVal, List[MaterializedInput], List[MaterializedOutput]]:

        exitVal, augmentedInputs, matOutputs = matWfEng.instance.launchWorkflow(matWfEng, inputs, outputs)

        return exitVal, augmentedInputs, matOutputs

    @classmethod
    def MaterializeWorkflow(cls, matWfEng: MaterializedWorkflowEngine) -> Tuple[MaterializedWorkflowEngine, List[Container]]:
        matWfEng, listOfContainerTags = matWfEng.instance.materializeWorkflow(matWfEng)

        listOfContainers = matWfEng.instance.materializeContainers(listOfContainerTags)

        return matWfEng, listOfContainers
    
    def identifyMaterializedOutputs(self, expectedOutputs:List[ExpectedOutput], outputsDir:AbsPath, outputsMapping:Mapping[SymbolicOutputName,Any]=None) -> List[MaterializedOutput]:
        """
        This method is used to identify outputs by either file glob descriptions
        or matching with a mapping
        """
        if not isinstance(outputsMapping, dict):
            outputsMapping = {}
        
        matOutputs = []
        for expectedOutput in expectedOutputs:
            cannotBeEmpty = expectedOutput.cardinality[0] != 0
            matValues = []
            if expectedOutput.glob is not None:
                filterMethod = None
                if expectedOutput.kind == ContentKind.Directory:
                    filterMethod = os.path.isdir
                else:
                    filterMethod = os.path.isfile
                matchedPaths = []
                
                for matchingPath in glob.iglob(os.path.join(outputsDir,expectedOutput.glob),recursive=True):
                    # Getting what it is only interesting for this
                    if filterMethod(matchingPath):
                        matchedPaths.append(matchingPath)
                
                if len(matchedPaths) == 0 and cannotBeEmpty:
                    self.logger.warning("Output {} got no path for pattern {}".format(expectedOutput.name, expectedOutput.glob))
                
                for matchedPath in matchedPaths:
                    theContent = None
                    if expectedOutput.kind == ContentKind.Directory:
                        theContent = GetGeneratedDirectoryContent(
                            matchedPath,
                            uri=None,   # TODO: generate URIs when it is advised
                            preferredFilename=expectedOutput.preferredFilename
                        )
                    elif expectedOutput.kind == ContentKind.File:
                        theContent = GeneratedContent(
                            local=matchedPath,
                            uri=None,   # TODO: generate URIs when it is advised
                            signature=ComputeDigestFromFile(matchedPath),
                            preferredFilename=expectedOutput.preferredFilename
                        )
                    else:
                        # Reading the value from a file, as the glob is telling that
                        with open(matchedPath, mode='r', encoding='utf-8', errors='ignore') as mP:
                            theContent = mP.read()
                    
                    matValues.append(theContent)
            else:
                outputVal = outputsMapping.get(expectedOutput.name)
                
                if (outputVal is None) and cannotBeEmpty:
                    self.logger.warning("Output {} got no match from the outputs mapping".format(expectedOutput.name))
                
                matValues = CWLDesc2Content(outputVal, self.logger, expectedOutput)
            
            matOutput = MaterializedOutput(
                name=expectedOutput.name,
                kind=expectedOutput.kind,
                expectedCardinality=expectedOutput.cardinality,
                values=matValues
            )
            
            matOutputs.append(matOutput)
        
        return matOutputs
