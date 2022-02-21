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

import atexit
import hashlib
import inspect
import io
import json
import jsonschema
import logging
import pathlib
import platform
import shutil
import sys
import threading
import time
import types
import uuid

from pathlib import Path
from typing import List, Mapping, Pattern, Tuple, Type, Union
from urllib import request, parse

from rocrate import rocrate
import bagit

# We have preference for the C based loader and dumper, but the code
# should fallback to default implementations when C ones are not present
try:
    from yaml import CLoader as YAMLLoader, CDumper as YAMLDumper
except ImportError:
    from yaml import Loader as YAMLLoader, Dumper as YAMLDumper
import yaml

import crypt4gh.lib
import crypt4gh.keys.kdf
import crypt4gh.keys.c4gh

from .common import *
from .encrypted_fs import *
from .engine import WorkflowEngine, WorkflowEngineException
from .engine import WORKDIR_WORKFLOW_META_FILE, WORKDIR_SECURITY_CONTEXT_FILE, WORKDIR_PASSPHRASE_FILE
from .engine import WORKDIR_MARSHALLED_STAGE_FILE, WORKDIR_MARSHALLED_EXECUTE_FILE, WORKDIR_MARSHALLED_EXPORT_FILE
from .engine import WORKDIR_INPUTS_RELDIR, WORKDIR_INTERMEDIATE_RELDIR, WORKDIR_META_RELDIR, WORKDIR_OUTPUTS_RELDIR, \
    WORKDIR_ENGINE_TWEAKS_RELDIR
from .cache_handler import SchemeHandlerCacheHandler

from .utils.digests import ComputeDigestFromDirectory, ComputeDigestFromFile, nihDigester
from .utils.marshalling_handling import marshall_namedtuple, unmarshall_namedtuple

from .fetchers import AbstractStatefulFetcher
from .fetchers import DEFAULT_SCHEME_HANDLERS
from .fetchers.git import SCHEME_HANDLERS as GIT_SCHEME_HANDLERS, GitFetcher
from .fetchers.pride import SCHEME_HANDLERS as PRIDE_SCHEME_HANDLERS
from .fetchers.drs import SCHEME_HANDLERS as DRS_SCHEME_HANDLERS
from .fetchers.trs_files import INTERNAL_TRS_SCHEME_PREFIX, SCHEME_HANDLERS as INTERNAL_TRS_SCHEME_HANDLERS
from .fetchers.s3 import S3_SCHEME_HANDLERS as S3_SCHEME_HANDLERS
from .fetchers.gs import GS_SCHEME_HANDLERS as GS_SCHEME_HANDLERS

from .nextflow_engine import NextflowWorkflowEngine
from .cwl_engine import CWLWorkflowEngine

# The list of classes to be taken into account
# CWL detection is before, as Nextflow one is
# a bit lax (only detects a couple of too common
# keywords)
WORKFLOW_ENGINE_CLASSES = [
    CWLWorkflowEngine,
    NextflowWorkflowEngine,
]


class WF:
    """
    Workflow enaction class
    """

    DEFAULT_PASSPHRASE_LENGTH = 4

    CRYPT4GH_SECTION = 'crypt4gh'
    CRYPT4GH_PRIVKEY_KEY = 'key'
    CRYPT4GH_PUBKEY_KEY = 'pub'
    CRYPT4GH_PASSPHRASE_KEY = 'passphrase'

    TRS_METADATA_FILE = 'trs_metadata.json'
    TRS_QUERY_CACHE_FILE = 'trs_result.json'
    TRS_TOOL_FILES_FILE = 'trs_tool_files.json'

    SCHEMAS_REL_DIR = 'schemas'
    CONFIG_SCHEMA = 'config.json'
    SECURITY_CONTEXT_SCHEMA = 'security-context.json'
    STAGE_DEFINITION_SCHEMA = 'stage-definition.json'

    DEFAULT_RO_EXTENSION = ".crate.zip"
    DEFAULT_TRS_ENDPOINT = "https://dev.workflowhub.eu/ga4gh/trs/v2/"  # root of GA4GH TRS API
    TRS_TOOLS_PATH = 'tools/'
    WORKFLOW_ENGINES = list(map(lambda clazz: clazz.WorkflowType(), WORKFLOW_ENGINE_CLASSES))

    RECOGNIZED_TRS_DESCRIPTORS = dict(map(lambda t: (t.trs_descriptor, t), WORKFLOW_ENGINES))


    def __init__(self,
                 wfexs,
                 workflow_id=None,
                 version_id=None,
                 descriptor_type=None,
                 trs_endpoint=DEFAULT_TRS_ENDPOINT,
                 params=None,
                 outputs=None,
                 workflow_config=None,
                 creds_config=None,
                 instanceId: Optional[str] = None,
                 rawWorkDir: Optional[Union[RelPath, AbsPath]] = None,
                 paranoid_mode: Optional[bool] = None
                 ):
        """
        Init function
        
        :param wfexs: A WfExSBackend instance
        :param workflow_id: A unique identifier of the workflow. Although it is an integer in WorkflowHub,
        we cannot assume it is so in all the GA4GH TRS implementations which are exposing workflows.
        :param version_id: An identifier of the workflow version. Although it is an integer in
        WorkflowHub, we cannot assume the format of the version id, as it could follow semantic
        versioning, providing an UUID, etc.
        :param descriptor_type: The type of descriptor that represents this version of the workflow
        (e.g. CWL, WDL, NFL, or GALAXY). It is optional, so it is guessed from the calls to the API.
        :param trs_endpoint: The TRS endpoint used to find the workflow.
        :param params: Optional params for the workflow execution.
        :param outputs:
        :param workflow_config: Tweaks for workflow enactment, like some overrides
        :param creds_config: Dictionary with the different credential contexts
        :param instanceId: The instance id of this working directory
        :param rawWorkDir: Raw working directory
        :param paranoid_mode: Should we enable paranoid mode for this workflow?
        :type wfexs: WfExSBackend
        :type workflow_id: str
        :type version_id: str
        :type descriptor_type: str
        :type trs_endpoint: str
        :type params: dict
        :type outputs: dict
        :type workflow_config: dict
        :type creds_config: dict
        :type instanceId: str
        :type rawWorkDir: str
        :type paranoid_mode: bool
        """
        if wfexs is None:
            raise WFException('Unable to initialize, no WfExSBackend instance provided')
        
        # Getting a logger focused on specific classes
        self.logger = logging.getLogger(dict(inspect.getmembers(self))['__module__'] + '::' + self.__class__.__name__)
        
        self.wfexs = wfexs
        
        if isinstance(paranoid_mode, bool):
            self.paranoidMode = paranoid_mode
        else:
            self.paranoidMode = self.wfexs.getDefaultParanoidMode()
        
        if not isinstance(workflow_config, dict):
            workflow_config = {}

        if workflow_id is not None:
            workflow_meta = {
                'workflow_id': workflow_id
            }
            if version_id is not None:
                workflow_meta['version'] = version_id
            if descriptor_type is not None:
                workflow_meta['workflow_type'] = descriptor_type
            if trs_endpoint is not None:
                workflow_meta['trs_endpoint'] = trs_endpoint
            if workflow_config is not None:
                workflow_meta['workflow_config'] = workflow_config
            if params is not None:
                workflow_meta['params'] = params
            if outputs is not None:
                workflow_meta['outputs'] = outputs
            
            valErrors = self.wfexs.ConfigValidate(workflow_meta, self.STAGE_DEFINITION_SCHEMA)
            if len(valErrors) > 0:
                errstr = f'ERROR in workflow staging definition block: {valErrors}'
                self.logger.error(errstr)
                raise WFException(errstr)

            if not isinstance(creds_config, dict):
                creds_config = {}

            valErrors = self.wfexs.ConfigValidate(creds_config, self.SECURITY_CONTEXT_SCHEMA)
            if len(valErrors) > 0:
                errstr = f'ERROR in security context block: {valErrors}'
                self.logger.error(errstr)
                raise WFException(errstr)

            if not isinstance(params, dict):
                params = {}

            if not isinstance(outputs, dict):
                outputs = {}

            # Workflow-specific
            self.workflow_config = workflow_config
            self.creds_config = creds_config

            self.id = str(workflow_id)
            self.version_id = str(version_id)
            self.descriptor_type = descriptor_type
            self.params = params
            self.outputs = self.parseExpectedOutputs(outputs)

            # The endpoint should always end with a slash
            if isinstance(trs_endpoint, str):
                if trs_endpoint[-1] != '/':
                    trs_endpoint += '/'

                # Removing the tools suffix, which appeared in first WfExS iterations
                if trs_endpoint.endswith('/' + self.TRS_TOOLS_PATH):
                    trs_endpoint = trs_endpoint[0:-len(self.TRS_TOOLS_PATH)]

            self.trs_endpoint = trs_endpoint
        
        if instanceId is not None:
            self.instanceId = instanceId
        
        self.fusermount_cmd = None
        self.encfs_idleMinutes = None
        self.doUnmount = False
        
        checkSecure = True
        if rawWorkDir is None:
            if instanceId is None:
                self.instanceId , self.rawWorkDir = self.wfexs.createRawWorkDir()
                checkSecure = False
            else:
                self.rawWorkDir = self.wfexs.getRawWorkDir(instanceId)
        else:
            self.rawWorkDir = rawWorkDir
            if instanceId is None:
                self.instanceId = self.wfexs.getInstanceIdFromRawWorkDir(rawWorkDir)

        # TODO: enforce restrictive permissions on each raw working directory
        self.allowOther = False
        
        if checkSecure:
            passphraseFile = os.path.join(self.rawWorkDir, WORKDIR_PASSPHRASE_FILE)
            self.secure = os.path.exists(passphraseFile)
        else:
            self.secure = workflow_config.get('secure', True)
        
        doSecureWorkDir = self.secure or self.paranoidMode

        self.setupWorkdir(doSecureWorkDir)
        
        # This directory will hold either symbolic links to the cached
        # inputs, or the inputs properly post-processed (decompressed,
        # decrypted, etc....)
        self.inputsDir = os.path.join(self.workDir, WORKDIR_INPUTS_RELDIR)
        os.makedirs(self.inputsDir, exist_ok=True)
        # This directory should hold intermediate workflow steps results
        self.intermediateDir = os.path.join(self.workDir, WORKDIR_INTERMEDIATE_RELDIR)
        os.makedirs(self.intermediateDir, exist_ok=True)
        # This directory will hold the final workflow results, which could
        # be either symbolic links to the intermediate results directory
        # or newly generated content
        self.outputsDir = os.path.join(self.workDir, WORKDIR_OUTPUTS_RELDIR)
        os.makedirs(self.outputsDir, exist_ok=True)
        # This directory is here for those files which are created in order
        # to tweak or patch workflow executions
        self.engineTweaksDir = os.path.join(self.workDir, WORKDIR_ENGINE_TWEAKS_RELDIR)
        os.makedirs(self.engineTweaksDir, exist_ok=True)
        # This directory will hold metadata related to the execution
        self.metaDir = os.path.join(self.workDir, WORKDIR_META_RELDIR)
        
        self.configMarshalled = False
        # This is true when the working directory already exists
        if checkSecure:
            if not os.path.isdir(self.metaDir):
                raise WFException("Staged working directory {} is incomplete".format(self.workDir))
            # In order to be able to build next paths to call
            self.unmarshallConfig()
        else:
            os.makedirs(self.metaDir, exist_ok=True)
            self.marshallConfig(overwrite=True)

        self.stagedSetup = StagedSetup(
            workflow_config=self.workflow_config,
            work_dir=self.workDir,
            inputs_dir=self.inputsDir,
            outputs_dir=self.outputsDir,
            intermediate_dir=self.intermediateDir,
            engine_tweaks_dir=self.engineTweaksDir,
            meta_dir=self.metaDir,
            temp_dir=self.tempDir,
            secure_exec=self.secure or self.paranoidMode,
            allow_other=self.allowOther
        )
        
        self.repoURL = None
        self.repoTag = None
        self.repoRelPath = None
        self.repoDir = None
        self.repoEffectiveCheckout = None
        self.engine = None
        self.engineVer = None
        self.engineDesc = None

        self.materializedParams = None
        self.localWorkflow = None
        self.materializedEngine = None
        self.listOfContainers = None

        self.exitVal = None
        self.augmentedInputs = None
        self.matCheckOutputs = None
        self.cacheROCrateFilename = None
        
        self.stageMarshalled = False
        self.executionMarshalled = False
        self.exportMarshalled = False

    FUSE_SYSTEM_CONF = '/etc/fuse.conf'

    def setupWorkdir(self, doSecureWorkDir):
        uniqueRawWorkDir = self.rawWorkDir

        allowOther = False
        if doSecureWorkDir:
            # We need to detect whether fuse has enabled user_allow_other
            # the only way I know is parsing /etc/fuse.conf
            if not self.paranoidMode and os.path.exists(self.FUSE_SYSTEM_CONF):
                with open(self.FUSE_SYSTEM_CONF, mode="r") as fsc:
                    for line in fsc:
                        if line.startswith('user_allow_other'):
                            allowOther = True
                            break
                    self.logger.debug(f"FUSE has user_allow_other: {allowOther}")

            uniqueEncWorkDir = os.path.join(uniqueRawWorkDir, '.crypt')
            uniqueWorkDir = os.path.join(uniqueRawWorkDir, 'work')

            # The directories should exist before calling encryption FS mount
            os.makedirs(uniqueEncWorkDir, exist_ok=True)
            os.makedirs(uniqueWorkDir, exist_ok=True)

            # This is the passphrase needed to decrypt the filesystem
            passphraseFile = os.path.join(uniqueRawWorkDir, WORKDIR_PASSPHRASE_FILE)
            
            if os.path.exists(passphraseFile):
                encfs_type, encfs_cmd, securePassphrase = self.wfexs.readSecuredPassphrase(passphraseFile)
            else:
                encfs_type, encfs_cmd, securePassphrase = self.wfexs.generateSecuredPassphrase(passphraseFile)
            
            self.encfs_type = encfs_type

            self.fusermount_cmd , self.encfs_idleMinutes = self.wfexs.getFusermountParams()
            # Warn/fail earlier
            if os.path.ismount(uniqueWorkDir):
                # raise WFException("Destination mount point {} is already in use")
                self.logger.warning("Destination mount point {} is already in use".format(uniqueWorkDir))
            else:
                # Now, time to mount the encrypted FS
                ENCRYPTED_FS_MOUNT_IMPLEMENTATIONS[encfs_type](encfs_cmd, self.encfs_idleMinutes, uniqueEncWorkDir,
                                                               uniqueWorkDir, uniqueRawWorkDir, securePassphrase,
                                                               allowOther)

                # and start the thread which keeps the mount working
                self.encfsThread = threading.Thread(target=self._wakeupEncDir, daemon=True)
                self.encfsThread.start()

                # We are going to unmount what we have mounted
                self.doUnmount = True

            # self.encfsPassphrase = securePassphrase
            del securePassphrase
        else:
            uniqueEncWorkDir = None
            uniqueWorkDir = uniqueRawWorkDir

        # The temporary directory is in the raw working directory as
        # some container engine could fail
        uniqueTempDir = os.path.join(uniqueRawWorkDir,'.TEMP')
        os.makedirs(uniqueTempDir, exist_ok=True)
        os.chmod(uniqueTempDir, 0o1777)

        # Setting up working directories, one per instance
        self.encWorkDir = uniqueEncWorkDir
        self.workDir = uniqueWorkDir
        self.tempDir = uniqueTempDir
        self.allowOther = allowOther

    def _wakeupEncDir(self):
        """
        This method periodically checks whether the directory is still available
        """
        while True:
            time.sleep(60)
            os.path.isdir(self.workDir)

    def unmountWorkdir(self):
        if self.doUnmount and (self.encWorkDir is not None):
            # Only unmount if it is needed
            if os.path.ismount(self.workDir):
                with tempfile.NamedTemporaryFile() as encfs_umount_stdout, tempfile.NamedTemporaryFile() as encfs_umount_stderr:
                    fusermountCommand = [
                        self.fusermount_cmd,
                        '-u',  # Umount the directory
                        '-z',  # Even if it is not possible to umount it now, hide the mount point
                        self.workDir,
                    ]

                    retval = subprocess.Popen(
                        fusermountCommand,
                        stdout=encfs_umount_stdout,
                        stderr=encfs_umount_stderr,
                    ).wait()

                    if retval != 0:
                        with open(encfs_umount_stdout.name, mode="r") as c_stF:
                            encfs_umount_stdout_v = c_stF.read()
                        with open(encfs_umount_stderr.name, mode="r") as c_stF:
                            encfs_umount_stderr_v = c_stF.read()

                        errstr = "Could not umount {} (retval {})\nCommand: {}\n======\nSTDOUT\n======\n{}\n======\nSTDERR\n======\n{}".format(
                            self.encfs_type, retval, ' '.join(fusermountCommand), encfs_umount_stdout_v,
                            encfs_umount_stderr_v)
                        raise WFException(errstr)

            # This is needed to avoid double work
            self.doUnmount = False
            self.encWorkDir = None
            self.workDir = None

    def cleanup(self):
        self.unmountWorkdir()
    
    def enableParanoidMode(self) -> None:
        self.paranoidMode = True

    # DEPRECATED
    @staticmethod
    def ReadConfigFromMeta(metaDir: AbsPath) -> Tuple[Mapping, Mapping]:
        # In order to be able to build next paths to call
        workflowMetaFilename = os.path.join(metaDir, WORKDIR_WORKFLOW_META_FILE)
        securityContextsConfigFilename = os.path.join(metaDir, WORKDIR_SECURITY_CONTEXT_FILE)
        
        with open(workflowMetaFilename, mode="r", encoding="utf-8") as wcf:
            workflow_meta = unmarshall_namedtuple(yaml.load(wcf, Loader=YAMLLoader))

        # Last, try loading the security contexts credentials file
        if os.path.exists(securityContextsConfigFilename):
            with open(securityContextsConfigFilename, mode="r", encoding="utf-8") as scf:
                creds_config = unmarshall_namedtuple(yaml.load(scf, Loader=YAMLLoader))
        else:
            creds_config = {}
        
        return workflow_meta, creds_config

    @classmethod
    def FromWorkDir(cls, wfexs, workflowWorkingDirectory: Union[RelPath, AbsPath]):
        if wfexs is None:
            raise WFException('Unable to initialize, no WfExSBackend instance provided')
        
        instanceId, rawWorkDir = wfexs.normalizeRawWorkingDirectory(workflowWorkingDirectory)
        
        return cls(wfexs, instanceId=instanceId, rawWorkDir=rawWorkDir)
    
    @classmethod
    def FromFiles(cls, wfexs, workflowMetaFilename, securityContextsConfigFilename=None, paranoidMode: bool = False):
        with open(workflowMetaFilename, mode="r", encoding="utf-8") as wcf:
            workflow_meta = unmarshall_namedtuple(yaml.load(wcf, Loader=YAMLLoader))

        # Last, try loading the security contexts credentials file
        if securityContextsConfigFilename and os.path.exists(securityContextsConfigFilename):
            with open(securityContextsConfigFilename, mode="r", encoding="utf-8") as scf:
                creds_config = unmarshall_namedtuple(yaml.load(scf, Loader=YAMLLoader))
        else:
            creds_config = {}

        return cls.FromDescription(wfexs, workflow_meta, creds_config, paranoidMode=paranoidMode)
    
    @classmethod
    def FromDescription(cls, wfexs, workflow_meta, creds_config=None, paranoidMode: bool = False):
        """
        :param wfexs: WfExSBackend instance
        :param workflow_meta: The configuration describing both the workflow
        and the inputs to use when it is being instantiated.
        :param creds_config: Dictionary with the different credential contexts (to be implemented)
        :param paranoidMode:
        :type wfexs: WfExSBackend
        :type workflow_meta: dict
        :type creds_config: dict
        :type paranoidMode: bool
        :return: Workflow configuration
        """
        
        # The preserved paranoid mode must be honoured
        preserved_paranoid_mode = workflow_meta.get('paranoid_mode')
        if preserved_paranoid_mode is not None:
            paranoidMode = preserved_paranoid_mode

        return cls(
            wfexs,
            workflow_meta['workflow_id'],
            workflow_meta.get('version'),
            descriptor_type=workflow_meta.get('workflow_type'),
            trs_endpoint=workflow_meta.get('trs_endpoint', cls.DEFAULT_TRS_ENDPOINT),
            params=workflow_meta.get('params', {}),
            outputs=workflow_meta.get('outputs', {}),
            workflow_config=workflow_meta.get('workflow_config'),
            creds_config=creds_config,
            paranoid_mode=paranoidMode
        )
    
    @classmethod
    def FromForm(cls, wfexs, workflow_meta, paranoidMode:bool = False):  # VRE
        """

        :param wfexs: WfExSBackend instance
        :param workflow_meta: The configuration describing both the workflow
        and the inputs to use when it is being instantiated.
        :param paranoidMode:
        :type workflow_meta: dict
        :type paranoidMode:
        :return: Workflow configuration
        """
        
        return cls(
            wfexs,
            workflow_meta['workflow_id'],
            workflow_meta.get('version'),
            descriptor_type=workflow_meta.get('workflow_type'),
            trs_endpoint=workflow_meta.get('trs_endpoint', cls.DEFAULT_TRS_ENDPOINT),
            params=workflow_meta.get('params', {}),
            workflow_config=workflow_meta.get('workflow_config'),
            paranoid_mode=paranoidMode
        )

    def fetchWorkflow(self, offline=False):
        """
        Fetch the whole workflow description based on the data obtained
        from the TRS where it is being published.

        If the workflow id is an URL, it is supposed to be a git repository,
        and the version will represent either the branch, tag or specific commit.
        So, the whole TRS fetching machinery is bypassed.
        """
        parsedRepoURL = parse.urlparse(self.id)

        # It is not an absolute URL, so it is being an identifier in the workflow
        if parsedRepoURL.scheme == '':
            if (self.trs_endpoint is not None) and len(self.trs_endpoint) > 0:
                engineDesc, repoURL, repoTag, repoRelPath = self.getWorkflowRepoFromTRS(offline=offline)
            else:
                raise WFException('trs_endpoint was not provided')
        else:
            engineDesc = None

            # Trying to be smarter
            guessedRepoURL, guessedRepoTag, guessedRepoRelPath = self.wfexs.guessRepoParams(parsedRepoURL, fail_ok=False)

            if guessedRepoURL is not None:
                repoURL = guessedRepoURL
                repoTag = guessedRepoTag if guessedRepoTag is not None else self.version_id
                repoRelPath = guessedRepoRelPath
            else:
                engineDesc, repoURL, repoTag, repoRelPath = self.getWorkflowRepoFromROCrateURL(self.id, offline=offline)

        if repoURL is None:
            # raise WFException('Unable to guess repository from RO-Crate manifest')
            repoURL = self.id
            repoTag = self.version_id
            repoRelPath = None

        repoDir = None
        repoEffectiveCheckout = None
        if ':' in repoURL:
            parsedRepoURL = parse.urlparse(repoURL)
            if len(parsedRepoURL.scheme) > 0:
                self.repoURL = repoURL
                self.repoTag = repoTag
                # It can be either a relative path to a directory or to a file
                # It could be even empty!
                if repoRelPath == '':
                    repoRelPath = None
                self.repoRelPath = repoRelPath

                repoDir, repoEffectiveCheckout = self.wfexs.doMaterializeRepo(repoURL, repoTag)

        # For the cases of pure TRS repos, like Dockstore
        if repoDir is None:
            repoDir = repoURL

        # Workflow Language version cannot be assumed here yet
        localWorkflow = LocalWorkflow(dir=repoDir, relPath=repoRelPath, effectiveCheckout=repoEffectiveCheckout)
        self.logger.info("materialized workflow repository (checkout {}): {}".format(repoEffectiveCheckout, repoDir))

        if repoRelPath is not None:
            if not os.path.exists(os.path.join(repoDir, repoRelPath)):
                raise WFException(
                    "Relative path {} cannot be found in materialized workflow repository {}".format(repoRelPath,
                                                                                                     repoDir))
        # A valid engine must be identified from the fetched content
        # TODO: decide whether to force some specific version
        if engineDesc is None:
            for engineDesc in self.WORKFLOW_ENGINES:
                self.logger.debug("Testing engine " + engineDesc.trs_descriptor)
                engine = self.wfexs.instantiateEngine(engineDesc, self.stagedSetup)
                    
                try:
                    engineVer, candidateLocalWorkflow = engine.identifyWorkflow(localWorkflow)
                    self.logger.debug("Tested engine {} {}".format(engineDesc.trs_descriptor, engineVer))
                    if engineVer is not None:
                        break
                except WorkflowEngineException:
                    # TODO: store the exceptions, to be shown if no workflow is recognized
                    pass
            else:
                raise WFException('No engine recognized a workflow at {}'.format(repoURL))
        else:
            self.logger.debug("Fixed engine " + engineDesc.trs_descriptor)
            engine = self.wfexs.instantiateEngine(engineDesc, self.stagedSetup)
            engineVer, candidateLocalWorkflow = engine.identifyWorkflow(localWorkflow)
            if engineVer is None:
                raise WFException(
                    'Engine {} did not recognize a workflow at {}'.format(engine.workflowType.engineName, repoURL))

        self.repoDir = repoDir
        self.repoEffectiveCheckout = repoEffectiveCheckout
        self.engineDesc = engineDesc
        self.engine = engine
        self.engineVer = engineVer
        self.localWorkflow = candidateLocalWorkflow

    def setupEngine(self, offline=False):
        # The engine is populated by self.fetchWorkflow()
        if self.engine is None:
            self.fetchWorkflow(offline=offline)

        if self.materializedEngine is None:
            localWorkflow = self.localWorkflow
        else:
            localWorkflow = self.materializedEngine.workflow

        self.materializedEngine = self.engine.materializeEngine(localWorkflow, self.engineVer)

    def materializeWorkflow(self, offline=False):
        if self.materializedEngine is None:
            self.setupEngine(offline=offline)

        # This information is badly needed for provenance
        if self.listOfContainers is None:
            self.materializedEngine, self.listOfContainers = WorkflowEngine.MaterializeWorkflow(self.materializedEngine, offline=offline)

    def injectInputs(self, paths, workflowInputs_destdir=None, workflowInputs_cacheDir=None, lastInput=0):
        if workflowInputs_destdir is None:
            workflowInputs_destdir = self.inputsDir
        if workflowInputs_cacheDir is None:
            workflowInputs_cacheDir = CacheType.Input

        cacheable = not self.paranoidMode
        # The storage dir depends on whether it can be cached or not
        storeDir = workflowInputs_cacheDir if cacheable else workflowInputs_destdir
        for path in paths:
            # We are sending the context name thinking in the future,
            # as it could contain potential hints for authenticated access
            fileuri = parse.urlunparse(('file', '', os.path.abspath(path), '', '', ''))
            matContent = self.wfexs.downloadContent(
                fileuri,
                dest=storeDir,
                ignoreCache=not cacheable,
                registerInCache=cacheable
            )

            # Now, time to create the symbolic link
            lastInput += 1

            prettyLocal = os.path.join(workflowInputs_destdir, matContent.prettyFilename)

            # As Nextflow has some issues when two inputs of a process
            # have the same basename, harden by default
            hardenPrettyLocal = True
            # hardenPrettyLocal = False
            # if os.path.islink(prettyLocal):
            #     oldLocal = os.readlink(prettyLocal)
            #
            #     hardenPrettyLocal = oldLocal != matContent.local
            # elif os.path.exists(prettyLocal):
            #     hardenPrettyLocal = True

            if hardenPrettyLocal:
                # Trying to avoid collisions on input naming
                prettyLocal = os.path.join(workflowInputs_destdir, str(lastInput) + '_' + matContent.prettyFilename)

            if not os.path.exists(prettyLocal):
                os.symlink(matContent.local, prettyLocal)

        return lastInput

    def materializeInputs(self, offline: bool = False, lastInput:int=0):
        theParams, numInputs = self.fetchInputs(
            self.params,
            workflowInputs_destdir=self.inputsDir,
            offline=offline,
            lastInput=lastInput
        )
        self.materializedParams = theParams
    
    def getContext(self, remote_file, contextName: Optional[str]):
        secContext = None
        if contextName is not None:
            secContext = self.creds_config.get(contextName)
            if secContext is None:
                raise WFException(
                    'No security context {} is available, needed by {}'.format(contextName, remote_file))
        
        return secContext
    
    def fetchInputs(self, params, workflowInputs_destdir: AbsPath,
                    prefix:str='', lastInput:int=0, offline: bool = False) -> Tuple[List[MaterializedInput], int]:
        """
        Fetch the input files for the workflow execution.
        All the inputs must be URLs or CURIEs from identifiers.org / n2t.net.

        :param params: Optional params for the workflow execution.
        :param workflowInputs_destdir:
        :param prefix:
        :param lastInput:
        :param offline:
        :type params: dict
        :type prefix: str
        """
        theInputs = []

        paramsIter = params.items() if isinstance(params, dict) else enumerate(params)
        for key, inputs in paramsIter:
            # We are here for the
            linearKey = prefix + key
            if isinstance(inputs, dict):
                inputClass = inputs.get('c-l-a-s-s')
                if inputClass is not None:
                    if inputClass in ("File", "Directory"):  # input files
                        inputDestDir = workflowInputs_destdir
                        globExplode = None
                        if inputClass == 'Directory':
                            # We have to autofill this with the outputs directory,
                            # so results are properly stored (without escaping the jail)
                            if inputs.get('autoFill', False):
                                if inputs.get('autoPrefix', True):
                                    autoFilledDir = os.path.join(self.outputsDir, *linearKey.split('.'))
                                else:
                                    autoFilledDir = self.outputsDir

                                theInputs.append(MaterializedInput(linearKey, [autoFilledDir]))
                                continue

                            globExplode = inputs.get('globExplode')

                            # This is to nest the directory where to place the different files
                            inputDestDir = os.path.join(inputDestDir, *linearKey.split('.'))
                            os.makedirs(inputDestDir, exist_ok=True)
                        elif inputClass == 'File' and inputs.get('autoFill', False):
                            # We have to autofill this with the outputs directory,
                            # so results are properly stored (without escaping the jail)
                            autoFilledFile = os.path.join(self.outputsDir, *linearKey.split('.'))
                            autoFilledDir = os.path.dirname(autoFilledFile)
                            # This is needed to assure the path exists
                            if autoFilledDir != self.outputsDir:
                                os.makedirs(autoFilledDir, exist_ok=True)

                            theInputs.append(MaterializedInput(linearKey, [autoFilledFile]))
                            continue

                        remote_files = inputs['url']
                        cacheable = not self.paranoidMode if inputs.get('cache', True) else False
                        if not isinstance(remote_files, list):  # more than one input file
                            remote_files = [remote_files]

                        remote_pairs = []
                        # The storage dir depends on whether it can be cached or not
                        storeDir = CacheType.Input if cacheable else workflowInputs_destdir
                        for remote_file in remote_files:
                            # We are sending the context name thinking in the future,
                            # as it could contain potential hints for authenticated access
                            contextName = inputs.get('security-context')
                            secContext = self.getContext(remote_file, contextName)
                            matContent = self.wfexs.downloadContent(
                                remote_file,
                                dest=storeDir,
                                secContext=secContext,
                                offline=offline,
                                ignoreCache=not cacheable,
                                registerInCache=cacheable
                            )

                            # Now, time to create the symbolic link
                            lastInput += 1

                            prettyLocal = os.path.join(inputDestDir, matContent.prettyFilename)

                            # As Nextflow has some issues when two inputs of a process
                            # have the same basename, harden by default
                            hardenPrettyLocal = True
                            # hardenPrettyLocal = False
                            # if os.path.islink(prettyLocal):
                            #     oldLocal = os.readlink(prettyLocal)
                            #
                            #     hardenPrettyLocal = oldLocal != matContent.local
                            # elif os.path.exists(prettyLocal):
                            #     hardenPrettyLocal = True

                            if hardenPrettyLocal:
                                # Trying to avoid collisions on input naming
                                prettyLocal = os.path.join(inputDestDir,
                                                           str(lastInput) + '_' + matContent.prettyFilename)

                            if not os.path.exists(prettyLocal):
                                os.symlink(matContent.local, prettyLocal)

                            if globExplode is not None:
                                prettyLocalPath = pathlib.Path(prettyLocal)
                                matParse = parse.urlparse(matContent.uri)
                                for exp in prettyLocalPath.glob(globExplode):
                                    relPath = exp.relative_to(prettyLocalPath)
                                    relName = str(relPath)
                                    relExpPath = matParse.path
                                    if relExpPath[-1] != '/':
                                        relExpPath += '/'
                                    relExpPath += '/'.join(map(lambda part: parse.quote_plus(part), relPath.parts))
                                    expUri = parse.urlunparse((matParse.scheme, matParse.netloc, relExpPath, matParse.params, matParse.query, matParse.fragment))
                                    remote_pairs.append(
                                        MaterializedContent(
                                            local=str(exp),
                                            uri=expUri,
                                            prettyFilename=relName,
                                            metadata_array=matContent.metadata_array,
                                            kind=ContentKind.Directory if exp.is_dir() else ContentKind.File
                                        )
                                    )
                            else:
                                remote_pairs.append(
                                    MaterializedContent(prettyLocal, matContent.uri, matContent.prettyFilename,
                                                        matContent.kind, matContent.metadata_array))

                        theInputs.append(MaterializedInput(linearKey, remote_pairs))
                    else:
                        raise WFException(
                            'Unrecognized input class "{}", attached to "{}"'.format(inputClass, linearKey))
                else:
                    # possible nested files
                    newInputsAndParams, lastInput = self.fetchInputs(inputs,
                                                                     workflowInputs_destdir=workflowInputs_destdir,
                                                                     prefix=linearKey + '.', lastInput=lastInput,
                                                                     offline=offline)
                    theInputs.extend(newInputsAndParams)
            else:
                if not isinstance(inputs, list):
                    inputs = [inputs]
                theInputs.append(MaterializedInput(linearKey, inputs))

        return theInputs, lastInput

    def stageWorkDir(self):
        """
        This method is here to simplify the understanding of the needed steps
        """
        self.fetchWorkflow()
        self.setupEngine()
        self.materializeWorkflow()
        self.materializeInputs()
        self.marshallStage()

        return self.instanceId

    def workdirToBagit(self):
        """
        BEWARE: This is a destructive step! So, once run, there is no back!
        """
        self.bag = bagit.make_bag(self.workDir)

    DefaultCardinality = '1'
    CardinalityMapping = {
        '1': (1, 1),
        '?': (0, 1),
        '*': (0, sys.maxsize),
        '+': (1, sys.maxsize),
    }

    OutputClassMapping = {
        ContentKind.File.name: ContentKind.File,
        ContentKind.Directory.name: ContentKind.Directory,
        ContentKind.Value.name: ContentKind.Value,
    }

    def parseExpectedOutputs(self, outputs: Union[List[Any], Mapping[str, Any]]) -> List[ExpectedOutput]:
        expectedOutputs = []

        # TODO: implement parsing of outputs
        outputsIter = outputs.items() if isinstance(outputs, dict) else enumerate(outputs)

        for outputKey, outputDesc in outputsIter:
            # The glob pattern
            patS = outputDesc.get('glob')
            if patS is not None:
                if len(patS) == 0:
                    patS = None

            # Fill from this input
            fillFrom = outputDesc.get('fillFrom')

            # Parsing the cardinality
            cardS = outputDesc.get('cardinality')
            cardinality = None
            if cardS is not None:
                if isinstance(cardS, int):
                    if cardS < 1:
                        cardinality = (0, 1)
                    else:
                        cardinality = (cardS, cardS)
                elif isinstance(cardS, list):
                    cardinality = (int(cardS[0]), int(cardS[1]))
                else:
                    cardinality = self.CardinalityMapping.get(cardS)

            if cardinality is None:
                cardinality = self.CardinalityMapping[self.DefaultCardinality]

            eOutput = ExpectedOutput(
                name=outputKey,
                kind=self.OutputClassMapping.get(outputDesc.get('c-l-a-s-s'), ContentKind.File.name),
                preferredFilename=outputDesc.get('preferredName'),
                cardinality=cardinality,
                fillFrom=fillFrom,
                glob=patS,
            )
            expectedOutputs.append(eOutput)

        return expectedOutputs

    def executeWorkflow(self, offline: bool = False):
        self.unmarshallStage(offline=offline)

        exitVal, augmentedInputs, matCheckOutputs = WorkflowEngine.ExecuteWorkflow(self.materializedEngine,
                                                                                   self.materializedParams,
                                                                                   self.outputs)

        self.exitVal = exitVal
        self.augmentedInputs = augmentedInputs
        self.matCheckOutputs = matCheckOutputs

        self.logger.debug(exitVal)
        self.logger.debug(augmentedInputs)
        self.logger.debug(matCheckOutputs)

        # Store serialized version of exitVal, augmentedInputs and matCheckOutputs
        self.marshallExecute()

    def exportResults(self):
        self.unmarshallExecute(offline=True)

        # TODO
        self.marshallExport()


    def marshallConfig(self, overwrite: bool = False):
        workflow_meta_file = os.path.join(self.metaDir, WORKDIR_WORKFLOW_META_FILE)
        if overwrite or not os.path.exists(workflow_meta_file):
            with open(workflow_meta_file, mode='w', encoding='utf-8') as wmF:
                workflow_meta = {
                    'workflow_id': self.id,
                    'paranoid_mode': self.paranoidMode
                }
                if self.version_id is not None:
                    workflow_meta['version'] = self.version_id
                if self.descriptor_type is not None:
                    workflow_meta['workflow_type'] = self.descriptor_type
                if self.trs_endpoint is not None:
                    workflow_meta['trs_endpoint'] = self.trs_endpoint
                if self.workflow_config is not None:
                    workflow_meta['workflow_config'] = self.workflow_config
                if self.params is not None:
                    workflow_meta['params'] = self.params
                if self.outputs is not None:
                    outputs = {output.name: output for output in self.outputs}
                    workflow_meta['outputs'] = outputs

                yaml.dump(marshall_namedtuple(workflow_meta), wmF, Dumper=YAMLDumper)
                
        creds_file = os.path.join(self.metaDir, WORKDIR_SECURITY_CONTEXT_FILE)
        if overwrite or not os.path.exists(creds_file):
            with open(creds_file, mode='w', encoding='utf-8') as crF:
                yaml.dump(marshall_namedtuple(self.creds_config), crF, Dumper=YAMLDumper)
        
        self.configMarshalled = True
    
    def unmarshallConfig(self):
        if not self.configMarshalled:
            workflow_meta_filename = os.path.join(self.metaDir, WORKDIR_WORKFLOW_META_FILE)
            with open(workflow_meta_filename, mode="r", encoding="utf-8") as wcf:
                workflow_meta = unmarshall_namedtuple(yaml.load(wcf, Loader=YAMLLoader))
                
                self.id = workflow_meta['workflow_id']
                self.paranoidMode = workflow_meta['paranoid_mode']
                self.version_id = workflow_meta.get('version')
                self.descriptor_type = workflow_meta.get('workflow_type')
                self.trs_endpoint = workflow_meta.get('trs_endpoint')
                self.workflow_config = workflow_meta.get('workflow_config')
                self.params = workflow_meta.get('params')
                outputsM = workflow_meta.get('outputs')
                if isinstance(outputsM, dict):
                    outputs = list(outputsM.values())
                    self.outputs = self.parseExpectedOutputs(outputsM)
                else:
                    self.outputs = None
            
            valErrors = self.wfexs.ConfigValidate(workflow_meta, self.STAGE_DEFINITION_SCHEMA)
            if len(valErrors) > 0:
                errstr = f'ERROR in workflow staging definition block: {valErrors}'
                self.logger.error(errstr)
                raise WFException(errstr)

            creds_file = os.path.join(self.metaDir, WORKDIR_SECURITY_CONTEXT_FILE)
            if os.path.exists(creds_file):
                with open(creds_file, mode="r", encoding="utf-8") as scf:
                    self.creds_config = unmarshall_namedtuple(yaml.load(scf, Loader=YAMLLoader))
            else:
                self.creds_config = {}
            
            valErrors = self.wfexs.ConfigValidate(self.creds_config, self.SECURITY_CONTEXT_SCHEMA)
            if len(valErrors) > 0:
                errstr = f'ERROR in security context block: {valErrors}'
                self.logger.error(errstr)
                raise WFException(errstr)
                
            self.configMarshalled = True

    
    def marshallStage(self, exist_ok: bool = True):
        if not self.stageMarshalled:
            self.marshallConfig(overwrite=False)

            marshalled_stage_file = os.path.join(self.metaDir, WORKDIR_MARSHALLED_STAGE_FILE)
            if os.path.exists(marshalled_stage_file):
                if not exist_ok:
                    raise WFException("Marshalled stage file already exists")
                self.logger.debug("Marshalled stage file {} already exists".format(marshalled_stage_file))
            else:
                stage = {
                    'repoURL': self.repoURL,
                    'repoTag': self.repoTag,
                    'repoRelPath': self.repoRelPath,
                    'repoEffectiveCheckout': self.repoEffectiveCheckout,
                    'engineDesc': self.engineDesc,
                    'engineVer': self.engineVer,
                    'materializedEngine': self.materializedEngine,
                    'containers': self.listOfContainers,
                    'materializedParams': self.materializedParams
                    # TODO: check nothing essential was left
                }

                self.logger.debug("Creating marshalled stage file {}".format(marshalled_stage_file))
                with open(marshalled_stage_file, mode='w', encoding='utf-8') as msF:
                    marshalled_stage = marshall_namedtuple(stage)
                    yaml.dump(marshalled_stage, msF, Dumper=YAMLDumper)

            self.stageMarshalled = True
        elif not exist_ok:
            raise WFException("Marshalled stage file already exists")

    def unmarshallStage(self, offline: bool = False):
        if not self.stageMarshalled:
            marshalled_stage_file = os.path.join(self.metaDir, WORKDIR_MARSHALLED_STAGE_FILE)
            if not os.path.exists(marshalled_stage_file):
                raise WFException("Marshalled stage file does not exists. Stage state was not stored")

            self.logger.debug("Parsing marshalled stage state file {}".format(marshalled_stage_file))
            with open(marshalled_stage_file, mode='r', encoding='utf-8') as msF:
                marshalled_stage = yaml.load(msF, Loader=YAMLLoader)
                try:
                    stage = unmarshall_namedtuple(marshalled_stage, globals())
                    self.repoURL = stage['repoURL']
                    self.repoTag = stage['repoTag']
                    self.repoRelPath = stage['repoRelPath']
                    self.repoEffectiveCheckout = stage['repoEffectiveCheckout']
                    self.engineDesc = stage['engineDesc']
                    self.engineVer = stage['engineVer']
                    self.materializedEngine = stage['materializedEngine']
                    self.listOfContainers = stage['containers']
                    self.materializedParams = stage['materializedParams']

                    # This is needed to properly set up the materializedEngine
                    self.setupEngine(offline=True)
                except Exception as e:
                    raise WFException("Error while unmarshalling content from stage state file {}. Reason: {}".format(marshalled_stage_file,e))

            self.stageMarshalled = True

    def marshallExecute(self, exist_ok: bool = True):
        if not self.executionMarshalled:
            self.marshallStage(exist_ok=exist_ok)

            marshalled_execution_file = os.path.join(self.metaDir, WORKDIR_MARSHALLED_EXECUTE_FILE)
            if os.path.exists(marshalled_execution_file):
                if not exist_ok:
                    raise WFException("Marshalled execution file already exists")
                self.logger.debug("Marshalled execution file {} already exists".format(marshalled_execution_file))
            else:
                execution = {
                    'exitVal': self.exitVal,
                    'augmentedInputs': self.augmentedInputs,
                    'matCheckOutputs': self.matCheckOutputs
                    # TODO: check nothing essential was left
                }

                self.logger.debug("Creating marshalled execution file {}".format(marshalled_execution_file))
                with open(marshalled_execution_file, mode='w', encoding='utf-8') as msF:
                    yaml.dump(marshall_namedtuple(execution), msF, Dumper=YAMLDumper)

            self.executionMarshalled = True
        elif not exist_ok:
            raise WFException("Marshalled execution file already exists")

    def unmarshallExecute(self, offline: bool = True):
        if not self.executionMarshalled:
            self.unmarshallStage(offline=offline)
            marshalled_execution_file = os.path.join(self.metaDir, WORKDIR_MARSHALLED_EXECUTE_FILE)
            if not os.path.exists(marshalled_execution_file):
                raise WFException("Marshalled execution file does not exists. Execution state was not stored")

            self.logger.debug("Parsing marshalled execution state file {}".format(marshalled_execution_file))
            with open(marshalled_execution_file, mode='r', encoding='utf-8') as meF:
                marshalled_execution = yaml.load(meF, Loader=YAMLLoader)
                try:
                    execution = unmarshall_namedtuple(marshalled_execution, globals())

                    self.exitVal = execution['exitVal']
                    self.augmentedInputs = execution['augmentedInputs']
                    self.matCheckOutputs = execution['matCheckOutputs']
                except Exception as e:
                    raise WFException("Error while unmarshalling content from execution state file {}. Reason: {}".format(marshalled_execution_file, e))

            self.executionMarshalled = True

    def marshallExport(self, exist_ok: bool = True):
        if not self.exportMarshalled:
            self.marshallExecute(exist_ok=exist_ok)

            marshalled_export_file = os.path.join(self.metaDir, WORKDIR_MARSHALLED_EXPORT_FILE)
            if os.path.exists(marshalled_export_file):
                if not exist_ok:
                    raise WFException("Marshalled export results file already exists")
                self.logger.debug("Marshalled export results file {} already exists".format(marshalled_export_file))
            else:
                exported_results = {
                    # TODO
                }

                self.logger.debug("Creating marshalled export results file {}".format(marshalled_export_file))
                with open(marshalled_export_file, mode='w', encoding='utf-8') as msF:
                    yaml.dump(marshall_namedtuple(exported_results), msF, Dumper=YAMLDumper)

            self.exportMarshalled = True
        elif not exist_ok:
            raise WFException("Marshalled export results file already exists")

    def unmarshallExport(self, offline: bool = True):
        if not self.exportMarshalled:
            self.unmarshallExecute(offline=offline)
            marshalled_export_file = os.path.join(self.metaDir, WORKDIR_MARSHALLED_EXPORT_FILE)
            if not os.path.exists(marshalled_export_file):
                raise WFException("Marshalled export results file does not exists. Export results state was not stored")

            self.logger.debug("Parsing marshalled export results state file {}".format(marshalled_export_file))
            with open(marshalled_export_file, mode='r', encoding='utf-8') as meF:
                marshalled_export = yaml.load(meF, Loader=YAMLLoader)
                try:
                    exported_results = unmarshall_namedtuple(marshalled_export, globals())

                    # TODO
                except Exception as e:
                    raise WFException(f"Error while unmarshalling content from export results state file {marshalled_export_file}. Reason: {e}")

            self.exportMarshalled = True

    def createStageResearchObject(self, doMaterializedROCrate: bool = False):
        """
        Create RO-crate from stage provenance.
        """

        # TODO: implement deserialization
        self.unmarshallStage(offline=True)

        # TODO: implement logic of doMaterializedROCrate

        # TODO
        pass

    def createResultsResearchObject(self, doMaterializedROCrate: bool = False):
        """
        Create RO-crate from execution provenance.
        """
        # TODO: implement deserialization
        self.unmarshallExport(offline=True)

        # TODO: implement logic of doMaterializedROCrate

        # TODO: digest the results from executeWorkflow plus all the provenance

        # Create RO-crate using crate.zip downloaded from WorkflowHub
        if os.path.isfile(str(self.cacheROCrateFilename)):
            wfCrate = rocrate.ROCrate(self.cacheROCrateFilename, gen_preview=True)

        # Create RO-Crate using rocrate class
        # TODO no exists the version implemented for Nextflow in rocrate_api
        else:
            # FIXME: What to do when workflow is in git repository different from GitHub??
            # FIXME: What to do when workflow is not in a git repository??
            wf_path = os.path.join(self.localWorkflow.dir, self.localWorkflow.relPath)
            wfCrate, compLang = self.materializedEngine.instance.getEmptyCrateAndComputerLanguage(self.localWorkflow.langVersion)
            wf_url = self.repoURL.replace(".git", "/") + "tree/" + self.repoTag + "/" + os.path.dirname(self.localWorkflow.relPath)

            # TODO create method to create wf_url
            matWf = self.materializedEngine.workflow
            parsed_repo_url = parse.urlparse(self.repoURL)
            if parsed_repo_url.netloc == 'github.com':
                parsed_repo_path = parsed_repo_url.path.split('/')
                repo_name = parsed_repo_path[2]
                if repo_name.endswith('.git'):
                    repo_name = repo_name[:-4]
                wf_entrypoint_path = [
                    '',  # Needed to prepend a slash
                    parsed_repo_path[1],
                    repo_name,
                    matWf.effectiveCheckout,
                    self.localWorkflow.relPath
                ]
                wf_entrypoint_url = parse.urlunparse(
                    ('https', 'raw.githubusercontent.com', '/'.join(wf_entrypoint_path), '', '', ''))
            else:
                raise WFException("FIXME: Unsupported http(s) git repository {}".format(self.repoURL))

            # TODO assign something meaningful to cwl
            cwl = True

            workflow_path = Path(wf_path)
            wf_file = wfCrate.add_workflow(
                str(workflow_path), workflow_path.name, fetch_remote=False,
                main=True, lang=compLang, gen_cwl=(cwl is None)
            )
            # This is needed, as it is not automatically added when the
            # `lang` argument in workflow creation was not a string
            wfCrate.add(compLang)

            # if the source is a remote URL then add https://schema.org/codeRepository
            # property to it this can be checked by checking if the source is a URL
            # instead of a local path
            wf_file.properties()['url'] = wf_entrypoint_url
            wf_file.properties()['codeRepository'] = wf_url
            # if 'url' in wf_file.properties():
            #    wf_file['codeRepository'] = wf_file['url']

            # TODO: add extra files, like nextflow.config in the case of
            # Nextflow workflows, the diagram, an abstract CWL
            # representation of the workflow (when it is not a CWL workflow)
            # etc...
            # for file_entry in include_files:
            #    wfCrate.add_file(file_entry)
            wfCrate.isBasedOn = wf_url

        # Add inputs provenance to RO-crate
        for in_item in self.augmentedInputs:
            if isinstance(in_item, MaterializedInput):
                itemInValues = in_item.values[0]
                if isinstance(itemInValues, MaterializedContent):
                    # TODO: embed metadata_array in some way
                    itemInLocalSource = itemInValues.local
                    itemInURISource = itemInValues.uri
                    if os.path.isfile(itemInLocalSource):   # if is a file
                        properties = {
                            'name': in_item.name
                        }
                        wfCrate.add_file(source=itemInURISource, fetch_remote=False, validate_url=False, properties=properties)
                    elif os.path.isdir(itemInLocalSource):  # if is a directory
                        self.logger.error("FIXME: input directory / dataset handling in RO-Crate")
                    else:
                        pass  # TODO raise Exception

                # TODO digest other types of inputs

        # Add outputs provenance to RO-crate
        for out_item in self.matCheckOutputs:
            if isinstance(out_item, MaterializedOutput):
                itemOutValues = out_item.values[0]
                itemOutSource = itemOutValues.local
                itemOutName = out_item.name
                properties = {
                    'name': itemOutName
                }
                if isinstance(itemOutValues, GeneratedDirectoryContent):    # if is a directory
                    if os.path.isdir(itemOutSource):
                        generatedDirectoryContentURI = ComputeDigestFromDirectory(itemOutSource, repMethod=nihDigester)   # generate nih for the directory
                        dirProperties = dict.fromkeys(['hasPart'])  # files in the directory
                        generatedContentList = []
                        generatedDirectoryContentList = []

                        for item in itemOutValues.values:
                            if isinstance(item, GeneratedContent):  # if is a directory that contains files
                                fileID = item.signature
                                if fileID is None:
                                    fileID = ComputeDigestFromFile(item.local, repMethod=nihDigester)
                                fileProperties = {
                                    'name': itemOutName + "::/" + os.path.basename(item.local),     # output name + file name
                                    'isPartOf': {'@id': generatedDirectoryContentURI}  # reference to the directory
                                }
                                generatedContentList.append({'@id': fileID})
                                wfCrate.add_file(source=fileID, fetch_remote=False, properties=fileProperties)

                            elif isinstance(item, GeneratedDirectoryContent):   # if is a directory that contains directories

                                # search recursively for other content inside directories
                                def search_new_content(content_list):
                                    tempList = []
                                    for content in content_list:
                                        if isinstance(content, GeneratedContent):   # if is a file
                                            fileID = content.signature  # TODO: create a method to add files to RO-crate
                                            if fileID is None:
                                                fileID = ComputeDigestFromFile(content.local, repMethod=nihDigester)
                                            fileProperties = {
                                                'name': itemOutName + "::/" + os.path.basename(content.local),
                                                'isPartOf': {'@id': generatedDirectoryContentURI}
                                            }
                                            tempList.append({'@id': fileID})
                                            wfCrate.add_file(source=fileID, fetch_remote=False, properties=fileProperties)

                                        if isinstance(content, GeneratedDirectoryContent):  # if is a directory
                                            tempList.extend(search_new_content(content.values))
                                    
                                    return tempList

                                generatedDirectoryContentList.append(search_new_content(item.values))

                            else:
                                pass  # TODO raise Exception

                        dirProperties['hasPart'] = sum(generatedDirectoryContentList, []) + generatedContentList
                        properties.update(dirProperties)
                        wfCrate.add_directory(source=generatedDirectoryContentURI, fetch_remote=False, properties=properties)

                    else:
                        pass  # TODO raise Exception

                elif isinstance(itemOutValues, GeneratedContent):   # if is a file
                    if os.path.isfile(itemOutSource):
                        fileID = itemOutValues.signature
                        if fileID is None:
                            fileID = ComputeDigestFromFile(itemOutSource, repMethod=nihDigester)
                        wfCrate.add_file(source=fileID, fetch_remote=False, properties=properties)

                    else:
                        pass  # TODO raise Exception

                else:
                    pass  # TODO raise Exception

        # Save RO-crate as execution.crate.zip
        wfCrate.write_zip(os.path.join(self.outputsDir, "execution.crate"))
        self.logger.info("RO-Crate created: {}".format(self.outputsDir))

        # TODO error handling

    def getWorkflowRepoFromTRS(self, offline: bool = False) -> Tuple[WorkflowType, RepoURL, RepoTag, RelPath]:
        """

        :return:
        """
        cacheHandler = self.wfexs.cacheHandler
        # Now, time to check whether it is a TRSv2
        trs_endpoint_v2_meta_url = self.trs_endpoint + 'service-info'
        trs_endpoint_v2_beta2_meta_url = self.trs_endpoint + 'metadata'
        trs_endpoint_meta_url = None

        # Needed to store this metadata
        trsMetadataCache = os.path.join(self.metaDir, self.TRS_METADATA_FILE)

        try:
            metaContentKind, cachedTRSMetaFile, trsMetaMeta = cacheHandler.fetch(trs_endpoint_v2_meta_url, self.metaDir, offline)
            trs_endpoint_meta_url = trs_endpoint_v2_meta_url
        except WFException as wfe:
            try:
                metaContentKind, cachedTRSMetaFile, trsMetaMeta = cacheHandler.fetch(trs_endpoint_v2_beta2_meta_url, self.metaDir, offline)
                trs_endpoint_meta_url = trs_endpoint_v2_beta2_meta_url
            except WFException as wfebeta:
                raise WFException("Unable to fetch metadata from {} in order to identify whether it is a working GA4GH TRSv2 endpoint. Exceptions:\n{}\n{}".format(self.trs_endpoint, wfe, wfebeta))

        # Giving a friendly name
        if not os.path.exists(trsMetadataCache):
            os.symlink(os.path.basename(cachedTRSMetaFile), trsMetadataCache)

        with open(trsMetadataCache, mode="r", encoding="utf-8") as ctmf:
            self.trs_endpoint_meta = json.load(ctmf)

        # Minimal check
        trs_version = self.trs_endpoint_meta.get('api_version')
        if trs_version is None:
            trs_version = self.trs_endpoint_meta.get('type', {}).get('version')

        if trs_version is None:
            raise WFException("Unable to identify TRS version from {}".format(trs_endpoint_meta_url))

        # Now, check the tool does exist in the TRS, and the version
        trs_tools_url = parse.urljoin(self.trs_endpoint, self.TRS_TOOLS_PATH + parse.quote(self.id, safe=''))

        trsQueryCache = os.path.join(self.metaDir, self.TRS_QUERY_CACHE_FILE)
        _, cachedTRSQueryFile, _ = cacheHandler.fetch(trs_tools_url, self.metaDir, offline)
        # Giving a friendly name
        if not os.path.exists(trsQueryCache):
            os.symlink(os.path.basename(cachedTRSQueryFile), trsQueryCache)

        with open(trsQueryCache, mode="r", encoding="utf-8") as tQ:
            rawToolDesc = tQ.read()

        # If the tool does not exist, an exception will be thrown before
        jd = json.JSONDecoder()
        toolDesc = jd.decode(rawToolDesc)

        # If the tool is not a workflow, complain
        if toolDesc.get('toolclass', {}).get('name', '') != 'Workflow':
            raise WFException(
                'Tool {} from {} is not labelled as a workflow. Raw answer:\n{}'.format(self.id, self.trs_endpoint,
                                                                                        rawToolDesc))

        possibleToolVersions = toolDesc.get('versions', [])
        if len(possibleToolVersions) == 0:
            raise WFException(
                'Version {} not found in workflow {} from {} . Raw answer:\n{}'.format(self.version_id, self.id,
                                                                                       self.trs_endpoint, rawToolDesc))

        toolVersion = None
        toolVersionId = self.version_id
        if (toolVersionId is not None) and len(toolVersionId) > 0:
            for possibleToolVersion in possibleToolVersions:
                if isinstance(possibleToolVersion, dict):
                    possibleId = str(possibleToolVersion.get('id', ''))
                    possibleName = str(possibleToolVersion.get('name', ''))
                    if self.version_id in (possibleId, possibleName):
                        toolVersion = possibleToolVersion
                        break
            else:
                raise WFException(
                    'Version {} not found in workflow {} from {} . Raw answer:\n{}'.format(self.version_id, self.id,
                                                                                           self.trs_endpoint,
                                                                                           rawToolDesc))
        else:
            toolVersionId = ''
            for possibleToolVersion in possibleToolVersions:
                possibleToolVersionId = str(possibleToolVersion.get('id', ''))
                if len(possibleToolVersionId) > 0 and toolVersionId < possibleToolVersionId:
                    toolVersion = possibleToolVersion
                    toolVersionId = possibleToolVersionId

        if toolVersion is None:
            raise WFException(
                'No valid version was found in workflow {} from {} . Raw answer:\n{}'.format(self.id, self.trs_endpoint,
                                                                                             rawToolDesc))

        # The version has been found
        toolDescriptorTypes = toolVersion.get('descriptor_type', [])
        if not isinstance(toolDescriptorTypes, list):
            raise WFException(
                'Version {} of workflow {} from {} has no valid "descriptor_type" (should be a list). Raw answer:\n{}'.format(
                    self.version_id, self.id, self.trs_endpoint, rawToolDesc))

        # Now, realize whether it matches
        chosenDescriptorType = self.descriptor_type
        if chosenDescriptorType is None:
            for candidateDescriptorType in self.RECOGNIZED_TRS_DESCRIPTORS.keys():
                if candidateDescriptorType in toolDescriptorTypes:
                    chosenDescriptorType = candidateDescriptorType
                    break
            else:
                raise WFException(
                    'Version {} of workflow {} from {} has no acknowledged "descriptor_type". Raw answer:\n{}'.format(
                        self.version_id, self.id, self.trs_endpoint, rawToolDesc))
        elif chosenDescriptorType not in toolVersion['descriptor_type']:
            raise WFException(
                'Descriptor type {} not available for version {} of workflow {} from {} . Raw answer:\n{}'.format(
                    self.descriptor_type, self.version_id, self.id, self.trs_endpoint, rawToolDesc))
        elif chosenDescriptorType not in self.RECOGNIZED_TRS_DESCRIPTORS:
            raise WFException(
                'Descriptor type {} is not among the acknowledged ones by this backend. Version {} of workflow {} from {} . Raw answer:\n{}'.format(
                    self.descriptor_type, self.version_id, self.id, self.trs_endpoint, rawToolDesc))

        toolFilesURL = trs_tools_url + '/versions/' + parse.quote(toolVersionId, safe='') + '/' + parse.quote(chosenDescriptorType, safe='') + '/files'

        # Detecting whether RO-Crate trick will work
        if self.trs_endpoint_meta.get('organization', {}).get('name') == 'WorkflowHub':
            self.logger.debug("WorkflowHub workflow")
            # And this is the moment where the RO-Crate must be fetched
            roCrateURL = toolFilesURL + '?' + parse.urlencode({'format': 'zip'})

            return self.getWorkflowRepoFromROCrateURL(roCrateURL,
                                                   expectedEngineDesc=self.RECOGNIZED_TRS_DESCRIPTORS[
                                                       chosenDescriptorType], offline=offline)
        else:
            self.logger.debug("TRS workflow")
            # Learning the available files and maybe
            # which is the entrypoint to the workflow
            _, trsFilesDir, trsFilesMeta = self.wfexs.cacheFetch(INTERNAL_TRS_SCHEME_PREFIX + ':' + toolFilesURL, CacheType.TRS, offline)

            expectedEngineDesc = self.RECOGNIZED_TRS_DESCRIPTORS[chosenDescriptorType]
            remote_workflow_entrypoint = trsFilesMeta[0].metadata.get('remote_workflow_entrypoint')
            if remote_workflow_entrypoint is not None:
                # Give it a chance to identify the original repo of the workflow
                repoURL, repoTag, repoRelPath = self.wfexs.guessRepoParams(remote_workflow_entrypoint, fail_ok=False)

                if repoURL is not None:
                    self.logger.debug("Derived repository {} ({} , rel {}) from {}".format(repoURL, repoTag, repoRelPath, trs_tools_url))
                    return expectedEngineDesc , repoURL, repoTag, repoRelPath

            workflow_entrypoint = trsFilesMeta[0].metadata.get('workflow_entrypoint')
            if workflow_entrypoint is not None:
                self.logger.debug("Using raw files from TRS tool {}".format(trs_tools_url))
                repoDir = trsFilesDir
                repoRelPath = workflow_entrypoint
                return expectedEngineDesc, repoDir, None, repoRelPath

        raise WFException("Unable to find a workflow in {}".format(trs_tools_url))

    def getWorkflowRepoFromROCrateURL(self, roCrateURL, expectedEngineDesc: WorkflowType = None, offline: bool = False) -> Tuple[WorkflowType, RepoURL, RepoTag, RelPath]:
        """

        :param roCrateURL:
        :param expectedEngineDesc: If defined, an instance of WorkflowType
        :return:
        """
        roCrateFile = self.wfexs.downloadROcrate(roCrateURL, offline=offline)
        self.logger.info("downloaded RO-Crate: {} -> {}".format(roCrateURL, roCrateFile))

        return self.getWorkflowRepoFromROCrateFile(roCrateFile, expectedEngineDesc)

    def getWorkflowRepoFromROCrateFile(self, roCrateFile: AbsPath, expectedEngineDesc: WorkflowType = None) -> Tuple[WorkflowType, RepoURL, RepoTag, RelPath]:
        """

        :param roCrateFile:
        :param expectedEngineDesc: If defined, an instance of WorkflowType
        :return:
        """
        roCrateObj = rocrate.ROCrate(roCrateFile)

        # TODO: get roCrateObj mainEntity programming language
        # self.logger.debug(roCrateObj.root_dataset.as_jsonld())
        mainEntityProgrammingLanguageId = None
        mainEntityProgrammingLanguageUrl = None
        mainEntityIdHolder = None
        mainEntityId = None
        workflowPID = None
        workflowUploadURL = None
        workflowTypeId = None
        for e in roCrateObj.get_entities():
            if (mainEntityIdHolder is None) and e['@type'] == 'CreativeWork' and '.json' in e['@id']:
                mainEntityIdHolder = e.as_jsonld()['about']['@id']
            elif e['@id'] == mainEntityIdHolder:
                eAsLD = e.as_jsonld()
                mainEntityId = eAsLD['mainEntity']['@id']
                workflowPID = eAsLD.get('identifier')
            elif e['@id'] == mainEntityId:
                eAsLD = e.as_jsonld()
                workflowUploadURL = eAsLD.get('url')
                workflowTypeId = eAsLD['programmingLanguage']['@id']
            elif e['@id'] == workflowTypeId:
                # A bit dirty, but it works
                eAsLD = e.as_jsonld()
                mainEntityProgrammingLanguageId = eAsLD.get('identifier', {}).get('@id')
                mainEntityProgrammingLanguageUrl = eAsLD.get('url', {}).get('@id')

        # Now, it is time to match the language id
        engineDescById = None
        engineDescByUrl = None
        for possibleEngineDesc in self.WORKFLOW_ENGINES:
            if (engineDescById is None) and (mainEntityProgrammingLanguageId is not None):
                for pat in possibleEngineDesc.uriMatch:
                    if isinstance(pat, Pattern):
                        match = pat.search(mainEntityProgrammingLanguageId)
                        if match:
                            engineDescById = possibleEngineDesc
                    elif pat == mainEntityProgrammingLanguageId:
                        engineDescById = possibleEngineDesc

            if (engineDescByUrl is None) and (mainEntityProgrammingLanguageUrl == possibleEngineDesc.url):
                engineDescByUrl = possibleEngineDesc

        engineDesc = None
        if engineDescById is not None:
            engineDesc = engineDescById
        elif engineDescByUrl is not None:
            engineDesc = engineDescByUrl
        else:
            raise WFException(
                'Found programming language {} (url {}) in RO-Crate manifest is not among the acknowledged ones'.format(
                    mainEntityProgrammingLanguageId, mainEntityProgrammingLanguageUrl))

        if (engineDescById is not None) and (engineDescByUrl is not None) and engineDescById != engineDescByUrl:
            self.logger.warning('Found programming language {} (url {}) leads to different engines'.format(
                mainEntityProgrammingLanguageId, mainEntityProgrammingLanguageUrl))

        if (expectedEngineDesc is not None) and engineDesc != expectedEngineDesc:
            raise WFException(
                'Expected programming language {} does not match identified one {} in RO-Crate manifest'.format(
                    expectedEngineDesc.engineName, engineDesc.engineName))

        # This workflow URL, in the case of github, can provide the repo,
        # the branch/tag/checkout , and the relative directory in the
        # fetched content (needed by Nextflow)

        # Some RO-Crates might have this value missing or ill-built
        if workflowUploadURL is not None:
            repoURL, repoTag, repoRelPath = self.wfexs.guessRepoParams(workflowUploadURL, fail_ok=False)

        if repoURL is None:
            repoURL, repoTag, repoRelPath = self.wfexs.guessRepoParams(roCrateObj.root_dataset['isBasedOn'], fail_ok=False)

        if repoURL is None:
            raise WFException('Unable to guess repository from RO-Crate manifest')

        # It must return four elements:
        return engineDesc, repoURL, repoTag, repoRelPath

