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

import datetime
import inspect
import json
import logging
import os
import pathlib
import shutil
import subprocess
import sys
import tempfile
import threading
import time

from typing import Any, List, Mapping, Optional, Pattern, Sequence
from typing import cast, Final, TYPE_CHECKING, Tuple, Type, Union

from urllib import parse

from rocrate import rocrate # type: ignore[import]
from .ro_crate import addInputsResearchObject, addOutputsResearchObject
import bagit    # type: ignore[import]

# We have preference for the C based loader and dumper, but the code
# should fallback to default implementations when C ones are not present

import yaml
YAMLLoader: Type[Union[yaml.Loader, yaml.CLoader]]
YAMLDumper: Type[Union[yaml.Dumper, yaml.CDumper]]
try:
    from yaml import CLoader as YAMLLoader, CDumper as YAMLDumper
except ImportError:
    from yaml import Loader as YAMLLoader, Dumper as YAMLDumper

from .common import AbstractWfExSException
from .common import AbstractWorkflowEngineType
from .common import AbsPath, RelPath, WfExSInstanceId
from .common import Fingerprint
from .common import RepoTag, RepoURL, LicensedURI
from .common import CacheType, ContentKind, WorkflowType, URIType
from .common import ExpectedOutput, MaterializedWorkflowEngine
from .common import IdentifiedWorkflow, LocalWorkflow
from .common import GeneratedContent, GeneratedDirectoryContent
from .common import MaterializedContent, MaterializedInput, MaterializedOutput
from .common import MarshallingStatus, StagedSetup, EngineVersion
from .common import SecurityContextConfig, SecurityContextConfigBlock
from .common import Attribution, DefaultNoLicenceTuple
from .common import TRS_Workflow_Descriptor, RemoteRepo
# These imports are needed to properly unmarshall from YAML
from .common import Container, URIWithMetadata, ExitVal

from .encrypted_fs import ENCRYPTED_FS_MOUNT_IMPLEMENTATIONS

from .engine import WorkflowEngine, WorkflowEngineException
from .engine import WORKDIR_WORKFLOW_META_FILE, WORKDIR_PASSPHRASE_FILE
from .engine import WORKDIR_MARSHALLED_STAGE_FILE, WORKDIR_MARSHALLED_EXECUTE_FILE, WORKDIR_MARSHALLED_EXPORT_FILE
from .engine import WORKDIR_INPUTS_RELDIR, WORKDIR_INTERMEDIATE_RELDIR, WORKDIR_META_RELDIR, WORKDIR_OUTPUTS_RELDIR, \
    WORKDIR_ENGINE_TWEAKS_RELDIR, WORKDIR_WORKFLOW_RELDIR, WORKDIR_CONTAINERS_RELDIR

from .utils.contents import link_or_copy
from .utils.digests import ComputeDigestFromDirectory, ComputeDigestFromFile, nihDigester
from .utils.marshalling_handling import marshall_namedtuple, unmarshall_namedtuple
from .utils.misc import config_validate

from .fetchers.trs_files import INTERNAL_TRS_SCHEME_PREFIX

from .nextflow_engine import NextflowWorkflowEngine
from .cwl_engine import CWLWorkflowEngine

if TYPE_CHECKING:
    from .wfexs_backend import WfExSBackend

# The list of classes to be taken into account
# CWL detection is before, as Nextflow one is
# a bit lax (only detects a couple of too common
# keywords)
WORKFLOW_ENGINE_CLASSES : List[Type[WorkflowEngine]] = [
    CWLWorkflowEngine,
    NextflowWorkflowEngine,
]


def _wakeupEncDir(cond: threading.Condition, workDir: AbsPath, logger: logging.Logger):
    """
    This method periodically checks whether the directory is still available
    """
    cond.acquire()
    try:
        while not cond.wait(60):
            os.path.isdir(workDir)
    except:
        logger.exception('Wakeup thread failed!')
    finally:
        cond.release()


class WFException(AbstractWfExSException):
    pass


class WF:
    """
    Workflow enaction class
    """

    TRS_METADATA_FILE: Final[RelPath] = cast(RelPath, 'trs_metadata.json')
    TRS_QUERY_CACHE_FILE: Final[RelPath] = cast(RelPath, 'trs_result.json')
    TRS_TOOL_FILES_FILE: Final[RelPath] =  cast(RelPath, 'trs_tool_files.json')

    SECURITY_CONTEXT_SCHEMA: Final[RelPath] =  cast(RelPath, 'security-context.json')
    STAGE_DEFINITION_SCHEMA: Final[RelPath] =  cast(RelPath, 'stage-definition.json')

    DEFAULT_RO_EXTENSION: Final[str] = ".crate.zip"
    DEFAULT_TRS_ENDPOINT: Final[str] = "https://dev.workflowhub.eu/ga4gh/trs/v2/"  # root of GA4GH TRS API
    TRS_TOOLS_PATH: Final[str] = 'tools/'
    
    WORKFLOW_ENGINES: Final[List[WorkflowType]] = list(map(lambda clazz: clazz.MyWorkflowType(), WORKFLOW_ENGINE_CLASSES))

    RECOGNIZED_TRS_DESCRIPTORS: Final[Mapping[TRS_Workflow_Descriptor, WorkflowType]] = dict(map(lambda t: (t.trs_descriptor, t), WORKFLOW_ENGINES))

    def __init__(self,
                 wfexs: "WfExSBackend",
                 workflow_id=None,
                 version_id=None,
                 descriptor_type=None,
                 trs_endpoint=DEFAULT_TRS_ENDPOINT,
                 params=None,
                 outputs=None,
                 workflow_config=None,
                 creds_config: Optional[SecurityContextConfigBlock] =None,
                 instanceId: Optional[WfExSInstanceId] = None,
                 nickname: Optional[str] = None,
                 creation: Optional[datetime.datetime] = None,
                 rawWorkDir: Optional[Union[RelPath, AbsPath]] = None,
                 paranoid_mode: Optional[bool] = None,
                 fail_ok: bool = False
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
        :param creds_config: Dictionary with the different credential contexts, only used to fetch fresh contents
        :param instanceId: The instance id of this working directory
        :param nickname: The nickname of this working directory
        :param creation: The creation timestamp
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
        :type creds_config: SecurityContextConfigBlock
        :type instanceId: str
        :type creation datetime.datetime
        :type rawWorkDir: str
        :type paranoid_mode: bool
        :type fail_ok: bool
        """
        if wfexs is None:
            raise WFException('Unable to initialize, no WfExSBackend instance provided')
        
        # Getting a logger focused on specific classes
        self.logger = logging.getLogger(dict(inspect.getmembers(self))['__module__'] + '::' + self.__class__.__name__)
        
        self.wfexs = wfexs
        self.encWorkDir : Optional[AbsPath] = None
        self.workDir : Optional[AbsPath] = None
        
        if isinstance(paranoid_mode, bool):
            self.paranoidMode = paranoid_mode
        else:
            self.paranoidMode = self.wfexs.getDefaultParanoidMode()
        
        if not isinstance(workflow_config, dict):
            workflow_config = {}
        
        self.outputs : Optional[List[ExpectedOutput]]
        if workflow_id is not None:
            workflow_meta = {
                'workflow_id': workflow_id
            }
            if version_id is not None:
                workflow_meta['version'] = version_id
            if nickname is not None:
                workflow_meta['nickname'] = nickname
            if descriptor_type is not None:
                descriptor = self.RECOGNIZED_TRS_DESCRIPTORS.get(descriptor_type)
                if descriptor is not None:
                    workflow_meta['workflow_type'] = descriptor.shortname
                else:
                    workflow_meta['workflow_type'] = descriptor_type
            if trs_endpoint is not None:
                workflow_meta['trs_endpoint'] = trs_endpoint
            if workflow_config is not None:
                workflow_meta['workflow_config'] = workflow_config
            if params is not None:
                workflow_meta['params'] = params
            if outputs is not None:
                workflow_meta['outputs'] = outputs
            
            valErrors = config_validate(workflow_meta, self.STAGE_DEFINITION_SCHEMA)
            if len(valErrors) > 0:
                errstr = f'ERROR in workflow staging definition block: {valErrors}'
                self.logger.error(errstr)
                raise WFException(errstr)

            if not isinstance(creds_config, dict):
                creds_config = {}

            valErrors = config_validate(creds_config, self.SECURITY_CONTEXT_SCHEMA)
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
        
        if creation is None:
            self.workdir_creation = datetime.datetime.now(tz=datetime.timezone.utc)
        else:
            self.workdir_creation = creation
        
        self.encfs_type = None
        self.encfsCond = None
        self.encfsThread = None
        self.fusermount_cmd = None
        self.encfs_idleMinutes = None
        self.doUnmount = False
        
        checkSecure = True
        if rawWorkDir is None:
            if instanceId is None:
                self.instanceId , self.nickname, self.workdir_creation , self.rawWorkDir = self.wfexs.createRawWorkDir(nickname_prefix=nickname)
                checkSecure = False
            else:
                self.instanceId , self.nickname, self.workdir_creation , self.rawWorkDir = self.wfexs.getOrCreateRawWorkDirFromInstanceId(instanceId, nickname=nickname, create_ok=False)
        else:
            self.rawWorkDir = cast(AbsPath, os.path.abspath(rawWorkDir))
            if instanceId is None:
                self.instanceId , self.nickname, self.workdir_creation, _ = self.wfexs.parseOrCreateRawWorkDir(self.rawWorkDir, nickname=nickname, create_ok=False)
            else:
                self.nickname = nickname  if nickname is not None  else  instanceId

        # TODO: enforce restrictive permissions on each raw working directory
        self.allowOther = False
        
        if checkSecure:
            passphraseFile = os.path.join(self.rawWorkDir, WORKDIR_PASSPHRASE_FILE)
            self.secure = os.path.exists(passphraseFile)
        else:
            self.secure = workflow_config.get('secure', True)
        
        doSecureWorkDir = self.secure or self.paranoidMode

        was_setup = self.setupWorkdir(doSecureWorkDir, fail_ok=fail_ok)
        
        self.configMarshalled : Optional[Union[bool, datetime.datetime]] = None
        self.inputsDir : Optional[AbsPath]
        self.intermediateDir : Optional[AbsPath]
        self.outputsDir : Optional[AbsPath]
        self.engineTweaksDir : Optional[AbsPath]
        self.metaDir : Optional[AbsPath]
        self.workflowDir : Optional[AbsPath]
        self.containersDir : Optional[AbsPath]
        if was_setup:
            assert self.workDir is not None, "Workdir has to be already defined at this point"
            # This directory will hold either symbolic links to the cached
            # inputs, or the inputs properly post-processed (decompressed,
            # decrypted, etc....)
            self.inputsDir = cast(AbsPath, os.path.join(self.workDir, WORKDIR_INPUTS_RELDIR))
            os.makedirs(self.inputsDir, exist_ok=True)
            # This directory should hold intermediate workflow steps results
            self.intermediateDir = cast(AbsPath, os.path.join(self.workDir, WORKDIR_INTERMEDIATE_RELDIR))
            os.makedirs(self.intermediateDir, exist_ok=True)
            # This directory will hold the final workflow results, which could
            # be either symbolic links to the intermediate results directory
            # or newly generated content
            self.outputsDir = cast(AbsPath, os.path.join(self.workDir, WORKDIR_OUTPUTS_RELDIR))
            os.makedirs(self.outputsDir, exist_ok=True)
            # This directory is here for those files which are created in order
            # to tweak or patch workflow executions
            self.engineTweaksDir = cast(AbsPath, os.path.join(self.workDir, WORKDIR_ENGINE_TWEAKS_RELDIR))
            os.makedirs(self.engineTweaksDir, exist_ok=True)
            # This directory will hold metadata related to the execution
            self.metaDir = cast(AbsPath, os.path.join(self.workDir, WORKDIR_META_RELDIR))
            # This directory will hold either a hardlink or a copy of the workflow
            self.workflowDir = cast(AbsPath, os.path.join(self.workDir, WORKDIR_WORKFLOW_RELDIR))
            # This directory will hold either a hardlink or a copy of the containers
            self.containersDir = cast(AbsPath, os.path.join(self.workDir, WORKDIR_CONTAINERS_RELDIR))

            # This is true when the working directory already exists
            if checkSecure:
                if not os.path.isdir(self.metaDir):
                    self.configMarshalled = False
                    errstr = "Staged working directory {} is incomplete".format(self.workDir)
                    self.logger.exception(errstr)
                    if not fail_ok:
                        raise WFException(errstr)
                    self.workflow_config = None
                    is_damaged = True
                else:
                    # In order to be able to build next paths to call
                    unmarshalled = self.unmarshallConfig(fail_ok=fail_ok)
                    # One of the worst scenarios
                    is_damaged = not unmarshalled
                    if is_damaged:
                        self.workflow_config = None
                        # self.marshallConfig(overwrite=False)
            else:
                os.makedirs(self.metaDir, exist_ok=True)
                self.marshallConfig(overwrite=True)
                is_damaged = False
        else:
            self.configMarshalled = False
            is_damaged = True
            self.inputsDir = None
            self.intermediateDir = None
            self.outputsDir = None
            self.engineTweaksDir = None
            self.metaDir = None
            self.workflowDir = None
            self.containersDir = None

        self.stagedSetup = StagedSetup(
            instance_id=self.instanceId,
            nickname=self.nickname,
            creation=self.workdir_creation,
            workflow_config=self.workflow_config,
            raw_work_dir=self.rawWorkDir,
            work_dir=self.workDir,
            workflow_dir=self.workflowDir,
            inputs_dir=self.inputsDir,
            outputs_dir=self.outputsDir,
            intermediate_dir=self.intermediateDir,
            engine_tweaks_dir=self.engineTweaksDir,
            meta_dir=self.metaDir,
            temp_dir=self.tempDir,
            secure_exec=self.secure or self.paranoidMode,
            allow_other=self.allowOther,
            is_encrypted=doSecureWorkDir,
            is_damaged=is_damaged
        )
        
        self.repoURL : Optional[RepoURL] = None
        self.repoTag : Optional[RepoTag] = None
        self.repoRelPath : Optional[RelPath] = None
        self.repoDir : Optional[AbsPath] = None
        self.repoEffectiveCheckout : Optional[RepoTag] = None
        self.engine : Optional[AbstractWorkflowEngineType] = None
        self.engineVer : Optional[EngineVersion] = None
        self.engineDesc : Optional[WorkflowType] = None

        self.materializedParams : Optional[Sequence[MaterializedInput]] = None
        self.localWorkflow : Optional[LocalWorkflow] = None
        self.materializedEngine : Optional[MaterializedWorkflowEngine] = None

        self.exitVal : Optional[ExitVal] = None
        self.augmentedInputs : Optional[Sequence[MaterializedInput]] = None
        self.matCheckOutputs : Optional[Sequence[MaterializedOutput]] = None
        self.cacheROCrateFilename : Optional[AbsPath] = None
        
        self.stageMarshalled : Optional[Union[bool, datetime.datetime]] = None
        self.executionMarshalled : Optional[Union[bool, datetime.datetime]] = None
        self.exportMarshalled : Optional[Union[bool, datetime.datetime]] = None

    FUSE_SYSTEM_CONF = '/etc/fuse.conf'

    def setupWorkdir(self, doSecureWorkDir: bool, fail_ok: bool = False) -> bool:
        uniqueRawWorkDir = self.rawWorkDir

        allowOther = False
        uniqueEncWorkDir : Optional[AbsPath]
        uniqueWorkDir : AbsPath
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

            uniqueEncWorkDir = cast(AbsPath, os.path.join(uniqueRawWorkDir, '.crypt'))
            uniqueWorkDir = cast(AbsPath, os.path.join(uniqueRawWorkDir, 'work'))

            # The directories should exist before calling encryption FS mount
            os.makedirs(uniqueEncWorkDir, exist_ok=True)
            os.makedirs(uniqueWorkDir, exist_ok=True)

            # This is the passphrase needed to decrypt the filesystem
            passphraseFile = cast(AbsPath, os.path.join(uniqueRawWorkDir, WORKDIR_PASSPHRASE_FILE))
            
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
                was_setup = True
            else:
                # DANGER!
                # We are removing leftovers in work directory
                with os.scandir(uniqueWorkDir) as uwi:
                    for entry in uwi:
                        # Tainted, not empty directory. Moving...
                        if entry.name not in ('.', '..'):
                            self.logger.warning(f"Destination mount point {uniqueWorkDir} is tainted. Moving...")
                            shutil.move(uniqueWorkDir, uniqueWorkDir + '_tainted_' + str(time.time()))
                            os.makedirs(uniqueWorkDir, exist_ok=True)
                            break
                
                # We are going to unmount what we have mounted
                self.doUnmount = True

                # Now, time to mount the encrypted FS
                try:
                    ENCRYPTED_FS_MOUNT_IMPLEMENTATIONS[encfs_type](encfs_cmd, self.encfs_idleMinutes, uniqueEncWorkDir,
                                                                   uniqueWorkDir, uniqueRawWorkDir, securePassphrase,
                                                                   allowOther)
                except Exception as e:
                    errmsg = f'Cannot FUSE mount {uniqueWorkDir} with {encfs_cmd}'
                    self.logger.exception(errmsg)
                    if not fail_ok:
                        raise WFException(errmsg) from e
                    was_setup = False
                else:
                    was_setup = True
                    # and start the thread which keeps the mount working
                    self.encfsCond = threading.Condition()
                    self.encfsThread = threading.Thread(target=_wakeupEncDir, args=(self.encfsCond, uniqueWorkDir, self.logger), daemon=True)
                    self.encfsThread.start()

            # self.encfsPassphrase = securePassphrase
            del securePassphrase
        else:
            uniqueEncWorkDir = None
            uniqueWorkDir = uniqueRawWorkDir
            was_setup = True

        # The temporary directory is in the raw working directory as
        # some container engine could fail
        uniqueTempDir = cast(AbsPath, os.path.join(uniqueRawWorkDir,'.TEMP'))
        os.makedirs(uniqueTempDir, exist_ok=True)
        os.chmod(uniqueTempDir, 0o1777)

        # Setting up working directories, one per instance
        self.encWorkDir = uniqueEncWorkDir
        self.workDir = uniqueWorkDir
        self.tempDir = uniqueTempDir
        self.allowOther = allowOther
        
        return was_setup

    def unmountWorkdir(self):
        if self.doUnmount and (self.encWorkDir is not None):
            if self.encfsCond is not None:
                self.encfsCond.acquire()
                self.encfsCond.notify()
                self.encfsThread = None
                self.encfsCond = None
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
    
    def getStagedSetup(self) -> StagedSetup:
        return self.stagedSetup
    
    def getMarshallingStatus(self) -> MarshallingStatus:
        return MarshallingStatus(
            config=self.configMarshalled,
            stage=self.stageMarshalled,
            execution=self.executionMarshalled,
            export=self.exportMarshalled
        )
    
    def enableParanoidMode(self) -> None:
        self.paranoidMode = True

    @classmethod
    def FromWorkDir(cls, wfexs: "WfExSBackend", workflowWorkingDirectory: Union[RelPath, AbsPath], fail_ok: bool = False) -> "WF":
        """
        This class method requires an existing staged working directory
        """
        
        if wfexs is None:
            raise WFException('Unable to initialize, no WfExSBackend instance provided')
        
        instanceId, nickname, creation, rawWorkDir = wfexs.normalizeRawWorkingDirectory(workflowWorkingDirectory)
        
        return cls(wfexs, instanceId=instanceId, nickname=nickname, rawWorkDir=rawWorkDir, creation=creation, fail_ok=fail_ok)
    
    @classmethod
    def ReadSecurityContextFile(cls, securityContextsConfigFilename: Union[RelPath, AbsPath]) -> SecurityContextConfigBlock:
        with open(securityContextsConfigFilename, mode="r", encoding="utf-8") as scf:
            creds_config = unmarshall_namedtuple(yaml.load(scf, Loader=YAMLLoader))
            
        return creds_config
    
    @classmethod
    def FromFiles(cls, wfexs: "WfExSBackend", workflowMetaFilename: Union[RelPath, AbsPath], securityContextsConfigFilename: Optional[Union[RelPath, AbsPath]] = None, nickname_prefix: Optional[str] = None, paranoidMode: bool = False) -> "WF":
        """
        This class method creates a new staged working directory
        """
        
        with open(workflowMetaFilename, mode="r", encoding="utf-8") as wcf:
            workflow_meta = unmarshall_namedtuple(yaml.load(wcf, Loader=YAMLLoader))
            
        # Should we prepend the nickname prefix?
        if nickname_prefix is not None:
            workflow_meta['nickname'] = nickname_prefix + workflow_meta.get('nickname', "")

        # Last, try loading the security contexts credentials file
        if securityContextsConfigFilename and os.path.exists(securityContextsConfigFilename):
            creds_config = cls.ReadSecurityContextFile(securityContextsConfigFilename)
        else:
            creds_config = {}

        return cls.FromDescription(wfexs, workflow_meta, creds_config, paranoidMode=paranoidMode)
    
    @classmethod
    def FromDescription(cls, wfexs: "WfExSBackend", workflow_meta, creds_config: Optional[SecurityContextConfigBlock] = None, paranoidMode: bool = False) -> "WF":
        """
        This class method might create a new staged working directory
        
        :param wfexs: WfExSBackend instance
        :param workflow_meta: The configuration describing both the workflow
        and the inputs to use when it is being instantiated.
        :param creds_config: Dictionary with the different credential contexts (to be implemented)
        :param paranoidMode:
        :type wfexs: WfExSBackend
        :type workflow_meta: dict
        :type creds_config: SecurityContextConfigBlock
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
            nickname=workflow_meta.get('nickname'),
            creds_config=creds_config,
            paranoid_mode=paranoidMode
        )
    
    @classmethod
    def FromForm(cls, wfexs: "WfExSBackend", workflow_meta, paranoidMode: bool = False):  # VRE
        """

        :param wfexs: WfExSBackend instance
        :param workflow_meta: The configuration describing both the workflow
        and the inputs to use when it is being instantiated.
        :param paranoidMode:
        :type workflow_meta: dict
        :type paranoidMode: bool
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
            nickname=workflow_meta.get('nickname'),
            paranoid_mode=paranoidMode
        )

    def fetchWorkflow(self, offline: bool = False):
        """
        Fetch the whole workflow description based on the data obtained
        from the TRS where it is being published.

        If the workflow id is an URL, it is supposed to be a git repository,
        and the version will represent either the branch, tag or specific commit.
        So, the whole TRS fetching machinery is bypassed.workflowDir
        """
        parsedRepoURL = parse.urlparse(self.id)

        # It is not an absolute URL, so it is being an identifier in the workflow
        i_workflow : Optional[IdentifiedWorkflow] = None
        engineDesc : Optional[WorkflowType] = None
        guessedRepo : Optional[RemoteRepo] = None
        if parsedRepoURL.scheme == '':
            if (self.trs_endpoint is not None) and len(self.trs_endpoint) > 0:
                i_workflow = self.getWorkflowRepoFromTRS(offline=offline)
            else:
                raise WFException('trs_endpoint was not provided')
        else:
            engineDesc = None

            # Trying to be smarter
            guessedRepo = self.wfexs.guessRepoParams(parsedRepoURL, fail_ok=True)

            if guessedRepo is not None:
                if guessedRepo.tag is None:
                    guessedRepo = RemoteRepo(
                        repo_url=guessedRepo.repo_url,
                        tag=cast(RepoTag, self.version_id),
                        rel_path=guessedRepo.rel_path
                    )
            else:
                i_workflow = self.getWorkflowRepoFromROCrateURL(cast(URIType, self.id), offline=offline)
        
        if i_workflow is not None:
            guessedRepo = i_workflow.remote_repo
            engineDesc = i_workflow.workflow_type
        
        if guessedRepo is None:
            # raise WFException('Unable to guess repository from RO-Crate manifest')
            guessedRepo = RemoteRepo(
                repo_url=cast(RepoURL, self.id),
                tag=cast(RepoTag, self.version_id)
            )
        
        repoURL = guessedRepo.repo_url
        repoTag = guessedRepo.tag
        repoRelPath = guessedRepo.rel_path

        repoDir : Optional[AbsPath] = None
        repoEffectiveCheckout : Optional[RepoTag] = None
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
            repoDir = cast(AbsPath, repoURL)

        # Workflow Language version cannot be assumed here yet
        # A copy of the workflows is kept
        assert self.workflowDir is not None, "The workflow directory should be defined"
        if os.path.isdir(self.workflowDir):
            shutil.rmtree(self.workflowDir)
        link_or_copy(repoDir, self.workflowDir)
        localWorkflow = LocalWorkflow(dir=self.workflowDir, relPath=repoRelPath, effectiveCheckout=repoEffectiveCheckout)
        self.logger.info("materialized workflow repository (checkout {}): {}".format(repoEffectiveCheckout, self.workflowDir))

        if repoRelPath is not None:
            if not os.path.exists(os.path.join(self.workflowDir, repoRelPath)):
                raise WFException(
                    "Relative path {} cannot be found in materialized workflow repository {}".format(repoRelPath,
                                                                                                     self.workflowDir))
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

    def setupEngine(self, offline: bool = False):
        # The engine is populated by self.fetchWorkflow()
        if self.engine is None:
            self.fetchWorkflow(offline=offline)
        
        assert self.engine is not None, "Workflow engine not properly identified or set up"

        if self.materializedEngine is None:
            assert self.localWorkflow is not None
            localWorkflow = self.localWorkflow
        else:
            localWorkflow = self.materializedEngine.workflow

        matWfEngV2 = self.engine.materializeEngine(localWorkflow, self.engineVer)
        
        # At this point, there can be uninitialized elements
        if (self.materializedEngine is not None) and (matWfEngV2 is not None):
            matWfEngV2 = MaterializedWorkflowEngine(
                instance=matWfEngV2.instance,
                version=matWfEngV2.version,
                fingerprint=matWfEngV2.fingerprint,
                engine_path=matWfEngV2.engine_path,
                workflow=matWfEngV2.workflow,
                containers_path=self.materializedEngine.containers_path,
                containers=self.materializedEngine.containers,
                operational_containers=self.materializedEngine.operational_containers
            )
        self.materializedEngine = matWfEngV2

    def materializeWorkflow(self, offline: bool = False):
        if self.materializedEngine is None:
            self.setupEngine(offline=offline)
        
        assert self.materializedEngine is not None, "The materialized workflow engine should be available at this point"
        
        # This information is badly needed for provenance
        if self.materializedEngine.containers is None:
            assert self.containersDir is not None, "The destination directory should be available here"
            if not offline:
                os.makedirs(self.containersDir, exist_ok=True)
            self.materializedEngine = WorkflowEngine.MaterializeWorkflowAndContainers(self.materializedEngine, self.containersDir, offline=offline)

    def injectInputs(self, paths, workflowInputs_destdir=None, workflowInputs_cacheDir=None, lastInput: int = 0):
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
                cast(URIType, fileuri),
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

    def materializeInputs(self, offline: bool = False, lastInput: int = 0):
        assert self.inputsDir is not None, "The working directory should not be corrupted beyond basic usage"
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
    
    def buildLicensedURI(self, remote_file: Union[URIType, Mapping, Sequence], contextName: Optional[str] = None, licences: Tuple[URIType, ...] = DefaultNoLicenceTuple, attributions: Sequence[Attribution] = []) -> Union[LicensedURI, Sequence[LicensedURI]]:
        if isinstance(remote_file, list):
            retvals = []
            for remote_url in remote_file:
                retval = self.buildLicensedURI(remote_url, contextName=contextName, licences=licences, attributions=attributions)
                if isinstance(retval, list):
                    retvals.extend(retval)
                else:
                    retvals.append(retval)
            
            return retvals
        
        if isinstance(remote_file, dict):
            # The value of the attributes is superseded
            remote_url = remote_file['uri']
            licences = remote_file.get('licences', licences)
            if isinstance(licences, list):
                licences = tuple(licences)
            contextName = remote_file.get('security-context', contextName)
            
            # Reconstruction of the attributions
            rawAttributions = remote_file.get('attributions')
            parsed_attributions = Attribution.ParseRawAttributions(remote_file.get('attributions'))
            # Only overwrite in this case
            if len(parsed_attributions) > 0:
                attributions = parsed_attributions
        else:
            remote_url = remote_file
        
        secContext = None
        if contextName is not None:
            secContext = self.creds_config.get(contextName)
            if secContext is None:
                raise WFException(
                    'No security context {} is available, needed by {}'.format(contextName, remote_file))
        
        return LicensedURI(
            uri=remote_url,
            licences=licences,
            attributions=attributions,
            secContext=secContext
        )
    
    def _fetchRemoteFiles(self, remote_files: Sequence[Union[URIType, Mapping, List]], contextName: Optional[str], offline:bool, storeDir: Union[AbsPath,CacheType], cacheable: bool, inputDestDir:AbsPath, globExplode: Optional[str], lastInput: int = 0) -> Tuple[Sequence[MaterializedContent], int]:
        remote_pairs = []
        # Embedding the context
        alt_remote_files = [ self.buildLicensedURI(remote_file, contextName=contextName) for remote_file in remote_files ]
        for alt_remote_file in alt_remote_files:
            matContent = self.wfexs.downloadContent(
                alt_remote_file,
                dest=storeDir,
                offline=offline,
                ignoreCache=not cacheable,
                registerInCache=cacheable
            )

            # Now, time to create the symbolic link
            lastInput += 1

            prettyLocal = cast(AbsPath, os.path.join(inputDestDir, matContent.prettyFilename))

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
                prettyLocal = cast(AbsPath, os.path.join(inputDestDir,
                                           str(lastInput) + '_' + matContent.prettyFilename))

            if not os.path.exists(prettyLocal):
                # We are either hardlinking or copying here
                link_or_copy(matContent.local, prettyLocal)

            if globExplode is not None:
                prettyLocalPath = pathlib.Path(prettyLocal)
                matParse = parse.urlparse(matContent.licensed_uri.uri)
                for exp in prettyLocalPath.glob(globExplode):
                    relPath = exp.relative_to(prettyLocalPath)
                    relName = cast(RelPath, str(relPath))
                    relExpPath = matParse.path
                    if relExpPath[-1] != '/':
                        relExpPath += '/'
                    relExpPath += '/'.join(map(lambda part: parse.quote_plus(part), relPath.parts))
                    expUri = parse.urlunparse((matParse.scheme, matParse.netloc, relExpPath, matParse.params, matParse.query, matParse.fragment))
                    
                    # TODO: enrich outputs to add licensing features?
                    lic_expUri = LicensedURI(
                        uri=cast(URIType, expUri),
                        licences=matContent.licensed_uri.licences
                    )
                    remote_pairs.append(
                        MaterializedContent(
                            local=cast(AbsPath, str(exp)),
                            licensed_uri=lic_expUri,
                            prettyFilename=relName,
                            metadata_array=matContent.metadata_array,
                            kind=ContentKind.Directory if exp.is_dir() else ContentKind.File
                        )
                    )
            else:
                remote_pairs.append(
                    MaterializedContent(
                        local=prettyLocal,
                        licensed_uri=matContent.licensed_uri,
                        prettyFilename=matContent.prettyFilename,
                        kind=matContent.kind,
                        metadata_array=matContent.metadata_array
                    )
                )
        
        return remote_pairs, lastInput
    
    def fetchInputs(self, params: Union[Mapping, Sequence], workflowInputs_destdir: AbsPath,
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
        assert self.outputsDir is not None, "Working directory should not be corrupted beyond basic usage"
        
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
                            inputDestDir = cast(AbsPath, os.path.join(inputDestDir, *linearKey.split('.')))
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

                        remote_files = inputs.get('url')
                        # It has to exist
                        if remote_files is not None:
                            # We are sending the context name thinking in the future,
                            # as it could contain potential hints for authenticated access
                            contextName = inputs.get('security-context')
                            
                            secondary_remote_files = inputs.get('secondary-urls')
                            
                            cacheable = not self.paranoidMode if inputs.get('cache', True) else False

                            # The storage dir depends on whether it can be cached or not
                            storeDir : Union[CacheType, AbsPath] = CacheType.Input if cacheable else workflowInputs_destdir
                            
                            if not isinstance(remote_files, list):  # more than one input file
                                remote_files = [ remote_files ]
                            remote_pairs, lastInput = self._fetchRemoteFiles(remote_files, contextName, offline, storeDir, cacheable, inputDestDir, globExplode, lastInput)
                            
                            if secondary_remote_files is not None:
                                secondary_remote_files = [ secondary_remote_files ]
                                secondary_remote_pairs, lastInput = self._fetchRemoteFiles(secondary_remote_files, contextName, offline, storeDir, cacheable, inputDestDir, globExplode, lastInput)
                            else:
                                secondary_remote_pairs = None
                            
                            theInputs.append(
                                MaterializedInput(
                                    name=linearKey,
                                    values=remote_pairs,
                                    secondaryInputs=secondary_remote_pairs
                                )
                            )
                        else:
                            if inputClass == 'File':
                                # Empty input, i.e. empty file
                                inputDestPath = cast(AbsPath, os.path.join(inputDestDir, *linearKey.split('.')))
                                os.makedirs(os.path.dirname(inputDestPath), exist_ok=True)
                                # Creating the empty file
                                with open(inputDestPath, mode="wb") as idH:
                                    pass
                                contentKind = ContentKind.File
                            else:
                                inputDestPath = inputDestDir
                                contentKind = ContentKind.Directory
                            
                            theInputs.append(
                                MaterializedInput(
                                    name=linearKey,
                                    values=[
                                        MaterializedContent(
                                            local=cast(AbsPath, inputDestPath),
                                            licensed_uri=LicensedURI(uri=cast(URIType, "data:,")),
                                            prettyFilename=cast(RelPath, os.path.basename(inputDestPath)),
                                            kind=contentKind
                                        )
                                    ],
                                )
                            )
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

    def stageWorkDir(self) -> StagedSetup:
        """
        This method is here to simplify the understanding of the needed steps
        """
        self.fetchWorkflow()
        self.setupEngine()
        self.materializeWorkflow()
        self.materializeInputs()
        self.marshallStage()

        return self.getStagedSetup()

    def workdirToBagit(self):
        """
        BEWARE: This is a destructive step! So, once run, there is no back!
        """
        return bagit.make_bag(self.workDir)

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
                kind=self.OutputClassMapping.get(outputDesc.get('c-l-a-s-s'), ContentKind.File),
                preferredFilename=outputDesc.get('preferredName'),
                cardinality=cardinality,
                fillFrom=fillFrom,
                glob=patS,
            )
            expectedOutputs.append(eOutput)

        return expectedOutputs

    def executeWorkflow(self, offline: bool = False):
        self.unmarshallStage(offline=offline)
        
        assert self.materializedEngine is not None
        assert self.materializedParams is not None
        assert self.outputs is not None
        
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


    def marshallConfig(self, overwrite: bool = False) -> Union[bool, datetime.datetime]:
        assert self.metaDir is not None, "Working directory should not be corrupted beyond basic usage"
        # The seed should have be already written
        
        # Now, the config itself
        if overwrite or (self.configMarshalled is None):
            workflow_meta_filename = os.path.join(self.metaDir, WORKDIR_WORKFLOW_META_FILE)
            if overwrite or not os.path.exists(workflow_meta_filename) or os.path.getsize(workflow_meta_filename) == 0:
                with open(workflow_meta_filename, mode='w', encoding='utf-8') as wmF:
                    workflow_meta = {
                        'workflow_id': self.id,
                        'paranoid_mode': self.paranoidMode
                    }
                    if self.nickname is not None:
                        workflow_meta['nickname'] = self.nickname
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
            
            # This has been commented-out, as credentials should NEVER be kept!!!
            #
            # creds_file = os.path.join(self.metaDir, WORKDIR_SECURITY_CONTEXT_FILE)
            # if overwrite or not os.path.exists(creds_file):
            #     with open(creds_file, mode='w', encoding='utf-8') as crF:
            #         yaml.dump(marshall_namedtuple(self.creds_config), crF, Dumper=YAMLDumper)
            
            self.configMarshalled = datetime.datetime.fromtimestamp(os.path.getctime(workflow_meta_filename), tz=datetime.timezone.utc)
        
        return self.configMarshalled
    
    def unmarshallConfig(self, fail_ok: bool = False) -> Optional[Union[bool, datetime.datetime]]:
        assert self.metaDir is not None, "Working directory should not be corrupted beyond basic usage"
        
        if self.configMarshalled is None:
            config_unmarshalled = True
            workflow_meta_filename = os.path.join(self.metaDir, WORKDIR_WORKFLOW_META_FILE)
            # If the file does not exist, fail fast
            if not os.path.isfile(workflow_meta_filename):
                self.logger.debug(f'Marshalled config file {workflow_meta_filename} does not exist')
                return False
            
            workflow_meta = None
            try:
                with open(workflow_meta_filename, mode="r", encoding="utf-8") as wcf:
                    workflow_meta = unmarshall_namedtuple(yaml.load(wcf, Loader=YAMLLoader))
                    
                    # If the file decodes to None, fail fast
                    if workflow_meta is None:
                        self.logger.error(f'Marshalled config file {workflow_meta_filename} is empty')
                        return False
                    
                    # Fixes
                    if ('workflow_type' in workflow_meta) and workflow_meta['workflow_type'] is None:
                        del workflow_meta['workflow_type']
                    
                    self.id = workflow_meta['workflow_id']
                    self.paranoidMode = workflow_meta['paranoid_mode']
                    self.nickname = workflow_meta.get('nickname', self.instanceId)
                    self.version_id = workflow_meta.get('version')
                    self.descriptor_type = workflow_meta.get('workflow_type')
                    self.trs_endpoint = workflow_meta.get('trs_endpoint')
                    self.workflow_config = workflow_meta.get('workflow_config')
                    self.params = workflow_meta.get('params')
                    outputsM = workflow_meta.get('outputs')
                    if isinstance(outputsM, dict):
                        outputs = list(outputsM.values())
                        if len(outputs) == 0 or isinstance(outputs[0], ExpectedOutput):
                            self.outputs = outputs
                        else:
                            self.outputs = self.parseExpectedOutputs(outputsM)
                    else:
                        self.outputs = None
            except IOError as ioe:
                config_unmarshalled = False
                self.logger.debug("Marshalled config file {} I/O errors".format(workflow_meta_filename))
                if not fail_ok:
                    raise WFException("ERROR opening/reading config file") from ioe
            except TypeError as te:
                config_unmarshalled = False
                self.logger.debug("Marshalled config file {} unmarshalling errors".format(workflow_meta_filename))
                if not fail_ok:
                    raise WFException("ERROR unmarshalling config file") from te
            except Exception as e:
                config_unmarshalled = False
                self.logger.debug("Marshalled config file {} misc errors".format(workflow_meta_filename))
                if not fail_ok:
                    raise WFException("ERROR processing config file") from e
            
            if workflow_meta is not None:
                valErrors = config_validate(workflow_meta, self.STAGE_DEFINITION_SCHEMA)
                if len(valErrors) > 0:
                    config_unmarshalled = False
                    errstr = f'ERROR in workflow staging definition block {workflow_meta_filename}: {valErrors}'
                    self.logger.error(errstr)
                    if not fail_ok:
                        raise WFException(errstr)

                # This has been commented-out, as credentials should NEVER be kept!!!
                #
                # creds_file = os.path.join(self.metaDir, WORKDIR_SECURITY_CONTEXT_FILE)
                # if os.path.exists(creds_file):
                #     with open(creds_file, mode="r", encoding="utf-8") as scf:
                #         self.creds_config = unmarshall_namedtuple(yaml.load(scf, Loader=YAMLLoader))
                # else:
                #     self.creds_config = {}
                # 
                # valErrors = config_validate(self.creds_config, self.SECURITY_CONTEXT_SCHEMA)
                # if len(valErrors) > 0:
                #     config_unmarshalled = False
                #     errstr = f'ERROR in security context block {creds_file}: {valErrors}'
                #     self.logger.error(errstr)
                #     if not fail_ok:
                #         raise WFException(errstr)
                self.creds_config = dict()
                    
                self.configMarshalled = datetime.datetime.fromtimestamp(os.path.getctime(workflow_meta_filename), tz=datetime.timezone.utc)
        
        return self.configMarshalled
    
    def marshallStage(self, exist_ok: bool = True, overwrite: bool = False) -> Optional[Union[bool, datetime.datetime]]:
        if overwrite or (self.stageMarshalled is None):
            # Do not even try
            if self.marshallConfig(overwrite=overwrite) is None:
                return None
            
            assert self.metaDir is not None, "The metadata directory should be available"
            
            marshalled_stage_file = os.path.join(self.metaDir, WORKDIR_MARSHALLED_STAGE_FILE)
            stageAlreadyMarshalled = False
            if os.path.exists(marshalled_stage_file):
                errmsg = "Marshalled stage file {} already exists".format(marshalled_stage_file)
                if not overwrite and not exist_ok:
                    raise WFException(errmsg)
                self.logger.debug(errmsg)
                stageAlreadyMarshalled = True

            if not stageAlreadyMarshalled or overwrite:
                assert self.materializedEngine is not None, "The engine should have already been materialized at this point"
                stage = {
                    'repoURL': self.repoURL,
                    'repoTag': self.repoTag,
                    'repoRelPath': self.repoRelPath,
                    'repoEffectiveCheckout': self.repoEffectiveCheckout,
                    'engineDesc': self.engineDesc,
                    'engineVer': self.engineVer,
                    'materializedEngine': self.materializedEngine,
                    'containers': self.materializedEngine.containers,
                    'materializedParams': self.materializedParams
                    # TODO: check nothing essential was left
                }

                self.logger.debug("Creating marshalled stage file {}".format(marshalled_stage_file))
                with open(marshalled_stage_file, mode='w', encoding='utf-8') as msF:
                    marshalled_stage = marshall_namedtuple(stage)
                    yaml.dump(marshalled_stage, msF, Dumper=YAMLDumper)

            self.stageMarshalled = datetime.datetime.fromtimestamp(os.path.getctime(marshalled_stage_file), tz=datetime.timezone.utc)
        elif not exist_ok:
            raise WFException(f"Marshalled stage file already exists")
        
        return self.stageMarshalled

    def unmarshallStage(self, offline: bool = False, fail_ok: bool = False) -> Optional[Union[bool, datetime.datetime]]:
        if self.stageMarshalled is None:
            # If basic state does not work, even do not try
            retval = self.unmarshallConfig(fail_ok=fail_ok)
            if not retval:
                return None
            
            assert self.metaDir is not None, "The metadata directory should be available"
            
            marshalled_stage_file = os.path.join(self.metaDir, WORKDIR_MARSHALLED_STAGE_FILE)
            if not os.path.exists(marshalled_stage_file):
                errmsg = f'Marshalled stage file {marshalled_stage_file} does not exists. Stage state was not stored'
                self.logger.debug(errmsg)
                self.stageMarshalled = False
                if fail_ok:
                    return self.stageMarshalled
                raise WFException(errmsg)

            self.logger.debug("Parsing marshalled stage state file {}".format(marshalled_stage_file))
            try:
                with open(marshalled_stage_file, mode='r', encoding='utf-8') as msF:
                    marshalled_stage = yaml.load(msF, Loader=YAMLLoader)
                    stage = unmarshall_namedtuple(marshalled_stage, globals())
                    self.repoURL = stage['repoURL']
                    self.repoTag = stage['repoTag']
                    self.repoRelPath = stage['repoRelPath']
                    self.repoEffectiveCheckout = stage['repoEffectiveCheckout']
                    self.engineDesc = stage['engineDesc']
                    self.engineVer = stage['engineVer']
                    self.materializedEngine = stage['materializedEngine']
                    self.materializedParams = stage['materializedParams']

                    # This is needed to properly set up the materializedEngine
                    self.setupEngine(offline=True)
            except Exception as e:
                errmsg = "Error while unmarshalling content from stage state file {}. Reason: {}".format(marshalled_stage_file,e)
                self.logger.debug(errmsg)
                self.stageMarshalled = False
                if fail_ok:
                    return self.stageMarshalled
                raise WFException(errmsg) from e

            self.stageMarshalled = datetime.datetime.fromtimestamp(os.path.getctime(marshalled_stage_file), tz=datetime.timezone.utc)
        
        return self.stageMarshalled

    def marshallExecute(self, exist_ok: bool = True, overwrite: bool = False) -> Optional[Union[bool, datetime.datetime]]:
        if overwrite or (self.executionMarshalled is None):
            if self.marshallStage(exist_ok=exist_ok, overwrite=overwrite) is None:
                return None

            assert self.metaDir is not None, "The metadata directory should be available"
            
            marshalled_execution_file = os.path.join(self.metaDir, WORKDIR_MARSHALLED_EXECUTE_FILE)
            executionAlreadyMarshalled = False
            if os.path.exists(marshalled_execution_file):
                errmsg = "Marshalled execution file {} already exists".format(marshalled_execution_file)
                if not overwrite and not exist_ok:
                    raise WFException(errmsg)
                self.logger.debug(errmsg)
                executionAlreadyMarshalled = True
            
            if not executionAlreadyMarshalled or overwrite:
                execution = {
                    'exitVal': self.exitVal,
                    'augmentedInputs': self.augmentedInputs,
                    'matCheckOutputs': self.matCheckOutputs
                    # TODO: check nothing essential was left
                }

                self.logger.debug("Creating marshalled execution file {}".format(marshalled_execution_file))
                with open(marshalled_execution_file, mode='w', encoding='utf-8') as msF:
                    yaml.dump(marshall_namedtuple(execution), msF, Dumper=YAMLDumper)

            self.executionMarshalled = datetime.datetime.fromtimestamp(os.path.getctime(marshalled_execution_file), tz=datetime.timezone.utc)
        elif not exist_ok:
            raise WFException("Marshalled execution file already exists")
        
        return self.executionMarshalled

    def unmarshallExecute(self, offline: bool = True, fail_ok: bool = False) -> Optional[Union[bool, datetime.datetime]]:
        if self.executionMarshalled is None:
            # If stage state is not properly prepared, even do not try
            retval = self.unmarshallStage(offline=offline, fail_ok=fail_ok)
            if not retval:
                return None

            assert self.metaDir is not None, "The metadata directory should be available"
            
            marshalled_execution_file = os.path.join(self.metaDir, WORKDIR_MARSHALLED_EXECUTE_FILE)
            if not os.path.exists(marshalled_execution_file):
                errmsg = f"Marshalled execution file {marshalled_execution_file} does not exists. Execution state was not stored"
                self.logger.debug(errmsg)
                self.executionMarshalled = False
                if fail_ok:
                    return self.executionMarshalled
                raise WFException(errmsg)

            self.logger.debug("Parsing marshalled execution state file {}".format(marshalled_execution_file))
            try:
                with open(marshalled_execution_file, mode='r', encoding='utf-8') as meF:
                    marshalled_execution = yaml.load(meF, Loader=YAMLLoader)
                    execution = unmarshall_namedtuple(marshalled_execution, globals())

                    self.exitVal = execution['exitVal']
                    self.augmentedInputs = execution['augmentedInputs']
                    self.matCheckOutputs = execution['matCheckOutputs']
            except Exception as e:
                errmsg = "Error while unmarshalling content from execution state file {}. Reason: {}".format(marshalled_execution_file, e)
                self.logger.debug(errmsg)
                self.executionMarshalled = False
                if fail_ok:
                    return self.executionMarshalled
                raise WFException(errmsg) from e

            self.executionMarshalled = datetime.datetime.fromtimestamp(os.path.getctime(marshalled_execution_file), tz=datetime.timezone.utc)
        
        return self.executionMarshalled

    def marshallExport(self, exist_ok: bool = True, overwrite: bool = False) -> Optional[Union[bool, datetime.datetime]]:
        if overwrite or (self.exportMarshalled is None):
            # Do not even try saving the state
            if self.marshallExecute(exist_ok=exist_ok, overwrite=overwrite) is None:
                return None

            assert self.metaDir is not None, "The metadata directory should be available"

            marshalled_export_file = os.path.join(self.metaDir, WORKDIR_MARSHALLED_EXPORT_FILE)
            exportAlreadyMarshalled = False
            if os.path.exists(marshalled_export_file):
                errmsg = "Marshalled export results file {} already exists".format(marshalled_export_file)
                if not overwrite and not exist_ok:
                    raise WFException(errmsg)
                self.logger.debug(errmsg)
                exportAlreadyMarshalled = True
            
            if not exportAlreadyMarshalled or overwrite:
                exported_results : Mapping[str, Any] = {
                    # TODO
                }

                self.logger.debug("Creating marshalled export results file {}".format(marshalled_export_file))
                with open(marshalled_export_file, mode='w', encoding='utf-8') as msF:
                    yaml.dump(marshall_namedtuple(exported_results), msF, Dumper=YAMLDumper)

            self.exportMarshalled = datetime.datetime.fromtimestamp(os.path.getctime(marshalled_export_file), tz=datetime.timezone.utc)
        elif not exist_ok:
            raise WFException("Marshalled export results file already exists")
        
        return self.exportMarshalled

    def unmarshallExport(self, offline: bool = True, fail_ok: bool = False) -> Optional[Union[bool, datetime.datetime]]:
        if self.exportMarshalled is None:
            # If execute state does not work, even do not try
            retval = self.unmarshallExecute(offline=offline, fail_ok=fail_ok)
            if not retval:
                return None

            assert self.metaDir is not None, "The metadata directory should be available"
            
            marshalled_export_file = os.path.join(self.metaDir, WORKDIR_MARSHALLED_EXPORT_FILE)
            if not os.path.exists(marshalled_export_file):
                errmsg = f"Marshalled export results file {marshalled_export_file} does not exists. Export results state was not stored"
                self.logger.debug(errmsg)
                self.exportMarshalled = False
                if fail_ok:
                    return self.exportMarshalled
                raise WFException(errmsg)

            self.logger.debug("Parsing marshalled export results state file {}".format(marshalled_export_file))
            try:
                with open(marshalled_export_file, mode='r', encoding='utf-8') as meF:
                    marshalled_export = yaml.load(meF, Loader=YAMLLoader)
                    exported_results = unmarshall_namedtuple(marshalled_export, globals())

                    # TODO
            except Exception as e:
                errmsg = f"Error while unmarshalling content from export results state file {marshalled_export_file}. Reason: {e}"
                self.logger.debug(e)
                self.exportMarshalled = False
                if fail_ok:
                    return self.exportMarshalled
                raise WFException(errmsg) from e

            self.exportMarshalled = datetime.datetime.fromtimestamp(os.path.getctime(marshalled_export_file), tz=datetime.timezone.utc)
        
        return self.exportMarshalled

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
        
        assert self.localWorkflow is not None
        assert self.materializedEngine is not None
        assert self.repoURL is not None
        assert self.augmentedInputs is not None
        assert self.matCheckOutputs is not None
        assert self.outputsDir is not None

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
            if self.localWorkflow.relPath is not None:
                wf_path = os.path.join(self.localWorkflow.dir, self.localWorkflow.relPath)
            else:
                wf_path = self.localWorkflow.dir
            wfCrate, compLang = self.materializedEngine.instance.getEmptyCrateAndComputerLanguage(self.localWorkflow.langVersion)
            # TODO: how to get the name of the default branch?
            repoTag = self.repoTag if self.repoTag is not None  else  "main"
            wf_url = self.repoURL.replace(".git", "/") + "tree/" + repoTag
            if self.localWorkflow.relPath is not None:
                wf_url += "/" + os.path.dirname(self.localWorkflow.relPath)

            # TODO create method to create wf_url
            matWf = self.materializedEngine.workflow
            
            assert matWf.effectiveCheckout is not None, "The effective checkout should be available"
            
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
                    matWf.effectiveCheckout
                ]
                
                if self.localWorkflow.relPath is not None:
                    wf_entrypoint_path.append(self.localWorkflow.relPath)
                
                wf_entrypoint_url = parse.urlunparse(
                    ('https', 'raw.githubusercontent.com', '/'.join(wf_entrypoint_path), '', '', ''))
            else:
                raise WFException("FIXME: Unsupported http(s) git repository {}".format(self.repoURL))

            # TODO assign something meaningful to cwl
            cwl = True

            workflow_path = pathlib.Path(wf_path)
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
        addInputsResearchObject(wfCrate, self.augmentedInputs)

        # Add outputs provenance to RO-crate
        addOutputsResearchObject(wfCrate, self.matCheckOutputs)

        # Save RO-crate as execution.crate.zip
        wfCrate.write_zip(os.path.join(self.outputsDir, "execution.crate"))
        self.logger.info("RO-Crate created: {}".format(self.outputsDir))

        # TODO error handling

    def getWorkflowRepoFromTRS(self, offline: bool = False) -> IdentifiedWorkflow:
        """

        :return:
        """
        assert self.metaDir is not None
        
        cacheHandler = self.wfexs.cacheHandler
        # Now, time to check whether it is a TRSv2
        trs_endpoint_v2_meta_url = self.trs_endpoint + 'service-info'
        trs_endpoint_v2_beta2_meta_url = self.trs_endpoint + 'metadata'
        trs_endpoint_meta_url = None

        # Needed to store this metadata
        trsMetadataCache = os.path.join(self.metaDir, self.TRS_METADATA_FILE)

        try:
            metaContentKind, cachedTRSMetaFile, trsMetaMeta, trsMetaLicences = cacheHandler.fetch(trs_endpoint_v2_meta_url, self.metaDir, offline)
            trs_endpoint_meta_url = trs_endpoint_v2_meta_url
        except WFException as wfe:
            try:
                metaContentKind, cachedTRSMetaFile, trsMetaMeta, trsMetaLicences = cacheHandler.fetch(trs_endpoint_v2_beta2_meta_url, self.metaDir, offline)
                trs_endpoint_meta_url = trs_endpoint_v2_beta2_meta_url
            except WFException as wfebeta:
                raise WFException("Unable to fetch metadata from {} in order to identify whether it is a working GA4GH TRSv2 endpoint. Exceptions:\n{}\n{}".format(self.trs_endpoint, wfe, wfebeta))

        # Giving a friendly name
        if not os.path.exists(trsMetadataCache):
            os.symlink(os.path.basename(cachedTRSMetaFile), trsMetadataCache)

        with open(trsMetadataCache, mode="r", encoding="utf-8") as ctmf:
            trs_endpoint_meta = json.load(ctmf)

        # Minimal check
        trs_version = trs_endpoint_meta.get('api_version')
        if trs_version is None:
            trs_version = trs_endpoint_meta.get('type', {}).get('version')

        if trs_version is None:
            raise WFException("Unable to identify TRS version from {}".format(trs_endpoint_meta_url))

        # Now, check the tool does exist in the TRS, and the version
        trs_tools_url = parse.urljoin(self.trs_endpoint, self.TRS_TOOLS_PATH + parse.quote(self.id, safe=''))

        trsQueryCache = os.path.join(self.metaDir, self.TRS_QUERY_CACHE_FILE)
        _, cachedTRSQueryFile, _, _ = cacheHandler.fetch(trs_tools_url, self.metaDir, offline)
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
        if trs_endpoint_meta.get('organization', {}).get('name') == 'WorkflowHub':
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
            _, trsFilesDir, trsFilesMeta, _ = self.wfexs.cacheFetch(INTERNAL_TRS_SCHEME_PREFIX + ':' + toolFilesURL, CacheType.TRS, offline)

            expectedEngineDesc = self.RECOGNIZED_TRS_DESCRIPTORS[chosenDescriptorType]
            remote_workflow_entrypoint = trsFilesMeta[0].metadata.get('remote_workflow_entrypoint')
            if remote_workflow_entrypoint is not None:
                # Give it a chance to identify the original repo of the workflow
                repo = self.wfexs.guessRepoParams(remote_workflow_entrypoint, fail_ok=True)

                if repo is not None:
                    self.logger.debug("Derived repository {} ({} , rel {}) from {}".format(repo.repo_url, repo.tag, repo.rel_path, trs_tools_url))
                    return IdentifiedWorkflow(
                        workflow_type=expectedEngineDesc,
                        remote_repo=repo
                    )

            workflow_entrypoint = trsFilesMeta[0].metadata.get('workflow_entrypoint')
            if workflow_entrypoint is not None:
                self.logger.debug("Using raw files from TRS tool {}".format(trs_tools_url))
                return IdentifiedWorkflow(
                    workflow_type=expectedEngineDesc,
                    remote_repo=RemoteRepo(
                        repo_url=cast(RepoURL, trsFilesDir),
                        rel_path=workflow_entrypoint
                    )
                )

        raise WFException("Unable to find a workflow in {}".format(trs_tools_url))

    def getWorkflowRepoFromROCrateURL(self, roCrateURL: URIType, expectedEngineDesc: WorkflowType = None, offline: bool = False) -> IdentifiedWorkflow:
        """

        :param roCrateURL:
        :param expectedEngineDesc: If defined, an instance of WorkflowType
        :return:
        """
        roCrateFile = self.wfexs.downloadROcrate(roCrateURL, offline=offline)
        self.cacheROCrateFilename = roCrateFile
        self.logger.info("downloaded RO-Crate: {} -> {}".format(roCrateURL, roCrateFile))

        return self.getWorkflowRepoFromROCrateFile(roCrateFile, expectedEngineDesc)

    def getWorkflowRepoFromROCrateFile(self, roCrateFile: AbsPath, expectedEngineDesc: Optional[WorkflowType] = None) -> IdentifiedWorkflow:
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

        engineDesc : WorkflowType
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
        remote_repo : Optional[RemoteRepo] = None
        if workflowUploadURL is not None:
            remote_repo = self.wfexs.guessRepoParams(workflowUploadURL, fail_ok=True)

        if remote_repo is None:
            remote_repo = self.wfexs.guessRepoParams(roCrateObj.root_dataset['isBasedOn'], fail_ok=True)

        if remote_repo is None:
            raise WFException('Unable to guess repository from RO-Crate manifest')

        # It must return four elements:
        return IdentifiedWorkflow(
            workflow_type=engineDesc,
            remote_repo=remote_repo
        )

