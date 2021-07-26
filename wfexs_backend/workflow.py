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

import atexit
import http
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
from typing import List, Pattern, Tuple, Union
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
import crypt4gh.keys

from .common import *
from .encrypted_fs import *
from .engine import WorkflowEngine, WorkflowEngineException
from .engine import WORKDIR_WORKFLOW_META_FILE, WORKDIR_SECURITY_CONTEXT_FILE, WORKDIR_PASSPHRASE_FILE
from .engine import WORKDIR_MARSHALLED_STAGE_FILE, WORKDIR_MARSHALLED_EXECUTE_FILE, WORKDIR_MARSHALLED_EXPORT_FILE
from .engine import WORKDIR_INPUTS_RELDIR, WORKDIR_INTERMEDIATE_RELDIR, WORKDIR_META_RELDIR, WORKDIR_OUTPUTS_RELDIR, \
    WORKDIR_ENGINE_TWEAKS_RELDIR
from .cache_handler import SchemeHandlerCacheHandler

from .utils.marshalling_handling import marshall_namedtuple, unmarshall_namedtuple

from .fetchers import DEFAULT_SCHEME_HANDLERS
from .fetchers.pride import SCHEME_HANDLERS as PRIDE_SCHEME_HANDLERS
from .fetchers.trs_files import INTERNAL_TRS_SCHEME_PREFIX, SCHEME_HANDLERS as INTERNAL_TRS_SCHEME_HANDLERS

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

    DEFAULT_RO_EXTENSION = ".crate.zip"
    DEFAULT_TRS_ENDPOINT = "https://dev.workflowhub.eu/ga4gh/trs/v2/"  # root of GA4GH TRS API
    TRS_TOOLS_PATH = 'tools/'
    WORKFLOW_ENGINES = list(map(lambda clazz: clazz.WorkflowType(), WORKFLOW_ENGINE_CLASSES))

    RECOGNIZED_TRS_DESCRIPTORS = dict(map(lambda t: (t.trs_descriptor, t), WORKFLOW_ENGINES))
    
    @classmethod
    def generate_passphrase(cls) -> str:
        import random
        from pwgen_passphrase.__main__ import generate_passphrase, list_wordlists, read_wordlist

        wordlists_filenames = list_wordlists()
        wordlists_tags = [*wordlists_filenames.keys()]
        wordlist_filename = wordlists_filenames[wordlists_tags[random.randrange(len(wordlists_tags))]]

        wordlist = read_wordlist(wordlist_filename).splitlines()

        return generate_passphrase(wordlist, cls.DEFAULT_PASSPHRASE_LENGTH)

    @classmethod
    def bootstrap(cls, local_config, config_directory=None, key_prefix=None):
        """
        :param local_config: Relevant local configuration, like the cache directory.
        :param config_directory: The filename to be used to resolve relative paths
        :param key_prefix:
        :type local_config: dict
        """

        import datetime
        import socket

        logger = logging.getLogger(cls.__name__)

        updated = False

        # Getting the config directory
        if config_directory is None:
            config_directory = os.getcwd()
        if not os.path.isabs(config_directory):
            config_directory = os.path.abspath(config_directory)

        if key_prefix is None:
            key_prefix = ''

        # This one is to assure the working directory is created
        workDir = local_config.get('workDir')
        if workDir:
            if not os.path.isabs(workDir):
                workDir = os.path.normpath(os.path.join(config_directory, workDir))
            os.makedirs(workDir, exist_ok=True)

        # Now, checking whether public and private key pairs exist
        numExist = 0
        for elem in (cls.CRYPT4GH_PRIVKEY_KEY, cls.CRYPT4GH_PUBKEY_KEY):
            fname = local_config.get(cls.CRYPT4GH_SECTION, {}).get(elem)
            # The default when no filename exist is creating hidden files in the config directory
            if fname is None:
                fname = key_prefix + '.' + elem
                local_config.setdefault(cls.CRYPT4GH_SECTION, {})[elem] = fname
                updated = True

            if not os.path.isabs(fname):
                fname = os.path.normpath(os.path.join(config_directory, fname))

            if os.path.exists(fname):
                if os.path.getsize(fname) == 0:
                    logger.warning("[WARNING] Installation {} file {} is empty".format(elem, fname))
                else:
                    numExist += 1
            else:
                logger.warning("[WARNING] Installation {} file {} does not exist".format(elem, fname))

        if numExist == 1:
            raise WFException("Inconsistent {} section, as one of the keys is missing".format(cls.CRYPT4GH_SECTION))

        # Time to generate the pairs needed to work with crypt4gh
        if numExist == 0:
            privKey = local_config[cls.CRYPT4GH_SECTION][cls.CRYPT4GH_PRIVKEY_KEY]
            if not os.path.isabs(privKey):
                privKey = os.path.normpath(os.path.join(config_directory, privKey))
            pubKey = local_config[cls.CRYPT4GH_SECTION][cls.CRYPT4GH_PUBKEY_KEY]
            if not os.path.isabs(pubKey):
                pubKey = os.path.normpath(os.path.join(config_directory, pubKey))

            if cls.CRYPT4GH_PASSPHRASE_KEY not in local_config[cls.CRYPT4GH_SECTION]:
                passphrase = cls.generate_passphrase()
                local_config[cls.CRYPT4GH_SECTION][cls.CRYPT4GH_PASSPHRASE_KEY] = passphrase
                updated = True
            else:
                passphrase = local_config[cls.CRYPT4GH_SECTION][cls.CRYPT4GH_PASSPHRASE_KEY]

            comment = 'WfExS crypt4gh keys {} {} {}'.format(socket.gethostname(), config_directory,
                                                            datetime.datetime.now().isoformat())
            crypt4gh.keys.c4gh.generate(privKey, pubKey, passphrase=passphrase.encode('utf-8'),
                                        comment=comment.encode('utf-8'))

        return updated, local_config

    @classmethod
    def FromDescription(cls, workflow_meta, local_config, creds_config=None, config_directory=None):
        """

        :param workflow_meta: The configuration describing both the workflow
        and the inputs to use when it is being instantiated.
        :param local_config: Relevant local configuration, like the cache directory.
        :param creds_config: Dictionary with the different credential contexts (to be implemented)
        :param config_directory:
        :type workflow_meta: dict
        :type local_config: dict
        :type creds_config: dict
        :type config_directory:
        :return: Workflow configuration
        """
        if creds_config is None:
            creds_config = {}

        _, updated_local_config = cls.bootstrap(local_config, config_directory=config_directory)

        return cls(
            local_config,
            config_directory=config_directory
        ).newSetup(
            workflow_meta['workflow_id'],
            workflow_meta.get('version'),
            descriptor_type=workflow_meta.get('workflow_type'),
            trs_endpoint=workflow_meta.get('trs_endpoint', cls.DEFAULT_TRS_ENDPOINT),
            params=workflow_meta.get('params', {}),
            outputs=workflow_meta.get('outputs', {}),
            workflow_config=workflow_meta.get('workflow_config'),
            creds_config=creds_config
        )
    
    @classmethod
    def ConfigValidate(cls, configToValidate, relSchemaFile):
        # Locating the schemas directory, where all the schemas should be placed
        schemaFile = os.path.join(os.path.dirname(__file__), cls.SCHEMAS_REL_DIR, relSchemaFile)
        
        try:
            with open(schemaFile, mode="r", encoding="utf-8") as sF:
                schema = json.load(sF)
            
            jv = jsonschema.validators.validator_for(schema)(schema)
            return list(jv.iter_errors(instance=configToValidate))
        except Exception as e:
            raise WFException(f"FATAL ERROR: corrupted schema {relSchemaFile}. Reason: {e}")
    
    def __init__(self, local_config=None, config_directory=None):
        """
        Init function

        :param local_config: Local setup configuration, telling where caching directories live
        :type local_config: dict
        """
        # Getting a logger focused on specific classes
        self.logger = logging.getLogger(self.__class__.__name__)

        if not isinstance(local_config, dict):
            local_config = {}
        
        # TODO: validate the local configuration object
        valErrors = self.ConfigValidate(local_config, self.CONFIG_SCHEMA)
        if len(valErrors) > 0:
            self.logger.error(f'ERROR in local configuration block: {valErrors}')
            sys.exit(1)
        
        self.local_config = local_config

        toolSect = local_config.get('tools', {})
        self.git_cmd = toolSect.get('gitCommand', DEFAULT_GIT_CMD)

        encfsSect = toolSect.get('encrypted_fs', {})
        encfs_type = encfsSect.get('type', DEFAULT_ENCRYPTED_FS_TYPE)
        try:
            encfs_type = EncryptedFSType(encfs_type)
        except:
            raise WFException('Invalid default encryption filesystem {}'.format(encfs_type))
        if encfs_type not in ENCRYPTED_FS_MOUNT_IMPLEMENTATIONS:
            raise WFException('FIXME: Default encryption filesystem {} mount procedure is not implemented')
        self.encfs_type = encfs_type

        self.encfs_cmd = shutil.which(encfsSect.get('command', DEFAULT_ENCRYPTED_FS_CMD[self.encfs_type]))
        self.fusermount_cmd = encfsSect.get('fusermount_command', DEFAULT_FUSERMOUNT_CMD)
        self.encfs_idleMinutes = encfsSect.get('idle', DEFAULT_ENCRYPTED_FS_IDLE_TIMEOUT)

        # Getting the config directory, needed for relative filenames
        if config_directory is None:
            config_directory = os.getcwd()
        if not os.path.isabs(config_directory):
            config_directory = os.path.abspath(config_directory)

        self.config_directory = config_directory

        # Getting the private and public keys, needed from this point
        crypt4ghSect = local_config.get(self.CRYPT4GH_SECTION, {})
        privKeyFilename = crypt4ghSect[self.CRYPT4GH_PRIVKEY_KEY]
        if not os.path.isabs(privKeyFilename):
            privKeyFilename = os.path.normpath(os.path.join(config_directory, privKeyFilename))
        pubKeyFilename = crypt4ghSect[self.CRYPT4GH_PUBKEY_KEY]
        if not os.path.isabs(pubKeyFilename):
            pubKeyFilename = os.path.normpath(os.path.join(config_directory, pubKeyFilename))
        passphrase = crypt4ghSect[self.CRYPT4GH_PASSPHRASE_KEY]

        # These are the keys to be used
        self.pubKey = crypt4gh.keys.get_public_key(pubKeyFilename)
        self.privKey = crypt4gh.keys.get_private_key(privKeyFilename, lambda: passphrase)

        # This directory will be used to cache repositories and distributable inputs
        cacheDir = local_config.get('cacheDir')
        if cacheDir:
            if not os.path.isabs(cacheDir):
                cacheDir = os.path.normpath(os.path.join(config_directory, cacheDir))
            os.makedirs(cacheDir, exist_ok=True)
        else:
            cacheDir = tempfile.mkdtemp(prefix='WfExS', suffix='backend')
            # Assuring this temporal directory is removed at the end
            atexit.register(shutil.rmtree, cacheDir)

        # Setting up caching directories
        self.cacheDir = cacheDir
        self.cacheWorkflowDir = os.path.join(cacheDir, 'wf-cache')
        os.makedirs(self.cacheWorkflowDir, exist_ok=True)
        self.cacheROCrateDir = os.path.join(cacheDir, 'ro-crate-cache')
        os.makedirs(self.cacheROCrateDir, exist_ok=True)
        self.cacheTRSFilesDir = os.path.join(cacheDir, 'trs-files-cache')
        os.makedirs(self.cacheTRSFilesDir, exist_ok=True)
        self.cacheWorkflowInputsDir = os.path.join(cacheDir, 'wf-inputs')
        os.makedirs(self.cacheWorkflowInputsDir, exist_ok=True)

        # This directory will be used to store the intermediate
        # and final results before they are sent away
        workDir = local_config.get('workDir')
        if workDir:
            if not os.path.isabs(workDir):
                workDir = os.path.normpath(os.path.join(config_directory, workDir))
            os.makedirs(workDir, exist_ok=True)
        else:
            workDir = tempfile.mkdtemp(prefix='WfExS-workdir', suffix='backend')
            # Assuring this temporal directory is removed at the end
            atexit.register(shutil.rmtree, workDir)

        self.baseWorkDir = workDir
        self.rawWorkDir = None
        self.workDir = None
        self.encWorkDir = None
        self.tempDir = None
        self.encfsThread = None
        self.doUnmount = False
        self.paranoidMode = False
        self.bag = None
        
        self.stageMarshalled = False
        self.executionMarshalled = False
        self.exportMarshalled = False

        # cacheHandler is created on first use
        self.cacheHandler = SchemeHandlerCacheHandler(self.cacheDir, {})
        
        # All the custom ones should be added here
        self.cacheHandler.addSchemeHandlers(PRIDE_SCHEME_HANDLERS)
        self.cacheHandler.addSchemeHandlers(INTERNAL_TRS_SCHEME_HANDLERS)
        
        # These ones should have prevalence over other custom ones
        self.cacheHandler.addSchemeHandlers(DEFAULT_SCHEME_HANDLERS)

    def newSetup(self,
                 workflow_id,
                 version_id,
                 descriptor_type=None,
                 trs_endpoint=DEFAULT_TRS_ENDPOINT,
                 params=None,
                 outputs=None,
                 workflow_config=None,
                 creds_config=None
                 ):
        """
        Init function

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
        :param creds_config: Dictionary with the different credential contexts (to be implemented)
        :type workflow_id: str
        :type version_id: str
        :type descriptor_type: str
        :type trs_endpoint: str
        :type params: dict
        :type outputs: dict
        :type workflow_config: dict
        :type creds_config: dict
        """
        if not isinstance(workflow_config, dict):
            workflow_config = {}

        if not isinstance(creds_config, dict):
            creds_config = {}

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

        if self.rawWorkDir is None:
            self.instanceId = str(uuid.uuid4())
            # This directory is the raw working directory
            # If the intermediate results should be hold in an encrypted
            # temporary directory, this directory will hold it
            uniqueRawWorkDir = os.path.join(self.baseWorkDir, self.instanceId)
            os.makedirs(uniqueRawWorkDir, exist_ok=True)
            self.rawWorkDir = uniqueRawWorkDir

        self.secure = workflow_config.get('secure', True)
        if self.workDir is None:
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
        os.makedirs(self.metaDir, exist_ok=True)
        
        self.marshallConfig(overwrite=False)
        
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

        return self

    def setupWorkdir(self, doSecureWorkDir):
        uniqueRawWorkDir = self.rawWorkDir

        if doSecureWorkDir:
            uniqueEncWorkDir = os.path.join(uniqueRawWorkDir, '.crypt')
            uniqueWorkDir = os.path.join(uniqueRawWorkDir, 'work')

            # The directories should exist before calling encryption FS mount
            os.makedirs(uniqueEncWorkDir, exist_ok=True)
            os.makedirs(uniqueWorkDir, exist_ok=True)

            # This is the passphrase needed to decrypt the filesystem
            passphraseFile = os.path.join(uniqueRawWorkDir, WORKDIR_PASSPHRASE_FILE)
            encfs_cmd = self.encfs_cmd
            if os.path.exists(passphraseFile):
                clearF = io.BytesIO()
                with open(passphraseFile, mode="rb") as encF:
                    crypt4gh.lib.decrypt(
                        [(0, self.privKey, None)],
                        encF,
                        clearF,
                        offset=0,
                        span=None,
                        sender_pubkey=None
                    )

                encfs_type, _, securePassphrase = clearF.getvalue().decode('utf-8').partition('=')
                self.logger.debug(encfs_type + ' ' + securePassphrase)
                try:
                    encfs_type = EncryptedFSType(encfs_type)
                except:
                    raise WFException('Invalid encryption filesystem {} in working directory'.format(encfs_type))
                if encfs_type not in ENCRYPTED_FS_MOUNT_IMPLEMENTATIONS:
                    raise WFException('FIXME: Encryption filesystem {} mount procedure is not implemented')

                # If the working directory encrypted filesystem does not
                # match the configured one, use its default executable
                if encfs_type != self.encfs_type:
                    encfs_cmd = DEFAULT_ENCRYPTED_FS_CMD[encfs_type]

                if securePassphrase == '':
                    raise WFException('Encryption filesystem key does not follow the right format')
            else:
                securePassphrase = self.generate_passphrase()
                encfs_type = self.encfs_type
                clearF = io.BytesIO((encfs_type.value + '=' + securePassphrase).encode('utf-8'))
                with open(passphraseFile, mode="wb") as encF:
                    crypt4gh.lib.encrypt(
                        [(0, self.privKey, self.pubKey)],
                        clearF,
                        encF,
                        offset=0,
                        span=None
                    )
            del clearF

            # Warn/fail earlier
            if os.path.ismount(uniqueWorkDir):
                # raise WFException("Destination mount point {} is already in use")
                self.logger.warning("Destination mount point {} is already in use".format(uniqueWorkDir))
            else:
                # Now, time to mount the encrypted FS
                ENCRYPTED_FS_MOUNT_IMPLEMENTATIONS[encfs_type](encfs_cmd, self.encfs_idleMinutes, uniqueEncWorkDir,
                                                               uniqueWorkDir, uniqueRawWorkDir, securePassphrase)

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

    def fromWorkDir(self, workflowWorkingDirectory):
        if workflowWorkingDirectory is None:
            raise WFException('Unable to initialize, no directory provided')

        # Obtaining the absolute path to the working directory
        if not os.path.isabs(workflowWorkingDirectory):
            workflowWorkingDirectory = os.path.normpath(os.path.join(self.baseWorkDir, workflowWorkingDirectory))

        if not os.path.isdir(workflowWorkingDirectory):
            raise WFException('Unable to initialize, {} is not a directory'.format(workflowWorkingDirectory))

        self.rawWorkDir = workflowWorkingDirectory
        self.instanceId = os.path.basename(workflowWorkingDirectory)

        # This is needed to parse
        passphraseFile = os.path.join(self.rawWorkDir, WORKDIR_PASSPHRASE_FILE)

        # Setting up the directory
        self.setupWorkdir(os.path.exists(passphraseFile))

        metaDir = os.path.join(self.workDir, WORKDIR_META_RELDIR)
        if not os.path.isdir(metaDir):
            raise WFException("Staged working directory {} is incomplete".format(self.workDir))

        # In order to be able to build next paths to call
        workflowMetaFilename = os.path.join(metaDir, WORKDIR_WORKFLOW_META_FILE)
        securityContextFilename = os.path.join(metaDir, WORKDIR_SECURITY_CONTEXT_FILE)

        return self.fromFiles(workflowMetaFilename, securityContextFilename)

    def enableParanoidMode(self):
        self.paranoidMode = True

    def fromFiles(self, workflowMetaFilename, securityContextsConfigFilename=None, paranoidMode=False):
        with open(workflowMetaFilename, mode="r", encoding="utf-8") as wcf:
            workflow_meta = unmarshall_namedtuple(yaml.load(wcf, Loader=YAMLLoader))

        # Last, try loading the security contexts credentials file
        if securityContextsConfigFilename and os.path.exists(securityContextsConfigFilename):
            with open(securityContextsConfigFilename, mode="r", encoding="utf-8") as scf:
                creds_config = unmarshall_namedtuple(yaml.load(scf, Loader=YAMLLoader))
        else:
            creds_config = {}

        return self.fromDescription(workflow_meta, creds_config, paranoidMode=paranoidMode)

    def fromDescription(self, workflow_meta, creds_config=None, paranoidMode=False):
        """

        :param workflow_meta: The configuration describing both the workflow
        and the inputs to use when it is being instantiated.
        :param creds_config: Dictionary with the different credential contexts (to be implemented)
        :param paranoidMode:
        :type workflow_meta: dict
        :type creds_config: dict
        :type paranoidMode:
        :return: Workflow configuration
        """
        
        # The preserved paranoid mode must be honoured
        preserved_paranoid_mode = workflow_meta.get('paranoid_mode')
        if preserved_paranoid_mode is not None:
            paranoidMode = preserved_paranoid_mode
            
        if paranoidMode:
            self.enableParanoidMode()

        return self.newSetup(
            workflow_meta['workflow_id'],
            workflow_meta.get('version'),
            descriptor_type=workflow_meta.get('workflow_type'),
            trs_endpoint=workflow_meta.get('trs_endpoint', self.DEFAULT_TRS_ENDPOINT),
            params=workflow_meta.get('params', {}),
            outputs=workflow_meta.get('outputs', {}),
            workflow_config=workflow_meta.get('workflow_config'),
            creds_config=creds_config
        )

    def fromForm(self, workflow_meta, paranoidMode=False):  # VRE
        """

        :param workflow_meta: The configuration describing both the workflow
        and the inputs to use when it is being instantiated.
        :param paranoidMode:
        :type workflow_meta: dict
        :type paranoidMode:
        :return: Workflow configuration
        """
        if paranoidMode:
            self.enableParanoidMode()

        return self.newSetup(
            workflow_meta['workflow_id'],
            workflow_meta.get('version'),
            descriptor_type=workflow_meta.get('workflow_type'),
            trs_endpoint=workflow_meta.get('trs_endpoint', self.DEFAULT_TRS_ENDPOINT),
            params=workflow_meta.get('params', {}),
            workflow_config=workflow_meta.get('workflow_config')
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
            guessedRepoURL, guessedRepoTag, guessedRepoRelPath = self.guessRepoParams(parsedRepoURL, fail_ok=False)
            
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

                repoDir, repoEffectiveCheckout = self.doMaterializeRepo(repoURL, repoTag)
        
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
                engine = engineDesc.clazz(cacheDir=self.cacheDir, workflow_config=self.workflow_config,
                                          local_config=self.local_config, engineTweaksDir=self.engineTweaksDir,
                                          cacheWorkflowDir=self.cacheWorkflowDir,
                                          cacheWorkflowInputsDir=self.cacheWorkflowInputsDir,
                                          workDir=self.workDir,
                                          outputsDir=self.outputsDir, intermediateDir=self.intermediateDir,
                                          tempDir=self.tempDir, secure_exec=self.secure or self.paranoidMode,
                                          config_directory=self.config_directory)
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
            engine = engineDesc.clazz(cacheDir=self.cacheDir, workflow_config=self.workflow_config,
                                      local_config=self.local_config, engineTweaksDir=self.engineTweaksDir,
                                      cacheWorkflowDir=self.cacheWorkflowDir,
                                      cacheWorkflowInputsDir=self.cacheWorkflowInputsDir,
                                      workDir=self.workDir,
                                      outputsDir=self.outputsDir, intermediateDir=self.intermediateDir,
                                      tempDir=self.tempDir, secure_exec=self.secure or self.paranoidMode,
                                      config_directory=self.config_directory)
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

    def addSchemeHandler(self, scheme, handler):
        """

        :param scheme:
        :param handler:
        """
        if not isinstance(handler, (
                types.FunctionType, types.LambdaType, types.MethodType, types.BuiltinFunctionType,
                types.BuiltinMethodType)):
            raise WFException('Trying to set for scheme {} a invalid handler'.format(scheme))

        self.cacheHandler.addSchemeHandlers({scheme.lower(): handler})

    def injectInputs(self, paths, workflowInputs_destdir=None, workflowInputs_cacheDir=None, lastInput=0):
        if workflowInputs_destdir is None:
            workflowInputs_destdir = self.inputsDir
        if workflowInputs_cacheDir is None:
            workflowInputs_cacheDir = self.cacheWorkflowInputsDir

        cacheable = not self.paranoidMode
        # The storage dir depends on whether it can be cached or not
        storeDir = workflowInputs_cacheDir if cacheable else workflowInputs_destdir
        for path in paths:
            # We are sending the context name thinking in the future,
            # as it could contain potential hints for authenticated access
            fileuri = parse.urlunparse(('file', '', os.path.abspath(path), '', '', ''))
            matContent = self.downloadInputFile(fileuri, workflowInputs_destdir=storeDir, ignoreCache=not cacheable, registerInCache=cacheable)

            # Now, time to create the symbolic link
            lastInput += 1

            prettyLocal = os.path.join(workflowInputs_destdir, matContent.prettyFilename)
            hardenPrettyLocal = False
            if os.path.islink(prettyLocal):
                oldLocal = os.readlink(prettyLocal)

                hardenPrettyLocal = oldLocal != matContent.local
            elif os.path.exists(prettyLocal):
                hardenPrettyLocal = True

            if hardenPrettyLocal:
                # Trying to avoid collisions on input naming
                prettyLocal = os.path.join(workflowInputs_destdir, str(lastInput) + '_' + matContent.prettyFilename)

            if not os.path.exists(prettyLocal):
                os.symlink(matContent.local, prettyLocal)

        return lastInput

    def materializeInputs(self, offline: bool = False, lastInput=0):
        theParams, numInputs = self.fetchInputs(self.params, workflowInputs_destdir=self.inputsDir,
                                                workflowInputs_cacheDir=self.cacheWorkflowInputsDir, offline=offline,
                                                lastInput=lastInput)
        self.materializedParams = theParams

    def fetchInputs(self, params, workflowInputs_destdir: AbsPath = None, workflowInputs_cacheDir: AbsPath = None,
                    prefix='', lastInput=0, offline: bool = False) -> Tuple[List[MaterializedInput], int]:
        """
        Fetch the input files for the workflow execution.
        All the inputs must be URLs or CURIEs from identifiers.org / n2t.net.

        :param params: Optional params for the workflow execution.
        :param workflowInputs_destdir:
        :param prefix:
        :param workflowInputs_cacheDir:
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

                        remote_files = inputs['url']
                        cacheable = not self.paranoidMode if inputs.get('cache', True) else False
                        if not isinstance(remote_files, list):  # more than one input file
                            remote_files = [remote_files]

                        remote_pairs = []
                        # The storage dir depends on whether it can be cached or not
                        storeDir = workflowInputs_cacheDir if cacheable else inputDestDir
                        for remote_file in remote_files:
                            # We are sending the context name thinking in the future,
                            # as it could contain potential hints for authenticated access
                            contextName = inputs.get('security-context')
                            matContent = self.downloadInputFile(remote_file,
                                                                workflowInputs_destdir=storeDir,
                                                                contextName=contextName,
                                                                offline=offline,
                                                                ignoreCache=not cacheable,
                                                                registerInCache=cacheable,
                                                                )

                            # Now, time to create the symbolic link
                            lastInput += 1

                            prettyLocal = os.path.join(inputDestDir, matContent.prettyFilename)
                            hardenPrettyLocal = False
                            if os.path.islink(prettyLocal):
                                oldLocal = os.readlink(prettyLocal)

                                hardenPrettyLocal = oldLocal != matContent.local
                            elif os.path.exists(prettyLocal):
                                hardenPrettyLocal = True

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
                                            kind=ContentKind.Directory  if exp.is_dir()  else  ContentKind.File
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
                                                                     workflowInputs_cacheDir=workflowInputs_cacheDir,
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
        'File': ContentKind.File,
        'Directory': ContentKind.Directory,
        'Value': ContentKind.Value,
    }

    def parseExpectedOutputs(self, outputs: List[Any]) -> List[ExpectedOutput]:
        expectedOutputs = []

        # TODO: implement parsing of outputs
        outputsIter = outputs.items() if isinstance(outputs, dict) else enumerate(outputs)

        for outputKey, outputDesc in outputsIter:
            # The glob pattern
            patS = outputDesc.get('glob')
            if patS is not None:
                if len(patS) == 0:
                    patS = None

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
                kind=self.OutputClassMapping.get(outputDesc.get('c-l-a-s-s'), 'File'),
                preferredFilename=outputDesc.get('preferredName'),
                cardinality=cardinality,
                glob=patS,
            )
            expectedOutputs.append(eOutput)

        return expectedOutputs

    def executeWorkflow(self, offline : bool = False):
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
        
        # TODO: implement store serialized version of exitVal, augmentedInputs and matCheckOutputs
        self.marshallExecute()
        
    def exportResults(self):
        self.unmarshallExecute(offline=True)
        
        # TODO
        self.marshallExport()
    
    
    def marshallConfig(self, overwrite : bool = False):
        workflow_meta_file = os.path.join(self.metaDir, WORKDIR_WORKFLOW_META_FILE)
        if overwrite or not os.path.exists(workflow_meta_file):
            with open(workflow_meta_file, mode='w', encoding='utf-8') as wmF:
                workflow_meta = {
                    'trs_endpoint': self.trs_endpoint,
                    'workflow_id': self.id,
                    'version': self.version_id,
                    'workflow_type': self.descriptor_type,
                    'paranoid_mode': self.paranoidMode,
                    'params': self.params,
                    'outputs': self.outputs,
                    'workflow_config': self.workflow_config
                }
                yaml.dump(marshall_namedtuple(workflow_meta), wmF, Dumper=YAMLDumper)
        
        creds_file = os.path.join(self.metaDir, WORKDIR_SECURITY_CONTEXT_FILE)
        if overwrite or not os.path.exists(creds_file):
            with open(creds_file, mode='w', encoding='utf-8') as crF:
                yaml.dump(marshall_namedtuple(self.creds_config), crF, Dumper=YAMLDumper)
        
    
    def marshallStage(self, exist_ok : bool = True):
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
    
    def unmarshallStage(self, offline : bool = False):
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
    
    def marshallExecute(self, exist_ok : bool = True):
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
    
    def unmarshallExecute(self, offline : bool = True):
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
    
    def marshallExport(self, exist_ok : bool = True):
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
    
    def unmarshallExport(self, offline : bool = True):
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
    
    def createStageResearchObject(self, doMaterializedROCrate : bool = False):
        """
        Create RO-crate from stage provenance.
        """
        
        # TODO: implement deserialization
        self.unmarshallStage(offline=True)
        
        # TODO: implement logic of doMaterializedROCrate
        
        # TODO
        pass
    
    def createResultsResearchObject(self, doMaterializedROCrate : bool = False):
        """
        Create RO-crate from execution provenance.
        """
        # TODO: implement deserialization
        self.unmarshallExport(offline=True)
        
        # TODO: implement logic of doMaterializedROCrate
        
        # TODO: digest the results from executeWorkflow plus all the provenance

        # Create RO-crate using crate.zip downloaded from WorkflowHub
        if os.path.isfile(str(self.cacheROCrateFilename)):
            wfCrate = rocrate.ROCrate(self.cacheROCrateFilename)

        # Create RO-Crate using rocrate_api
        # TODO no exists the version implemented for Nextflow in rocrate_api
        else:
            # FIXME: What to do when workflow is in git repository different from GitHub??
            # FIXME: What to do when workflow is not in a git repository??
            wf_path = os.path.join(self.localWorkflow.dir, self.localWorkflow.relPath)
            wfCrate, compLang = self.materializedEngine.instance.getEmptyCrateAndComputerLanguage(
                self.localWorkflow.langVersion)
            wf_url = self.repoURL.replace(".git", "/") + "tree/" + self.repoTag + "/" + os.path.dirname(
                self.localWorkflow.relPath)

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
                    itemInSource = itemInValues.local
                    if os.path.isfile(itemInSource):
                        properties = {
                            'name': in_item.name,
                            'url': itemInValues.uri
                        }
                        wfCrate.add_file(source=itemInSource, properties=properties)
                    elif os.path.isdir(itemInSource):
                        self.logger.error("FIXME: input directory / dataset handling in RO-Crate")
                    else:
                        pass  # TODO raise Exception

                # TODO digest other types of inputs

        # Add outputs provenance to RO-crate
        # for out_item in self.matCheckOutputs:
        #     if isinstance(out_item, MaterializedOutput):
        #         itemOutKind = out_item.kind.value
        #         itemOutValues = out_item.values[0]
        #         itemOutSource = itemOutValues.local
        #         properties = {'name': out_item.name}
        #         if itemOutKind == "dir":
        #             if isinstance(itemOutValues, GeneratedDirectoryContent):
        #                 if os.path.isdir(itemOutSource):
        #                     dirProperties = dict.fromkeys(['values'])
        #                     dirProperties['values'] = itemOutValues.values
        #                     properties.update(dirProperties)
        #                     wfCrate.add_directory(source=itemOutSource, properties=properties)
        #
        #                 else:
        #                     pass  # TODO raise Exception
        #
        #         elif itemOutKind == "file":
        #             if isinstance(itemOutValues, GeneratedContent):
        #                 if os.path.isfile(itemOutSource):
        #                     fileProperties = {
        #                         'uri': itemOutValues.uri
        #                     }
        #                     properties.update(fileProperties)
        #                     wfCrate.add_file(source=itemOutSource, properties=properties)
        #
        #                 else:
        #                     pass  # TODO raise Exception
        #         # elif itemOutKind == "val":
        #         else:
        #             pass # TODO raise Exception

        # Save RO-crate as execution.crate.zip
        wfCrate.writeZip(os.path.join(self.outputsDir, "execution.crate"))
        self.logger.info("RO-Crate created: {}".format(self.outputsDir))

        # TODO error handling

    def doMaterializeRepo(self, repoURL, repoTag: RepoTag = None, doUpdate: bool = True) -> Tuple[AbsPath, RepoTag]:
        """

        :param repoURL:
        :param repoTag:
        :param doUpdate:
        :return:
        """
        repo_hashed_id = hashlib.sha1(repoURL.encode('utf-8')).hexdigest()
        repo_hashed_tag_id = hashlib.sha1(b'' if repoTag is None else repoTag.encode('utf-8')).hexdigest()

        # Assure directory exists before next step
        repo_destdir = os.path.join(self.cacheWorkflowDir, repo_hashed_id)
        if not os.path.exists(repo_destdir):
            try:
                os.makedirs(repo_destdir)
            except IOError:
                errstr = "ERROR: Unable to create intermediate directories for repo {}. ".format(repoURL)
                raise WFException(errstr)

        repo_tag_destdir = os.path.join(repo_destdir, repo_hashed_tag_id)
        # We are assuming that, if the directory does exist, it contains the repo
        doRepoUpdate = True
        if not os.path.exists(repo_tag_destdir):
            # Try cloning the repository without initial checkout
            if repoTag is not None:
                gitclone_params = [
                    self.git_cmd, 'clone', '-n', '--recurse-submodules', repoURL, repo_tag_destdir
                ]

                # Now, checkout the specific commit
                gitcheckout_params = [
                    self.git_cmd, 'checkout', repoTag
                ]
            else:
                # We know nothing about the tag, or checkout
                gitclone_params = [
                    self.git_cmd, 'clone', '--recurse-submodules', repoURL, repo_tag_destdir
                ]

                gitcheckout_params = None
        elif doUpdate:
            gitclone_params = None
            gitcheckout_params = [
                self.git_cmd, 'pull', '--recurse-submodules'
            ]
            if repoTag is not None:
                gitcheckout_params.extend(['origin', repoTag])
        else:
            doRepoUpdate = False

        if doRepoUpdate:
            with tempfile.NamedTemporaryFile() as git_stdout, tempfile.NamedTemporaryFile() as git_stderr:

                # First, (bare) clone
                retval = 0
                if gitclone_params is not None:
                    retval = subprocess.call(gitclone_params, stdout=git_stdout, stderr=git_stderr)
                # Then, checkout (which can be optional)
                if retval == 0 and (gitcheckout_params is not None):
                    retval = subprocess.Popen(gitcheckout_params, stdout=git_stdout, stderr=git_stderr,
                                              cwd=repo_tag_destdir).wait()
                # Last, submodule preparation
                if retval == 0:
                    # Last, initialize submodules
                    gitsubmodule_params = [
                        self.git_cmd, 'submodule', 'update', '--init', '--recursive'
                    ]

                    retval = subprocess.Popen(gitsubmodule_params, stdout=git_stdout, stderr=git_stderr,
                                              cwd=repo_tag_destdir).wait()

                # Proper error handling
                if retval != 0:
                    # Reading the output and error for the report
                    with open(git_stdout.name, "r") as c_stF:
                        git_stdout_v = c_stF.read()
                    with open(git_stderr.name, "r") as c_stF:
                        git_stderr_v = c_stF.read()

                    errstr = "ERROR: Unable to pull '{}' (tag '{}'). Retval {}\n======\nSTDOUT\n======\n{}\n======\nSTDERR\n======\n{}".format(
                        repoURL, repoTag, retval, git_stdout_v, git_stderr_v)
                    raise WFException(errstr)

        # Last, we have to obtain the effective checkout
        gitrevparse_params = [
            self.git_cmd, 'rev-parse', '--verify', 'HEAD'
        ]

        with subprocess.Popen(gitrevparse_params, stdout=subprocess.PIPE, encoding='iso-8859-1',
                              cwd=repo_tag_destdir) as revproc:
            repo_effective_checkout = revproc.stdout.read().rstrip()

        return repo_tag_destdir, repo_effective_checkout

    def getWorkflowRepoFromTRS(self, offline: bool = False) -> Tuple[WorkflowType, RepoURL, RepoTag, RelPath]:
        """

        :return:
        """
        # Now, time to check whether it is a TRSv2
        trs_endpoint_v2_meta = self.trs_endpoint + 'service-info'
        trs_endpoint_v2_beta2_meta = self.trs_endpoint + 'metadata'
        trs_endpoint_meta = None
        
        # Needed to store this metadata
        trsMetadataCache = os.path.join(self.metaDir, self.TRS_METADATA_FILE)
        
        try:
            metaContentKind , cachedTRSMetaFile , trsMetaMeta = self.cacheHandler.fetch(trs_endpoint_v2_meta, self.metaDir, offline)
            trs_endpoint_meta = trs_endpoint_v2_meta
        except WFException as wfe:
            try:
                metaContentKind , cachedTRSMetaFile , trsMetaMeta = self.cacheHandler.fetch(trs_endpoint_v2_beta2_meta, self.metaDir, offline)
                trs_endpoint_meta = trs_endpoint_v2_beta2_meta
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
            raise WFException("Unable to identify TRS version from {}".format(trs_endpoint_meta))
        
        # Now, check the tool does exist in the TRS, and the version
        trs_tools_url = parse.urljoin(self.trs_endpoint, self.TRS_TOOLS_PATH + parse.quote(self.id, safe=''))

        trsQueryCache = os.path.join(self.metaDir, self.TRS_QUERY_CACHE_FILE)
        _ , cachedTRSQueryFile , _ = self.cacheHandler.fetch(trs_tools_url, self.metaDir, offline)
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
        if self.trs_endpoint_meta.get('organization',{}).get('name') == 'WorkflowHub':
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
            _ , trsFilesDir , trsFilesMeta = self.cacheHandler.fetch(INTERNAL_TRS_SCHEME_PREFIX + ':' + toolFilesURL, self.cacheTRSFilesDir, offline)
            
            expectedEngineDesc = self.RECOGNIZED_TRS_DESCRIPTORS[chosenDescriptorType]
            remote_workflow_entrypoint = trsFilesMeta[0].metadata.get('remote_workflow_entrypoint')
            if remote_workflow_entrypoint is not None:
                # Give it a chance to identify the original repo of the workflow
                repoURL, repoTag, repoRelPath = self.guessRepoParams(remote_workflow_entrypoint, fail_ok=False)
                
                if repoURL is not None:
                    self.logger.debug("Derived repository {} ({} , rel {}) from {}".format(repoURL, repoTag, repoRelPath, trs_tools_url))
                    return expectedEngineDesc , repoURL, repoTag, repoRelPath
            
            workflow_entrypoint = trsFilesMeta[0].metadata.get('workflow_entrypoint')
            if workflow_entrypoint is not None:
                self.logger.debug("Using raw files from TRS tool {}".format(trs_tools_url))
                repoDir = trsFilesDir
                repoRelPath = workflow_entrypoint
                return expectedEngineDesc , repoDir, None, repoRelPath
                
        raise WFException("Unable to find a workflow in {}".format(trs_tools_url))

    def getWorkflowRepoFromROCrateURL(self, roCrateURL, expectedEngineDesc: WorkflowType = None, offline: bool = False) -> Tuple[WorkflowType, RepoURL, RepoTag, RelPath]:
        """

        :param roCrateURL:
        :param expectedEngineDesc: If defined, an instance of WorkflowType
        :return:
        """
        roCrateFile = self.downloadROcrate(roCrateURL, offline=offline)
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
            repoURL, repoTag, repoRelPath = self.guessRepoParams(workflowUploadURL, fail_ok=False)
        
        if repoURL is None:
            repoURL, repoTag, repoRelPath = self.guessRepoParams(roCrateObj.root_dataset['isBasedOn'], fail_ok=False)
        
        if repoURL is None:
            raise WFException('Unable to guess repository from RO-Crate manifest')

        # It must return four elements:
        return engineDesc, repoURL, repoTag, repoRelPath

    def guessRepoParams(self, wf_url: Union[URIType, parse.ParseResult], fail_ok: bool = True) -> Tuple[RepoURL, RepoTag, RelPath]:
        repoURL = None
        repoTag = None
        repoRelPath = None

        # Deciding which is the input
        if isinstance(wf_url, parse.ParseResult):
            parsed_wf_url = wf_url
        else:
            parsed_wf_url = parse.urlparse(wf_url)
        
        # These are the usual URIs which can be understood by pip
        # See https://pip.pypa.io/en/stable/cli/pip_install/#git
        if parsed_wf_url.scheme.startswith('git+') or parsed_wf_url.scheme == 'git':
            # Getting the scheme git is going to understand
            if len(parsed_wf_url.scheme) > 3:
                gitScheme = parsed_wf_url.scheme[4:]
            else:
                gitScheme = parsed_wf_url.scheme
            
            # Getting the tag or branch
            if '@' in parsed_wf_url.path:
                gitPath , repoTag = parsed_wf_url.path.split('@',1)
            else:
                gitPath = parsed_wf_url.path
            
            # Getting the repoRelPath (if available)
            if len(parsed_wf_url.fragment) > 0:
                frag_qs = parse.parse_qs(parsed_wf_url.fragment)
                subDirArr = frag_qs.get('subdirectory',[])
                if len(subDirArr) > 0:
                    repoRelPath = subDirArr[0]
            
            # Now, reassemble the repoURL
            repoURL = parse.urlunparse((gitScheme, parsed_wf_url.netloc, gitPath, '', '', ''))
            
        # TODO handling other popular cases, like bitbucket
        elif parsed_wf_url.netloc == 'github.com':
            wf_path = parsed_wf_url.path.split('/')

            if len(wf_path) >= 3:
                repoGitPath = wf_path[:3]
                if not repoGitPath[-1].endswith('.git'):
                    repoGitPath[-1] += '.git'

                # Rebuilding repo git path
                repoURL = parse.urlunparse(
                    (parsed_wf_url.scheme, parsed_wf_url.netloc, '/'.join(repoGitPath), '', '', ''))

                # And now, guessing the tag and the relative path
                if len(wf_path) >= 5 and (wf_path[3] in ('blob', 'tree')):
                    repoTag = wf_path[4]

                    if len(wf_path) >= 6:
                        repoRelPath = '/'.join(wf_path[5:])
        elif parsed_wf_url.netloc == 'raw.githubusercontent.com':
            wf_path = parsed_wf_url.path.split('/')
            if len(wf_path) >= 3:
                # Rebuilding it
                repoGitPath = wf_path[:3]
                repoGitPath[-1] += '.git'

                # Rebuilding repo git path
                repoURL = parse.urlunparse(
                    ('https', 'github.com', '/'.join(repoGitPath), '', '', ''))

                # And now, guessing the tag/checkout and the relative path
                if len(wf_path) >= 4:
                    repoTag = wf_path[3]

                    if len(wf_path) >= 5:
                        repoRelPath = '/'.join(wf_path[4:])
        elif fail_ok:
            raise WFException("FIXME: Unsupported http(s) git repository {}".format(wf_url))

        self.logger.debug("From {} was derived {} {} {}".format(wf_url, repoURL, repoTag, repoRelPath))

        return repoURL, repoTag, repoRelPath

    def downloadROcrate(self, roCrateURL, offline: bool = False) -> AbsPath:
        """
        Download RO-crate from WorkflowHub (https://dev.workflowhub.eu/)
        using GA4GH TRS API and save RO-Crate in path.

        :param roCrateURL: location path to save RO-Crate
        :param offline: Are we in offline mode?
        :type roCrateURL: str
        :type offline: bool
        :return:
        """
        
        try:
            roCK , roCrateFile , _ = self.cacheHandler.fetch(roCrateURL, self.cacheROCrateDir, offline)
        except Exception as e:
            raise WFException("Cannot download RO-Crate from {}, {}".format(roCrateURL, e))
        
        crate_hashed_id = hashlib.sha1(roCrateURL.encode('utf-8')).hexdigest()
        cachedFilename = os.path.join(self.cacheROCrateDir, crate_hashed_id + self.DEFAULT_RO_EXTENSION)
        if not os.path.exists(cachedFilename):
            os.symlink(os.path.basename(roCrateFile),cachedFilename)

        self.cacheROCrateFilename = cachedFilename

        return cachedFilename

    def downloadInputFile(self, remote_file, workflowInputs_destdir: AbsPath = None,
                          contextName=None, offline: bool = False, ignoreCache:bool=False, registerInCache:bool=True) -> MaterializedContent:
        """
        Download remote file or directory / dataset.

        :param remote_file: URL or CURIE to download remote file
        :param contextName:
        :param workflowInputs_destdir:
        :param offline:
        :type remote_file: str
        """
        parsedInputURL = parse.urlparse(remote_file)

        if not all([parsedInputURL.scheme, parsedInputURL.path]):
            raise RuntimeError("Input is not a valid remote URL or CURIE source")

        else:
            prettyFilename = parsedInputURL.path.split('/')[-1]

            # Assure workflow inputs directory exists before the next step
            if workflowInputs_destdir is None:
                workflowInputs_destdir = self.cacheWorkflowInputsDir

            self.logger.info("downloading workflow input: {}".format(remote_file))
            # Security context is obtained here
            secContext = None
            if contextName is not None:
                secContext = self.creds_config.get(contextName)
                if secContext is None:
                    raise WFException(
                        'No security context {} is available, needed by {}'.format(contextName, remote_file))
            
            inputKind, cachedFilename, metadata_array = self.cacheHandler.fetch(remote_file, workflowInputs_destdir, offline, ignoreCache, registerInCache, secContext)
            self.logger.info("downloaded workflow input: {} => {}".format(remote_file, cachedFilename))
            
            return MaterializedContent(cachedFilename, remote_file, prettyFilename, inputKind, metadata_array)
