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
import datetime
import hashlib
import inspect
import io
import json
import jsonschema
import logging
import os
import shutil
import stat
import subprocess
import sys
import tempfile
import types
import uuid

from typing import Any, Iterator, List, Mapping, Optional, Tuple, Type, Union
from urllib import parse

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

from .common import AbstractWfExSException
from .common import AbsPath, RelPath
from .common import RepoTag, RepoURL, LicensedURI
from .common import CacheType, ContentKind, URIType, URIWithMetadata
from .common import MaterializedContent, SecurityContextConfig, WorkflowType
from .common import ExitVal, ProtocolFetcher, WfExSInstanceId
from .common import MarshallingStatus, StagedSetup
from .common import DEFAULT_FUSERMOUNT_CMD, DEFAULT_GIT_CMD, DEFAULT_PROGS

from .encrypted_fs import DEFAULT_ENCRYPTED_FS_TYPE, \
  DEFAULT_ENCRYPTED_FS_CMD, DEFAULT_ENCRYPTED_FS_IDLE_TIMEOUT, \
  ENCRYPTED_FS_MOUNT_IMPLEMENTATIONS, EncryptedFSType
from .engine import WorkflowEngine


from .cache_handler import SchemeHandlerCacheHandler

from .utils.marshalling_handling import unmarshall_namedtuple
from .utils.misc import DatetimeEncoder, jsonFilterDecodeFromStream, translate_glob_args
from .utils.passphrase_wrapper import generate_nickname, generate_passphrase

from .fetchers import AbstractStatefulFetcher
from .fetchers import DEFAULT_SCHEME_HANDLERS
from .fetchers.git import SCHEME_HANDLERS as GIT_SCHEME_HANDLERS, GitFetcher
from .fetchers.pride import SCHEME_HANDLERS as PRIDE_SCHEME_HANDLERS
from .fetchers.drs import SCHEME_HANDLERS as DRS_SCHEME_HANDLERS
from .fetchers.trs_files import SCHEME_HANDLERS as INTERNAL_TRS_SCHEME_HANDLERS
from .fetchers.s3 import S3_SCHEME_HANDLERS as S3_SCHEME_HANDLERS
from .fetchers.gs import GS_SCHEME_HANDLERS as GS_SCHEME_HANDLERS

from .workflow import WF

class WfExSBackendException(AbstractWfExSException):
    pass

class WfExSBackend:
    """
    WfExS-backend setup class
    """

    DEFAULT_PASSPHRASE_LENGTH = 4

    CRYPT4GH_SECTION = 'crypt4gh'
    CRYPT4GH_PRIVKEY_KEY = 'key'
    CRYPT4GH_PUBKEY_KEY = 'pub'
    CRYPT4GH_PASSPHRASE_KEY = 'passphrase'

    ID_JSON_FILENAME = '.id.json'

    SCHEMAS_REL_DIR = 'schemas'
    CONFIG_SCHEMA = 'config.json'
    
    @classmethod
    def generate_passphrase(cls) -> str:
        return generate_passphrase(passphrase_length=cls.DEFAULT_PASSPHRASE_LENGTH)

    @classmethod
    def bootstrap(cls, local_config: Mapping[str, Any], config_directory: Optional[Union[RelPath,AbsPath]] = None, key_prefix: Optional[str] = None) -> Tuple[bool, Mapping[str, Any]]:
        """
        :param local_config: Relevant local configuration, like the cache directory.
        :param config_directory: The filename to be used to resolve relative paths
        :param key_prefix: Prefix for the files of newly generated key pairs
        :type local_config: dict
        """

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
        crypt4ghSect = local_config.get(cls.CRYPT4GH_SECTION)
        if crypt4ghSect is None:
            local_config[cls.CRYPT4GH_SECTION] = {}
            crypt4ghSect = local_config[cls.CRYPT4GH_SECTION]

        for elem in (cls.CRYPT4GH_PRIVKEY_KEY, cls.CRYPT4GH_PUBKEY_KEY):
            fname = crypt4ghSect.get(elem)
            # The default when no filename exist is creating hidden files in the config directory
            if fname is None:
                fname = key_prefix + '.' + elem
                crypt4ghSect[elem] = fname
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
            raise WfExSBackendException("Inconsistent {} section, as one of the keys is missing".format(cls.CRYPT4GH_SECTION))

        # Time to generate the pairs needed to work with crypt4gh
        if numExist == 0:
            privKey = crypt4ghSect[cls.CRYPT4GH_PRIVKEY_KEY]
            if not os.path.isabs(privKey):
                privKey = os.path.normpath(os.path.join(config_directory, privKey))
            pubKey = crypt4ghSect[cls.CRYPT4GH_PUBKEY_KEY]
            if not os.path.isabs(pubKey):
                pubKey = os.path.normpath(os.path.join(config_directory, pubKey))

            if cls.CRYPT4GH_PASSPHRASE_KEY not in crypt4ghSect:
                passphrase = cls.generate_passphrase()
                crypt4ghSect[cls.CRYPT4GH_PASSPHRASE_KEY] = passphrase
                updated = True
            else:
                passphrase = crypt4ghSect[cls.CRYPT4GH_PASSPHRASE_KEY]

            comment = 'WfExS crypt4gh keys {} {} {}'.format(socket.gethostname(), config_directory, datetime.datetime.now().isoformat())

            # This is a way to avoid encoding private keys with scrypt,
            # which is not supported in every Python interpreter
            orig_scrypt_supported = crypt4gh.keys.c4gh.scrypt_supported
            crypt4gh.keys.c4gh.scrypt_supported = False
            try:
                crypt4gh.keys.c4gh.generate(
                    privKey,
                    pubKey,
                    passphrase=passphrase.encode('utf-8'),
                    comment=comment.encode('utf-8')
                )
            finally:
                crypt4gh.keys.c4gh.scrypt_supported = orig_scrypt_supported
        elif not crypt4gh.keys.c4gh.scrypt_supported:
            logger.info("Python interpreter does not support scrypt, so encoded crypt4gh keys with that algorithm cannot be used")

        return updated, local_config

    @classmethod
    def FromDescription(cls, workflow_meta, local_config, creds_config=None, config_directory=None) -> WF:
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
            updated_local_config,
            config_directory=config_directory
        ).newSetup(
            workflow_meta['workflow_id'],
            workflow_meta.get('version'),
            descriptor_type=workflow_meta.get('workflow_type'),
            trs_endpoint=workflow_meta.get('trs_endpoint', WF.DEFAULT_TRS_ENDPOINT),
            params=workflow_meta.get('params', {}),
            outputs=workflow_meta.get('outputs', {}),
            workflow_config=workflow_meta.get('workflow_config'),
            creds_config=creds_config
        )

    @classmethod
    def ConfigValidate(cls, configToValidate: Mapping[str, Any], relSchemaFile: RelPath) -> List[Any]:
        # Locating the schemas directory, where all the schemas should be placed
        schemaFile = os.path.join(os.path.dirname(__file__), cls.SCHEMAS_REL_DIR, relSchemaFile)

        try:
            with open(schemaFile, mode="r", encoding="utf-8") as sF:
                schema = json.load(sF)

            jv = jsonschema.validators.validator_for(schema)(schema)
            return list(jv.iter_errors(instance=configToValidate))
        except Exception as e:
            raise WfExSBackendException(f"FATAL ERROR: corrupted schema {relSchemaFile}. Reason: {e}")

    def __init__(self, local_config: Optional[Mapping[str, Any]] = None, config_directory: Optional[Union[RelPath, AbsPath]] = None):
        """
        Init function

        :param local_config: Local setup configuration, telling where caching directories live
        :type local_config: dict
        """
        # Getting a logger focused on specific classes
        self.logger = logging.getLogger(dict(inspect.getmembers(self))['__module__'] + '::' + self.__class__.__name__)

        if not isinstance(local_config, dict):
            local_config = {}

        # validate the local configuration object
        valErrors = self.ConfigValidate(local_config, self.CONFIG_SCHEMA)
        if len(valErrors) > 0:
            self.logger.error(f'ERROR in local configuration block: {valErrors}')
            sys.exit(1)

        self.local_config = local_config
        self.progs = DEFAULT_PROGS.copy()

        toolSect = local_config.get('tools', {})
        self.git_cmd = toolSect.get('gitCommand', DEFAULT_GIT_CMD)
        self.progs[DEFAULT_GIT_CMD] = self.git_cmd

        encfsSect = toolSect.get('encrypted_fs', {})
        encfs_type = encfsSect.get('type', DEFAULT_ENCRYPTED_FS_TYPE)
        try:
            encfs_type = EncryptedFSType(encfs_type)
        except:
            raise WfExSBackendException('Invalid default encryption filesystem {}'.format(encfs_type))
        if encfs_type not in ENCRYPTED_FS_MOUNT_IMPLEMENTATIONS:
            raise WfExSBackendException('FIXME: Default encryption filesystem {} mount procedure is not implemented')
        self.encfs_type = encfs_type

        self.encfs_cmd = encfsSect.get('command', DEFAULT_ENCRYPTED_FS_CMD[self.encfs_type])
        abs_encfs_cmd = shutil.which(self.encfs_cmd)
        if abs_encfs_cmd is None:
            self.logger.error(f'FUSE filesystem command {self.encfs_cmd} not found. Please install it if you are going to use a secured staged workdir')
        else:
            self.encfs_cmd = abs_encfs_cmd
        
        self.fusermount_cmd = encfsSect.get('fusermount_command', DEFAULT_FUSERMOUNT_CMD)
        abs_fusermount_cmd = shutil.which(self.fusermount_cmd)
        if abs_fusermount_cmd is None:
            self.logger.error(f'FUSE fusermount command {self.fusermount_cmd} not found')
        else:
            self.fusermount_cmd = abs_fusermount_cmd
        
        self.progs[DEFAULT_FUSERMOUNT_CMD] = self.fusermount_cmd
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
        self.cachePathMap = dict()
        cacheWorkflowDir = os.path.join(cacheDir, 'wf-cache')
        os.makedirs(cacheWorkflowDir, exist_ok=True)
        self.cachePathMap[CacheType.Workflow] = cacheWorkflowDir

        cacheROCrateDir = os.path.join(cacheDir, 'ro-crate-cache')
        os.makedirs(cacheROCrateDir, exist_ok=True)
        self.cachePathMap[CacheType.ROCrate] = cacheROCrateDir

        cacheTRSFilesDir = os.path.join(cacheDir, 'trs-files-cache')
        os.makedirs(cacheTRSFilesDir, exist_ok=True)
        self.cachePathMap[CacheType.TRS] = cacheTRSFilesDir

        cacheWorkflowInputsDir = os.path.join(cacheDir, 'wf-inputs')
        os.makedirs(cacheWorkflowInputsDir, exist_ok=True)
        self.cachePathMap[CacheType.Input] = cacheWorkflowInputsDir

        # This directory will be used to store the intermediate
        # and final results before they are sent away
        baseWorkDir = local_config.get('workDir')
        if baseWorkDir:
            if not os.path.isabs(baseWorkDir):
                baseWorkDir = os.path.normpath(os.path.join(config_directory, baseWorkDir))
            os.makedirs(baseWorkDir, exist_ok=True)
        else:
            baseWorkDir = tempfile.mkdtemp(prefix='WfExS-workdir', suffix='backend')
            # Assuring this temporal directory is removed at the end
            atexit.register(shutil.rmtree, baseWorkDir)

        self.baseWorkDir = baseWorkDir
        self.defaultParanoidMode = False

        # cacheHandler is created on first use
        self._sngltn = dict()
        self.cacheHandler = SchemeHandlerCacheHandler(self.cacheDir, dict())

        # All the custom ones should be added here
        self.cacheHandler.addSchemeHandlers(PRIDE_SCHEME_HANDLERS)
        self.cacheHandler.addSchemeHandlers(DRS_SCHEME_HANDLERS)
        self.cacheHandler.addSchemeHandlers(INTERNAL_TRS_SCHEME_HANDLERS)
        self.cacheHandler.addSchemeHandlers(S3_SCHEME_HANDLERS)
        self.cacheHandler.addSchemeHandlers(GS_SCHEME_HANDLERS)

        # These ones should have prevalence over other custom ones
        self.addSchemeHandlers(GIT_SCHEME_HANDLERS)
        self.addSchemeHandlers(DEFAULT_SCHEME_HANDLERS)

    @property
    def cacheWorkflowDir(self) -> AbsPath:
        return self.cachePathMap[CacheType.Workflow]

    @property
    def cacheROCrateDir(self) -> AbsPath:
        return self.cachePathMap[CacheType.ROCrate]

    @property
    def cacheTRSFilesDir(self) -> AbsPath:
        return self.cachePathMap[CacheType.TRS]

    @property
    def cacheWorkflowInputsDir(self) -> AbsPath:
        return self.cachePathMap[CacheType.Input]

    def getCacheHandler(self, cache_type:CacheType) -> Tuple[SchemeHandlerCacheHandler, AbsPath]:
        return self.cacheHandler, self.cachePathMap.get(cache_type)

    def instantiateStatefulFetcher(self, statefulFetcher: Type[AbstractStatefulFetcher]) -> AbstractStatefulFetcher:
        """
        Method to instantiate stateful fetchers once
        """
        instStatefulFetcher = None
        if inspect.isclass(statefulFetcher):
            if issubclass(statefulFetcher, AbstractStatefulFetcher):
                instStatefulFetcher = self._sngltn.get(statefulFetcher)
                if instStatefulFetcher is None:
                    instStatefulFetcher = statefulFetcher(progs=self.progs)
                    self._sngltn[statefulFetcher] = instStatefulFetcher

        return instStatefulFetcher

    def addSchemeHandlers(self, schemeHandlers:Mapping[str, Union[ProtocolFetcher, Type[AbstractStatefulFetcher]]]) -> None:
        """
        This method adds scheme handlers (aka "fetchers")
        or instantiates stateful scheme handlers (aka "stateful fetchers")
        """
        if isinstance(schemeHandlers, dict):
            instSchemeHandlers = dict()
            for scheme, schemeHandler in schemeHandlers.items():
                instSchemeHandler = None
                if inspect.isclass(schemeHandler):
                    instSchemeHandler = self.instantiateStatefulFetcher(schemeHandler).fetch
                elif callable(schemeHandler):
                    instSchemeHandler = schemeHandler

                # Only the ones which have overcome the sanity checks
                if instSchemeHandler is not None:
                    instSchemeHandlers[scheme] = instSchemeHandler

            self.cacheHandler.addSchemeHandlers(instSchemeHandlers)

    def newSetup(self,
                 workflow_id,
                 version_id,
                 descriptor_type=None,
                 trs_endpoint=WF.DEFAULT_TRS_ENDPOINT,
                 params=None,
                 outputs=None,
                 workflow_config=None,
                 creds_config=None
                 ) -> WF:

        """
        Init function, which delegates on WF class
        """
        return WF(self, workflow_id, version_id, descriptor_type, trs_endpoint, params, outputs, workflow_config, creds_config)
    
    def createRawWorkDir(self, nickname: Optional[str] = None) -> Tuple[WfExSInstanceId, str, str, AbsPath]:
        """
        This method creates a new, empty, raw working directory
        """
        instanceId = str(uuid.uuid4())
        if nickname is None:
            nickname = generate_nickname()
        else:
            nickname += ' ' + generate_nickname()
        
        return self.getOrCreateRawWorkDirFromInstanceId(instanceId, nickname, create_ok=True)
    
    def getOrCreateRawWorkDirFromInstanceId(self, instanceId: WfExSInstanceId, nickname: Optional[str] = None, create_ok: bool = False) -> Tuple[WfExSInstanceId, str, str, AbsPath]:
        """
        This method returns the absolute path to the raw working directory
        """
        # TODO: Add some validation about the working directory
        uniqueRawWorkDir = os.path.join(self.baseWorkDir, instanceId)
        
        return self.parseOrCreateRawWorkDir(uniqueRawWorkDir, instanceId, nickname, create_ok=create_ok)
    
    def parseOrCreateRawWorkDir(self, uniqueRawWorkDir: AbsPath, instanceId: Optional[WfExSInstanceId] = None, nickname: Optional[str] = None, create_ok: bool = False) -> Tuple[WfExSInstanceId, str, datetime.datetime, AbsPath]:
        """
        This method returns the absolute path to the raw working directory
        """
        # TODO: Add some validation about the working directory
        id_json_path = os.path.join(uniqueRawWorkDir, self.ID_JSON_FILENAME)
        if not os.path.exists(uniqueRawWorkDir):
            if not create_ok:
                raise WfExSBackendException(f"Creation of {uniqueRawWorkDir} is not allowed by parameter")
                
            os.makedirs(uniqueRawWorkDir, exist_ok=True)
            if nickname is None:
                nickname = generate_nickname()
            creation = datetime.datetime.now(tz=datetime.timezone.utc)
            with open(id_json_path, mode='w', encoding='utf-8') as idF:
                idNick = {
                    'instance_id': instanceId,
                    'nickname': nickname,
                    'creation': creation
                }
                json.dump(idNick, idF, cls=DatetimeEncoder)
            os.chmod(id_json_path, stat.S_IRUSR | stat.S_IRGRP | stat.S_IROTH)
        elif os.path.exists(id_json_path):
            with open(id_json_path, mode='r', encoding='utf-8') as iH:
                idNick = jsonFilterDecodeFromStream(iH)
                instanceId = idNick['instance_id']
                nickname = idNick.get('nickname', instanceId)
                creation = idNick.get('creation')
            
            # This file should not change
            if creation is None:
                creation = datetime.datetime.fromtimestamp(os.path.getctime(id_json_path), tz=datetime.timezone.utc)
        else:
            instanceId = os.path.basename(uniqueRawWorkDir)
            nickname = instanceId
            creation = None
        
        if creation is None:
            creation = datetime.datetime.fromtimestamp(os.path.getctime(uniqueRawWorkDir), tz=datetime.timezone.utc)
        
        return instanceId, nickname, creation, uniqueRawWorkDir
    
    def normalizeRawWorkingDirectory(self, uniqueRawWorkDir: Union[RelPath, AbsPath]) -> Tuple[WfExSInstanceId, str, str, AbsPath]:
        """
        This method returns the id of a working directory,
        as well as the nickname
        """
        if uniqueRawWorkDir is None:
            raise WfExSBackendException('Unable to initialize, no directory provided')
        
        # Obtaining the absolute path to the working directory
        if not os.path.isabs(uniqueRawWorkDir):
            uniqueRawWorkDir = os.path.normpath(os.path.join(self.baseWorkDir, uniqueRawWorkDir))

        if not os.path.isdir(uniqueRawWorkDir):
            raise WfExSBackendException('Unable to initialize, {} is not a directory'.format(uniqueRawWorkDir))
        
        return self.parseOrCreateRawWorkDir(uniqueRawWorkDir, create_ok=False)

    def fromWorkDir(self, workflowWorkingDirectory: Union[RelPath, AbsPath], fail_ok: bool = False) -> WF:
        return WF.FromWorkDir(self, workflowWorkingDirectory, fail_ok=fail_ok)
    
    def getDefaultParanoidMode(self) -> bool:
        return self.defaultParanoidMode
    
    def enableDefaultParanoidMode(self):
        self.defaultParanoidMode = True

    def fromFiles(self, workflowMetaFilename: Union[RelPath, AbsPath], securityContextsConfigFilename: Optional[Union[RelPath, AbsPath]] = None, paranoidMode: bool = False) -> WF:
        return WF.FromFiles(self, workflowMetaFilename, securityContextsConfigFilename, paranoidMode)

    def validateConfigFiles(self, workflowMetaFilename: Union[RelPath, AbsPath], securityContextsConfigFilename: Optional[Union[RelPath, AbsPath]] = None) -> ExitVal:
        numErrors = 0
        self.logger.info(f'Validating {workflowMetaFilename}')

        with open(workflowMetaFilename, mode="r", encoding="utf-8") as wcf:
            workflow_meta = unmarshall_namedtuple(yaml.load(wcf, Loader=YAMLLoader))

        if not isinstance(workflow_meta, dict):
            workflow_meta = {}

        valErrors = self.ConfigValidate(workflow_meta, WF.STAGE_DEFINITION_SCHEMA)
        if len(valErrors) == 0:
            self.logger.info('No validation errors in staging definition block')
        else:
            for iErr, valError in enumerate(valErrors):
                self.logger.error(f'ERROR {iErr} in staging definition block: {valError}')
                numErrors += 1

        # Last, try loading the security contexts credentials file
        if securityContextsConfigFilename and os.path.exists(securityContextsConfigFilename):
            self.logger.info(f'Validating {securityContextsConfigFilename}')

            with open(securityContextsConfigFilename, mode="r", encoding="utf-8") as scf:
                creds_config = unmarshall_namedtuple(yaml.load(scf, Loader=YAMLLoader))

            valErrors = self.ConfigValidate(creds_config, WF.SECURITY_CONTEXT_SCHEMA)
            if len(valErrors) == 0:
                self.logger.info('No validation errors in security block')
            else:
                for iErr, valError in enumerate(valErrors):
                    self.logger.error(f'ERROR {iErr} in security context block: {valError}')
                    numErrors += 1

        return 1 if numErrors > 0 else 0

    def fromDescription(self, workflow_meta, creds_config=None, paranoidMode: bool = False) -> WF:
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

        return WF.FromDescription(self, workflow_meta, creds_config, paranoidMode)

    def fromForm(self, workflow_meta, paranoidMode: bool = False) -> WF:  # VRE
        """

        :param workflow_meta: The configuration describing both the workflow
        and the inputs to use when it is being instantiated.
        :param paranoidMode:
        :type workflow_meta: dict
        :type paranoidMode:
        :return: Workflow configuration
        """
        return WF.FromForm(self, workflow_meta, paranoidMode=paranoidMode)
    
    def getFusermountParams(self) -> Tuple[str, int]:
        return self.fusermount_cmd , self.encfs_idleMinutes
    
    def readSecuredPassphrase(self, passphraseFile: AbsPath) -> Tuple[EncryptedFSType, Union[AbsPath, RelPath], str]:
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
        del clearF
        self.logger.debug(encfs_type + ' ' + securePassphrase)
        try:
            encfs_type = EncryptedFSType(encfs_type)
        except:
            raise WfExSBackendException('Invalid encryption filesystem {} in working directory'.format(encfs_type))
        if encfs_type not in ENCRYPTED_FS_MOUNT_IMPLEMENTATIONS:
            raise WfExSBackendException('FIXME: Encryption filesystem {} mount procedure is not implemented')

        # If the working directory encrypted filesystem does not
        # match the configured one, use its default executable
        if encfs_type != self.encfs_type:
            encfs_cmd = DEFAULT_ENCRYPTED_FS_CMD[encfs_type]
        else:
            encfs_cmd = self.encfs_cmd

        if securePassphrase == '':
            raise WfExSBackendException('Encryption filesystem key does not follow the right format')
        
        return encfs_type, encfs_cmd, securePassphrase

    def generateSecuredPassphrase(self, passphraseFile: AbsPath) -> Tuple[EncryptedFSType, Union[AbsPath, RelPath], str]:
        securePassphrase = self.generate_passphrase()
        clearF = io.BytesIO((self.encfs_type.value + '=' + securePassphrase).encode('utf-8'))
        with open(passphraseFile, mode="wb") as encF:
            crypt4gh.lib.encrypt(
                [(0, self.privKey, self.pubKey)],
                clearF,
                encF,
                offset=0,
                span=None
            )
        del clearF
        
        return self.encfs_type, self.encfs_cmd, securePassphrase
    
    def listStagedWorkflows(self, *args, acceptGlob:bool=False, doCleanup:bool=True) -> Iterator[Tuple[WfExSInstanceId, str, str, Optional[StagedSetup], Optional[WF]]]:
        entries = set(args)
        if entries and acceptGlob:
            reEntries = translate_glob_args(entries)
        else:
            reEntries = None
        
        with os.scandir(self.baseWorkDir) as swD:
            for entry in swD:
                # Avoiding loops
                if entry.is_dir(follow_symlinks=False) and not entry.name.startswith('.'):
                    try:
                        instanceId, nickname, creation, _ = self.parseOrCreateRawWorkDir(entry.path, create_ok=False)
                    except:
                        self.logger.warning(f'Skipped {entry.name} on listing')
                        continue
                    
                    if entries:
                        if reEntries:
                            if all(map(lambda r: (r.match(instanceId) is None) and (r.match(nickname) is None), reEntries)):
                                continue
                        elif (instanceId not in entries) and (nickname not in entries):
                            continue
                    
                    self.logger.debug(f'{instanceId} {nickname}')
                    isDamaged = False
                    isEncrypted = False
                    wfSetup = None
                    wfInstance = None
                    try:
                        wfInstance = self.fromWorkDir(instanceId, fail_ok=True)
                        try:
                            wfSetup = wfInstance.getStagedSetup()
                        except Exception as e:
                            self.logger.exception(f'Something wrong with staged setup from {instanceId} ({nickname})')
                        
                    except:
                        self.logger.exception(f'Something wrong with workflow {instanceId} ({nickname})')
                    
                    # Give a chance to work on the passed instance
                    yield instanceId, nickname, creation, wfSetup, wfInstance
                    
                    # Should we force an unmount?
                    if doCleanup and (wfInstance is not None):
                        wfInstance.cleanup()
                        wfInstance = None
                    
    
    def statusStagedWorkflows(self, *args, acceptGlob:bool=False) -> Iterator[Tuple[WfExSInstanceId, str, str, Optional[StagedSetup], Optional[MarshallingStatus]]]:
        if len(args) > 0:
            for instance_id, nickname, creation, wfSetup, wfInstance in self.listStagedWorkflows(*args, acceptGlob=acceptGlob, doCleanup=True):
                self.logger.debug(f"Status {instance_id} {nickname}")
                
                # This is needed to trigger the cascade of
                # state unmarshalling and validations
                if wfInstance is not None:
                    wfInstance.unmarshallExport(offline=True, fail_ok=True)
                    mStatus = wfInstance.getMarshallingStatus()
                
                yield instance_id, nickname, creation, wfSetup, mStatus
    
    def removeStagedWorkflows(self, *args, acceptGlob:bool=False) -> Iterator[Tuple[WfExSInstanceId, str]]:
        if len(args) > 0:
            for instance_id, nickname, creation, wfSetup, _ in self.listStagedWorkflows(*args, acceptGlob=acceptGlob, doCleanup=True):
                self.logger.debug(f"Removing {instance_id} {nickname}")
                shutil.rmtree(wfSetup.raw_work_dir, ignore_errors=True)
                yield instance_id, nickname
    
    def shellFirstStagedWorkflow(self, *args, stdin=sys.stdin, stdout=sys.stdout, stderr=sys.stderr, acceptGlob:bool=False, firstMatch:bool=True) -> ExitVal:
        retval = -1
        if len(args) > 0:
            theEnv = dict(os.environ)
            if len(args) > 1:
                command = args[1:]
            else:
                command = [ os.environ.get('SHELL', '/bin/sh') ]
            for instance_id, nickname, creation, wfSetup, wfInstance in self.listStagedWorkflows(args[0], acceptGlob=acceptGlob, doCleanup=False):
                # We are doing it only for the first match
                self.logger.info(f'Running {command} at {instance_id} ({nickname})')
                # Setting a custom symbol
                theEnv['PROMPT_COMMAND'] = f"echo \"(WfExS '{nickname}')\""

                cp = subprocess.run(command, cwd=wfSetup.work_dir, stdin=stdin, stdout=stdout, stderr=stderr, env=theEnv)
                retval = cp.returncode
                wfInstance.cleanup()
                if firstMatch:
                    break
        return retval

    def cacheFetch(self, remote_file:Union[LicensedURI, parse.ParseResult, URIType, List[Union[LicensedURI, parse.ParseResult, URIType]]], cacheType: CacheType, offline:bool, ignoreCache:bool=False, registerInCache:bool=True, secContext:Optional[SecurityContextConfig]=None) -> Tuple[ContentKind, AbsPath, List[URIWithMetadata], List[URIType]]:
        """
        This is a pass-through method to the cache handler, which translates from symbolic types of cache to their corresponding directories
        
        :param remote_file: The URI to be fetched (if not already cached)
        :param cacheType: The type of cache where to look up the URI
        :param offline: Is the instance working in offline mode?
        (i.e. raise exceptions when external content is needed)
        :param ignoreCache: Even if the content is cache, discard and re-fetch it
        :param registerInCache: Should the fetched content be registered
        in the cache?
        :param secContext: The security context which has to be passed to
        the fetchers, in case they have to be used
        """
        return self.cacheHandler.fetch(
            remote_file,
            self.cachePathMap[cacheType],
            offline,
            ignoreCache=ignoreCache,
            registerInCache=registerInCache,
            secContext=secContext
        )
    
    def instantiateEngine(self, engineDesc: WorkflowType, stagedSetup:StagedSetup) -> WorkflowEngine:
        
        return engineDesc.clazz.FromStagedSetup(
            staged_setup=stagedSetup,
            cache_dir=self.cacheDir,
            cache_workflow_dir=self.cacheWorkflowDir,
            cache_workflow_inputs_dir=self.cacheWorkflowInputsDir,
            local_config=self.local_config,
            config_directory=self.config_directory
        )    

    def addSchemeHandler(self, scheme, handler):
        """

        :param scheme:
        :param handler:
        """
        if not isinstance(handler, (
                types.FunctionType, types.LambdaType, types.MethodType, types.BuiltinFunctionType,
                types.BuiltinMethodType)):
            raise WfExSBackendException('Trying to set for scheme {} a invalid handler'.format(scheme))

        self.cacheHandler.addSchemeHandlers({scheme.lower(): handler})

    def doMaterializeRepo(self, repoURL: RepoURL, repoTag: RepoTag = None, doUpdate: bool = True) -> Tuple[AbsPath, RepoTag]:
        """

        :param repoURL:
        :param repoTag:
        :param doUpdate:
        :return:
        """
        gitFetcherInst = self.instantiateStatefulFetcher(GitFetcher)
        repoDir, repoEffectiveCheckout, metadata = gitFetcherInst.doMaterializeRepo(repoURL, repoTag=repoTag, doUpdate=doUpdate, base_repo_destdir=self.cacheWorkflowDir)

        # Now, let's register the checkout with cache structures
        # using its public URI
        if not repoURL.startswith('git'):
            remote_url = 'git+' + repoURL
        else:
            remote_url = repoURL
        
        if repoTag is not None:
            remote_url += '@' + repoTag

        self.cacheHandler.inject(
            self.cacheWorkflowDir,
            remote_url,
            fetched_metadata_array=[
                URIWithMetadata(
                    uri=remote_url,
                    metadata=metadata,
                )
            ],
            finalCachedFilename=repoDir,
            inputKind=ContentKind.Directory
        )

        return repoDir, repoEffectiveCheckout


    def guessRepoParams(self, wf_url: Union[URIType, parse.ParseResult], fail_ok: bool = False) -> Tuple[RepoURL, RepoTag, RelPath]:
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
                gitPath, repoTag = parsed_wf_url.path.split('@', 1)
            else:
                gitPath = parsed_wf_url.path

            # Getting the repoRelPath (if available)
            if len(parsed_wf_url.fragment) > 0:
                frag_qs = parse.parse_qs(parsed_wf_url.fragment)
                subDirArr = frag_qs.get('subdirectory', [])
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
        elif not fail_ok:
            raise WfExSBackendException("FIXME: Unsupported http(s) git repository {}".format(wf_url))

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
            roCK, roCrateFile, _, _ = self.cacheHandler.fetch(roCrateURL, self.cacheROCrateDir, offline)
        except Exception as e:
            raise WfExSBackendException("Cannot download RO-Crate from {}, {}".format(roCrateURL, e)) from e

        crate_hashed_id = hashlib.sha1(roCrateURL.encode('utf-8')).hexdigest()
        cachedFilename = os.path.join(self.cacheROCrateDir, crate_hashed_id + WF.DEFAULT_RO_EXTENSION)
        if not os.path.exists(cachedFilename):
            os.symlink(os.path.basename(roCrateFile), cachedFilename)

        return cachedFilename

    def downloadContent(self, remote_file: Union[URIType, LicensedURI, List[URIType], List[LicensedURI]], dest: Union[AbsPath,CacheType],
                          secContext: Optional[SecurityContextConfig] = None, offline: bool = False, ignoreCache:bool=False, registerInCache:bool=True) -> MaterializedContent:
        """
        Download remote file or directory / dataset.

        :param remote_file: URL or CURIE to download remote file
        :param contextName:
        :param workflowInputs_destdir:
        :param offline:
        :type remote_file: str
        """
        
        # Preparation of needed structures
        if isinstance(remote_file, list):
            remote_uris_e = remote_file
        else:
            remote_uris_e = [ remote_file ]
        
        firstURI : URIType = None
        firstParsedURI = None
        remote_uris : List[URIType] = []
        # Brief validation of correct uris
        for remote_uri_e in remote_uris_e:
            if isinstance(remote_uri_e, LicensedURI):
                remote_uri = remote_uri_e.uri
            else:
                remote_uri = remote_uri_e
            
            parsedURI = parse.urlparse(remote_uri)
            validableComponents = [ parsedURI.scheme, parsedURI.path ]
            if not all(validableComponents):
                raise RuntimeError(f"Input does not have {remote_uri} as a valid remote URL or CURIE source ")
            remote_uris.append(remote_uri)
            if firstParsedURI is None:
                firstURI = remote_uri_e
                firstParsedURI = parsedURI

        # Assure workflow inputs directory exists before the next step
        if isinstance(dest, CacheType):
            workflowInputs_destdir = self.cachePathMap[dest]

        self.logger.info("downloading workflow input: {}".format(' or '.join(remote_uris)))

        inputKind, cachedFilename, metadata_array, cachedLicences = self.cacheHandler.fetch(remote_file, workflowInputs_destdir, offline, ignoreCache, registerInCache, secContext)
        self.logger.info("downloaded workflow input: {} => {}".format(remote_file, cachedFilename))

        prettyFilename = None
        if len(metadata_array) > 0:
            self.logger.info("downloaded workflow input: {} => {}".format(' -> '.join(map(lambda m: m.uri, metadata_array)), cachedFilename))
            
            if isinstance(firstURI, LicensedURI):
                firstLicensedURI = LicensedURI(
                    uri=metadata_array[0].uri,
                    licences=cachedLicences,
                    attributions=firstURI.attributions
                )
            else:
                firstURI = metadata_array[0].uri
            # The preferred name is obtained from the metadata
            for m in metadata_array:
                if m.preferredName is not None:
                    prettyFilename = m.preferredName
                    break
        
        if prettyFilename is None:
            # Default pretty filename in the worst case
            prettyFilename = firstParsedURI.path.split('/')[-1]
        
        if isinstance(firstURI, LicensedURI):
            # Junking the security context
            if firstURI.secContext is None:
                firstLicensedURI = firstURI
            else:
                firstLicensedURI = LicensedURI(
                    uri=firstURI.uri,
                    licences=firstURI.licences,
                    attributions=firstURI.attributions
                )
        else:
            # No licensing information attached
            firstLicensedURI = LicensedURI(
                uri=firstURI
            )
        
        return MaterializedContent(
            local=cachedFilename,
            licensed_uri=firstLicensedURI,
            prettyFilename=prettyFilename,
            kind=inputKind,
            metadata_array=metadata_array
        )
