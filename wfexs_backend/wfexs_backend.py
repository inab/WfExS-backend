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
import platform
import shutil
import sys
import tempfile
import time
import types
import uuid

from typing import Any, List, Mapping, Optional, Pattern, Tuple, Type, Union
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

from .common import *
from .encrypted_fs import DEFAULT_ENCRYPTED_FS_TYPE, \
  DEFAULT_ENCRYPTED_FS_CMD, DEFAULT_ENCRYPTED_FS_IDLE_TIMEOUT, \
  ENCRYPTED_FS_MOUNT_IMPLEMENTATIONS, EncryptedFSType
#from .encrypted_fs import *
from .engine import WorkflowEngine

from .cache_handler import SchemeHandlerCacheHandler

from .utils.digests import ComputeDigestFromDirectory, ComputeDigestFromFile, nihDigester
from .utils.marshalling_handling import marshall_namedtuple, unmarshall_namedtuple
from .utils.passphrase_wrapper import generate_passphrase

from .fetchers import AbstractStatefulFetcher
from .fetchers import DEFAULT_SCHEME_HANDLERS
from .fetchers.git import SCHEME_HANDLERS as GIT_SCHEME_HANDLERS, GitFetcher
from .fetchers.pride import SCHEME_HANDLERS as PRIDE_SCHEME_HANDLERS
from .fetchers.drs import SCHEME_HANDLERS as DRS_SCHEME_HANDLERS
from .fetchers.trs_files import SCHEME_HANDLERS as INTERNAL_TRS_SCHEME_HANDLERS
from .fetchers.s3 import S3_SCHEME_HANDLERS as S3_SCHEME_HANDLERS
from .fetchers.gs import GS_SCHEME_HANDLERS as GS_SCHEME_HANDLERS

from .workflow import WF

class WfExSBackend:
    """
    WfExS-backend setup class
    """

    DEFAULT_PASSPHRASE_LENGTH = 4

    CRYPT4GH_SECTION = 'crypt4gh'
    CRYPT4GH_PRIVKEY_KEY = 'key'
    CRYPT4GH_PUBKEY_KEY = 'pub'
    CRYPT4GH_PASSPHRASE_KEY = 'passphrase'

    SCHEMAS_REL_DIR = 'schemas'
    CONFIG_SCHEMA = 'config.json'

    @classmethod
    def generate_passphrase(cls) -> str:
        return generate_passphrase(cls.DEFAULT_PASSPHRASE_LENGTH)

    @classmethod
    def bootstrap(cls, local_config: Mapping[str, Any], config_directory: Optional[Union[RelPath,AbsPath]] = None, key_prefix: Optional[str] = None) -> Tuple[bool, Mapping[str, Any]]:
        """
        :param local_config: Relevant local configuration, like the cache directory.
        :param config_directory: The filename to be used to resolve relative paths
        :param key_prefix: Prefix for the files of newly generated key pairs
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
            raise WFException("Inconsistent {} section, as one of the keys is missing".format(cls.CRYPT4GH_SECTION))

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
            raise WFException(f"FATAL ERROR: corrupted schema {relSchemaFile}. Reason: {e}")

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
            raise WFException('Invalid default encryption filesystem {}'.format(encfs_type))
        if encfs_type not in ENCRYPTED_FS_MOUNT_IMPLEMENTATIONS:
            raise WFException('FIXME: Default encryption filesystem {} mount procedure is not implemented')
        self.encfs_type = encfs_type

        self.encfs_cmd = shutil.which(encfsSect.get('command', DEFAULT_ENCRYPTED_FS_CMD[self.encfs_type]))
        self.fusermount_cmd = encfsSect.get('fusermount_command', DEFAULT_FUSERMOUNT_CMD)
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
    
    def createRawWorkDir(self) -> Tuple[str, AbsPath]:
        """
        This method creates a new, empty, raw working directory
        """
        instanceId = str(uuid.uuid4())
        
        return instanceId, self.getRawWorkDir(instanceId)
    
    def getRawWorkDir(self, instanceId) -> AbsPath:
        """
        This method returns the absolute path to the raw working directory
        """
        # TODO: Add some validation about the working directory
        uniqueRawWorkDir = os.path.join(self.baseWorkDir, instanceId)
        os.makedirs(uniqueRawWorkDir, exist_ok=True)
        
        return uniqueRawWorkDir
    
    def getInstanceIdFromRawWorkDir(self, uniqueRawWorkDir: AbsPath) -> str:
        """
        This method returns the id of a working directory
        """
        
        # TODO: Add some validation about the working directory
        return os.path.basename(uniqueRawWorkDir)

    def normalizeRawWorkingDirectory(self, uniqueRawWorkDir: Union[RelPath, AbsPath]) -> Tuple[str, AbsPath]:
        if uniqueRawWorkDir is None:
            raise WFException('Unable to initialize, no directory provided')
        
        # Obtaining the absolute path to the working directory
        if not os.path.isabs(uniqueRawWorkDir):
            uniqueRawWorkDir = os.path.normpath(os.path.join(self.baseWorkDir, uniqueRawWorkDir))

        if not os.path.isdir(uniqueRawWorkDir):
            raise WFException('Unable to initialize, {} is not a directory'.format(uniqueRawWorkDir))
        
        instanceId = os.path.basename(uniqueRawWorkDir)
        
        return instanceId, uniqueRawWorkDir

    def fromWorkDir(self, workflowWorkingDirectory):
        return WF.FromWorkDir(self, workflowWorkingDirectory)
    
    def getDefaultParanoidMode(self) -> bool:
        return self.defaultParanoidMode
    
    def enableDefaultParanoidMode(self):
        self.defaultParanoidMode = True

    def fromFiles(self, workflowMetaFilename, securityContextsConfigFilename=None, paranoidMode=False) -> WF:
        return WF.FromFiles(self, workflowMetaFilename, securityContextsConfigFilename, paranoidMode)

    def validateConfigFiles(self, workflowMetaFilename, securityContextsConfigFilename=None):
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

    def fromDescription(self, workflow_meta, creds_config=None, paranoidMode=False) -> WF:
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

    def fromForm(self, workflow_meta, paranoidMode=False) -> WF:  # VRE
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
            raise WFException('Invalid encryption filesystem {} in working directory'.format(encfs_type))
        if encfs_type not in ENCRYPTED_FS_MOUNT_IMPLEMENTATIONS:
            raise WFException('FIXME: Encryption filesystem {} mount procedure is not implemented')

        # If the working directory encrypted filesystem does not
        # match the configured one, use its default executable
        if encfs_type != self.encfs_type:
            encfs_cmd = DEFAULT_ENCRYPTED_FS_CMD[encfs_type]
        else:
            encfs_cmd = self.encfs_cmd

        if securePassphrase == '':
            raise WFException('Encryption filesystem key does not follow the right format')
        
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
    
    def cacheFetch(self, remote_file:Union[parse.ParseResult, URIType, List[Union[parse.ParseResult, URIType]]], cacheType: CacheType, offline:bool, ignoreCache:bool=False, registerInCache:bool=True, secContext:Optional[SecurityContextConfig]=None) -> Tuple[ContentKind, AbsPath, List[URIWithMetadata]]:
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
            raise WFException('Trying to set for scheme {} a invalid handler'.format(scheme))

        self.cacheHandler.addSchemeHandlers({scheme.lower(): handler})

    def doMaterializeRepo(self, repoURL, repoTag: RepoTag = None, doUpdate: bool = True) -> Tuple[AbsPath, RepoTag]:
        """

        :param repoURL:
        :param repoTag:
        :param doUpdate:
        :return:
        """
        gitFetcherInst = self.instantiateStatefulFetcher(GitFetcher)
        repoDir, repoEffectiveCheckout, metadata = gitFetcherInst.doMaterializeRepo(repoURL,repoTag=repoTag, doUpdate=doUpdate, base_repo_destdir=self.cacheWorkflowDir)

        # Now, let's register the checkout with cache structures
        # using its public URI
        if not repoURL.startswith('git'):
            remote_url = 'git+' + repoURL
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
            roCK, roCrateFile, _ = self.cacheHandler.fetch(roCrateURL, self.cacheROCrateDir, offline)
        except Exception as e:
            raise WFException("Cannot download RO-Crate from {}, {}".format(roCrateURL, e))

        crate_hashed_id = hashlib.sha1(roCrateURL.encode('utf-8')).hexdigest()
        cachedFilename = os.path.join(self.cacheROCrateDir, crate_hashed_id + WF.DEFAULT_RO_EXTENSION)
        if not os.path.exists(cachedFilename):
            os.symlink(os.path.basename(roCrateFile), cachedFilename)

        self.cacheROCrateFilename = cachedFilename

        return cachedFilename

    def downloadContent(self, remote_file, dest: Union[AbsPath,CacheType],
                          secContext: Optional=None, offline: bool = False, ignoreCache:bool=False, registerInCache:bool=True) -> MaterializedContent:
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
            # Default pretty filename
            prettyFilename = parsedInputURL.path.split('/')[-1]

            # Assure workflow inputs directory exists before the next step
            if isinstance(dest, CacheType):
                workflowInputs_destdir = self.cachePathMap[dest]

            self.logger.info("downloading workflow input: {}".format(remote_file))

            inputKind, cachedFilename, metadata_array = self.cacheHandler.fetch(remote_file, workflowInputs_destdir, offline, ignoreCache, registerInCache, secContext)
            self.logger.info("downloaded workflow input: {} => {}".format(remote_file, cachedFilename))

            # FIXME: What to do when there is more than one entry in the metadata array?
            if len(metadata_array) > 0 and (metadata_array[0].preferredName is not None):
                prettyFilename = metadata_array[0].preferredName

            return MaterializedContent(cachedFilename, remote_file, prettyFilename, inputKind, metadata_array)
