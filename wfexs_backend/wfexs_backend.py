#!/usr/bin/env python
# -*- coding: utf-8 -*-

# SPDX-License-Identifier: Apache-2.0
# Copyright 2020-2023 Barcelona Supercomputing Center (BSC), Spain
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
import copy
import datetime
import hashlib
import inspect
import io
import json
import logging
import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import types
import urllib.parse
import uuid
import warnings

from typing import (
    cast,
    NamedTuple,
    Pattern,
    TYPE_CHECKING,
)
from urllib import parse

# We have preference for the C based loader and dumper, but the code
# should fallback to default implementations when C ones are not present
import yaml

import crypt4gh.lib
import crypt4gh.keys.kdf
import crypt4gh.keys.c4gh

import magic

from .common import (
    AbstractWfExSException,
    CacheType,
    ContentKind,
    DEFAULT_FUSERMOUNT_CMD,
    DEFAULT_PROGS,
    LicensedURI,
    MaterializedContent,
    RemoteRepo,
    RepoType,
    URIWithMetadata,
)

from .encrypted_fs import (
    DEFAULT_ENCRYPTED_FS_CMD,
    DEFAULT_ENCRYPTED_FS_IDLE_TIMEOUT,
    DEFAULT_ENCRYPTED_FS_TYPE,
    ENCRYPTED_FS_MOUNT_IMPLEMENTATIONS,
    EncryptedFSType,
)


from .cache_handler import (
    CachedContent,
    SchemeHandlerCacheHandler,
)

from .engine import (
    WORKDIR_META_RELDIR,
    WORKDIR_PASSPHRASE_FILE,
    WORKDIR_WORKFLOW_META_FILE,
)
from .ro_crate import FixedROCrate

from .security_context import SecurityContextVault

from .utils.marshalling_handling import unmarshall_namedtuple
from .utils.misc import config_validate
from .utils.misc import (
    DatetimeEncoder,
    jsonFilterDecodeFromStream,
    translate_glob_args,
)
from .utils.passphrase_wrapper import (
    WfExSPassGenSingleton,
)

from .fetchers import (
    DocumentedProtocolFetcher,
    DocumentedStatefulProtocolFetcher,
)
from .fetchers.http import SCHEME_HANDLERS as HTTP_SCHEME_HANDLERS
from .fetchers.ftp import SCHEME_HANDLERS as FTP_SCHEME_HANDLERS
from .fetchers.sftp import SCHEME_HANDLERS as SFTP_SCHEME_HANDLERS
from .fetchers.file import SCHEME_HANDLERS as FILE_SCHEME_HANDLERS
from .fetchers.data import SCHEME_HANDLERS as DATA_SCHEME_HANDLERS

from .fetchers.git import (
    GitFetcher,
    guess_git_repo_params,
)

from .fetchers.swh import (
    guess_swh_repo_params,
    SoftwareHeritageFetcher,
)

from .fetchers.pride import SCHEME_HANDLERS as PRIDE_SCHEME_HANDLERS
from .fetchers.drs import SCHEME_HANDLERS as DRS_SCHEME_HANDLERS
from .fetchers.trs_files import SCHEME_HANDLERS as INTERNAL_TRS_SCHEME_HANDLERS
from .fetchers.s3 import S3_SCHEME_HANDLERS as S3_SCHEME_HANDLERS
from .fetchers.gs import GS_SCHEME_HANDLERS as GS_SCHEME_HANDLERS
from .fetchers.fasp import FASPFetcher
from .fetchers.doi import SCHEME_HANDLERS as DOI_SCHEME_HANDLERS
from .fetchers.zenodo import SCHEME_HANDLERS as ZENODO_SCHEME_HANDLERS
from .fetchers.b2share import SCHEME_HANDLERS as B2SHARE_SCHEME_HANDLERS
from .fetchers.osf_io import SCHEME_HANDLERS as OSF_IO_SCHEME_HANDLERS

from .pushers.cache_export import CacheExportPlugin
from .pushers.nextcloud_export import NextcloudExportPlugin

from .workflow import (
    WF,
    WFException,
)

from .fetchers.trs_files import (
    TRS_SCHEME_PREFIX,
    INTERNAL_TRS_SCHEME_PREFIX,
)


if TYPE_CHECKING:
    from typing import (
        Any,
        ClassVar,
        IO,
        Iterator,
        Mapping,
        MutableMapping,
        MutableSequence,
        Optional,
        Sequence,
        Set,
        Tuple,
        Type,
        Union,
    )

    from typing_extensions import Final

    from crypt4gh.header import CompoundKey

    from .common import (
        AbsPath,
        AnyPath,
        EnvironmentBlock,
        ExitVal,
        ExportActionBlock,
        MarshallingStatus,
        OutputsBlock,
        ParamsBlock,
        ProgsMapping,
        RelPath,
        RepoTag,
        RepoURL,
        SecurityContextConfig,
        SecurityContextConfigBlock,
        StagedSetup,
        SymbolicName,
        TRS_Workflow_Descriptor,
        URIType,
        WfExSConfigBlock,
        WfExSInstanceId,
        WorkflowConfigBlock,
        WorkflowMetaConfigBlock,
        WritableWfExSConfigBlock,
    )

    from .engine import (
        AbstractWorkflowEngineType,
        WorkflowType,
    )

    from .fetchers import (
        AbstractStatefulFetcher,
        StatefulFetcher,
    )

    from .pushers import AbstractExportPlugin

    from .utils.passphrase_wrapper import (
        WfExSPassphraseGenerator,
    )

    from .workflow import (
        WFVersionId,
        WorkflowId,
    )


class IdentifiedWorkflow(NamedTuple):
    """
    workflow_type: The identified workflow type
    """

    workflow_type: "WorkflowType"
    remote_repo: "RemoteRepo"


class WfExSBackendException(AbstractWfExSException):
    pass


class WfExSBackend:
    """
    WfExS-backend setup class
    """

    DEFAULT_PASSPHRASE_LENGTH: "Final[int]" = 4

    CRYPT4GH_SECTION: "Final[str]" = "crypt4gh"
    CRYPT4GH_PRIVKEY_KEY: "Final[str]" = "key"
    CRYPT4GH_PUBKEY_KEY: "Final[str]" = "pub"
    CRYPT4GH_PASSPHRASE_KEY: "Final[str]" = "passphrase"

    ID_JSON_FILENAME: "Final[str]" = ".id.json"

    SCHEMAS_REL_DIR: "Final[str]" = "schemas"
    CONFIG_SCHEMA: "Final[RelPath]" = cast("RelPath", "config.json")
    _PassGen: "ClassVar[Optional[WfExSPassphraseGenerator]]" = None

    @classmethod
    def GetPassGen(cls) -> "WfExSPassphraseGenerator":
        if cls._PassGen is None:
            cls._PassGen = WfExSPassGenSingleton()
            assert cls._PassGen is not None

        return cls._PassGen

    @classmethod
    def generate_passphrase(cls) -> "str":
        return cls.GetPassGen().generate_passphrase_random(
            passphrase_length=cls.DEFAULT_PASSPHRASE_LENGTH
        )

    @classmethod
    def bootstrap(
        cls,
        local_config_ro: "WfExSConfigBlock",
        config_directory: "Optional[AnyPath]" = None,
        key_prefix: "Optional[str]" = None,
    ) -> "Tuple[bool, WfExSConfigBlock]":
        """
        :param local_config: Relevant local configuration, like the cache directory.
        :param config_directory: The filename to be used to resolve relative paths
        :param key_prefix: Prefix for the files of newly generated key pairs
        :type local_config: dict
        """

        import socket

        logger = logging.getLogger(cls.__name__)

        updated = False

        local_config = cast("WritableWfExSConfigBlock", copy.deepcopy(local_config_ro))

        # Getting the config directory
        if config_directory is None:
            config_directory = cast("AbsPath", os.getcwd())
        if not os.path.isabs(config_directory):
            config_directory = cast("AbsPath", os.path.abspath(config_directory))

        if key_prefix is None:
            key_prefix = ""

        # This one is to assure the working directory is created
        workDir = local_config.get("workDir")
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
                fname = key_prefix + "." + elem
                crypt4ghSect[elem] = fname
                updated = True

            if not os.path.isabs(fname):
                fname = os.path.normpath(os.path.join(config_directory, fname))

            if os.path.exists(fname):
                if os.path.getsize(fname) == 0:
                    logger.warning(
                        "[WARNING] Installation {} file {} is empty".format(elem, fname)
                    )
                else:
                    numExist += 1
            else:
                logger.warning(
                    "[WARNING] Installation {} file {} does not exist".format(
                        elem, fname
                    )
                )

        if numExist == 1:
            raise WfExSBackendException(
                "Inconsistent {} section, as one of the keys is missing".format(
                    cls.CRYPT4GH_SECTION
                )
            )

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

            comment = "WfExS crypt4gh keys {} {} {}".format(
                socket.gethostname(),
                config_directory,
                datetime.datetime.now().isoformat(),
            )

            # This is a way to avoid encoding private keys with scrypt,
            # which is not supported in every Python interpreter
            orig_scrypt_supported = crypt4gh.keys.c4gh.scrypt_supported
            crypt4gh.keys.c4gh.scrypt_supported = False
            try:
                crypt4gh.keys.c4gh.generate(
                    privKey,
                    pubKey,
                    passphrase=passphrase.encode("utf-8"),
                    comment=comment.encode("utf-8"),
                )
            finally:
                crypt4gh.keys.c4gh.scrypt_supported = orig_scrypt_supported
        elif not crypt4gh.keys.c4gh.scrypt_supported:
            logger.info(
                "Python interpreter does not support scrypt, so encoded crypt4gh keys with that algorithm cannot be used"
            )

        return updated, local_config

    @classmethod
    def FromDescription(
        cls,
        workflow_meta: "WorkflowMetaConfigBlock",
        local_config: "WfExSConfigBlock",
        vault: "Optional[SecurityContextVault]" = None,
        config_directory: "Optional[AnyPath]" = None,
        public_key_filenames: "Sequence[AnyPath]" = [],
        private_key_filename: "Optional[AnyPath]" = None,
        private_key_passphrase: "Optional[str]" = None,
    ) -> "WF":
        """

        :param workflow_meta: The configuration describing both the workflow
        and the inputs to use when it is being instantiated.
        :param local_config: Relevant local configuration, like the cache directory.
        :param config_directory:
        :type workflow_meta: dict
        :type local_config: dict
        :type config_directory:
        :return: Workflow configuration
        """
        warnings.warn(
            "fromDescription is being deprecated",
            PendingDeprecationWarning,
            stacklevel=2,
        )

        _, updated_local_config = cls.bootstrap(
            local_config, config_directory=config_directory
        )

        return cls(updated_local_config, config_directory=config_directory).newSetup(
            workflow_meta["workflow_id"],
            workflow_meta.get("version"),
            descriptor_type=workflow_meta.get("workflow_type"),
            trs_endpoint=workflow_meta.get("trs_endpoint", WF.DEFAULT_TRS_ENDPOINT),
            params=workflow_meta.get("params", {}),
            environment=workflow_meta.get("environment", {}),
            outputs=workflow_meta.get("outputs", {}),
            default_actions=workflow_meta.get("default_actions", []),
            workflow_config=workflow_meta.get("workflow_config"),
            vault=vault,
            public_key_filenames=public_key_filenames,
            private_key_filename=private_key_filename,
            private_key_passphrase=private_key_passphrase,
        )

    def __init__(
        self,
        local_config: "Optional[WfExSConfigBlock]" = None,
        config_directory: "Optional[AnyPath]" = None,
    ):
        """
        Init function

        :param local_config: Local setup configuration, telling where caching directories live
        :type local_config: dict
        """
        # Getting a logger focused on specific classes
        self.logger = logging.getLogger(
            dict(inspect.getmembers(self))["__module__"]
            + "::"
            + self.__class__.__name__
        )

        if not isinstance(local_config, dict):
            local_config = {}

        # validate the local configuration object
        valErrors = config_validate(local_config, self.CONFIG_SCHEMA)
        if len(valErrors) > 0:
            self.logger.error(f"ERROR in local configuration block: {valErrors}")
            sys.exit(1)

        self.local_config = local_config
        # This is an updatable copy, as it is going to be augmented
        # through the needs of the stateful fetchers
        self.progs: "ProgsMapping" = copy.copy(DEFAULT_PROGS)

        toolSect = local_config.get("tools", {})
        # Populating paths
        for keyC, pathC in toolSect.items():
            # Skipping what this section is not going to manage and store
            if keyC.endswith("Command") and not keyC.startswith("static"):
                progKey = keyC[0 : -len("Command")]
                abs_cmd = shutil.which(pathC)
                if abs_cmd is None:
                    self.logger.critical(
                        f'{progKey} command {pathC}, could not be reached relatively or through PATH {os.environ["PATH"]} (core: {progKey in self.progs})'
                    )
                else:
                    self.logger.info(
                        f"Setting up {progKey} to {abs_cmd} (derived from {pathC}) (core: {progKey in self.progs})"
                    )
                    self.progs[progKey] = cast("AbsPath", abs_cmd)

        encfsSect = toolSect.get("encrypted_fs", {})
        encfs_type = encfsSect.get("type", DEFAULT_ENCRYPTED_FS_TYPE)
        try:
            encfs_type = EncryptedFSType(encfs_type)
        except:
            raise WfExSBackendException(
                "Invalid default encryption filesystem {}".format(encfs_type)
            )
        if encfs_type not in ENCRYPTED_FS_MOUNT_IMPLEMENTATIONS:
            raise WfExSBackendException(
                "FIXME: Default encryption filesystem {} mount procedure is not implemented"
            )
        self.encfs_type = encfs_type

        self.encfs_cmd = encfsSect.get(
            "command", DEFAULT_ENCRYPTED_FS_CMD[self.encfs_type]
        )
        abs_encfs_cmd = shutil.which(self.encfs_cmd)
        if abs_encfs_cmd is None:
            self.logger.error(
                f"FUSE filesystem command {self.encfs_cmd} not found. Please install it if you are going to use a secured staged workdir"
            )
        else:
            self.encfs_cmd = abs_encfs_cmd

        self.fusermount_cmd = cast(
            "AnyPath", encfsSect.get("fusermount_command", DEFAULT_FUSERMOUNT_CMD)
        )
        abs_fusermount_cmd = shutil.which(self.fusermount_cmd)
        if abs_fusermount_cmd is None:
            self.logger.error(
                f"FUSE fusermount command {self.fusermount_cmd} not found"
            )
        else:
            self.fusermount_cmd = cast("AbsPath", abs_fusermount_cmd)

        self.progs[DEFAULT_FUSERMOUNT_CMD] = self.fusermount_cmd
        self.encfs_idleMinutes = encfsSect.get(
            "idle", DEFAULT_ENCRYPTED_FS_IDLE_TIMEOUT
        )

        # Getting the config directory, needed for relative filenames
        if config_directory is None:
            config_directory = cast("AbsPath", os.getcwd())
        if not os.path.isabs(config_directory):
            config_directory = cast("AbsPath", os.path.abspath(config_directory))

        self.config_directory = config_directory

        # Getting the private and public keys, needed from this point
        crypt4ghSect = local_config.get(self.CRYPT4GH_SECTION, {})
        privKeyFilename = crypt4ghSect[self.CRYPT4GH_PRIVKEY_KEY]
        if not os.path.isabs(privKeyFilename):
            privKeyFilename = os.path.normpath(
                os.path.join(config_directory, privKeyFilename)
            )
        pubKeyFilename = crypt4ghSect[self.CRYPT4GH_PUBKEY_KEY]
        if not os.path.isabs(pubKeyFilename):
            pubKeyFilename = os.path.normpath(
                os.path.join(config_directory, pubKeyFilename)
            )
        passphrase = crypt4ghSect[self.CRYPT4GH_PASSPHRASE_KEY]

        # These are the keys to be used
        self.pubKey = crypt4gh.keys.get_public_key(pubKeyFilename)
        self.privKey = crypt4gh.keys.get_private_key(
            privKeyFilename, lambda: passphrase
        )

        # This directory will be used to cache repositories and distributable inputs
        cacheDir = local_config.get("cacheDir")
        if cacheDir:
            if not os.path.isabs(cacheDir):
                cacheDir = os.path.normpath(os.path.join(config_directory, cacheDir))
            os.makedirs(cacheDir, exist_ok=True)
        else:
            cacheDir = tempfile.mkdtemp(prefix="WfExS", suffix="backend")
            # Assuring this temporal directory is removed at the end
            atexit.register(shutil.rmtree, cacheDir)

        # Setting up caching directories
        self.cacheDir = cacheDir
        self.cachePathMap: "MutableMapping[str, AbsPath]" = dict()
        cacheWorkflowDir = cast("AbsPath", os.path.join(cacheDir, "wf-cache"))
        os.makedirs(cacheWorkflowDir, exist_ok=True)
        self.cachePathMap[CacheType.Workflow] = cacheWorkflowDir

        cacheROCrateDir = cast("AbsPath", os.path.join(cacheDir, "ro-crate-cache"))
        os.makedirs(cacheROCrateDir, exist_ok=True)
        self.cachePathMap[CacheType.ROCrate] = cacheROCrateDir

        cacheTRSFilesDir = cast("AbsPath", os.path.join(cacheDir, "trs-files-cache"))
        os.makedirs(cacheTRSFilesDir, exist_ok=True)
        self.cachePathMap[CacheType.TRS] = cacheTRSFilesDir

        cacheWorkflowInputsDir = cast("AbsPath", os.path.join(cacheDir, "wf-inputs"))
        os.makedirs(cacheWorkflowInputsDir, exist_ok=True)
        self.cachePathMap[CacheType.Input] = cacheWorkflowInputsDir

        # This directory will be used to store the intermediate
        # and final results before they are sent away
        baseWorkDir = local_config.get("workDir")
        if baseWorkDir:
            if not os.path.isabs(baseWorkDir):
                baseWorkDir = os.path.normpath(
                    os.path.join(config_directory, baseWorkDir)
                )
            os.makedirs(baseWorkDir, exist_ok=True)
        else:
            baseWorkDir = tempfile.mkdtemp(prefix="WfExS-workdir", suffix="backend")
            # Assuring this temporal directory is removed at the end
            atexit.register(shutil.rmtree, baseWorkDir)

        self.baseWorkDir = baseWorkDir
        self.defaultParanoidMode = False

        # cacheHandler is created on first use
        self._sngltn: "MutableMapping[Type[AbstractStatefulFetcher], AbstractStatefulFetcher]" = (
            dict()
        )
        self.cacheHandler = SchemeHandlerCacheHandler(self.cacheDir)

        fetchers_setup_block = local_config.get("fetchers-setup")
        # All the custom ones should be added here
        self.addSchemeHandlers(PRIDE_SCHEME_HANDLERS, fetchers_setup_block)
        self.addSchemeHandlers(DRS_SCHEME_HANDLERS, fetchers_setup_block)
        self.addSchemeHandlers(INTERNAL_TRS_SCHEME_HANDLERS, fetchers_setup_block)
        self.addSchemeHandlers(S3_SCHEME_HANDLERS, fetchers_setup_block)
        self.addSchemeHandlers(GS_SCHEME_HANDLERS, fetchers_setup_block)
        self.addStatefulSchemeHandlers(FASPFetcher, fetchers_setup_block)

        self.addSchemeHandlers(DOI_SCHEME_HANDLERS, fetchers_setup_block)
        self.addSchemeHandlers(ZENODO_SCHEME_HANDLERS, fetchers_setup_block)

        self.addSchemeHandlers(B2SHARE_SCHEME_HANDLERS, fetchers_setup_block)
        self.addSchemeHandlers(OSF_IO_SCHEME_HANDLERS, fetchers_setup_block)

        # These ones should have prevalence over other custom ones
        self.addStatefulSchemeHandlers(GitFetcher, fetchers_setup_block)
        self.addStatefulSchemeHandlers(SoftwareHeritageFetcher, fetchers_setup_block)
        self.addSchemeHandlers(HTTP_SCHEME_HANDLERS, fetchers_setup_block)
        self.addSchemeHandlers(FTP_SCHEME_HANDLERS, fetchers_setup_block)
        self.addSchemeHandlers(SFTP_SCHEME_HANDLERS, fetchers_setup_block)
        self.addSchemeHandlers(FILE_SCHEME_HANDLERS, fetchers_setup_block)
        self.addSchemeHandlers(DATA_SCHEME_HANDLERS, fetchers_setup_block)

        # Registry of export plugins is created here
        self._export_plugins: "MutableMapping[SymbolicName, Type[AbstractExportPlugin]]" = (
            dict()
        )
        self.addExportPlugin(CacheExportPlugin)
        self.addExportPlugin(NextcloudExportPlugin)

    @property
    def cacheWorkflowDir(self) -> "AbsPath":
        return self.cachePathMap[CacheType.Workflow]

    @property
    def cacheROCrateDir(self) -> "AbsPath":
        return self.cachePathMap[CacheType.ROCrate]

    @property
    def cacheTRSFilesDir(self) -> "AbsPath":
        return self.cachePathMap[CacheType.TRS]

    @property
    def cacheWorkflowInputsDir(self) -> "AbsPath":
        return self.cachePathMap[CacheType.Input]

    def getCacheHandler(
        self, cache_type: "CacheType"
    ) -> "Tuple[SchemeHandlerCacheHandler, Optional[AbsPath]]":
        return self.cacheHandler, self.cachePathMap.get(cache_type)

    def instantiateStatefulFetcher(
        self,
        statefulFetcher: "Type[StatefulFetcher]",
        setup_block: "Optional[Mapping[str, Any]]" = None,
    ) -> "StatefulFetcher":
        """
        Method to instantiate stateful fetchers once
        """
        instStatefulFetcher = self._sngltn.get(statefulFetcher)
        if instStatefulFetcher is None:
            # Setting the default list of programs
            for prog in statefulFetcher.GetNeededPrograms():
                self.progs.setdefault(prog, cast("RelPath", prog))
            # Let's augment the list of needed progs by this
            # stateful fetcher
            instStatefulFetcher = self.cacheHandler.instantiateStatefulFetcher(
                statefulFetcher, progs=self.progs, setup_block=setup_block
            )
            self._sngltn[statefulFetcher] = instStatefulFetcher

        return cast("StatefulFetcher", instStatefulFetcher)

    def addExportPlugin(self, exportClazz: "Type[AbstractExportPlugin]") -> None:
        self._export_plugins[exportClazz.PluginName()] = exportClazz

    def listExportPluginNames(self) -> "Sequence[SymbolicName]":
        return list(self._export_plugins.keys())

    def getExportPluginClass(
        self, plugin_id: "SymbolicName"
    ) -> "Optional[Type[AbstractExportPlugin]]":
        return self._export_plugins.get(plugin_id)

    def addStatefulSchemeHandlers(
        self,
        statefulSchemeHandler: "Type[AbstractStatefulFetcher]",
        fetchers_setup_block: "Optional[Mapping[str, Mapping[str, Any]]]" = None,
    ) -> None:
        """
        This method adds scheme handlers (aka "fetchers") from
        a given stateful fetcher, also adding the needed programs
        """

        # Get the scheme handlers from this fetcher
        schemeHandlers = statefulSchemeHandler.GetSchemeHandlers()

        self.addSchemeHandlers(
            schemeHandlers, fetchers_setup_block=fetchers_setup_block
        )

    # This pattern is used to validate the schemes
    SCHEME_PAT: "Final[Pattern[str]]" = re.compile(r"^[a-zA-Z][a-zA-Z0-9+.-]*$")

    def addSchemeHandlers(
        self,
        schemeHandlers: "Mapping[str, Union[DocumentedProtocolFetcher, DocumentedStatefulProtocolFetcher]]",
        fetchers_setup_block: "Optional[Mapping[str, Mapping[str, Any]]]" = None,
    ) -> None:
        """
        This method adds scheme handlers (aka "fetchers")
        or instantiates stateful scheme handlers (aka "stateful fetchers")
        """
        if isinstance(schemeHandlers, dict):
            instSchemeHandlers = dict()
            if fetchers_setup_block is None:
                fetchers_setup_block = dict()
            for scheme, schemeHandler in schemeHandlers.items():
                if self.SCHEME_PAT.search(scheme) is None:
                    self.logger.warning(
                        f"Fetcher associated to scheme {scheme} has been skipped, as the scheme does not comply with RFC3986"
                    )
                    continue

                lScheme = scheme.lower()
                # When no setup block is available for the scheme fetcher,
                # provide an empty one
                setup_block = fetchers_setup_block.get(lScheme, dict())

                instSchemeHandler = None
                if isinstance(schemeHandler, DocumentedStatefulProtocolFetcher):
                    instSchemeInstance = self.instantiateStatefulFetcher(
                        schemeHandler.fetcher_class, setup_block=setup_block
                    )
                    if instSchemeInstance is not None:
                        instSchemeHandler = DocumentedProtocolFetcher(
                            fetcher=instSchemeInstance.fetch,
                            description=instSchemeInstance.description
                            if schemeHandler.description is None
                            else schemeHandler.description,
                            priority=schemeHandler.priority,
                        )
                elif isinstance(schemeHandler, DocumentedProtocolFetcher) and callable(
                    schemeHandler.fetcher
                ):
                    instSchemeHandler = schemeHandler

                # Only the ones which have overcome the sanity checks
                if instSchemeHandler is not None:
                    # Schemes are case insensitive, so register only
                    # the lowercase version
                    instSchemeHandlers[lScheme] = instSchemeHandler

            self.cacheHandler.addRawSchemeHandlers(instSchemeHandlers)

    def describeFetchableSchemes(self) -> "Sequence[Tuple[str, str, int]]":
        return self.cacheHandler.describeRegisteredSchemes()

    def newSetup(
        self,
        workflow_id: "WorkflowId",
        version_id: "Optional[WFVersionId]" = None,
        descriptor_type: "Optional[TRS_Workflow_Descriptor]" = None,
        trs_endpoint: "str" = WF.DEFAULT_TRS_ENDPOINT,
        params: "Optional[ParamsBlock]" = None,
        environment: "Optional[EnvironmentBlock]" = None,
        outputs: "Optional[OutputsBlock]" = None,
        default_actions: "Optional[Sequence[ExportActionBlock]]" = None,
        workflow_config: "Optional[WorkflowConfigBlock]" = None,
        vault: "Optional[SecurityContextVault]" = None,
        public_key_filenames: "Sequence[AnyPath]" = [],
        private_key_filename: "Optional[AnyPath]" = None,
        private_key_passphrase: "Optional[str]" = None,
    ) -> "WF":
        """
        Init function, which delegates on WF class
        """
        return WF(
            wfexs=self,
            workflow_id=workflow_id,
            version_id=version_id,
            descriptor_type=descriptor_type,
            trs_endpoint=trs_endpoint,
            params=params,
            environment=environment,
            outputs=outputs,
            default_actions=default_actions,
            workflow_config=workflow_config,
            vault=vault,
            public_key_filenames=public_key_filenames,
            private_key_filename=private_key_filename,
            private_key_passphrase=private_key_passphrase,
        )

    def createRawWorkDir(
        self,
        nickname_prefix: "Optional[str]" = None,
        orcids: "Sequence[str]" = [],
    ) -> "Tuple[WfExSInstanceId, str, datetime.datetime, Sequence[str], AbsPath]":
        """
        This method creates a new, empty, raw working directory
        """
        instanceId = cast("WfExSInstanceId", str(uuid.uuid4()))
        if nickname_prefix is None:
            nickname = self.GetPassGen().generate_nickname()
        else:
            nickname = nickname_prefix + self.GetPassGen().generate_nickname()

        return self.getOrCreateRawWorkDirFromInstanceId(
            instanceId, nickname=nickname, orcids=orcids, create_ok=True
        )

    def getOrCreateRawWorkDirFromInstanceId(
        self,
        instanceId: "WfExSInstanceId",
        nickname: "Optional[str]" = None,
        orcids: "Sequence[str]" = [],
        create_ok: "bool" = False,
    ) -> "Tuple[WfExSInstanceId, str, datetime.datetime, Sequence[str], AbsPath]":
        """
        This method returns the absolute path to the raw working directory
        """
        # TODO: Add some validation about the working directory
        uniqueRawWorkDir = cast("AbsPath", os.path.join(self.baseWorkDir, instanceId))

        return self.parseOrCreateRawWorkDir(
            uniqueRawWorkDir, instanceId, nickname, orcids=orcids, create_ok=create_ok
        )

    def parseOrCreateRawWorkDir(
        self,
        uniqueRawWorkDir: "AbsPath",
        instanceId: "Optional[WfExSInstanceId]" = None,
        nickname: "Optional[str]" = None,
        orcids: "Sequence[str]" = [],
        create_ok: "bool" = False,
    ) -> "Tuple[WfExSInstanceId, str, datetime.datetime, Sequence[str], AbsPath]":
        """
        This method returns the absolute path to the raw working directory
        """
        # TODO: Add some validation about the working directory
        id_json_path = os.path.join(uniqueRawWorkDir, self.ID_JSON_FILENAME)
        creation: "Optional[datetime.datetime]"
        if not os.path.exists(uniqueRawWorkDir):
            if not create_ok:
                raise WfExSBackendException(
                    f"Creation of {uniqueRawWorkDir} is not allowed by parameter"
                )

            os.makedirs(uniqueRawWorkDir, exist_ok=True)
            if instanceId is None:
                instanceId = cast("WfExSInstanceId", os.path.basename(uniqueRawWorkDir))
            if nickname is None:
                nickname = self.GetPassGen().generate_nickname()
            creation = datetime.datetime.now(tz=datetime.timezone.utc)
            with open(id_json_path, mode="w", encoding="utf-8") as idF:
                idNick = {
                    "instance_id": instanceId,
                    "nickname": nickname,
                    "creation": creation,
                    "orcids": orcids,
                }
                json.dump(idNick, idF, cls=DatetimeEncoder)
            os.chmod(id_json_path, stat.S_IRUSR | stat.S_IRGRP | stat.S_IROTH)
        elif os.path.exists(id_json_path):
            with open(id_json_path, mode="r", encoding="utf-8") as iH:
                idNick = jsonFilterDecodeFromStream(iH)
                instanceId = cast("WfExSInstanceId", idNick["instance_id"])
                nickname = cast("str", idNick.get("nickname", instanceId))
                creation = cast("Optional[datetime.datetime]", idNick.get("creation"))
                orcids = cast("Sequence[str]", idNick.get("orcids", []))

            # This file should not change
            if creation is None:
                creation = datetime.datetime.fromtimestamp(
                    os.path.getctime(id_json_path), tz=datetime.timezone.utc
                )
        else:
            instanceId = cast("WfExSInstanceId", os.path.basename(uniqueRawWorkDir))
            nickname = instanceId
            creation = None
            orcids = []

        if creation is None:
            # Just guessing
            w_m_path = os.path.join(
                uniqueRawWorkDir, WORKDIR_META_RELDIR, WORKDIR_WORKFLOW_META_FILE
            )
            workdir_passphrase_file = os.path.join(
                uniqueRawWorkDir, WORKDIR_PASSPHRASE_FILE
            )
            if os.path.exists(w_m_path):
                # This is valid for unencrypted working directories
                reference_path = w_m_path
            elif os.path.exists(workdir_passphrase_file):
                # This is valid for encrypted working directories
                reference_path = workdir_passphrase_file
            else:
                # This is the poor default
                reference_path = uniqueRawWorkDir

            creation = datetime.datetime.fromtimestamp(
                os.path.getctime(reference_path), tz=datetime.timezone.utc
            )

        return instanceId, nickname, creation, orcids, uniqueRawWorkDir

    def normalizeRawWorkingDirectory(
        self, uniqueRawWorkDir: "AnyPath"
    ) -> "Tuple[WfExSInstanceId, str, datetime.datetime, Sequence[str], AbsPath]":
        """
        This method returns the id of a working directory,
        as well as the nickname
        """
        if uniqueRawWorkDir is None:
            raise WfExSBackendException("Unable to initialize, no directory provided")

        # Obtaining the absolute path to the working directory
        if not os.path.isabs(uniqueRawWorkDir):
            uniqueRawWorkDir = cast(
                "AbsPath",
                os.path.normpath(os.path.join(self.baseWorkDir, uniqueRawWorkDir)),
            )

        if not os.path.isdir(uniqueRawWorkDir):
            raise WfExSBackendException(
                "Unable to initialize, {} is not a directory".format(uniqueRawWorkDir)
            )

        return self.parseOrCreateRawWorkDir(
            cast("AbsPath", uniqueRawWorkDir), create_ok=False
        )

    def fromWorkDir(
        self,
        workflowWorkingDirectory: "AnyPath",
        private_key_filename: "Optional[AnyPath]" = None,
        private_key_passphrase: "Optional[str]" = None,
        fail_ok: "bool" = False,
    ) -> "WF":
        return WF.FromWorkDir(
            self,
            workflowWorkingDirectory,
            private_key_filename=private_key_filename,
            private_key_passphrase=private_key_passphrase,
            fail_ok=fail_ok,
        )

    def getDefaultParanoidMode(self) -> "bool":
        return self.defaultParanoidMode

    def enableDefaultParanoidMode(self) -> None:
        self.defaultParanoidMode = True

    def fromFiles(
        self,
        workflowMetaFilename: "AnyPath",
        securityContextsConfigFilename: "Optional[AnyPath]" = None,
        nickname_prefix: "Optional[str]" = None,
        orcids: "Sequence[str]" = [],
        public_key_filenames: "Sequence[AnyPath]" = [],
        private_key_filename: "Optional[AnyPath]" = None,
        private_key_passphrase: "Optional[str]" = None,
        paranoidMode: "bool" = False,
    ) -> "WF":
        return WF.FromFiles(
            self,
            workflowMetaFilename,
            securityContextsConfigFilename=securityContextsConfigFilename,
            nickname_prefix=nickname_prefix,
            orcids=orcids,
            public_key_filenames=public_key_filenames,
            private_key_filename=private_key_filename,
            private_key_passphrase=private_key_passphrase,
            paranoidMode=paranoidMode,
        )

    def fromPreviousInstanceDeclaration(
        self,
        wfInstance: "WF",
        securityContextsConfigFilename: "Optional[AnyPath]" = None,
        nickname_prefix: "Optional[str]" = None,
        orcids: "Sequence[str]" = [],
        public_key_filenames: "Sequence[AnyPath]" = [],
        private_key_filename: "Optional[AnyPath]" = None,
        private_key_passphrase: "Optional[str]" = None,
        paranoidMode: "bool" = False,
    ) -> "WF":
        return WF.FromPreviousInstanceDeclaration(
            self,
            wfInstance,
            securityContextsConfigFilename=securityContextsConfigFilename,
            nickname_prefix=nickname_prefix,
            orcids=orcids,
            public_key_filenames=public_key_filenames,
            private_key_filename=private_key_filename,
            private_key_passphrase=private_key_passphrase,
            paranoidMode=paranoidMode,
        )

    def parseAndValidateSecurityContextFile(
        self, securityContextsConfigFilename: "AnyPath"
    ) -> "Tuple[ExitVal, SecurityContextConfigBlock]":
        numErrors = 0
        self.logger.info(f"Validating {securityContextsConfigFilename}")

        creds_config, valErrors = SecurityContextVault.ReadSecurityContextFile(
            securityContextsConfigFilename
        )

        if len(valErrors) == 0:
            self.logger.info("No validation errors in security block")
        else:
            for iErr, valError in enumerate(valErrors):
                self.logger.error(f"ERROR {iErr} in security context block: {valError}")
                numErrors += 1

        return cast("ExitVal", numErrors), creds_config

    def validateConfigFiles(
        self,
        workflowMetaFilename: "AnyPath",
        securityContextsConfigFilename: "Optional[AnyPath]" = None,
    ) -> "ExitVal":
        numErrors = 0
        self.logger.info(f"Validating {workflowMetaFilename}")

        with open(workflowMetaFilename, mode="r", encoding="utf-8") as wcf:
            workflow_meta = unmarshall_namedtuple(yaml.safe_load(wcf))

        if not isinstance(workflow_meta, dict):
            workflow_meta = {}

        valErrors = config_validate(workflow_meta, WF.STAGE_DEFINITION_SCHEMA)
        if len(valErrors) == 0:
            self.logger.info("No validation errors in staging definition block")
        else:
            for iErr, valError in enumerate(valErrors):
                self.logger.error(
                    f"ERROR {iErr} in staging definition block: {valError}"
                )
                numErrors += 1

        # Last, try loading the security contexts credentials file
        if securityContextsConfigFilename and os.path.exists(
            securityContextsConfigFilename
        ):
            numErrors_sec, _ = self.parseAndValidateSecurityContextFile(
                securityContextsConfigFilename
            )
            numErrors += numErrors_sec

        return cast("ExitVal", 1 if numErrors > 0 else 0)

    def fromDescription(
        self,
        workflow_meta: "WorkflowMetaConfigBlock",
        vault: "Optional[SecurityContextVault]" = None,
        orcids: "Sequence[str]" = [],
        public_key_filenames: "Sequence[AnyPath]" = [],
        private_key_filename: "Optional[AnyPath]" = None,
        private_key_passphrase: "Optional[str]" = None,
        paranoidMode: "bool" = False,
    ) -> "WF":
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
        warnings.warn(
            "fromDescription is being deprecated",
            PendingDeprecationWarning,
            stacklevel=2,
        )

        return WF.FromDescription(
            self,
            workflow_meta,
            SecurityContextVault() if vault is None else vault,
            orcids=orcids,
            public_key_filenames=public_key_filenames,
            private_key_filename=private_key_filename,
            private_key_passphrase=private_key_passphrase,
            paranoidMode=paranoidMode,
        )

    def fromForm(
        self,
        workflow_meta: "WorkflowMetaConfigBlock",
        orcids: "Sequence[str]" = [],
        public_key_filenames: "Sequence[AnyPath]" = [],
        private_key_filename: "Optional[AnyPath]" = None,
        paranoidMode: "bool" = False,
    ) -> "WF":
        """
        Method mainly used by OpenVRE deployment in iPC

        :param workflow_meta: The configuration describing both the workflow
        and the inputs to use when it is being instantiated.
        :param paranoidMode:
        :type workflow_meta: dict
        :type paranoidMode:
        :return: Workflow configuration
        """
        return WF.FromForm(
            self,
            workflow_meta,
            orcids=orcids,
            public_key_filenames=public_key_filenames,
            private_key_filename=private_key_filename,
            paranoidMode=paranoidMode,
        )

    def getFusermountParams(self) -> "Tuple[AnyPath, int]":
        return self.fusermount_cmd, self.encfs_idleMinutes

    def readSecuredWorkdirPassphrase(
        self,
        workdir_passphrase_file: "AbsPath",
        private_key_filename: "Optional[AnyPath]" = None,
        private_key_passphrase: "Optional[str]" = None,
    ) -> "Tuple[EncryptedFSType, AnyPath, str]":
        """
        This method decrypts a crypt4gh file containing a passphrase
        which has been encrypted with either the WfExS installation
        public key (if the filename is not provided), or the public key
        paired with the provided private key stored in the file.
        """
        clearF = io.BytesIO()
        if private_key_filename is None:
            private_key = self.privKey
        else:
            if private_key_passphrase is None:
                private_key_passphrase_r = ""
            else:
                private_key_passphrase_r = private_key_passphrase
            assert private_key_passphrase is not None
            private_key = crypt4gh.keys.get_private_key(
                private_key_filename, lambda: private_key_passphrase_r
            )

        with open(workdir_passphrase_file, mode="rb") as encF:
            crypt4gh.lib.decrypt(
                [(0, private_key, None)],
                encF,
                clearF,
                offset=0,
                span=None,
                sender_pubkey=None,
            )

        encfs_type_str, _, secureWorkdirPassphrase = (
            clearF.getvalue().decode("utf-8").partition("=")
        )
        del clearF
        self.logger.debug(encfs_type_str + " " + secureWorkdirPassphrase)
        try:
            encfs_type = EncryptedFSType(encfs_type_str)
        except:
            raise WfExSBackendException(
                "Invalid encryption filesystem {} in working directory".format(
                    encfs_type_str
                )
            )
        if encfs_type not in ENCRYPTED_FS_MOUNT_IMPLEMENTATIONS:
            raise WfExSBackendException(
                "FIXME: Encryption filesystem {} mount procedure is not implemented"
            )

        # If the working directory encrypted filesystem does not
        # match the configured one, use its default executable
        if encfs_type != self.encfs_type:
            encfs_cmd = DEFAULT_ENCRYPTED_FS_CMD[encfs_type]
        else:
            encfs_cmd = self.encfs_cmd

        if secureWorkdirPassphrase == "":
            raise WfExSBackendException(
                "Encryption filesystem key does not follow the right format"
            )

        return encfs_type, encfs_cmd, secureWorkdirPassphrase

    def generateSecuredWorkdirPassphrase(
        self,
        workdir_passphrase_file: "AbsPath",
        private_key_filename: "Optional[AnyPath]" = None,
        private_key_passphrase: "Optional[str]" = None,
        public_key_filenames: "Sequence[AnyPath]" = [],
    ) -> "Tuple[EncryptedFSType, AnyPath, str, Sequence[AnyPath]]":
        """
        This method generates a random passphrase, which is stored
        in a crypt4gh encrypted file (along with the FUSE filesystem used)
        using either the default WfExS-backend public key, or the public
        keys stored in the files provided as a parameter.
        It returns the FUSE filesystem, the command to be used to mount,
        the generated passphrase (to be consumed in memory) and the list
        of public keys used to encrypt the passphrase file,
        which can be used later for some additional purposes.
        """
        secureWorkdirPassphrase = self.generate_passphrase()
        clearF = io.BytesIO(
            (self.encfs_type.value + "=" + secureWorkdirPassphrase).encode("utf-8")
        )
        if private_key_filename is None:
            private_key = self.privKey
        else:
            if private_key_passphrase is None:
                private_key_passphrase_r = ""
            else:
                private_key_passphrase_r = private_key_passphrase
            assert private_key_passphrase is not None
            private_key = crypt4gh.keys.get_private_key(
                private_key_filename, lambda: private_key_passphrase_r
            )

        public_keys: "MutableSequence[bytes]" = []
        if len(public_key_filenames) == 0:
            if private_key_filename is not None:
                raise WfExSBackendException(
                    "When a custom private key is provided, at least the public key paired with it must also be provided"
                )
            public_keys = [self.pubKey]
        else:
            for pub_key_filename in public_key_filenames:
                pub_key = crypt4gh.keys.get_public_key(pub_key_filename)
                public_keys.append(pub_key)

        encrypt_keys: "MutableSequence[CompoundKey]" = []
        for pub_key in public_keys:
            encrypt_keys.append((0, private_key, pub_key))
        with open(workdir_passphrase_file, mode="wb") as encF:
            crypt4gh.lib.encrypt(encrypt_keys, clearF, encF, offset=0, span=None)
        del clearF

        return (
            self.encfs_type,
            self.encfs_cmd,
            secureWorkdirPassphrase,
            public_key_filenames,
        )

    def listStagedWorkflows(
        self,
        *args: "str",
        acceptGlob: "bool" = False,
        doCleanup: "bool" = True,
        private_key_filename: "Optional[AnyPath]" = None,
        private_key_passphrase: "Optional[str]" = None,
    ) -> "Iterator[Tuple[WfExSInstanceId, str, datetime.datetime, Optional[StagedSetup], Optional[WF]]]":
        # Removing duplicates
        entries: "Set[str]" = set(args)
        if entries and acceptGlob:
            reEntries = translate_glob_args(list(entries))
        else:
            reEntries = None

        with os.scandir(self.baseWorkDir) as swD:
            for entry in swD:
                # Avoiding loops
                if entry.is_dir(follow_symlinks=False) and not entry.name.startswith(
                    "."
                ):
                    try:
                        (
                            instanceId,
                            nickname,
                            creation,
                            orcids,  # TODO: give some use to this
                            instanceRawWorkdir,
                        ) = self.parseOrCreateRawWorkDir(entry.path, create_ok=False)
                    except:
                        self.logger.warning(f"Skipped {entry.name} on listing")
                        continue

                    if entries:
                        if reEntries:
                            if all(
                                map(
                                    lambda r: (r.match(instanceId) is None)
                                    and (r.match(nickname) is None),
                                    reEntries,
                                )
                            ):
                                continue
                        elif (instanceId not in entries) and (nickname not in entries):
                            continue

                    self.logger.debug(f"{instanceId} {nickname}")
                    isDamaged = False
                    isEncrypted = False
                    wfSetup = None
                    wfInstance = None
                    try:
                        wfInstance = self.fromWorkDir(
                            instanceRawWorkdir,
                            private_key_filename=private_key_filename,
                            private_key_passphrase=private_key_passphrase,
                            fail_ok=True,
                        )
                        try:
                            wfSetup = wfInstance.getStagedSetup()
                        except Exception as e:
                            self.logger.exception(
                                f"Something wrong with staged setup from {instanceId} ({nickname})"
                            )

                    except:
                        self.logger.exception(
                            f"Something wrong with workflow {instanceId} ({nickname})"
                        )

                    # Give a chance to work on the passed instance
                    yield instanceId, nickname, creation, wfSetup, wfInstance

                    # Should we force an unmount?
                    if doCleanup and (wfInstance is not None):
                        wfInstance.cleanup()
                        wfInstance = None

    def statusStagedWorkflows(
        self,
        *args: "str",
        acceptGlob: "bool" = False,
        private_key_filename: "Optional[AnyPath]" = None,
        private_key_passphrase: "Optional[str]" = None,
    ) -> "Iterator[Tuple[WfExSInstanceId, str, datetime.datetime, Optional[StagedSetup], Optional[MarshallingStatus]]]":
        if len(args) > 0:
            for (
                instance_id,
                nickname,
                creation,
                wfSetup,
                wfInstance,
            ) in self.listStagedWorkflows(
                *args,
                private_key_filename=private_key_filename,
                private_key_passphrase=private_key_passphrase,
                acceptGlob=acceptGlob,
                doCleanup=True,
            ):
                self.logger.debug(f"Status {instance_id} {nickname}")

                # This is needed to trigger the cascade of
                # state unmarshalling and validations
                if wfInstance is not None:
                    mStatus = wfInstance.getMarshallingStatus(reread_stats=True)

                yield instance_id, nickname, creation, wfSetup, mStatus

    def removeStagedWorkflows(
        self,
        *args: "str",
        acceptGlob: "bool" = False,
        private_key_filename: "Optional[AnyPath]" = None,
        private_key_passphrase: "Optional[str]" = None,
    ) -> "Iterator[Tuple[WfExSInstanceId, str]]":
        if len(args) > 0:
            for instance_id, nickname, creation, wfSetup, _ in self.listStagedWorkflows(
                *args,
                private_key_filename=private_key_filename,
                private_key_passphrase=private_key_passphrase,
                acceptGlob=acceptGlob,
                doCleanup=True,
            ):
                if wfSetup is not None:
                    self.logger.debug(f"Removing {instance_id} {nickname}")
                    shutil.rmtree(wfSetup.raw_work_dir, ignore_errors=True)
                    yield instance_id, nickname

    def shellFirstStagedWorkflow(
        self,
        *args: "str",
        stdin: "IO[str]" = sys.stdin,
        stdout: "IO[str]" = sys.stdout,
        stderr: "IO[str]" = sys.stderr,
        acceptGlob: "bool" = False,
        firstMatch: "bool" = True,
        private_key_filename: "Optional[AnyPath]" = None,
        private_key_passphrase: "Optional[str]" = None,
    ) -> "ExitVal":
        arg0 = []
        if len(args) > 0:
            if not firstMatch or args[0] != "":
                arg0.append(args[0])

        if len(args) > 1:
            command = cast("Sequence[str]", args[1:])
        else:
            command = [os.environ.get("SHELL", "/bin/sh")]

        listIter: "Union[Iterator[Tuple[WfExSInstanceId, str, datetime.datetime, Optional[StagedSetup], Optional[WF]]], Sequence[Tuple[WfExSInstanceId, str, datetime.datetime, StagedSetup, WF]]]" = self.listStagedWorkflows(
            *arg0,
            private_key_filename=private_key_filename,
            private_key_passphrase=private_key_passphrase,
            acceptGlob=acceptGlob,
            doCleanup=False,
        )

        # This is needed to implement the case of no working directory
        # and no command, so the latest is used, so avoiding to leave other mountpoints
        if firstMatch and len(arg0) == 0:
            listIterNew = []
            prev_creation: "Optional[datetime.datetime]" = None
            prev_wfInstance: "Optional[WF]" = None
            for (
                instance_id,
                nickname,
                creation,
                wfSetup,
                wfInstance,
            ) in listIter:
                if (wfSetup is not None) and (wfInstance is not None):
                    if (prev_creation is None) or creation > prev_creation:
                        listIterNew = [
                            (instance_id, nickname, creation, wfSetup, wfInstance)
                        ]
                        if prev_wfInstance is not None:
                            prev_wfInstance.cleanup()
                        prev_creation = creation
                        prev_wfInstance = wfInstance

                    if wfInstance != prev_wfInstance:
                        wfInstance.cleanup()

            listIter = listIterNew

        theEnv = dict(os.environ)
        retval = cast("ExitVal", -1)
        for (
            instance_id,
            nickname,
            creation,
            wfSetup,
            wfInstance,
        ) in listIter:
            # We are doing it only for the first non-corrupted match
            if (wfSetup is not None) and (wfInstance is not None):
                self.logger.info(f"Running {command} at {instance_id} ({nickname})")
                # Setting a custom symbol
                theEnv["PROMPT_COMMAND"] = f"echo \"(WfExS '{nickname}')\""
                theEnv["PROMPT_DIRTRIM"] = "2"

                cp = subprocess.run(
                    command,
                    cwd=wfSetup.work_dir,
                    stdin=stdin,
                    stdout=stdout,
                    stderr=stderr,
                    env=theEnv,
                )
                retval = cast("ExitVal", cp.returncode)
                wfInstance.cleanup()
                if firstMatch:
                    break
            else:
                self.logger.info(
                    f"Cannot run {command} at {instance_id} ({nickname}), as it is corrupted"
                )
        return retval

    def cacheFetch(
        self,
        remote_file: "Union[LicensedURI, parse.ParseResult, URIType, Sequence[LicensedURI], Sequence[parse.ParseResult], Sequence[URIType]]",
        cacheType: "CacheType",
        offline: "bool",
        ignoreCache: "bool" = False,
        registerInCache: "bool" = True,
        vault: "Optional[SecurityContextVault]" = None,
        sec_context_name: "Optional[str]" = None,
    ) -> "CachedContent":
        """
        This is a pass-through method to the cache handler, which translates from symbolic types of cache to their corresponding directories

        :param remote_file: The URI to be fetched (if not already cached)
        :param cacheType: The type of cache where to look up the URI
        :param offline: Is the instance working in offline mode?
        (i.e. raise exceptions when external content is needed)
        :param ignoreCache: Even if the content is cache, discard and re-fetch it
        :param registerInCache: Should the fetched content be registered
        in the cache?
        :param vault: The security context which has to be passed to
        the fetchers, in case they have to be used
        """
        if cacheType != CacheType.Workflow:
            return self.cacheHandler.fetch(
                remote_file,
                destdir=self.cachePathMap[cacheType],
                offline=offline,
                ignoreCache=ignoreCache,
                registerInCache=registerInCache,
                vault=vault,
                sec_context_name=sec_context_name,
            )
        else:
            workflow_dir, repo, _, effective_checkout = self.cacheWorkflow(
                workflow_id=cast("WorkflowId", remote_file),
                ignoreCache=ignoreCache,
                registerInCache=registerInCache,
                offline=offline,
            )
            return CachedContent(
                kind=ContentKind.Directory
                if os.path.isdir(workflow_dir)
                else ContentKind.File,
                path=workflow_dir,
                metadata_array=[],
                licences=tuple(),
            )

    def instantiateEngine(
        self, engineDesc: "WorkflowType", stagedSetup: "StagedSetup"
    ) -> "AbstractWorkflowEngineType":
        return engineDesc.clazz.FromStagedSetup(
            staged_setup=stagedSetup,
            cache_dir=self.cacheDir,
            cache_workflow_dir=self.cacheWorkflowDir,
            cache_workflow_inputs_dir=self.cacheWorkflowInputsDir,
            local_config=self.local_config,
            config_directory=self.config_directory,
        )

    def guess_repo_params(
        self,
        wf_url: "Union[URIType, parse.ParseResult]",
        fail_ok: "bool" = False,
    ) -> "Optional[RemoteRepo]":
        if isinstance(wf_url, parse.ParseResult):
            parsedRepoURL = wf_url
        else:
            parsedRepoURL = urllib.parse.urlparse(wf_url)

        remote_repo = guess_swh_repo_params(
            parsedRepoURL, logger=self.logger, fail_ok=fail_ok
        )
        if remote_repo is None:
            # Assume it might be a git repo or a link to a git repo
            remote_repo = guess_git_repo_params(
                parsedRepoURL, logger=self.logger, fail_ok=fail_ok
            )

        return remote_repo

    def cacheWorkflow(
        self,
        workflow_id: "WorkflowId",
        version_id: "Optional[WFVersionId]" = None,
        trs_endpoint: "Optional[str]" = None,
        descriptor_type: "Optional[TRS_Workflow_Descriptor]" = None,
        ignoreCache: "bool" = False,
        registerInCache: "bool" = True,
        offline: "bool" = False,
        meta_dir: "Optional[AbsPath]" = None,
    ) -> "Tuple[AbsPath, RemoteRepo, Optional[WorkflowType], Optional[RepoTag]]":
        """
        Fetch the whole workflow description based on the data obtained
        from the TRS where it is being published.

        If the workflow id is an URL, it is supposed to be a git repository,
        and the version will represent either the branch, tag or specific commit.
        So, the whole TRS fetching machinery is bypassed.
        """
        putative_repo_url = str(workflow_id)
        parsedRepoURL = urllib.parse.urlparse(putative_repo_url)

        # It is not an absolute URL, so it is being an identifier in the workflow
        i_workflow: "Optional[IdentifiedWorkflow]" = None
        engineDesc: "Optional[WorkflowType]" = None
        guessedRepo: "Optional[RemoteRepo]" = None
        repoDir: "Optional[AbsPath]" = None
        putative: "bool" = False
        cached_putative_path: "Optional[AbsPath]" = None
        if parsedRepoURL.scheme in ("", TRS_SCHEME_PREFIX):
            # Extracting the TRS endpoint details from the parsedRepoURL
            if parsedRepoURL.scheme == TRS_SCHEME_PREFIX:
                # Duplication of code borrowed from trs_files.py
                path_steps: "Sequence[str]" = parsedRepoURL.path.split("/")
                if len(path_steps) < 3 or path_steps[0] != "":
                    raise WfExSBackendException(
                        f"Ill-formed TRS CURIE {putative_repo_url}. It should be in the format of {TRS_SCHEME_PREFIX}://id/version or {TRS_SCHEME_PREFIX}://prefix-with-slashes/id/version"
                    )
                trs_steps = cast("MutableSequence[str]", path_steps[0:-2])
                trs_steps.extend(["ga4gh", "trs", "v2", "tools"])
                trs_endpoint = urllib.parse.urlunparse(
                    urllib.parse.ParseResult(
                        scheme="https",
                        netloc=parsedRepoURL.netloc,
                        path="/".join(trs_steps),
                        params="",
                        query="",
                        fragment="",
                    )
                )

                workflow_id = urllib.parse.unquote(path_steps[-2])
                version_id = urllib.parse.unquote(path_steps[-1])
            if (trs_endpoint is not None) and len(trs_endpoint) > 0:
                i_workflow, repoDir = self.getWorkflowRepoFromTRS(
                    trs_endpoint,
                    workflow_id,
                    version_id,
                    descriptor_type,
                    ignoreCache=ignoreCache,
                    offline=offline,
                    meta_dir=meta_dir,
                )
                # For the cases of pure TRS repos, like Dockstore
                # repoDir contains the cached path
            else:
                raise WFException("trs_endpoint was not provided")
        else:
            # Trying to be smarter
            guessedRepo = self.guess_repo_params(parsedRepoURL, fail_ok=True)

            if guessedRepo is not None:
                if guessedRepo.tag is None and version_id is not None:
                    guessedRepo = RemoteRepo(
                        repo_url=guessedRepo.repo_url,
                        tag=cast("RepoTag", version_id),
                        rel_path=guessedRepo.rel_path,
                        repo_type=guessedRepo.repo_type,
                        web_url=guessedRepo.web_url,
                    )
            else:
                (
                    i_workflow,
                    cached_putative_path,
                    metadata_array,
                ) = self.getWorkflowBundleFromURI(
                    cast("URIType", workflow_id),
                    offline=offline,
                    ignoreCache=ignoreCache,
                )

                if i_workflow is None:
                    repoDir = cached_putative_path
                    repoRelPath: "Optional[str]" = None
                    if os.path.isdir(repoDir):
                        if len(parsedRepoURL.fragment) > 0:
                            frag_qs = urllib.parse.parse_qs(parsedRepoURL.fragment)
                            subDirArr = frag_qs.get("subdirectory", [])
                            if len(subDirArr) > 0:
                                repoRelPath = subDirArr[0]
                    elif len(metadata_array) > 0:
                        # Let's try getting a pretty filename
                        # when the workflow is a single file
                        repoRelPath = metadata_array[0].preferredName

                    # It can be either a relative path to a directory or to a file
                    # It could be even empty!
                    if repoRelPath == "":
                        repoRelPath = None
                    # raise WFException('Unable to guess repository from RO-Crate manifest')
                    guessedRepo = RemoteRepo(
                        repo_url=cast("RepoURL", workflow_id),
                        tag=cast("RepoTag", version_id),
                        rel_path=cast("Optional[RelPath]", repoRelPath),
                    )
                    putative = True

        # This can be incorrect, but let it be for now
        if i_workflow is not None:
            guessedRepo = i_workflow.remote_repo
            engineDesc = i_workflow.workflow_type
            if cached_putative_path is not None:
                self.cacheROCrateFilename = cached_putative_path

        assert guessedRepo is not None
        assert guessedRepo.repo_url is not None

        repoEffectiveCheckout: "Optional[RepoTag]" = None
        # A putative workflow is one which is already materialized
        # but we can only guess
        if repoDir is None:
            parsedRepoURL = urllib.parse.urlparse(guessedRepo.repo_url)
            assert (
                len(parsedRepoURL.scheme) > 0
            ), f"Repository id {guessedRepo.repo_url} should be a parsable URI"

            repoDir, repoEffectiveCheckout = self.doMaterializeRepo(
                guessedRepo,
                doUpdate=ignoreCache,
                registerInCache=registerInCache,
            )

        return repoDir, guessedRepo, engineDesc, repoEffectiveCheckout

    TRS_METADATA_FILE: "Final[RelPath]" = cast("RelPath", "trs_metadata.json")
    TRS_QUERY_CACHE_FILE: "Final[RelPath]" = cast("RelPath", "trs_result.json")

    def getWorkflowRepoFromTRS(
        self,
        trs_endpoint: "str",
        workflow_id: "WorkflowId",
        version_id: "Optional[WFVersionId]",
        descriptor_type: "Optional[TRS_Workflow_Descriptor]",
        offline: "bool" = False,
        ignoreCache: "bool" = False,
        meta_dir: "Optional[AbsPath]" = None,
    ) -> "Tuple[IdentifiedWorkflow, Optional[AbsPath]]":
        """

        :return:
        """

        # If nothing is set, just create a temporary directory
        if meta_dir is None:
            meta_dir = cast(
                "AbsPath", tempfile.mkdtemp(prefix="WfExS", suffix="TRSFetched")
            )
            # Assuring this temporal directory is removed at the end
            atexit.register(shutil.rmtree, meta_dir)
        else:
            # Assuring the destination directory does exist
            os.makedirs(meta_dir, exist_ok=True)

        if isinstance(workflow_id, int):
            workflow_id_str = str(workflow_id)
        else:
            workflow_id_str = workflow_id

        # Now, time to check whether it is a TRSv2
        trs_endpoint_v2_meta_url = cast("URIType", trs_endpoint + "service-info")
        trs_endpoint_v2_beta2_meta_url = cast("URIType", trs_endpoint + "metadata")
        trs_endpoint_meta_url = None

        # Needed to store this metadata
        trsMetadataCache = os.path.join(meta_dir, self.TRS_METADATA_FILE)

        try:
            trs_cached_content = self.cacheHandler.fetch(
                trs_endpoint_v2_meta_url,
                destdir=meta_dir,
                offline=offline,
                ignoreCache=ignoreCache,
            )
            trs_endpoint_meta_url = trs_endpoint_v2_meta_url
        except WFException as wfe:
            try:
                trs_cached_content = self.cacheHandler.fetch(
                    trs_endpoint_v2_beta2_meta_url,
                    destdir=meta_dir,
                    offline=offline,
                    ignoreCache=ignoreCache,
                )
                trs_endpoint_meta_url = trs_endpoint_v2_beta2_meta_url
            except WFException as wfebeta:
                raise WFException(
                    "Unable to fetch metadata from {} in order to identify whether it is a working GA4GH TRSv2 endpoint. Exceptions:\n{}\n{}".format(
                        trs_endpoint, wfe, wfebeta
                    )
                )

        # Giving a friendly name
        if not os.path.exists(trsMetadataCache):
            os.symlink(os.path.basename(trs_cached_content.path), trsMetadataCache)

        with open(trsMetadataCache, mode="r", encoding="utf-8") as ctmf:
            trs_endpoint_meta = json.load(ctmf)

        # Minimal check
        trs_version = trs_endpoint_meta.get("api_version")
        if trs_version is None:
            trs_version = trs_endpoint_meta.get("type", {}).get("version")

        if trs_version is None:
            raise WFException(
                "Unable to identify TRS version from {}".format(trs_endpoint_meta_url)
            )

        # Now, check the tool does exist in the TRS, and the version
        trs_tools_url = cast(
            "URIType",
            urllib.parse.urljoin(
                trs_endpoint,
                WF.TRS_TOOLS_PATH + urllib.parse.quote(workflow_id_str, safe=""),
            ),
        )

        trsQueryCache = os.path.join(meta_dir, self.TRS_QUERY_CACHE_FILE)
        trs_cached_tool = self.cacheHandler.fetch(
            trs_tools_url, destdir=meta_dir, offline=offline, ignoreCache=ignoreCache
        )
        # Giving a friendly name
        if not os.path.exists(trsQueryCache):
            os.symlink(os.path.basename(trs_cached_tool.path), trsQueryCache)

        with open(trsQueryCache, mode="r", encoding="utf-8") as tQ:
            rawToolDesc = tQ.read()

        # If the tool does not exist, an exception will be thrown before
        jd = json.JSONDecoder()
        toolDesc = jd.decode(rawToolDesc)

        # If the tool is not a workflow, complain
        if toolDesc.get("toolclass", {}).get("name", "") != "Workflow":
            raise WFException(
                "Tool {} from {} is not labelled as a workflow. Raw answer:\n{}".format(
                    workflow_id_str, trs_endpoint, rawToolDesc
                )
            )

        possibleToolVersions = toolDesc.get("versions", [])
        if len(possibleToolVersions) == 0:
            raise WFException(
                "Version {} not found in workflow {} from {} . Raw answer:\n{}".format(
                    version_id, workflow_id_str, trs_endpoint, rawToolDesc
                )
            )

        toolVersion = None
        toolVersionId = str(version_id) if isinstance(version_id, int) else version_id
        if (toolVersionId is not None) and len(toolVersionId) > 0:
            for possibleToolVersion in possibleToolVersions:
                if isinstance(possibleToolVersion, dict):
                    possibleId = str(possibleToolVersion.get("id", ""))
                    possibleName = str(possibleToolVersion.get("name", ""))
                    if version_id in (possibleId, possibleName):
                        toolVersion = possibleToolVersion
                        break
            else:
                raise WFException(
                    "Version {} not found in workflow {} from {} . Raw answer:\n{}".format(
                        version_id, workflow_id_str, trs_endpoint, rawToolDesc
                    )
                )
        else:
            toolVersionId = ""
            for possibleToolVersion in possibleToolVersions:
                possibleToolVersionId = str(possibleToolVersion.get("id", ""))
                if (
                    len(possibleToolVersionId) > 0
                    and toolVersionId < possibleToolVersionId
                ):
                    toolVersion = possibleToolVersion
                    toolVersionId = possibleToolVersionId

        if toolVersion is None:
            raise WFException(
                "No valid version was found in workflow {} from {} . Raw answer:\n{}".format(
                    workflow_id_str, trs_endpoint, rawToolDesc
                )
            )

        # The version has been found
        toolDescriptorTypes = toolVersion.get("descriptor_type", [])
        if not isinstance(toolDescriptorTypes, list):
            raise WFException(
                'Version {} of workflow {} from {} has no valid "descriptor_type" (should be a list). Raw answer:\n{}'.format(
                    version_id, workflow_id_str, trs_endpoint, rawToolDesc
                )
            )

        # Now, realize whether it matches
        chosenDescriptorType = descriptor_type
        if chosenDescriptorType is None:
            for candidateDescriptorType in WF.RECOGNIZED_TRS_DESCRIPTORS.keys():
                if candidateDescriptorType in toolDescriptorTypes:
                    chosenDescriptorType = candidateDescriptorType
                    break
            else:
                raise WFException(
                    'Version {} of workflow {} from {} has no acknowledged "descriptor_type". Raw answer:\n{}'.format(
                        version_id, workflow_id_str, trs_endpoint, rawToolDesc
                    )
                )
        elif chosenDescriptorType not in toolVersion["descriptor_type"]:
            raise WFException(
                "Descriptor type {} not available for version {} of workflow {} from {} . Raw answer:\n{}".format(
                    descriptor_type,
                    version_id,
                    workflow_id_str,
                    trs_endpoint,
                    rawToolDesc,
                )
            )
        elif chosenDescriptorType not in WF.RECOGNIZED_TRS_DESCRIPTORS:
            raise WFException(
                "Descriptor type {} is not among the acknowledged ones by this backend. Version {} of workflow {} from {} . Raw answer:\n{}".format(
                    descriptor_type,
                    version_id,
                    workflow_id_str,
                    trs_endpoint,
                    rawToolDesc,
                )
            )

        toolFilesURL = (
            trs_tools_url
            + "/versions/"
            + urllib.parse.quote(toolVersionId, safe="")
            + "/"
            + urllib.parse.quote(chosenDescriptorType, safe="")
            + "/files"
        )

        # Detecting whether RO-Crate trick will work
        if trs_endpoint_meta.get("organization", {}).get("name") == "WorkflowHub":
            self.logger.debug("WorkflowHub workflow")
            # And this is the moment where the RO-Crate must be fetched
            roCrateURL = cast(
                "URIType",
                toolFilesURL + "?" + urllib.parse.urlencode({"format": "zip"}),
            )

            (
                i_workflow,
                self.cacheROCrateFilename,
                metadata_array,
            ) = self.getWorkflowBundleFromURI(
                roCrateURL,
                expectedEngineDesc=WF.RECOGNIZED_TRS_DESCRIPTORS[chosenDescriptorType],
                offline=offline,
                ignoreCache=ignoreCache,
            )
            assert i_workflow is not None
            return i_workflow, None
        else:
            self.logger.debug("TRS workflow")
            # Learning the available files and maybe
            # which is the entrypoint to the workflow
            cached_trs_files = self.cacheFetch(
                cast("URIType", INTERNAL_TRS_SCHEME_PREFIX + ":" + toolFilesURL),
                CacheType.TRS,
                offline=offline,
                ignoreCache=ignoreCache,
            )

            expectedEngineDesc = WF.RECOGNIZED_TRS_DESCRIPTORS[chosenDescriptorType]
            trs_meta = cached_trs_files.metadata_array[0]
            remote_workflow_entrypoint = trs_meta.metadata.get(
                "remote_workflow_entrypoint"
            )
            if remote_workflow_entrypoint is not None:
                # Give it a chance to identify the original repo of the workflow
                repo = self.guess_repo_params(remote_workflow_entrypoint, fail_ok=True)

                if repo is not None:
                    self.logger.debug(
                        "Derived repository {} ({} , rel {}) from {}".format(
                            repo.repo_url, repo.tag, repo.rel_path, trs_tools_url
                        )
                    )
                    return (
                        IdentifiedWorkflow(
                            workflow_type=expectedEngineDesc, remote_repo=repo
                        ),
                        None,
                    )

            workflow_entrypoint = trs_meta.metadata.get("workflow_entrypoint")
            if workflow_entrypoint is not None:
                self.logger.debug(
                    "Using raw files from TRS tool {}".format(trs_tools_url)
                )
                return (
                    IdentifiedWorkflow(
                        workflow_type=expectedEngineDesc,
                        remote_repo=RemoteRepo(
                            repo_url=cast("RepoURL", toolFilesURL),
                            rel_path=workflow_entrypoint,
                            repo_type=RepoType.TRS,
                        ),
                    ),
                    cached_trs_files.path,
                )

        raise WFException("Unable to find a workflow in {}".format(trs_tools_url))

    def doMaterializeRepo(
        self,
        repo: "RemoteRepo",
        doUpdate: "bool" = True,
        registerInCache: "bool" = True,
    ) -> "Tuple[AbsPath, RepoTag]":
        if repo.repo_type not in (RepoType.Other, RepoType.SoftwareHeritage):
            (
                remote_url,
                repo_effective_checkout,
                repo_path,
                metadata_array,
            ) = self._doMaterializeGitRepo(repo, doUpdate=doUpdate)
        elif repo.repo_type == RepoType.SoftwareHeritage:
            (
                remote_url,
                repo_effective_checkout,
                repo_path,
                metadata_array,
            ) = self._doMaterializeSoftwareHeritageDirOrContent(repo, doUpdate=doUpdate)
        else:
            raise WfExSBackendException(
                f"Don't know how to materialize {repo.repo_url} as a repository"
            )

        if registerInCache:
            kind = (
                ContentKind.Directory if os.path.isdir(repo_path) else ContentKind.File
            )
            self.cacheHandler.inject(
                remote_url,
                destdir=self.cacheWorkflowDir,
                fetched_metadata_array=metadata_array,
                finalCachedFilename=repo_path,
                inputKind=kind,
            )

        return repo_path, repo_effective_checkout

    def _doMaterializeGitRepo(
        self,
        repo: "RemoteRepo",
        doUpdate: "bool" = True,
    ) -> "Tuple[URIType, RepoTag, AbsPath, Sequence[URIWithMetadata]]":
        """

        :param repoURL:
        :param repoTag:
        :param doUpdate:
        :return:
        """
        gitFetcherInst = self.instantiateStatefulFetcher(GitFetcher)
        repoDir, repo_desc, metadata_array = gitFetcherInst.doMaterializeRepo(
            repo.repo_url,
            repoTag=repo.tag,
            doUpdate=doUpdate,
            base_repo_destdir=self.cacheWorkflowDir,
        )

        # Now, let's register the checkout with cache structures
        # using its public URI
        if not repo.repo_url.startswith("git"):
            remote_url = "git+" + repo.repo_url
        else:
            remote_url = repo.repo_url

        if repo.tag is not None:
            remote_url += "@" + repo.tag

        augmented_metadata_array = [
            URIWithMetadata(
                uri=cast("URIType", remote_url),
                metadata=repo_desc,
            ),
            *metadata_array,
        ]
        return (
            cast("URIType", remote_url),
            repo_desc["checkout"],
            repoDir,
            augmented_metadata_array,
        )

    def _doMaterializeSoftwareHeritageDirOrContent(
        self,
        repo: "RemoteRepo",
        doUpdate: "bool" = True,
    ) -> "Tuple[URIType, RepoTag, AbsPath, Sequence[URIWithMetadata]]":
        """

        :param repoURL:
        :param repoTag:
        :param doUpdate:
        :return:
        """
        swhFetcherInst = self.instantiateStatefulFetcher(SoftwareHeritageFetcher)
        repoDir, repo_desc, metadata_array = swhFetcherInst.doMaterializeRepo(
            cast("RepoURL", repo.tag) if repo.tag is not None else repo.repo_url,
            doUpdate=doUpdate,
            base_repo_destdir=self.cacheWorkflowDir,
        )

        augmented_metadata_array = [
            URIWithMetadata(
                uri=cast("URIType", repo.repo_url),
                metadata=repo_desc,
            ),
            *metadata_array,
        ]
        return (
            repo.repo_url,
            repo_desc["checkout"],
            repoDir,
            augmented_metadata_array,
        )

    def getWorkflowBundleFromURI(
        self,
        remote_url: "URIType",
        expectedEngineDesc: "Optional[WorkflowType]" = None,
        offline: "bool" = False,
        ignoreCache: "bool" = False,
        registerInCache: "bool" = True,
    ) -> "Tuple[Optional[IdentifiedWorkflow], AbsPath, Sequence[URIWithMetadata]]":
        try:
            cached_content = self.cacheFetch(
                remote_url,
                CacheType.Input,
                offline=offline,
                ignoreCache=ignoreCache,
                registerInCache=registerInCache,
            )
        except Exception as e:
            raise WfExSBackendException(
                "Cannot download putative workflow from {}, {}".format(remote_url, e)
            ) from e
        self.logger.info(
            "downloaded putative workflow: {} -> {}".format(
                remote_url, cached_content.path
            )
        )

        if os.path.isfile(cached_content.path):
            # Now, let's guess whether it is a possible RO-Crate or a bare file
            encoding = magic.from_file(cached_content.path, mime=True)
        else:
            # A directory does not have mime type
            encoding = ""
        if encoding == "application/zip":
            self.logger.info(
                "putative workflow {} seems to be a packed RO-Crate".format(remote_url)
            )

            crate_hashed_id = hashlib.sha1(remote_url.encode("utf-8")).hexdigest()
            roCrateFile = os.path.join(
                self.cacheROCrateDir, crate_hashed_id + self.DEFAULT_RO_EXTENSION
            )
            if not os.path.exists(roCrateFile):
                if os.path.lexists(roCrateFile):
                    os.unlink(roCrateFile)
                os.symlink(
                    os.path.relpath(cached_content.path, self.cacheROCrateDir),
                    roCrateFile,
                )

            return (
                self.getWorkflowRepoFromROCrateFile(
                    cast("AbsPath", roCrateFile), expectedEngineDesc
                ),
                cast("AbsPath", roCrateFile),
                cached_content.metadata_array,
            )
        else:
            return (
                None,
                cached_content.path,
                cached_content.metadata_array,
            )

    def getWorkflowRepoFromROCrateFile(
        self,
        roCrateFile: "AbsPath",
        expectedEngineDesc: "Optional[WorkflowType]" = None,
    ) -> "IdentifiedWorkflow":
        """

        :param roCrateFile:
        :param expectedEngineDesc: If defined, an instance of WorkflowType
        :return:
        """
        roCrateObj = FixedROCrate(roCrateFile)

        # TODO: get roCrateObj mainEntity programming language
        # self.logger.debug(roCrateObj.root_dataset.as_jsonld())
        mainEntityProgrammingLanguageId = None
        mainEntityProgrammingLanguageUrl = None
        mainEntityIdHolder: "Optional[str]" = None
        mainEntityId = None
        workflowPID = None
        workflowUploadURL = None
        workflowRepoURL = None
        workflowTypeId = None
        for e in roCrateObj.get_entities():
            if (
                (mainEntityIdHolder is None)
                and e["@type"] == "CreativeWork"
                and ".json" in e["@id"]
            ):
                mainEntityIdHolder = e.as_jsonld()["about"]["@id"]
            elif e["@id"] == mainEntityIdHolder:
                eAsLD = e.as_jsonld()
                mainEntityId = eAsLD["mainEntity"]["@id"]
                workflowRepoURL = eAsLD.get("isBasedOn")
                workflowPID = eAsLD.get("identifier")
            elif e["@id"] == mainEntityId:
                eAsLD = e.as_jsonld()
                workflowUploadURL = eAsLD.get("url")
                workflowTypeId = eAsLD["programmingLanguage"]["@id"]
            elif e["@id"] == workflowTypeId:
                # A bit dirty, but it works
                eAsLD = e.as_jsonld()
                mainEntityProgrammingLanguageId = eAsLD.get("identifier", {}).get("@id")
                mainEntityProgrammingLanguageUrl = eAsLD.get("url", {}).get("@id")

        # Now, it is time to match the language id
        engineDescById: "Optional[WorkflowType]" = None
        engineDescByUrl: "Optional[WorkflowType]" = None
        for possibleEngineDesc in WF.WORKFLOW_ENGINES:
            if (engineDescById is None) and (
                mainEntityProgrammingLanguageId is not None
            ):
                for pat in possibleEngineDesc.uriMatch:
                    if isinstance(pat, Pattern):
                        match = pat.search(mainEntityProgrammingLanguageId)
                        if match:
                            engineDescById = possibleEngineDesc
                    elif pat == mainEntityProgrammingLanguageId:
                        engineDescById = possibleEngineDesc

            if (engineDescByUrl is None) and (
                mainEntityProgrammingLanguageUrl == possibleEngineDesc.url
            ):
                engineDescByUrl = possibleEngineDesc

        engineDesc: "WorkflowType"
        if engineDescById is not None:
            engineDesc = engineDescById
        elif engineDescByUrl is not None:
            engineDesc = engineDescByUrl
        else:
            raise WfExSBackendException(
                "Found programming language {} (url {}) in RO-Crate manifest is not among the acknowledged ones".format(
                    mainEntityProgrammingLanguageId, mainEntityProgrammingLanguageUrl
                )
            )

        if (
            (engineDescById is not None)
            and (engineDescByUrl is not None)
            and engineDescById != engineDescByUrl
        ):
            self.logger.warning(
                "Found programming language {} (url {}) leads to different engines".format(
                    mainEntityProgrammingLanguageId, mainEntityProgrammingLanguageUrl
                )
            )

        if (expectedEngineDesc is not None) and engineDesc != expectedEngineDesc:
            raise WfExSBackendException(
                "Expected programming language {} does not match identified one {} in RO-Crate manifest".format(
                    expectedEngineDesc.engineName, engineDesc.engineName
                )
            )

        # This workflow URL, in the case of github, can provide the repo,
        # the branch/tag/checkout , and the relative directory in the
        # fetched content (needed by Nextflow)

        # Some RO-Crates might have this value missing or ill-built
        remote_repo: "Optional[RemoteRepo]" = None
        if workflowUploadURL is not None:
            try:
                remote_repo = self.guess_repo_params(workflowUploadURL, fail_ok=True)
            except:
                self.logger.exception(
                    f"Unable to use RO-Crate derived {workflowUploadURL} as workflow source"
                )

        if workflowRepoURL is not None and (
            remote_repo is None or remote_repo.repo_type is None
        ):
            try:
                remote_repo = self.guess_repo_params(workflowRepoURL, fail_ok=True)
            except:
                self.logger.exception(
                    f"Unable to use RO-Crate derived {workflowRepoURL} as workflow source"
                )

        if remote_repo is None or remote_repo.repo_type is None:
            raise WfExSBackendException(
                "Unable to guess repository from RO-Crate manifest"
            )

        # It must return four elements:
        return IdentifiedWorkflow(workflow_type=engineDesc, remote_repo=remote_repo)

    DEFAULT_RO_EXTENSION: "Final[str]" = ".crate.zip"

    def cacheROcrate(
        self,
        roCrateURL: "URIType",
        offline: "bool" = False,
        ignoreCache: "bool" = False,
    ) -> "AbsPath":
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
            cached_rocrate = self.cacheHandler.fetch(
                roCrateURL,
                destdir=self.cacheROCrateDir,
                offline=offline,
                ignoreCache=ignoreCache,
            )
        except Exception as e:
            raise WfExSBackendException(
                "Cannot download RO-Crate from {}, {}".format(roCrateURL, e)
            ) from e

        crate_hashed_id = hashlib.sha1(roCrateURL.encode("utf-8")).hexdigest()
        cachedFilename = os.path.join(
            self.cacheROCrateDir, crate_hashed_id + self.DEFAULT_RO_EXTENSION
        )
        if not os.path.exists(cachedFilename):
            os.symlink(os.path.basename(cached_rocrate.path), cachedFilename)

        return cast("AbsPath", cachedFilename)

    def downloadContent(
        self,
        remote_file: "Union[LicensedURI, Sequence[LicensedURI]]",
        dest: "Union[AbsPath, CacheType]",
        vault: "Optional[SecurityContextVault]" = None,
        offline: "bool" = False,
        ignoreCache: "bool" = False,
        registerInCache: "bool" = True,
        keep_cache_licence: "bool" = True,
    ) -> "MaterializedContent":
        """
        Download remote file or directory / dataset.

        :param remote_file: URL or CURIE to download remote file
        :param contextName:
        :param workflowInputs_destdir:
        :param offline:
        :type remote_file: str
        """

        # Preparation of needed structures
        remote_uris_e: "Sequence[LicensedURI]"
        if isinstance(remote_file, list):
            remote_uris_e = remote_file
        else:
            remote_uris_e = cast(
                "MutableSequence[LicensedURI]",
                [remote_file],
            )

        assert (
            len(remote_uris_e) > 0
        ), "The list of remote URIs to download should have at least one element"

        firstURI: "Optional[LicensedURI]" = None
        firstParsedURI: "Optional[parse.ParseResult]" = None
        remote_uris: "MutableSequence[URIType]" = []
        # Brief validation of correct uris
        for remote_uri_e in remote_uris_e:
            remote_uri = remote_uri_e.uri

            parsedURI = parse.urlparse(remote_uri)
            validableComponents = [parsedURI.scheme, parsedURI.path]
            if not all(validableComponents):
                raise RuntimeError(
                    f"Input does not have {remote_uri} as a valid remote URL or CURIE source "
                )
            remote_uris.append(remote_uri)

            if firstParsedURI is None:
                firstURI = remote_uri_e
                firstParsedURI = parsedURI

        assert firstURI is not None
        assert firstParsedURI is not None

        # Assure workflow inputs directory exists before the next step
        if isinstance(dest, CacheType):
            workflowInputs_destdir = self.cachePathMap[dest]

        self.logger.info(
            "downloading workflow input: {}".format(" or ".join(remote_uris))
        )

        cached_content = self.cacheHandler.fetch(
            remote_file,
            destdir=workflowInputs_destdir,
            offline=offline,
            ignoreCache=ignoreCache,
            registerInCache=registerInCache,
            vault=vault,
        )
        # TODO: Properly test alternatives
        downloaded_uri = firstURI.uri
        self.logger.info(
            "downloaded workflow input: {} => {}".format(
                downloaded_uri, cached_content.path
            )
        )

        prettyFilename = None
        if len(cached_content.metadata_array) > 0:
            self.logger.info(
                "downloaded workflow input chain: {} => {}".format(
                    " -> ".join(map(lambda m: m.uri, cached_content.metadata_array)),
                    cached_content.path,
                )
            )

            firstLicensedURI = LicensedURI(
                uri=cached_content.metadata_array[0].uri,
                licences=cached_content.licences
                if keep_cache_licence
                else firstURI.licences,
                attributions=firstURI.attributions,
            )
            # The preferred name is obtained from the metadata
            for m in cached_content.metadata_array:
                if m.preferredName is not None:
                    prettyFilename = m.preferredName
                    break
        else:
            # This alternative could happen,
            # but it should not.
            # Anyway, junking the security context
            firstLicensedURI = firstURI._replace(
                licences=cached_content.licences
                if keep_cache_licence
                else firstURI.licences,
                secContext=None,
            )

        if prettyFilename is None:
            # Default pretty filename in the worst case
            prettyFilename = cast("RelPath", firstParsedURI.path.split("/")[-1])

        return MaterializedContent(
            local=cached_content.path,
            licensed_uri=firstLicensedURI,
            prettyFilename=prettyFilename,
            kind=cached_content.kind,
            metadata_array=cached_content.metadata_array,
            fingerprint=cached_content.fingerprint,
        )
