#!/usr/bin/env python
# -*- coding: utf-8 -*-

# SPDX-License-Identifier: Apache-2.0
# Copyright 2020-2024 Barcelona Supercomputing Center (BSC), Spain
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
import importlib
import inspect
import io
import json
import logging
import os
import pathlib
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

from .utils.misc import lazy_import

magic = lazy_import("magic")
# import magic

from .common import (
    AbstractWfExSException,
    CacheType,
    ContentKind,
    DEFAULT_FUSERMOUNT_CMD,
    DEFAULT_PROGS,
    LicensedURI,
    MaterializedContent,
    NoLicenceDescription,
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

from .container_factories import (
    ContainerFactory,
)

from .workflow_engines import (
    WORKDIR_META_RELDIR,
    WORKDIR_PASSPHRASE_FILE,
    WORKDIR_WORKFLOW_META_FILE,
)
from .ro_crate import FixedROCrate

from .security_context import SecurityContextVault

from .utils.licences import (
    AcceptableLicenceSchemes,
    LicenceMatcherSingleton,
)

from .utils.marshalling_handling import (
    unmarshall_namedtuple,
)

from .utils.misc import (
    config_validate,
    DatetimeEncoder,
    iter_namespace,
    jsonFilterDecodeFromStream,
    translate_glob_args,
)

from .utils.passphrase_wrapper import (
    WfExSPassGenSingleton,
)

from .utils.rocrate import (
    ReadROCrateMetadata,
    ROCrateToolbox,
)

from .fetchers import (
    AbstractRepoFetcher,
    AbstractStatefulFetcher,
    DocumentedProtocolFetcher,
    DocumentedStatefulProtocolFetcher,
    RemoteRepo,
    RepoType,
)

from .fetchers.git import (
    GitFetcher,
)

from .fetchers.swh import (
    SoftwareHeritageFetcher,
)

from .pushers import AbstractExportPlugin

from .utils.rocrate import (
    ReproducibilityLevel,
)

from .workflow import (
    WF,
    WFException,
)

from .workflow_engines import (
    WorkflowEngine,
)

from .fetchers.trs_files import (
    TRS_SCHEME_PREFIX,
    INTERNAL_TRS_SCHEME_PREFIX,
)


if TYPE_CHECKING:
    from types import ModuleType

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

    from typing_extensions import (
        Final,
        TypeAlias,
    )

    from crypt4gh.header import CompoundKey

    from .common import (
        AbsPath,
        AnyPath,
        ContainerType,
        ExitVal,
        LicenceDescription,
        MarshallingStatus,
        ProgsMapping,
        RelPath,
        RepoTag,
        RepoURL,
        SecurityContextConfig,
        StagedSetup,
        SymbolicName,
        TRS_Workflow_Descriptor,
        URIType,
        WfExSInstanceId,
    )

    from .workflow_engines import (
        AbstractWorkflowEngineType,
        WorkflowType,
    )

    from .fetchers import (
        RepoFetcher,
        StatefulFetcher,
    )

    from .utils.licences import (
        LicenceMatcher,
    )

    from .utils.passphrase_wrapper import (
        WfExSPassphraseGenerator,
    )

    from .workflow import (
        EnvironmentBlock,
        ExportActionBlock,
        OutputsBlock,
        ParamsBlock,
        WFVersionId,
        WorkflowConfigBlock,
        WorkflowId,
        WorkflowMetaConfigBlock,
    )

    SecurityContextConfigBlock: TypeAlias = Mapping[str, SecurityContextConfig]

    WfExSConfigBlock: TypeAlias = Mapping[str, Any]
    WritableWfExSConfigBlock: TypeAlias = MutableMapping[str, Any]


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
    def bootstrap_config(
        cls,
        local_config_ro: "WfExSConfigBlock",
        config_directory: "Optional[pathlib.Path]" = None,
        key_prefix: "Optional[str]" = None,
    ) -> "Tuple[bool, WfExSConfigBlock, pathlib.Path]":
        """
        :param local_config: Relevant local configuration, like the cache directory.
        :param config_directory: The filename to be used to resolve relative paths
        :param key_prefix: Prefix for the files of newly generated key pairs
        :type local_config: dict
        """

        import socket

        logger = logging.getLogger(cls.__name__)

        updated = False

        valErrors = config_validate(local_config_ro, cls.CONFIG_SCHEMA)
        if len(valErrors) > 0:
            logging.error(
                f"ERROR on incoming local configuration block for bootstrap config: {valErrors}"
            )
            sys.exit(1)

        local_config = cast("WritableWfExSConfigBlock", copy.deepcopy(local_config_ro))

        # Getting the config directory
        if config_directory is None:
            config_directory = pathlib.Path(
                tempfile.mkdtemp(prefix="WfExS", suffix="config")
            )
        if not config_directory.is_absolute():
            config_directory = config_directory.absolute()

        if key_prefix is None:
            key_prefix = ""

        # This one is to assure the working directory is created
        workDir: "Optional[pathlib.Path]" = None
        workDir_str: "Optional[str]" = local_config.get("workDir")
        if workDir_str:
            workDir = pathlib.Path(workDir_str)
            if not workDir.is_absolute():
                workDir = (config_directory / workDir).resolve()
            workDir.mkdir(parents=True, exist_ok=True)

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

            # This is needed to protect WfExS from unwanted umask changes
            # from the reference crypt4gh library
            umask = os.umask(0)
            os.umask(umask)
            try:
                crypt4gh.keys.c4gh.generate(
                    privKey,
                    pubKey,
                    passphrase=passphrase.encode("utf-8"),
                    comment=comment.encode("utf-8"),
                )
            finally:
                os.umask(umask)
                crypt4gh.keys.c4gh.scrypt_supported = orig_scrypt_supported
        elif not crypt4gh.keys.c4gh.scrypt_supported:
            logger.info(
                "Python interpreter does not support scrypt, so encoded crypt4gh keys with that algorithm cannot be used"
            )

        # Validate, again, as it changed
        if updated:
            valErrors = config_validate(local_config, cls.CONFIG_SCHEMA)
            if len(valErrors) > 0:
                logging.error(
                    f"ERROR in bootstrapped updated local configuration block: {valErrors}"
                )
                sys.exit(1)

        return updated, local_config, config_directory

    @classmethod
    def FromDescription(
        cls,
        workflow_meta: "WorkflowMetaConfigBlock",
        local_config: "WfExSConfigBlock",
        vault: "Optional[SecurityContextVault]" = None,
        config_directory: "Optional[pathlib.Path]" = None,
        public_key_filenames: "Sequence[pathlib.Path]" = [],
        private_key_filename: "Optional[pathlib.Path]" = None,
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

        _, updated_local_config, config_directory = cls.bootstrap_config(
            local_config, config_directory=config_directory
        )

        profiles: "Optional[Union[str, Sequence[str]]]" = workflow_meta.get("profile")
        enabled_profiles: "Optional[Sequence[str]]" = None
        if profiles is not None:
            if isinstance(profiles, list):
                enabled_profiles = profiles
            elif isinstance(profiles, str):
                split_by_comma = re.compile(r"[ \t]*,[ \t]*")
                enabled_profiles = split_by_comma.split(profiles)
            else:
                # It should not happen
                enabled_profiles = [str(profiles)]

        return cls(updated_local_config, config_directory=config_directory).newSetup(
            workflow_meta["workflow_id"],
            workflow_meta.get("version"),
            descriptor_type=workflow_meta.get("workflow_type"),
            trs_endpoint=workflow_meta.get("trs_endpoint", WF.DEFAULT_TRS_ENDPOINT),
            params=workflow_meta.get("params", {}),
            enabled_profiles=enabled_profiles,
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
        config_directory: "Optional[pathlib.Path]" = None,
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
            # Minimal bootstrapping for embedded cases
            _, local_config, config_directory = self.bootstrap_config(
                {}, config_directory
            )

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
            key_path: "MutableSequence[Tuple[str, str]]" = []
            if keyC.endswith("Command"):
                prog_key = keyC[0 : -len("Command")]
                key_path.append((prog_key, pathC))
            elif keyC == "commands":
                assert isinstance(pathC, list)

                for command_block in pathC:
                    assert isinstance(command_block, dict)

                    if "key" in command_block and "path" in command_block:
                        key_path.append((command_block["key"], command_block["path"]))

            for prog_key, path_val in key_path:
                abs_cmd = shutil.which(path_val)
                if abs_cmd is None:
                    self.logger.critical(
                        f'{prog_key} command {path_val}, could not be reached relatively or through PATH {os.environ["PATH"]} (core: {prog_key in self.progs})'
                    )
                else:
                    self.logger.info(
                        f"Setting up {prog_key} to {abs_cmd} (derived from {path_val}) (core: {prog_key in self.progs})"
                    )
                    self.progs[prog_key] = cast("AbsPath", abs_cmd)

        encfsSect = toolSect.get("encrypted_fs", {})
        encfs_type_str: "Optional[str]" = encfsSect.get(
            "type", DEFAULT_ENCRYPTED_FS_TYPE
        )
        assert encfs_type_str is not None
        try:
            encfs_type = EncryptedFSType(encfs_type_str)
        except:
            errmsg = f"Invalid default encryption filesystem {encfs_type_str}"
            self.logger.error(errmsg)
            raise WfExSBackendException(errmsg)
        if encfs_type not in ENCRYPTED_FS_MOUNT_IMPLEMENTATIONS:
            errmsg = f"FIXME: Default encryption filesystem {encfs_type} mount procedure is not implemented"
            self.logger.fatal(errmsg)
            raise WfExSBackendException(errmsg)
        self.encfs_type = encfs_type

        self.encfs_cmd = encfsSect.get(
            "command", DEFAULT_ENCRYPTED_FS_CMD[self.encfs_type]
        )
        abs_encfs_cmd = shutil.which(self.encfs_cmd)
        if abs_encfs_cmd is None:
            errmsg = f"FUSE filesystem command {self.encfs_cmd}, needed by {encfs_type}, was not found. Please install it if you are going to use a secured staged workdir"
            self.logger.error(errmsg)
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
            config_directory = pathlib.Path.cwd()
        if not config_directory.is_absolute():
            config_directory = config_directory.absolute()

        self.config_directory = config_directory

        # Getting the private and public keys, needed from this point
        crypt4ghSect = local_config.get(self.CRYPT4GH_SECTION, {})
        privKeyFilename = pathlib.Path(crypt4ghSect[self.CRYPT4GH_PRIVKEY_KEY])
        if not privKeyFilename.is_absolute():
            privKeyFilename = (config_directory / privKeyFilename).resolve()

        pubKeyFilename = pathlib.Path(crypt4ghSect[self.CRYPT4GH_PUBKEY_KEY])
        if not pubKeyFilename.is_absolute():
            pubKeyFilename = (config_directory / pubKeyFilename).resolve()
        passphrase = crypt4ghSect[self.CRYPT4GH_PASSPHRASE_KEY]

        # These are the keys to be used
        self.pubKey = crypt4gh.keys.get_public_key(pubKeyFilename.as_posix())
        self.privKey = crypt4gh.keys.get_private_key(
            privKeyFilename.as_posix(), lambda: passphrase
        )

        # This directory will be used to cache repositories and distributable inputs
        cacheDir_str = local_config.get("cacheDir")
        if cacheDir_str:
            cacheDir = pathlib.Path(cacheDir_str)
            if not cacheDir.is_absolute():
                cacheDir = (config_directory / cacheDir).resolve()
            cacheDir.mkdir(parents=True, exist_ok=True)
        else:
            cacheDir = pathlib.Path(tempfile.mkdtemp(prefix="WfExS", suffix="backend"))
            # Assuring this temporal directory is removed at the end
            atexit.register(shutil.rmtree, cacheDir, True)

        # Setting up caching directories
        self.cacheDir = cacheDir
        self.cachePathMap: "MutableMapping[str, pathlib.Path]" = dict()
        cacheWorkflowDir = cacheDir / "wf-cache"
        cacheWorkflowDir.mkdir(parents=True, exist_ok=True)
        self.cachePathMap[CacheType.Workflow] = cacheWorkflowDir

        cacheROCrateDir = cacheDir / "ro-crate-cache"
        cacheROCrateDir.mkdir(parents=True, exist_ok=True)
        self.cachePathMap[CacheType.ROCrate] = cacheROCrateDir

        cacheTRSFilesDir = cacheDir / "trs-files-cache"
        cacheTRSFilesDir.mkdir(parents=True, exist_ok=True)
        self.cachePathMap[CacheType.TRS] = cacheTRSFilesDir

        cacheWorkflowInputsDir = cacheDir / "wf-inputs"
        cacheWorkflowInputsDir.mkdir(parents=True, exist_ok=True)
        self.cachePathMap[CacheType.Input] = cacheWorkflowInputsDir

        # This directory will be used to store the intermediate
        # and final results before they are sent away
        baseWorkDir_str: "Optional[str]" = local_config.get("workDir")
        if baseWorkDir_str:
            baseWorkDir = pathlib.Path(baseWorkDir_str)
            if not baseWorkDir.is_absolute():
                baseWorkDir = (config_directory / baseWorkDir).resolve()
            baseWorkDir.mkdir(parents=True, exist_ok=True)
        else:
            baseWorkDir = pathlib.Path(
                tempfile.mkdtemp(prefix="WfExS-workdir", suffix="backend")
            )
            # Assuring this temporal directory is removed at the end
            atexit.register(shutil.rmtree, baseWorkDir, True)

        self.baseWorkDir = baseWorkDir
        self.defaultParanoidMode = False

        self._sngltn: "MutableMapping[Type[AbstractStatefulFetcher], AbstractStatefulFetcher]" = (
            dict()
        )
        self.repo_fetchers: "MutableSequence[AbstractRepoFetcher]" = list()
        # cacheHandler is created on first use
        self.cacheHandler = SchemeHandlerCacheHandler(self.cacheDir)

        fetchers_setup_block = local_config.get("fetchers-setup")

        # All the scheme handlers should be added here
        self.findAndAddSchemeHandlersFromModuleName(
            fetchers_setup_block=fetchers_setup_block
        )

        # Registry of export plugins is created here
        self._export_plugins: "MutableMapping[SymbolicName, Type[AbstractExportPlugin]]" = (
            dict()
        )

        # All the export plugins should be added here
        self.findAndAddExportPluginsFromModuleName()

        # Registry of workflow engines is created here
        self._workflow_engines: "MutableMapping[str, Type[WorkflowEngine]]" = dict()

        # All the workflow engines should be added here
        self.findAndAddWorkflowEnginesFromModuleName()

        self.WORKFLOW_ENGINES: "Sequence[WorkflowType]" = sorted(
            map(lambda clazz: clazz.MyWorkflowType(), self._workflow_engines.values()),
            key=lambda clz: (-clz.priority, clz.shortname),
        )

        self.RECOGNIZED_TRS_DESCRIPTORS: "Mapping[TRS_Workflow_Descriptor, WorkflowType]" = dict(
            map(lambda t: (t.trs_descriptor, t), self.WORKFLOW_ENGINES)
        )

        self.RECOGNIZED_SHORTNAME_DESCRIPTORS: "Mapping[TRS_Workflow_Descriptor, WorkflowType]" = dict(
            map(lambda t: (t.shortname, t), self.WORKFLOW_ENGINES)
        )

        # Registry of container factories is created here
        self._container_factories: "MutableMapping[ContainerType, Type[ContainerFactory]]" = (
            dict()
        )

        # All the container factories should be added here
        self.findAndAddContainerFactoriesFromModuleName()

        # The toolbox to be shared with others
        self.rocrate_toolbox = ROCrateToolbox(self)

    @property
    def cacheWorkflowDir(self) -> "pathlib.Path":
        return self.cachePathMap[CacheType.Workflow]

    @property
    def cacheROCrateDir(self) -> "pathlib.Path":
        return self.cachePathMap[CacheType.ROCrate]

    @property
    def cacheTRSFilesDir(self) -> "pathlib.Path":
        return self.cachePathMap[CacheType.TRS]

    @property
    def cacheWorkflowInputsDir(self) -> "pathlib.Path":
        return self.cachePathMap[CacheType.Input]

    def getCacheHandler(
        self, cache_type: "CacheType"
    ) -> "Tuple[SchemeHandlerCacheHandler, Optional[pathlib.Path]]":
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

    def instantiateRepoFetcher(
        self,
        repoFetcher: "Type[RepoFetcher]",
        setup_block: "Optional[Mapping[str, Any]]" = None,
    ) -> "RepoFetcher":
        """
        Method to instantiate repo fetchers once
        """
        return self.instantiateStatefulFetcher(repoFetcher, setup_block=setup_block)

    def findAndAddWorkflowEnginesFromModuleName(
        self,
        the_module_name: "str" = "wfexs_backend.workflow_engines",
    ) -> None:
        try:
            the_module = importlib.import_module(the_module_name)
            self.findAndAddWorkflowEnginesFromModule(the_module)
        except Exception as e:
            errmsg = f"Unable to import module {the_module_name} in order to gather workflow engines, due errors:"
            self.logger.exception(errmsg)
            raise WfExSBackendException(errmsg) from e

    def findAndAddWorkflowEnginesFromModule(
        self,
        the_module: "ModuleType",
    ) -> None:
        for finder, module_name, ispkg in iter_namespace(the_module):
            try:
                named_module = importlib.import_module(module_name)
            except:
                self.logger.exception(
                    f"Skipping module {module_name} in order to gather workflow engines, due errors:"
                )
                continue

            for name, obj in inspect.getmembers(named_module):
                if (
                    inspect.isclass(obj)
                    and not inspect.isabstract(obj)
                    and issubclass(obj, WorkflowEngine)
                ):
                    # Now, let's learn whether the class is enabled
                    if obj.MyWorkflowType().enabled:
                        self.addWorkflowEngine(obj)
                    else:
                        self.logger.debug(
                            f"Workflow engine class {name} from module {named_module} was not eligible"
                        )

    def addWorkflowEngine(self, workflowEngineClazz: "Type[WorkflowEngine]") -> None:
        self._workflow_engines[
            workflowEngineClazz.MyWorkflowType().shortname
        ] = workflowEngineClazz

    def listWorkflowEngines(self) -> "Sequence[str]":
        return list(self._workflow_engines.keys())

    def listWorkflowEngineClasses(self) -> "Sequence[Type[WorkflowEngine]]":
        return list(self._workflow_engines.values())

    def getWorkflowEngineClass(
        self, engine_shortname: "str"
    ) -> "Optional[Type[WorkflowEngine]]":
        return self._workflow_engines.get(engine_shortname)

    def matchWorkflowType(
        self,
        mainEntityProgrammingLanguageUrl: "str",
        mainEntityProgrammingLanguageId: "Optional[str]",
    ) -> "WorkflowType":
        # Now, it is time to match the language id
        engineDescById: "Optional[WorkflowType]" = None
        engineDescByUrl: "Optional[WorkflowType]" = None
        for possibleEngineDesc in self.WORKFLOW_ENGINES:
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
                "Found programming language {} (url {}) in RO-Crate manifest is not among the supported ones by WfExS-backend".format(
                    mainEntityProgrammingLanguageId, mainEntityProgrammingLanguageUrl
                )
            )

        if (
            (engineDescById is not None)
            and (engineDescByUrl is not None)
            and engineDescById != engineDescByUrl
        ):
            self.logger.warning(
                "Queried programming language {} and its url {} lead to different engines".format(
                    mainEntityProgrammingLanguageId, mainEntityProgrammingLanguageUrl
                )
            )

        return engineDesc

    def findAndAddContainerFactoriesFromModuleName(
        self,
        the_module_name: "str" = "wfexs_backend.container_factories",
    ) -> None:
        try:
            the_module = importlib.import_module(the_module_name)
            self.findAndAddContainerFactoriesFromModule(the_module)
        except Exception as e:
            errmsg = f"Unable to import module {the_module_name} in order to gather container factories, due errors:"
            self.logger.exception(errmsg)
            raise WfExSBackendException(errmsg) from e

    def findAndAddContainerFactoriesFromModule(
        self,
        the_module: "ModuleType",
    ) -> None:
        for finder, module_name, ispkg in iter_namespace(the_module):
            try:
                named_module = importlib.import_module(module_name)
            except:
                self.logger.exception(
                    f"Skipping module {module_name} in order to gather container factories, due errors:"
                )
                continue

            for name, obj in inspect.getmembers(named_module):
                if (
                    inspect.isclass(obj)
                    and not inspect.isabstract(obj)
                    and issubclass(obj, ContainerFactory)
                ):
                    # Now, let's learn whether the class is enabled
                    if getattr(obj, "ENABLED", False):
                        self.addContainerFactory(obj)
                    else:
                        self.logger.debug(
                            f"Container factory class {name} from module {named_module} was not eligible"
                        )

    def addContainerFactory(
        self, containerFactoryClazz: "Type[ContainerFactory]"
    ) -> None:
        self._container_factories[
            containerFactoryClazz.ContainerType()
        ] = containerFactoryClazz

    def listImplementedContainerTypes(self) -> "Sequence[ContainerType]":
        return list(self._container_factories.keys())

    def listContainerFactoryClasses(self) -> "Sequence[Type[ContainerFactory]]":
        return list(self._container_factories.values())

    def getContainerFactoryClass(
        self, container_type: "ContainerType"
    ) -> "Optional[Type[ContainerFactory]]":
        return self._container_factories.get(container_type)

    def findAndAddExportPluginsFromModuleName(
        self,
        the_module_name: "str" = "wfexs_backend.pushers",
    ) -> None:
        try:
            the_module = importlib.import_module(the_module_name)
            self.findAndAddExportPluginsFromModule(the_module)
        except Exception as e:
            errmsg = f"Unable to import module {the_module_name} in order to gather export plugins, due errors:"
            self.logger.exception(errmsg)
            raise WfExSBackendException(errmsg) from e

    def findAndAddExportPluginsFromModule(
        self,
        the_module: "ModuleType",
    ) -> None:
        for finder, module_name, ispkg in iter_namespace(the_module):
            try:
                named_module = importlib.import_module(module_name)
            except:
                self.logger.exception(
                    f"Skipping module {module_name} in order to gather export plugins, due errors:"
                )
                continue

            for name, obj in inspect.getmembers(named_module):
                if (
                    inspect.isclass(obj)
                    and not inspect.isabstract(obj)
                    and issubclass(obj, AbstractExportPlugin)
                ):
                    # Now, let's learn whether the class is enabled
                    if getattr(obj, "ENABLED", False):
                        self.addExportPlugin(obj)
                    else:
                        self.logger.debug(
                            f"Export class {name} from module {named_module} was not eligible"
                        )

    def addExportPlugin(self, exportClazz: "Type[AbstractExportPlugin]") -> None:
        self._export_plugins[exportClazz.PluginName()] = exportClazz

    def listExportPluginNames(self) -> "Sequence[SymbolicName]":
        return list(self._export_plugins.keys())

    def getExportPluginClass(
        self, plugin_id: "SymbolicName"
    ) -> "Optional[Type[AbstractExportPlugin]]":
        return self._export_plugins.get(plugin_id)

    def findAndAddSchemeHandlersFromModuleName(
        self,
        the_module_name: "str" = "wfexs_backend.fetchers",
        fetchers_setup_block: "Optional[Mapping[str, Mapping[str, Any]]]" = None,
    ) -> None:
        try:
            the_module = importlib.import_module(the_module_name)
            self.findAndAddSchemeHandlersFromModule(
                the_module,
                fetchers_setup_block=fetchers_setup_block,
            )
        except Exception as e:
            errmsg = f"Unable to import module {the_module_name} in order to gather scheme handlers, due errors:"
            self.logger.exception(errmsg)
            raise WfExSBackendException(errmsg) from e

    def findAndAddSchemeHandlersFromModule(
        self,
        the_module: "ModuleType",
        fetchers_setup_block: "Optional[Mapping[str, Mapping[str, Any]]]" = None,
    ) -> None:
        for finder, module_name, ispkg in iter_namespace(the_module):
            try:
                named_module = importlib.import_module(module_name)
            except:
                self.logger.exception(
                    f"Skipping module {module_name} in order to gather scheme handlers, due errors:"
                )
                continue

            # First, try locating a variable named SCHEME_HANDLERS
            # then, the different class declarations inheriting
            # from AbstractStatefulFetcher
            skipit = True
            for name, obj in inspect.getmembers(named_module):
                if name == "SCHEME_HANDLERS":
                    if isinstance(obj, dict):
                        self.addSchemeHandlers(
                            obj,
                            fetchers_setup_block=fetchers_setup_block,
                        )
                        skipit = False
                elif (
                    inspect.isclass(obj)
                    and not inspect.isabstract(obj)
                    and issubclass(obj, AbstractStatefulFetcher)
                ):
                    # Now, let's learn whether the class is enabled
                    if getattr(obj, "ENABLED", False):
                        self.addStatefulSchemeHandlers(
                            obj,
                            fetchers_setup_block=fetchers_setup_block,
                        )
                        skipit = False

            if skipit:
                self.logger.debug(
                    f"Fetch module {named_module} was not eligible (no SCHEME_HANDLERS dictionary or subclass of {AbstractStatefulFetcher.__name__})"
                )

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

                        # Also, if it is a repository fetcher, record it separately
                        if isinstance(instSchemeInstance, AbstractRepoFetcher):
                            self.repo_fetchers.append(instSchemeInstance)
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

    def gen_workflow_pid(self, remote_repo: "RemoteRepo") -> "str":
        """
        This method tries generating the workflow pid passing the remote
        repo to each one of the registered repo fetchers. The contract
        is that BuildPIDFromRepo should return None if it does not
        recognize the repo_url as usable.
        """
        retval: "Optional[str]" = None

        for fetcher in self.repo_fetchers:
            retval = fetcher.build_pid_from_repo(remote_repo)
            if retval is not None:
                break

        return remote_repo.repo_url if retval is None else retval

    def describeFetchableSchemes(self) -> "Sequence[Tuple[str, str, int]]":
        return self.cacheHandler.describeRegisteredSchemes()

    def newSetup(
        self,
        workflow_id: "WorkflowId",
        version_id: "Optional[WFVersionId]" = None,
        descriptor_type: "Optional[TRS_Workflow_Descriptor]" = None,
        trs_endpoint: "str" = WF.DEFAULT_TRS_ENDPOINT,
        params: "Optional[ParamsBlock]" = None,
        enabled_profiles: "Optional[Sequence[str]]" = None,
        environment: "Optional[EnvironmentBlock]" = None,
        outputs: "Optional[OutputsBlock]" = None,
        default_actions: "Optional[Sequence[ExportActionBlock]]" = None,
        workflow_config: "Optional[WorkflowConfigBlock]" = None,
        vault: "Optional[SecurityContextVault]" = None,
        public_key_filenames: "Sequence[pathlib.Path]" = [],
        private_key_filename: "Optional[pathlib.Path]" = None,
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
            enabled_profiles=enabled_profiles,
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
    ) -> "Tuple[WfExSInstanceId, str, datetime.datetime, Sequence[str], pathlib.Path]":
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
    ) -> "Tuple[WfExSInstanceId, str, datetime.datetime, Sequence[str], pathlib.Path]":
        """
        This method returns the absolute path to the raw working directory
        """
        # TODO: Add some validation about the working directory
        uniqueRawWorkDir = self.baseWorkDir / instanceId

        return self.parseOrCreateRawWorkDir(
            uniqueRawWorkDir, instanceId, nickname, orcids=orcids, create_ok=create_ok
        )

    def parseOrCreateRawWorkDir(
        self,
        uniqueRawWorkDir: "pathlib.Path",
        instanceId: "Optional[WfExSInstanceId]" = None,
        nickname: "Optional[str]" = None,
        orcids: "Sequence[str]" = [],
        create_ok: "bool" = False,
    ) -> "Tuple[WfExSInstanceId, str, datetime.datetime, Sequence[str], pathlib.Path]":
        """
        This method returns the absolute path to the raw working directory
        """
        # TODO: Add some validation about the working directory
        id_json_path = uniqueRawWorkDir / self.ID_JSON_FILENAME
        creation: "Optional[datetime.datetime]"
        if not uniqueRawWorkDir.exists():
            if not create_ok:
                raise WfExSBackendException(
                    f"Creation of {uniqueRawWorkDir} is not allowed by parameter"
                )

            uniqueRawWorkDir.mkdir(parents=True, exist_ok=True)
            if instanceId is None:
                instanceId = cast("WfExSInstanceId", uniqueRawWorkDir.name)
            if nickname is None:
                nickname = self.GetPassGen().generate_nickname()
            creation = datetime.datetime.now(tz=datetime.timezone.utc)
            with id_json_path.open(mode="w", encoding="utf-8") as idF:
                idNick = {
                    "instance_id": instanceId,
                    "nickname": nickname,
                    "creation": creation,
                    "orcids": orcids,
                }
                json.dump(idNick, idF, cls=DatetimeEncoder)
            id_json_path.chmod(stat.S_IRUSR | stat.S_IRGRP | stat.S_IROTH)
        elif id_json_path.exists():
            with id_json_path.open(mode="r", encoding="utf-8") as iH:
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
            instanceId = cast("WfExSInstanceId", uniqueRawWorkDir.name)
            nickname = instanceId
            creation = None
            orcids = []

        if creation is None:
            # Just guessing
            w_m_path = (
                uniqueRawWorkDir / WORKDIR_META_RELDIR / WORKDIR_WORKFLOW_META_FILE
            )
            workdir_passphrase_file = uniqueRawWorkDir / WORKDIR_PASSPHRASE_FILE
            if w_m_path.exists():
                # This is valid for unencrypted working directories
                reference_path = w_m_path
            elif workdir_passphrase_file.exists():
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
        self, uniqueRawWorkDir: "pathlib.Path"
    ) -> "Tuple[WfExSInstanceId, str, datetime.datetime, Sequence[str], pathlib.Path]":
        """
        This method returns the id of a working directory,
        as well as the nickname
        """
        if uniqueRawWorkDir is None:
            raise WfExSBackendException("Unable to initialize, no directory provided")

        # Obtaining the absolute path to the working directory
        if not uniqueRawWorkDir.is_absolute():
            uniqueRawWorkDir = (self.baseWorkDir / uniqueRawWorkDir).resolve()

        if not uniqueRawWorkDir.is_dir():
            raise WfExSBackendException(
                "Unable to initialize, {} is not a directory".format(uniqueRawWorkDir)
            )

        return self.parseOrCreateRawWorkDir(uniqueRawWorkDir, create_ok=False)

    def fromWorkDir(
        self,
        workflowWorkingDirectory: "pathlib.Path",
        private_key_filename: "Optional[pathlib.Path]" = None,
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
        workflowMetaFilename: "pathlib.Path",
        securityContextsConfigFilename: "Optional[pathlib.Path]" = None,
        nickname_prefix: "Optional[str]" = None,
        orcids: "Sequence[str]" = [],
        public_key_filenames: "Sequence[pathlib.Path]" = [],
        private_key_filename: "Optional[pathlib.Path]" = None,
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
        securityContextsConfigFilename: "Optional[pathlib.Path]" = None,
        replaced_parameters_filename: "Optional[pathlib.Path]" = None,
        nickname_prefix: "Optional[str]" = None,
        orcids: "Sequence[str]" = [],
        public_key_filenames: "Sequence[pathlib.Path]" = [],
        private_key_filename: "Optional[pathlib.Path]" = None,
        private_key_passphrase: "Optional[str]" = None,
        secure: "bool" = True,
        paranoidMode: "bool" = False,
        reproducibility_level: "ReproducibilityLevel" = ReproducibilityLevel.Metadata,
        strict_reproducibility_level: "bool" = False,
    ) -> "WF":
        return WF.FromPreviousInstanceDeclaration(
            self,
            wfInstance,
            securityContextsConfigFilename=securityContextsConfigFilename,
            replaced_parameters_filename=replaced_parameters_filename,
            nickname_prefix=nickname_prefix,
            orcids=orcids,
            public_key_filenames=public_key_filenames,
            private_key_filename=private_key_filename,
            private_key_passphrase=private_key_passphrase,
            secure=secure,
            paranoidMode=paranoidMode,
            reproducibility_level=reproducibility_level,
            strict_reproducibility_level=strict_reproducibility_level,
        )

    def fromPreviousROCrate(
        self,
        workflowROCrateFilenameOrURI: "Union[AnyPath, URIType]",
        securityContextsConfigFilename: "Optional[pathlib.Path]" = None,
        replaced_parameters_filename: "Optional[pathlib.Path]" = None,
        nickname_prefix: "Optional[str]" = None,
        orcids: "Sequence[str]" = [],
        public_key_filenames: "Sequence[pathlib.Path]" = [],
        private_key_filename: "Optional[pathlib.Path]" = None,
        private_key_passphrase: "Optional[str]" = None,
        secure: "bool" = True,
        paranoidMode: "bool" = False,
        reproducibility_level: "ReproducibilityLevel" = ReproducibilityLevel.Metadata,
        strict_reproducibility_level: "bool" = False,
        retrospective_first: "bool" = True,
    ) -> "WF":
        # Let's check whether it is a local file
        # or a remote RO-Crate
        parsedROCrateURI = urllib.parse.urlparse(workflowROCrateFilenameOrURI)
        if parsedROCrateURI.scheme == "":
            workflowROCrateFilename = pathlib.Path(workflowROCrateFilenameOrURI)
        else:
            self.logger.info(f"* Fetching RO-Crate {workflowROCrateFilenameOrURI}")
            local_content = self.cacheFetch(
                cast("URIType", workflowROCrateFilenameOrURI),
                cacheType=CacheType.ROCrate,
                offline=False,
                ignoreCache=paranoidMode,
                registerInCache=not paranoidMode,
            )

            workflowROCrateFilename = local_content.path

        return WF.FromPreviousROCrate(
            self,
            workflowROCrateFilename,
            public_name=workflowROCrateFilenameOrURI,
            securityContextsConfigFilename=securityContextsConfigFilename,
            replaced_parameters_filename=replaced_parameters_filename,
            nickname_prefix=nickname_prefix,
            orcids=orcids,
            public_key_filenames=public_key_filenames,
            private_key_filename=private_key_filename,
            private_key_passphrase=private_key_passphrase,
            secure=secure,
            paranoidMode=paranoidMode,
            reproducibility_level=reproducibility_level,
            strict_reproducibility_level=strict_reproducibility_level,
            retrospective_first=retrospective_first,
        )

    def parseAndValidateSecurityContextFile(
        self, securityContextsConfigFilename: "pathlib.Path"
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
        workflowMetaFilename: "Union[pathlib.Path, WorkflowMetaConfigBlock]",
        securityContextsConfigFilename: "Optional[pathlib.Path]" = None,
    ) -> "ExitVal":
        numErrors = 0
        workflow_meta: "WorkflowMetaConfigBlock"

        if isinstance(workflowMetaFilename, pathlib.Path):
            self.logger.info(f"Validating {workflowMetaFilename}")

            with workflowMetaFilename.open(mode="r", encoding="utf-8") as wcf:
                workflow_meta = unmarshall_namedtuple(yaml.safe_load(wcf))

            if not isinstance(workflow_meta, dict):
                workflow_meta = {}
        else:
            self.logger.info(f"Validating inline configuration")
            workflow_meta = workflowMetaFilename

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
        if securityContextsConfigFilename and securityContextsConfigFilename.exists():
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
        public_key_filenames: "Sequence[pathlib.Path]" = [],
        private_key_filename: "Optional[pathlib.Path]" = None,
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
        public_key_filenames: "Sequence[pathlib.Path]" = [],
        private_key_filename: "Optional[pathlib.Path]" = None,
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
        workdir_passphrase_file: "pathlib.Path",
        private_key_filename: "Optional[pathlib.Path]" = None,
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

        with workdir_passphrase_file.open(mode="rb") as encF:
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

        if secureWorkdirPassphrase == "":
            errmsg = "Encryption filesystem key does not follow the right format"
            self.logger.error(errmsg)
            raise WfExSBackendException(errmsg)

        try:
            encfs_type = EncryptedFSType(encfs_type_str)
        except:
            errmsg = (
                f"Invalid encryption filesystem {encfs_type_str} in working directory"
            )
            raise WfExSBackendException(errmsg)

        if encfs_type not in ENCRYPTED_FS_MOUNT_IMPLEMENTATIONS:
            errmsg = f"FIXME: Encryption filesystem {encfs_type_str} mount procedure is not implemented"
            self.logger.fatal(errmsg)
            raise WfExSBackendException(errmsg)

        # If the working directory encrypted filesystem does not
        # match the configured one, use its default executable
        if encfs_type != self.encfs_type:
            encfs_cmd = DEFAULT_ENCRYPTED_FS_CMD[encfs_type]
        else:
            encfs_cmd = self.encfs_cmd

        abs_encfs_cmd = shutil.which(encfs_cmd)
        if abs_encfs_cmd is None:
            errmsg = f"FUSE filesystem command {encfs_cmd}, needed by {encfs_type}, was not found. Please install it in order to access the encrypted working directory"
            self.logger.fatal(errmsg)
            raise WfExSBackendException(errmsg)

        return encfs_type, cast("AbsPath", abs_encfs_cmd), secureWorkdirPassphrase

    def generateSecuredWorkdirPassphrase(
        self,
        workdir_passphrase_file: "pathlib.Path",
        private_key_filename: "Optional[pathlib.Path]" = None,
        private_key_passphrase: "Optional[str]" = None,
        public_key_filenames: "Sequence[pathlib.Path]" = [],
    ) -> "Tuple[EncryptedFSType, AnyPath, str, Sequence[pathlib.Path]]":
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
                private_key_filename.as_posix(), lambda: private_key_passphrase_r
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
                pub_key = crypt4gh.keys.get_public_key(pub_key_filename.as_posix())
                public_keys.append(pub_key)

        encrypt_keys: "MutableSequence[CompoundKey]" = []
        for pub_key in public_keys:
            encrypt_keys.append((0, private_key, pub_key))
        with workdir_passphrase_file.open(mode="wb") as encF:
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
        private_key_filename: "Optional[pathlib.Path]" = None,
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
                        ) = self.parseOrCreateRawWorkDir(
                            pathlib.Path(entry.path), create_ok=False
                        )
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
        private_key_filename: "Optional[pathlib.Path]" = None,
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
                else:
                    mStatus = None

                yield instance_id, nickname, creation, wfSetup, mStatus

    def removeStagedWorkflows(
        self,
        *args: "str",
        acceptGlob: "bool" = False,
        private_key_filename: "Optional[pathlib.Path]" = None,
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
        private_key_filename: "Optional[pathlib.Path]" = None,
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
                if workflow_dir.is_dir()
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
            container_factory_classes=self.listContainerFactoryClasses(),
            progs_mapping=self.progs,
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

        remote_repo = SoftwareHeritageFetcher.GuessRepoParams(
            parsedRepoURL, logger=self.logger, fail_ok=fail_ok
        )
        if remote_repo is None:
            # Assume it might be a git repo or a link to a git repo
            remote_repo = GitFetcher.GuessRepoParams(
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
        meta_dir: "Optional[pathlib.Path]" = None,
    ) -> "Tuple[pathlib.Path, RemoteRepo, Optional[WorkflowType], Optional[RepoTag]]":
        """
        Fetch the whole workflow description based on the data obtained
        from the TRS where it is being published.

        If the workflow id is an URL, it is supposed to be a git repository,
        and the version will represent either the branch, tag or specific commit.
        So, the whole TRS fetching machinery is bypassed.
        """

        requested_workflow_type: "Optional[WorkflowType]" = None
        if descriptor_type is not None:
            # First, try with the workflow type shortname
            requested_workflow_type = self.RECOGNIZED_SHORTNAME_DESCRIPTORS.get(
                descriptor_type
            )
            if requested_workflow_type is None:
                # then, with the workflow type TRS name
                requested_workflow_type = self.RECOGNIZED_TRS_DESCRIPTORS.get(
                    descriptor_type
                )

            if requested_workflow_type is None:
                self.logger.warning(
                    f"Workflow of type {descriptor_type} is not supported by this version of WfExS-backend"
                )

        putative_repo_url = str(workflow_id)
        parsedRepoURL = urllib.parse.urlparse(putative_repo_url)

        # It is not an absolute URL, so it is being an identifier in the workflow
        i_workflow: "Optional[IdentifiedWorkflow]" = None
        engineDesc: "Optional[WorkflowType]" = None
        guessedRepo: "Optional[RemoteRepo]" = None
        repoDir: "Optional[pathlib.Path]" = None
        putative: "bool" = False
        cached_putative_path: "Optional[pathlib.Path]" = None
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
                    if repoDir.is_dir():
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
            if (
                requested_workflow_type is not None
                and requested_workflow_type != i_workflow.workflow_type
            ):
                message = f"Fetched workflow is of type {i_workflow.workflow_type.shortname} , but it was explicitly requested to be of type {requested_workflow_type.shortname}"
                self.logger.error(message)
                raise WfExSBackendException(message)

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
        meta_dir: "Optional[pathlib.Path]" = None,
    ) -> "Tuple[IdentifiedWorkflow, Optional[pathlib.Path]]":
        """

        :return:
        """

        # If nothing is set, just create a temporary directory
        if meta_dir is None:
            meta_dir = pathlib.Path(
                tempfile.mkdtemp(prefix="WfExS", suffix="TRSFetched")
            )
            # Assuring this temporal directory is removed at the end
            atexit.register(shutil.rmtree, meta_dir, True)
        else:
            # Assuring the destination directory does exist
            meta_dir.mkdir(parents=True, exist_ok=True)

        if isinstance(workflow_id, int):
            workflow_id_str = str(workflow_id)
        else:
            workflow_id_str = workflow_id

        # Now, time to check whether it is a TRSv2
        trs_endpoint_v2_meta_url = cast("URIType", trs_endpoint + "service-info")
        trs_endpoint_v2_beta2_meta_url = cast("URIType", trs_endpoint + "metadata")
        trs_endpoint_meta_url = None

        # Needed to store this metadata
        trsMetadataCache = meta_dir / self.TRS_METADATA_FILE

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
        if not trsMetadataCache.exists():
            os.symlink(trs_cached_content.path.name, trsMetadataCache)

        with trsMetadataCache.open(mode="r", encoding="utf-8") as ctmf:
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

        trsQueryCache = meta_dir / self.TRS_QUERY_CACHE_FILE
        trs_cached_tool = self.cacheHandler.fetch(
            trs_tools_url, destdir=meta_dir, offline=offline, ignoreCache=ignoreCache
        )
        # Giving a friendly name
        if not trsQueryCache.exists():
            os.symlink(trs_cached_tool.path.name, trsQueryCache)

        with trsQueryCache.open(mode="r", encoding="utf-8") as tQ:
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
            for candidateDescriptorType in self.RECOGNIZED_TRS_DESCRIPTORS.keys():
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
        elif chosenDescriptorType not in self.RECOGNIZED_TRS_DESCRIPTORS:
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
                expectedEngineDesc=self.RECOGNIZED_TRS_DESCRIPTORS[
                    chosenDescriptorType
                ],
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

            expectedEngineDesc = self.RECOGNIZED_TRS_DESCRIPTORS[chosenDescriptorType]
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
    ) -> "Tuple[pathlib.Path, RepoTag]":
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
            kind = ContentKind.Directory if repo_path.is_dir() else ContentKind.File
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
    ) -> "Tuple[URIType, RepoTag, pathlib.Path, Sequence[URIWithMetadata]]":
        """

        :param repoURL:
        :param repoTag:
        :param doUpdate:
        :return:
        """
        gitFetcherInst = self.instantiateRepoFetcher(GitFetcher)
        repoDir, materialized_repo, metadata_array = gitFetcherInst.materialize_repo(
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

        repo_desc: "Optional[Mapping[str, Any]]" = materialized_repo.gen_repo_desc()
        if repo_desc is None:
            repo_desc = {}
        augmented_metadata_array = [
            URIWithMetadata(
                uri=cast("URIType", remote_url),
                metadata=repo_desc,
            ),
            *metadata_array,
        ]
        return (
            cast("URIType", remote_url),
            materialized_repo.get_checkout(),
            repoDir,
            augmented_metadata_array,
        )

    def _doMaterializeSoftwareHeritageDirOrContent(
        self,
        repo: "RemoteRepo",
        doUpdate: "bool" = True,
    ) -> "Tuple[URIType, RepoTag, pathlib.Path, Sequence[URIWithMetadata]]":
        """

        :param repoURL:
        :param repoTag:
        :param doUpdate:
        :return:
        """
        swhFetcherInst = self.instantiateRepoFetcher(SoftwareHeritageFetcher)
        repoDir, materialized_repo, metadata_array = swhFetcherInst.materialize_repo(
            cast("RepoURL", repo.tag) if repo.tag is not None else repo.repo_url,
            doUpdate=doUpdate,
            base_repo_destdir=self.cacheWorkflowDir,
        )

        repo_desc: "Optional[Mapping[str, Any]]" = materialized_repo.gen_repo_desc()
        if repo_desc is None:
            repo_desc = {}
        augmented_metadata_array = [
            URIWithMetadata(
                uri=cast("URIType", repo.repo_url),
                metadata=repo_desc,
            ),
            *metadata_array,
        ]
        return (
            repo.repo_url,
            materialized_repo.get_checkout(),
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
    ) -> "Tuple[Optional[IdentifiedWorkflow], pathlib.Path, Sequence[URIWithMetadata]]":
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

        if cached_content.path.is_file():
            # Now, let's guess whether it is a possible RO-Crate or a bare file
            encoding = magic.from_file(cached_content.path.as_posix(), mime=True)
        else:
            # A directory does not have mime type
            encoding = ""
        if encoding == "application/zip":
            self.logger.info(
                "putative workflow {} seems to be a packed RO-Crate".format(remote_url)
            )

            crate_hashed_id = hashlib.sha1(remote_url.encode("utf-8")).hexdigest()
            roCrateFile = pathlib.Path(self.cacheROCrateDir) / (
                crate_hashed_id + self.DEFAULT_RO_EXTENSION
            )
            if not roCrateFile.exists():
                if os.path.lexists(roCrateFile):
                    roCrateFile.unlink()
                os.symlink(
                    os.path.relpath(cached_content.path, self.cacheROCrateDir),
                    roCrateFile,
                )

            return (
                self.getWorkflowRepoFromROCrateFile(roCrateFile, expectedEngineDesc),
                roCrateFile,
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
        roCrateFile: "pathlib.Path",
        expectedEngineDesc: "Optional[WorkflowType]" = None,
    ) -> "IdentifiedWorkflow":
        """

        :param roCrateFile:
        :param expectedEngineDesc: If defined, an instance of WorkflowType
        :return:
        """

        public_name = str(roCrateFile)
        jsonld_obj, payload_dir = ReadROCrateMetadata(
            roCrateFile, public_name=public_name
        )
        matched_crate, g = self.rocrate_toolbox.identifyROCrate(
            jsonld_obj, public_name=public_name
        )
        # Is it an RO-Crate?
        if matched_crate is None:
            raise WfExSBackendException(
                f"JSON-LD from {public_name} is not an RO-Crate"
            )

        if matched_crate.wfcrateprofile is None:
            raise WfExSBackendException(
                f"JSON-LD from {public_name} is not a Workflow RO-Crate"
            )

        if matched_crate.mainentity is None:
            raise WfExSBackendException(
                f"Unable to find the main entity workflow at {public_name} Workflow RO-Crate"
            )

        # This workflow URL, in the case of github, can provide the repo,
        # the branch/tag/checkout , and the relative directory in the
        # fetched content (needed by Nextflow)

        # Some RO-Crates might have this value missing or ill-built
        repo, workflow_type, _ = self.rocrate_toolbox.extractWorkflowMetadata(
            g,
            matched_crate.mainentity,
            default_repo=str(matched_crate.wfhrepourl),
            public_name=public_name,
        )

        if (expectedEngineDesc is not None) and workflow_type != expectedEngineDesc:
            raise WfExSBackendException(
                "Expected programming language {} does not match identified one {} in RO-Crate manifest".format(
                    expectedEngineDesc.engineName, workflow_type.engineName
                )
            )

        # We need this additional step to guess the repo type
        guessedRepo = self.guess_repo_params(repo.repo_url, fail_ok=True)
        if guessedRepo is None or guessedRepo.repo_type is None:
            raise WfExSBackendException(
                f"Unable to guess repository from RO-Crate manifest obtained from {public_name}"
            )

        # Rescuing some values
        if repo.tag is not None and guessedRepo.tag is None:
            guessedRepo = guessedRepo._replace(tag=repo.tag)

        if repo.rel_path is not None and (
            guessedRepo.rel_path is None or len(guessedRepo.rel_path) == 0
        ):
            guessedRepo = guessedRepo._replace(rel_path=repo.rel_path)

        if repo.web_url is not None:
            guessedRepo = guessedRepo._replace(web_url=repo.web_url)

        # It must return four elements:
        return IdentifiedWorkflow(workflow_type=workflow_type, remote_repo=guessedRepo)

    DEFAULT_RO_EXTENSION: "Final[str]" = ".crate.zip"

    def cacheROcrate(
        self,
        roCrateURL: "URIType",
        offline: "bool" = False,
        ignoreCache: "bool" = False,
    ) -> "pathlib.Path":
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
        cachedFilename = self.cacheROCrateDir / (
            crate_hashed_id + self.DEFAULT_RO_EXTENSION
        )
        if not cachedFilename.exists():
            os.symlink(os.path.basename(cached_rocrate.path), cachedFilename)

        return cachedFilename

    def downloadContent(
        self,
        remote_file: "Union[LicensedURI, Sequence[LicensedURI]]",
        dest: "Union[pathlib.Path, CacheType]",
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
        workflowInputs_destdir: "pathlib.Path"
        if isinstance(dest, CacheType):
            workflowInputs_destdir = self.cachePathMap[dest]
        else:
            workflowInputs_destdir = dest

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
            local=pathlib.Path(cached_content.path),
            licensed_uri=firstLicensedURI,
            prettyFilename=prettyFilename,
            kind=cached_content.kind,
            metadata_array=cached_content.metadata_array,
            fingerprint=cached_content.fingerprint,
        )

    _LicenceMatcher: "ClassVar[Optional[LicenceMatcher]]" = None

    @classmethod
    def GetLicenceMatcher(cls) -> "LicenceMatcher":
        if cls._LicenceMatcher is None:
            cls._LicenceMatcher = LicenceMatcherSingleton()
            assert cls._LicenceMatcher is not None

        return cls._LicenceMatcher

    def curate_licence_list(
        self,
        licences: "Sequence[str]",
        default_licence: "Optional[LicenceDescription]" = None,
    ) -> "Sequence[LicenceDescription]":
        # As these licences can be in short format, resolve them to URIs
        expanded_licences: "MutableSequence[LicenceDescription]" = []
        if len(licences) == 0:
            expanded_licences.append(NoLicenceDescription)
        else:
            licence_matcher = self.GetLicenceMatcher()
            rejected_licences: "MutableSequence[str]" = []
            for lic in licences:
                matched_licence = licence_matcher.matchLicence(lic)
                if matched_licence is None:
                    rejected_licences.append(lic)
                    if default_licence is not None:
                        expanded_licences.append(default_licence)
                else:
                    expanded_licences.append(matched_licence)

            if len(rejected_licences) > 0:
                if default_licence is None:
                    raise WFException(
                        f"Unsupported license URI scheme(s) or Workflow RO-Crate short license(s): {', '.join(rejected_licences)}"
                    )
                else:
                    self.logger.warning(
                        f"Default license {default_licence} used instead of next unsupported license URI scheme(s) or Workflow RO-Crate short license(s): {', '.join(rejected_licences)}"
                    )

        return expanded_licences
