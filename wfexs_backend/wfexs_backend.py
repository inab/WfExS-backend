#!/usr/bin/env python
# -*- coding: utf-8 -*-

# SPDX-License-Identifier: Apache-2.0
# Copyright 2020-2025 Barcelona Supercomputing Center (BSC), Spain
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

from RWFileLock import RWFileLock

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


from .scheme_catalog import (
    SchemeCatalog,
)

from .cache_handler import (
    CachedContent,
    CacheHandler,
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
    marshall_namedtuple,
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
    ROCRATE_JSONLD_FILENAME,
    ROCrateToolbox,
)

from .fetchers import (
    AbstractSchemeRepoFetcher,
    AbstractStatefulFetcher,
    DocumentedProtocolFetcher,
    DocumentedStatefulProtocolFetcher,
    FetcherException,
    MaterializedRepo,
    RemoteRepo,
    RepoGuessFlavor,  # This is needed for proper unmarshalling of cached repository guesses
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
    GA4GHTRSFetcher,
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
        SchemeRepoFetcher,
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

        logger = logging.getLogger(
            dict(inspect.getmembers(cls))["__module__"] + "::" + cls.__name__
        )

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

        parsed_workflow_id = urllib.parse.urlparse(workflow_meta["workflow_id"])
        trs_endpoint: "Optional[str]"
        if parsed_workflow_id.scheme != "":
            trs_endpoint = workflow_meta.get("trs_endpoint")
        else:
            trs_endpoint = workflow_meta.get("trs_endpoint", WF.DEFAULT_TRS_ENDPOINT)

        return cls(updated_local_config, config_directory=config_directory).newSetup(
            workflow_meta["workflow_id"],
            workflow_meta.get("version"),
            descriptor_type=workflow_meta.get("workflow_type"),
            trs_endpoint=trs_endpoint,
            prefer_upstream_source=workflow_meta.get("prefer_upstream_source"),
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
            key_path: "MutableSequence[Tuple[SymbolicName, str]]" = []
            if keyC.endswith("Command"):
                prog_key = keyC[0 : -len("Command")]
                key_path.append((cast("SymbolicName", prog_key), pathC))
            elif keyC == "commands":
                assert isinstance(pathC, list)

                for command_block in pathC:
                    assert isinstance(command_block, dict)

                    if "key" in command_block and "path" in command_block:
                        key_path.append(
                            (
                                cast("SymbolicName", command_block["key"]),
                                command_block["path"],
                            )
                        )

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

        self._sngltn_fetcher: "MutableMapping[Type[AbstractStatefulFetcher], AbstractStatefulFetcher]" = (
            dict()
        )
        # scheme_catalog is created on first use
        self.scheme_catalog = SchemeCatalog()
        # cacheHandler is created on first use
        self.cacheHandler = CacheHandler(
            self.cacheDir, scheme_catalog=self.scheme_catalog
        )

        fetchers_setup_block = local_config.get("fetchers-setup")

        # All the scheme handlers should be added here
        self._repo_fetchers = (
            self.scheme_catalog.findAndAddSchemeHandlersFromModuleName(
                fetchers_setup_block=fetchers_setup_block,
                progs=self.progs,
            )
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

    @property
    def repo_fetchers(self) -> "Sequence[AbstractSchemeRepoFetcher]":
        return sorted(self._repo_fetchers, key=lambda f: f.PRIORITY, reverse=True)

    def getCacheHandler(
        self, cache_type: "CacheType"
    ) -> "Tuple[CacheHandler, Optional[pathlib.Path]]":
        return self.cacheHandler, self.cachePathMap.get(cache_type)

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
        return self.scheme_catalog.describeRegisteredSchemes()

    def newSetup(
        self,
        workflow_id: "WorkflowId",
        version_id: "Optional[WFVersionId]" = None,
        descriptor_type: "Optional[TRS_Workflow_Descriptor]" = None,
        trs_endpoint: "Optional[str]" = None,
        prefer_upstream_source: "Optional[bool]" = None,
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
            prefer_upstream_source=prefer_upstream_source,
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
                wlock = RWFileLock(idF)
                with wlock.exclusive_lock():
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
                rlock = RWFileLock(iH)
                with rlock.shared_blocking_lock():
                    idNick = jsonFilterDecodeFromStream(iH)
                    instanceId = cast("WfExSInstanceId", idNick["instance_id"])
                    nickname = cast("str", idNick.get("nickname", instanceId))
                    creation = cast(
                        "Optional[datetime.datetime]", idNick.get("creation")
                    )
                    orcids = cast("Sequence[str]", idNick.get("orcids", []))

            # This file should not change
            if creation is None:
                creation = datetime.datetime.fromtimestamp(
                    os.path.getctime(id_json_path)
                ).astimezone()
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
                os.path.getctime(reference_path)
            ).astimezone()

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

    def tryWorkflowURI(
        self,
        workflow_uri: "str",
        securityContextsConfigFilename: "Optional[pathlib.Path]" = None,
        nickname_prefix: "Optional[str]" = None,
    ) -> "WF":
        return WF.TryWorkflowURI(
            self,
            workflow_uri,
            securityContextsConfigFilename=securityContextsConfigFilename,
            nickname_prefix=nickname_prefix,
        )

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
            rplock = RWFileLock(encF)
            with rplock.shared_blocking_lock():
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
            wplock = RWFileLock(encF)
            with wplock.exclusive_lock():
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

        for arg in args:
            entries.add(arg)

            # As we cannot be sure whether it is a filename or a string
            # add both the filename and the content of the file
            if os.path.isfile(arg):
                try:
                    with open(arg, mode="r", encoding="utf-8") as wdH:
                        query_id = wdH.readline().strip()
                        entries.add(query_id)
                except:
                    pass

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
                # The default (for sh)
                theEnv["PS1"] = f"(WfExS '{nickname}') {instance_id} "

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
        default_clonable: "bool" = True,
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
                default_clonable=default_clonable,
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

    def matchRepoFetcherByClassname(
        self, clazzname: "str"
    ) -> "Optional[AbstractSchemeRepoFetcher]":
        for fetcher in self._repo_fetchers:
            if fetcher.__class__.__name__ == clazzname:
                return fetcher

        return None

    def guess_repo_params(
        self,
        wf_url: "Union[URIType, parse.ParseResult]",
        fail_ok: "bool" = False,
        offline: "bool" = False,
        ignoreCache: "bool" = False,
        registerInCache: "bool" = True,
    ) -> "Optional[Tuple[RemoteRepo, AbstractSchemeRepoFetcher]]":
        remote_repo: "Optional[RemoteRepo]" = None
        fetcher: "Optional[AbstractSchemeRepoFetcher]" = None
        guess_cache = self.cacheWorkflowDir / "guess-cache"

        if not ignoreCache:
            try:
                # Let's check whether the workflow was registered
                # kind: "ContentKind"
                # path: "pathlib.Path"
                # metadata_array: "Sequence[URIWithMetadata]"
                # licences: "Tuple[URIType, ...]"
                # fingerprint: "Optional[Fingerprint]" = None
                # clonable: "bool" = True
                cached_content = self.cacheHandler.fetch(
                    cast("URIType", wf_url),
                    offline=True,
                    destdir=guess_cache,
                )
                # Always a cached metadata file
                assert cached_content.kind == ContentKind.File
                with cached_content.path.open(mode="r", encoding="utf-8") as ccH:
                    guessed_repo_payload = json.load(ccH)

                if isinstance(guessed_repo_payload, (tuple, list)):
                    remote_repo, fetcher_class_name = unmarshall_namedtuple(
                        guessed_repo_payload
                    )
                    # Now, time to find the fetcher itself
                    if remote_repo is not None:
                        fetcher = self.matchRepoFetcherByClassname(fetcher_class_name)
                        if fetcher is not None:
                            return remote_repo, fetcher
                    self.logger.debug(
                        f"Cached empty guessing elements associated to {wf_url}. Ignoring"
                    )
                elif offline:
                    # Do not try again if it is in offline mode
                    return None
            except Exception as e:
                self.logger.debug(f"Guessed {wf_url} not cached (exception {e})")

        if isinstance(wf_url, parse.ParseResult):
            parsedRepoURL = wf_url
        else:
            parsedRepoURL = urllib.parse.urlparse(wf_url)

        for fetcher in self.repo_fetchers:
            remote_repo = fetcher.GuessRepoParams(
                parsedRepoURL,
                logger=self.logger,
                fail_ok=fail_ok,
                offline=offline,
            )
            if remote_repo is not None:
                if registerInCache:
                    temp_cached = guess_cache / ("caching-" + str(uuid.uuid4()))
                    try:
                        with temp_cached.open(mode="w", encoding="utf-8") as tC:
                            json.dump(
                                marshall_namedtuple(
                                    (remote_repo, fetcher.__class__.__name__)
                                ),
                                tC,
                            )
                        self.cacheHandler.inject(
                            cast("URIType", wf_url),
                            destdir=guess_cache,
                            tempCachedFilename=temp_cached,
                            inputKind=ContentKind.File,
                        )
                    except Exception as e:
                        self.logger.exception(
                            f"Unable to register guess cache for {wf_url} (see exception trace)"
                        )
                    finally:
                        # Removing the leftovers, whether they worked or not
                        if temp_cached.exists():
                            temp_cached.unlink()

                return remote_repo, fetcher

        return None

    def cacheWorkflow(
        self,
        workflow_id: "WorkflowId",
        version_id: "Optional[WFVersionId]" = None,
        trs_endpoint: "Optional[str]" = None,
        descriptor_type: "Optional[TRS_Workflow_Descriptor]" = None,
        prefer_upstream_source: "bool" = True,
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
                    f"Workflow of type {descriptor_type} is not supported by this version of WfExS-backend. Switching to guess mode."
                )

        if (trs_endpoint is not None) and len(trs_endpoint) > 0:
            putative_repo_url = GA4GHTRSFetcher.BuildRepoPIDFromTRSParams(
                trs_endpoint, workflow_id, version_id
            )
        else:
            putative_repo_url = cast("URIType", str(workflow_id))

        parsedRepoURL = urllib.parse.urlparse(putative_repo_url)

        # It is not an absolute URL, so it is being an identifier in the workflow
        i_workflow: "Optional[IdentifiedWorkflow]" = None
        workflow_type: "Optional[WorkflowType]" = None
        guessedRepo: "Optional[RemoteRepo]" = None
        repoDir: "Optional[pathlib.Path]" = None
        putative: "bool" = False
        cached_putative_path: "Optional[pathlib.Path]" = None
        if parsedRepoURL.scheme == "":
            raise WFException("trs_endpoint was not provided")

        # Trying to be smarter
        guessed = self.guess_repo_params(
            parsedRepoURL,
            offline=offline,
            ignoreCache=ignoreCache,
            registerInCache=registerInCache,
            fail_ok=True,
        )
        if guessed is not None:
            guessedRepo = guessed[0]
            if guessedRepo.tag is None and version_id is not None:
                guessedRepo = RemoteRepo(
                    repo_url=guessedRepo.repo_url,
                    tag=cast("RepoTag", str(version_id)),
                    rel_path=guessedRepo.rel_path,
                    repo_type=guessedRepo.repo_type,
                    web_url=guessedRepo.web_url,
                )
        else:
            repoRelPath: "Optional[str]" = None
            (
                i_workflow,
                cached_putative_path,
                metadata_array,
                repoRelPath,
            ) = self.getWorkflowBundleFromURI(
                putative_repo_url,
                prefer_upstream_source=prefer_upstream_source,
                offline=offline,
                ignoreCache=ignoreCache,
                registerInCache=registerInCache,
            )

            if i_workflow is None:
                repoDir = cached_putative_path
                if not repoRelPath:
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
            else:
                # This can be incorrect, but let it be for now
                if (
                    requested_workflow_type is not None
                    and requested_workflow_type != i_workflow.workflow_type
                ):
                    message = f"Fetched workflow is of type {i_workflow.workflow_type.shortname} , but it was explicitly requested to be of type {requested_workflow_type.shortname}"
                    self.logger.error(message)
                    raise WfExSBackendException(message)

                guessedRepo = i_workflow.remote_repo
                workflow_type = i_workflow.workflow_type

        assert guessedRepo is not None
        assert guessedRepo.repo_url is not None
        repo: "RemoteRepo" = guessedRepo

        repoEffectiveCheckout: "Optional[RepoTag]" = None
        # A putative workflow is one which is already materialized
        # but we can only guess
        if repoDir is None:
            parsedRepoURL = urllib.parse.urlparse(guessedRepo.repo_url)
            assert (
                len(parsedRepoURL.scheme) > 0
            ), f"Repository id {guessedRepo.repo_url} should be a parsable URI"

            (
                repoDir,
                materialized_repo,
                workflow_type,
                downstream_repos,
            ) = self.doMaterializeRepo(
                guessedRepo,
                fetcher=guessed[1] if guessed is not None else None,
                prefer_upstream_source=prefer_upstream_source,
                doUpdate=ignoreCache,
                registerInCache=registerInCache,
                offline=offline,
            )
            assert len(downstream_repos) > 0
            repo = materialized_repo.repo
            repoEffectiveCheckout = repo.get_checkout()
            # TODO: should we preserve the chain of repos?

        return repoDir, repo, workflow_type, repoEffectiveCheckout

    TRS_METADATA_FILE: "Final[RelPath]" = cast("RelPath", "trs_metadata.json")
    TRS_QUERY_CACHE_FILE: "Final[RelPath]" = cast("RelPath", "trs_result.json")

    def doMaterializeRepo(
        self,
        repo: "RemoteRepo",
        fetcher: "Optional[AbstractSchemeRepoFetcher]" = None,
        prefer_upstream_source: "bool" = True,
        doUpdate: "bool" = True,
        registerInCache: "bool" = True,
        offline: "bool" = False,
    ) -> "Tuple[pathlib.Path, MaterializedRepo, Optional[WorkflowType], Sequence[RemoteRepo]]":
        """
        This method is used to materialize repos described using instances
        of RemoteRepo. It starts asking all the known repo fetchers whether
        they recognize the URI as consumable by them.

        Later, they fulfil the materialization task, answering the local
        path where the repo was cloned, an updated instance of RemoteRepo,
        the metadata array of all the requests, and whether their copy
        came from another upstream repo (and whether it is recommended).

        If the upstream repo is recommended, then doMaterializeRepo calls
        itself using it in order to fetch the contents of the upstream repo.

        If no repo fetcher is able to materialize the repo, then it is
        considered a "raw" one, so it is fetched using standard fetchers.
        With the fetched content, it is detected whether it is an RO-Crate.
        If it is so, and the associated upstream repo is obtained, then
        doMaterializeRepo calls itself in order to materialize it.

        At the end of the process the path to the repo, the identified
        tag, a MaterializedRepo instance and the list of repos which brought
        to this one is returned.
        """

        # This is needed in case a proposed fetcher is already set
        # by the caller of this method (discouraged)
        if fetcher is None:
            for fetcher in self.repo_fetchers:
                if fetcher.build_pid_from_repo(repo) is not None:
                    break
            else:
                fetcher = None

        workflow_type: "Optional[WorkflowType]" = None
        # An specialized fetcher is used
        downstream_repos: "MutableSequence[RemoteRepo]"
        if fetcher is not None:
            materialized_repo = fetcher.materialize_repo_from_repo(
                repo,
                doUpdate=doUpdate,
                base_repo_destdir=self.cacheWorkflowDir,
            )

            downstream_repos = [repo]
            repo_path = materialized_repo.local
            materialized_repo_repo = materialized_repo.repo
            metadata_array = materialized_repo.metadata_array

            # Now, let's register the checkout with cache structures
            # using its public URI
            remote_url: "str" = repo.repo_url
            if fetcher.__class__ == GitFetcher:
                if not repo.repo_url.startswith("git"):
                    remote_url = "git+" + repo.repo_url

                if repo.tag is not None:
                    remote_url += "@" + repo.tag

            repo_desc: "Optional[Mapping[str, Any]]" = (
                materialized_repo_repo.gen_repo_desc()
            )
            if repo_desc is None:
                repo_desc = {}
            augmented_metadata_array = [
                URIWithMetadata(
                    uri=cast("URIType", remote_url),
                    metadata=repo_desc,
                ),
                *metadata_array,
            ]

            # Give the chance to register the current fetched repo in the corresponding cache
            if registerInCache:
                kind = ContentKind.Directory if repo_path.is_dir() else ContentKind.File
                self.cacheHandler.inject(
                    cast("URIType", remote_url),
                    destdir=self.cacheWorkflowDir,
                    fetched_metadata_array=augmented_metadata_array,
                    finalCachedFilename=repo_path,
                    inputKind=kind,
                )

            # Go to the next repo only if it is recommended
            if (
                prefer_upstream_source
                and materialized_repo.recommends_upstream
                and materialized_repo.upstream_repo is not None
            ):
                try:
                    (
                        upstream_repo_path,
                        upstream_materialized_repo,
                        upstream_workflow_type,
                        upstream_downstream_repos,
                    ) = self.doMaterializeRepo(
                        materialized_repo.upstream_repo,
                        prefer_upstream_source=prefer_upstream_source,
                        doUpdate=doUpdate,
                        registerInCache=registerInCache,
                        offline=offline,
                    )
                    downstream_repos.extend(upstream_downstream_repos)
                    return (
                        upstream_repo_path,
                        upstream_materialized_repo,
                        upstream_workflow_type,
                        downstream_repos,
                    )
                except Exception as e:
                    self.logger.warning(
                        f"Recommended upstream repo {materialized_repo.upstream_repo} from repo {repo} could not be fetched, skipping. Exception: {e}"
                    )
        elif repo.repo_type not in (RepoType.Raw, None):
            raise WfExSBackendException(
                f"Don't know how to materialize {repo.repo_url} (of type {repo.repo_type}) as a repository"
            )
        else:
            downstream_repos = []
            # Let's try guessing whether it is an RO-Crate
            (
                i_workflow,
                cached_putative_path,
                metadata_array,
                repo_rel_path,
            ) = self.getWorkflowBundleFromURI(
                repo.repo_url,
                prefer_upstream_source=prefer_upstream_source,
                ignoreCache=doUpdate,
                registerInCache=registerInCache,
                offline=offline,
            )

            if i_workflow is not None:
                # It is an RO-Crate
                downstream_repos.append(repo)
                i_workflow_repo = i_workflow.remote_repo
                workflow_type = i_workflow.workflow_type
                if repo_rel_path is not None:
                    i_workflow_repo = i_workflow_repo._replace(rel_path=repo_rel_path)
                downstream_repos.append(i_workflow_repo)

                # We are assuming it is always recommended
                try:
                    (
                        upstream_repo_path,
                        upstream_materialized_repo,
                        upstream_workflow_type,
                        upstream_downstream_repos,
                    ) = self.doMaterializeRepo(
                        i_workflow_repo,
                        prefer_upstream_source=prefer_upstream_source,
                        doUpdate=doUpdate,
                        registerInCache=registerInCache,
                        offline=offline,
                    )
                    downstream_repos.extend(upstream_downstream_repos)
                    return (
                        upstream_repo_path,
                        upstream_materialized_repo,
                        upstream_workflow_type,
                        downstream_repos,
                    )
                except Exception as e:
                    raise
                    # TODO: extract and use payload workflow from RO-Crate as a fallback
            else:
                # It was not an RO-Crate, so it is a raw workflow
                repo_path = cached_putative_path
                parsed_repo_url = urllib.parse.urlparse(repo.repo_url)
                if not repo_rel_path:
                    if repo_path.is_dir():
                        if len(parsed_repo_url.fragment) > 0:
                            frag_qs = urllib.parse.parse_qs(parsed_repo_url.fragment)
                            subDirArr = frag_qs.get("subdirectory", [])
                            if len(subDirArr) > 0:
                                repo_rel_path = cast("RelPath", subDirArr[0])
                    elif len(metadata_array) > 0:
                        # Let's try getting a pretty filename
                        # when the workflow is a single file
                        repo_rel_path = metadata_array[0].preferredName

                # It can be either a relative path to a directory or to a file
                # It could be even empty!
                if repo_rel_path == "":
                    repo_rel_path = None
                # raise WFException('Unable to guess repository from RO-Crate manifest')
                guessed_repo = RemoteRepo(
                    repo_url=repo.repo_url,
                    rel_path=repo_rel_path,
                    repo_type=RepoType.Raw,
                )
                downstream_repos.append(guessed_repo)
                materialized_repo = MaterializedRepo(
                    local=repo_path,
                    repo=guessed_repo,
                    metadata_array=metadata_array,
                )

        return repo_path, materialized_repo, workflow_type, downstream_repos

    def getWorkflowBundleFromURI(
        self,
        remote_url: "URIType",
        expectedEngineDesc: "Optional[WorkflowType]" = None,
        prefer_upstream_source: "bool" = True,
        offline: "bool" = False,
        ignoreCache: "bool" = False,
        registerInCache: "bool" = True,
    ) -> "Tuple[Optional[IdentifiedWorkflow], pathlib.Path, Sequence[URIWithMetadata], Optional[RelPath]]":
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
            metadata_file = cached_content.path
            encoding = magic.from_file(metadata_file.as_posix(), mime=True)
        elif cached_content.path.is_dir():
            metadata_file = cached_content.path / ROCRATE_JSONLD_FILENAME
            if metadata_file.is_file():
                encoding = magic.from_file(metadata_file.as_posix(), mime=True)
            else:
                # A directory does not have mime type
                encoding = ""
        else:
            raise WfExSBackendException(
                f"Unexpected cached path {cached_content.path}, which is neither file nor directory"
            )

        if encoding in ("application/zip", "application/json"):
            if encoding == "application/zip":
                info_message = (
                    f"putative workflow {remote_url} seems to be a packed RO-Crate"
                )
            else:
                info_message = f"putative workflow from {remote_url} seems to be an unpacked RO-Crate"
            self.logger.info(info_message)

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

            try:
                identified_workflow = self.getWorkflowRepoFromROCrateFile(
                    roCrateFile,
                    expectedEngineDesc=expectedEngineDesc,
                    prefer_upstream_source=prefer_upstream_source,
                    offline=offline,
                    ignoreCache=ignoreCache,
                    registerInCache=registerInCache,
                )
                return (
                    identified_workflow,
                    roCrateFile,
                    cached_content.metadata_array,
                    identified_workflow.remote_repo.rel_path,
                )
            except Exception as e:
                self.logger.info(
                    f"Putative workflow from {remote_url} is considered a raw one."
                )
                self.logger.debug(f"Rejection traces {e}")

        # Default return
        return (
            None,
            cached_content.path,
            cached_content.metadata_array,
            None,
        )

    def getWorkflowRepoFromROCrateFile(
        self,
        roCrateFile: "pathlib.Path",
        expectedEngineDesc: "Optional[WorkflowType]" = None,
        prefer_upstream_source: "bool" = True,
        offline: "bool" = False,
        ignoreCache: "bool" = False,
        registerInCache: "bool" = True,
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

        # TODO: honour prefer_upstream_source parameter when it is false
        # and the payload of the RO-Crate contains a copy of the workflow

        # Some RO-Crates might have this value missing or ill-built
        repo, workflow_type, _a, _b = self.rocrate_toolbox.extractWorkflowMetadata(
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
        guessed = self.guess_repo_params(
            repo.repo_url,
            offline=offline,
            ignoreCache=ignoreCache,
            registerInCache=registerInCache,
            fail_ok=True,
        )
        if guessed is None or guessed[0].repo_type is None:
            raise WfExSBackendException(
                f"Unable to guess repository from RO-Crate manifest obtained from {public_name}"
            )
        guessedRepo = guessed[0]

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
        default_clonable: "bool" = True,
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
            default_clonable=default_clonable,
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
                members=firstURI.members,
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
            splitted_path = firstParsedURI.path.split("/")
            splitted_path.reverse()
            prettyFilename = cast("RelPath", "")
            for elem in splitted_path:
                if len(elem) > 0:
                    prettyFilename = cast("RelPath", elem)
                    break

        return MaterializedContent(
            local=pathlib.Path(cached_content.path),
            licensed_uri=firstLicensedURI,
            prettyFilename=prettyFilename,
            kind=cached_content.kind,
            metadata_array=cached_content.metadata_array,
            fingerprint=cached_content.fingerprint,
            # We are returning with the most restrictive setting
            clonable=cached_content.clonable and default_clonable,
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
