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

import copy
from dataclasses import dataclass
import json
import os
import pathlib
import tempfile
import atexit
import platform
import shutil
import subprocess
import abc
import logging
import inspect
import uuid

from typing import (
    cast,
    TYPE_CHECKING,
)

from ..common import (
    AbstractWfExSException,
    ContainerTaggedName,
    ContainerType,
    META_JSON_POSTFIX,
)

if TYPE_CHECKING:
    from typing import (
        Any,
        Callable,
        ClassVar,
        Mapping,
        MutableMapping,
        MutableSequence,
        NewType,
        Optional,
        Sequence,
        Set,
        Tuple,
        Type,
        Union,
    )

    from typing_extensions import (
        NotRequired,
        TypeAlias,
        TypedDict,
        Final,
    )

    from ..common import (
        AbsPath,
        AnyPath,
        ContainerTaggedName,
        Fingerprint,
        PathlibLike,
        RelPath,
        URIType,
    )

    # As each workflow engine can have its own naming convention, leave them to
    # provide it
    ContainerFileNamingMethod: TypeAlias = Callable[[URIType], RelPath]

    ContainerLocalConfig: TypeAlias = Mapping[str, Any]

    # This is a container engine version
    ContainerEngineVersionStr = NewType("ContainerEngineVersionStr", str)
    ContainerOperatingSystem = NewType("ContainerOperatingSystem", str)
    ProcessorArchitecture = NewType("ProcessorArchitecture", str)

    class AbstractImageManifestMetadata(TypedDict):
        image_signature: NotRequired[Fingerprint]

    import yaml

    AnyYAMLLoader: TypeAlias = Union[yaml.Loader, yaml.CLoader]

from .. import common

from ..utils.contents import (
    link_or_copy,
    link_or_copy_pathlib,
    real_unlink_if_exists,
)

from ..utils.digests import ComputeDigestFromFile


# A couple of constants needed for several fixes
DOCKER_SCHEME: "Final[str]" = "docker"
DOCKER_URI_PREFIX: "Final[str]" = DOCKER_SCHEME + ":"
# This string is a repetition from what it is in the helper
DEFAULT_DOCKER_REGISTRY: "Final[str]" = "docker.io"


@dataclass
class Container(ContainerTaggedName):
    """
    origTaggedName: Symbolic name or identifier of the container
        (including tag) which appears in the workflow.
    type: Container type
    registries:
    taggedName: Symbolic name or identifier of the container (including tag)
    localPath: The full local path to the container file (it can be None)
    signature: Signature (aka file fingerprint) of the container
        (sha256 or similar). It could be None outside Singularity solutions.
    fingerprint: Server fingerprint of the container.
        Mainly from docker registries.
    metadataLocalPath: The full local path to the container metadata file (it can be None)
    source_type: This one helps to identify transformations. The original source
    might be a docker registry, but the materialized one is a singularity image.
    image_signature: The signature of the image
    """

    taggedName: "URIType" = cast("URIType", "")
    architecture: "Optional[ProcessorArchitecture]" = None
    operatingSystem: "Optional[ContainerOperatingSystem]" = None
    localPath: "Optional[PathlibLike]" = None
    signature: "Optional[Fingerprint]" = None
    fingerprint: "Optional[Fingerprint]" = None
    metadataLocalPath: "Optional[PathlibLike]" = None
    source_type: "Optional[ContainerType]" = None
    image_signature: "Optional[Fingerprint]" = None

    def _value_defaults_fixes(self) -> None:
        if isinstance(self.localPath, str):
            # Properly casting the path
            self.localPath = pathlib.Path(self.localPath)
            print(f"localPath {self.localPath}")

        # This code is needed for old working directories
        if self.metadataLocalPath is None and self.localPath is not None:
            self.metadataLocalPath = self.localPath.with_name(
                self.localPath.name + META_JSON_POSTFIX
            )
        elif isinstance(self.metadataLocalPath, str):
            # Properly casting the path
            self.metadataLocalPath = pathlib.Path(self.metadataLocalPath)

        # And this is to tell the kind of source container type
        if self.source_type is None:
            if self.type == ContainerType.Singularity:
                if self.taggedName.startswith(DOCKER_URI_PREFIX):
                    self.source_type = ContainerType.Docker
            elif self.type == ContainerType.Podman:
                self.source_type = ContainerType.Docker

            # Fallback
            if self.source_type is None:
                self.source_type = self.type

    @property
    def decompose_docker_tagged_name(
        self,
    ) -> "Tuple[Optional[str], str, Optional[str]]":
        # Preparing the tagged_name to properly separate everything
        tagged_name: "str" = self.taggedName
        if tagged_name.startswith(DOCKER_URI_PREFIX):
            tagged_name = tagged_name[len(DOCKER_URI_PREFIX) :].lstrip("/")
        if self.source_type == ContainerType.Docker:
            # Now ...
            registry: "str"
            tag_name: "str"
            tag_label: "Optional[str]"

            # Is it a fully qualified docker tag?
            left_slash_pos = tagged_name.find("/")
            if left_slash_pos > 0 and left_slash_pos != tagged_name.rfind("/"):
                registry = tagged_name[0:left_slash_pos]
                tagged_name = tagged_name[left_slash_pos + 1 :]
            else:
                registry = DEFAULT_DOCKER_REGISTRY

            # Now, the tag label
            right_sha256_pos = tagged_name.rfind("@sha256:")
            if right_sha256_pos > 0:
                tag_name = tagged_name[0:right_sha256_pos]
                # No tag label, as it is an specific layer
                tag_label = None
            else:
                right_colon_pos = tagged_name.rfind(":")
                right_slash_pos = tagged_name.rfind("/")
                if right_colon_pos > right_slash_pos:
                    tag_name = tagged_name[0:right_colon_pos]
                    tag_label = tagged_name[right_colon_pos + 1 :]
                else:
                    tag_name = tagged_name
                    # Default
                    tag_label = "latest"

            return registry, tag_name, tag_label
        else:
            # Nothing could be done
            return None, tagged_name, None

    @classmethod
    def ContainerYAMLConstructor(
        cls, loader: "AnyYAMLLoader", node: "Any"
    ) -> "Container":
        fields = loader.construct_mapping(node)
        # This could be a fix for old cases being parsed
        # where the concept of image_signature did not exist.
        # But it could break future cases where no image can be materialized
        # if "image_signature" not in fields:
        #     fields["image_signature"] = fields["signature"]

        return cls(**fields)  # type: ignore[misc]

    @classmethod
    def RegisterYAMLConstructor(cls, loader: "Type[AnyYAMLLoader]") -> None:
        # yaml.add_constructor('!python/object:wfexs_backend.common.Container', container_yaml_constructor)
        # yaml.constructor.Constructor.add_constructor('tag:yaml.org,2002:python/object:wfexs_backend.common.Container', container_yaml_constructor)
        loader.add_constructor(
            "tag:yaml.org,2002:python/object:wfexs_backend.common.Container",
            cls.ContainerYAMLConstructor,
        )


REGISTER_CONSTRUCTOR = True
if REGISTER_CONSTRUCTOR:
    YAMLLoader: "Type[AnyYAMLLoader]"
    try:
        from yaml import CLoader as YAMLLoader
    except ImportError:
        from yaml import Loader as YAMLLoader
    # This is needed to keep backward compatibility
    # with ancient working directories
    Container.RegisterYAMLConstructor(YAMLLoader)
    REGISTER_CONSTRUCTOR = False


class ContainerFactoryException(AbstractWfExSException):
    """
    Exceptions fired by instances of ContainerFactory
    """

    pass


class ContainerEngineException(ContainerFactoryException):
    """
    Exceptions fired by instances of ContainerFactory when calling the
    container engine
    """

    pass


class ContainerNotFoundException(ContainerFactoryException):
    """
    Exceptions fired by instances of ContainerFactory
    when the container image or its metadata could not be found
    """

    pass


class ContainerCacheHandler:
    """
    This class abstracts all the common caching handling
    """

    def __init__(
        self,
        containers_cache_dir: "Optional[pathlib.Path]",
        engine_name: "str",
        simple_file_name_method: "ContainerFileNamingMethod",
    ):
        # Getting a logger focused on specific classes
        self.logger = logging.getLogger(
            dict(inspect.getmembers(self))["__module__"]
            + "::"
            + self.__class__.__name__
        )

        # TODO: create caching database???
        # containers_cache_dir
        if containers_cache_dir is None:
            containers_cache_dir = pathlib.Path(
                tempfile.mkdtemp(prefix="wfexs", suffix="backend")
            )
            # Assuring this temporal directory is removed at the end
            atexit.register(shutil.rmtree, containers_cache_dir, True)
        else:
            containers_cache_dir.mkdir(parents=True, exist_ok=True)

        # But, for materialized containers, we should use common directories
        # This for the containers themselves
        self.containersCacheDir = containers_cache_dir

        # This for the symlinks to the containers, following the engine convention
        self.engineContainersSymlinkDir = self.containersCacheDir / engine_name
        self.engineContainersSymlinkDir.mkdir(parents=True, exist_ok=True)

        self.simpleFileNameMethod = simple_file_name_method

    def _genTmpContainerPath(self) -> "pathlib.Path":
        """
        This is a helper method
        """
        return self.containersCacheDir / str(uuid.uuid4())

    def _genContainerPaths(
        self, container: "ContainerTaggedName"
    ) -> "Tuple[pathlib.Path, pathlib.Path]":
        containerFilename = self.simpleFileNameMethod(
            cast("URIType", container.origTaggedName)
        )
        containerFilenameMeta = containerFilename + META_JSON_POSTFIX
        localContainerPath = self.engineContainersSymlinkDir / containerFilename
        localContainerPathMeta = self.engineContainersSymlinkDir / containerFilenameMeta

        return localContainerPath, localContainerPathMeta

    def _computeFingerprint(self, image_path: "pathlib.Path") -> "Fingerprint":
        return cast("Fingerprint", ComputeDigestFromFile(image_path.as_posix()))

    def _computeCanonicalImagePath(
        self, image_path: "pathlib.Path"
    ) -> "Tuple[pathlib.Path, Fingerprint]":
        imageSignature = self._computeFingerprint(image_path)

        # Some filesystems complain when filenames contain 'equal', 'slash' or 'plus' symbols
        canonical_image_path = self.containersCacheDir / imageSignature.replace(
            "=", "~"
        ).replace("/", "-").replace("+", "_")

        return canonical_image_path, imageSignature

    def query(
        self, container: "ContainerTaggedName"
    ) -> "Tuple[bool, pathlib.Path, pathlib.Path, Optional[Fingerprint]]":
        """
        This method checks whether the container snapshot and its
        metadata are in the caching directory
        """
        localContainerPath, localContainerPathMeta = self._genContainerPaths(container)

        trusted_copy = False
        imageSignature: "Optional[Fingerprint]" = None
        if localContainerPath.is_file():
            if localContainerPath.is_symlink():
                # Some filesystems complain when filenames contain 'equal', 'slash' or 'plus' symbols
                unlinkedContainerPath = localContainerPath.readlink()
                fsImageSignature = unlinkedContainerPath.name
                imageSignature = cast(
                    "Fingerprint",
                    fsImageSignature.replace("~", "=")
                    .replace("-", "/")
                    .replace("_", "+"),
                )

                # Do not trust paths outside the caching directory
                canonicalContainerPath = self.containersCacheDir / fsImageSignature

                trusted_copy = localContainerPath.resolve().samefile(
                    canonicalContainerPath.resolve()
                )
            else:
                (
                    canonicalContainerPath,
                    imageSignature,
                ) = self._computeCanonicalImagePath(localContainerPath)

                if localContainerPath.samefile(canonicalContainerPath):
                    trusted_copy = True
                elif canonicalContainerPath.is_file():
                    canonicalImageSignature = self._computeFingerprint(
                        canonicalContainerPath
                    )

                    trusted_copy = canonicalImageSignature == imageSignature

        if trusted_copy:
            if localContainerPathMeta.is_file():
                try:
                    with localContainerPathMeta.open(mode="r", encoding="utf-8") as mH:
                        signaturesAndManifest = cast(
                            "AbstractImageManifestMetadata", json.load(mH)
                        )
                        imageSignature_in_metadata = signaturesAndManifest.get(
                            "image_signature"
                        )
                        trusted_copy = imageSignature_in_metadata == imageSignature
                except:
                    trusted_copy = False
            else:
                trusted_copy = False

        return trusted_copy, localContainerPath, localContainerPathMeta, imageSignature

    def genStagedContainersDirPaths(
        self,
        container: "ContainerTaggedName",
        stagedContainersDir: "pathlib.Path",
    ) -> "Tuple[pathlib.Path, pathlib.Path]":
        containerFilename = self.simpleFileNameMethod(
            cast("URIType", container.origTaggedName)
        )
        containerFilenameMeta = containerFilename + META_JSON_POSTFIX

        containerPath = stagedContainersDir / containerFilename

        containerPathMeta = stagedContainersDir / containerFilenameMeta

        return containerPath, containerPathMeta

    def transfer(
        self,
        container: "ContainerTaggedName",
        stagedContainersDir: "pathlib.Path",
        force: "bool" = False,
    ) -> "Optional[Tuple[pathlib.Path, pathlib.Path]]":
        """
        This method is used to transfer both the container snapshot and
        its metadata from the caching directory to stagedContainersDir
        """
        # First, get the local paths
        (
            trusted_copy,
            localContainerPath,
            localContainerPathMeta,
            imageSignature,
        ) = self.query(container)
        if not trusted_copy:
            return None

        # Last, but not the least important
        # Hardlink or copy the container and its metadata
        stagedContainersDir.mkdir(parents=True, exist_ok=True)
        containerPath, containerPathMeta = self.genStagedContainersDirPaths(
            container, stagedContainersDir
        )

        if force or not containerPath.exists():
            link_or_copy_pathlib(localContainerPath, containerPath)
        if force or not containerPathMeta.exists():
            link_or_copy_pathlib(localContainerPathMeta, containerPathMeta)

        return (containerPath, containerPathMeta)

    def update(
        self,
        container: "ContainerTaggedName",
        image_path: "pathlib.Path",
        image_metadata_path: "pathlib.Path",
        do_move: "bool" = True,
    ) -> "None":
        # First, let's remove what it is still there
        self.invalidate(container)

        # Then, get the local paths
        localContainerPath, localContainerPathMeta = self._genContainerPaths(container)

        # Now, compute the hash
        canonicalContainerPath, imageSignature = self._computeCanonicalImagePath(
            image_path
        )
        canonicalContainerPathMeta = canonicalContainerPath.with_name(
            canonicalContainerPath.name + META_JSON_POSTFIX
        )

        # And ..... transfer!!!
        if do_move:
            shutil.move(image_path, canonicalContainerPath)
            shutil.move(image_metadata_path, canonicalContainerPathMeta)
        else:
            link_or_copy(image_path, canonicalContainerPath, force_copy=True)
            link_or_copy(
                image_metadata_path, canonicalContainerPathMeta, force_copy=True
            )

        # Last, the symbolic links
        localContainerPath.symlink_to(
            os.path.relpath(canonicalContainerPath, self.engineContainersSymlinkDir)
        )

        localContainerPathMeta.symlink_to(
            os.path.relpath(canonicalContainerPathMeta, self.engineContainersSymlinkDir)
        )

    def invalidate(self, container: "ContainerTaggedName") -> "None":
        # First, get the local paths
        localContainerPath, localContainerPathMeta = self._genContainerPaths(container)

        # Let's remove what it is still there
        real_unlink_if_exists(localContainerPath)
        real_unlink_if_exists(localContainerPathMeta)


class ContainerFactory(abc.ABC):
    # Is this implementation enabled?
    ENABLED: "ClassVar[bool]" = True

    def __init__(
        self,
        simpleFileNameMethod: "ContainerFileNamingMethod",
        containersCacheDir: "Optional[pathlib.Path]" = None,
        stagedContainersDir: "Optional[pathlib.Path]" = None,
        tools_config: "Optional[ContainerLocalConfig]" = None,
        engine_name: "str" = "unset",
        tempDir: "Optional[pathlib.Path]" = None,
    ):
        """
        Abstract init method

        containersCacheDir: Base directory where
        """
        # This factory was created by the workflow engine, which
        # provides its file naming method
        self.simpleFileNameMethod = simpleFileNameMethod

        if tools_config is None:
            tools_config = dict()
        self.tools_config = tools_config

        # Getting a logger focused on specific classes
        self.logger = logging.getLogger(
            dict(inspect.getmembers(self))["__module__"]
            + "::"
            + self.__class__.__name__
        )

        # But, for materialized containers, we should use common directories
        # This for the containers themselves
        # containersCacheDir
        if containersCacheDir is None:
            self.containersCacheDir = pathlib.Path(
                tempfile.mkdtemp(prefix="wfexs", suffix="backend")
            )
            # Assuring this temporal directory is removed at the end
            atexit.register(shutil.rmtree, self.containersCacheDir, True)
        else:
            self.containersCacheDir = containersCacheDir.absolute()

        if tempDir is None:
            tempDir = pathlib.Path(
                tempfile.mkdtemp(prefix="WfExS-container", suffix="tempdir")
            )
            # Assuring this temporal directory is removed at the end
            atexit.register(shutil.rmtree, tempDir, True)

        # This directory might be needed by temporary processes, like
        # image materialization in singularity or podman
        self.tempDir = tempDir

        self.cc_handler = ContainerCacheHandler(
            self.containersCacheDir,
            engine_name=engine_name,
            simple_file_name_method=simpleFileNameMethod,
        )

        # stagedContainersDir
        if stagedContainersDir is None:
            stagedContainersDir = self.containersCacheDir
        self.stagedContainersDir = stagedContainersDir

        # This for the symlinks to the containers, following the engine convention
        self.engineContainersSymlinkDir = self.cc_handler.engineContainersSymlinkDir

        # This variable contains the dictionary of set up environment
        # variables needed to run the tool with the proper setup
        self._environment: "MutableMapping[str, str]" = dict()

        # This variable contains the set of optional features
        # supported by this container factory in this installation
        self._features = set()

        self.runtime_cmd = ""

        # Detecting host userns support
        host_userns_supported = False
        if os.path.lexists("/proc/self/ns/user"):
            host_userns_supported = True
            self._features.add("host_userns")
        else:
            self.logger.warning(
                "Host does not support userns (needed for encrypted working directories in several container technologies)"
            )

        self.logger.debug(f"Host supports userns: {host_userns_supported}")

    @classmethod
    @abc.abstractmethod
    def ContainerType(cls) -> "common.ContainerType":
        pass

    @classmethod
    def AcceptsContainer(cls, container: "ContainerTaggedName") -> "bool":
        if isinstance(container, Container) and container.source_type is not None:
            return cls.AcceptsContainerType(container.source_type)
        else:
            return cls.AcceptsContainerType(container.type)

    @classmethod
    @abc.abstractmethod
    def AcceptsContainerType(
        cls, container_type: "Union[common.ContainerType, Set[common.ContainerType]]"
    ) -> "bool":
        pass

    @property
    def environment(self) -> "Mapping[str, str]":
        return self._environment

    @property
    def containerType(self) -> "common.ContainerType":
        return self.ContainerType()

    @property
    def command(self) -> "str":
        return self.runtime_cmd

    @property
    def cacheDir(self) -> "pathlib.Path":
        """
        This method returns the symlink dir instead of the cache dir
        as the entries following the naming convention of the engine
        are placed in the symlink dir
        """
        return self.engineContainersSymlinkDir

    def engine_version(self) -> "ContainerEngineVersionStr":
        """
        As most of the engines return the version with this flag,
        the default implementation is this
        """

        matEnv = dict(os.environ)
        matEnv.update(self.environment)
        with tempfile.NamedTemporaryFile() as e_err:
            with subprocess.Popen(
                [self.runtime_cmd, "--version"],
                env=matEnv,
                stdout=subprocess.PIPE,
                stderr=e_err,
            ) as sp_v:
                engine_ver: "str" = ""
                if sp_v.stdout is not None:
                    engine_ver = sp_v.stdout.read().decode("utf-8", errors="continue")
                    self.logger.debug(f"{self.runtime_cmd} version => {engine_ver}")

                d_retval = sp_v.wait()

            if d_retval == 0:
                return cast("ContainerEngineVersionStr", engine_ver.strip())
            else:
                with open(e_err.name, mode="rb") as eH:
                    d_err_v = eH.read().decode("utf-8", errors="continue")
                errstr = f"""Could not obtain version string from {self.runtime_cmd}. Retval {d_retval}
======
STDOUT
======
{engine_ver}

======
STDERR
======
{d_err_v}"""
                raise ContainerEngineException(errstr)

    @property
    def architecture(self) -> "Tuple[ContainerOperatingSystem, ProcessorArchitecture]":
        return cast("ContainerOperatingSystem", platform.system().lower()), cast(
            "ProcessorArchitecture", platform.machine()
        )

    def materializeContainers(
        self,
        tagList: "Sequence[ContainerTaggedName]",
        containers_dir: "Optional[pathlib.Path]" = None,
        offline: "bool" = False,
        force: "bool" = False,
    ) -> "Sequence[Container]":
        """
        It is assured the containers are materialized
        """
        materialized_containers: "MutableSequence[Container]" = []
        not_found_containers: "MutableSequence[str]" = []

        if containers_dir is None:
            containers_dir = self.stagedContainersDir
        for tag in tagList:
            if self.AcceptsContainer(tag):
                container: "Optional[Container]"
                try:
                    container, was_redeployed = self.deploySingleContainer(
                        tag, containers_dir=containers_dir, force=force
                    )
                except ContainerFactoryException as cfe:
                    container = self.materializeSingleContainer(
                        tag,
                        containers_dir=containers_dir,
                        offline=offline,
                        force=force,
                    )
                    if container is not None:
                        if container not in materialized_containers:
                            materialized_containers.append(container)
                    else:
                        not_found_containers.append(tag.origTaggedName)

        if len(not_found_containers) > 0:
            raise ContainerNotFoundException(
                f"Could not fetch metadata for next tags because they were not found:\n{', '.join(not_found_containers)}"
            )

        return materialized_containers

    @abc.abstractmethod
    def materializeSingleContainer(
        self,
        tag: "ContainerTaggedName",
        containers_dir: "Optional[pathlib.Path]" = None,
        offline: "bool" = False,
        force: "bool" = False,
    ) -> "Optional[Container]":
        """
        It is assured the container is properly materialized
        """
        pass

    def deployContainers(
        self,
        containers_list: "Sequence[Container]",
        containers_dir: "Optional[pathlib.Path]" = None,
        force: "bool" = False,
    ) -> "Sequence[Container]":
        """
        It is assured the containers are properly deployed
        """
        redeployed_containers: "MutableSequence[Container]" = []

        if containers_dir is None:
            containers_dir = self.stagedContainersDir
        for container in containers_list:
            if self.AcceptsContainer(container):
                deployed_container, was_redeployed = self.deploySingleContainer(
                    container,
                    containers_dir=containers_dir,
                    force=force,
                )
                if was_redeployed:
                    redeployed_containers.append(container)

        return redeployed_containers

    @abc.abstractmethod
    def deploySingleContainer(
        self,
        container: "ContainerTaggedName",
        containers_dir: "Optional[pathlib.Path]" = None,
        force: "bool" = False,
    ) -> "Tuple[Container, bool]":
        """
        It is assured the container is properly deployed
        """
        pass

    def supportsFeature(self, feat: "str") -> "bool":
        """
        Checking whether some feature is supported by this container
        factory in this installation. Currently userns
        """
        return feat in self._features
