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
import os
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
        TypeAlias,
        TypedDict,
        Final,
    )

    from ..common import (
        AbsPath,
        AnyPath,
        ContainerTaggedName,
        Fingerprint,
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

    DockerLikeManifest: TypeAlias = Mapping[str, Any]
    MutableDockerLikeManifest: TypeAlias = MutableMapping[str, Any]

    class DockerManifestMetadata(TypedDict):
        image_id: Fingerprint
        image_signature: Fingerprint
        manifests_signature: Fingerprint
        manifests: Sequence[DockerLikeManifest]

    import yaml

    YAMLLoader: TypeAlias = Union[yaml.Loader, yaml.CLoader]

from .. import common

from ..utils.contents import (
    link_or_copy,
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
    localPath: "Optional[AbsPath]" = None
    signature: "Optional[Fingerprint]" = None
    fingerprint: "Optional[Fingerprint]" = None
    metadataLocalPath: "Optional[AbsPath]" = None
    source_type: "Optional[ContainerType]" = None
    image_signature: "Optional[Fingerprint]" = None

    def _value_defaults_fixes(self) -> None:
        # This code is needed for old working directories
        if self.metadataLocalPath is None and self.localPath is not None:
            self.metadataLocalPath = cast("AbsPath", self.localPath + META_JSON_POSTFIX)

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
            tag_label: "str"

            # Is it a fully qualified docker tag?
            left_slash_pos = tagged_name.find("/")
            if left_slash_pos > 0 and left_slash_pos != tagged_name.rfind("/"):
                registry = tagged_name[0:left_slash_pos]
                tagged_name = tagged_name[left_slash_pos + 1 :]
            else:
                registry = DEFAULT_DOCKER_REGISTRY

            # Now, the tag label
            right_colon_pos = tagged_name.rfind(":")
            if right_colon_pos < 0:
                tag_name = tagged_name
                tag_label = "latest"
            else:
                tag_name = tagged_name[0:right_colon_pos]
                tag_label = tagged_name[right_colon_pos + 1 :]

            return registry, tag_name, tag_label
        else:
            # Nothing could be done
            return None, tagged_name, None

    @classmethod
    def ContainerYAMLConstructor(cls, loader: "YAMLLoader", node: "Any") -> "Container":
        fields = loader.construct_mapping(node)
        # This could be a fix for old cases being parsed
        # where the concept of image_signature did not exist.
        # But it could break future cases where no image can be materialized
        # if "image_signature" not in fields:
        #     fields["image_signature"] = fields["signature"]

        return cls(**fields)  # type: ignore[misc]

    @classmethod
    def RegisterYAMLConstructor(cls, loader: "Type[YAMLLoader]") -> None:
        # yaml.add_constructor('!python/object:wfexs_backend.common.Container', container_yaml_constructor)
        # yaml.constructor.Constructor.add_constructor('tag:yaml.org,2002:python/object:wfexs_backend.common.Container', container_yaml_constructor)
        loader.add_constructor(
            "tag:yaml.org,2002:python/object:wfexs_backend.common.Container",
            cls.ContainerYAMLConstructor,
        )


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
        containers_cache_dir: "Optional[AbsPath]",
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
            containers_cache_dir = cast(
                "AbsPath", tempfile.mkdtemp(prefix="wfexs", suffix="backend")
            )
            # Assuring this temporal directory is removed at the end
            atexit.register(shutil.rmtree, containers_cache_dir)
        else:
            os.makedirs(containers_cache_dir, exist_ok=True)

        # But, for materialized containers, we should use common directories
        # This for the containers themselves
        self.containersCacheDir = containers_cache_dir

        # This for the symlinks to the containers, following the engine convention
        self.engineContainersSymlinkDir = cast(
            "AbsPath", os.path.join(self.containersCacheDir, engine_name)
        )
        os.makedirs(self.engineContainersSymlinkDir, exist_ok=True)

        self.simpleFileNameMethod = simple_file_name_method

    def _genTmpContainerPath(self) -> "AbsPath":
        """
        This is a helper method
        """
        return cast("AbsPath", os.path.join(self.containersCacheDir, str(uuid.uuid4())))

    def _genContainerPaths(
        self, container: "ContainerTaggedName"
    ) -> "Tuple[AbsPath, AbsPath]":
        containerFilename = self.simpleFileNameMethod(
            cast("URIType", container.origTaggedName)
        )
        containerFilenameMeta = containerFilename + META_JSON_POSTFIX
        localContainerPath = cast(
            "AbsPath",
            os.path.join(self.engineContainersSymlinkDir, containerFilename),
        )
        localContainerPathMeta = cast(
            "AbsPath",
            os.path.join(self.engineContainersSymlinkDir, containerFilenameMeta),
        )

        return localContainerPath, localContainerPathMeta

    def _computeFingerprint(self, image_path: "AnyPath") -> "Fingerprint":
        return cast("Fingerprint", ComputeDigestFromFile(image_path))

    def _computeCanonicalImagePath(
        self, image_path: "AbsPath"
    ) -> "Tuple[AbsPath, Fingerprint]":
        imageSignature = self._computeFingerprint(image_path)

        # Some filesystems complain when filenames contain 'equal', 'slash' or 'plus' symbols
        canonical_image_path = os.path.join(
            self.containersCacheDir,
            imageSignature.replace("=", "~").replace("/", "-").replace("+", "_"),
        )

        return cast("AbsPath", canonical_image_path), imageSignature

    def query(
        self, container: "ContainerTaggedName"
    ) -> "Tuple[bool, AbsPath, AbsPath, Optional[Fingerprint]]":
        """
        This method checks whether the container snapshot and its
        metadata are in the caching directory
        """
        localContainerPath, localContainerPathMeta = self._genContainerPaths(container)

        trusted_copy = False
        imageSignature: "Optional[Fingerprint]" = None
        if os.path.isfile(localContainerPath):
            if os.path.islink(localContainerPath):
                # Some filesystems complain when filenames contain 'equal', 'slash' or 'plus' symbols
                unlinkedContainerPath = os.readlink(localContainerPath)
                fsImageSignature = os.path.basename(unlinkedContainerPath)
                imageSignature = cast(
                    "Fingerprint",
                    fsImageSignature.replace("~", "=")
                    .replace("-", "/")
                    .replace("_", "+"),
                )

                # Do not trust paths outside the caching directory
                canonicalContainerPath = os.path.join(
                    self.containersCacheDir,
                    fsImageSignature,
                )

                trusted_copy = os.path.samefile(
                    os.path.realpath(localContainerPath),
                    os.path.realpath(canonicalContainerPath),
                )
            else:
                (
                    canonicalContainerPath,
                    imageSignature,
                ) = self._computeCanonicalImagePath(localContainerPath)

                if os.path.samefile(localContainerPath, canonicalContainerPath):
                    trusted_copy = True
                elif os.path.isfile(canonicalContainerPath):
                    canonicalImageSignature = self._computeFingerprint(
                        canonicalContainerPath
                    )

                    trusted_copy = canonicalImageSignature == imageSignature

        if trusted_copy:
            trusted_copy = os.path.isfile(localContainerPathMeta)

        return trusted_copy, localContainerPath, localContainerPathMeta, imageSignature

    def genStagedContainersDirPaths(
        self,
        container: "ContainerTaggedName",
        stagedContainersDir: "AnyPath",
    ) -> "Tuple[AbsPath, AbsPath]":
        containerFilename = self.simpleFileNameMethod(
            cast("URIType", container.origTaggedName)
        )
        containerFilenameMeta = containerFilename + META_JSON_POSTFIX

        containerPath = cast(
            "AbsPath", os.path.join(stagedContainersDir, containerFilename)
        )

        containerPathMeta = cast(
            "AbsPath", os.path.join(stagedContainersDir, containerFilenameMeta)
        )

        return containerPath, containerPathMeta

    def transfer(
        self,
        container: "ContainerTaggedName",
        stagedContainersDir: "AnyPath",
        force: "bool" = False,
    ) -> "Optional[Tuple[AbsPath, AbsPath]]":
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
        containerPath, containerPathMeta = self.genStagedContainersDirPaths(
            container, stagedContainersDir
        )

        os.makedirs(stagedContainersDir, exist_ok=True)
        if force or not os.path.exists(containerPath):
            link_or_copy(localContainerPath, containerPath)
        if force or not os.path.exists(containerPathMeta):
            link_or_copy(localContainerPathMeta, containerPathMeta)

        return (containerPath, containerPathMeta)

    def update(
        self,
        container: "ContainerTaggedName",
        image_path: "AbsPath",
        image_metadata_path: "AbsPath",
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
        canonicalContainerPathMeta = cast(
            "AbsPath", canonicalContainerPath + META_JSON_POSTFIX
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
        os.symlink(
            os.path.relpath(canonicalContainerPath, self.engineContainersSymlinkDir),
            localContainerPath,
        )

        os.symlink(
            os.path.relpath(
                canonicalContainerPathMeta, self.engineContainersSymlinkDir
            ),
            localContainerPathMeta,
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
        containersCacheDir: "Optional[AnyPath]" = None,
        stagedContainersDir: "Optional[AnyPath]" = None,
        tools_config: "Optional[ContainerLocalConfig]" = None,
        engine_name: "str" = "unset",
        tempDir: "Optional[AnyPath]" = None,
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
            self.containersCacheDir = cast(
                "AbsPath", tempfile.mkdtemp(prefix="wfexs", suffix="backend")
            )
            # Assuring this temporal directory is removed at the end
            atexit.register(shutil.rmtree, self.containersCacheDir)
        else:
            self.containersCacheDir = cast(
                "AbsPath", os.path.abspath(containersCacheDir)
            )

        if tempDir is None:
            tempDir = cast(
                "AbsPath", tempfile.mkdtemp(prefix="WfExS-container", suffix="tempdir")
            )
            # Assuring this temporal directory is removed at the end
            atexit.register(shutil.rmtree, tempDir)

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
        self.engineContainersSymlinkDir = cast(
            "AbsPath", os.path.join(self.containersCacheDir, engine_name)
        )
        os.makedirs(self.engineContainersSymlinkDir, exist_ok=True)

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
    def cacheDir(self) -> "AbsPath":
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
        containers_dir: "Optional[AnyPath]" = None,
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
        containers_dir: "Optional[AnyPath]" = None,
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
        containers_dir: "Optional[AnyPath]" = None,
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
        containers_dir: "Optional[AnyPath]" = None,
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
