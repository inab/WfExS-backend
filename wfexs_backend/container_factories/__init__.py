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
        ClassVar,
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
        TypeAlias,
        TypedDict,
        Final,
    )

    from ..common import (
        AbsPath,
        AnyPath,
        ContainerEngineVersionStr,
        ContainerFileNamingMethod,
        ContainerLocalConfig,
        ContainerOperatingSystem,
        ContainerTaggedName,
        Fingerprint,
        ProcessorArchitecture,
        RelPath,
        URIType,
    )

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

# A couple of constants needed for several fixes
DOCKER_SCHEME: "Final[str]" = "docker"
DOCKER_URI_PREFIX: "Final[str]" = DOCKER_SCHEME + ":"


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
                registry = "docker.io"

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


class ContainerFactory(abc.ABC):
    # Is this implementation enabled?
    ENABLED: "ClassVar[bool]" = True

    def __init__(
        self,
        cacheDir: "Optional[AnyPath]" = None,
        stagedContainersDir: "Optional[AnyPath]" = None,
        local_config: "Optional[ContainerLocalConfig]" = None,
        engine_name: "str" = "unset",
        tempDir: "Optional[AnyPath]" = None,
    ):
        """
        Abstract init method


        """
        if local_config is None:
            local_config = dict()
        self.local_config = local_config

        # Getting a logger focused on specific classes
        self.logger = logging.getLogger(
            dict(inspect.getmembers(self))["__module__"]
            + "::"
            + self.__class__.__name__
        )

        # cacheDir
        if cacheDir is None:
            cacheDir = local_config.get("cacheDir")
            if cacheDir:
                os.makedirs(cacheDir, exist_ok=True)
            else:
                cacheDir = cast(
                    "AbsPath", tempfile.mkdtemp(prefix="wfexs", suffix="backend")
                )
                # Assuring this temporal directory is removed at the end
                atexit.register(shutil.rmtree, cacheDir)

        if tempDir is None:
            tempDir = cast(
                "AbsPath", tempfile.mkdtemp(prefix="WfExS-container", suffix="tempdir")
            )
            # Assuring this temporal directory is removed at the end
            atexit.register(shutil.rmtree, tempDir)

        # This directory might be needed by temporary processes, like
        # image materialization in singularity or podman
        self.tempDir = tempDir
        # But, for materialized containers, we should use common directories
        # This for the containers themselves
        self.containersCacheDir = cast(
            "AnyPath", os.path.join(cacheDir, "containers", self.__class__.__name__)
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
        simpleFileNameMethod: "ContainerFileNamingMethod",
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
                container = self.materializeSingleContainer(
                    tag,
                    simpleFileNameMethod,
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
        simpleFileNameMethod: "ContainerFileNamingMethod",
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
        simpleFileNameMethod: "ContainerFileNamingMethod",
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
                was_redeployed = self.deploySingleContainer(
                    container,
                    simpleFileNameMethod,
                    containers_dir=containers_dir,
                    force=force,
                )
                if was_redeployed is not None:
                    redeployed_containers.append(container)

        return redeployed_containers

    @abc.abstractmethod
    def deploySingleContainer(
        self,
        container: "Container",
        simpleFileNameMethod: "ContainerFileNamingMethod",
        containers_dir: "Optional[AnyPath]" = None,
        force: "bool" = False,
    ) -> "bool":
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
