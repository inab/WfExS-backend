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

import copy
import lzma
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

import magic
import pgzip

from .common import (
    AbstractWfExSException,
)

if TYPE_CHECKING:
    from types import (
        ModuleType,
    )

    from typing import (
        Any,
        IO,
        Mapping,
        MutableMapping,
        MutableSequence,
        Optional,
        Sequence,
        Set,
        Tuple,
        Union,
    )

    from typing_extensions import (
        TypeAlias,
        TypedDict,
        Final,
    )

    from .common import (
        AbsPath,
        AnyPath,
        ContainerEngineVersionStr,
        ContainerFileNamingMethod,
        ContainerLocalConfig,
        ContainerOperatingSystem,
        ContainerTaggedName,
        ExitVal,
        Fingerprint,
        ProcessorArchitecture,
        RelPath,
    )

    from .container import (
        Container,
    )

    DockerLikeManifest: TypeAlias = Mapping[str, Any]
    MutableDockerLikeManifest: TypeAlias = MutableMapping[str, Any]

    class DockerManifestMetadata(TypedDict):
        image_id: "Fingerprint"
        image_signature: "Fingerprint"
        manifests_signature: "Fingerprint"
        manifests: "Sequence[DockerLikeManifest]"


from . import common
from .container import (
    ContainerFactory,
    ContainerFactoryException,
    DOCKER_URI_PREFIX,
)
from .utils.digests import ComputeDigestFromObject


DOCKER_PROTO = DOCKER_URI_PREFIX + "//"


class AbstractDockerContainerFactory(ContainerFactory):
    ACCEPTED_CONTAINER_TYPES = set(
        (
            common.ContainerType.Docker,
            common.ContainerType.UDocker,
            common.ContainerType.Podman,
        )
    )

    @classmethod
    def AcceptsContainerType(
        cls, container_type: "Union[common.ContainerType, Set[common.ContainerType]]"
    ) -> "bool":
        return not cls.ACCEPTED_CONTAINER_TYPES.isdisjoint(
            container_type if isinstance(container_type, set) else (container_type,)
        )

    @classmethod
    @abc.abstractmethod
    def trimmable_manifest_keys(cls) -> "Sequence[str]":
        pass

    def _gen_trimmed_manifests_signature(
        self, manifests: "Sequence[DockerLikeManifest]"
    ) -> "Fingerprint":
        trimmed_manifests: "MutableSequence[DockerLikeManifest]" = []
        some_trimmed = False
        for manifest in manifests:
            # Copy the manifest
            trimmed_manifest = cast("MutableDockerLikeManifest", copy.copy(manifest))
            # And trim the keys
            for key in self.trimmable_manifest_keys():
                if key in trimmed_manifest:
                    del trimmed_manifest[key]
                    some_trimmed = True

            trimmed_manifests.append(trimmed_manifest)

        return cast(
            "Fingerprint",
            ComputeDigestFromObject(trimmed_manifests if some_trimmed else manifests),
        )

    @classmethod
    @abc.abstractmethod
    def variant_name(cls) -> "str":
        pass

    def _images(self, matEnv: "Mapping[str, str]") -> "Tuple[ExitVal, str, str]":
        with tempfile.NamedTemporaryFile() as d_out, tempfile.NamedTemporaryFile() as d_err:
            self.logger.debug(f"querying available {self.variant_name()} containers")
            d_retval = subprocess.Popen(
                [self.runtime_cmd, "images"],
                env=matEnv,
                stdout=d_out,
                stderr=d_err,
            ).wait()

            self.logger.debug(f"{self.variant_name()} images retval: {d_retval}")

            with open(d_out.name, mode="rb") as c_stF:
                d_out_v = c_stF.read().decode("utf-8", errors="continue")
            with open(d_err.name, mode="rb") as c_stF:
                d_err_v = c_stF.read().decode("utf-8", errors="continue")

            self.logger.debug(f"{self.variant_name()} inspect stdout: {d_out_v}")

            self.logger.debug(f"{self.variant_name()} inspect stderr: {d_err_v}")

            return cast("ExitVal", d_retval), d_out_v, d_err_v

    def _inspect(
        self, dockerTag: "str", matEnv: "Mapping[str, str]"
    ) -> "Tuple[ExitVal, str, str]":
        with tempfile.NamedTemporaryFile() as d_out, tempfile.NamedTemporaryFile() as d_err:
            self.logger.debug(f"querying {self.variant_name()} container {dockerTag}")
            d_retval = subprocess.Popen(
                [self.runtime_cmd, "inspect", dockerTag],
                env=matEnv,
                stdout=d_out,
                stderr=d_err,
            ).wait()

            self.logger.debug(
                f"{self.variant_name()} inspect {dockerTag} retval: {d_retval}"
            )

            with open(d_out.name, mode="rb") as c_stF:
                d_out_v = c_stF.read().decode("utf-8", errors="continue")
            with open(d_err.name, mode="rb") as c_stF:
                d_err_v = c_stF.read().decode("utf-8", errors="continue")

            self.logger.debug(f"{self.variant_name()} inspect stdout: {d_out_v}")

            self.logger.debug(f"{self.variant_name()} inspect stderr: {d_err_v}")

            return cast("ExitVal", d_retval), d_out_v, d_err_v

    def _pull(
        self, dockerTag: "str", matEnv: "Mapping[str, str]"
    ) -> "Tuple[ExitVal, str, str]":
        with tempfile.NamedTemporaryFile() as d_out, tempfile.NamedTemporaryFile() as d_err:
            self.logger.debug(f"pulling {self.variant_name()} container {dockerTag}")
            d_retval = subprocess.Popen(
                [self.runtime_cmd, "pull", dockerTag],
                env=matEnv,
                stdout=d_out,
                stderr=d_err,
            ).wait()

            self.logger.debug(
                f"{self.variant_name()} pull {dockerTag} retval: {d_retval}"
            )

            with open(d_out.name, mode="r") as c_stF:
                d_out_v = c_stF.read()
            with open(d_err.name, "r") as c_stF:
                d_err_v = c_stF.read()

            self.logger.debug(f"{self.variant_name()} pull stdout: {d_out_v}")

            self.logger.debug(f"{self.variant_name()} pull stderr: {d_err_v}")

            return cast("ExitVal", d_retval), d_out_v, d_err_v

    def _rmi(
        self, dockerTag: "str", matEnv: "Mapping[str, str]"
    ) -> "Tuple[ExitVal, str, str]":
        with tempfile.NamedTemporaryFile() as d_out, tempfile.NamedTemporaryFile() as d_err:
            self.logger.debug(f"removing {self.variant_name()} container {dockerTag}")
            d_retval = subprocess.Popen(
                [self.runtime_cmd, "rmi", dockerTag],
                env=matEnv,
                stdout=d_out,
                stderr=d_err,
            ).wait()

            self.logger.debug(
                f"{self.variant_name()} rmi {dockerTag} retval: {d_retval}"
            )

            with open(d_out.name, mode="r") as c_stF:
                d_out_v = c_stF.read()
            with open(d_err.name, "r") as c_stF:
                d_err_v = c_stF.read()

            self.logger.debug(f"{self.variant_name()} rmi stdout: {d_out_v}")

            self.logger.debug(f"{self.variant_name()} rmi stderr: {d_err_v}")

            return cast("ExitVal", d_retval), d_out_v, d_err_v

    def _load(
        self,
        archivefile: "AbsPath",
        dockerTag: "str",
        matEnv: "Mapping[str, str]",
    ) -> "Tuple[ExitVal, str, str]":
        foundmime = magic.from_file(archivefile, mime=True)
        package: "ModuleType"
        if foundmime == "application/x-xz":
            package = lzma
        elif foundmime == "application/gzip":
            package = pgzip
        else:
            raise ContainerFactoryException(
                f"Unknown {self.variant_name()} archive compression format: {foundmime}"
            )

        with package.open(
            archivefile, mode="rb"
        ) as d_in, tempfile.NamedTemporaryFile() as d_out, tempfile.NamedTemporaryFile() as d_err:
            self.logger.debug(f"loading {self.variant_name()} container {dockerTag}")
            with subprocess.Popen(
                [self.runtime_cmd, "load"],
                env=matEnv,
                stdin=d_in,
                stdout=d_out,
                stderr=d_err,
            ) as sp:
                d_retval = sp.wait()

            self.logger.debug(
                f"{self.variant_name()} load {dockerTag} retval: {d_retval}"
            )

            with open(d_out.name, "r") as c_stF:
                d_out_v = c_stF.read()

            self.logger.debug(f"{self.variant_name()} load stdout: {d_out_v}")

            with open(d_err.name, "r") as c_stF:
                d_err_v = c_stF.read()

            self.logger.debug(f"{self.variant_name()} load stderr: {d_err_v}")

            return cast("ExitVal", d_retval), d_out_v, d_err_v

    def _save(
        self,
        dockerTag: "str",
        destfile: "AbsPath",
        matEnv: "Mapping[str, str]",
    ) -> "Tuple[ExitVal, str]":
        with pgzip.open(
            destfile, mode="wb"
        ) as d_out, tempfile.NamedTemporaryFile() as d_err:
            self.logger.debug(f"saving {self.variant_name()} container {dockerTag}")
            with subprocess.Popen(
                [self.runtime_cmd, "save", dockerTag],
                env=matEnv,
                stdout=subprocess.PIPE,
                stderr=d_err,
            ) as sp:
                if sp.stdout is not None:
                    shutil.copyfileobj(
                        cast("IO[str]", sp.stdout), d_out, length=1024 * 1024
                    )
                d_retval = sp.wait()

            self.logger.debug(
                f"{self.variant_name()} save {dockerTag} retval: {d_retval}"
            )

            with open(d_err.name, "r") as c_stF:
                d_err_v = c_stF.read()

            self.logger.debug(f"{self.variant_name()} save stderr: {d_err_v}")

            return cast("ExitVal", d_retval), d_err_v

    def _version(
        self,
    ) -> "Tuple[ExitVal, str, str]":
        with tempfile.NamedTemporaryFile() as d_out, tempfile.NamedTemporaryFile() as d_err:
            self.logger.debug(f"querying {self.variant_name()} version and details")
            d_retval = subprocess.Popen(
                [self.runtime_cmd, "version", "--format", "{{json .}}"],
                stdout=d_out,
                stderr=d_err,
            ).wait()

            self.logger.debug(f"{self.variant_name()} version retval: {d_retval}")

            with open(d_out.name, mode="r") as c_stF:
                d_out_v = c_stF.read()
            with open(d_err.name, "r") as c_stF:
                d_err_v = c_stF.read()

            self.logger.debug(f"{self.variant_name()} version stdout: {d_out_v}")

            self.logger.debug(f"{self.variant_name()} version stderr: {d_err_v}")

            return cast("ExitVal", d_retval), d_out_v, d_err_v
