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

import json
import lzma
import os
import shutil
import subprocess
import tempfile
from typing import (
    cast,
    TYPE_CHECKING,
)
import uuid

if TYPE_CHECKING:
    from typing import (
        Mapping,
        Optional,
        Sequence,
        Tuple,
        Union,
    )

    from .common import (
        AbsPath,
        AnyPath,
        ContainerFileNamingMethod,
        ContainerLocalConfig,
        ContainerOperatingSystem,
        ContainerTaggedName,
        ExitVal,
        ProcessorArchitecture,
        RelPath,
        URIType,
    )

from .common import (
    DEFAULT_PODMAN_CMD,
    Container,
    ContainerType,
)
from .container import (
    AbstractDockerContainerFactory,
    ContainerEngineException,
    ContainerFactoryException,
)
from .utils.contents import link_or_copy
from .utils.digests import ComputeDigestFromFile, ComputeDigestFromObject

DOCKER_PROTO = "docker://"


class PodmanContainerFactory(AbstractDockerContainerFactory):
    def __init__(
        self,
        cacheDir: "Optional[AnyPath]" = None,
        local_config: "Optional[ContainerLocalConfig]" = None,
        engine_name: "str" = "unset",
        tempDir: "Optional[AnyPath]" = None,
    ):
        super().__init__(
            cacheDir=cacheDir,
            local_config=local_config,
            engine_name=engine_name,
            tempDir=tempDir,
        )
        tools = local_config.get("tools", {}) if local_config else {}
        self.runtime_cmd = tools.get("podmanCommand", DEFAULT_PODMAN_CMD)

        self._environment.update(
            {
                "XDG_DATA_HOME": self.containersCacheDir,
            }
        )

        # Now, detect whether userns could work
        userns_supported = False
        if self.supportsFeature("host_userns"):
            userns_supported = True
            self._features.add("userns")

        self.logger.debug(f"Podman supports userns: {userns_supported}")

    @classmethod
    def ContainerType(cls) -> "ContainerType":
        return ContainerType.Podman

    def _inspect(
        self, dockerTag: "str", matEnv: "Mapping[str, str]"
    ) -> "Tuple[ExitVal, str, str]":
        with tempfile.NamedTemporaryFile() as d_out, tempfile.NamedTemporaryFile() as d_err:
            self.logger.debug(f"querying podman container {dockerTag}")
            d_retval = subprocess.Popen(
                [self.runtime_cmd, "inspect", dockerTag],
                env=matEnv,
                stdout=d_out,
                stderr=d_err,
            ).wait()

            self.logger.debug(f"podman inspect {dockerTag} retval: {d_retval}")

            with open(d_out.name, mode="rb") as c_stF:
                d_out_v = c_stF.read().decode("utf-8", errors="continue")
            with open(d_err.name, mode="rb") as c_stF:
                d_err_v = c_stF.read().decode("utf-8", errors="continue")

            self.logger.debug(f"podman inspect stdout: {d_out_v}")

            self.logger.debug(f"podman inspect stderr: {d_err_v}")

            return cast("ExitVal", d_retval), d_out_v, d_err_v

    def _pull(
        self, dockerTag: "str", matEnv: "Mapping[str, str]"
    ) -> "Tuple[ExitVal, str, str]":
        with tempfile.NamedTemporaryFile() as d_out, tempfile.NamedTemporaryFile() as d_err:
            self.logger.debug(f"pulling podman container {dockerTag}")
            d_retval = subprocess.Popen(
                [self.runtime_cmd, "pull", dockerTag],
                env=matEnv,
                stdout=d_out,
                stderr=d_err,
            ).wait()

            self.logger.debug(f"podman pull {dockerTag} retval: {d_retval}")

            with open(d_out.name, mode="r") as c_stF:
                d_out_v = c_stF.read()
            with open(d_err.name, "r") as c_stF:
                d_err_v = c_stF.read()

            self.logger.debug(f"podman pull stdout: {d_out_v}")

            self.logger.debug(f"podman pull stderr: {d_err_v}")

            return cast("ExitVal", d_retval), d_out_v, d_err_v

    def _rmi(
        self, dockerTag: "str", matEnv: "Mapping[str, str]"
    ) -> "Tuple[ExitVal, str, str]":
        with tempfile.NamedTemporaryFile() as d_out, tempfile.NamedTemporaryFile() as d_err:
            self.logger.debug(f"removing podman container {dockerTag}")
            d_retval = subprocess.Popen(
                [self.runtime_cmd, "rmi", dockerTag],
                env=matEnv,
                stdout=d_out,
                stderr=d_err,
            ).wait()

            self.logger.debug(f"podman rmi {dockerTag} retval: {d_retval}")

            with open(d_out.name, mode="r") as c_stF:
                d_out_v = c_stF.read()
            with open(d_err.name, "r") as c_stF:
                d_err_v = c_stF.read()

            self.logger.debug(f"podman rmi stdout: {d_out_v}")

            self.logger.debug(f"podman rmi stderr: {d_err_v}")

            return cast("ExitVal", d_retval), d_out_v, d_err_v

    def _save(
        self,
        dockerTag: "str",
        destfile: "AbsPath",
        matEnv: "Mapping[str, str]",
    ) -> "Tuple[ExitVal, str]":
        with lzma.open(
            destfile, mode="wb"
        ) as d_out, tempfile.NamedTemporaryFile() as d_err:
            self.logger.debug(f"saving podman container {dockerTag}")
            with subprocess.Popen(
                [self.runtime_cmd, "save", dockerTag],
                env=matEnv,
                stdout=subprocess.PIPE,
                stderr=d_err,
            ) as sp:
                if sp.stdout is not None:
                    shutil.copyfileobj(sp.stdout, d_out)
                d_retval = sp.wait()

            self.logger.debug(f"podman save {dockerTag} retval: {d_retval}")

            with open(d_err.name, "r") as c_stF:
                d_err_v = c_stF.read()

            self.logger.debug(f"podman save stderr: {d_err_v}")

            return cast("ExitVal", d_retval), d_err_v

    def _version(
        self,
    ) -> "Tuple[ExitVal, str, str]":
        with tempfile.NamedTemporaryFile() as d_out, tempfile.NamedTemporaryFile() as d_err:
            self.logger.debug(f"querying podman version and details")
            d_retval = subprocess.Popen(
                [self.runtime_cmd, "version", "--format", "{{json .}}"],
                stdout=d_out,
                stderr=d_err,
            ).wait()

            self.logger.debug(f"podman version retval: {d_retval}")

            with open(d_out.name, mode="r") as c_stF:
                d_out_v = c_stF.read()
            with open(d_err.name, "r") as c_stF:
                d_err_v = c_stF.read()

            self.logger.debug(f"podman version stdout: {d_out_v}")

            self.logger.debug(f"podman version stderr: {d_err_v}")

            return cast("ExitVal", d_retval), d_out_v, d_err_v

    @property
    def architecture(self) -> "Tuple[ContainerOperatingSystem, ProcessorArchitecture]":
        v_retval, payload, v_stderr = self._version()

        if v_retval != 0:
            errstr = """Could not get podman version. Retval {}
======
STDOUT
======
{}

======
STDERR
======
{}""".format(
                v_retval, payload, v_stderr
            )
            raise ContainerEngineException(errstr)

        try:
            version_json = json.loads(payload)
            osstr, arch = version_json["Client"]["OsArch"].split("/")

            # Trying to be coherent with Python
            if arch == "amd64":
                arch = "x86_64"

            return cast("ContainerOperatingSystem", osstr), cast(
                "ProcessorArchitecture", arch
            )
        except Exception as e:
            raise ContainerEngineException(
                "Ill-formed answer from podman version"
            ) from e

    def materializeSingleContainer(
        self,
        tag: "ContainerTaggedName",
        simpleFileNameMethod: "ContainerFileNamingMethod",
        containers_dir: "Optional[Union[RelPath, AbsPath]]" = None,
        offline: "bool" = False,
        force: "bool" = False,
    ) -> "Optional[Container]":
        """
        It is assured the containers are materialized
        """

        matEnv = dict(os.environ)
        matEnv.update(self.environment)

        # It is an absolute URL, we are removing the docker://
        tag_name = tag.origTaggedName
        if tag_name.startswith(DOCKER_PROTO):
            dockerTag = tag_name[len(DOCKER_PROTO) :]
            podmanPullTag = tag_name
        else:
            dockerTag = tag_name
            podmanPullTag = DOCKER_PROTO + tag_name

        self.logger.info(f"downloading podman container: {tag_name}")
        if force:
            if offline:
                raise ContainerFactoryException(
                    f"Banned remove podman containers in offline mode from {tag_name}"
                )

            # Blindly remove
            _, _, _ = self._rmi(dockerTag, matEnv)
            d_retval = -1
        else:
            d_retval, d_out_v, d_err_v = self._inspect(dockerTag, matEnv)

        # Time to pull the image
        if d_retval != 0:
            if offline:
                raise ContainerFactoryException(
                    f"Banned pull podman containers in offline mode from {tag_name}"
                )

            d_retval, d_out_v, d_err_v = self._pull(podmanPullTag, matEnv)
            if d_retval == 0:
                # Second try
                d_retval, d_out_v, d_err_v = self._inspect(dockerTag, matEnv)

        if d_retval != 0:
            errstr = """Could not materialize podman image {}. Retval {}
======
STDOUT
======
{}

======
STDERR
======
{}""".format(
                podmanPullTag, d_retval, d_out_v, d_err_v
            )
            raise ContainerEngineException(errstr)

        # Parsing the output from podman inspect
        try:
            manifests = json.loads(d_out_v)
            manifest = manifests[0]
        except Exception as e:
            raise ContainerFactoryException(
                f"FATAL ERROR: Podman finished properly but it did not properly materialize {tag_name}: {e}"
            )

        # Then, compute the signature
        tagId = manifest["Id"]
        fingerprint = None
        if len(manifest["RepoDigests"]) > 0:
            fingerprint = manifest["RepoDigests"][0]

        # Last but one, let's save a copy of the container locally
        containerFilename = simpleFileNameMethod(cast("URIType", tag_name))
        containerFilenameMeta = containerFilename + self.META_JSON_POSTFIX
        localContainerPath = cast(
            "AbsPath",
            os.path.join(self.engineContainersSymlinkDir, containerFilename),
        )
        localContainerPathMeta = cast(
            "AbsPath",
            os.path.join(self.engineContainersSymlinkDir, containerFilenameMeta),
        )

        self.logger.info(
            "saving docker container (for reproducibility matters): {} => {}".format(
                tag_name, localContainerPath
            )
        )
        # First, let's materialize the container image
        manifestsImageSignature = ComputeDigestFromObject(manifests)
        canonicalContainerPath = os.path.join(
            self.containersCacheDir,
            manifestsImageSignature.replace("=", "~")
            .replace("/", "-")
            .replace("+", "_"),
        )
        canonicalContainerPathMeta = canonicalContainerPath + self.META_JSON_POSTFIX

        # Defining the destinations
        if os.path.isfile(canonicalContainerPathMeta):
            with open(canonicalContainerPathMeta, mode="r", encoding="utf-8") as tcpm:
                metadataLocal = json.load(tcpm)

            manifestsImageSignatureLocal = metadataLocal.get("manifests_signature")
            manifestsImageSignatureLocalRead = ComputeDigestFromObject(
                metadataLocal.get("manifests", [])
            )
            if (
                manifestsImageSignature != manifestsImageSignatureLocal
                or manifestsImageSignature != manifestsImageSignatureLocalRead
            ):
                self.logger.warning(
                    f"Corrupted canonical container metadata {tag_name}. Re-saving"
                )
                saveContainerPathMeta = True
                imageSignatureLocal = None
            else:
                saveContainerPathMeta = False
                imageSignatureLocal = metadataLocal.get("image_signature")
        else:
            saveContainerPathMeta = True
            imageSignature = None
            imageSignatureLocal = None

        # Only trust when they match
        tmpContainerPath: "Optional[str]" = os.path.join(
            self.containersCacheDir, str(uuid.uuid4())
        )
        if os.path.isfile(canonicalContainerPath) and (imageSignatureLocal is not None):
            imageSignatureLocalRead = ComputeDigestFromFile(canonicalContainerPath)
            if imageSignatureLocalRead != imageSignatureLocal:
                self.logger.warning(
                    f"Corrupted canonical container {tag_name}. Re-saving"
                )
            else:
                imageSignature = imageSignatureLocal
                tmpContainerPath = None

        if tmpContainerPath is not None:
            saveContainerPathMeta = True
            d_retval, d_err_ev = self._save(
                dockerTag, cast("AbsPath", tmpContainerPath), matEnv
            )
            self.logger.debug("podman save retval: {}".format(d_retval))
            self.logger.debug("podman save stderr: {}".format(d_err_v))

            if d_retval != 0:
                errstr = """Could not save podman image {}. Retval {}
======
STDERR
======
{}""".format(
                    dockerTag, d_retval, d_err_v
                )
                if os.path.exists(tmpContainerPath):
                    try:
                        os.unlink(tmpContainerPath)
                    except:
                        pass
                raise ContainerEngineException(errstr)

            shutil.move(tmpContainerPath, canonicalContainerPath)
            imageSignature = ComputeDigestFromFile(canonicalContainerPath)

        if saveContainerPathMeta:
            with open(canonicalContainerPathMeta, mode="w", encoding="utf-8") as tcpM:
                json.dump(
                    {
                        "image_signature": imageSignature,
                        "manifests_signature": manifestsImageSignature,
                        "manifests": manifests,
                    },
                    tcpM,
                )

        # Now, check the relative symbolic link of image
        createSymlink = True
        if os.path.lexists(localContainerPath):
            if os.path.realpath(localContainerPath) != os.path.realpath(
                canonicalContainerPath
            ):
                os.unlink(localContainerPath)
            else:
                createSymlink = False
        if createSymlink:
            os.symlink(
                os.path.relpath(
                    canonicalContainerPath, self.engineContainersSymlinkDir
                ),
                localContainerPath,
            )

        # Now, check the relative symbolic link of metadata
        createSymlink = True
        if os.path.lexists(localContainerPathMeta):
            if os.path.realpath(localContainerPathMeta) != os.path.realpath(
                canonicalContainerPathMeta
            ):
                os.unlink(localContainerPathMeta)
            else:
                createSymlink = False
        if createSymlink:
            os.symlink(
                os.path.relpath(
                    canonicalContainerPathMeta, self.engineContainersSymlinkDir
                ),
                localContainerPathMeta,
            )

        # Last, hardlink or copy the container and its metadata
        if containers_dir is not None:
            containerPath = cast(
                "AbsPath", os.path.join(containers_dir, containerFilename)
            )
            containerPathMeta = cast(
                "AbsPath", os.path.join(containers_dir, containerFilenameMeta)
            )

            # Do not allow overwriting in offline mode
            if not offline or not os.path.exists(containerPath):
                link_or_copy(localContainerPath, containerPath)
            if not offline or not os.path.exists(containerPathMeta):
                link_or_copy(localContainerPathMeta, containerPathMeta)
        else:
            containerPath = localContainerPath

        # Learning about the intended processor architecture and variant
        architecture = manifest.get("Architecture")
        # As of version 4.5.0, podman does not report the architecture variant
        if architecture is not None:
            variant = manifest.get("Variant")
            if variant is not None:
                architecture += "/" + variant
        # And add to the list of containers
        return Container(
            origTaggedName=tag_name,
            taggedName=cast("URIType", dockerTag),
            signature=tagId,
            fingerprint=fingerprint,
            architecture=architecture,
            operatingSystem=manifest.get("Os"),
            type=self.containerType,
            localPath=containerPath,
        )
