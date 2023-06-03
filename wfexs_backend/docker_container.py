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
    Container,
    ContainerType,
    DEFAULT_DOCKER_CMD,
)

from .container import (
    ContainerFactory,
    ContainerEngineException,
    ContainerFactoryException,
)
from .utils.contents import link_or_copy
from .utils.digests import ComputeDigestFromFile, ComputeDigestFromObject

DOCKER_PROTO = "docker://"


class DockerContainerFactory(ContainerFactory):
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
        self.runtime_cmd = tools.get("dockerCommand", DEFAULT_DOCKER_CMD)

    @classmethod
    def ContainerType(cls) -> "ContainerType":
        return ContainerType.Docker

    def _inspect(
        self, dockerTag: "ContainerTaggedName", matEnv: "Mapping[str, str]"
    ) -> "Tuple[ExitVal, str, str]":
        with tempfile.NamedTemporaryFile() as d_out, tempfile.NamedTemporaryFile() as d_err:
            self.logger.debug(f"querying docker container {dockerTag}")
            d_retval = subprocess.Popen(
                [self.runtime_cmd, "inspect", dockerTag],
                env=matEnv,
                stdout=d_out,
                stderr=d_err,
            ).wait()

            self.logger.debug(f"docker inspect {dockerTag} retval: {d_retval}")

            with open(d_out.name, mode="rb") as c_stF:
                d_out_v = c_stF.read().decode("utf-8", errors="continue")
            with open(d_err.name, mode="rb") as c_stF:
                d_err_v = c_stF.read().decode("utf-8", errors="continue")

            self.logger.debug(f"docker inspect stdout: {d_out_v}")

            self.logger.debug(f"docker inspect stderr: {d_err_v}")

            return cast("ExitVal", d_retval), d_out_v, d_err_v

    def _pull(
        self, dockerTag: "ContainerTaggedName", matEnv: "Mapping[str, str]"
    ) -> "Tuple[ExitVal, str, str]":
        with tempfile.NamedTemporaryFile() as d_out, tempfile.NamedTemporaryFile() as d_err:
            self.logger.debug(f"pulling docker container {dockerTag}")
            d_retval = subprocess.Popen(
                [self.runtime_cmd, "pull", dockerTag],
                env=matEnv,
                stdout=d_out,
                stderr=d_err,
            ).wait()

            self.logger.debug(f"docker pull {dockerTag} retval: {d_retval}")

            with open(d_out.name, mode="r") as c_stF:
                d_out_v = c_stF.read()
            with open(d_err.name, "r") as c_stF:
                d_err_v = c_stF.read()

            self.logger.debug(f"docker pull stdout: {d_out_v}")

            self.logger.debug(f"docker pull stderr: {d_err_v}")

            return cast("ExitVal", d_retval), d_out_v, d_err_v

    def _rmi(
        self, dockerTag: "ContainerTaggedName", matEnv: "Mapping[str, str]"
    ) -> "Tuple[ExitVal, str, str]":
        with tempfile.NamedTemporaryFile() as d_out, tempfile.NamedTemporaryFile() as d_err:
            self.logger.debug(f"removing docker container {dockerTag}")
            d_retval = subprocess.Popen(
                [self.runtime_cmd, "rmi", dockerTag],
                env=matEnv,
                stdout=d_out,
                stderr=d_err,
            ).wait()

            self.logger.debug(f"docker rmi {dockerTag} retval: {d_retval}")

            with open(d_out.name, mode="r") as c_stF:
                d_out_v = c_stF.read()
            with open(d_err.name, "r") as c_stF:
                d_err_v = c_stF.read()

            self.logger.debug(f"docker rmi stdout: {d_out_v}")

            self.logger.debug(f"docker rmi stderr: {d_err_v}")

            return cast("ExitVal", d_retval), d_out_v, d_err_v

    def _save(
        self,
        dockerTag: "ContainerTaggedName",
        destfile: "AbsPath",
        matEnv: "Mapping[str, str]",
    ) -> "Tuple[ExitVal, str]":
        with lzma.open(
            destfile, mode="wb"
        ) as d_out, tempfile.NamedTemporaryFile() as d_err:
            self.logger.debug(f"saving docker container {dockerTag}")
            with subprocess.Popen(
                [self.runtime_cmd, "save", dockerTag],
                env=matEnv,
                stdout=subprocess.PIPE,
                stderr=d_err,
            ) as sp:
                if sp.stdout is not None:
                    shutil.copyfileobj(sp.stdout, d_out)
                d_retval = sp.wait()

            self.logger.debug(f"docker save {dockerTag} retval: {d_retval}")

            with open(d_err.name, "r") as c_stF:
                d_err_v = c_stF.read()

            self.logger.debug(f"docker save stderr: {d_err_v}")

            return cast("ExitVal", d_retval), d_err_v

    def _version(
        self,
    ) -> "Tuple[ExitVal, str, str]":
        with tempfile.NamedTemporaryFile() as d_out, tempfile.NamedTemporaryFile() as d_err:
            self.logger.debug(f"querying docker version and details")
            d_retval = subprocess.Popen(
                [self.runtime_cmd, "version", "--format", "{{json .}}"],
                stdout=d_out,
                stderr=d_err,
            ).wait()

            self.logger.debug(f"docker version retval: {d_retval}")

            with open(d_out.name, mode="r") as c_stF:
                d_out_v = c_stF.read()
            with open(d_err.name, "r") as c_stF:
                d_err_v = c_stF.read()

            self.logger.debug(f"docker version stdout: {d_out_v}")

            self.logger.debug(f"docker version stderr: {d_err_v}")

            return cast("ExitVal", d_retval), d_out_v, d_err_v

    @property
    def architecture(self) -> "Tuple[ContainerOperatingSystem, ProcessorArchitecture]":
        v_retval, payload, v_stderr = self._version()

        if v_retval != 0:
            errstr = """Could not get docker version. Retval {}
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
            arch = version_json["Client"]["Arch"]

            # Trying to be coherent with Python
            if arch == "amd64":
                arch = "x86_64"
            return cast("ContainerOperatingSystem", version_json["Client"]["Os"]), cast(
                "ProcessorArchitecture", arch
            )
        except json.JSONDecodeError as je:
            raise ContainerEngineException(
                "Ill-formed answer from docker version"
            ) from je

    def materializeContainers(
        self,
        tagList: "Sequence[ContainerTaggedName]",
        simpleFileNameMethod: "ContainerFileNamingMethod",
        containers_dir: "Optional[Union[RelPath, AbsPath]]" = None,
        offline: "bool" = False,
        force: "bool" = False,
    ) -> "Sequence[Container]":
        """
        It is assured the containers are materialized
        """
        containersList = []

        matEnv = dict(os.environ)
        matEnv.update(self.environment)
        for tag in tagList:
            # It is an absolute URL, we are removing the docker://
            dockerTag = cast(
                "ContainerTaggedName",
                tag[len(DOCKER_PROTO) :] if tag.startswith(DOCKER_PROTO) else tag,
            )

            self.logger.info(f"downloading docker container: {tag}")
            if force:
                if offline:
                    raise ContainerFactoryException(
                        f"Banned remove podman containers in offline mode from {tag}"
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
                        f"Banned pull podman containers in offline mode from {tag}"
                    )

                d_retval, d_out_v, d_err_v = self._pull(dockerTag, matEnv)
                if d_retval == 0:
                    # Second try
                    d_retval, d_out_v, d_err_v = self._inspect(dockerTag, matEnv)

            if d_retval != 0:
                errstr = """Could not materialize docker image {}. Retval {}
======
STDOUT
======
{}

======
STDERR
======
{}""".format(
                    dockerTag, d_retval, d_out_v, d_err_v
                )
                raise ContainerEngineException(errstr)

            # Parsing the output from docker inspect
            try:
                manifests = json.loads(d_out_v)
                manifest = manifests[0]
            except Exception as e:
                raise ContainerFactoryException(
                    f"FATAL ERROR: Docker finished properly but it did not properly materialize {tag}: {e}"
                )

            # Then, compute the signature
            tagId = manifest["Id"]
            fingerprint = None
            if len(manifest["RepoDigests"]) > 0:
                fingerprint = manifest["RepoDigests"][0]

            # Last but one, let's save a copy of the container locally
            containerFilename = simpleFileNameMethod(cast("URIType", tag))
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
                    tag, localContainerPath
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
                with open(
                    canonicalContainerPathMeta, mode="r", encoding="utf-8"
                ) as tcpm:
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
                        "Corrupted canonical container metadata {tag}. Re-saving"
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
            if os.path.isfile(canonicalContainerPath) and (
                imageSignatureLocal is not None
            ):
                imageSignatureLocalRead = ComputeDigestFromFile(canonicalContainerPath)
                if imageSignatureLocalRead != imageSignatureLocal:
                    self.logger.warning(
                        "Corrupted canonical container {tag}. Re-saving"
                    )
                else:
                    imageSignature = imageSignatureLocal
                    tmpContainerPath = None

            if tmpContainerPath is not None:
                saveContainerPathMeta = True
                d_retval, d_err_ev = self._save(
                    dockerTag, cast("AbsPath", tmpContainerPath), matEnv
                )
                self.logger.debug("docker save retval: {}".format(d_retval))
                self.logger.debug("docker save stderr: {}".format(d_err_v))

                if d_retval != 0:
                    errstr = """Could not save docker image {}. Retval {}
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
                with open(
                    canonicalContainerPathMeta, mode="w", encoding="utf-8"
                ) as tcpM:
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

            # And add to the list of containers
            containersList.append(
                Container(
                    origTaggedName=tag,
                    taggedName=cast("URIType", dockerTag),
                    signature=tagId,
                    fingerprint=fingerprint,
                    type=self.containerType,
                    localPath=containerPath,
                )
            )

        return containersList
