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
        Any,
        Mapping,
        Optional,
        Sequence,
        Tuple,
        Union,
    )

    from typing_extensions import (
        Final,
    )

    from .common import (
        AbsPath,
        AnyPath,
        ContainerFileNamingMethod,
        ContainerLocalConfig,
        ContainerOperatingSystem,
        ContainerTaggedName,
        ExitVal,
        Fingerprint,
        ProcessorArchitecture,
        RelPath,
        URIType,
    )

    from .container import (
        DockerManifestMetadata,
    )

from .common import (
    Container,
    ContainerType,
    DEFAULT_DOCKER_CMD,
)

from .container import (
    AbstractDockerContainerFactory,
    ContainerEngineException,
    ContainerFactoryException,
)
from .utils.contents import (
    link_or_copy,
    real_unlink_if_exists,
)
from .utils.digests import ComputeDigestFromFile

DOCKER_PROTO = "docker://"


class DockerContainerFactory(AbstractDockerContainerFactory):
    TRIMMABLE_MANIFEST_KEYS: "Final[Sequence[str]]" = [
        "RepoDigests",
    ]

    @classmethod
    def trimmable_manifest_keys(cls) -> "Sequence[str]":
        return cls.TRIMMABLE_MANIFEST_KEYS

    def __init__(
        self,
        cacheDir: "Optional[AnyPath]" = None,
        stagedContainersDir: "Optional[AnyPath]" = None,
        local_config: "Optional[ContainerLocalConfig]" = None,
        engine_name: "str" = "unset",
        tempDir: "Optional[AnyPath]" = None,
    ):
        super().__init__(
            cacheDir=cacheDir,
            stagedContainersDir=stagedContainersDir,
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
        self, dockerTag: "str", matEnv: "Mapping[str, str]"
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
        self, dockerTag: "str", matEnv: "Mapping[str, str]"
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
        self, dockerTag: "str", matEnv: "Mapping[str, str]"
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

    def _load(
        self,
        archivefile: "AbsPath",
        dockerTag: "str",
        matEnv: "Mapping[str, str]",
    ) -> "Tuple[ExitVal, str, str]":
        with lzma.open(
            archivefile, mode="rb"
        ) as d_in, tempfile.NamedTemporaryFile() as d_out, tempfile.NamedTemporaryFile() as d_err:
            self.logger.debug(f"loading docker container {dockerTag}")
            with subprocess.Popen(
                [self.runtime_cmd, "load"],
                env=matEnv,
                stdin=d_in,
                stdout=d_out,
                stderr=d_err,
            ) as sp:
                d_retval = sp.wait()

            self.logger.debug(f"docker load {dockerTag} retval: {d_retval}")

            with open(d_out.name, "r") as c_stF:
                d_out_v = c_stF.read()

            self.logger.debug(f"docker load stdout: {d_out_v}")

            with open(d_err.name, "r") as c_stF:
                d_err_v = c_stF.read()

            self.logger.debug(f"docker load stderr: {d_err_v}")

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
            self.logger.debug(f"saving docker container {dockerTag}")
            with subprocess.Popen(
                [self.runtime_cmd, "save", dockerTag],
                env=matEnv,
                stdout=subprocess.PIPE,
                stderr=d_err,
            ) as sp:
                if sp.stdout is not None:
                    shutil.copyfileobj(sp.stdout, d_out, 1024 * 1024)
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

    def materializeSingleContainer(
        self,
        tag: "ContainerTaggedName",
        simpleFileNameMethod: "ContainerFileNamingMethod",
        containers_dir: "Optional[AnyPath]" = None,
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
        dockerTag = (
            tag_name[len(DOCKER_PROTO) :]
            if tag_name.startswith(DOCKER_PROTO)
            else tag_name
        )

        # Should we enrich the tag with the registry?
        if isinstance(tag.registries, dict) and (
            ContainerType.Docker in tag.registries
        ):
            registry = tag.registries[ContainerType.Docker]
            # Bare case
            if "/" not in dockerTag:
                dockerTag = f"{registry}/library/{dockerTag}"
            elif dockerTag.find("/") == dockerTag.rfind("/"):
                dockerTag = f"{registry}/{dockerTag}"
            # Last case, it already has a registry declared

        self.logger.info(f"downloading docker container: {tag_name} => {dockerTag}")
        # These are the paths to the copy of the saved container
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

        # Keep a copy outside the cache directory
        if containers_dir is None:
            containers_dir = self.stagedContainersDir
        containerPath = cast("AbsPath", os.path.join(containers_dir, containerFilename))
        containerPathMeta = cast(
            "AbsPath", os.path.join(containers_dir, containerFilenameMeta)
        )

        # Now it is time to check whether the local cache of the container
        # does exist and it is right
        trusted_copy = False
        image_id: "Optional[Fingerprint]" = None
        imageSignature: "Optional[Fingerprint]" = None
        manifestsImageSignature: "Optional[Fingerprint]" = None
        manifests = None
        manifest = None
        if not force and os.path.isfile(localContainerPathMeta):
            trusted_copy = True
            try:
                with open(localContainerPathMeta, mode="r", encoding="utf-8") as mH:
                    signaturesAndManifest = cast(
                        "DockerManifestMetadata", json.load(mH)
                    )
                    image_id = signaturesAndManifest["image_id"]
                    imageSignature = signaturesAndManifest["image_signature"]
                    manifestsImageSignature = signaturesAndManifest[
                        "manifests_signature"
                    ]
                    manifests = signaturesAndManifest["manifests"]

                    # Check the status of the gathered manifests
                    trusted_copy = (
                        manifestsImageSignature
                        == self._gen_trimmed_manifests_signature(manifests)
                    )
            except Exception as e:
                self.logger.exception(
                    f"Problems extracting docker metadata at {localContainerPathMeta}"
                )
                trusted_copy = False

            # Let's check metadata coherence
            if trusted_copy:
                trusted_copy = (
                    imageSignature is not None
                    and manifestsImageSignature is not None
                    and manifests is not None
                )

            if trusted_copy:
                assert manifestsImageSignature is not None
                if os.path.islink(localContainerPathMeta):
                    # Some filesystems complain when filenames contain 'equal', 'slash' or 'plus' symbols
                    unlinkedContainerPathMeta = os.readlink(localContainerPathMeta)
                    fsImageSignatureMeta = os.path.basename(unlinkedContainerPathMeta)
                    if fsImageSignatureMeta.endswith(self.META_JSON_POSTFIX):
                        fsImageSignatureMeta = fsImageSignatureMeta[
                            : -len(self.META_JSON_POSTFIX)
                        ]
                    putativeManifestsImageSignature = (
                        fsImageSignatureMeta.replace("~", "=")
                        .replace("-", "/")
                        .replace("_", "+")
                    )

                    trusted_copy = (
                        putativeManifestsImageSignature == manifestsImageSignature
                    )
                    if trusted_copy:
                        canonicalContainerPathMeta = os.path.join(
                            self.containersCacheDir,
                            fsImageSignatureMeta + self.META_JSON_POSTFIX,
                        )

                        trusted_copy = os.path.samefile(
                            os.path.realpath(localContainerPathMeta),
                            os.path.realpath(canonicalContainerPathMeta),
                        )
                else:
                    # Some filesystems complain when filenames contain 'equal', 'slash' or 'plus' symbols
                    putativeCanonicalContainerPathMeta = os.path.join(
                        self.containersCacheDir,
                        manifestsImageSignature.replace("=", "~")
                        .replace("/", "-")
                        .replace("+", "_"),
                    )

                    # This is to detect poisoned caches
                    trusted_copy = os.path.samefile(
                        localContainerPathMeta, putativeCanonicalContainerPathMeta
                    )

            # Now, let's check the image itself
            if trusted_copy and os.path.isfile(localContainerPath):
                trusted_copy = imageSignature == ComputeDigestFromFile(
                    localContainerPath
                )

            if trusted_copy:
                assert imageSignature is not None
                if os.path.islink(localContainerPath):
                    # Some filesystems complain when filenames contain 'equal', 'slash' or 'plus' symbols
                    unlinkedContainerPath = os.readlink(localContainerPath)
                    fsImageSignature = os.path.basename(unlinkedContainerPath)
                    putativeImageSignature = (
                        fsImageSignature.replace("~", "=")
                        .replace("-", "/")
                        .replace("_", "+")
                    )

                    trusted_copy = putativeImageSignature == manifestsImageSignature
                    if trusted_copy:
                        canonicalContainerPath = os.path.join(
                            self.containersCacheDir,
                            fsImageSignature,
                        )

                        trusted_copy = os.path.samefile(
                            os.path.realpath(localContainerPath),
                            os.path.realpath(canonicalContainerPath),
                        )

                else:
                    # Some filesystems complain when filenames contain 'equal', 'slash' or 'plus' symbols
                    putativeCanonicalContainerPath = os.path.join(
                        self.containersCacheDir,
                        imageSignature.replace("=", "~")
                        .replace("/", "-")
                        .replace("+", "_"),
                    )

                    # This is to detect poisoned caches
                    trusted_copy = os.path.samefile(
                        localContainerPath, putativeCanonicalContainerPath
                    )

        # And now, the final judgement!
        if force or not trusted_copy:
            if offline:
                raise ContainerFactoryException(
                    f"Banned remove docker containers in offline mode from {tag_name}"
                )

            if os.path.exists(localContainerPathMeta) or os.path.exists(
                localContainerPath
            ):
                self.logger.warning(
                    f"Unable to trust Docker container {tag_name} => {dockerTag} . Discarding cached contents"
                )
                real_unlink_if_exists(localContainerPathMeta)
                real_unlink_if_exists(localContainerPath)

            # Blindly remove
            _, _, _ = self._rmi(dockerTag, matEnv)

            # And now, let's materialize the new world
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
                manifests = cast("Sequence[Mapping[str, Any]]", json.loads(d_out_v))
                manifest = manifests[0]
                image_id = cast("Fingerprint", manifest["Id"])
            except Exception as e:
                raise ContainerFactoryException(
                    f"FATAL ERROR: Docker finished properly but it did not properly materialize {tag_name}: {e}"
                )

            self.logger.info(
                "saving docker container (for reproducibility matters): {} => {}".format(
                    tag_name, localContainerPath
                )
            )

            # Let's materialize the container image for preservation
            manifestsImageSignature = self._gen_trimmed_manifests_signature(manifests)
            canonicalContainerPath = os.path.join(
                self.containersCacheDir,
                manifestsImageSignature.replace("=", "~")
                .replace("/", "-")
                .replace("+", "_"),
            )

            # Being sure the paths do not exist
            if os.path.exists(canonicalContainerPath):
                os.unlink(canonicalContainerPath)
            canonicalContainerPathMeta = canonicalContainerPath + self.META_JSON_POSTFIX
            if os.path.exists(canonicalContainerPathMeta):
                os.unlink(canonicalContainerPathMeta)

            # Now, save the image as such
            d_retval, d_err_ev = self._save(
                dockerTag, cast("AbsPath", canonicalContainerPath), matEnv
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

                # Removing partial dumps
                if os.path.exists(canonicalContainerPath):
                    try:
                        os.unlink(canonicalContainerPath)
                    except:
                        pass
                raise ContainerEngineException(errstr)

            imageSignature = cast(
                "Fingerprint", ComputeDigestFromFile(canonicalContainerPath)
            )

            # Last, save the metadata itself for further usage
            with open(canonicalContainerPathMeta, mode="w", encoding="utf-8") as tcpM:
                manifest_metadata: "DockerManifestMetadata" = {
                    "image_id": image_id,
                    "image_signature": imageSignature,
                    "manifests_signature": manifestsImageSignature,
                    "manifests": manifests,
                }
                json.dump(manifest_metadata, tcpM)

            # Now, check the relative symbolic link of image
            if os.path.lexists(localContainerPath):
                os.unlink(localContainerPath)

            os.symlink(
                os.path.relpath(
                    canonicalContainerPath, self.engineContainersSymlinkDir
                ),
                localContainerPath,
            )

            # Now, check the relative symbolic link of metadata
            if os.path.lexists(localContainerPathMeta):
                os.unlink(localContainerPathMeta)
            os.symlink(
                os.path.relpath(
                    canonicalContainerPathMeta, self.engineContainersSymlinkDir
                ),
                localContainerPathMeta,
            )

        assert manifestsImageSignature is not None
        assert manifests is not None
        if manifest is None:
            manifest = manifests[0]

        # Do not allow overwriting in offline mode
        if not offline or not os.path.exists(containerPath):
            link_or_copy(localContainerPath, containerPath)
        if not offline or not os.path.exists(containerPathMeta):
            link_or_copy(localContainerPathMeta, containerPathMeta)

        # Now the image is not loaded here, but later in deploySingleContainer

        # Then, compute the fingerprint
        fingerprint = None
        if len(manifest["RepoDigests"]) > 0:
            fingerprint = manifest["RepoDigests"][0]

        # Learning about the intended processor architecture and variant
        architecture = manifest.get("Architecture")
        if architecture is not None:
            variant = manifest.get("Variant")
            if variant is not None:
                architecture += "/" + variant
        # And add to the list of containers
        return Container(
            origTaggedName=tag_name,
            taggedName=cast("URIType", dockerTag),
            signature=image_id,
            fingerprint=fingerprint,
            architecture=architecture,
            operatingSystem=manifest.get("Os"),
            type=self.containerType,
            localPath=containerPath,
            registries=tag.registries,
        )

    def deploySingleContainer(
        self,
        container: "Container",
        simpleFileNameMethod: "ContainerFileNamingMethod",
        containers_dir: "Optional[AnyPath]" = None,
        force: "bool" = False,
    ) -> "bool":
        # Should we load the image?
        matEnv = dict(os.environ)
        matEnv.update(self.environment)
        dockerTag = container.taggedName
        tag_name = container.origTaggedName

        # These are the paths to the copy of the saved container
        containerFilename = simpleFileNameMethod(cast("URIType", tag_name))
        containerFilenameMeta = containerFilename + self.META_JSON_POSTFIX

        # Keep a copy outside the cache directory
        if containers_dir is None:
            containers_dir = self.stagedContainersDir
        containerPath = cast("AbsPath", os.path.join(containers_dir, containerFilename))
        containerPathMeta = cast(
            "AbsPath", os.path.join(containers_dir, containerFilenameMeta)
        )

        imageSignature: "Optional[Fingerprint]" = None
        manifestsImageSignature: "Optional[Fingerprint]" = None
        manifests = None
        manifest = None
        if not os.path.isfile(containerPathMeta):
            errmsg = f"FATAL ERROR: Docker saved image {containerFilenameMeta} is not in the staged working dir for {tag_name}"
            self.logger.error(errmsg)
            raise ContainerFactoryException(errmsg)

        try:
            with open(containerPathMeta, mode="r", encoding="utf-8") as mH:
                signaturesAndManifest = cast("DockerManifestMetadata", json.load(mH))
                imageSignature = signaturesAndManifest["image_signature"]
                manifestsImageSignature = signaturesAndManifest["manifests_signature"]
                manifests = signaturesAndManifest["manifests"]
        except Exception as e:
            errmsg = f"Problems extracting docker metadata at {containerPathMeta}"
            self.logger.exception(errmsg)
            raise ContainerFactoryException(errmsg)

        d_retval, d_out_v, d_err_v = self._inspect(dockerTag, matEnv)
        #        d_retval, d_out_v, d_err_v = self._images(matEnv)

        if d_retval not in (0, 125):
            errstr = """Could not inspect docker image {}. Retval {}
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
            ins_manifests = json.loads(d_out_v)
        except Exception as e:
            errmsg = f"FATAL ERROR: Docker inspect finished properly but it did not properly answered for {tag_name}"
            self.logger.exception(errmsg)
            raise ContainerFactoryException(errmsg) from e

        # Let's load then
        do_redeploy = manifestsImageSignature != self._gen_trimmed_manifests_signature(
            ins_manifests
        )
        if do_redeploy:
            self.logger.debug(f"Redeploying {dockerTag}")
            # Should we load the image?
            d_retval, d_out_v, d_err_v = self._load(containerPath, dockerTag, matEnv)

            if d_retval != 0:
                errstr = """Could not load docker image {}. Retval {}
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
                self.logger.error(errstr)
                raise ContainerEngineException(errstr)

        return do_redeploy
