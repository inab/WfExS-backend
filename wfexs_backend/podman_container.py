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
    DEFAULT_PODMAN_CMD,
    Container,
    ContainerType,
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
from .utils.digests import ComputeDigestFromFile, ComputeDigestFromObject

DOCKER_PROTO = "docker://"


class PodmanContainerFactory(AbstractDockerContainerFactory):
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
        self.runtime_cmd = tools.get("podmanCommand", DEFAULT_PODMAN_CMD)

        self._environment.update(
            {
                "XDG_DATA_HOME": os.path.join(self.stagedContainersDir, ".podman"),
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

    def _images(self, matEnv: "Mapping[str, str]") -> "Tuple[ExitVal, str, str]":
        with tempfile.NamedTemporaryFile() as d_out, tempfile.NamedTemporaryFile() as d_err:
            self.logger.debug("querying available podman containers")
            d_retval = subprocess.Popen(
                [self.runtime_cmd, "images"],
                env=matEnv,
                stdout=d_out,
                stderr=d_err,
            ).wait()

            self.logger.debug(f"podman images retval: {d_retval}")

            with open(d_out.name, mode="rb") as c_stF:
                d_out_v = c_stF.read().decode("utf-8", errors="continue")
            with open(d_err.name, mode="rb") as c_stF:
                d_err_v = c_stF.read().decode("utf-8", errors="continue")

            self.logger.debug(f"podman inspect stdout: {d_out_v}")

            self.logger.debug(f"podman inspect stderr: {d_err_v}")

            return cast("ExitVal", d_retval), d_out_v, d_err_v

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

    def _load(
        self,
        archivefile: "AbsPath",
        dockerTag: "str",
        matEnv: "Mapping[str, str]",
    ) -> "Tuple[ExitVal, str, str]":
        with lzma.open(
            archivefile, mode="rb"
        ) as d_in, tempfile.NamedTemporaryFile() as d_out, tempfile.NamedTemporaryFile() as d_err:
            self.logger.debug(f"loading podman container {dockerTag}")
            with subprocess.Popen(
                [self.runtime_cmd, "load"],
                env=matEnv,
                stdin=d_in,
                stdout=d_out,
                stderr=d_err,
            ) as sp:
                d_retval = sp.wait()

            self.logger.debug(f"podman load {dockerTag} retval: {d_retval}")

            with open(d_out.name, "r") as c_stF:
                d_out_v = c_stF.read()

            self.logger.debug(f"podman load stdout: {d_out_v}")

            with open(d_err.name, "r") as c_stF:
                d_err_v = c_stF.read()

            self.logger.debug(f"podman load stderr: {d_err_v}")

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
                    shutil.copyfileobj(sp.stdout, d_out, length=1024 * 1024)
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
        if tag_name.startswith(DOCKER_PROTO):
            dockerTag = tag_name[len(DOCKER_PROTO) :]
            podmanPullTag = tag_name
        else:
            dockerTag = tag_name
            podmanPullTag = DOCKER_PROTO + tag_name

        # Should we enrich the tag with the registry?
        if isinstance(tag.registries, dict) and (
            (ContainerType.Docker in tag.registries)
            or (ContainerType.Podman in tag.registries)
        ):
            if ContainerType.Podman in tag.registries:
                registry = tag.registries[ContainerType.Podman]
            else:
                registry = tag.registries[ContainerType.Docker]

            # Bare case
            if "/" not in dockerTag:
                dockerTag = f"{registry}/library/{dockerTag}"
                podmanPullTag = DOCKER_PROTO + dockerTag
            elif dockerTag.find("/") == dockerTag.rfind("/"):
                dockerTag = f"{registry}/{dockerTag}"
                podmanPullTag = DOCKER_PROTO + dockerTag
            # Last case, it already has a registry declared

        self.logger.info(f"downloading podman container: {tag_name} => {podmanPullTag}")
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
                    imageSignature = signaturesAndManifest["image_signature"]
                    manifestsImageSignature = signaturesAndManifest[
                        "manifests_signature"
                    ]
                    manifests = signaturesAndManifest["manifests"]

                    # Check the status of the gathered manifests
                    trusted_copy = manifestsImageSignature == ComputeDigestFromObject(
                        manifests
                    )
            except Exception as e:
                self.logger.exception(
                    f"Problems extracting podman metadata at {localContainerPathMeta}"
                )
                trusted_copy = False

            # Let's check metadata coherence
            assert imageSignature is not None
            assert manifestsImageSignature is not None
            assert manifests is not None

            if trusted_copy:
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
                    f"Banned remove podman containers in offline mode from {tag_name}"
                )

            if os.path.exists(localContainerPathMeta) or os.path.exists(
                localContainerPath
            ):
                self.logger.warning(
                    f"Unable to trust Podman container {dockerTag} => {podmanPullTag} . Discarding cached contents"
                )
                import sys

                sys.exit(1)
                real_unlink_if_exists(localContainerPathMeta)
                real_unlink_if_exists(localContainerPath)

            # Blindly remove
            _, _, _ = self._rmi(dockerTag, matEnv)

            # And now, let's materialize the new world
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
                manifests = cast("Sequence[Mapping[str, Any]]", json.loads(d_out_v))
                manifest = manifests[0]
            except Exception as e:
                raise ContainerFactoryException(
                    f"FATAL ERROR: Podman finished properly but it did not properly materialize {tag_name}: {e}"
                )

            self.logger.info(
                "saving podman container (for reproducibility matters): {} => {}".format(
                    tag_name, localContainerPath
                )
            )

            # Let's materialize the container image for preservation
            manifestsImageSignature = ComputeDigestFromObject(manifests)
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

        # Should we load the image?
        d_retval, d_out_v, d_err_v = self._inspect(dockerTag, matEnv)
        #        d_retval, d_out_v, d_err_v = self._images(matEnv)

        if d_retval not in (0, 125):
            errstr = """Could not inspect podman image {}. Retval {}
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
            ins_manifests = json.loads(d_out_v)
        except Exception as e:
            raise ContainerFactoryException(
                f"FATAL ERROR: Podman inspect finished properly but it did not properly answered for {tag_name}: {e}"
            )

        # Let's load then
        if manifestsImageSignature != ComputeDigestFromObject(ins_manifests):
            # Should we load the image?
            d_retval, d_out_v, d_err_v = self._load(containerPath, dockerTag, matEnv)

            if d_retval != 0:
                errstr = """Could not load podman image {}. Retval {}
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

        # Then, compute the signature
        fingerprint = None
        if len(manifest["RepoDigests"]) > 0:
            fingerprint = manifest["RepoDigests"][0]

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
            signature=manifest["Id"],
            fingerprint=fingerprint,
            architecture=architecture,
            operatingSystem=manifest.get("Os"),
            type=self.containerType,
            localPath=containerPath,
            registries=tag.registries,
        )
