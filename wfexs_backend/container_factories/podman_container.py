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

import json
import os
from typing import (
    cast,
    TYPE_CHECKING,
)

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

    from ..common import (
        AbsPath,
        AnyPath,
        ContainerTaggedName,
        Fingerprint,
        RelPath,
        URIType,
    )

    from . import (
        ContainerFileNamingMethod,
        ContainerLocalConfig,
        ContainerOperatingSystem,
        DockerManifestMetadata,
        ProcessorArchitecture,
    )

from ..common import (
    ContainerType,
    DEFAULT_PODMAN_CMD,
    META_JSON_POSTFIX,
)
from . import (
    Container,
    ContainerEngineException,
    ContainerFactoryException,
    DOCKER_URI_PREFIX,
)
from .abstract_docker_container import (
    AbstractDockerContainerFactory,
    DOCKER_PROTO,
)
from ..utils.contents import (
    link_or_copy,
    real_unlink_if_exists,
)
from ..utils.digests import ComputeDigestFromFile


class PodmanContainerFactory(AbstractDockerContainerFactory):
    TRIMMABLE_MANIFEST_KEYS: "Final[Sequence[str]]" = [
        "Digest",
        "RepoDigests",
        "Size",
        "VirtualSize",
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

    @classmethod
    def variant_name(self) -> "str":
        return "podman"

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
        containerFilenameMeta = containerFilename + META_JSON_POSTFIX
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
                    f"Problems extracting podman metadata at {localContainerPathMeta}"
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
                    if fsImageSignatureMeta.endswith(META_JSON_POSTFIX):
                        fsImageSignatureMeta = fsImageSignatureMeta[
                            : -len(META_JSON_POSTFIX)
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
                            fsImageSignatureMeta + META_JSON_POSTFIX,
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
                    f"Banned remove podman containers in offline mode from {tag_name}"
                )

            if os.path.exists(localContainerPathMeta) or os.path.exists(
                localContainerPath
            ):
                self.logger.warning(
                    f"Unable to trust Podman container {dockerTag} => {podmanPullTag} . Discarding cached contents"
                )
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
                image_id = cast("Fingerprint", manifest["Id"])
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
            canonicalContainerPathMeta = canonicalContainerPath + META_JSON_POSTFIX
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

        # Then, compute the fingerprint based on remote repo's information
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
            signature=image_id,
            fingerprint=fingerprint,
            architecture=architecture,
            operatingSystem=manifest.get("Os"),
            type=self.containerType,
            localPath=containerPath,
            registries=tag.registries,
            metadataLocalPath=containerPathMeta,
            source_type=tag.type,
            image_signature=imageSignature,
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
        containerFilenameMeta = containerFilename + META_JSON_POSTFIX

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
            errmsg = f"FATAL ERROR: Podman saved image {containerFilenameMeta} is not in the staged working dir for {tag_name}"
            self.logger.error(errmsg)
            raise ContainerFactoryException(errmsg)

        try:
            with open(containerPathMeta, mode="r", encoding="utf-8") as mH:
                signaturesAndManifest = cast("DockerManifestMetadata", json.load(mH))
                imageSignature = signaturesAndManifest["image_signature"]
                manifestsImageSignature = signaturesAndManifest["manifests_signature"]
                manifests = signaturesAndManifest["manifests"]
        except Exception as e:
            errmsg = f"Problems extracting podman metadata at {containerPathMeta}"
            self.logger.exception(errmsg)
            raise ContainerFactoryException(errmsg)

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
                dockerTag, d_retval, d_out_v, d_err_v
            )
            raise ContainerEngineException(errstr)

        # Parsing the output from podman inspect
        try:
            ins_manifests = json.loads(d_out_v)
        except Exception as e:
            errmsg = f"FATAL ERROR: Podman inspect finished properly but it did not properly answered for {tag_name}"
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
                errstr = """Could not load podman image {}. Retval {}
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
