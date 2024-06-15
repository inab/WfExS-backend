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
import os.path
import pathlib
import re
import shutil
import subprocess
import tempfile
from typing import (
    cast,
    NamedTuple,
    TYPE_CHECKING,
)
from urllib import parse
import uuid

from ..common import (
    META_JSON_POSTFIX,
    DEFAULT_SINGULARITY_CMD,
)

from .. import common

if TYPE_CHECKING:
    from typing import (
        Any,
        Mapping,
        MutableSequence,
        Optional,
        Sequence,
        Set,
        Tuple,
        Union,
    )
    from typing_extensions import (
        Final,
        NotRequired,
        Required,
        TypedDict,
    )

    from ..common import (
        AbsPath,
        AnyPath,
        ContainerTaggedName,
        ExitVal,
        Fingerprint,
        RelPath,
        URIType,
    )

    from . import (
        AbstractImageManifestMetadata,
        ContainerFileNamingMethod,
        ContainerLocalConfig,
        ProcessorArchitecture,
    )

    class SingularityManifest(AbstractImageManifestMetadata):
        registryServer: Required[str]
        registryType: Required[str]
        repo: Required[str]
        alias: Required[Optional[str]]
        dcd: NotRequired[str]
        manifest: NotRequired[Mapping[str, Any]]


from . import (
    Container,
    ContainerFactory,
    ContainerEngineException,
    ContainerFactoryException,
    ContainerNotFoundException,
    DEFAULT_DOCKER_REGISTRY,
    DOCKER_SCHEME,
)

from ..utils.contents import link_or_copy
from ..utils.docker import DockerHelper


class FailedContainerTag(NamedTuple):
    tag: "str"
    sing_tag: "str"


class SingularityContainerFactory(ContainerFactory):
    ACCEPTED_SING_SCHEMES: "Final[Set[str]]" = {
        "library",
        DOCKER_SCHEME,
        "shub",
        "oras",
        "http",
        "https",
        "ftp",
    }

    ACCEPTED_CONTAINER_TYPES = set(
        (
            common.ContainerType.Podman,
            common.ContainerType.UDocker,
            common.ContainerType.Docker,
            common.ContainerType.Singularity,
        )
    )

    def __init__(
        self,
        simpleFileNameMethod: "ContainerFileNamingMethod",
        containersCacheDir: "Optional[pathlib.Path]" = None,
        stagedContainersDir: "Optional[pathlib.Path]" = None,
        tools_config: "Optional[ContainerLocalConfig]" = None,
        engine_name: "str" = "unset",
        tempDir: "Optional[pathlib.Path]" = None,
    ):
        super().__init__(
            simpleFileNameMethod=simpleFileNameMethod,
            containersCacheDir=containersCacheDir,
            stagedContainersDir=stagedContainersDir,
            tools_config=tools_config,
            engine_name=engine_name,
            tempDir=tempDir,
        )
        self.runtime_cmd = self.tools_config.get(
            "singularityCommand", DEFAULT_SINGULARITY_CMD
        )

        # This is needed due a bug in singularity 3.6, where
        # singularity pull --disable-cache does not create a container
        singularityCacheDir = self.stagedContainersDir / ".singularity"
        singularityCacheDir.mkdir(parents=True, exist_ok=True)

        self._environment.update(
            {
                "APPTAINER_TMPDIR": self.tempDir.as_posix(),
                "APPTAINER_CACHEDIR": singularityCacheDir.as_posix(),
                "SINGULARITY_TMPDIR": self.tempDir.as_posix(),
                "SINGULARITY_CACHEDIR": singularityCacheDir.as_posix(),
            }
        )

        # Now, detect userns feature using some ideas from
        # https://github.com/hpcng/singularity/issues/1445#issuecomment-381588444
        userns_supported = False
        if self.supportsFeature("host_userns"):
            matEnv = dict(os.environ)
            matEnv.update(self.environment)
            with tempfile.NamedTemporaryFile() as s_out, tempfile.NamedTemporaryFile() as s_err:
                s_retval = subprocess.Popen(
                    [self.runtime_cmd, "exec", "--userns", "/etc", "true"],
                    env=matEnv,
                    stdout=s_out,
                    stderr=s_err,
                ).wait()

                # The command always fails.
                # We only need to find 'Failed to create user namespace'
                # in order to discard this feature
                with open(s_err.name, "r") as c_stF:
                    s_err_v = c_stF.read()
                if "Failed to create user namespace" not in s_err_v:
                    userns_supported = True
                    self._features.add("userns")

        self.logger.debug(f"Singularity supports userns: {userns_supported}")
        if not userns_supported:
            self.logger.warning(
                "Singularity does not support userns (needed for encrypted working directories)"
            )

    @classmethod
    def ContainerType(cls) -> "common.ContainerType":
        return common.ContainerType.Singularity

    @classmethod
    def AcceptsContainerType(
        cls, container_type: "Union[common.ContainerType, Set[common.ContainerType]]"
    ) -> "bool":
        return not cls.ACCEPTED_CONTAINER_TYPES.isdisjoint(
            container_type if isinstance(container_type, set) else (container_type,)
        )

    def _getContainerArchitecture(
        self,
        container_filename: "Union[AnyPath, os.PathLike[str]]",
        matEnv: "Mapping[str, str]" = {},
    ) -> "Optional[ProcessorArchitecture]":
        if len(matEnv) == 0:
            matEnv = dict(os.environ)
            matEnv.update(self.environment)

        with tempfile.NamedTemporaryFile() as s_out, tempfile.NamedTemporaryFile() as s_err:
            self.logger.debug(
                f"Checking {container_filename} looks like a singularity container"
            )
            s_retval = subprocess.Popen(
                [self.runtime_cmd, "inspect", container_filename],
                env=matEnv,
                stdout=s_out,
                stderr=s_err,
            ).wait()
            self.logger.debug(f"singularity inspect retval: {s_retval}")

            if s_retval != 0:
                with open(s_out.name, "r") as c_stF:
                    s_out_v = c_stF.read()
                with open(s_err.name, "r") as c_stF:
                    s_err_v = c_stF.read()
                errstr = f"""\
Could not inspect singularity image {container_filename}. Retval {s_retval}
======
STDOUT
======
{s_out_v}

======
STDERR
======
{s_err_v}"""

                self.logger.error(errstr)
                raise ContainerEngineException(errstr)

            self.logger.debug(f"Describing container {container_filename}")
            # Singularity command line borrowed from
            # https://github.com/nextflow-io/nextflow/blob/539a22b68c114c94eaf4a88ea8d26b7bfe2d0c39/modules/nextflow/src/main/groovy/nextflow/container/SingularityCache.groovy#L221
            s_retval = subprocess.Popen(
                [self.runtime_cmd, "sif", "list", container_filename],
                env=matEnv,
                stdout=s_out,
                stderr=s_err,
            ).wait()

            self.logger.debug(f"singularity sif list retval: {s_retval}")

            with open(s_out.name, "r") as c_stF:
                s_out_v = c_stF.read()
            with open(s_err.name, "r") as c_stF:
                s_err_v = c_stF.read()

            self.logger.debug(f"singularity sif list stdout: {s_out_v}")

            self.logger.debug(f"singularity sif list stderr: {s_err_v}")

            if s_retval != 0:
                errstr = f"""\
Could not describe singularity image {container_filename}. Retval {s_retval}
======
STDOUT
======
{s_out_v}

======
STDERR
======
{s_err_v}"""

                self.logger.warning(errstr)
                self.logger.warning(
                    f"Most probably, image {container_filename} was built using singularity older than 3.0.0"
                )
                self.logger.warning(
                    "So, we cannot learn the architecture of the image using singularity"
                )
                return None

            # The default for images translated from docker are usually these
            data_bundle_id = "4"
            type_column_id = 3
            column_id = 0
            parse_header = True
            with open(s_out.name, mode="r") as c_stF:
                for line in c_stF:
                    if line.startswith("-"):
                        continue

                    cells = re.split(r"\s*\|\s*", line.strip())
                    if parse_header:
                        if cells[0].startswith("ID"):
                            for i_cell, cell_name in enumerate(cells):
                                if cell_name.startswith("TYPE"):
                                    type_column_id = i_cell
                                elif cell_name.startswith("ID"):
                                    column_id = i_cell
                            parse_header = False
                    elif cells[type_column_id].startswith("FS"):
                        data_bundle_id = cells[column_id]
                        break

        # Now, the details
        architecture = None
        with tempfile.NamedTemporaryFile() as s_out, tempfile.NamedTemporaryFile() as s_err:
            self.logger.debug(
                f"Learning container architecture from {container_filename}"
            )
            # Singularity command line borrowed from
            # https://github.com/nextflow-io/nextflow/blob/539a22b68c114c94eaf4a88ea8d26b7bfe2d0c39/modules/nextflow/src/main/groovy/nextflow/container/SingularityCache.groovy#L221
            s_retval = subprocess.Popen(
                [self.runtime_cmd, "sif", "info", data_bundle_id, container_filename],
                env=matEnv,
                stdout=s_out,
                stderr=s_err,
            ).wait()

            self.logger.debug(f"singularity sif info retval: {s_retval}")

            with open(s_out.name, "r") as c_stF:
                s_out_v = c_stF.read()
            with open(s_err.name, "r") as c_stF:
                s_err_v = c_stF.read()

            self.logger.debug(f"singularity sif info stdout: {s_out_v}")

            self.logger.debug(f"singularity sif info stderr: {s_err_v}")

            if s_retval != 0:
                errstr = f"""\
Could not describe bundle {data_bundle_id} from singularity image {container_filename}. Retval {s_retval}
======
STDOUT
======
{s_out_v}

======
STDERR
======
{s_err_v}"""
                raise ContainerEngineException(errstr)

            # Learning the architecture
            with open(s_out.name, mode="r") as c_stF:
                for line in c_stF:
                    key, value = re.split(r":\s*", line.strip(), maxsplit=1)
                    if key == "Architecture":
                        architecture = value
                        break

        return (
            cast("ProcessorArchitecture", architecture)
            if architecture is not None
            else None
        )

    def materializeSingleContainer(
        self,
        tag: "ContainerTaggedName",
        containers_dir: "Optional[pathlib.Path]" = None,
        offline: "bool" = False,
        force: "bool" = False,
    ) -> "Optional[Container]":
        """
        This is a no-op
        """
        the_cont = self._materializeSingleContainerSing(
            tag,
            containers_dir=containers_dir,
            offline=offline,
            force=force,
        )

        return the_cont if isinstance(the_cont, Container) else None

    def _genSingTag(
        self,
        tag: "ContainerTaggedName",
    ) -> "Tuple[str, parse.ParseResult, str, bool]":
        # It is not an absolute URL, we are prepending the docker://
        tag_name = tag.origTaggedName
        parsedTag = parse.urlparse(tag_name)
        if parsedTag.scheme in self.ACCEPTED_SING_SCHEMES:
            singTag = tag_name
            isDocker = parsedTag.scheme == DOCKER_SCHEME
        else:
            if parsedTag.scheme == "":
                singTag = "docker://" + tag_name
                parsedTag = parse.urlparse(singTag)
            else:
                parsedTag = parsedTag._replace(
                    scheme=DOCKER_SCHEME,
                    netloc=parsedTag.scheme + ":" + parsedTag.path,
                    path="",
                )
                singTag = parse.urlunparse(parsedTag)
            # Assuming it is docker
            isDocker = True

        # Should we enrich the tag with the registry?
        if (
            isDocker
            and isinstance(tag.registries, dict)
            and (common.ContainerType.Docker in tag.registries)
        ):
            registry = tag.registries[common.ContainerType.Docker]
            # Bare case
            if len(parsedTag.path) <= 1:
                singTag = f"docker://{registry}/library/{parsedTag.netloc}"
                parsedTag = parse.urlparse(singTag)
            elif "/" not in parsedTag.path[1:]:
                singTag = f"docker://{registry}/{parsedTag.netloc}{parsedTag.path}"
                parsedTag = parse.urlparse(singTag)
            # Last case, it already has a registry declared
        # It is not an absolute URL, we are prepending the docker://
        tag_name = tag.origTaggedName
        parsedTag = parse.urlparse(tag_name)
        if parsedTag.scheme in self.ACCEPTED_SING_SCHEMES:
            singTag = tag_name
            isDocker = parsedTag.scheme == DOCKER_SCHEME
        else:
            if parsedTag.scheme == "":
                singTag = "docker://" + tag_name
                parsedTag = parse.urlparse(singTag)
            else:
                parsedTag = parsedTag._replace(
                    scheme=DOCKER_SCHEME,
                    netloc=parsedTag.scheme + ":" + parsedTag.path,
                    path="",
                )
                singTag = parse.urlunparse(parsedTag)
            # Assuming it is docker
            isDocker = True

        # Should we enrich the tag with the registry?
        if (
            isDocker
            and isinstance(tag.registries, dict)
            and (common.ContainerType.Docker in tag.registries)
        ):
            registry = tag.registries[common.ContainerType.Docker]
            # Bare case
            if len(parsedTag.path) <= 1:
                singTag = f"docker://{registry}/library/{parsedTag.netloc}"
                parsedTag = parse.urlparse(singTag)
            elif "/" not in parsedTag.path[1:]:
                singTag = f"docker://{registry}/{parsedTag.netloc}{parsedTag.path}"
                parsedTag = parse.urlparse(singTag)
            # Last case, it already has a registry declared

        # Now, the singPullTag
        if isDocker and isinstance(tag, Container) and tag.fingerprint is not None:
            shapos = singTag.rfind("@sha256:")
            atpos = tag.fingerprint.rfind("@")
            if shapos != -1 or atpos <= 0:
                # The sha256 tag takes precedence over the recorded signature
                singPullTag = singTag
            else:
                partial_fingerprint = tag.fingerprint[atpos:]
                colonpos = singTag.rfind(":")
                slashpos = singTag.rfind("/")
                if colonpos > slashpos:
                    singPullTag = singTag[:colonpos]
                else:
                    singPullTag = singTag

                singPullTag += partial_fingerprint
        else:
            singPullTag = singTag

        return singTag, parsedTag, singPullTag, isDocker

    def _pull(
        self,
        singTag: "str",
        tmpContainerPath: "Union[str, os.PathLike[str]]",
        matEnv: "Mapping[str, str]",
    ) -> "Tuple[ExitVal, str, str]":
        with tempfile.NamedTemporaryFile() as s_out, tempfile.NamedTemporaryFile() as s_err:
            self.logger.debug(
                f"downloading temporary container: {singTag} => {tmpContainerPath}"
            )
            # Singularity command line borrowed from
            # https://github.com/nextflow-io/nextflow/blob/539a22b68c114c94eaf4a88ea8d26b7bfe2d0c39/modules/nextflow/src/main/groovy/nextflow/container/SingularityCache.groovy#L221
            s_retval = subprocess.Popen(
                [self.runtime_cmd, "pull", "--name", tmpContainerPath, singTag],
                env=matEnv,
                stdout=s_out,
                stderr=s_err,
            ).wait()

            self.logger.debug(f"singularity pull retval: {s_retval}")

            with open(s_out.name, "r") as c_stF:
                s_out_v = c_stF.read()
            with open(s_err.name, "r") as c_stF:
                s_err_v = c_stF.read()

            self.logger.debug(f"singularity pull stdout: {s_out_v}")

            self.logger.debug(f"singularity pull stderr: {s_err_v}")

        return cast("ExitVal", s_retval), s_out_v, s_err_v

    def _materializeSingleContainerSing(
        self,
        tag: "ContainerTaggedName",
        matEnv: "Mapping[str, str]" = {},
        dhelp: "DockerHelper" = DockerHelper(),
        containers_dir: "Optional[pathlib.Path]" = None,
        offline: "bool" = False,
        force: "bool" = False,
    ) -> "Union[Container, FailedContainerTag]":
        if len(matEnv) == 0:
            matEnvNew = dict(os.environ)
            matEnvNew.update(self.environment)
            matEnv = matEnvNew

        tag_name = tag.origTaggedName
        singTag, parsedTag, singPullTag, isDocker = self._genSingTag(tag)

        fetch_metadata = True
        trusted_copy = False
        localContainerPath: "Optional[pathlib.Path]" = None
        localContainerPathMeta: "Optional[pathlib.Path]" = None
        imageSignature: "Optional[Fingerprint]" = None
        fingerprint: "Optional[Fingerprint]" = None
        if not force:
            (
                trusted_copy,
                localContainerPath,
                localContainerPathMeta,
                imageSignature,
            ) = self.cc_handler.query(tag)

            if trusted_copy:
                try:
                    with localContainerPathMeta.open(mode="r", encoding="utf8") as tcpm:
                        raw_metadata = json.load(tcpm)
                        if isinstance(raw_metadata, dict) and (
                            "registryServer" in raw_metadata
                        ):
                            metadata = cast("SingularityManifest", raw_metadata)
                            registryServer = metadata["registryServer"]
                            registryType = metadata.get("registryType", "docker")
                            repo = metadata["repo"]
                            alias = metadata.get("alias")
                            partial_fingerprint = metadata.get("dcd")
                            imageSignature_in_metadata = metadata.get("image_signature")
                            manifest = metadata.get("manifest")
                            if partial_fingerprint is not None:
                                usableRegistryServer = (
                                    DEFAULT_DOCKER_REGISTRY
                                    if registryServer.endswith(
                                        "." + DEFAULT_DOCKER_REGISTRY
                                    )
                                    else registryServer
                                )
                                fingerprint = cast(
                                    # Maybe in the future registryServer + '/' + repo + "@" + partial_fingerprint
                                    "Fingerprint",
                                    usableRegistryServer
                                    + "/"
                                    + repo
                                    + "@"
                                    + partial_fingerprint,
                                )
                            else:
                                # TODO: is there a better alternative?
                                fingerprint = cast("Fingerprint", tag_name)

                            if imageSignature_in_metadata is not None:
                                # Do the signatures match?
                                fetch_metadata = (
                                    imageSignature != imageSignature_in_metadata
                                )
                        else:
                            registryServer = ""
                            registryType = None
                            repo = ""
                            alias = ""
                            partial_fingerprint = ""
                            imageSignature_in_metadata = None
                            manifest = None
                            fingerprint = cast("Fingerprint", tag_name)

                except Exception as e:
                    # Some problem happened parsing the existing metadata
                    self.logger.exception(
                        f"Error while reading or parsing {localContainerPathMeta}. Discarding it"
                    )

        self.logger.info(f"downloading singularity container: {tag_name}")

        # Now, time to fetch the container itself
        # (if it is needed)
        tmpContainerPath: "Optional[pathlib.Path]" = None
        if not trusted_copy:
            if offline:
                raise ContainerFactoryException(
                    f"Cannot download containers in offline mode from {tag_name}"
                )

            tmpContainerPath = self.cc_handler._genTmpContainerPath()
            s_retval, s_out_v, s_err_v = self._pull(
                singPullTag, tmpContainerPath, matEnv
            )

            # Reading the output and error for the report
            if s_retval == 0:
                if not tmpContainerPath.exists():
                    raise ContainerFactoryException(
                        "FATAL ERROR: Singularity finished properly but it did not materialize {} into {}".format(
                            tag_name, tmpContainerPath
                        )
                    )

                # This is needed for the metadata
                imageSignature = self.cc_handler._computeFingerprint(tmpContainerPath)
            else:
                errstr = f"""\
Could not materialize singularity image {singTag} ({singPullTag}). Retval {s_retval}
======
STDOUT
======
{s_out_v}

======
STDERR
======
{s_err_v}"""

                if tmpContainerPath.exists():
                    try:
                        tmpContainerPath.unlink()
                    except:
                        pass
                self.logger.error(errstr)

                return FailedContainerTag(
                    tag=tag_name,
                    sing_tag=singPullTag,
                )

        # At this point we should always have a image signature
        assert imageSignature is not None

        # When no metadata exists, we are bringing the metadata
        # to a temporary path
        tmpContainerPathMeta: "Optional[pathlib.Path]" = None
        if fetch_metadata:
            if offline:
                raise ContainerFactoryException(
                    f"Cannot download containers metadata in offline mode from {tag_name} to {localContainerPath}"
                )

            if tmpContainerPath is None:
                assert localContainerPath is not None
                tmpContainerPath = self.cc_handler._genTmpContainerPath()
                link_or_copy(localContainerPath, tmpContainerPath)
            tmpContainerPathMeta = tmpContainerPath.with_name(
                tmpContainerPath.name + META_JSON_POSTFIX
            )

            self.logger.debug(
                f"downloading temporary container metadata: {tag_name} => {tmpContainerPathMeta}"
            )

            tag_details = None
            # If it is a docker container, fetch the associated metadata
            if isDocker:
                tag_details = dhelp.query_tag(singTag)
                if tag_details is None:
                    self.logger.error(f"FALLA {singTag}")
                    return FailedContainerTag(tag=tag_name, sing_tag=singTag)
                if singTag != singPullTag:
                    tag_pull_details = dhelp.query_tag(singPullTag)
                    if tag_pull_details is None:
                        self.logger.error(f"CANALLA {singPullTag}")
                        return FailedContainerTag(tag=tag_name, sing_tag=singPullTag)
                else:
                    tag_pull_details = tag_details
            else:
                tag_pull_details = tag_details

            # Save the temporary metadata
            with tmpContainerPathMeta.open(mode="w", encoding="utf8") as tcpm:
                tmp_meta: "SingularityManifest"
                if tag_details is not None:
                    assert tag_pull_details is not None
                    tmp_meta = {
                        "image_signature": imageSignature,
                        "registryServer": tag_pull_details.registryServer,
                        "registryType": "docker",
                        "repo": tag_pull_details.repo,
                        "alias": tag_details.alias,
                        "dcd": tag_pull_details.partial_fingerprint,
                        "manifest": tag_pull_details.manifest,
                    }
                    usableRegistryServer = (
                        DEFAULT_DOCKER_REGISTRY
                        if tag_pull_details.registryServer.endswith(
                            "." + DEFAULT_DOCKER_REGISTRY
                        )
                        else tag_pull_details.registryServer
                    )
                    fingerprint = cast(
                        "Fingerprint",
                        usableRegistryServer
                        + "/"
                        + tag_pull_details.repo
                        + "@"
                        + tag_pull_details.partial_fingerprint,
                    )
                else:
                    # TODO: Which metadata could we add for other schemes?
                    tmp_meta = {
                        "image_signature": imageSignature,
                        "registryServer": parsedTag.netloc,
                        "registryType": parsedTag.scheme,
                        "repo": singTag,
                        "alias": None,
                    }
                    fingerprint = cast("Fingerprint", tag_name)
                json.dump(tmp_meta, tcpm)

        # Last, but not the least important
        # Hardlink or copy the container and its metadata
        if tmpContainerPath is not None and tmpContainerPathMeta is not None:
            self.cc_handler.update(
                tag,
                image_path=tmpContainerPath,
                image_metadata_path=tmpContainerPathMeta,
                do_move=True,
            )

        if containers_dir is None:
            containers_dir = pathlib.Path(self.stagedContainersDir)

        # Do not allow overwriting in offline mode
        transferred_image = self.cc_handler.transfer(
            tag, stagedContainersDir=containers_dir, force=force and not offline
        )
        assert transferred_image is not None, f"Unexpected cache miss for {tag}"
        containerPath, containerPathMeta = transferred_image

        return Container(
            origTaggedName=tag_name,
            taggedName=cast("URIType", singTag),
            signature=imageSignature,
            fingerprint=fingerprint,
            architecture=self._getContainerArchitecture(containerPath, matEnv),
            type=self.containerType,
            localPath=containerPath,
            registries=tag.registries,
            metadataLocalPath=containerPathMeta,
            source_type=tag.source_type if isinstance(tag, Container) else tag.type,
            image_signature=imageSignature,
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
        containersList: "MutableSequence[Container]" = []
        notFoundContainersList: "MutableSequence[FailedContainerTag]" = []

        if containers_dir is None:
            containers_dir = self.stagedContainersDir

        matEnv = dict(os.environ)
        matEnv.update(self.environment)
        dhelp = DockerHelper()

        for tag in tagList:
            # If we cannot materialize it we cannot accept it
            if not self.AcceptsContainer(tag):
                continue

            matched_container: "Union[Container, FailedContainerTag]"
            try:
                matched_container, was_redeployed = self.deploySingleContainer(
                    tag, containers_dir=containers_dir, force=force
                )
            except ContainerFactoryException as cfe:
                matched_container = self._materializeSingleContainerSing(
                    tag,
                    matEnv=matEnv,
                    dhelp=dhelp,
                    containers_dir=containers_dir,
                    offline=offline,
                    force=force,
                )

            if isinstance(matched_container, Container):
                if matched_container not in containersList:
                    containersList.append(matched_container)
            else:
                notFoundContainersList.append(matched_container)

        if len(notFoundContainersList) > 0:
            raise ContainerNotFoundException(
                "Could not fetch metadata for next tags because they were not found:\n\t"
                + "\n\t".join(
                    map(
                        lambda nfc: nfc.tag + " => " + nfc.sing_tag,
                        notFoundContainersList,
                    )
                )
            )

        return containersList

    def deploySingleContainer(
        self,
        container: "ContainerTaggedName",
        containers_dir: "Optional[pathlib.Path]" = None,
        force: "bool" = False,
    ) -> "Tuple[Container, bool]":
        """
        This is almost no-op, but it should check
        the integrity of the local images
        """
        if containers_dir is None:
            containers_dir = self.stagedContainersDir
        containerPath, containerPathMeta = self.cc_handler.genStagedContainersDirPaths(
            container, containers_dir
        )

        if not containerPath.is_file():
            errmsg = f"SIF saved image {containerPath.name} is not in the staged working dir for {container.origTaggedName}"
            self.logger.warning(errmsg)
            raise ContainerFactoryException(errmsg)

        if not containerPathMeta.is_file():
            errmsg = f"SIF saved image metadata {containerPathMeta.name} is not in the staged working dir for {container.origTaggedName}"
            self.logger.warning(errmsg)
            raise ContainerFactoryException(errmsg)

        try:
            with containerPathMeta.open(mode="r", encoding="utf-8") as mH:
                signaturesAndManifest = cast("SingularityManifest", json.load(mH))
                imageSignature_in_metadata = signaturesAndManifest["image_signature"]

                if isinstance(container, Container):
                    # Reuse the input container instance
                    rebuilt_container = container
                else:
                    singTag, parsedTag, singPullTag, isDocker = self._genSingTag(
                        container
                    )

                    partial_fingerprint = signaturesAndManifest.get("dcd")
                    repo = signaturesAndManifest["repo"]
                    if partial_fingerprint is not None:
                        registryServer = signaturesAndManifest["registryServer"]
                        usableRegistryServer = (
                            DEFAULT_DOCKER_REGISTRY
                            if registryServer.endswith("." + DEFAULT_DOCKER_REGISTRY)
                            else registryServer
                        )
                        fingerprint = cast(
                            # Maybe in the future registryServer + '/' + repo + "@" + partial_fingerprint
                            "Fingerprint",
                            usableRegistryServer
                            + "/"
                            + repo
                            + "@"
                            + partial_fingerprint,
                        )
                    else:
                        # TODO: is there a better alternative?
                        fingerprint = cast("Fingerprint", container.origTaggedName)

                    rebuilt_container = Container(
                        origTaggedName=container.origTaggedName,
                        taggedName=cast("URIType", singTag),
                        signature=imageSignature_in_metadata,
                        fingerprint=fingerprint,
                        architecture=self._getContainerArchitecture(containerPath),
                        type=self.containerType,
                        localPath=containerPath,
                        registries=container.registries,
                        metadataLocalPath=containerPathMeta,
                        source_type=container.source_type
                        if isinstance(container, Container)
                        else container.type,
                        image_signature=imageSignature_in_metadata,
                    )

        except Exception as e:
            errmsg = f"Problems extracting SIF metadata at {containerPathMeta} or {containerPath}"
            self.logger.exception(errmsg)
            raise ContainerFactoryException(errmsg)

        imageSignature = self.cc_handler._computeFingerprint(containerPath)

        if imageSignature != imageSignature_in_metadata:
            errmsg = f"Image signature recorded in {containerPathMeta.name} does not match image signature of {containerPath.name}"
            self.logger.exception(errmsg)
            raise ContainerFactoryException(errmsg)

        return rebuilt_container, False
