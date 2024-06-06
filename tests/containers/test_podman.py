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

import pytest
import logging

from typing import (
    cast,
    TYPE_CHECKING,
)

if TYPE_CHECKING:
    from wfexs_backend.common import (
        Fingerprint,
        RelPath,
        URIType,
    )

    from wfexs_backend.container_factories import (
        ContainerOperatingSystem,
        ProcessorArchitecture,
    )

from wfexs_backend.common import (
    ContainerTaggedName,
    ContainerType,
)

from wfexs_backend.container_factories import (
    Container,
    ContainerEngineException,
    ContainerFactoryException,
)

from wfexs_backend.container_factories.podman_container import (
    PodmanContainerFactory,
)

from tests.containers.util import simpleTestContainerFileName

# Enable logging
logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)


def test_podman_basic(tmpdir) -> "None":  # type: ignore[no-untyped-def]
    """
    Check podman container factory instantiation
    """
    temppath = tmpdir.mkdir("TEMP")
    cachepath = tmpdir.mkdir("CACHE")
    stagedpath = tmpdir.mkdir("STAGED")
    pcf = PodmanContainerFactory(
        simpleFileNameMethod=simpleTestContainerFileName,
        containersCacheDir=cachepath.strpath,
        stagedContainersDir=stagedpath.strpath,
        tempDir=temppath.strpath,
    )


TAGGED_TESTBED = pytest.mark.parametrize(
    ["cont_tagged"],
    [
        (
            ContainerTaggedName(
                origTaggedName="busybox:stable",
                type=ContainerType.Docker,
            ),
        ),
        (
            ContainerTaggedName(
                origTaggedName="quay/busybox:latest",
                type=ContainerType.Docker,
                registries={
                    ContainerType.Docker: "quay.io",
                },
            ),
        ),
        (
            Container(
                origTaggedName="busybox:stable",
                type=ContainerType.Podman,
                taggedName=cast("URIType", "busybox:stable"),
                operatingSystem=cast("ContainerOperatingSystem", "linux"),
                architecture=cast("ProcessorArchitecture", "amd64"),
                signature=cast(
                    "Fingerprint", "sha256=sBYlsI2WjxCwGm9juxawq1ryW3OpivFxFUWxEvQ9vBU="
                ),
                fingerprint=cast(
                    "Fingerprint",
                    "docker.io/library/busybox@sha256:50aa4698fa6262977cff89181b2664b99d8a56dbca847bf62f2ef04854597cf8",
                ),
                source_type=ContainerType.Docker,
                image_signature=cast(
                    "Fingerprint", "sha256=sBYlsI2WjxCwGm9juxawq1ryW3OpivFxFUWxEvQ9vBU="
                ),
            ),
        ),
        (
            Container(
                origTaggedName="quay/busybox:latest",
                type=ContainerType.Podman,
                registries={
                    ContainerType.Docker: "quay.io",
                },
                taggedName=cast("URIType", "quay.io/quay/busybox:latest"),
                operatingSystem=cast("ContainerOperatingSystem", "linux"),
                architecture=cast("ProcessorArchitecture", "amd64"),
                signature=cast(
                    "Fingerprint", "sha256=WTkWLbkE2f3HvwpLcWIOMaW85YxuZBCPXSffBez6hKY="
                ),
                fingerprint=cast(
                    "Fingerprint",
                    "quay.io/quay/busybox@sha256:92f3298bf80a1ba949140d77987f5de081f010337880cd771f7e7fc928f8c74d",
                ),
                source_type=ContainerType.Docker,
                image_signature=cast(
                    "Fingerprint", "sha256=WTkWLbkE2f3HvwpLcWIOMaW85YxuZBCPXSffBez6hKY="
                ),
            ),
        ),
    ],
)


@TAGGED_TESTBED
def test_podman_container_tagged_name(cont_tagged: "ContainerTaggedName", tmpdir) -> "None":  # type: ignore[no-untyped-def]
    """
    Check podman container factory instantiation
    """
    temppath = tmpdir.mkdir("TEMP")
    cachepath = tmpdir.mkdir("CACHE")
    stagedpath = tmpdir.mkdir("STAGED")
    pcf = PodmanContainerFactory(
        simpleFileNameMethod=simpleTestContainerFileName,
        containersCacheDir=cachepath.strpath,
        stagedContainersDir=stagedpath.strpath,
        tempDir=temppath.strpath,
    )
    containers = pcf.materializeContainers(tagList=[cont_tagged])
    if isinstance(cont_tagged, Container):
        for attr in (
            "origTaggedName",
            "type",
            "registries",
            "taggedName",
            "architecture",
            "operatingSystem",
            "fingerprint",
            "source_type",
        ):
            assert getattr(cont_tagged, attr) == getattr(
                containers[0], attr
            ), f"Expected and obtainer container '{attr}' do not match: {getattr(cont_tagged, attr)} vs {getattr(containers[0], attr)}"


@TAGGED_TESTBED
def test_podman_container_tagged_name_fail(cont_tagged: "ContainerTaggedName", tmpdir) -> "None":  # type: ignore[no-untyped-def]
    """
    Check podman container factory instantiation
    """
    temppath = tmpdir.mkdir("TEMP")
    cachepath = tmpdir.mkdir("CACHE")
    stagedpath = tmpdir.mkdir("STAGED")
    pcf = PodmanContainerFactory(
        simpleFileNameMethod=simpleTestContainerFileName,
        containersCacheDir=cachepath.strpath,
        stagedContainersDir=stagedpath.strpath,
        tempDir=temppath.strpath,
    )
    with pytest.raises(ContainerFactoryException):
        containers = pcf.materializeContainers(tagList=[cont_tagged], offline=True)
        logger.info(containers)


@TAGGED_TESTBED
def test_podman_container_tagged_name_cached(cont_tagged: "ContainerTaggedName", tmpdir) -> "None":  # type: ignore[no-untyped-def]
    """
    Check podman container factory instantiation
    """
    temppath = tmpdir.mkdir("TEMP")
    cachepath = tmpdir.mkdir("CACHE")
    stagedpath = tmpdir.mkdir("STAGED")
    pcf = PodmanContainerFactory(
        simpleFileNameMethod=simpleTestContainerFileName,
        containersCacheDir=cachepath.strpath,
        stagedContainersDir=stagedpath.strpath,
        tempDir=temppath.strpath,
    )
    containers = pcf.materializeContainers(tagList=[cont_tagged])
    containers2 = pcf.materializeContainers(tagList=[cont_tagged], offline=True)
    for container, container2 in zip(containers, containers2):
        for attr in (
            "origTaggedName",
            "type",
            "registries",
            "taggedName",
            "architecture",
            "operatingSystem",
            "fingerprint",
            "source_type",
        ):
            assert getattr(container, attr) == getattr(
                container2, attr
            ), f"Expected and obtainer container '{attr}' do not match: {getattr(container, attr)} vs {getattr(container2, attr)}"
