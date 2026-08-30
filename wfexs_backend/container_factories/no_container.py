#!/usr/bin/env python
# -*- coding: utf-8 -*-

# SPDX-License-Identifier: Apache-2.0
# Copyright 2020-2026 Barcelona Supercomputing Center (BSC), Spain
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

from typing import (
    cast,
    TYPE_CHECKING,
)

if TYPE_CHECKING:
    import pathlib
    from typing import (
        FrozenSet,
        Optional,
        Set,
        Tuple,
        Union,
    )

    from typing_extensions import (
        Final,
    )

    from ..common import (
        ContainerTaggedName,
    )

    from . import (
        ContainerEngineVersionStr,
    )

from . import (
    Container,
    ContainerFactory,
)

from .. import common


class NoContainerFactory(ContainerFactory):
    """
    The 'no container approach', for development and local installed software
    """

    AcceptedContainerTypes: "Final[FrozenSet[common.ContainerType]]" = frozenset(
        [common.ContainerType.NoContainer]
    )

    @classmethod
    def ContainerType(cls) -> "common.ContainerType":
        return common.ContainerType.NoContainer

    @classmethod
    def AcceptsContainerType(
        cls,
        container_type: "Union[common.ContainerType, Set[common.ContainerType], FrozenSet[common.ContainerType]]",
    ) -> "bool":
        return not cls.AcceptedContainerTypes.isdisjoint(
            container_type
            if isinstance(container_type, (set, frozenset))
            else (container_type,)
        )

    def engine_version(self) -> "ContainerEngineVersionStr":
        """No container engine, empty version"""
        return cast("ContainerEngineVersionStr", "")

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
        return None

    def deploySingleContainer(
        self,
        container: "ContainerTaggedName",
        containers_dir: "Optional[pathlib.Path]" = None,
        force: "bool" = False,
    ) -> "Tuple[Container, bool]":
        """
        This is a no-op
        """
        assert isinstance(container, Container)

        return container, False

    def generateCanonicalTag(self, container: "ContainerTaggedName") -> "str":
        """
        This is a no-op
        """
        return container.origTaggedName
