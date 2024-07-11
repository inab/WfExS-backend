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

from typing import (
    cast,
    TYPE_CHECKING,
)

if TYPE_CHECKING:
    from typing import (
        Sequence,
    )

    from wfexs_backend.common import (
        RelPath,
        URIType,
    )


def simpleTestContainerFileName(imageUrl: "URIType") -> "Sequence[RelPath]":
    """
    This method was borrowed from
    https://github.com/nextflow-io/nextflow/blob/539a22b68c114c94eaf4a88ea8d26b7bfe2d0c39/modules/nextflow/src/main/groovy/nextflow/container/SingularityCache.groovy#L80
    and translated to Python
    """
    p = imageUrl.find("://")
    name = imageUrl[p + 3 :] if p != -1 else imageUrl
    extension = ".img"
    if ".sif:" in name:
        extension = ".sif"
        name = name.replace(".sif:", "-")
    elif name.endswith(".sif"):
        extension = ".sif"
        name = name[:-4]

    name = name.replace(":", "-").replace("/", "-")

    return [cast("RelPath", name + extension)]
