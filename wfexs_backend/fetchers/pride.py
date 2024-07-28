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

import io
import json

from typing import (
    cast,
    TYPE_CHECKING,
)

from ..common import (
    URIWithMetadata,
)

if TYPE_CHECKING:
    from typing import (
        Mapping,
        Optional,
    )

    from ..common import (
        AbsPath,
        PathLikePath,
        SecurityContextConfig,
        URIType,
    )

from urllib import parse

from . import (
    DocumentedProtocolFetcher,
    FetcherException,
    ProtocolFetcherReturn,
)
from .http import fetchClassicURL


PRIDE_PROJECT_SCHEME = "pride.project"
PRIDE_PROJECTS_REST = "https://www.ebi.ac.uk/pride/ws/archive/v2/projects/"


def fetchPRIDEProject(
    remote_file: "URIType",
    cachedFilename: "PathLikePath",
    secContext: "Optional[SecurityContextConfig]" = None,
) -> "ProtocolFetcherReturn":
    """
    Method to resolve contents from PRIDE project ids

    :param remote_file:
    :param cachedFilename: Destination filename for the fetched content
    :param secContext: The security context containing the credentials
    """

    # Dealing with an odd behaviour from urlparse
    for det in ("/", "?", "#"):
        if det in remote_file:
            parsedInputURL = parse.urlparse(remote_file)
            break
    else:
        parsedInputURL = parse.urlparse(remote_file + "#")
    parsed_steps = parsedInputURL.path.split("/")

    if len(parsed_steps) < 1 or parsed_steps[0] == "":
        raise FetcherException(
            f"{remote_file} is not a valid {PRIDE_PROJECT_SCHEME} CURIE. It should start with something like {PRIDE_PROJECT_SCHEME}:project_id"
        )

    projectId = parsed_steps[0]
    metadata_url = cast("URIType", parse.urljoin(PRIDE_PROJECTS_REST, projectId))

    gathered_meta = {"fetched": metadata_url}
    metadata_array = [URIWithMetadata(remote_file, gathered_meta)]
    metadata = None
    try:
        metaio = io.BytesIO()
        _, metametaio, _ = fetchClassicURL(metadata_url, metaio)
        metadata = json.loads(metaio.getvalue().decode("utf-8"))
        gathered_meta["payload"] = metadata
        metadata_array.extend(metametaio)
    except FetcherException as fe:
        raise FetcherException(
            "Error fetching PRIDE metadata for {} : {} {}".format(
                projectId, fe.code, fe.reason
            )
        ) from fe

    try:
        for addAtt in metadata["additionalAttributes"]:
            # https://github.com/PRIDE-Utilities/pride-ontology/blob/3b9cc024ea7d16481a04d9e583c0188205145db4/pride_cv.obo#L2620
            if (
                addAtt.get("@type") == "CvParam"
                and addAtt.get("accession") == "PRIDE:0000411"
            ):
                pride_project_url = addAtt.get("value")
                if pride_project_url is not None:
                    break
        else:
            pride_project_url = metadata["_links"]["datasetFtpUrl"]["href"]
    except Exception as e:
        raise FetcherException(
            "Error processing PRIDE project metadata for {} : {}".format(remote_file, e)
        )

    if len(parsed_steps) > 1:
        # Needed to avoid path handling problems
        if pride_project_url[-1] != "/":
            pride_project_url += "/"
        composed_pride_project_url = parse.urljoin(
            pride_project_url, "/".join(parsed_steps[1:])
        )
    else:
        composed_pride_project_url = pride_project_url

    return ProtocolFetcherReturn(
        kind_or_resolved=composed_pride_project_url,
        metadata_array=metadata_array,
    )


# These are schemes from identifiers.org
SCHEME_HANDLERS: "Mapping[str, DocumentedProtocolFetcher]" = {
    PRIDE_PROJECT_SCHEME: DocumentedProtocolFetcher(
        fetcher=fetchPRIDEProject,
        description="'pride' datasets metadata is fetched using the APIs described at https://www.ebi.ac.uk/pride/ws/archive/v2/swagger-ui.html#/projects . Contents are downloaded delegating their associated URIs to other fetchers",
    ),
}
