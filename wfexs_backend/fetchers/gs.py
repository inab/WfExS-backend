#!/usr/bin/env python
# -*- coding: utf-8 -*-

# SPDX-License-Identifier: Apache-2.0
# Copyright 2020-2025 Barcelona Supercomputing Center (BSC), Spain
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

from google.cloud import storage  # type: ignore[import]
from urllib.parse import urlparse
import logging
import os
from typing import (
    TYPE_CHECKING,
)

if TYPE_CHECKING:
    from typing import (
        Any,
        Mapping,
        MutableSequence,
        Optional,
    )

    from ..common import (
        AbsPath,
        PathLikePath,
        SecurityContextConfig,
        URIType,
    )

from . import (
    DocumentedProtocolFetcher,
    FetcherException,
    ProtocolFetcherReturn,
)

from ..common import (
    ContentKind,
    URIWithMetadata,
)

logger = logging.getLogger()


def downloadContentFrom_gs(
    remote_file: "URIType",
    cachedFilename: "PathLikePath",
    secContext: "Optional[SecurityContextConfig]" = None,
    explicit_redirects: "bool" = False,
) -> "ProtocolFetcherReturn":
    """
    Method to download contents from Google Storage.

    :param remote_file:
    :param cachedFilename:
    :param secContext:
    """
    parsedInputURL = urlparse(remote_file)
    bucket_name = parsedInputURL.netloc
    prefix = parsedInputURL.path[1:]
    local_path = cachedFilename

    # Does the security context contain credentials
    if isinstance(secContext, dict):
        credentials = secContext.get("gs_credentials")
    else:
        credentials = None

    # Based on fetched credentials, create the Client instance
    try:
        if credentials is None:
            gs = storage.Client.create_anonymous_client()
        else:
            gs = storage.Client.from_service_account_json(credentials)
    except Exception as e:
        errmsg = f"GS authentication error on {remote_file}"
        logger.exception(errmsg)
        raise FetcherException(errmsg) from e

    # Obtain the instance of the bucket
    try:
        bucket = gs.bucket(bucket_name)
    except Exception as e:
        errmsg = f"Invalid bucket name {bucket_name} on {remote_file}"
        logger.exception(errmsg)
        raise FetcherException(errmsg)

    # Build the blob
    try:
        blob = bucket.blob(prefix)
    except Exception as e:
        errmsg = f"Unable to create blob {prefix} for {remote_file}"
        logger.exception(errmsg)
        raise FetcherException(errmsg)

    # Does the blob exist?
    metadata_payload: MutableSequence[Mapping[str, Any]] = []
    metadata = {"fetched": remote_file, "payload": metadata_payload}
    if blob.exists():
        try:
            blob.download_to_filename(local_path)
            metadata_payload.append(blob.metadata)
            kind = ContentKind.File
        except Exception as e:
            errmsg = f"Error downloading {remote_file} to {local_path}"
            logger.exception(errmsg)
            raise FetcherException(errmsg) from e
    else:
        # Let's assume this is a prefix, so use the slash delimiter
        blob_prefix = prefix
        if prefix[-1] != "/":
            blob_prefix += "/"

        blobs = list(gs.list_blobs(bucket, prefix=blob_prefix))
        if len(blobs) == 0:
            errmsg = f"Path prefix {blob_prefix} from {remote_file} matches no blob"
            logger.error(errmsg)
            raise FetcherException(errmsg)

        for blob in blobs:
            local_blob_filename = os.path.join(
                local_path, blob.name[len(blob_prefix) :]
            )
            try:
                os.makedirs(os.path.dirname(local_blob_filename), exist_ok=True)
                blob.download_to_filename(local_blob_filename)
                metadata_payload.append(blob.metadata)
            except Exception as e:
                errmsg = f"Error downloading {blob.name} from {remote_file} to {local_blob_filename}"
                logger.exception(errmsg)
                raise FetcherException(errmsg) from e

        kind = ContentKind.Directory

    return ProtocolFetcherReturn(
        kind_or_resolved=kind,
        metadata_array=[URIWithMetadata(remote_file, metadata)],
    )


SCHEME_HANDLERS: "Mapping[str, DocumentedProtocolFetcher]" = {
    "gs": DocumentedProtocolFetcher(
        fetcher=downloadContentFrom_gs,
        description="Google Cloud Storage resource path scheme, whose downloads are delegated on Google Cloud Storage libraries",
    ),
}
