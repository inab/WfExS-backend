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

import copy
import io
import json
import os
import warnings

from typing import (
    cast,
    TYPE_CHECKING,
)

from urllib import parse

from . import (
    AbstractStatefulFetcher,
    DocumentedProtocolFetcher,
    FetcherException,
    ProtocolFetcherReturn,
)
from .http import fetchClassicURL

from ..common import (
    ContentKind,
    URIWithMetadata,
)

from ..utils.misc import (
    urlresolv,
)

if TYPE_CHECKING:
    from typing import (
        Mapping,
        MutableMapping,
        MutableSequence,
        Optional,
        Sequence,
    )

    from ..common import (
        AbsPath,
        PathLikePath,
        SecurityContextConfig,
        URIType,
    )

INTERNAL_TRS_SCHEME_PREFIX = "wfexs.trs.files"
TRS_SCHEME_PREFIX = "trs"

TRS_FILES_SUFFIX = "/files"
TRS_DESCRIPTOR_INFIX = "/descriptor/"


def fetchTRSFiles(
    remote_file: "URIType",
    cachedFilename: "PathLikePath",
    secContext: "Optional[SecurityContextConfig]" = None,
) -> "ProtocolFetcherReturn":
    """
    Method to download contents from TRS files related to a tool

    :param remote_file:
    :param cachedFilename: Destination filename for the fetched content
    :param secContext: The security context containing the credentials
    """

    parsedInputURL = parse.urlparse(remote_file)
    path_steps: "Sequence[str]" = parsedInputURL.path.split("/")
    embedded_remote_file = parsedInputURL.path

    metadata_array: "MutableSequence[URIWithMetadata]" = []
    if parsedInputURL.scheme == INTERNAL_TRS_SCHEME_PREFIX:
        # TODO: Improve this code
        if not embedded_remote_file.endswith(TRS_FILES_SUFFIX):
            metadata_url = cast("URIType", embedded_remote_file + TRS_FILES_SUFFIX)
            descriptor_base_url = embedded_remote_file + TRS_DESCRIPTOR_INFIX
        else:
            metadata_url = cast("URIType", embedded_remote_file)
            descriptor_base_url = (
                embedded_remote_file[0 : -len(TRS_FILES_SUFFIX)] + TRS_DESCRIPTOR_INFIX
            )
    elif parsedInputURL.scheme == TRS_SCHEME_PREFIX:
        # TRS official scheme
        if len(path_steps) < 3 or path_steps[0] != "":
            raise FetcherException(
                f"Ill-formed TRS CURIE {remote_file}. It should be in the format of {TRS_SCHEME_PREFIX}://id/version or {TRS_SCHEME_PREFIX}://prefix-with-slashes/id/version"
            )

        trs_base_steps = cast("MutableSequence[str]", path_steps[0:-2])
        trs_base_steps.extend(["ga4gh", "trs", "v2"])

        # Performing some sanity checks about the API
        service_info_steps = copy.copy(trs_base_steps)
        service_info_steps.append("service-info")
        service_info_metadata_url = cast(
            "URIType",
            parse.urlunparse(
                parse.ParseResult(
                    scheme="https",
                    netloc=parsedInputURL.netloc,
                    path="/".join(service_info_steps),
                    params="",
                    query="",
                    fragment="",
                )
            ),
        )
        service_info_meta = {
            "fetched": service_info_metadata_url,
            "payload": None,
        }
        metadata_array.append(URIWithMetadata(remote_file, service_info_meta))
        try:
            metaio = io.BytesIO()
            _, metametaio, _ = fetchClassicURL(service_info_metadata_url, metaio)
            service_info_metadata = json.loads(metaio.getvalue().decode("utf-8"))
            service_info_meta["payload"] = service_info_metadata
            metadata_array.extend(metametaio)
        except FetcherException as fe:
            raise FetcherException(
                f"Error fetching or processing TRS service info metadata for {remote_file} : {fe.code} {fe.reason}"
            ) from fe

        trs_version_str: "Optional[str]" = None
        trs_artifact: "Optional[str]" = None
        trs_group: "Optional[str]" = None
        trs_endpoint_meta_type: "Optional[Mapping[str, str]]" = (
            service_info_metadata.get("type")
        )
        if trs_endpoint_meta_type is not None:
            trs_version_str = trs_endpoint_meta_type.get("version")
            trs_artifact = trs_endpoint_meta_type.get("artifact")
            trs_group = trs_endpoint_meta_type.get("group")

        if trs_version_str is None:
            errstr = f"Unable to identify TRS version from {service_info_metadata_url}. Is this a TRS endpoint?"
            raise FetcherException(errstr)

        # Avoiding querying a GA4GH DRS service, for instance
        if trs_artifact is not None and trs_artifact.lower() not in ("trs", "yevis"):
            errstr = f"Unsupported GA4GH service {trs_artifact} (group {trs_group}) from {service_info_metadata_url}"
            raise FetcherException(errstr)

        # Warning about potentially unsupported versions
        trs_version_tuple = tuple(map(int, trs_version_str.split(".")))
        if trs_version_tuple < (2, 0, 1):
            warnings.warn(
                f"{service_info_metadata_url} is offering old TRS version {trs_version_str}, which diverges from what this implementation supports"
            )
        elif trs_version_tuple > (3, 0):
            warnings.warn(
                f"{service_info_metadata_url} is offering TRS version {trs_version_str}, which might diverge from what this implementation supports"
            )

        version_steps = copy.copy(trs_base_steps)
        version_steps.extend(["tools", path_steps[-2], "versions", path_steps[-1]])
        version_metadata_url = cast(
            "URIType",
            parse.urlunparse(
                parse.ParseResult(
                    scheme="https",
                    netloc=parsedInputURL.netloc,
                    path="/".join(version_steps),
                    params="",
                    query="",
                    fragment="",
                )
            ),
        )
        version_meta = {
            "fetched": version_metadata_url,
            "payload": None,
        }
        metadata_array.append(URIWithMetadata(remote_file, version_meta))
        try:
            metaio = io.BytesIO()
            _, metametaio, _ = fetchClassicURL(version_metadata_url, metaio)
            version_metadata = json.loads(metaio.getvalue().decode("utf-8"))
            version_meta["payload"] = version_metadata
            metadata_array.extend(metametaio)

        except FetcherException as fe:
            raise FetcherException(
                f"Error fetching or processing TRS version metadata for {remote_file} : {fe.code} {fe.reason}"
            ) from fe

        # At last, we can finish building the URL
        new_path_steps = [
            *version_steps,
            version_metadata["descriptor_type"][0],
            "files",
        ]

        metadata_url = cast(
            "URIType",
            parse.urlunparse(
                parse.ParseResult(
                    scheme="https",
                    netloc=parsedInputURL.netloc,
                    path="/".join(new_path_steps),
                    params="",
                    query="",
                    fragment="",
                )
            ),
        )

        descriptor_steps = [
            *version_steps,
            version_metadata["descriptor_type"][0],
            "descriptor",
        ]
        descriptor_base_url = parse.urlunparse(
            parse.ParseResult(
                scheme="https",
                netloc=parsedInputURL.netloc,
                path="/".join(descriptor_steps) + "/",
                params="",
                query="",
                fragment="",
            )
        )
    else:
        raise FetcherException(f"FIXME: Unhandled scheme {parsedInputURL.scheme}")

    topMeta = {
        "fetched": metadata_url,
        "payload": None,
        "workflow_entrypoint": None,
        "remote_workflow_entrypoint": None,
    }
    metadata_array = [URIWithMetadata(remote_file, topMeta)]
    try:
        metaio = io.BytesIO()
        _, metametaio, _ = fetchClassicURL(metadata_url, metaio)
        metadata = json.loads(metaio.getvalue().decode("utf-8"))
        topMeta["payload"] = metadata
        metadata_array.extend(metametaio)
    except FetcherException as fe:
        raise FetcherException(
            "Error fetching or processing TRS files metadata for {} : {} {}".format(
                remote_file, fe.code, fe.reason
            )
        ) from fe

    os.makedirs(cachedFilename, exist_ok=True)
    absdirs = set()
    emptyWorkflow = True

    # First pass, identify primary descriptor / workflow entrypoint
    # and learn whether the destination paths should be sanitized
    is_abs_url = False
    is_anon = False
    file_rel_2_url: "MutableMapping[str, str]" = dict()
    for file_desc in metadata:
        file_rel_path = file_desc.get("path")
        if file_rel_path is None:
            continue

        emptyWorkflow = False

        # BEWARE! The relpath could contain references to parent directories
        # escaping from the URL to be built and from the download "sandbox"
        frp_parsed = parse.urlparse(file_rel_path)
        is_abs_url = frp_parsed.scheme in ("http", "https", "ftp")

        if is_abs_url:
            # This one has to be dealt with a shortcut
            file_rel_2_url[file_rel_path] = urlresolv(file_rel_path)
            continue

        descriptor_url = cast(
            "URIType",
            descriptor_base_url + parse.quote(file_rel_path, safe="/"),
        )
        try:
            descmetaio = io.BytesIO()
            _, descmetaelem, _ = fetchClassicURL(
                descriptor_url, descmetaio, {"headers": {"Accept": "application/json"}}
            )
            descriptor_meta = json.loads(descmetaio.getvalue().decode("utf-8"))
        except FetcherException as fe:
            raise FetcherException(
                "Error fetching or processing TRS descriptor metadata for {} : {} {}".format(
                    descriptor_url, fe.code, fe.reason
                )
            ) from fe

        is_anon = (
            not isinstance(descriptor_meta, dict) or descriptor_meta.get("url") is None
        )
        if is_anon:
            # This one has to be dealt in a different way
            break
        file_rel_2_url[file_rel_path] = urlresolv(descriptor_meta["url"])

    if emptyWorkflow:
        raise FetcherException(
            "Error processing TRS files for {} : no file was found.\n{}".format(
                remote_file, metadata
            )
        )

    if is_anon:
        prefix_url = ""
    else:
        prefix_url = os.path.commonpath(tuple(file_rel_2_url.values()))

    # We have to create anonymous directories to avoid leaving the download "sandbox"
    abs_download_dir = cachedFilename
    if "/" in prefix_url:
        # This is needed to perform an effective work
        prefix_url += "/"
        # Due the peversion of commonpath, double slashes are collapsed
        colon_pos = prefix_url.find(":")
        if colon_pos > 0:
            prefix_url = (
                prefix_url[0 : colon_pos + 1] + "/" + prefix_url[colon_pos + 1 :]
            )

        # Computing resolved relative paths
        for file_desc in metadata:
            file_rel_path = file_desc.get("path")
            if file_rel_path is not None:
                # BEWARE! The relpath could contain references to parent directories
                # escaping from the URL to be built and from the download "sandbox"
                frp_parsed = parse.urlparse(file_rel_path)
                is_abs_url = frp_parsed.scheme in ("http", "https", "ftp")
                if is_abs_url:
                    # An absolute URL, like in the case of DDBJ TRS implementation
                    file_url = cast("URIType", file_rel_path)
                else:
                    file_url = cast(
                        "URIType",
                        descriptor_base_url + parse.quote(file_rel_path, safe="/"),
                    )
                local_rel_path = file_rel_2_url[file_rel_path][len(prefix_url) :]
                absfile = cast(
                    "AbsPath", os.path.join(abs_download_dir, local_rel_path)
                )

                # Intermediate path creation
                absdir = os.path.dirname(absfile)
                if absdir not in absdirs:
                    absdirs.add(absdir)
                    os.makedirs(absdir, exist_ok=True)
                real_rel_path = os.path.relpath(
                    os.path.normpath(absfile), cachedFilename
                )

                # When it is the primary descriptor, it is fetched twice
                if file_desc.get("file_type") == "PRIMARY_DESCRIPTOR":
                    topMeta["workflow_entrypoint"] = cast("URIType", real_rel_path)
                    if is_abs_url:
                        topMeta["remote_workflow_entrypoint"] = file_url
                    else:
                        topMeta["remote_workflow_entrypoint"] = cast(
                            "URIType", file_rel_2_url[file_rel_path]
                        )

                # Getting the raw content
                accept_val = "*/*" if is_abs_url else "text/plain"
                _, metaelem, _ = fetchClassicURL(
                    file_url, absfile, {"headers": {"Accept": accept_val}}
                )
                metadata_array.extend(metaelem)
    else:
        # First pass, identify primary descriptor / workflow entrypoint
        # and learn whether the destination paths should be sanitized
        deepest_file_rel = 0
        for file_desc in metadata:
            file_rel_path = file_desc.get("path")
            if file_rel_path is not None:
                frp_parsed = parse.urlparse(file_rel_path)
                if frp_parsed.scheme in ("http", "https", "ftp"):
                    # An absolute URL, like in the case of DDBJ TRS implementation
                    # A mixure of resource might be catastrophic, the code is doing
                    # its best effort
                    file_rel_path = os.path.join(frp_parsed.netloc, frp_parsed.params)

                # BEWARE! The relpath could contain references to parent directories
                # escaping from the URL to be built and from the download "sandbox"
                # Avoid absolute paths corner case before splitting
                file_rel_path_steps = file_rel_path.lstrip("/").split("/")

                deepest = 0
                depth = 0
                for step in file_rel_path_steps:
                    if step == "..":
                        depth -= 1
                        if depth < deepest:
                            deepest = depth
                    elif step not in (".", ""):
                        depth += 1

                if deepest < deepest_file_rel:
                    deepest_file_rel = deepest

        if deepest_file_rel < 0:
            for depth in range(-deepest_file_rel):
                abs_download_dir = cast(
                    "AbsPath", os.path.join(abs_download_dir, f"unnamed{depth}")
                )

        # Second pass, fetching the contents, sanitizing the destination paths
        for file_desc in metadata:
            file_rel_path = file_desc.get("path")
            if file_rel_path is not None:
                emptyWorkflow = False

                # BEWARE! The relpath could contain references to parent directories
                # escaping from the URL to be built and from the download "sandbox"
                frp_parsed = parse.urlparse(file_rel_path)
                is_abs_url = frp_parsed.scheme in ("http", "https", "ftp")
                if is_abs_url:
                    # An absolute URL, like in the case of DDBJ TRS implementation
                    file_url = cast("URIType", file_rel_path)
                    absfile = cast(
                        "AbsPath",
                        os.path.join(
                            abs_download_dir,
                            frp_parsed.netloc,
                            frp_parsed.path.lstrip("/"),
                        ),
                    )
                else:
                    file_url = cast(
                        "URIType",
                        descriptor_base_url + parse.quote(file_rel_path, safe="/"),
                    )
                    absfile = cast(
                        "AbsPath",
                        os.path.join(abs_download_dir, file_rel_path.lstrip("/")),
                    )

                # Intermediate path creation
                absdir = os.path.dirname(absfile)
                if absdir not in absdirs:
                    absdirs.add(absdir)
                    os.makedirs(absdir, exist_ok=True)
                real_rel_path = os.path.relpath(
                    os.path.normpath(absfile), cachedFilename
                )

                # When it is the primary descriptor, it is fetched twice
                if file_desc.get("file_type") == "PRIMARY_DESCRIPTOR":
                    topMeta["workflow_entrypoint"] = cast("URIType", real_rel_path)
                    if is_abs_url:
                        topMeta["remote_workflow_entrypoint"] = file_url
                    else:
                        descriptorMeta = io.BytesIO()
                        _, metaprimary, _ = fetchClassicURL(file_url, descriptorMeta)
                        metadata_array.extend(metaprimary)

                        # This metadata can help a lot to get the workflow repo
                        metadataPD = json.loads(
                            descriptorMeta.getvalue().decode("utf-8")
                        )
                        topMeta["remote_workflow_entrypoint"] = metadataPD.get("url")

                        del descriptorMeta
                        del metadataPD

                # Getting the raw content
                accept_val = "*/*" if is_abs_url else "text/plain"
                try:
                    _, metaelem, _ = fetchClassicURL(
                        file_url, absfile, {"headers": {"Accept": accept_val}}
                    )
                    metadata_array.extend(metaelem)
                except FetcherException as fe:
                    if file_desc.get("file_type") in (
                        "PRIMARY_DESCRIPTOR",
                        "SECONDARY_DESCRIPTOR",
                    ):
                        raise
                    else:
                        warnings.warn(
                            f"Unable to fetch {file_url}. TRS Dataset {metadata_url} might be incomplete"
                        )

    if emptyWorkflow:
        raise FetcherException(
            "Error processing TRS files for {} : no file was found.\n{}".format(
                remote_file, metadata
            )
        )

    return ProtocolFetcherReturn(
        kind_or_resolved=ContentKind.Directory,
        metadata_array=metadata_array,
    )


# These are schemes from identifiers.org
SCHEME_HANDLERS: "Mapping[str, DocumentedProtocolFetcher]" = {
    INTERNAL_TRS_SCHEME_PREFIX: DocumentedProtocolFetcher(
        fetcher=fetchTRSFiles,
        description="WfExS internal pseudo-scheme used to materialize files from pure TRS servers",
    ),
    TRS_SCHEME_PREFIX: DocumentedProtocolFetcher(
        fetcher=fetchTRSFiles,
        description="GA4GH TRS metadata is fetched using the APIs described at https://ga4gh.github.io/tool-registry-service-schemas/. Contents are downloaded delegating their associated URIs to other fetchers",
    ),
}
