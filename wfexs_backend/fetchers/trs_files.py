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

import atexit
import copy
import hashlib
import io
import json
import logging
import os
import pathlib
import shutil
import tempfile
import urllib.parse
import warnings

from typing import (
    cast,
    TYPE_CHECKING,
)

from urllib import parse

from . import (
    AbstractSchemeRepoFetcher,
    DocumentedProtocolFetcher,
    DocumentedStatefulProtocolFetcher,
    FetcherException,
    MaterializedRepo,
    ProtocolFetcherReturn,
    RemoteRepo,
    RepoType,
)

from ..common import (
    ContentKind,
    URIWithMetadata,
)

from ..utils.contents import (
    link_or_copy_pathlib,
)

from ..utils.misc import (
    urlresolv,
)

if TYPE_CHECKING:
    from typing import (
        Any,
        Mapping,
        MutableMapping,
        MutableSequence,
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
        PathLikePath,
        ProgsMapping,
        RelPath,
        RepoURL,
        SecurityContextConfig,
        SymbolicName,
        URIType,
    )

    from ..scheme_catalog import (
        SchemeCatalog,
    )


class GA4GHTRSFetcher(AbstractSchemeRepoFetcher):
    INTERNAL_TRS_SCHEME_PREFIX: "Final[str]" = "wfexs.trs.files"
    TRS_SCHEME_PREFIX: "Final[str]" = "trs"

    TRS_FILES_SUFFIX: "Final[str]" = "/files"
    TRS_DESCRIPTOR_INFIX: "Final[str]" = "/descriptor/"

    @classmethod
    def GetSchemeHandlers(cls) -> "Mapping[str, DocumentedStatefulProtocolFetcher]":
        # These are de-facto schemes supported by Software Heritage
        # libraries and other implementations
        return {
            cls.INTERNAL_TRS_SCHEME_PREFIX: DocumentedStatefulProtocolFetcher(
                fetcher_class=cls,
                description="WfExS internal pseudo-scheme used to materialize files from pure TRS servers",
                priority=cls.PRIORITY,
            ),
            cls.TRS_SCHEME_PREFIX: DocumentedStatefulProtocolFetcher(
                fetcher_class=cls,
                description="GA4GH TRS metadata is fetched using the APIs described at https://ga4gh.github.io/tool-registry-service-schemas/. Contents are downloaded delegating their associated URIs to other fetchers",
                priority=cls.PRIORITY,
            ),
        }

    @property
    def description(self) -> "str":
        return "Fetcher for GA4GH TRSv2 tools"

    @classmethod
    def GetNeededPrograms(cls) -> "Sequence[SymbolicName]":
        return tuple()

    @classmethod
    def GuessRepoParams(
        cls,
        orig_wf_url: "Union[URIType, parse.ParseResult]",
        logger: "Optional[logging.Logger]" = None,
        fail_ok: "bool" = False,
    ) -> "Optional[RemoteRepo]":
        pass

    def materialize_repo_from_repo(
        self,
        repo: "RemoteRepo",
        repo_tag_destdir: "Optional[PathLikePath]" = None,
        base_repo_destdir: "Optional[PathLikePath]" = None,
        doUpdate: "Optional[bool]" = True,
    ) -> "MaterializedRepo":
        remote_file = repo.repo_url
        repoTag = repo.tag

        parsedInputURL = parse.urlparse(remote_file)
        path_steps: "Sequence[str]" = parsedInputURL.path.split("/")
        embedded_remote_file = parsedInputURL.path

        metadata_array: "MutableSequence[URIWithMetadata]" = []
        if parsedInputURL.scheme == self.INTERNAL_TRS_SCHEME_PREFIX:
            # TODO: Improve this code
            if not embedded_remote_file.endswith(self.TRS_FILES_SUFFIX):
                files_metadata_url = cast(
                    "URIType", embedded_remote_file + self.TRS_FILES_SUFFIX
                )
                descriptor_base_url = embedded_remote_file + self.TRS_DESCRIPTOR_INFIX
            else:
                files_metadata_url = cast("URIType", embedded_remote_file)
                descriptor_base_url = (
                    embedded_remote_file[0 : -len(self.TRS_FILES_SUFFIX)]
                    + self.TRS_DESCRIPTOR_INFIX
                )
            # TODO: fetch here service info metadata
        elif parsedInputURL.scheme == self.TRS_SCHEME_PREFIX:
            # TRS official scheme
            if len(path_steps) < 3 or path_steps[0] != "":
                raise FetcherException(
                    f"Ill-formed TRS CURIE {remote_file}. It should be in the format of {self.TRS_SCHEME_PREFIX}://id/version or {self.TRS_SCHEME_PREFIX}://prefix-with-slashes/id/version"
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
            service_info_wfexs_meta = {
                "fetched": service_info_metadata_url,
                "payload": None,
            }
            metadata_array.append(URIWithMetadata(remote_file, service_info_wfexs_meta))
            try:
                metaio = io.BytesIO()
                _, metametaio, _ = self.scheme_catalog.streamfetch(
                    service_info_metadata_url, metaio
                )
                service_info_metadata = json.loads(metaio.getvalue().decode("utf-8"))
                service_info_wfexs_meta["payload"] = service_info_metadata
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
            if trs_artifact is not None and trs_artifact.lower() not in (
                "trs",
                "yevis",
            ):
                errstr = f"Unsupported GA4GH service {trs_artifact} (group {trs_group}) from {service_info_metadata_url}"
                raise FetcherException(errstr)

            # Warning about potentially unsupported versions
            trs_version_tuple = tuple(map(int, trs_version_str.split(".")))
            if trs_version_tuple < (2, 0, 1):
                self.logger.warning(
                    f"{service_info_metadata_url} is offering old TRS version {trs_version_str}, which diverges from what this implementation supports"
                )
            elif trs_version_tuple > (3, 0):
                self.logger.warning(
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
                _, metametaio, _ = self.scheme_catalog.streamfetch(
                    version_metadata_url, metaio
                )
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

            files_metadata_url = cast(
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

        # Assure directory exists before next step
        if repo_tag_destdir is None:
            if base_repo_destdir is None:
                repo_tag_destpath = pathlib.Path(
                    tempfile.mkdtemp(prefix="wfexs", suffix=".trs")
                )
                atexit.register(shutil.rmtree, repo_tag_destpath, True)
            else:
                repo_hashed_id = hashlib.sha1(remote_file.encode("utf-8")).hexdigest()
                repo_destpath = pathlib.Path(base_repo_destdir, repo_hashed_id)
                # repo_destdir = pathlib.Path(self.cacheWorkflowDir, repo_hashed_id)

                if not repo_destpath.exists():
                    try:
                        repo_destpath.mkdir(parents=True)
                    except IOError:
                        errstr = "ERROR: Unable to create intermediate directories for repo {}. ".format(
                            remote_file
                        )
                        raise FetcherException(errstr)

                repo_hashed_tag_id = hashlib.sha1(
                    b"" if repoTag is None else repoTag.encode("utf-8")
                ).hexdigest()
                repo_tag_destpath = repo_destpath / repo_hashed_tag_id
        else:
            repo_tag_destpath = (
                repo_tag_destdir
                if isinstance(repo_tag_destdir, pathlib.Path)
                else pathlib.Path(repo_tag_destdir)
            )

        self.logger.debug(f"Repo dir {repo_tag_destpath}")

        topMeta = {
            "fetched": files_metadata_url,
            "payload": None,
            "workflow_entrypoint": None,
            "remote_workflow_entrypoint": None,
        }
        metadata_array = [URIWithMetadata(remote_file, topMeta)]
        try:
            metaio = io.BytesIO()
            _, metametaio, _ = self.scheme_catalog.streamfetch(
                files_metadata_url, metaio
            )
            metadata = json.loads(metaio.getvalue().decode("utf-8"))
            topMeta["payload"] = metadata
            metadata_array.extend(metametaio)
        except FetcherException as fe:
            raise FetcherException(
                "Error fetching or processing TRS files metadata for {} : {} {}".format(
                    remote_file, fe.code, fe.reason
                )
            ) from fe

        repo_tag_destpath.mkdir(parents=True, exist_ok=True)
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
                _, descmetaelem, _ = self.scheme_catalog.streamfetch(
                    descriptor_url,
                    descmetaio,
                    {"headers": {"Accept": "application/json"}},
                )
                descriptor_meta = json.loads(descmetaio.getvalue().decode("utf-8"))
            except FetcherException as fe:
                raise FetcherException(
                    "Error fetching or processing TRS descriptor metadata for {} : {} {}".format(
                        descriptor_url, fe.code, fe.reason
                    )
                ) from fe

            is_anon = (
                not isinstance(descriptor_meta, dict)
                or descriptor_meta.get("url") is None
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
        abs_download_dir = repo_tag_destpath
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
                    absfile = (abs_download_dir / local_rel_path).resolve()

                    # Intermediate path creation
                    absdir = absfile.parent
                    if absdir not in absdirs:
                        absdirs.add(absdir)
                        os.makedirs(absdir, exist_ok=True)
                    real_rel_path = absfile.relative_to(repo_tag_destpath)

                    # When it is the primary descriptor, it is fetched twice
                    if file_desc.get("file_type") == "PRIMARY_DESCRIPTOR":
                        topMeta["workflow_entrypoint"] = cast(
                            "URIType", real_rel_path.as_posix()
                        )
                        if is_abs_url:
                            topMeta["remote_workflow_entrypoint"] = file_url
                        else:
                            topMeta["remote_workflow_entrypoint"] = cast(
                                "URIType", file_rel_2_url[file_rel_path]
                            )

                    # Getting the raw content
                    accept_val = "*/*" if is_abs_url else "text/plain"
                    _, metaelem, _ = self.scheme_catalog.fetch(
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
                        file_rel_path = os.path.join(
                            frp_parsed.netloc, frp_parsed.params
                        )

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
                    abs_download_dir = abs_download_dir / f"unnamed{depth}"

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
                        absfile = (
                            abs_download_dir
                            / frp_parsed.netloc
                            / frp_parsed.path.lstrip("/")
                        )
                    else:
                        file_url = cast(
                            "URIType",
                            descriptor_base_url + parse.quote(file_rel_path, safe="/"),
                        )
                        absfile = abs_download_dir / file_rel_path.lstrip("/")

                    absfile = absfile.resolve()

                    # Intermediate path creation
                    absdir = absfile.parent
                    if absdir not in absdirs:
                        absdirs.add(absdir)
                        absdir.mkdir(parents=True, exist_ok=True)
                    real_rel_path = absfile.relative_to(repo_tag_destpath)

                    # When it is the primary descriptor, it is fetched twice
                    if file_desc.get("file_type") == "PRIMARY_DESCRIPTOR":
                        topMeta["workflow_entrypoint"] = cast(
                            "URIType", real_rel_path.as_posix()
                        )
                        if is_abs_url:
                            topMeta["remote_workflow_entrypoint"] = file_url
                        else:
                            descriptorMeta = io.BytesIO()
                            _, metaprimary, _ = self.scheme_catalog.streamfetch(
                                file_url, descriptorMeta
                            )
                            metadata_array.extend(metaprimary)

                            # This metadata can help a lot to get the workflow repo
                            metadataPD = json.loads(
                                descriptorMeta.getvalue().decode("utf-8")
                            )
                            topMeta["remote_workflow_entrypoint"] = metadataPD.get(
                                "url"
                            )

                            del descriptorMeta
                            del metadataPD

                    # Getting the raw content
                    accept_val = "*/*" if is_abs_url else "text/plain"
                    try:
                        _, metaelem, _ = self.scheme_catalog.fetch(
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
                            self.logger.warning(
                                f"Unable to fetch {file_url}. TRS Dataset {files_metadata_url} might be incomplete"
                            )

        if emptyWorkflow:
            raise FetcherException(
                "Error processing TRS files for {} : no file was found.\n{}".format(
                    remote_file, metadata
                )
            )

        upstream_repo: "Optional[RemoteRepo]" = None
        recommends_upstream: "bool" = False
        # Checking whether it is WorkflowHub
        # to recommend the generated Workflow RO-Crate
        if service_info_metadata.get("organization", {}).get("name") == "WorkflowHub":
            recommends_upstream = True
            upstream_repo = RemoteRepo(
                repo_url=cast(
                    "RepoURL",
                    files_metadata_url
                    + "?"
                    + urllib.parse.urlencode({"format": "zip"}),
                ),
                repo_type=RepoType.Raw,
            )
        elif topMeta["remote_workflow_entrypoint"] is not None:
            upstream_repo = RemoteRepo(
                repo_url=cast("RepoURL", topMeta["remote_workflow_entrypoint"]),
            )

        return MaterializedRepo(
            local=repo_tag_destpath,
            repo=RemoteRepo(
                repo_url=remote_file,
                rel_path=cast("Optional[RelPath]", topMeta["workflow_entrypoint"]),
                repo_type=RepoType.TRS,
            ),
            metadata_array=metadata_array,
            upstream_repo=upstream_repo,
            recommends_upstream=recommends_upstream,
        )

    def build_pid_from_repo(self, remote_repo: "RemoteRepo") -> "Optional[str]":
        """
        This method is required to generate a PID which usually
        represents an element (usually a workflow) in a repository.
        If the fetcher does not recognize the type of repo, either using
        repo_url content or the repo type in the worst case, it should
        return None
        """

        # TODO: improve this to cover the different cases
        parsedInputURL = parse.urlparse(remote_repo.repo_url)
        if (
            parsedInputURL.scheme
            in (self.INTERNAL_TRS_SCHEME_PREFIX, self.TRS_SCHEME_PREFIX)
            or remote_repo.repo_type == RepoType.TRS
        ):
            return remote_repo.repo_url

        return None

    def fetch(
        self,
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

        # For cases where the URI is not one of the native schemes
        # fallback to INTERNAL_TRS_SCHEME_PREFIX
        if parsedInputURL.scheme not in self.GetSchemeHandlers():
            the_remote_file = self.INTERNAL_TRS_SCHEME_PREFIX + ":" + remote_file
        else:
            the_remote_file = remote_file

        # Getting the repoRelPath (if available)
        params = parse.parse_qs(parsedInputURL.path, separator=";")
        repoRelPath_l = params.get("path", [])
        repoRelPath: "Optional[str]"
        if len(repoRelPath_l) > 0:
            repoRelPath = repoRelPath_l[0]
            # Directories also end with slashes
            repoRelPath.strip("/")
        else:
            repoRelPath = None

        # It is materialized in a temporary location
        materialized_repo_return = self.materialize_repo_from_repo(
            RemoteRepo(repo_url=cast("RepoURL", remote_file), repo_type=RepoType.TRS),
        )
        repo_tag_destdir = materialized_repo_return.local
        remote_repo = materialized_repo_return.repo
        metadata_array = materialized_repo_return.metadata_array

        preferredName: "Optional[RelPath]"
        # repoRelPath is only acknowledged when the resolved repo
        # is translated to a directory
        if repoRelPath is not None and repo_tag_destdir.is_dir():
            cachedContentPath = repo_tag_destdir / repoRelPath
            preferredName = cast("RelPath", cachedContentPath.name)
        else:
            cachedContentPath = repo_tag_destdir
            preferredName = None
            # This is to remove spurious detections
            repoRelPath = None

        remote_repo = remote_repo._replace(rel_path=cast("RelPath", repoRelPath))

        if cachedContentPath.is_dir():
            kind = ContentKind.Directory
        elif cachedContentPath.is_file():
            kind = ContentKind.File
        else:
            raise FetcherException(
                f"Remote {remote_file} is neither a file nor a directory (does it exist?)"
            )

        # shutil.move(cachedContentPath, cachedFilename)
        link_or_copy_pathlib(cachedContentPath, pathlib.Path(cachedFilename))

        repo_desc: "Optional[Mapping[str, Any]]" = remote_repo.gen_repo_desc()
        if repo_desc is None:
            repo_desc = {}
        augmented_metadata_array = [
            URIWithMetadata(
                uri=remote_file, metadata=repo_desc, preferredName=preferredName
            ),
            *metadata_array,
        ]
        return ProtocolFetcherReturn(
            kind_or_resolved=kind,
            metadata_array=augmented_metadata_array,
            # TODO: Integrate licences from TRS report??
            licences=None,
        )
