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

from __future__ import absolute_import

import atexit
import copy
import hashlib
import inspect
import io
import json
import logging
import os
import pathlib
import shutil
import tempfile
import urllib.parse
import sys
import warnings

from typing import (
    cast,
    TYPE_CHECKING,
)

from urllib import parse

# This code needs exception groups
if sys.version_info[:2] < (3, 11):
    from exceptiongroup import ExceptionGroup

from . import (
    AbstractSchemeRepoFetcher,
    DocumentedProtocolFetcher,
    DocumentedStatefulProtocolFetcher,
    FetcherException,
    MaterializedRepo,
    OfflineRepoGuessException,
    ProtocolFetcherReturn,
    RemoteRepo,
    RepoGuessException,
    RepoType,
)

from .. import (
    get_WfExS_version_str,
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

from .http import HTTPFetcher

from ..scheme_catalog import (
    SchemeCatalog,
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
        RepoTag,
        RepoURL,
        SecurityContextConfig,
        SymbolicName,
        TRS_Workflow_Descriptor,
        URIType,
    )

    from ..workflow import (
        WFVersionId,
        WorkflowId,
    )


class GA4GHTRSFetcher(AbstractSchemeRepoFetcher):
    INTERNAL_TRS_SCHEME_PREFIX: "Final[str]" = "wfexs.trs.files"
    TRS_SCHEME_PREFIX: "Final[str]" = "trs"

    TRS_TOOLS_SUFFIX: "Final[str]" = "tools/"
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
    def GuessTRSParams(
        cls,
        orig_wf_url: "Union[URIType, parse.ParseResult]",
        override_version_id: "Optional[WFVersionId]" = None,
        logger: "Optional[logging.Logger]" = None,
        fail_ok: "bool" = False,
        scheme_catalog: "Optional[SchemeCatalog]" = None,
        offline: "bool" = False,
    ) -> "Optional[Tuple[RepoURL, str, Sequence[str], WorkflowId, WFVersionId, str, Sequence[URIWithMetadata], Optional[Mapping[str, Any]]]]":
        if scheme_catalog is None:
            scheme_catalog = SchemeCatalog(
                scheme_handlers=HTTPFetcher.GetSchemeHandlers()
            )

        if logger is None:
            logger = logging.getLogger(
                dict(inspect.getmembers(cls))["__module__"] + "::" + cls.__name__
            )

        # Deciding which is the input
        wf_url: "RepoURL"
        parsed_wf_url: "parse.ParseResult"
        if isinstance(orig_wf_url, parse.ParseResult):
            parsed_wf_url = orig_wf_url
            wf_url = cast("RepoURL", parse.urlunparse(orig_wf_url))
        else:
            wf_url = cast("RepoURL", orig_wf_url)
            parsed_wf_url = parse.urlparse(orig_wf_url)

        if parsed_wf_url.scheme in HTTPFetcher.GetSchemeHandlers():
            wf_url = cast("RepoURL", cls.INTERNAL_TRS_SCHEME_PREFIX + ":" + wf_url)
            parsed_wf_url = parse.urlparse(wf_url)

        metadata_array: "MutableSequence[URIWithMetadata]" = []
        putative_tool_uri: "Optional[URIType]" = None
        descriptor: "Optional[str]" = None
        service_info_metadata: "Optional[MutableMapping[str, Any]]" = None
        trs_tool_uri: "URIType"
        trs_tool_meta: "Optional[Mapping[str, Any]]" = None
        version_id: "Optional[WFVersionId]" = None
        if parsed_wf_url.scheme == cls.TRS_SCHEME_PREFIX:
            if offline:
                raise OfflineRepoGuessException(
                    f"Queries related to {wf_url} are not allowed in offline mode"
                )
            # Duplication of code
            path_steps: "Sequence[str]" = parsed_wf_url.path.split("/")
            if len(path_steps) < 3 or path_steps[0] != "":
                if fail_ok:
                    return None
                raise RepoGuessException(
                    f"Ill-formed TRS CURIE {wf_url}. It should be in the format of {cls.TRS_SCHEME_PREFIX}://server/id/version or {cls.TRS_SCHEME_PREFIX}://server-plus-prefix-with-slashes/id/version"
                )

            trs_steps = cast("MutableSequence[str]", path_steps[0:-2])
            trs_steps.extend(["ga4gh", "trs", "v2", "service-info"])

            trs_service_netloc = parsed_wf_url.netloc
            trs_service_info = urllib.parse.urlunparse(
                urllib.parse.ParseResult(
                    scheme="https",
                    netloc=trs_service_netloc,
                    path="/".join(trs_steps),
                    params="",
                    query="",
                    fragment="",
                )
            )

            service_info_wfexs_meta = {
                "fetched": trs_service_info,
                "payload": cast("Optional[Mapping[str, Any]]", None),
            }
            metadata_array.append(URIWithMetadata(wf_url, service_info_wfexs_meta))
            try:
                metaio = io.BytesIO()
                _, metametaio, _ = scheme_catalog.streamfetch(
                    cast("URIType", trs_service_info), metaio
                )
                service_info_metadata = json.loads(metaio.getvalue().decode("utf-8"))
                service_info_wfexs_meta["payload"] = service_info_metadata
                metadata_array.extend(metametaio)

                trs_endpoint = trs_service_info[0 : -len("service-info")]
            except Exception as e1:
                non_standard_trs_steps = cast("MutableSequence[str]", path_steps[0:-2])
                non_standard_trs_steps.extend(["service-info"])

                non_standard_trs_service_info = urllib.parse.urlunparse(
                    urllib.parse.ParseResult(
                        scheme="https",
                        netloc=trs_service_netloc,
                        path="/".join(non_standard_trs_steps),
                        params="",
                        query="",
                        fragment="",
                    )
                )

                try:
                    metaio = io.BytesIO()
                    _, metametaio, _ = scheme_catalog.streamfetch(
                        cast("URIType", non_standard_trs_service_info), metaio
                    )
                    service_info_metadata = json.loads(
                        metaio.getvalue().decode("utf-8")
                    )
                    service_info_wfexs_meta["payload"] = service_info_metadata
                    metadata_array.extend(metametaio)
                    trs_endpoint = non_standard_trs_service_info[
                        0 : -len("service-info")
                    ]
                except Exception as e2:
                    if fail_ok:
                        return None
                    raise ExceptionGroup(
                        f"Error fetching or processing TRS service info metadata for {wf_url} (tried both {trs_service_info} and {non_standard_trs_service_info})",
                        [e1, e2],
                    )

            version_id = (
                urllib.parse.unquote(path_steps[-1])
                if not override_version_id
                else override_version_id
            )
            trs_tool_uri = cast(
                "URIType",
                trs_endpoint
                + cls.TRS_TOOLS_SUFFIX
                + path_steps[-2]
                + "/versions/"
                + urllib.parse.quote(cast("str", version_id), safe=""),
            )
            workflow_id = urllib.parse.unquote(path_steps[-2])
            descriptor = None
        elif parsed_wf_url.scheme == cls.INTERNAL_TRS_SCHEME_PREFIX:
            if offline:
                raise OfflineRepoGuessException(
                    f"Queries related to {wf_url} are not allowed in offline mode"
                )
            putative_tool_uri = cast(
                "URIType",
                parsed_wf_url.path[0:-1]
                if parsed_wf_url.path.endswith("/")
                else parsed_wf_url.path,
            )

            parsed_putative_tool_uri = urllib.parse.urlparse(putative_tool_uri)
            trs_service_netloc = parsed_putative_tool_uri.netloc
            # Detecting workflowhub derivatives
            is_wh = parsed_putative_tool_uri.netloc.endswith("workflowhub.eu")

            # Time to try guessing everything
            tool_wfexs_meta = {
                "fetched": putative_tool_uri,
                "payload": None,
            }
            metadata_array.append(URIWithMetadata(wf_url, tool_wfexs_meta))
            try:
                resio = io.BytesIO()
                _, metaresio, _ = scheme_catalog.streamfetch(
                    putative_tool_uri,
                    resio,
                    sec_context={
                        "headers": {
                            "Accept": "application/json",
                            # Added to avoid Cloudflare anti-bot policy
                            "User-Agent": get_WfExS_version_str(),
                        },
                    },
                )
                trs__meta = json.loads(resio.getvalue().decode("utf-8"))
                tool_wfexs_meta["payload"] = trs__meta
                metadata_array.extend(metaresio)
            except Exception as e:
                if fail_ok:
                    return None
                raise RepoGuessException(
                    f"trs_endpoint could not be guessed from {putative_tool_uri} (raised exception {e})"
                ) from e

            if not isinstance(trs__meta, dict):
                if fail_ok:
                    return None
                raise RepoGuessException(
                    f"trs_endpoint could not be guessed from {putative_tool_uri} (not returning JSON object)"
                )

            # Is this the "abstract" tool definition?
            versions = trs__meta.get("versions")
            if isinstance(versions, list) and "toolclass" in trs__meta:
                if len(versions) == 0:
                    if fail_ok:
                        return None
                    raise RepoGuessException(
                        f"No versions found associated to TRS tool reachable through {putative_tool_uri}"
                    )

                if override_version_id:
                    for putative_trs_tool_meta in versions:
                        version_id = putative_trs_tool_meta.get("id")
                        name = putative_trs_tool_meta.get("name")
                        if version_id is not None:
                            # Dockstore misbehaves
                            if (
                                name is not None
                                and str(version_id).endswith(name)
                                and parsed_putative_tool_uri.netloc.endswith(
                                    "dockstore.org"
                                )
                            ):
                                version_id = name
                        if version_id == override_version_id:
                            trs_tool_meta = putative_trs_tool_meta
                            break
                    else:
                        if fail_ok:
                            return None
                        raise RepoGuessException(
                            f"Forced version {override_version_id} not found associated to TRS tool reachable through {putative_tool_uri}"
                        )

                else:
                    # Reuse the last version
                    trs_tool_meta = versions[-1]

                assert trs_tool_meta is not None

                trs_endpoint = urllib.parse.urlunparse(
                    urllib.parse.ParseResult(
                        scheme=parsed_putative_tool_uri.scheme,
                        netloc=parsed_putative_tool_uri.netloc,
                        path="/".join(parsed_putative_tool_uri.path.split("/")[0:-2])
                        + "/",
                        params="",
                        query="",
                        fragment="",
                    )
                )
                workflow_id = urllib.parse.unquote(
                    parsed_putative_tool_uri.path.split("/")[-1]
                )
                trs_tool_prefix = putative_tool_uri
                version_id = cast("Optional[WFVersionId]", trs_tool_meta.get("id"))
                name = trs_tool_meta.get("name")
                if version_id is not None:
                    # Dockstore misbehaves
                    if (
                        name is not None
                        and str(version_id).endswith(name)
                        and parsed_putative_tool_uri.netloc.endswith("dockstore.org")
                    ):
                        version_id = name
                    trs_tool_uri = cast(
                        "URIType",
                        trs_tool_prefix
                        + "/versions/"
                        + urllib.parse.quote(str(version_id), safe=""),
                    )
                elif fail_ok:
                    return None
                else:
                    raise RepoGuessException(
                        f"No version id found associated to specific version of TRS tool reachable through {putative_tool_uri}"
                    )
            # ... or a concrete one?
            elif "descriptor_type" in trs__meta:
                if override_version_id:
                    rpslash = putative_tool_uri.rfind("/")
                    putative_tool_uri = cast(
                        "URIType",
                        putative_tool_uri[0 : rpslash + 1]
                        + urllib.parse.quote(str(override_version_id), safe=""),
                    )
                    parsed_putative_tool_uri = urllib.parse.urlparse(putative_tool_uri)
                    # Time to try guessing everything
                    tool_wfexs_meta = {
                        "fetched": putative_tool_uri,
                        "payload": None,
                    }
                    metadata_array.append(URIWithMetadata(wf_url, tool_wfexs_meta))
                    try:
                        resio = io.BytesIO()
                        _, metaresio, _ = scheme_catalog.streamfetch(
                            putative_tool_uri,
                            resio,
                            sec_context={
                                "headers": {
                                    "Accept": "application/json",
                                    # Added to avoid Cloudflare anti-bot policy
                                    "User-Agent": get_WfExS_version_str(),
                                },
                            },
                        )
                        trs__meta = json.loads(resio.getvalue().decode("utf-8"))
                        tool_wfexs_meta["payload"] = trs__meta
                        metadata_array.extend(metaresio)
                    except Exception as e:
                        if fail_ok:
                            return None
                        raise RepoGuessException(
                            f"trs_endpoint could not be guessed from {putative_tool_uri} (forced version {override_version_id}, raised exception {e})"
                        ) from e

                    if "descriptor_type" not in trs__meta:
                        if fail_ok:
                            return None
                        raise RepoGuessException(
                            f"trs_endpoint at {putative_tool_uri} (forced version {override_version_id}) is not answering what it is expected"
                        )

                trs_tool_meta = trs__meta
                trs_endpoint = urllib.parse.urlunparse(
                    urllib.parse.ParseResult(
                        scheme=parsed_putative_tool_uri.scheme,
                        netloc=parsed_putative_tool_uri.netloc,
                        path="/".join(parsed_putative_tool_uri.path.split("/")[0:-4])
                        + "/",
                        params="",
                        query="",
                        fragment="",
                    )
                )
                trs_tool_prefix = cast(
                    "URIType",
                    urllib.parse.urlunparse(
                        urllib.parse.ParseResult(
                            scheme=parsed_putative_tool_uri.scheme,
                            netloc=parsed_putative_tool_uri.netloc,
                            path="/".join(
                                parsed_putative_tool_uri.path.split("/")[0:-2]
                            )
                            + "/",
                            params="",
                            query="",
                            fragment="",
                        )
                    ),
                )
                workflow_id = urllib.parse.unquote(
                    parsed_putative_tool_uri.path.split("/")[-3]
                )
                version_id = urllib.parse.unquote(
                    parsed_putative_tool_uri.path.split("/")[-1]
                )
                trs_tool_uri = putative_tool_uri
            elif fail_ok:
                return None
            else:
                raise RepoGuessException(
                    f"trs_endpoint at {putative_tool_uri} is not answering what it is expected"
                )

            parsed_trs_endpoint = urllib.parse.urlparse(trs_endpoint)
            trs_steps = parsed_trs_endpoint.path[0:-1].split("/")

        # Next two elifs should *never* happen
        elif fail_ok:
            return None
        else:
            raise RepoGuessException(
                f"trs_endpoint could not be guessed from {orig_wf_url} (no clues)"
            )

        # This is needed to guarantee it is always declared
        assert version_id is not None
        assert trs_tool_uri is not None
        if trs_tool_meta is None:
            trs_tool_wfexs_meta: "MutableMapping[str, Union[URIType, Optional[Mapping[str, Any]]]]" = {
                "fetched": trs_tool_uri,
                "payload": None,
            }
            metadata_array.append(URIWithMetadata(wf_url, trs_tool_wfexs_meta))
            try:
                resio = io.BytesIO()
                _, metaresio, _ = scheme_catalog.streamfetch(
                    trs_tool_uri,
                    resio,
                    sec_context={
                        "headers": {
                            "Accept": "application/json",
                            # Added to avoid Cloudflare anti-bot policy
                            "User-Agent": get_WfExS_version_str(),
                        },
                    },
                )
                trs_tool_meta = json.loads(resio.getvalue().decode("utf-8"))
                trs_tool_wfexs_meta["payload"] = trs_tool_meta
                metadata_array.extend(metaresio)
            except Exception as e:
                if fail_ok:
                    return None
                raise RepoGuessException(
                    f"trs_endpoint could not be guessed from {putative_tool_uri} (forced version {override_version_id}, raised exception {e})"
                ) from e

        assert trs_tool_meta is not None

        if not isinstance(trs_tool_meta.get("descriptor_type"), list):
            raise RepoGuessException(
                f"Unable to obtain descriptor_type from tool descriptor obtained from {putative_tool_uri}"
            )

        descriptor_types = trs_tool_meta["descriptor_type"]
        if len(descriptor_types) == 0:
            raise RepoGuessException(
                f"Empty list of descriptor_type from tool descriptor obtained from {putative_tool_uri}"
            )

        descriptor = descriptor_types[0]
        assert descriptor is not None
        if len(descriptor_types) > 1:
            logger.warning(
                f"Found {len(descriptor_types)} descriptor types for tool {putative_tool_uri}, using first ({descriptor})"
            )

        return (
            cast("RepoURL", trs_tool_uri),
            trs_service_netloc,
            trs_steps,
            workflow_id,
            version_id,
            descriptor,
            metadata_array,
            service_info_metadata,
        )

    @classmethod
    def GuessRepoParams(
        cls,
        orig_wf_url: "Union[URIType, parse.ParseResult]",
        logger: "Optional[logging.Logger]" = None,
        fail_ok: "bool" = False,
        offline: "bool" = False,
    ) -> "Optional[RemoteRepo]":
        trs_params = cls.GuessTRSParams(
            orig_wf_url, logger=logger, fail_ok=fail_ok, offline=offline
        )

        return (
            None
            if trs_params is None
            else RemoteRepo(
                repo_url=trs_params[0],
                tag=cast("RepoTag", trs_params[4]),
                repo_type=RepoType.TRS,
            )
        )

    @classmethod
    def BuildRepoPIDFromTRSParams(
        cls,
        trs_endpoint: "str",
        workflow_id: "WorkflowId",
        version_id: "Optional[WFVersionId]",
    ) -> "URIType":
        if isinstance(workflow_id, int):
            workflow_id_str = str(workflow_id)
        else:
            workflow_id_str = workflow_id

        # The base URL must end with a slash
        if trs_endpoint[-1] != "/":
            trs_endpoint += "/"

        # Removing the tools suffix, which appeared in first WfExS iterations
        if trs_endpoint.endswith("/" + cls.TRS_TOOLS_SUFFIX):
            trs_endpoint = trs_endpoint[0 : -len(cls.TRS_TOOLS_SUFFIX)]

        trs_tools_url = cast(
            "URIType",
            urllib.parse.urljoin(
                trs_endpoint,
                cls.TRS_TOOLS_SUFFIX + urllib.parse.quote(workflow_id_str, safe=""),
            ),
        )

        if version_id is not None:
            trs_tool_url = (
                trs_tools_url
                + "/versions/"
                + urllib.parse.quote(str(version_id), safe="")
            )
        else:
            trs_tool_url = trs_tools_url

        return cast("URIType", cls.INTERNAL_TRS_SCHEME_PREFIX + ":" + trs_tool_url)

    def materialize_repo_from_repo(
        self,
        repo: "RemoteRepo",
        repo_tag_destdir: "Optional[PathLikePath]" = None,
        base_repo_destdir: "Optional[PathLikePath]" = None,
        doUpdate: "Optional[bool]" = True,
    ) -> "MaterializedRepo":
        if repo.repo_type not in (RepoType.TRS, None):
            raise FetcherException(
                f"Remote repository {repo} is not of type TRS. Unable to fulfil request"
            )
        remote_file = repo.repo_url
        repoTag = repo.tag

        guessed_trs_params = self.GuessTRSParams(
            remote_file,
            logger=self.logger,
            scheme_catalog=self.scheme_catalog,
            override_version_id=repoTag,
        )
        if guessed_trs_params is None:
            raise FetcherException(f"Unable to guess TRS params from {repo}")

        (
            trs_tool_url,
            trs_service_netloc,
            trs_steps,
            workflow_id,
            version_id,
            descriptor,
            guessed_metadata_array,
            service_info_metadata,
        ) = guessed_trs_params
        files_metadata_url = (
            trs_tool_url
            + "/"
            + urllib.parse.quote(descriptor, safe="")
            + self.TRS_FILES_SUFFIX
        )
        descriptor_base_url = (
            trs_tool_url
            + "/"
            + urllib.parse.quote(descriptor, safe="")
            + self.TRS_DESCRIPTOR_INFIX
        )

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
                    b"" if version_id is None else str(version_id).encode("utf-8")
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
        metadata_array = [
            *guessed_metadata_array,
            URIWithMetadata(remote_file, topMeta),
        ]
        try:
            metaio = io.BytesIO()
            _, metametaio, _ = self.scheme_catalog.streamfetch(
                cast("URIType", files_metadata_url), metaio
            )
            metadata = json.loads(metaio.getvalue().decode("utf-8"))
            topMeta["payload"] = metadata
            metadata_array.extend(metametaio)
        except FetcherException as fe:
            raise FetcherException(
                "Error fetching or processing TRS files metadata for {} : {} {} (offending url {})".format(
                    remote_file, fe.code, fe.reason, files_metadata_url
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
        elif len(file_rel_2_url) == 1:
            # FIXME?: this is not going to work in Windows
            prefix_url = os.path.dirname(tuple(file_rel_2_url.values())[0])
        else:
            prefix_url = os.path.commonpath(tuple(file_rel_2_url.values()))

            # Due the peversion of commonpath, double slashes are collapsed
            colon_pos = prefix_url.find(":")
            if colon_pos > 0:
                prefix_url = (
                    prefix_url[0 : colon_pos + 1] + "/" + prefix_url[colon_pos + 1 :]
                )

        # We have to create anonymous directories to avoid leaving the download "sandbox"
        abs_download_dir = repo_tag_destpath
        if "/" in prefix_url:
            # This is needed to perform an effective work
            if not prefix_url.endswith("/"):
                prefix_url += "/"

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

        if service_info_metadata is None:
            parsed_trs_tool_url = urllib.parse.urlparse(trs_tool_url)
            trs_service_info = urllib.parse.urlunparse(
                urllib.parse.ParseResult(
                    scheme=parsed_trs_tool_url.scheme,
                    netloc=parsed_trs_tool_url.netloc,
                    path="/".join(parsed_trs_tool_url.path.split("/")[0:-4])
                    + "/service-info",
                    params="",
                    query="",
                    fragment="",
                )
            )

            service_info_wfexs_meta = {
                "fetched": trs_service_info,
                "payload": cast("Optional[Mapping[str, Any]]", None),
            }
            metadata_array.append(
                URIWithMetadata(trs_tool_url, service_info_wfexs_meta)
            )
            try:
                metaio = io.BytesIO()
                _, metametaio, _ = self.scheme_catalog.streamfetch(
                    cast("URIType", trs_service_info), metaio
                )
                service_info_metadata = json.loads(metaio.getvalue().decode("utf-8"))
                service_info_wfexs_meta["payload"] = service_info_metadata
                metadata_array.extend(metametaio)

            except Exception as e:
                raise FetcherException(
                    f"Unable to fetch service info metadata {trs_service_info} (affects tool {trs_tool_url})"
                ) from e

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
                tag=cast("RepoTag", str(version_id)),
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
        if remote_repo.repo_type is None and parsedInputURL.scheme in (
            self.INTERNAL_TRS_SCHEME_PREFIX,
            self.TRS_SCHEME_PREFIX,
        ):
            return remote_repo.repo_url
        elif remote_repo.repo_type == RepoType.TRS:
            try:
                guessed_trs_params = self.GuessTRSParams(
                    parsedInputURL,
                    override_version_id=remote_repo.tag,
                    logger=self.logger,
                    fail_ok=True,
                    offline=True,
                )
            except OfflineRepoGuessException as orge:
                self.logger.error(
                    f"While building pid for {remote_repo.repo_url} called code which should be safe offline"
                )
                guessed_trs_params = None

            if guessed_trs_params is not None:
                (
                    trs_tool_url,
                    trs_service_netloc,
                    trs_steps,
                    workflow_id,
                    version_id,
                    descriptor,
                    guessed_metadata_array,
                    service_info_metadata,
                ) = guessed_trs_params

                # Remove /ga4gh/trs/v2 from the end
                if (
                    len(trs_steps) >= 3
                    and trs_steps[-1] == "v2"
                    and trs_steps[-2] == "trs"
                    and trs_steps[-3] == "ga4gh"
                ):
                    trs_steps = trs_steps[0:-3]
                new_steps = [*trs_steps, urllib.parse.quote(str(workflow_id), safe="")]
                if version_id is not None:
                    new_steps.append(urllib.parse.quote(str(version_id), safe=""))

                computed_trs_endpoint = urllib.parse.urlunparse(
                    urllib.parse.ParseResult(
                        scheme=self.TRS_SCHEME_PREFIX,
                        netloc=trs_service_netloc,
                        path="/".join(new_steps),
                        params="",
                        query="",
                        fragment="",
                    )
                )

                return computed_trs_endpoint

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
