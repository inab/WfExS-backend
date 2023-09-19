#!/usr/bin/env python
# -*- coding: utf-8 -*-

# SPDX-License-Identifier: Apache-2.0
# Copyright 2020-2023 Barcelona Supercomputing Center (BSC), Spain
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

import atexit
import hashlib
import io
import json
import os
import shutil
import tarfile
import tempfile
import time
from typing import (
    cast,
    TYPE_CHECKING,
)
from urllib import parse

if TYPE_CHECKING:
    import logging

    from typing import (
        Any,
        IO,
        Mapping,
        MutableSequence,
        Optional,
        Sequence,
        Tuple,
        Type,
        Union,
    )

    from typing_extensions import (
        Final,
    )

    from . import (
        RepoDesc,
    )

    from ..common import (
        AbsPath,
        AnyPath,
        ProgsMapping,
        RelPath,
        RepoTag,
        RepoURL,
        SecurityContextConfig,
        SymbolicName,
        URIType,
    )

from . import (
    AbstractRepoFetcher,
    FetcherException,
    ProtocolFetcherReturn,
    RepoGuessException,
)

from .http import fetchClassicURL

from ..common import (
    ContentKind,
    RemoteRepo,
    RepoType,
    URIWithMetadata,
)

from ..utils.contents import link_or_copy


class SoftwareHeritageFetcher(AbstractRepoFetcher):
    SOFTWARE_HERITAGE_SCHEME: "Final[str]" = "swh"
    SWH_API_REST: "Final[str]" = "https://archive.softwareheritage.org/api/1/"
    SWH_API_REST_KNOWN: "Final[URIType]" = cast(
        "URIType", parse.urljoin(SWH_API_REST, "known/")
    )
    SWH_API_REST_RESOLVE: "Final[str]" = parse.urljoin(SWH_API_REST, "resolve/")
    SWH_API_REST_RELEASE: "Final[str]" = parse.urljoin(SWH_API_REST, "release/")
    SWH_API_REST_REVISION: "Final[str]" = parse.urljoin(SWH_API_REST, "revision/")
    SWH_API_REST_VAULT_FLAT: "Final[str]" = parse.urljoin(SWH_API_REST, "vault/flat/")
    SWH_API_REST_CONTENT: "Final[str]" = parse.urljoin(SWH_API_REST, "content/")

    DIR_RETRIES: "Final[int]" = 60
    WAIT_SECS: "Final[int]" = 60

    @classmethod
    def GetSchemeHandlers(cls) -> "Mapping[str, Type[AbstractRepoFetcher]]":
        # These are de-facto schemes supported by Software Heritage
        # libraries and other implementations
        return {
            cls.SOFTWARE_HERITAGE_SCHEME: cls,
        }

    @property
    def description(self) -> "str":
        return "Permanent identifiers of files, directories and repos at SoftwareHeritage. These URIs follow what it is described at https://docs.softwareheritage.org/devel/swh-model/persistent-identifiers.html"

    @classmethod
    def GetNeededPrograms(cls) -> "Sequence[SymbolicName]":
        return tuple()

    def doMaterializeRepo(
        self,
        repoURL: "RepoURL",
        repoTag: "Optional[RepoTag]" = None,
        repo_tag_destdir: "Optional[AbsPath]" = None,
        base_repo_destdir: "Optional[AbsPath]" = None,
        doUpdate: "Optional[bool]" = True,
    ) -> "Tuple[AbsPath, RepoDesc, Sequence[URIWithMetadata]]":
        # If we are here is because the repo is valid
        # as it should have been checked by guess_swh_repo_params

        # ## Use the resolver, see https://archive.softwareheritage.org/api/1/resolve/doc/
        # curl -H "Accept: application/json" https://archive.softwareheritage.org/api/1/resolve/swh:1:rev:31348ed533961f84cf348bf1af660ad9de6f870c/
        # The service does not work with quoted identifiers, neither with
        # fully unquoted identifiers. Only the semicolons have to be
        # substituted
        res_doc, metadata_array = resolve_swh_id(repoURL)

        # Error handling
        if "exception" in res_doc:
            raise FetcherException(f"{repoURL} is not valid. Message: {res_doc}")

        # Now, handling the cases
        object_type = res_doc["object_type"]
        object_id = res_doc["object_id"]

        # Early detection in order to get the checkout context
        if object_type == "content":
            anchor = res_doc.get("metadata", {}).get("anchor")
            if anchor is not None:
                anc_res_doc, anchor_metadata_array = resolve_swh_id(anchor)
                metadata_array.extend(anchor_metadata_array)

                # Now, truly yes the context
                object_type = anc_res_doc["object_type"]
                object_id = anc_res_doc["object_id"]

        if object_type == "snapshot":
            # ## As a snapshot contains all the branches in form of swhid release, it is improbable
            # ## that this is going to be used to fetch all the branches at once. So, refuse to use it.
            raise FetcherException(f"{repoURL} is a snapshot, which is not supported")

        object_uri = None
        if object_type == "release":
            # ## See https://archive.softwareheritage.org/api/1/release/doc/
            # curl -H "Accept: application/json" https://archive.softwareheritage.org/api/1/release/22ece559cc7cc2364edc5e5593d63ae8bd229f9f/

            try:
                relio = io.BytesIO()
                release_uri = cast(
                    "URIType",
                    parse.urljoin(
                        self.SWH_API_REST_RELEASE,
                        object_id + "/",
                    ),
                )
                _, metarelio, _ = fetchClassicURL(
                    release_uri,
                    relio,
                    secContext={
                        "headers": {
                            "Accept": "application/json",
                        },
                    },
                )
                rel_doc = json.loads(relio.getvalue().decode("utf-8"))
            except Exception as e:
                raise FetcherException(f"HTTP REST call {release_uri} failed") from e
            gathered_meta = {
                "fetched": release_uri,
                "payload": rel_doc,
            }
            metadata_array.append(URIWithMetadata(repoURL, gathered_meta))
            metadata_array.extend(metarelio)

            # ## Extract content needed from answer in order to process the target_type: either as a release, revision, content or directory
            # ## target_url points to the right URL to be used next, and target contains the bare id
            object_type = rel_doc["target_type"]
            object_id = rel_doc["target"]
            object_uri = rel_doc["target_url"]

        if object_type == "revision":
            # ## See https://archive.softwareheritage.org/api/1/revision/doc/
            # curl -H "Accept: application/json" https://archive.softwareheritage.org/api/1/revision/31348ed533961f84cf348bf1af660ad9de6f870c/

            if object_uri is not None:
                revision_uri = object_uri
                object_uri = None
            else:
                revision_uri = parse.urljoin(
                    self.SWH_API_REST_REVISION,
                    object_id + "/",
                )
            try:
                revio = io.BytesIO()
                _, metarevio, _ = fetchClassicURL(
                    cast("URIType", revision_uri),
                    revio,
                    secContext={
                        "headers": {
                            "Accept": "application/json",
                        },
                    },
                )
                rev_doc = json.loads(revio.getvalue().decode("utf-8"))
            except Exception as e:
                raise FetcherException(f"HTTP REST call {revision_uri} failed") from e
            gathered_meta = {
                "fetched": revision_uri,
                "payload": rev_doc,
            }
            metadata_array.append(URIWithMetadata(repoURL, gathered_meta))
            metadata_array.extend(metarevio)

            # ## Prepare swh:1:dir identifier from the answer of the revision API call
            object_type = "directory"
            object_id = rev_doc["directory"]
            # As directory_url points to the list instead of the vault
            # url, we are leaving this empty
            object_uri = None

        if object_type == "directory":
            # ## Prepare swh:1:dir identifier from the answer
            # ## See https://archive.softwareheritage.org/api/1/vault/flat/doc/
            # curl -H "Accept: application/json" -X POST https://archive.softwareheritage.org/api/1/vault/flat/swh:1:dir:193ea87c2bc5f08967c456056b9f5475a1b91481/
            repo_effective_checkout = (
                self.SOFTWARE_HERITAGE_SCHEME + ":1:dir:" + object_id
            )

            if object_uri is not None:
                directory_url = object_uri
            else:
                directory_url = (
                    self.SWH_API_REST_VAULT_FLAT + repo_effective_checkout + "/"
                )

            http_method = "POST"
            status = None
            dir_doc = {}
            for retry in range(self.DIR_RETRIES):
                if status in ("failed", "done"):
                    break

                if http_method == "GET":
                    # TODO: set up a smarter sleep?
                    time.sleep(self.WAIT_SECS)
                try:
                    dirio = io.BytesIO()
                    _, metadirio, _ = fetchClassicURL(
                        cast("URIType", directory_url),
                        dirio,
                        secContext={
                            "headers": {
                                "Accept": "application/json",
                            },
                            "method": http_method,
                        },
                    )
                    dir_doc = json.loads(dirio.getvalue().decode("utf-8"))
                except Exception as e:
                    raise FetcherException(
                        f"HTTP REST call {directory_url} failed"
                    ) from e
                # It could be a valid swh identifier, but it is not registered
                if not isinstance(dir_doc, dict):
                    raise FetcherException(
                        f"Ill-formed answer obtained from {directory_url}"
                    )

                gathered_meta = {
                    "fetched": directory_url,
                    "payload": dir_doc,
                }
                metadata_array.append(URIWithMetadata(repoURL, gathered_meta))
                metadata_array.extend(metadirio)

                status = dir_doc["status"]
                http_method = "GET"

            if status == "failed":
                # Unable to obtain the bundle
                raise FetcherException("")

            if status == "done":
                # ## Get fetch_url property
                # ## See https://archive.softwareheritage.org/api/1/vault/flat/raw/doc/
                # curl -O targz https://archive.softwareheritage.org/api/1/vault/flat/swh:1:dir:193ea87c2bc5f08967c456056b9f5475a1b91481/raw/
                # tar xf targz
                dir_fetch_url = cast("URIType", dir_doc["fetch_url"])

                with tempfile.NamedTemporaryFile() as tmp_targz_filename:
                    try:
                        _, metafetchio, _ = fetchClassicURL(
                            dir_fetch_url,
                            cast("AbsPath", tmp_targz_filename.name),
                        )
                    except Exception as e:
                        raise FetcherException(
                            f"HTTP REST call {dir_fetch_url} failed"
                        ) from e

                    gathered_meta = {
                        "fetched": dir_fetch_url,
                    }
                    metadata_array.append(URIWithMetadata(repoURL, gathered_meta))
                    metadata_array.extend(metadirio)

                    # Assure directory exists before next step
                    if repo_tag_destdir is None:
                        if base_repo_destdir is None:
                            repo_tag_destdir = cast(
                                "AbsPath",
                                tempfile.mkdtemp(prefix="wfexs", suffix=".swh"),
                            )
                            atexit.register(shutil.rmtree, repo_tag_destdir)
                        else:
                            repo_hashed_id = hashlib.sha1(
                                repoURL.encode("utf-8")
                            ).hexdigest()
                            repo_destdir = os.path.join(
                                base_repo_destdir, repo_hashed_id
                            )
                            # repo_destdir = os.path.join(self.cacheWorkflowDir, repo_hashed_id)

                            if not os.path.exists(repo_destdir):
                                try:
                                    os.makedirs(repo_destdir)
                                except IOError:
                                    errstr = "ERROR: Unable to create intermediate directories for repo {}. ".format(
                                        repoURL
                                    )
                                    raise FetcherException(errstr)

                            repo_hashed_tag_id = hashlib.sha1(
                                b"" if repoTag is None else repoTag.encode("utf-8")
                            ).hexdigest()
                            repo_tag_destdir = cast(
                                "AbsPath",
                                os.path.join(repo_destdir, repo_hashed_tag_id),
                            )

                    # These steps are needed because the bundle has its contents in the parent
                    extract_dir = tempfile.mkdtemp(prefix="wfexs", suffix=".swh")
                    atexit.register(shutil.rmtree, extract_dir)
                    with tarfile.open(
                        tmp_targz_filename.name, mode="r|*", bufsize=10 * 1024 * 1024
                    ) as tF:
                        tF.extractall(path=extract_dir)
                    # The directory has as name the swhid
                    extract_dir_dir = os.path.join(extract_dir, repo_effective_checkout)
                    if os.path.exists(extract_dir_dir):
                        extract_dir = extract_dir_dir
                    link_or_copy(cast("AbsPath", extract_dir), repo_tag_destdir)
            else:
                raise FetcherException(
                    f"For {repoURL}, Software Heritage directory {directory_url} is not ready after {self.DIR_RETRIES}, waiting {self.WAIT_SECS} seconds on each"
                )

        elif object_type == "content":
            # ## Prepare sha1_git: identifier from the answer
            # ## See https://archive.softwareheritage.org/api/1/content/doc/
            # curl https://archive.softwareheritage.org/api/1/content/sha1_git:f10371aa7b8ccabca8479196d6cd640676fd4a04/

            repo_effective_checkout = (
                self.SOFTWARE_HERITAGE_SCHEME + ":1:cnt:" + object_id
            )

            if object_uri is not None:
                content_url = object_uri
            else:
                content_url = self.SWH_API_REST_CONTENT + "sha1_git:" + object_id + "/"

            try:
                contentio = io.BytesIO()
                _, metacontentio, _ = fetchClassicURL(
                    cast("URIType", content_url),
                    contentio,
                    secContext={
                        "headers": {
                            "Accept": "application/json",
                        },
                    },
                )
                content_doc = json.loads(contentio.getvalue().decode("utf-8"))
            except Exception as e:
                raise FetcherException(f"HTTP REST call {content_url} failed") from e
            # It could be a valid swh identifier, but it is not registered
            if not isinstance(content_doc, dict):
                raise FetcherException(f"Ill-formed answer obtained from {content_url}")

            gathered_meta = {
                "fetched": content_url,
                "payload": content_doc,
            }
            metadata_array.append(URIWithMetadata(repoURL, gathered_meta))
            metadata_array.extend(metacontentio)

            # ## Get data_url property
            # ## See https://archive.softwareheritage.org/api/1/content/raw/doc/
            # curl https://archive.softwareheritage.org/api/1/content/sha1_git:f10371aa7b8ccabca8479196d6cd640676fd4a04/raw/
            content_fetch_url = cast("URIType", content_doc["data_url"])

            # Assure base directory exists before next step
            # here repo_tag_destdir is a file
            repo_tag_destfile: "Union[AbsPath, IO[bytes]]"
            if repo_tag_destdir is None:
                if base_repo_destdir is None:
                    temp_file_descriptor, repo_tag_destdir = cast(
                        "Tuple[int, AbsPath]",
                        tempfile.mkstemp(prefix="wfexs", suffix=".swh"),
                    )
                    repo_tag_destfile = os.fdopen(temp_file_descriptor, mode="wb")
                    atexit.register(os.unlink, repo_tag_destdir)
                else:
                    repo_hashed_id = hashlib.sha1(repoURL.encode("utf-8")).hexdigest()
                    repo_destdir = os.path.join(base_repo_destdir, repo_hashed_id)
                    # repo_destdir = os.path.join(self.cacheWorkflowDir, repo_hashed_id)

                    if not os.path.exists(repo_destdir):
                        try:
                            os.makedirs(repo_destdir)
                        except IOError:
                            errstr = "ERROR: Unable to create intermediate directories for repo {}. ".format(
                                repoURL
                            )
                            raise FetcherException(errstr)

                    repo_hashed_tag_id = hashlib.sha1(
                        b"" if repoTag is None else repoTag.encode("utf-8")
                    ).hexdigest()
                    repo_tag_destdir = cast(
                        "AbsPath", os.path.join(repo_destdir, repo_hashed_tag_id)
                    )
                    repo_tag_destfile = repo_tag_destdir
            else:
                repo_tag_destfile = repo_tag_destdir

            try:
                _, metafetchio, _ = fetchClassicURL(
                    content_fetch_url,
                    repo_tag_destfile,
                )
            except Exception as e:
                raise FetcherException(
                    f"HTTP REST call {content_fetch_url} failed"
                ) from e
            finally:
                if not isinstance(repo_tag_destfile, str):
                    repo_tag_destfile.close()

            gathered_meta = {
                "fetched": content_fetch_url,
            }
            metadata_array.append(URIWithMetadata(repoURL, gathered_meta))
            metadata_array.extend(metafetchio)
        else:
            raise FetcherException(
                f"Unexpected Software Heritage object type {object_type} for {repoURL}"
            )

        repo_desc: "RepoDesc" = {
            "repo": repoURL,
            "tag": repoTag,
            "checkout": cast("RepoTag", repo_effective_checkout),
        }

        return (
            repo_tag_destdir,
            repo_desc,
            metadata_array,
        )

    def fetch(
        self,
        remote_file: "URIType",
        cachedFilename: "AbsPath",
        secContext: "Optional[SecurityContextConfig]" = None,
    ) -> "ProtocolFetcherReturn":
        parsedInputURL = parse.urlparse(remote_file)

        # These are the usual URIs which can be understood by pip
        # See https://pip.pypa.io/en/stable/cli/pip_install/#git
        if parsedInputURL.scheme not in self.GetSchemeHandlers():
            raise FetcherException(f"FIXME: Unhandled scheme {parsedInputURL.scheme}")

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
        repo_tag_destdir, repo_desc, metadata_array = self.doMaterializeRepo(
            cast("RepoURL", remote_file)
        )

        preferredName: "Optional[RelPath]"
        # repoRelPath is only acknowledged when the resolved repo
        # is translated to a directory
        if repoRelPath is not None and os.path.isdir(repo_tag_destdir):
            cachedContentPath = os.path.join(repo_tag_destdir, repoRelPath)
            preferredName = cast("RelPath", repoRelPath.split("/")[-1])
        else:
            cachedContentPath = repo_tag_destdir
            preferredName = None
            # This is to remove spurious detections
            repoRelPath = None

        repo_desc["relpath"] = cast("RelPath", repoRelPath)

        if os.path.isdir(cachedContentPath):
            kind = ContentKind.Directory
        elif os.path.isfile(cachedContentPath):
            kind = ContentKind.File
        else:
            raise FetcherException(
                f"Remote {remote_file} is neither a file nor a directory (does it exist?)"
            )

        # shutil.move(cachedContentPath, cachedFilename)
        link_or_copy(cast("AnyPath", cachedContentPath), cachedFilename)

        augmented_metadata_array = [
            URIWithMetadata(
                uri=remote_file, metadata=repo_desc, preferredName=preferredName
            ),
            *metadata_array,
        ]
        return ProtocolFetcherReturn(
            kind_or_resolved=kind,
            metadata_array=augmented_metadata_array,
            # TODO: Integrate licences from swh report??
            licences=None,
        )


def resolve_swh_id(
    the_id: "URIType",
) -> "Tuple[Mapping[str, Any], MutableSequence[URIWithMetadata]]":
    # ## Use the resolver, see https://archive.softwareheritage.org/api/1/resolve/doc/
    # curl -H "Accept: application/json" https://archive.softwareheritage.org/api/1/resolve/swh:1:rev:31348ed533961f84cf348bf1af660ad9de6f870c/
    # The service does not work with quoted identifiers, neither with
    # fully unquoted identifiers. Only the semicolons have to be
    # substituted
    swh_quoted_id = the_id.replace(";", parse.quote(";"))
    resio = io.BytesIO()
    # urljoin cannot be used due working with URIs
    resolve_uri = cast(
        "URIType", SoftwareHeritageFetcher.SWH_API_REST_RESOLVE + swh_quoted_id + "/"
    )
    try:
        _, metaresio, _ = fetchClassicURL(
            resolve_uri,
            resio,
            secContext={
                "headers": {
                    "Accept": "application/json",
                },
            },
        )
        res_doc = json.loads(resio.getvalue().decode("utf-8"))
    except Exception as e:
        raise FetcherException(f"HTTP REST call {resolve_uri} failed") from e

    if not isinstance(res_doc, dict):
        raise FetcherException(f"{the_id} is not valid. Message: {res_doc}")

    gathered_meta = {
        "fetched": resolve_uri,
        "payload": res_doc,
    }
    metadata_array = [
        URIWithMetadata(
            uri=the_id,
            metadata=gathered_meta,
        )
    ]
    metadata_array.extend(metaresio)

    return res_doc, metadata_array


def guess_swh_repo_params(
    orig_wf_url: "Union[URIType, parse.ParseResult]",
    logger: "logging.Logger",
    fail_ok: "bool" = False,
) -> "Optional[RemoteRepo]":
    # Deciding which is the input
    wf_url: "RepoURL"
    parsed_wf_url: "parse.ParseResult"
    if isinstance(orig_wf_url, parse.ParseResult):
        parsed_wf_url = orig_wf_url
        wf_url = cast("RepoURL", parse.urlunparse(orig_wf_url))
    else:
        wf_url = cast("RepoURL", orig_wf_url)
        parsed_wf_url = parse.urlparse(orig_wf_url)

    if parsed_wf_url.scheme not in SoftwareHeritageFetcher.GetSchemeHandlers():
        return None

    # ## Check against Software Heritage the validity of the id
    # echo '["swh:1:rev:31348ed533961f84cf348bf1af660ad9de6f870c"]' | curl -H "Content-Type: application/json" -T - -X POST https://archive.softwareheritage.org/api/1/known/
    putative_core_swhid = wf_url.split(";", 1)[0]
    try:
        valio = io.BytesIO()
        _, metavalio, _ = fetchClassicURL(
            SoftwareHeritageFetcher.SWH_API_REST_KNOWN,
            valio,
            secContext={
                "headers": {
                    "Content-Type": "application/json",
                },
                "method": "POST",
                # Only core SWHids are accepted
                "data": json.dumps([putative_core_swhid]).encode("utf-8"),
            },
        )
        val_doc = json.loads(valio.getvalue().decode("utf-8"))
    except Exception as e:
        if fail_ok:
            return None
        raise

    # It could be a valid swh identifier, but it is not registered
    if not isinstance(val_doc, dict) or not val_doc.get(putative_core_swhid, {}).get(
        "known", False
    ):
        return None

    # Now we are sure it is known, let's learn the web url to browse it
    resolved_payload, _ = resolve_swh_id(wf_url)
    web_url = resolved_payload["browse_url"]
    return RemoteRepo(
        repo_url=wf_url,
        tag=cast("RepoTag", putative_core_swhid),
        repo_type=RepoType.SoftwareHeritage,
        web_url=web_url,
    )
