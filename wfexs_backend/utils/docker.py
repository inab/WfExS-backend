#!/usr/bin/env python3
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

import abc
import json
import logging
from typing import (
    cast,
    NamedTuple,
    TYPE_CHECKING,
)
import urllib.parse

if TYPE_CHECKING:
    from typing import (
        Any,
        Union,
        Mapping,
        MutableMapping,
        Optional,
        Tuple,
    )

    from typing_extensions import Final

    from dxf import DXFBase

from dxf import (
    DXF,
    _verify_manifest,
    hash_bytes as dxf_hash_bytes,
    _schema2_mimetype as DockerManifestV2MIMEType,
    _schema2_list_mimetype as DockerFAT_schema2_mimetype,
)

import dxf.exceptions

# Needed for proper error handling
import requests


class DockerHelperException(Exception):
    pass


class Credentials(NamedTuple):
    domain: "Optional[str]" = None
    username: "Optional[str]" = None
    password: "Optional[str]" = None


class DockerTagMetadata(NamedTuple):
    registryServer: "str"
    repo: "str"
    alias: "str"
    manifest: "Mapping[str, Any]"
    partial_fingerprint: "str"


# This is needed to obtain the remote repo digest
class DXFFat(DXF):
    # See https://docs.docker.com/registry/spec/manifest-v2-2/ for
    # "fat" manifest description

    def get_fat_manifest_and_response(
        self, alias: "str", http_method: "str" = "get"
    ) -> "Tuple[str, requests.Response]":
        """
        Request the "fat" manifest for an alias, which returns the list
        of all the available architectures, and returns the manifest and
        the response.

        :param alias: Alias name.
        :type alias: str

        :rtype: tuple
        :returns: Tuple containing the "fat" manifest as a string (JSON)
        and the `requests.Response <http://docs.python-requests.org/en/master/api/#requests.Response>`_
        """
        r: "requests.Response"
        try:
            headersFATV2 = {"Accept": DockerFAT_schema2_mimetype}
            r = self._request(http_method, "manifests/" + alias, headers=headersFATV2)  # type: ignore[no-untyped-call]
        except requests.exceptions.HTTPError as he:
            if he.response is None or he.response.status_code != 404:
                raise he

            headersV2 = {"Accept": DockerManifestV2MIMEType}
            r = self._request(http_method, "manifests/" + alias, headers=headersV2)  # type: ignore[no-untyped-call]

        return r.content.decode("utf-8"), r

    def get_parsed_manifest_and_dcd(
        self, alias: "str"
    ) -> "Union[Tuple[Mapping[str, Any], str], Tuple[None, None]]":
        # Based on  DXF._get_alias
        # https://github.com/davedoesdev/dxf/blob/89d4c9bafd75f0fbc028b3f83c0e10350505cd32/dxf/__init__.py#L616-L679
        try:
            manifest, r = self.get_manifest_and_response(alias)
        except requests.exceptions.HTTPError as he:
            if he.response is None or he.response.status_code != 404:
                raise he

            return None, None

        content = r.content
        parsed_manifest = json.loads(manifest)

        if parsed_manifest["schemaVersion"] == 1:
            # https://github.com/docker/distribution/issues/1662#issuecomment-213101772
            # "A schema1 manifest should always produce the same image id but
            # defining the steps to produce directly from the manifest is not
            # straight forward."
            dcd_h = r.headers.get("Docker-Content-Digest")
            _, dcd = _verify_manifest(  # type: ignore[no-untyped-call]
                manifest,
                parsed_manifest,
                content_digest=dcd_h,
                verify=False,
                get_content_digest=True,
            )
            assert dcd is not None, f"Empty dcd for {alias}"
        else:
            dcd = dxf_hash_bytes(manifest.encode("utf8"))

        return parsed_manifest, dcd

    def get_fat_manifest_and_dcd(
        self, alias: "str", http_method: "str" = "get"
    ) -> "Tuple[str, Optional[str]]":
        """
        Request the "fat" manifest for an alias, which returns the list
        of all the available architectures, and returns the manifest and
        the response.

        :param alias: Alias name.
        :type alias: str

        :rtype: tuple
        :returns: Tuple containing the "fat" manifest as a string (JSON)
        and the dcd
        """
        fat_manifest, r = self.get_fat_manifest_and_response(
            alias, http_method=http_method
        )
        return fat_manifest, r.headers.get("Docker-Content-Digest")

    def get_fat_manifest(self, alias: "str") -> "str":
        """
        Get the "fat" manifest for an alias

        :param alias: Alias name.
        :type alias: str

        :rtype: str
        :returns: The "fat" manifest as string (JSON)
        """
        fat_manifest, _ = self.get_fat_manifest_and_response(alias)
        return fat_manifest


class DockerHelper(abc.ABC):
    DEFAULT_DOCKER_REGISTRY: "Final[str]" = "docker.io"
    DOCKER_REGISTRY: "Final[str]" = "registry-1.docker.io"

    DEFAULT_ALIAS: "Final[str]" = "latest"

    def __init__(self) -> None:
        self.logger = logging.getLogger(self.__class__.__name__)
        # Default credentials are no credentials
        self.creds: "MutableMapping[Optional[str], Credentials]" = {
            None: Credentials(None, None, None)
        }

        # These credentials are used only when querying
        self.choose_domain()

    def add_creds(
        self, username: "str", password: "str", domain: "Optional[str]" = None
    ) -> None:
        self.creds[domain] = Credentials(
            domain=domain, username=username, password=password
        )

    def choose_domain(self, domain_name: "Optional[str]" = None) -> None:
        if domain_name not in self.creds:
            domain_name = None

        self.domain = self.creds[domain_name]

    def _auth(self, dxf: "DXFBase", response: "requests.Response") -> None:
        """Helper method for DXF machinery"""

        dxf.authenticate(
            self.domain.username,
            self.domain.password,
            actions=["pull"],
            response=response,
        )

    def query_tag(self, tag: "str") -> "Optional[DockerTagMetadata]":
        parsedTag = urllib.parse.urlparse(tag)
        if parsedTag.scheme == "":
            docker_tag = "docker://" + tag
            parsedTag = urllib.parse.urlparse(docker_tag)
        elif parsedTag.scheme not in ("http", "https", "ftp", "docker"):
            docker_tag = f"docker://{self.DEFAULT_DOCKER_REGISTRY}/{tag}"
            parsedTag = urllib.parse.urlparse(docker_tag)
        else:
            self.logger.debug(f"Parsed as {parsedTag}")
            docker_tag = tag

        if parsedTag.scheme != "docker":
            raise DockerHelperException(f"Unable to parse {tag} as a Docker tag")

        # Deciding the partial repo and alias
        if parsedTag.path == "":
            pathToParse = parsedTag.netloc
        else:
            pathToParse = parsedTag.netloc + parsedTag.path

        splitSep = "@sha256:"
        splitPos = pathToParse.find(splitSep)
        if splitPos == -1:
            splitSep = ":"
            splitPos = pathToParse.find(splitSep)

        if splitPos != -1:
            repo = pathToParse[0:splitPos]
            alias = pathToParse[splitPos + len(splitSep) :]
        else:
            repo = pathToParse
            alias = self.DEFAULT_ALIAS

        # Deciding the registry server and finishing adjustment of repo
        registry = None
        if "." not in repo:
            registry = self.DEFAULT_DOCKER_REGISTRY
        else:
            if repo[0] == "/":
                repo = repo[1:]

            if "/" in repo:
                registry, repo = repo.split("/", 1)
            else:
                # FIXME!!!!
                registry = self.DEFAULT_DOCKER_REGISTRY

        # Last repo adjustment, in case it is a 'library' one
        if "/" not in repo:
            repo = "library/" + repo

        registryServer = registry
        if registry == self.DEFAULT_DOCKER_REGISTRY:
            registryServer = self.DOCKER_REGISTRY

        # Connecting to the registry
        dxffat = DXFFat(registryServer, repo, self._auth)

        try:
            # This is needed for the cases of compatibility "FAT" manifest
            manifest, partial_fingerprint = dxffat.get_parsed_manifest_and_dcd(alias)
            if manifest is None:
                return None

            assert partial_fingerprint is not None
        except Exception as e:
            raise DockerHelperException(
                f"Unable to obtain fingerprint from {tag}. Reason {e}"
            ) from e

        return DockerTagMetadata(
            registryServer=registryServer,
            repo=repo,
            alias=alias,
            manifest=manifest,
            partial_fingerprint=partial_fingerprint,
        )

        # print(dxf.list_aliases())
        #
        # dxfq = DXF('quay.io', 'biocontainers/samtools', auth)
        #
        # print(dxfq.list_aliases())
