#!/usr/bin/env python3
#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Copyright 2020-2022 Barcelona Supercomputing Center (BSC), Spain
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
        MutableMapping,
        Optional,
        Tuple,
    )

    from typing_extensions import Final

    from dxf import DXFBase

from dxf import (
    DXF,
    _schema2_mimetype as DockerManifestV2MIMEType,
    _schema2_list_mimetype as DockerFAT_schema2_mimetype,
)

# Needed for proper error handling
import requests


class DockerHelperException(Exception):
    pass


class Credentials(NamedTuple):
    domain: "Optional[str]" = None
    username: "Optional[str]" = None
    password: "Optional[str]" = None


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
            if he.response.status_code != 404:
                raise he

            headersV2 = {"Accept": DockerManifestV2MIMEType}
            r = self._request(http_method, "manifests/" + alias, headers=headersV2)  # type: ignore[no-untyped-call]

        return r.content.decode("utf-8"), r

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

    def _get_fat_dcd(self, alias: "str") -> "Optional[str]":
        """
        Get the Docker-Content-Digest header for the "fat manifest"
        of an alias.

        :param alias: Alias name.
        :type alias: str

        :rtype: str
        :returns: DCD header for the alias.
        """
        # https://docs.docker.com/registry/spec/api/#deleting-an-image
        # Note When deleting a manifest from a registry version 2.3 or later,
        # the following header must be used when HEAD or GET-ing the manifest
        # to obtain the correct digest to delete:
        # Accept: application/vnd.docker.distribution.manifest.v2+json
        _, fat_dcd = self.get_fat_manifest_and_dcd(alias, http_method="head")
        return fat_dcd

    def get_fingerprint(self, alias: "str") -> "Optional[str]":
        dcd: "Optional[str]"
        _, dcd = self._get_alias(alias, manifest=None, verify=True, sizes=False, get_digest=False, get_dcd=True)  # type: ignore[no-untyped-call]
        return dcd


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

    def query_tag(self, tag: "str") -> "Tuple[str, str, str, Optional[str]]":
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
            manifest_str, partial_fingerprint = dxffat.get_fat_manifest_and_dcd(alias)
            manifest = json.loads(manifest_str)
            if manifest.get("schemaVersion", 1) == 1:
                partial_fingerprint = dxffat.get_fingerprint(alias)
        except Exception as e:
            raise DockerHelperException(
                f"Unable to obtain fingerprint from {tag}. Reason {e}"
            )

        return registryServer, repo, alias, partial_fingerprint

        # print(dxf.list_aliases())
        #
        # dxfq = DXF('quay.io', 'biocontainers/samtools', auth)
        #
        # print(dxfq.list_aliases())
