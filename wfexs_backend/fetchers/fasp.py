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

import os
import subprocess
import tempfile
from typing import (
    cast,
    TYPE_CHECKING,
)

if TYPE_CHECKING:
    from typing import (
        Any,
        Mapping,
        Optional,
        Sequence,
        Type,
    )

    from typing_extensions import Final

    from ..common import (
        AbsPath,
        PathLikePath,
        ProgsMapping,
        RelPath,
        SecurityContextConfig,
        SymbolicName,
        URIType,
    )

    from ..scheme_catalog import (
        SchemeCatalog,
    )

from . import (
    AbstractStatefulFetcher,
    DocumentedStatefulProtocolFetcher,
    FetcherException,
    ProtocolFetcherReturn,
)

from ..common import (
    ContentKind,
    URIWithMetadata,
)


class FASPFetcher(AbstractStatefulFetcher):
    FASP_PROTO: "Final[str]" = "fasp"
    DEFAULT_LIMIT_THROUGHPUT: "Final[str]" = "100m"
    DEFAULT_ASPERA_CMD: "Final[SymbolicName]" = cast("SymbolicName", "ascp")

    def __init__(
        self,
        progs: "ProgsMapping",
        setup_block: "Optional[Mapping[str, Any]]" = None,
        scheme_catalog: "Optional[SchemeCatalog]" = None,
    ):
        super().__init__(
            progs=progs, setup_block=setup_block, scheme_catalog=scheme_catalog
        )

        self.ascp_cmd = self.progs.get(
            self.DEFAULT_ASPERA_CMD, cast("RelPath", self.DEFAULT_ASPERA_CMD)
        )
        self.limit_throughput = self.setup_block.get(
            "limit-throughput", self.DEFAULT_LIMIT_THROUGHPUT
        )

    @classmethod
    def GetSchemeHandlers(cls) -> "Mapping[str, DocumentedStatefulProtocolFetcher]":
        # These are de-facto schemes supported by pip and git client
        return {
            cls.FASP_PROTO: DocumentedStatefulProtocolFetcher(
                fetcher_class=cls,
                priority=cls.PRIORITY,
            ),
        }

    @classmethod
    def GetNeededPrograms(cls) -> "Sequence[SymbolicName]":
        return (cls.DEFAULT_ASPERA_CMD,)

    @property
    def description(self) -> "str":
        return "This pseudo-scheme, which mimics ssh scheme, represents datasets behind IBM Aspera servers (quite common in life sciences infrastructures), which follow FASP protocol. Materialization of these datasets are delegated to ascp command line"

    def fetch(
        self,
        remote_file: "URIType",
        cachedFilename: "PathLikePath",
        secContext: "Optional[SecurityContextConfig]" = None,
    ) -> "ProtocolFetcherReturn":
        # Sanitizing possible ill-formed inputs
        if not isinstance(secContext, dict):
            secContext = {}

        orig_remote_file = remote_file
        parsedInputURL, remote_file = self.ParseAndRemoveCredentials(orig_remote_file)
        if parsedInputURL.scheme != self.FASP_PROTO:
            raise FetcherException(f"FIXME: Unhandled scheme {parsedInputURL.scheme}")

        aspera_server = parsedInputURL.hostname
        aspera_server_tcp_port = (
            22 if parsedInputURL.port is None else parsedInputURL.port
        )
        remote_path = parsedInputURL.path
        # Removing the initial slash
        if remote_path.startswith("/"):
            remote_path = remote_path[1:]

        """
        ports: -O 22 TCP, -P 33001 and 33002 UDP
        
        -q quiet
        -T disable encryption
        -l max transfer rate
        #--src-base= remove this prefix from the sources
        ascp --ignore-host-key -k 1 --partial-file-suffix=PART -q -T -l 100m user@host:file_or_dir dest_file_or_dir
        """

        # FASP / Aspera URIs are going to be parsed like they were sftp ones

        # Although username and password could be obtained from URL, they are
        # intentionally ignored in favour of security context
        username = (
            secContext.get("username")
            if parsedInputURL.username is None
            else parsedInputURL.username
        )
        password = (
            secContext.get("password")
            if parsedInputURL.password is None
            else parsedInputURL.password
        )
        faspKey = secContext.get("key")
        faspToken = secContext.get("token")
        if (username is None) or (
            (password is None) and (faspKey is None) and (faspToken is None)
        ):
            raise FetcherException(
                f"Cannot download content from {remote_file} without credentials"
            )

        faspKeyFilename = None
        if faspKey is not None:
            # Program expects to read the key from a file
            with tempfile.NamedTemporaryFile(
                mode="w+", encoding="iso-8859-1", delete=False
            ) as tKey:
                tKey.write(faspKey)
                faspKeyFilename = tKey.name

        # This is needed to isolate execution environment
        runEnv = dict()
        # These variables are needed to have the installation working
        # so external commands like ascp can be found
        for envKey in ("LD_LIBRARY_PATH", "PATH"):
            valToSet = os.environ.get(envKey)
            if valToSet is not None:
                runEnv[envKey] = valToSet
        if faspKey is not None:
            runEnv["ASPERA_SCP_KEY"] = faspKey
        elif faspToken is not None:
            runEnv["ASPERA_SCP_TOKEN"] = faspToken
        elif password is not None:
            runEnv["ASPERA_SCP_PASS"] = password

        # The command-line to use
        ascp_params = [
            self.ascp_cmd,
            "--ignore-host-key",
            "-k",
            "1",  # Resume level
            "--partial-file-suffix=PART",
            "-q",  # Quiet
            "-T",  # Disable in-transit encryption
            # '-p',   # Preserve timestamps
            "-l",
            self.limit_throughput,  # Limit throughput
            "-P",
            str(aspera_server_tcp_port),
            f"{username}@{aspera_server}:{remote_path}",
            cachedFilename,
        ]

        with tempfile.NamedTemporaryFile() as ascp_stdout, tempfile.NamedTemporaryFile() as ascp_stderr:
            self.logger.debug(f'Running "{" ".join(ascp_params)}"')
            comp_proc = subprocess.run(
                ascp_params, env=runEnv, stdout=ascp_stdout, stderr=ascp_stderr
            )

            # Did it finish properly?
            if comp_proc.returncode != 0:
                # Reading the output and error for the report
                with open(ascp_stdout.name, "r") as c_stF:
                    ascp_stdout_v = c_stF.read()
                with open(ascp_stderr.name, "r") as c_stF:
                    ascp_stderr_v = c_stF.read()

                errstr = "ERROR: Unable to fetch '{}'. Retval {}\n======\nSTDOUT\n======\n{}\n======\nSTDERR\n======\n{}".format(
                    remote_file, comp_proc.returncode, ascp_stdout_v, ascp_stderr_v
                )
                raise FetcherException(errstr)

        if os.path.isdir(cachedFilename):
            kind = ContentKind.Directory
        elif os.path.isfile(cachedFilename):
            kind = ContentKind.File
        else:
            raise FetcherException(
                f"Remote {remote_file} is neither a file nor a directory (does it exist?)"
            )

        return ProtocolFetcherReturn(
            kind_or_resolved=kind,
            metadata_array=[
                URIWithMetadata(
                    uri=remote_file,
                    # Some metadata could be gathered through the
                    # usage of --file-manifest=text --file-manifest-path=
                    metadata={},
                )
            ],
        )
