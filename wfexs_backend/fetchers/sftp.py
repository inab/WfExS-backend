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

import logging
import os
import paramiko
import paramiko.pkey
from paramiko.config import SSH_PORT as DEFAULT_SSH_PORT

import stat

from typing import (
    cast,
    TYPE_CHECKING,
)

if TYPE_CHECKING:
    from typing import (
        Any,
        Callable,
        Iterable,
        IO,
        Mapping,
        MutableMapping,
        MutableSequence,
        Optional,
        Sequence,
        Tuple,
        Type,
        Union,
    )

    from typing_extensions import (
        Literal,
        NotRequired,
        Required,
        TypedDict,
    )

    from _typeshed import SupportsRead
    from ssl import SSLContext
    from mypy_extensions import DefaultNamedArg

    from ..common import (
        AbsPath,
        ProgsMapping,
        RelPath,
        RepoURL,
        RepoTag,
        SecurityContextConfig,
        SymbolicName,
        URIType,
    )

    class SSHConnBlock(TypedDict):
        pkey: "NotRequired[paramiko.pkey.PKey]"
        username: "NotRequired[str]"
        password: "NotRequired[str]"


from . import (
    AbstractStatefulFetcher,
    DocumentedProtocolFetcher,
    FetcherException,
    ProtocolFetcherReturn,
)

from ..common import (
    ContentKind,
    URIWithMetadata,
)


def sftpCopy(
    sftp: "paramiko.SFTPClient",
    sshPath: "AbsPath",
    localPath: "AbsPath",
    sshStat: "Optional[paramiko.SFTPAttributes]" = None,
) -> "Tuple[Union[int, Literal[False]], Optional[ContentKind]]":
    if sshStat is None:
        sshStat = sftp.stat(sshPath)

    # Trios
    transTrios = []
    recur: "MutableSequence[Tuple[AbsPath, paramiko.sftp_attr.SFTPAttributes, AbsPath]]" = (
        []
    )
    kind: "Optional[ContentKind]" = None
    if sshStat.st_mode is not None:
        if stat.S_ISREG(sshStat.st_mode):
            transTrios.append((sshPath, sshStat, localPath))
            kind = ContentKind.File
        elif stat.S_ISDIR(sshStat.st_mode):
            # Recursive
            os.makedirs(localPath, exist_ok=True)
            recur = []
            # List of remote files
            for filename in sftp.listdir(sshPath):
                rPath = cast("AbsPath", os.path.join(sshPath, filename))
                lPath = cast("AbsPath", os.path.join(localPath, filename))
                rStat = sftp.stat(rPath)

                if rStat.st_mode is not None:
                    if stat.S_ISREG(rStat.st_mode):
                        transTrios.append((rPath, rStat, lPath))
                    elif stat.S_ISDIR(rStat.st_mode):
                        recur.append((rPath, rStat, lPath))
                else:
                    sftp_channel = sftp.get_channel()
                    server_name = (
                        None if sftp_channel is None else sftp_channel.getpeername()
                    )
                    logging.warning(
                        f"Corner case where either paramiko or server {server_name} is not providing stats for {rPath}"
                    )
            kind = ContentKind.Directory

    numCopied: "Union[Literal[False], int]"
    if kind is None:
        numCopied = False
    else:
        # Now, transfer these
        numCopied = 0
        for remotePath, rStat, filename in transTrios:
            sftp.get(remotePath, filename)
            # Only set it when it is possible
            if rStat.st_mtime is not None:
                st_atime = rStat.st_mtime if rStat.st_atime is None else rStat.st_atime
                os.utime(filename, (st_atime, rStat.st_mtime))
            numCopied += 1

        # And recurse on these
        for rDir, rStat, lDir in recur:
            subNumCopied, _ = sftpCopy(sftp, rDir, lDir, sshStat=rStat)
            if isinstance(subNumCopied, int):
                numCopied += subNumCopied

    return numCopied, kind


# TODO: test this codepath
def fetchSSHURL(
    remote_file: "URIType",
    cachedFilename: "AbsPath",
    secContext: "Optional[SecurityContextConfig]" = None,
) -> "ProtocolFetcherReturn":
    """
    Method to fetch contents from ssh / sftp servers

    :param remote_file:
    :param cachedFilename: Destination filename for the fetched content
    :param secContext: The security context containing the credentials
    """

    orig_remote_file = remote_file
    parsedInputURL, remote_file = AbstractStatefulFetcher.ParseAndRemoveCredentials(
        orig_remote_file
    )
    # Now the credentials are properly removed from remote_file
    # we get them from the parsed url
    username = parsedInputURL.username
    password = parsedInputURL.password

    # Sanitizing possible ill-formed inputs
    if not isinstance(secContext, dict):
        secContext = {}

    # Although username and password could be obtained from URL,
    # security context takes precedence
    username = secContext.get("username", username)
    password = secContext.get("password", password)
    sshKey = secContext.get("key")
    if (username is None) or ((password is None) and (sshKey is None)):
        raise FetcherException(
            "Cannot download content from {} without credentials".format(remote_file)
        )
    elif not isinstance(password, str) and not isinstance(sshKey, str):
        raise FetcherException(
            "Cannot download content from {} with crippled credentials".format(
                remote_file
            )
        )

    connBlock: "SSHConnBlock" = {
        "username": username,
    }

    if sshKey is not None:
        pKey = paramiko.pkey.PKey(data=sshKey)
        connBlock["pkey"] = pKey
    elif isinstance(password, str):
        connBlock["password"] = password

    sshHost = parsedInputURL.hostname
    if sshHost is None:
        sshHost = ""
    sshPort = (
        parsedInputURL.port if parsedInputURL.port is not None else DEFAULT_SSH_PORT
    )
    sshPath = cast("AbsPath", parsedInputURL.path)

    t = None
    try:
        t = paramiko.Transport((sshHost, sshPort))
        # Performance reasons!
        # t.window_size = 134217727
        # t.use_compression()

        t.connect(**connBlock)
        sftp = paramiko.SFTPClient.from_transport(t)

        if sftp is None:
            raise FetcherException(
                f"Unable to set up a connection to {sshHost}:{sshPort}"
            )
        _, kind = sftpCopy(sftp, sshPath, cachedFilename)
        if kind is None:
            raise FetcherException(
                f"sftp copy from {sshHost}:{sshPort}/{sshPath} failed"
            )
        return ProtocolFetcherReturn(
            kind_or_resolved=kind,
            metadata_array=[URIWithMetadata(remote_file, {})],
        )
    finally:
        # Closing the SFTP connection
        if t is not None:
            t.close()


SCHEME_HANDLERS: "Mapping[str, DocumentedProtocolFetcher]" = {
    "sftp": DocumentedProtocolFetcher(
        fetcher=fetchSSHURL,
        description="'sftp' scheme represents contents behind an SSH server",
        priority=20,
    ),
    "ssh": DocumentedProtocolFetcher(
        fetcher=fetchSSHURL,
        description="'ssh' scheme represents contents behind an SSH server",
        priority=20,
    ),
}
