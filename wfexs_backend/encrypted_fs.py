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

import enum
import pathlib
import subprocess
import tempfile

from typing import (
    cast,
    TYPE_CHECKING,
)

if TYPE_CHECKING:
    from typing import (
        MutableSequence,
    )

    from .common import (
        AbsPath,
        AnyPath,
        RelPath,
    )

from .common import (
    AbstractWfExSException,
)


class EncryptedFSException(AbstractWfExSException):
    pass


# This is needed to support different FUSE encryption filesystem implementations
class EncryptedFSType(enum.Enum):
    EncFS = "encfs"
    GoCryptFS = "gocryptfs"


DEFAULT_ENCRYPTED_FS_TYPE = EncryptedFSType.EncFS
DEFAULT_ENCRYPTED_FS_CMD = {
    EncryptedFSType.EncFS: cast("RelPath", "encfs"),
    EncryptedFSType.GoCryptFS: cast("RelPath", "gocryptfs"),
}

# Idle timeout, in minutes
DEFAULT_ENCRYPTED_FS_IDLE_TIMEOUT = 5


def _mountEncFS(
    encfs_cmd: "pathlib.Path",
    encfs_idleMinutes: "int",
    uniqueEncWorkDir: "pathlib.Path",
    uniqueWorkDir: "pathlib.Path",
    uniqueRawWorkDir: "pathlib.Path",
    clearPass: "str",
    allowOther: "bool" = False,
) -> None:
    with tempfile.NamedTemporaryFile() as encfs_init_stdout, tempfile.NamedTemporaryFile() as encfs_init_stderr:
        encfsCommand: "MutableSequence[str]" = [
            encfs_cmd.as_posix(),
            "-i",
            str(encfs_idleMinutes),
            "--stdinpass",
            "--standard",
            uniqueEncWorkDir.as_posix(),
            uniqueWorkDir.as_posix(),
        ]

        # This parameter can be a security hole
        if allowOther:
            encfsCommand.extend(["--", "-o", "allow_other"])

        try:
            efs = subprocess.Popen(
                encfsCommand,
                stdin=subprocess.PIPE,
                stdout=encfs_init_stdout,
                stderr=encfs_init_stderr,
                cwd=uniqueRawWorkDir,
            )
        except IOError as ioe:
            errstr = f"Could not init/mount directory encryption FUSE using {encfsCommand} (maybe was not found)"
            raise EncryptedFSException(errstr) from ioe

        efs.communicate(input=clearPass.encode("utf-8"))
        retval = efs.wait()

        # Reading the output and error for the report
        if retval != 0:
            with open(encfs_init_stdout.name, "r") as c_stF:
                encfs_init_stdout_v = c_stF.read()
            with open(encfs_init_stderr.name, "r") as c_stF:
                encfs_init_stderr_v = c_stF.read()

            errstr = "Could not init/mount encfs (retval {})\nCommand: {}\n======\nSTDOUT\n======\n{}\n======\nSTDERR\n======\n{}".format(
                retval, " ".join(encfsCommand), encfs_init_stdout_v, encfs_init_stderr_v
            )
            raise EncryptedFSException(errstr)


def _mountGoCryptFS(
    gocryptfs_cmd: "pathlib.Path",
    gocryptfs_idleMinutes: "int",
    uniqueEncWorkDir: "pathlib.Path",
    uniqueWorkDir: "pathlib.Path",
    uniqueRawWorkDir: "pathlib.Path",
    clearPass: "str",
    allowOther: "bool" = False,
) -> None:
    with tempfile.NamedTemporaryFile() as gocryptfs_init_stdout, tempfile.NamedTemporaryFile() as gocryptfs_init_stderr:
        # First, detect whether there is an already created filesystem
        gocryptfsInfo: "MutableSequence[str]" = [
            gocryptfs_cmd.as_posix(),
            "-info",
            uniqueEncWorkDir.as_posix(),
        ]

        retval = subprocess.call(
            gocryptfsInfo,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            cwd=uniqueRawWorkDir,
        )

        if retval != 0:
            # Let's try creating it!
            gocryptfsInit: "MutableSequence[str]" = [
                gocryptfs_cmd.as_posix(),
                "-init",
                uniqueEncWorkDir.as_posix(),
            ]

            gocryptfsCommand = gocryptfsInit

            efs = subprocess.Popen(
                gocryptfsInit,
                stdin=subprocess.PIPE,
                stdout=gocryptfs_init_stdout,
                stderr=gocryptfs_init_stderr,
                cwd=uniqueRawWorkDir,
            )
            efs.communicate(input=clearPass.encode("utf-8"))
            retval = efs.wait()

        if retval == 0:
            # And now, let's mount it
            gocryptfsMount: "MutableSequence[str]" = [
                gocryptfs_cmd.as_posix(),
                "-i",
                str(gocryptfs_idleMinutes) + "m",
            ]

            if allowOther:
                gocryptfsMount.append("-allow_other")

            gocryptfsMount.extend(
                [uniqueEncWorkDir.as_posix(), uniqueWorkDir.as_posix()]
            )

            gocryptfsCommand = gocryptfsMount

            efs = subprocess.Popen(
                gocryptfsMount,
                stdin=subprocess.PIPE,
                stdout=gocryptfs_init_stdout,
                stderr=gocryptfs_init_stdout,
                cwd=uniqueRawWorkDir,
            )
            efs.communicate(input=clearPass.encode("utf-8"))
            retval = efs.wait()

        # Reading the output and error for the report
        if retval != 0:
            with open(gocryptfs_init_stdout.name, "r") as c_stF:
                encfs_init_stdout_v = c_stF.read()
            with open(gocryptfs_init_stderr.name, "r") as c_stF:
                encfs_init_stderr_v = c_stF.read()

            errstr = "Could not init/mount gocryptfs (retval {})\nCommand: {}\n======\nSTDOUT\n======\n{}\n======\nSTDERR\n======\n{}".format(
                retval,
                " ".join(gocryptfsCommand),
                encfs_init_stdout_v,
                encfs_init_stderr_v,
            )
            raise EncryptedFSException(errstr)


ENCRYPTED_FS_MOUNT_IMPLEMENTATIONS = {
    EncryptedFSType.EncFS: _mountEncFS,
    EncryptedFSType.GoCryptFS: _mountGoCryptFS,
}
