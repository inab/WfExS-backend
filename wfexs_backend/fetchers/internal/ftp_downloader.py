#!/usr/bin/env python3
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

import datetime
import logging
import os
import pathlib
import sys
import time

from typing import (
    TYPE_CHECKING,
)

if TYPE_CHECKING:
    from typing import (
        Any,
        Coroutine,
        Mapping,
        MutableSequence,
        Sequence,
        Tuple,
        TypeVar,
        Union,
    )

    from typing_extensions import (
        Final,
    )

    CT = TypeVar("CT")

import ftplib
import ftputil

import ftputil.session


# This monkeypatching approach is needed to fix the cases where the FTP
# server does not support FEAT command, or it is not allowed.
# For instance ftp.broadinstitute.org (tested on 2025-05-19)
def _maybe_send_opts_utf8_on_patched(session: "ftplib.FTP", encoding: "str") -> None:
    """
    If the requested encoding is UTF-8 and the server supports the `UTF8`
    feature, send "OPTS UTF8 ON".

    See https://datatracker.ietf.org/doc/html/rfc2640.html .
    """
    if ((encoding is None) and ftputil.path_encoding.RUNNING_UNDER_PY39_AND_UP) or (
        encoding in ["UTF-8", "UTF8", "utf-8", "utf8"]
    ):
        server_supports_opts_utf8_on = False
        try:
            feat_output = session.sendcmd("FEAT")
            for line in feat_output.splitlines():
                # The leading space is important. See RFC 2640.
                if line.upper().rstrip() == " UTF8":
                    server_supports_opts_utf8_on = True
        except ftplib.error_perm:
            # FEAT is not supported
            pass
        if server_supports_opts_utf8_on:
            session.sendcmd("OPTS UTF8 ON")


ftputil.session._maybe_send_opts_utf8_on = _maybe_send_opts_utf8_on_patched  # type: ignore[attr-defined]


class FTPDownloader:
    DEFAULT_USER: "Final[str]" = "ftp"
    DEFAULT_PASS: "Final[str]" = "guest@example.org"
    DEFAULT_FTP_PORT: "Final[int]" = 21

    DEFAULT_MAX_RETRIES: "Final[int]" = 5

    def __init__(
        self,
        HOST: "str",
        PORT: "int" = DEFAULT_FTP_PORT,
        USER: "str" = DEFAULT_USER,
        PASSWORD: "str" = DEFAULT_PASS,
        max_retries: "int" = DEFAULT_MAX_RETRIES,
    ):
        self.HOST = HOST
        self.PORT = PORT
        self.USER = USER
        self.PASSWORD = PASSWORD

        self.max_retries = max_retries

        self.session_factory = ftputil.session.session_factory(
            port=self.PORT,
            encoding="UTF-8",
            # debug_level=2,
        )

        # Getting a logger focused on specific classes
        from inspect import getmembers as inspect_getmembers

        self.logger = logging.getLogger(
            dict(inspect_getmembers(self))["__module__"]
            + "::"
            + self.__class__.__name__
        )

    def __enter__(self) -> "FTPDownloader":
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):  # type: ignore
        pass

    def _download_dir(
        self,
        ftp_host: "ftputil.FTPHost",
        download_path: "str",
        utdPath: "pathlib.Path",
        exclude_ext: "Sequence[str]",
    ) -> "Sequence[pathlib.Path]":
        """
        This method mirrors a whole directory into a destination one
        dfdPath must be absolute
        """
        self.logger.debug(f"Get files list {download_path}")

        utdPath.mkdir(parents=True, exist_ok=True)
        retries = self.max_retries
        directories: "MutableSequence[Tuple[str, str]]" = []
        downloaded_path: "MutableSequence[pathlib.Path]" = []
        while retries > 0:
            try:
                directories = []
                downloaded_path = []
                names = ftp_host.listdir(download_path)
                for name in names:
                    full_name = ftp_host.path.join(download_path, name)
                    if ftp_host.path.isfile(full_name):
                        for e_ext in exclude_ext:
                            # Discarding any file ending in any of the extensions listed
                            if name.endswith(e_ext):
                                break
                        else:
                            dest_file = utdPath / name
                            ftp_host.download_if_newer(full_name, dest_file.as_posix())
                            downloaded_path.append(dest_file)
                    elif ftp_host.path.isdir(full_name):
                        directories.append((full_name, name))
            except Exception as e:
                retries -= 1
                self.logger.debug("Left {} tries".format(retries))
                if retries == 0:
                    raise e

        if downloaded_path:
            self.logger.debug(
                f"({len(downloaded_path)}) {download_path} -> " f"{utdPath}"
            )

        for full_name, name in directories:
            dest_dir = utdPath / name
            fetched = self._download_dir(
                ftp_host, full_name, dest_dir, exclude_ext=exclude_ext
            )
            downloaded_path.extend(fetched)

        self.logger.debug(f"Files from {download_path} downloaded to {downloaded_path}")

        return downloaded_path

    def _download_file(
        self,
        ftp_host: "ftputil.FTPHost",
        download_path: "str",
        upload_file_path: "pathlib.Path",
    ) -> "pathlib.Path":
        """
        download_path must be absolute
        """

        self.logger.debug(f"Get file {download_path}")

        downloaded = ftp_host.download_if_newer(
            download_path, upload_file_path.as_posix()
        )

        if downloaded:
            self.logger.debug("Loading: Complete")
        else:
            self.logger.debug("Nothing new to download")

        self.logger.debug(f"File {download_path} downloaded to {upload_file_path}")

        return upload_file_path

    def download_dir(
        self,
        download_from_dir: "str",
        upload_to_dir: "str" = ".",
        exclude_ext: "Sequence[str]" = [],
    ) -> "Sequence[pathlib.Path]":
        destpath = os.path.abspath(upload_to_dir)
        utdPath = pathlib.Path(destpath)
        with ftputil.FTPHost(
            self.HOST, self.USER, self.PASSWORD, session_factory=self.session_factory
        ) as ftp_host:
            # Changing to absolute path
            if not ftp_host.path.isabs(download_from_dir):
                download_from_dir = ftp_host.path.abspath(download_from_dir)

            retval = self._download_dir(
                ftp_host, download_from_dir, utdPath, exclude_ext=exclude_ext
            )

        return retval

    def download_file(
        self, download_from_file: "str", upload_to_file: "str"
    ) -> "pathlib.Path":
        destpath = os.path.abspath(upload_to_file)
        utdPath = pathlib.Path(destpath)
        with ftputil.FTPHost(
            self.HOST, self.USER, self.PASSWORD, session_factory=self.session_factory
        ) as ftp_host:
            # Changing to absolute path
            if not ftp_host.path.isabs(download_from_file):
                download_from_file = ftp_host.path.abspath(download_from_file)

            retval = self._download_file(ftp_host, download_from_file, utdPath)

        return retval

    def download(
        self,
        download_path: "str",
        upload_path: "str",
        exclude_ext: "Sequence[str]" = [],
    ) -> "Union[pathlib.Path, Sequence[pathlib.Path]]":
        """
        This method returns a pathlib.Path when a file is fetched
        and a list of pathlib.Path when it is a directory
        """
        destpath = os.path.abspath(upload_path)
        utdPath = pathlib.Path(destpath)
        with ftputil.FTPHost(
            self.HOST, self.USER, self.PASSWORD, session_factory=self.session_factory
        ) as ftp_host:
            # Changing to absolute path
            if not ftp_host.path.isabs(download_path):
                download_path = ftp_host.path.abspath(download_path)

            retval: "Union[pathlib.Path, Sequence[pathlib.Path]]"
            if ftp_host.path.isdir(download_path):
                retval = self._download_dir(
                    ftp_host, download_path, utdPath, exclude_ext=exclude_ext
                )
            else:
                retval = self._download_file(ftp_host, download_path, utdPath)

        return retval
