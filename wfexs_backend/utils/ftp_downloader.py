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

# Code from this class is an iteration of
#
# https://github.com/bigpe/FtpDownloader/blob/891bee35566078531b6f1ed3975627e29b935a97/ftp_downloader/FTPDownloader.py
#
# which was following MIT license
#
# https://github.com/bigpe/ftp-downloader/blob/891bee35566078531b6f1ed3975627e29b935a97/LICENSE.txt

import asyncio
import datetime
import logging
import os
from pathlib import Path
import socket
import sys
import time

from typing import (
    Any,
    Coroutine,
    Mapping,
    Sequence,
    Tuple,
    TypeVar,
    Union,
)

from typing_extensions import (
    Final,
)

import aioftp  # type: ignore[import]

CT = TypeVar("CT")


def asyncio_run(tasks: Tuple[Coroutine[Any, Any, CT], ...]) -> CT:
    """
    Helper method which abstracts differences from
    Python 3.7 and before about coroutines
    """
    if hasattr(asyncio, "run"):
        done, _ = asyncio.run(asyncio.wait(tasks))
    else:
        loop = asyncio.new_event_loop()
        try:
            done, _ = loop.run_until_complete(asyncio.wait(tasks))
        finally:
            loop.close()

    task = done.pop()
    retval_exception = task.exception()

    if retval_exception is not None:
        raise retval_exception

    return task.result()


class FTPDownloader:
    DEFAULT_USER: Final[str] = "ftp"
    DEFAULT_PASS: Final[str] = "guest@"
    DEFAULT_FTP_PORT: Final[int] = 21

    DEFAULT_MAX_RETRIES: Final[int] = 5

    def __init__(
        self,
        HOST: str,
        PORT: int = DEFAULT_FTP_PORT,
        USER: str = DEFAULT_USER,
        PASSWORD: str = DEFAULT_PASS,
        max_retries: int = DEFAULT_MAX_RETRIES,
    ):
        # Due a misbehaviour in asyncio.open_connection with
        # EPSV connection in ftp-trace.ncbi.nih.gov
        # this only works always when HOST is an IP address
        # instead of a hostname
        # FIXME: Prepare it for IPv6
        self.HOST = socket.gethostbyname(HOST)
        self.PORT = PORT
        self.USER = USER
        self.PASSWORD = PASSWORD

        self.max_retries = max_retries
        # Trying to be adaptive to the aioftp implementation
        if hasattr(aioftp, "ClientSession"):
            # aioftp 0.16.x
            self.aioSessMethod = aioftp.ClientSession
        else:
            # aioftp 0.18.x
            self.aioSessMethod = aioftp.Client.context

        # Getting a logger focused on specific classes
        self.logger = logging.getLogger(self.__class__.__name__)

    def __enter__(self):  # type: ignore
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):  # type: ignore
        pass

    async def __download_file_async(
        self,
        client: aioftp.Client,
        upload_file_path: Path,
        dfdPath: Path,
        dfdStat: Mapping[str, Any],
    ) -> None:
        if upload_file_path.exists():
            upload_file_path.unlink()  # Remove file before append stream to file
        upload_file_path.parent.mkdir(exist_ok=True, parents=True)  # Create dirs

        downloaded_size = 0
        # This is needed to detect reconnections
        stream = None
        retries = self.max_retries
        open_mode = "wb"
        while retries > 0:
            try:
                stream = await client.download_stream(dfdPath, offset=downloaded_size)
                with upload_file_path.open(mode=open_mode, buffering=1024 * 1024) as wb:
                    wb.seek(downloaded_size)
                    async for block in stream.iter_by_block():
                        wb.write(block)
                        downloaded_size += sys.getsizeof(block)
                        # self.logger.debug(
                        #    f'Loading: {math.floor(downloaded_size / ftp_file_size * 100)}%...')
                    await stream.finish()

                ttuple = datetime.datetime.strptime(
                    dfdStat["modify"], "%Y%m%d%H%M%S"
                ).timetuple()
                ttime = time.mktime(ttuple)
                os.utime(upload_file_path, (ttime, ttime))

                break
            except ConnectionResetError:
                await self._reconnect(client)
            except Exception as e:
                retries -= 1
                self.logger.debug("Left {} retries".format(retries))
                if retries == 0:
                    raise e
                await self._reconnect(client)

            # In order to concatenate
            open_mode = "ab"

    async def _reconnect(self, client: aioftp.Client) -> None:
        self.logger.debug(f"Reconnecting {self.HOST}:{self.PORT}")
        try:
            await client.quit()
        except:
            pass
        await client.connect(self.HOST, self.PORT)
        await client.login(self.USER, self.PASSWORD)

    async def _download_dir_async(
        self,
        client: aioftp.Client,
        dfdPath: Path,
        utdPath: Path,
        exclude_ext: Sequence[str],
    ) -> Sequence[Path]:
        """
        This method mirrors a whole directory into a destination one
        dfdPath must be absolute
        """
        self.logger.debug(f"Get files list {dfdPath}")

        retries = self.max_retries
        while retries > 0:
            try:
                files_list = list(  # Filter list, exclude extensions and directories
                    filter(
                        lambda f: f[1]["type"] == "file"
                        and f[0].suffix not in exclude_ext,
                        await client.list(path=dfdPath, recursive=True),
                    )
                )
                break
            except Exception as e:
                retries -= 1
                self.logger.debug("Left {} tries".format(retries))
                if retries == 0:
                    raise e
                await self._reconnect(client)

        downloaded_path = []
        if files_list:
            self.logger.debug(f"({len(files_list)}) {dfdPath} -> " f"{utdPath}")
            info: Mapping[str, Any]
            for i, (path, info) in enumerate(files_list):
                download = False
                upload_file_path = Path.joinpath(utdPath, path.relative_to(dfdPath))
                destination_dir = upload_file_path.parents[0]
                file_name = path.name

                if upload_file_path.exists():
                    ftp_file_size = int(info["size"])
                    local_file_size = upload_file_path.stat().st_size
                    # TODO diff creation time too
                    if ftp_file_size != local_file_size:
                        download = True
                else:
                    download = True

                downloaded_path.append(upload_file_path)
                self.logger.debug(
                    f"({i + 1}/{len(files_list)}) {file_name} -> ../{path}"
                )
                if download:
                    await self.__download_file_async(
                        client, upload_file_path, path, info
                    )
                    self.logger.debug("Loading: Complete")
        else:
            self.logger.debug("Nothing new to download")
        #                self.clear_tasks()
        self.logger.debug(f"Files from {dfdPath} downloaded to {downloaded_path}")

        return downloaded_path

    async def _download_file_async(
        self, client: aioftp.Client, dfdPath: Path, utdPath: Path
    ) -> Path:
        """
        dfdPath must be absolute
        """

        self.logger.debug(f"Get file {dfdPath}")

        file_name = dfdPath.name
        upload_file_path = utdPath
        destination_dir = utdPath.parent

        dfdStat = await client.stat(dfdPath)
        ftp_file_size = int(dfdStat["size"])
        download = False
        if upload_file_path.exists():
            local_file_size = upload_file_path.stat().st_size
            # TODO diff creation time too
            if ftp_file_size != local_file_size:
                download = True
        else:
            download = True

        self.logger.debug(f"{dfdPath} -> " f"{upload_file_path}")
        if download:
            await self.__download_file_async(client, upload_file_path, dfdPath, dfdStat)
            self.logger.debug("Loading: Complete")
        else:
            self.logger.debug("Nothing new to download")
        #           self.clear_tasks()
        self.logger.debug(f"File {dfdPath} downloaded to {upload_file_path}")

        return upload_file_path

    async def download_dir_async(
        self, download_from_dir: str, upload_to_dir: str, exclude_ext: Sequence[str]
    ) -> Sequence[Path]:
        dfdPath = Path(download_from_dir)
        destdir = os.path.abspath(upload_to_dir)
        os.makedirs(destdir, exist_ok=True)
        utdPath = Path(destdir)

        client: aioftp.Client
        async with self.aioSessMethod(
            self.HOST, self.PORT, self.USER, self.PASSWORD
        ) as client:
            # Changing to absolute path
            if not dfdPath.is_absolute():
                currRemoteDir = await client.get_current_directory()
                dfdPath = currRemoteDir.joinpath(dfdPath).resolve()

            retval = await self._download_dir_async(
                client, dfdPath, utdPath, exclude_ext
            )
            return retval

    async def download_file_async(
        self, download_from_file: str, upload_to_file: str
    ) -> Path:
        dfdPath = Path(download_from_file)
        destfile = os.path.abspath(upload_to_file)
        utdPath = Path(destfile)
        async with self.aioSessMethod(
            self.HOST, self.PORT, self.USER, self.PASSWORD
        ) as client:
            # Changing to absolute path
            if not dfdPath.is_absolute():
                currRemoteDir = await client.get_current_directory()
                dfdPath = currRemoteDir.joinpath(dfdPath).resolve()

            retval = await self._download_file_async(client, dfdPath, utdPath)
            return retval

    async def download_async(
        self, download_from_df: str, upload_to_df: str, exclude_ext: Sequence[str]
    ) -> Union[Path, Sequence[Path]]:
        """
        This method returns a Path when a file is fetched
        and a list of Path when it is a directory
        """
        dfdPath = Path(download_from_df)
        destpath = os.path.abspath(upload_to_df)
        utdPath = Path(destpath)
        async with self.aioSessMethod(
            self.HOST, self.PORT, self.USER, self.PASSWORD
        ) as client:
            # Changing to absolute path
            if not dfdPath.is_absolute():
                currRemoteDir = await client.get_current_directory()
                dfdPath = currRemoteDir.joinpath(dfdPath).resolve()

            dfdStat = await client.stat(dfdPath)
            retval: Union[Path, Sequence[Path]]
            if dfdStat["type"] == "dir":
                os.makedirs(destpath, exist_ok=True)
                retval = await self._download_dir_async(
                    client, dfdPath, utdPath, exclude_ext
                )
            else:
                retval = await self._download_file_async(client, dfdPath, utdPath)

            return retval

    def download_dir(
        self,
        download_from_dir: str,
        upload_to_dir: str = ".",
        exclude_ext: Sequence[str] = [],
    ) -> Sequence[Path]:
        tasks = (
            self.download_dir_async(download_from_dir, upload_to_dir, exclude_ext),
        )
        return asyncio_run(tasks)

    def download_file(self, download_from_file: str, upload_to_file: str) -> Path:
        tasks = (self.download_file_async(download_from_file, upload_to_file),)
        return asyncio_run(tasks)

    def download(
        self, download_path: str, upload_path: str, exclude_ext: Sequence[str] = []
    ) -> Union[Path, Sequence[Path]]:
        tasks = (self.download_async(download_path, upload_path, exclude_ext),)
        return asyncio_run(tasks)

    @staticmethod
    def clear_tasks() -> None:
        # This line should be asyncio.current_task(asyncio.get_running_loop())
        # when it is migrated to python 3.7 and later
        if hasattr(asyncio, "current_task"):
            task = asyncio.current_task()
        else:
            task = asyncio.Task.current_task(asyncio.get_running_loop())

        if task is not None:
            task.cancel()
