#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# Copyright 2020-2021 Barcelona Supercomputing Center (BSC), Spain
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
# https://github.com/bigpe/FtpDownloader/blob/891bee35566078531b6f1ed3975627e29b935a97/ftp_downloader/FTPDownloader.py

import asyncio
import datetime
import logging
import math
import os
from pathlib import Path, PurePosixPath
import sys
import time

import aioftp

class FTPDownloader:
    DEFAULT_USER = 'ftp'
    DEFAULT_PASS = 'guest@'
    DEFAULT_FTP_PORT = 21
    
    DEFAULT_MAX_RETRIES = 5

    def __init__(self, HOST, PORT=DEFAULT_FTP_PORT, USER=DEFAULT_USER, PASSWORD=DEFAULT_PASS, max_retries=DEFAULT_MAX_RETRIES):
        self.HOST = HOST
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


    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        pass
    
    async def __download_file_async(self, client, upload_file_path, dfdPath, dfdStat):
        if upload_file_path.exists():
            upload_file_path.unlink()  # Remove file before append stream to file
        upload_file_path.parent.mkdir(exist_ok=True, parents=True)  # Create dirs
        
        downloaded_size = 0
        # This is needed to detect reconnections
        stream = None
        retries = self.max_retries
        while retries > 0:
            try:
                stream = await client.download_stream(dfdPath, offset=downloaded_size)
                with upload_file_path.open(mode='ab', buffering=1024*1024) as wb:
                    wb.seek(downloaded_size)
                    async for block in stream.iter_by_block():
                        wb.write(block)
                        downloaded_size += sys.getsizeof(block)
                        #self.logger.debug(
                        #    f'Loading: {math.floor(downloaded_size / ftp_file_size * 100)}%...')
                    await stream.finish()
                
                ttuple = datetime.datetime.strptime(dfdStat['modify'],'%Y%m%d%H%M%S').timetuple()
                ttime = time.mktime(ttuple)
                os.utime(upload_file_path, (ttime, ttime))
    
                break
            except ConnectionResetError:
                self.logger.debug("Reconnecting")
                await self._reconnect(client)
            except Exception as e:
                retries -= 1
                self.logger.debug("Left {} retries".format(retries))
                if retries == 0:
                    raise e
                await self._reconnect(client)
        
    async def _reconnect(self, client):
        self.logger.debug("Reconnecting")
        try:
            await client.quit()
        except:
            pass
        await client.connect(self.HOST, self.PORT)
        await client.login(self.USER, self.PASSWORD)
    
    async def _download_dir_async(self, client, dfdPath, utdPath, exclude_ext):
        """
        This method mirrors a whole directory into a destination one
        dfdPath must be absolute
        """
        self.logger.info('Get files list')
        
        retries = self.max_retries
        while retries > 0:
            try:
                files_list = list(  # Filter list, exclude extensions and directories
                    filter(
                        lambda f:
                        f[1]['type'] == 'file'
                        and f[0].suffix not in exclude_ext,
                        await client.list(path=dfdPath, recursive=True)
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
            self.logger.debug(f'({len(files_list)}) {dfdPath} -> '
                                 f'{utdPath}')
            for i, (path, info) in enumerate(files_list):
                download = False
                upload_file_path = Path.joinpath(
                    utdPath, path.relative_to(dfdPath)
                )
                destination_dir = upload_file_path.parents[0]
                file_name = path.name
                
                if upload_file_path.exists():
                    ftp_file_size = int(info['size'])
                    local_file_size = upload_file_path.stat().st_size
                    # TODO diff creation time too
                    if ftp_file_size != local_file_size:
                        download = True
                else:
                    download = True
                
                downloaded_path.append(upload_file_path)
                self.logger.debug(
                    f'({i + 1}/{len(files_list)}) {file_name} -> ../{path}')
                if download:
                    await self.__download_file_async(client, upload_file_path, path, info)
                    self.logger.info('Loading: Complete')
        else:
            self.logger.warning('Nothing new to download')
#                self.clear_tasks()
        self.logger.info('Files downloaded')
        
        return downloaded_path

    async def _download_file_async(self, client, dfdPath, utdPath):
        """
        dfdPath must be absolute
        """
        
        self.logger.info('Get file')
        
        file_name = dfdPath.name
        upload_file_path = utdPath
        destination_dir = utdPath.parent
        
        dfdStat = await client.stat(dfdPath)
        ftp_file_size = int(dfdStat['size'])
        download = False
        if upload_file_path.exists():
            local_file_size = upload_file_path.stat().st_size
            # TODO diff creation time too
            if ftp_file_size != local_file_size:
                download = True
        else:
            download = True
        
        self.logger.debug(f'{dfdPath} -> '
                             f'{upload_file_path}')
        if download:
            await self.__download_file_async(client, upload_file_path, dfdPath, dfdStat)
            self.logger.info('Loading: Complete')
        else:
            self.logger.warning('Nothing new to download')
#           self.clear_tasks()
        self.logger.info('File downloaded')
        
        return upload_file_path

    async def download_dir_async(self, download_from_dir, upload_to_dir, exclude_ext):
        dfdPath = Path(download_from_dir)
        destdir = os.path.abspath(upload_to_dir)
        os.makedirs(destdir, exist_ok=True)
        utdPath = Path(destdir)
        
        async with self.aioSessMethod(self.HOST, self.PORT, self.USER, self.PASSWORD) as client:
            # Changing to absolute path
            if not dfdPath.is_absolute():
                currRemoteDir = await client.get_current_directory()
                dfdPath = currRemoteDir.joinpath(dfdPath).resolve()
            
            retval = await self._download_dir_async(client, dfdPath, utdPath, exclude_ext)
            return retval
    
    async def download_file_async(self, download_from_file, upload_to_file):
        dfdPath = Path(download_from_file)
        destfile = os.path.abspath(upload_to_file)
        utdPath = Path(destfile)
        async with self.aioSessMethod(self.HOST, self.PORT, self.USER, self.PASSWORD) as client:
            # Changing to absolute path
            if not dfdPath.is_absolute():
                currRemoteDir = await client.get_current_directory()
                dfdPath = currRemoteDir.joinpath(dfdPath).resolve()
            
            retval = await self._download_file_async(client, dfdPath, utdPath)
            return retval
    
    async def download_async(self, download_from_df, upload_to_df, exclude_ext):
        """
        This method returns a Path when a file is fetched
        and a list of Path when it is a directory
        """
        dfdPath = Path(download_from_df)
        destpath = os.path.abspath(upload_to_df)
        utdPath = Path(destpath)
        async with self.aioSessMethod(self.HOST, self.PORT, self.USER, self.PASSWORD) as client:
            # Changing to absolute path
            if not dfdPath.is_absolute():
                currRemoteDir = await client.get_current_directory()
                dfdPath = currRemoteDir.joinpath(dfdPath).resolve()
            
            dfdStat = await client.stat(dfdPath)
            if dfdStat['type'] == 'dir':
                os.makedirs(destpath, exist_ok=True)
                retval = await self._download_dir_async(client, dfdPath, utdPath, exclude_ext)
            else:
                retval = await self._download_file_async(client, dfdPath, utdPath)
            
            return retval
    
    def download_dir(self, download_from_dir, upload_to_dir='.', exclude_ext=[]):
        loop = asyncio.new_event_loop()
        tasks = (
            self.download_dir_async(download_from_dir, upload_to_dir, exclude_ext)
            ,
        )
        try:
            done, _ = loop.run_until_complete(asyncio.wait(tasks))
        finally:
            loop.close()
        
        task = done.pop()
        retval_exception = task.exception()
        
        if retval_exception is not None:
            raise retval_exception
        
        return task.result()
    
    def download_file(self, download_from_file, upload_to_file):
        loop = asyncio.new_event_loop()
        tasks = (
            self.download_file_async(download_from_file, upload_to_file)
            ,
        )
        try:
            done, _ = loop.run_until_complete(asyncio.wait(tasks))
        finally:
            loop.close()
        
        task = done.pop()
        retval_exception = task.exception()
        
        if retval_exception is not None:
            raise retval_exception
        
        return task.result()
    
    def download(self, download_path, upload_path, exclude_ext=[]):
        loop = asyncio.new_event_loop()
        tasks = (
            self.download_async(download_path, upload_path, exclude_ext)
            ,
        )
        try:
            done, _ = loop.run_until_complete(asyncio.wait(tasks))
        finally:
            loop.close()
        
        task = done.pop()
        retval_exception = task.exception()
        
        if retval_exception is not None:
            raise retval_exception
        
        return task.result()

    @staticmethod
    def clear_tasks():
        # This line should be asyncio.current_task(asyncio.get_running_loop())
        # when it is migrated to python 3.7 and later
        for task in asyncio.Task.current_task():
            task.cancel()
