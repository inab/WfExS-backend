#!/usr/bin/env python
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

from __future__ import absolute_import

import abc
import http.client
import io
import logging
import os
import paramiko
import paramiko.pkey
from paramiko.config import SSH_PORT as DEFAULT_SSH_PORT

import shutil
import stat

from typing import Any, List, Mapping, Optional, Tuple, Union

from urllib import request, parse
import urllib.error

from ..common import AbstractWfExSException
from ..common import AbsPath, AnyURI, ContentKind, SecurityContextConfig
from ..common import SymbolicName, URIType, URIWithMetadata

from ..utils.ftp_downloader import FTPDownloader

class FetcherException(AbstractWfExSException):
    pass

class AbstractStatefulFetcher(abc.ABC):
    """
    Abstract class to model stateful fetchers
    """
    def __init__(self, progs: Mapping[SymbolicName, AbsPath]):
        import inspect
        
        self.logger = logging.getLogger(dict(inspect.getmembers(self))['__module__'] + '::' + self.__class__.__name__)
        # This is used to resolve program names
        self.progs = progs
    
    @abc.abstractmethod
    def fetch(self, remote_file:URIType, cachedFilename:Union[AbsPath, io.BytesIO], secContext:Optional[SecurityContextConfig]=None) -> Tuple[Union[AnyURI, ContentKind, List[AnyURI]], List[URIWithMetadata]]:
        """
        This is the method to be implemented by the stateful fetcher
        """
        pass

def fetchClassicURL(remote_file:URIType, cachedFilename:Union[AbsPath, io.BytesIO], secContext:Optional[SecurityContextConfig]=None) -> Tuple[Union[AnyURI, ContentKind, List[AnyURI]], List[URIWithMetadata]]:
    """
    Method to fetch contents from http, https and ftp

    :param remote_file:
    :param cachedFilename:
    :param secContext:
    """
    
    headers = {}
    method = None
    orig_remote_file = remote_file
    if isinstance(secContext, dict):
        headers = secContext.get('headers', {}).copy()
        token = secContext.get('token')
        token_header = secContext.get('token_header')
        username = secContext.get('username')
        password = secContext.get('password')
        
        if token is not None:
            if token_header is not None:
                headers[token_header] = token
            else:
                headers['Authorization'] = f'Bearer {token}'
        elif username is not None:
            if password is None:
                password = ''

            # Time to set up user and password in URL
            parsedInputURL = parse.urlparse(remote_file)

            netloc = parse.quote(username, safe='') + ':' + parse.quote(password,
                                                                        safe='') + '@' + parsedInputURL.hostname
            if parsedInputURL.port is not None:
                netloc += ':' + str(parsedInputURL.port)

            # Now the credentials are properly set up
            remote_file = parse.urlunparse((parsedInputURL.scheme, netloc, parsedInputURL.path,
                                            parsedInputURL.params, parsedInputURL.query, parsedInputURL.fragment))
        method = secContext.get('method')
    
    # Preparing where it is going to be written
    if isinstance(cachedFilename, (io.TextIOBase, io.BufferedIOBase, io.RawIOBase, io.IOBase)):
        download_file = cachedFilename
    else:
        download_file = open(cachedFilename, 'wb')
    
    uri_with_metadata = None
    try:
        req_remote = request.Request(remote_file, headers=headers, method=method)
        with request.urlopen(req_remote) as url_response:
            
            uri_with_metadata = URIWithMetadata(url_response.url, dict(url_response.headers.items()))
            
            while True:
                try:
                    # Try getting it
                    shutil.copyfileobj(url_response, download_file)
                except http.client.IncompleteRead as icread:
                    download_file.write(icread.partial)
                    # Restarting the copy
                    continue
                break
            
    except urllib.error.HTTPError as he:
        raise FetcherException("Error fetching {} : {} {}".format(orig_remote_file, he.code, he.reason))
    finally:
        # Closing files opened by this code
        if download_file != cachedFilename:
            download_file.close()
    
    return ContentKind.File, [ uri_with_metadata ]

def fetchFTPURL(remote_file:URIType, cachedFilename:AbsPath, secContext:Optional[SecurityContextConfig]=None) -> Tuple[Union[AnyURI, ContentKind, List[AnyURI]], List[URIWithMetadata]]:
    """
    Method to fetch contents from ftp

    :param remote_file:
    :param cachedFilename:
    :param secContext:
    """
    
    parsedInputURL = parse.urlparse(remote_file)
    kind = None
    connParams = {
        'HOST': parsedInputURL.hostname,
    }
    if parsedInputURL.port is not None:
        connParams['PORT'] = parsedInputURL.port
    
    if isinstance(secContext, dict):
        connParams['USER'] = secContext.get('username')
        connParams['PASSWORD'] = secContext.get('password')
    
    ftp_client = FTPDownloader(**connParams)
    retval = ftp_client.download(download_path=parsedInputURL.path, upload_path=cachedFilename)
    if isinstance(retval, list):
        kind = ContentKind.Directory
    else:
        kind = ContentKind.File
    
    return kind, [ URIWithMetadata(remote_file, {}) ]

def sftpCopy(sftp:paramiko.SFTPClient, sshPath, localPath, sshStat=None) -> Tuple[Union[int,bool], ContentKind]:
    if sshStat is None:
        sshStat = sftp.stat(sshPath)
    
    # Trios
    transTrios = []
    recur = []
    kind = None
    if stat.S_ISREG(sshStat.st_mode):
        transTrios.append((sshPath, sshStat, localPath))
        kind = ContentKind.File
    elif stat.S_ISDIR(sshStat.st_mode):
        # Recursive
        os.makedirs(localPath, exist_ok=True)
        recur = []
        # List of remote files
        for filename in sftp.listdir(sshPath):
            rPath = os.path.join(sshPath, filename)
            lPath = os.path.join(localPath, filename)
            rStat = sftp.stat(rPath)
            
            if stat.S_ISREG(rStat.st_mode):
                transTrios.append((rPath, rStat, lPath))
            elif stat.S_ISDIR(rStat.st_mode):
                recur.append((rPath, rStat, lPath))
        kind = ContentKind.Directory
    else:
        return False, None
    
    # Now, transfer these
    numCopied = 0
    for remotePath, rStat, filename in transTrios:
        sftp.get(remotePath, filename)
        os.utime(filename, (rStat.st_atime, rStat.st_mtime))
        numCopied += 1
    
    # And recurse on these
    for rDir, rStat, lDir in recur:
        numCopied += sftpCopy(sftp, rDir, lDir, sshStat=rStat)
    
    return numCopied, kind

# TODO: test this codepath
def fetchSSHURL(remote_file:URIType, cachedFilename:AbsPath, secContext:Optional[SecurityContextConfig]=None) -> Tuple[Union[AnyURI, ContentKind, List[AnyURI]], List[URIWithMetadata]]:
    """
    Method to fetch contents from ssh / sftp servers

    :param remote_file:
    :param cachedFilename: Destination filename for the fetched content
    :param secContext: The security context containing the credentials
    """
    
    # Sanitizing possible ill-formed inputs
    if not isinstance(secContext, dict):
        secContext = {}
    
    parsedInputURL = parse.urlparse(remote_file)
    # Although username and password could be obtained from URL, they are
    # intentionally ignore in favour of security context
    username = secContext.get('username')
    password = secContext.get('password')
    sshKey = secContext.get('key')
    if (username is None) or ((password is None) and (sshKey is None)):
        raise FetcherException("Cannot download content from {} without credentials".format(remote_file))
    
    connBlock = {
        'username': username,
    }
    
    if sshKey is not None:
        pKey = paramiko.pkey.PKey(data=sshKey)
        connBlock['pkey'] = pKey
    else:
        connBlock['password'] = password
    
    sshHost = parsedInputURL.hostname
    sshPort = parsedInputURL.port  if parsedInputURL.port is not None  else  DEFAULT_SSH_PORT
    sshPath = parsedInputURL.path
    
    t = None
    try:
        t = paramiko.Transport((sshHost, sshPort))
        # Performance reasons!
        # t.window_size = 134217727
        # t.use_compression()
        
        t.connect(**connBlock)
        sftp = paramiko.SFTPClient.from_transport(t)
        
        _ , kind = sftpCopy(sftp,sshPath,cachedFilename)
        return kind, [ URIWithMetadata(remote_file, {}) ]
    finally:
        # Closing the SFTP connection
        if t is not None:
            t.close()

def fetchFile(remote_file:URIType, cachedFilename:AbsPath, secContext:Optional[SecurityContextConfig]=None) -> Tuple[Union[AnyURI, ContentKind, List[AnyURI]], List[URIWithMetadata]]:
    """
    Method to fetch contents from local contents

    :param remote_file:
    :param cachedFilename: Destination filename for the fetched content
    :param secContext: The security context containing the credentials
    """
    
    parsedInputURL = parse.urlparse(remote_file)
    localPath = parsedInputURL.path
    if not os.path.exists(localPath):
        raise FetcherException("Local path {} is not available".format(localPath))
    
    kind = None
    if os.path.isdir(localPath):
        shutil.copytree(localPath, cachedFilename)
        kind = ContentKind.Directory
    elif os.path.isfile(localPath):
        shutil.copy2(localPath, cachedFilename)
        kind = ContentKind.File
    else:
        raise FetcherException("Local path {} is neither a file nor a directory".format(localPath))
    
    return kind, [ URIWithMetadata(remote_file, {}) ]

DEFAULT_SCHEME_HANDLERS = {
    'http': fetchClassicURL,
    'https': fetchClassicURL,
    'ftp': fetchFTPURL,
    'sftp': fetchSSHURL,
    'ssh': fetchSSHURL,
    'file': fetchFile,
}
