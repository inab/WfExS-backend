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

import os
import paramiko
import paramiko.pkey
from paramiko.config import SSH_PORT as DEFAULT_SSH_PORT

import shutil
import stat

from typing import Any, List, Optional, Tuple, Union

from urllib import request, parse
import urllib.error

from ..common import *
from ..utils.ftp_downloader import FTPDownloader


def fetchClassicURL(remote_file:URIType, cachedFilename:AbsPath, secContext:Optional[SecurityContextConfig]=None) -> Tuple[Union[URIType, ContentKind], List[URIWithMetadata]]:
    """
    Method to fetch contents from http, https and ftp

    :param remote_file:
    :param cachedFilename:
    :param secContext:
    """
    
    if isinstance(secContext, dict):
        username = secContext.get('username')
        password = secContext.get('password')
        if username is not None:
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
    
    uri_with_metadata = None
    try:
        with request.urlopen(remote_file) as url_response, open(cachedFilename, 'wb') as download_file:
            uri_with_metadata = URIWithMetadata(url_response.url, dict(url_response.headers.items()))
            shutil.copyfileobj(url_response, download_file)
    except urllib.error.HTTPError as he:
        raise WFException("Error fetching {} : {} {}".format(remote_file, he.code, he.reason))
    
    return ContentKind.File, [ uri_with_metadata ]

def fetchFTPURL(remote_file:URIType, cachedFilename:AbsPath, secContext:Optional[SecurityContextConfig]=None) -> Tuple[Union[URIType, ContentKind], List[URIWithMetadata]]:
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
def fetchSSHURL(remote_file:URIType, cachedFilename:AbsPath, secContext:Optional[SecurityContextConfig]=None) -> Tuple[Union[URIType, ContentKind], List[URIWithMetadata]]:
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
        raise WFException("Cannot download content from {} without credentials".format(remote_file))
    
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

def fetchFile(remote_file:URIType, cachedFilename:AbsPath, secContext:Optional[SecurityContextConfig]=None) -> Tuple[Union[URIType, ContentKind], List[URIWithMetadata]]:
    """
    Method to fetch contents from local contents

    :param remote_file:
    :param cachedFilename: Destination filename for the fetched content
    :param secContext: The security context containing the credentials
    """
    
    parsedInputURL = parse.urlparse(remote_file)
    localPath = parsedInputURL.path
    if not os.path.exists(localPath):
        raise WFException("Local path {} is not available".format(localPath))
    
    kind = None
    if os.path.isdir(localPath):
        shutil.copytree(localPath, cachedFilename)
        kind = ContentKind.Directory
    elif os.path.isfile(localPath):
        shutil.copy2(localPath, cachedFilename)
        kind = ContentKind.File
    else:
        raise WFException("Local path {} is neither a file nor a directory".format(localPath))
    
    return kind, [ URIWithMetadata(remote_file, {}) ]

DEFAULT_SCHEME_HANDLERS = {
    'http': fetchClassicURL,
    'https': fetchClassicURL,
    'ftp': fetchFTPURL,
    'sftp': fetchSSHURL,
    'ssh': fetchSSHURL,
    'file': fetchFile,
}
