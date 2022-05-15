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

from typing import cast, Any, Dict, List, Mapping, Optional, Tuple, Union
from typing import MutableMapping, Sequence, Type

from urllib import request, parse
import urllib.error

from ..common import AbstractWfExSException
from ..common import AbsPath, RelPath, ContentKind, SecurityContextConfig
from ..common import SymbolicName, URIType, URIWithMetadata
from ..common import ProtocolFetcher, ProtocolFetcherReturn

from ..utils.contents import link_or_copy
from ..utils.ftp_downloader import FTPDownloader

class FetcherException(AbstractWfExSException):
    pass

class AbstractStatefulFetcher(abc.ABC):
    """
    Abstract class to model stateful fetchers
    """
    def __init__(self, progs: Mapping[SymbolicName, Union[RelPath, AbsPath]], setup_block: Optional[Mapping[str, Any]] = None):
        import inspect
        
        self.logger = logging.getLogger(dict(inspect.getmembers(self))['__module__'] + '::' + self.__class__.__name__)
        # This is used to resolve program names
        self.progs = progs
        self.setup_block = setup_block  if isinstance(setup_block, dict)  else dict()
    
    @abc.abstractmethod
    def fetch(self, remote_file:URIType, cachedFilename: AbsPath, secContext:Optional[SecurityContextConfig]=None) -> ProtocolFetcherReturn:
        """
        This is the method to be implemented by the stateful fetcher
        """
        pass
    
    @classmethod
    @abc.abstractmethod
    def GetSchemeHandlers(cls) -> "Mapping[str, Type[AbstractStatefulFetcher]]":
        return dict()
    
    @classmethod
    @abc.abstractmethod
    def GetNeededPrograms(cls) -> Sequence[SymbolicName]:
        return tuple()
    
    @staticmethod
    def ParseAndRemoveCredentials(remote_file: URIType) -> Tuple[parse.ParseResult, URIType]:
        parsedInputURL = parse.urlparse(remote_file)
        if parsedInputURL.username is not None:
            assert parsedInputURL.hostname is not None
            netloc = parsedInputURL.hostname
            if parsedInputURL.port is not None:
                netloc += ':' + str(parsedInputURL.port)
            # Now the credentials are properly removed
            remote_file = cast(URIType,
                parse.urlunparse(
                    (
                        parsedInputURL.scheme,
                        netloc,
                        parsedInputURL.path,
                        parsedInputURL.params,
                        parsedInputURL.query,
                        parsedInputURL.fragment
                    )
                )
            )
        
        return parsedInputURL, remote_file

class AbstractStatefulStreamingFetcher(AbstractStatefulFetcher):
    
    @abc.abstractmethod
    def fetch(self, remote_file:URIType, cachedFilename: Union[AbsPath, io.BytesIO], secContext:Optional[SecurityContextConfig]=None) -> ProtocolFetcherReturn:
        """
        This is the method to be implemented by the stateful fetcher
        """
        pass

def get_opener_with_auth(top_level_url: str, username: str, password: str) -> request.OpenerDirector:
	"""
	Taken from https://stackoverflow.com/a/44239906
	"""
	
	# create a password manager
	password_mgr = request.HTTPPasswordMgrWithPriorAuth()
	
	# Add the username and password.
	# If we knew the realm, we could use it instead of None.
	password_mgr.add_password(None, top_level_url, username, password, is_authenticated=True)
	
	handler = request.HTTPBasicAuthHandler(password_mgr)

	# create "opener" (OpenerDirector instance)
	return request.build_opener(handler)

def fetchClassicURL(remote_file:URIType, cachedFilename:Union[AbsPath, io.BytesIO], secContext:Optional[SecurityContextConfig]=None) -> ProtocolFetcherReturn:
    """
    Method to fetch contents from http, https and ftp

    :param remote_file:
    :param cachedFilename:
    :param secContext:
    """
    
    
    # This is needed to remove possible embedded credentials,
    # which should not be stored in the cache
    orig_remote_file = remote_file
    parsedInputURL, remote_file = AbstractStatefulFetcher.ParseAndRemoveCredentials(orig_remote_file)
    # Now the credentials are properly removed from remote_file
    # we get them from the parsed url
    username = parsedInputURL.username
    password = parsedInputURL.password
    
    if isinstance(secContext, dict):
        headers = secContext.get('headers', {}).copy()
        token = secContext.get('token')
        token_header = secContext.get('token_header')
        username = secContext.get('username', username)
        password = secContext.get('password', password)
        
        method = secContext.get('method')
    else:
        headers = {}
        method = None
        token = None
        token_header = None
        
    opener = request.urlopen
    if token is not None:
        if token_header is not None:
            headers[token_header] = token
        else:
            headers['Authorization'] = f'Bearer {token}'
    elif username is not None:
        if password is None:
            password = ''
        
        opener = get_opener_with_auth(remote_file, username, password).open
        
        # # Time to set up user and password in URL
        # parsedInputURL = parse.urlparse(remote_file)
        # 
        # netloc = parse.quote(username, safe='') + ':' + parse.quote(password,
        #                                                             safe='') + '@' + parsedInputURL.hostname
        # if parsedInputURL.port is not None:
        #     netloc += ':' + str(parsedInputURL.port)
        # 
        # # Now the credentials are properly set up
        # remote_file = cast(URIType, parse.urlunparse((parsedInputURL.scheme, netloc, parsedInputURL.path,
        #                                 parsedInputURL.params, parsedInputURL.query, parsedInputURL.fragment)))
    
    # Preparing where it is going to be written
    download_file : Union[io.TextIOBase, io.BufferedIOBase, io.RawIOBase, io.IOBase, io.BufferedWriter]
    if isinstance(cachedFilename, (io.TextIOBase, io.BufferedIOBase, io.RawIOBase, io.IOBase)):
        download_file = cachedFilename
    else:
        download_file = open(cachedFilename, 'wb')
    
    uri_with_metadata = None
    try:
        req_remote = request.Request(remote_file, headers=headers, method=method)
        with opener(req_remote) as url_response:
            
            uri_with_metadata = URIWithMetadata(
                uri=url_response.url,
                metadata=dict(url_response.headers.items())
            )
            
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
    
    return ContentKind.File, [ uri_with_metadata ], None

def fetchFTPURL(remote_file:URIType, cachedFilename:AbsPath, secContext:Optional[SecurityContextConfig]=None) -> ProtocolFetcherReturn:
    """
    Method to fetch contents from ftp

    :param remote_file:
    :param cachedFilename:
    :param secContext:
    """
    
    orig_remote_file = remote_file
    parsedInputURL, remote_file = AbstractStatefulFetcher.ParseAndRemoveCredentials(orig_remote_file)
    # Now the credentials are properly removed from remote_file
    # we get them from the parsed url
    username = parsedInputURL.username
    password = parsedInputURL.password
    
    kind = None
    connParams : Dict[str, Optional[Union[int, str]]] = {
        'HOST': parsedInputURL.hostname,
    }
    if parsedInputURL.port is not None:
        connParams['PORT'] = parsedInputURL.port
    
    if isinstance(secContext, dict):
        # There could be some corner cases where an empty
        # dictionary, or a dictionary without the needed keys
        # has been provided
        username = secContext.get('username', username)
        password = secContext.get('password', password)
    
    # Setting credentials only when it is set
    if (username is not None):
        connParams['USER'] = username
        connParams['PASSWORD'] = password  if password is not None  else  ''
    
    ftp_client = FTPDownloader(**connParams)
    retval = ftp_client.download(download_path=parsedInputURL.path, upload_path=cachedFilename)
    if isinstance(retval, list):
        kind = ContentKind.Directory
    else:
        kind = ContentKind.File
    
    return kind, [ URIWithMetadata(remote_file, {}) ], None

def sftpCopy(sftp:paramiko.SFTPClient, sshPath:AbsPath, localPath:AbsPath, sshStat: Optional[paramiko.SFTPAttributes] = None) -> Tuple[Union[int,bool], Optional[ContentKind]]:
    if sshStat is None:
        sshStat = sftp.stat(sshPath)
    
    # Trios
    transTrios = []
    recur : List[Tuple[AbsPath, paramiko.sftp_attr.SFTPAttributes, AbsPath]] = []
    kind : Optional[ContentKind] = None
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
                rPath = cast(AbsPath, os.path.join(sshPath, filename))
                lPath = cast(AbsPath, os.path.join(localPath, filename))
                rStat = sftp.stat(rPath)
                
                if rStat.st_mode is not None:
                    if stat.S_ISREG(rStat.st_mode):
                        transTrios.append((rPath, rStat, lPath))
                    elif stat.S_ISDIR(rStat.st_mode):
                        recur.append((rPath, rStat, lPath))
                else:
                    sftp_channel = sftp.get_channel()
                    server_name = None  if  sftp_channel is None  else  sftp_channel.getpeername()
                    logging.warning(f"Corner case where either paramiko or server {server_name} is not providing stats for {rPath}")
            kind = ContentKind.Directory
    
    numCopied : Union[bool, int]
    if kind is None:
        numCopied = False
    else:
        # Now, transfer these
        numCopied = 0
        for remotePath, rStat, filename in transTrios:
            sftp.get(remotePath, filename)
            # Only set it when it is possible
            if rStat.st_mtime is not None:
                st_atime = rStat.st_mtime  if rStat.st_atime is None  else  rStat.st_atime
                os.utime(filename, (st_atime, rStat.st_mtime))
            numCopied += 1
        
        # And recurse on these
        for rDir, rStat, lDir in recur:
            subNumCopied , _ = sftpCopy(sftp, rDir, lDir, sshStat=rStat)
            if isinstance(subNumCopied, int):
                numCopied += subNumCopied
    
    return numCopied, kind

# TODO: test this codepath
def fetchSSHURL(remote_file:URIType, cachedFilename:AbsPath, secContext:Optional[SecurityContextConfig]=None) -> ProtocolFetcherReturn:
    """
    Method to fetch contents from ssh / sftp servers

    :param remote_file:
    :param cachedFilename: Destination filename for the fetched content
    :param secContext: The security context containing the credentials
    """
    
    orig_remote_file = remote_file
    parsedInputURL, remote_file = AbstractStatefulFetcher.ParseAndRemoveCredentials(orig_remote_file)
    # Now the credentials are properly removed from remote_file
    # we get them from the parsed url
    username = parsedInputURL.username
    password = parsedInputURL.password
    
    # Sanitizing possible ill-formed inputs
    if not isinstance(secContext, dict):
        secContext = {}
    
    # Although username and password could be obtained from URL,
    # security context takes precedence
    username = secContext.get('username', username)
    password = secContext.get('password', password)
    sshKey = secContext.get('key')
    if (username is None) or ((password is None) and (sshKey is None)):
        raise FetcherException("Cannot download content from {} without credentials".format(remote_file))
    elif not isinstance(password, str) and not isinstance(sshKey, str):
        raise FetcherException("Cannot download content from {} with crippled credentials".format(remote_file))
    
    connBlock : MutableMapping[str, Union[paramiko.pkey.PKey, str]] = {
        'username': username,
    }
    
    if sshKey is not None:
        pKey = paramiko.pkey.PKey(data=sshKey)
        connBlock['pkey'] = pKey
    elif isinstance(password, str):
        connBlock['password'] = password
    
    sshHost = parsedInputURL.hostname
    if sshHost is None:
        sshHost = ''
    sshPort = parsedInputURL.port  if parsedInputURL.port is not None  else  DEFAULT_SSH_PORT
    sshPath = cast(AbsPath, parsedInputURL.path)
    
    t = None
    try:
        t = paramiko.Transport((sshHost, sshPort))
        # Performance reasons!
        # t.window_size = 134217727
        # t.use_compression()
        
        t.connect(**connBlock)
        sftp = paramiko.SFTPClient.from_transport(t)
        
        if sftp is None:
            raise FetcherException(f"Unable to set up a connection to {sshHost}:{sshPort}")
        _ , kind = sftpCopy(sftp, sshPath, cachedFilename)
        if kind is None:
            raise FetcherException(f"sftp copy from {sshHost}:{sshPort}/{sshPath} failed")
        return kind, [ URIWithMetadata(remote_file, {}) ], None
    finally:
        # Closing the SFTP connection
        if t is not None:
            t.close()

def fetchFile(remote_file:URIType, cachedFilename:AbsPath, secContext:Optional[SecurityContextConfig]=None) -> ProtocolFetcherReturn:
    """
    Method to fetch contents from local contents, optionally impersonating
    the original CURIE (useful for cache exports)

    :param remote_file:
    :param cachedFilename: Destination filename for the fetched content
    :param secContext: The security context containing the credentials
    """
    
    parsedInputURL = parse.urlparse(remote_file)
    localPath = cast(AbsPath, parsedInputURL.path)
    if not os.path.exists(localPath):
        raise FetcherException("Local path {} is not available".format(localPath))
    
    kind = None
    if os.path.isdir(localPath):
        kind = ContentKind.Directory
    elif os.path.isfile(localPath):
        kind = ContentKind.File
    else:
        raise FetcherException("Local path {} is neither a file nor a directory".format(localPath))
    # Efficient linking of data
    force_copy = parsedInputURL.fragment=="copy"
    metadata = {}
    the_remote_file = remote_file
    # Only impersonate under very specific conditions
    if parsedInputURL.query:
        qP = parse.parse_qs(parsedInputURL.query)
        new_remote_file = qP.get('inject_as')
        if new_remote_file:
            nP = parse.urlparse(new_remote_file[0])
            if nP.scheme:
                the_remote_file = cast(URIType, new_remote_file[0])
                force_copy = True
                metadata['injected'] = True
                metadata['impersonated'] = True
    link_or_copy(localPath, cachedFilename, force_copy=force_copy)
    
    return kind, [ URIWithMetadata(the_remote_file, metadata) ], None

DEFAULT_SCHEME_HANDLERS : Mapping[str, ProtocolFetcher] = {
    'http': fetchClassicURL,
    'https': fetchClassicURL,
    'ftp': fetchFTPURL,
    'sftp': fetchSSHURL,
    'ssh': fetchSSHURL,
    'file': fetchFile,
}
