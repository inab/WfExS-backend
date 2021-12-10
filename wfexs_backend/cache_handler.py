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

import hashlib
import json
import logging
import os
import os.path
import shutil
import urllib.parse
import uuid

from typing import List, Mapping
from typing import Optional, Tuple, Union

from .common import *

class SchemeHandlerCacheHandler:
    def __init__(self, cacheDir, schemeHandlers:Mapping[str,ProtocolFetcher]):
        # Getting a logger focused on specific classes
        import inspect
        
        self.logger = logging.getLogger(dict(inspect.getmembers(self))['__module__'] + '::' + self.__class__.__name__)
        
        # TODO: create caching database
        self.cacheDir = cacheDir
        self.schemeHandlers = dict()
        
        self.addSchemeHandlers(schemeHandlers)
    
    def addSchemeHandlers(self, schemeHandlers:Mapping[str, ProtocolFetcher]) -> None:
        if isinstance(schemeHandlers, dict):
            self.schemeHandlers.update(schemeHandlers)
    
    def _genUriMetaCachedFilename(self, hashDir:AbsPath, the_remote_file:Union[urllib.parse.ParseResult, URIType]) -> Tuple[AbsPath, AbsPath]:
        input_file = hashlib.sha1(the_remote_file.encode('utf-8')).hexdigest()
        metadata_input_file = input_file + '_meta.json'
        
        return os.path.join(hashDir, metadata_input_file), os.path.join(hashDir, input_file)
    
    def inject(self, hashDir:AbsPath, the_remote_file:Union[urllib.parse.ParseResult, URIType], fetched_metadata_array:List[URIWithMetadata]=list(), finalCachedFilename:Optional[AbsPath]=None, tempCachedFilename:Optional[AbsPath]=None, destdir:Optional[AbsPath]=None, inputKind:Optional[Union[ContentKind, AbsPath]]=None) -> Tuple[AbsPath, Fingerprint]:
        """
        This method has been created to be able to inject a cached metadata entry
        """
        if isinstance(the_remote_file, urllib.parse.ParseResult):
            the_remote_file = urllib.parse.urlunparse(the_remote_file)
        
        uriMetaCachedFilename , _ = self._genUriMetaCachedFilename(hashDir, the_remote_file)

        if tempCachedFilename is None:
            tempCachedFilename = finalCachedFilename
        
        if inputKind is None:
            if tempCachedFilename is None:
                raise WFException(f"No defined paths or input kinds, which would lead to an empty cache entry")
                
            if os.path.isdir(tempCachedFilename):
                inputKind = ContentKind.Directory
            elif os.path.isfile(tempCachedFilename):
                inputKind = ContentKind.File
            else:
                raise WFException(f"Local path {tempCachedFilename} is neither a file nor a directory")
        
        fingerprint = None
        # Are we dealing with a redirection?
        if isinstance(inputKind, ContentKind):
            if os.path.isfile(tempCachedFilename): # inputKind == ContentKind.File:
                fingerprint = ComputeDigestFromFile(tempCachedFilename, repMethod=stringifyFilenameDigest)
                putativeInputKind = ContentKind.File
            elif os.path.isdir(tempCachedFilename): # inputKind == ContentKind.Directory:
                fingerprint = ComputeDigestFromDirectory(tempCachedFilename, repMethod=stringifyFilenameDigest)
                putativeInputKind = ContentKind.Directory
            else:
                raise WFException(f"FIXME: Cached {tempCachedFilename} from {the_remote_file} is neither file nor directory")
            
            if inputKind != putativeInputKind:
                self.logger.error(f"FIXME: Mismatch at {the_remote_file} : {inputKind} vs {putativeInputKind}")
            
            if finalCachedFilename is None:
                finalCachedFilename = os.path.join(destdir, fingerprint)
        else:
            finalCachedFilename = None
        
        # Saving the metadata
        with open(uriMetaCachedFilename, mode="w", encoding="utf-8") as mOut:
            # Serializing the metadata
            metaStructure = {
                'metadata_array': list(map(lambda m: {'uri': m.uri, 'metadata': m.metadata, 'preferredName': m.preferredName}, fetched_metadata_array))
            }
            if finalCachedFilename is not None:
                metaStructure['kind'] = str(inputKind.value)
                metaStructure['fingerprint'] = fingerprint
                metaStructure['path'] = {
                    'relative': os.path.relpath(finalCachedFilename, hashDir),
                    'absolute': finalCachedFilename
                }
            else:
                metaStructure['resolves_to'] = inputKind
            
            json.dump(metaStructure, mOut)
        
        return finalCachedFilename, fingerprint
    
    def fetch(self, remote_file:Union[urllib.parse.ParseResult, URIType], destdir:AbsPath, offline:bool, ignoreCache:bool=False, registerInCache:bool=True, secContext:Optional[SecurityContextConfig]=None) -> Tuple[ContentKind, AbsPath, List[URIWithMetadata]]:
        # The directory with the content, whose name is based on sha256
        if not os.path.exists(destdir):
            try:
                os.makedirs(destdir)
            except IOError:
                errstr = "ERROR: Unable to create directory for workflow inputs {}.".format(destdir)
                raise WFException(errstr)
        
        # The directory where the symlinks derived from SHA1 obtained from URIs
        # to the content are placed
        hashDir = os.path.join(destdir,'uri_hashes')
        if not os.path.exists(hashDir):
            try:
                os.makedirs(hashDir)
            except IOError:
                errstr = "ERROR: Unable to create directory for workflow URI hashes {}.".format(hashDir)
                raise WFException(errstr)
        
        # This filename will only be used when content is being fetched
        tempCachedFilename = os.path.join(destdir, 'caching-' + str(uuid.uuid4()))
        # This is an iterative process, where the URI is resolved and peeled until a basic fetching protocol is reached
        inputKind = remote_file
        metadata_array = []
        while not isinstance(inputKind, ContentKind):
            the_remote_file = inputKind
            if isinstance(the_remote_file, urllib.parse.ParseResult):
                parsedInputURL = the_remote_file
                the_remote_file = urllib.parse.urlunparse(the_remote_file)
            else:
                parsedInputURL = urllib.parse.urlparse(the_remote_file)
            
            # uriCachedFilename is going to be always a symlink
            uriMetaCachedFilename , uriCachedFilename = self._genUriMetaCachedFilename(hashDir, the_remote_file)
            
            # TODO: check cached state in future database
            # Cleaning up
            if registerInCache and ignoreCache:
                # Removing the metadata
                if os.path.exists(uriMetaCachedFilename):
                    os.unlink(uriMetaCachedFilename)
                
                # Removing the symlink
                if os.path.exists(uriCachedFilename):
                    os.unlink(uriCachedFilename)
                # We cannot remove the content as
                # it could be referenced by other symlinks
            
            refetch = not registerInCache or ignoreCache or not os.path.exists(uriCachedFilename) or not os.path.exists(uriMetaCachedFilename) or os.stat(uriMetaCachedFilename).st_size == 0
            
            metaStructure = None
            if not refetch:
                try:
                    with open(uriMetaCachedFilename, mode="r", encoding="utf-8") as mIn:
                        # Deserializing the metadata
                        metaStructure = json.load(mIn)
                except:
                    # Metadata is corrupted
                    self.logger.warning(f'Metadata cache {uriMetaCachedFilename} is corrupted. Ignoring.')
                    pass
            
            if metaStructure is not None:
                # Metadata cache hit
                inputKind = metaStructure.get('kind')
                if inputKind is None:
                    inputKind = metaStructure['resolves_to']
                else:
                    # Additional checks
                    inputKind = ContentKind(inputKind)
                    relFinalCachedFilename = metaStructure.get('path', {}).get('relative', os.readlink(uriCachedFilename))
                    finalCachedFilename = os.path.normpath(os.path.join(hashDir, relFinalCachedFilename))
                    
                    if not os.path.exists(finalCachedFilename):
                        self.logger.warning(f'Relative cache path {relFinalCachedFilename} was not found')
                        finalCachedFilename = metaStructure.get('path', {}).get('absolute')
                        
                        if (finalCachedFilename is None) or not os.path.exists(finalCachedFilename):
                            self.logger.warning(f'Absolute cache path {finalCachedFilename} was not found. Cache miss!!!')
                            
                            # Cleaning up
                            metaStructure = None
                
            if metaStructure is not None:
                # Cache hit
                # As the content still exists, get the metadata
                
                fetched_metadata_array = list(map(lambda rm: URIWithMetadata(uri=rm['uri'], metadata=rm['metadata'], preferredName=rm.get('preferredName')), metaStructure['metadata_array']))
            else:
                # Cache miss
                # As this is a handler for online resources, comply with offline mode
                if offline:
                    raise WFException(f"Cannot download content in offline mode from {remote_file} to {uriCachedFilename}")
                
                # Content is fetched here
                theScheme = parsedInputURL.scheme.lower()
                schemeHandler = self.schemeHandlers.get(theScheme)

                if schemeHandler is None:
                    raise WFException(f'No {theScheme} scheme handler for {the_remote_file} (while processing {remote_file}). Was this data injected in the cache?')

                try:
                    # Content is fetched here
                    inputKind, fetched_metadata_array = schemeHandler(the_remote_file, tempCachedFilename, secContext=secContext)
                    
                    # The cache entry is injected
                    finalCachedFilename, fingerprint = self.inject(
                        hashDir,
                        the_remote_file,
                        fetched_metadata_array,
                        tempCachedFilename=tempCachedFilename,
                        destdir=destdir,
                        inputKind=inputKind
                    )
                    
                    # Now, creating the symlink
                    # (which should not be needed in the future)
                    if finalCachedFilename is not None:
                        if os.path.isfile(finalCachedFilename):
                            os.unlink(finalCachedFilename)
                        elif os.path.isdir(finalCachedFilename):
                            shutil.rmtree(finalCachedFilename)
                        os.rename(tempCachedFilename, finalCachedFilename)
                        
                        next_input_file = os.path.relpath(finalCachedFilename, hashDir)
                    else:
                        next_input_file = hashlib.sha1(inputKind.encode('utf-8')).hexdigest()
                    
                    if os.path.lexists(uriCachedFilename):
                        os.unlink(uriCachedFilename)
                    os.symlink(next_input_file, uriCachedFilename)
                except WFException as we:
                    raise we
                except Exception as e:
                    raise WFException("Cannot download content from {} to {} (while processing {}) (temp file {}): {}".format(the_remote_file, uriCachedFilename, remote_file, tempCachedFilename, e))
            
            # Store the metadata
            metadata_array.extend(fetched_metadata_array)

        return inputKind, finalCachedFilename, metadata_array