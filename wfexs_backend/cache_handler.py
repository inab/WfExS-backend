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
        self.logger = logging.getLogger(self.__class__.__name__)
        
        # TODO: create caching database
        self.cacheDir = cacheDir
        self.schemeHandlers = {}
        
        self.addSchemeHandlers(schemeHandlers)
    
    def addSchemeHandlers(self, schemeHandlers:Mapping[str,ProtocolFetcher]) -> None:
        if isinstance(schemeHandlers, dict):
            self.schemeHandlers.update(schemeHandlers)
    
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
            
            input_file = hashlib.sha1(the_remote_file.encode('utf-8')).hexdigest()
            metadata_input_file = input_file + '_meta.json'
            uriCachedFilename = os.path.join(hashDir, input_file)
            uriMetaCachedFilename = os.path.join(hashDir, metadata_input_file)
            
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
            
            if not registerInCache or ignoreCache or not os.path.exists(uriCachedFilename) or not os.path.exists(uriMetaCachedFilename):
                # As this is a handler for online resources, comply with offline mode
                if offline:
                    raise WFException("Cannot download content in offline mode from {} to {}".format(remote_file, uriCachedFilename))
                
                # Content is fetched here
                theScheme = parsedInputURL.scheme.lower()
                schemeHandler = self.schemeHandlers.get(theScheme)

                if schemeHandler is None:
                    raise WFException('No {} scheme handler for {} (while processing {})'.format(theScheme, the_remote_file, remote_file))

                try:
                    # Content is fetched here
                    inputKind, fetched_metadata_array = schemeHandler(the_remote_file, tempCachedFilename, secContext=secContext)
                    
                    fingerprint = None
                    if isinstance(inputKind, ContentKind):
                        if os.path.isfile(tempCachedFilename): # inputKind == ContentKind.File:
                            fingerprint = ComputeDigestFromFile(tempCachedFilename, repMethod=stringifyFilenameDigest)
                            putativeInputKind = ContentKind.File
                        elif os.path.isdir(tempCachedFilename): # inputKind == ContentKind.Directory:
                            fingerprint = ComputeDigestFromDirectory(tempCachedFilename, repMethod=stringifyFilenameDigest)
                            putativeInputKind = ContentKind.Directory
                        else:
                            raise WFException("Cached {} from {} is neither file nor directory".format(tempCachedFilename, remote_file))
                        
                        if inputKind != putativeInputKind:
                            self.logger.error("FIXME: Mismatch at {} : {} vs {}".format(remote_file, inputKind, putativeInputKind))
                    
                    # Saving the metadata
                    with open(uriMetaCachedFilename, mode="w", encoding="utf-8") as mOut:
                        # Serializing the metadata
                        metaStructure = {
                            'metadata_array': list(map(lambda m: {'uri': m.uri, 'metadata': m.metadata}, fetched_metadata_array))
                        }
                        if fingerprint is not None:
                            metaStructure['kind'] = str(inputKind.value)
                            metaStructure['fingerprint'] = fingerprint
                        else:
                            metaStructure['resolves_to'] = inputKind
                        
                        json.dump(metaStructure, mOut)
                    
                    # Now, creating the symlink
                    if fingerprint is not None:
                        finalCachedFilename = os.path.join(destdir, fingerprint)
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
                
            else:
                with open(uriMetaCachedFilename, mode="r", encoding="utf-8") as mIn:
                    # Deserializing the metadata
                    metaStructure = json.load(mIn)
                    inputKind = metaStructure.get('kind')
                    if inputKind is None:
                        inputKind = metaStructure['resolves_to']
                    else:
                        inputKind = ContentKind(inputKind)
                        finalCachedFilename = os.path.normpath(os.path.join(hashDir, os.readlink(uriCachedFilename)))
                    fetched_metadata_array = list(map(lambda m: URIWithMetadata(m['uri'],m['metadata']), metaStructure['metadata_array']))
            
            # Store the metadata
            metadata_array.extend(fetched_metadata_array)

        return inputKind, finalCachedFilename, metadata_array