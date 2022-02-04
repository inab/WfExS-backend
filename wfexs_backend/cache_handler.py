#!/usr/bin/env python
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

from __future__ import absolute_import

import datetime
import fnmatch
import hashlib
import json
import logging
import os
import os.path
import re
import shutil
import urllib.parse
import uuid

from typing import Iterator, List, Mapping
from typing import Optional, Pattern, Tuple, Union

from .common import *
from .utils.digests import ComputeDigestFromDirectory, ComputeDigestFromFile, stringifyFilenameDigest

class DatetimeEncoder(json.JSONEncoder):
        def default(self, obj):
                if isinstance(obj, datetime.datetime):
                        return obj.isoformat()
                # Let the base class default method raise the TypeError
                return super().default(obj)

META_JSON_POSTFIX = '_meta.json'
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
        metadata_input_file = input_file + META_JSON_POSTFIX
        
        return os.path.join(hashDir, metadata_input_file), input_file, os.path.join(hashDir, input_file)
    
    @staticmethod
    def getHashDir(destdir) -> AbsPath:
        hashDir = os.path.join(destdir,'uri_hashes')
        if not os.path.exists(hashDir):
            try:
                os.makedirs(hashDir)
            except IOError:
                errstr = "ERROR: Unable to create directory for workflow URI hashes {}.".format(hashDir)
                raise WFException(errstr)
        
        return hashDir
    
    @staticmethod
    def _parseMetaStructure(fMeta: AbsPath) -> Mapping[str, Any]:
        with open(fMeta, mode="r", encoding="utf-8") as eH:
            metaStructure = json.load(eH)
        
        # Generating an stamp signature
        if metaStructure.get('stamp') is None:
            metaStructure['stamp'] = datetime.datetime.fromtimestamp(os.path.getmtime(fMeta), tz=datetime.timezone.utc).isoformat() + 'Z'
        
        metaStructure.setdefault('path', dict())['meta'] = {
            'relative': os.path.basename(fMeta),
            'absolute': fMeta
        }
        
        # Generating a path structure for old cases
        if (metaStructure.get('resolves_to') is None) and (metaStructure['path'].get('relative') is None):
            if fMeta.endswith(META_JSON_POSTFIX):
                fname = fMeta[0:-len(META_JSON_POSTFIX)]
                if os.path.exists(fname):
                    finalCachedFilename = os.path.realpath(fname)
                    hashDir = os.path.dirname(fMeta)
                    metaStructure['path'].update({
                        'relative': os.path.relpath(finalCachedFilename, hashDir),
                        'absolute': finalCachedFilename
                    })
        
        return metaStructure
    
    @staticmethod
    def _translateArgs(args:Iterator[str]) -> List[Pattern]:
        return list(map(lambda e: re.compile(fnmatch.translate(e)), args))
        
    
    def list(self, destdir:AbsPath, *args, acceptGlob:bool=False, cascade:bool=False) -> Iterator[Tuple[AnyURI, Mapping[str,Any]]]:
        """
        This method iterates over the list of metadata entries,
        using glob patterns if requested
        """
        entries = set(args)
        if entries and acceptGlob:
            reEntries = self._translateArgs(entries)
        else:
            reEntries = None
        
        cascadeEntries = set()
        unmatchedEntries = dict()
        returnEntries = []
        
        hashDir = self.getHashDir(destdir)
        with os.scandir(hashDir) as hD:
            for entry in hD:
                # We are avoiding to enter in loops around '.' and '..'
                if entry.is_file(follow_symlinks=False) and entry.name.endswith(META_JSON_POSTFIX):
                    try:
                        metaStructure = self._parseMetaStructure(entry.path)
                        meta_uri = None
                        if not entries:
                            for meta in metaStructure['metadata_array']:
                                meta_uri = meta['uri']
                                break
                        else:
                            for meta in metaStructure['metadata_array']:
                                meta_uri = meta['uri']
                                meta_uri_str = meta_uri['uri']  if isinstance(meta_uri, dict)  else  meta_uri
                                if reEntries and any(map(lambda r: r.match(meta_uri_str) is not None, reEntries)):
                                    break
                                elif meta_uri_str in entries:
                                    break
                                elif cascade:
                                    # Only when something was specified
                                    unmatchedEntries[meta_uri_str] = metaStructure
                                meta_uri = None
                        
                        if meta_uri is not None:
                            yield meta_uri, metaStructure
                            if cascade and len(entries) > 0:
                                # Only when something was specified
                                resolves_to = metaStructure.get('resolves_to')
                                if resolves_to is not None:
                                    if not isinstance(resolves_to, list):
                                        resolves_to = [ resolves_to ]
                                    
                                    cascadeEntries.add(*resolves_to)
                    except:
                        pass
        
        # Now, the cascade passes
        while len(cascadeEntries) > 0:
            newCascadeEntries = set()
            for meta_uri in cascadeEntries:
                if meta_uri in unmatchedEntries:
                    metaStructure = unmatchedEntries.pop(meta_uri)
                    
                    resolves_to = metaStructure.get('resolves_to')
                    if resolves_to is not None:
                        # Only when something was specified
                        if not isinstance(resolves_to, list):
                            resolves_to = [ resolves_to ]
                        
                        newCascadeEntries.add(*resolves_to)
                    
                    # Yielding what it was gathered
                    yield meta_uri, metaStructure
            
            cascadeEntries = newCascadeEntries
    
    def remove(self, destdir:AbsPath, *args, doRemoveFiles:bool=False, acceptGlob:bool=False, cascade:bool=False) -> Iterator[Tuple[AnyURI, AbsPath, Optional[AbsPath]]]:
        """
        This method iterates elements from metadata entries,
        and optionally the cached value
        """
        if len(args) > 0:
            hashDir = self.getHashDir(destdir)
            for meta_uri, metaStructure in self.list(destdir, *args, acceptGlob=acceptGlob, cascade=cascade):
                removeCachedCopyPath = None
                for meta in metaStructure['metadata_array']:
                    if doRemoveFiles and not meta['metadata'].get('injected'):
                        # Decide the removal path
                        finalCachedFilename = None
                        relFinalCachedFilename = metaStructure.get('path', {}).get('relative')
                        if relFinalCachedFilename is not None:
                            finalCachedFilename = os.path.normpath(os.path.join(hashDir, relFinalCachedFilename))
                        
                            if not os.path.exists(finalCachedFilename):
                                self.logger.warning(f'Relative cache path {relFinalCachedFilename} was not found')
                        
                        if finalCachedFilename is None:
                            finalCachedFilename = metaStructure.get('path', {}).get('absolute')
                            
                        if (finalCachedFilename is not None) and os.path.exists(finalCachedFilename):
                            removeCachedCopyPath = finalCachedFilename
                        else:
                            self.logger.warning(f'Absolute cache path {finalCachedFilename} was not found. Cache miss!!!')
                        
                        break
                
                if removeCachedCopyPath is not None:
                    self.logger.info(f"Removing cache {metaStructure['fingerprint']} physical path {removeCachedCopyPath}")
                    if os.path.isdir(removeCachedCopyPath):
                        shutil.rmtree(removeCachedCopyPath, ignore_errors=True)
                    else:
                        os.unlink(removeCachedCopyPath)
                
                metaFile = metaStructure['path']['meta']['absolute']
                self.logger.info(f"Removing cache {metaStructure.get('fingerprint')} metadata {metaFile}")
                os.unlink(metaFile)
                
                yield meta_uri, metaFile, removeCachedCopyPath
    
    def inject(self, destdir:AbsPath, the_remote_file:Union[urllib.parse.ParseResult, URIType], fetched_metadata_array:Optional[List[URIWithMetadata]]=None, finalCachedFilename:Optional[AbsPath]=None, tempCachedFilename:Optional[AbsPath]=None, inputKind:Optional[Union[ContentKind, AbsPath, List[AbsPath]]]=None) -> Tuple[AbsPath, Fingerprint]:
        return self._inject(
            self.getHashDir(destdir),
            the_remote_file,
            fetched_metadata_array=fetched_metadata_array,
            finalCachedFilename=finalCachedFilename,
            tempCachedFilename=tempCachedFilename,
            destdir=destdir,
            inputKind=inputKind
        )
    
    def _inject(self, hashDir:AbsPath, the_remote_file:Union[urllib.parse.ParseResult, URIType], fetched_metadata_array:Optional[List[URIWithMetadata]]=None, finalCachedFilename:Optional[AbsPath]=None, tempCachedFilename:Optional[AbsPath]=None, destdir:Optional[AbsPath]=None, inputKind:Optional[Union[ContentKind, AbsPath, List[AbsPath]]]=None) -> Tuple[AbsPath, Fingerprint]:
        """
        This method has been created to be able to inject a cached metadata entry
        """
        if isinstance(the_remote_file, urllib.parse.ParseResult):
            the_remote_file = urllib.parse.urlunparse(the_remote_file)
        
        uriMetaCachedFilename , _ , _ = self._genUriMetaCachedFilename(hashDir, the_remote_file)

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
            if fetched_metadata_array is None:
                fetched_metadata_array = [
                    URIWithMetadata(
                        uri=the_remote_file,
                        metadata={
                            'injected': True
                        }
                    )
                ]
            metaStructure = {
                'stamp': datetime.datetime.utcnow().isoformat() + 'Z',
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
            
            json.dump(metaStructure, mOut, cls=DatetimeEncoder)
        
        return finalCachedFilename, fingerprint
    
    def validate(self, destdir:AbsPath, *args, acceptGlob:bool=False, cascade:bool=False) -> Tuple[int, int]:
        hashDir = self.getHashDir(destdir)
        
        for meta_uri, metaStructure in self.list(destdir, *args, acceptGlob=acceptGlob, cascade=cascade):
            inputKind = metaStructure.get('kind')
            validated = False
            if inputKind is None:
                inputKind = metaStructure['resolves_to']
                
                # Blindly accept it
                validated = True
            else:
                # Additional checks
                stored_fingerprint = metaStructure.get('fingerprint')
                if stored_fingerprint is not None:
                    inputKind = ContentKind(inputKind)
                    relFinalCachedFilename = metaStructure.get('path', {}).get('relative')
                    finalCachedFilename = os.path.normpath(os.path.join(hashDir, relFinalCachedFilename))
                    
                    if not os.path.exists(finalCachedFilename):
                        self.logger.warning(f'Relative cache path {relFinalCachedFilename} was not found')
                        finalCachedFilename = metaStructure.get('path', {}).get('absolute')
                        
                        if (finalCachedFilename is None) or not os.path.exists(finalCachedFilename):
                            self.logger.warning(f'Absolute cache path {finalCachedFilename} was not found. Cache miss!!!')
                            
                            # Cleaning up
                            metaStructure = None
                    
                    computed_fingerprint = None
                    if metaStructure is not None:
                        if inputKind == ContentKind.Directory:
                            computed_fingerprint = ComputeDigestFromDirectory(finalCachedFilename, repMethod=stringifyFilenameDigest)
                        elif inputKind == ContentKind.File:
                            computed_fingerprint = ComputeDigestFromFile(finalCachedFilename, repMethod=stringifyFilenameDigest)
                    
                    validated = computed_fingerprint == stored_fingerprint
            
            yield meta_uri, validated, metaStructure
    
    def fetch(self, remote_file:Union[urllib.parse.ParseResult, URIType, List[Union[urllib.parse.ParseResult, URIType]]], destdir:AbsPath, offline:bool, ignoreCache:bool=False, registerInCache:bool=True, secContext:Optional[SecurityContextConfig]=None) -> Tuple[ContentKind, AbsPath, List[URIWithMetadata]]:
        # The directory with the content, whose name is based on sha256
        if not os.path.exists(destdir):
            try:
                os.makedirs(destdir)
            except IOError:
                errstr = "ERROR: Unable to create directory for workflow inputs {}.".format(destdir)
                raise WFException(errstr)
        
        # The directory where the symlinks derived from SHA1 obtained from URIs
        # to the content are placed
        hashDir = self.getHashDir(destdir)
        
        # This filename will only be used when content is being fetched
        tempCachedFilename = os.path.join(destdir, 'caching-' + str(uuid.uuid4()))
        # This is an iterative process, where the URI is resolved and peeled until a basic fetching protocol is reached
        inputKind = remote_file
        metadata_array = []
        while not isinstance(inputKind, ContentKind):
            # These elements are alternative URIs. Any of them should
            # provide the very same content
            altInputs = inputKind  if isinstance(inputKind, list)  else  [ inputKind ]
            uncachedInputs = list()
            for the_remote_file in altInputs:
                if isinstance(the_remote_file, urllib.parse.ParseResult):
                    parsedInputURL = the_remote_file
                    the_remote_file = urllib.parse.urlunparse(the_remote_file)
                else:
                    parsedInputURL = urllib.parse.urlparse(the_remote_file)
                
                # uriCachedFilename is going to be always a symlink
                uriMetaCachedFilename , uriCachedFilename , absUriCachedFilename = self._genUriMetaCachedFilename(hashDir, the_remote_file)
                
                # TODO: check cached state in future database
                # Cleaning up
                if registerInCache and ignoreCache:
                    # Removing the metadata
                    if os.path.exists(uriMetaCachedFilename):
                        os.unlink(uriMetaCachedFilename)
                    
                    # Removing the symlink
                    if os.path.exists(absUriCachedFilename):
                        os.unlink(absUriCachedFilename)
                    # We cannot remove the content as
                    # it could be referenced by other symlinks
                
                refetch = not registerInCache or ignoreCache or not os.path.exists(uriMetaCachedFilename) or os.stat(uriMetaCachedFilename).st_size == 0
                
                metaStructure = None
                if not refetch:
                    try:
                        metaStructure = self._parseMetaStructure(uriMetaCachedFilename)
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
                        relFinalCachedFilename = metaStructure.get('path', {}).get('relative', os.readlink(absUriCachedFilename))
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
                    break
                else:
                    uncachedInputs.append((the_remote_file, parsedInputURL))
            
            if metaStructure is not None:
                fetched_metadata_array = list(map(lambda rm: URIWithMetadata(uri=rm['uri'], metadata=rm['metadata'], preferredName=rm.get('preferredName')), metaStructure['metadata_array']))
            elif offline:
                # As this is a handler for online resources, comply with offline mode
                raise WFException(f"Cannot download content in offline mode from {remote_file} to {uriCachedFilename}")
            else:
                # Cache miss
                # As this is a handler for online resources, comply with offline mode
                nested_exception = None
                failed = True
                for the_remote_file, parsedInputURL in uncachedInputs:
                    # Content is fetched here
                    theScheme = parsedInputURL.scheme.lower()
                    schemeHandler = self.schemeHandlers.get(theScheme)
                    
                    try:
                        if schemeHandler is None:
                            errmsg = f'No {theScheme} scheme handler for {the_remote_file} (while processing {remote_file}). Was this data injected in the cache?'
                            self.logger.error(errmsg)
                            raise WFException(errmsg) from nested_exception

                        try:
                            # Content is fetched here
                            inputKind, fetched_metadata_array = schemeHandler(the_remote_file, tempCachedFilename, secContext=secContext)
                            
                            # The cache entry is injected
                            finalCachedFilename, fingerprint = self._inject(
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
                                next_input_file = hashlib.sha1(the_remote_file.encode('utf-8')).hexdigest()
                            
                            if os.path.lexists(absUriCachedFilename):
                                os.unlink(absUriCachedFilename)
                            
                            os.symlink(next_input_file, absUriCachedFilename)
                        except WFException as we:
                            raise we from nested_exception
                        except Exception as e:
                            errmsg = "Cannot download content from {} to {} (while processing {}) (temp file {}): {}".format(the_remote_file, uriCachedFilename, remote_file, tempCachedFilename, e)
                            self.logger.error(errmsg)
                            raise WFException(errmsg) from nested_exception
                    except WFException as wfe:
                        # Keeping the newest element of the chain
                        nested_exception = wfe
                    else:
                        # This URI could be resolved (implement alternative URLs)
                        failed = False
                        break
                    
                # No one of the URIs could be fetched or resolved
                if failed:
                    if len(uncachedInputs) > 1:
                        raise WFException(f"{len(uncachedInputs)} alternate URIs have failed (see nested reasons)") from nested_exception
                    else:
                        raise nested_exception
            
            # Store the metadata
            metadata_array.extend(fetched_metadata_array)

        return inputKind, finalCachedFilename, metadata_array
