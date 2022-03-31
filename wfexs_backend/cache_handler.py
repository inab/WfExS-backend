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
import hashlib
import json
import logging
import os
import os.path
import shutil
import traceback
import urllib.parse
import uuid

from typing import cast, Any, Dict, Iterator, List, Mapping, Set
from typing import Optional, Tuple, Union

from .common import AbstractWfExSException
from .common import AbsPath, RelPath
from .common import Attribution, DefaultNoLicenceTuple
from .common import ContentKind, LicensedURI, ProtocolFetcher, URIWithMetadata
from .common import Fingerprint, SecurityContextConfig, URIType

from .fetchers import FetcherException

from .utils.digests import ComputeDigestFromDirectory, ComputeDigestFromFile, stringifyFilenameDigest
from .utils.misc import config_validate
from .utils.misc import DatetimeEncoder, jsonFilterDecodeFromStream, translate_glob_args

META_JSON_POSTFIX = '_meta.json'

class CacheHandlerException(AbstractWfExSException):
    pass

class SchemeHandlerCacheHandler:
    CACHE_METADATA_SCHEMA = cast(RelPath, 'cache-metadata.json')
    
    def __init__(self, cacheDir, schemeHandlers:Mapping[str,ProtocolFetcher]):
        # Getting a logger focused on specific classes
        import inspect
        
        self.logger = logging.getLogger(dict(inspect.getmembers(self))['__module__'] + '::' + self.__class__.__name__)
        
        # TODO: create caching database
        self.cacheDir = cacheDir
        self.schemeHandlers : Dict[str, ProtocolFetcher] = dict()
        
        self.addSchemeHandlers(schemeHandlers)
    
    def addSchemeHandlers(self, schemeHandlers:Mapping[str, ProtocolFetcher]) -> None:
        if isinstance(schemeHandlers, dict):
            self.schemeHandlers.update(schemeHandlers)
    
    def _genUriMetaCachedFilename(self, hashDir:AbsPath, the_remote_file: URIType) -> Tuple[AbsPath, RelPath, AbsPath]:
        input_file = hashlib.sha1(the_remote_file.encode('utf-8')).hexdigest()
        metadata_input_file = input_file + META_JSON_POSTFIX
        
        return cast(AbsPath, os.path.join(hashDir, metadata_input_file)), cast(RelPath, input_file), cast(AbsPath, os.path.join(hashDir, input_file))
    
    @staticmethod
    def getHashDir(destdir) -> AbsPath:
        hashDir = os.path.join(destdir,'uri_hashes')
        if not os.path.exists(hashDir):
            try:
                os.makedirs(hashDir)
            except IOError:
                errstr = "ERROR: Unable to create directory for workflow URI hashes {}.".format(hashDir)
                raise CacheHandlerException(errstr)
        
        return cast(AbsPath, hashDir)
    
    def _parseMetaStructure(self, fMeta: AbsPath, validate_meta: bool = False) -> Mapping[str, Any]:
        """
        Parse cache metadata structure, with optional validation
        """
        
        with open(fMeta, mode="r", encoding="utf-8") as eH:
            metaStructure = jsonFilterDecodeFromStream(eH)
        
        # Generating an stamp signature
        if metaStructure.get('stamp') is None:
            metaStructure['stamp'] = datetime.datetime.fromtimestamp(os.path.getmtime(fMeta), tz=datetime.timezone.utc)
        
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
        
        if validate_meta or self.logger.getEffectiveLevel() <= logging.DEBUG:
            # Serialize JSON to serialize instances and deserialize without typecasts
            # in order to properly validate
            flatMetaStructure = json.loads(json.dumps(metaStructure, cls=DatetimeEncoder))
            
            val_errors = config_validate(flatMetaStructure, self.CACHE_METADATA_SCHEMA)
            if len(val_errors) > 0:
                self.logger.error(f'CMVE => {len(val_errors)} errors in cache metadata file {fMeta}')
                for i_err, val_error in enumerate(val_errors):
                    self.logger.error(f'CMVE {i_err}: {val_error}')
        
        return metaStructure
    
    def list(self, destdir:AbsPath, *args: str, acceptGlob:bool=False, cascade:bool=False) -> Iterator[Tuple[LicensedURI, Mapping[str,Any]]]:
        """
        This method iterates over the list of metadata entries,
        using glob patterns if requested
        """
        entries = set(args)
        if entries and acceptGlob:
            reEntries = translate_glob_args(list(entries))
        else:
            reEntries = None
        
        cascadeEntries : Set[URIType] = set()
        unmatchedEntries = dict()
        
        hashDir = self.getHashDir(destdir)
        with os.scandir(hashDir) as hD:
            for entry in hD:
                # We are avoiding to enter in loops around '.' and '..'
                if entry.is_file(follow_symlinks=False) and entry.name.endswith(META_JSON_POSTFIX):
                    try:
                        metaStructure = self._parseMetaStructure(cast(AbsPath, entry.path))
                        meta_uri = None
                        if not entries:
                            for meta in metaStructure['metadata_array']:
                                meta_uri = meta['uri']
                                break
                        else:
                            for meta in metaStructure['metadata_array']:
                                meta_uri = meta['uri']
                                # CLEANUP
                                # meta_uri_str = meta_uri['uri']  if isinstance(meta_uri, dict)  else  meta_uri
                                meta_uri_str = meta_uri
                                if reEntries and any(map(lambda r: r.match(meta_uri_str) is not None, reEntries)):
                                    break
                                elif meta_uri_str in entries:
                                    break
                                elif cascade:
                                    # Only when something was specified
                                    unmatchedEntries[meta_uri_str] = metaStructure
                                meta_uri = None
                        
                        if meta_uri is not None:
                            licences = metaStructure.get('licences', DefaultNoLicenceTuple)
                            if isinstance(licences, list):
                                licences = tuple(licences)
                            c_licensed_meta_uri : LicensedURI = LicensedURI(
                                uri=meta_uri,
                                licences=licences,
                                attributions=Attribution.ParseRawAttributions(metaStructure.get('attributions'))
                            )
                            yield c_licensed_meta_uri, metaStructure
                            if cascade and len(entries) > 0:
                                # Only when something was specified
                                c_resolves_to : Optional[List[URIType]] = metaStructure.get('resolves_to')
                                if c_resolves_to is not None:
                                    if not isinstance(c_resolves_to, list):
                                        c_resolves_to = [ c_resolves_to ]
                                    
                                    cascadeEntries.add(*c_resolves_to)
                    except Exception as e:
                        self.logger.debug(traceback.format_exc())
        
        # Now, the cascade passes
        while len(cascadeEntries) > 0:
            newCascadeEntries : Set[URIType] = set()
            for meta_uri in cascadeEntries:
                if meta_uri in unmatchedEntries:
                    metaStructure = unmatchedEntries.pop(meta_uri)
                    
                    resolves_to : Optional[List[URIType]] = metaStructure.get('resolves_to')
                    if resolves_to is not None:
                        # Only when something was specified
                        if not isinstance(resolves_to, list):
                            resolves_to = [ resolves_to ]
                        
                        newCascadeEntries.add(*resolves_to)
                    
                    # Yielding what it was gathered
                    licences = metaStructure.get('licences', DefaultNoLicenceTuple)
                    if isinstance(licences, list):
                        licences = tuple(licences)
                    licensed_meta_uri : LicensedURI = LicensedURI(
                        uri=meta_uri,
                        licences=licences,
                        attributions=Attribution.ParseRawAttributions(metaStructure.get('attributions'))
                    )
                    yield licensed_meta_uri, metaStructure
            
            cascadeEntries = newCascadeEntries
    
    def remove(self, destdir:AbsPath, *args, doRemoveFiles:bool=False, acceptGlob:bool=False, cascade:bool=False) -> Iterator[Tuple[LicensedURI, AbsPath, Optional[AbsPath]]]:
        """
        This method iterates elements from metadata entries,
        and optionally the cached value
        """
        if len(args) > 0:
            hashDir = self.getHashDir(destdir)
            for licensed_meta_uri, metaStructure in self.list(destdir, *args, acceptGlob=acceptGlob, cascade=cascade):
                removeCachedCopyPath : Optional[AbsPath] = None
                for meta in metaStructure['metadata_array']:
                    if doRemoveFiles and not meta['metadata'].get('injected'):
                        # Decide the removal path
                        finalCachedFilename : Optional[AbsPath] = None
                        relFinalCachedFilename : Optional[RelPath] = metaStructure.get('path', {}).get('relative')
                        if relFinalCachedFilename is not None:
                            finalCachedFilename = cast(AbsPath, os.path.normpath(os.path.join(hashDir, relFinalCachedFilename)))
                        
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
                
                metaFile : AbsPath = metaStructure['path']['meta']['absolute']
                self.logger.info(f"Removing cache {metaStructure.get('fingerprint')} metadata {metaFile}")
                os.unlink(metaFile)
                
                yield licensed_meta_uri, metaFile, removeCachedCopyPath
    
    def inject(self, destdir:AbsPath, the_remote_file:Union[LicensedURI, urllib.parse.ParseResult, URIType], fetched_metadata_array:Optional[List[URIWithMetadata]]=None, finalCachedFilename:Optional[AbsPath]=None, tempCachedFilename:Optional[AbsPath]=None, inputKind:Optional[Union[ContentKind, AbsPath, List[AbsPath]]]=None) -> Tuple[Optional[AbsPath], Optional[Fingerprint]]:
        return self._inject(
            self.getHashDir(destdir),
            the_remote_file,
            destdir=destdir,
            fetched_metadata_array=fetched_metadata_array,
            finalCachedFilename=finalCachedFilename,
            tempCachedFilename=tempCachedFilename,
            inputKind=inputKind
        )
    
    def _inject(self, hashDir:AbsPath, the_remote_file:Union[LicensedURI, urllib.parse.ParseResult, URIType], destdir:AbsPath, fetched_metadata_array:Optional[List[URIWithMetadata]]=None, finalCachedFilename:Optional[AbsPath]=None, tempCachedFilename:Optional[AbsPath]=None, inputKind:Optional[Union[ContentKind, AbsPath, List[AbsPath]]]=None) -> Tuple[Optional[AbsPath], Optional[Fingerprint]]:
        """
        This method has been created to be able to inject a cached metadata entry
        """
        the_licences : Tuple[URIType, ...] = tuple()
        if isinstance(the_remote_file, LicensedURI):
            the_remote_uri = the_remote_file.uri
            the_licences = the_remote_file.licences
        elif isinstance(the_remote_file, urllib.parse.ParseResult):
            the_remote_uri = cast(URIType, urllib.parse.urlunparse(the_remote_file))
        else:
            the_remote_uri = the_remote_file
        
        uriMetaCachedFilename , _ , _ = self._genUriMetaCachedFilename(hashDir, the_remote_uri)

        if tempCachedFilename is None:
            tempCachedFilename = finalCachedFilename
        
        if inputKind is None:
            if tempCachedFilename is None:
                raise CacheHandlerException("No defined paths or input kinds, which would lead to an empty cache entry")
                
            if os.path.isdir(tempCachedFilename):
                inputKind = ContentKind.Directory
            elif os.path.isfile(tempCachedFilename):
                inputKind = ContentKind.File
            else:
                raise CacheHandlerException(f"Local path {tempCachedFilename} is neither a file nor a directory")
        
        fingerprint: Optional[Fingerprint] = None
        # Are we dealing with a redirection?
        if isinstance(inputKind, ContentKind):
            if os.path.isfile(cast(AbsPath, tempCachedFilename)): # inputKind == ContentKind.File:
                fingerprint = cast(Fingerprint, ComputeDigestFromFile(cast(AbsPath, tempCachedFilename), repMethod=stringifyFilenameDigest))
                putativeInputKind = ContentKind.File
            elif os.path.isdir(cast(AbsPath, tempCachedFilename)): # inputKind == ContentKind.Directory:
                fingerprint = cast(Fingerprint, ComputeDigestFromDirectory(cast(AbsPath, tempCachedFilename), repMethod=stringifyFilenameDigest))
                putativeInputKind = ContentKind.Directory
            else:
                raise CacheHandlerException(f"FIXME: Cached {tempCachedFilename} from {the_remote_uri} is neither file nor directory")
            
            if inputKind != putativeInputKind:
                self.logger.error(f"FIXME: Mismatch at {the_remote_uri} : {inputKind} vs {putativeInputKind}")
            
            if finalCachedFilename is None:
                finalCachedFilename = cast(AbsPath, os.path.join(destdir, fingerprint))
        else:
            finalCachedFilename = None
        
        # Saving the metadata
        with open(uriMetaCachedFilename, mode="w", encoding="utf-8") as mOut:
            # Serializing the metadata
            if fetched_metadata_array is None:
                fetched_metadata_array = [
                    URIWithMetadata(
                        uri=the_remote_uri,
                        metadata={
                            'injected': True
                        }
                    )
                ]
            metaStructure = {
                'stamp': datetime.datetime.now(tz=datetime.timezone.utc),
                'metadata_array': list(map(lambda m: {'uri': m.uri, 'metadata': m.metadata, 'preferredName': m.preferredName}, fetched_metadata_array)),
                'licences': the_licences,
            }
            if finalCachedFilename is not None:
                metaStructure['kind'] = str(cast(ContentKind, inputKind).value)
                metaStructure['fingerprint'] = fingerprint
                metaStructure['path'] = {
                    'relative': os.path.relpath(finalCachedFilename, hashDir),
                    'absolute': finalCachedFilename
                }
            else:
                metaStructure['resolves_to'] = inputKind
            
            json.dump(metaStructure, mOut, cls=DatetimeEncoder)
            
            if self.logger.getEffectiveLevel() <= logging.DEBUG:
                flatMetaStructure = json.loads(json.dumps(metaStructure, cls=DatetimeEncoder))
                val_errors = config_validate(flatMetaStructure, self.CACHE_METADATA_SCHEMA)
                if len(val_errors) > 0:
                    self.logger.error(f'CMSVE => {len(val_errors)} errors in just stored cache metadata file {uriMetaCachedFilename}')
                    for i_err, val_error in enumerate(val_errors):
                        self.logger.error(f'CMSVE {i_err}: {val_error}')
        
        return finalCachedFilename, fingerprint
    
    def validate(self, destdir:AbsPath, *args, acceptGlob:bool=False, cascade:bool=False) -> Iterator[Tuple[LicensedURI, bool, Optional[Mapping]]]:
        hashDir = self.getHashDir(destdir)
        
        retMetaStructure : Optional[Mapping]
        for licensed_meta_uri, metaStructure in self.list(destdir, *args, acceptGlob=acceptGlob, cascade=cascade):
            inputKind = metaStructure.get('kind')
            validated = False
            retMetaStructure = metaStructure
            if inputKind is None:
                inputKind = metaStructure['resolves_to']
                
                # Blindly accept it
                validated = True
            else:
                # Additional checks
                stored_fingerprint : Optional[Fingerprint] = metaStructure.get('fingerprint')
                if stored_fingerprint is not None:
                    inputKind = ContentKind(inputKind)
                    relFinalCachedFilename = metaStructure.get('path', {}).get('relative')
                    finalCachedFilename = cast(AbsPath, os.path.normpath(os.path.join(hashDir, relFinalCachedFilename)))
                    
                    if not os.path.exists(finalCachedFilename):
                        self.logger.warning(f'Relative cache path {relFinalCachedFilename} was not found')
                        finalCachedFilename = metaStructure.get('path', {}).get('absolute')
                        
                        if (finalCachedFilename is None) or not os.path.exists(finalCachedFilename):
                            self.logger.warning(f'Absolute cache path {finalCachedFilename} was not found. Cache miss!!!')
                            
                            # Cleaning up
                            retMetaStructure = None
                    
                    computed_fingerprint : Optional[Fingerprint] = None
                    if retMetaStructure is not None:
                        if inputKind == ContentKind.Directory:
                            computed_fingerprint = cast(Fingerprint, ComputeDigestFromDirectory(finalCachedFilename, repMethod=stringifyFilenameDigest))
                        elif inputKind == ContentKind.File:
                            computed_fingerprint = cast(Fingerprint, ComputeDigestFromFile(finalCachedFilename, repMethod=stringifyFilenameDigest))
                    
                    validated = computed_fingerprint == stored_fingerprint
            
            yield licensed_meta_uri, validated, retMetaStructure
    
    def fetch(self, remote_file:Union[LicensedURI, urllib.parse.ParseResult, URIType, List[LicensedURI], List[urllib.parse.ParseResult], List[URIType]], destdir:AbsPath, offline:bool, ignoreCache:bool=False, registerInCache:bool=True, secContext:Optional[SecurityContextConfig]=None) -> Tuple[ContentKind, AbsPath, List[URIWithMetadata], Tuple[URIType, ...]]:
        # The directory with the content, whose name is based on sha256
        if not os.path.exists(destdir):
            try:
                os.makedirs(destdir)
            except IOError:
                errstr = "ERROR: Unable to create directory for workflow inputs {}.".format(destdir)
                raise CacheHandlerException(errstr)
        
        # The directory where the symlinks derived from SHA1 obtained from URIs
        # to the content are placed
        hashDir = self.getHashDir(destdir)
        
        # This filename will only be used when content is being fetched
        tempCachedFilename = cast(AbsPath, os.path.join(destdir, 'caching-' + str(uuid.uuid4())))
        # This is an iterative process, where the URI is resolved and peeled until a basic fetching protocol is reached
        inputKind : Union[LicensedURI, urllib.parse.ParseResult, URIType, List[Union[LicensedURI, urllib.parse.ParseResult, URIType]], ContentKind] = remote_file
        metadata_array = []
        licences : List[URIType] = []
        # The security context could be augmented, so avoid side effects
        currentSecContext = dict()  if secContext is None  else  secContext.copy()
        
        relFinalCachedFilename : RelPath
        finalCachedFilename : Optional[AbsPath]
        while not isinstance(inputKind, ContentKind):
            # These elements are alternative URIs. Any of them should
            # provide the very same content
            altInputs = inputKind  if isinstance(inputKind, list)  else  [ inputKind ]
            uncachedInputs = list()
            
            for a_remote_file in altInputs:
                attachedSecContext = None
                the_licences : Tuple[URIType, ...] = tuple()
                if isinstance(a_remote_file, urllib.parse.ParseResult):
                    parsedInputURL = a_remote_file
                    the_remote_file = cast(URIType, urllib.parse.urlunparse(a_remote_file))
                else:
                    if isinstance(a_remote_file, LicensedURI):
                        the_remote_file = a_remote_file.uri
                        attachedSecContext = a_remote_file.secContext
                        the_licences = a_remote_file.licences
                    else:
                        the_remote_file = a_remote_file
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
                    except Exception as e:
                        # Metadata is corrupted
                        self.logger.warning(f'Metadata cache {uriMetaCachedFilename} is corrupted. Ignoring.')
                        self.logger.debug(traceback.format_exc())
                
                if metaStructure is not None:
                    # Metadata cache hit
                    inputKindRaw = metaStructure.get('kind')
                    if inputKindRaw is None:
                        inputKind = cast(Union[URIType, List[URIType]], metaStructure['resolves_to'])
                    else:
                        # Additional checks
                        inputKind = ContentKind(inputKindRaw)
                        relFinalCachedFilename = metaStructure.get('path', {}).get('relative', os.readlink(absUriCachedFilename))
                        finalCachedFilename = cast(AbsPath, os.path.normpath(os.path.join(hashDir, relFinalCachedFilename)))
                        
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
                    # Prepare the attachedSecContext
                    usableSecContext = currentSecContext.copy()
                    if attachedSecContext is not None:
                        usableSecContext.update(attachedSecContext)
                    
                    uncachedInputs.append((the_remote_file, parsedInputURL, usableSecContext))
            
            if metaStructure is not None:
                fetched_metadata_array = list(map(lambda rm: URIWithMetadata(uri=rm['uri'], metadata=rm['metadata'], preferredName=rm.get('preferredName')), metaStructure['metadata_array']))
                # Getting the recorded licence
                the_licences = metaStructure.get('licences', [])
            elif offline:
                # As this is a handler for online resources, comply with offline mode
                raise CacheHandlerException(f"Cannot download content in offline mode from {remote_file} to {uriCachedFilename}")
            else:
                # Cache miss
                # As this is a handler for online resources, comply with offline mode
                nested_exception = None
                failed = True
                for the_remote_file, parsedInputURL, usableSecContext in uncachedInputs:
                    # Content is fetched here
                    theScheme = parsedInputURL.scheme.lower()
                    schemeHandler = self.schemeHandlers.get(theScheme)
                    
                    try:
                        if schemeHandler is None:
                            errmsg = f'No {theScheme} scheme handler for {the_remote_file} (while processing {remote_file}). Was this data injected in the cache?'
                            self.logger.error(errmsg)
                            raise CacheHandlerException(errmsg) from nested_exception

                        try:
                            # Content is fetched here
                            inputKind, fetched_metadata_array, fetched_licences = schemeHandler(the_remote_file, tempCachedFilename, secContext=usableSecContext if usableSecContext else None)
                            
                            # Overwrite the licence if it is explicitly returned
                            if fetched_licences is not None:
                                the_licences = fetched_licences
                            
                            # The cache entry is injected
                            finalCachedFilename, fingerprint = self._inject(
                                hashDir,
                                LicensedURI(
                                    uri=the_remote_file,
                                    licences=the_licences
                                ),
                                destdir=destdir,
                                fetched_metadata_array=fetched_metadata_array,
                                tempCachedFilename=tempCachedFilename,
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
                        except FetcherException as che:
                            raise che from nested_exception
                        except Exception as e:
                            errmsg = "Cannot download content from {} to {} (while processing {}) (temp file {}): {}".format(the_remote_file, uriCachedFilename, remote_file, tempCachedFilename, e)
                            self.logger.exception(errmsg)
                            raise CacheHandlerException(errmsg) from nested_exception
                    except FetcherException as wfe:
                        # Keeping the newest element of the chain
                        nested_exception = wfe
                    else:
                        # This URI could be resolved (implement alternative URLs)
                        failed = False
                        currentSecContext = usableSecContext
                        break
                    
                # No one of the URIs could be fetched or resolved
                if failed:
                    if len(uncachedInputs) > 1:
                        raise CacheHandlerException(f"{len(uncachedInputs)} alternate URIs have failed (see nested reasons)") from nested_exception
                    else:
                        raise nested_exception
            
            # Store the metadata
            metadata_array.extend(fetched_metadata_array)
            licences.extend(the_licences)

        return inputKind, finalCachedFilename, metadata_array, tuple(licences)
