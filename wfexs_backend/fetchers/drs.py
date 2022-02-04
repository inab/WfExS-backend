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

from __future__ import absolute_import

import io
import json

from typing import List, Optional, Tuple

from urllib import request, parse
import urllib.error

from . import fetchClassicURL
from ..common import *

DRS_SCHEME = 'drs'

def downloadContentFromDRS(remote_file:URIType, cachedFilename:AbsPath, secContext:Optional[SecurityContextConfig]=None) -> Tuple[Union[AnyURI, ContentKind, List[AnyURI]], List[URIWithMetadata]]:
    upperSecContext = dict()
    
    parsedInputURL = parse.urlparse(remote_file)
    
    # Complaining about unknown schemes
    if parsedInputURL.scheme != DRS_SCHEME:
        raise Exception(f'Unexpected scheme {parsedInputURL.scheme}, expected {DRS_SCHEME}')
    
    # Computing the path prefix
    path_tokens = parsedInputURL.path.split('/')
    object_id = path_tokens[-1]
    path_tokens[-1] = ''
    ga4gh_path_prefix = '/'.join(path_tokens) + 'ga4gh/drs/v1/'
    
    
    token = None
    token_header = None
    username = None
    password = None
    
    # Setting up the credentials
    netloc = parsedInputURL.hostname
    headers = dict()
    if isinstance(secContext, dict):
        headers = secContext.get('headers', {})
        token = secContext.get('token')
        token_header = secContext.get('token_header')
        username = secContext.get('username')
        password = secContext.get('password')
        
        if token is not None:
            upperSecContext['token'] = token
            if token_header is not None:
                upperSecContext['token_header'] = token_header
        elif username is not None:
            if password is None:
                password = ''
            upperSecContext['username'] = username
            upperSecContext['password'] = password
        
        upperSecContext['headers'] = headers

    scheme = 'https'
    if parsedInputURL.port is not None:
        netloc += ':' + str(parsedInputURL.port)
        if parsedInputURL.port == 80:
            scheme = 'http'
    
    # And the service prefix
    drs_service_prefix = parse.urlunparse((scheme, netloc, ga4gh_path_prefix,
                                            '', '', ''))
    
    # Now, get the object metadata
    object_metadata_url = drs_service_prefix + 'objects/' + object_id
    
    gathered_meta = {'fetched': object_metadata_url}
    metadata_array = [ ]
    metadata = None
    try:
        metaio = io.BytesIO()
        _ , metametaio = fetchClassicURL(object_metadata_url, metaio, secContext=upperSecContext)
        object_metadata = json.loads(metaio.getvalue().decode('utf-8'))
        # Gathering the preferred name
        preferredName = object_metadata.get('name')
        
        gathered_meta['payload'] = object_metadata
        metadata_array.append(URIWithMetadata(remote_file, gathered_meta, preferredName))
        metadata_array.extend(metametaio)
    except urllib.error.HTTPError as he:
        raise WFException("Error fetching DRS metadata for {} : {} {}".format(remote_file, he.code, he.reason))
    
    # With the metadata, let's compose the URL to be returned
    # (which could not be cached)
    retURL = []
    for access_method in object_metadata.get('access_methods', []):
        object_url = access_method.get('access_url')
        access_id = access_method.get('access_id')
        if (object_url is None) and (access_id is not None):
            object_access_metadata_url = object_metadata_url + '/access/' + parse.quote(access_id, safe='')
            
            try:
                metaaccio = io.BytesIO()
                _ , metametaaccio = fetchClassicURL(object_access_metadata_url, metaaccio, secContext=upperSecContext)
                object_access_metadata = json.loads(metaaccio.getvalue().decode('utf-8'))
            except urllib.error.HTTPError as he:
                raise WFException("Error fetching DRS access link {} for {} : {} {}".format(access_id, remote_file, he.code, he.reason))

            object_url = object_access_metadata.get('url')
        
        if object_url is not None:
            retURL.append(object_url)
    
    return retURL, metadata_array

SCHEME_HANDLERS = {
    DRS_SCHEME: downloadContentFromDRS,
}
