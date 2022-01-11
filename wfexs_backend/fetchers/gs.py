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

from google.cloud import storage
from urllib.parse import urlparse
import argparse
import logging
import shutil
import os

from ..common import *
from typing import Any, List, Optional, Tuple, Union

def downloadContentFrom_gs(remote_file:URIType, cachedFilename:AbsPath, secContext:Optional[SecurityContextConfig]=None) -> Tuple[Union[URIType, ContentKind], List[URIWithMetadata]]:

    url = urlparse(remote_file)
    bucket = url.netloc
    prefix = url.path[1:]
    local_path = cachedFilename

    if(isinstance(secContext, dict)):
        credentials = secContext.get('gs_credentials')
    else:
        credentials = None

    try:
        if credentials == None:
            gs = storage.Client.create_anonymous_client()
        else:
            gs = storage.Client.from_service_account_json(credentials)         
    except Exception as e:
        logging.warning("Authentication error")

    bucket = gs.bucket(bucket)
    blob = bucket.blob(prefix)
    blobs = bucket.list_blobs(prefix=prefix)
    listBlobs = bucket.list_blobs(prefix=prefix)
    total_bobs = 0

    for blob in blobs:
        total_bobs+=1
    if total_bobs == 1:
        if(local_path[-1] == '/'): 
            path = local_path + blob.name.split('/')[-1]
        elif(local_path == './'):
            path = local_path + blob.name.split('/')[-1]
        elif(local_path[-1] != '/'):
            path = local_path + '/' + blob.name.split('/')[-1]

        try:
            blob.download_to_filename(path)
        except Exception as e:
            logging.warning("Error downloading file")

    elif total_bobs > 1:
        try:
            for blob in listBlobs:
                if blob.name.endswith("/"):
                    continue

                if(local_path[-1] == '/'):
                    path = local_path + blob.name
                elif(local_path == './'):
                    path = local_path + blob.name
                elif(local_path[-1] != '/'):
                    path = local_path + '/' + blob.name

                if not os.path.exists(os.path.dirname(path)):
                    os.makedirs(os.path.dirname(path))
                blob.download_to_filename(path)
        except Exception as e:
            logging.warning("Error downloading files")

    kind = None
    if os.path.isdir(local_path):
        shutil.move(local_path, cachedFilename)
        kind = ContentKind.Directory
    elif os.path.isfile(local_path):
        shutil.move(local_path, cachedFilename)
        kind = ContentKind.File
    else:
        raise WFException("Local path {} is neither a file nor a directory".format(local_path))
    
    return kind, [ URIWithMetadata(remote_file, {}) ]

GS_SCHEME_HANDLERS = {
    'gs': downloadContentFrom_gs
}