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

import boto3
from botocore import UNSIGNED
from botocore.client import Config
import botocore.exceptions
from urllib.parse import urlparse
from typing import List, Optional, Tuple, Union
import os
import shutil
import logging

from . import FetcherException

from ..common import AbsPath, AnyURI, ContentKind, SecurityContextConfig
from ..common import URIType, URIWithMetadata

# Logger of this module
logger = logging.getLogger(__name__)

def downloadContentFrom_s3(remote_file:URIType, cachedFilename:AbsPath, secContext:Optional[SecurityContextConfig]=None) -> Tuple[Union[AnyURI, ContentKind, List[AnyURI]], List[URIWithMetadata]]:
    urlParse = urlparse(remote_file)
    bucket = urlParse.netloc
    prefix = urlParse.path
    prefix = prefix[1:]
    local_path = cachedFilename
    
    if(isinstance(secContext, dict)):
        access_key = secContext.get('access_key')
        secret_key = secContext.get('secret_key')
    else:
        access_key = None
        secret_key = None

    try:
        if access_key == None and secret_key == None:
            s3cli = boto3.client('s3', config=Config(signature_version=UNSIGNED))
        else:
            s3cli = boto3.client('s3', access_key, secret_key)
    except botocore.exceptions.ClientError as error:
        errmsg = f'S3 client authentication error on {remote_file}'
        logger.exception(errmsg)
        raise FetcherException(errmsg) from error
    
    metadata_payload = []
    metadata = {
        'fetched': remote_file,
        'payload': metadata_payload
    }
    try:
        s3_obj = s3cli.get_object(Bucket=bucket, Key=prefix)
        with open(cachedFilename, mode='wb') as dH:
            shutil.copyfileobj(s3_obj['Body'], dH)
        s3_obj.pop('Body')
        metadata_payload.append(s3_obj)
        kind = ContentKind.File
    except botocore.exceptions.ClientError as error:
        if error.response['Error']['Code'] != 'NoSuchKey':
            raise error
        
        # This happens when the object is not a file
        blob_prefix = prefix
        if blob_prefix[-1] != '/':
            blob_prefix += '/'
        
        # Check whether there is something
        response = s3cli.list_objects_v2(Bucket=bucket, Prefix=blob_prefix, MaxKeys=1)
        
        # Nothing leads to an exception
        if response["KeyCount"] == 0:
            errmsg = f'Path prefix {blob_prefix} from {remote_file} matches no blob'
            logger.error(errmsg)
            raise FetcherException(errmsg)
        
        # Let's use the paginator
        try:
            paginator = s3cli.get_paginator('list_objects_v2')
            for result in paginator.paginate(Bucket=bucket, Prefix=prefix):
                for key in result['Contents']:
                    local_blob_filename = os.path.join(local_path, key['Key'][len(blob_prefix):])
                    try:
                        os.makedirs(os.path.dirname(local_blob_filename), exist_ok=True)
                        s3cli.download_file(bucket, key['Key'], local_blob_filename)
                        metadata_payload.append(key)
                    except Exception as e:
                        errmsg = f'Error downloading {key["Key"]} from {remote_file} to {local_blob_filename}'
                        logger.exception(errmsg)
                        raise FetcherException(errmsg) from e
        except FetcherException as fe:
            raise fe
        except Exception as e:
            errmsg = f'Error paginating {prefix} from {remote_file} to {local_path}'
            logger.exception(errmsg)
            raise FetcherException(errmsg) from e
        kind = ContentKind.Directory
    
    return kind, [ URIWithMetadata(remote_file, metadata) ]

S3_SCHEME_HANDLERS = {
    's3': downloadContentFrom_s3
}
