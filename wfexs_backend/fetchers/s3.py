import boto3
from botocore import UNSIGNED
from botocore.client import Config
import botocore.exceptions
from urllib.parse import urlparse
from typing import Any, List, Optional, Tuple, Union
import os
import shutil
import logging
import argparse
from ..common import *

def downloadContentFrom_s3(remote_file:URIType, cachedFilename:AbsPath, secContext:Optional[SecurityContextConfig]=None) -> Tuple[Union[URIType, ContentKind], List[URIWithMetadata]]:
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
                s3 = boto3.client('s3', config=Config(signature_version=UNSIGNED))
                response = s3.list_objects_v2(Bucket=bucket,Prefix=prefix)
        else:
                s3 = boto3.client('s3',access_key,secret_key)
                response = s3.list_objects_v2(Bucket=bucket, Prefix=prefix)
    except botocore.exceptions.ClientError as error:
        logger.warn('Error in the connection with s3 ' + error)

    if response["KeyCount"] == 1:
        file_name = urlParse.path.split('/')
        file_name = file_name[len(file_name) - 1]

        if(local_path[:1] == '/'):
            local_path = local_path + file_name
        elif(local_path == './'):
            local_path = local_path + file_name
        elif(local_path[:1] != '/'):
            local_path = local_path + '/' + file_name
        
        try:
            s3.download_file(bucket, prefix, local_path)
        
        except botocore.exceptions.ParamValidationError as error:
            logger.warn("Error downloading file" + error)

    elif response["KeyCount"] > 1:
        try:

            paginator = s3.get_paginator('list_objects_v2')
            for result in paginator.paginate(Bucket=bucket, Prefix=prefix):
                for key in result['Contents']:
                    rel_path = key['Key'][len(prefix):]
                    if not key['Key'].endswith('/'):
                        local_file_path = os.path.join(local_path, rel_path)
                        local_file_dir = os.path.dirname(local_file_path)
                        if not os.path.exists(local_file_dir):
                            os.makedirs(local_file_dir)
                        s3.download_file(bucket, key['Key'],local_file_path)

        except botocore.exceptions.ParamValidationError as error:
            logger.warn("Error downloading file " + error)
    
    kind = None
    if os.path.isdir(local_path):
        shutil.copytree(local_path, cachedFilename)
        kind = ContentKind.Directory
    elif os.path.isfile(local_path):
        shutil.copy2(local_path, cachedFilename)
        kind = ContentKind.File
    else:
        raise WFException("Local path {} is neither a file nor a directory".format(local_path))
    
    return kind, [ URIWithMetadata(remote_file, {}) ]

S3_SCHEME_HANDLERS = {
    's3': downloadContentFrom_s3
}