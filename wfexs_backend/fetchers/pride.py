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

import io
import json

from typing import List, Optional, Tuple

from urllib import request, parse
import urllib.error

from . import fetchClassicURL
from ..common import *


PRIDE_PROJECTS_REST='https://www.ebi.ac.uk/pride/ws/archive/v2/projects/'

def fetchPRIDEProject(remote_file:URIType, cachedFilename:AbsPath, secContext:Optional[SecurityContextConfig]=None) -> Tuple[Union[URIType, ContentKind], List[URIWithMetadata]]:
    """
    Method to resolve contents from PRIDE project ids

    :param remote_file:
    :param cachedFilename: Destination filename for the fetched content
    :param secContext: The security context containing the credentials
    """
    
    parsedInputURL = parse.urlparse(remote_file)
    projectId = parsedInputURL.path
    metadata_url = parse.urljoin(PRIDE_PROJECTS_REST, projectId)
    
    gathered_meta = {'fetched': metadata_url}
    metadata_array = [
        URIWithMetadata(remote_file, gathered_meta)
    ]
    metadata = None
    try:
        metaio = io.BytesIO()
        _ , metametaio = fetchClassicURL(metadata_url, metaio)
        metadata = json.loads(metaio.getvalue().decode('utf-8'))
        gathered_meta['payload'] = metadata
        metadata_array.extend(metametaio)
    except urllib.error.HTTPError as he:
        raise WFException("Error fetching PRIDE metadata for {} : {} {}".format(projectId, he.code, he.reason))
    
    try:
        for addAtt in metadata['additionalAttributes']:
            if addAtt.get('@type') == 'CvParam' and addAtt.get('accession') == 'PRIDE:0000411':
                pride_project_url = addAtt.get('value')
                if pride_project_url is not None:
                    break
        else:
            pride_project_url = metadata['_links']['datasetFtpUrl']['href']
    except Exception as e:
        raise WFException("Error processing PRIDE project metadata for {} : {}".format(remote_file, e))
    
    return pride_project_url, metadata_array

# These are schemes from identifiers.org
SCHEME_HANDLERS = {
    'pride.project': fetchPRIDEProject,
}
