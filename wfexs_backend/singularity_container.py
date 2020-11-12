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

import os
import re
import subprocess
import tempfile
from urllib import parse

from typing import Dict, List, Tuple
from .common import *
from .container import ContainerFactory, ContainerFactoryException


# This method was borrowed from
# https://github.com/nextflow-io/nextflow/blob/539a22b68c114c94eaf4a88ea8d26b7bfe2d0c39/modules/nextflow/src/main/groovy/nextflow/container/SingularityCache.groovy#L80
# and translated to Python
def simpleFileName(imageUrl: str) -> str:
    p = imageUrl.find('://')
    name = imageUrl[p+3:]  if p != -1   else imageUrl
    extension = '.img'
    if '.sif:' in name:
        extension = '.sif'
        name = name.replace('.sif:','-')
    elif name.endswith('.sif'):
        extension = '.sif'
        name = name[:-4]
    
    name = name.replace(':','-').replace('/','-')
    
    return name + extension


class SingularityContainerFactory(ContainerFactory):
    def __init__(self, cacheDir=None, local_config=None):
        super().__init__(cacheDir=cacheDir, local_config=local_config)
        self.singularity_cmd = local_config.get('tools', {}).get('singularityCommand', DEFAULT_SINGULARITY_CMD)
    
    @classmethod
    def ContainerType(cls) -> ContainerType:
        return ContainerType.Singularity
    
    def materializeContainers(self, tagList: List[ContainerTaggedName]) -> List[Container]:
        """
        It is assured the containers are materialized
        """
        containersList = []
	
        for tag in tagList:
            # It is not an absolute URL, we are prepending the docker://
            parsedTag = parse.urlparse(tag)
            singTag = 'docker://' + tag  if parsedTag.scheme == ''  else tag
            
            containerFilename = simpleFileName(tag)
            localContainerPath = os.path.join(self.containersCacheDir,containerFilename)
                
            print("downloading container: {} => {}".format(tag, localContainerPath))
            # First, let's materialize the container image
            if not os.path.isfile(localContainerPath):
                with tempfile.NamedTemporaryFile() as s_out, tempfile.NamedTemporaryFile() as s_err:
                    # Singularity command line borrowed from
                    # https://github.com/nextflow-io/nextflow/blob/539a22b68c114c94eaf4a88ea8d26b7bfe2d0c39/modules/nextflow/src/main/groovy/nextflow/container/SingularityCache.groovy#L221
                    s_retval = subprocess.Popen(
                    [self.singularity_cmd, 'pull', '--name', localContainerPath, singTag],
                    stdout=s_out,
                    stderr=s_err
                    ).wait()
                    
                    # Reading the output and error for the report
                    if s_retval != 0:
                        with open(s_out.name,"r") as c_stF:
                            s_out_v = c_stF.read()
                        with open(s_err.name,"r") as c_stF:
                            s_err_v = c_stF.read()
                        
                        errstr = """Could not materialize singularity image {}. Retval {}
======
STDOUT
======
{}

======
STDERR
======
{}""".format(singTag, s_retval, s_out_v, s_err_v)
                        raise ContainerFactoryException(errstr)
                
            
            # Then, compute the signature
            imageSignature = ComputeDigestFromFile(localContainerPath)
            
            containersList.append(
                Container(
                    taggedName=tag,
                    signature=imageSignature,
                    type=self.containerType,
                    localPath=localContainerPath
                )
            )
        
        return containersList
