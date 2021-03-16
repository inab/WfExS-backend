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
import os.path
import re
import subprocess
import tempfile
from urllib import parse
import uuid

from typing import Dict, List, Tuple
from .common import *
from .container import ContainerFactory, ContainerFactoryException

class SingularityContainerFactory(ContainerFactory):
    def __init__(self, cacheDir=None, local_config=None, engine_name='unset'):
        super().__init__(cacheDir=cacheDir, local_config=local_config, engine_name=engine_name)
        self.singularity_cmd = local_config.get('tools', {}).get('singularityCommand', DEFAULT_SINGULARITY_CMD)
    
    @classmethod
    def ContainerType(cls) -> ContainerType:
        return ContainerType.Singularity
    
    def materializeContainers(self, tagList: List[ContainerTaggedName], simpleFileNameMethod: ContainerFileNamingMethod) -> List[Container]:
        """
        It is assured the containers are materialized
        """
        containersList = []
	
        for tag in tagList:
            # It is not an absolute URL, we are prepending the docker://
            parsedTag = parse.urlparse(tag)
            singTag = 'docker://' + tag  if parsedTag.scheme == ''  else tag
            
            containerFilename = simpleFileNameMethod(tag)
            localContainerPath = os.path.join(self.engineContainersSymlinkDir,containerFilename)
                
            self.logger.info("downloading container: {} => {}".format(tag, localContainerPath))
            # First, let's materialize the container image
            imageSignature = None
            if not os.path.isfile(localContainerPath):
                with tempfile.NamedTemporaryFile() as s_out, tempfile.NamedTemporaryFile() as s_err:
                    tmpContainerPath = os.path.join(self.containersCacheDir,str(uuid.uuid4()))
                    # Singularity command line borrowed from
                    # https://github.com/nextflow-io/nextflow/blob/539a22b68c114c94eaf4a88ea8d26b7bfe2d0c39/modules/nextflow/src/main/groovy/nextflow/container/SingularityCache.groovy#L221
                    s_retval = subprocess.Popen(
                    [self.singularity_cmd, 'pull', '--disable-cache', '--name', tmpContainerPath, singTag],
                    stdout=s_out,
                    stderr=s_err
                    ).wait()
                    
                    # Reading the output and error for the report
                    if s_retval == 0:
                        imageSignature = ComputeDigestFromFile(tmpContainerPath)
                        # Some filesystems complain when filenames contain 'equal', 'slash' or 'plus' symbols
                        canonicalContainerPath = os.path.join(self.containersCacheDir, imageSignature.replace('=','~').replace('/','-').replace('+','_'))
                        if os.path.exists(canonicalContainerPath):
                            tmpSize = os.path.getsize(tmpContainerPath)
                            canonicalSize = os.path.getsize(canonicalContainerPath)
                            
                            # Remove the temporary one
                            os.unlink(tmpContainerPath)
                            if tmpSize != canonicalSize:
                                # If files were not the same complain
                                # This should not happen!!!!!
                                raise ContainerFactoryException("FATAL ERROR: Singularity cache collision for {}, with differing sizes ({} local, {} remote {})".format(imageSignature,canonicalSize,tmpSize,tag))
                        else:
                            shutil.move(tmpContainerPath,canonicalContainerPath)
                        
                        # Now, create the relative symbolic link
                        os.symlink(os.path.relpath(canonicalContainerPath,self.engineContainersSymlinkDir),localContainerPath)
                            
                    else:
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
                        if os.path.exists(tmpContainerPath):
                            try:
                                os.unlink(tmpContainerPath)
                            except:
                                pass
                        raise ContainerFactoryException(errstr)
                
            
            # Then, compute the signature
            if imageSignature is None:
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
