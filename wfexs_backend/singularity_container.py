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

import json
import os
import os.path
import re
import shutil
import subprocess
import tempfile
from typing import Dict, List, Tuple, Union
from urllib import parse
import uuid

from .common import AbsPath, RelPath
from .common import Container, ContainerType
from .common import ContainerFileNamingMethod, ContainerTaggedName
from .common import DEFAULT_SINGULARITY_CMD

from .container import ContainerFactory, ContainerFactoryException

from .utils.contents import link_or_copy
from .utils.digests import ComputeDigestFromFile, nihDigester
from .utils.docker import DockerHelper

class SingularityContainerFactory(ContainerFactory):
    def __init__(self, cacheDir=None, local_config=None, engine_name='unset', tempDir=None):
        super().__init__(cacheDir=cacheDir, local_config=local_config, engine_name=engine_name, tempDir=tempDir)
        self.runtime_cmd = local_config.get('tools', {}).get('singularityCommand', DEFAULT_SINGULARITY_CMD)
        
        # This is needed due a bug in singularity 3.6, where
        # singularity pull --disable-cache does not create a container
        singularityCacheDir = os.path.join(self.containersCacheDir, '.singularity')
        os.makedirs(singularityCacheDir, exist_ok=True)
        
        self._environment.update({
            'SINGULARITY_TMPDIR': self.tempDir,
            'SINGULARITY_CACHEDIR': singularityCacheDir,
        })
        
        # Now, detect userns feature using some ideas from
        # https://github.com/hpcng/singularity/issues/1445#issuecomment-381588444
        userns_supported = False
        if self.supportsFeature('host_userns'):
            matEnv = dict(os.environ)
            matEnv.update(self.environment)
            with tempfile.NamedTemporaryFile() as s_out, tempfile.NamedTemporaryFile() as s_err:
                s_retval = subprocess.Popen(
                    [self.runtime_cmd, 'exec', '--userns', '/etc', 'true'],
                    env=matEnv,
                    stdout=s_out,
                    stderr=s_err
                ).wait()
                
                # The command always fails.
                # We only need to find 'Failed to create user namespace'
                # in order to discard this feature
                with open(s_err.name,"r") as c_stF:
                    s_err_v = c_stF.read()
                if 'Failed to create user namespace' not in s_err_v:
                    userns_supported = True
                    self._features.add('userns')
        
        self.logger.debug(f'Singularity supports userns: {userns_supported}')
        if not userns_supported:
            self.logger.warning('Singularity does not support userns (needed for encrypted working directories)')
    
    
    @classmethod
    def ContainerType(cls) -> ContainerType:
        return ContainerType.Singularity
    
    def materializeContainers(self, tagList: List[ContainerTaggedName], simpleFileNameMethod: ContainerFileNamingMethod, containers_dir: Union[RelPath, AbsPath] = None, offline: bool = False) -> List[Container]:
        """
        It is assured the containers are materialized
        """
        containersList = []
        
        matEnv = dict(os.environ)
        matEnv.update(self.environment)
        dhelp = DockerHelper()
        for tag in tagList:
            # It is not an absolute URL, we are prepending the docker://
            parsedTag = parse.urlparse(tag)
            singTag = 'docker://' + tag  if parsedTag.scheme == ''  else tag
            
            containerFilename = simpleFileNameMethod(tag)
            containerFilenameMeta = containerFilename + self.META_JSON_POSTFIX
            localContainerPath = os.path.join(self.engineContainersSymlinkDir, containerFilename)
            localContainerPathMeta = os.path.join(self.engineContainersSymlinkDir, containerFilenameMeta)
            
            self.logger.info("downloading singularity container: {} => {}".format(tag, localContainerPath))
            # First, let's materialize the container image
            imageSignature = None
            
            tmpContainerPath = None
            tmpContainerPathMeta = None
            if os.path.isfile(localContainerPathMeta):
                with open(localContainerPathMeta, mode="r", encoding="utf8") as tcpm:
                    metadata = json.load(tcpm)
                    registryServer = metadata['registryServer']
                    repo = metadata['repo']
                    alias = metadata['alias']
                    partial_fingerprint = metadata['dcd']
            elif offline:
                raise ContainerFactoryException("Cannot download containers metadata in offline mode from {} to {}".format(tag, localContainerPath))
            else:
                tmpContainerPath = os.path.join(self.containersCacheDir,str(uuid.uuid4()))
                tmpContainerPathMeta = tmpContainerPath + self.META_JSON_POSTFIX
                
                self.logger.debug("downloading temporary container metadata: {} => {}".format(tag, tmpContainerPathMeta))
                
                with open(tmpContainerPathMeta, mode="w", encoding="utf8") as tcpm:
                    registryServer, repo, alias, partial_fingerprint = dhelp.query_tag(singTag)
                    json.dump({
                        'registryServer': registryServer,
                        'repo': repo,
                        'alias': alias,
                        'dcd': partial_fingerprint,
                    }, tcpm)
            
                
            canonicalContainerPath = None
            canonicalContainerPathMeta = None
            if not os.path.isfile(localContainerPath):
                if offline:
                    raise ContainerFactoryException("Cannot download containers in offline mode from {} to {}".format(tag, localContainerPath))
                    
                with tempfile.NamedTemporaryFile() as s_out, tempfile.NamedTemporaryFile() as s_err:
                    if tmpContainerPath is None:
                        tmpContainerPath = os.path.join(self.containersCacheDir,str(uuid.uuid4()))
                    
                    self.logger.debug("downloading temporary container: {} => {}".format(tag, tmpContainerPath))
                    # Singularity command line borrowed from
                    # https://github.com/nextflow-io/nextflow/blob/539a22b68c114c94eaf4a88ea8d26b7bfe2d0c39/modules/nextflow/src/main/groovy/nextflow/container/SingularityCache.groovy#L221
                    s_retval = subprocess.Popen(
                        [self.runtime_cmd, 'pull', '--name', tmpContainerPath, singTag],
                        env=matEnv,
                        stdout=s_out,
                        stderr=s_err
                    ).wait()
                    
                    self.logger.debug("singularity pull retval: {}".format(s_retval))
                    
                    with open(s_out.name,"r") as c_stF:
                        s_out_v = c_stF.read()
                    with open(s_err.name,"r") as c_stF:
                        s_err_v = c_stF.read()
                    
                    self.logger.debug("singularity pull stdout: {}".format(s_out_v))
                    
                    self.logger.debug("singularity pull stderr: {}".format(s_err_v))
                    
                    # Reading the output and error for the report
                    if s_retval == 0:
                        if not os.path.exists(tmpContainerPath):
                            raise ContainerFactoryException("FATAL ERROR: Singularity finished properly but it did not materialize {} into {}".format(tag, tmpContainerPath))
                        
                        imageSignature = ComputeDigestFromFile(tmpContainerPath)
                        # Some filesystems complain when filenames contain 'equal', 'slash' or 'plus' symbols
                        canonicalContainerPath = os.path.join(self.containersCacheDir, imageSignature.replace('=','~').replace('/','-').replace('+','_'))
                        if os.path.exists(canonicalContainerPath):
                            tmpSize = os.path.getsize(tmpContainerPath)
                            canonicalSize = os.path.getsize(canonicalContainerPath)
                            
                            # Remove the temporary one
                            os.unlink(tmpContainerPath)
                            tmpContainerPath = None
                            if tmpContainerPathMeta is not None:
                                os.unlink(tmpContainerPathMeta)
                                tmpContainerPathMeta = None
                            if tmpSize != canonicalSize:
                                # If files were not the same complain
                                # This should not happen!!!!!
                                raise ContainerFactoryException("FATAL ERROR: Singularity cache collision for {}, with differing sizes ({} local, {} remote {})".format(imageSignature,canonicalSize,tmpSize,tag))
                        else:
                            shutil.move(tmpContainerPath, canonicalContainerPath)
                            tmpContainerPath = None
                        
                        # Now, create the relative symbolic link
                        if os.path.lexists(localContainerPath):
                            os.unlink(localContainerPath)
                        os.symlink(os.path.relpath(canonicalContainerPath,self.engineContainersSymlinkDir),localContainerPath)
                            
                    else:
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
            
            # Only metadata was generated
            if tmpContainerPathMeta is not None:
                if canonicalContainerPath is None:
                    canonicalContainerPath = os.path.normpath(os.path.join(self.engineContainersSymlinkDir, os.readlink(localContainerPath)))
                canonicalContainerPathMeta = canonicalContainerPath + self.META_JSON_POSTFIX
                shutil.move(tmpContainerPathMeta, canonicalContainerPathMeta)
            
            if canonicalContainerPathMeta is not None:
                if os.path.lexists(localContainerPathMeta):
                    os.unlink(localContainerPathMeta)
                os.symlink(os.path.relpath(canonicalContainerPathMeta,self.engineContainersSymlinkDir),localContainerPathMeta)
                
            
            # Then, compute the signature
            if imageSignature is None:
                imageSignature = ComputeDigestFromFile(localContainerPath, repMethod=nihDigester)
            
            # Hardlink or copy the container and its metadata
            if containers_dir is not None:
                containerPath = os.path.join(containers_dir, containerFilename)
                containerPathMeta = os.path.join(containers_dir, containerFilenameMeta)
                
                # Do not allow overwriting in offline mode
                if not offline or not os.path.exists(containerPath):
                    link_or_copy(localContainerPath, containerPath)
                if not offline or not os.path.exists(containerPathMeta):
                    link_or_copy(localContainerPathMeta, containerPathMeta)
            else:
                containerPath = localContainerPath
            
            containersList.append(
                Container(
                    origTaggedName=tag,
                    taggedName=singTag,
                    signature=imageSignature,
                    fingerprint=repo + '@' + partial_fingerprint,
                    type=self.containerType,
                    localPath=containerPath
                )
            )
        
        return containersList
