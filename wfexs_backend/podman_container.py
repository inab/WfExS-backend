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

import json
import lzma
import os
import shutil
import subprocess
import tempfile
from typing import Dict, List, Mapping, Tuple, Union
import uuid

from .common import AbsPath, RelPath
from .common import Container, ContainerType
from .common import ContainerFileNamingMethod, ContainerTaggedName
from .common import DEFAULT_PODMAN_CMD

from .container import ContainerFactory, ContainerFactoryException
from .utils.contents import link_or_copy
from .utils.digests import ComputeDigestFromFile, ComputeDigestFromObject, nihDigester

DOCKER_PROTO = 'docker://'

class PodmanContainerFactory(ContainerFactory):
    def __init__(self, cacheDir=None, local_config=None, engine_name='unset', tempDir=None):
        super().__init__(cacheDir=cacheDir, local_config=local_config, engine_name=engine_name, tempDir=tempDir)
        self.runtime_cmd = local_config.get('tools', {}).get('podmanCommand', DEFAULT_PODMAN_CMD)
        
        self._environment.update({
            'XDG_DATA_HOME': self.containersCacheDir,
        })
    
        # Now, detect whether userns could work
        userns_supported = False
        if self.supportsFeature('host_userns'):
            userns_supported = True
            self._features.add('userns')
        
        self.logger.debug(f'Podman supports userns: {userns_supported}')
    
    
    @classmethod
    def ContainerType(cls) -> ContainerType:
        return ContainerType.Podman
    
    def _inspect(self, dockerTag : ContainerTaggedName, matEnv: Mapping) -> Tuple[int, bytes, str]:
        with tempfile.NamedTemporaryFile() as d_out, tempfile.NamedTemporaryFile() as d_err:
            self.logger.debug(f"querying podman container {dockerTag}")
            d_retval = subprocess.Popen(
                [self.runtime_cmd, 'inspect', dockerTag],
                env=matEnv,
                stdout=d_out,
                stderr=d_err
            ).wait()
            
            self.logger.debug(f"podman inspect {dockerTag} retval: {d_retval}")
            
            with open(d_out.name, mode="rb") as c_stF:
                d_out_v = c_stF.read().decode('utf-8', errors='continue')
            with open(d_err.name, mode="r") as c_stF:
                d_err_v = c_stF.read()
            
            self.logger.debug(f"podman inspect stdout: {d_out_v}")
            
            self.logger.debug(f"podman inspect stderr: {d_err_v}")
            
            return d_retval , d_out_v , d_err_v
    
    def _pull(self, dockerTag : ContainerTaggedName, matEnv: Mapping) -> Tuple[int, str, str]:
        with tempfile.NamedTemporaryFile() as d_out, tempfile.NamedTemporaryFile() as d_err:
            self.logger.debug(f"pulling podman container {dockerTag}")
            d_retval = subprocess.Popen(
                [self.runtime_cmd, 'pull', dockerTag],
                env=matEnv,
                stdout=d_out,
                stderr=d_err
            ).wait()
            
            self.logger.debug(f"podman pull {dockerTag} retval: {d_retval}")
            
            with open(d_out.name, mode="r") as c_stF:
                d_out_v = c_stF.read()
            with open(d_err.name,"r") as c_stF:
                d_err_v = c_stF.read()
            
            self.logger.debug(f"podman pull stdout: {d_out_v}")
            
            self.logger.debug(f"podman pull stderr: {d_err_v}")
            
            return d_retval , d_out_v , d_err_v
    
    def _save(self, dockerTag: ContainerTaggedName, destfile: AbsPath, matEnv: Mapping) -> Tuple[int, str]:
        with lzma.open(destfile, mode='wb') as d_out, tempfile.NamedTemporaryFile() as d_err:
            self.logger.debug(f"saving podman container {dockerTag}")
            with subprocess.Popen(
                [self.runtime_cmd, 'save', dockerTag],
                env=matEnv,
                stdout=subprocess.PIPE,
                stderr=d_err
            ) as sp:
                shutil.copyfileobj(sp.stdout, d_out)
                d_retval = sp.wait()
            
            self.logger.debug(f"podman save {dockerTag} retval: {d_retval}")
            
            with open(d_err.name, "r") as c_stF:
                d_err_v = c_stF.read()
            
            self.logger.debug(f"podman save stderr: {d_err_v}")
            
            return d_retval , d_err_v
    
    def materializeContainers(self, tagList: List[ContainerTaggedName], simpleFileNameMethod: ContainerFileNamingMethod, containers_dir: Union[RelPath, AbsPath] = None, offline: bool = False) -> List[Container]:
        """
        It is assured the containers are materialized
        """
        containersList = []
        
        matEnv = dict(os.environ)
        matEnv.update(self.environment)
        for tag in tagList:
            # It is an absolute URL, we are removing the docker://
            if tag.startswith(DOCKER_PROTO):
                dockerTag = tag[len(DOCKER_PROTO):]
                podmanPullTag = tag
            else:
                dockerTag = tag
                podmanPullTag = DOCKER_PROTO + tag
            
            self.logger.info(f"downloading podman container: {tag}")
            d_retval , d_out_v , d_err_v = self._inspect(dockerTag, matEnv)
            
            # Time to pull the image
            if d_retval != 0:
                d_retval , d_out_v , d_err_v = self._pull(podmanPullTag, matEnv)
                if d_retval == 0:
                    # Second try
                    d_retval , d_out_v , d_err_v = self._inspect(dockerTag, matEnv)
                    
            
            if d_retval != 0:
                errstr = """Could not materialize podman image {}. Retval {}
======
STDOUT
======
{}

======
STDERR
======
{}""".format(podmanPullTag, d_retval, d_out_v, d_err_v)
                raise ContainerFactoryException(errstr)
                
            # Parsing the output from podman inspect
            try:
                manifests = json.loads(d_out_v)
                manifest = manifests[0]
            except Exception as e:
                raise ContainerFactoryException(f"FATAL ERROR: Podman finished properly but it did not properly materialize {tag}: {e}")
            
            # Then, compute the signature
            tagId = manifest['Id']
            fingerprint = None
            if len(manifest['RepoDigests']) > 0:
                fingerprint = manifest['RepoDigests'][0]
            
            # Last but one, let's save a copy of the container locally
            containerFilename = simpleFileNameMethod(tag)
            containerFilenameMeta = containerFilename + self.META_JSON_POSTFIX
            localContainerPath = os.path.join(self.engineContainersSymlinkDir, containerFilename)
            localContainerPathMeta = os.path.join(self.engineContainersSymlinkDir, containerFilenameMeta)
            
            self.logger.info("saving docker container (for reproducibility matters): {} => {}".format(tag, localContainerPath))
            # First, let's materialize the container image
            manifestsImageSignature = ComputeDigestFromObject(manifests)
            canonicalContainerPath = os.path.join(self.containersCacheDir, manifestsImageSignature.replace('=','~').replace('/','-').replace('+','_'))
            canonicalContainerPathMeta = canonicalContainerPath + self.META_JSON_POSTFIX
            
            # Defining the destinations
            if os.path.isfile(canonicalContainerPathMeta):
                with open(canonicalContainerPathMeta, mode="r", encoding="utf-8") as tcpm:
                    metadataLocal = json.load(tcpm)
                
                manifestsImageSignatureLocal = metadataLocal.get('manifests_signature')
                manifestsImageSignatureLocalRead = ComputeDigestFromObject(metadataLocal.get('manifests', []))
                if manifestsImageSignature != manifestsImageSignatureLocal or manifestsImageSignature != manifestsImageSignatureLocalRead:
                    self.logger.warning("Corrupted canonical container metadata {tag}. Re-saving")
                    saveContainerPathMeta = True
                    imageSignatureLocal = None
                else:
                    saveContainerPathMeta = False
                    imageSignatureLocal = metadataLocal.get('image_signature')
            else:
                saveContainerPathMeta = True
                imageSignature = None
                imageSignatureLocal = None
            
            # Only trust when they match
            tmpContainerPath = os.path.join(self.containersCacheDir,str(uuid.uuid4()))
            if os.path.isfile(canonicalContainerPath) and (imageSignatureLocal is not None):
                imageSignatureLocalRead = ComputeDigestFromFile(canonicalContainerPath)
                if imageSignatureLocalRead != imageSignatureLocal:
                    self.logger.warning("Corrupted canonical container {tag}. Re-saving")
                else:
                    imageSignature = imageSignatureLocal
                    tmpContainerPath = None
            
            if tmpContainerPath is not None:
                saveContainerPathMeta = True
                d_retval, d_err_ev = self._save(dockerTag, tmpContainerPath, matEnv)
                self.logger.debug("podman save retval: {}".format(d_retval))
                self.logger.debug("podman save stderr: {}".format(d_err_v))
                
                if d_retval != 0:
                    errstr = """Could not save podman image {}. Retval {}
======
STDERR
======
{}""".format(dockerTag, d_retval, d_err_v)
                    if os.path.exists(tmpContainerPath):
                        try:
                            os.unlink(tmpContainerPath)
                        except:
                            pass
                    raise ContainerFactoryException(errstr)
                
                shutil.move(tmpContainerPath, canonicalContainerPath)
                imageSignature = ComputeDigestFromFile(canonicalContainerPath)
            
            if saveContainerPathMeta:
                with open(canonicalContainerPathMeta, mode="w", encoding='utf-8') as tcpM:
                    json.dump({
                        "image_signature": imageSignature,
                        "manifests_signature": manifestsImageSignature,
                        "manifests": manifests
                    }, tcpM)
            
            # Now, check the relative symbolic link of image
            createSymlink = True
            if os.path.lexists(localContainerPath):
                if os.path.realpath(localContainerPath) != os.path.realpath(canonicalContainerPath):
                    os.unlink(localContainerPath)
                else:
                    createSymlink = False
            if createSymlink:
                os.symlink(os.path.relpath(canonicalContainerPath, self.engineContainersSymlinkDir), localContainerPath)
            
            # Now, check the relative symbolic link of metadata
            createSymlink = True
            if os.path.lexists(localContainerPathMeta):
                if os.path.realpath(localContainerPathMeta) != os.path.realpath(canonicalContainerPathMeta):
                    os.unlink(localContainerPathMeta)
                else:
                    createSymlink = False
            if createSymlink:
                os.symlink(os.path.relpath(canonicalContainerPathMeta, self.engineContainersSymlinkDir), localContainerPathMeta)
            
            # Last, hardlink or copy the container and its metadata
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
            
            # And add to the list of containers
            containersList.append(
                Container(
                    origTaggedName=tag,
                    taggedName=dockerTag,
                    signature=tagId,
                    fingerprint=fingerprint,
                    type=self.containerType,
                    localPath=containerPath
                )
            )
        
        return containersList
