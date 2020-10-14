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
import shutil
import zipfile
import platform
import git
import tempfile
import atexit
import shutil
import urllib.parse
import json

from urllib import request
from rocrate import rocrate

if platform.system() == "Darwin":
    import ssl

    ssl._create_default_https_context = ssl._create_unverified_context


class WFException(Exception):
    pass

class WF:
    """
    Workflow class
    """

    filename = "crate.zip"
    DEFAULT_TRS_ENDPOINT = "https://dev.workflowhub.eu/ga4gh/trs/v2/tools/"  # the root of GA4GH TRS API
    rocrate_path = "/ro/"
    
    DEFAULT_GIT_CMD = 'git'
    
    RECOGNIZED_DESCRIPTORS = ['NFL','CWL']
    
    @classmethod
    def fromDescription(cls,workflow_config,local_config):
        """
        
        :param workflow_config: The configuration describing both the workflow
        and the inputs to use when it is being instantiated
        :param local_config: Relevant local configuration, like the cache directory
        """
        return cls(
            workflow_config['workflow_id'],
            workflow_config['version'],
            descriptor_type=workflow_config.get('workflow_type'),
            trs_endpoint=workflow_config.get('trs_endpoint',cls.DEFAULT_TRS_ENDPOINT),
            params=workflow_config.get('params',{}),
            local_config=local_config
        )
    
    def __init__(self, workflow_id, version_id, descriptor_type=None,trs_endpoint=DEFAULT_TRS_ENDPOINT,params={},local_config={}):
        """
        Init function

        :param id: A unique identifier of the workflow. Although it is an integer in WorkflowHub,
        we cannot assume it is so in all the GA4GH TRS implementations which are exposing workflows.
        :param version_id: An identifier of the workflow version. Although it is an integer in
        WorkflowHub, we cannot assume the format of the version id, as it could follow semantic
        versioning, providing an UUID, etc...
        :param descriptor_type: The type of descriptor that represents this version of the workflow
        (e.g. CWL, WDL, NFL, or GALAXY). It is optional, so it is guessed from
        the calls to the API
        :param trs_endpoint: The TRS endpoint used to find the workflow
        :param params: Optional params for the workflow execution
        :type id: str
        :type version_id: str
        :type descriptor_type: str
        :type trs_endpoint: str
        :type params: dict
        """
        self.id = str(workflow_id)
        self.version_id = str(version_id)
        self.descriptor_type = descriptor_type
        self.params = params
        self.local_config = local_config
        
        # The endpoint should always end with a slash
        if isinstance(trs_endpoint,str) and trs_endpoint[-1] != '/':
            trs_endpoint += '/'
        
        self.trs_endpoint = trs_endpoint
        
        # This directory will be used to cache repositories
        cacheDir = local_config.get('cacheDir')
        if cacheDir:
            os.makedirs(cacheDir, exist_ok=True)	
        else:
            cacheDir = tempfile.mkdtemp(prefix='wes',suffix='backend')
            # Assuring this temporal directory is removed at the end
            atexit.register(shutil.rmtree,cacheDir)
            
        self.git_cmd = local_config.get('gitCommand',DEFAULT_GIT_CMD)
        
        self.cacheDir = cacheDir
        self.cacheWorkflowDir = os.path.join(cacheDir,'wf-cache')
        os.makedirs(self.cacheWorkflowDir, exist_ok=True)
        self.cacheROCrateDir = os.path.join(cacheDir,'ro-crate-cache')
        os.makedirs(self.cacheROCrateDir, exist_ok=True)
    
    def fetchWorkflow(self):
        """
        Fetch the whole workflow description based on the data obtained
        from the TRS where it is being published.
        
        If the workflow id is an URL, it is supposed to be a git repository,
        and the version will represent either the branch, tag or specific commit.
        So, the whole TRS fetching machinery is bypassed
        """
        parsedRepoURL = urllib.parse.urlparse(self.id)
        
        # It is not an absolute URL, so it is being an identifier in the workflow
        if parsedRepoURL.scheme == '':
            repoURL , repoTag , repoRelDir = self.getWorkflowRepoFromTRS()
        else:
            repoURL = self.id
            repoTag = self.version_id
            repoRelDir = None
        
        self.repoURL = repoURL
        self.repoTag = repoTag
        
        repoDir = self.doMaterializeRepo(repoURL,repoTag)
        # This is needed for specific cases
        if repoRelDir is not None:
            repoDir = os.path.join(repoDir,repoRelDir)
        
        self.repoDir = repoDir
    
    def setupEngine(self):
        pass
    
    def fetchInputs(self):
        pass
    
    def executeWorkflow(self):
        pass
    
    def doMaterializeRepo(self, repoURL, repoTag):
        repo_hashed_id = hashlib.sha1(repoURL.encode('utf-8')).hexdigest()
        repo_hashed_tag_id = hashlib.sha1(repoTag.encode('utf-8')).hexdigest()
        
        # Assure directory exists before next step
        repo_destdir = os.path.join(self.cacheWorkflowDir,repo_hashed_id)
        if not os.path.exists(repo_destdir):
            try:
                os.makedirs(repo_destdir)
            except IOError as error:
                errstr = "ERROR: Unable to create intermediate directories for repo {}. ".format(repoURL,);
                raise WFException(errstr)
        
        repo_tag_destdir = os.path.join(repo_destdir,repo_hashed_tag_id)
        # We are assuming that, if the directory does exist, it contains the repo
        if not os.path.exists(repo_tag_destdir):
            # Try cloning the repository without initial checkout
            gitclone_params = [
                self.git_cmd,'clone','-n','--recurse-submodules',repoURL,repo_tag_destdir
            ]
            
            # Now, checkout the specific commit
            gitcheckout_params = [
                self.git_cmd,'checkout',repoTag
            ]
            
            # Last, initialize submodules
            gitsubmodule_params = [
                self.git_cmd,'submodule','update','--init'
            ]
            
            with tempfile.NamedTemporaryFile() as git_stdout:
                with tempfile.NamedTemporaryFile() as git_stderr:
                    # First, bare clone
                    retval = subprocess.call(gitclone_params,stdout=git_stdout,stderr=git_stderr)
                    # Then, checkout
                    if retval == 0:
                        retval = subprocess.Popen(gitcheckout_params,stdout=git_stdout,stderr=git_stderr,cwd=repo_tag_destdir).wait()
                    # Last, submodule preparation
                    if retval == 0:
                        retval = subprocess.Popen(gitsubmodule_params,stdout=git_stdout,stderr=git_stderr,cwd=repo_tag_destdir).wait()
                    
                    # Proper error handling
                    if retval != 0:
                        # Reading the output and error for the report
                        with open(git_stdout.name,"r") as c_stF:
                            git_stdout_v = c_stF.read()
                        with open(git_stderr.name,"r") as c_stF:
                            git_stderr_v = c_stF.read()
                        
                        errstr = "ERROR: Unable to pull '{}' (tag '{}'). Retval {}\n======\nSTDOUT\n======\n{}\n======\nSTDERR\n======\n{}".format(repoURL,repoTag,retval,git_stdout_v,git_stderr_v)
                        raise WFException(errstr)
	 
        return repo_tag_destdir
    
    def getWorkflowRepoFromTRS(self):
        # First, check the tool does exist in the TRS, and the version
        trs_tool_url = urllib.parse.urljoin(self.trs_endpoint,urllib.parse.quote(self.id,safe=''))
        
        # The original bytes
        response = b''
        with request.urlopen(trs_tool_url) as req:
            while True:
                try:
                    # Try getting it
                    responsePart = req.read()
                except http.client.IncompleteRead as icread:
                    # Getting at least the partial content
                    response += icread.partial
                    continue
                else:
                    # In this case, saving all
                    response += responsePart
                break
        
        # If the tool does not exist, an exception will be thrown before
        jd = json.JSONDecoder()
        rawToolDesc = response.decode('utf-8')
        toolDesc = jd.decode(rawToolDesc)
        
        # If the tool is not a workflow, complain
        if toolDesc.get('toolclass',{}).get('name','') != 'Workflow':
            raise WFException('Tool {} from {} is not labelled as a workflow. Raw answer:\n{}'.format(self.id,self.trs_endpoint,rawToolDesc))
        
        possibleToolVersions = toolDesc.get('versions',[])
        if len(possibleToolVersions) == 0:
            raise WFException('Version {} not found in workflow {} from {} . Raw answer:\n{}'.format(self.version_id,self.id,self.trs_endpoint,rawToolDesc))
        
        toolVersion = None
        toolVersionId = self.version_id
        if (toolVersionId is not None) and len(toolVersionId) > 0:
            for possibleToolVersion in possibleToolVersions:
                if isinstance(possibleToolVersion,dict) and str(possibleToolVersion.get('id','')) == self.version_id;
                    toolVersion = possibleToolVersion
                    break
            else:
                raise WFException('Version {} not found in workflow {} from {} . Raw answer:\n{}'.format(self.version_id,self.id,self.trs_endpoint,rawToolDesc))
        else:
            toolVersionId = ''
            for possibleToolVersion in possibleToolVersions:
                possibleToolVersionId = str(possibleToolVersion.get('id',''))
                if len(possibleToolVersionId) > 0 and toolVersionId < possibleToolVersionId:
                    toolVersion = possibleToolVersion
                    toolVersionId = possibleToolVersionId
        
        if toolVersion is None:
            raise WFException('No valid version was found in workflow {} from {} . Raw answer:\n{}'.format(self.id,self.trs_endpoint,rawToolDesc))
    
        # The version has been found
        toolDescriptorTypes = toolVersion.get('descriptor_type',[])
        if not isinstance(toolDescriptorTypes,list):
            raise WFException('Version {} of workflow {} from {} has no valid "descriptor_type" (should be a list). Raw answer:\n{}'.format(self.version_id,self.id,self.trs_endpoint,rawToolDesc))
        
        # Now, realize whether it matches
        chosenDescriptorType = self.descriptor_type
        if chosenDescriptorType is None:
            for candidateDescriptorType in self.RECOGNIZED_DESCRIPTORS:
                if candidateDescriptorType in toolDescriptorTypes:
                    chosenDescriptorType = candidateDescriptorType
                    break
            else:
                raise WFException('Version {} of workflow {} from {} has no acknowledged "descriptor_type". Raw answer:\n{}'.format(self.version_id,self.id,self.trs_endpoint,rawToolDesc))
        elif chosenDescriptorType not in toolVersion['descriptor_type']:
            raise WFException('Descriptor type {} not available for version {} of workflow {} from {} . Raw answer:\n{}'.format(self.descriptor_type,self.version_id,self.id,self.trs_endpoint,rawToolDesc))
        elif chosenDescriptorType not in self.RECOGNIZED_DESCRIPTORS:
            raise WFException('Descriptor type {} is not among the acknowledged ones by this backend. Version {} of workflow {} from {} . Raw answer:\n{}'.format(self.descriptor_type,self.version_id,self.id,self.trs_endpoint,rawToolDesc))
        
        
        # And this is the moment where the RO-Crate must be fetched
        roCrateURL = trs_tool_url + '/versions/'+urllib.parse.quote(toolVersionId,safe='')+'/'+urllib.parse.quote(chosenDescriptorType,safe='')+'/files?'+urllib.parse.urlencode({'format': 'zip'})
        
        return self.getWorkflowRepoFromROCrate(roCrateURL)
    
    def getWorkflowRepoFromROCrate(self,roCrateURL)
        roCrateFile = self.downloadROcrate(roCrateURL)
        roCrateObj = rocrate.ROCrate(roCrateFile)
        
        # This workflow URL, in the case of github, can provide the repo,
        # the branch/tag/checkout , and the relative directory in the
        # fetched content (needed by Nextflow)
        wf_url = roCrateObj.root_dataset['isBasedOn']
        
        # TO BE CONTINUED
        
        # It must return three elements:
        # repoURL , repoTag , repoRelDir
        
    def downloadROcrate(self, roCrateURL):
        """
        Download RO-crate from WorkflowHub (https://dev.workflowhub.eu/)
        using GA4GH TRS API and save RO-Crate in path
        It returns the 

        :param path: location path to save RO-Crate
        :type path: str
        """
        crate_hashed_id = hashlib.sha1(roCrateURL.encode('utf-8')).hexdigest()
        cachedFilename = os.path.join(self.cacheROCrateDir,crate_hashed_id+'.zip')
        if not os.path.exists(cachedFilename):
            try:
                with request.urlopen(roCrateURL) as url_response, open(cachedFilename, "wb") as download_file:
                    shutil.copyfileobj(url_response, download_file)
            except Exception as e:
                raise WFException("Cannot download RO-Crate, {}".format(e))
        
        return cachedFilename

    def unzipROcrate(self, path):
        """
        Unzip RO-crate to rocrate_path

        :param path: location path of RO-Crate zip file
        :type path: str
        """
        try:
            with zipfile.ZipFile(path + self.filename, "r") as zip_file:
                zip_file.extractall(path + self.rocrate_path)

        except Exception as e:
            raise Exception("Cannot unzip RO-Crate, {}".format(e))

    def downloadWorkflow(self, path):
        """
        Download main workflow and his repository from RO-Crate

        :param path: location path of RO-Crate folder
        :type path: str
        """
        global wf_url_raw
        try:
            # Create RO-Crate
            ro_crate = rocrate.ROCrate(path + self.rocrate_path, load_preview=False)

            # Save main URL workflow from RO-Crate
            wf_url = ro_crate.root_dataset['isBasedOn']
            wf_url_str = wf_url.replace(wf_url.split("/")[5] + "/", "")  # removed blob str
            # TODO validate wf_url

            if "github" in wf_url:  # main workflow from Github
                wf_url_raw = wf_url_str.replace("https://github.com", "https://raw.githubusercontent.com")
                # TODO validate wf_url_raw

            # download main workflow
            with request.urlopen(wf_url_raw) as url_response, open(os.path.basename(wf_url_raw), "wb") as download_file:
                shutil.copyfileobj(url_response, download_file)

            # download main workflow repository
            self.downloadRepository(path, wf_url_str)

        except Exception as e:
            raise Exception("Cannot download main workflow, {}".format(e))

    def downloadRepository(self, path, url_repo):
        """
        Download GitHub repository of main workflow specified by url_repo

        :param path: location path to save the repository
        :param url_repo: URL of main workflow
        :type path: str
        :type url_repo: str
        """
        try:
            repo_name = url_repo.split("/")[4]
            branch_name = url_repo.split("/")[5]
            repo = url_repo.split(branch_name)[0][:-1] + ".git"
            git.Repo.clone_from(repo, path + repo_name, branch=branch_name)

        except Exception as e:
            raise Exception("Cannot download GitHub repository, {}".format(e))
