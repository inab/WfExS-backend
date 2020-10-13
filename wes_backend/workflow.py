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

from urllib import request
from rocrate import rocrate

if platform.system() == "Darwin":
    import ssl

    ssl._create_default_https_context = ssl._create_unverified_context


class WF:
    """
    Workflow class
    """

    filename = "crate.zip"
    DEFAULT_TRS_ENDPOINT = "https://dev.workflowhub.eu/ga4gh/trs/v2/tools/"  # the root of GA4GH TRS API
    rocrate_path = "/ro/"
    
    @classmethod
    def fromDescription(cls,config):
        return cls(
            config['workflow_id'],
            config['version'],
            descriptor_type=config.get('workflow_type'),
            trs_endpoint=config.get('trs_endpoint',cls.DEFAULT_TRS_ENDPOINT),
            params=config.get('params',{})
        )
    
    def __init__(self, id, version_id, descriptor_type=None,trs_endpoint=DEFAULT_TRS_ENDPOINT,params={}):
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
        self.id = id
        self.version_id = version_id
        self.descriptor_type = descriptor_type
        self.trs_endpoint = trs_endpoint

    def downloadROcrate(self, path):
        """
        Download RO-crate from WorkflowHub (https://dev.workflowhub.eu/)
        using GA4GH TRS API and save RO-Crate in path

        :param path: location path to save RO-Crate
        :type path: str
        """
        try:
            endpoint = "{}{}/versions/{}/{}/files?format=zip".format(self.trs_endpoint, self.id, self.version_id,
                                                                     self.descriptor_type)

            with request.urlopen(endpoint) as url_response, open(path + self.filename, "wb") as download_file:
                shutil.copyfileobj(url_response, download_file)

        except Exception as e:
            raise Exception("Cannot download RO-Crate from WorkflowHub, {}".format(e))

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
