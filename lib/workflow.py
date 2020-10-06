#!/usr/bin/env python

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
import os
import shutil
import zipfile
import platform

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
    root_url = "https://dev.workflowhub.eu/ga4gh/trs/v2/tools/"  # the root of GA4GH TRS API
    rocrate_path = "/ro/"

    def __init__(self, id, version_id, descriptor_type):
        """
        Init function

        :param id: A unique identifier of the workflow
        :param version_id: An identifier of the workflow version
        :param descriptor_type: The type of descriptor that represents this version of the workflow
        (e.g. CWL, WDL, NFL, or GALAXY)
        :type id: int
        :type version_id: int
        :type descriptor_type: str
        """
        self.id = id
        self.version_id = version_id
        self.descriptor_type = descriptor_type

    def downloadROcrate(self, path):
        """
        Download RO-crate from WorkflowHub (https://dev.workflowhub.eu/)
        using GA4GH TRS API and save RO-Crate in path

        :param path: location path to save RO-Crate
        :type path: str
        """
        try:
            endpoint = "{}{}/versions/{}/{}/files?format=zip".format(self.root_url,
                                                                     self.id,
                                                                     self.version_id,
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
        Download main workflow of RO-Crate

        :param path: location path of RO-Crate folder
        :type path: str
        """
        try:
            # Create RO-Crate ES MEJOR PARA MANIPULAR
            ro_crate = rocrate.ROCrate(path + self.rocrate_path, load_preview=False)

            # Save main URL workflow from RO-Crate
            wf_url = ro_crate.root_dataset['isBasedOn']

            # TODO validate wf_url

            if "github" in wf_url:  # main workflow from Github
                wf_url_parsed = wf_url.replace("https://github.com", "https://raw.githubusercontent.com").replace(
                    wf_url.split("/")[5] + "/", "")

                # TODO validate wf_url_parsed

            # TODO add other repositories ???

            with request.urlopen(wf_url_parsed) as url_response, open(os.path.basename(wf_url_parsed),
                                                                      "wb") as download_file:
                shutil.copyfileobj(url_response, download_file)

        except Exception as e:
            raise Exception("Cannot download main workflow, {}".format(e))
