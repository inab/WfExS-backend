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

from lib.workflow import WF

if __name__ == '__main__':

    current_path = os.getcwd() + "/"

    # workflow proprieties
    id = 126
    version_id = 1
    descriptor_type = "NFL"  # Nextflow

    # workflow object
    wf = WF(id, version_id, descriptor_type)

    # download RO-Crate from WorkflowHub
    wf.downloadROcrate(current_path)

    # unzip RO-Crate
    wf.unzipROcrate(current_path)

    # download main workflow from RO-Crate
    wf.downloadWorkflow(current_path)
