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

import re
import os
import sys
import setuptools

# In this way, we are sure we are getting
# the installer's version of the library
# not the system's one
setupDir = os.path.dirname(__file__)
sys.path.insert(0, setupDir)

from wfexs_backend import __version__ as wfexs_backend_version
from wfexs_backend import __author__ as wfexs_backend_author
from wfexs_backend import __license__ as wfexs_backend_license

# Populating the long description
with open("README.md", "r") as fh:
    long_description = fh.read()

# Populating the install requirements
with open('requirements.txt') as f:
    requirements = []
    egg = re.compile(r"#[^#]*egg=([^=&]+)")
    for line in f.read().splitlines():
        m = egg.search(line)
        requirements.append(line if m is None else m.group(1))

package_data = {
    'wfexs_backend': [
        'payloads/*.bash'
    ],
}
    
setuptools.setup(
    name="wfexs_backend",
    version=wfexs_backend_version,
    scripts=["WfExS-backend.py","WfExS-config-replicator.py"],
    package_data=package_data,
    author=wfexs_backend_author,
    author_email="lrodrin@users.noreply.github.com, jose.m.fernandez@bsc.es",
    license=wfexs_backend_license,
    description="Workflow Execution Service backend",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/inab/WfExS-backend",
    packages=setuptools.find_packages(),
    install_requires=requirements,
    classifiers=[
        "Programming Language :: Python :: 3",
        "Development Status :: 3 - Alpha",
        "License :: OSI Approved :: Apache Software License",
        "Operating System :: OS Independent",
    ],
)
