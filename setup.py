#!/usr/bin/env python
# -*- coding: utf-8 -*-

# SPDX-License-Identifier: Apache-2.0
# Copyright 2020-2024 Barcelona Supercomputing Center (BSC), Spain
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
from wfexs_backend import __url__ as wfexs_backend_url

# Populating the long description
with open(os.path.join(setupDir, "README.md"), mode="r", encoding="utf-8") as fh:
    long_description = fh.read()

# Populating the install requirements
with open(
    os.path.join(setupDir, "requirements.txt"), mode="r", encoding="iso-8859-1"
) as f:
    requirements = []
    egg = re.compile(r"#[^#]*egg=([^=&]+)")
    for line in f.read().splitlines():
        m = egg.search(line)
        requirements.append(line if m is None else m.group(1))

package_data = {
    "wfexs_backend": [
        "py.typed",
        "payloads/*.bash",
        "schemas/*.json",
    ],
}

setuptools.setup(
    name="wfexs_backend",
    version=wfexs_backend_version,
    scripts=["WfExS-backend.py", "WfExS-config-replicator.py"],
    package_data=package_data,
    author=wfexs_backend_author,
    author_email="lrodrin@users.noreply.github.com, jose.m.fernandez@bsc.es",
    license=wfexs_backend_license,
    description="Workflow Execution Service backend",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url=wfexs_backend_url,
    python_requires=">=3.7",
    packages=setuptools.find_packages(),
    install_requires=requirements,
    entry_points={
        "console_scripts": [
            "WfExS-backend=wfexs_backend.__main__:main",
        ],
    },
    classifiers=[
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Development Status :: 3 - Alpha",
        "License :: OSI Approved :: Apache Software License",
        "Operating System :: OS Independent",
    ],
)
