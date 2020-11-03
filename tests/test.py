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
import sys

import yaml

sys.path.insert(1, os.path.abspath(".."))

from collections import defaultdict
from wfexs_backend import common
from wfexs_backend.workflow import WFException


def createYAMLFile(materializedParams):
    """
    Create YAML file with input values required for workflow execution.

    :param materializedParams: List of materialized input values
    :type materializedParams: list
    """
    if len(materializedParams) != 0:  # list of materializedParams not empty
        try:
            inputs = defaultdict(list)
            for param in materializedParams:
                if isinstance(param, common.MaterializedInput):  # is MaterializedInput
                    param_dict = param._asdict()
                    param_input_name = param_dict['name']
                    param_input_values = param_dict['values']
                    # if len(param_input_values) != 0:
                    for input_value in param_input_values:
                        if isinstance(input_value, common.MaterializedContent):  # is MaterializedContent
                            # TODO resolve filename to real filename specified in prettyFilename
                            input_file = input_value.local
                            # print(input_value.prettyFilename)
                            if os.path.isfile(input_file):  # is File
                                # TODO add type File in common in MaterializedContent
                                inputs[param_input_name].append({"class": "File", "location": input_file})
                        else:
                            inputs[param_input_name] = input_value
                    # else:
                    #     raise WFException("")

            # print(json.dumps(inputs, indent=2))
            # TODO remove static name
            with open("tests/wetlab2variations_cwl.yaml", 'w+') as yam_file:
                yaml.dump(dict(inputs), yam_file, allow_unicode=True, default_flow_style=False, sort_keys=False)

        except Exception as error:
            raise WFException("YAML file not created")
    else:
        raise WFException("No exists materialized input values")
