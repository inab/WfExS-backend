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

import logging

from .utils.digests import ComputeDigestFromDirectory, ComputeDigestFromFile, nihDigester
from .common import *

logger = logging.getLogger()


def addInputsResearchObject(crate, inputs):
    """
    Add the input's provenance data to a Research Object.

    :param crate: Research Object
    :type crate: ROCrate object
    :param inputs: List of inputs to add
    :type inputs: list
    """
    for in_item in inputs:
        if isinstance(in_item, MaterializedInput):
            itemInValues = in_item.values[0]
            if isinstance(itemInValues, MaterializedContent):
                # TODO: embed metadata_array in some way
                itemInLocalSource = itemInValues.local  # local source
                itemInURISource = itemInValues.licensed_uri.uri  # uri source
                if os.path.isfile(itemInLocalSource):
                    properties = {
                        'name': in_item.name
                    }
                    crate.add_file(source=itemInURISource, fetch_remote=False, validate_url=False, properties=properties)

                elif os.path.isdir(itemInLocalSource):
                    errmsg = "FIXME: input directory / dataset handling in RO-Crate"
                    logger.error(errmsg)

                else:
                    pass    # TODO: raise exception

            # TODO digest other types of inputs


def addOutputsResearchObject(crate, outputs):
    """
    Add the output's provenance data to a Research Object.

    :param crate: Research Object
    :type crate: ROCrate object
    :param outputs: List of outputs to add
    :type outputs: list
    """
    for out_item in outputs:
        if isinstance(out_item, MaterializedOutput):
            itemOutValues = out_item.values[0]

            assert isinstance(itemOutValues, (GeneratedContent, GeneratedDirectoryContent))

            itemOutSource = itemOutValues.local     # local source
            itemOutName = out_item.name
            properties = {
                'name': itemOutName
            }
            if isinstance(itemOutValues, GeneratedDirectoryContent):  # if directory
                if os.path.isdir(itemOutSource):
                    generatedDirectoryContentURI = ComputeDigestFromDirectory(itemOutSource, repMethod=nihDigester)  # generate directory digest
                    dirProperties = dict.fromkeys(['hasPart'])
                    generatedContentList = []
                    generatedDirectoryContentList = []

                    for item in itemOutValues.values:
                        if isinstance(item, GeneratedContent):  # directory of files
                            fileID = item.signature
                            if fileID is None:
                                fileID = ComputeDigestFromFile(item.local, repMethod=nihDigester)
                            fileProperties = {
                                'name': itemOutName + "::/" + os.path.basename(item.local),
                                'isPartOf': {'@id': generatedDirectoryContentURI}  # reference to directory containing the file
                            }
                            generatedContentList.append({'@id': fileID})
                            crate.add_file(source=fileID, fetch_remote=False, properties=fileProperties)

                        elif isinstance(item, GeneratedDirectoryContent):  # directory of directories

                            # search recursively for other content inside directory
                            def search_new_content(content_list):
                                tempList = []
                                for content in content_list:
                                    if isinstance(content, GeneratedContent):  # file
                                        fileID = content.signature     # TODO: create a method to add files to RO-crate
                                        if fileID is None:
                                            fileID = ComputeDigestFromFile(content.local, repMethod=nihDigester)   # generate file digest
                                        fileProperties = {
                                            'name': itemOutName + "::/" + os.path.basename(content.local),
                                            'isPartOf': {'@id': generatedDirectoryContentURI}   # reference to directory containing the file
                                        }
                                        tempList.append({'@id': fileID})
                                        crate.add_file(source=fileID, fetch_remote=False, properties=fileProperties)

                                    if isinstance(content, GeneratedDirectoryContent):  # directory
                                        tempList.extend(search_new_content(content.values))

                                return tempList

                            generatedDirectoryContentList.append(search_new_content(item.values))

                        else:
                            pass  # TODO: raise exception

                    dirProperties['hasPart'] = sum(generatedDirectoryContentList, []) + generatedContentList    # all the content
                    properties.update(dirProperties)
                    crate.add_directory(source=generatedDirectoryContentURI, fetch_remote=False, properties=properties)

                else:
                    errmsg = "ERROR: The output directory %s does not exist" % itemOutSource
                    logger.error(errmsg)

            elif isinstance(itemOutValues, GeneratedContent):  # file
                if os.path.isfile(itemOutSource):
                    fileID = itemOutValues.signature
                    if fileID is None:
                        fileID = ComputeDigestFromFile(itemOutSource, repMethod=nihDigester)
                    crate.add_file(source=fileID, fetch_remote=False, properties=properties)

                else:
                    errmsg = "ERROR: The output file %s does not exist" % itemOutSource
                    logger.error(errmsg)

            else:
                pass
                # TODO digest other types of inputs
