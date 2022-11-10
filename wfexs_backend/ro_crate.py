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

import copy
import logging
import os
from typing import (
    cast,
    Any,
    Mapping,
    MutableMapping,
    MutableSequence,
    Optional,
    Sequence,
    Union,
)
import urllib.parse

import rocrate.model.entity  # type:ignore
import rocrate.rocrate  # type:ignore

from .utils.digests import (
    nihDigester,
    ComputeDigestFromDirectory,
    ComputeDigestFromFile,
)
from .common import (
    AbstractGeneratedContent,
    ContentKind,
    Fingerprint,
    GeneratedContent,
    GeneratedDirectoryContent,
    MaterializedContent,
    MaterializedInput,
    MaterializedOutput,
    SymbolicOutputName,
    URIType,
)

logger = logging.getLogger()


class FormalParameter(rocrate.model.entity.Entity):  # type: ignore[misc]
    def __init__(
        self,
        crate: "rocrate.rocrate.ROCrate",
        name: "str",
        additional_type: "Optional[str]" = None,
        identifier: "Optional[str]" = None,
        properties: "Optional[Mapping[str, Any]]" = None,
    ):
        fp_properties = {
            "name": name,
            "conformsTo": "https://bioschemas.org/profiles/FormalParameter/1.0-RELEASE/",
        }

        if additional_type is not None:
            fp_properties["additionalType"] = additional_type

        if properties is not None:
            fp_properties.update(properties)
        super().__init__(crate, identifier=identifier, properties=fp_properties)


class PropertyValue(rocrate.model.entity.Entity):  # type: ignore[misc]
    def __init__(
        self,
        crate: "rocrate.rocrate.ROCrate",
        name: "str",
        value: "Union[bool,str,int,float]",
        identifier: "Optional[str]" = None,
        properties: "Optional[Mapping[str, Any]]" = None,
    ):
        pv_properties = {
            "name": name,
            "value": value,
        }

        if properties is not None:
            pv_properties.update(properties)
        super().__init__(crate, identifier=identifier, properties=pv_properties)


# class PropertyValue(rocrate.model.entity.Entity):
#    def __init__(self, crate, )


def addInputsResearchObject(
    wf_crate: "rocrate.model.computationalworkflow.ComputationalWorkflow",
    inputs: "Sequence[MaterializedInput]",
    workflow_id: "URIType",
) -> None:
    """
    Add the input's provenance data to a Research Object.

    :param crate: Research Object
    :type crate: ROCrate object
    :param inputs: List of inputs to add
    :type inputs: Sequence[MaterializedInput]
    """
    crate = wf_crate.crate
    for in_item in inputs:
        formal_parameter_id = (
            workflow_id + "#param:" + urllib.parse.quote(in_item.name, safe="")
        )
        itemInValue0 = in_item.values[0]
        additional_type: "Optional[str]" = None
        if isinstance(itemInValue0, int):
            additional_type = "Integer"
        elif isinstance(itemInValue0, str):
            additional_type = "String"
        elif isinstance(itemInValue0, bool):
            additional_type = "Boolean"
        elif isinstance(itemInValue0, float):
            additional_type = "Float"
        elif isinstance(itemInValue0, MaterializedContent):
            if itemInValue0.kind == ContentKind.File:
                additional_type = "File"
            elif itemInValue0.kind == ContentKind.Directory:
                additional_type = "Dataset"

        formal_parameter = FormalParameter(
            crate,
            name=in_item.name,
            identifier=formal_parameter_id,
            additional_type=additional_type,
        )
        crate.add(formal_parameter)
        wf_crate.append_to("input", formal_parameter)

        if additional_type in ("File", "Dataset"):
            for itemInValues in cast("Sequence[MaterializedContent]", in_item.values):
                # TODO: embed metadata_array in some way
                assert isinstance(itemInValues, MaterializedContent)
                itemInLocalSource = itemInValues.local  # local source
                itemInURISource = itemInValues.licensed_uri.uri  # uri source
                if os.path.isfile(itemInLocalSource):
                    # file_properties = {
                    #    "exampleOfWork": {
                    #        "@id": formal_parameter_id
                    #    }
                    # }
                    crate_file = crate.add_file(
                        source=itemInURISource,
                        fetch_remote=False,
                        validate_url=False,
                        # properties=file_properties,
                    )
                    crate_file.append_to("exampleOfWork", formal_parameter)
                    formal_parameter.append_to("workExample", crate_file)

                elif os.path.isdir(itemInLocalSource):
                    errmsg = "FIXME: input directory / dataset handling in RO-Crate"
                    logger.error(errmsg)

                else:
                    pass  # TODO: raise exception
        else:
            for itemInAtomicValues in cast(
                "Sequence[Union[bool,str,float,int]]", in_item.values
            ):
                assert isinstance(itemInAtomicValues, (bool, str, float, int))
                parameter_value = PropertyValue(crate, in_item.name, itemInAtomicValues)
                crate_pv = crate.add(parameter_value)
                crate_pv.append_to("exampleOfWork", formal_parameter)
                formal_parameter.append_to("workExample", crate_pv)

        # TODO digest other types of inputs


def addOutputsResearchObject(
    wf_crate: "rocrate.model.computationalworkflow.ComputationalWorkflow",
    outputs: Sequence[MaterializedOutput],
) -> None:
    """
    Add the output's provenance data to a Research Object.

    :param crate: Research Object
    :type crate: ROCrate object
    :param outputs: List of outputs to add
    :type outputs: Sequence[MaterializedOutput]
    """
    crate = wf_crate.crate
    for out_item in outputs:
        # This can happen when there is no output, like when a workflow has failed
        if len(out_item.values) == 0:
            continue

        itemOutValues = out_item.values[0]

        assert isinstance(itemOutValues, (GeneratedContent, GeneratedDirectoryContent))

        itemOutSource = itemOutValues.local  # local source
        itemOutName = out_item.name
        properties: MutableMapping[str, SymbolicOutputName] = {"name": itemOutName}
        if isinstance(itemOutValues, GeneratedDirectoryContent):  # if directory
            if os.path.isdir(itemOutSource):
                generatedDirectoryContentURI = ComputeDigestFromDirectory(
                    itemOutSource, repMethod=nihDigester
                )  # generate directory digest
                dirProperties: MutableMapping[str, Any] = dict.fromkeys(["hasPart"])
                generatedContentList: MutableSequence[Mapping[str, Fingerprint]] = []
                generatedDirectoryContentList: MutableSequence[
                    Mapping[str, Fingerprint]
                ] = []

                assert itemOutValues.values is not None
                for item in itemOutValues.values:
                    if isinstance(item, GeneratedContent):  # directory of files
                        fileID = item.signature
                        if fileID is None:
                            fileID = cast(
                                Fingerprint,
                                ComputeDigestFromFile(
                                    item.local, repMethod=nihDigester
                                ),
                            )
                        fileProperties = {
                            "name": itemOutName + "::/" + os.path.basename(item.local),
                            "isPartOf": {
                                "@id": generatedDirectoryContentURI
                            },  # reference to directory containing the file
                        }
                        generatedContentList.append({"@id": fileID})
                        crate.add_file(
                            source=fileID, fetch_remote=False, properties=fileProperties
                        )

                    elif isinstance(
                        item, GeneratedDirectoryContent
                    ):  # directory of directories

                        # search recursively for other content inside directory
                        def search_new_content(
                            content_list: Sequence[AbstractGeneratedContent],
                        ) -> Sequence[Mapping[str, Fingerprint]]:
                            tempList: MutableSequence[Mapping[str, Fingerprint]] = []
                            for content in content_list:
                                if isinstance(content, GeneratedContent):  # file
                                    fileID = (
                                        content.signature
                                    )  # TODO: create a method to add files to RO-crate
                                    if fileID is None:
                                        fileID = cast(
                                            Fingerprint,
                                            ComputeDigestFromFile(
                                                content.local, repMethod=nihDigester
                                            ),
                                        )  # generate file digest
                                    fileProperties = {
                                        "name": itemOutName
                                        + "::/"
                                        + os.path.basename(content.local),
                                        "isPartOf": {
                                            "@id": generatedDirectoryContentURI
                                        },  # reference to directory containing the file
                                    }
                                    tempList.append({"@id": fileID})
                                    crate.add_file(
                                        source=fileID,
                                        fetch_remote=False,
                                        properties=fileProperties,
                                    )

                                elif isinstance(
                                    content, GeneratedDirectoryContent
                                ):  # directory
                                    assert content.values is not None
                                    tempList.extend(search_new_content(content.values))

                            return tempList

                        assert item.values is not None
                        generatedDirectoryContentList.extend(
                            search_new_content(item.values)
                        )

                    else:
                        pass  # TODO: raise exception

                d_has_part = copy.copy(generatedDirectoryContentList)
                d_has_part.extend(generatedContentList)
                dirProperties["hasPart"] = d_has_part  # all the content
                properties.update(dirProperties)
                crate.add_directory(
                    source=generatedDirectoryContentURI,
                    fetch_remote=False,
                    properties=properties,
                )

            else:
                errmsg = "ERROR: The output directory %s does not exist" % itemOutSource
                logger.error(errmsg)

        elif isinstance(itemOutValues, GeneratedContent):  # file
            if os.path.isfile(itemOutSource):
                fileID = itemOutValues.signature
                if fileID is None:
                    fileID = cast(
                        Fingerprint,
                        ComputeDigestFromFile(itemOutSource, repMethod=nihDigester),
                    )
                crate.add_file(source=fileID, fetch_remote=False, properties=properties)

            else:
                errmsg = "ERROR: The output file %s does not exist" % itemOutSource
                logger.error(errmsg)

        else:
            pass
            # TODO digest other types of inputs
