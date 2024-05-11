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
from __future__ import absolute_import

import abc
import copy
import enum
import inspect
import json
import logging

from typing import (
    cast,
    NamedTuple,
    TYPE_CHECKING,
)

import warnings

if TYPE_CHECKING:
    from typing import (
        Any,
        Mapping,
        MutableMapping,
        MutableSequence,
        Optional,
        Sequence,
        Tuple,
    )

    from typing_extensions import (
        Final,
    )

    from ..common import (
        ContainerOperatingSystem,
        Fingerprint,
        ProcessorArchitecture,
        URIType,
        WritableWorkflowMetaConfigBlock,
    )

    from ..wfexs_backend import (
        WfExSBackend,
    )

# Needed by pyld to detect it
import aiohttp
import pyld  # type: ignore[import, import-untyped]
import rdflib
import rdflib.plugins.sparql

from ..common import (
    ContainerType,
)

from ..container_factories import (
    DEFAULT_DOCKER_REGISTRY,
    Container,
)

from .digests import (
    stringifyDigest,
)


class ContainerTypeMetadata(NamedTuple):
    sa_id: "str"
    applicationCategory: "str"
    ct_applicationCategory: "str"


ContainerTypeMetadataDetails: "Final[Mapping[ContainerType, ContainerTypeMetadata]]" = {
    ContainerType.Singularity: ContainerTypeMetadata(
        sa_id="https://apptainer.org/",
        applicationCategory="https://www.wikidata.org/wiki/Q51294208",
        ct_applicationCategory="https://www.wikidata.org/wiki/Q7935198",
    ),
    ContainerType.Docker: ContainerTypeMetadata(
        sa_id="https://www.docker.com/",
        applicationCategory="https://www.wikidata.org/wiki/Q15206305",
        ct_applicationCategory="https://www.wikidata.org/wiki/Q7935198",
    ),
    ContainerType.Podman: ContainerTypeMetadata(
        sa_id="https://podman.io/",
        applicationCategory="https://www.wikidata.org/wiki/Q70876440",
        ct_applicationCategory="https://www.wikidata.org/wiki/Q7935198",
    ),
    ContainerType.Conda: ContainerTypeMetadata(
        sa_id="https://conda.io/",
        applicationCategory="https://www.wikidata.org/wiki/Q22907431",
        ct_applicationCategory="https://www.wikidata.org/wiki/Q98400282",
    ),
}

ApplicationCategory2ContainerType: "Final[Mapping[str, ContainerType]]" = {
    container_type_metadata.applicationCategory: container_type
    for container_type, container_type_metadata in ContainerTypeMetadataDetails.items()
}

WORKFLOW_RUN_CONTEXT: "Final[str]" = "https://w3id.org/ro/terms/workflow-run"
WORKFLOW_RUN_NAMESPACE: "Final[str]" = WORKFLOW_RUN_CONTEXT + "#"


class ContainerImageAdditionalType(enum.Enum):
    Docker = WORKFLOW_RUN_NAMESPACE + "DockerImage"
    Singularity = WORKFLOW_RUN_NAMESPACE + "SIFImage"
    # No one is available for Conda yet


ContainerType2AdditionalType: "Final[Mapping[ContainerType, ContainerImageAdditionalType]]" = {
    ContainerType.Docker: ContainerImageAdditionalType.Docker,
    ContainerType.Singularity: ContainerImageAdditionalType.Singularity,
    ContainerType.Podman: ContainerImageAdditionalType.Docker,
    # No one is available for Conda yet
}

AdditionalType2ContainerType: "Final[Mapping[ContainerImageAdditionalType, ContainerType]]" = {
    ContainerImageAdditionalType.Docker: ContainerType.Docker,
    ContainerImageAdditionalType.Singularity: ContainerType.Singularity,
}


class ROCrateToolboxException(Exception):
    pass


class ROCrateToolbox(abc.ABC):
    # This is needed due limitations from rdflib mangling relative ids
    WFEXS_TRICK_SPARQL_PRE_PREFIX: "Final[str]" = "shttp:"
    WFEXS_TRICK_SPARQL_BASE: "Final[str]" = f"{WFEXS_TRICK_SPARQL_PRE_PREFIX}///"
    WFEXS_TRICK_SPARQL_NS: "Final[str]" = "wfexs"

    SPARQL_NS = {
        "dc": "http://purl.org/dc/elements/1.1/",
        "dcterms": "http://purl.org/dc/terms/",
        "s": "http://schema.org/",
        "bs": "https://bioschemas.org/",
        "bsworkflow": "https://bioschemas.org/profiles/ComputationalWorkflow/",
        "rocrate": "https://w3id.org/ro/crate/",
        "wfcrate": "https://w3id.org/workflowhub/workflow-ro-crate/",
        "wfhprofile": "https://about.workflowhub.eu/Workflow-RO-Crate/",
        "wrprocess": "https://w3id.org/ro/wfrun/process/",
        "wrwf": "https://w3id.org/ro/wfrun/workflow/",
        "wrterm": WORKFLOW_RUN_NAMESPACE,
        "wikidata": "https://www.wikidata.org/wiki/",
        WFEXS_TRICK_SPARQL_NS: WFEXS_TRICK_SPARQL_BASE,
    }

    def __init__(self, wfexs: "WfExSBackend"):
        if wfexs is None:
            raise ROCrateToolboxException(
                "Unable to initialize, no WfExSBackend instance provided"
            )

        # Getting a logger focused on specific classes
        self.logger = logging.getLogger(
            dict(inspect.getmembers(self))["__module__"]
            + "::"
            + self.__class__.__name__
        )

        self.wfexs = wfexs

    IS_ROCRATE_SPARQL: "Final[str]" = """\
SELECT  ?rocratejson ?rootdataset ?rocrateprofile ?wfcrateprofile ?mainentity ?bsworkflowprofile ?wrprocessprofile ?wrwfprofile
WHERE   {
    ?rocratejson
        a s:CreativeWork ;
        dcterms:conformsTo ?rocrateprofile ;
        s:about ?rootdataset .
    ?rootdataset a s:Dataset .
    FILTER (
        STRSTARTS(str(?rocrateprofile), str(rocrate:))
    ) .
    OPTIONAL {
        ?rocratejson dcterms:conformsTo ?wfcrateprofile .
        FILTER (
            ?wfcrateprofile = wfhprofile: || STRSTARTS(str(?wfcrateprofile), str(wfcrate:))
        ) .
        OPTIONAL  {
            ?rootdataset
                s:mainEntity ?mainentity .
            ?mainentity
                a bs:ComputationalWorkflow ;
                dcterms:conformsTo ?bsworkflowprofile .
            FILTER (
                STRSTARTS(str(?bsworkflowprofile), str(bsworkflow:))
            ) .
        }
        OPTIONAL  {
            ?rootdataset
                dcterms:conformsTo ?wfcrateprofile ;
                dcterms:conformsTo ?wrprocessprofile ;
                dcterms:conformsTo ?wrwfprofile .
            FILTER (
                STRSTARTS(str(?wrprocessprofile), str(wrprocess:)) &&
                STRSTARTS(str(?wrwfprofile), str(wrwf:))
            ) .
        }
    }
}
"""

    def identifyROCrate(
        self, jsonld: "Mapping[str, Any]", public_name: "str"
    ) -> "Tuple[Optional[rdflib.query.ResultRow], rdflib.graph.Graph]":
        """
        This method is used to identify where the input JSON is a
        JSON-LD related to RO-Crate.

        The returned value is a tuple, where the first element is the
        result row giving the QName of the root dataset, and the different
        profiles being matched: RO-Crate, Workflow RO-Crate, WRROC process and WRROC workflow.
        The second element of the returned tuple is the rdflib RDF
        graph from the read JSON-LD, which should allow exploring it.
        """
        jsonld_obj = cast("MutableMapping[str, Any]", copy.deepcopy(jsonld))

        # # Let's load it using RDFLib tricks
        # context: "MutableSequence[Union[str, Mapping[str, str]]]"
        # got_context = jsonld_obj.get("@context")
        # if got_context is None:
        #     context = []
        # elif isinstance(got_context, (str, dict)):
        #     context = [got_context]
        # elif isinstance(got_context, list):
        #     context = got_context
        #
        # # Setting the augmented context with the trick
        # context.append(
        #     {
        #         "@base": self.WFEXS_TRICK_SPARQL_BASE,
        #     }
        # )
        #
        # if context != got_context:
        #     jsonld_obj["@context"] = context

        # Now, let's load it in RDFLib, in order learn
        g = rdflib.Graph()
        # expand a document, removing its context
        # see: https://json-ld.org/spec/latest/json-ld/#expanded-document-form
        # which is the issue RDFLib 7.0.0 has

        # jsonld_obj_ser = jsonld_obj
        with warnings.catch_warnings():
            # Disable possible warnings emitted by pyld library
            # when it is not run in debug mode
            if self.logger.getEffectiveLevel() > logging.DEBUG:
                warnings.filterwarnings(
                    "ignore", category=SyntaxWarning, module="^pyld\.jsonld$"
                )
            jsonld_obj_ser = {
                "@graph": pyld.jsonld.expand(
                    jsonld_obj, {"keepFreeFloatingNodes": True}
                )
            }
        jsonld_str = json.dumps(jsonld_obj_ser)
        parsed = g.parse(
            data=jsonld_str,
            format="json-ld",
            base=self.WFEXS_TRICK_SPARQL_PRE_PREFIX,
        )

        # This query will tell us whether the JSON-LD is about an RO-Crate 1.1
        q = rdflib.plugins.sparql.prepareQuery(
            self.IS_ROCRATE_SPARQL,
            initNs=self.SPARQL_NS,
        )

        # TODO: cache resolution of contexts
        # TODO: disallow network access for context resolution
        # when not in right phase
        try:
            qres = g.query(q)
        except Exception as e:
            raise ROCrateToolboxException(
                f"Unable to perform JSON-LD check query over {public_name} (see cascading exceptions)"
            ) from e

        resrow: "Optional[rdflib.query.ResultRow]" = None
        # In the future, there could be more than one match, when
        # nested RO-Crate scenarios happen
        for row in qres:
            assert isinstance(
                row, rdflib.query.ResultRow
            ), "Check the SPARQL code, as it should be a SELECT query"
            resrow = row
            break

        return (resrow, g)

    OBTAIN_WORKFLOW_PID_SPARQL: "Final[str]" = """\
SELECT  ?identifier ?programminglanguage_identifier ?programminglanguage_url ?programminglanguage_version
WHERE   {
    ?mainentity s:programmingLanguage ?programminglanguage .
    ?programminglanguage
        a s:ComputerLanguage ;
        s:url ?programminglanguage_url .
    OPTIONAL {
        ?mainentity s:identifier ?identifier .
    }
    OPTIONAL {
        ?programminglanguage
            s:version ?programminglanguage_version .
    }
    OPTIONAL {
        ?programminglanguage
            s:identifier ?programminglanguage_identifier .
    }
}
"""

    OBTAIN_RUNS_SPARQL: "Final[str]" = """\
SELECT  ?execution
WHERE   {
    ?rootdataset s:mentions ?execution .
    ?execution
        a s:CreateAction ;
        s:instrument ?mainentity .
}
"""

    OBTAIN_RUN_CONTAINERS_SPARQL: "Final[str]" = """\
SELECT ?container ?container_additional_type ?type_of_container ?type_of_container_type ?container_registry ?container_name ?container_tag ?container_sha256 ?container_platform ?container_arch
WHERE   {
    ?execution wrterm:containerImage ?container .
    ?container
        a wrterm:ContainerImage ;
        s:additionalType ?container_additional_type .
    OPTIONAL {
        ?container
            s:softwareRequirements ?container_type ;
            s:applicationCategory ?type_of_container .
        ?container_type
            a s:SoftwareApplication ;
            s:applicationCategory ?type_of_container_type .
        FILTER(
            STRSTARTS(str(?type_of_container), str(wikidata:)) &&
            STRSTARTS(str(?type_of_container_type), str(wikidata:))
        ) .
    }
    OPTIONAL {
        ?container wrterm:registry ?container_registry .
    }
    OPTIONAL {
        ?container s:name ?container_name .
    }
    OPTIONAL {
        ?container wrterm:tag ?container_tag .
    }
    OPTIONAL {
        ?container wrterm:sha256 ?container_sha256 .
    }
    OPTIONAL {
        ?container
            a s:SoftwareApplication ;
            s:operatingSystem ?container_platform .
    }
    OPTIONAL {
        ?container
            a s:SoftwareApplication ;
            s:processorRequirements ?container_arch .
    }
}
"""

    # This compound query is much faster when each of the UNION components
    # is evaluated separatedly
    OBTAIN_INPUTS_SPARQL: "Final[str]" = """\
SELECT  ?input ?name ?inputfp ?additional_type ?fileuri ?value ?inputcol ?component ?leaf_type
WHERE   {
    ?execution s:object ?input .
    {
        # A file, which is a schema.org MediaObject
        VALUES (?additional_type) { ( "File" ) }
        ?input
            a s:MediaObject ;
            s:contentUrl ?fileuri ;
            s:exampleOfWork ?inputfp .
        ?inputfp
            a bs:FormalParameter ;
            s:name ?name ;
            s:additionalType ?additional_type .
    } UNION {
        # A directory, which is a schema.org Dataset
        VALUES (?additional_type) { ( "Dataset" ) }
        ?input
            a s:Dataset ;
            s:contentUrl ?fileuri ;
            s:exampleOfWork ?inputfp ;
            s:hasPart+ ?component .
        ?inputfp
            a bs:FormalParameter ;
            s:name ?name ;
            s:additionalType ?additional_type .
        ?component
            a s:MediaObject .
    } UNION {
        # A single property value, which can be either Integer, Text, Boolean or Float
        VALUES (?additional_type) { ( "Integer" ) ( "Text" ) ( "Boolean" ) ( "Float" ) }
        ?input
            a s:PropertyValue ;
            s:exampleOfWork ?inputfp ;
            s:value ?value .
        ?inputfp
            a bs:FormalParameter ;
            s:name ?name ;
            s:additionalType ?additional_type .
    } UNION {
        # A combination of files or directories or property values
        VALUES (?leaf_type ?additional_type) { ( s:Integer "Collection" ) ( s:Text "Collection" ) ( s:Boolean "Collection" ) ( s:Float "Collection" ) ( s:MediaObject "Collection" ) ( s:Dataset "Collection" ) }
        ?input
            a s:Collection ;
            s:exampleOfWork ?inputfp ;
            s:hasPart+ ?component .
        ?inputfp
            a bs:FormalParameter ;
            s:name ?name ;
            s:additionalType ?additional_type .
        ?component
            a ?leaf_type .
        OPTIONAL {
            ?component s:contentUrl ?fileuri .
        }
        OPTIONAL {
            ?component s:value ?value .
        }
    }
}
"""

    def _parseContainersFromExecution(
        self,
        g: "rdflib.graph.Graph",
        execution: "rdflib.term.Identifier",
        main_entity: "rdflib.term.Identifier",
    ) -> "Optional[Tuple[ContainerType, Sequence[Container]]]":
        # Get the list of containers
        qcontainers = rdflib.plugins.sparql.prepareQuery(
            self.OBTAIN_RUN_CONTAINERS_SPARQL,
            initNs=self.SPARQL_NS,
        )
        qcontainersres = g.query(
            qcontainers,
            initBindings={
                "execution": execution,
            },
        )

        container_type: "Optional[ContainerType]" = None
        additional_container_type: "Optional[ContainerType]" = None
        the_containers: "MutableSequence[Container]" = []
        # This is the first pass, to learn about the kind of
        # container factory to use
        for containerrow in qcontainersres:
            assert isinstance(
                containerrow, rdflib.query.ResultRow
            ), "Check the SPARQL code, as it should be a SELECT query"
            # These hints were left by WfExS, but they are not expected
            # from other implementations.
            if containerrow.type_of_container is not None:
                putative_container_type = ApplicationCategory2ContainerType.get(
                    str(containerrow.type_of_container)
                )
                if container_type is None:
                    container_type = putative_container_type
                elif (
                    putative_container_type is not None
                    and putative_container_type != container_type
                ):
                    self.logger.warning(
                        f"Not all the containers of execution {main_entity} were materialized with {container_type} factory (also found {putative_container_type})"
                    )

            # These hints should be left by any compliant WRROC
            # implementation
            if containerrow.container_additional_type is not None:
                try:
                    putative_additional_container_type = (
                        AdditionalType2ContainerType.get(
                            ContainerImageAdditionalType(
                                str(containerrow.container_additional_type)
                            )
                        )
                    )
                    if additional_container_type is None:
                        additional_container_type = putative_additional_container_type
                    elif (
                        putative_additional_container_type is not None
                        and putative_additional_container_type
                        not in (container_type, additional_container_type)
                    ):
                        self.logger.warning(
                            f"Not all the containers of execution {main_entity} were labelled with {additional_container_type} factory (also found {putative_additional_container_type})"
                        )
                except Exception as e:
                    self.logger.error(
                        f"Unable to map additional type {str(containerrow.container_additional_type)} for {str(containerrow.container)}"
                    )

        # Assigning this, as it is going to be used later to
        # build the list of containers
        if container_type is None and additional_container_type is not None:
            container_type = additional_container_type

        if container_type is None:
            return None

        # This is the second pass, to generate the list of
        # containers described in the RO-Crate
        for containerrow in qcontainersres:
            assert isinstance(
                containerrow, rdflib.query.ResultRow
            ), "Check the SPARQL code, as it should be a SELECT query"
            self.logger.debug(
                f"""\
Container {containerrow.container}
{containerrow.container_additional_type}
{containerrow.type_of_container}
{containerrow.type_of_container_type}
{containerrow.container_registry}
{containerrow.container_name}
{containerrow.container_tag}
{containerrow.container_sha256}
{containerrow.container_platform}
{containerrow.container_arch}
"""
            )

            if (
                containerrow.container_additional_type is not None
                and containerrow.container_name is not None
            ):
                try:
                    putative_additional_container_type = (
                        AdditionalType2ContainerType.get(
                            ContainerImageAdditionalType(
                                str(containerrow.container_additional_type)
                            )
                        )
                    )
                    registries: "Optional[Mapping[ContainerType, str]]" = None
                    fingerprint = None
                    origTaggedName = ""
                    taggedName = ""
                    image_signature = None
                    if putative_additional_container_type == ContainerType.Docker:
                        the_registry = (
                            str(containerrow.container_registry)
                            if containerrow.container_registry is not None
                            else DEFAULT_DOCKER_REGISTRY
                        )
                        registries = {
                            ContainerType.Docker: the_registry,
                        }
                        container_identifier = str(containerrow.container_name)
                        assert containerrow.container_sha256 is not None
                        fingerprint = f"{the_registry}/{container_identifier}@sha256:{str(containerrow.container_sha256)}"
                        assert containerrow.container_tag is not None
                        origTaggedName = (
                            f"{container_identifier}:{str(containerrow.container_tag)}"
                        )
                        taggedName = f"docker://{the_registry}/{container_identifier}:{str(containerrow.container_tag)}"
                        # Disable for now
                        # image_signature = stringifyDigest("sha256", bytes.fromhex(str(containerrow.container_sha256)))
                    elif (
                        putative_additional_container_type == ContainerType.Singularity
                    ):
                        origTaggedName = str(containerrow.container_name)
                        taggedName = origTaggedName
                        fingerprint = origTaggedName

                    the_containers.append(
                        Container(
                            origTaggedName=origTaggedName,
                            type=container_type,
                            registries=registries,
                            taggedName=cast("URIType", taggedName),
                            architecture=None
                            if containerrow.container_arch is None
                            else cast(
                                "ProcessorArchitecture",
                                str(containerrow.container_arch),
                            ),
                            operatingSystem=None
                            if containerrow.container_platform is None
                            else cast(
                                "ContainerOperatingSystem",
                                str(containerrow.container_platform),
                            ),
                            fingerprint=cast("Fingerprint", fingerprint),
                            source_type=putative_additional_container_type,
                            image_signature=image_signature,
                        )
                    )
                except Exception as e:
                    self.logger.exception(
                        f"Unable to assign from additional type {str(containerrow.container_additional_type)} for {str(containerrow.container)}"
                    )

        return container_type, the_containers

    def _parseInputsFromExecution(
        self,
        g: "rdflib.graph.Graph",
        execution: "rdflib.term.Identifier",
        main_entity: "rdflib.term.Identifier",
    ) -> "None":
        # Get the list of inputs
        qinputs = rdflib.plugins.sparql.prepareQuery(
            self.OBTAIN_INPUTS_SPARQL,
            initNs=self.SPARQL_NS,
        )
        qinputsres = g.query(
            qinputs,
            initBindings={
                "execution": execution,
            },
        )

        # TODO: implement this

        return None

    def generateWorkflowMetaFromJSONLD(
        self,
        jsonld_obj: "Mapping[str, Any]",
        public_name: "str",
        retrospective_first: "bool" = True,
    ) -> "Tuple[WritableWorkflowMetaConfigBlock, Sequence[Container]]":
        matched_crate, g = self.identifyROCrate(jsonld_obj, public_name)
        # Is it an RO-Crate?
        if matched_crate is None:
            raise ROCrateToolboxException(
                f"JSON-LD from {public_name} is not an RO-Crate"
            )

        if matched_crate.wfcrateprofile is None:
            raise ROCrateToolboxException(
                f"JSON-LD from {public_name} is not a Workflow RO-Crate"
            )

        if matched_crate.mainentity is None:
            raise ROCrateToolboxException(
                f"Unable to find the main entity workflow at {public_name} Workflow RO-Crate"
            )

        if matched_crate.wrwfprofile is None:
            raise ROCrateToolboxException(
                f"JSON-LD from {public_name} is not a WRROC Workflow"
            )

        # This query will tell us where the original workflow was located,
        # its language and version
        qlang = rdflib.plugins.sparql.prepareQuery(
            self.OBTAIN_WORKFLOW_PID_SPARQL,
            initNs=self.SPARQL_NS,
        )

        # TODO: cache resolution of contexts
        # TODO: disallow network access for context resolution
        # when not in right phase
        try:
            qlangres = g.query(
                qlang,
                initBindings={
                    "mainentity": matched_crate.mainentity,
                },
            )
        except Exception as e:
            raise ROCrateToolboxException(
                f"Unable to perform JSON-LD workflow details query over {public_name} (see cascading exceptions)"
            ) from e

        langrow: "Optional[rdflib.query.ResultRow]" = None
        # In the future, there could be more than one match, when
        # nested RO-Crate scenarios happen
        for row in qlangres:
            assert isinstance(
                row, rdflib.query.ResultRow
            ), "Check the SPARQL code, as it should be a SELECT query"
            langrow = row
            break

        if langrow is None:
            raise ROCrateToolboxException(
                f"Unable to get workflow engine details from {public_name}"
            )

        programminglanguage_url = (
            None
            if langrow.programminglanguage_url is None
            else str(langrow.programminglanguage_url)
        )
        programminglanguage_identifier = (
            None
            if langrow.programminglanguage_identifier is None
            else str(langrow.programminglanguage_identifier)
        )
        # Getting the workflow type.
        # This call will raise an exception in case the workflow type
        # is not supported by this implementation.
        workflow_type = self.wfexs.matchWorkflowType(
            programminglanguage_url, programminglanguage_identifier
        )

        # At this point we know WfExS supports the workflow engine.
        # Now it is the moment to choose whether to use one of the stored
        # executions as template (retrospective provenance)
        # or delegate on the prospective one.
        container_type: "Optional[ContainerType]" = None
        additional_container_type: "Optional[ContainerType]" = None
        the_containers: "Sequence[Container]" = []
        if retrospective_first:
            # For the retrospective provenance at least an execution must
            # be described in the RO-Crate. Once one is chosen,
            # we need to be sure the container solution used then is
            # also supported.
            # So, we are starting with the retrospective provenance
            # gathering the list of containers, to learn
            # whi.
            try:
                qexecs = rdflib.plugins.sparql.prepareQuery(
                    self.OBTAIN_RUNS_SPARQL,
                    initNs=self.SPARQL_NS,
                )
                qexecsres = g.query(
                    qexecs,
                    initBindings={
                        "rootdataset": matched_crate.rootdataset,
                        "mainentity": matched_crate.mainentity,
                    },
                )
                for execrow in qexecsres:
                    assert isinstance(
                        execrow, rdflib.query.ResultRow
                    ), "Check the SPARQL code, as it should be a SELECT query"
                    print(f"\tExecution {execrow.execution}")

                    contresult = self._parseContainersFromExecution(
                        g, execrow.execution, main_entity=matched_crate.mainentity
                    )
                    # TODO: deal with more than one execution
                    if contresult is None:
                        continue

                    container_type, the_containers = contresult

                    # TODO: which are the needed inputs, to be integrated
                    # into the latter workflow_meta?
                    self._parseInputsFromExecution(
                        g, execrow.execution, main_entity=matched_crate.mainentity
                    )

                    # Now, let's get the list of input parameters
                    break
            except Exception as e:
                raise ROCrateToolboxException(
                    f"Unable to perform JSON-LD workflow execution details query over {public_name} (see cascading exceptions)"
                ) from e

        # TODO: finish

        self.logger.info(
            f"Workflow type {workflow_type} container factory {container_type} {additional_container_type}"
        )
        workflow_meta: "WritableWorkflowMetaConfigBlock" = {
            "workflow_id": {},
            "workflow_type": workflow_type.shortname,
            "environment": {},
            "params": {},
            "outputs": {},
            "workflow_config": {},
        }
        if container_type is not None:
            workflow_meta["workflow_config"]["containerType"] = container_type.value

        self.logger.info(f"{json.dumps(workflow_meta, indent=4)}")

        return workflow_meta, the_containers
