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
import inspect
import json
import logging

from typing import (
    cast,
    TYPE_CHECKING,
)

if TYPE_CHECKING:
    from typing import (
        Any,
        Mapping,
        MutableMapping,
        Optional,
        Tuple,
    )

    from typing_extensions import (
        Final,
    )

    from ..common import (
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
        "wrterm": "https://w3id.org/ro/terms/workflow-run#",
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
        jsonld_obj_ser = {
            "@graph": pyld.jsonld.expand(jsonld_obj, {"keepFreeFloatingNodes": True})
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

    OBTAIN_RUN_CONTAINERS: "Final[str]" = """\
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

    def generateWorkflowMetaFromJSONLD(
        self,
        jsonld_obj: "Mapping[str, Any]",
        public_name: "str",
        retrospective_first: "bool" = True,
    ) -> "WritableWorkflowMetaConfigBlock":
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
        # Getting the workflow type
        workflow_type = self.wfexs.matchWorkflowType(
            programminglanguage_url, programminglanguage_identifier
        )

        # At this point we know WfExS supports the workflow engine.
        # Now it is the moment to choose whether to use one of the stored
        # executions as template (retrospective provenance)
        # or delegate on the prospective one.
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
                    qcontainers = rdflib.plugins.sparql.prepareQuery(
                        self.OBTAIN_RUN_CONTAINERS,
                        initNs=self.SPARQL_NS,
                    )
                    qcontainersres = g.query(
                        qcontainers,
                        initBindings={
                            "execution": execrow.execution,
                        },
                    )
                    for containerrow in qcontainersres:
                        assert isinstance(
                            containerrow, rdflib.query.ResultRow
                        ), "Check the SPARQL code, as it should be a SELECT query"
                        print(
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
            except Exception as e:
                raise ROCrateToolboxException(
                    f"Unable to perform JSON-LD workflow execution details query over {public_name} (see cascading exceptions)"
                ) from e

        # TODO: finish

        workflow_meta: "WritableWorkflowMetaConfigBlock" = {
            "workflow_id": {},
            "workflow_type": workflow_type.shortname,
            "environment": {},
            "params": {},
            "outputs": {},
            "workflow_config": {},
        }

        return workflow_meta
