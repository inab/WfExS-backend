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
import os.path
import sys
import zipfile

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
        Union,
    )

    from typing_extensions import (
        Final,
    )

    from ..common import (
        Fingerprint,
        RelPath,
        RepoURL,
        RepoTag,
        URIType,
    )

    from ..container_factories import (
        ContainerOperatingSystem,
        ProcessorArchitecture,
    )

    from ..wfexs_backend import (
        WfExSBackend,
    )

    from ..workflow import (
        EnvironmentBlock,
        MutableParamsBlock,
        ParamsBlock,
        MutableOutputsBlock,
        OutputsBlock,
    )

    from ..workflow_engines import (
        WorkflowType,
    )

# Needed by pyld to detect it
import aiohttp
import pyld  # type: ignore[import, import-untyped]
import rdflib
import rdflib.plugins.sparql

# This code needs exception groups
if sys.version_info[:2] < (3, 11):
    from exceptiongroup import ExceptionGroup

from ..common import (
    ContainerType,
    ContentKind,
)

from ..container_factories import (
    DEFAULT_DOCKER_REGISTRY,
    Container,
)

from .digests import (
    stringifyDigest,
)

from ..fetchers import (
    RemoteRepo,
)

from ..utils.misc import (
    lazy_import,
)

magic = lazy_import("magic")
# import magic


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

WFEXS_CONTEXT: "Final[str]" = "https://w3id.org/ro/terms/wfexs"
WFEXS_NAMESPACE: "Final[str]" = WFEXS_CONTEXT + "#"

CONTAINER_DOCKERIMAGE_SHORT: "Final[str]" = "DockerImage"
CONTAINER_SIFIMAGE_SHORT: "Final[str]" = "SIFImage"


class ContainerImageAdditionalType(enum.Enum):
    Docker = WORKFLOW_RUN_NAMESPACE + CONTAINER_DOCKERIMAGE_SHORT
    Singularity = WORKFLOW_RUN_NAMESPACE + CONTAINER_SIFIMAGE_SHORT
    # No one is available for Conda yet


# This is needed to match ill implementations
StrContainerAdditionalType2ContainerImageAdditionalType: "Final[Mapping[str, ContainerImageAdditionalType]]" = {
    ContainerImageAdditionalType.Docker.value: ContainerImageAdditionalType.Docker,
    CONTAINER_DOCKERIMAGE_SHORT: ContainerImageAdditionalType.Docker,
    ContainerImageAdditionalType.Singularity.value: ContainerImageAdditionalType.Singularity,
    CONTAINER_SIFIMAGE_SHORT: ContainerImageAdditionalType.Singularity,
}


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


ROCRATE_JSONLD_FILENAME: "Final[str]" = "ro-crate-metadata.json"
LEGACY_ROCRATE_JSONLD_FILENAME: "Final[str]" = "ro-crate-metadata.jsonld"


def ReadROCrateMetadata(workflowROCrateFilename: "str", public_name: "str") -> "Any":
    # Is it a bare file or an archive?
    jsonld_filename: "Optional[str]" = None
    if os.path.isdir(workflowROCrateFilename):
        possible_jsonld_filename = os.path.join(
            workflowROCrateFilename, ROCRATE_JSONLD_FILENAME
        )
        legacy_jsonld_filename = os.path.join(
            workflowROCrateFilename, LEGACY_ROCRATE_JSONLD_FILENAME
        )
        if os.path.exists(possible_jsonld_filename):
            jsonld_filename = possible_jsonld_filename
        elif os.path.exists(legacy_jsonld_filename):
            jsonld_filename = legacy_jsonld_filename
        else:
            raise ROCrateToolboxException(
                f"{public_name} does not contain a member {ROCRATE_JSONLD_FILENAME} or {LEGACY_ROCRATE_JSONLD_FILENAME}"
            )
    elif os.path.isfile(workflowROCrateFilename):
        jsonld_filename = workflowROCrateFilename
    else:
        raise ROCrateToolboxException(
            f"Input {public_name} is neither a file or a directory"
        )

    jsonld_bin: "Optional[bytes]" = None
    mag = magic.Magic(mime=True)
    putative_mime = mag.from_file(os.path.realpath(jsonld_filename))
    # Bare possible RO-Crate
    if putative_mime == "application/json":
        with open(jsonld_filename, mode="rb") as jdf:
            jsonld_bin = jdf.read()
    # Archived possible RO-Crate
    elif putative_mime == "application/zip":
        with zipfile.ZipFile(workflowROCrateFilename, mode="r") as zf:
            try:
                jsonld_bin = zf.read(ROCRATE_JSONLD_FILENAME)
            except Exception as e:
                try:
                    jsonld_bin = zf.read(LEGACY_ROCRATE_JSONLD_FILENAME)
                except Exception as e2:
                    raise ROCrateToolboxException(
                        f"Unable to locate RO-Crate metadata descriptor within {public_name}"
                    ) from ExceptionGroup(  # pylint: disable=possibly-used-before-assignment
                        f"Both {ROCRATE_JSONLD_FILENAME} and {LEGACY_ROCRATE_JSONLD_FILENAME} tried",
                        [e, e2],
                    )

            putative_mime_ld = mag.from_buffer(jsonld_bin)
            if putative_mime_ld != "application/json":
                raise ROCrateToolboxException(
                    f"{ROCRATE_JSONLD_FILENAME} from within {public_name} has unmanagable MIME {putative_mime_ld}"
                )
    else:
        raise ROCrateToolboxException(
            f"The RO-Crate parsing code does not know how to parse {public_name} with MIME {putative_mime}"
        )

    # Let's parse the JSON (in order to check whether it is valid)
    try:
        jsonld_obj = json.loads(jsonld_bin)
    except json.JSONDecodeError as jde:
        raise ROCrateToolboxException(
            f"Content from {public_name} is not a valid JSON"
        ) from jde

    return jsonld_obj


class ROCrateToolbox(abc.ABC):
    # This is needed due limitations from rdflib mangling relative ids
    WFEXS_TRICK_SPARQL_PRE_PREFIX: "Final[str]" = "shttp:"
    WFEXS_TRICK_SPARQL_BASE: "Final[str]" = f"{WFEXS_TRICK_SPARQL_PRE_PREFIX}///"
    WFEXS_TRICK_SPARQL_NS: "Final[str]" = "wfexs"

    SCHEMA_ORG_PREFIX: "Final[str]" = "http://schema.org/"

    SPARQL_NS = {
        "dc": "http://purl.org/dc/elements/1.1/",
        "dcterms": "http://purl.org/dc/terms/",
        "s": SCHEMA_ORG_PREFIX,
        "bs": "https://bioschemas.org/",
        "bswfprofile": "https://bioschemas.org/profiles/ComputationalWorkflow/",
        "bsworkflow": "https://bioschemas.org/ComputationalWorkflow#",
        "rocrate": "https://w3id.org/ro/crate/",
        "wfcrate": "https://w3id.org/workflowhub/workflow-ro-crate/",
        "wfhprofile": "https://about.workflowhub.eu/Workflow-RO-Crate/",
        "wrprocess": "https://w3id.org/ro/wfrun/process/",
        "wrwf": "https://w3id.org/ro/wfrun/workflow/",
        "wrterm": WORKFLOW_RUN_NAMESPACE,
        "wikidata": "https://www.wikidata.org/wiki/",
        WFEXS_TRICK_SPARQL_NS: WFEXS_TRICK_SPARQL_BASE,
    }

    LEAF_TYPE_2_ADDITIONAL_TYPE: "Final[Mapping[str, str]]" = {
        SCHEMA_ORG_PREFIX + "Integer": "Integer",
        SCHEMA_ORG_PREFIX + "Text": "Text",
        SCHEMA_ORG_PREFIX + "Boolean": "Boolean",
        SCHEMA_ORG_PREFIX + "Float": "Float",
        SCHEMA_ORG_PREFIX + "MediaObject": "File",
        SCHEMA_ORG_PREFIX + "Dataset": "Directory",
    }

    # WfExS-backend is not able to deal with collections of atomic values
    # (yet)
    LEAF_TYPE_2_OUTPUT_ADDITIONAL_TYPE: "Final[Mapping[str, str]]" = {
        SCHEMA_ORG_PREFIX + "MediaObject": "File",
        SCHEMA_ORG_PREFIX + "Dataset": "Directory",
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
SELECT  ?rocratejson ?rootdataset ?rocrateprofile ?wfcrateprofile ?wfhrepourl ?mainentity ?bsworkflowprofile ?wrprocessprofile ?wrwfprofile
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
                STRSTARTS(str(?bsworkflowprofile), str(bswfprofile:))
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
        OPTIONAL {
            ?rootdataset s:isBasedOn ?wfhrepourl
        }
    }
}
"""

    GET_LICENCES_SPARQL: "Final[str]" = """\
SELECT  ?license
WHERE {
    ?entity s:license ?license .
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
                    "ignore", category=SyntaxWarning, module=r"^pyld\.jsonld$"
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
SELECT  ?identifier ?workflow_repository ?workflow_version ?workflow_url ?workflow_alternate_name ?programminglanguage_identifier ?programminglanguage_url ?programminglanguage_version
WHERE   {
    ?mainentity s:programmingLanguage ?programminglanguage .
    ?programminglanguage
        a s:ComputerLanguage ;
        s:url ?programminglanguage_url .
    OPTIONAL {
        ?programminglanguage
            s:version ?programminglanguage_version .
    }
    OPTIONAL {
        ?programminglanguage
            s:identifier ?programminglanguage_identifier .
    }
    {
        {
            FILTER NOT EXISTS {
                ?mainentity s:isBasedOn ?origmainentity .
                ?origmainentity
                    a bs:ComputationalWorkflow ;
                    dcterms:conformsTo ?bsworkflowprofile .
                FILTER (
                    STRSTARTS(str(?bsworkflowprofile), str(bswfprofile:))
                ) .
            }
            OPTIONAL {
                ?mainentity s:codeRepository ?workflow_repository .
            }
            OPTIONAL {
                ?mainentity s:version ?workflow_version .
            }
            OPTIONAL {
                ?mainentity s:url ?workflow_url .
            }
            OPTIONAL {
                ?mainentity s:identifier ?identifier .
            }
            OPTIONAL {
                ?mainentity s:alternateName ?workflow_alternate_name .
            }
        } UNION {
            ?mainentity s:isBasedOn ?origmainentity .
            ?origmainentity
                a bs:ComputationalWorkflow ;
                dcterms:conformsTo ?bsworkflowprofile .
            OPTIONAL {
                ?origmainentity s:codeRepository ?workflow_repository .
            }
            OPTIONAL {
                ?origmainentity s:version ?workflow_version .
            }
            OPTIONAL {
                ?origmainentity s:url ?workflow_url .
            }
            FILTER (
                STRSTARTS(str(?bsworkflowprofile), str(bswfprofile:))
            ) .
            OPTIONAL {
                ?origmainentity s:identifier ?identifier .
            }
            OPTIONAL {
                ?origmainentity s:alternateName ?workflow_alternate_name .
            }
        }
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
    {
        ?execution wrterm:containerImage ?container .
    } UNION {
        ?entity s:softwareAddOn ?container.
    }
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
    # is evaluated separately
    OBTAIN_WORKFLOW_INPUTS_SPARQL: "Final[str]" = """\
SELECT  ?input ?name ?inputfp ?additional_type ?fileuri ?value ?component ?leaf_type
WHERE   {
    ?main_entity bsworkflow:input ?inputfp .
    ?inputfp
        a bs:FormalParameter ;
        s:name ?name ;
        s:additionalType ?additional_type ;
        s:workExample ?input .
    {
        # A file, which is a schema.org MediaObject
        ?input
            a s:MediaObject ;
            s:contentUrl ?fileuri .
    } UNION {
        # A directory, which is a schema.org Dataset
        ?input
            a s:Dataset ;
            s:contentUrl ?fileuri .
        FILTER EXISTS { 
            # subquery to determine it is not an empty Dataset
            SELECT ?dircomp
            WHERE { 
                ?input
                    s:hasPart+ ?dircomp .
                ?dircomp
                    a s:MediaObject .
            }
        }
    } UNION {
        # A single property value, which can be either Integer, Text, Boolean or Float
        ?input
            a s:PropertyValue ;
            s:value ?value .
    } UNION {
        # A combination of files or directories or property values
        VALUES ( ?leaf_type ) { ( s:Integer ) ( s:Text ) ( s:Boolean ) ( s:Float ) ( s:MediaObject ) ( s:Dataset ) }
        ?input
            a s:Collection ;
            s:hasPart+ ?component .
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

    # This compound query is much faster when each of the UNION components
    # is evaluated separately
    OBTAIN_WORKFLOW_ENV_SPARQL: "Final[str]" = """\
SELECT  ?env ?name ?name_env ?envfp ?additional_type ?fileuri ?value ?component ?leaf_type
WHERE   {
    ?main_entity wrterm:environment ?envfp .
    ?envfp
        a bs:FormalParameter ;
        s:name ?name ;
        s:additionalType ?additional_type ;
        s:workExample ?env .
    {
        # A file, which is a schema.org MediaObject
        ?env
            a s:MediaObject ;
            s:name ?name_env ;
            s:contentUrl ?fileuri .
    } UNION {
        # A directory, which is a schema.org Dataset
        ?env
            a s:Dataset ;
            s:name ?name_env ;
            s:contentUrl ?fileuri .
        FILTER EXISTS { 
            # subquery to determine it is not an empty Dataset
            SELECT ?dircomp
            WHERE { 
                ?env
                    s:hasPart+ ?dircomp .
                ?dircomp
                    a s:MediaObject .
            }
        }
    } UNION {
        # A single property value, which can be either Integer, Text, Boolean or Float
        ?env
            a s:PropertyValue ;
            s:name ?name_env ;
            s:value ?value .
    } UNION {
        # A combination of files or directories or property values
        VALUES ( ?leaf_type ) { ( s:Integer ) ( s:Text ) ( s:Boolean ) ( s:Float ) ( s:MediaObject ) ( s:Dataset ) }
        ?env
            a s:Collection ;
            s:name ?name_env ;
            s:hasPart+ ?component .
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

    # This compound query is much faster when each of the UNION components
    # is evaluated separately
    OBTAIN_WORKFLOW_OUTPUTS_SPARQL: "Final[str]" = """\
SELECT  ?name ?outputfp ?additional_type ?default_value
WHERE   {
    ?main_entity bsworkflow:output ?outputfp .
    ?outputfp
        a bs:FormalParameter ;
        s:name ?name ;
        s:additionalType ?additional_type .
    OPTIONAL {
        ?ouputfp
            s:defaultValue ?default_value .
    }
}
"""

    # This compound query is much faster when each of the UNION components
    # is evaluated separately
    OBTAIN_EXECUTION_INPUTS_SPARQL: "Final[str]" = """\
SELECT  ?input ?name ?inputfp ?additional_type ?fileuri ?value ?component ?leaf_type
WHERE   {
    ?execution s:object ?input .
    {
        # A file, which is a schema.org MediaObject
        BIND ( "File" AS ?additional_type )
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
        BIND ( "Dataset" AS ?additional_type )
        ?input
            a s:Dataset ;
            s:contentUrl ?fileuri ;
            s:exampleOfWork ?inputfp .
        ?inputfp
            a bs:FormalParameter ;
            s:name ?name ;
            s:additionalType ?additional_type .
        FILTER EXISTS { 
            # subquery to determine it is not an empty Dataset
            SELECT ?dircomp
            WHERE { 
                ?input
                    s:hasPart+ ?dircomp .
                ?dircomp
                    a s:MediaObject .
            }
        }
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
        BIND ( "Collection" AS ?additional_type )
        VALUES ( ?leaf_type ) { ( s:Integer ) ( s:Text ) ( s:Boolean ) ( s:Float ) ( s:MediaObject ) ( s:Dataset ) }
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

    # This compound query is much faster when each of the UNION components
    # is evaluated separately
    OBTAIN_EXECUTION_ENV_SPARQL: "Final[str]" = """\
SELECT  ?env ?name ?name_env ?envfp ?additional_type ?fileuri ?value ?component ?leaf_type
WHERE   {
    ?execution wrterm:environment ?env .
    {
        # A file, which is a schema.org MediaObject
        BIND ( "File" AS ?additional_type )
        ?env
            a s:MediaObject ;
            s:name ?name_env ;
            s:contentUrl ?fileuri ;
            s:exampleOfWork ?envfp .
        ?envfp
            a bs:FormalParameter ;
            s:name ?name ;
            s:additionalType ?additional_type .
    } UNION {
        # A directory, which is a schema.org Dataset
        BIND ( "Dataset" AS ?additional_type )
        ?env
            a s:Dataset ;
            s:name ?name_env ;
            s:contentUrl ?fileuri ;
            s:exampleOfWork ?envfp .
        ?envfp
            a bs:FormalParameter ;
            s:name ?name ;
            s:additionalType ?additional_type .
        FILTER EXISTS { 
            # subquery to determine it is not an empty Dataset
            SELECT ?dircomp
            WHERE { 
                ?input
                    s:hasPart+ ?dircomp .
                ?dircomp
                    a s:MediaObject .
            }
        }
    } UNION {
        # A single property value, which can be either Integer, Text, Boolean or Float
        VALUES (?additional_type) { ( "Integer" ) ( "Text" ) ( "Boolean" ) ( "Float" ) }
        ?env
            a s:PropertyValue ;
            s:name ?name_env ;
            s:exampleOfWork ?envfp ;
            s:value ?value .
        ?envfp
            a bs:FormalParameter ;
            s:name ?name ;
            s:additionalType ?additional_type .
    } UNION {
        # A combination of files or directories or property values
        BIND ( "Collection" AS ?additional_type )
        VALUES ( ?leaf_type ) { ( s:Integer ) ( s:Text ) ( s:Boolean ) ( s:Float ) ( s:MediaObject ) ( s:Dataset ) }
        ?env
            a s:Collection ;
            s:name ?name_env ;
            s:exampleOfWork ?envfp ;
            s:hasPart+ ?component .
        ?envfp
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

    # This compound query is much faster when each of the UNION components
    # is evaluated separately
    OBTAIN_EXECUTION_OUTPUTS_SPARQL: "Final[str]" = """\
SELECT  ?output ?name ?alternate_name ?outputfp ?default_value ?additional_type ?fileuri ?value ?component ?leaf_type
WHERE   {
    ?execution s:result ?output .
    {
        # A file, which is a schema.org MediaObject
        BIND ( "File" AS ?additional_type )
        ?output
            a s:MediaObject ;
            s:exampleOfWork ?outputfp .
        ?outputfp
            a bs:FormalParameter ;
            s:name ?name ;
            s:additionalType ?additional_type .
        OPTIONAL {
            ?output
                s:contentUrl ?fileuri .
        }
    } UNION {
        # A directory, which is a schema.org Dataset
        BIND ( "Dataset" AS ?additional_type )
        ?output
            a s:Dataset ;
            s:exampleOfWork ?outputfp .
        ?outputfp
            a bs:FormalParameter ;
            s:name ?name ;
            s:additionalType ?additional_type .
        FILTER EXISTS { 
            # subquery to determine it is not an empty Dataset
            SELECT ?dircomp
            WHERE { 
                ?output
                    s:hasPart+ ?dircomp .
                ?dircomp
                    a s:MediaObject .
            }
        }
        OPTIONAL {
            ?output
                s:contentUrl ?fileuri .
        }
    } UNION {
        # A single property value, which can be either Integer, Text, Boolean or Float
        VALUES (?additional_type) { ( "Integer" ) ( "Text" ) ( "Boolean" ) ( "Float" ) }
        ?output
            a s:PropertyValue ;
            s:exampleOfWork ?outputfp ;
            s:value ?value .
        ?outputfp
            a bs:FormalParameter ;
            s:name ?name ;
            s:additionalType ?additional_type .
    } UNION {
        # A combination of files or directories or property values
        BIND ( "Collection" AS ?additional_type )
        VALUES ( ?leaf_type ) { ( s:Integer ) ( s:Text ) ( s:Boolean ) ( s:Float ) ( s:MediaObject ) ( s:Dataset ) }
        ?output
            a s:Collection ;
            s:exampleOfWork ?outputfp ;
            s:hasPart+ ?component .
        ?outputfp
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
    OPTIONAL {
        ?ouputfp
            s:defaultValue ?default_value .
    }
    OPTIONAL {
        ?output
            s:alternateName ?alternate_name .
    }
}
"""

    def _parseContainersFromWorkflow(
        self,
        g: "rdflib.graph.Graph",
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
                "execution": rdflib.term.Literal(None),
                "entity": main_entity,
            },
        )

        return self.__parseContainersResults(qcontainersres, main_entity)

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
                "entity": rdflib.term.Literal(None),
            },
        )

        return self.__parseContainersResults(qcontainersres, main_entity)

    def __parseContainersResults(
        self,
        qcontainersres: "rdflib.query.Result",
        main_entity: "rdflib.term.Identifier",
    ) -> "Optional[Tuple[ContainerType, Sequence[Container]]]":
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
                    putative_additional_container_image_additional_type = (
                        StrContainerAdditionalType2ContainerImageAdditionalType.get(
                            str(containerrow.container_additional_type)
                        )
                    )
                    putative_additional_container_type = (
                        None
                        if putative_additional_container_image_additional_type is None
                        else (
                            AdditionalType2ContainerType.get(
                                putative_additional_container_image_additional_type
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
                    putative_additional_container_image_additional_type = (
                        StrContainerAdditionalType2ContainerImageAdditionalType.get(
                            str(containerrow.container_additional_type)
                        )
                    )
                    putative_additional_container_type = (
                        None
                        if putative_additional_container_image_additional_type is None
                        else (
                            AdditionalType2ContainerType.get(
                                putative_additional_container_image_additional_type
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
                        assert containerrow.container_tag is not None
                        if containerrow.container_sha256 is not None:
                            fingerprint = f"{the_registry}/{container_identifier}@sha256:{str(containerrow.container_sha256)}"
                        else:
                            fingerprint = f"{the_registry}/{container_identifier}:{str(containerrow.container_tag)}"
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

    def _parseOutputsFromExecution(
        self,
        g: "rdflib.graph.Graph",
        execution: "rdflib.term.Identifier",
        main_entity: "rdflib.term.Identifier",
        public_name: "str",
    ) -> "OutputsBlock":
        # Get the list of outputs
        qoutputs = rdflib.plugins.sparql.prepareQuery(
            self.OBTAIN_EXECUTION_OUTPUTS_SPARQL,
            initNs=self.SPARQL_NS,
        )
        qoutputsres = g.query(
            qoutputs,
            initBindings={
                "execution": execution,
            },
        )

        return self.__parseOutputsResults(qoutputsres, g, public_name)

    def _parseOutputsFromMainEntity(
        self,
        g: "rdflib.graph.Graph",
        main_entity: "rdflib.term.Identifier",
        public_name: "str",
    ) -> "OutputsBlock":
        # Get the list of outputs
        qwoutputs = rdflib.plugins.sparql.prepareQuery(
            self.OBTAIN_WORKFLOW_OUTPUTS_SPARQL,
            initNs=self.SPARQL_NS,
        )
        qwoutputsres = g.query(
            qwoutputs,
            initBindings={
                "main_entity": main_entity,
            },
        )

        return self.__parseOutputsResults(qwoutputsres, g, public_name)

    def __parseOutputsResults(
        self,
        qoutputsres: "rdflib.query.Result",
        g: "rdflib.graph.Graph",
        public_name: "str",
    ) -> "OutputsBlock":
        # TODO: implement this
        outputs: "MutableOutputsBlock" = {}
        for outputrow in qoutputsres:
            assert isinstance(
                outputrow, rdflib.query.ResultRow
            ), "Check the SPARQL code, as it should be a SELECT query"

            base = outputs
            output_path = str(outputrow.name).split(".")
            output_last = output_path[-1]

            # Reaching the relative position
            if len(output_path) > 1:
                for output_step in output_path[0:-1]:
                    base = base.setdefault(output_step, {})

            # Now, fill in the values
            additional_type = str(outputrow.additional_type)
            # Is it a nested one?
            cardinality = "1"
            if additional_type == "Collection":
                if not hasattr(outputrow, "leaf_type"):
                    raise ROCrateToolboxException(
                        f"Unable to handle Collections of unknown type in output {str(outputrow.name)}"
                    )

                cardinality = "+"
                leaf_output_type = str(outputrow.leaf_type)
                leaf_output_additional_type = (
                    self.LEAF_TYPE_2_OUTPUT_ADDITIONAL_TYPE.get(leaf_output_type)
                )
                if leaf_output_additional_type is None:
                    raise ROCrateToolboxException(
                        f"Unable to handle contents of type {leaf_output_type} in output Collection {str(outputrow.name)}"
                    )
                additional_type = leaf_output_additional_type

            # Is it a file or a directory?
            if additional_type not in ("File", "Dataset"):
                raise ROCrateToolboxException(
                    f"Unable to handle contents of additional type {additional_type} in output Collection {str(outputrow.name)}"
                )

            preferred_name: "Optional[str]" = (
                None
                if outputrow.default_value is None
                else str(outputrow.default_value)
            )
            if hasattr(outputrow, "alternate_name"):
                preferred_name = str(outputrow.alternate_name)

            valobj: "MutableMapping[str, Any]" = base.setdefault(
                output_last,
                {
                    "c-l-a-s-s": ContentKind.Directory.name
                    if additional_type == "Dataset"
                    else ContentKind.File.name,
                    "cardinality": cardinality,
                },
            )

            if preferred_name is not None:
                valobj["preferredName"] = preferred_name

        return outputs

    def _parseInputsFromExecution(
        self,
        g: "rdflib.graph.Graph",
        execution: "rdflib.term.Identifier",
        main_entity: "rdflib.term.Identifier",
        default_licences: "Sequence[str]",
        public_name: "str",
    ) -> "ParamsBlock":
        # Get the list of inputs
        qinputs = rdflib.plugins.sparql.prepareQuery(
            self.OBTAIN_EXECUTION_INPUTS_SPARQL,
            initNs=self.SPARQL_NS,
        )
        qinputsres = g.query(
            qinputs,
            initBindings={
                "execution": execution,
            },
        )

        return self.__parseInputsResults(qinputsres, g, default_licences, public_name)

    def _parseInputsFromMainEntity(
        self,
        g: "rdflib.graph.Graph",
        main_entity: "rdflib.term.Identifier",
        default_licences: "Sequence[str]",
        public_name: "str",
    ) -> "ParamsBlock":
        # Get the list of inputs
        qwinputs = rdflib.plugins.sparql.prepareQuery(
            self.OBTAIN_WORKFLOW_INPUTS_SPARQL,
            initNs=self.SPARQL_NS,
        )
        qwinputsres = g.query(
            qwinputs,
            initBindings={
                "main_entity": main_entity,
            },
        )

        return self.__parseInputsResults(qwinputsres, g, default_licences, public_name)

    def __parseInputsResults(
        self,
        qinputsres: "rdflib.query.Result",
        g: "rdflib.graph.Graph",
        default_licences: "Sequence[str]",
        public_name: "str",
    ) -> "ParamsBlock":
        # TODO: implement this
        params: "MutableParamsBlock" = {}
        for inputrow in qinputsres:
            assert isinstance(
                inputrow, rdflib.query.ResultRow
            ), "Check the SPARQL code, as it should be a SELECT query"

            base = params
            param_path = str(inputrow.name).split(".")
            param_last = param_path[-1]

            # Reaching the relative position
            if len(param_path) > 1:
                for param_step in param_path[0:-1]:
                    base = base.setdefault(param_step, {})

            # Now, fill in the values
            additional_type = str(inputrow.additional_type)
            valarr: "Optional[MutableSequence[Any]]" = None
            valobj: "Optional[MutableMapping[str, Any]]" = None
            # Is it a nested one?
            if additional_type == "Collection":
                leaf_type = str(inputrow.leaf_type)
                leaf_additional_type = self.LEAF_TYPE_2_ADDITIONAL_TYPE.get(leaf_type)
                if leaf_additional_type is None:
                    raise ROCrateToolboxException(
                        f"Unable to handle contents of type {leaf_type} in input Collection {str(inputrow.name)}"
                    )
                additional_type = leaf_additional_type
                if leaf_additional_type not in ("File", "Dataset"):
                    valarr = base.setdefault(param_last, [])

            # Is it a file or a directory?
            if additional_type in ("File", "Dataset"):
                valobj = base.setdefault(
                    param_last,
                    {
                        "c-l-a-s-s": ContentKind.Directory.name
                        if additional_type == "Dataset"
                        else ContentKind.File.name,
                    },
                )

            if isinstance(valobj, dict):
                licences = self._getLicences(g, inputrow.input, public_name)
                if len(licences) == 0:
                    licences = default_licences
                the_url: "Union[str, Mapping[str, Any]]"
                if len(licences) == 0:
                    the_url = str(inputrow.fileuri)
                else:
                    the_url = {
                        "uri": str(inputrow.fileuri),
                        "licences": licences,
                    }

                valurl = valobj.get("url")
                if isinstance(valurl, (str, dict)):
                    valurl = [valurl]
                    valobj["url"] = valurl

                if isinstance(valurl, list):
                    valurl.append(the_url)
                else:
                    valobj["url"] = the_url
            else:
                the_value_node: "rdflib.term.Identifier" = inputrow.value
                the_value: "Union[str, int, float, bool]"
                if isinstance(the_value_node, rdflib.term.Literal):
                    the_value = the_value_node.value
                else:
                    the_value = str(the_value_node)

                if additional_type == "Integer":
                    try:
                        the_value = int(the_value)
                    except:
                        self.logger.exception(
                            f"Expected type {additional_type} for value {the_value}"
                        )
                elif additional_type == "Boolean":
                    the_value = bool(the_value)
                elif additional_type == "Float":
                    the_value = float(the_value)
                elif additional_type == "Text":
                    the_value = str(the_value)
                else:
                    raise ROCrateToolboxException(
                        f"Unable to handle additional type {additional_type} for input {str(inputrow.name)}"
                    )

                if isinstance(valarr, list):
                    valarr.append(the_value)
                else:
                    base[param_last] = the_value

        return params

    def _parseEnvFromExecution(
        self,
        g: "rdflib.graph.Graph",
        execution: "rdflib.term.Identifier",
        main_entity: "rdflib.term.Identifier",
        default_licences: "Sequence[str]",
        public_name: "str",
    ) -> "EnvironmentBlock":
        # Get the list of inputs
        qenv = rdflib.plugins.sparql.prepareQuery(
            self.OBTAIN_EXECUTION_ENV_SPARQL,
            initNs=self.SPARQL_NS,
        )
        qenvres = g.query(
            qenv,
            initBindings={
                "execution": execution,
            },
        )

        return self.__parseEnvResults(qenvres, g, default_licences, public_name)

    def _parseEnvFromMainEntity(
        self,
        g: "rdflib.graph.Graph",
        main_entity: "rdflib.term.Identifier",
        default_licences: "Sequence[str]",
        public_name: "str",
    ) -> "EnvironmentBlock":
        # Get the list of inputs
        qwenv = rdflib.plugins.sparql.prepareQuery(
            self.OBTAIN_WORKFLOW_ENV_SPARQL,
            initNs=self.SPARQL_NS,
        )
        qwenvres = g.query(
            qwenv,
            initBindings={
                "main_entity": main_entity,
            },
        )

        return self.__parseEnvResults(qwenvres, g, default_licences, public_name)

    def __parseEnvResults(
        self,
        qenvres: "rdflib.query.Result",
        g: "rdflib.graph.Graph",
        default_licences: "Sequence[str]",
        public_name: "str",
    ) -> "EnvironmentBlock":
        """
        This method is (almost) identical to __parseInputsResults
        """
        # TODO: implement this
        environment: "MutableMapping[str, Any]" = {}
        for envrow in qenvres:
            assert isinstance(
                envrow, rdflib.query.ResultRow
            ), "Check the SPARQL code, as it should be a SELECT query"

            env_name = str(envrow.name)

            # Now, fill in the values
            additional_type = str(envrow.additional_type)
            valarr: "Optional[MutableSequence[Any]]" = None
            valobj: "Optional[MutableMapping[str, Any]]" = None
            # Is it a nested one?
            if additional_type == "Collection":
                leaf_type = str(envrow.leaf_type)
                leaf_additional_type = self.LEAF_TYPE_2_ADDITIONAL_TYPE.get(leaf_type)
                if leaf_additional_type is None:
                    raise ROCrateToolboxException(
                        f"Unable to handle contents of type {leaf_type} in Collection reflecting contents pointed by environment variable {env_name}"
                    )
                additional_type = leaf_additional_type
                if leaf_additional_type not in ("File", "Dataset"):
                    valarr = environment.setdefault(env_name, [])

            # Is it a file or a directory?
            if additional_type in ("File", "Dataset"):
                valobj = environment.setdefault(
                    env_name,
                    {
                        "c-l-a-s-s": ContentKind.Directory.name
                        if additional_type == "Dataset"
                        else ContentKind.File.name,
                    },
                )

            if isinstance(valobj, dict):
                licences = self._getLicences(g, envrow.env, public_name)
                if len(licences) == 0:
                    licences = default_licences
                the_url: "Union[str, Mapping[str, Any]]"
                if len(licences) == 0:
                    the_url = str(envrow.fileuri)
                else:
                    the_url = {
                        "uri": str(envrow.fileuri),
                        "licences": licences,
                    }

                valurl = valobj.get("url")
                if isinstance(valurl, (str, dict)):
                    valurl = [valurl]
                    valobj["url"] = valurl

                if isinstance(valurl, list):
                    valurl.append(the_url)
                else:
                    valobj["url"] = the_url
            else:
                the_value_node: "rdflib.term.Identifier" = envrow.value
                the_value: "Union[str, int, float, bool]"
                if isinstance(the_value_node, rdflib.term.Literal):
                    the_value = the_value_node.value
                else:
                    the_value = str(the_value_node)

                if additional_type == "Integer":
                    try:
                        the_value = int(the_value)
                    except:
                        self.logger.exception(
                            f"Expected type {additional_type} for value {the_value} in environment variable {env_name}"
                        )
                elif additional_type == "Boolean":
                    the_value = bool(the_value)
                elif additional_type == "Float":
                    the_value = float(the_value)
                elif additional_type == "Text":
                    the_value = str(the_value)
                else:
                    raise ROCrateToolboxException(
                        f"Unable to handle additional type {additional_type} for environment variable {env_name}"
                    )

                if isinstance(valarr, list):
                    valarr.append(the_value)
                else:
                    environment[env_name] = the_value

        return environment

    def _getLicences(
        self,
        g: "rdflib.graph.Graph",
        entity: "rdflib.term.Identifier",
        public_name: "str",
    ) -> "Sequence[str]":
        # This query will return the list of licences associated to the
        # input entity
        qlic = rdflib.plugins.sparql.prepareQuery(
            self.GET_LICENCES_SPARQL,
            initNs=self.SPARQL_NS,
        )
        # TODO: cache resolution of contexts
        # TODO: disallow network access for context resolution
        # when not in right phase
        try:
            qlicres = g.query(
                qlic,
                initBindings={
                    "entity": entity,
                },
            )
        except Exception as e:
            raise ROCrateToolboxException(
                f"Unable to perform JSON-LD workflow details query over {public_name} (see cascading exceptions)"
            ) from e

        licences: "MutableSequence[str]" = []
        for licrow in qlicres:
            assert isinstance(
                licrow, rdflib.query.ResultRow
            ), "Check the SPARQL code, as it should be a SELECT query"
            licences.append(str(licrow.license))

        return licences

    def extractWorkflowMetadata(
        self,
        g: "rdflib.graph.Graph",
        main_entity: "rdflib.term.Identifier",
        default_repo: "Optional[str]",
        public_name: "str",
    ) -> "Tuple[RemoteRepo, WorkflowType]":
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
                    "mainentity": main_entity,
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
                f"Unable to get workflow PID and engine details from {public_name}"
            )

        # Creating the workflow permanent identifier
        repo_pid: "str"
        if langrow.workflow_repository is not None:
            repo_pid = str(langrow.workflow_repository)

        elif langrow.identifier is not None:
            repo_pid = str(langrow.identifier)
        elif langrow.workflow_url is not None:
            repo_pid = str(langrow.workflow_url)
        else:
            raise ROCrateToolboxException(
                f"Unable to infer the permanent identifier from the workflow at {public_name}"
            )

        # The RO-Crate was produced by RO-Crate
        if ("workflowhub.eu" in repo_pid) and default_repo is not None:
            repo_pid = default_repo

        repo_version: "Optional[str]" = None
        if langrow.workflow_version:
            repo_version = str(langrow.workflow_version)

        repo_relpath: "Optional[str]" = None
        if langrow.workflow_alternate_name is not None:
            repo_relpath = str(langrow.workflow_alternate_name)

        repo_web_url: "Optional[str]" = None
        if langrow.workflow_url is not None:
            repo_web_url = str(langrow.workflow_url)

        repo = RemoteRepo(
            repo_url=cast("RepoURL", repo_pid),
            tag=cast("Optional[RepoTag]", repo_version),
            rel_path=cast("Optional[RelPath]", repo_relpath),
            web_url=cast("Optional[URIType]", repo_web_url),
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

        return repo, workflow_type

    def generateWorkflowMetaFromJSONLD(
        self,
        jsonld_obj: "Mapping[str, Any]",
        public_name: "str",
        retrospective_first: "bool" = True,
    ) -> "Tuple[RemoteRepo, WorkflowType, ContainerType, Sequence[Container], ParamsBlock, EnvironmentBlock, OutputsBlock]":
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

        # The default crate licences
        crate_licences = self._getLicences(g, matched_crate.mainentity, public_name)

        repo, workflow_type = self.extractWorkflowMetadata(
            g,
            matched_crate.mainentity,
            default_repo=str(matched_crate.wfhrepourl),
            public_name=public_name,
        )

        # At this point we know WfExS supports the workflow engine.
        # Now it is the moment to choose whether to use one of the stored
        # executions as template (retrospective provenance)
        # or delegate on the prospective one.
        container_type: "Optional[ContainerType]" = None
        additional_container_type: "Optional[ContainerType]" = None
        the_containers: "Sequence[Container]" = []
        params: "ParamsBlock" = {}
        environment: "EnvironmentBlock" = {}
        outputs: "OutputsBlock" = {}
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
                    self.logger.debug(f"\tExecution {execrow.execution}")

                    contresult = self._parseContainersFromExecution(
                        g, execrow.execution, main_entity=matched_crate.mainentity
                    )
                    # TODO: deal with more than one execution
                    if contresult is None:
                        continue

                    container_type, the_containers = contresult

                    # TODO: which are the needed inputs, to be integrated
                    # into the latter workflow_meta?
                    params = self._parseInputsFromExecution(
                        g,
                        execrow.execution,
                        main_entity=matched_crate.mainentity,
                        default_licences=crate_licences,
                        public_name=public_name,
                    )

                    environment = self._parseEnvFromExecution(
                        g,
                        execrow.execution,
                        main_entity=matched_crate.mainentity,
                        default_licences=crate_licences,
                        public_name=public_name,
                    )

                    outputs = self._parseOutputsFromExecution(
                        g,
                        execrow.execution,
                        main_entity=matched_crate.mainentity,
                        public_name=public_name,
                    )

                    # Now, let's get the list of input parameters
                    break
            except Exception as e:
                raise ROCrateToolboxException(
                    f"Unable to perform JSON-LD workflow execution details query over {public_name} (see cascading exceptions)"
                ) from e

        # Following the prospective path
        if len(params) == 0:
            contresult = self._parseContainersFromWorkflow(
                g,
                main_entity=matched_crate.mainentity,
            )
            # TODO: deal with more than one execution
            if contresult is not None:
                container_type, the_containers = contresult

            params = self._parseInputsFromMainEntity(
                g,
                main_entity=matched_crate.mainentity,
                default_licences=crate_licences,
                public_name=public_name,
            )

            environment = self._parseEnvFromMainEntity(
                g,
                main_entity=matched_crate.mainentity,
                default_licences=crate_licences,
                public_name=public_name,
            )

        if len(outputs) == 0:
            outputs = self._parseOutputsFromMainEntity(
                g,
                main_entity=matched_crate.mainentity,
                public_name=public_name,
            )

        # TODO: finish
        assert container_type is not None

        return (
            repo,
            workflow_type,
            container_type,
            the_containers,
            params,
            environment,
            outputs,
        )
