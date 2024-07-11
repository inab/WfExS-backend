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
import pathlib
import sys
import urllib.parse
import zipfile

# Older versions of Python do not have zipfile.Path
# and newer do not inherit from pathlib.Path
from .zipfile_path import ZipfilePath

from typing import (
    cast,
    NamedTuple,
    TYPE_CHECKING,
)

import warnings

if TYPE_CHECKING:
    from typing import (
        Any,
        IO,
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
        TypeAlias,
    )

    from ..common import (
        AbsPath,
        EngineVersion,
        Fingerprint,
        PathlibLike,
        RelPath,
        RepoURL,
        RepoTag,
        SymbolicParamName,
        URIType,
        URIWithMetadata,
        WFLangVersion,
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
        Sch_Output,
    )

    from ..workflow_engines import (
        WorkflowType,
    )

# Needed by pyld to detect it
import pyld  # type: ignore[import, import-untyped]
import rdflib
import rdflib.plugins.sparql

# This code needs exception groups
if sys.version_info[:2] < (3, 11):
    from exceptiongroup import ExceptionGroup

from ..common import (
    ContainerType,
    ContentKind,
    DefaultNoLicenceTuple,
    LicensedURI,
    LocalWorkflow,
    MaterializedContent,
    MaterializedInput,
    NoLicenceDescription,
)

from ..container_factories import (
    DEFAULT_DOCKER_REGISTRY,
    Container,
)

from .digests import (
    ComputeDigestFromFileLike,
    stringifyDigest,
)

from .pyld_caching import (
    pyld_cache_initialize,
)

from ..fetchers import (
    RemoteRepo,
)

from .misc import (
    is_uri,
    lazy_import,
)

magic = lazy_import("magic")
# import magic


class ReproducibilityLevel(enum.IntEnum):
    Minimal = enum.auto()  # Minimal / no reproducibility is requested
    Metadata = enum.auto()  # Metadata reproducibility is requested
    Full = enum.auto()  # Full reproducibility (metadata + payload) is required")


class ContainerTypeMetadata(NamedTuple):
    sa_id: "str"
    applicationCategory: "str"
    ct_applicationCategory: "str"


class ROCratePayload(NamedTuple):
    rel_path: "str"
    path: "pathlib.Path"
    signature: "Optional[Fingerprint]"


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

WORKFLOW_RUN_BASE: "Final[str]" = "https://w3id.org/ro/terms/workflow-run"
WORKFLOW_RUN_CONTEXT: "Final[str]" = WORKFLOW_RUN_BASE + "/context"
WORKFLOW_RUN_NAMESPACE: "Final[str]" = WORKFLOW_RUN_BASE + "#"

WFEXS_TERMS_BASE: "Final[str]" = "https://w3id.org/ro/terms/wfexs"
# Not yet ....
# WFEXS_TERMS_CONTEXT: "Final[str]" = WFEXS_TERMS_BASE + "/context"
WFEXS_TERMS_CONTEXT: "Final[str]" = WFEXS_TERMS_BASE
WFEXS_TERMS_NAMESPACE: "Final[str]" = WFEXS_TERMS_BASE + "#"

CONTAINER_DOCKERIMAGE_SHORT: "Final[str]" = "DockerImage"
CONTAINER_SIFIMAGE_SHORT: "Final[str]" = "SIFImage"


ContentWithURIsMIMEs = {
    "tabular": "text/csv",
}


RevContentWithURIsMIMEs = dict((v, k) for k, v in ContentWithURIsMIMEs.items())


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


def ReadROCrateMetadata(
    workflowROCrateFilename: "pathlib.Path", public_name: "str"
) -> "Tuple[Any, Optional[pathlib.Path]]":
    # Is it a bare file or an archive?
    jsonld_filename: "Optional[pathlib.Path]" = None
    payload_dir: "Optional[pathlib.Path]" = None
    if workflowROCrateFilename.is_dir():
        possible_jsonld_filename = workflowROCrateFilename / ROCRATE_JSONLD_FILENAME
        legacy_jsonld_filename = (
            workflowROCrateFilename / LEGACY_ROCRATE_JSONLD_FILENAME
        )
        if possible_jsonld_filename.exists():
            jsonld_filename = possible_jsonld_filename
        elif legacy_jsonld_filename.exists():
            jsonld_filename = legacy_jsonld_filename
        else:
            raise ROCrateToolboxException(
                f"{public_name} does not contain a member {ROCRATE_JSONLD_FILENAME} or {LEGACY_ROCRATE_JSONLD_FILENAME}"
            )
        payload_dir = workflowROCrateFilename
    elif workflowROCrateFilename.is_file():
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
        with jsonld_filename.open(mode="rb") as jdf:
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
        payload_dir = ZipfilePath(workflowROCrateFilename)
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

    return jsonld_obj, payload_dir


class ROCrateToolbox(abc.ABC):
    # This is needed due limitations from rdflib mangling relative ids
    RELATIVE_ROCRATE_SCHEME: "Final[str]" = "rel-crate"
    RELATIVE_ROCRATE_SPARQL_BASE: "Final[str]" = RELATIVE_ROCRATE_SCHEME + ":"
    RELATIVE_ROCRATE_NS: "Final[str]" = "crate"

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
        "wfexsterm": WFEXS_TERMS_NAMESPACE,
        "wikidata": "https://www.wikidata.org/wiki/",
        RELATIVE_ROCRATE_NS: RELATIVE_ROCRATE_SPARQL_BASE,
    }

    LEAF_TYPE_2_ADDITIONAL_TYPE: "Final[Mapping[str, str]]" = {
        SCHEMA_ORG_PREFIX + "Integer": "Integer",
        SCHEMA_ORG_PREFIX + "Text": "Text",
        SCHEMA_ORG_PREFIX + "Boolean": "Boolean",
        SCHEMA_ORG_PREFIX + "Float": "Float",
        SCHEMA_ORG_PREFIX + "PropertyValue": "PropertyValue",
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

        # Caching path for the contexts
        pyld_cache_initialize()

        # This is needed for proper behaviour
        # https://stackoverflow.com/a/6264214
        if self.RELATIVE_ROCRATE_SCHEME not in urllib.parse.uses_relative:
            urllib.parse.uses_relative.append(self.RELATIVE_ROCRATE_SCHEME)
        if self.RELATIVE_ROCRATE_SCHEME not in urllib.parse.uses_fragment:
            urllib.parse.uses_fragment.append(self.RELATIVE_ROCRATE_SCHEME)

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
        #         "@base": self.RELATIVE_ROCRATE_SPARQL_BASE,
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
            base=self.RELATIVE_ROCRATE_SPARQL_BASE,
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
SELECT  ?origmainentity ?identifier ?workflow_repository ?workflow_version ?workflow_url ?workflow_name ?workflow_alternate_name ?programminglanguage_identifier ?programminglanguage_url ?programminglanguage_version ?file_size ?file_sha256
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
        FILTER NOT EXISTS {
            ?mainentity s:isBasedOn ?somemainentity .
            ?somemainentity
                a bs:ComputationalWorkflow ;
                dcterms:conformsTo ?somebsworkflowprofile .
            FILTER (
                STRSTARTS(str(?somebsworkflowprofile), str(bswfprofile:))
            ) .
        }
        BIND (?mainentity AS ?origmainentity)
    } UNION {
        ?mainentity s:isBasedOn ?origmainentity .
        ?origmainentity
            a bs:ComputationalWorkflow ;
            dcterms:conformsTo ?bsworkflowprofile .
        FILTER (
            STRSTARTS(str(?bsworkflowprofile), str(bswfprofile:))
        )
    }
    OPTIONAL {
        ?origmainentity s:codeRepository ?workflow_repository .
    }
    OPTIONAL {
        ?origmainentity s:version ?workflow_version .
    }
    OPTIONAL {
        ?origmainentity s:url ?workflow_url .
    }
    OPTIONAL {
        ?origmainentity s:identifier ?identifier .
    }
    OPTIONAL {
        ?origmainentity s:name ?workflow_name .
    }
    OPTIONAL {
        ?origmainentity s:alternateName ?workflow_alternate_name .
    }
    OPTIONAL {
        ?origmainentity
            wrterm:sha256 ?file_sha256 .
    }
    OPTIONAL {
        ?origmainentity
            s:contentSize ?file_size .
    }
}
"""

    LIST_PARTS_SPARQL: "Final[str]" = """\
SELECT  ?part_entity ?identifier ?part_repository ?part_version ?part_url ?part_name ?part_alternate_name ?file_size ?file_sha256
WHERE   {
    ?entity s:hasPart+ $part_entity .
    ?part_entity a s:MediaObject .
    OPTIONAL {
        ?part_entity s:codeRepository ?part_repository .
    }
    OPTIONAL {
        ?part_entity s:version ?part_version .
    }
    OPTIONAL {
        ?part_entity s:url ?part_url .
    }
    OPTIONAL {
        ?part_entity s:identifier ?identifier .
    }
    OPTIONAL {
        ?part_entity s:name ?part_name .
    }
    OPTIONAL {
        ?part_entity s:alternateName ?part_alternate_name .
    }
    OPTIONAL {
        ?part_entity
            wrterm:sha256 ?file_sha256 .
    }
    OPTIONAL {
        ?part_entity
            s:contentSize ?file_size .
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
SELECT DISTINCT ?container ?container_snapshot_size ?container_snapshot_sha256 ?container_additional_type ?type_of_container ?type_of_container_type ?source_container ?source_container_additional_type ?source_container_registry ?source_container_name ?source_container_tag ?source_container_sha256 ?source_container_platform ?source_container_arch ?source_container_metadata ?source_container_metadata_size ?source_container_metadata_sha256 ?type_of_source_container ?type_of_source_container_type
WHERE   {
    {
        ?execution wrterm:containerImage ?source_container .
    } UNION {
        ?entity s:softwareAddOn|s:softwareRequirements ?source_container.
    }
    ?source_container
        a wrterm:ContainerImage ;
        s:additionalType ?source_container_additional_type .
    OPTIONAL {
        ?source_container
            s:softwareRequirements ?source_container_type ;
            s:applicationCategory ?type_of_source_container .
        ?source_container_type
            a s:SoftwareApplication ;
            s:applicationCategory ?type_of_source_container_type .
        FILTER(
            STRSTARTS(str(?type_of_source_container), str(wikidata:)) &&
            STRSTARTS(str(?type_of_source_container_type), str(wikidata:))
        ) .
    }

    OPTIONAL {
        ?create_snapshot_container
            a s:CreateAction ;
            s:object ?source_container ;
            s:result ?container .
        ?container
            a s:MediaObject ;
            a wrterm:ContainerImage ;
            s:additionalType ?container_additional_type .
        OPTIONAL {
            ?container wrterm:sha256 ?container_snapshot_sha256 .
        }
        OPTIONAL {
            ?container
                s:contentSize ?container_snapshot_size .
        }
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
    }
    OPTIONAL {
        ?source_container wrterm:registry ?source_container_registry .
    }
    OPTIONAL {
        ?source_container s:name ?source_container_name .
    }
    OPTIONAL {
        ?source_container wrterm:tag ?source_container_tag .
    }
    OPTIONAL {
        ?source_container wrterm:sha256 ?source_container_sha256 .
    }
    OPTIONAL {
        ?source_container
            a s:SoftwareApplication ;
            s:operatingSystem ?source_container_platform .
    }
    OPTIONAL {
        ?source_container
            a s:SoftwareApplication ;
            s:processorRequirements ?source_container_arch .
    }
    OPTIONAL {
        ?source_container_metadata
            a s:MediaObject ;
            s:about ?source_container .
        OPTIONAL {
            ?source_container_metadata
                s:contentSize ?source_container_metadata_size .
        }
        OPTIONAL {
            ?source_container_metadata
                s:sha256 ?source_container_metadata_sha256 .
        }
    }
}
"""

    # This compound query is much faster when each of the UNION components
    # is evaluated separately
    OBTAIN_WORKFLOW_INPUTS_SPARQL: "Final[str]" = """\
SELECT DISTINCT  ?input ?name ?inputfp ?additional_type ?fileuri ?filepid ?value ?component ?leaf_type ?fileid ?file_size ?file_sha256 ?encoding_format ?content_with_uris ?header_rows ?row_sep ?column_sep ?uri_columns
WHERE   {
    ?main_entity bsworkflow:input ?inputfp .
    ?inputfp
        a bs:FormalParameter ;
        s:name ?name ;
        s:additionalType ?additional_type .

    {
        ?input s:exampleOfWork ?inputfp .
    } UNION {
        ?inputfp s:workExample ?input .
    }

    {
        # A file, which is a schema.org MediaObject
        ?input
            a s:MediaObject .
        BIND (?input AS ?fileid)
    } UNION {
        # A directory, which is a schema.org Dataset
        ?input
            a s:Dataset .
        BIND (?input AS ?fileid)
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
        BIND (?input AS ?fileid)
        ?input
            a s:PropertyValue .
    } UNION {
        # A combination of files or directories or property values
        VALUES ( ?leaf_type ) { ( s:PropertyValue ) ( s:MediaObject ) ( s:Dataset ) }
        ?input
            a s:Collection ;
            s:hasPart+ ?component .
        ?component
            a ?leaf_type .
        FILTER NOT EXISTS { ?inputfp wfexsterm:contentWithURIs ?content_with_uris }
        BIND (?component AS ?fileid)
    } UNION {
        # A combination of files or directories or property values
        ?input
            a s:Collection ;
            s:mainEntity ?extrapolated_input .
        ?inputfp
            s:encodingFormat ?encoding_format ;
            wfexsterm:contentWithURIs ?content_with_uris ;
            wfexsterm:headerRows ?header_rows ;
            wfexsterm:rowSep ?row_sep ;
            wfexsterm:columnSep ?column_sep .
        # It is an all or nothing situation
        {{
            SELECT ?inputfp (GROUP_CONCAT(?uri_column ; SEPARATOR=";") AS ?uri_columns)
            WHERE {
                ?inputfp wfexsterm:uriColumns ?uri_column .
            } GROUP BY ?inputfp
        }}
        ?extrapolate_action
            a s:CreateAction ;
            s:object ?real_input ;
            s:result ?extrapolated_input .
        ?real_input a s:MediaObject .

        BIND (?real_input AS ?fileid)
    }
    OPTIONAL {
        ?fileid s:contentUrl ?fileuri .
    }
    OPTIONAL {
        ?fileid s:identifier ?filepid .
    }
    OPTIONAL {
        ?fileid
            wrterm:sha256 ?file_sha256 .
    }
    OPTIONAL {
        ?fileid
            s:contentSize ?file_size .
    }
    OPTIONAL {
        ?fileid s:value ?value .
    }
}
"""

    # This compound query is much faster when each of the UNION components
    # is evaluated separately
    OBTAIN_WORKFLOW_ENV_SPARQL: "Final[str]" = """\
SELECT DISTINCT  ?env ?name ?name_env ?envfp ?additional_type ?fileuri ?filepid ?value ?component ?leaf_type ?fileid ?file_sha256 ?file_size ?encoding_format ?content_with_uris ?header_rows ?row_sep ?column_sep ?uri_columns
WHERE   {
    ?main_entity wrterm:environment ?envfp .
    ?envfp
        a bs:FormalParameter ;
        s:name ?name ;
        s:additionalType ?additional_type .

    {
        ?env s:exampleOfWork ?envfp .
    } UNION {
        ?envfp s:workExample ?env .
    }

    {
        # A file, which is a schema.org MediaObject
        ?env
            a s:MediaObject ;
            s:name ?name_env .
        BIND (?env AS ?fileid)
    } UNION {
        # A directory, which is a schema.org Dataset
        ?env
            a s:Dataset ;
            s:name ?name_env .
        BIND (?env AS ?fileid)
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
            s:name ?name_env .
        BIND (?env AS ?fileid)
    } UNION {
        # A combination of files or directories or property values
        VALUES ( ?leaf_type ) { ( s:PropertyValue ) ( s:MediaObject ) ( s:Dataset ) }
        ?env
            a s:Collection ;
            s:name ?name_env ;
            s:hasPart+ ?component .
        ?component
            a ?leaf_type .
        FILTER NOT EXISTS { ?envfp wfexsterm:contentWithURIs ?content_with_uris }
        BIND (?component AS ?fileid)
    } UNION {
        # A combination of files or directories or property values
        ?env
            a s:Collection ;
            s:mainEntity ?extrapolated_input .
        ?envfp
            s:encodingFormat ?encoding_format ;
            wfexsterm:contentWithURIs ?content_with_uris ;
            wfexsterm:headerRows ?header_rows ;
            wfexsterm:rowSep ?row_sep ;
            wfexsterm:columnSep ?column_sep .
        # It is an all or nothing situation
        {{
            SELECT ?envfp (GROUP_CONCAT(?uri_column ; SEPARATOR=";") AS ?uri_columns)
            WHERE {
                ?envfp wfexsterm:uriColumns ?uri_column .
            } GROUP BY ?envfp
        }}
        ?extrapolate_action
            a s:CreateAction ;
            s:object ?real_input ;
            s:result ?extrapolated_input .
        ?real_input a s:MediaObject .

        BIND (?real_input AS ?fileid)
    }
    OPTIONAL {
        ?fileid s:contentUrl ?fileuri .
    }
    OPTIONAL {
        ?fileid s:identifier ?filepid .
    }
    OPTIONAL {
        ?fileid
            wrterm:sha256 ?file_sha256 .
    }
    OPTIONAL {
        ?fileid
            s:contentSize ?file_size .
    }
    OPTIONAL {
        ?fileid s:value ?value .
    }
}
"""

    # This compound query is much faster when each of the UNION components
    # is evaluated separately
    OBTAIN_WORKFLOW_OUTPUTS_SPARQL: "Final[str]" = """\
SELECT  ?name ?outputfp ?additional_type ?default_value ?synthetic_output ?glob_pattern ?filled_from_name
WHERE   {
    ?main_entity bsworkflow:output ?outputfp .
    ?outputfp
        a bs:FormalParameter ;
        s:name ?name ;
        s:additionalType ?additional_type .
    OPTIONAL {
        ?outputfp
            s:defaultValue ?default_value .
    }
    OPTIONAL {
        ?outputfp
            wfexsterm:syntheticOutput ?synthetic_output .
    }
    OPTIONAL {
        ?outputfp
            wfexsterm:globPattern ?glob_pattern .
    }
    OPTIONAL {
        ?outputfp
            wfexsterm:filledFrom ?filled_from_name .
    }
}
"""

    # This compound query is much faster when each of the UNION components
    # is evaluated separately
    OBTAIN_EXECUTION_INPUTS_SPARQL: "Final[str]" = """\
SELECT DISTINCT ?input ?name ?inputfp ?additional_type ?fileuri ?filepid ?value ?component ?leaf_type ?fileid ?file_sha256 ?file_size ?encoding_format ?content_with_uris ?header_rows ?row_sep ?column_sep ?uri_columns
WHERE   {
    ?execution s:object ?input .
    ?inputfp
        a bs:FormalParameter ;
        s:name ?name ;
        s:additionalType ?additional_type .

    {
        ?input s:exampleOfWork ?inputfp .
    } UNION {
        ?inputfp s:workExample ?input .
    }

    {
        # A file, which is a schema.org MediaObject
        BIND ( "File" AS ?additional_type )
        ?input
            a s:MediaObject .
        BIND (?input AS ?fileid)
    } UNION {
        # A directory, which is a schema.org Dataset
        BIND ( "Dataset" AS ?additional_type )
        ?input
            a s:Dataset .
        BIND (?input AS ?fileid)
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
            a s:PropertyValue .
        BIND (?input AS ?fileid)
    } UNION {
        # A combination of files or directories or property values
        VALUES (?additional_type) { ( "Integer" ) ( "Text" ) ( "Boolean" ) ( "Float" ) ( "Collection" ) }
        VALUES ( ?leaf_type ) { ( s:PropertyValue ) ( s:MediaObject ) ( s:Dataset ) }
        ?input
            a s:Collection ;
            s:hasPart+ ?component .
        ?component
            a ?leaf_type .
        FILTER NOT EXISTS { ?inputfp wfexsterm:contentWithURIs ?content_with_uris }
        BIND (?component AS ?fileid)
    } UNION {
        # A file which points to other remote files or directories
        BIND ( "File" AS ?additional_type )
        ?input
            a s:Collection ;
            s:mainEntity ?extrapolated_input .
        ?inputfp
            s:encodingFormat ?encoding_format ;
            wfexsterm:contentWithURIs ?content_with_uris ;
            wfexsterm:headerRows ?header_rows ;
            wfexsterm:rowSep ?row_sep ;
            wfexsterm:columnSep ?column_sep .
        # It is an all or nothing situation
        {{
            SELECT ?inputfp (GROUP_CONCAT(?uri_column ; SEPARATOR=";") AS ?uri_columns)
            WHERE {
                ?inputfp wfexsterm:uriColumns ?uri_column .
            } GROUP BY ?inputfp
        }}
        ?extrapolate_action
            a s:CreateAction ;
            s:object ?real_input ;
            s:result ?extrapolated_input .
        ?real_input a s:MediaObject .
        
        BIND (?real_input AS ?fileid)
    }
    OPTIONAL {
        ?fileid s:contentUrl ?fileuri .
    }
    OPTIONAL {
        ?fileid s:identifier ?filepid .
    }
    OPTIONAL {
        ?fileid
            wrterm:sha256 ?file_sha256 .
    }
    OPTIONAL {
        ?fileid
            s:contentSize ?file_size .
    }
    OPTIONAL {
        ?fileid s:value ?value .
    }
}
"""

    # This compound query is much faster when each of the UNION components
    # is evaluated separately
    OBTAIN_EXECUTION_ENV_SPARQL: "Final[str]" = """\
SELECT DISTINCT ?env ?name ?name_env ?envfp ?additional_type ?fileuri ?filepid ?value ?component ?leaf_type ?fileid ?file_sha256 ?file_size ?encoding_format ?content_with_uris ?header_rows ?row_sep ?column_sep ?uri_columns
WHERE   {
    ?execution wrterm:environment ?env .
    ?envfp
        a bs:FormalParameter ;
        s:name ?name ;
        s:additionalType ?additional_type .

    {
        ?env s:exampleOfWork ?envfp .
    } UNION {
        ?envfp s:workExample ?env .
    }

    {
        # A file, which is a schema.org MediaObject
        BIND ( "File" AS ?additional_type )
        ?env
            a s:MediaObject ;
            s:name ?name_env .
        BIND (?env AS ?fileid)
    } UNION {
        # A directory, which is a schema.org Dataset
        BIND ( "Dataset" AS ?additional_type )
        ?env
            a s:Dataset ;
            s:name ?name_env .
        BIND (?env AS ?fileid)
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
            s:name ?name_env .
        BIND (?env AS ?fileid)
    } UNION {
        # A combination of files or directories or property values
        VALUES (?additional_type) { ( "Integer" ) ( "Text" ) ( "Boolean" ) ( "Float" ) ( "Collection" ) }
        VALUES ( ?leaf_type ) { ( s:PropertyValue ) ( s:MediaObject ) ( s:Dataset ) }
        ?env
            a s:Collection ;
            s:name ?name_env ;
            s:hasPart+ ?component .
        ?component
            a ?leaf_type .
        FILTER NOT EXISTS { ?envfp wfexsterm:contentWithURIs ?content_with_uris }
        BIND (?component AS ?fileid)
    } UNION {
        # A file which points to other remote files or directories
        BIND ( "File" AS ?additional_type )
        ?env
            a s:Collection ;
            s:mainEntity ?extrapolated_input .
        ?envfp
            s:encodingFormat ?encoding_format ;
            wfexsterm:contentWithURIs ?content_with_uris ;
            wfexsterm:headerRows ?header_rows ;
            wfexsterm:rowSep ?row_sep ;
            wfexsterm:columnSep ?column_sep .
        # It is an all or nothing situation
        {{
            SELECT ?envfp (GROUP_CONCAT(?uri_column ; SEPARATOR=";") AS ?uri_columns)
            WHERE {
                ?envfp wfexsterm:uriColumns ?uri_column .
            } GROUP BY ?envfp
        }}
        ?extrapolate_action
            a s:CreateAction ;
            s:object ?real_input ;
            s:result ?extrapolated_input .
        ?real_input a s:MediaObject .
        
        BIND (?real_input AS ?fileid)
    }
    OPTIONAL {
        ?fileid s:contentUrl ?fileuri .
    }
    OPTIONAL {
        ?fileid s:identifier ?filepid .
    }
    OPTIONAL {
        ?fileid
            wrterm:sha256 ?file_sha256 .
    }
    OPTIONAL {
        ?fileid
            s:contentSize ?file_size .
    }
    OPTIONAL {
        ?fileid s:value ?value .
    }
}
"""

    # This compound query is much faster when each of the UNION components
    # is evaluated separately
    OBTAIN_EXECUTION_OUTPUTS_SPARQL: "Final[str]" = """\
SELECT  ?output ?name ?alternate_name ?outputfp ?default_value ?additional_type ?fileuri ?filepid ?value ?component ?leaf_type ?synthetic_output ?glob_pattern ?filled_from_name
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
        OPTIONAL {
            ?output
                s:identifier ?filepid .
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
        OPTIONAL {
            ?output
                s:identifier ?filepid .
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
        VALUES (?additional_type) { ( "Integer" ) ( "Text" ) ( "Boolean" ) ( "Float" ) ( "Collection" ) }
        VALUES ( ?leaf_type ) { ( s:PropertyValue ) ( s:MediaObject ) ( s:Dataset ) }
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
            ?component s:identifier ?filepid .
        }
        OPTIONAL {
            ?component s:value ?value .
        }
    }
    OPTIONAL {
        ?outputfp
            s:defaultValue ?default_value .
    }
    OPTIONAL {
        ?outputfp
            wfexsterm:syntheticOutput ?synthetic_output .
    }
    OPTIONAL {
        ?outputfp
            wfexsterm:globPattern ?glob_pattern .
    }
    OPTIONAL {
        ?outputfp
            wfexsterm:filledFrom ?filled_from_name .
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
        payload_dir: "Optional[pathlib.Path]" = None,
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

        return self.__parseContainersResults(
            qcontainersres, main_entity, payload_dir=payload_dir
        )

    def _parseContainersFromExecution(
        self,
        g: "rdflib.graph.Graph",
        execution: "rdflib.term.Identifier",
        main_entity: "rdflib.term.Identifier",
        payload_dir: "Optional[pathlib.Path]" = None,
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

        return self.__parseContainersResults(
            qcontainersres, main_entity, payload_dir=payload_dir
        )

    def __parseContainersResults(
        self,
        qcontainersres: "rdflib.query.Result",
        main_entity: "rdflib.term.Identifier",
        payload_dir: "Optional[pathlib.Path]" = None,
    ) -> "Optional[Tuple[ContainerType, Sequence[Container]]]":
        container_type: "Optional[ContainerType]" = None
        source_container_type: "Optional[ContainerType]" = None
        additional_container_type: "Optional[ContainerType]" = None
        additional_source_container_type: "Optional[ContainerType]" = None
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

            if containerrow.type_of_source_container is not None:
                putative_source_container_type = ApplicationCategory2ContainerType.get(
                    str(containerrow.type_of_source_container)
                )
                if source_container_type is None:
                    source_container_type = putative_source_container_type
                elif (
                    putative_source_container_type is not None
                    and putative_source_container_type != source_container_type
                ):
                    self.logger.warning(
                        f"Not all the source containers of execution {main_entity} were materialized with {source_container_type} factory (also found {putative_source_container_type})"
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

            # These hints should be left by any compliant WRROC
            # implementation
            if containerrow.source_container_additional_type is not None:
                try:
                    putative_additional_source_container_image_additional_type = (
                        StrContainerAdditionalType2ContainerImageAdditionalType.get(
                            str(containerrow.source_container_additional_type)
                        )
                    )
                    putative_additional_source_container_type = (
                        None
                        if putative_additional_source_container_image_additional_type
                        is None
                        else (
                            AdditionalType2ContainerType.get(
                                putative_additional_source_container_image_additional_type
                            )
                        )
                    )
                    if additional_source_container_type is None:
                        additional_source_container_type = (
                            putative_additional_source_container_type
                        )
                    elif (
                        putative_additional_source_container_type is not None
                        and putative_additional_source_container_type
                        not in (source_container_type, additional_source_container_type)
                    ):
                        self.logger.warning(
                            f"Not all the source containers of execution {main_entity} were labelled with {additional_source_container_type} factory (also found {putative_additional_source_container_type})"
                        )
                except Exception as e:
                    self.logger.error(
                        f"Unable to map additional type {str(containerrow.source_container_additional_type)} for {str(containerrow.source_container)}"
                    )

        # Assigning this, as it is going to be used later to
        # build the list of containers
        if (
            source_container_type is None
            and additional_source_container_type is not None
        ):
            source_container_type = additional_source_container_type

        # Assigning this, as it is going to be used later to
        # build the list of containers
        if container_type is None and additional_container_type is not None:
            container_type = additional_container_type

        if container_type is None and source_container_type is not None:
            container_type = source_container_type

        if container_type is None:
            return None

        # This is the second pass, to generate the list of
        # containers described in the RO-Crate
        for containerrow in qcontainersres:
            assert isinstance(
                containerrow, rdflib.query.ResultRow
            ), "Check the SPARQL code, as it should be a SELECT query"

            self.logger.debug("\nTuple")
            for key, val in containerrow.asdict().items():
                self.logger.debug(f"{key} => {val}")

            source_container_type = None
            if containerrow.source_container_additional_type is not None:
                try:
                    putative_additional_source_container_image_additional_type = (
                        StrContainerAdditionalType2ContainerImageAdditionalType.get(
                            str(containerrow.source_container_additional_type)
                        )
                    )
                    source_container_type = (
                        None
                        if putative_additional_source_container_image_additional_type
                        is None
                        else (
                            AdditionalType2ContainerType.get(
                                putative_additional_source_container_image_additional_type
                            )
                        )
                    )
                except Exception as e:
                    self.logger.error(
                        f"Unable to map additional type {str(containerrow.source_container_additional_type)} for {str(containerrow.source_container)}"
                    )

            if source_container_type is None:
                source_container_type = container_type

            if containerrow.source_container_name is not None:
                try:
                    registries: "Optional[Mapping[ContainerType, str]]" = None
                    fingerprint = None
                    origTaggedName = ""
                    taggedName = ""
                    if source_container_type == ContainerType.Docker:
                        the_registry = (
                            str(containerrow.source_container_registry)
                            if containerrow.source_container_registry is not None
                            else DEFAULT_DOCKER_REGISTRY
                        )
                        registries = {
                            ContainerType.Docker: the_registry,
                        }
                        container_identifier = str(containerrow.source_container_name)
                        if "/" not in container_identifier:
                            container_identifier = "library/" + container_identifier
                        assert containerrow.source_container_tag is not None
                        if containerrow.source_container_sha256 is not None:
                            fingerprint = f"{the_registry}/{container_identifier}@sha256:{str(containerrow.source_container_sha256)}"
                        else:
                            fingerprint = f"{the_registry}/{container_identifier}:{str(containerrow.source_container_tag)}"
                        origTaggedName = f"{container_identifier}:{str(containerrow.source_container_tag)}"
                        taggedName = f"docker://{the_registry}/{container_identifier}:{str(containerrow.source_container_tag)}"
                    elif source_container_type == ContainerType.Singularity:
                        origTaggedName = str(containerrow.source_container_name)
                        taggedName = origTaggedName
                        fingerprint = origTaggedName

                    container_image_path: "Optional[str]" = None
                    located_snapshot: "Optional[pathlib.Path]" = None
                    metadata_container_image_path: "Optional[str]" = None
                    located_metadata: "Optional[pathlib.Path]" = None
                    image_signature: "Optional[Fingerprint]" = None
                    if payload_dir is not None:
                        if containerrow.container != containerrow.source_container:
                            include_container_image = self.__processPayloadEntity(
                                the_entity=containerrow.container,
                                payload_dir=payload_dir,
                                kindobj=ContentKind.File,
                                entity_type="container image",
                                entity_name=origTaggedName,
                                the_file_size=containerrow.container_snapshot_size,
                                the_file_sha256=containerrow.container_snapshot_sha256,
                            )
                            if include_container_image is not None:
                                container_image_path = include_container_image.rel_path
                                located_snapshot = include_container_image.path
                                image_signature = include_container_image.signature

                        if containerrow.source_container_metadata is not None:
                            include_metadata_container_image = self.__processPayloadEntity(
                                the_entity=containerrow.source_container_metadata,
                                payload_dir=payload_dir,
                                kindobj=ContentKind.File,
                                entity_type="container metadata",
                                entity_name=origTaggedName,
                                the_file_size=containerrow.source_container_metadata_size,
                                the_file_sha256=containerrow.source_container_metadata_sha256,
                            )

                            if include_metadata_container_image is not None:
                                metadata_container_image_path = (
                                    include_metadata_container_image.rel_path
                                )
                                located_metadata = include_metadata_container_image.path
                                computed_source_container_metadata_signature = (
                                    include_metadata_container_image.signature
                                )

                    the_containers.append(
                        Container(
                            origTaggedName=origTaggedName,
                            type=container_type,
                            registries=registries,
                            taggedName=cast("URIType", taggedName),
                            localPath=located_snapshot,
                            metadataLocalPath=located_metadata,
                            architecture=None
                            if containerrow.source_container_arch is None
                            else cast(
                                "ProcessorArchitecture",
                                str(containerrow.source_container_arch),
                            ),
                            operatingSystem=None
                            if containerrow.source_container_platform is None
                            else cast(
                                "ContainerOperatingSystem",
                                str(containerrow.source_container_platform),
                            ),
                            fingerprint=cast("Fingerprint", fingerprint),
                            source_type=source_container_type,
                            image_signature=image_signature,
                        )
                    )
                except Exception as e:
                    self.logger.exception(
                        f"Unable to assign from additional type {str(containerrow.source_container_additional_type)} for {str(containerrow.source_container)}"
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
            if (
                hasattr(outputrow, "leaf_type") and outputrow.leaf_type is not None
            ) or additional_type == "Collection":
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

            synthetic_output = False
            if outputrow.synthetic_output is not None:
                if isinstance(outputrow.synthetic_output, rdflib.term.Literal):
                    synthetic_output = bool(outputrow.synthetic_output.value)
                else:
                    ser_val = str(outputrow.synthetic_output).lower()
                    synthetic_output = (
                        False if len(ser_val) == 0 or ser_val == "false" else True
                    )

            # Self generated outputs with fake names => skip it!!!!!
            if (
                synthetic_output
                and outputrow.glob_pattern is None
                and outputrow.filled_from_name is None
            ):
                continue

            sch_output: "Sch_Output" = {
                "c-l-a-s-s": ContentKind.Directory.name
                if additional_type == "Dataset"
                else ContentKind.File.name,
                "cardinality": cardinality,
            }

            valobj: "Sch_Output" = base.setdefault(output_last, sch_output)

            if preferred_name is not None:
                valobj["preferredName"] = preferred_name

            # Now, WfExS terms processing
            if outputrow.synthetic_output is not None:
                valobj["syntheticOutput"] = synthetic_output

            if outputrow.glob_pattern is not None:
                valobj["glob"] = str(outputrow.glob_pattern)

            if outputrow.filled_from_name is not None:
                valobj["fillFrom"] = str(outputrow.filled_from_name)

        return outputs

    def _parseInputsFromExecution(
        self,
        g: "rdflib.graph.Graph",
        execution: "rdflib.term.Identifier",
        main_entity: "rdflib.term.Identifier",
        default_licences: "Sequence[str]",
        public_name: "str",
        payload_dir: "Optional[pathlib.Path]" = None,
    ) -> "Tuple[ParamsBlock, Optional[Sequence[MaterializedInput]]]":
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

        return self.__parseInputsResults(
            qinputsres, g, default_licences, public_name, payload_dir=payload_dir
        )

    def _parseInputsFromMainEntity(
        self,
        g: "rdflib.graph.Graph",
        main_entity: "rdflib.term.Identifier",
        default_licences: "Sequence[str]",
        public_name: "str",
        payload_dir: "Optional[pathlib.Path]" = None,
    ) -> "Tuple[ParamsBlock, Optional[Sequence[MaterializedInput]]]":
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

        return self.__parseInputsResults(
            qwinputsres, g, default_licences, public_name, payload_dir=payload_dir
        )

    def __processPayloadInput(
        self,
        inputrow: "rdflib.query.ResultRow",
        payload_dir: "pathlib.Path",
        the_uri: "str",
        licences: "Sequence[str]",
        input_type: "str",
        kindobj: "ContentKind",
        cached_inputs_hash: "MutableMapping[str, MaterializedInput]",
    ) -> "MutableMapping[str, MaterializedInput]":
        input_name = str(inputrow.name)
        include_input = self.__processPayloadEntity(
            the_entity=inputrow.fileid,
            payload_dir=payload_dir,
            kindobj=kindobj,
            entity_type=input_type,
            entity_name=input_name,
            the_file_size=inputrow.file_size,
            the_file_sha256=inputrow.file_sha256,
        )

        if include_input is not None:
            input_path = include_input.rel_path
            located_input = include_input.path
            file_signature = include_input.signature
            licences_tuple = (
                cast("Tuple[URIType, ...]", tuple(licences))
                if len(licences) > 0
                else DefaultNoLicenceTuple
            )
            mat_content = MaterializedContent(
                local=located_input,
                licensed_uri=LicensedURI(
                    uri=cast("URIType", the_uri),
                    licences=licences_tuple,
                ),
                # TODO: better inference, as it might have a side effect
                prettyFilename=cast("RelPath", located_input.name),
                kind=kindobj,
                fingerprint=file_signature,
            )
            cached_input = cached_inputs_hash.get(input_name)
            if cached_input is None:
                cached_input = MaterializedInput(
                    name=cast("SymbolicParamName", input_name),
                    values=[mat_content],
                    # implicit=,
                )
            else:
                cached_input = cached_input._replace(
                    values=[*cached_input.values, mat_content],
                )

            cached_inputs_hash[input_name] = cached_input

        return cached_inputs_hash

    def __parseInputsResults(
        self,
        qinputsres: "rdflib.query.Result",
        g: "rdflib.graph.Graph",
        default_licences: "Sequence[str]",
        public_name: "str",
        payload_dir: "Optional[pathlib.Path]" = None,
    ) -> "Tuple[ParamsBlock, Optional[Sequence[MaterializedInput]]]":
        params: "MutableParamsBlock" = {}
        cached_inputs_hash: "MutableMapping[str, MaterializedInput]" = {}
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
            kindobj: "Optional[ContentKind]" = None
            # Is it a nested one?
            if inputrow.leaf_type is not None:
                leaf_type = str(inputrow.leaf_type)
                leaf_additional_type = self.LEAF_TYPE_2_ADDITIONAL_TYPE.get(leaf_type)
                if leaf_additional_type is None:
                    raise ROCrateToolboxException(
                        f"Unable to handle contents of type {leaf_type} in input Collection {str(inputrow.name)}"
                    )
                if additional_type == "Collection":
                    additional_type = leaf_additional_type
                if leaf_additional_type not in ("File", "Dataset"):
                    valarr = base.setdefault(param_last, [])

            # Is it a file or a directory?
            # Or even better, a ContentWithURIs
            if additional_type in ("File", "Dataset"):
                if (
                    isinstance(inputrow.content_with_uris, rdflib.term.Literal)
                    and bool(inputrow.content_with_uris.value)
                    and str(inputrow.encoding_format) in RevContentWithURIsMIMEs
                ):
                    kindobj = ContentKind.ContentWithURIs
                elif additional_type == "Dataset":
                    kindobj = ContentKind.Directory
                else:
                    kindobj = ContentKind.File

                valobj = base.setdefault(
                    param_last,
                    {
                        "c-l-a-s-s": kindobj.name,
                    },
                )

                # Time to transfer the additional properties
                if kindobj == ContentKind.ContentWithURIs:
                    assert isinstance(inputrow.header_rows, rdflib.term.Literal)
                    assert isinstance(inputrow.row_sep, rdflib.term.Literal)
                    assert isinstance(inputrow.column_sep, rdflib.term.Literal)
                    assert isinstance(inputrow.uri_columns, rdflib.term.Literal)

                    encoding_format_key = RevContentWithURIsMIMEs[
                        str(inputrow.encoding_format)
                    ]
                    base[param_last].update(
                        {
                            encoding_format_key: {
                                "header-rows": inputrow.header_rows.value,
                                "row-sep": inputrow.row_sep.value,
                                "column-sep": inputrow.column_sep.value,
                                "uri-columns": list(
                                    map(int, inputrow.uri_columns.value.split(";"))
                                ),
                            }
                        }
                    )

            if isinstance(valobj, dict):
                the_uri: "str"
                if inputrow.fileuri is not None:
                    the_uri = str(inputrow.fileuri)
                elif inputrow.filepid is not None:
                    the_uri = str(inputrow.filepid)
                else:
                    the_uri = str(inputrow.fileid)

                # Check it is not an originally relative URI
                parsed_uri = urllib.parse.urlparse(the_uri)
                if parsed_uri.scheme in ("", self.RELATIVE_ROCRATE_SCHEME):
                    errmsg = f"Input parameter {inputrow.name} from {public_name} is of type {additional_type}, but no associated `contentUrl` or `identifier` were found, and its @id is a relative URI. Stopping."
                    self.logger.error(errmsg)
                    raise ROCrateToolboxException(errmsg)

                # Now, the licence
                licences = self._getLicences(g, inputrow.input, public_name)
                if len(licences) == 0:
                    licences = default_licences

                expanded_licences = self.wfexs.curate_licence_list(
                    licences, default_licence=NoLicenceDescription
                )

                the_url: "Union[str, Mapping[str, Any]]"
                if len(licences) == 0:
                    the_url = the_uri
                else:
                    the_url = {
                        "uri": the_uri,
                        "licences": list(map(lambda el: el.uris[0], expanded_licences)),
                    }

                valurl = valobj.get("url")
                if isinstance(valurl, (str, dict)):
                    valurl = [valurl]
                    valobj["url"] = valurl

                if isinstance(valurl, list):
                    valurl.append(the_url)
                else:
                    valobj["url"] = the_url

                if payload_dir is not None and inputrow.fileid is not None:
                    assert kindobj is not None
                    self.__processPayloadInput(
                        inputrow,
                        payload_dir,
                        the_uri,
                        licences,
                        "input",
                        kindobj,
                        cached_inputs_hash,
                    )
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

        return (
            params,
            list(cached_inputs_hash.values()) if payload_dir is not None else None,
        )

    def _parseEnvFromExecution(
        self,
        g: "rdflib.graph.Graph",
        execution: "rdflib.term.Identifier",
        main_entity: "rdflib.term.Identifier",
        default_licences: "Sequence[str]",
        public_name: "str",
        payload_dir: "Optional[pathlib.Path]" = None,
    ) -> "Tuple[EnvironmentBlock, Optional[Sequence[MaterializedInput]]]":
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

        return self.__parseEnvResults(
            qenvres, g, default_licences, public_name, payload_dir=payload_dir
        )

    def _parseEnvFromMainEntity(
        self,
        g: "rdflib.graph.Graph",
        main_entity: "rdflib.term.Identifier",
        default_licences: "Sequence[str]",
        public_name: "str",
        payload_dir: "Optional[pathlib.Path]" = None,
    ) -> "Tuple[EnvironmentBlock, Optional[Sequence[MaterializedInput]]]":
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

        return self.__parseEnvResults(
            qwenvres, g, default_licences, public_name, payload_dir=payload_dir
        )

    def __parseEnvResults(
        self,
        qenvres: "rdflib.query.Result",
        g: "rdflib.graph.Graph",
        default_licences: "Sequence[str]",
        public_name: "str",
        payload_dir: "Optional[pathlib.Path]" = None,
    ) -> "Tuple[EnvironmentBlock, Optional[Sequence[MaterializedInput]]]":
        """
        This method is (almost) identical to __parseInputsResults
        """
        # TODO: implement this
        environment: "MutableMapping[str, Any]" = {}
        cached_environment_hash: "MutableMapping[str, MaterializedInput]" = {}
        for envrow in qenvres:
            assert isinstance(
                envrow, rdflib.query.ResultRow
            ), "Check the SPARQL code, as it should be a SELECT query"

            env_name = str(envrow.name)

            # Now, fill in the values
            additional_type = str(envrow.additional_type)
            valarr: "Optional[MutableSequence[Any]]" = None
            valobj: "Optional[MutableMapping[str, Any]]" = None
            kindobj: "Optional[ContentKind]" = None
            # Is it a nested one?
            if envrow.leaf_type is not None:
                leaf_type = str(envrow.leaf_type)
                leaf_additional_type = self.LEAF_TYPE_2_ADDITIONAL_TYPE.get(leaf_type)
                if leaf_additional_type is None:
                    raise ROCrateToolboxException(
                        f"Unable to handle contents of type {leaf_type} in Collection reflecting contents pointed by environment variable {env_name}"
                    )
                if additional_type == "Collection":
                    additional_type = leaf_additional_type
                if leaf_additional_type not in ("File", "Dataset"):
                    valarr = environment.setdefault(env_name, [])

            # Is it a file or a directory?
            if additional_type in ("File", "Dataset"):
                kindobj = (
                    ContentKind.Directory
                    if additional_type == "Dataset"
                    else ContentKind.File
                )
                valobj = environment.setdefault(
                    env_name,
                    {
                        "c-l-a-s-s": kindobj.name,
                    },
                )

            if isinstance(valobj, dict):
                the_uri: "str"
                if envrow.fileuri is not None:
                    the_uri = str(envrow.fileuri)
                elif envrow.filepid is not None:
                    the_uri = str(envrow.filepid)
                else:
                    the_uri = str(envrow.fileid)

                # Check it is not an originally relative URI
                parsed_uri = urllib.parse.urlparse(the_uri)
                if parsed_uri.scheme in ("", self.RELATIVE_ROCRATE_SCHEME):
                    errmsg = f"Environment variable {env_name} from {public_name} is of type {additional_type}, but no associated `contentUrl` or `identifier` were found, and its @id is a relative URI. Stopping."
                    self.logger.error(errmsg)
                    raise ROCrateToolboxException(errmsg)

                # Now, the licence
                licences = self._getLicences(g, envrow.env, public_name)
                if len(licences) == 0:
                    licences = default_licences

                expanded_licences = self.wfexs.curate_licence_list(
                    licences, default_licence=NoLicenceDescription
                )

                the_url: "Union[str, Mapping[str, Any]]"
                if len(licences) == 0:
                    the_url = str(envrow.fileuri)
                else:
                    the_url = {
                        "uri": str(envrow.fileuri),
                        "licences": list(map(lambda el: el.uris[0], expanded_licences)),
                    }

                valurl = valobj.get("url")
                if isinstance(valurl, (str, dict)):
                    valurl = [valurl]
                    valobj["url"] = valurl

                if isinstance(valurl, list):
                    valurl.append(the_url)
                else:
                    valobj["url"] = the_url

                if payload_dir is not None and envrow.fileid is not None:
                    assert kindobj is not None
                    self.__processPayloadInput(
                        envrow,
                        payload_dir,
                        the_uri,
                        licences,
                        "environment variable",
                        kindobj,
                        cached_environment_hash,
                    )
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

        return (
            environment,
            list(cached_environment_hash.values()) if payload_dir is not None else None,
        )

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

    def __processPayloadEntity(
        self,
        the_entity: "rdflib.term.Identifier",
        payload_dir: "pathlib.Path",
        kindobj: "ContentKind",
        entity_type: "str",
        entity_name: "str",
        the_file_size: "rdflib.term.Node",
        the_file_sha256: "rdflib.term.Node",
    ) -> "Optional[ROCratePayload]":
        entity_uri = str(the_entity)
        entity_parsed_uri = urllib.parse.urlparse(entity_uri)
        include_entity = entity_parsed_uri.scheme == self.RELATIVE_ROCRATE_SCHEME

        entity_path: "Optional[str]" = None
        located_entity: "Optional[pathlib.Path]" = None
        if include_entity:
            entity_path = urllib.parse.unquote(entity_parsed_uri.path)
            if entity_path.startswith("/"):
                entity_path = entity_path[1:]

            located_entity = payload_dir / entity_path
            include_entity = located_entity.exists()
            if not include_entity:
                self.logger.warning(
                    f"Discarding payload {entity_path} for {entity_type} {entity_name} (not found)"
                )

        if include_entity:
            assert located_entity is not None
            include_entity = (
                kindobj == ContentKind.File and located_entity.is_file()
            ) or (kindobj == ContentKind.Directory and located_entity.is_dir())

            if not include_entity:
                self.logger.warning(
                    f"Discarding payload {entity_path} for {entity_type} {entity_name} (not is a {kindobj.value})"
                )

        if include_entity and kindobj == ContentKind.File and the_file_size is not None:
            assert entity_path is not None
            assert located_entity is not None
            # Does the recorded file size match?
            if isinstance(located_entity, ZipfilePath):
                the_size = located_entity.zip_root.getinfo(entity_path).file_size
            else:
                the_size = located_entity.stat().st_size
            if isinstance(the_file_size, rdflib.term.Literal):
                file_size = int(the_file_size.value)
            else:
                file_size = int(str(the_file_size))

            include_entity = the_size == file_size
            if not include_entity:
                self.logger.warning(
                    f"Discarding payload {entity_path} for {entity_type} {entity_name} (mismatching file size {the_size} vs {file_size})"
                )

        file_signature: "Optional[Fingerprint]" = None
        if include_entity and kindobj == ContentKind.File:
            assert located_entity is not None
            with located_entity.open(mode="rb") as lE:
                the_signature = ComputeDigestFromFileLike(
                    lE,
                    digestAlgorithm="sha256",
                )
            if the_file_sha256 is not None:
                file_signature = stringifyDigest(
                    "sha256",
                    bytes.fromhex(str(the_file_sha256)),
                )

                include_entity = file_signature == the_signature
                if not include_entity:
                    self.logger.warning(
                        f"Discarding payload {entity_path} for {entity_type} {entity_name} (mismatching digest)"
                    )
            else:
                file_signature = the_signature

        if include_entity:
            assert entity_path is not None
            assert located_entity is not None
            return ROCratePayload(
                rel_path=entity_path,
                path=located_entity,
                signature=file_signature,
            )
        else:
            return None

    def __list_entity_parts(
        self,
        g: "rdflib.graph.Graph",
        entity: "rdflib.term.Identifier",
        public_name: "str",
    ) -> "rdflib.query.Result":
        qlist = rdflib.plugins.sparql.prepareQuery(
            self.LIST_PARTS_SPARQL,
            initNs=self.SPARQL_NS,
        )
        try:
            qlistres = g.query(
                qlist,
                initBindings={
                    "entity": entity,
                },
            )
        except Exception as e:
            raise ROCrateToolboxException(
                f"Unable to perform JSON-LD list entity parts query over {public_name} (see cascading exceptions)"
            ) from e

        return qlistres

    def __list_payload_entity_parts(
        self,
        g: "rdflib.graph.Graph",
        entity: "rdflib.term.Identifier",
        public_name: "str",
        payload_dir: "pathlib.Path",
    ) -> "Sequence[Union[str, ROCratePayload]]":
        entity_parts = self.__list_entity_parts(g, entity, public_name)

        payload_entity_parts = []
        for part_row in entity_parts:
            assert isinstance(
                part_row, rdflib.query.ResultRow
            ), "Check the SPARQL code, as it should be a SELECT query"

            included_part_entity: "Optional[Union[str, ROCratePayload]]" = None
            if is_uri(str(part_row.part_entity)) and not str(
                part_row.part_entity
            ).startswith(self.RELATIVE_ROCRATE_SCHEME + ":"):
                included_part_entity = str(part_row.part_entity)
            else:
                included_part_entity = self.__processPayloadEntity(
                    the_entity=part_row.part_entity,
                    payload_dir=payload_dir,
                    kindobj=ContentKind.File,
                    entity_type="secondary workflow component",
                    entity_name=str(part_row.part_name)
                    if part_row.part_name is not None
                    else "PACO",  # FIXME
                    the_file_size=part_row.file_size,
                    the_file_sha256=part_row.file_sha256,
                )

            if included_part_entity is not None:
                payload_entity_parts.append(included_part_entity)
            else:
                self.logger.warning(
                    f"Entity part {str(part_row.part_entity)} from {str(entity)} in {public_name} did not have a valid payload"
                )

        return payload_entity_parts

    def extractWorkflowMetadata(
        self,
        g: "rdflib.graph.Graph",
        main_entity: "rdflib.term.Identifier",
        default_repo: "Optional[str]",
        public_name: "str",
        payload_dir: "Optional[pathlib.Path]" = None,
    ) -> "Tuple[RemoteRepo, WorkflowType, Optional[LocalWorkflow]]":
        # This query will tell us where the original workflow was located,
        # its language and version
        cached_workflow: "Optional[LocalWorkflow]" = None
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

        if payload_dir is not None:
            workflow_name = langrow.workflow_name
            if langrow.workflow_name is not None:
                workflow_name = langrow.workflow_name
            elif langrow.workflow_alternate_name is not None:
                workflow_name = langrow.workflow_alternate_name
            elif langrow.identifier is not None:
                workflow_name = langrow.identifier
            else:
                workflow_name = None
            include_main_entity = self.__processPayloadEntity(
                the_entity=langrow.origmainentity,
                payload_dir=payload_dir,
                kindobj=ContentKind.File,
                entity_type="main workflow component",
                entity_name=str(workflow_name)
                if workflow_name is not None
                else "PEPE",  # FIXME
                the_file_size=langrow.file_size,
                the_file_sha256=langrow.file_sha256,
            )

            if include_main_entity is not None:
                main_entity_relpath = include_main_entity.rel_path
                main_entity_path = include_main_entity.path

                # TODO
                workflow_parts = self.__list_payload_entity_parts(
                    g, langrow.origmainentity, public_name, payload_dir
                )
                rel_path_files: "MutableSequence[Union[RelPath, URIType]]" = []
                base_dir = main_entity_path.parent
                main_entity_relpath = main_entity_path.name
                if len(workflow_parts) > 0:
                    rel_path_str: "MutableSequence[str]" = []
                    rel_path_index: "MutableSequence[int]" = []
                    for i_part, part in enumerate(workflow_parts):
                        rel_path_file = cast(
                            "RelPath",
                            part.rel_path if isinstance(part, ROCratePayload) else part,
                        )
                        rel_path_files.append(rel_path_file)
                        if isinstance(part, ROCratePayload):
                            rel_path_str.append(rel_path_file)
                            rel_path_index.append(i_part)

                    if len(rel_path_str) > 0:
                        common_prefix = os.path.commonpath(
                            [include_main_entity.rel_path, *rel_path_str]
                        )
                        if len(common_prefix) > 0:
                            base_dir = payload_dir / common_prefix
                            main_entity_relpath = main_entity_path.relative_to(
                                base_dir
                            ).as_posix()
                            for i_part in rel_path_index:
                                part = workflow_parts[i_part]
                                assert isinstance(part, ROCratePayload)
                                rel_path_files[i_part] = cast(
                                    "RelPath",
                                    part.path.relative_to(base_dir).as_posix(),
                                )

                cached_workflow = LocalWorkflow(
                    dir=base_dir,
                    relPath=cast("RelPath", main_entity_relpath),
                    effectiveCheckout=repo.tag,
                    langVersion=cast(
                        "Union[EngineVersion, WFLangVersion]",
                        str(langrow.programminglanguage_version),
                    )
                    if langrow.programminglanguage_version is not None
                    else None,
                    relPathFiles=rel_path_files,
                )

        return repo, workflow_type, cached_workflow

    def generateWorkflowMetaFromJSONLD(
        self,
        jsonld_obj: "Mapping[str, Any]",
        public_name: "str",
        retrospective_first: "bool" = True,
        reproducibility_level: "ReproducibilityLevel" = ReproducibilityLevel.Metadata,
        strict_reproducibility_level: "bool" = False,
        payload_dir: "Optional[pathlib.Path]" = None,
    ) -> "Tuple[RemoteRepo, WorkflowType, ContainerType, ParamsBlock, Optional[Sequence[str]], EnvironmentBlock, OutputsBlock, Optional[LocalWorkflow], Sequence[Container], Optional[Sequence[MaterializedInput]], Optional[Sequence[MaterializedInput]]]":
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

        cached_inputs: "Optional[Sequence[MaterializedInput]]" = None
        cached_environment: "Optional[Sequence[MaterializedInput]]" = None

        # The default crate licences
        crate_licences = self._getLicences(g, matched_crate.mainentity, public_name)

        repo, workflow_type, cached_workflow = self.extractWorkflowMetadata(
            g,
            matched_crate.mainentity,
            default_repo=str(matched_crate.wfhrepourl),
            public_name=public_name,
            payload_dir=payload_dir
            if reproducibility_level >= ReproducibilityLevel.Full
            else None,
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
        num_execs: "int" = 0
        if retrospective_first:
            # For the retrospective provenance at least an execution must
            # be described in the RO-Crate. Once one is chosen,
            # we need to be sure the container solution used then is
            # also supported.
            # So, we are starting with the retrospective provenance
            # gathering the list of containers, to learn
            # which.
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
                num_execs = len(qexecsres)
                for execrow in qexecsres:
                    assert isinstance(
                        execrow, rdflib.query.ResultRow
                    ), "Check the SPARQL code, as it should be a SELECT query"
                    self.logger.debug(f"\tExecution {execrow.execution}")

                    contresult = self._parseContainersFromExecution(
                        g,
                        execrow.execution,
                        main_entity=matched_crate.mainentity,
                        payload_dir=payload_dir
                        if reproducibility_level >= ReproducibilityLevel.Full
                        else None,
                    )
                    # TODO: deal with more than one execution
                    if contresult is None:
                        continue

                    container_type, the_containers = contresult

                    # TODO: which are the needed inputs, to be integrated
                    # into the latter workflow_meta?
                    params, cached_inputs = self._parseInputsFromExecution(
                        g,
                        execrow.execution,
                        main_entity=matched_crate.mainentity,
                        default_licences=crate_licences,
                        public_name=public_name,
                        payload_dir=payload_dir
                        if reproducibility_level >= ReproducibilityLevel.Full
                        else None,
                    )

                    environment, cached_environment = self._parseEnvFromExecution(
                        g,
                        execrow.execution,
                        main_entity=matched_crate.mainentity,
                        default_licences=crate_licences,
                        public_name=public_name,
                        payload_dir=payload_dir
                        if reproducibility_level >= ReproducibilityLevel.Full
                        else None,
                    )

                    outputs = self._parseOutputsFromExecution(
                        g,
                        execrow.execution,
                        main_entity=matched_crate.mainentity,
                        public_name=public_name,
                    )

                    # TODO: deal with more than one execution
                    # Now, let's check the list of captured input parameters
                    if len(params) == 0:
                        break
            except Exception as e:
                raise ROCrateToolboxException(
                    f"Unable to perform JSON-LD workflow execution details query over {public_name} (see cascading exceptions)"
                ) from e

        # Following the prospective path
        if len(params) == 0:
            if retrospective_first and num_execs > 0:
                self.logger.warning(
                    f"No params found associated to {num_execs} executions"
                )
            contresult = self._parseContainersFromWorkflow(
                g,
                main_entity=matched_crate.mainentity,
                payload_dir=payload_dir
                if reproducibility_level >= ReproducibilityLevel.Full
                else None,
            )
            # TODO: deal with more than one execution
            if contresult is not None:
                container_type, the_containers = contresult

            params, cached_inputs = self._parseInputsFromMainEntity(
                g,
                main_entity=matched_crate.mainentity,
                default_licences=crate_licences,
                public_name=public_name,
                payload_dir=payload_dir
                if reproducibility_level >= ReproducibilityLevel.Full
                else None,
            )

            environment, cached_environment = self._parseEnvFromMainEntity(
                g,
                main_entity=matched_crate.mainentity,
                default_licences=crate_licences,
                public_name=public_name,
                payload_dir=payload_dir
                if reproducibility_level >= ReproducibilityLevel.Full
                else None,
            )

        if len(outputs) == 0:
            outputs = self._parseOutputsFromMainEntity(
                g,
                main_entity=matched_crate.mainentity,
                public_name=public_name,
            )

        # TODO: finish
        assert container_type is not None

        # This postprocessing is needed to declare the parameters
        # which are really outputs
        if not workflow_type.has_explicit_outputs:
            new_params = cast("MutableParamsBlock", copy.copy(params))
            for output_name, output_decl in outputs.items():
                if not output_decl.get("syntheticOutput", False):
                    # Additional check
                    fill_from = output_decl.get("fillFrom")
                    if fill_from != output_name:
                        self.logger.warning(
                            f"fillFrom property differs from what it is expected: {fill_from} vs {output_name} . Fixing"
                        )
                        output_decl["fillFrom"] = output_name
                    # Now, inject an input
                    new_params[output_name] = {
                        "c-l-a-s-s": output_decl["c-l-a-s-s"],
                        "autoFill": True,
                        "autoPrefix": True,
                    }
            params = new_params

        # Beware!! This is a tweak!!
        profiles: "Optional[Sequence[str]]" = params.get("-profile")
        if profiles is not None:
            new_params = cast("MutableParamsBlock", copy.copy(params))
            del new_params["-profile"]
            params = new_params

        return (
            repo,
            workflow_type,
            container_type,
            params,
            profiles,
            environment,
            outputs,
            cached_workflow,
            the_containers,
            cached_inputs,
            cached_environment,
        )
