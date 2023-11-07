#!/usr/bin/env python
# -*- coding: utf-8 -*-

# SPDX-License-Identifier: Apache-2.0
# Copyright 2020-2023 Barcelona Supercomputing Center (BSC), Spain
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

import atexit
import copy
import enum
import inspect
import logging
import os
import pathlib
import subprocess
import tempfile
from typing import (
    cast,
    NamedTuple,
    TYPE_CHECKING,
)
import warnings

if TYPE_CHECKING:
    import datetime

    from typing import (
        Any,
        Mapping,
        MutableMapping,
        MutableSequence,
        Optional,
        Sequence,
        Tuple,
        Type,
        Union,
    )

    from typing_extensions import (
        Final,
    )

    from .common import (
        AbsPath,
        AbstractGeneratedContent,
        AnyPath,
        ContainerEngineVersionStr,
        ContainerOperatingSystem,
        EngineVersion,
        ExpectedOutput,
        Fingerprint,
        LocalWorkflow,
        MaterializedInput,
        MaterializedOutput,
        ProcessorArchitecture,
        ProgsMapping,
        RelPath,
        RemoteRepo,
        RepoTag,
        RepoURL,
        StagedExecution,
        StagedSetup,
        SymbolicOutputName,
        URIType,
        WFLangVersion,
        WorkflowEngineVersionStr,
    )

    from .container import (
        Container,
    )

    from .engine import (
        MaterializedWorkflowEngine,
        WorkflowType,
    )

    from .fetchers.internal.orcid import (
        ORCIDPublicRecord,
    )

import urllib.parse
import uuid

import magic
from rfc6920.methods import extract_digest
import rocrate.model.entity
import rocrate.model.dataset
import rocrate.model.computationalworkflow
import rocrate.model.computerlanguage
import rocrate.model.file
import rocrate.model.file_or_dir
import rocrate.model.metadata
import rocrate.model.person
import rocrate.model.softwareapplication
import rocrate.model.creativework
import rocrate.rocrate

from rocrate.utils import (
    get_norm_value,
    is_url,
)

from .fetchers import (
    FetcherException,
)

from .fetchers.internal.orcid import (
    validate_orcid,
)

from .utils.digests import (
    ComputeDigestFromDirectory,
    ComputeDigestFromFile,
    ComputeDigestFromObject,
    hexDigest,
    nullProcessDigest,
    unstringifyDigest,
)
from .utils.marshalling_handling import (
    marshall_namedtuple,
)
from .common import (
    AbstractWfExSException,
    ContainerType,
    ContentKind,
    CratableItem,
    DEFAULT_DOT_CMD,
    GeneratedContent,
    GeneratedDirectoryContent,
    MaterializedContent,
    META_JSON_POSTFIX,
    NoCratableItem,
    NoLicence,
)

from .utils.licences import (
    AcceptableLicenceSchemes,
    NoLicenceShort,
    CC_BY_40_LICENCE,
    ROCrateLongLicences,
    ROCrateShortLicences,
)

from . import __url__ as wfexs_backend_url
from . import __official_name__ as wfexs_backend_name
from . import get_WfExS_version_str


class ROCrateGenerationException(AbstractWfExSException):
    pass


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
            # As of https://www.researchobject.org/ro-crate/1.1/workflows.html#describing-inputs-and-outputs
            "conformsTo": {
                "@id": "https://bioschemas.org/profiles/FormalParameter/1.0-RELEASE/",
            },
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


class Intangible(rocrate.model.entity.Entity):  # type: ignore[misc]
    """
    Although an intangible is a more general concept than PropertyValue
    keep them isolated for now.
    """

    def __init__(
        self,
        crate: "rocrate.rocrate.ROCrate",
        name: "str",
        additionalType: "Optional[str]" = None,
        identifier: "Optional[str]" = None,
        properties: "Optional[Mapping[str, Any]]" = None,
    ):
        pv_properties = {
            "name": name,
        }

        if additionalType is not None:
            pv_properties["additionalType"] = additionalType

        if properties is not None:
            pv_properties.update(properties)
        super().__init__(crate, identifier=identifier, properties=pv_properties)


class ContactPoint(rocrate.model.entity.Entity):
    def __init__(
        self,
        crate: "rocrate.rocrate.ROCrate",
        contactType: "str",
        identifier: "str",
        properties: "Optional[Mapping[str, Any]]" = None,
    ):
        cp_properties = {
            "contactType": contactType,
        }

        if properties is not None:
            cp_properties.update(properties)
        super().__init__(crate, identifier=identifier, properties=cp_properties)


class Action(rocrate.model.entity.Entity):  # type: ignore[misc]
    def __init__(
        self,
        crate: "rocrate.rocrate.ROCrate",
        name: "str",
        startTime: "Optional[datetime.datetime]" = None,
        endTime: "Optional[datetime.datetime]" = None,
        identifier: "Optional[str]" = None,
        properties: "Optional[Mapping[str, Any]]" = None,
    ):
        pv_properties = {
            "name": name,
        }
        if startTime is not None:
            pv_properties["startTime"] = startTime.isoformat()
        if endTime is not None:
            pv_properties["endTime"] = endTime.isoformat()

        if properties is not None:
            pv_properties.update(properties)
        super().__init__(crate, identifier=identifier, properties=pv_properties)


class CreateAction(Action):
    pass


class OrganizeAction(Action):
    pass


class ControlAction(Action):
    pass


class Collection(rocrate.model.creativework.CreativeWork):  # type: ignore[misc]
    def __init__(
        self,
        crate: "rocrate.rocrate.ROCrate",
        main_entity: "Union[FixedFile, FixedDataset, Collection, None]",
        identifier: "Optional[str]" = None,
        properties: "Optional[Mapping[str, Any]]" = None,
    ):
        pv_properties: "MutableMapping[str, Any]" = {}

        if properties is not None:
            pv_properties.update(properties)
        super().__init__(crate, identifier=identifier, properties=pv_properties)

        if main_entity is not None:
            self["mainEntity"] = main_entity


class FixedMixin(rocrate.model.file_or_dir.FileOrDir):  # type: ignore[misc]
    def __init__(
        self,
        crate: "rocrate.rocrate.ROCrate",
        source: "Optional[Union[str, pathlib.Path]]" = None,
        dest_path: "Optional[Union[str, pathlib.Path]]" = None,
        identifier: "Optional[str]" = None,
        fetch_remote: "bool" = False,
        validate_url: "bool" = False,
        properties: "Optional[Mapping[str, Any]]" = None,
    ):
        if properties is None:
            properties = {}
        self.fetch_remote = fetch_remote
        self.validate_url = validate_url
        self.source = source
        if dest_path is not None:
            dest_path = pathlib.Path(dest_path)
            if dest_path.is_absolute():
                raise ValueError("if provided, dest_path must be relative")
            if identifier is None:
                identifier = dest_path.as_posix()
        elif identifier is None:
            if not isinstance(source, (str, pathlib.Path)):
                raise ValueError(
                    "dest_path must be provided if source is not a path or URI"
                )
            elif is_url(str(source)):
                identifier = os.path.basename(source) if fetch_remote else str(source)
            else:
                identifier = "./" if source == "./" else os.path.basename(source)
        super(rocrate.model.file_or_dir.FileOrDir, self).__init__(
            crate, identifier, properties
        )


class FixedFile(FixedMixin, rocrate.model.file.File):  # type: ignore[misc]
    pass


WORKFLOW_RUN_CONTEXT: "Final[str]" = "https://w3id.org/ro/terms/workflow-run"


class ContainerImageAdditionalType(enum.Enum):
    Docker = WORKFLOW_RUN_CONTEXT + "#DockerImage"
    Singularity = WORKFLOW_RUN_CONTEXT + "#SIFImage"


ContainerType2AdditionalType: "Mapping[ContainerType, ContainerImageAdditionalType]" = {
    ContainerType.Docker: ContainerImageAdditionalType.Docker,
    ContainerType.Singularity: ContainerImageAdditionalType.Singularity,
    ContainerType.Podman: ContainerImageAdditionalType.Docker,
}


class ContainerImage(rocrate.model.entity.Entity):  # type: ignore[misc]
    TYPES = ["ContainerImage", "SoftwareApplication"]

    def __init__(
        self,
        crate: "rocrate.rocrate.ROCrate",
        name: "str",
        container_type: "ContainerType",
        registry: "Optional[str]" = None,
        tag: "Optional[str]" = None,
        identifier: "Optional[str]" = None,
        properties: "Optional[Mapping[str, Any]]" = None,
    ):
        fp_properties = self._prepare_properties(
            name,
            container_type,
            registry=registry,
            tag=tag,
            properties=properties,
        )
        super().__init__(crate, identifier=identifier, properties=fp_properties)

    def _empty(self) -> "Mapping[str, Any]":
        return {
            "@id": self.id,
            "@type": self.TYPES[:],
        }

    @staticmethod
    def _prepare_properties(
        name: "str",
        container_type: "ContainerType",
        registry: "Optional[str]" = None,
        tag: "Optional[str]" = None,
        properties: "Optional[Mapping[str, Any]]" = None,
    ) -> "Mapping[str, Any]":
        additional_type = ContainerType2AdditionalType.get(container_type)
        if additional_type is None:
            raise ValueError(
                f"Unable to map container type {container_type.value} to an RO-Crate equivalent"
            )
        fp_properties = {
            "name": name,
            "additionalType": {
                "@id": additional_type.value,
            },
        }

        if registry is not None:
            fp_properties["registry"] = registry

        if tag is not None:
            fp_properties["tag"] = tag

        if properties is not None:
            fp_properties.update(properties)

        return fp_properties


# Multiple inheritance order does matter when super is called!!!!
class MaterializedContainerImage(ContainerImage, FixedFile):  # type: ignore[misc]
    TYPES = ["File", "ContainerImage", "SoftwareApplication"]

    def __init__(
        self,
        crate: "rocrate.rocrate.ROCrate",
        container_type: "ContainerType",
        registry: "Optional[str]" = None,
        name: "str" = "",
        tag: "Optional[str]" = None,
        identifier: "Optional[str]" = None,
        source: "Optional[Union[str, pathlib.Path]]" = None,
        dest_path: "Optional[Union[str, pathlib.Path]]" = None,
        properties: "Optional[Mapping[str, Any]]" = None,
    ):
        fp_properties = self._prepare_properties(
            name,
            container_type,
            registry=registry,
            tag=tag,
            properties=properties,
        )

        super(FixedFile, self).__init__(
            crate=crate,
            source=source,
            dest_path=dest_path,
            identifier=identifier,
            fetch_remote=False,
            validate_url=False,
            properties=fp_properties,
        )


class WorkflowDiagram(FixedFile):  # type: ignore[misc]
    TYPES = ["File", "ImageObject"]

    def _empty(self) -> "Mapping[str, Any]":
        return {
            "@id": self.id,
            "@type": self.TYPES[:],
        }


class SourceCodeFile(FixedFile):  # type: ignore[misc]
    TYPES = ["File", "SoftwareSourceCode"]

    def _empty(self) -> "Mapping[str, Any]":
        return {
            "@id": self.id,
            "@type": self.TYPES[:],
        }


class FixedDataset(FixedMixin, rocrate.model.dataset.Dataset):  # type: ignore[misc]
    pass


class FixedWorkflow(FixedMixin, rocrate.model.computationalworkflow.ComputationalWorkflow):  # type: ignore[misc]
    TYPES = [
        "File",
        "SoftwareSourceCode",
        "ComputationalWorkflow",
        "SoftwareApplication",
    ]


class FixedROCrate(rocrate.rocrate.ROCrate):  # type: ignore[misc]
    """
    This subclass fixes the limitations from original ROCrate class
    """

    def add_file(
        self,
        source: "Optional[Union[str, pathlib.Path]]" = None,
        dest_path: "Optional[str]" = None,
        fetch_remote: "bool" = False,
        validate_url: "bool" = False,
        properties: "Optional[Mapping[str, Any]]" = None,
    ) -> "FixedFile":
        return self.add_file_ext(
            source=source,
            dest_path=dest_path,
            fetch_remote=fetch_remote,
            validate_url=validate_url,
            properties=properties,
        )

    def add_file_ext(
        self,
        source: "Optional[Union[str, pathlib.Path]]" = None,
        dest_path: "Optional[str]" = None,
        identifier: "Optional[str]" = None,
        fetch_remote: "bool" = False,
        validate_url: "bool" = False,
        properties: "Optional[Mapping[str, Any]]" = None,
        clazz: "Type[FixedFile]" = FixedFile,
    ) -> "FixedFile":
        """
        source: The absolute path to the local copy of the file, if exists.
        dest_path: The relative path inside the RO-Crate for the file copy.
        identifier: The forced value for the @id of the File declaration.
        """
        return self.add(
            clazz(
                self,
                source=source,
                dest_path=dest_path,
                identifier=identifier,
                fetch_remote=fetch_remote,
                validate_url=validate_url,
                properties=properties,
            )
        )

    def add_dataset(
        self,
        source: "Optional[Union[str, pathlib.Path]]" = None,
        dest_path: "Optional[str]" = None,
        fetch_remote: "bool" = False,
        validate_url: "bool" = False,
        properties: "Optional[Mapping[str, Any]]" = None,
    ) -> "FixedDataset":
        return self.add_dataset_ext(
            source=source,
            dest_path=dest_path,
            fetch_remote=fetch_remote,
            validate_url=validate_url,
            properties=properties,
        )

    def add_dataset_ext(
        self,
        source: "Optional[Union[str, pathlib.Path]]" = None,
        dest_path: "Optional[str]" = None,
        identifier: "Optional[str]" = None,
        fetch_remote: "bool" = False,
        validate_url: "bool" = False,
        properties: "Optional[Mapping[str, Any]]" = None,
    ) -> "FixedDataset":
        """
        source: The absolute path to the local copy of the file, if exists.
        dest_path: The relative path inside the RO-Crate for the file copy.
        identifier: The forced value for the @id of the File declaration.
        """
        return self.add(
            FixedDataset(
                self,
                source=source,
                dest_path=dest_path,
                identifier=identifier,
                fetch_remote=fetch_remote,
                validate_url=validate_url,
                properties=properties,
            )
        )

    add_directory = add_dataset

    def add_workflow(
        self,
        source: "Optional[Union[str, pathlib.Path]]" = None,
        dest_path: "Optional[str]" = None,
        fetch_remote: "bool" = False,
        validate_url: "bool" = False,
        properties: "Optional[Mapping[str, Any]]" = None,
        main: "bool" = False,
        lang: "Union[str, rocrate.model.computerlanguage.ComputerLanguage]" = "cwl",
        lang_version: "Optional[str]" = None,
        gen_cwl: "bool" = False,
        cls: "Type[rocrate.model.computationalworkflow.ComputationalWorkflow]" = FixedWorkflow,
    ) -> "FixedWorkflow":
        return self.add_workflow_ext(
            source=source,
            dest_path=dest_path,
            fetch_remote=fetch_remote,
            validate_url=validate_url,
            properties=properties,
            main=main,
            lang=lang,
            lang_version=lang_version,
            gen_cwl=gen_cwl,
            cls=cls,
        )

    def add_workflow_ext(
        self,
        source: "Optional[Union[str, pathlib.Path]]" = None,
        dest_path: "Optional[str]" = None,
        identifier: "Optional[str]" = None,
        fetch_remote: "bool" = False,
        validate_url: "bool" = False,
        properties: "Optional[Mapping[str, Any]]" = None,
        main: "bool" = False,
        lang: "Union[str, rocrate.model.computerlanguage.ComputerLanguage]" = "cwl",
        lang_version: "Optional[str]" = None,
        gen_cwl: "bool" = False,
        cls: "Type[rocrate.model.computationalworkflow.ComputationalWorkflow]" = FixedWorkflow,
    ) -> "FixedWorkflow":
        workflow: "rocrate.model.computationalworkflow.ComputationalWorkflow"
        if issubclass(cls, FixedWorkflow):
            workflow = self.add(
                cls(
                    self,
                    source=source,
                    dest_path=dest_path,
                    identifier=identifier,
                    fetch_remote=fetch_remote,
                    validate_url=validate_url,
                    properties=properties,
                )
            )
        else:
            workflow = self.add(
                cls(
                    self,
                    source=source,
                    dest_path=dest_path,
                    fetch_remote=fetch_remote,
                    validate_url=validate_url,
                    properties=properties,
                )
            )
        if isinstance(lang, rocrate.model.computerlanguage.ComputerLanguage):
            assert lang.crate is self
        else:
            lang = rocrate.model.computerlanguage.get_lang(
                self, lang, version=lang_version
            )
            self.add(lang)
        lang_str = lang.id.rsplit("#", 1)[1]
        workflow.lang = lang
        if main:
            self.mainEntity = workflow
            profiles = set(
                _.rstrip("/") for _ in get_norm_value(self.metadata, "conformsTo")
            )
            profiles.add(rocrate.model.metadata.WORKFLOW_PROFILE)
            self.metadata["conformsTo"] = [{"@id": _} for _ in sorted(profiles)]
        if gen_cwl and lang_str != "cwl":
            assert source is not None
            if lang_str != "galaxy":
                raise ValueError(
                    f"conversion from {lang.name} to abstract CWL not supported"
                )
            cwl_source = rocrate.model.computationalworkflow.galaxy_to_abstract_cwl(
                source
            )
            cwl_dest_path = pathlib.Path(source).with_suffix(".cwl").name
            cwl_workflow = self.add_workflow_ext(
                source=cwl_source,
                dest_path=cwl_dest_path,
                fetch_remote=fetch_remote,
                properties=properties,
                main=False,
                lang="cwl",
                gen_cwl=False,
                cls=rocrate.model.computationalworkflow.WorkflowDescription,
            )
            workflow.subjectOf = cwl_workflow
        return cast("FixedWorkflow", workflow)


class ContainerTypeMetadata(NamedTuple):
    sa_id: "str"
    applicationCategory: "str"
    ct_applicationCategory: "str"


class WorkflowRunROCrate:
    """
    This class rules the generation of an RO-Crate
    """

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

    def __init__(
        self,
        remote_repo: "RemoteRepo",
        workflow_pid: "Optional[str]",
        localWorkflow: "LocalWorkflow",
        materializedEngine: "MaterializedWorkflowEngine",
        workflowEngineVersion: "Optional[WorkflowEngineVersionStr]",
        containerEngineVersion: "Optional[ContainerEngineVersionStr]",
        containerEngineOs: "Optional[ContainerOperatingSystem]",
        arch: "Optional[ProcessorArchitecture]",
        staged_setup: "StagedSetup",
        payloads: "CratableItem" = NoCratableItem,
        licences: "Sequence[str]" = [],
        orcids: "Sequence[str]" = [],
        progs: "ProgsMapping" = {},
        tempdir: "Optional[str]" = None,
        scheme_desc: "Sequence[Tuple[str, str]]" = [],
        crate_pid: "Optional[str]" = None,
    ):
        # Getting a logger focused on specific classes
        self.logger = logging.getLogger(
            dict(inspect.getmembers(self))["__module__"]
            + "::"
            + self.__class__.__name__
        )

        # Saving the path to needed programs
        # (right now "dot" to translate the diagram)
        self.dot_binary = progs.get(DEFAULT_DOT_CMD, DEFAULT_DOT_CMD)

        # Where should be place generated temporary files?
        self.tempdir = tempdir

        self.cached_cts: "MutableMapping[ContainerType, rocrate.model.softwareapplication.SoftwareApplication]" = (
            {}
        )

        # This is used to avoid including twice the very same value
        # in the RO-Crate
        self._item_hash: "MutableMapping[bytes, rocrate.model.entity.Entity]" = {}
        self._added_containers: "MutableSequence[Container]" = []
        self._wf_to_containers: "MutableMapping[str, MutableSequence[ContainerImage]]" = (
            {}
        )
        self._wf_to_operational_containers: "MutableMapping[str, MutableSequence[ContainerImage]]" = (
            {}
        )
        self._wf_to_container_sa: "MutableMapping[str, rocrate.model.softwareapplication.SoftwareApplication]" = (
            {}
        )

        if len(licences) == 0:
            licences = [NoLicenceShort]

        if localWorkflow.relPath is not None:
            wf_local_path = os.path.join(localWorkflow.dir, localWorkflow.relPath)
        else:
            wf_local_path = localWorkflow.dir

        self.arch = arch
        self.containerEngineOs = containerEngineOs
        self.containerEngineVersion = containerEngineVersion

        assert staged_setup.work_dir is not None
        assert staged_setup.inputs_dir is not None
        self.staged_setup = staged_setup
        self.work_dir = staged_setup.work_dir
        self.payloads = payloads

        self.crate: "FixedROCrate"
        self.compLang: "rocrate.model.computerlanguage.ComputerLanguage"
        self._init_empty_crate_and_ComputerLanguage(
            materializedEngine.instance.workflowType,
            localWorkflow.langVersion,
            licences,
            crate_pid=crate_pid,
        )

        # add agents
        self._agents: "MutableSequence[rocrate.model.person.Person]" = []
        failed_orcids: "MutableSequence[str]" = []
        for orcid in orcids:
            # validate ORCID asking for its public metadata
            try:
                val_res = validate_orcid(orcid)
                if val_res is not None:
                    agent = rocrate.model.person.Person(
                        self.crate, identifier=val_res[1]
                    )

                    # enrich agent entry from the metadata obtained from the ORCID
                    agent_name = val_res[2].get("displayName")
                    if agent_name is not None:
                        agent["name"] = agent_name

                    emails_dict = val_res[2].get("emails", {})
                    if isinstance(emails_dict, dict):
                        emails = emails_dict.get("emails", [])
                        if isinstance(emails, list):
                            for email_entry in emails:
                                if isinstance(email_entry, dict):
                                    the_email = email_entry.get("value")
                                    if the_email is not None:
                                        contact_point = ContactPoint(
                                            self.crate,
                                            identifier="mailto:" + the_email,
                                            contactType="Author",
                                        )
                                        contact_point["email"] = the_email
                                        contact_point["identifier"] = the_email
                                        contact_point["url"] = val_res[1]

                                        self.crate.add(contact_point)
                                        agent.append_to(
                                            "contactPoint", contact_point, compact=True
                                        )

                    self.crate.add(agent)
                    self._agents.append(agent)
            except FetcherException as fe:
                self.logger.exception(f"Error validating ORCID {orcid}")

        if len(failed_orcids) > 0:
            raise ROCrateGenerationException(
                f"{len(failed_orcids)} of {len(orcids)} ORCIDs were not valid: {', '.join(failed_orcids)}"
            )

        self.wf_wfexs = self._add_wfexs_to_crate(scheme_desc)

        # Description of the workflow engine as a software application
        self.weng_crate = rocrate.model.softwareapplication.SoftwareApplication(
            self.crate, identifier=materializedEngine.instance.engine_url
        )
        self.crate.add(self.weng_crate)
        if workflowEngineVersion is not None:
            self.weng_crate["softwareVersion"] = workflowEngineVersion

        # It should have the operational containers
        if materializedEngine.operational_containers is not None:
            self._add_containers(
                materializedEngine.operational_containers,
                sa_crate=self.weng_crate,
            )

        # TODO: research why relPathFiles is not populated sometimes in matWf
        matWf = materializedEngine.workflow
        ran_is_original = (
            localWorkflow.dir == matWf.dir and localWorkflow.relPath == matWf.relPath
        )
        original_workflow_crate = self._add_workflow_to_crate(
            localWorkflow,
            lang=self.compLang,
            the_uri=workflow_pid,
            the_description="Workflow Entrypoint"
            if ran_is_original
            else "Unconsolidated Workflow Entrypoint",
            the_weng_crate=self.weng_crate,
            materialized_engine=materializedEngine,
            main=ran_is_original,
            remote_repo=remote_repo,
            gen_cwl=False,
            do_attach=CratableItem.Workflow in payloads,
            was_workflow_run=ran_is_original,
        )

        ran_workflow_crate: "FixedWorkflow"
        if not ran_is_original:
            ran_workflow_crate = self._add_workflow_to_crate(
                matWf,
                lang=self.compLang,
                the_description="Consolidated Workflow Entrypoint",
                the_weng_crate=self.weng_crate,
                materialized_engine=materializedEngine,
                main=True,
                gen_cwl=False,
                do_attach=True,
            )
            ran_workflow_crate["isBasedOn"] = original_workflow_crate

            # Now, describe the transformation
            wf_consolidate_action = CreateAction(self.crate, "Workflow consolidation")
            wf_consolidate_action = self.crate.add(wf_consolidate_action)
            wf_consolidate_action["object"] = original_workflow_crate
            wf_consolidate_action["result"] = ran_workflow_crate
            # instruments: "MutableSequence[rocrate.model.entity.Entity]" = [
            #     self.wf_wfexs,
            #     self.weng_crate,
            # ]
            # if ran_workflow_crate.id in self._wf_to_operational_containers:
            #     if ran_workflow_crate.id in self._wf_to_container_sa:
            #         instruments.append(self._wf_to_container_sa[ran_workflow_crate.id])
            #     instruments.extend(
            #         self._wf_to_operational_containers[ran_workflow_crate.id]
            #     )
            wf_consolidate_action.append_to("instrument", self.wf_wfexs, compact=True)
            wf_consolidate_action.append_to(
                "actionStatus",
                {"@id": "http://schema.org/CompletedActionStatus"},
                compact=True,
            )
            if len(self._agents) > 0:
                wf_consolidate_action.append_to("agent", self._agents, compact=True)
        else:
            ran_workflow_crate = original_workflow_crate

        # From now on, we use this elsewhere
        self.wf_file = ran_workflow_crate

        # TODO: add extra files, like the diagram, an abstract CWL
        # representation of the workflow (when it is not a CWL workflow)
        # etc...
        # for file_entry in include_files:
        #    self.crate.add_file(file_entry)

    def _init_empty_crate_and_ComputerLanguage(
        self,
        wf_type: "WorkflowType",
        langVersion: "Optional[Union[EngineVersion, WFLangVersion]]",
        licences: "Sequence[str]",
        crate_pid: "Optional[str]",
    ) -> "None":
        """
        Due the internal synergies between an instance of ComputerLanguage
        and the RO-Crate it is attached to, both of them should be created
        here, just at the same time
        """

        # Let's check the licences
        rejected_lics: "MutableSequence[str]" = []
        for lic in licences:
            if lic in ROCrateShortLicences:
                continue
            if urllib.parse.urlparse(lic).scheme in AcceptableLicenceSchemes:
                continue

            rejected_lics.append(lic)

        if len(rejected_lics) > 0:
            raise ROCrateGenerationException(
                f"Unsupported Workflow RO-Crate short license(s) or license URI scheme(s): {', '.join(rejected_lics)}"
            )

        self.crate = FixedROCrate(gen_preview=False)
        if crate_pid is not None:
            self.crate.root_dataset.append_to("identifier", crate_pid, compact=True)

        RO_licences = self._process_licences(licences)

        # Add extra terms
        # self.crate.metadata.extra_terms.update(
        #     {
        #         "sha256": WORKFLOW_RUN_CONTEXT + "#sha256",
        #         # Next ones are experimental
        #         ContainerImageAdditionalType.Docker.value: WORKFLOW_RUN_CONTEXT + "#"
        #         + ContainerImageAdditionalType.Docker.value,
        #         ContainerImageAdditionalType.Singularity.value: WORKFLOW_RUN_CONTEXT + "#"
        #         + ContainerImageAdditionalType.Singularity.value,
        #         "containerImage": WORKFLOW_RUN_CONTEXT + "#containerImage",
        #         "ContainerImage": WORKFLOW_RUN_CONTEXT + "#ContainerImage",
        #         "registry": WORKFLOW_RUN_CONTEXT + "#registry",
        #         "tag": WORKFLOW_RUN_CONTEXT + "#tag",
        #     }
        # )
        self.crate.metadata.extra_contexts.append(WORKFLOW_RUN_CONTEXT)

        self.compLang = rocrate.model.computerlanguage.ComputerLanguage(
            self.crate,
            identifier=wf_type.rocrate_programming_language,
            properties={
                "name": wf_type.name,
                "alternateName": wf_type.trs_descriptor,
                "identifier": {"@id": wf_type.uriTemplate.format(langVersion)},
                "url": {"@id": wf_type.url},
                "version": langVersion,
            },
        )
        self.crate.description = f"RO-Crate from staged WfExS working directory {self.staged_setup.instance_id} ({self.staged_setup.nickname})"
        self.crate.root_dataset.append_to("license", RO_licences, compact=True)
        # This should not be needed, as it is added later
        self.crate.add(self.compLang)

    def _process_licences(
        self, licences: "Sequence[str]"
    ) -> "Sequence[Union[str, rocrate.model.creativework.CreativeWork]]":
        RO_licences: "MutableSequence[Union[str, rocrate.model.creativework.CreativeWork]]" = (
            []
        )
        for lic in licences:
            RO_licences.append(self._process_licence(lic))

        return RO_licences

    def _process_licence(
        self, licence: "str"
    ) -> "Union[str, rocrate.model.creativework.CreativeWork]":
        # In order to avoid so prominent "No Permission url"
        if licence == NoLicence:
            licence = NoLicenceShort

        parsed_lic: "Union[str, rocrate.model.creativework.CreativeWork]"
        rec_lic: "bool" = False
        if licence in ROCrateShortLicences:
            if licence == NoLicenceShort:
                parsed_lic = licence
            else:
                licdesc = ROCrateShortLicences[licence]
                cw = cast(
                    "Optional[rocrate.model.creativework.CreativeWork]",
                    self.crate.dereference(licdesc.uri),
                )
                if cw is None:
                    rec_lic = True
                    parsed_lic = rocrate.model.creativework.CreativeWork(
                        self.crate,
                        identifier=licdesc.uri,
                        properties={
                            "identifier": licdesc.uri,
                            "name": licdesc.description,
                        },
                    )
                else:
                    parsed_lic = cw
        elif licence in ROCrateLongLicences:
            licdesc = ROCrateLongLicences[licence]
            cw = cast(
                "Optional[rocrate.model.creativework.CreativeWork]",
                self.crate.dereference(licdesc.uri),
            )
            if cw is None:
                rec_lic = True
                parsed_lic = rocrate.model.creativework.CreativeWork(
                    self.crate,
                    identifier=licdesc.uri,
                    properties={
                        "identifier": licdesc.uri,
                        "name": licdesc.description,
                    },
                )
            else:
                parsed_lic = cw
        else:
            cw = cast(
                "Optional[rocrate.model.creativework.CreativeWork]",
                self.crate.dereference(licence),
            )
            if cw is None:
                rec_lic = True
                parsed_lic = rocrate.model.creativework.CreativeWork(
                    self.crate,
                    identifier=licence,
                    properties={
                        "identifier": licence,
                    },
                )
            else:
                parsed_lic = cw

        if rec_lic and isinstance(parsed_lic, rocrate.model.creativework.CreativeWork):
            self.crate.add(parsed_lic)

        return parsed_lic

    def _add_wfexs_to_crate(
        self, scheme_desc: "Sequence[Tuple[str, str]]"
    ) -> "rocrate.model.softwareapplication.SoftwareApplication":
        # First, the profiles to be attached to the root dataset
        wrroc_profiles = [
            rocrate.model.creativework.CreativeWork(
                self.crate,
                identifier="https://w3id.org/ro/wfrun/process/0.3",
                properties={"name": "ProcessRun Crate", "version": "0.3"},
            ),
            rocrate.model.creativework.CreativeWork(
                self.crate,
                identifier="https://w3id.org/ro/wfrun/workflow/0.3",
                properties={"name": "Workflow Run Crate", "version": "0.3"},
            ),
            # TODO: This one can be enabled only when proper provenance
            # describing the execution steps is implemented
            # rocrate.model.creativework.CreativeWork(
            #     self.crate,
            #     identifier="https://w3id.org/ro/wfrun/provenance/0.3",
            #     properties={"name": "Provenance Run Crate", "version": "0.3"},
            # ),
            rocrate.model.creativework.CreativeWork(
                self.crate,
                identifier="https://w3id.org/workflowhub/workflow-ro-crate/1.0",
                properties={"name": "Workflow RO-Crate", "version": "1.0"},
            ),
        ]
        self.crate.add(*wrroc_profiles)
        self.crate.root_dataset.append_to("conformsTo", wrroc_profiles, compact=True)

        # Now, WfExS reference as such
        wf_wfexs = rocrate.model.softwareapplication.SoftwareApplication(
            self.crate, identifier=wfexs_backend_url
        )
        wf_wfexs = self.crate.add(wf_wfexs)
        wf_wfexs["name"] = wfexs_backend_name
        wf_wfexs.url = wfexs_backend_url
        verstr = get_WfExS_version_str()
        wf_wfexs["softwareVersion"] = verstr

        # And the README.md
        readme_md_handle, readme_md_path = tempfile.mkstemp(
            prefix="WfExS", suffix="README", dir=self.tempdir
        )
        # Registering for removal the temporary file
        atexit.register(os.unlink, readme_md_path)
        with os.fdopen(readme_md_handle, mode="w", encoding="utf-8") as wMD:
            scheme_desc_str = "\n\n* ".join(
                map(lambda sd: f"`{sd[0]}`: {sd[1]}", scheme_desc)
            )
            print(
                f"""\
# Notes about this generated RO-Crate

{self.crate.description}

This RO-Crate has been generated by {wfexs_backend_name} {verstr} ,
whose sources are available at {wfexs_backend_url}.

## Software containers and metadata

Metadata files which are produced and consumed by {wfexs_backend_name} in
order to properly detect when a local cached copy of a software container
is stale are also included in this RO-Crate. These files are in JSON format.

In case this RO-Crate also contains a copy of the software containers,
their format will depend on whether they are going to be consumed by
Singularity / Apptainer, or they are going to be consumed by Docker or Podman.

Singularity / Apptainer images usually have the singularity image format.

Both Docker and Podman images are compressed tar archives obtained through
either `docker save` or `podman save` commands. These archives have all
the layers needed to restore the container image in a local registry
through either `docker load` or `podman load`.

## Posibly used URI schemes

As {wfexs_backend_name} is able to manage several exotic CURIEs and schemes,
you can find here an almost complete list of the possible ones:

* {scheme_desc_str}
""",
                file=wMD,
            )

        readme_file = self._add_file_to_crate(
            readme_md_path,
            the_uri=None,
            the_name=cast("RelPath", "README.md"),
            the_mime="text/markdown",
            the_licences=[CC_BY_40_LICENCE],
        )
        readme_file.append_to("about", self.crate.root_dataset, compact=True)

        return wf_wfexs

    def _add_containers(
        self,
        containers: "Sequence[Container]",
        sa_crate: "Union[rocrate.model.computationalworkflow.ComputationalWorkflow, rocrate.model.softwareapplication.SoftwareApplication]",
        the_workflow_crate: "Optional[FixedWorkflow]" = None,
    ) -> "MutableSequence[ContainerImage]":
        # Operational containers are needed by the workflow engine, not by the workflow
        added_containers: "MutableSequence[ContainerImage]" = []
        if len(containers) > 0:
            do_attach = CratableItem.Containers in self.payloads
            for container in containers:
                # Skip early what it was already included in the crate
                if container in self._added_containers:
                    continue

                container_type_metadata = self.ContainerTypeMetadataDetails[
                    container.type
                ]
                crate_cont_type = self.cached_cts.get(container.type)
                if crate_cont_type is None:
                    container_type = (
                        rocrate.model.softwareapplication.SoftwareApplication(
                            self.crate, identifier=container_type_metadata.sa_id
                        )
                    )
                    container_type[
                        "applicationCategory"
                    ] = container_type_metadata.ct_applicationCategory
                    container_type["name"] = container.type.value
                    if self.containerEngineVersion is not None:
                        container_type["softwareVersion"] = self.containerEngineVersion

                    crate_cont_type = self.crate.add(container_type)
                    self.cached_cts[container.type] = crate_cont_type

                # Saving it for later usage when CreateAction are declared
                if (
                    the_workflow_crate is not None
                    and the_workflow_crate.id not in self._wf_to_container_sa
                ):
                    self._wf_to_container_sa[the_workflow_crate.id] = crate_cont_type

                # And the container source type
                crate_source_cont_type: "Optional[rocrate.model.softwareapplication.SoftwareApplication]"
                if (
                    container.source_type is None
                    or container.source_type == container.type
                ):
                    crate_source_cont_type = crate_cont_type
                    container_source_type_metadata = container_type_metadata
                else:
                    container_source_type_metadata = self.ContainerTypeMetadataDetails[
                        container.source_type
                    ]
                    crate_source_cont_type = self.cached_cts.get(container.source_type)
                    if crate_source_cont_type is None:
                        container_source_type = (
                            rocrate.model.softwareapplication.SoftwareApplication(
                                self.crate,
                                identifier=container_source_type_metadata.sa_id,
                            )
                        )
                        container_source_type[
                            "applicationCategory"
                        ] = container_source_type_metadata.ct_applicationCategory
                        container_source_type["name"] = container.source_type.value

                        crate_source_cont_type = self.crate.add(container_source_type)
                        self.cached_cts[container.source_type] = crate_source_cont_type

                software_container: "ContainerImage"
                registry, tag_name, tag_label = container.decompose_docker_tagged_name
                original_container_type = (
                    container.source_type
                    if container.source_type is not None
                    else container.type
                )
                upper_properties = {}
                # This is for the cases where we have the docker image fingerprint
                # This sha256 is about the image, but it is not associated
                # to the physical image when it is materialized in some way
                # like docker save or singularity pull
                if (
                    container.fingerprint is not None
                    and "@sha256:" in container.fingerprint
                ):
                    _, upper_properties["sha256"] = container.fingerprint.split(
                        "@sha256:", 1
                    )
                software_container = ContainerImage(
                    self.crate,
                    identifier=container.taggedName,
                    registry=registry,
                    name=tag_name,
                    tag=tag_label,
                    container_type=original_container_type,
                    properties=upper_properties,
                )
                if do_attach and container.localPath is not None:
                    the_size = os.stat(container.localPath).st_size
                    if container.image_signature is not None:
                        digest, algo = extract_digest(container.image_signature)
                        if digest is None:
                            digest, algo = unstringifyDigest(container.image_signature)
                        assert algo is not None
                        the_signature = hexDigest(algo, digest)
                    else:
                        the_signature = cast(
                            "Fingerprint",
                            ComputeDigestFromFile(
                                container.localPath,
                                "sha256",
                                repMethod=hexDigest,
                            ),
                        )

                    materialized_software_container = MaterializedContainerImage(
                        self.crate,
                        source=container.localPath,
                        dest_path=os.path.relpath(container.localPath, self.work_dir),
                        container_type=container.type,
                        registry=registry,
                        name=tag_name,
                        tag=tag_label,
                        properties={
                            "contentSize": str(the_size),
                            "identifier": container.taggedName,
                            "sha256": the_signature,
                            "encodingFormat": magic.from_file(
                                container.localPath, mime=True
                            ),
                        },
                    )
                    materialized_software_container = self.crate.add(
                        materialized_software_container
                    )

                    container_consolidate_action = CreateAction(
                        self.crate, f"Materialize {container.taggedName}"
                    )
                    container_consolidate_action = self.crate.add(
                        container_consolidate_action
                    )
                    container_consolidate_action["object"] = software_container
                    container_consolidate_action[
                        "result"
                    ] = materialized_software_container
                    container_consolidate_action.append_to(
                        "instrument", crate_cont_type, compact=True
                    )
                    container_consolidate_action.append_to(
                        "actionStatus",
                        {"@id": "http://schema.org/CompletedActionStatus"},
                        compact=True,
                    )

                crate_cont = self.crate.dereference(software_container.id)
                if crate_cont is None:
                    # Record the container
                    self._added_containers.append(container)

                    # Now, add container metadata, which is going to be
                    # consumed by WfExS or third parties
                    metadataLocalPath: "Optional[str]" = None
                    if container.metadataLocalPath is not None:
                        metadataLocalPath = container.metadataLocalPath
                    # This code is needed for old working directories
                    if metadataLocalPath is None and container.localPath is not None:
                        metadataLocalPath = container.localPath + META_JSON_POSTFIX

                    if metadataLocalPath is not None and os.path.exists(
                        metadataLocalPath
                    ):
                        meta_file = self._add_file_to_crate(
                            the_path=metadataLocalPath,
                            the_uri=None,
                            the_name=cast(
                                "RelPath",
                                os.path.relpath(metadataLocalPath, self.work_dir),
                            ),
                        )
                        meta_file.append_to("about", software_container, compact=True)

                    software_container["softwareVersion"] = container.fingerprint
                    container_os = container.operatingSystem
                    if container_os is None:
                        container_os = self.containerEngineOs
                    if container_os is not None:
                        software_container["operatingSystem"] = container_os
                    # Getting the processor architecture of the container
                    container_arch = container.architecture
                    if container_arch is None:
                        container_arch = self.arch
                    if container_arch is not None:
                        software_container["processorRequirements"] = container_arch
                    software_container["softwareRequirements"] = crate_cont_type

                    # Describing the the kind of container
                    software_container[
                        "applicationCategory"
                    ] = container_type_metadata.applicationCategory

                    crate_cont = self.crate.add(software_container)

                    # We are assuming these are operational containers
                    if isinstance(
                        sa_crate, rocrate.model.softwareapplication.SoftwareApplication
                    ):
                        sa_crate.append_to(
                            "softwareRequirements", crate_cont, compact=True
                        )

                added_containers.append(cast("ContainerImage", crate_cont))

        return added_containers

    def addWorkflowInputs(
        self,
        inputs: "Sequence[MaterializedInput]",
        are_envvars: "bool" = False,
    ) -> "Sequence[rocrate.model.entity.Entity]":
        """
        Add the input's or environment variables provenance data to a Research Object.

        :param inputs: List of inputs to add
        :type inputs: Sequence[MaterializedInput]
        """
        crate_inputs = []
        do_attach = CratableItem.Inputs in self.payloads
        input_sep = "envvar" if are_envvars else "param"
        fp_dest = "environment" if are_envvars else "input"
        for in_item in inputs:
            formal_parameter_id = (
                f"{self.wf_file.id}#{input_sep}:"
                + urllib.parse.quote(in_item.name, safe="")
            )

            itemInValue0 = in_item.values[0]
            additional_type: "Optional[str]" = None
            if isinstance(itemInValue0, int):
                additional_type = "Integer"
            elif isinstance(itemInValue0, str):
                additional_type = "Text"
            elif isinstance(itemInValue0, bool):
                additional_type = "Boolean"
            elif isinstance(itemInValue0, float):
                additional_type = "Float"
            elif isinstance(itemInValue0, MaterializedContent):
                if len(in_item.values) > 1:
                    additional_type = "Collection"
                elif itemInValue0.kind in (
                    ContentKind.File,
                    ContentKind.ContentWithURIs,
                ):
                    additional_type = "File"
                elif itemInValue0.kind == ContentKind.Directory:
                    additional_type = "Dataset"

            formal_parameter = cast(
                "Optional[FormalParameter]", self.crate.dereference(formal_parameter_id)
            )

            if formal_parameter is None:
                formal_parameter = FormalParameter(
                    self.crate,
                    name=in_item.name,
                    identifier=formal_parameter_id,
                    additional_type=additional_type,
                )
                self.crate.add(formal_parameter)
                # TODO: fix this at the standard level in some way
                # so it is possible in the future to distinguish among
                # inputs and environment variables in an standardized way
                self.wf_file.append_to(fp_dest, formal_parameter, compact=True)
                value_required = not in_item.implicit
                formal_parameter["valueRequired"] = str(value_required)

            item_signature = cast(
                "bytes",
                ComputeDigestFromObject(
                    marshall_namedtuple(in_item.values), repMethod=nullProcessDigest
                ),
            ) + formal_parameter_id.encode("utf-8")
            # Do we already have the value in cache?
            crate_coll = cast(
                "Union[Collection, FixedDataset, FixedFile, PropertyValue, None]",
                self._item_hash.get(item_signature),
            )
            # We don't, so let's populate it
            if crate_coll is None:
                if len(in_item.values) > 1:
                    crate_coll = self._add_collection_to_crate()

                if additional_type in ("File", "Dataset", "Collection"):
                    for itemInValues in cast(
                        "Sequence[MaterializedContent]", in_item.values
                    ):
                        # TODO: embed metadata_array in some way
                        assert isinstance(itemInValues, MaterializedContent)
                        itemInLocalSource = itemInValues.local  # local source
                        itemInURISource = itemInValues.licensed_uri.uri  # uri source
                        itemInURILicences = itemInValues.licensed_uri.licences
                        if os.path.isfile(itemInLocalSource):
                            the_signature: "Optional[Fingerprint]" = None
                            if itemInValues.fingerprint is not None:
                                digest, algo = extract_digest(itemInValues.fingerprint)
                                if digest is not None:
                                    assert algo is not None
                                    the_signature = hexDigest(algo, digest)

                            # This is needed to avoid including the input
                            crate_file = self._add_file_to_crate(
                                the_path=itemInLocalSource,
                                the_uri=itemInURISource,
                                the_name=cast(
                                    "RelPath",
                                    os.path.relpath(itemInLocalSource, self.work_dir),
                                ),
                                the_signature=the_signature,
                                the_licences=itemInURILicences,
                                do_attach=do_attach,
                            )

                            # An extrapolated input, which needs special handling
                            if itemInValues.extrapolated_local is not None:
                                crate_extrapolated_file = self._add_file_to_crate(
                                    the_path=itemInValues.extrapolated_local,
                                    the_uri=None,
                                    the_name=cast(
                                        "RelPath",
                                        os.path.relpath(
                                            itemInValues.extrapolated_local,
                                            self.work_dir,
                                        ),
                                    ),
                                    do_attach=True,
                                )
                                crate_extrapolated_file[
                                    "description"
                                ] = "This file is an extrapolation of other. The original file contained URIs which were fetched, and this file, where URIs where substituted by the local paths, was generated and used for workflow execution"

                                # Now, related the file with the extrapolated
                                # contents to the original file
                                crate_extrapolated_file.append_to(
                                    "exampleOfWork", crate_file, compact=True
                                )

                                crate_file.append_to(
                                    "workExample", crate_extrapolated_file, compact=True
                                )

                                # and describe the transformation
                                extrap_action = CreateAction(
                                    self.crate,
                                    "File content with embedded URIs extrapolation process",
                                )
                                extrap_action = self.crate.add(extrap_action)
                                extrap_action["object"] = crate_file
                                extrap_action["result"] = crate_extrapolated_file
                                extrap_action.append_to(
                                    "instrument", self.wf_wfexs, compact=True
                                )
                                extrap_action.append_to(
                                    "actionStatus",
                                    {"@id": "http://schema.org/CompletedActionStatus"},
                                    compact=True,
                                )
                                if len(self._agents) > 0:
                                    extrap_action.append_to(
                                        "agent", self._agents, compact=True
                                    )

                            else:
                                crate_extrapolated_file = crate_file

                            if isinstance(crate_coll, Collection):
                                crate_coll.append_to(
                                    "hasPart", crate_extrapolated_file, compact=True
                                )
                            else:
                                crate_coll = crate_extrapolated_file

                        elif os.path.isdir(itemInLocalSource):
                            crate_dataset, _ = self._add_directory_as_dataset(
                                itemInLocalSource,
                                itemInURISource,
                                the_name=cast(
                                    "RelPath",
                                    os.path.relpath(itemInLocalSource, self.work_dir)
                                    + "/",
                                ),
                                do_attach=do_attach,
                            )
                            # crate_dataset = self.crate.add_dataset_ext(
                            #    source=itemInURISource,
                            #    fetch_remote=False,
                            #    validate_url=False,
                            #    do_attach=do_attach,
                            #    # properties=file_properties,
                            # )

                            if crate_dataset is not None:
                                if isinstance(crate_coll, Collection):
                                    crate_coll.append_to(
                                        "hasPart", crate_dataset, compact=True
                                    )
                                else:
                                    crate_coll = crate_dataset

                        else:
                            pass  # TODO: raise exception

                else:
                    # Detecting nullified values
                    some_not_null = False
                    for itemInAtomicValues in cast(
                        "Sequence[Union[bool,str,float,int]]", in_item.values
                    ):
                        if isinstance(itemInAtomicValues, (bool, str, float, int)):
                            some_not_null = True
                            break

                    if some_not_null:
                        if in_item.implicit and len(in_item.values) == 1:
                            formal_parameter["defaultValue"] = str(in_item.values[0])

                        for itemInAtomicValues in cast(
                            "Sequence[Union[bool,str,float,int]]", in_item.values
                        ):
                            if isinstance(itemInAtomicValues, (bool, str, float, int)):
                                # This case happens when an input is telling
                                # some kind of output file or directory.
                                # So, its value should be fixed, to avoid
                                # containing absolute paths
                                fixedAtomicValue: "Union[bool,str,float,int]"
                                if in_item.autoFilled:
                                    fixedAtomicValue = os.path.relpath(
                                        cast("str", itemInAtomicValues),
                                        self.staged_setup.work_dir,
                                    )
                                else:
                                    fixedAtomicValue = itemInAtomicValues
                                parameter_value = PropertyValue(
                                    self.crate, in_item.name, str(fixedAtomicValue)
                                )
                                crate_pv = self.crate.add(parameter_value)
                                if isinstance(crate_coll, Collection):
                                    crate_coll.append_to(
                                        "hasPart", crate_pv, compact=True
                                    )
                                else:
                                    crate_coll = crate_pv
                    # Null values are right now represented as no values
                    # At this moment there is no satisfactory way to represent it
                    # else:
                    #     # Let's suppose it is an str
                    #     parameter_no_value = Intangible(
                    #         self.crate,
                    #         in_item.name,
                    #         additionalType="Text",
                    #     )
                    #     crate_pnv = self.crate.add(parameter_no_value)
                    #     if isinstance(crate_coll, Collection):
                    #         crate_coll.append_to("hasPart", crate_pnv, compact=True)
                    #     else:
                    #         crate_coll = crate_pnv

                # Avoiding corner cases
                if crate_coll is not None:
                    # And now, let's process the secondary inputs
                    if (
                        isinstance(in_item.secondaryInputs, list)
                        and len(in_item.secondaryInputs) > 0
                    ):
                        # TODO: Can a value have secondary values in workflow
                        # paradigms like CWL???
                        if isinstance(crate_coll, PropertyValue):
                            self.logger.warning(
                                "Unexpected case: PropertyValue as main entity of a Collection. Please open an issue on WfExS-backend repo providing the workflow which raised this corner case."
                            )

                        sec_crate_coll = self._add_collection_to_crate(
                            main_entity=cast(
                                "Union[Collection, FixedDataset, FixedFile]", crate_coll
                            )
                        )

                        for secInput in in_item.secondaryInputs:
                            sec_crate_elem: "Union[FixedFile, FixedDataset, Collection, None]"

                            secInputLocalSource = secInput.local  # local source
                            secInputURISource = secInput.licensed_uri.uri  # uri source
                            secInputURILicences = (
                                secInput.licensed_uri.licences
                            )  # licences
                            if os.path.isfile(secInputLocalSource):
                                # This is needed to avoid including the input
                                the_sec_signature: "Optional[Fingerprint]" = None
                                if secInput.fingerprint is not None:
                                    sec_digest, sec_algo = extract_digest(
                                        secInput.fingerprint
                                    )
                                    if sec_digest is not None:
                                        assert sec_algo is not None
                                        the_sec_signature = hexDigest(
                                            sec_algo, sec_digest
                                        )

                                sec_crate_elem = self._add_file_to_crate(
                                    the_path=secInputLocalSource,
                                    the_uri=secInputURISource,
                                    the_name=cast(
                                        "RelPath",
                                        os.path.relpath(
                                            secInputLocalSource, self.work_dir
                                        ),
                                    ),
                                    the_signature=the_sec_signature,
                                    the_licences=secInputURILicences,
                                    do_attach=do_attach,
                                )

                            elif os.path.isdir(secInputLocalSource):
                                sec_crate_elem, _ = self._add_directory_as_dataset(
                                    secInputLocalSource,
                                    secInputURISource,
                                    do_attach=do_attach,
                                )
                                # crate_dataset = self.crate.add_dataset_ext(
                                #    source=secInputURISource,
                                #    fetch_remote=False,
                                #    validate_url=False,
                                #    # properties=file_properties,
                                # )
                                the_sec_name = os.path.relpath(
                                    secInputLocalSource, self.work_dir
                                )

                                if sec_crate_elem is not None:
                                    sec_crate_elem["alternateName"] = the_sec_name + "/"
                            else:
                                sec_crate_elem = None

                            if sec_crate_elem is not None:
                                sec_crate_coll.append_to(
                                    "hasPart", sec_crate_elem, compact=True
                                )

                        # Last, put it in place
                        crate_coll = sec_crate_coll

            # Now, let's interrelate formal parameters with the input values
            if crate_coll is not None:
                # Updating the cache is the first
                if item_signature not in self._item_hash:
                    self._item_hash[item_signature] = crate_coll

                examples_of_work = crate_coll.get("exampleOfWork")
                if (
                    examples_of_work is None
                    or formal_parameter != examples_of_work
                    or (
                        isinstance(examples_of_work, list)
                        and formal_parameter not in examples_of_work
                    )
                ):
                    crate_coll.append_to(
                        "exampleOfWork", formal_parameter, compact=True
                    )
                work_examples = formal_parameter.get("workExample")
                if (
                    work_examples is None
                    or crate_coll != work_examples
                    or (
                        isinstance(work_examples, list)
                        and crate_coll not in work_examples
                    )
                ):
                    formal_parameter.append_to("workExample", crate_coll, compact=True)
                crate_inputs.append(crate_coll)

            # TODO digest other types of inputs
        return crate_inputs

    def _add_file_to_crate(
        self,
        the_path: "str",
        the_uri: "Optional[URIType]",
        the_id: "Optional[str]" = None,
        the_name: "Optional[RelPath]" = None,
        the_alternate_name: "Optional[RelPath]" = None,
        the_size: "Optional[int]" = None,
        the_signature: "Optional[Fingerprint]" = None,
        the_licences: "Optional[Sequence[str]]" = None,
        the_mime: "Optional[str]" = None,
        is_soft_source: "bool" = False,
        do_attach: "bool" = True,
    ) -> "FixedFile":
        # The do_attach logic helps on the ill internal logic of add_file
        # when an id has to be assigned

        # assert do_attach or (the_id is not None), "We must provide an @id for non local files"
        assert not do_attach or (
            the_name is not None
        ), "A name must be provided for local files"

        # When the id is none and ...
        if the_id is None:
            the_id = the_name if do_attach or (the_uri is None) else the_uri

        the_file_crate = self.crate.add_file_ext(
            identifier=the_id,
            source=the_path if do_attach else None,
            dest_path=the_name if do_attach else None,
            clazz=SourceCodeFile if is_soft_source else FixedFile,
        )
        if do_attach and (the_uri is not None):
            if the_uri.startswith("http") or the_uri.startswith("ftp"):
                # See https://github.com/ResearchObject/ro-crate/pull/259
                uri_key = "contentUrl"
            else:
                uri_key = "identifier"

            the_file_crate[uri_key] = the_uri
        if the_alternate_name is not None:
            the_file_crate["alternateName"] = the_alternate_name

        if the_size is None:
            the_size = os.stat(the_path).st_size
        if the_signature is None:
            the_signature = cast(
                "Fingerprint", ComputeDigestFromFile(the_path, repMethod=hexDigest)
            )
        the_file_crate.append_to("contentSize", str(the_size), compact=True)
        the_file_crate.append_to("sha256", the_signature, compact=True)
        if the_mime is None:
            # Real path is needed because libmagic is able to provide
            # a mime type for symbolic links, and some engines and
            # workflows provide their outputs symbolically linked to
            # the file in the intermediate working directory
            the_mime = magic.from_file(os.path.realpath(the_path), mime=True)
        the_file_crate.append_to("encodingFormat", the_mime, compact=True)

        if the_licences is not None:
            for the_licence in the_licences:
                the_file_crate.append_to(
                    "license", self._process_licence(the_licence), compact=True
                )

        return the_file_crate

    def _add_collection_to_crate(
        self,
        main_entity: "Union[FixedFile, FixedDataset, Collection, None]" = None,
    ) -> "Collection":
        wf_coll = Collection(self.crate, main_entity)
        wf_coll = self.crate.add(wf_coll)

        return wf_coll

    def _add_directory_as_dataset(
        self,
        the_path: "str",
        the_uri: "URIType",
        the_id: "Optional[str]" = None,
        the_name: "Optional[RelPath]" = None,
        the_alternate_name: "Optional[RelPath]" = None,
        do_attach: "bool" = True,
    ) -> "Union[Tuple[FixedDataset, Sequence[FixedFile]], Tuple[None, None]]":
        # FUTURE IMPROVEMENT
        # Describe datasets referred from DOIs
        # as in https://github.com/ResearchObject/ro-crate/pull/255/files

        if not os.path.isdir(the_path):
            return None, None

        assert not do_attach or (
            the_name is not None
        ), "A name must be provided for local directories"

        # When the id is none and ...
        if the_id is None:
            the_id = the_name if do_attach or (the_uri is None) else the_uri

        the_files_crates: "MutableSequence[FixedFile]" = []
        crate_dataset = self.crate.add_dataset_ext(
            identifier=the_id,
            source=the_path if do_attach else None,
            dest_path=the_name if do_attach else None,
            fetch_remote=False,
            validate_url=False,
            # properties=file_properties,
        )
        if do_attach and (the_uri is not None):
            if the_uri.startswith("http") or the_uri.startswith("ftp"):
                # See https://github.com/ResearchObject/ro-crate/pull/259
                uri_key = "contentUrl"
            else:
                uri_key = "identifier"

            crate_dataset[uri_key] = the_uri
        if the_alternate_name is not None:
            crate_dataset["alternateName"] = the_alternate_name

        # Now, recursively walk it
        with os.scandir(the_path) as the_dir:
            for the_file in the_dir:
                if the_file.name[0] == ".":
                    continue
                the_item_uri = cast(
                    "URIType",
                    the_uri + "/" + urllib.parse.quote(the_file.name, safe=""),
                )
                if the_file.is_file():
                    the_file_crate = self._add_file_to_crate(
                        the_path=the_file.path,
                        the_uri=the_item_uri,
                        the_size=the_file.stat().st_size,
                        do_attach=do_attach,
                    )

                    crate_dataset.append_to("hasPart", the_file_crate, compact=True)

                    the_files_crates.append(the_file_crate)
                elif the_file.is_dir():
                    # TODO: fix URI handling
                    (
                        the_dir_crate,
                        the_subfiles_crates,
                    ) = self._add_directory_as_dataset(
                        the_path=the_file.path,
                        the_uri=the_item_uri,
                        do_attach=do_attach,
                    )
                    if the_dir_crate is not None:
                        assert the_subfiles_crates is not None
                        crate_dataset.append_to("hasPart", the_dir_crate, compact=True)
                        crate_dataset.append_to(
                            "hasPart", the_subfiles_crates, compact=True
                        )

                        the_files_crates.extend(the_subfiles_crates)

        return crate_dataset, the_files_crates

    def _add_workflow_to_crate(
        self,
        the_workflow: "LocalWorkflow",
        lang: "rocrate.model.computerlanguage.ComputerLanguage",
        the_description: "Optional[str]",
        the_weng_crate: "rocrate.model.softwareapplication.SoftwareApplication",
        materialized_engine: "MaterializedWorkflowEngine",
        the_uri: "Optional[str]" = None,
        remote_repo: "Optional[RemoteRepo]" = None,
        main: "bool" = False,
        gen_cwl: "bool" = False,
        do_attach: "bool" = True,
        was_workflow_run: "bool" = True,
    ) -> "FixedWorkflow":
        # Determining the absolute path of the workflow
        the_path: "str"
        if the_workflow.relPath is not None:
            if os.path.isabs(the_workflow.relPath):
                the_path = the_workflow.relPath
            else:
                the_path = os.path.join(the_workflow.dir, the_workflow.relPath)
        else:
            the_path = the_workflow.dir

        wf_url: "Optional[str]" = None
        wf_entrypoint_url: "Optional[str]" = None
        if remote_repo is not None:
            if remote_repo.web_url is not None:
                wf_url = remote_repo.web_url
                wf_entrypoint_url = wf_url
            else:
                wf_url = remote_repo.repo_url.replace(".git", "/")
                if remote_repo.tag is not None:
                    wf_url += "tree/" + remote_repo.tag
                if the_workflow.relPath is not None:
                    wf_url += the_workflow.dir.rsplit("workflow")[1]

                parsed_repo_url = urllib.parse.urlparse(remote_repo.repo_url)
                if parsed_repo_url.netloc == "github.com":
                    assert (
                        materialized_engine.workflow.effectiveCheckout is not None
                    ), "The effective checkout should be available"

                    parsed_repo_path = parsed_repo_url.path.split("/")
                    repo_name = parsed_repo_path[2]
                    # TODO: should we urldecode repo_name?
                    if repo_name.endswith(".git"):
                        repo_name = repo_name[:-4]
                    wf_entrypoint_path = [
                        "",  # Needed to prepend a slash
                        parsed_repo_path[1],
                        # TODO: should we urlencode repo_name?
                        repo_name,
                        materialized_engine.workflow.effectiveCheckout,
                    ]

                    if the_workflow.relPath is not None:
                        wf_entrypoint_path.append(the_workflow.relPath)

                    wf_entrypoint_url = urllib.parse.urlunparse(
                        (
                            "https",
                            "raw.githubusercontent.com",
                            "/".join(wf_entrypoint_path),
                            "",
                            "",
                            "",
                        )
                    )

                elif "gitlab" in parsed_repo_url.netloc:
                    parsed_repo_path = parsed_repo_url.path.split("/")
                    # FIXME: cover the case of nested groups
                    repo_name = parsed_repo_path[2]
                    if repo_name.endswith(".git"):
                        repo_name = repo_name[:-4]
                    wf_entrypoint_path = [parsed_repo_path[1], repo_name]
                    if remote_repo.tag is not None and the_workflow.relPath is not None:
                        # TODO: should we urlencode repoTag?
                        wf_entrypoint_path.extend(
                            ["-", "raw", remote_repo.tag, the_workflow.relPath]
                        )

                    wf_entrypoint_url = urllib.parse.urlunparse(
                        (
                            parsed_repo_url.scheme,
                            parsed_repo_url.netloc,
                            "/".join(wf_entrypoint_path),
                            "",
                            "",
                            "",
                        )
                    )

                else:
                    raise ROCrateGenerationException(
                        "FIXME: Unsupported http(s) git repository {}".format(
                            remote_repo.repo_url
                        )
                    )
        else:
            # If there is no information about the remote origin
            # of the workflow, better keep a copy in the RO-Crate
            do_attach = True

        # The do_attach logic helps on the ill internal logic of add_workflow
        # and add_file when an id has to be assigned
        the_name: "Optional[str]" = None
        rocrate_wf_folder: "str" = os.path.relpath(the_workflow.dir, self.work_dir)
        the_alternate_name: "str"
        if do_attach:
            # if wf_entrypoint_url is not None:
            #    # This is needed to avoid future collisions with other workflows stored in the RO-Crate
            #    rocrate_wf_folder = str(
            #        uuid.uuid5(uuid.NAMESPACE_URL, wf_entrypoint_url)
            #    )
            # else:
            #    rocrate_wf_folder = str(uuid.uuid4())

            the_alternate_name = os.path.relpath(the_path, the_workflow.dir)
            the_name = rocrate_wf_folder + "/" + the_alternate_name
        else:
            the_alternate_name = cast(
                "RelPath",
                os.path.join(
                    rocrate_wf_folder, os.path.relpath(the_path, the_workflow.dir)
                ),
            )

        # When the id is none and ...
        the_id = the_name if do_attach or (the_uri is None) else the_uri
        assert the_id is not None

        rocrate_file_id_base = the_id if the_uri is None else the_uri

        the_workflow_crate = self.crate.add_workflow_ext(
            identifier=the_id,
            source=the_path if do_attach else None,
            dest_path=the_name if do_attach else None,
            main=main,
            lang=lang,
            gen_cwl=gen_cwl,
            fetch_remote=False,
        )

        the_workflow_crate.append_to(
            "conformsTo",
            # As of https://www.researchobject.org/ro-crate/1.1/workflows.html#complying-with-bioschemas-computational-workflow-profile
            {
                "@id": "https://bioschemas.org/profiles/ComputationalWorkflow/1.0-RELEASE"
            },
            compact=True,
        )
        the_workflow_crate.append_to(
            "softwareRequirements", the_weng_crate, compact=True
        )
        workflow_engine_version = the_weng_crate.get("softwareVersion")
        if workflow_engine_version is not None:
            the_workflow_crate["runtimePlatform"] = workflow_engine_version

        # This is a property from SoftwareSourceCode
        # the_workflow_crate["targetProduct"] = the_weng_crate

        if materialized_engine.containers is not None:
            added_containers = self._add_containers(
                materialized_engine.containers,
                sa_crate=the_workflow_crate,
                the_workflow_crate=the_workflow_crate,
            )
            if was_workflow_run and len(added_containers) > 0:
                the_workflow_crate.append_to(
                    "softwareRequirements",
                    self._wf_to_container_sa[the_workflow_crate.id],
                    compact=True,
                )
            existing_containers = self._wf_to_containers.setdefault(
                the_workflow_crate.id, []
            )
            for added_container in added_containers:
                # Add containers as addons which were used
                if added_container not in existing_containers:
                    existing_containers.append(added_container)
                    if was_workflow_run:
                        the_workflow_crate.append_to(
                            "softwareRequirements", added_container, compact=True
                        )
        if materialized_engine.operational_containers is not None:
            added_operational_containers = self._add_containers(
                materialized_engine.operational_containers,
                sa_crate=the_weng_crate,
                the_workflow_crate=the_workflow_crate,
            )
            existing_operational_containers = (
                self._wf_to_operational_containers.setdefault(the_workflow_crate.id, [])
            )
            for added_operational_container in added_operational_containers:
                if added_operational_container not in existing_operational_containers:
                    existing_operational_containers.append(added_operational_container)

        if do_attach and (the_uri is not None):
            if the_uri.startswith("http") or the_uri.startswith("ftp"):
                # See https://github.com/ResearchObject/ro-crate/pull/259
                uri_key = "contentUrl"
            else:
                uri_key = "identifier"

            the_workflow_crate[uri_key] = the_uri

        if the_alternate_name is not None:
            the_workflow_crate["alternateName"] = the_alternate_name

        if os.path.isfile(the_path):
            the_size = os.stat(the_path).st_size

            the_signature = cast(
                "Fingerprint", ComputeDigestFromFile(the_path, repMethod=hexDigest)
            )
            the_workflow_crate.append_to("contentSize", str(the_size), compact=True)
            the_workflow_crate.append_to("sha256", the_signature, compact=True)
            the_workflow_crate.append_to(
                "encodingFormat",
                magic.from_file(os.path.realpath(the_path), mime=True),
                compact=True,
            )

        if remote_repo is not None:
            the_workflow_crate["codeRepository"] = remote_repo.repo_url

        effective_checkout = materialized_engine.workflow.effectiveCheckout
        if effective_checkout is None:
            effective_checkout = the_workflow.effectiveCheckout
        if effective_checkout is not None:
            the_workflow_crate["version"] = effective_checkout

        if the_description is not None:
            the_workflow_crate["description"] = the_description
        if wf_url is not None:
            the_workflow_crate["url"] = wf_url

        if the_workflow.relPathFiles:
            rel_entities: "MutableSequence[Union[FixedFile, rocrate.model.creativework.CreativeWork]]" = (
                []
            )
            for rel_file in the_workflow.relPathFiles:
                if rel_file == the_workflow.relPath:
                    # Ignore itself, so it is not overwritten
                    continue

                # First, are we dealing with relative files or with URIs?
                p_rel_file = urllib.parse.urlparse(rel_file)
                the_entity: "Union[FixedFile, rocrate.model.creativework.CreativeWork]"
                if p_rel_file.scheme != "":
                    the_entity = rocrate.model.creativework.CreativeWork(
                        self.crate,
                        identifier=rel_file,
                    )
                    self.crate.add(the_entity)
                else:
                    rocrate_file_id = rocrate_file_id_base + "/" + rel_file
                    the_name = cast(
                        "RelPath", os.path.join(rocrate_wf_folder, rel_file)
                    )
                    the_entity = self._add_file_to_crate(
                        the_path=os.path.join(the_workflow.dir, rel_file),
                        the_name=the_name,
                        the_alternate_name=cast("RelPath", rel_file)
                        if do_attach
                        else the_name,
                        the_uri=cast("URIType", rocrate_file_id),
                        do_attach=do_attach,
                        is_soft_source=True,
                    )

                rel_entities.append(the_entity)

            if len(rel_entities) > 0:
                the_workflow_crate.append_to("hasPart", rel_entities, compact=True)

        return the_workflow_crate

    def addWorkflowExpectedOutputs(
        self,
        outputs: "Sequence[ExpectedOutput]",
    ) -> None:
        for out_item in outputs:
            formal_parameter_id = (
                self.wf_file.id
                + "#output:"
                + urllib.parse.quote(out_item.name, safe="")
            )

            formal_parameter = cast(
                "Optional[FormalParameter]", self.crate.dereference(formal_parameter_id)
            )

            if out_item.kind == ContentKind.File:
                additional_type = "File"
            elif out_item.kind == ContentKind.Directory:
                additional_type = "Dataset"
            else:
                additional_type = None

            # Create a new one only when it is needed
            if formal_parameter is None:
                formal_parameter = FormalParameter(
                    self.crate,
                    name=out_item.name,
                    identifier=formal_parameter_id,
                    additional_type=additional_type,
                )
                self.crate.add(formal_parameter)

            # Add to the list only when it is needed
            wf_file_outputs = self.wf_file.get("output")
            if (
                wf_file_outputs is None
                or formal_parameter != wf_file_outputs
                or (
                    isinstance(wf_file_outputs, list)
                    and formal_parameter not in wf_file_outputs
                    and {"@id": formal_parameter_id} not in wf_file_outputs
                )
            ):
                self.wf_file.append_to("output", formal_parameter, compact=True)

    def writeWRROC(self, filename: "AnyPath") -> None:
        with warnings.catch_warnings():
            # Disable possible warnings emitted by rocrate-py library
            # when it is not run in debug mode
            if self.logger.getEffectiveLevel() > logging.DEBUG:
                warnings.filterwarnings(
                    "ignore", category=UserWarning, module="^rocrate\.model\.file$"
                )
            self.crate.write_zip(filename)

    def addWorkflowExecution(
        self,
        stagedExec: "StagedExecution",
    ) -> None:
        # TODO: Add a new CreateAction for each stagedExec
        # as it is explained at https://www.researchobject.org/workflow-run-crate/profiles/workflow_run_crate
        assert self.staged_setup.inputs_dir is not None

        outputsDir = cast(
            "AbsPath",
            os.path.normpath(os.path.join(self.work_dir, stagedExec.outputsDir)),
        )

        crate_action = CreateAction(
            self.crate,
            "Run " + stagedExec.outputsDir + " of " + self.wf_file.id,
            stagedExec.started,
            stagedExec.ended,
        )
        self.crate.add(crate_action)
        if len(self._agents) > 0:
            crate_action.append_to("agent", self._agents, compact=True)
        self.crate.root_dataset.append_to("mentions", crate_action, compact=True)

        # Skipping adding operational containers for now
        # if self.wf_file.id in self._wf_to_operational_containers:
        #     for container_image in self._wf_to_operational_containers[self.wf_file.id]:
        #         crate_action.append_to("containerImage", container_image, compact=True)
        # Adding "normal" containers
        if self.wf_file.id in self._wf_to_containers:
            for container_image in self._wf_to_containers[self.wf_file.id]:
                crate_action.append_to("containerImage", container_image, compact=True)

        crate_action.append_to("instrument", self.wf_file, compact=True)
        # subjectOf is not fulfilled as this execution has not public page
        if stagedExec.exitVal == 0:
            action_status = "http://schema.org/CompletedActionStatus"
        else:
            action_status = "http://schema.org/FailedActionStatus"

        crate_action.append_to("actionStatus", {"@id": action_status}, compact=True)

        crate_inputs = self.addWorkflowInputs(
            stagedExec.augmentedInputs,
            are_envvars=False,
        )
        crate_envvars = self.addWorkflowInputs(
            stagedExec.environment,
            are_envvars=True,
        )
        crate_action["object"] = [*crate_inputs, *crate_envvars]

        # TODO: Add engine specific traces
        # see https://www.researchobject.org/workflow-run-crate/profiles/workflow_run_crate#adding-engine-specific-traces
        # TODO: Add "augmented environment variables"

        crate_outputs = self._add_workflow_execution_outputs(
            stagedExec.matCheckOutputs,
            rel_work_dir=stagedExec.outputsDir,
        )

        # Now, the logfiles and diagram
        crate_meta_outputs: "MutableSequence[rocrate.model.entity.Entity]" = []
        if stagedExec.diagram is not None:
            # This is the original diagram, in DOT format (for now)
            abs_diagram = os.path.join(self.work_dir, stagedExec.diagram)
            dot_file = WorkflowDiagram(
                self.crate,
                source=os.path.join(self.work_dir, stagedExec.diagram),
                dest_path=stagedExec.diagram,
                fetch_remote=False,
                validate_url=False,
                properties={
                    "contentSize": str(os.stat(abs_diagram).st_size),
                    "sha256": ComputeDigestFromFile(
                        abs_diagram, "sha256", repMethod=hexDigest
                    ),
                    "encodingFormat": magic.from_file(abs_diagram, mime=True),
                },
            )
            self.crate.add(dot_file)

            the_diagram = dot_file

            # Declaring the provenance of the diagram
            dot_file["isBasedOn"] = self.wf_file
            crate_meta_outputs.append(dot_file)

            png_dot_handle, png_dot_path = tempfile.mkstemp(
                prefix="WfExS", suffix="diagram", dir=self.tempdir
            )
            # Registering for removal the temporary file
            atexit.register(os.unlink, png_dot_path)
            # We are not using the handle, so close it
            os.close(png_dot_handle)

            with tempfile.NamedTemporaryFile() as d_err:
                dot_cmd = [self.dot_binary, "-Tpng", "-o" + png_dot_path, abs_diagram]
                dot_cmd_for_rocrate = [
                    DEFAULT_DOT_CMD,
                    "-Tpng",
                    "-o" + stagedExec.diagram + ".png",
                    stagedExec.diagram,
                ]
                d_retval = subprocess.Popen(
                    dot_cmd,
                    stdout=d_err,
                    stderr=d_err,
                ).wait()

                self.logger.debug(f"'{' '.join(dot_cmd)}' retval: {d_retval}")

                if d_retval == 0:
                    png_dot_file = WorkflowDiagram(
                        self.crate,
                        source=png_dot_path,
                        dest_path=stagedExec.diagram + ".png",
                        fetch_remote=False,
                        validate_url=False,
                        properties={
                            "contentSize": str(os.stat(png_dot_path).st_size),
                            "sha256": ComputeDigestFromFile(
                                png_dot_path, "sha256", repMethod=hexDigest
                            ),
                            "encodingFormat": magic.from_file(png_dot_path, mime=True),
                        },
                    )
                    self.crate.add(png_dot_file)
                    the_diagram = png_dot_file

                    # Declaring the provenance
                    png_dot_file["isBasedOn"] = dot_file
                    crate_meta_outputs.append(png_dot_file)

                    # Now describe the transformation
                    dot_action = CreateAction(
                        self.crate,
                        "Generate diagram PNG image from DOT",
                    )
                    dot_action = self.crate.add(dot_action)
                    dot_action["object"] = dot_file
                    dot_action["description"] = " ".join(dot_cmd_for_rocrate)
                    dot_action["result"] = png_dot_file
                    dot_action.append_to("instrument", self.wf_wfexs, compact=True)
                    dot_action.append_to(
                        "actionStatus",
                        {"@id": "http://schema.org/CompletedActionStatus"},
                        compact=True,
                    )
                    if len(self._agents) > 0:
                        dot_action.append_to("agent", self._agents, compact=True)
                else:
                    # Diagram image generation failed
                    with open(d_err.name, mode="rb") as c_stF:
                        d_err_v = c_stF.read().decode("utf-8", errors="continue")

                    self.logger.error(f"'{' '.join(dot_cmd)}' stderr: {d_err_v}")

            # Associating the diagram to the main workflow
            self.wf_file.append_to("image", the_diagram, compact=True)

        # Processing the log files
        if len(stagedExec.logfile) > 0:
            crate_coll: "Union[Collection, FixedFile, None]"
            if len(stagedExec.logfile) > 1:
                crate_coll = self._add_collection_to_crate()
            else:
                crate_coll = None

            for logfile in stagedExec.logfile:
                the_log_file = self._add_file_to_crate(
                    os.path.join(self.work_dir, logfile), the_uri=None, the_name=logfile
                )
                if crate_coll is None:
                    crate_coll = the_log_file
                else:
                    crate_coll.append_to("hasPart", the_log_file, compact=True)

            if crate_coll is not None:
                crate_meta_outputs.append(crate_coll)
                if stagedExec.exitVal != 0:
                    crate_action["error"] = crate_coll

        crate_action["result"] = [*crate_outputs, *crate_meta_outputs]

        # TODO: Uncomment this when we are able to describe
        # the internal workflow execution. Each workflow step
        # should be described through a ControlAction, and all these
        # instances should be linked from the "object" property
        # of this OrganizeAction.
        # Also, each step will have its own CreateAction
        #
        # control_action = ControlAction(
        #     self.crate,
        #     "Orchestration of " + self.wf_file.id + " for" + stagedExec.outputsDir,
        # )
        # self.crate.add(control_action)
        # The "instrument" should be the step itself, not the workflow
        # control_action["instrument"] = self.wf_file
        # control_action["object"] = crate_action
        #
        # org_action = OrganizeAction(
        #     self.crate,
        #     "Orchestration of " + stagedExec.outputsDir + " from " + self.wf_file.id,
        #     stagedExec.started,
        #     stagedExec.ended,
        # )
        # self.crate.add(org_action)
        # org_action["agent"] = self.wf_wfexs
        # # The used workflow engine
        # org_action["instrument"] = self.weng_crate
        #
        # org_action.append_to("object", control_action, compact=True)
        # # TODO: add configuration files (if available) to object
        # org_action["result"] = crate_action

    def _add_workflow_execution_outputs(
        self,
        outputs: "Sequence[MaterializedOutput]",
        rel_work_dir: "RelPath",
    ) -> "Sequence[rocrate.model.entity.Entity]":
        """
        Add the output's provenance data to a Research Object.

        :param outputs: List of outputs to add
        :type outputs: Sequence[MaterializedOutput]
        """
        do_attach = CratableItem.Outputs in self.payloads
        crate_outputs: "MutableSequence[rocrate.model.entity.Entity]" = []
        for out_item in outputs:
            formal_parameter_id = (
                self.wf_file.id
                + "#output:"
                + urllib.parse.quote(out_item.name, safe="")
            )

            formal_parameter = cast(
                "Optional[FormalParameter]", self.crate.dereference(formal_parameter_id)
            )

            additional_type: "Optional[str]" = None
            if out_item.kind == ContentKind.File:
                additional_type = "Collection" if len(out_item.values) > 1 else "File"
            elif out_item.kind == ContentKind.Directory:
                additional_type = (
                    "Collection" if len(out_item.values) > 1 else "Dataset"
                )
            elif len(out_item.values) > 0:
                itemOutValue0 = out_item.values[0]
                if isinstance(itemOutValue0, int):
                    additional_type = "Integer"
                elif isinstance(itemOutValue0, str):
                    additional_type = "Text"
                elif isinstance(itemOutValue0, bool):
                    additional_type = "Boolean"
                elif isinstance(itemOutValue0, float):
                    additional_type = "Float"

            if formal_parameter is None:
                formal_parameter = FormalParameter(
                    self.crate,
                    name=out_item.name,
                    identifier=formal_parameter_id,
                    additional_type=additional_type,
                )
                self.crate.add(formal_parameter)
                self.wf_file.append_to("output", formal_parameter, compact=True)

            # This can happen when there is no output, like when a workflow has failed
            if len(out_item.values) == 0:
                continue

            if additional_type in ("File", "Dataset", "Collection"):
                crate_coll: "Union[Collection, FixedDataset, FixedFile, None]"
                if len(out_item.values) > 1:
                    crate_coll = self._add_collection_to_crate()
                else:
                    crate_coll = None
                for itemOutValues in cast(
                    "Sequence[AbstractGeneratedContent]", out_item.values
                ):
                    if not isinstance(
                        itemOutValues, (GeneratedContent, GeneratedDirectoryContent)
                    ):
                        self.logger.error("FIXME: elements of incorrect types")

                    assert isinstance(
                        itemOutValues, (GeneratedContent, GeneratedDirectoryContent)
                    )

                    itemOutLocalSource = itemOutValues.local  # local source
                    # TODO: use exported results logs to complement this
                    itemOutURISource = None
                    if isinstance(
                        itemOutValues, GeneratedDirectoryContent
                    ):  # if directory
                        if os.path.isdir(itemOutLocalSource):
                            (
                                crate_dataset,
                                _,
                            ) = self._add_GeneratedDirectoryContent_as_dataset(
                                itemOutValues,
                                rel_work_dir=rel_work_dir,
                                do_attach=do_attach,
                            )

                            if crate_dataset is not None:
                                if isinstance(crate_coll, Collection):
                                    crate_coll.append_to(
                                        "hasPart", crate_dataset, compact=True
                                    )
                                else:
                                    crate_coll = crate_dataset

                        else:
                            errmsg = (
                                "ERROR: The output directory %s does not exist"
                                % itemOutLocalSource
                            )
                            self.logger.error(errmsg)

                    elif isinstance(itemOutValues, GeneratedContent):  # file
                        if os.path.isfile(itemOutLocalSource):
                            crate_file = self._add_GeneratedContent_to_crate(
                                itemOutValues,
                                rel_work_dir=rel_work_dir,
                                do_attach=do_attach,
                            )

                            if isinstance(crate_coll, Collection):
                                crate_coll.append_to(
                                    "hasPart", crate_file, compact=True
                                )
                            else:
                                crate_coll = crate_file

                        else:
                            errmsg = (
                                "ERROR: The output file %s does not exist"
                                % itemOutLocalSource
                            )
                            self.logger.error(errmsg)

                    else:
                        pass
                        # TODO digest other types of outputs

                # Last rites to set all of them properly
                if crate_coll is not None:
                    if (
                        isinstance(crate_coll, Collection)
                        and additional_type != "Collection"
                    ):
                        formal_parameter["additionalType"] = "Collection"

                    crate_coll.append_to(
                        "exampleOfWork", formal_parameter, compact=True
                    )
                    formal_parameter.append_to("workExample", crate_coll, compact=True)
                    crate_outputs.append(crate_coll)
            else:
                self.logger.error(
                    f"FIXME: output parameter {formal_parameter_id} is of type {additional_type}, but no output mechanism was implemented"
                )

        return crate_outputs

    def _add_GeneratedContent_to_crate(
        self,
        the_content: "GeneratedContent",
        rel_work_dir: "RelPath",
        do_attach: "bool" = True,
    ) -> "Union[FixedFile, Collection]":
        assert the_content.signature is not None

        digest, algo = extract_digest(the_content.signature)
        if digest is None:
            digest, algo = unstringifyDigest(the_content.signature)
        assert algo is not None
        dest_path = os.path.relpath(the_content.local, self.work_dir)
        # dest_path = hexDigest(algo, digest)

        alternateName = os.path.relpath(
            the_content.local, os.path.join(self.work_dir, rel_work_dir)
        )

        if the_content.uri is not None and not the_content.uri.uri.startswith("nih:"):
            the_content_uri = the_content.uri.uri
        else:
            the_content_uri = None

        crate_file = self._add_file_to_crate(
            the_path=the_content.local,
            the_uri=the_content_uri,
            the_name=cast("RelPath", dest_path),
            the_alternate_name=cast("RelPath", alternateName),
            the_signature=hexDigest(algo, digest),
            do_attach=do_attach,
        )

        # The corner case of output files with secondary files
        if (
            isinstance(the_content.secondaryFiles, list)
            and len(the_content.secondaryFiles) > 0
        ):
            crate_coll = self._add_collection_to_crate(main_entity=crate_file)

            for secFile in the_content.secondaryFiles:
                gen_content: "Union[FixedFile, Collection, FixedDataset]"
                if isinstance(secFile, GeneratedContent):
                    gen_content = self._add_GeneratedContent_to_crate(
                        secFile,
                        rel_work_dir=rel_work_dir,
                        do_attach=do_attach,
                    )
                else:
                    # elif isinstance(secFile, GeneratedDirectoryContent):
                    gen_dir_content, _ = self._add_GeneratedDirectoryContent_as_dataset(
                        secFile,
                        rel_work_dir=rel_work_dir,
                        do_attach=do_attach,
                    )
                    assert gen_dir_content is not None
                    gen_content = gen_dir_content

                crate_coll.append_to("hasPart", gen_content, compact=True)

            return crate_coll
        else:
            return crate_file

    def _add_GeneratedDirectoryContent_as_dataset(
        self,
        the_content: "GeneratedDirectoryContent",
        rel_work_dir: "RelPath",
        do_attach: "bool" = True,
    ) -> "Union[Tuple[Union[FixedDataset, Collection], Sequence[Union[FixedFile, Collection]]], Tuple[None, None]]":
        if os.path.isdir(the_content.local):
            the_files_crates: "MutableSequence[Union[FixedFile, Collection]]" = []

            the_uri = the_content.uri.uri if the_content.uri is not None else None
            dest_path = os.path.relpath(the_content.local, self.work_dir) + "/"
            if do_attach or (the_uri is None):
                the_id = dest_path
            else:
                the_id = the_uri
            # if the_uri is not None:
            #    an_uri = the_uri
            #    dest_path = None
            # else:
            #    an_uri = None
            #    dest_path = os.path.relpath(the_content.local, self.work_dir)
            #    # digest, algo = extract_digest(the_content.signature)
            #    # dest_path = hexDigest(algo, digest)

            crate_dataset = self.crate.add_dataset_ext(
                identifier=the_id,
                source=the_content.local if do_attach else None,
                dest_path=dest_path if do_attach else None,
                fetch_remote=False,
                validate_url=False,
                # properties=file_properties,
            )

            if do_attach and (the_uri is not None):
                if the_uri.startswith("http") or the_uri.startswith("ftp"):
                    # See https://github.com/ResearchObject/ro-crate/pull/259
                    uri_key = "contentUrl"
                else:
                    uri_key = "identifier"

                crate_dataset[uri_key] = the_uri
            alternateName = (
                os.path.relpath(
                    the_content.local, os.path.join(self.work_dir, rel_work_dir)
                )
                + "/"
            )
            crate_dataset["alternateName"] = alternateName

            if isinstance(the_content.values, list):
                for the_val in the_content.values:
                    if isinstance(the_val, GeneratedContent):
                        the_val_file = self._add_GeneratedContent_to_crate(
                            the_val,
                            rel_work_dir=rel_work_dir,
                            do_attach=do_attach,
                        )
                        crate_dataset.append_to("hasPart", the_val_file, compact=True)
                        the_files_crates.append(the_val_file)
                    elif isinstance(the_val, GeneratedDirectoryContent):
                        (
                            the_val_dataset,
                            the_subfiles_crates,
                        ) = self._add_GeneratedDirectoryContent_as_dataset(
                            the_val,
                            rel_work_dir=rel_work_dir,
                            do_attach=do_attach,
                        )
                        if the_val_dataset is not None:
                            assert the_subfiles_crates is not None
                            crate_dataset.append_to(
                                "hasPart", the_val_dataset, compact=True
                            )
                            crate_dataset.append_to(
                                "hasPart", the_subfiles_crates, compact=True
                            )

                            the_files_crates.extend(the_subfiles_crates)

            # The very corner case of output directories with secondary files
            if (
                isinstance(the_content.secondaryFiles, list)
                and len(the_content.secondaryFiles) > 0
            ):
                crate_coll = self._add_collection_to_crate(main_entity=crate_dataset)

                for secFile in the_content.secondaryFiles:
                    gen_content: "Union[FixedFile, Collection, FixedDataset]"
                    if isinstance(secFile, GeneratedContent):
                        gen_content = self._add_GeneratedContent_to_crate(
                            secFile,
                            rel_work_dir=rel_work_dir,
                            do_attach=do_attach,
                        )
                    else:
                        # elif isinstance(secFile, GeneratedDirectoryContent):
                        (
                            gen_dir_content,
                            _,
                        ) = self._add_GeneratedDirectoryContent_as_dataset(
                            secFile,
                            rel_work_dir=rel_work_dir,
                            do_attach=do_attach,
                        )
                        assert gen_dir_content is not None
                        gen_content = gen_dir_content

                    crate_coll.append_to("hasPart", gen_content, compact=True)

                return crate_coll, the_files_crates
            else:
                return crate_dataset, the_files_crates

        return None, None
