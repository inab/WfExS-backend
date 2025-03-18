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

import atexit
import copy
import errno
import http.client
import inspect
import io
import logging
import os
import pathlib
import shutil
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
        EngineVersion,
        ExpectedOutput,
        Fingerprint,
        LocalWorkflow,
        PathLikePath,
        ProgsMapping,
        RelPath,
        RepoTag,
        RepoURL,
        StagedSetup,
        SymbolicParamName,
        SymbolicOutputName,
        URIType,
        WFLangVersion,
    )

    from .container_factories import (
        Container,
        ContainerEngineVersionStr,
        ContainerOperatingSystem,
        ProcessorArchitecture,
    )

    from .fetchers import (
        RemoteRepo,
    )

    from .workflow_engines import (
        MaterializedWorkflowEngine,
        StagedExecution,
        WorkflowType,
        WorkflowEngineVersionStr,
    )

    from .utils.licences import (
        LicenceMatcher,
    )

import urllib.parse
import uuid

from .utils.misc import (
    is_uri,
    lazy_import,
)
from .utils.rocrate import (
    ContainerType2AdditionalType,
    ContainerTypeMetadata,
    ContainerTypeMetadataDetails,
    WFEXS_TERMS_CONTEXT,
    WFEXS_TERMS_NAMESPACE,
    WORKFLOW_RUN_CONTEXT,
    WORKFLOW_RUN_NAMESPACE,
)

from .workflow_engines import (
    WorkflowEngine,
)

magic = lazy_import("magic")
# import magic

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
    iso_now,
)

from .fetchers import (
    FetcherException,
)

from .utils.orcid import (
    validate_orcid,
)

from .utils.contents import (
    MaterializedContent2AbstractGeneratedContent,
    Path2AbstractGeneratedContent,
)

from .utils.digests import (
    ComputeDigestFromDirectory,
    ComputeDigestFromFile,
    ComputeDigestFromObject,
    hexDigest,
    nullProcessDigest,
    unstringifyDigest,
)
from .utils.licences import (
    LicenceMatcherSingleton,
)
from .utils.marshalling_handling import (
    marshall_namedtuple,
)
from .common import (
    AbstractWfExSException,
    CC_BY_40_LicenceDescription,
    ContainerType,
    ContentKind,
    CratableItem,
    DEFAULT_DOT_CMD,
    GeneratedContent,
    GeneratedDirectoryContent,
    LicenceDescription,
    MaterializedContent,
    MaterializedInput,
    MaterializedOutput,
    META_JSON_POSTFIX,
    NoCratableItem,
    NoLicence,
    NoLicenceDescription,
    NoLicenceShort,
    ResolvedORCID,
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
                "@id": "https://bioschemas.org/profiles/FormalParameter/1.0-RELEASE",
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
        self.dest_path = dest_path
        if dest_path is not None:
            dest_path = pathlib.Path(dest_path)
            if dest_path.is_absolute():
                raise ValueError("if provided, dest_path must be relative")
            if identifier is None:
                identifier = urllib.parse.quote(dest_path.as_posix())
        elif identifier is None:
            if not isinstance(source, (str, pathlib.Path)):
                raise ValueError(
                    "dest_path must be provided if source is not a path or URI"
                )
            elif is_uri(str(source)):
                identifier = os.path.basename(source) if fetch_remote else str(source)
            else:
                identifier = "./" if source == "./" else os.path.basename(source)
        super(rocrate.model.file_or_dir.FileOrDir, self).__init__(
            crate, identifier, properties
        )


class FixedFile(FixedMixin, rocrate.model.file.File):  # type: ignore[misc]
    def write(self, base_path: "PathLikePath") -> "None":
        base_path_p: "pathlib.Path"
        if isinstance(base_path, pathlib.Path):
            base_path_p = base_path
        else:
            base_path_p = pathlib.Path(base_path)
        if self.dest_path is not None:
            out_file_path = base_path_p / self.dest_path
        else:
            out_file_path = base_path_p / self.id
        if isinstance(self.source, (io.BytesIO, io.StringIO)):
            out_file_path.parent.mkdir(parents=True, exist_ok=True)
            mode = "w" + ("b" if isinstance(self.source, io.BytesIO) else "t")
            with out_file_path.open(mode=mode) as out_file:
                out_file.write(self.source.getvalue())
        elif self.source is None:
            # Allows to record a File entity whose @id does not exist, see #73
            warnings.warn(f"No source for {self.id}")
        elif is_uri(str(self.source)):
            if self.fetch_remote or self.validate_url:
                with urllib.request.urlopen(str(self.source)) as response:
                    if self.validate_url:
                        if isinstance(response, http.client.HTTPResponse):
                            self._jsonld.update(  # type: ignore[attr-defined]
                                {
                                    "contentSize": response.getheader("Content-Length"),
                                    "encodingFormat": response.getheader(
                                        "Content-Type"
                                    ),
                                }
                            )
                        if not self.fetch_remote:
                            self._jsonld["sdDatePublished"] = iso_now()  # type: ignore[attr-defined]
                    if self.fetch_remote:
                        out_file_path.parent.mkdir(parents=True, exist_ok=True)
                        urllib.request.urlretrieve(response.url, out_file_path)
                        self._jsonld["contentUrl"] = str(self.source)  # type: ignore[attr-defined]
        else:
            out_file_path.parent.mkdir(parents=True, exist_ok=True)
            if not out_file_path.exists() or not out_file_path.samefile(self.source):
                shutil.copy(self.source, out_file_path)


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
    def write(self, base_path: "Union[str, os.PathLike[str]]") -> "None":
        if isinstance(base_path, pathlib.Path):
            base_path_p = base_path
        else:
            base_path_p = pathlib.Path(base_path)
        if self.dest_path is not None:
            out_path = base_path_p / self.dest_path
        else:
            out_path = base_path_p / self.id
        if self.source is None:
            pass
            # out_path.mkdir(parents=True, exist_ok=True)
        elif is_uri(str(self.source)):
            if self.validate_url and not self.fetch_remote:
                with urllib.request.urlopen(str(self.source)) as _:
                    self._jsonld["sdDatePublished"] = iso_now()  # type: ignore[attr-defined]
            if self.fetch_remote:
                self.__get_parts(out_path)  # type: ignore[attr-defined]
        else:
            if not pathlib.Path(self.source).exists():
                raise FileNotFoundError(
                    errno.ENOENT, os.strerror(errno.ENOENT), str(self.source)
                )
            out_path.mkdir(parents=True, exist_ok=True)
            if not self.crate.source:
                self.crate._copy_unlisted(self.source, out_path)  # type: ignore[attr-defined]


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


class WorkflowRunROCrate:
    """
    This class rules the generation of an RO-Crate
    """

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
        licences: "Sequence[LicenceDescription]" = [],
        orcids: "Sequence[Union[str, ResolvedORCID]]" = [],
        progs: "ProgsMapping" = {},
        tempdir: "Optional[pathlib.Path]" = None,
        scheme_desc: "Sequence[Tuple[str, str, int]]" = [],
        crate_pid: "Optional[str]" = None,
        licence_matcher: "Optional[LicenceMatcher]" = None,
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
        self._added_container_images: "MutableMapping[int, ContainerImage]" = {}
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
            licences = [NoLicenceDescription]

        # This is only used for licences attached to materialized content
        if licence_matcher is None:
            licence_matcher = LicenceMatcherSingleton()
        self.licence_matcher = licence_matcher

        if localWorkflow.relPath is not None:
            wf_local_path = localWorkflow.dir / localWorkflow.relPath
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
        self.workflow_type = materializedEngine.instance.workflowType
        self._init_empty_crate_and_ComputerLanguage(
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
                resolved_orcid: "Optional[ResolvedORCID]"
                if isinstance(orcid, ResolvedORCID):
                    resolved_orcid = orcid
                else:
                    resolved_orcid = validate_orcid(orcid)

                if resolved_orcid is not None:
                    agent = rocrate.model.person.Person(
                        self.crate, identifier=resolved_orcid.url
                    )

                    # enrich agent entry from the metadata obtained from the ORCID
                    agent_name = resolved_orcid.record.get("displayName")
                    if agent_name is not None:
                        agent["name"] = agent_name

                    emails_dict = resolved_orcid.record.get("emails", {})
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
                                        contact_point["url"] = resolved_orcid.url

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
        langVersion: "Optional[Union[EngineVersion, WFLangVersion]]",
        licences: "Sequence[LicenceDescription]",
        crate_pid: "Optional[str]",
    ) -> "None":
        wf_type = self.workflow_type
        """
        Due the internal synergies between an instance of ComputerLanguage
        and the RO-Crate it is attached to, both of them should be created
        here, just at the same time
        """

        self.crate = FixedROCrate(gen_preview=False)
        if crate_pid is not None:
            self.crate.root_dataset.append_to("identifier", crate_pid, compact=True)

        RO_licences = self._process_licences(licences)

        # Add extra terms
        self.crate.metadata.extra_terms.update(
            {
                # "sha256": WORKFLOW_RUN_NAMESPACE + "sha256",
                # # Next ones are experimental
                # ContainerImageAdditionalType.Docker.value: WORKFLOW_RUN_NAMESPACE
                # + ContainerImageAdditionalType.Docker.value,
                # ContainerImageAdditionalType.Singularity.value: WORKFLOW_RUN_NAMESPACE
                # + ContainerImageAdditionalType.Singularity.value,
                # "containerImage": WORKFLOW_RUN_NAMESPACE + "containerImage",
                # "ContainerImage": WORKFLOW_RUN_NAMESPACE + "ContainerImage",
                # "registry": WORKFLOW_RUN_NAMESPACE + "registry",
                # "tag": WORKFLOW_RUN_NAMESPACE + "tag",
                # "syntheticOutput": WFEXS_TERMS_NAMESPACE + "syntheticOutput",
                # "globPattern": WFEXS_TERMS_NAMESPACE + "globPattern",
                # "filledFrom": WFEXS_TERMS_NAMESPACE + "filledFrom",
                "contentWithURIs": WFEXS_TERMS_NAMESPACE + "contentWithURIs",
                "headerRows": WFEXS_TERMS_NAMESPACE + "headerRows",
                "rowSep": WFEXS_TERMS_NAMESPACE + "rowSep",
                "columnSep": WFEXS_TERMS_NAMESPACE + "columnSep",
                "uriColumns": WFEXS_TERMS_NAMESPACE + "uriColumns",
            }
        )
        self.crate.metadata.extra_contexts.append(WORKFLOW_RUN_CONTEXT)
        self.crate.metadata.extra_contexts.append(WFEXS_TERMS_CONTEXT)

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
        self, licdescs: "Sequence[LicenceDescription]"
    ) -> "Sequence[Union[str, rocrate.model.creativework.CreativeWork]]":
        RO_licences: "MutableSequence[Union[str, rocrate.model.creativework.CreativeWork]]" = (
            []
        )
        for licdesc in licdescs:
            RO_licences.append(self._process_licence(licdesc))

        return RO_licences

    def _process_licence(
        self, licdesc: "LicenceDescription"
    ) -> "Union[str, rocrate.model.creativework.CreativeWork]":
        parsed_lic: "Union[str, rocrate.model.creativework.CreativeWork]"
        rec_lic: "bool" = False
        # In order to avoid so prominent "No Permission url"
        if licdesc.short == NoLicenceShort or licdesc.get_uri() == NoLicence:
            parsed_lic = NoLicenceShort
        else:
            lic_uri = licdesc.get_uri()
            cw = cast(
                "Optional[rocrate.model.creativework.CreativeWork]",
                self.crate.dereference(lic_uri),
            )
            if cw is None:
                rec_lic = True
                parsed_lic = rocrate.model.creativework.CreativeWork(
                    self.crate,
                    identifier=lic_uri,
                    properties={
                        "identifier": licdesc.short,
                        "name": licdesc.description,
                        "url": licdesc.uris[0]
                        if len(licdesc.uris) == 1
                        else licdesc.uris,
                    },
                )
            else:
                parsed_lic = cw

        if rec_lic and isinstance(parsed_lic, rocrate.model.creativework.CreativeWork):
            self.crate.add(parsed_lic)

        return parsed_lic

    def _add_wfexs_to_crate(
        self, scheme_desc: "Sequence[Tuple[str, str, int]]"
    ) -> "rocrate.model.softwareapplication.SoftwareApplication":
        # First, the profiles to be attached to the root dataset
        wrroc_profiles = [
            rocrate.model.creativework.CreativeWork(
                self.crate,
                identifier="https://w3id.org/ro/wfrun/process/0.5",
                properties={"name": "ProcessRun Crate", "version": "0.5"},
            ),
            rocrate.model.creativework.CreativeWork(
                self.crate,
                identifier="https://w3id.org/ro/wfrun/workflow/0.5",
                properties={"name": "Workflow Run Crate", "version": "0.5"},
            ),
            # TODO: This one can be enabled only when proper provenance
            # describing the execution steps is implemented
            # rocrate.model.creativework.CreativeWork(
            #     self.crate,
            #     identifier="https://w3id.org/ro/wfrun/provenance/0.5",
            #     properties={"name": "Provenance Run Crate", "version": "0.5"},
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

## Possibly used URI schemes

As {wfexs_backend_name} is able to manage several exotic CURIEs and schemes,
you can find here an almost complete list of the possible ones:

* {scheme_desc_str}
""",
                file=wMD,
            )

        readme_file = self._add_file_to_crate(
            pathlib.Path(readme_md_path),
            the_uri=None,
            the_name=cast("RelPath", "README.md"),
            the_mime="text/markdown",
            the_licences=[CC_BY_40_LicenceDescription],
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
                container_type_metadata = ContainerTypeMetadataDetails[container.type]
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
                    container_source_type_metadata = ContainerTypeMetadataDetails[
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

                # Skip early what it was already included in the crate
                if id(container) in self._added_container_images:
                    added_containers.append(self._added_container_images[id(container)])
                    continue

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
                        if digest is None or digest == False:
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
                    # Now, add container metadata, which is going to be
                    # consumed by WfExS or third parties
                    metadataLocalPath: "Optional[pathlib.Path]" = None
                    if container.metadataLocalPath is not None:
                        metadataLocalPath = container.metadataLocalPath
                    # This code is needed for old working directories
                    if metadataLocalPath is None and container.localPath is not None:
                        metadataLocalPath = container.localPath.with_name(
                            container.localPath.name + META_JSON_POSTFIX
                        )

                    if metadataLocalPath is not None and metadataLocalPath.exists():
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

                # Record the container image
                self._added_container_images[id(container)] = cast(
                    "ContainerImage", crate_cont
                )

                added_containers.append(cast("ContainerImage", crate_cont))

        return added_containers

    def _add_reference_from_MaterializedContent(
        self, mat_content: "MaterializedContent"
    ) -> "Optional[FixedMixin]":
        the_ref_crate: "Optional[FixedMixin]" = None
        if mat_content.reference_uri is not None:
            the_uri = mat_content.reference_uri.uri

            the_ref_crate = cast(
                "Optional[FixedMixin]", self.crate.dereference(the_uri)
            )
            if the_ref_crate is None:
                assert mat_content.reference_kind is not None
                if mat_content.reference_kind == ContentKind.File:
                    the_ref_crate = self.crate.add_file_ext(
                        identifier=the_uri,
                        source=None,
                        dest_path=None,
                        fetch_remote=False,
                        validate_url=False,
                        clazz=FixedFile,
                    )
                elif mat_content.reference_kind == ContentKind.Directory:
                    the_ref_crate = self.crate.add_dataset_ext(
                        identifier=the_uri,
                        source=None,
                        dest_path=None,
                        fetch_remote=False,
                        validate_url=False,
                    )
                else:
                    # TODO: emit a warning or raise a exception
                    return None

                if the_uri.startswith("http") or the_uri.startswith("ftp"):
                    # See https://github.com/ResearchObject/ro-crate/pull/259
                    uri_key = "contentUrl"
                else:
                    uri_key = "identifier"

                the_ref_crate[uri_key] = the_uri

                if mat_content.reference_uri.licences is not None:
                    for licence in mat_content.reference_uri.licences:
                        matched_licence: "Optional[LicenceDescription]"
                        if isinstance(licence, LicenceDescription):
                            matched_licence = licence
                        else:
                            matched_licence = self.licence_matcher.matchLicence(licence)

                        if matched_licence is not None:
                            the_ref_crate.append_to(
                                "license",
                                self._process_licence(matched_licence),
                                compact=True,
                            )

                if mat_content.reference_size is not None:
                    the_ref_crate.append_to(
                        "contentSize", str(mat_content.reference_size), compact=True
                    )

                if mat_content.reference_mime is not None:
                    the_ref_crate.append_to(
                        "encodingFormat", mat_content.reference_mime, compact=True
                    )

                if mat_content.reference_fingerprint is not None:
                    digest, algo = extract_digest(mat_content.reference_fingerprint)
                    if digest is not None and digest != False:
                        assert algo is not None
                        the_signature = hexDigest(algo, digest)
                        the_ref_crate.append_to("sha256", the_signature, compact=True)

        return the_ref_crate

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

        failed_licences: "MutableSequence[URIType]" = []
        for in_item in inputs:
            # Skip autoFilled inputs, as they should have their
            # mirror parameters in outputs
            if in_item.autoFilled:
                continue

            formal_parameter_id = (
                f"{self.wf_file.id}#{input_sep}:"
                + urllib.parse.quote(in_item.name, safe="")
            )

            additional_type: "Optional[str]" = None
            is_content_with_uris = False
            if in_item.values is not None:
                itemInValue0 = in_item.values[0]
                # A bool is an instance of int in Python
                if isinstance(itemInValue0, bool):
                    additional_type = "Boolean"
                elif isinstance(itemInValue0, int):
                    additional_type = "Integer"
                elif isinstance(itemInValue0, str):
                    additional_type = "Text"
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
                        is_content_with_uris = (
                            itemInValue0.kind == ContentKind.ContentWithURIs
                        )
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
                # This one must be a real boolean, as of schema.org
                formal_parameter["valueRequired"] = value_required

                if is_content_with_uris:
                    assert in_item.contentWithURIs is not None

                    formal_parameter["contentWithURIs"] = True
                    formal_parameter[
                        "encodingFormat"
                    ] = in_item.contentWithURIs.encodingFormat
                    formal_parameter["headerRows"] = in_item.contentWithURIs.setup[
                        "headerRows"
                    ]
                    formal_parameter["rowSep"] = in_item.contentWithURIs.setup["rowSep"]
                    formal_parameter["columnSep"] = in_item.contentWithURIs.setup[
                        "columnSep"
                    ]
                    formal_parameter["uriColumns"] = in_item.contentWithURIs.setup[
                        "uriColumns"
                    ]

            item_signature = cast(
                "bytes",
                ComputeDigestFromObject(
                    marshall_namedtuple(in_item.values, workdir=self.work_dir),
                    repMethod=nullProcessDigest,
                ),
            ) + formal_parameter_id.encode("utf-8")
            # Do we already have the value in cache?
            crate_coll = cast(
                "Union[Collection, FixedDataset, FixedFile, PropertyValue, None]",
                self._item_hash.get(item_signature),
            )
            # We don't, so let's populate it
            if crate_coll is None:
                if in_item.values is not None and len(in_item.values) > 1:
                    crate_coll = self._add_collection_to_crate()

                if additional_type in ("File", "Dataset", "Collection"):
                    for itemInValues in cast(
                        "Sequence[MaterializedContent]", in_item.values
                    ):
                        # TODO: embed metadata_array in some way
                        assert isinstance(itemInValues, MaterializedContent)
                        itemInLocalSource = pathlib.Path(
                            itemInValues.local
                        )  # local source
                        itemInURISource = itemInValues.licensed_uri.uri  # uri source

                        itemInURILicences: "Optional[MutableSequence[LicenceDescription]]" = (
                            None
                        )
                        if itemInValues.licensed_uri.licences is not None:
                            itemInURILicences = []
                            for licence in itemInValues.licensed_uri.licences:
                                matched_licence: "Optional[LicenceDescription]"
                                if isinstance(licence, LicenceDescription):
                                    matched_licence = licence
                                else:
                                    matched_licence = self.licence_matcher.matchLicence(
                                        licence
                                    )
                                    if matched_licence is None:
                                        failed_licences.append(licence)

                                if matched_licence is not None:
                                    itemInURILicences.append(matched_licence)

                        ref_mixin = self._add_reference_from_MaterializedContent(
                            itemInValues
                        )

                        if itemInLocalSource.is_file():
                            the_signature: "Optional[Fingerprint]" = None
                            if itemInValues.fingerprint is not None:
                                digest, algo = extract_digest(itemInValues.fingerprint)
                                if digest is not None and digest != False:
                                    assert algo is not None
                                    the_signature = hexDigest(algo, digest)

                            # This is needed to avoid including the input
                            crate_file = self._add_file_to_crate(
                                the_path=itemInLocalSource,
                                the_uri=itemInURISource,
                                the_name=cast(
                                    "RelPath",
                                    itemInLocalSource.relative_to(
                                        self.work_dir
                                    ).as_posix(),
                                ),
                                the_signature=the_signature,
                                the_licences=itemInURILicences,
                                do_attach=do_attach
                                and in_item.disclosable
                                and itemInValues.clonable,
                            )
                            if ref_mixin is not None:
                                crate_file.append_to(
                                    "isPartOf", ref_mixin, compact=True
                                )

                            # An extrapolated input, which needs special handling
                            if itemInValues.extrapolated_local is not None:
                                crate_extrapolated_file = self._add_file_to_crate(
                                    the_path=pathlib.Path(
                                        itemInValues.extrapolated_local
                                    ),
                                    the_uri=None,
                                    the_name=cast(
                                        "RelPath",
                                        os.path.relpath(
                                            itemInValues.extrapolated_local,
                                            self.work_dir,
                                        ),
                                    ),
                                    do_attach=in_item.disclosable
                                    and itemInValues.clonable,
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

                        elif itemInLocalSource.is_dir():
                            crate_dataset, _ = self._add_directory_as_dataset(
                                itemInLocalSource,
                                itemInURISource,
                                the_name=cast(
                                    "RelPath",
                                    itemInLocalSource.relative_to(
                                        self.work_dir
                                    ).as_posix()
                                    + "/",
                                ),
                                do_attach=do_attach
                                and in_item.disclosable
                                and itemInValues.clonable,
                            )
                            # crate_dataset = self.crate.add_dataset_ext(
                            #    source=itemInURISource,
                            #    fetch_remote=False,
                            #    validate_url=False,
                            #    do_attach=do_attach,
                            #    # properties=file_properties,
                            # )

                            if crate_dataset is not None:
                                if ref_mixin is not None:
                                    crate_dataset.append_to(
                                        "isPartOf", ref_mixin, compact=True
                                    )

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
                    if in_item.values is not None:
                        for itemInAtomicValues in cast(
                            "Sequence[Union[bool,str,float,int]]", in_item.values
                        ):
                            if isinstance(itemInAtomicValues, (bool, str, float, int)):
                                some_not_null = True
                                break

                    if some_not_null:
                        assert in_item.values is not None
                        if in_item.implicit and len(in_item.values) == 1:
                            the_default_value: "Union[bool,str,float,int]"
                            if isinstance(in_item.values[0], (bool, int, float)):
                                the_default_value = in_item.values[0]
                            else:
                                the_default_value = str(in_item.values[0])
                            formal_parameter["defaultValue"] = the_default_value

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
                                the_value: "Union[bool,str,float,int]"
                                if isinstance(fixedAtomicValue, (bool, int, float)):
                                    the_value = fixedAtomicValue
                                else:
                                    the_value = str(fixedAtomicValue)
                                parameter_value = PropertyValue(
                                    self.crate, in_item.name, value=the_value
                                )
                                crate_pv = self.crate.add(parameter_value)
                                if isinstance(crate_coll, Collection):
                                    crate_coll.append_to(
                                        "hasPart", crate_pv, compact=True
                                    )
                                else:
                                    crate_coll = crate_pv
                    # TODO:
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
                            # Properly curate secondary input licences
                            secInputURILicences: "Optional[MutableSequence[LicenceDescription]]" = (
                                None  # licences
                            )

                            if secInput.licensed_uri.licences is not None:
                                secInputURILicences = []
                                for licence in secInput.licensed_uri.licences:
                                    sec_matched_licence: "Optional[LicenceDescription]"
                                    if isinstance(licence, LicenceDescription):
                                        sec_matched_licence = licence
                                    else:
                                        sec_matched_licence = (
                                            self.licence_matcher.matchLicence(licence)
                                        )
                                        if sec_matched_licence is None:
                                            failed_licences.append(licence)

                                    if sec_matched_licence is not None:
                                        secInputURILicences.append(sec_matched_licence)

                            ref_mixin = self._add_reference_from_MaterializedContent(
                                secInput
                            )

                            if os.path.isfile(secInputLocalSource):
                                # This is needed to avoid including the input
                                the_sec_signature: "Optional[Fingerprint]" = None
                                if secInput.fingerprint is not None:
                                    sec_digest, sec_algo = extract_digest(
                                        secInput.fingerprint
                                    )
                                    if sec_digest is not None and sec_digest != False:
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
                                    do_attach=do_attach
                                    and in_item.disclosable
                                    and secInput.clonable,
                                )

                            elif os.path.isdir(secInputLocalSource):
                                sec_crate_elem, _ = self._add_directory_as_dataset(
                                    secInputLocalSource,
                                    secInputURISource,
                                    do_attach=do_attach
                                    and in_item.disclosable
                                    and secInput.clonable,
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

                                if ref_mixin is not None:
                                    sec_crate_elem.append_to(
                                        "isPartOf", ref_mixin, compact=True
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

        if len(failed_licences) > 0:
            raise ROCrateGenerationException(
                f"Unsupported Workflow RO-Crate short license(s) or license URI scheme(s): {', '.join(failed_licences)}"
            )

            # TODO digest other types of inputs
        return crate_inputs

    def _add_file_to_crate(
        self,
        the_path: "pathlib.Path",
        the_uri: "Optional[URIType]",
        the_id: "Optional[str]" = None,
        the_name: "Optional[RelPath]" = None,
        the_alternate_name: "Optional[RelPath]" = None,
        the_size: "Optional[int]" = None,
        the_signature: "Optional[Fingerprint]" = None,
        the_licences: "Optional[Sequence[LicenceDescription]]" = None,
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
            the_id = the_name if the_name is not None else the_uri

        the_file_crate = self.crate.add_file_ext(
            identifier=the_id,
            source=the_path if do_attach else None,
            dest_path=the_name,
            clazz=SourceCodeFile if is_soft_source else FixedFile,
        )
        if the_uri is not None:
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
        the_path: "pathlib.Path",
        the_uri: "Optional[URIType]",
        the_id: "Optional[str]" = None,
        the_name: "Optional[RelPath]" = None,
        the_alternate_name: "Optional[RelPath]" = None,
        do_attach: "bool" = True,
    ) -> "Union[Tuple[FixedDataset, Sequence[FixedFile]], Tuple[None, None]]":
        # FUTURE IMPROVEMENT
        # Describe datasets referred from DOIs
        # as in https://github.com/ResearchObject/ro-crate/pull/255/files

        if not the_path.is_dir():
            return None, None

        if the_name is not None and not the_name.endswith("/"):
            the_name = cast("RelPath", the_name + "/")

        if the_alternate_name is not None and not the_alternate_name.endswith("/"):
            the_alternate_name = cast("RelPath", the_alternate_name + "/")

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
            dest_path=the_name,
            fetch_remote=False,
            validate_url=False,
            # properties=file_properties,
        )
        if the_uri is not None:
            the_uri_parsed = urllib.parse.urlparse(the_uri)

            if the_uri_parsed.scheme in ("http", "https", "ftp", "file"):
                # See https://github.com/ResearchObject/ro-crate/pull/259
                uri_key = "contentUrl"
            else:
                uri_key = "identifier"

            crate_dataset[uri_key] = the_uri
        else:
            the_uri_parsed = None
        if the_alternate_name is not None:
            crate_dataset["alternateName"] = the_alternate_name

        # Now, recursively walk it
        with os.scandir(the_path) as the_dir:
            for the_file in the_dir:
                if the_file.name[0] == ".":
                    continue
                if the_uri_parsed is not None:
                    if the_uri_parsed.scheme in ("http", "https", "ftp", "file", "s3"):
                        new_path = the_uri_parsed.path
                        if not new_path.endswith("/"):
                            new_path += "/"
                        new_path += urllib.parse.quote(the_file.name, safe="")
                        the_item_uri = urllib.parse.urlunparse(
                            the_uri_parsed._replace(path=new_path)
                        )
                    else:
                        new_fragment = the_uri_parsed.fragment
                        if len(new_fragment) > 0:
                            new_fragment += "/"
                        new_fragment += urllib.parse.quote(the_file.name, safe="")
                        the_item_uri = urllib.parse.urlunparse(
                            the_uri_parsed._replace(fragment=new_fragment)
                        )
                else:
                    the_item_uri = None
                if the_file.is_file():
                    the_file_crate = self._add_file_to_crate(
                        the_path=pathlib.Path(the_file.path),
                        the_uri=cast("Optional[URIType]", the_item_uri),
                        the_name=None
                        if the_name is None
                        else cast("RelPath", the_name + the_file.name),
                        the_alternate_name=None
                        if the_alternate_name is None
                        else cast("RelPath", the_alternate_name + the_file.name),
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
                        the_path=pathlib.Path(the_file.path),
                        the_uri=cast("Optional[URIType]", the_item_uri),
                        the_name=None
                        if the_name is None
                        else cast("RelPath", the_name + the_file.name),
                        the_alternate_name=None
                        if the_alternate_name is None
                        else cast("RelPath", the_alternate_name + the_file.name),
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
        the_path: "pathlib.Path"
        if the_workflow.relPath is not None:
            if os.path.isabs(the_workflow.relPath):
                the_path = pathlib.Path(the_workflow.relPath)
            else:
                the_path = the_workflow.dir / the_workflow.relPath
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
                    wf_url += the_workflow.dir.as_posix().rsplit("workflow")[1]

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
                    self.logger.warning(
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
        assert self.staged_setup.workflow_dir is not None
        the_alternate_name = os.path.relpath(the_path, self.staged_setup.workflow_dir)
        if do_attach:
            # if wf_entrypoint_url is not None:
            #    # This is needed to avoid future collisions with other workflows stored in the RO-Crate
            #    rocrate_wf_folder = str(
            #        uuid.uuid5(uuid.NAMESPACE_URL, wf_entrypoint_url)
            #    )
            # else:
            #    rocrate_wf_folder = str(uuid.uuid4())

            the_name = os.path.join(
                rocrate_wf_folder, os.path.relpath(the_path, the_workflow.dir)
            )

        # When the id is none and ...
        the_id = the_name if do_attach or (the_uri is None) else the_uri
        assert the_id is not None

        rocrate_file_id_base = the_id if the_uri is None else the_uri

        the_workflow_crate = self.crate.add_workflow_ext(
            identifier=the_id,
            source=the_path if do_attach else None,
            dest_path=the_name,
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

        if the_uri is not None:
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
            rel_entities: "MutableSequence[Union[FixedFile, rocrate.model.creativework.CreativeWork, FixedDataset]]" = (
                []
            )
            for rel_file in the_workflow.relPathFiles:
                if rel_file == the_workflow.relPath:
                    # Ignore itself, so it is not overwritten
                    continue

                # First, are we dealing with relative files or with URIs?
                p_rel_file = urllib.parse.urlparse(rel_file)
                the_entity: "Union[FixedFile, rocrate.model.creativework.CreativeWork, FixedDataset]"
                if p_rel_file.scheme != "":
                    the_entity = rocrate.model.creativework.CreativeWork(
                        self.crate,
                        identifier=rel_file,
                    )
                    self.crate.add(the_entity)
                else:
                    rel_file_steps = rel_file.split(os.sep)
                    rocrate_file_id = (
                        rocrate_file_id_base
                        + "#"
                        + "/".join(
                            map(
                                lambda s: urllib.parse.quote(s, safe=""), rel_file_steps
                            )
                        )
                    )
                    the_s_name = cast(
                        "RelPath", os.path.join(rocrate_wf_folder, rel_file)
                    )
                    the_alternate_name = os.path.relpath(
                        os.path.join(the_workflow.dir, rel_file),
                        self.staged_setup.workflow_dir,
                    )
                    abs_file = pathlib.Path(the_workflow.dir) / rel_file
                    if abs_file.is_file():
                        the_entity = self._add_file_to_crate(
                            the_path=abs_file,
                            the_name=the_s_name,
                            the_alternate_name=cast("RelPath", the_alternate_name),
                            the_uri=cast("URIType", rocrate_file_id),
                            do_attach=do_attach,
                            is_soft_source=True,
                        )
                    elif abs_file.is_dir():
                        (
                            the_possible_entity,
                            the_files_within_the_entity,
                        ) = self._add_directory_as_dataset(
                            the_path=abs_file,
                            the_name=the_s_name,
                            the_alternate_name=cast("RelPath", the_alternate_name),
                            the_uri=cast("URIType", rocrate_file_id),
                            do_attach=do_attach,
                        )
                        if the_possible_entity is None:
                            raise ROCrateGenerationException(
                                f"Unable to include {abs_file} directory into the RO-Crate being generated"
                            )

                        the_entity = the_possible_entity
                    else:
                        raise ROCrateGenerationException(
                            f"Unable to include {abs_file} into the RO-Crate being generated (unmanaged file object)"
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

                # This one must be a real boolean, as of schema.org
                if out_item.syntheticOutput is not None:
                    formal_parameter["valueRequired"] = not out_item.syntheticOutput
                    formal_parameter["syntheticOutput"] = out_item.syntheticOutput
                    if out_item.syntheticOutput:
                        if out_item.glob is not None:
                            formal_parameter["globPattern"] = out_item.glob
                    if out_item.fillFrom is not None:
                        # This is a bit dirty, but effective
                        formal_parameter["filledFrom"] = out_item.fillFrom

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

    def writeWRROC(self, filename: "pathlib.Path") -> None:
        with warnings.catch_warnings():
            # Disable possible warnings emitted by rocrate-py library
            # when it is not run in debug mode
            if self.logger.getEffectiveLevel() > logging.DEBUG:
                warnings.filterwarnings(
                    "ignore", category=UserWarning, module=r"^rocrate\.model\.file$"
                )
            self.crate.write_zip(filename.as_posix())

    def addStagedWorkflowDetails(
        self,
        inputs: "Sequence[MaterializedInput]",
        environment: "Sequence[MaterializedInput]",
        outputs: "Optional[Sequence[ExpectedOutput]]",
        profiles: "Optional[Sequence[str]]" = None,
    ) -> None:
        """
        This method is used for WRROCs with only prospective provenance
        """
        augmented_inputs: "Sequence[MaterializedInput]"
        if profiles:
            augmented_inputs = [
                MaterializedInput(
                    name=cast("SymbolicParamName", "-profile"),
                    values=profiles,
                ),
                *inputs,
            ]
        else:
            augmented_inputs = inputs
        self.addWorkflowInputs(augmented_inputs, are_envvars=False)

        if len(environment) > 0:
            self.addWorkflowInputs(environment, are_envvars=True)

        if outputs is not None:
            self.addWorkflowExpectedOutputs(outputs)

    def addWorkflowExecution(
        self,
        stagedExec: "StagedExecution",
        expected_outputs: "Optional[Sequence[ExpectedOutput]]" = None,
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
            "Run " + stagedExec.outputsDir.name + " of " + self.wf_file.id,
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

        augmented_inputs: "Sequence[MaterializedInput]"
        if stagedExec.profiles:
            # Profiles are represented as this custom parameter
            # assuming no parameter name can start with a minus
            augmented_inputs = [
                MaterializedInput(
                    name=cast("SymbolicParamName", "-profile"),
                    values=stagedExec.profiles,
                ),
                *stagedExec.augmentedInputs,
            ]
        else:
            augmented_inputs = stagedExec.augmentedInputs
        crate_inputs = self.addWorkflowInputs(
            augmented_inputs,
            are_envvars=False,
        )
        crate_action["object"] = crate_inputs

        # Add environment, according to WRROC 0.5
        if len(stagedExec.environment) > 0:
            crate_envvars = self.addWorkflowInputs(
                stagedExec.environment,
                are_envvars=True,
            )
            crate_action["environment"] = crate_envvars

        # TODO: Add engine specific traces
        # see https://www.researchobject.org/workflow-run-crate/profiles/workflow_run_crate#adding-engine-specific-traces
        # TODO: Add "augmented environment variables"

        augmented_outputs: "Sequence[MaterializedOutput]"
        if not self.workflow_type.has_explicit_outputs:
            if expected_outputs is None:
                expected_outputs = []
            expected_outputs_h: "Mapping[str, ExpectedOutput]" = {
                expected_output.name: expected_output
                for expected_output in expected_outputs
            }
            # This code is needed to heal old nextflow-like executions.
            # First, identify what it should be transferred,
            # in case it does not appear yet
            not_synthetic_inputs: "MutableMapping[str, MaterializedInput]" = {}
            for augmented_input in stagedExec.augmentedInputs:
                if augmented_input.autoFilled:
                    not_synthetic_inputs[augmented_input.name] = augmented_input

            the_augmented_outputs: "MutableSequence[MaterializedOutput]" = []
            for mat_output in stagedExec.matCheckOutputs:
                if (
                    mat_output.name not in not_synthetic_inputs
                    and mat_output.syntheticOutput is None
                ):
                    augmented_output = mat_output._replace(syntheticOutput=True)
                else:
                    del not_synthetic_inputs[mat_output.name]
                    augmented_output = mat_output

                the_augmented_outputs.append(augmented_output)

            # What it is still in not_synthetic_inputs is what
            # it has to be injected as an output
            for augmented_input in not_synthetic_inputs.values():
                preferred_filename: "Optional[RelPath]" = None
                expected_output = expected_outputs_h.get(augmented_input.name)
                if expected_output is not None:
                    preferred_filename = expected_output.preferredFilename

                assert (
                    augmented_input.values is not None
                    and len(augmented_input.values) > 0
                )
                if isinstance(augmented_input.values[0], MaterializedContent):
                    kind = augmented_input.values[0].kind
                elif isinstance(augmented_input.values[0], str):
                    # It is a bare path (sigh, technical debt)
                    the_path = augmented_input.values[0]
                    assert os.path.exists(the_path)
                    kind = (
                        ContentKind.Directory
                        if os.path.isdir(the_path)
                        else ContentKind.File
                    )
                else:
                    raise ROCrateGenerationException(
                        "Unexpected type of augmented input for expected output healing"
                    )

                non_synthetic_values: "MutableSequence[AbstractGeneratedContent]" = []
                for mat_content in cast(
                    "Sequence[Union[str, MaterializedContent]]", augmented_input.values
                ):
                    non_synthetic_values.append(
                        MaterializedContent2AbstractGeneratedContent(
                            mat_content, preferred_filename
                        )
                        if isinstance(mat_content, MaterializedContent)
                        else Path2AbstractGeneratedContent(
                            pathlib.Path(mat_content), preferred_filename
                        )
                    )

                the_augmented_outputs.append(
                    MaterializedOutput(
                        name=cast("SymbolicOutputName", augmented_input.name),
                        kind=kind,
                        expectedCardinality=WorkflowEngine.GuessedCardinalityMapping[
                            len(non_synthetic_values) > 1
                        ],
                        values=non_synthetic_values,
                        syntheticOutput=False,
                        filledFrom=augmented_input.name,
                    )
                )
            augmented_outputs = the_augmented_outputs
        else:
            # No healing should be needed
            augmented_outputs = stagedExec.matCheckOutputs

        crate_outputs = self._add_workflow_execution_outputs(
            augmented_outputs,
            job_work_dir=stagedExec.outputsDir,
        )

        # Now, the logfiles and diagram
        crate_meta_outputs: "MutableSequence[rocrate.model.entity.Entity]" = []
        if stagedExec.diagram is not None:
            # This is the original diagram, in DOT format (for now)
            abs_diagram = (
                stagedExec.diagram
                if stagedExec.diagram.is_absolute()
                else (self.work_dir / stagedExec.diagram).resolve()
            )
            rel_diagram = stagedExec.diagram.relative_to(self.work_dir)
            dot_file = WorkflowDiagram(
                self.crate,
                source=abs_diagram,
                dest_path=rel_diagram,
                fetch_remote=False,
                validate_url=False,
                properties={
                    "contentSize": str(abs_diagram.stat().st_size),
                    "sha256": ComputeDigestFromFile(
                        abs_diagram, "sha256", repMethod=hexDigest
                    ),
                    "encodingFormat": magic.from_file(
                        abs_diagram.as_posix(), mime=True
                    ),
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
                dot_cmd = [
                    self.dot_binary,
                    "-Tpng",
                    "-o" + png_dot_path,
                    abs_diagram.as_posix(),
                ]

                diagram_dot_path_for_rocrate = stagedExec.diagram.relative_to(
                    self.work_dir
                ).as_posix()
                diagram_png_path_for_rocrate = diagram_dot_path_for_rocrate + ".png"
                dot_cmd_for_rocrate = [
                    DEFAULT_DOT_CMD,  # This path must be agnostic
                    "-Tpng",
                    "-o" + diagram_png_path_for_rocrate,
                    diagram_dot_path_for_rocrate,
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
                        dest_path=rel_diagram.as_posix() + ".png",
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
            # https://about.workflowhub.eu/Workflow-RO-Crate/#main-workflow-diagram
            self.wf_file.append_to("image", the_diagram, compact=True)

        # Processing the log files
        if len(stagedExec.logfile) > 0:
            work_dir = pathlib.Path(self.work_dir)
            crate_coll: "Union[Collection, FixedFile, None]"
            if len(stagedExec.logfile) > 1:
                crate_coll = self._add_collection_to_crate()
            else:
                crate_coll = None

            for logfile in stagedExec.logfile:
                the_log_file = self._add_file_to_crate(
                    logfile,
                    the_uri=None,
                    the_name=cast(
                        "RelPath", logfile.relative_to(self.work_dir).as_posix()
                    ),
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
        job_work_dir: "pathlib.Path",
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
                assert out_item.values is not None
                additional_type = "Collection" if len(out_item.values) > 1 else "File"
            elif out_item.kind == ContentKind.Directory:
                assert out_item.values is not None
                additional_type = (
                    "Collection" if len(out_item.values) > 1 else "Dataset"
                )
            elif out_item.values is not None and len(out_item.values) > 0:
                itemOutValue0 = out_item.values[0]
                if isinstance(itemOutValue0, bool):
                    additional_type = "Boolean"
                elif isinstance(itemOutValue0, int):
                    additional_type = "Integer"
                elif isinstance(itemOutValue0, str):
                    additional_type = "Text"
                elif isinstance(itemOutValue0, float):
                    additional_type = "Float"

            if formal_parameter is None:
                formal_parameter = FormalParameter(
                    self.crate,
                    name=out_item.name,
                    identifier=formal_parameter_id,
                    additional_type=additional_type,
                )

                # This one must be a real boolean, as of schema.org
                if out_item.syntheticOutput is not None:
                    formal_parameter["valueRequired"] = not out_item.syntheticOutput
                    formal_parameter["syntheticOutput"] = out_item.syntheticOutput
                    if out_item.syntheticOutput:
                        if out_item.glob is not None:
                            formal_parameter["globPattern"] = out_item.glob
                if out_item.filledFrom is not None:
                    # This is a bit dirty, but effective
                    formal_parameter["filledFrom"] = out_item.filledFrom

                self.crate.add(formal_parameter)
                self.wf_file.append_to("output", formal_parameter, compact=True)

            # This can happen when there is no output, like when a workflow has failed
            if out_item.values is not None and len(out_item.values) == 0:
                continue

            if additional_type in ("File", "Dataset", "Collection"):
                crate_coll: "Union[Collection, FixedDataset, FixedFile, None]"
                if out_item.values is not None and len(out_item.values) > 1:
                    crate_coll = self._add_collection_to_crate()
                else:
                    crate_coll = None
                if out_item.values is not None:
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
                                    job_work_dir=job_work_dir,
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
                                    job_work_dir=job_work_dir,
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
        job_work_dir: "pathlib.Path",
        do_attach: "bool" = True,
    ) -> "Union[FixedFile, Collection]":
        assert the_content.signature is not None

        digest, algo = extract_digest(the_content.signature)
        if digest is None or digest == False:
            digest, algo = unstringifyDigest(the_content.signature)
        assert algo is not None
        dest_path = os.path.relpath(the_content.local, self.work_dir)
        # dest_path = hexDigest(algo, digest)

        alternateName = os.path.relpath(the_content.local, job_work_dir)

        if the_content.uri is not None and not the_content.uri.uri.startswith("nih:"):
            the_content_uri = the_content.uri.uri
            crate_file = cast(
                "Optional[FixedFile]", self.crate.dereference(the_content_uri)
            )
            if crate_file is not None:
                return crate_file
        else:
            the_content_uri = None

        crate_file = self._add_file_to_crate(
            the_path=pathlib.Path(the_content.local),
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
                        job_work_dir=job_work_dir,
                        do_attach=do_attach,
                    )
                else:
                    # elif isinstance(secFile, GeneratedDirectoryContent):
                    gen_dir_content, _ = self._add_GeneratedDirectoryContent_as_dataset(
                        secFile,
                        job_work_dir=job_work_dir,
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
        job_work_dir: "pathlib.Path",
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
            crate_dataset = cast(
                "Optional[FixedDataset]", self.crate.dereference(the_id)
            )
            # if the_uri is not None:
            #    an_uri = the_uri
            #    dest_path = None
            # else:
            #    an_uri = None
            #    dest_path = os.path.relpath(the_content.local, self.work_dir)
            #    # digest, algo = extract_digest(the_content.signature)
            #    # dest_path = hexDigest(algo, digest)

            if crate_dataset is not None:
                return crate_dataset, the_files_crates

            crate_dataset = self.crate.add_dataset_ext(
                identifier=the_id,
                source=the_content.local if do_attach else None,
                dest_path=dest_path,
                fetch_remote=False,
                validate_url=False,
                # properties=file_properties,
            )

            if the_uri is not None:
                if the_uri.startswith("http") or the_uri.startswith("ftp"):
                    # See https://github.com/ResearchObject/ro-crate/pull/259
                    uri_key = "contentUrl"
                else:
                    uri_key = "identifier"

                crate_dataset[uri_key] = the_uri
            alternateName = os.path.relpath(the_content.local, job_work_dir) + "/"
            crate_dataset["alternateName"] = alternateName

            if isinstance(the_content.values, list):
                for the_val in the_content.values:
                    if isinstance(the_val, GeneratedContent):
                        the_val_file = self._add_GeneratedContent_to_crate(
                            the_val,
                            job_work_dir=job_work_dir,
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
                            job_work_dir=job_work_dir,
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
                            job_work_dir=job_work_dir,
                            do_attach=do_attach,
                        )
                    else:
                        # elif isinstance(secFile, GeneratedDirectoryContent):
                        (
                            gen_dir_content,
                            _,
                        ) = self._add_GeneratedDirectoryContent_as_dataset(
                            secFile,
                            job_work_dir=job_work_dir,
                            do_attach=do_attach,
                        )
                        assert gen_dir_content is not None
                        gen_content = gen_dir_content

                    crate_coll.append_to("hasPart", gen_content, compact=True)

                return crate_coll, the_files_crates
            else:
                return crate_dataset, the_files_crates

        return None, None
