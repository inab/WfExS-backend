#!/usr/bin/env python
# -*- coding: utf-8 -*-

# SPDX-License-Identifier: Apache-2.0
# Copyright 2020-2025 Barcelona Supercomputing Center (BSC), Spain
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

import pytest
import logging

import pathlib

from typing import (
    cast,
    TYPE_CHECKING,
)

if TYPE_CHECKING:
    from typing import (
        Optional,
    )

    from wfexs_backend.common import (
        RelPath,
        RepoTag,
        RepoURL,
        TRS_Workflow_Descriptor,
        URIType,
    )

    from wfexs_backend.workflow import (
        WFVersionId,
        WorkflowId,
    )

from wfexs_backend.scheme_catalog import (
    SchemeCatalog,
)

from wfexs_backend.fetchers import (
    RemoteRepo,
    RepoGuessFlavor,
    RepoType,
)

from wfexs_backend.fetchers.http import HTTPFetcher

from wfexs_backend.fetchers.trs_files import GA4GHTRSFetcher

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

TRS_PARAMS_TESTBED = pytest.mark.parametrize(
    [
        "trs_endpoint",
        "workflow_id",
        "version_id",
        "descriptor_type",
        "url",
        "remote_repo",
        "repo_pid",
        "upstream_repo",
    ],
    [
        (
            "https://dockstore.org/api/ga4gh/trs/v2/",
            cast(
                "WorkflowId",
                "#workflow/github.com/sevenbridges-openworkflows/Broad-Best-Practice-Somatic-CNV-Workflows/GATK-Somatic-CNV-Panel-Workflow",
            ),
            cast("Optional[WFVersionId]", "master"),
            None,
            cast(
                "URIType",
                GA4GHTRSFetcher.INTERNAL_TRS_SCHEME_PREFIX
                + ":"
                + "https://dockstore.org/api/ga4gh/trs/v2/tools/%23workflow%2Fgithub.com%2Fsevenbridges-openworkflows%2FBroad-Best-Practice-Somatic-CNV-Workflows%2FGATK-Somatic-CNV-Panel-Workflow/versions/master",
            ),
            RemoteRepo(
                repo_url=cast(
                    "RepoURL",
                    "https://dockstore.org/api/ga4gh/trs/v2/tools/%23workflow%2Fgithub.com%2Fsevenbridges-openworkflows%2FBroad-Best-Practice-Somatic-CNV-Workflows%2FGATK-Somatic-CNV-Panel-Workflow/versions/master",
                ),
                tag=cast("RepoTag", "master"),
                repo_type=RepoType.TRS,
            ),
            "trs://dockstore.org/api/%23workflow%2Fgithub.com%2Fsevenbridges-openworkflows%2FBroad-Best-Practice-Somatic-CNV-Workflows%2FGATK-Somatic-CNV-Panel-Workflow/master",
            RemoteRepo(
                repo_url=cast(
                    "RepoURL",
                    "https://raw.githubusercontent.com/sevenbridges-openworkflows/Broad-Best-Practice-Somatic-CNV-Workflows/master/BroadCNVPanelWorkflow/gatk-cnv-panel-workflow_decomposed.cwl",
                ),
            ),
        ),
        (
            "https://dockstore.org/api/ga4gh/trs/v2/",
            cast(
                "WorkflowId", "#workflow/github.com/NCI-GDC/gdc-dnaseq-cwl/GDC_DNASeq"
            ),
            cast("Optional[WFVersionId]", "master"),
            None,
            cast(
                "URIType",
                GA4GHTRSFetcher.INTERNAL_TRS_SCHEME_PREFIX
                + ":"
                + "https://dockstore.org/api/ga4gh/trs/v2/tools/%23workflow%2Fgithub.com%2FNCI-GDC%2Fgdc-dnaseq-cwl%2FGDC_DNASeq/versions/master",
            ),
            RemoteRepo(
                repo_url=cast(
                    "RepoURL",
                    "https://dockstore.org/api/ga4gh/trs/v2/tools/%23workflow%2Fgithub.com%2FNCI-GDC%2Fgdc-dnaseq-cwl%2FGDC_DNASeq/versions/master",
                ),
                tag=cast("RepoTag", "master"),
                repo_type=RepoType.TRS,
            ),
            "trs://dockstore.org/api/%23workflow%2Fgithub.com%2FNCI-GDC%2Fgdc-dnaseq-cwl%2FGDC_DNASeq/master",
            RemoteRepo(
                repo_url=cast(
                    "RepoURL",
                    "https://raw.githubusercontent.com/NCI-GDC/gdc-dnaseq-cwl/master/workflows/dnaseq/transform.cwl",
                ),
            ),
        ),
        (
            "https://dockstore.org/api/ga4gh/trs/v2/",
            cast(
                "WorkflowId", "#workflow/github.com/NCI-GDC/gdc-dnaseq-cwl/GDC_DNASeq"
            ),
            None,
            None,
            cast(
                "URIType",
                GA4GHTRSFetcher.INTERNAL_TRS_SCHEME_PREFIX
                + ":"
                + "https://dockstore.org/api/ga4gh/trs/v2/tools/%23workflow%2Fgithub.com%2FNCI-GDC%2Fgdc-dnaseq-cwl%2FGDC_DNASeq",
            ),
            RemoteRepo(
                repo_url=cast(
                    "RepoURL",
                    "https://dockstore.org/api/ga4gh/trs/v2/tools/%23workflow%2Fgithub.com%2FNCI-GDC%2Fgdc-dnaseq-cwl%2FGDC_DNASeq/versions/release",
                ),
                tag=cast("RepoTag", "release"),
                repo_type=RepoType.TRS,
            ),
            "trs://dockstore.org/api/%23workflow%2Fgithub.com%2FNCI-GDC%2Fgdc-dnaseq-cwl%2FGDC_DNASeq/release",
            RemoteRepo(
                repo_url=cast(
                    "RepoURL",
                    "https://raw.githubusercontent.com/NCI-GDC/gdc-dnaseq-cwl/release/workflows/dnaseq/transform.cwl",
                ),
            ),
        ),
        (
            "https://workflowhub.eu/ga4gh/trs/v2/tools/",
            cast("WorkflowId", 107),
            cast("Optional[WFVersionId]", 1),
            None,
            cast(
                "URIType",
                GA4GHTRSFetcher.INTERNAL_TRS_SCHEME_PREFIX
                + ":"
                + "https://workflowhub.eu/ga4gh/trs/v2/tools/107/versions/1",
            ),
            RemoteRepo(
                repo_url=cast(
                    "RepoURL",
                    "https://workflowhub.eu/ga4gh/trs/v2/tools/107/versions/1",
                ),
                tag=cast("RepoTag", "1"),
                repo_type=RepoType.TRS,
            ),
            "trs://workflowhub.eu/107/1",
            RemoteRepo(
                repo_url=cast(
                    "RepoURL",
                    "https://workflowhub.eu/ga4gh/trs/v2/tools/107/versions/1/CWL/files?format=zip",
                ),
                repo_type=RepoType.Raw,
            ),
        ),
        (
            "https://workflowhub.eu/ga4gh/trs/v2/tools/",
            cast("WorkflowId", 106),
            cast("Optional[WFVersionId]", 3),
            None,
            cast(
                "URIType",
                GA4GHTRSFetcher.INTERNAL_TRS_SCHEME_PREFIX
                + ":"
                + "https://workflowhub.eu/ga4gh/trs/v2/tools/106/versions/3",
            ),
            RemoteRepo(
                repo_url=cast(
                    "RepoURL",
                    "https://workflowhub.eu/ga4gh/trs/v2/tools/106/versions/3",
                ),
                tag=cast("RepoTag", "3"),
                repo_type=RepoType.TRS,
            ),
            "trs://workflowhub.eu/106/3",
            RemoteRepo(
                repo_url=cast(
                    "RepoURL",
                    "https://workflowhub.eu/ga4gh/trs/v2/tools/106/versions/3/NFL/files?format=zip",
                ),
                repo_type=RepoType.Raw,
            ),
        ),
        (
            "https://workflowhub.eu/ga4gh/trs/v2/",
            cast("WorkflowId", 119),
            cast("Optional[WFVersionId]", 1),
            None,
            cast(
                "URIType",
                GA4GHTRSFetcher.INTERNAL_TRS_SCHEME_PREFIX
                + ":"
                + "https://workflowhub.eu/ga4gh/trs/v2/tools/119/versions/1",
            ),
            RemoteRepo(
                repo_url=cast(
                    "RepoURL",
                    "https://workflowhub.eu/ga4gh/trs/v2/tools/119/versions/1",
                ),
                tag=cast("RepoTag", "1"),
                repo_type=RepoType.TRS,
            ),
            "trs://workflowhub.eu/119/1",
            RemoteRepo(
                repo_url=cast(
                    "RepoURL",
                    "https://workflowhub.eu/ga4gh/trs/v2/tools/119/versions/1/NFL/files?format=zip",
                ),
                repo_type=RepoType.Raw,
            ),
        ),
        (
            "https://workflowhub.eu/ga4gh/trs/v2/tools/",
            cast("WorkflowId", 244),
            cast("Optional[WFVersionId]", 4),
            None,
            cast(
                "URIType",
                GA4GHTRSFetcher.INTERNAL_TRS_SCHEME_PREFIX
                + ":"
                + "https://workflowhub.eu/ga4gh/trs/v2/tools/244/versions/4",
            ),
            RemoteRepo(
                repo_url=cast(
                    "RepoURL",
                    "https://workflowhub.eu/ga4gh/trs/v2/tools/244/versions/4",
                ),
                tag=cast("RepoTag", "4"),
                repo_type=RepoType.TRS,
            ),
            "trs://workflowhub.eu/244/4",
            RemoteRepo(
                repo_url=cast(
                    "RepoURL",
                    "https://workflowhub.eu/ga4gh/trs/v2/tools/244/versions/4/NFL/files?format=zip",
                ),
                repo_type=RepoType.Raw,
            ),
        ),
        (
            "https://ddbj.github.io/workflow-registry/",
            cast("WorkflowId", "0d2ae4c2-fe4c-48f7-811a-ac277776533e"),
            cast("Optional[WFVersionId]", "1.0.0"),
            None,
            cast(
                "URIType",
                GA4GHTRSFetcher.INTERNAL_TRS_SCHEME_PREFIX
                + ":"
                + "https://ddbj.github.io/workflow-registry/tools/0d2ae4c2-fe4c-48f7-811a-ac277776533e/versions/1.0.0",
            ),
            RemoteRepo(
                repo_url=cast(
                    "RepoURL",
                    "https://ddbj.github.io/workflow-registry/tools/0d2ae4c2-fe4c-48f7-811a-ac277776533e/versions/1.0.0",
                ),
                tag=cast("RepoTag", "1.0.0"),
                repo_type=RepoType.TRS,
            ),
            "trs://ddbj.github.io/workflow-registry/0d2ae4c2-fe4c-48f7-811a-ac277776533e/1.0.0",
            RemoteRepo(
                repo_url=cast(
                    "RepoURL",
                    "https://zenodo.org/api/files/2422dda0-1bd9-4109-aa44-53d55fd934de/download-sra.cwl",
                ),
            ),
        ),
    ],
)


@TRS_PARAMS_TESTBED
def test_guess_trs_repo_params(
    trs_endpoint: "str",
    workflow_id: "WorkflowId",
    version_id: "Optional[WFVersionId]",
    descriptor_type: "Optional[TRS_Workflow_Descriptor]",
    url: "str",
    remote_repo: "Optional[RemoteRepo]",
    repo_pid: "Optional[str]",
    upstream_repo: "Optional[RemoteRepo]",
) -> "None":
    output = GA4GHTRSFetcher.GuessRepoParams(cast("URIType", url), logger=logger)

    # When no web url is given, ignore what it was discovered
    if output is not None and remote_repo is not None:
        if remote_repo.web_url is None:
            output = output._replace(web_url=None)
        # For now, patch this
        if remote_repo.checkout is None:
            output = output._replace(checkout=None)
    assert output == remote_repo


@TRS_PARAMS_TESTBED
def test_build_trs_internal_url_from_repo(
    trs_endpoint: "str",
    workflow_id: "WorkflowId",
    version_id: "Optional[WFVersionId]",
    descriptor_type: "Optional[TRS_Workflow_Descriptor]",
    url: "str",
    remote_repo: "Optional[RemoteRepo]",
    repo_pid: "Optional[str]",
    upstream_repo: "Optional[RemoteRepo]",
) -> "None":
    output = GA4GHTRSFetcher.BuildRepoPIDFromTRSParams(
        trs_endpoint,
        workflow_id,
        version_id,
        descriptor_type,
    )

    assert output == url


@TRS_PARAMS_TESTBED
def test_build_trs_pid_from_repo(
    trs_endpoint: "str",
    workflow_id: "WorkflowId",
    version_id: "Optional[WFVersionId]",
    descriptor_type: "Optional[TRS_Workflow_Descriptor]",
    url: "str",
    remote_repo: "Optional[RemoteRepo]",
    repo_pid: "Optional[str]",
    upstream_repo: "Optional[RemoteRepo]",
) -> "None":
    if remote_repo is None:
        pytest.skip("Skipped test because no remote repo was provided")
    else:
        scheme_catalog = SchemeCatalog(
            scheme_handlers=HTTPFetcher.GetSchemeHandlers(),
        )

        fetcher = GA4GHTRSFetcher(scheme_catalog, progs={})
        output = fetcher.build_pid_from_repo(remote_repo)

        assert output in (url, repo_pid)


@TRS_PARAMS_TESTBED
def test_materialize_repo_from_repo(
    tmppath: "pathlib.Path",
    trs_endpoint: "str",
    workflow_id: "WorkflowId",
    version_id: "Optional[WFVersionId]",
    descriptor_type: "Optional[TRS_Workflow_Descriptor]",
    url: "str",
    remote_repo: "Optional[RemoteRepo]",
    repo_pid: "Optional[str]",
    upstream_repo: "Optional[RemoteRepo]",
) -> "None":
    if remote_repo is None:
        pytest.skip("Skipped test because no remote repo was provided")
    else:
        scheme_catalog = SchemeCatalog(
            scheme_handlers=HTTPFetcher.GetSchemeHandlers(),
        )

        fetcher = GA4GHTRSFetcher(scheme_catalog, progs={})
        materialized_repo = fetcher.materialize_repo_from_repo(
            remote_repo, base_repo_destdir=tmppath
        )

        # Let's check the guessed repo'
        assert materialized_repo.upstream_repo == upstream_repo
