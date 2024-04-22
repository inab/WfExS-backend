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

import copy
import datetime

# import http.cookiejar
import json
import logging
import os
from typing import (
    cast,
    NamedTuple,
    TYPE_CHECKING,
)
import urllib.error
import urllib.parse
import urllib.request
import uuid
import xml.etree.ElementTree
import xml.dom

from defusedxml import ElementTree

from ..common import (
    CC_BY_40_LicenceDescription,
    MaterializedContent,
    NoLicenceDescription,
    ResolvedORCID,
    URIWithMetadata,
)

if TYPE_CHECKING:
    from typing import (
        Any,
        Callable,
        ClassVar,
        Dict,
        IO,
        Iterable,
        Mapping,
        MutableMapping,
        MutableSet,
        Optional,
        Sequence,
        Set,
        Tuple,
        Union,
    )

    from typing_extensions import (
        Buffer,
        Final,
        Protocol,
    )

    from _typeshed import SupportsRead

    import urllib.request

    import xml.dom.minidom

    from ..common import (
        AbsPath,
        AnyContent,
        LicenceDescription,
        RelPath,
        SecurityContextConfig,
        SymbolicName,
        URIType,
    )

    from ..workflow import WF

    class AuthenticatedURLOpener(Protocol):
        def __call__(
            self,
            url: Union[str, urllib.request.Request],
            data: Union[Buffer, SupportsRead[bytes], Iterable[bytes], None] = None,
            timeout: Optional[float] = None,
        ) -> Any:
            ...


from . import (
    DraftEntry,
    ExportPluginException,
)

from .abstract_token_export import (
    AbstractTokenExportPlugin,
)

from ..utils.misc import (
    get_opener_with_auth,
)

from ..utils.io_wrappers import (
    DigestIOWrapper,
    LimitedStreamIOWrapper,
    MIMETypeIOWrapper,
    MultipartEncoderIOWrapper,
    MultipartFile,
)


class DataversePublisher(AbstractTokenExportPlugin):
    """
    Class to model exporting results to Dataverse
    """

    PLUGIN_NAME: "ClassVar[SymbolicName]" = cast("SymbolicName", "dataverse")

    # Is this implementation ready?
    ENABLED: "ClassVar[bool]" = True

    ATOM_CONTENT_TYPE: "Final[str]" = "application/atom+xml"
    SWORD_APP_NAMESPACE: "Final[str]" = "http://www.w3.org/2007/app"
    SWORD_APP_PREFIX: "Final[str]" = "app"
    ATOM_NAMESPACE: "Final[str]" = "http://www.w3.org/2005/Atom"
    ATOM_PREFIX: "Final[str]" = "atom"
    PURL_NAMESPACE: "Final[str]" = "http://purl.org/dc/terms/"
    PURL_PREFIX: "Final[str]" = "dcterms"
    SWORD_TERMS_NAMESPACE: "Final[str]" = "http://purl.org/net/sword/terms/"
    SWORD_TERMS_PREFIX: "Final[str]" = "st"

    DATAVERSE_VALID_LICENCES: "Final[Set[str]]" = {
        "CC0 1.0",
        "CC BY 4.0",
        "CC BY-NC 4.0",
        "CC BY-NC-ND 4.0",
        "CC BY-NC-SA 4.0",
        "CC BY-ND 4.0",
        "CC BY-SA 4.0",
        "PDDL-1.0",
        "ODC-By 1.0",
        "ODbL 1.0",
        "OGL UK 3.0",
    }
    VALID_LICENCES_MAPPING: "Final[Mapping[str, str]]" = {
        dataverse_label.replace(" ", "-"): dataverse_label
        for dataverse_label in DATAVERSE_VALID_LICENCES
    }

    XML_NS: "Final[Dict[str, str]]" = {
        SWORD_APP_PREFIX: SWORD_APP_NAMESPACE,
        ATOM_PREFIX: ATOM_NAMESPACE,
        SWORD_TERMS_PREFIX: SWORD_TERMS_NAMESPACE,
    }

    def __init__(
        self,
        refdir: "AbsPath",
        setup_block: "Optional[SecurityContextConfig]" = None,
        default_licences: "Sequence[LicenceDescription]" = [],
        default_orcids: "Sequence[ResolvedORCID]" = [],
        default_preferred_id: "Optional[str]" = None,
    ):
        super().__init__(
            refdir=refdir,
            setup_block=setup_block,
            default_licences=default_licences,
            default_orcids=default_orcids,
            default_preferred_id=default_preferred_id,
        )

        # This is for the native API
        self.datasets_api_prefix = self.api_prefix + "datasets/"

        # This is for the SWORDv2 API
        if self.api_prefix.endswith("/api/"):
            self.sword_api_prefix = self.api_prefix[:-4]
        else:
            self.sword_api_prefix = self.api_prefix
        self.sword_api_prefix += "dvn/api/data-deposit/v1.1/swordv2/"

        self.sword_opener = self.__get_sword_opener()

        # See https://guides.dataverse.org/en/latest/api/native-api.html#submit-dataset
        self.dataverse_id = self.setup_block.get("dataverse-id", "root")

        # This call helps checking the auth token gives access to the specific dataverse_id
        dataverse_collection_url = self._get_dataverse_collection_url(self.dataverse_id)
        if dataverse_collection_url is None:
            raise ExportPluginException(
                f"Dataverse {self.dataverse_id} is not available at {self.api_prefix}. Check both existence and privileges"
            )

        self.dataverse_collection_url = dataverse_collection_url

        self.depositions_api_url = (
            self.api_prefix
            + f"dataverses/{self.dataverse_id}/datasets?doNotValidate=true"
        )

    def _gen_headers(self) -> "MutableMapping[str, str]":
        return {
            "X-Dataverse-key": self.api_token,
        }

    def __get_sword_opener(self) -> "AuthenticatedURLOpener":
        return cast(
            "AuthenticatedURLOpener",
            get_opener_with_auth(self.sword_api_prefix, self.api_token, "").open,
        )

    def _sword_get_collections(self) -> "Mapping[str, str]":
        # Let's return a mapping
        req = urllib.request.Request(
            url=self.sword_api_prefix + "service-document",
        )

        dataverses: "MutableMapping[str, str]" = dict()
        try:
            with self.sword_opener(req) as sH:
                root = ElementTree.parse(sH)
                for coll in root.findall(
                    f".//{self.SWORD_APP_PREFIX}:collection", namespaces=self.XML_NS
                ):
                    colllnk = coll.attrib.get("href")
                    if colllnk is not None:
                        colldescelem = coll.find(
                            f"./{self.ATOM_PREFIX}:title", namespaces=self.XML_NS
                        )
                        if colldescelem is not None:
                            colldesc = colldescelem.text
                            if colldesc is not None:
                                self.logger.debug(
                                    f"Found dataverse {colldesc}: {colllnk}"
                                )
                                dataverses[colllnk] = colldesc

        except:
            self.logger.exception(
                f"Unable to fetch the service document from {self.sword_api_prefix}"
            )

        return dataverses

    def _get_dataverse_collection_url(self, dataverse_id: "str") -> "Optional[str]":
        possible_dataverse_url = (
            self.sword_api_prefix
            + "collection/dataverse/"
            + urllib.parse.quote(dataverse_id, safe="")
        )
        available_dataverses = self._sword_get_collections()
        return (
            possible_dataverse_url
            if possible_dataverse_url in available_dataverses
            else None
        )

    @staticmethod
    def _genLicenceText(licences: "Sequence[LicenceDescription]") -> "str":
        return "This dataset has next licences:\n\n" + "\n".join(
            map(lambda licence: licence.short + " => " + licence.get_uri(), licences)
        )

    def get_pid_metadata(self, pid: "str") -> "Optional[Mapping[str, Any]]":
        if pid.isnumeric():
            req = urllib.request.Request(
                url=self.datasets_api_prefix + pid,
                headers={"Accept": "application/json", **self._gen_headers()},
            )
            try:
                with urllib.request.urlopen(req) as bH:
                    retval = json.load(bH)
                    if isinstance(retval, dict) and retval.get("status") == "OK":
                        return cast("Mapping[str, Any]", retval.get("data", {}))
            except:
                self.logger.exception(
                    f"Unable to fetch info about {pid} Dataverse entry at {self.api_prefix}"
                )
        else:
            query = {
                "persistentId": pid,
            }

            req = urllib.request.Request(
                url=self.datasets_api_prefix
                + ":persistentId/"
                + "?"
                + urllib.parse.urlencode(query, encoding="utf-8"),
                headers={"Accept": "application/json", **self._gen_headers()},
            )
            try:
                with urllib.request.urlopen(req) as bH:
                    retval = json.load(bH)
                    if isinstance(retval, dict) and retval.get("status") == "OK":
                        return cast("Mapping[str, Any]", retval.get("data", {}))
            except:
                self.logger.exception(
                    f"Unable to fetch info about {pid} Dataverse entry at {self.api_prefix}"
                )

        return None

    def get_pid_draftentry(self, pid: "str") -> "Optional[DraftEntry]":
        """
        This method is used to obtained the metadata associated to a PID,
        in case the destination allows it.
        """

        raw_metadata = self.get_pid_metadata(pid)

        if raw_metadata is None:
            return None

        latest_meta = raw_metadata.get("latestVersion", {})
        return DraftEntry(
            # These assignments could be wrong
            draft_id=str(latest_meta["datasetId"]),
            pid=latest_meta["datasetPersistentId"],
            metadata=latest_meta,
            raw_metadata=raw_metadata,
        )

    def _sword_book_entry(
        self,
        title: "Optional[str]" = None,
        description: "Optional[str]" = None,
        licences: "Sequence[LicenceDescription]" = [],
        resolved_orcids: "Sequence[ResolvedORCID]" = [],
    ) -> "Optional[str]":
        if title is None:
            title = f"Draft record created at {datetime.datetime.utcnow().isoformat()}"

        if description is None:
            description = f"Empty draft record created by WfExS-backend at {datetime.datetime.utcnow().isoformat()}"

        if len(licences) == 0:
            licences = self.default_licences

        # Corner case, as Dataverse always requires providing a licence
        if len(licences) == 0:
            licences = [CC_BY_40_LicenceDescription]

        if len(resolved_orcids) == 0:
            resolved_orcids = self.default_orcids
            # The entry must have at least one author
            if len(resolved_orcids) == 0:
                resolved_orcids = [
                    ResolvedORCID(
                        orcid="",
                        url=cast("URIType", ""),
                        record={
                            "title": None,
                            "displayName": None,
                            "names": None,
                            "biography": None,
                            "otherNames": None,
                            "countries": None,
                            "keyword": None,
                            "emails": None,
                            "externalIdentifier": None,
                            "website": None,
                            "lastModifiedTime": None,
                        },
                        record_fetch_metadata=[],
                    ),
                ]

        #        sword_draft_entry = f"""\
        # <?xml version="1.0"?>
        # <entry xmlns="{self.ATOM_NAMESPACE}" xmlns:dcterms="http://purl.org/dc/terms/">
        #   <!-- some embedded metadata -->
        #   <dcterms:title>Draft record created at {datetime.datetime.utcnow().isoformat()}</dcterms:title>
        #   <dcterms:creator>WfExS-backend ghost creator</dcterms:creator>
        #   <!-- Dataverse controlled vocabulary subject term -->
        #   <dcterms:subject>Bioinformatics</dcterms:subject>
        #   <dcterms:description>Empty draft record created by WfExS-backend at {datetime.datetime.utcnow().isoformat()}</dcterms:description>
        #   <!-- Producer with financial or admin responsibility of the data -->
        #   <!--
        #   <dcterms:contributor type="Contact">CaffeineForAll</dcterms:contributor>
        #   -->
        # </entry>
        # """

        domi = xml.dom.getDOMImplementation()
        xdoc = domi.createDocument(self.ATOM_NAMESPACE, "entry", None)
        xroot = xdoc.documentElement
        xroot.setAttribute("xmlns", self.ATOM_NAMESPACE)
        xroot.setAttribute(f"xmlns:{self.PURL_PREFIX}", self.PURL_NAMESPACE)

        title_node = xdoc.createElementNS(
            self.PURL_NAMESPACE, f"{self.PURL_PREFIX}:title"
        )
        title_node.appendChild(xdoc.createTextNode(title))
        xroot.appendChild(title_node)

        for resolved_orcid in resolved_orcids:
            # TODO: implement authors management properly
            creator_node = xdoc.createElementNS(
                self.PURL_NAMESPACE, f"{self.PURL_PREFIX}:creator"
            )
            displayName = resolved_orcid.record.get("displayName")
            creator_node.appendChild(
                xdoc.createTextNode(
                    "WfExS-backend ghost creator"
                    if displayName is None
                    else displayName
                )
            )
            xroot.appendChild(creator_node)

        subject_node = xdoc.createElementNS(
            self.PURL_NAMESPACE, f"{self.PURL_PREFIX}:subject"
        )
        subject_node.appendChild(xdoc.createTextNode("Bioinformatics"))
        xroot.appendChild(subject_node)

        description_node = xdoc.createElementNS(
            self.PURL_NAMESPACE, f"{self.PURL_PREFIX}:description"
        )
        description_node.appendChild(xdoc.createTextNode(description))
        xroot.appendChild(description_node)

        # Dataverse only supports a single licence from the restricted list it manages
        licence_node: "Optional[xml.dom.minidom.Element]" = None
        if len(licences) == 1:
            licence_label = self.VALID_LICENCES_MAPPING.get(
                licences[0].short, licences[0].short
            )
            if licence_label in self.DATAVERSE_VALID_LICENCES:
                licence_node = xdoc.createElementNS(
                    self.PURL_NAMESPACE, f"{self.PURL_PREFIX}:license"
                )
                # Assertion needed by mypy
                assert licence_node is not None
                licence_node.appendChild(xdoc.createTextNode(licence_label))

        # Otherwise, a compound description has to be provided
        if licence_node is None:
            licence_node = xdoc.createElementNS(
                self.PURL_NAMESPACE, f"{self.PURL_PREFIX}:rights"
            )
            licence_text = self._genLicenceText(licences)
            licence_node.appendChild(xdoc.createTextNode(licence_text))
        xroot.appendChild(licence_node)

        req = urllib.request.Request(
            url=self.dataverse_collection_url,
            headers={
                "Content-Type": self.ATOM_CONTENT_TYPE,
            },
            data=xdoc.toxml(encoding="UTF-8"),
            method="POST",
        )
        try:
            with self.sword_opener(req) as bH:
                root = ElementTree.parse(bH)
                link_elem = root.find(
                    f".//{self.ATOM_PREFIX}:id", namespaces=self.XML_NS
                )
                if link_elem is None:
                    return None

                link_id = link_elem.text
                if link_id is None:
                    return None

                doipos = link_id.find("doi:")
                if doipos < 0:
                    return None

                return link_id[doipos:]
        except urllib.error.HTTPError as he:
            errmsg = f"Could not book Dataverse entry using {self.dataverse_collection_url}. Server response: {he.read().decode('utf-8')}"
            self.logger.exception(errmsg)
            # for cookie in self._shared_cookie_jar:
            #    self.logger.error(f"Cookie: {cookie.name}, {cookie.value}")
            raise ExportPluginException(errmsg) from he

    def book_pid(
        self,
        preferred_id: "Optional[str]" = None,
        initially_required_metadata: "Optional[Mapping[str, Any]]" = None,
        initially_required_community_specific_metadata: "Optional[Mapping[str, Any]]" = None,
        title: "Optional[str]" = None,
        description: "Optional[str]" = None,
        licences: "Sequence[LicenceDescription]" = [],
        resolved_orcids: "Sequence[ResolvedORCID]" = [],
    ) -> "Optional[DraftEntry]":
        """
        This method is used to book a new PID,
        in case the destination allows it.

        We can even "suggest" either a new or existing PID.

        It can return both the internal PID as the future, official one.
        It also returns the associated internal metadata.

        When it returns None, it means either
        the destination does not allow booking
        pids, either temporary or permanently
        """
        """
        We are booking a new PID, in case the default
        preferred id is None or an invalid one
        """
        if preferred_id is None:
            preferred_id = self.default_preferred_id

        booked_entry: "Optional[DraftEntry]" = None
        fill_in_new_entry = True
        newentry_url: "Optional[str]" = None
        if preferred_id is not None:
            booked_entry = self.get_pid_draftentry(preferred_id)
            if booked_entry is not None and booked_entry.metadata is not None:
                # Booked
                fill_in_new_entry = False
                # Submitted
                if booked_entry.metadata.get("versionState") != "DRAFT":
                    # Built the request url for new version
                    # This should force the creation of a new draft
                    updated_metadata = self.update_record_metadata(
                        booked_entry,
                        metadata=booked_entry.metadata,
                    )
                    if updated_metadata is not None:
                        new_draft_id = updated_metadata.get("id")
                        if new_draft_id is not None:
                            assert new_draft_id != booked_entry.metadata.get("id")
                            return booked_entry._replace(
                                draft_id=updated_metadata["datasetId"],
                                metadata=updated_metadata,
                            )
                    return None
                    # updated_entry = self._sword_book_revision(booked_entry)
                    #
                    # return updated_entry
                else:
                    preferred_id = booked_entry.draft_id
            else:
                self.logger.info(
                    f"Discarding pre-booked {preferred_id} Dataverse entry id reusage from {self.api_prefix}"
                )

        if fill_in_new_entry:
            # With the booked_id
            booked_id = self._sword_book_entry(
                title=title,
                description=description,
                licences=licences,
                resolved_orcids=resolved_orcids,
            )

            # we are getting the entry in the native API
            if booked_id is not None:
                booked_entry = self.get_pid_draftentry(booked_id)
                if booked_entry is not None and (
                    initially_required_metadata is not None
                    or initially_required_community_specific_metadata is not None
                ):
                    # As _sword_book_entry is incomplete, and uses SWORD API
                    # it is better to use the update call to set custom metadata
                    updated_metadata = self.update_record_metadata(
                        booked_entry,
                        metadata=initially_required_metadata,
                        community_specific_metadata=initially_required_community_specific_metadata,
                        title=title,
                        description=description,
                        licences=licences,
                        resolved_orcids=resolved_orcids,
                    )
                    if updated_metadata is not None:
                        booked_entry = booked_entry._replace(
                            metadata=updated_metadata,
                        )
            # Book new entry
            newentry_url = self.depositions_api_url

        # TO BE FINISHED
        return booked_entry

    @property
    def _customized_book_pid_error_string(self) -> "str":
        """
        This method can be overridden to provide more context
        """
        return f"Unable to book a Dataverse entry at {self.api_prefix}"

    def discard_booked_pid(self, pid_or_draft: "Union[str, DraftEntry]") -> "bool":
        """
        This method is used to release a previously booked PID,
        which has not been published.

        When it returns False, it means that the
        provided id did exist, but it was not a draft
        """
        if isinstance(pid_or_draft, str):
            if pid_or_draft.isnumeric():
                draft_id = pid_or_draft
            else:
                pid_meta = self.get_pid_draftentry(pid_or_draft)
                if pid_meta is None:
                    return False

                draft_id = pid_meta.draft_id
        else:
            draft_id = pid_or_draft.draft_id

        req = urllib.request.Request(
            url=self.datasets_api_prefix + f"{draft_id}/versions/:draft",
            headers=self._gen_headers(),
            method="DELETE",
        )
        try:
            with urllib.request.urlopen(req) as bH:
                retval = json.load(bH)
                return isinstance(retval, dict) and retval.get("status") == "OK"
        except:
            self.logger.exception(
                f"Unable to fetch info about {draft_id} Dataverse entry at {self.api_prefix}"
            )

        return False

    def get_file_bucket_prefix(
        self,
        draft_entry: "DraftEntry",
    ) -> "str":
        """
        This is an accessory method which is used to build upload paths
        """
        query = {
            "persistentId": draft_entry.pid,
        }

        return (
            self.datasets_api_prefix
            + ":persistentId/add"
            + "?"
            + urllib.parse.urlencode(query, encoding="utf-8")
        )

    def _direct_upload_file_to_draft(
        self,
        draft_entry: "DraftEntry",
        filename: "Union[str, IO[bytes]]",
        remote_filename: "Optional[str]",
        content_size: "Optional[int]" = None,
    ) -> "Mapping[str, Any]":
        """
        It takes as input the draft record representation, a local filename and optionally the remote filename to use
        """
        # curl -H "X-Dataverse-key:$API_TOKEN" -X POST -F "file=@$FILENAME" -F 'jsonData={"description":"My description.","directoryLabel":"data/subdir1","categories":["Data"], "restrict":"false", "tabIngest":"false"}' "$SERVER_URL/api/datasets/:persistentId/add?persistentId=$PERSISTENT_ID"

        pH: "SupportsRead[bytes]"
        if isinstance(filename, str):
            pH = open(filename, mode="rb")
            content_size = os.stat(filename).st_size
            if remote_filename is None:
                remote_filename = os.path.relpath(filename, self.refdir)
        else:
            assert isinstance(
                remote_filename, str
            ), "When filename is a data stream, remote_filename must be declared"
            assert (
                content_size is not None
            ), "When filename is a data stream, content_size must be declared"
            pH = filename

        filename_label: "str" = remote_filename
        directory_label: "Optional[str]" = None
        rslash = remote_filename.rfind("/")
        if rslash > 0:
            directory_label = remote_filename[0:rslash]
            filename_label = remote_filename[rslash + 1 :]

        # The code is guessing the MIME type of the stream on the fly
        mpH = MIMETypeIOWrapper(stream=pH)

        # Also, the code is computing the SHA256 of the stream on the fly
        dpH = DigestIOWrapper(stream=mpH, algo="sha256")

        # Assuming direct uploads are available ....
        query = {
            "persistentId": draft_entry.pid,
            "size": content_size,
        }
        req = urllib.request.Request(
            url=self.datasets_api_prefix
            + ":persistentId/uploadurls"
            + "?"
            + urllib.parse.urlencode(query, encoding="utf-8"),
            headers=self._gen_headers(),
        )
        with urllib.request.urlopen(req) as uF:
            upload_desc = json.load(uF)

            if upload_desc.get("status") != "OK":
                raise ExportPluginException()
        storage_identifier = upload_desc.get("data", {}).get("storageIdentifier")
        if not isinstance(storage_identifier, str):
            raise ExportPluginException()

        upload_url = upload_desc.get("data", {}).get("url")
        if isinstance(upload_url, str):
            putreq = urllib.request.Request(
                url=upload_url,
                data=dpH,
                method="PUT",
                headers={
                    "x-amz-tagging:dv-state": "temp",
                },
            )
            with urllib.request.urlopen(putreq) as pr:
                # upload_response = cast("Mapping[str, Any]", json.load(pr))
                pass
        else:
            upload_urls_mapping: "Optional[Mapping[str,str]]" = upload_desc.get(
                "data", {}
            ).get("urls")
            if not isinstance(upload_urls_mapping, dict):
                raise ExportPluginException()

            # Sorting the URLs in a list
            upload_urls = list(
                sorted(upload_urls_mapping.items(), key=lambda p: int(p[0]))
            )

            maxreadsize: "Optional[int]" = upload_desc.get("data", {}).get("partSize")
            if not isinstance(maxreadsize, int):
                raise ExportPluginException()

            abort_url: "Optional[str]" = upload_desc.get("data", {}).get("abort")
            if not isinstance(abort_url, str):
                raise ExportPluginException()

            completion_url: "Optional[str]" = upload_desc.get("data", {}).get(
                "complete"
            )
            if not isinstance(completion_url, str):
                raise ExportPluginException()

            try:
                etags: "MutableMapping[str, str]" = {}
                for upload_label, upload_url in upload_urls:
                    lH = LimitedStreamIOWrapper(stream=dpH, maxreadsize=maxreadsize)
                    putreq = urllib.request.Request(
                        url=upload_url,
                        data=lH,
                        method="PUT",
                        headers={
                            "x-amz-tagging:dv-state": "temp",
                        },
                    )
                    with urllib.request.urlopen(putreq) as pr:
                        etag = pr.headers.get("ETag")
                        if etag is None:
                            raise ExportPluginException()

                        etags[upload_label] = etag

                creq = urllib.request.Request(
                    url=completion_url,
                    data=json.dumps(etags).encode("utf-8"),
                    method="PUT",
                )
                with urllib.request.urlopen(creq) as cr:
                    pass
            except Exception as e:
                # In case of some failure, remove remote fragments
                dreq = urllib.request.Request(
                    url=abort_url,
                    method="DELETE",
                )
                with urllib.request.urlopen(creq) as cr:
                    pass
                raise e

        # Now, time to attach the file to the entry
        JSON_DATA = {
            "description": "My description.",
            "categories": ["Data"],
            "restrict": "false",
            "storageIdentifier": storage_identifier,
            "fileName": filename_label,
            "mimeType": mpH.mime(),
            "checksum": {
                # This must correlate with the algorithm
                # Supported ones are declared at https://guides.dataverse.org/en/latest/developers/s3-direct-upload-api.html#adding-the-uploaded-file-to-the-dataset
                "@type": "SHA-256",
                "@value": dpH.hexdigest(),
            },
        }
        if directory_label is not None:
            JSON_DATA["directoryLabel"] = directory_label

        areq = urllib.request.Request(
            url=self.get_file_bucket_prefix(draft_entry),
            data=urllib.parse.urlencode(
                {"jsonData": json.dumps(JSON_DATA)}, encoding="utf-8"
            ).encode("ascii"),
            headers={
                "Content-Type": "application/x-www-form-urlencoded",
                **self._gen_headers(),
            },
            method="POST",
        )
        with urllib.request.urlopen(areq) as aH:
            upload_response = cast("Mapping[str, Any]", json.load(aH))

        return upload_response

    def _form_upload_file_to_draft(
        self,
        draft_entry: "DraftEntry",
        filename: "Union[str, IO[bytes]]",
        remote_filename: "Optional[str]",
        content_size: "Optional[int]" = None,
    ) -> "Mapping[str, Any]":
        pH: "SupportsRead[bytes]"
        if isinstance(filename, str):
            pH = open(filename, mode="rb")
            content_size = os.stat(filename).st_size
            if remote_filename is None:
                remote_filename = os.path.relpath(filename, self.refdir)
        else:
            assert isinstance(
                remote_filename, str
            ), "When filename is a data stream, remote_filename must be declared"
            assert (
                content_size is not None
            ), "When filename is a data stream, content_size must be declared"
            pH = filename

        filename_label: "str" = remote_filename
        directory_label: "Optional[str]" = None
        rslash = remote_filename.rfind("/")
        if rslash > 0:
            directory_label = remote_filename[0:rslash]
            filename_label = remote_filename[rslash + 1 :]

        # Now, time to attach the file to the entry
        JSON_DATA = {
            "description": "My description.",
            "categories": ["Data"],
            "restrict": "false",
            "tabIngest": "false",
            "fileName": filename_label,
        }
        if directory_label is not None:
            JSON_DATA["directoryLabel"] = directory_label

        mpH = MIMETypeIOWrapper(pH)

        mencH = MultipartEncoderIOWrapper(
            [
                ("jsonData", [json.dumps(JSON_DATA)]),
                (
                    "file",
                    [
                        MultipartFile(
                            filename=filename_label,
                            mime=mpH.mime(),
                            stream=cast("SupportsRead[bytes]", mpH),
                            size=content_size,
                        )
                    ],
                ),
            ]
        )
        areq = urllib.request.Request(
            url=self.get_file_bucket_prefix(draft_entry),
            data=mencH,
            headers={
                "Content-Type": mencH.content_type,
                **self._gen_headers(),
            },
            method="POST",
        )
        with urllib.request.urlopen(areq) as aH:
            upload_response = cast("Mapping[str, Any]", json.load(aH))

        return upload_response

    def upload_file_to_draft(
        self,
        draft_entry: "DraftEntry",
        filename: "Union[str, IO[bytes]]",
        remote_filename: "Optional[str]",
        content_size: "Optional[int]" = None,
    ) -> "Mapping[str, Any]":
        try:
            # First, try the direct upload API
            return self._direct_upload_file_to_draft(
                draft_entry, filename, remote_filename, content_size=content_size
            )
        except urllib.error.HTTPError as he:
            if he.code != 404:
                errmsg = f"Could not upload file to Dataverse draft entry. Server response: {he.read().decode('utf-8')}"
                self.logger.exception(errmsg)
                # for cookie in self._shared_cookie_jar:
                #    self.logger.error(f"Cookie: {cookie.name}, {cookie.value}")
                raise ExportPluginException(errmsg) from he

            return self._form_upload_file_to_draft(
                draft_entry, filename, remote_filename, content_size=content_size
            )

    def __gen_sword_dataset_url(self, draft_entry: "DraftEntry") -> "str":
        return (
            self.sword_api_prefix
            + "edit/study/"
            + urllib.parse.quote(draft_entry.pid, safe="/:")
        )

    EXPORT_FORMATS: "Final[Set[str]]" = {
        "ddi",
        "oai_ddi",
        "dcterms",
        "oai_dc",
        "schema.org",
        "OAI_ORE",
        "Datacite",
        "oai_datacite",
        "dataverse_json",
    }

    def _export_metadata_raw(
        self, draft_entry: "DraftEntry", format: "str" = "dcterms"
    ) -> "bytes":
        """
        Get the metadata in SWORD format
        """
        if format not in self.EXPORT_FORMATS:
            raise KeyError(f"{format} is an unsupported export format")

        query = {
            "exporter": format,
            "persistentId": draft_entry.pid,
        }

        req = urllib.request.Request(
            url=self.datasets_api_prefix
            + "export"
            + "?"
            + urllib.parse.urlencode(query, encoding="utf-8"),
            headers=self._gen_headers(),
        )
        try:
            with urllib.request.urlopen(req) as bH:
                return cast("bytes", bH.read())
        except urllib.error.HTTPError as he:
            errmsg = f"Could not get metadata from entry {draft_entry.pid} . Server response: {he.read().decode('utf-8')}"
            self.logger.exception(errmsg)
            raise ExportPluginException(errmsg) from he

    def _sword_book_revision(self, draft_entry: "DraftEntry") -> "Optional[DraftEntry]":
        existing_metadata_raw = self._export_metadata_raw(draft_entry, format="dcterms")

        req = urllib.request.Request(
            url=self.__gen_sword_dataset_url(draft_entry),
            headers={
                "Content-Type": self.ATOM_CONTENT_TYPE,
            },
            data=existing_metadata_raw,
            method="PUT",
        )
        try:
            with self.sword_opener(req) as bH:
                root = ElementTree.parse(bH)
                link_elem = root.find(
                    f".//{self.ATOM_PREFIX}:id", namespaces=self.XML_NS
                )
                if link_elem is None:
                    return None

                link_id = link_elem.text
                if link_id is None:
                    return None

                doipos = link_id.find("doi:")
                if doipos < 0:
                    return None

                return self.get_pid_draftentry(link_id[doipos:])
        except urllib.error.HTTPError as he:
            errmsg = f"Could not book Dataverse entry using {self.dataverse_collection_url}. Server response: {he.read().decode('utf-8')}"
            self.logger.exception(errmsg)
            # for cookie in self._shared_cookie_jar:
            #    self.logger.error(f"Cookie: {cookie.name}, {cookie.value}")
            raise ExportPluginException(errmsg) from he

    def update_record_metadata(
        self,
        draft_entry: "DraftEntry",
        metadata: "Optional[Mapping[str, Any]]" = None,
        community_specific_metadata: "Optional[Mapping[str, Any]]" = None,
        title: "Optional[str]" = None,
        description: "Optional[str]" = None,
        licences: "Sequence[LicenceDescription]" = [],
        resolved_orcids: "Sequence[ResolvedORCID]" = [],
    ) -> "Mapping[str, Any]":
        """
        This method updates the draft record metadata,
        both the general one, and the specific of the community.
        This one could not make sense for some providers.
        For non draft entries, it fails
        """

        # When no parameter is provided, get the latest metadata
        # because this operation can be used to create a new revision
        if metadata is None:
            existing_entry = self.get_pid_draftentry(draft_entry.draft_id)
            if existing_entry is None:
                raise ExportPluginException(
                    f"Dataverse draft/entry {draft_entry.draft_id} is unavailable at {self.api_prefix}"
                )
            assert existing_entry.metadata is not None
            cleaned_metadata = cast("MutableMapping[str, Any]", existing_entry.metadata)
        else:
            cleaned_metadata = cast("MutableMapping[str, Any]", copy.copy(metadata))

        if cleaned_metadata.get("versionState") != "DRAFT":
            cleaned_metadata["versionNumber"] += 1

        # These keys must not exist on submitted metadata!!!
        for key in ("files", "versionState"):
            if key in cleaned_metadata:
                del cleaned_metadata[key]

        if title is not None or description is not None or len(resolved_orcids) > 0:
            fields = (
                cleaned_metadata.setdefault("metadataBlocks", {})
                .setdefault("citation", {})
                .setdefault("fields", [])
            )

            # These are the specific fields we are updated later
            title_field: "Optional[MutableMapping[str, Any]]" = None
            description_field: "Optional[MutableMapping[str, Any]]" = None
            authors_field: "Optional[MutableMapping[str, Any]]" = None

            # But first, we have to locate already declared instances
            for field in fields:
                if not isinstance(field, dict):
                    continue

                typeName = field.get("typeName")
                if typeName == "title" and title is not None:
                    title_field = field
                elif typeName == "author" and len(resolved_orcids) > 0:
                    authors_field = field
                elif typeName == "dsDescription" and description is not None:
                    description_field = field

            # This part of the code is needed because there could happen
            # no title or description was previously provided
            # (i.e. incomplete minimal metadata)
            if title is not None:
                if title_field is None:
                    title_field = {
                        "typeName": "title",
                        "multiple": False,
                        "typeClass": "primitive",
                    }
                    fields.append(title_field)

                title_field["value"] = title

            if description is not None:
                if description_field is None:
                    description_field = {
                        "typeName": "dsDescription",
                        "multiple": True,
                        "typeClass": "compound",
                    }
                    fields.append(description_field)

                description_field["value"] = [
                    {
                        "dsDescriptionValue": {
                            "typeName": "dsDescriptionValue",
                            "multiple": False,
                            "typeClass": "primitive",
                            "value": description,
                        },
                    },
                ]

            if len(resolved_orcids) > 0:
                if authors_field is None:
                    authors_field = {
                        "typeName": "author",
                        "multiple": True,
                        "typeClass": "compound",
                    }
                    fields.append(authors_field)

                field_values = []
                for resolved_orcid in resolved_orcids:
                    displayName = resolved_orcid.record.get("displayName")
                    field_value = {
                        "authorName": {
                            "typeName": "authorName",
                            "multiple": False,
                            "typeClass": "primitive",
                            "value": "Unknown author"
                            if displayName is None
                            else displayName,
                        }
                    }
                    # Covering the corner case of empty orcid
                    if len(resolved_orcid.orcid) > 0:
                        field_value["authorIdentifierScheme"] = {
                            "typeName": "authorIdentifierScheme",
                            "multiple": False,
                            "typeClass": "controlledVocabulary",
                            "value": "ORCID",
                        }
                        field_value["authorIdentifier"] = {
                            "typeName": "authorIdentifier",
                            "multiple": False,
                            "typeClass": "primitive",
                            "value": resolved_orcid.orcid,
                        }
                    field_values.append(field_value)

                authors_field["value"] = field_values

        if len(licences) > 0:
            # First, remove previous elements
            for k in ("termsOfUse", "license"):
                if k in cleaned_metadata:
                    del cleaned_metadata[k]

            added_licence = False
            if len(licences) == 1:
                licence_label = self.VALID_LICENCES_MAPPING.get(
                    licences[0].short, licences[0].short
                )
                if licence_label in self.DATAVERSE_VALID_LICENCES:
                    cleaned_metadata["license"] = {
                        "name": licence_label,
                        "uri": licences[0].get_uri(),
                    }
                    added_licence = True

            # Otherwise, a compound description has to be provided
            if not added_licence:
                cleaned_metadata["termsOfUse"] = self._genLicenceText(licences)

        query = {
            "persistentId": draft_entry.pid,
        }

        req = urllib.request.Request(
            url=self.datasets_api_prefix
            + ":persistentId/versions/:draft"
            + "?"
            + urllib.parse.urlencode(query, encoding="utf-8"),
            headers={"Content-Type": "application/json", **self._gen_headers()},
            data=json.dumps(cleaned_metadata).encode("utf-8"),
            method="PUT",
        )
        try:
            with urllib.request.urlopen(req) as bH:
                retval = json.load(bH)
                return cast("Mapping[str, Any]", retval.get("data", {}))
        except urllib.error.HTTPError as he:
            # This corner case happens when there is a draft already
            if he.code == 400:
                err_payload = json.load(he)
                self.logger.error(f"Error {he.code} on update metadata {err_payload}")
            else:
                self.logger.error(f"Error {he.code} on update metadata (raw)")
                self.logger.error(he.read())
            self.logger.error(
                f"Error arisen with this payload {json.dumps(cleaned_metadata, indent=4)}"
            )
            raise ExportPluginException(
                f"Unable to update metadata about {draft_entry.pid} Dataverse entry at {self.api_prefix} (error {he.code})"
            ) from he
        except:
            self.logger.exception(
                f"Unable to update metadata about {draft_entry.pid} Dataverse entry at {self.api_prefix}"
            )
            raise

    def publish_draft_record(
        self,
        draft_entry: "DraftEntry",
    ) -> "Mapping[str, Any]":
        """
        This method publishes a draft record, so its public id is permanent
        """
        query = {"persistentId": draft_entry.pid, "type": "major"}

        req = urllib.request.Request(
            url=self.api_prefix
            + "datasets/:persistentId/actions/:publish"
            + "?"
            + urllib.parse.urlencode(query, encoding="utf-8"),
            headers={"Accept": "application/json", **self._gen_headers()},
            method="POST",
        )
        try:
            with urllib.request.urlopen(req) as bH:
                retval = json.load(bH)
                if isinstance(retval, dict) and retval.get("status") == "OK":
                    return cast("Mapping[str, Any]", retval.get("data", {}))
        except:
            self.logger.exception(
                f"Unable to fetch info about {draft_entry.pid} Dataverse entry at {self.api_prefix}"
            )

        return {}
