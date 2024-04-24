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

import datetime
import logging
import os
import shutil
import tempfile
from typing import (
    cast,
    NamedTuple,
    TYPE_CHECKING,
)
import urllib.parse
import uuid

from extended_nc_client.extended_nc_client import (
    ExtendedNextcloudClient,
)

import nextcloud_client.nextcloud_client  # type: ignore[import-untyped]

from ..common import (
    ContentKind,
    LicensedURI,
    MaterializedContent,
    URIWithMetadata,
)

if TYPE_CHECKING:
    from typing import (
        Any,
        ClassVar,
        IO,
        Mapping,
        MutableSequence,
        MutableSet,
        Optional,
        Sequence,
        Set,
        Tuple,
        Union,
    )

    from extended_nc_client.extended_nc_client import (
        DAVRequestResponse,
    )

    from ..common import (
        AbsPath,
        AnyContent,
        LicenceDescription,
        RelPath,
        ResolvedORCID,
        SecurityContextConfig,
        SymbolicName,
        URIType,
    )

    from ..workflow import WF

from . import (
    DraftEntry,
    ExportPluginException,
)

from .abstract_token_export import (
    AbstractTokenExportPlugin,
)


class ExportMapping(NamedTuple):
    local_filename: "AbsPath"
    remote_dirname: "RelPath"
    remote_basename: "RelPath"


class NextcloudContentExporter:
    """
    This code is a trimmed version of the one created for ES-FEGA
    (Spanish Federated EGA) infrastructure
    """

    def __init__(
        self,
        nextcloud_url: "URIType",
        nextcloud_user: "str",
        nextcloud_token: "str",
        nextcloud_base_directory: "AbsPath",
        retention_tag_name: "Optional[str]" = None,
    ):
        import inspect

        # Getting a logger focused on specific classes
        self.logger = logging.getLogger(
            dict(inspect.getmembers(self))["__module__"]
            + "::"
            + self.__class__.__name__
        )

        # This set is used to record the directories which have already
        # been created (or ensured they exist)
        self._ensured_paths: "MutableSet[str]" = set()

        self.nextcloud_url = nextcloud_url
        self.nextcloud_user = nextcloud_user
        self.nextcloud_token = nextcloud_token
        self.base_directory = nextcloud_base_directory

        self.chunk_size = 65536

        self.enc = ExtendedNextcloudClient(nextcloud_url)
        self.enc.login(nextcloud_user, nextcloud_token)

        # Creating the retention system tag to be used to label
        if retention_tag_name is not None:
            retention_tag_id = self.enc.get_systemtag(retention_tag_name)
            if retention_tag_id is None:
                retention_tag_id = self.enc.create_systemtag(retention_tag_name)
        else:
            retention_tag_id = None

        self.ret_tag_name = retention_tag_name
        self.ret_tag_id = retention_tag_id

    def create_remote_path(
        self, reldir: "Optional[RelPath]" = None, name: "Optional[RelPath]" = None
    ) -> "Tuple[Any, AbsPath, RelPath]":
        # If the name is not defined, generate a random, new one
        if name is None:
            name = cast("RelPath", str(uuid.uuid4()))

        if reldir:
            relretval = cast("RelPath", reldir + "/" + name)
        else:
            relretval = name

        retval = cast("AbsPath", self.base_directory + "/" + relretval)
        retvalobj = None

        if retval not in self._ensured_paths:
            encoded_path = urllib.parse.quote(retval)

            path_info = self.enc.ensure_tree_exists(encoded_path)

            if path_info and (self.ret_tag_name is not None):
                self.enc.add_tag(path_info, tag_name=self.ret_tag_name)

            # import pprint
            # pprint.pprint(created)
            # pprint.pprint(retvalobj)

            # Adding all the prefixes of the path
            self._ensured_paths.add(retval)
            rslash = retval.rfind("/")
            while rslash > 0:
                self._ensured_paths.add(retval[0:rslash])
                rslash = retval.rfind("/", 0, rslash)

        return retvalobj, retval, relretval

    def remove_remote_path(
        self,
        name: "RelPath",
        reldir: "Optional[RelPath]" = None,
    ) -> "bool":
        if reldir:
            relretval = cast("RelPath", reldir + "/" + name)
        else:
            relretval = name

        retval = cast("AbsPath", self.base_directory + "/" + relretval)
        retvalobj = None

        try:
            return bool(self.enc.delete(retval))
        except nextcloud_client.nextcloud_client.HTTPResponseError as nce:
            if nce.status_code == 404:
                return False
            raise nce
        except urllib.error.HTTPError as he:
            if he.code == 404:
                return False
            raise he

    def _chunked_uploader(self, fmapping: "ExportMapping") -> "DAVRequestResponse":
        local_file, uplodir, destname = fmapping
        if destname is None:
            destname = cast("RelPath", os.path.basename(local_file))

        destpath = urllib.parse.quote(self.base_directory) + "/"
        if uplodir:
            destpath += urllib.parse.quote(uplodir) + "/"

        destpath += urllib.parse.quote(destname, safe="")

        self.logger.debug(f"{local_file} -> {destpath}")
        timestamp = int(os.path.getmtime(local_file))
        with open(local_file, mode="rb") as uH:
            retval = self.enc.put_stream(uH, destpath, remote_timestamp=timestamp)

        if retval and (self.ret_tag_name is not None):
            path_info = self.enc.file_info(destpath)
            if path_info:
                self.enc.add_tag(path_info, tag_name=self.ret_tag_name)

        return retval

    def _chunked_file_batch_uploader(
        self, files_to_process: "Sequence[ExportMapping]"
    ) -> "Sequence[DAVRequestResponse]":
        retvals = []
        self.logger.debug(f"{len(files_to_process)} files to upload")
        for fmapping in files_to_process:
            self.logger.debug(
                f"{fmapping.local_filename} {fmapping.remote_dirname} {fmapping.remote_basename}"
            )
            retvals.append(self._chunked_uploader(fmapping))

        return retvals

    def mappings_uploader(
        self,
        contents_to_process: "Sequence[ExportMapping]",
        destname: "Optional[RelPath]" = None,
    ) -> "Tuple[Sequence[DAVRequestResponse], Optional[AbsPath], Optional[RelPath]]":
        files_to_process = []
        dirs_to_process = []

        retval_reldir = None
        retval_relreldir = None
        # Reading the CSV file
        if len(contents_to_process) > 0:
            # Declaring the remote path
            _, retval_reldir, retval_relreldir = self.create_remote_path(name=destname)

        for mapping in contents_to_process:
            assert retval_relreldir is not None
            local_filename = mapping.local_filename
            remote_dirname = cast(
                "RelPath",
                os.path.join(retval_relreldir, mapping.remote_dirname.lstrip("/")),
            )
            remote_basename = mapping.remote_basename

            if os.path.exists(local_filename):
                if os.path.isfile(local_filename):
                    files_to_process.append(
                        mapping._replace(remote_dirname=remote_dirname)
                    )
                    self.create_remote_path(name=remote_dirname)
                elif os.path.isdir(local_filename):
                    dirs_to_process.append(
                        mapping._replace(remote_dirname=remote_dirname)
                    )
                else:
                    raise NotImplementedError(
                        f'Unimplemented management of "files" like {local_filename}'
                    )
            else:
                raise ValueError(f"Local file {local_filename} does not exist")

        while len(dirs_to_process) > 0:
            new_dirs_to_process = []
            for dmapping in dirs_to_process:
                local_dir, upload_base_dir, upload_dir_basename = dmapping
                self.logger.debug(
                    f"{local_dir} {upload_base_dir} {upload_dir_basename}"
                )
                _, remote_path, rel_remote_path = self.create_remote_path(
                    upload_base_dir, upload_dir_basename
                )
                for entry in os.scandir(local_dir):
                    # Skipping problematic files,
                    if not entry.name.startswith("."):
                        if entry.is_file():
                            files_to_process.append(
                                ExportMapping(
                                    local_filename=cast("AbsPath", entry.path),
                                    remote_dirname=rel_remote_path,
                                    remote_basename=cast("RelPath", entry.name),
                                )
                            )
                        elif entry.is_dir():
                            new_dirs_to_process.append(
                                ExportMapping(
                                    local_filename=cast("AbsPath", entry.path),
                                    remote_dirname=rel_remote_path,
                                    remote_basename=cast("RelPath", entry.name),
                                )
                            )

            # Now, rotation time
            dirs_to_process = new_dirs_to_process

        # No work, then return
        retvals: "Sequence[DAVRequestResponse]"
        if len(files_to_process) == 0 and len(dirs_to_process) == 0:
            retvals = []
        else:
            retvals = self._chunked_file_batch_uploader(files_to_process)

        return retvals, retval_reldir, retval_relreldir

    def create_share_links(
        self,
        relpath: "str",
        emails: "Sequence[str]",
        expire_in: "Optional[int]" = None,
        licences: "Tuple[LicenceDescription, ...]" = tuple(),
    ) -> "Sequence[LicensedURI]":
        retvals = []
        permissions = ExtendedNextcloudClient.OCS_PERMISSION_READ
        the_path = urllib.parse.quote(self.base_directory + "/" + relpath)

        if expire_in is not None:
            expire_at_d = datetime.date.today() + datetime.timedelta(days=expire_in)
            expire_at = expire_at_d.isoformat()
        else:
            expire_at = None

        if not isinstance(emails, (list, tuple)) or len(emails) == 0:
            share_info = self.enc.share_file(
                the_path,
                ExtendedNextcloudClient.OCS_SHARE_TYPE_LINK,
                perms=permissions,
                expire_date=expire_at,
            )
            if not isinstance(share_info, bool):
                retvals.append(
                    LicensedURI(
                        uri=cast("URIType", share_info.get_link()),
                        licences=licences,
                    )
                )
        else:
            for email in emails:
                share_info = self.enc.share_file(
                    the_path,
                    ExtendedNextcloudClient.OCS_SHARE_TYPE_EMAIL,
                    share_dest=email,
                    perms=permissions,
                    expire_date=expire_at,
                )
                if not isinstance(share_info, bool):
                    share_link = share_info.get_link()
                    if share_link is None:
                        share_token = share_info.get_token()
                        share_link = urllib.parse.urljoin(
                            self.enc._webdav_url + "/", "index.php/s/" + share_token
                        )

                    retvals.append(
                        LicensedURI(
                            uri=cast("URIType", share_link),
                            licences=licences,
                        )
                    )

        return retvals

    def get_share_link_info(
        self, share_link: "str"
    ) -> "Sequence[nextcloud_client.nextcloud_client.ShareInfo]":
        # First, realize whether this is either an internal
        # or an "permanent" external (URI)
        p_shared = urllib.parse.urlparse(share_link)
        # It is not
        if p_shared.scheme == "":
            if share_link.startswith("/"):
                # Absolute one
                internal_path = share_link
            else:
                internal_path = self.base_directory + "/" + share_link
                if not self.base_directory.startswith("/"):
                    internal_path = "/" + internal_path
            share_path = None
        else:
            internal_path = None
            share_path = share_link

        shared_infos = []
        for share_info in self.enc.get_shares():
            if internal_path is not None and share_info.get_path() == internal_path:
                shared_infos.append(share_info)
            elif share_path is not None and share_info.get_link() == share_path:
                shared_infos.append(share_info)

        return shared_infos


class NextcloudExportPlugin(AbstractTokenExportPlugin):
    """
    Class to model exporting results to a Nextcloud instance
    """

    PLUGIN_NAME = cast("SymbolicName", "nextcloud")

    # Is this implementation ready?
    ENABLED: "ClassVar[bool]" = True

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

        for conf_key in ("base-directory",):
            if conf_key not in self.setup_block:
                raise ExportPluginException(
                    f"Key {conf_key} was not found in setup block"
                )
        for conf_key in ("user",):
            if conf_key not in self.setup_block:
                raise ExportPluginException(
                    f"Key {conf_key} was not found in security context block"
                )

        # Setting up the instance
        self.ce = NextcloudContentExporter(
            cast("URIType", self.api_prefix),
            self.setup_block["user"],
            self.api_token,
            self.setup_block["base-directory"],
            retention_tag_name=self.setup_block.get("retention-tag-name"),
        )

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
        if preferred_id is None:
            preferred_id = self.default_preferred_id

        # Maybe the pid already exists
        if preferred_id is not None:
            pid_draftentry = self.get_pid_draftentry(preferred_id)
            if pid_draftentry is not None:
                return pid_draftentry

        _, retpath, relretpath = self.ce.create_remote_path(
            name=cast("RelPath", preferred_id)
        )
        # TODO: embargo share links, fix this, revise
        share_links, email_addresses, expire_in = self._create_share_links(relretpath)
        if len(share_links) == 0:
            return None

        draftentry_metadata: "Mapping[str, Any]" = {
            "internal_path": relretpath,
            "pid": share_links[0].uri,
            "share_links": share_links,
            "email_addresses": email_addresses,
            "expire_in": expire_in,
        }
        return DraftEntry(
            draft_id=relretpath,
            pid=share_links[0].uri,
            metadata=draftentry_metadata,
            # TODO: hook raw metadata
            raw_metadata=None,
        )

    def discard_booked_pid(self, pid_or_draft: "Union[str, DraftEntry]") -> "bool":
        """
        This method is used to release a previously booked PID,
        which has not been published.

        When it returns False, it means that the
        provided id did exist, but it was not a draft
        """

        if isinstance(pid_or_draft, DraftEntry):
            internal = pid_or_draft.draft_id
        else:
            internal = pid_or_draft

        return self.ce.remove_remote_path(cast("RelPath", internal))

    def get_pid_metadata(self, pid: "str") -> "Optional[Mapping[str, Any]]":
        # TODO: implement get_pid_metadata, as it might be useful
        shared_infos = self.ce.get_share_link_info(pid)
        if len(shared_infos) > 0:
            share_links: "MutableSequence[str]" = []
            expire_in = None
            shared_with: "Set[str]" = set()
            internal_path = shared_infos[0].get_path()
            for shared_info in shared_infos:
                share_links.append(shared_info.get_link())

                if shared_info.get_path() != internal_path:
                    self.logger.warning(
                        f"Found more than one share link for {pid} in Nextcloud service at {self.api_prefix} using user {self.ce.nextcloud_user}"
                    )

                # Setting the soonest expiration as the one reported
                # (in some scenarios they could expire)
                this_expiration = shared_info.get_expiration()
                if this_expiration is not None:
                    if expire_in is None or expire_in > this_expiration:
                        expire_in = this_expiration

                this_shared_with = shared_info.get_share_with()
                if this_shared_with is not None:
                    shared_with.add(this_shared_with)

            return {
                "internal_path": internal_path,
                "pid": share_links[0],
                "share_links": share_links,
                "email_addresses": list(shared_with),
                "expire_in": expire_in,
            }

        return None

    def get_pid_draftentry(self, pid: "str") -> "Optional[DraftEntry]":
        """
        This method is used to obtained the metadata associated to a PID,
        in case the destination allows it.
        """

        pid_metadata = self.get_pid_metadata(pid)

        if pid_metadata is None:
            return None

        internal_path = pid_metadata["internal_path"]
        base_directory: "str" = self.ce.base_directory
        if not base_directory.startswith("/"):
            base_directory = "/" + base_directory
        if not base_directory.endswith("/"):
            base_directory += "/"
        if internal_path.startswith(base_directory):
            internal_path = internal_path[len(base_directory) :]
        return DraftEntry(
            draft_id=internal_path,
            pid=pid_metadata["pid"],
            metadata=pid_metadata,
            # TODO: hook raw metadata
            raw_metadata=None,
        )

    def _prepare_upload_mappings(
        self,
        items: "Sequence[AnyContent]",
    ) -> "Sequence[ExportMapping]":
        mappings = []
        if len(items) > 1:
            for i_item, item in enumerate(items):
                relitem = os.path.relpath(item.local, self.refdir)
                # Outside the relative directory
                if relitem.startswith(os.path.pardir):
                    # This is needed to avoid collisions
                    prefname: "Optional[RelPath]"
                    if isinstance(item, MaterializedContent):
                        prefname = item.prettyFilename
                    else:
                        prefname = item.preferredFilename

                    if prefname is None:
                        prefname = cast("RelPath", os.path.basename(item.local))
                    relitem = str(i_item) + "_" + prefname
                mappings.append(
                    ExportMapping(
                        local_filename=cast("AbsPath", item.local),
                        remote_dirname=cast("RelPath", os.path.dirname(relitem)),
                        remote_basename=cast("RelPath", os.path.basename(relitem)),
                    )
                )
        else:
            if isinstance(items[0], MaterializedContent):
                prefname = items[0].prettyFilename
            else:
                prefname = items[0].preferredFilename
            if prefname is None:
                prefname = cast("RelPath", os.path.basename(items[0].local))
            mappings.append(
                ExportMapping(
                    local_filename=cast("AbsPath", items[0].local),
                    remote_dirname=cast("RelPath", ""),
                    remote_basename=prefname,
                )
            )

        return mappings

    def get_file_bucket_prefix(
        self,
        draft_entry: "DraftEntry",
    ) -> "str":
        """
        This is an accessory method which is used to build upload paths
        """

        return draft_entry.draft_id

    def upload_file_to_draft(
        self,
        draft_entry: "DraftEntry",
        filename: "Union[str, IO[bytes]]",
        remote_filename: "Optional[str]",
        content_size: "Optional[int]" = None,
    ) -> "Mapping[str, Any]":
        local_filename: "str"
        do_remove_temp = False
        if isinstance(filename, str):
            local_filename = filename
            if remote_filename is None:
                remote_filename = os.path.relpath(local_filename, self.refdir)
        else:
            assert isinstance(
                remote_filename, str
            ), "When filename is a data stream, remote_filename must be declared"
            # assert content_size is not None, "When filename is a data stream, content_size must be declared"

            # This has to be simulated
            lfd, local_filename = tempfile.mkstemp(
                prefix="wfexs-nextcloud", suffix="push.bin"
            )
            do_remove_temp = True
            with os.fdopen(lfd, "wb") as lH:
                if content_size is not None:
                    shutil.copyfileobj(filename, lH, length=content_size)
                else:
                    shutil.copyfileobj(filename, lH)

        try:
            mappings = [
                MaterializedContent(
                    local=cast("AbsPath", local_filename),
                    licensed_uri=LicensedURI(uri=cast("URIType", "")),
                    prettyFilename=cast("RelPath", remote_filename),
                    kind=ContentKind.File,
                )
            ]
            # Now, upload the contents
            retvals, remote_path, remote_relpath = self.ce.mappings_uploader(
                self._prepare_upload_mappings(mappings),
                destname=cast("RelPath", draft_entry.draft_id),
            )
        finally:
            if do_remove_temp:
                os.unlink(local_filename)

        # And check errors
        failed = False
        for retval in retvals:
            if not retval:
                failed = True
                self.logger.error(f"There was some problem uploading to {remote_path}")

        if failed:
            raise ExportPluginException(
                f"Some contents could not be uploaded to {remote_path}"
            )

        assert remote_relpath is not None

        # TODO: add something more meaningful
        return {
            "remote_path": remote_path,
            "remote_relpath": remote_relpath,
        }

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
        # TODO: implement this (if it makes sense!)

        return {}

    def _create_share_links(
        self,
        remote_relpath: "str",
        licences: "Sequence[LicenceDescription]" = [],
    ) -> "Tuple[Sequence[LicensedURI], Sequence[str], Optional[int]]":
        # Generate the share link(s) once all the contents are there
        email_addresses = self.setup_block.get("email-addresses")
        if not isinstance(email_addresses, list):
            email_addresses = []

        expire_in = self.setup_block.get("expires-in")
        return (
            self.ce.create_share_links(
                remote_relpath,
                email_addresses,
                expire_in=expire_in,
                licences=tuple(licences)
                if len(licences) > 0
                else self.default_licences,
            ),
            email_addresses,
            expire_in,
        )

    def publish_draft_record(
        self,
        draft_entry: "DraftEntry",
    ) -> "Mapping[str, Any]":
        self._create_share_links(draft_entry.draft_id)

        # TODO: improve this (if it makes sense!)
        return {}

    def push(
        self,
        items: "Sequence[AnyContent]",
        preferred_id: "Optional[str]" = None,
        title: "Optional[str]" = None,
        description: "Optional[str]" = None,
        licences: "Sequence[LicenceDescription]" = [],
        resolved_orcids: "Sequence[ResolvedORCID]" = [],
        metadata: "Optional[Mapping[str, Any]]" = None,
        community_specific_metadata: "Optional[Mapping[str, Any]]" = None,
    ) -> "Sequence[URIWithMetadata]":
        """
        These contents will be included in the Nextcloud share
        """
        if len(items) == 0:
            raise ValueError(
                "This plugin requires at least one element to be processed"
            )

        # We are starting to learn whether we already have a PID
        preferred_id = (
            self.default_preferred_id if preferred_id is None else preferred_id
        )
        if (preferred_id is not None) and len(preferred_id) > 0:
            self.logger.debug(f"Ignoring preferred PID {preferred_id}")

        # Generate mappings
        mappings = self._prepare_upload_mappings(items)

        # Now, upload the contents
        retvals, remote_path, remote_relpath = self.ce.mappings_uploader(mappings)

        # And check errors
        failed = False
        for retval in retvals:
            if not retval:
                failed = True
                self.logger.error(f"There was some problem uploading to {remote_path}")

        if failed:
            raise ExportPluginException(
                f"Some contents could not be uploaded to {remote_path}"
            )

        assert remote_relpath is not None

        # Generate the share link(s) once all the contents are there
        shared_links, email_addresses, expire_in = self._create_share_links(
            remote_relpath
        )

        shared_uris = []
        for i_share, shared_link in enumerate(shared_links):
            self.logger.debug(f"Generated share link {shared_link}")
            shared_uris.append(
                URIWithMetadata(
                    uri=shared_link.uri,
                    # TODO: Add meaninful metadata
                    metadata={
                        "shared-with": email_addresses[i_share]
                        if len(email_addresses) > 0
                        else None,
                        "expires-in": expire_in,
                    },
                )
            )

        return shared_uris
