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

import datetime
import logging
import os
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

from ..common import (
    LicensedURI,
    MaterializedContent,
    URIWithMetadata,
)

if TYPE_CHECKING:
    from typing import (
        Any,
        MutableSet,
        Optional,
        Sequence,
        Tuple,
    )

    from extended_nc_client.extended_nc_client import (
        DAVRequestResponse,
    )

    from ..common import (
        AbsPath,
        AnyContent,
        RelPath,
        SecurityContextConfig,
        SymbolicName,
        URIType,
    )

    from ..workflow import WF

from . import AbstractExportPlugin, ExportPluginException


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
        uplodir: "Optional[str]" = None,
        destname: "Optional[str]" = None,
    ) -> "Tuple[Sequence[DAVRequestResponse], Optional[AbsPath], Optional[RelPath]]":
        files_to_process = []
        dirs_to_process = []

        retval_reldir = None
        retval_relreldir = None
        # Reading the CSV file
        if len(contents_to_process) > 0:
            # Declaring the remote path
            _, retval_reldir, retval_relreldir = self.create_remote_path()

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
        licences: "Tuple[URIType, ...]" = tuple(),
    ) -> "Sequence[Optional[LicensedURI]]":
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


class NextcloudExportPlugin(AbstractExportPlugin):
    """
    Class to model exporting results to a Nextcloud instance
    """

    PLUGIN_NAME = cast("SymbolicName", "nextcloud")

    def __init__(
        self,
        wfInstance: "WF",
        setup_block: "Optional[SecurityContextConfig]" = None,
        licences: "Sequence[str]" = [],
    ):
        super().__init__(wfInstance, setup_block=setup_block, licences=licences)

        for conf_key in ("server", "base-directory"):
            if conf_key not in self.setup_block:
                raise ExportPluginException(
                    f"Key {conf_key} was not found in setup block"
                )
        for conf_key in ("user", "token"):
            if conf_key not in self.setup_block:
                raise ExportPluginException(
                    f"Key {conf_key} was not found in security context block"
                )

    def push(
        self,
        items: "Sequence[AnyContent]",
        preferred_scheme: "Optional[str]" = None,
        preferred_id: "Optional[str]" = None,
    ) -> "Sequence[URIWithMetadata]":
        """
        These contents will be included in the Nextcloud share
        """
        if len(items) == 0:
            raise ValueError(
                "This plugin requires at least one element to be processed"
            )

        if (preferred_scheme is not None) and len(preferred_scheme) > 0:
            self.logger.debug(f"Ignoring preferred scheme {preferred_scheme}")

        if (preferred_id is not None) and len(preferred_id) > 0:
            self.logger.debug(f"Ignoring preferred PID {preferred_id}")

        # Setting up the instance
        ce = NextcloudContentExporter(
            self.setup_block["server"],
            self.setup_block["user"],
            self.setup_block["token"],
            self.setup_block["base-directory"],
            retention_tag_name=self.setup_block.get("retention-tag-name"),
        )

        # Generate mappings
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

        # Now, upload the contents
        retvals, remote_path, remote_relpath = ce.mappings_uploader(mappings)

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
        email_addresses = self.setup_block.get("email-addresses")
        if not isinstance(email_addresses, list):
            email_addresses = []

        expire_in = self.setup_block.get("expires-in")
        shared_links = ce.create_share_links(
            remote_relpath, email_addresses, expire_in=expire_in, licences=self.licences
        )

        shared_uris = []
        for i_share, shared_link in enumerate(shared_links):
            self.logger.debug(f"Generated share link {shared_link}")
            if shared_link is not None:
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
