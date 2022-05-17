#!/usr/bin/env python
# -*- coding: utf-8 -*-

# Copyright 2020-2022 Barcelona Supercomputing Center (BSC), Spain
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
from typing import Any, Mapping, Optional, Sequence, TYPE_CHECKING, Union
from typing import cast, MutableSet, NamedTuple, Tuple
from typing_extensions import Final
import urllib.parse
import uuid

import nextcloud    # type: ignore[import]
from nextcloud.codes import ShareType  # type: ignore[import]
import nextcloud.codes  # type: ignore[import]

from ..common import AbsPath, RelPath, ExportItem, SymbolicName
from ..common import SecurityContextConfig, URIWithMetadata
from ..common import MaterializedInput, MaterializedOutput
from ..common import AnyContent, MaterializedContent
from ..common import CacheType, URIType

from . import AbstractExportPlugin, ExportPluginException

if TYPE_CHECKING:
    from ..workflow import WF

def patched_create_share(
        self, path, share_type, share_with=None, public_upload=None,
        password=None, permissions=None, expire_date=None):
    """
    Share a file/folder with a user/group or as public link
    Mandatory fields: share_type, path and share_with for share_type USER (0) or GROUP (1).
    Args:
        path (str): path to the file/folder which should be shared
        share_type (int): ShareType attribute
        share_with (str): user/group id with which the file should be shared
        public_upload (bool): bool, allow public upload to a public shared folder (true/false)
        password (str): password to protect public link Share with
        permissions (int): sum of selected Permission attributes
    Returns:
        requester response
    """
    if not self.validate_share_parameters(path, share_type, share_with):
        return False

    url = self.get_local_url()
    if public_upload:
        public_upload = "true"

    data = {"path": path, "shareType": share_type}
    if share_type in [ShareType.GROUP, ShareType.USER, ShareType.FEDERATED_CLOUD_SHARE, 4]:
        data["shareWith"] = share_with
    if public_upload:
        data["publicUpload"] = public_upload
    if share_type == ShareType.PUBLIC_LINK and password is not None:
        data["password"] = str(password)
    if permissions is not None:
        data["permissions"] = permissions
    if expire_date is not None:
        data["expireDate"] = expire_date
    return self.requester.post(url, data)

class ExportMapping(NamedTuple):
    local_filename: AbsPath
    remote_dirname: RelPath
    remote_basename: RelPath

class NextcloudContentExporter:
    """
    This code is a trimmed version of the one created for ES-FEGA
    (Spanish Federated EGA) infrastructure
    """
    def __init__(self, nextcloud_url: URIType, nextcloud_user: str, nextcloud_token: str, nextcloud_base_directory:AbsPath, retention_tag_name: Optional[str] = None):
        import inspect
        
        # Getting a logger focused on specific classes
        self.logger = logging.getLogger(dict(inspect.getmembers(self))['__module__'] + '::' + self.__class__.__name__)
        
        # This set is used to record the directories which have already
        # been created (or ensured they exist)
        self._ensured_paths : MutableSet[str] = set()
        
        self.nextcloud_url = nextcloud_url
        self.nextcloud_user = nextcloud_user
        self.nextcloud_token = nextcloud_token
        self.base_directory = nextcloud_base_directory
        
        self.chunk_size = 65536
        
        self.nc = nextcloud.NextCloud(
            nextcloud_url,
            user=nextcloud_user,
            password=nextcloud_token,
            # session_kwargs={
            #     'verify': False
            # }
        )
        
        # Monkey patch
        self.nc.create_share = patched_create_share.__get__(self.nc.create_share.__self__, self.nc.create_share.__self__.__class__) # pylint: disable=E1120
        
        self.nc.login()
        
        # Creating the retention system tag to be used to label
        self.ret_tag_name : Optional[str]
        if retention_tag_name is not None:
            # pylint: disable=E1101
            retention_tag = self.nc.get_systemtag(retention_tag_name)
            if retention_tag is None:
                self.nc.create_systemtag(retention_tag_name)
        
            self.ret_tag_name = retention_tag_name
        else:
            self.ret_tag_name = None
    
    def create_remote_path(self, reldir: Optional[RelPath] = None, name: Optional[RelPath] = None) -> Tuple[Any, AbsPath, RelPath]:
        # If the name is not defined, generate a random, new one
        if name is None:
            name = cast(RelPath, str(uuid.uuid4()))
        
        if reldir:
            relretval = cast(RelPath, reldir + '/' + name)
        else:
            relretval = name
        
        retval = cast(AbsPath, self.base_directory + '/' + relretval)
        retvalobj = None
        
        if retval not in self._ensured_paths:
            encoded_path = urllib.parse.quote(retval)
            
            created = self.nc.ensure_tree_exists(encoded_path)  # pylint: disable=E1101
            
            if created and self.ret_tag_name:
                retvalobj = self.nc.get_folder(encoded_path)  # pylint: disable=E1101
                retvalobj.add_tag(tag_name=self.ret_tag_name)
            
            # import pprint
            # pprint.pprint(created)
            # pprint.pprint(retvalobj)
            
            # Adding all the prefixes of the path
            self._ensured_paths.add(retval)
            rslash = retval.rfind('/')
            while rslash > 0:
                self._ensured_paths.add(retval[0:rslash])
                rslash = retval.rfind('/', 0, rslash)

        return retvalobj, retval, relretval
    
    def _chunked_uploader(self, fmapping: ExportMapping) -> nextcloud.response.WebDAVResponse:
        local_file , uplodir, destname = fmapping
        if destname is None:
            destname = cast(RelPath, os.path.basename(local_file))
        
        
        destpath = urllib.parse.quote(self.base_directory) + '/'
        if uplodir:
            destpath += urllib.parse.quote(uplodir) + '/'
            
        destpath += urllib.parse.quote(destname, safe='')
        
        self.logger.debug(f'{local_file} -> {destpath}')
        timestamp = int(os.path.getmtime(local_file))
        retval = None
        with open(local_file, mode='rb') as uH:
            retval = self._stream_chunked_uploader(uH, destpath, timestamp)
        
        if retval.is_ok and self.ret_tag_name:
            # pylint: disable=E1101
            self.nc.get_file(destpath).add_tag(tag_name=self.ret_tag_name)
        
        return retval
    
    def _chunked_file_batch_uploader(self, files_to_process: Sequence[ExportMapping]) -> Sequence[nextcloud.response.WebDAVResponse]:
        retvals = []
        self.logger.debug(f'{len(files_to_process)} files to upload')
        for fmapping in files_to_process:
            self.logger.debug(f'{fmapping.local_filename} {fmapping.remote_dirname} {fmapping.remote_basename}')
            retvals.append(self._chunked_uploader(fmapping))
        
        return retvals
    
    def mappings_uploader(
        self,
        contents_to_process: Sequence[ExportMapping],
        uplodir: Optional[str] = None,
        destname: Optional[str] = None
    ) -> Tuple[Sequence[nextcloud.response.WebDAVResponse], Optional[AbsPath], Optional[RelPath]]:
        files_to_process = []
        dirs_to_process = []
        
        retval_reldir = None
        retval_relreldir = None
        # Reading the CSV file
        if len(contents_to_process) > 0:
            # Declaring the remote path
            _ , retval_reldir, retval_relreldir = self.create_remote_path()
        
        for mapping in contents_to_process:
            assert retval_relreldir is not None
            local_filename = mapping.local_filename
            remote_dirname = cast(RelPath, os.path.join(retval_relreldir, mapping.remote_dirname.lstrip('/')))
            remote_basename = mapping.remote_basename
                
            if os.path.exists(local_filename):
                if os.path.isfile(local_filename):
                    files_to_process.append(
                        mapping._replace(remote_dirname=remote_dirname)
                    )
                    self.create_remote_path(name=remote_dirname)
                elif os.path.isdir(local_filename):
                    dirs_to_process.append(mapping._replace(remote_dirname=remote_dirname))
                else:
                    raise NotImplementedError(f'Unimplemented management of "files" like {local_filename}')
            else:
                raise ValueError(f"Local file {local_filename} does not exist")
        
        while len(dirs_to_process) > 0:
            new_dirs_to_process = []
            for dmapping in dirs_to_process:
                local_dir, upload_base_dir, upload_dir_basename = dmapping
                self.logger.debug(f'{local_dir} {upload_base_dir} {upload_dir_basename}')
                _ , remote_path, rel_remote_path = self.create_remote_path(upload_base_dir, upload_dir_basename)
                for entry in os.scandir(local_dir):
                    # Skipping problematic files,
                    if not entry.name.startswith('.'):
                        if entry.is_file():
                            files_to_process.append(
                                ExportMapping(
                                    local_filename=cast(AbsPath, entry.path),
                                    remote_dirname=rel_remote_path,
                                    remote_basename=cast(RelPath, entry.name)
                                )
                            )
                        elif entry.is_dir():
                            new_dirs_to_process.append(
                                ExportMapping(
                                    local_filename=cast(AbsPath, entry.path),
                                    remote_dirname=rel_remote_path,
                                    remote_basename=cast(RelPath, entry.name)
                                )
                            )
            
            # Now, rotation time
            dirs_to_process = new_dirs_to_process
        
        # No work, then return
        retvals: Sequence[nextcloud.response.WebDAVResponse]
        if len(files_to_process) == 0 and len(dirs_to_process) == 0:
            retvals = []
        else:
            retvals = self._chunked_file_batch_uploader(files_to_process)
        
        return retvals, retval_reldir, retval_relreldir
    
    def _stream_chunked_uploader(self, stream, destpath, timestamp) -> nextcloud.response.WebDAVResponse:
        # pylint: disable=E1101
        return self.nc.upload_file_contents(stream, destpath, timestamp=timestamp)
    
    def create_share_links(self, relpath, emails: Sequence[str], expire_in: Optional[int] = None):
        retvals = []
        permissions = nextcloud.codes.Permission.READ
        the_path = urllib.parse.quote(self.base_directory + '/' + relpath)
        
        if expire_in is not None:
            expire_at_d = datetime.date.today() + datetime.timedelta(days=expire_in)
            expire_at = expire_at_d.isoformat()
        else:
            expire_at = None
        
        if not isinstance(emails, (list, tuple)) or len(emails)==0:
            retvals.append(self.nc.create_share(the_path, ShareType.PUBLIC_LINK, permissions=permissions, expire_date=expire_at))
        else:
            share_type = 4
            for email in emails:
                retvals.append(self.nc.create_share(the_path, share_type, permissions=permissions, share_with=email, expire_date=expire_at))
        
        return retvals


class NextcloudExportPlugin(AbstractExportPlugin):
    """
    Class to model exporting results to a Nextcloud instance
    """
    
    PLUGIN_NAME : SymbolicName = cast(SymbolicName, "nextcloud")
    
    def __init__(self, wfInstance: "WF", setup_block: Optional[SecurityContextConfig] = None):
        super().__init__(wfInstance, setup_block)
        
        for conf_key in ('server', 'base-directory'):
            if conf_key not in self.setup_block:
                raise ExportPluginException(f'Key {conf_key} was not found in setup block')
        for conf_key in ('user', 'token'):
            if conf_key not in self.setup_block:
                raise ExportPluginException(f'Key {conf_key} was not found in security context block')
    
    def push(self, items: Sequence[AnyContent], preferred_scheme: Optional[str] = None, preferred_id: Optional[str] = None) -> Sequence[URIWithMetadata]:
        """
        These contents will be included in the nextflow share
        """
        if len(items) == 0:
            raise ValueError("This plugin requires at least one element to be processed")
        
        if (preferred_scheme is not None) and len(preferred_scheme) > 0:
            self.logger.debug(f"Ignoring preferred scheme {preferred_scheme}")
        
        if (preferred_id is not None) and len(preferred_id) > 0:
            self.logger.debug(f"Ignoring preferred PID {preferred_id}")
        
        # Setting up the instance
        ce = NextcloudContentExporter(
            self.setup_block['server'],
            self.setup_block['user'],
            self.setup_block['token'],
            self.setup_block['base-directory'],
            retention_tag_name=self.setup_block.get('retention-tag-name')
        )
        
        # Generate mappings
        mappings = []
        if len(items) > 1:
            for i_item, item in enumerate(items):
                relitem = os.path.relpath(item.local, self.refdir)
                # Outside the relative directory
                if relitem.startswith(os.path.pardir):
                    # This is needed to avoid collisions
                    prefname : Optional[RelPath]
                    if isinstance(item, MaterializedContent):
                        prefname = item.prettyFilename
                    else:
                        prefname = item.preferredFilename
                    
                    if prefname is None:
                        prefname = cast(RelPath, os.path.basename(item.local))
                    relitem = str(i_item) + '_' + prefname
                mappings.append(
                    ExportMapping(
                        local_filename=cast(AbsPath, item.local),
                        remote_dirname=cast(RelPath, os.path.dirname(relitem)),
                        remote_basename=cast(RelPath, os.path.basename(relitem))
                    )
                )
        else:
            if isinstance(item, MaterializedContent):
                prefname = item.prettyFilename
            else:
                prefname = item.preferredFilename
            if prefname is None:
                prefname = cast(RelPath, os.path.basename(items[0].local))
            mappings.append(
                ExportMapping(
                    local_filename=cast(AbsPath, items[0].local),
                    remote_dirname=cast(RelPath, ''),
                    remote_basename=prefname
                )
            )
        
        # Now, upload the contents
        retvals , remote_path, remote_relpath = ce.mappings_uploader(mappings)
        
        # And check errors
        errmsg = ''
        for retval in retvals:
            if not retval.is_ok:
                the_errmsg = retval.get_error_message()
                self.logger.error(f"There was some problem uploading to {remote_path}: {the_errmsg}")
                errmsg += "\n" + the_errmsg
        
        if len(errmsg) > 0:
            raise ExportPluginException(f'Some contents could not be uploaded to {remote_path}: {errmsg}')
        
        # Generate the share link(s) once all the contents are there
        email_addresses = self.setup_block.get('email-addresses')
        if not isinstance(email_addresses, list):
            email_addresses = []
        
        expire_in = self.setup_block.get('expires-in')
        shared_links = ce.create_share_links(remote_relpath, email_addresses, expire_in=expire_in)
        
        shared_uris = []
        for i_share, shared_link in enumerate(shared_links):
            self.logger.debug(f'Generated share link {shared_link.data["url"]}')
            shared_uris.append(
                URIWithMetadata(
                    uri=shared_link.data['url'],
                    # TODO: Add meaninful metadata
                    metadata={
                        "shared-with": email_addresses[i_share]  if len(email_addresses) > 0  else None,
                        "expires-in": expire_in
                    }
                )
            )
            
        return shared_uris
        