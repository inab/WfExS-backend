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
import logging
from typing import (
    cast,
    NamedTuple,
    TYPE_CHECKING,
)
import urllib.parse

if TYPE_CHECKING:
    from typing import (
        Any,
        ClassVar,
        IO,
        Mapping,
        MutableSequence,
        Optional,
        Sequence,
        Tuple,
        Union,
    )

    from typing_extensions import Final

    from ..common import (
        AbsPath,
        AnyContent,
        MaterializedInput,
        MaterializedOutput,
        RelPath,
        SecurityContextConfig,
        SymbolicName,
        URIType,
        URIWithMetadata,
    )


class ExportPluginException(Exception):
    pass


class DraftEntry(NamedTuple):
    draft_id: "str"
    pid: "str"
    metadata: "Optional[Mapping[str, Any]]"


class AbstractExportPlugin(abc.ABC):
    """
    Abstract class to model stateful export plugins
    """

    PLUGIN_NAME: "ClassVar[SymbolicName]" = cast("SymbolicName", "")
    # Is this implementation enabled?
    ENABLED: "ClassVar[bool]" = True

    def __init__(
        self,
        refdir: "AbsPath",
        setup_block: "Optional[SecurityContextConfig]" = None,
        default_licences: "Sequence[URIType]" = [],
        default_orcids: "Sequence[str]" = [],
        default_preferred_id: "Optional[str]" = None,
    ):
        import inspect

        self.logger = logging.getLogger(
            dict(inspect.getmembers(self))["__module__"]
            + "::"
            + self.__class__.__name__
        )
        # This is used to resolve paths
        self.refdir = refdir
        self.setup_block = setup_block if isinstance(setup_block, dict) else dict()

        # This is the default value for the preferred PID
        # which can be updated through a call to book_pid
        self.default_preferred_id = default_preferred_id

        self.default_licences: "Tuple[URIType, ...]" = tuple(default_licences)
        self.default_orcids: "Tuple[str, ...]" = tuple(default_orcids)

    @abc.abstractmethod
    def push(
        self,
        items: "Sequence[AnyContent]",
        preferred_id: "Optional[str]" = None,
        title: "Optional[str]" = None,
        description: "Optional[str]" = None,
        licences: "Sequence[URIType]" = [],
        orcids: "Sequence[str]" = [],
        metadata: "Optional[Mapping[str, Any]]" = None,
        community_specific_metadata: "Optional[Mapping[str, Any]]" = None,
    ) -> "Sequence[URIWithMetadata]":
        """
        This is the method to be implemented by the stateful pusher
        """
        pass

    @abc.abstractmethod
    def get_pid_metadata(self, pid: "str") -> "Optional[Mapping[str, Any]]":
        """
        This method is used to obtained the metadata associated to a PID,
        in case the destination allows it.
        """

        pass

    def get_pid_draftentry(self, pid: "str") -> "Optional[DraftEntry]":
        """
        This method is used to obtained the metadata associated to a PID,
        in case the destination allows it.
        """

        metadata = self.get_pid_metadata(pid)

        if metadata is None:
            return None

        return DraftEntry(
            # These assignments could be wrong
            draft_id=pid,
            pid=pid,
            metadata=metadata,
        )

    @abc.abstractmethod
    def book_pid(
        self,
        preferred_id: "Optional[str]" = None,
        initially_required_metadata: "Optional[Mapping[str, Any]]" = None,
        initially_required_community_specific_metadata: "Optional[Mapping[str, Any]]" = None,
        title: "Optional[str]" = None,
        description: "Optional[str]" = None,
        licences: "Sequence[URIType]" = [],
        orcids: "Sequence[str]" = [],
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

        pass

    @abc.abstractmethod
    def discard_booked_pid(self, pid_or_draft: "Union[str, DraftEntry]") -> "bool":
        """
        This method is used to release a previously booked PID,
        which has not been published.

        When it returns False, it means that the
        provided id did exist, but it was not a draft
        """

        pass

    @abc.abstractmethod
    def upload_file_to_draft(
        self,
        draft_entry: "DraftEntry",
        filename: "Union[str, IO[bytes]]",
        remote_filename: "Optional[str]",
        content_size: "Optional[int]" = None,
    ) -> "Mapping[str, Any]":
        """
        It takes as input the draft record representation, a local filename and optionally the remote filename to use
        """
        pass

    def upload_file_to_draft_by_id(
        self,
        record_id: "str",
        filename: "Union[str, IO[bytes]]",
        remote_filename: "Optional[str]",
    ) -> "Mapping[str, Any]":
        draft_record = self.get_pid_draftentry(record_id)
        if draft_record is None:
            raise KeyError(
                f"Record {record_id} could not be updated because it was not available"
            )

        return self.upload_file_to_draft(draft_record, filename, remote_filename)

    @abc.abstractmethod
    def update_record_metadata(
        self,
        draft_entry: "DraftEntry",
        metadata: "Optional[Mapping[str, Any]]" = None,
        community_specific_metadata: "Optional[Mapping[str, Any]]" = None,
        title: "Optional[str]" = None,
        description: "Optional[str]" = None,
        licences: "Sequence[URIType]" = [],
        orcids: "Sequence[str]" = [],
    ) -> "Mapping[str, Any]":
        """
        This method updates the (draft or not) record metadata,
        both the general one, and the specific of the community.
        This one could not make sense for some providers.
        """
        pass

    def update_record_metadata_by_id(
        self,
        record_id: "str",
        metadata: "Mapping[str, Any]",
        community_specific_metadata: "Optional[Mapping[str, Any]]" = None,
        licences: "Sequence[URIType]" = [],
        orcids: "Sequence[str]" = [],
    ) -> "Mapping[str, Any]":
        """
        This method updates the (draft or not) record metadata,
        both the general one, and the specific of the community.
        This one could not make sense for some providers.
        """
        record = self.get_pid_draftentry(record_id)
        if record is None:
            raise KeyError(
                f"Record {record_id} could not be updated because it was not available"
            )

        return self.update_record_metadata(
            record, metadata, community_specific_metadata=community_specific_metadata
        )

    @abc.abstractmethod
    def publish_draft_record(
        self,
        draft_entry: "DraftEntry",
    ) -> "Mapping[str, Any]":
        """
        This method publishes a draft record, so its public id is permanent
        """
        pass

    def publish_draft_record_by_id(
        self,
        record_id: "str",
    ) -> "Mapping[str, Any]":
        """
        This method publishes a draft record, so its public id is permanent
        """
        draft_record = self.get_pid_draftentry(record_id)
        if draft_record is None:
            raise KeyError(
                f"Draft record {record_id} could not be published because it was not available"
            )

        return self.publish_draft_record(draft_record)

    @classmethod
    def PluginName(cls) -> "SymbolicName":
        return cls.PLUGIN_NAME
