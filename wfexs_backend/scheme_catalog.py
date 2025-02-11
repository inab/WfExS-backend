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

from __future__ import absolute_import

import copy
import datetime
import hashlib
import importlib
import inspect
import json
import logging
import os
import os.path
import pathlib
import re
import shutil
import traceback
import types
import urllib.parse
import uuid

from typing import (
    cast,
    NamedTuple,
    Pattern,
    TYPE_CHECKING,
)

if TYPE_CHECKING:
    from types import ModuleType

    from typing import (
        Any,
        IO,
        Iterator,
        Mapping,
        MutableMapping,
        MutableSequence,
        Optional,
        Sequence,
        Set,
        Tuple,
        Type,
        Union,
    )

    from typing_extensions import (
        Final,
        NotRequired,
        TypedDict,
    )

    from .common import (
        AbsPath,
        AnyURI,
        Fingerprint,
        PathLikePath,
        ProgsMapping,
        RelPath,
        SecurityContextConfig,
        WritableSecurityContextConfig,
        URIType,
    )

    from .fetchers import (
        ProtocolFetcherReturn,
        StatefulFetcher,
    )

    from .security_context import (
        SecurityContextVault,
    )

    class RelAbsDict(TypedDict):
        relative: RelPath
        absolute: AbsPath

    class PathMetaDict(TypedDict):
        meta: NotRequired[RelAbsDict]
        relative: NotRequired[RelPath]
        absolute: NotRequired[AbsPath]

    class MetadataEntryMetaDict(TypedDict):
        injected: bool

    class MetadataEntryDict(TypedDict):
        uri: URIType
        metadata: MetadataEntryMetaDict
        preferredName: RelPath

    class CacheMetadataDict(TypedDict):
        stamp: datetime.datetime
        path: PathMetaDict
        kind: str
        metadata_array: Sequence[MetadataEntryDict]
        resolves_to: Sequence[URIType]
        licences: Tuple[URIType, ...]
        attributions: Sequence[Mapping[str, Any]]
        fingerprint: Fingerprint
        clonable: bool


from .common import (
    AbstractWfExSException,
    Attribution,
    ContentKind,
    DefaultNoLicenceTuple,
    LicenceDescription,
    LicensedURI,
    META_JSON_POSTFIX,
    URIWithMetadata,
)

from .fetchers import (
    AbstractSchemeRepoFetcher,
    AbstractStatefulFetcher,
    AbstractStatefulStreamingFetcher,
    DocumentedProtocolFetcher,
    DocumentedStatefulProtocolFetcher,
    FetcherException,
    FetcherInstanceException,
    InvalidFetcherException,
    RemoteRepo,
)

from .utils.contents import link_or_copy
from .utils.digests import (
    ComputeDigestFromDirectory,
    ComputeDigestFromFile,
    stringifyFilenameDigest,
)
from .utils.misc import (
    config_validate,
    DatetimeEncoder,
    iter_namespace,
    jsonFilterDecodeFromStream,
    translate_glob_args,
)


class SchemeCatalogException(AbstractWfExSException):
    pass


class SchemeCatalogImportException(SchemeCatalogException):
    pass


class SchemeCatalog:
    def __init__(
        self,
        scheme_handlers: "Mapping[str, Union[DocumentedStatefulProtocolFetcher, DocumentedProtocolFetcher]]" = dict(),
    ):
        # Getting a logger focused on specific classes
        self.logger = logging.getLogger(
            dict(inspect.getmembers(self))["__module__"]
            + "::"
            + self.__class__.__name__
        )

        self.schemeHandlers: "MutableMapping[str, DocumentedProtocolFetcher]" = dict()

        self.bypassSchemeHandlers(scheme_handlers)

    def addRawSchemeHandlers(
        self, schemeHandlers: "Mapping[str, DocumentedProtocolFetcher]"
    ) -> None:
        # No validation is done here about validness of schemes
        if isinstance(schemeHandlers, dict):
            self.schemeHandlers.update(schemeHandlers)
        else:
            raise InvalidFetcherException("Unable to add raw scheme handlers")

    def bypassSchemeHandler(
        self,
        scheme: "str",
        handler: "Union[DocumentedStatefulProtocolFetcher, DocumentedProtocolFetcher]",
        progs: "ProgsMapping" = dict(),
        setup_block: "Optional[Mapping[str, Any]]" = None,
    ) -> None:
        """
        This method adds and overwrites a scheme handler,
        instantiating it if it is a stateful one.

        :param scheme:
        :param handler:
        """
        the_handler: "DocumentedProtocolFetcher"
        if isinstance(handler, DocumentedStatefulProtocolFetcher):
            inst_handler = self.instantiateStatefulFetcher(
                handler.fetcher_class, progs=progs, setup_block=setup_block
            )
            the_handler = DocumentedProtocolFetcher(
                fetcher=inst_handler.fetch,
                description=inst_handler.description
                if handler.description is None
                else handler.description,
                priority=handler.priority,
            )
        elif isinstance(handler, DocumentedProtocolFetcher) and isinstance(
            handler.fetcher,
            (
                types.FunctionType,
                types.LambdaType,
                types.MethodType,
                types.BuiltinFunctionType,
                types.BuiltinMethodType,
            ),
        ):
            the_handler = handler
        else:
            raise InvalidFetcherException(
                "Trying to set for scheme {} a invalid handler".format(scheme)
            )

        self.schemeHandlers[scheme.lower()] = the_handler

    def bypassSchemeHandlers(
        self,
        schemeHandlers: "Mapping[str, Union[DocumentedStatefulProtocolFetcher, DocumentedProtocolFetcher]]",
    ) -> None:
        # No validation is done here about validness of schemes
        if isinstance(schemeHandlers, dict):
            for scheme, clazz in schemeHandlers.items():
                self.bypassSchemeHandler(scheme, clazz)
        else:
            raise InvalidFetcherException(
                "Unable to instantiate to add scheme handlers"
            )

    def instantiateStatefulFetcher(
        self,
        statefulFetcher: "Type[StatefulFetcher]",
        progs: "ProgsMapping" = dict(),
        setup_block: "Optional[Mapping[str, Any]]" = None,
    ) -> "StatefulFetcher":
        """
        Method to instantiate stateful fetchers
        """
        instStatefulFetcher: "Optional[AbstractStatefulFetcher]" = None
        if inspect.isclass(statefulFetcher):
            if issubclass(statefulFetcher, AbstractStatefulFetcher):
                # Setting the default list of programs
                mutable_progs = copy.copy(progs)
                for prog in statefulFetcher.GetNeededPrograms():
                    mutable_progs.setdefault(prog, cast("RelPath", prog))
                try:
                    if issubclass(statefulFetcher, AbstractSchemeRepoFetcher):
                        instStatefulFetcher = statefulFetcher(
                            self, progs=mutable_progs, setup_block=setup_block
                        )
                    else:
                        instStatefulFetcher = statefulFetcher(
                            progs=progs,
                            setup_block=setup_block,
                            scheme_catalog=self,
                        )
                except Exception as e:
                    raise FetcherInstanceException(
                        f"Error while instantiating {statefulFetcher.__name__}"
                    ) from e

        if instStatefulFetcher is None:
            raise InvalidFetcherException(
                "Unable to instantiate something which is not a class inheriting from AbstractStatefulFetcher"
            )

        return cast("StatefulFetcher", instStatefulFetcher)

    def describeRegisteredSchemes(self) -> "Sequence[Tuple[str, str, int]]":
        return [
            (scheme, desc_fetcher.description, desc_fetcher.priority)
            for scheme, desc_fetcher in self.schemeHandlers.items()
        ]

    def findAndAddSchemeHandlersFromModuleName(
        self,
        the_module_name: "str" = "wfexs_backend.fetchers",
        fetchers_setup_block: "Optional[Mapping[str, Mapping[str, Any]]]" = None,
        progs: "ProgsMapping" = dict(),
    ) -> "Sequence[AbstractSchemeRepoFetcher]":
        try:
            the_module = importlib.import_module(the_module_name)
            return self.findAndAddSchemeHandlersFromModule(
                the_module,
                fetchers_setup_block=fetchers_setup_block,
                progs=progs,
            )
        except Exception as e:
            errmsg = f"Unable to import module {the_module_name} in order to gather scheme handlers, due errors:"
            self.logger.exception(errmsg)
            raise SchemeCatalogImportException(errmsg) from e

    def findAndAddSchemeHandlersFromModule(
        self,
        the_module: "ModuleType",
        fetchers_setup_block: "Optional[Mapping[str, Mapping[str, Any]]]" = None,
        progs: "ProgsMapping" = dict(),
    ) -> "Sequence[AbstractSchemeRepoFetcher]":
        repo_fetchers: "MutableSequence[AbstractSchemeRepoFetcher]" = []

        for finder, module_name, ispkg in iter_namespace(the_module):
            try:
                named_module = importlib.import_module(module_name)
            except:
                self.logger.exception(
                    f"Skipping module {module_name} in order to gather scheme handlers, due errors:"
                )
                continue

            # First, try locating a variable named SCHEME_HANDLERS
            # then, the different class declarations inheriting
            # from AbstractStatefulFetcher
            skipit = True
            for name, obj in inspect.getmembers(named_module):
                if name == "SCHEME_HANDLERS":
                    if isinstance(obj, dict):
                        self.addSchemeHandlers(
                            obj,
                            fetchers_setup_block=fetchers_setup_block,
                        )
                        skipit = False
                elif (
                    inspect.isclass(obj)
                    and not inspect.isabstract(obj)
                    and issubclass(obj, AbstractStatefulFetcher)
                ):
                    # Now, let's learn whether the class is enabled
                    if getattr(obj, "ENABLED", False):
                        repo_fetchers.extend(
                            self.addStatefulSchemeHandlers(
                                obj,
                                fetchers_setup_block=fetchers_setup_block,
                                progs=progs,
                            )
                        )
                        skipit = False

            if skipit:
                self.logger.debug(
                    f"Fetch module {named_module} was not eligible (no SCHEME_HANDLERS dictionary or subclass of {AbstractStatefulFetcher.__name__})"
                )

        return repo_fetchers

    def addStatefulSchemeHandlers(
        self,
        statefulSchemeHandler: "Type[AbstractStatefulFetcher]",
        fetchers_setup_block: "Optional[Mapping[str, Mapping[str, Any]]]" = None,
        progs: "ProgsMapping" = dict(),
    ) -> "Sequence[AbstractSchemeRepoFetcher]":
        """
        This method adds scheme handlers (aka "fetchers") from
        a given stateful fetcher, also adding the needed programs
        """

        # Get the scheme handlers from this fetcher
        schemeHandlers = statefulSchemeHandler.GetSchemeHandlers()

        return self.addSchemeHandlers(
            schemeHandlers,
            fetchers_setup_block=fetchers_setup_block,
            progs=progs,
        )

    def get(self, scheme: "str") -> "Optional[DocumentedProtocolFetcher]":
        return self.schemeHandlers.get(scheme)

    def getSchemeHandler(
        self, the_remote_file: "URIType"
    ) -> "DocumentedProtocolFetcher":
        # Content is fetched here
        # As of RFC3986, schemes are case insensitive
        parsedInputURL = urllib.parse.urlparse(the_remote_file)
        the_scheme = parsedInputURL.scheme.lower()
        scheme_handler = self.get(the_scheme)

        if scheme_handler is None:
            errmsg = f"No {the_scheme} scheme handler for {the_remote_file}. Was this URI injected in the cache? Is it a supported one?"
            self.logger.error(errmsg)
            raise SchemeCatalogException(errmsg)

        return scheme_handler

    def fetch(
        self,
        the_remote_file: "URIType",
        cached_filename: "PathLikePath",
        sec_context: "Optional[SecurityContextConfig]" = None,
    ) -> "ProtocolFetcherReturn":
        scheme_handler = self.getSchemeHandler(the_remote_file)

        # Content is fetched here
        return scheme_handler.fetcher(
            the_remote_file,
            cached_filename,
            secContext=sec_context,
        )

    def streamfetch(
        self,
        the_remote_file: "URIType",
        the_stream: "IO[bytes]",
        sec_context: "Optional[SecurityContextConfig]" = None,
    ) -> "ProtocolFetcherReturn":
        scheme_handler = self.getSchemeHandler(the_remote_file)

        stream_fetcher = (
            scheme_handler.fetcher.__self__
            if hasattr(scheme_handler.fetcher, "__self__")
            else None
        )

        if not isinstance(stream_fetcher, AbstractStatefulStreamingFetcher):
            errmsg = f"Scheme handler for {the_remote_file} does not offer streaming capabilities."
            self.logger.error(errmsg)
            raise SchemeCatalogException(errmsg)

        # Content is fetched here
        return stream_fetcher.streamfetch(
            the_remote_file,
            the_stream,
            secContext=sec_context,
        )

    # This pattern is used to validate the schemes
    SCHEME_PAT: "Final[Pattern[str]]" = re.compile(r"^[a-zA-Z][a-zA-Z0-9+.-]*$")

    def addSchemeHandlers(
        self,
        schemeHandlers: "Mapping[str, Union[DocumentedProtocolFetcher, DocumentedStatefulProtocolFetcher]]",
        fetchers_setup_block: "Optional[Mapping[str, Mapping[str, Any]]]" = None,
        progs: "ProgsMapping" = dict(),
    ) -> "Sequence[AbstractSchemeRepoFetcher]":
        """
        This method adds scheme handlers (aka "fetchers")
        or instantiates stateful scheme handlers (aka "stateful fetchers")
        """
        instSchemeHandlers = dict()
        fetchers_mapping: "MutableMapping[Type[AbstractStatefulFetcher], DocumentedProtocolFetcher]" = (
            dict()
        )
        repo_fetchers: "MutableSequence[AbstractSchemeRepoFetcher]" = []
        if fetchers_setup_block is None:
            fetchers_setup_block = dict()
        for scheme, schemeHandler in schemeHandlers.items():
            if self.SCHEME_PAT.search(scheme) is None:
                self.logger.warning(
                    f"Fetcher associated to scheme {scheme} has been skipped, as the scheme does not comply with RFC3986"
                )
                continue

            lScheme = scheme.lower()
            # When no setup block is available for the scheme fetcher,
            # provide an empty one
            setup_block = fetchers_setup_block.get(lScheme, dict())

            instSchemeHandler: "Optional[DocumentedProtocolFetcher]" = None
            if isinstance(schemeHandler, DocumentedStatefulProtocolFetcher):
                instSchemeHandler = fetchers_mapping.get(schemeHandler.fetcher_class)
                if instSchemeHandler is None:
                    try:
                        instSchemeInstance = self.instantiateStatefulFetcher(
                            schemeHandler.fetcher_class,
                            setup_block=setup_block,
                            progs=progs,
                        )
                        if instSchemeInstance is not None:
                            instSchemeHandler = DocumentedProtocolFetcher(
                                fetcher=instSchemeInstance.fetch,
                                description=instSchemeInstance.description
                                if schemeHandler.description is None
                                else schemeHandler.description,
                                priority=schemeHandler.priority,
                            )
                            fetchers_mapping[
                                schemeHandler.fetcher_class
                            ] = instSchemeHandler
                            if isinstance(
                                instSchemeInstance, AbstractSchemeRepoFetcher
                            ):
                                repo_fetchers.append(instSchemeInstance)
                    except Exception as e:
                        self.logger.exception(
                            f"Error while instantiating handler implemented at {schemeHandler.fetcher_class} for scheme {lScheme}"
                        )
            elif isinstance(schemeHandler, DocumentedProtocolFetcher) and callable(
                schemeHandler.fetcher
            ):
                instSchemeHandler = schemeHandler

            # Only the ones which have overcome the sanity checks
            if instSchemeHandler is not None:
                # Schemes are case insensitive, so register only
                # the lowercase version
                instSchemeHandlers[lScheme] = instSchemeHandler
            else:
                self.logger.warning(
                    f"Scheme {lScheme} could not be properly instantiated"
                )

        self.addRawSchemeHandlers(instSchemeHandlers)

        return repo_fetchers
