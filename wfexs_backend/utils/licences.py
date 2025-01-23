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


from typing import (
    cast,
    NamedTuple,
    TYPE_CHECKING,
)

if TYPE_CHECKING:
    from typing import (
        ClassVar,
        Mapping,
        MutableMapping,
        Optional,
        Sequence,
        Set,
    )

    from typing_extensions import (
        Final,
    )

    from ..common import (
        AbsPath,
        URIType,
    )

import copy
import inspect
import json
import logging
import os.path
import pathlib
import urllib.parse

import xdg.BaseDirectory

from ..scheme_catalog import (
    SchemeCatalog,
)

from ..cache_handler import (
    CacheHandlerException,
    CacheHandler,
)

from ..common import (
    CC_BY_40_LicenceDescription,
    LicenceDescription,
    NoLicenceDescription,
)

from ..fetchers.http import HTTPFetcher


# Licences
AcceptableLicenceSchemes: "Final[Set[str]]" = {
    "ftp",
    "http",
    "https",
    "data",
}

# The correspondence from short Workflow RO-Crate licences and their URIs
# taken from https://about.workflowhub.eu/Workflow-RO-Crate/#supported-licenses
WorkflowHubShortLicencesList: "Final[Sequence[LicenceDescription]]" = [
    LicenceDescription(
        short="AFL-3.0",
        uris=[cast("URIType", "https://opensource.org/licenses/AFL-3.0")],
        description="Academic Free License 3.0",
    ),
    LicenceDescription(
        short="APL-1.0",
        uris=[cast("URIType", "https://opensource.org/licenses/APL-1.0")],
        description="Adaptive Public License 1.0",
    ),
    LicenceDescription(
        short="Apache-1.1",
        uris=[cast("URIType", "https://opensource.org/licenses/Apache-1.1")],
        description="Apache Software License 1.1",
    ),
    LicenceDescription(
        short="Apache-2.0",
        uris=[cast("URIType", "https://opensource.org/licenses/Apache-2.0")],
        description="Apache Software License 2.0",
    ),
    LicenceDescription(
        short="APSL-2.0",
        uris=[cast("URIType", "https://opensource.org/licenses/APSL-2.0")],
        description="Apple Public Source License 2.0",
    ),
    LicenceDescription(
        short="Artistic-2.0",
        uris=[cast("URIType", "https://opensource.org/licenses/Artistic-2.0")],
        description="Artistic License 2.0",
    ),
    LicenceDescription(
        short="AAL",
        uris=[cast("URIType", "https://opensource.org/licenses/AAL")],
        description="Attribution Assurance Licenses",
    ),
    LicenceDescription(
        short="BSD-2-Clause",
        uris=[cast("URIType", "https://opensource.org/licenses/BSD-2-Clause")],
        description="BSD 2-Clause “Simplified” or “FreeBSD” License (BSD-2-Clause)",
    ),
    LicenceDescription(
        short="BSD-3-Clause",
        uris=[cast("URIType", "https://opensource.org/licenses/BSD-3-Clause")],
        description="BSD 3-Clause “New” or “Revised” License (BSD-3-Clause)",
    ),
    LicenceDescription(
        short="BitTorrent-1.1",
        uris=[cast("URIType", "https://spdx.org/licenses/BitTorrent-1.1")],
        description="BitTorrent Open Source License 1.1",
    ),
    LicenceDescription(
        short="BSL-1.0",
        uris=[cast("URIType", "https://opensource.org/licenses/BSL-1.0")],
        description="Boost Software License 1.0",
    ),
    CC_BY_40_LicenceDescription,
    LicenceDescription(
        short="CC0-1.0",
        uris=[cast("URIType", "https://creativecommons.org/publicdomain/zero/1.0/")],
        description="CC0 1.0",
    ),
    LicenceDescription(
        short="CNRI-Python",
        uris=[cast("URIType", "https://opensource.org/licenses/CNRI-Python")],
        description="CNRI Python License",
    ),
    LicenceDescription(
        short="CUA-OPL-1.0",
        uris=[cast("URIType", "https://opensource.org/licenses/CUA-OPL-1.0")],
        description="CUA Office Public License 1.0",
    ),
    LicenceDescription(
        short="CECILL-2.1",
        uris=[cast("URIType", "https://opensource.org/licenses/CECILL-2.1")],
        description="CeCILL License 2.1",
    ),
    LicenceDescription(
        short="CDDL-1.0",
        uris=[cast("URIType", "https://opensource.org/licenses/CDDL-1.0")],
        description="Common Development and Distribution License 1.0",
    ),
    LicenceDescription(
        short="CPAL-1.0",
        uris=[cast("URIType", "https://opensource.org/licenses/CPAL-1.0")],
        description="Common Public Attribution License 1.0",
    ),
    LicenceDescription(
        short="CATOSL-1.1",
        uris=[cast("URIType", "https://opensource.org/licenses/CATOSL-1.1")],
        description="Computer Associates Trusted Open Source License 1.1 (CATOSL-1.1)",
    ),
    LicenceDescription(
        short="EUDatagrid",
        uris=[cast("URIType", "https://opensource.org/licenses/EUDatagrid")],
        description="EU DataGrid Software License",
    ),
    LicenceDescription(
        short="EPL-1.0",
        uris=[cast("URIType", "https://opensource.org/licenses/EPL-1.0")],
        description="Eclipse Public License 1.0",
    ),
    LicenceDescription(
        short="ECL-2.0",
        uris=[cast("URIType", "https://opensource.org/licenses/ECL-2.0")],
        description="Educational Community License 2.0",
    ),
    LicenceDescription(
        short="EFL-2.0",
        uris=[cast("URIType", "https://opensource.org/licenses/EFL-2.0")],
        description="Eiffel Forum License 2.0",
    ),
    LicenceDescription(
        short="Entessa",
        uris=[cast("URIType", "https://opensource.org/licenses/Entessa")],
        description="Entessa Public License",
    ),
    LicenceDescription(
        short="EUPL-1.1",
        uris=[cast("URIType", "https://opensource.org/licenses/EUPL-1.1")],
        description="European Union Public License 1.1",
    ),
    LicenceDescription(
        short="Fair",
        uris=[cast("URIType", "https://opensource.org/licenses/Fair")],
        description="Fair License",
    ),
    LicenceDescription(
        short="Frameworx-1.0",
        uris=[cast("URIType", "https://opensource.org/licenses/Frameworx-1.0")],
        description="Frameworx License 1.0",
    ),
    LicenceDescription(
        short="AGPL-3.0",
        uris=[cast("URIType", "https://opensource.org/licenses/AGPL-3.0")],
        description="GNU Affero General Public License v3",
    ),
    LicenceDescription(
        short="GPL-2.0",
        uris=[cast("URIType", "https://opensource.org/licenses/GPL-2.0")],
        description="GNU General Public License 2.0",
    ),
    LicenceDescription(
        short="GPL-3.0",
        uris=[cast("URIType", "https://opensource.org/licenses/GPL-3.0")],
        description="GNU General Public License 3.0",
    ),
    LicenceDescription(
        short="LGPL-2.1",
        uris=[cast("URIType", "https://opensource.org/licenses/LGPL-2.1")],
        description="GNU Lesser General Public License 2.1",
    ),
    LicenceDescription(
        short="LGPL-3.0",
        uris=[cast("URIType", "https://opensource.org/licenses/LGPL-3.0")],
        description="GNU Lesser General Public License 3.0",
    ),
    LicenceDescription(
        short="HPND",
        uris=[cast("URIType", "https://opensource.org/licenses/HPND")],
        description="Historical Permission Notice and Disclaimer",
    ),
    LicenceDescription(
        short="IPL-1.0",
        uris=[cast("URIType", "https://opensource.org/licenses/IPL-1.0")],
        description="IBM Public License 1.0",
    ),
    LicenceDescription(
        short="IPA",
        uris=[cast("URIType", "https://opensource.org/licenses/IPA")],
        description="IPA Font License",
    ),
    LicenceDescription(
        short="ISC",
        uris=[cast("URIType", "https://opensource.org/licenses/ISC")],
        description="ISC License",
    ),
    LicenceDescription(
        short="Intel",
        uris=[cast("URIType", "https://opensource.org/licenses/Intel")],
        description="Intel Open Source License",
    ),
    LicenceDescription(
        short="LPPL-1.3c",
        uris=[cast("URIType", "https://opensource.org/licenses/LPPL-1.3c")],
        description="LaTeX Project Public License 1.3c",
    ),
    LicenceDescription(
        short="LPL-1.0",
        uris=[cast("URIType", "https://opensource.org/licenses/LPL-1.0")],
        description="Lucent Public License (“Plan9”) 1.0",
    ),
    LicenceDescription(
        short="LPL-1.02",
        uris=[cast("URIType", "https://opensource.org/licenses/LPL-1.02")],
        description="Lucent Public License 1.02",
    ),
    LicenceDescription(
        short="MIT",
        uris=[cast("URIType", "https://opensource.org/licenses/MIT")],
        description="MIT License",
    ),
    LicenceDescription(
        short="mitre",
        uris=[cast("URIType", "https://opensource.org/licenses/CVW")],
        description="MITRE Collaborative Virtual Workspace License (CVW License)",
        is_spdx=False,
    ),
    LicenceDescription(
        short="MS-PL",
        uris=[cast("URIType", "https://opensource.org/licenses/MS-PL")],
        description="Microsoft Public License",
    ),
    LicenceDescription(
        short="MS-RL",
        uris=[cast("URIType", "https://opensource.org/licenses/MS-RL")],
        description="Microsoft Reciprocal License",
    ),
    LicenceDescription(
        short="MirOS",
        uris=[cast("URIType", "https://opensource.org/licenses/MirOS")],
        description="MirOS Licence",
    ),
    LicenceDescription(
        short="Motosoto",
        uris=[cast("URIType", "https://opensource.org/licenses/Motosoto")],
        description="Motosoto License",
    ),
    LicenceDescription(
        short="MPL-1.0",
        uris=[cast("URIType", "https://opensource.org/licenses/MPL-1.0")],
        description="Mozilla Public License 1.0",
    ),
    LicenceDescription(
        short="MPL-1.1",
        uris=[cast("URIType", "https://opensource.org/licenses/MPL-1.1")],
        description="Mozilla Public License 1.1",
    ),
    LicenceDescription(
        short="MPL-2.0",
        uris=[cast("URIType", "https://opensource.org/licenses/MPL-2.0")],
        description="Mozilla Public License 2.0",
    ),
    LicenceDescription(
        short="Multics",
        uris=[cast("URIType", "https://opensource.org/licenses/Multics")],
        description="Multics License",
    ),
    LicenceDescription(
        short="NASA-1.3",
        uris=[cast("URIType", "https://opensource.org/licenses/NASA-1.3")],
        description="NASA Open Source Agreement 1.3",
    ),
    LicenceDescription(
        short="NTP",
        uris=[cast("URIType", "https://opensource.org/licenses/NTP")],
        description="NTP License",
    ),
    LicenceDescription(
        short="Naumen",
        uris=[cast("URIType", "https://opensource.org/licenses/Naumen")],
        description="Naumen Public License",
    ),
    LicenceDescription(
        short="NGPL",
        uris=[cast("URIType", "https://opensource.org/licenses/NGPL")],
        description="Nethack General Public License",
    ),
    LicenceDescription(
        short="Nokia",
        uris=[cast("URIType", "https://opensource.org/licenses/Nokia")],
        description="Nokia Open Source License",
    ),
    LicenceDescription(
        short="NPOSL-3.0",
        uris=[cast("URIType", "https://opensource.org/licenses/NPOSL-3.0")],
        description="Non-Profit Open Software License 3.0",
    ),
    LicenceDescription(
        short="OCLC-2.0",
        uris=[cast("URIType", "https://opensource.org/licenses/OCLC-2.0")],
        description="OCLC Research Public License 2.0",
    ),
    LicenceDescription(
        short="OFL-1.1",
        uris=[cast("URIType", "https://opensource.org/licenses/OFL-1.1")],
        description="Open Font License 1.1",
    ),
    LicenceDescription(
        short="OGL-UK-1.0",
        uris=[
            cast(
                "URIType",
                "https://www.nationalarchives.gov.uk/doc/open-government-licence/version/1/",
            )
        ],
        description="Open Government Licence 1.0 (United Kingdom)",
    ),
    LicenceDescription(
        short="OGL-UK-2.0",
        uris=[
            cast(
                "URIType",
                "https://www.nationalarchives.gov.uk/doc/open-government-licence/version/2/",
            )
        ],
        description="Open Government Licence 2.0 (United Kingdom)",
    ),
    LicenceDescription(
        short="OGL-UK-3.0",
        uris=[
            cast(
                "URIType",
                "https://www.nationalarchives.gov.uk/doc/open-government-licence/version/3/",
            )
        ],
        description="Open Government Licence 3.0 (United Kingdom)",
    ),
    LicenceDescription(
        short="OGTSL",
        uris=[cast("URIType", "https://opensource.org/licenses/OGTSL")],
        description="Open Group Test Suite License",
    ),
    LicenceDescription(
        short="OSL-3.0",
        uris=[cast("URIType", "https://opensource.org/licenses/OSL-3.0")],
        description="Open Software License 3.0",
    ),
    LicenceDescription(
        short="PHP-3.0",
        uris=[cast("URIType", "https://opensource.org/licenses/PHP-3.0")],
        description="PHP License 3.0",
    ),
    LicenceDescription(
        short="PostgreSQL",
        uris=[cast("URIType", "https://opensource.org/licenses/PostgreSQL")],
        description="PostgreSQL License",
    ),
    LicenceDescription(
        short="Python-2.0",
        uris=[cast("URIType", "https://opensource.org/licenses/Python-2.0")],
        description="Python License 2.0",
    ),
    LicenceDescription(
        short="QPL-1.0",
        uris=[cast("URIType", "https://opensource.org/licenses/QPL-1.0")],
        description="Q Public License 1.0",
    ),
    LicenceDescription(
        short="RPSL-1.0",
        uris=[cast("URIType", "https://opensource.org/licenses/RPSL-1.0")],
        description="RealNetworks Public Source License 1.0",
    ),
    LicenceDescription(
        short="RPL-1.5",
        uris=[cast("URIType", "https://opensource.org/licenses/RPL-1.5")],
        description="Reciprocal Public License 1.5",
    ),
    LicenceDescription(
        short="RSCPL",
        uris=[cast("URIType", "https://opensource.org/licenses/RSCPL")],
        description="Ricoh Source Code Public License",
    ),
    LicenceDescription(
        short="SimPL-2.0",
        uris=[cast("URIType", "https://opensource.org/licenses/SimPL-2.0")],
        description="Simple Public License 2.0",
    ),
    LicenceDescription(
        short="Sleepycat",
        uris=[cast("URIType", "https://opensource.org/licenses/Sleepycat")],
        description="Sleepycat License",
    ),
    LicenceDescription(
        short="SISSL",
        uris=[cast("URIType", "https://opensource.org/licenses/SISSL")],
        description="Sun Industry Standards Source License 1.1",
    ),
    LicenceDescription(
        short="SPL-1.0",
        uris=[cast("URIType", "https://opensource.org/licenses/SPL-1.0")],
        description="Sun Public License 1.0",
    ),
    LicenceDescription(
        short="Watcom-1.0",
        uris=[cast("URIType", "https://opensource.org/licenses/Watcom-1.0")],
        description="Sybase Open Watcom Public License 1.0",
    ),
    LicenceDescription(
        short="NCSA",
        uris=[cast("URIType", "https://opensource.org/licenses/NCSA")],
        description="University of Illinois/NCSA Open Source License",
    ),
    LicenceDescription(
        short="Unlicense",
        uris=[cast("URIType", "https://unlicense.org/")],
        description="Unlicense",
    ),
    LicenceDescription(
        short="VSL-1.0",
        uris=[cast("URIType", "https://opensource.org/licenses/VSL-1.0")],
        description="Vovida Software License 1.0",
    ),
    LicenceDescription(
        short="W3C",
        uris=[cast("URIType", "https://opensource.org/licenses/W3C")],
        description="W3C License",
    ),
    LicenceDescription(
        short="Xnet",
        uris=[cast("URIType", "https://opensource.org/licenses/Xnet")],
        description="X.Net License",
    ),
    LicenceDescription(
        short="ZPL-2.0",
        uris=[cast("URIType", "https://opensource.org/licenses/ZPL-2.0")],
        description="Zope Public License 2.0",
    ),
    LicenceDescription(
        short="WXwindows",
        uris=[cast("URIType", "https://opensource.org/licenses/WXwindows")],
        description="wxWindows Library License",
        is_spdx=False,
    ),
    LicenceDescription(
        short="Zlib",
        uris=[cast("URIType", "https://opensource.org/licenses/Zlib")],
        description="zlib/libpng license",
    ),
    NoLicenceDescription,
]


class LicenceMatcher:
    DEFAULT_SPDX_VERSION: "Final[str]" = "3.23"

    SPDX_JSON_URL_TEMPLATE: "Final[str]" = "https://raw.githubusercontent.com/spdx/license-list-data/v{}/json/licenses.json"

    def __init__(
        self,
        cacheHandler: "CacheHandler",
        cacheDir: "Optional[pathlib.Path]" = None,
        spdx_version: "str" = DEFAULT_SPDX_VERSION,
    ):
        # Getting a logger focused on specific classes
        from inspect import getmembers as inspect_getmembers

        self.logger = logging.getLogger(
            dict(inspect_getmembers(self))["__module__"]
            + "::"
            + self.__class__.__name__
        )

        # The cache is an integral part, as it is where the
        # different components are going to be fetched
        self.cacheHandler = cacheHandler
        self.cacheDir = cacheDir
        dict_short_licences: "MutableMapping[str, LicenceDescription]" = {
            lictup.short: lictup for lictup in WorkflowHubShortLicencesList
        }
        dict_long_licences: "MutableMapping[str, LicenceDescription]" = {
            uri: lictup
            for lictup in WorkflowHubShortLicencesList
            for uri in lictup.uris
        }

        spdx_source = cast("URIType", self.SPDX_JSON_URL_TEMPLATE.format(spdx_version))
        try:
            cached_content = self.cacheHandler.fetch(
                spdx_source, destdir=self.cacheDir, offline=False
            )

            # This it should be superfluous
            if os.path.exists(cached_content.path):
                with open(cached_content.path, mode="r", encoding="utf-8") as lH:
                    spdx_licences = json.load(lH)

                if isinstance(spdx_licences, dict):
                    spdx_lic_list = spdx_licences.get("licenses", [])
                    for spdx_lic in spdx_lic_list:
                        short_lic = spdx_lic.get("licenseId")
                        desc_lic = spdx_lic.get("name")

                        # Giving precedence to the original source
                        uri_lics = spdx_lic.get("seeAlso", [])
                        uri_lic = spdx_lic.get("reference")
                        if uri_lic is not None:
                            uri_lics.append(uri_lic)

                        if (
                            short_lic is not None
                            and desc_lic is not None
                            and len(uri_lics) > 0
                        ):
                            lic = LicenceDescription(
                                short=short_lic,
                                uris=uri_lics,
                                description=desc_lic,
                            )
                            dict_short_licences[short_lic] = lic
                            for the_long_lic in uri_lics:
                                dict_long_licences[the_long_lic] = lic

        except CacheHandlerException as che:
            self.logger.debug(
                f"Error while fetching or parsing version {spdx_version} of SPDX from {spdx_source}"
            )
            pass

        self.dict_short_licences = dict_short_licences
        self.dict_long_licences = dict_long_licences

    def match_ShortLicence(
        self, short_licence: "str"
    ) -> "Optional[LicenceDescription]":
        return self.dict_short_licences.get(short_licence)

    def match_LongLicence(self, long_licence: "str") -> "Optional[LicenceDescription]":
        return self.dict_long_licences.get(long_licence)

    def matchLicence(self, licence: "str") -> "Optional[LicenceDescription]":
        resolved_licence = self.match_ShortLicence(licence)
        if resolved_licence is None:
            resolved_licence = self.match_LongLicence(licence)
        if resolved_licence is None:
            if urllib.parse.urlparse(licence).scheme in AcceptableLicenceSchemes:
                resolved_licence = LicenceDescription(
                    short=licence,
                    uris=[
                        cast("URIType", licence),
                    ],
                    description=f"Custom licence {licence} . Please visit the link to learn more details",
                    is_spdx=False,
                )
        return resolved_licence

    def describeDocumentedLicences(self) -> "Sequence[LicenceDescription]":
        return list(self.dict_short_licences.values())


class LicenceMatcherSingleton(LicenceMatcher):
    __instance: "ClassVar[Optional[LicenceMatcher]]" = None

    def __new__(cls) -> "LicenceMatcher":  # type: ignore
        if cls.__instance is None:
            cachePath = pathlib.Path(
                xdg.BaseDirectory.save_cache_path("es.elixir.WfExSLicenceMatcher")
            )

            scheme_catalog = SchemeCatalog(
                scheme_handlers=HTTPFetcher.GetSchemeHandlers(),
            )

            # Private cache handler instance
            # with LicenceMatcher
            cacheHandler = CacheHandler(
                cachePath,
                scheme_catalog=scheme_catalog,
            )
            cls.__instance = LicenceMatcher(cacheHandler)

        return cls.__instance

    def __init__(self) -> None:
        pass
