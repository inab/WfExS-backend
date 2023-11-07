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


from typing import (
    cast,
    NamedTuple,
    TYPE_CHECKING,
)

if TYPE_CHECKING:
    from typing import (
        Mapping,
        Sequence,
        Set,
    )

    from typing_extensions import (
        Final,
    )

    from ..common import (
        URIType,
    )

from ..common import (
    NoLicence,
)


class LicenceDescription(NamedTuple):
    """
    This tuple is used to describe licences
    """

    short: "str"
    uri: "str"
    description: "str"


# Licences
AcceptableLicenceSchemes: "Final[Set[str]]" = {
    "ftp",
    "http",
    "https",
    "data",
}

# According to Workflow RO-Crate, this is the term for no license (or not specified)
NoLicenceShort: "Final[str]" = "notspecified"
CC_BY_40_LICENCE: "Final[str]" = "CC-BY-4.0"

# The correspondence from short Workflow RO-Crate licences and their URIs
# taken from https://about.workflowhub.eu/Workflow-RO-Crate/#supported-licenses
ROCrateShortLicencesList: "Final[Sequence[LicenceDescription]]" = [
    LicenceDescription(
        "AFL-3.0",
        "https://opensource.org/licenses/AFL-3.0",
        "Academic Free License 3.0",
    ),
    LicenceDescription(
        "APL-1.0",
        "https://opensource.org/licenses/APL-1.0",
        "Adaptive Public License 1.0",
    ),
    LicenceDescription(
        "Apache-1.1",
        "https://opensource.org/licenses/Apache-1.1",
        "Apache Software License 1.1",
    ),
    LicenceDescription(
        "Apache-2.0",
        "https://opensource.org/licenses/Apache-2.0",
        "Apache Software License 2.0",
    ),
    LicenceDescription(
        "APSL-2.0",
        "https://opensource.org/licenses/APSL-2.0",
        "Apple Public Source License 2.0",
    ),
    LicenceDescription(
        "Artistic-2.0",
        "https://opensource.org/licenses/Artistic-2.0",
        "Artistic License 2.0",
    ),
    LicenceDescription(
        "AAL", "https://opensource.org/licenses/AAL", "Attribution Assurance Licenses"
    ),
    LicenceDescription(
        "BSD-2-Clause",
        "https://opensource.org/licenses/BSD-2-Clause",
        "BSD 2-Clause “Simplified” or “FreeBSD” License (BSD-2-Clause)",
    ),
    LicenceDescription(
        "BSD-3-Clause",
        "https://opensource.org/licenses/BSD-3-Clause",
        "BSD 3-Clause “New” or “Revised” License (BSD-3-Clause)",
    ),
    LicenceDescription(
        "BitTorrent-1.1",
        "https://spdx.org/licenses/BitTorrent-1.1",
        "BitTorrent Open Source License 1.1",
    ),
    LicenceDescription(
        "BSL-1.0",
        "https://opensource.org/licenses/BSL-1.0",
        "Boost Software License 1.0",
    ),
    LicenceDescription(
        CC_BY_40_LICENCE,
        "https://creativecommons.org/licenses/by/4.0/",
        "Creative Commons Attribution 4.0 International",
    ),
    LicenceDescription(
        "CC0-1.0", "https://creativecommons.org/publicdomain/zero/1.0/", "CC0 1.0"
    ),
    LicenceDescription(
        "CNRI-Python",
        "https://opensource.org/licenses/CNRI-Python",
        "CNRI Python License",
    ),
    LicenceDescription(
        "CUA-OPL-1.0",
        "https://opensource.org/licenses/CUA-OPL-1.0",
        "CUA Office Public License 1.0",
    ),
    LicenceDescription(
        "CECILL-2.1", "https://opensource.org/licenses/CECILL-2.1", "CeCILL License 2.1"
    ),
    LicenceDescription(
        "CDDL-1.0",
        "https://opensource.org/licenses/CDDL-1.0",
        "Common Development and Distribution License 1.0",
    ),
    LicenceDescription(
        "CPAL-1.0",
        "https://opensource.org/licenses/CPAL-1.0",
        "Common Public Attribution License 1.0",
    ),
    LicenceDescription(
        "CATOSL-1.1",
        "https://opensource.org/licenses/CATOSL-1.1",
        "Computer Associates Trusted Open Source License 1.1 (CATOSL-1.1)",
    ),
    LicenceDescription(
        "EUDatagrid",
        "https://opensource.org/licenses/EUDatagrid",
        "EU DataGrid Software License",
    ),
    LicenceDescription(
        "EPL-1.0",
        "https://opensource.org/licenses/EPL-1.0",
        "Eclipse Public License 1.0",
    ),
    LicenceDescription(
        "ECL-2.0",
        "https://opensource.org/licenses/ECL-2.0",
        "Educational Community License 2.0",
    ),
    LicenceDescription(
        "EFL-2.0", "https://opensource.org/licenses/EFL-2.0", "Eiffel Forum License 2.0"
    ),
    LicenceDescription(
        "Entessa", "https://opensource.org/licenses/Entessa", "Entessa Public License"
    ),
    LicenceDescription(
        "EUPL-1.1",
        "https://opensource.org/licenses/EUPL-1.1",
        "European Union Public License 1.1",
    ),
    LicenceDescription("Fair", "https://opensource.org/licenses/Fair", "Fair License"),
    LicenceDescription(
        "Frameworx-1.0",
        "https://opensource.org/licenses/Frameworx-1.0",
        "Frameworx License 1.0",
    ),
    LicenceDescription(
        "AGPL-3.0",
        "https://opensource.org/licenses/AGPL-3.0",
        "GNU Affero General Public License v3",
    ),
    LicenceDescription(
        "GPL-2.0",
        "https://opensource.org/licenses/GPL-2.0",
        "GNU General Public License 2.0",
    ),
    LicenceDescription(
        "GPL-3.0",
        "https://opensource.org/licenses/GPL-3.0",
        "GNU General Public License 3.0",
    ),
    LicenceDescription(
        "LGPL-2.1",
        "https://opensource.org/licenses/LGPL-2.1",
        "GNU Lesser General Public License 2.1",
    ),
    LicenceDescription(
        "LGPL-3.0",
        "https://opensource.org/licenses/LGPL-3.0",
        "GNU Lesser General Public License 3.0",
    ),
    LicenceDescription(
        "HPND",
        "https://opensource.org/licenses/HPND",
        "Historical Permission Notice and Disclaimer",
    ),
    LicenceDescription(
        "IPL-1.0", "https://opensource.org/licenses/IPL-1.0", "IBM Public License 1.0"
    ),
    LicenceDescription(
        "IPA", "https://opensource.org/licenses/IPA", "IPA Font License"
    ),
    LicenceDescription("ISC", "https://opensource.org/licenses/ISC", "ISC License"),
    LicenceDescription(
        "Intel", "https://opensource.org/licenses/Intel", "Intel Open Source License"
    ),
    LicenceDescription(
        "LPPL-1.3c",
        "https://opensource.org/licenses/LPPL-1.3c",
        "LaTeX Project Public License 1.3c",
    ),
    LicenceDescription(
        "LPL-1.0",
        "https://opensource.org/licenses/LPL-1.0",
        "Lucent Public License (“Plan9”) 1.0",
    ),
    LicenceDescription(
        "LPL-1.02",
        "https://opensource.org/licenses/LPL-1.02",
        "Lucent Public License 1.02",
    ),
    LicenceDescription("MIT", "https://opensource.org/licenses/MIT", "MIT License"),
    LicenceDescription(
        "mitre",
        "https://opensource.org/licenses/CVW",
        "MITRE Collaborative Virtual Workspace License (CVW License)",
    ),
    LicenceDescription(
        "MS-PL", "https://opensource.org/licenses/MS-PL", "Microsoft Public License"
    ),
    LicenceDescription(
        "MS-RL", "https://opensource.org/licenses/MS-RL", "Microsoft Reciprocal License"
    ),
    LicenceDescription(
        "MirOS", "https://opensource.org/licenses/MirOS", "MirOS Licence"
    ),
    LicenceDescription(
        "Motosoto", "https://opensource.org/licenses/Motosoto", "Motosoto License"
    ),
    LicenceDescription(
        "MPL-1.0",
        "https://opensource.org/licenses/MPL-1.0",
        "Mozilla Public License 1.0",
    ),
    LicenceDescription(
        "MPL-1.1",
        "https://opensource.org/licenses/MPL-1.1",
        "Mozilla Public License 1.1",
    ),
    LicenceDescription(
        "MPL-2.0",
        "https://opensource.org/licenses/MPL-2.0",
        "Mozilla Public License 2.0",
    ),
    LicenceDescription(
        "Multics", "https://opensource.org/licenses/Multics", "Multics License"
    ),
    LicenceDescription(
        "NASA-1.3",
        "https://opensource.org/licenses/NASA-1.3",
        "NASA Open Source Agreement 1.3",
    ),
    LicenceDescription("NTP", "https://opensource.org/licenses/NTP", "NTP License"),
    LicenceDescription(
        "Naumen", "https://opensource.org/licenses/Naumen", "Naumen Public License"
    ),
    LicenceDescription(
        "NGPL", "https://opensource.org/licenses/NGPL", "Nethack General Public License"
    ),
    LicenceDescription(
        "Nokia", "https://opensource.org/licenses/Nokia", "Nokia Open Source License"
    ),
    LicenceDescription(
        "NPOSL-3.0",
        "https://opensource.org/licenses/NPOSL-3.0",
        "Non-Profit Open Software License 3.0",
    ),
    LicenceDescription(
        "OCLC-2.0",
        "https://opensource.org/licenses/OCLC-2.0",
        "OCLC Research Public License 2.0",
    ),
    LicenceDescription(
        "OFL-1.1", "https://opensource.org/licenses/OFL-1.1", "Open Font License 1.1"
    ),
    LicenceDescription(
        "OGL-UK-1.0",
        "https://www.nationalarchives.gov.uk/doc/open-government-licence/version/1/",
        "Open Government Licence 1.0 (United Kingdom)",
    ),
    LicenceDescription(
        "OGL-UK-2.0",
        "https://www.nationalarchives.gov.uk/doc/open-government-licence/version/2/",
        "Open Government Licence 2.0 (United Kingdom)",
    ),
    LicenceDescription(
        "OGL-UK-3.0",
        "https://www.nationalarchives.gov.uk/doc/open-government-licence/version/3/",
        "Open Government Licence 3.0 (United Kingdom)",
    ),
    LicenceDescription(
        "OGTSL",
        "https://opensource.org/licenses/OGTSL",
        "Open Group Test Suite License",
    ),
    LicenceDescription(
        "OSL-3.0",
        "https://opensource.org/licenses/OSL-3.0",
        "Open Software License 3.0",
    ),
    LicenceDescription(
        "PHP-3.0", "https://opensource.org/licenses/PHP-3.0", "PHP License 3.0"
    ),
    LicenceDescription(
        "PostgreSQL", "https://opensource.org/licenses/PostgreSQL", "PostgreSQL License"
    ),
    LicenceDescription(
        "Python-2.0", "https://opensource.org/licenses/Python-2.0", "Python License 2.0"
    ),
    LicenceDescription(
        "QPL-1.0", "https://opensource.org/licenses/QPL-1.0", "Q Public License 1.0"
    ),
    LicenceDescription(
        "RPSL-1.0",
        "https://opensource.org/licenses/RPSL-1.0",
        "RealNetworks Public Source License 1.0",
    ),
    LicenceDescription(
        "RPL-1.5",
        "https://opensource.org/licenses/RPL-1.5",
        "Reciprocal Public License 1.5",
    ),
    LicenceDescription(
        "RSCPL",
        "https://opensource.org/licenses/RSCPL",
        "Ricoh Source Code Public License",
    ),
    LicenceDescription(
        "SimPL-2.0",
        "https://opensource.org/licenses/SimPL-2.0",
        "Simple Public License 2.0",
    ),
    LicenceDescription(
        "Sleepycat", "https://opensource.org/licenses/Sleepycat", "Sleepycat License"
    ),
    LicenceDescription(
        "SISSL",
        "https://opensource.org/licenses/SISSL",
        "Sun Industry Standards Source License 1.1",
    ),
    LicenceDescription(
        "SPL-1.0", "https://opensource.org/licenses/SPL-1.0", "Sun Public License 1.0"
    ),
    LicenceDescription(
        "Watcom-1.0",
        "https://opensource.org/licenses/Watcom-1.0",
        "Sybase Open Watcom Public License 1.0",
    ),
    LicenceDescription(
        "NCSA",
        "https://opensource.org/licenses/NCSA",
        "University of Illinois/NCSA Open Source License",
    ),
    LicenceDescription("Unlicense", "https://unlicense.org/", "Unlicense"),
    LicenceDescription(
        "VSL-1.0",
        "https://opensource.org/licenses/VSL-1.0",
        "Vovida Software License 1.0",
    ),
    LicenceDescription("W3C", "https://opensource.org/licenses/W3C", "W3C License"),
    LicenceDescription("Xnet", "https://opensource.org/licenses/Xnet", "X.Net License"),
    LicenceDescription(
        "ZPL-2.0", "https://opensource.org/licenses/ZPL-2.0", "Zope Public License 2.0"
    ),
    LicenceDescription(
        "WXwindows",
        "https://opensource.org/licenses/WXwindows",
        "wxWindows Library License",
    ),
    LicenceDescription(
        "Zlib", "https://opensource.org/licenses/Zlib", "zlib/libpng license"
    ),
    LicenceDescription(
        NoLicenceShort,
        NoLicence,
        "No license - no permission to use unless the owner grants a licence",
    ),
]

ROCrateShortLicences: "Final[Mapping[str, LicenceDescription]]" = {
    lictup[0]: lictup for lictup in ROCrateShortLicencesList
}

ROCrateLongLicences: "Final[Mapping[str, LicenceDescription]]" = {
    lictup[1]: lictup for lictup in ROCrateShortLicencesList
}
