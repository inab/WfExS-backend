#!/usr/bin/env python3
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

import abc
import inspect
import logging
import re
from typing import (
    cast,
    TYPE_CHECKING,
)
import urllib.parse

if TYPE_CHECKING:
    from typing import (
        MutableMapping,
        MutableSequence,
        Pattern,
        Optional,
        Sequence,
        Tuple,
        Type,
        Union,
    )

    from typing_extensions import (
        Final,
    )

    from jsonschema.exceptions import ValidationError

    from .common import (
        AnyPath,
        RelPath,
        SecurityContextConfig,
    )

    from .wfexs_backend import (
        SecurityContextConfigBlock,
    )

import yaml

YAMLLoader: "Type[Union[yaml.Loader, yaml.CLoader]]"
YAMLDumper: "Type[Union[yaml.Dumper, yaml.CDumper]]"
try:
    from yaml import CLoader as YAMLLoader, CDumper as YAMLDumper
except ImportError:
    from yaml import Loader as YAMLLoader, Dumper as YAMLDumper

from .common import (
    AbstractWfExSException,
)

from .utils.marshalling_handling import unmarshall_namedtuple

from .utils.misc import config_validate


class SecurityContextVaultException(AbstractWfExSException):
    pass


class SecurityContextVault(abc.ABC):
    SCHEME_PATTERN: "Final[Pattern[str]]" = re.compile(r"^([a-z][a-z0-9+.-]*):")

    SECURITY_CONTEXT_SCHEMA: "Final[RelPath]" = cast("RelPath", "security-context.json")

    def __init__(self, creds_config: "Optional[SecurityContextConfigBlock]" = None):
        # Getting a logger focused on specific classes
        self.logger = logging.getLogger(
            dict(inspect.getmembers(self))["__module__"]
            + "::"
            + self.__class__.__name__
        )

        creds_config_by_name: "MutableMapping[str, SecurityContextConfig]" = dict()
        creds_config_by_prefix: "MutableMapping[str, MutableSequence[Tuple[str, SecurityContextConfig]]]" = (
            dict()
        )

        if creds_config is not None:
            valErrors = config_validate(creds_config, self.SECURITY_CONTEXT_SCHEMA)
            if len(valErrors) > 0:
                errstr = f"ERROR in security context block: {valErrors}"
                self.logger.error(errstr)
                raise SecurityContextVaultException(errstr)

            # Processing the input creds_config
            for name_or_prefix, sec_context in creds_config.items():
                pat = self.SCHEME_PATTERN.search(name_or_prefix)
                if pat is not None:
                    # Let's be sure the scheme is in lowercase
                    sec_scheme = pat.group(1).lower()
                    prefix = sec_scheme + name_or_prefix[len(sec_scheme) :]
                    creds_config_by_prefix.setdefault(sec_scheme, []).append(
                        (prefix, sec_context)
                    )
                else:
                    creds_config_by_name[name_or_prefix] = sec_context

        self._creds_config_by_name: "SecurityContextConfigBlock" = creds_config_by_name
        self._creds_config_by_prefix = creds_config_by_prefix

    def getContext(
        self,
        remote_file: "str",
        contextName: "Optional[str]" = None,
    ) -> "Optional[SecurityContextConfig]":
        sec_context = None
        # There are two behavioural modes
        # First one is a context by name
        if contextName is not None:
            sec_context = self._creds_config_by_name.get(contextName)
            if sec_context is None:
                raise SecurityContextVaultException(
                    "No security context {} is available, needed by {}".format(
                        contextName, remote_file
                    )
                )
        # and the second one is a context by URI prefix
        elif len(self._creds_config_by_prefix) > 0:
            parsed_remote = urllib.parse.urlparse(remote_file)
            parsed_remote_scheme = parsed_remote.scheme.lower()
            prefixes = self._creds_config_by_prefix.get(parsed_remote_scheme)
            if isinstance(prefixes, list):
                for prefix, a_sec_context in sorted(
                    prefixes, key=lambda val: (-len(val[0]), val[0])
                ):
                    if remote_file.startswith(prefix):
                        sec_context = a_sec_context
                        break

        return sec_context

    @classmethod
    def ReadSecurityContextFile(
        cls, securityContextsConfigFilename: "AnyPath"
    ) -> "Tuple[SecurityContextConfigBlock, Sequence[ValidationError]]":
        with open(securityContextsConfigFilename, mode="r", encoding="utf-8") as scf:
            creds_config = unmarshall_namedtuple(yaml.safe_load(scf))

        valErrors = config_validate(creds_config, cls.SECURITY_CONTEXT_SCHEMA)

        return cast("SecurityContextConfigBlock", creds_config), valErrors

    @classmethod
    def FromFile(
        cls, securityContextsConfigFilename: "AnyPath"
    ) -> "SecurityContextVault":
        creds_config, val_errors = cls.ReadSecurityContextFile(
            securityContextsConfigFilename
        )
        if len(val_errors) > 0:
            errstr = f"ERROR in security context block: {val_errors}"
            raise SecurityContextVaultException(errstr)

        return cls(creds_config)
