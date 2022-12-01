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
import fnmatch
import json
import os
import re

from typing import (
    TYPE_CHECKING,
)

if TYPE_CHECKING:
    from typing import (
        Any,
        Dict,
        Iterator,
        List,
        Mapping,
        Optional,
        Pattern,
        Sequence,
        TextIO,
        Tuple,
        Union,
    )

    from ..common import (
        RelPath,
    )

import jsonschema

from ..common import AbstractWfExSException


def translate_glob_args(
    args: "Union[Iterator[str], Sequence[str]]",
) -> "List[Pattern[str]]":
    return list(map(lambda e: re.compile(fnmatch.translate(e)), args))


class DatetimeEncoder(json.JSONEncoder):
    def default(self, obj: "Any") -> "Any":
        if isinstance(obj, datetime.datetime):
            return obj.isoformat()
        # Let the base class default method raise the TypeError
        return super().default(obj)


# Next implementation of datetime.datetime.fromisoformat has been
# borrowed from cpython, so the code does not depend on Python 3.7+
# https://github.com/python/cpython/blob/998ae1fa3fb05a790071217cf8f6ae3a928da13f/Lib/datetime.py#L1721
def datetimeFromISOFormat(date_string: "str") -> "datetime.datetime":
    """Construct a datetime from the output of datetime.isoformat()."""
    if not isinstance(date_string, str):
        raise TypeError("fromisoformat: argument must be str")

    # Split this at the separator
    dstr = date_string[0:10]
    tstr = date_string[11:]

    try:
        date_components = _parse_isoformat_date(dstr)
    except IndexError as ie:
        # When the string is shorter than it was expected,
        # an IndexError arises, instead of a ValueError
        raise ValueError(f"Invalid isoformat string: {date_string!r}") from ie
    except ValueError as ve:
        raise ValueError(f"Invalid isoformat string: {date_string!r}") from ve

    if tstr:
        try:
            time_components, tzi = _parse_isoformat_time(tstr)
        except ValueError as ve2:
            raise ValueError(f"Invalid isoformat string: {date_string!r}") from ve2
    else:
        time_components = [0, 0, 0, 0]
        tzi = None

    return datetime.datetime(
        date_components[0],
        date_components[1],
        date_components[2],
        time_components[0],
        time_components[1],
        time_components[2],
        time_components[3],
        tzinfo=tzi,
    )


def _parse_isoformat_date(dtstr: "str") -> "List[int]":
    # It is assumed that this function will only be called with a
    # string of length exactly 10, and (though this is not used) ASCII-only
    year = int(dtstr[0:4])
    if dtstr[4] != "-":
        raise ValueError("Invalid date separator: %s" % dtstr[4])

    month = int(dtstr[5:7])

    if dtstr[7] != "-":
        raise ValueError(f"Invalid date separator {dtstr[7]}")

    day = int(dtstr[8:10])

    return [year, month, day]


def _parse_isoformat_time(
    tstr: "str",
) -> "Tuple[List[int], Optional[datetime.timezone]]":
    # Format supported is HH[:MM[:SS[.fff[fff]]]][+HH:MM[:SS[.ffffff]]]
    len_str = len(tstr)
    if len_str < 2:
        raise ValueError(f"Isoformat time {tstr} too short")

    # This is equivalent to re.search('[+-]', tstr), but faster
    tz_pos = tstr.find("-") + 1 or tstr.find("+") + 1 or tstr.find("Z") + 1
    timestr = tstr[: tz_pos - 1] if tz_pos > 0 else tstr

    time_comps = _parse_hh_mm_ss_ff(timestr)

    tzi = None
    if tz_pos > 0:
        tzstr = tstr[tz_pos:]

        # Valid time zone strings are:
        # HH:MM               len: 5
        # HH:MM:SS            len: 8
        # HH:MM:SS.ffffff     len: 15

        if len(tzstr) == 0:
            if tstr[tz_pos - 1] != "Z":
                raise ValueError(f"Malformed time zone string {tzstr}")
            tzi = datetime.timezone.utc
        elif (len(tzstr) not in (5, 8, 15)) or tstr[tz_pos - 1] == "Z":
            raise ValueError(f"Malformed time zone string {tzstr}")
        else:
            tz_comps = _parse_hh_mm_ss_ff(tzstr)
            if all(x == 0 for x in tz_comps):
                tzi = datetime.timezone.utc
            else:
                tzsign = -1 if tstr[tz_pos - 1] == "-" else 1

                td = datetime.timedelta(
                    hours=tz_comps[0],
                    minutes=tz_comps[1],
                    seconds=tz_comps[2],
                    microseconds=tz_comps[3],
                )

                tzi = datetime.timezone(tzsign * td)

    return time_comps, tzi


def _parse_hh_mm_ss_ff(tstr: "str") -> "List[int]":
    # Parses things of the form HH[:MM[:SS[.fff[fff]]]]
    len_str = len(tstr)

    time_comps = [0, 0, 0, 0]
    pos = 0
    for comp in range(0, 3):
        if (len_str - pos) < 2:
            raise ValueError("Incomplete time component")

        time_comps[comp] = int(tstr[pos : pos + 2])

        pos += 2
        next_char = tstr[pos : pos + 1]

        if not next_char or comp >= 2:
            break

        if next_char != ":":
            raise ValueError("Invalid time separator: %c" % next_char)

        pos += 1

    if pos < len_str:
        if tstr[pos] != ".":
            raise ValueError("Invalid microsecond component")
        else:
            pos += 1

            len_remainder = len_str - pos
            if len_remainder not in (3, 6):
                raise ValueError("Invalid microsecond component")

            time_comps[3] = int(tstr[pos:])
            if len_remainder == 3:
                time_comps[3] *= 1000

    return time_comps


def load_with_datetime(
    pairs: "Sequence[Tuple[str, Any]]", tz: "Optional[datetime.tzinfo]" = None
) -> "Mapping[str, Any]":
    """Load with dates"""
    d: "Dict[str, Any]" = {}
    for k, v in pairs:
        if isinstance(v, str):
            try:
                dv = datetimeFromISOFormat(v)
                if tz is not None:
                    dv = dv.astimezone(tz)
                d[k] = dv
            except ValueError:
                d[k] = v
        else:
            d[k] = v
    return d


def jsonFilterDecodeFromStream(
    stream: "TextIO", tz: "Optional[datetime.tzinfo]" = None
) -> "Any":
    """
    Decode JSON content from a stream, translating ISO8601 dates to strings
    """
    return json.load(stream, object_pairs_hook=lambda x: load_with_datetime(x, tz))


class ConfigValidationException(AbstractWfExSException):
    pass


SCHEMAS_REL_DIR = "schemas"


def config_validate(
    configToValidate: "Union[Mapping[str, Any], Sequence[Mapping[str, Any]]]",
    relSchemaFile: "RelPath",
) -> "List[Any]":
    # Locating the schemas directory, where all the schemas should be placed
    schemaFile = os.path.join(
        os.path.dirname(__file__), "..", SCHEMAS_REL_DIR, relSchemaFile
    )

    try:
        with open(schemaFile, mode="r", encoding="utf-8") as sF:
            schema = json.load(sF)

        jv = jsonschema.validators.validator_for(schema)(schema)
        return list(jv.iter_errors(instance=configToValidate))
    except Exception as e:
        raise ConfigValidationException(
            f"FATAL ERROR: corrupted schema {relSchemaFile}. Reason: {e}"
        )
