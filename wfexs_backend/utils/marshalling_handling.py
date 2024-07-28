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

from functools import partial
import abc
import collections.abc
import copy
import enum
import logging
import pathlib
from typing import (
    TYPE_CHECKING,
    cast,
)

if TYPE_CHECKING:
    from typing import (
        Any,
        Callable,
        Iterable,
        Mapping,
        Optional,
    )

# This method was inspired by https://stackoverflow.com/a/52989965

logger = logging.getLogger(__name__)


def marshall_namedtuple(obj: "Any", workdir: "Optional[pathlib.Path]" = None) -> "Any":
    """
    This method takes any atomic value, list, dictionary or namedtuple,
    and recursively it tries translating namedtuples into dictionaries
    """

    # recurse_orig = lambda x: map(marshall_namedtuple, x)
    obj_is = partial(isinstance, obj)
    if hasattr(obj, "_marshall"):
        return marshall_namedtuple(obj._marshall(), workdir=workdir)
    elif obj_is(enum.Enum):  # Enum
        return {
            "_enum": obj.__class__.__name__,
            "value": obj.value,
        }
    elif obj_is(pathlib.Path):
        # Store the relative path, not the instance
        # Path.is_relative_to was introduced in Python 3.9
        is_relative_path = False
        if workdir is not None:
            # Path.is_relative_to was introduced in Python 3.9
            # is_relative_path = obj.is_relative_to(workdir)
            is_relative_path = obj.samefile(workdir) or workdir in obj.parents
        return (
            obj.relative_to(workdir).as_posix() if is_relative_path else obj.as_posix()
        )
    elif obj_is(tuple) and hasattr(obj, "_fields"):  # namedtuple
        fields = zip(obj._fields, _recurse_m(obj, workdir))
        class_name = obj.__class__.__name__
        return dict(fields, **{"_type": class_name})
    elif obj_is(object) and hasattr(obj, "__dataclass_fields__"):  # dataclass
        fields_m = map(
            lambda field: (
                field,
                marshall_namedtuple(getattr(obj, field), workdir=workdir),
            ),
            obj.__dataclass_fields__.keys(),
        )
        class_name = obj.__class__.__name__
        return dict(fields_m, **{"_type": class_name})
    elif obj_is((collections.abc.Mapping, dict)):
        return type(obj)(zip(obj.keys(), _recurse_m(obj.values(), workdir)))
    elif obj_is(collections.abc.Iterable) and not obj_is(str):
        return type(obj)(_recurse_m(obj, workdir))
    elif obj_is(abc.ABC):
        return {"_instance_of": obj.__class__.__name__}
    elif obj_is(abc.ABCMeta):
        return {"_class": obj.__name__}
    else:
        return obj


def _recurse_m(
    x: "Iterable[Any]", workdir: "Optional[pathlib.Path]"
) -> "Iterable[Any]":
    return map(lambda a_x: marshall_namedtuple(a_x, workdir=workdir), x)


def unmarshall_namedtuple(
    obj: "Any",
    myglobals: "Optional[Mapping[str, Any]]" = None,
    workdir: "Optional[pathlib.Path]" = None,
) -> "Any":
    """
    This method takes any atomic value, list or dictionary,
    and recursively it tries translating dictionaries into namedtuples
    """

    # Peeking the globals from the caller
    if myglobals is None:
        import inspect

        myglobals = inspect.stack()[1].frame.f_globals

    # recurse_orig = lambda x, myglobals: map(lambda l: unmarshall_namedtuple(l, myglobals, workdir), x)
    objres = obj
    obj_is = partial(isinstance, obj)
    if obj_is((collections.abc.Mapping, dict)):
        if "_enum" in obj:  # originally an enum
            try:
                clazz = myglobals[obj["_enum"]]
                the_value = obj["value"]
                u_table_m = getattr(clazz, "_undeprecate_table", None)
                if callable(u_table_m):
                    u_table = u_table_m()
                    the_value = u_table.get(the_value, the_value)
                retval = clazz(the_value)
            except:
                logger.error(
                    f"Unmarshalling Error peeking class implementation for {obj['_enum']}"
                )
                raise

            return retval

        if "_class" in obj:  # originally a class
            try:
                clazz = myglobals[obj["_class"]]
            except:
                logger.error(
                    f"Unmarshalling Error peeking class implementation for {obj['_class']}"
                )
                raise

            return clazz

        if "_type" in obj:  # originally namedtuple
            objn = obj.copy()
            theTypeName = objn.pop("_type")
            try:
                clazz = myglobals[theTypeName]
            except:
                logger.error(
                    f"Unmarshalling Error peeking namedtuple implementation for {theTypeName}"
                )
                raise
        else:
            objn = obj
            clazz = type(obj)
            # theTypeName = clazz.__name__

        # Fixes where some key was added or removed along the development
        c_objn = objn

        v_fixes_m = getattr(clazz, "_value_fixes", None)
        if callable(v_fixes_m):
            v_fixes = cast("Callable[[], Mapping[str, str]]", v_fixes_m)()
            c_objn = copy.copy(c_objn)
            for dest_key, source_key in v_fixes.items():
                if source_key is None:
                    # Removal if it is there
                    if dest_key in c_objn:
                        c_objn.pop(dest_key)
                elif dest_key not in c_objn:
                    # Addition if it is there
                    if source_key in c_objn:
                        c_objn[dest_key] = c_objn[source_key]

        # Complex fixes, like type change
        # this is needed for namedtuples, where their values are immutable
        # once the object is built
        m_fixes_m = getattr(clazz, "_mapping_fixes", None)
        if callable(m_fixes_m):
            c_objn = cast(
                "Callable[[Mapping[str, Any], Optional[pathlib.Path]], Mapping[str, Any]]",
                m_fixes_m,
            )(c_objn, workdir)

        # Fixes where some key was renamed along the development
        fixes_m = getattr(clazz, "_key_fixes", None)
        if callable(fixes_m):
            fixes = cast("Callable[[], Mapping[str, str]]", fixes_m)()
            c_objn_keys = map(
                lambda c_objn_key: fixes.get(c_objn_key, c_objn_key), c_objn.keys()
            )
        else:
            c_objn_keys = c_objn.keys()

        fields_list = list(
            zip(c_objn_keys, _recurse_u(c_objn.values(), myglobals, workdir))
        )
        if issubclass(clazz, dict):
            objres = clazz(fields_list)
        else:
            fields = dict(fields_list)
            # print("{} {} {}".format(clazz, theTypeName, fields))

            # Deactivated for now, as the code is not ready for this magic
            # if hasattr(clazz, '_unmarshall'):
            #    return clazz._unmarshall(**fields)
            # else:
            #    return clazz(**fields)

            try:
                # In the future, get_type_hints(clazz, globalns=myglobals) could be used
                # to learn about which fields are not strings, but pathlib.Path, for instance
                objres = clazz(**fields)
            except:
                logger.exception(f"Unmarshalling Error instantiating {clazz.__name__}")
                raise
    elif obj_is(collections.abc.Iterable) and not obj_is(str):
        # print(type(obj))
        return type(obj)(_recurse_u(obj, myglobals, workdir))

    if isinstance(objres, object):
        if hasattr(objres, "_value_defaults_fixes") and callable(
            getattr(objres, "_value_defaults_fixes")
        ):
            objres._value_defaults_fixes()
    return objres


def _recurse_u(
    x: "Iterable[Any]",
    myglobals: "Optional[Mapping[str, Any]]",
    workdir: "Optional[pathlib.Path]",
) -> "Iterable[Any]":
    return map(
        lambda l: unmarshall_namedtuple(l, myglobals=myglobals, workdir=workdir), x
    )
