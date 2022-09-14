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

from functools import partial
import abc
import collections.abc
from typing import (
    Any,
    Iterable,
    Mapping,
    Optional,
)

# This method was inspired by https://stackoverflow.com/a/52989965


def marshall_namedtuple(obj: Any) -> Any:
    """
    This method takes any atomic value, list, dictionary or namedtuple,
    and recursively it tries translating namedtuples into dictionaries
    """

    def recurse_m(x: Iterable[Any]) -> Iterable[Any]:
        return map(marshall_namedtuple, x)

    # recurse_orig = lambda x: map(marshall_namedtuple, x)
    obj_is = partial(isinstance, obj)
    if hasattr(obj, "_marshall"):
        return marshall_namedtuple(obj._marshall())
    elif obj_is(tuple) and hasattr(obj, "_fields"):  # namedtuple
        fields = zip(obj._fields, recurse_m(obj))
        class_name = obj.__class__.__name__
        return dict(fields, **{"_type": class_name})
    elif obj_is((collections.abc.Mapping, dict)):
        return type(obj)(zip(obj.keys(), recurse_m(obj.values())))
    elif obj_is(collections.abc.Iterable) and not obj_is(str):
        return type(obj)(recurse_m(obj))
    elif obj_is(abc.ABC):
        return {"_instance_of": obj.__class__.__name__}
    elif obj_is(abc.ABCMeta):
        return {"_class": obj.__name__}
    else:
        return obj


def unmarshall_namedtuple(
    obj: Any, myglobals: Optional[Mapping[str, Any]] = None
) -> Any:
    """
    This method takes any atomic value, list or dictionary,
    and recursively it tries translating dictionaries into namedtuples
    """

    def recurse_u(
        x: Iterable[Any], myglobals: Optional[Mapping[str, Any]]
    ) -> Iterable[Any]:
        return map(lambda l: unmarshall_namedtuple(l, myglobals), x)

    # recurse_orig = lambda x, myglobals: map(lambda l: unmarshall_namedtuple(l, myglobals), x)
    obj_is = partial(isinstance, obj)
    if obj_is((collections.abc.Mapping, dict)):
        if "_class" in obj:  # originally a class
            if myglobals is None:
                myglobals = globals()
            clazz = myglobals[obj["_class"]]

            return clazz

        if "_type" in obj:  # originally namedtuple
            objn = obj.copy()
            theTypeName = objn.pop("_type")
            if myglobals is None:
                myglobals = globals()
            clazz = myglobals[theTypeName]
        else:
            objn = obj
            clazz = type(obj)
            # theTypeName = clazz.__name__

        fields = dict(zip(objn.keys(), recurse_u(objn.values(), myglobals)))
        # print("{} {} {}".format(clazz, theTypeName, fields))

        # Deactivated for now, as the code is not ready for this magic
        # if hasattr(clazz, '_unmarshall'):
        #    return clazz._unmarshall(**fields)
        # else:
        #    return clazz(**fields)

        return clazz(**fields)
    elif obj_is(collections.abc.Iterable) and not obj_is(str):
        # print(type(obj))
        return type(obj)(recurse_u(obj, myglobals))
    else:
        return obj
