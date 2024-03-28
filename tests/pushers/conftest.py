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

import pytest

from tests.pushers.marks import (
    MARKERS,
)


def pytest_configure(config: "pytest.Config") -> "None":
    for mark_details in MARKERS:
        config.addinivalue_line(
            "markers",
            f"{mark_details.name}: {mark_details.mark_description}",
        )


import logging

logger = logging.getLogger(__name__)
# logger.setLevel(logging.INFO)


# import inspect
# from _pytest.compat import is_generator
#
# FirstPassCollect: "MutableMapping[str, List[Union[nodes.Item, nodes.Collector]]]" = dict()
#
# @pytest.hookimpl(tryfirst=True)
# def pytest_pycollect_makeitem(
#    collector: "Union[pytest.Module, pytest.Class]", name: "str", obj: "object"
# ) -> "Union[None, pytest.Item, pytest.Collector, List[Union[nodes.Item, nodes.Collector]]]":
#    assert isinstance(collector, (pytest.Class, pytest.Module)), type(collector)
#    # Nothing was collected elsewhere, let's do it here.
#    if collector.istestfunction(obj, name):
#        # mock seems to store unbound methods (issue473), normalize it.
#        obj = getattr(obj, "__func__", obj)
#        # We need to try and unwrap the function if it's a functools.partial
#        # or a functools.wrapped.
#        # We mustn't if it's been wrapped with mock.patch (python 2 only).
#        if (inspect.isfunction(obj) or inspect.isfunction(get_real_func(obj))) and getattr(obj, "__test__", True):
#            if not is_generator(obj):
#                retval = list(collector._genfunctions(name, obj))
#                FirstPassCollect[name] = retval
#                return retval
#    return None


@pytest.hookimpl(tryfirst=True)
def pytest_generate_tests(metafunc: "pytest.Metafunc") -> "None":
    for mark_details in MARKERS:
        found_mark = False
        for mark in metafunc.definition.iter_markers(name=mark_details.name):
            found_mark = True

        if found_mark:
            mark_config_filename = metafunc.config.getoption(mark_details.param)
            if mark_config_filename is not None:
                the_mark = pytest.mark.param_file(mark_config_filename, fmt="yaml")
            else:
                the_mark = pytest.mark.skip(
                    f"No configuration file provided through {mark_details.option} for this batch of {mark_details.acronym} tests"
                )

            metafunc.function = the_mark(metafunc.function)
            metafunc.definition.obj = metafunc.function
            metafunc.definition.add_marker(the_mark)
            metafunc.function.pytestmark = [
                mark
                for mark in metafunc.function.pytestmark
                if mark.name != mark_details.name
            ]


# @pytest.hookimpl(tryfirst=True)
# def pytest_collection_modifyitems(config: "pytest.Config", items: "MutableSequence[pytest.Item]") -> "None":
#    # Borrowed from https://github.com/RKrahl/pytest-dependency/issues/37#issuecomment-1589629688
#    # It is not perfect, because it borks fixtures
#    seen: "MutableMapping[str, Set[str]]" = dict()
#    new_items: "MutableSequence[pytest.Item]" = list()
#
#    def dfs(item: "pytest.Item", do_collect: "bool" = False) -> "Set[str]":
#        if item.name in seen:
#            return seen[item.name]
#
#        do_append = True
#        new_dependencies = set()
#        for marker in item.iter_markers(name="dependency"):
#            if do_collect or marker.kwargs.get("collect"):
#                new_dependencies = set()
#                if len(item.name) > len(item.originalname):
#                    postfix = item.name[len(item.originalname):]
#                else:
#                    postfix = ""
#                dependencies = set(marker.kwargs.get("depends", []))
#                dfs_funs = []
#                for dependency in dependencies:
#                    funs = FirstPassCollect.get(dependency)
#                    new_dependency = dependency
#                    if funs is not None:
#                        for fun in funs:
#                            dependency_alt = dependency + postfix
#                            # Could find the dependency
#                            if fun.name in (dependency, dependency_alt):
#                                if fun.name != dependency:
#                                    new_dependency = dependency_alt
#                                dfs_funs.append(fun)
#                                break
#                        #for fun in funs:
#                        #    fun = pytest.Function.from_parent(
#                        #        name=basefun.name,
#                        #        parent=basefun.parent,
#                        #        callspec=basefun.callspec,
#                        #        callobj=basefun.obj,
#                        #        keywords=basefun.keywords,
#                        #        fixtureinfo=basefun._fixtureinfo,
#                        #        originalname=basefun.originalname,
#                        #    )
#
#                    # Always add, so dependencies to be skipped can be still detected
#                    new_dependencies.add(new_dependency)
#                    #    fun = pytest.Function.from_parent(name=dependency, parent=item.parent)
#                    #    # fun.setup()
#                    #    dfs(fun, True)
#                    #fun = pytest.Function.from_parent(name=dependency, parent=item.parent)
#                    ## fun.setup()
#                    #dfs(fun)
#                # Only when all the dependencies could be resolved is when
#                # we are going to the next level
#                if len(dfs_funs) == len(new_dependencies):
#                    for fun in dfs_funs:
#                        new_dependencies.update(dfs(fun, do_collect=True))
#                else:
#                    do_append = False
#                marker.kwargs["depends"] = list(new_dependencies)
#
#        if do_append:
#            new_items.append(item)
#        seen[item.name] = new_dependencies
#        return new_dependencies
#
#    for item in items:
#        dfs(item)
#
#    old_names = set(item.name for item in items)
#    new_names = [item.name for item in new_items if item.name not in old_names]
#    if new_names:
#        logger.debug("Un-deselected:", *new_names)
#
#    items[:] = new_items
