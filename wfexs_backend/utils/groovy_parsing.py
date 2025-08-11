#!/usr/bin/env python3
# -*- coding: utf-8 -*-

# SPDX-License-Identifier: Apache-2.0
# Parts of this module are inspired on translated-groovy3-parser.py
# from groovy-parser module
# Copyright (C) 2024 Barcelona Supercomputing Center, José M. Fernández
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

import copy
import functools
import json
import logging
import os
import re
import sys

from typing import (
    cast,
    NamedTuple,
    TYPE_CHECKING,
)

if TYPE_CHECKING:
    from typing import (
        Any,
        Iterator,
        Mapping,
        MutableMapping,
        MutableSequence,
        Optional,
        Sequence,
        Tuple,
        TypeVar,
        Union,
    )

    from ..common import (
        PathLikePath,
    )

    from groovy_parser.parser import (
        EmptyNode,
        LeafNode,
        RuleNode,
    )

    LeafPair = Tuple[str, str]
    ContextAssignments = MutableMapping[
        str, Union[Sequence[LeafPair], "ContextAssignments"]
    ]

from groovy_parser.parser import (
    parse_and_digest_groovy_content,
)

# The root_rule of any groovy/nextflow content
ROOT_RULE = ["compilation_unit", "script_statements"]

# Usually, most of the keywords from Nextflow language
# share these parsing rules
INCLUDE_PROCESS_RULE = [
    #    "script_statement",
    "statement",
    "statement_expression",
    "command_expression",
]

VAR_RULE = INCLUDE_PROCESS_RULE + [
    "expression",
]


IDENTIFIER_RULE = ["primary", "identifier"]

NAME_PART_RULE = ["name_part", "identifier"]

BLOCK_STATEMENTS_RULE = ["block_statements_opt", "block_statements"]

PATHEXP_RULE = [
    "expression",
    "postfix_expression",
    "path_expression",
]

PRE_IDENTIFIER_NAME = PATHEXP_RULE

PRE_CLOSURE_NAME = PATHEXP_RULE + [
    "primary",
    "identifier",
]

PROCESS_CHILD = {"leaf": "IDENTIFIER", "value": "process"}

INCLUDE_CHILD = {"leaf": "IDENTIFIER", "value": "include"}

WORKFLOW_CHILD = {"leaf": "IDENTIFIER", "value": "workflow"}


CONTAINER_CHILD = {"leaf": "IDENTIFIER", "value": "container"}

CONDA_CHILD = {"leaf": "IDENTIFIER", "value": "conda"}

TEMPLATE_CHILD = {"leaf": "IDENTIFIER", "value": "template"}

MANIFEST_CHILD = {"leaf": "IDENTIFIER", "value": "manifest"}

# This is from nextflow.config files
INCLUDECONFIG_CHILD = {"leaf": "IDENTIFIER", "value": "includeConfig"}

PLUGINS_CHILD = {"leaf": "IDENTIFIER", "value": "plugins"}

ID_CHILD = {"leaf": "IDENTIFIER", "value": "id"}

COMMON_RULE = [
    "argument_list",
    "first_argument_list_element",
    "expression_list_element",
    "expression",
    "postfix_expression",
    "path_expression",
]

P_RULE = COMMON_RULE

CLOSURE_RULE = COMMON_RULE + [
    "primary",
    "closure_or_lambda_expression",
    "closure",
    "block",
]

W_RULE = COMMON_RULE

NAMELESS_W_RULE = COMMON_RULE + [
    "primary",
    "closure_or_lambda_expression",
    "closure",
]


def extract_strings(node: "Union[EmptyNode, LeafNode, RuleNode]") -> "Iterator[str]":
    leaf_type = node.get("leaf")
    if leaf_type is not None:
        lnode = cast("LeafNode", node)
        if leaf_type in ("STRING_LITERAL", "STRING_LITERAL_PART"):
            yield lnode["value"]
    else:
        children = node.get("children")
        if isinstance(children, list):
            for child in children:
                yield from extract_strings(child)


def extract_values_as_pairs(
    node: "Union[EmptyNode, LeafNode, RuleNode]",
) -> "Iterator[LeafPair]":
    a_leaf_type = node.get("leaf")
    if a_leaf_type is not None:
        leaf_type = cast("str", a_leaf_type)
        lnode = cast("LeafNode", node)
        if leaf_type.endswith("_LITERAL") or leaf_type == "STRING_LITERAL_PART":
            yield leaf_type, lnode["value"]
    else:
        children = node.get("children")
        if isinstance(children, list):
            for child in children:
                yield from extract_values_as_pairs(child)


class NfProcess(NamedTuple):
    name: "str"
    containers: "Sequence[str]"
    condas: "Sequence[str]"
    templates: "Sequence[str]"


def extract_nextflow_containers(
    node: "Union[EmptyNode, LeafNode, RuleNode]",
) -> "Iterator[str]":
    # return [ node ]
    yield from filter(
        lambda s: s not in ("singularity", "docker"), extract_strings(node)
    )


def extract_nextflow_condas(
    node: "Union[EmptyNode, LeafNode, RuleNode]",
) -> "Iterator[str]":
    # return [ node ]
    spsplt = re.compile("[\t ]+")
    for conda_str in extract_strings(node):
        yield from spsplt.split(conda_str)


def extract_nextflow_templates(
    node: "Union[EmptyNode, LeafNode, RuleNode]",
) -> "Iterator[str]":
    # return [ node ]
    yield from extract_strings(node)


def extract_process_features(
    t_tree: "RuleNode",
) -> "Tuple[Sequence[str], Sequence[str], Sequence[str]]":
    templates: "MutableSequence[str]" = []
    containers: "MutableSequence[str]" = []
    condas: "MutableSequence[str]" = []

    # First, sanity check
    # root_rule = t_tree.get("rule")
    # if root_rule[-len(ROOT_RULE):] == ROOT_RULE:

    # Now, capture what it is interesting
    for child in t_tree["children"]:
        if "rule" in child:
            r_child = cast("RuleNode", child)
            child_rule = r_child["rule"]
            unprocessed = True
            if child_rule[-len(INCLUDE_PROCESS_RULE) :] == INCLUDE_PROCESS_RULE:
                # Save the process
                c_children = r_child["children"]
                c_children_0 = cast("RuleNode", c_children[0])
                c_children_0_rule = c_children_0.get("rule")
                if (
                    c_children_0_rule is not None
                    and c_children_0_rule[-len(PRE_IDENTIFIER_NAME) :]
                    == PRE_IDENTIFIER_NAME
                ):
                    c_children_0 = cast("RuleNode", c_children_0["children"][0])
                    c_children_0_rule = c_children_0.get("rule")

                # This is needed to re-evaluate
                if (
                    c_children_0_rule is not None
                    and c_children_0_rule[-len(IDENTIFIER_RULE) :] == IDENTIFIER_RULE
                ):
                    c_children_0_children = c_children_0["children"]

                    if c_children_0_children[0] == CONTAINER_CHILD:
                        containers.extend(extract_nextflow_containers(c_children[1]))
                        unprocessed = False
                    elif c_children_0_children[0] == CONDA_CHILD:
                        # both named and nameless workflows
                        condas.extend(extract_nextflow_condas(c_children[1]))
                        unprocessed = False
                    elif c_children_0_children[0] == TEMPLATE_CHILD:
                        templates.extend(extract_nextflow_templates(c_children[-1]))
                        unprocessed = False

            if unprocessed:
                c_containers, c_condas, c_templates = extract_process_features(r_child)
                containers.extend(c_containers)
                condas.extend(c_condas)
                templates.extend(c_templates)

    return containers, condas, templates


ERROR_PROCESS_NAME = "<error>"


def extract_nextflow_process(node: "RuleNode") -> "NfProcess":
    p_rule = node.get("rule")
    process_name = ERROR_PROCESS_NAME
    templates: "Sequence[str]" = []
    containers: "Sequence[str]" = []
    condas: "Sequence[str]" = []
    if p_rule == P_RULE:
        p_c_children = node["children"]
        assert len(p_c_children) > 0
        assert "children" in p_c_children[0]
        pro_node = cast("RuleNode", p_c_children[0])
        assert len(pro_node["children"]) > 0
        assert "value" in pro_node["children"][0]
        process_name = cast("LeafNode", pro_node["children"][0])["value"]
        process_body = cast("RuleNode", p_c_children[1])
        containers, condas, templates = extract_process_features(process_body)
    return NfProcess(
        name=process_name,
        templates=templates,
        containers=containers,
        condas=condas,
    )


class NfInclude(NamedTuple):
    path: "str"


def extract_nextflow_includes(node: "RuleNode") -> "Sequence[NfInclude]":
    # return [ node ]
    return [
        NfInclude(
            path=path,
        )
        for path in extract_strings(node)
    ]


class NfIncludeConfig(NamedTuple):
    path: "str"


def extract_nextflow_config_includeconfigs(
    node: "RuleNode",
) -> "Sequence[NfIncludeConfig]":
    # return [ node ]
    return [
        NfIncludeConfig(
            path=path,
        )
        for path in extract_strings(node)
    ]


class NfWorkflow(NamedTuple):
    name: "Optional[str]"


def extract_nextflow_workflow(node: "RuleNode") -> "NfWorkflow":
    nodes = None
    name = None
    if node["rule"] == W_RULE:
        assert len(node["children"]) > 1
        name = cast("LeafNode", cast("RuleNode", node["children"][0])["children"][0])[
            "value"
        ]
        nodes = cast("RuleNode", node["children"][1])["children"]
    elif node["rule"] == NAMELESS_W_RULE:
        nodes = node["children"]

    return NfWorkflow(
        name=name,
    )


class NfPlugin(NamedTuple):
    label: "str"


def extract_nextflow_config_plugins(
    node: "RuleNode",
) -> "Sequence[NfPlugin]":
    # return [ node ]
    return [
        NfPlugin(
            label=label,
        )
        for label in extract_strings(node)
    ]


if TYPE_CHECKING:
    KeyType = TypeVar("KeyType")
    DeepValType = TypeVar("DeepValType", contravariant=True)


def deep_update(
    mapping: "Mapping[KeyType, DeepValType]",
    *updating_mappings: "Mapping[KeyType, DeepValType]",
) -> "Mapping[KeyType, DeepValType]":
    # def deep_update(mapping: "DeepType", *updating_mappings: "DeepType") -> "DeepType":
    """
    This method was borrowed from pydantic
    """
    updated_mapping = cast("MutableMapping[KeyType, DeepValType]", copy.copy(mapping))
    # updated_mapping = copy.copy(mapping)
    for updating_mapping in updating_mappings:
        for k, v in updating_mapping.items():
            if (
                k in updated_mapping
                and isinstance(updated_mapping[k], dict)
                and isinstance(v, dict)
            ):
                updated_mapping[k] = cast(
                    "DeepValType",
                    deep_update(
                        cast("Mapping[KeyType, DeepValType]", updated_mapping[k]), v
                    ),
                )
            else:
                updated_mapping[k] = v
    return updated_mapping


def extract_nested_assignments(
    children: "Sequence[Union[EmptyNode, LeafNode, RuleNode]]",
    only_names: "Sequence[str]" = [],
) -> "ContextAssignments":
    context: "ContextAssignments" = dict()
    for a_child in children:
        if "rule" not in a_child:
            continue

        child = cast("RuleNode", a_child)
        child_rule = child["rule"]

        unprocessed = True
        if child_rule[-len(INCLUDE_PROCESS_RULE) :] == INCLUDE_PROCESS_RULE:
            if len(child["children"]) != 2:
                continue

            # This can be a closure. First, get the name
            a_name_node = child["children"][0]
            if "children" not in a_name_node:
                continue

            name_node = cast("RuleNode", a_name_node)
            if name_node["rule"][-len(IDENTIFIER_RULE) :] != IDENTIFIER_RULE:
                continue

            # Getting the name
            a_name = name_node["children"][0].get("value")
            if a_name is None:
                continue

            name = cast("str", a_name)
            if len(only_names) > 0 and name not in only_names:
                continue

            a_payload_node = child["children"][1]
            if "children" not in a_payload_node:
                continue

            payload_node = cast("RuleNode", a_payload_node)
            if payload_node["rule"][-len(CLOSURE_RULE) :] != CLOSURE_RULE:
                continue

            if len(payload_node["children"]) != 3:
                continue

            # The real payload is in the middle node
            if (
                payload_node["children"][0].get("leaf") != "LBRACE"
                or payload_node["children"][2].get("leaf") != "RBRACE"
            ):
                continue

            a_block_statements = payload_node["children"][1]
            if "rule" not in a_block_statements:
                continue

            block_statements = cast("RuleNode", a_block_statements)
            subcontext = extract_nested_assignments(block_statements["children"])

            if (name in context) and isinstance(context[name], dict):
                context[name] = cast(
                    "ContextAssignments",
                    deep_update(cast("ContextAssignments", context[name]), subcontext),
                )
            else:
                context[name] = subcontext
        elif child_rule[-len(VAR_RULE) :] == VAR_RULE:
            # An assignment has three children: identifier, assignment and payload
            if len(child["children"]) != 3:
                continue

            if child["children"][1].get("leaf") != "ASSIGN":
                continue

            # First, get the name
            a_name_node = child["children"][0]
            if "children" not in a_name_node:
                continue

            name_node = cast("RuleNode", a_name_node)
            if name_node["rule"][-len(IDENTIFIER_RULE) :] == IDENTIFIER_RULE:
                # Getting the starting name
                a_name = name_node["children"][0].get("value")
                if a_name is None:
                    continue
                name = cast("str", a_name)
                if len(only_names) > 0 and name not in only_names:
                    continue
                context[name] = list(extract_values_as_pairs(child["children"][2]))
            elif name_node["rule"][-len(PATHEXP_RULE) :] == PATHEXP_RULE:
                # Getting the starting name
                a_name = cast(
                    "Sequence[LeafNode]", name_node["children"][0].get("children", [{}])
                )[0].get("value")
                # name = name_node["children"][0].get("value")
                if a_name is None:
                    continue

                name = a_name
                if len(only_names) > 0 and name not in only_names:
                    continue

                p_subcontext: "ContextAssignments" = dict()
                subname = name
                nested = p_subcontext
                for a_c_name_node in name_node["children"][1:]:
                    if "rule" in a_c_name_node:
                        c_name_node = cast("RuleNode", a_c_name_node)
                        if c_name_node["rule"][0] == "path_element":
                            if (
                                len(c_name_node["children"]) == 2
                                and c_name_node["children"][0].get("leaf") == "DOT"
                            ):
                                if (
                                    c_name_node["children"][1].get("rule")
                                    == NAME_PART_RULE
                                ):
                                    a_nested_subname = cast(
                                        "RuleNode", c_name_node["children"][1]
                                    )["children"][0].get("value")
                                    if a_nested_subname is not None:
                                        nested_subname = cast("str", a_nested_subname)
                                        new_nested: "ContextAssignments" = dict()
                                        nested[subname] = new_nested
                                        nested = new_nested
                                        subname = nested_subname
                                        continue

                    # This point can be reached only if the extraction did not succeed
                    name = None
                    break

                if name is not None:
                    # Getting the value
                    # TODO: manage other types of values
                    nested[subname] = list(
                        extract_values_as_pairs(child["children"][2])
                    )
                    if name in context and isinstance(context[name], dict):
                        context[name] = cast(
                            "ContextAssignments",
                            deep_update(
                                cast("ContextAssignments", context[name]),
                                cast("ContextAssignments", p_subcontext[name]),
                            ),
                        )
                    else:
                        context[name] = p_subcontext[name]

    return context


def extract_nextflow_features(
    t_tree: "RuleNode",
) -> "Tuple[Sequence[NfProcess], Sequence[NfInclude], Sequence[NfWorkflow], Sequence[NfIncludeConfig], Sequence[NfPlugin]]":
    """
    This method takes as input a parsed groovy tree, and tries finding
    Nextflow and nextflow.config features
    """

    processes: "MutableSequence[NfProcess]" = []
    includes: "MutableSequence[NfInclude]" = []
    workflows: "MutableSequence[NfWorkflow]" = []
    includeconfigs: "MutableSequence[NfIncludeConfig]" = []
    plugins: "MutableSequence[NfPlugin]" = []

    # First, sanity check
    # root_rule = t_tree.get("rule")
    # if root_rule[-len(ROOT_RULE):] == ROOT_RULE:

    # Now, capture what it is interesting
    for a_child in t_tree["children"]:
        if "rule" in a_child:
            child = cast("RuleNode", a_child)
            child_rule = child["rule"]

            unprocessed = True
            if child_rule[-len(INCLUDE_PROCESS_RULE) :] == INCLUDE_PROCESS_RULE:
                # Save the process
                c_children = child["children"]
                c_children_0 = cast("RuleNode", c_children[0])
                c_children_0_rule = c_children_0.get("rule")
                if (
                    c_children_0_rule is not None
                    and c_children_0_rule[-len(PRE_IDENTIFIER_NAME) :]
                    == PRE_IDENTIFIER_NAME
                ):
                    c_children_0 = cast("RuleNode", c_children_0["children"][0])
                    c_children_0_rule = c_children_0.get("rule")

                # This is needed to re-evaluate
                if (
                    c_children_0_rule is not None
                    and c_children_0_rule[-len(IDENTIFIER_RULE) :] == IDENTIFIER_RULE
                ):
                    c_children_0_children = c_children_0["children"]

                    if c_children_0_children[0] == PROCESS_CHILD:
                        processes.append(
                            extract_nextflow_process(cast("RuleNode", c_children[1]))
                        )
                        unprocessed = False
                    elif c_children_0_children[0] == WORKFLOW_CHILD:
                        # both named and nameless workflows
                        workflows.append(
                            extract_nextflow_workflow(cast("RuleNode", c_children[1]))
                        )
                        unprocessed = False
                    elif c_children_0_children[0] == INCLUDE_CHILD:
                        includes.extend(
                            extract_nextflow_includes(cast("RuleNode", c_children[-1]))
                        )
                        unprocessed = False
                    elif c_children_0_children[0] == INCLUDECONFIG_CHILD:
                        includeconfigs.extend(
                            extract_nextflow_config_includeconfigs(
                                cast("RuleNode", c_children[-1])
                            )
                        )
                        unprocessed = False
                    elif c_children_0_children[0] == PLUGINS_CHILD:
                        plugins.extend(
                            extract_nextflow_config_plugins(
                                cast("RuleNode", c_children[-1])
                            )
                        )
                        unprocessed = False

            elif child_rule[-len(VAR_RULE) :] == VAR_RULE:
                # Save the process
                c_children = child["children"]
                c_children_0 = cast("RuleNode", c_children[0])
                c_children_0_rule = c_children_0.get("rule")
                if (
                    c_children_0_rule is not None
                    and c_children_0_rule[-len(PRE_IDENTIFIER_NAME) :]
                    == PRE_IDENTIFIER_NAME
                ):
                    c_children_0 = cast("RuleNode", c_children_0["children"][0])
                    c_children_0_rule = c_children_0.get("rule")

                # This is needed to re-evaluate
                if (
                    c_children_0_rule is not None
                    and c_children_0_rule[-len(IDENTIFIER_RULE) :] == IDENTIFIER_RULE
                ):
                    # TODO: extract variable assignment
                    pass

            if unprocessed:
                (
                    c_processes,
                    c_includes,
                    c_workflows,
                    c_includeconfigs,
                    c_plugins,
                ) = extract_nextflow_features(child)
                processes.extend(c_processes)
                includes.extend(c_includes)
                workflows.extend(c_workflows)
                includeconfigs.extend(c_includeconfigs)
                plugins.extend(c_plugins)

    return processes, includes, workflows, includeconfigs, plugins


# ro_cache_dirs and cache_dirs must be str in order to be hashable
@functools.lru_cache(maxsize=128)
def cached_parse_and_digest_groovy_content(
    content: "str",
    cache_dir: "Optional[str]" = None,
    ro_cache_dir: "Optional[str]" = None,
) -> "Union[RuleNode, LeafNode, EmptyNode]":
    ro_cache_dirs: "Sequence[str]" = []
    if ro_cache_dir is not None:
        ro_cache_dirs = [
            ro_cache_dir,
        ]
    t_tree = parse_and_digest_groovy_content(
        content,
        cache_directory=cache_dir,
        ro_cache_directories=ro_cache_dirs,
    )

    # This one can be written as JSON
    return t_tree


def analyze_nf_content(
    content: "str",
    only_names: "Sequence[str]" = [],
    cache_path: "Optional[PathLikePath]" = None,
    ro_cache_path: "Optional[PathLikePath]" = None,
) -> "Tuple[Union[RuleNode, LeafNode, EmptyNode], Sequence[NfProcess], Sequence[NfInclude], Sequence[NfWorkflow], Sequence[NfIncludeConfig], Sequence[NfPlugin], ContextAssignments]":
    cache_dir: "Optional[str]" = None
    if cache_path is not None:
        cache_dir = (
            cache_path if isinstance(cache_path, str) else cache_path.__fspath__()
        )
    ro_cache_dir: "Optional[str]" = None
    if ro_cache_path is not None:
        ro_cache_dir = (
            ro_cache_path
            if isinstance(ro_cache_path, str)
            else ro_cache_path.__fspath__()
        )

    t_tree = cached_parse_and_digest_groovy_content(
        content,
        cache_dir=cache_dir,
        ro_cache_dir=ro_cache_dir,
    )

    if "rule" in t_tree:
        c_t_tree = cast("RuleNode", t_tree)
        (
            processes,
            includes,
            workflows,
            includeconfigs,
            plugins,
        ) = extract_nextflow_features(
            c_t_tree,
        )
        interesting_assignments = extract_nested_assignments(
            c_t_tree["children"], only_names=only_names
        )

    else:
        processes = []
        includes = []
        workflows = []
        includeconfigs = []
        plugins = []
        interesting_assignments = dict()

    return (
        # cast("Union[RuleNode, LeafNode, EmptyNode]", t_tree),
        t_tree,
        processes,
        includes,
        workflows,
        includeconfigs,
        plugins,
        interesting_assignments,
    )


if __name__ == "__main__":
    logging.basicConfig(
        level=logging.DEBUG,
    )
    log = logging.getLogger()  # root logger
    cache_directory = os.environ.get("GROOVY_CACHEDIR")
    if cache_directory is not None:
        print(f"* Using as caching directory {cache_directory}")
        os.makedirs(cache_directory, exist_ok=True)
    else:
        print(
            "[WARNING] No caching is done. If you want to cache parsed content declare variable GROOVY_CACHEDIR"
        )
    for filename in sys.argv[1:]:
        print(f"* Parsing {filename}")
        logfile = filename + ".wfex.log"
        jsonfile = filename + ".wfex.json"
        resultfile = filename + ".wfex.result"
        lH = logging.FileHandler(logfile, mode="w", encoding="utf-8")
        for hdlr in log.handlers[:]:  # remove all old handlers
            log.removeHandler(hdlr)
        log.addHandler(lH)  # set the new handler
        try:
            with open(filename, mode="rt", encoding="utf-8") as fH:
                content = fH.read()
                (
                    t_tree,
                    processes,
                    includes,
                    workflows,
                    includeconfigs,
                    plugins,
                    interesting_assignments,
                ) = analyze_nf_content(content, cache_path=cache_directory)
            with open(jsonfile, mode="w", encoding="utf-8") as jH:
                json.dump(t_tree, jH, indent=4)
            with open(resultfile, mode="w", encoding="utf-8") as rW:
                print(f"PROCESS {processes}", file=rW)
                print(f"INCLUDE {includes}", file=rW)
                print(f"WORKFLOW {workflows}", file=rW)
                print(f"INCLUDECONFIG {includeconfigs}", file=rW)
                print(f"PLUGINS {plugins}", file=rW)
                print(f"ASSIGNMENTS:", file=rW)
                json.dump(interesting_assignments, rW, indent=4)
        except Exception as e:
            print(f"\tParse failed, see {logfile}")
            logging.exception("Parse failed")
        lH.close()
