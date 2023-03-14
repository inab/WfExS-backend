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

import argparse
import codecs
import copy
import csv
import mimetypes
import os
import sys

from typing import (
    Any,
    cast,
    Mapping,
    MutableMapping,
    MutableSequence,
    Optional,
    Sequence,
    Tuple,
    Type,
    Union,
)

import openpyxl
import xlrd2  # type:ignore
import yaml

# We have preference for the C based loader and dumper, but the code
# should fallback to default implementations when C ones are not present
YAMLDumper: Type[Union[yaml.Dumper, yaml.CDumper]]
try:
    from yaml import CDumper as YAMLDumper
except ImportError:
    from yaml import Dumper as YAMLDumper


def loadWorkflowConfig(workflowConfigFilename: str) -> Mapping[str, Any]:
    with open(workflowConfigFilename, mode="r", encoding="utf-8") as wcf:
        workflow_config = yaml.safe_load(wcf)

        return cast(Mapping[str, Any], workflow_config)


def loadXLSParams(paramsFilename: str) -> Sequence[Mapping[str, Any]]:
    paramsArray = []

    wb = xlrd2.open_workbook(filename=paramsFilename)

    for sheet in wb.sheets():
        gotHeader = False
        header: MutableSequence[Tuple[str, int]] = []
        for row in sheet.get_rows():
            if row is None:
                continue

            # Either get the header or the data
            if gotHeader:
                params: MutableMapping[str, MutableSequence[Any]] = dict()
                for headerName, iCell in header:
                    theVal = row[iCell].value
                    params.setdefault(headerName, []).append(theVal)

                paramsArray.append(params)
            else:
                for iCell, cell in enumerate(row):
                    headerName = cell.value
                    if headerName is not None:
                        if not isinstance(headerName, str):
                            headerName = str(headerName)
                        headerName = headerName.strip()
                        if len(headerName) > 0:
                            gotHeader = True
                            header.append((headerName, iCell))

    return paramsArray


def loadXLSXParams(paramsFilename: str) -> Sequence[Mapping[str, Any]]:
    paramsArray = []

    wb = openpyxl.load_workbook(filename=paramsFilename, data_only=True, read_only=True)
    sheets = wb.worksheets

    for sheet in sheets:
        gotHeader = False
        headerMap: "MutableMapping[int,str]" = {}
        for cells_in_row in sheet.iter_rows():
            # Either get the header or the data
            if gotHeader:
                params: "MutableMapping[str, MutableSequence[Any]]" = dict()
                for cell in cells_in_row:
                    headerName = headerMap.get(cell.col_idx)
                    if headerName is not None:
                        theVal = cell.value
                        params.setdefault(headerName, []).append(theVal)

                paramsArray.append(params)
            else:
                for cell in cells_in_row:
                    headerName = cell.value
                    if headerName is not None:
                        if not isinstance(headerName, str):
                            headerName = str(headerName)
                        headerName = headerName.strip()
                        if len(headerName) > 0:
                            gotHeader = True
                            # The column index is 1-based
                            headerMap[cell.col_idx] = headerName

    return paramsArray


def loadCSVParams(paramsFilename: str) -> Sequence[Mapping[str, Any]]:
    paramsArray = []

    with open(paramsFilename, mode="rb") as cR:
        rawCSV = cR.read()

        guessedEncoding = "iso-8859-1"

        try:
            decoded = rawCSV.decode("utf-8")
            guessedEncoding = "utf-8"
        except:
            decoded = rawCSV.decode(guessedEncoding)

        sep = "\t"
        for testSep in (",", ";", "\t"):
            if testSep in decoded:
                sep = testSep
                break

        cR.seek(0)
        readerC = codecs.getreader(encoding=guessedEncoding)

        with readerC(cR) as f:
            cReader = csv.reader(f, delimiter=sep)

            gotHeader = False
            header: MutableSequence[Tuple[str, int]] = []
            for row in cReader:
                # Skip commented-out lines
                if row[0][0] == "#":
                    continue

                # Either get the header or the data
                if gotHeader:
                    params: MutableMapping[str, MutableSequence[Any]] = dict()
                    for headerName, iCell in header:
                        theVal = row[iCell]
                        params.setdefault(headerName, []).append(theVal)

                    paramsArray.append(params)
                else:
                    for iCell, headerName in enumerate(row):
                        if headerName is not None:
                            headerName = headerName.strip()
                            if len(headerName) > 0:
                                gotHeader = True
                                header.append((headerName, iCell))

    return paramsArray


MIME_PARSERS = {
    "application/vnd.ms-excel": loadXLSParams,
    "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet": loadXLSXParams,
    "text/csv": loadCSVParams,
}


def loadParamsFiles(paramsFilenames: Sequence[str]) -> Sequence[Mapping[str, Any]]:
    """
    This method returns a list of dictionaries
    being each dictionary a set of values to substitute
    into the workflow configuration template
    """
    paramsArray: MutableSequence[Mapping[str, Any]] = list()

    if not mimetypes.inited:
        mimetypes.init()

    for paramsFilename in paramsFilenames:
        if os.path.exists(paramsFilename):
            guessed_mime, guessed_encoding = mimetypes.guess_type(paramsFilename)

            print(
                "* Processing {} ({} {})".format(
                    paramsFilename, guessed_mime, guessed_encoding
                )
            )

            # If no guessed mime, bet on CSV
            mime_parser = (
                loadCSVParams
                if guessed_mime is None
                else MIME_PARSERS.get(guessed_mime)
            )

            if mime_parser is not None:
                read_paramsArray = mime_parser(paramsFilename)
                paramsArray.extend(read_paramsArray)
            else:
                print("\tNo handler for MIME {}. Skipping".format(guessed_mime))

    return paramsArray


VALID_ROOTS_DICT = {
    "params": "url",
    "outputs": "preferredName",
}
VALID_ROOTS = tuple(VALID_ROOTS_DICT.keys())


def applyValuesToTemplate(
    workflow_config_template: Mapping[str, Any], params: Mapping[str, Any]
) -> Mapping[str, Any]:
    """
    The parameters are set using as template the input
    """

    workflow_config = cast(
        MutableMapping[str, Any], copy.deepcopy(workflow_config_template)
    )

    workflow_config.setdefault("params", {})
    workflow_config.setdefault("outputs", {})

    for key, value in params.items():
        steps = list(key.split("."))
        if len(steps) < 2:
            raise Exception(
                "key names have to start with any of these keys, and then have the path to the parameter or output: {}".format(
                    VALID_ROOTS
                )
            )

        rootStep = steps.pop(0)
        leafStep = VALID_ROOTS_DICT.get(rootStep)
        if leafStep is not None:
            section = workflow_config[rootStep]
        else:
            raise Exception(
                "key names have to start with any of these keys: {}".format(VALID_ROOTS)
            )

        lastStep = steps.pop()
        for step in steps:
            section = section.setdefault(step, {})

        lastStepSection = section.get(lastStep)
        if (
            (lastStepSection is not None)
            and isinstance(lastStepSection, dict)
            and (lastStepSection.get("c-l-a-s-s") is not None)
        ):
            section = lastStepSection
            lastStep = leafStep

        section[lastStep] = value[0] if len(value) == 1 else value

    return workflow_config


def writeWorkflowConfigVariations(
    workflow_config_template: Mapping[str, Any],
    paramsArray: Sequence[Mapping[str, Any]],
    fnameTemplate: str,
    paramSymbolTemplate: Optional[str] = None,
) -> Sequence[str]:
    # Creating the directory, in case it does not exist
    destdir = os.path.abspath(args.destdir)
    os.makedirs(destdir, exist_ok=True)

    createdConfigurationFiles = []
    paramSymbolPath = None
    if paramSymbolTemplate is not None:
        paramSymbolPath = paramSymbolTemplate.split(".")

    for iParams, params in enumerate(paramsArray):
        workflow_config = applyValuesToTemplate(workflow_config_template, params)

        symbolicValue = None
        if paramSymbolPath is not None:
            symbolicValue = workflow_config.get("params")
            for paramSymbol in paramSymbolPath:
                if isinstance(symbolicValue, dict):
                    symbolicValue = symbolicValue.get(paramSymbol)

        if symbolicValue is None:
            symbolicValue = iParams

        relCreatedFilename = fnameTemplate.format(symbolicValue)
        createdFilename = os.path.join(destdir, relCreatedFilename)

        print("* Storing updated configuration at {}".format(createdFilename))
        with open(createdFilename, mode="w", encoding="utf-8") as cf:
            yaml.dump(workflow_config, cf, Dumper=YAMLDumper, sort_keys=False)

            createdConfigurationFiles.append(relCreatedFilename)

    return createdConfigurationFiles


if __name__ == "__main__":

    ap = argparse.ArgumentParser(description="WfExS config replicator")
    ap.add_argument(
        "-W",
        "--workflow-config",
        dest="workflowConfigFilename",
        required=True,
        help="Workflow configuration file, to be used as template",
    )

    app = ap.add_mutually_exclusive_group(required=True)
    app.add_argument(
        "-p",
        "--param",
        dest="inline_params",
        help="Param to substitute. Repeat to tell arrays of values",
        nargs=2,
        metavar=("PARAM_NAME", "VALUE"),
        action="append",
    )
    app.add_argument(
        "--params-file",
        dest="params_files",
        help="Tabular params file with the different variations",
        action="append",
    )

    ap.add_argument(
        "--fname-template",
        dest="filename_template",
        help="Filename template for the created workflows",
    )
    ap.add_argument(
        "--symbol-template",
        dest="paramSymbolTemplate",
    )
    ap.add_argument(
        "destdir",
        help="Directory where all the variations of the workflow configuration file are going to be created",
        nargs="?",
        default=".",
    )

    args = ap.parse_args()

    if not args.workflowConfigFilename:
        print("[ERROR] Workflow config was not provided! Stopping.", file=sys.stderr)
        sys.exit(1)

    workflow_config_template = loadWorkflowConfig(args.workflowConfigFilename)
    paramsArray = None
    if args.params_files:
        paramsArray = loadParamsFiles(args.params_files)
    else:
        params: MutableMapping[str, Any] = {}
        paramsArray = [params]
        for param, value in args.inline_params:
            params.setdefault(param, []).append(value)

    fnameTemplate = args.filename_template
    if not fnameTemplate:
        fnameTemplate = os.path.basename(args.workflowConfigFilename) + ".{}.yaml"

    paramSymbolTemplate = args.paramSymbolTemplate

    if paramsArray:
        createdConfigurationFiles = writeWorkflowConfigVariations(
            workflow_config_template, paramsArray, fnameTemplate, paramSymbolTemplate
        )

        print("These are the created files: {}".format(createdConfigurationFiles))
