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

import argparse
import atexit
import datetime
import functools
import json
import logging
import os
import os.path
import pathlib
import sys
import shutil
import tempfile
from typing import (
    cast,
    TYPE_CHECKING,
)

from .common import (
    ArgsDefaultWithRawHelpFormatter,
    CacheType as WfExS_CacheType,
    StrDocEnum,
)

if TYPE_CHECKING:
    from typing import (
        Callable,
        Sequence,
        Tuple,
        Type,
        Union,
    )

    from typing_extensions import (
        NotRequired,
        TypeAlias,
        TypedDict,
    )

    from .common import (
        AbsPath,
        SymbolicName,
        URIType,
    )

    Callable_WfExS_CacheType: TypeAlias = Callable[[str], WfExS_CacheType]

    class BasicLoggingConfigDict(TypedDict):
        filename: NotRequired[str]
        format: str
        level: int


import yaml

# We have preference for the C based loader and dumper, but the code
# should fallback to default implementations when C ones are not present
YAMLLoader: "Type[Union[yaml.Loader, yaml.CLoader]]"
YAMLDumper: "Type[Union[yaml.Dumper, yaml.CDumper]]"
try:
    from yaml import CLoader as YAMLLoader, CDumper as YAMLDumper
except ImportError:
    from yaml import Loader as YAMLLoader, Dumper as YAMLDumper

from .security_context import SecurityContextVault
from .side_caches import populate_side_caches
from .utils.rocrate import (
    ReproducibilityLevel,
)
from .wfexs_backend import WfExSBackend
from .workflow import (
    WF,
)
from . import get_WfExS_version_str
from .utils.licences import LicenceMatcherSingleton
from .utils.misc import DatetimeEncoder


class WfExS_Commands(StrDocEnum):
    PopulateSideCaches = (
        "populate-side-caches",
        "Populate read-only side caches which live in XDG_CACHE_HOME (shared by all the WfExS instances of the very same user)",
    )
    Init = ("init", "Init local setup")
    Cache = ("cache", "Cache handling subcommands")
    ConfigValidate = (
        "config-validate",
        "Validate the configuration files to be used for staging and execution",
    )
    ListFetchers = (
        "list-fetchers",
        "List the supported fetchers / schemes",
    )
    ListPushers = (
        "list-exporters",
        "List the supported export plugins",
    )
    ListLicences = (
        "list-licences",
        f"List the documented licences, both embedded and fetched from SPDX release {LicenceMatcherSingleton.DEFAULT_SPDX_VERSION}",
    )
    ListContainerFactories = (
        "list-container-factories",
        "List the supported container factories",
    )
    ListWorkflowEngines = (
        "list-workflow-engines",
        "List the supported workflow engines",
    )
    Stage = (
        "stage",
        "Prepare the staging (working) directory for workflow execution, fetching dependencies and contents",
    )
    ReStage = (
        "re-stage",
        "Prepare a new staging (working) directory for workflow execution, repeating the fetch of dependencies and contents",
    )
    MountWorkDir = (
        "mount-workdir",
        "Mount the encrypted staging directory on secure staging scenarios",
    )
    StagedWorkDir = (
        "staged-workdir",
        "Staged working directories handling subcommands",
    )
    Import = (
        "import",
        "Workflow Run RO-Crate import into a new staged working directory",
    )
    Export = ("export", "Staged working directories export subcommands")
    ExportStage = ("export-stage", "Export the staging directory as an RO-Crate")
    OfflineExecute = (
        "offline-execute",
        "Execute an already prepared workflow in the staging directory",
    )
    Execute = ("execute", "Execute the stage + offline-execute + export steps")
    ExportResults = (
        "export-results",
        "Export the results to a remote location, gathering their public ids",
    )
    ExportCrate = (
        "export-crate",
        "Export an already executed workflow in the staging directory as an RO-Crate",
    )


if TYPE_CHECKING:
    Callable_WfExS_Commands: TypeAlias = Callable[[str], WfExS_Commands]


class WfExS_Cache_Commands(StrDocEnum):
    List = ("ls", "List the cache entries")
    Status = ("status", "Show the cache entries metadata")
    Inject = ("inject", "Inject a new entry in the cache")
    Fetch = (
        "fetch",
        "Fetch a new cache entry, giving as input both the URI and optionally both a security context file and a security context name",
    )
    Remove = ("rm", "Remove an entry from the cache")
    Validate = ("validate", "Validate the consistency of the cache")


if TYPE_CHECKING:
    Callable_WfExS_Cache_Commands = Callable[[str], WfExS_Cache_Commands]


class WfExS_Staged_WorkDir_Commands(StrDocEnum):
    OfflineExecute = (
        "offline-exec",
        "Offline execute the staged instances which match the input pattern",
    )
    OfflineQueueExecute = (
        "offline-queue",
        "Queue offline execution about the staged instances which match the input pattern",
    )
    List = (
        "ls",
        "List the staged instances\n\tIt shows the instance id, nickname,\n\tencryption and whether they are damaged",
    )
    Mount = ("mount", "Mount the staged instances which match the input pattern")
    Remove = ("rm", "Removes the staged instances which match the input pattern")
    Shell = (
        "shell",
        "Launches a command in the workdir\n\tFirst parameter is either the staged instance id or the nickname.\n\tIt launches the command specified after the id.\n\tIf there is no additional parameters, it launches a shell\n\tin the mounted working directory of the instance",
    )
    Status = ("status", "Shows staged instances status")
    CreateStagedROCrate = (
        "create-staged-crate",
        "It creates an RO-Crate from the prospective provenance",
    )
    CreateProvenanceROCrate = (
        "create-prov-crate",
        "It creates an RO-Crate from the retrospective provenance (after a workflow execution)",
    )


#    Validate = 'validate'
if TYPE_CHECKING:
    Callable_WfExS_Staged_WorkDir_Commands = Callable[
        [str], WfExS_Staged_WorkDir_Commands
    ]


class WfExS_Export_Commands(StrDocEnum):
    List = ("ls", "List the public identifiers obtained from previous export actions")
    Run = (
        "run",
        "Run the different export actions, pushing the exported content and gathering the obtained permanent / public identifiers",
    )


if TYPE_CHECKING:
    Callable_WfExS_Export_Commands = Callable[[str], WfExS_Export_Commands]


DEFAULT_LOCAL_CONFIG_RELNAME = "wfexs_config.yml"
LOGGING_FORMAT = "%(asctime)-15s - [%(levelname)s] %(message)s"
DEBUG_LOGGING_FORMAT = (
    "%(asctime)-15s - [%(name)s %(funcName)s %(lineno)d][%(levelname)s] %(message)s"
)

# This is going to be wildly reused
PathArgType = lambda p: pathlib.Path(p).absolute()


def genParserSub(
    sp: "argparse._SubParsersAction[argparse.ArgumentParser]",
    command: "WfExS_Commands",
    preStageParams: "bool" = False,
    postStageParams: "bool" = False,
    crateParams: "bool" = False,
    exportParams: "bool" = False,
) -> "argparse.ArgumentParser":
    ap_ = sp.add_parser(
        command.value,
        formatter_class=ArgsDefaultWithRawHelpFormatter,
        help=command.description,
    )

    if preStageParams:
        if command == WfExS_Commands.Import:
            ap_.add_argument(
                "-R",
                "--workflow-rocrate",
                dest="workflowROCrateFilenameOrURI",
                required=True,
                help="Workflow Run RO-Crate describing a previous workflow execution. It can be either a local path or an URI resolvable from WfExS with no authentication",
            )

            ap_.add_argument(
                "--ignore-retrospective-provenance",
                dest="retrospective_first",
                action="store_false",
                default=True,
                help="Retrospective provenance is ignored",
            )
            ap_.add_argument(
                "--prefer-retrospective-provenance",
                dest="retrospective_first",
                action="store_true",
                help="Retrospective provenance is first inspected",
            )

        not_restage = command not in (WfExS_Commands.Import, WfExS_Commands.ReStage)
        ap_.add_argument(
            "-W",
            "--workflow-config",
            dest="workflowConfigFilename",
            required=not_restage,
            type=PathArgType,
            help="Configuration file, describing workflow and inputs"
            if not_restage
            else "Optional configuration file, describing some inputs which will replace the base, original ones",
        )

        if not not_restage:
            ap_.add_argument(
                "-s",
                "--no-secure",
                dest="secure",
                action="store_false",
                default=True,
                help="Make unsecured working directory",
            )
            ap_.add_argument(
                "-S",
                "--secure",
                dest="secure",
                action="store_true",
                help="Make secured working directory (default)",
            )

            ap_.add_argument(
                "--strict-reproducibility",
                dest="strict_reproducibility_level",
                action="store_true",
                default=False,
                help="Strict reproducibility",
            )
            ap_.add_argument(
                "--no-strict-reproducibility",
                dest="strict_reproducibility_level",
                action="store_false",
                help="Permissive reproducibility",
            )

            ap_.add_argument(
                "--reproducibility-level",
                dest="reproducibility_level",
                default=ReproducibilityLevel.Metadata,
                choices=range(
                    min(ReproducibilityLevel).value, max(ReproducibilityLevel).value + 1
                ),
                type=int,
                help="Max reproducibility level to be tried",
            )

        if command in (WfExS_Commands.Stage, WfExS_Commands.Execute):
            ap_.add_argument(
                "--paranoid",
                dest="secure",
                action="store_true",
                default=False,
                help="Force secured working directory",
            )

    if preStageParams or exportParams or command == WfExS_Commands.ReStage:
        ap_.add_argument(
            "-Z",
            "--creds-config",
            dest="securityContextsConfigFilename",
            type=PathArgType,
            help="Configuration file, describing security contexts, which hold credentials and similar",
        )

    if exportParams:
        ap_.add_argument(
            "-E",
            "--exports-config",
            dest="exportsConfigFilename",
            type=PathArgType,
            help="Configuration file, describing exports which can be done",
        )

    if (
        preStageParams and command not in (WfExS_Commands.ConfigValidate,)
    ) or command == WfExS_Commands.ReStage:
        ap_.add_argument(
            "-n",
            "--nickname-prefix",
            dest="nickname_prefix",
            help="Nickname prefix to be used on staged workdir creation",
        )

    if (
        (preStageParams and command not in (WfExS_Commands.ConfigValidate,))
        or crateParams
        or exportParams
        or command in (WfExS_Commands.ReStage, WfExS_Commands.ExportResults)
    ):
        ap_.add_argument(
            "--orcid",
            dest="orcids",
            action="append",
            default=[],
            help="ORCID(s) of the person(s) staging, running or exporting the workflow scenario",
        )

    if (
        command
        in (
            WfExS_Commands.Stage,
            WfExS_Commands.ReStage,
            WfExS_Commands.Import,
            WfExS_Commands.Execute,
        )
        or exportParams
    ):
        ap_.add_argument(
            "--public-key-file",
            dest="public_key_files",
            action="append",
            type=PathArgType,
            default=[],
            help="This parameter switches on secure processing. Path to the public key(s) to be used to encrypt the working directory",
        )

    if (
        command
        in (
            WfExS_Commands.Stage,
            WfExS_Commands.StagedWorkDir,
            WfExS_Commands.Import,
            WfExS_Commands.Execute,
        )
        or postStageParams
        or exportParams
    ):
        # if command is not WfExS_Commands.ConfigValidate and (
        #    preStageParams or postStageParams or exportParams
        # ):
        # When it is a one shot, like Execute,
        # the --private-key-file parameter is not needed
        priv_opts = ap_.add_argument_group(
            "secure workdir arguments",
            "Private key and passphrase to access secured working directories",
        )
        priv_opts.add_argument(
            "--private-key-file",
            dest="private_key_file",
            type=PathArgType,
            help="This parameter passes the name of the file containing the private key needed to unlock an encrypted working directory.",
        )
        priv_opts.add_argument(
            "--private-key-passphrase-envvar",
            dest="private_key_passphrase_envvar",
            default="",
            help="This parameter passes the name of the environment variable containing the passphrase needed to decrypt the private key needed to unlock an encrypted working directory.",
        )

    if postStageParams:
        ap_.add_argument(
            "-J",
            "--staged-job-dir",
            dest="workflowWorkingDirectory",
            required=True,
            help="Already staged job directory",
        )

    if crateParams:
        mat_opts = ap_.add_argument_group(
            "ro-crate-payload", "What to include in the RO-Crate"
        )
        for key_mat, val_mat in WF.ExportROCrate2Payloads.items():
            if key_mat:
                mat_opts.add_argument(
                    "--" + key_mat,
                    dest="doMaterializedROCrate",
                    action="append_const",
                    default=[],
                    const=val_mat,
                    help=f"Should the RO-Crate contain a {key_mat} copy (of everything)?",
                )
        mat_opts.add_argument(
            "--licence",
            dest="licences",
            action="append",
            default=[],
            help="Licence(s) to attach to the generated RO-Crate",
        )

        mat_opts.add_argument(
            "--crate-pid",
            dest="crate_pid",
            help="Permanent identifier to embed within the generated RO-Crate metadata, like a pre-generated DOI",
        )

    if (exportParams or command == WfExS_Commands.ExportResults) and not crateParams:
        ap_.add_argument(
            "--licence",
            dest="licences",
            action="append",
            default=[],
            help="Licence(s) to attach to the exported contents",
        )

    return ap_


def processListFetchersCommand(wfBackend: "WfExSBackend", logLevel: "int") -> "int":
    fetchable_schemes = wfBackend.describeFetchableSchemes()
    print(f"{len(fetchable_schemes)} supported fetchers")
    for fetchable_scheme, description, priority in fetchable_schemes:
        print(f"\t{fetchable_scheme} => {description} (priority {priority})")

    return 0


def processListPushersCommand(wfBackend: "WfExSBackend", logLevel: "int") -> "int":
    export_plugin_names = wfBackend.listExportPluginNames()
    print(f"{len(export_plugin_names)} supported export plugins")
    for export_plugin_name in export_plugin_names:
        print(f"\t{export_plugin_name}")
    return 0


def processListContainerFactoriesCommand(
    wfBackend: "WfExSBackend", logLevel: "int"
) -> "int":
    container_types = wfBackend.listImplementedContainerTypes()
    print(f"{len(container_types)} supported container factories")
    for container_type in container_types:
        print(f"\t{container_type.value}")

    return 0


def processListWorkflowEnginesCommand(
    wfBackend: "WfExSBackend", logLevel: "int"
) -> "int":
    print(f"{len(wfBackend.WORKFLOW_ENGINES)} supported workflow engines")
    for workflow_type in wfBackend.WORKFLOW_ENGINES:
        print(
            f"\t{workflow_type.shortname} => {workflow_type.name} (priority {workflow_type.priority})"
        )

    return 0


def processListLicencesCommand(wfBackend: "WfExSBackend", logLevel: "int") -> "int":
    licence_matcher = LicenceMatcherSingleton()
    documented_licences = licence_matcher.describeDocumentedLicences()
    print(f"{len(documented_licences)} documented licences")
    for lic in documented_licences:
        print(f"\t{lic.short} => {lic.description}")
        print("\t\tMore details at:")
        for lic_uri in lic.uris:
            print(f"\t\t-> {lic_uri}")

    return 0


def processCacheCommand(
    wfBackend: "WfExSBackend", args: "argparse.Namespace", logLevel: "int"
) -> "int":
    """
    This method processes the cache subcommands, and returns the retval
    to be used with sys.exit
    """
    print(f"\t- Subcommand {args.cache_command} {args.cache_type}")

    cH, cPath = wfBackend.getCacheHandler(args.cache_type)
    assert cPath is not None
    retval = 0
    if args.cache_command in (WfExS_Cache_Commands.List, WfExS_Cache_Commands.Status):
        the_path: "Union[AbsPath, str, URIType]"
        if logLevel <= logging.INFO:
            contentsI = sorted(
                cH.list(
                    *args.cache_command_args,
                    destdir=cPath,
                    acceptGlob=args.filesAsGlobs,
                    cascade=args.doCacheCascade,
                ),
                key=lambda x: x[1]["stamp"],
            )
            for entryI in contentsI:
                if args.cache_command == WfExS_Cache_Commands.List:
                    if "resolves_to" in entryI[1]:
                        the_path = (
                            " ".join(entryI[1]["resolves_to"])
                            if isinstance(entryI[1]["resolves_to"], list)
                            else cast("URIType", entryI[1]["resolves_to"])
                        )
                        the_type = "uri"
                    elif "path" in entryI[1]:
                        the_path = entryI[1]["path"].get("absolute", "????")
                        the_type = "path"
                    else:
                        the_path = "(not recorded)"
                        the_type = "???"

                    if "clonable" in entryI[1]:
                        clonable = entryI[1]["clonable"]
                    else:
                        clonable = True
                    the_clonable = "yes" if clonable else "no"

                    print(
                        f"({entryI[1]['stamp']}) {entryI[0].uri} => {the_type} {the_path} (clonable: {the_clonable})"
                    )
                else:
                    json.dump(
                        entryI[1],
                        sys.stdout,
                        cls=DatetimeEncoder,
                        indent=4,
                        sort_keys=True,
                    )
                    print()
        else:
            contentsD = sorted(
                cH.list(
                    *args.cache_command_args,
                    destdir=cPath,
                    acceptGlob=args.filesAsGlobs,
                    cascade=args.doCacheCascade,
                ),
                key=lambda x: x[0].uri,
            )
            for entryD in contentsD:
                if args.cache_command == WfExS_Cache_Commands.List:
                    if "resolves_to" in entryD[1]:
                        the_path = (
                            " ".join(entryD[1]["resolves_to"])
                            if isinstance(entryD[1]["resolves_to"], list)
                            else cast("URIType", entryD[1]["resolves_to"])
                        )
                        the_type = "uri"
                    elif "path" in entryD[1]:
                        the_path = entryD[1]["path"].get("absolute", "????")
                        the_type = "path"
                    else:
                        the_path = "(not recorded)"
                        the_type = "???"

                    if "clonable" in entryD[1]:
                        clonable = entryD[1]["clonable"]
                    else:
                        clonable = True
                    the_clonable = "yes" if clonable else "no"

                    print(
                        f"({entryD[1]['stamp']}) {entryD[0].uri} => {the_type} {the_path} (clonable: {the_clonable})"
                    )
                else:
                    print(entryD[0])

    elif args.cache_command == WfExS_Cache_Commands.Remove:
        print(
            "\n".join(
                map(
                    lambda x: "\t".join([x[0].uri, x[1].as_posix()]),
                    cH.remove(
                        *args.cache_command_args,
                        destdir=cPath,
                        acceptGlob=args.filesAsGlobs,
                        doRemoveFiles=args.doCacheRecursively,
                        cascade=args.doCacheCascade,
                    ),
                )
            )
        )
    elif args.cache_command == WfExS_Cache_Commands.Inject:
        if len(args.cache_command_args) in (2, 3):
            injected_uri = args.cache_command_args[0]
            finalCachedFilename = args.cache_command_args[1]
            if len(args.cache_command_args) == 3:
                clonable = args.cache_command_args[2] != "false"
            else:
                # If we have injected anything by hand, most probably
                # we do not want it cloned in the working directories.
                clonable = False
            # # First, remove old occurrence
            # cH.remove(cPath, injected_uri)
            # Then, inject new occurrence
            cH.inject(
                injected_uri,
                destdir=cPath,
                finalCachedFilename=finalCachedFilename,
                clonable=clonable,
            )
        else:
            print(
                f"ERROR: subcommand {args.cache_command} takes two required positional parameters: the URI to be injected, and the path to the local content to be associated to that URI. A third optional parameter, which is either 'true' or 'false', tells whether it is allowed to clone the injected content into the working directories.",
                file=sys.stderr,
            )
            retval = 1
    elif args.cache_command == WfExS_Cache_Commands.Validate:
        for metaUri, validated, metaStructure in cH.validate(
            *args.cache_command_args,
            destdir=cPath,
            acceptGlob=args.filesAsGlobs,
            cascade=args.doCacheCascade,
        ):
            print(f"\t- {metaUri.uri} {validated}")
    #    pass
    elif args.cache_command == WfExS_Cache_Commands.Fetch:
        if len(args.cache_command_args) >= 1 and len(args.cache_command_args) <= 4:
            uri_to_fetch = args.cache_command_args[0]
            vault = SecurityContextVault()
            if len(args.cache_command_args) >= 3:
                secContextFilename = args.cache_command_args[1]
                secContextName = args.cache_command_args[2]

                if os.path.exists(secContextFilename):
                    try:
                        vault = SecurityContextVault(secContextFilename)
                    except:
                        logging.exception(
                            f"ERROR: security context file {secContextFilename} is corrupted"
                        )
                        retval = 1
                else:
                    print(
                        f"ERROR: security context file {secContextFilename} does not exist",
                        file=sys.stderr,
                    )
                    retval = 1

                if retval == 0:
                    # TODO: Revise and Fix this
                    secContext = vault.getContext(uri_to_fetch, secContextName)
                    if secContext is None:
                        print(
                            f"ERROR: security context file {secContextFilename} does not contain the security context {secContextName}",
                            file=sys.stderr,
                        )
                        retval = 1

            if len(args.cache_command_args) in (2, 4):
                default_clonable = args.cache_command_args[-1] != "false"
            else:
                # If we are fetching anything by hand, most probably
                # we do not mind it cloned in the working directories.
                default_clonable = True

            if retval == 0:
                cached_content = wfBackend.cacheFetch(
                    uri_to_fetch,
                    args.cache_type,
                    offline=False,
                    vault=vault,
                    sec_context_name=secContextName,
                    default_clonable=default_clonable,
                )
                print(
                    f"{cached_content.kind}\t{cached_content.path}\t{cached_content.licences}\t{cached_content.metadata_array}\t{cached_content.clonable}"
                )
        else:
            print(
                f"ERROR: subcommand {args.cache_command} takes either one or three positional parameters: the URI to be fetched, the path to a security context file and the security context to be used for the fetch operation. An optional last parameter tells whether the fetched content should be allowed to be cloned in working directories",
                file=sys.stderr,
            )
            retval = 1

    return retval


def processStagedWorkdirCommand(
    wB: "WfExSBackend", args: "argparse.Namespace", loglevel: "int"
) -> "int":
    """
    This method processes the cache subcommands, and returns the retval
    to be used with sys.exit
    """
    print(f"\t- Subcommand {args.staged_workdir_command}")

    retval = 0
    # This is needed to be sure the encfs instance is unmounted
    # if args.staged_workdir_command != WfExS_Staged_WorkDir_Commands.Mount:
    #    atexit.register(wfInstance.cleanup)
    if (
        hasattr(args, "private_key_passphrase_envvar")
        and args.private_key_passphrase_envvar is not None
    ):
        private_key_passphrase = os.environ.get(args.private_key_passphrase_envvar, "")
    else:
        private_key_passphrase = ""

    # Getting the list of licences (in case they are needed)
    op_licences: "Sequence[str]"
    if hasattr(args, "licences") and args.licences is not None:
        op_licences = args.licences
    else:
        op_licences = []

    # Getting the list of ORCIDs (in case they are needed)
    if hasattr(args, "orcids") and args.orcids is not None:
        op_orcids = args.orcids
    else:
        op_orcids = []

    if (
        hasattr(args, "crate_pid")
        and args.crate_pid is not None
        and len(args.crate_pid) > 0
    ):
        op_crate_pid = args.crate_pid
    else:
        op_crate_pid = None

    if args.staged_workdir_command == WfExS_Staged_WorkDir_Commands.Mount:
        if len(args.staged_workdir_command_args) > 0:
            for (
                instance_id,
                nickname,
                creation,
                wfSetup,
                wfInstance,
            ) in wB.listStagedWorkflows(
                *args.staged_workdir_command_args,
                acceptGlob=args.filesAsGlobs,
                doCleanup=False,
                private_key_filename=args.private_key_file,
                private_key_passphrase=private_key_passphrase,
            ):
                if wfSetup is not None:
                    print(f"Mounted {instance_id} ({nickname}) at {wfSetup.work_dir}")
    elif args.staged_workdir_command == WfExS_Staged_WorkDir_Commands.List:
        contents = sorted(
            wB.listStagedWorkflows(
                *args.staged_workdir_command_args,
                private_key_filename=args.private_key_file,
                private_key_passphrase=private_key_passphrase,
                acceptGlob=args.filesAsGlobs,
            ),
            key=lambda x: x[2],
        )
        print(
            "\t".join(
                (
                    "# Instance id",
                    "nickname",
                    "creation date",
                    "Workflow type",
                    "Container type",
                    "Workflow PID",
                    "Encrypted?",
                    "Staged (not damaged)?",
                )
            )
        )
        for instance_id, nickname, creation, wfSetup, wfInstance in contents:
            is_encrypted: "Union[bool, str]"
            wfPID = None
            engineName = None
            containerType = None
            if wfSetup is None:
                is_damaged = True
                is_encrypted = "(unknown)"
            else:
                is_damaged = wfSetup.is_damaged
                is_encrypted = wfSetup.is_encrypted
            if wfInstance is not None:
                # As we can need additional data, let's ask it
                wfInstance.unmarshallStage(
                    offline=True, fail_ok=True, do_full_setup=False
                )

                wfPID = wfInstance.getPID()
                if wfInstance.engineDesc is not None:
                    engineName = wfInstance.engineDesc.engineName
                if wfInstance.engine is not None:
                    containerType = wfInstance.engine.getConfiguredContainerType()
            print(
                "\t".join(
                    (
                        instance_id,
                        nickname,
                        creation.isoformat(),
                        "(unknown)" if engineName is None else engineName,
                        "(unknown)" if containerType is None else containerType.value,
                        "(unknown)" if wfPID is None else wfPID,
                        str(is_encrypted),
                        str(not is_damaged),
                    )
                )
            )

    elif args.staged_workdir_command == WfExS_Staged_WorkDir_Commands.Remove:
        print(
            "\n".join(
                map(
                    lambda x: "Removed: " + "\t".join(x),
                    wB.removeStagedWorkflows(
                        *args.staged_workdir_command_args,
                        private_key_filename=args.private_key_file,
                        private_key_passphrase=private_key_passphrase,
                        acceptGlob=args.filesAsGlobs,
                    ),
                )
            )
        )

    elif args.staged_workdir_command == WfExS_Staged_WorkDir_Commands.Shell:
        retval = wB.shellFirstStagedWorkflow(
            *args.staged_workdir_command_args,
            private_key_filename=args.private_key_file,
            private_key_passphrase=private_key_passphrase,
            acceptGlob=args.filesAsGlobs,
        )
    elif args.staged_workdir_command == WfExS_Staged_WorkDir_Commands.OfflineExecute:
        if len(args.staged_workdir_command_args) > 0:
            for (
                instance_id,
                nickname,
                creation,
                wfSetup,
                wfInstance,
            ) in wB.listStagedWorkflows(
                *args.staged_workdir_command_args,
                acceptGlob=args.filesAsGlobs,
                doCleanup=False,
                private_key_filename=args.private_key_file,
                private_key_passphrase=private_key_passphrase,
            ):
                is_damaged = True if wfSetup is None else wfSetup.is_damaged
                if not is_damaged and (wfInstance is not None):
                    try:
                        assert wfSetup is not None
                        print(
                            "\t- Instance {} (nickname '{}') is being run\n".format(
                                wfSetup.instance_id,
                                wfSetup.nickname,
                            )
                        )
                        staged_exec = wfInstance.executeWorkflow(offline=True)
                        print(
                            "\t- Instance {} (nickname '{}') exit value: {} ({})\n".format(
                                wfSetup.instance_id,
                                wfSetup.nickname,
                                staged_exec.exitVal,
                                "FAILED" if staged_exec.exitVal != 0 else "DONE",
                            )
                        )
                    except Exception as e:
                        logging.exception(
                            f"Error while executing {instance_id} ({nickname})"
                        )
                    finally:
                        wfInstance.cleanup()
    elif (
        args.staged_workdir_command == WfExS_Staged_WorkDir_Commands.OfflineQueueExecute
    ):
        if len(args.staged_workdir_command_args) > 0:
            for (
                instance_id,
                nickname,
                creation,
                wfSetup,
                wfInstance,
            ) in wB.listStagedWorkflows(
                *args.staged_workdir_command_args,
                acceptGlob=args.filesAsGlobs,
                doCleanup=False,
                private_key_filename=args.private_key_file,
                private_key_passphrase=private_key_passphrase,
            ):
                is_damaged = True if wfSetup is None else wfSetup.is_damaged
                if not is_damaged and (wfInstance is not None):
                    try:
                        assert wfSetup is not None
                        print(
                            "\t- Instance {} (nickname '{}') is being run\n".format(
                                wfSetup.instance_id,
                                wfSetup.nickname,
                            )
                        )
                        job_id = wfInstance.queueExecution(offline=True)
                        print(
                            f"\t- Instance {wfSetup.instance_id} (nickname '{wfSetup.nickname}') job id {job_id}"
                        )
                    except Exception as e:
                        logging.exception(
                            f"Error while queueing {instance_id} ({nickname})"
                        )
                    finally:
                        wfInstance.cleanup()
    elif args.staged_workdir_command == WfExS_Staged_WorkDir_Commands.Status:
        if len(args.staged_workdir_command_args) > 0:
            for (
                instance_id,
                nickname,
                creation,
                wfSetup,
                mStatus,
            ) in wB.statusStagedWorkflows(
                *args.staged_workdir_command_args,
                private_key_filename=args.private_key_file,
                private_key_passphrase=private_key_passphrase,
                acceptGlob=args.filesAsGlobs,
            ):
                is_damaged = True if wfSetup is None else wfSetup.is_damaged
                if wfSetup is None:
                    is_damaged = True
                    is_encrypted = "(unknown)"
                else:
                    is_damaged = wfSetup.is_damaged
                    is_encrypted = wfSetup.is_encrypted

                print(
                    f"""=> Instance {instance_id} ({nickname})
* Id: {instance_id}
* Nickname: {nickname}
* Created: {creation.isoformat()}
* Secure (encrypted)? {is_encrypted}
{repr(mStatus)}
* Is damaged? {is_damaged}
"""
                )
    elif args.staged_workdir_command in (
        WfExS_Staged_WorkDir_Commands.CreateStagedROCrate,
        WfExS_Staged_WorkDir_Commands.CreateProvenanceROCrate,
    ):
        if len(args.staged_workdir_command_args) == 2:
            for (
                instance_id,
                nickname,
                creation,
                wfSetup,
                wfInstance,
            ) in wB.listStagedWorkflows(
                args.staged_workdir_command_args[0],
                acceptGlob=args.filesAsGlobs,
                doCleanup=False,
                private_key_filename=args.private_key_file,
                private_key_passphrase=private_key_passphrase,
            ):
                is_damaged = True if wfSetup is None else wfSetup.is_damaged
                if not is_damaged and (wfInstance is not None):
                    assert wfSetup is not None
                    try:
                        if args.doMaterializedROCrate:
                            doMaterializedROCrate = functools.reduce(
                                lambda a, b: a | b, args.doMaterializedROCrate
                            )
                        else:
                            doMaterializedROCrate = WF.ExportROCrate2Payloads[""]

                        resolved_orcids = wfInstance._curate_orcid_list(op_orcids)
                        if (
                            args.staged_workdir_command
                            == WfExS_Staged_WorkDir_Commands.CreateStagedROCrate
                        ):
                            print(
                                "\t- Generating prospective RO-Crate provenance from instance {} (nickname '{}')\n".format(
                                    wfSetup.instance_id,
                                    wfSetup.nickname,
                                )
                            )
                            expanded_licences = wB.curate_licence_list(op_licences)
                            wfInstance.createStageResearchObject(
                                filename=args.staged_workdir_command_args[1],
                                payloads=doMaterializedROCrate,
                                licences=expanded_licences,
                                resolved_orcids=resolved_orcids,
                                crate_pid=op_crate_pid,
                            )
                        else:
                            mStatus = wfInstance.getMarshallingStatus(reread_stats=True)
                            if isinstance(mStatus.execution, datetime.datetime):
                                print(
                                    "\t- Generating retrospective provenance RO-Crate from instance {} (nickname '{}')\n".format(
                                        wfSetup.instance_id,
                                        wfSetup.nickname,
                                    )
                                )
                                expanded_licences = wB.curate_licence_list(op_licences)
                                wfInstance.createResultsResearchObject(
                                    filename=args.staged_workdir_command_args[1],
                                    payloads=doMaterializedROCrate,
                                    licences=expanded_licences,
                                    resolved_orcids=resolved_orcids,
                                    crate_pid=op_crate_pid,
                                )
                            else:
                                print(
                                    f"ERROR: workflow was never executed at staged workdir {instance_id} ({nickname})",
                                    file=sys.stderr,
                                )
                                retval = 1
                    except Exception as e:
                        logging.exception(
                            f"Error while creating RO-Crate for {instance_id} ({nickname})"
                        )
                    finally:
                        wfInstance.cleanup()
                else:
                    print(
                        f"ERROR: staged workdir {instance_id} ({nickname}) is damaged",
                        file=sys.stderr,
                    )
                    retval = 1
        else:
            print(
                f"ERROR: subcommand {args.staged_workdir_command} takes two positional parameters: the staged workdir name or id and the path where to store the RO-Crate",
                file=sys.stderr,
            )
            retval = 1

    # Thi
    return retval


def processExportCommand(
    wfInstance: "WF", args: "argparse.Namespace", loglevel: "int"
) -> "int":
    """
    This method processes the export subcommands, and returns the retval
    to be used with sys.exit
    """
    print(f"\t- Subcommand {args.export_contents_command}")

    retval = 0
    if args.export_contents_command == WfExS_Export_Commands.List:
        for mExport in wfInstance.listMaterializedExportActions():
            print(f"{mExport}")
    elif args.export_contents_command == WfExS_Export_Commands.Run:
        expval = wfInstance.exportResultsFromFiles(
            args.exportsConfigFilename,
            args.securityContextsConfigFilename,
            action_ids=cast(
                "Sequence[SymbolicName]", args.export_contents_command_args
            ),
        )
        print(f"{expval}")

    return retval


def get_wfexs_argparse() -> "argparse.ArgumentParser":
    retval, _ = _get_wfexs_argparse_internal(docgen=True)
    return retval


def _get_wfexs_argparse_internal(
    docgen: "bool",
) -> "Tuple[argparse.ArgumentParser, str]":
    verstr = get_WfExS_version_str()

    defaultLocalConfigFilename = os.environ.get("WFEXS_CONFIG_FILE")
    if defaultLocalConfigFilename is None:
        defaultLocalConfigFilename = os.path.join(
            os.getcwd(), DEFAULT_LOCAL_CONFIG_RELNAME
        )
    elif not os.path.isabs(defaultLocalConfigFilename):
        defaultLocalConfigFilename = os.path.join(
            os.getcwd(), defaultLocalConfigFilename
        )

    rawpre = "" if docgen else "raw|"

    ap = argparse.ArgumentParser(
        description="WfExS (workflow execution service) backend " + verstr,
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    ap.add_argument(
        "--log-file",
        dest="logFilename",
        help="Store messages in a file instead of using standard error and standard output",
    )
    ap.add_argument(
        "-q",
        "--quiet",
        dest="logLevel",
        action="store_const",
        const=logging.WARNING,
        help="Only show engine warnings and errors",
    )
    ap.add_argument(
        "-v",
        "--verbose",
        dest="logLevel",
        action="store_const",
        const=logging.INFO,
        help="Show verbose (informational) messages",
    )
    ap.add_argument(
        "-d",
        "--debug",
        dest="logLevel",
        action="store_const",
        const=logging.DEBUG,
        help="Show debug messages (use with care, as it can disclose passphrases and passwords)",
    )
    ap.add_argument(
        "-L",
        "--local-config",
        dest="localConfigFilename",
        default=defaultLocalConfigFilename,
        help="Local installation configuration file (can also be set up through WFEXS_CONFIG_FILE environment variable)",
    )
    ap.add_argument(
        "--cache-dir",
        dest="cacheDir",
        help="Caching directory",
    )

    ap.add_argument(
        "-V", "--version", action="version", version="%(prog)s version " + verstr
    )
    ap.add_argument(
        "--full-help",
        dest="fullHelp",
        action="store_true",
        default=False,
        help="It returns full help",
    )

    sp = ap.add_subparsers(
        dest="command",
        title="commands",
        description="Command to run. It must be one of these",
    )

    ap_i = genParserSub(sp, WfExS_Commands.Init)

    ap_psd = genParserSub(sp, WfExS_Commands.PopulateSideCaches)

    ap_c = genParserSub(sp, WfExS_Commands.Cache)
    ap_c.add_argument(
        "cache_command",
        help=f"{rawpre}Cache command to perform\n\n"
        + "\n".join(
            map(lambda c: f"{c.value:<12}{c.description}", WfExS_Cache_Commands)  # type: ignore[attr-defined]
        ),
        type=cast("Callable_WfExS_Cache_Commands", WfExS_Cache_Commands.argtype),
        choices=WfExS_Cache_Commands,
    )
    ap_c.add_argument(
        "-r",
        dest="doCacheRecursively",
        help="Try doing the operation recursively (i.e. both metadata and data)",
        action="store_true",
        default=False,
    )
    ap_c.add_argument(
        "--cascade",
        dest="doCacheCascade",
        help="Try doing the operation in cascade (including the URIs which resolve to other URIs)",
        action="store_true",
        default=False,
    )
    ap_c.add_argument(
        "-g",
        "--glob",
        dest="filesAsGlobs",
        help="Given cache element names are globs",
        action="store_true",
        default=False,
    )
    ap_c.add_argument(
        "cache_type",
        help=f"{rawpre}Cache type to perform the cache command\n\n"
        + "\n".join(map(lambda c: f"{c.value:<12}{c.description}", WfExS_CacheType)),  # type: ignore[attr-defined]
        type=cast("Callable_WfExS_CacheType", WfExS_CacheType.argtype),
        choices=WfExS_CacheType,
    )
    ap_c.add_argument(
        "cache_command_args", help="Optional cache element names", nargs="*"
    )

    ap_w = genParserSub(sp, WfExS_Commands.StagedWorkDir, crateParams=True)
    ap_w.add_argument(
        "staged_workdir_command",
        help=f"{rawpre}Staged working directory command to perform\n\n"
        + "\n".join(
            map(
                lambda c: f"{c.value:<16}{c.description}", WfExS_Staged_WorkDir_Commands  # type: ignore[attr-defined]
            )
        ),
        type=cast(
            "Callable_WfExS_Staged_WorkDir_Commands",
            WfExS_Staged_WorkDir_Commands.argtype,
        ),
        choices=WfExS_Staged_WorkDir_Commands,
    )
    ap_w.add_argument(
        "staged_workdir_command_args",
        help="Optional staged working directory element names",
        nargs="*",
    )
    ap_w.add_argument(
        "-g",
        "--glob",
        dest="filesAsGlobs",
        help="Given staged workflow names are globs",
        action="store_true",
        default=False,
    )

    ap_expt = genParserSub(
        sp, WfExS_Commands.Export, postStageParams=True, exportParams=True
    )
    ap_expt.add_argument(
        "export_contents_command",
        help=f"{rawpre}Export operations from staged working directory to perform\n\n"
        + "\n".join(
            map(lambda c: f"{c.value:<16}{c.description}", WfExS_Export_Commands)  # type: ignore[attr-defined]
        ),
        type=cast("Callable_WfExS_Export_Commands", WfExS_Export_Commands.argtype),
        choices=WfExS_Export_Commands,
    )
    ap_expt.add_argument(
        "export_contents_command_args", help="Optional export names", nargs="*"
    )

    ap_lf = genParserSub(sp, WfExS_Commands.ListFetchers)
    ap_lp = genParserSub(sp, WfExS_Commands.ListPushers)
    ap_lc = genParserSub(sp, WfExS_Commands.ListContainerFactories)
    ap_lw = genParserSub(sp, WfExS_Commands.ListWorkflowEngines)
    ap_ll = genParserSub(sp, WfExS_Commands.ListLicences)
    ap_cv = genParserSub(sp, WfExS_Commands.ConfigValidate, preStageParams=True)

    ap_s = genParserSub(sp, WfExS_Commands.Stage, preStageParams=True)

    ap_r_s = genParserSub(
        sp, WfExS_Commands.ReStage, preStageParams=True, postStageParams=True
    )

    ap_imp = genParserSub(sp, WfExS_Commands.Import, preStageParams=True)

    ap_m = genParserSub(sp, WfExS_Commands.MountWorkDir, postStageParams=True)

    ap_es = genParserSub(
        sp, WfExS_Commands.ExportStage, postStageParams=True, crateParams=True
    )

    ap_oe = genParserSub(sp, WfExS_Commands.OfflineExecute, postStageParams=True)

    ap_e = genParserSub(
        sp,
        WfExS_Commands.Execute,
        preStageParams=True,
        crateParams=True,
        exportParams=True,
    )

    ap_er = genParserSub(sp, WfExS_Commands.ExportResults, postStageParams=True)

    ap_ec = genParserSub(
        sp, WfExS_Commands.ExportCrate, postStageParams=True, crateParams=True
    )

    return ap, defaultLocalConfigFilename


def main() -> None:
    ap, defaultLocalConfigFilename = _get_wfexs_argparse_internal(docgen=False)

    args = ap.parse_args()

    fullHelp = args.fullHelp
    if args.command is None:
        fullHelp = True

    if fullHelp:
        print(ap.format_help())

        # retrieve subparsers from parser
        subparsers_actions = [
            action
            for action in ap._actions
            if isinstance(action, argparse._SubParsersAction)
        ]
        # there will probably only be one subparser_action,
        # but better safe than sorry
        for subparsers_action in subparsers_actions:
            # get all subparsers and print help
            for choice, subparser in subparsers_action.choices.items():
                print("Subparser '{}'".format(choice))
                print(subparser.format_help())

        sys.exit(0)

    command = WfExS_Commands(args.command)

    # Setting up the log
    logLevel = logging.INFO
    if args.logLevel:
        logLevel = args.logLevel

    if logLevel < logging.INFO:
        logFormat = DEBUG_LOGGING_FORMAT
    else:
        logFormat = LOGGING_FORMAT

    loggingConf: "BasicLoggingConfigDict" = {"format": logFormat, "level": logLevel}

    if args.logFilename is not None:
        loggingConf["filename"] = args.logFilename
    #    loggingConf['encoding'] = 'utf-8'

    logging.basicConfig(**loggingConf)
    if logLevel >= logging.INFO:
        logging.getLogger("crypt4gh").setLevel(
            logLevel if logLevel > logging.WARNING else logging.WARNING
        )

    # Very early command
    if command == WfExS_Commands.PopulateSideCaches:
        populate_side_caches()
        sys.exit(0)

    # First, try loading the configuration file
    localConfigFilename = (
        pathlib.Path(args.localConfigFilename) if args.localConfigFilename else None
    )
    if localConfigFilename and localConfigFilename.exists():
        with localConfigFilename.open(mode="r", encoding="utf-8") as cf:
            local_config = yaml.safe_load(cf)
    else:
        local_config = {}
        if localConfigFilename and not localConfigFilename.exists():
            print(
                "[WARNING] Configuration file {} does not exist".format(
                    localConfigFilename
                ),
                file=sys.stderr,
            )

    # A filename is needed later, in order to initialize installation keys
    if not localConfigFilename:
        config_directory = None
        config_relname = os.path.basename(defaultLocalConfigFilename)
    else:
        # Hints for the the default path for the Crypt4GH keys
        config_directory = localConfigFilename.parent
        config_relname = localConfigFilename.name

    if args.cacheDir:
        local_config["cacheDir"] = args.cacheDir

    # In any case, assuring the cache directory does exist
    cacheDir = local_config.get("cacheDir")
    if cacheDir:
        if not os.path.isabs(cacheDir) and config_directory is not None:
            cacheDir = os.path.normpath(os.path.join(config_directory, cacheDir))
        os.makedirs(cacheDir, exist_ok=True)
    else:
        cacheDir = tempfile.mkdtemp(prefix="wfexs", suffix="tmpcache")
        local_config["cacheDir"] = cacheDir
        # Assuring this temporal directory is removed at the end
        atexit.register(shutil.rmtree, cacheDir, True)
        print(
            f"[WARNING] Cache directory not defined. Created a temporary one at {cacheDir}",
            file=sys.stderr,
        )

    # Initialize (and create config file)
    if command in (
        WfExS_Commands.Init,
        WfExS_Commands.Cache,
        WfExS_Commands.ListFetchers,
        WfExS_Commands.ListPushers,
        WfExS_Commands.Stage,
        WfExS_Commands.ReStage,
        WfExS_Commands.Import,
        WfExS_Commands.Execute,
    ):
        updated_config, local_config, config_directory = WfExSBackend.bootstrap_config(
            local_config, config_directory, key_prefix=config_relname
        )
        # This is needed because config directory could have been empty
        localConfigFilename = config_directory / config_relname

        # Last, should config be saved back?
        if updated_config or not localConfigFilename.exists():
            print("* Storing updated configuration at {}".format(localConfigFilename))
            with localConfigFilename.open(mode="w", encoding="utf-8") as cf:
                yaml.dump(local_config, cf, Dumper=YAMLDumper)

        # We are finishing here!
        if command == WfExS_Commands.Init:
            sys.exit(0)

    # Is the work already staged?
    wfBackend = WfExSBackend(local_config, config_directory)

    # Cache handling commands
    print('* Command "{}".'.format(command), file=sys.stderr)
    if command == WfExS_Commands.ListFetchers:
        sys.exit(processListFetchersCommand(wfBackend, logLevel))

    if command == WfExS_Commands.ListPushers:
        sys.exit(processListPushersCommand(wfBackend, logLevel))

    if command == WfExS_Commands.ListContainerFactories:
        sys.exit(processListContainerFactoriesCommand(wfBackend, logLevel))

    if command == WfExS_Commands.ListWorkflowEngines:
        sys.exit(processListWorkflowEnginesCommand(wfBackend, logLevel))

    if command == WfExS_Commands.ListLicences:
        sys.exit(processListLicencesCommand(wfBackend, logLevel))

    if command == WfExS_Commands.Cache:
        sys.exit(processCacheCommand(wfBackend, args, logLevel))

    # Staged working directory handling commands
    if command == WfExS_Commands.StagedWorkDir:
        sys.exit(processStagedWorkdirCommand(wfBackend, args, logLevel))

    # These can be needed in more than one place
    if (
        hasattr(args, "private_key_passphrase_envvar")
        and args.private_key_passphrase_envvar is not None
    ):
        private_key_passphrase = os.environ.get(args.private_key_passphrase_envvar, "")
    else:
        private_key_passphrase = ""

    if hasattr(args, "licences") and args.licences is not None:
        op_licences = args.licences
    else:
        op_licences = []

    if hasattr(args, "orcids") and args.orcids is not None:
        op_orcids = args.orcids
    else:
        op_orcids = []

    if (
        hasattr(args, "crate_pid")
        and args.crate_pid is not None
        and len(args.crate_pid) > 0
    ):
        op_crate_pid = args.crate_pid
    else:
        op_crate_pid = None

    wfInstance = None
    if command in (
        WfExS_Commands.MountWorkDir,
        WfExS_Commands.ReStage,
        WfExS_Commands.Export,
        WfExS_Commands.ExportStage,
        WfExS_Commands.OfflineExecute,
        WfExS_Commands.ExportResults,
        WfExS_Commands.ExportCrate,
    ):
        if os.path.isdir(args.workflowWorkingDirectory):
            wfInstance = wfBackend.fromWorkDir(
                pathlib.Path(args.workflowWorkingDirectory),
                private_key_filename=args.private_key_file,
                private_key_passphrase=private_key_passphrase,
                fail_ok=command != WfExS_Commands.MountWorkDir,
            )
        else:
            for (
                instance_id,
                nickname,
                creation,
                wfSetup,
                wfInstance,
            ) in wfBackend.listStagedWorkflows(
                args.workflowWorkingDirectory,
                private_key_filename=args.private_key_file,
                private_key_passphrase=private_key_passphrase,
                acceptGlob=True,
                doCleanup=False,
            ):
                is_damaged = True if wfSetup is None else wfSetup.is_damaged
                if is_damaged or (wfInstance is None):
                    print(
                        f"[ERROR] Workflow {instance_id} is corrupted! Stopping.",
                        file=sys.stderr,
                    )
                    sys.exit(1)
                break
        if wfInstance is None:
            print(
                f"[ERROR] Workflow {args.workflowWorkingDirectory} could not be found! Stopping.",
                file=sys.stderr,
            )
            sys.exit(1)
    elif command != WfExS_Commands.Import and not args.workflowConfigFilename:
        print("[ERROR] Workflow config was not provided! Stopping.", file=sys.stderr)
        sys.exit(1)
    elif command == WfExS_Commands.ConfigValidate:
        retval = wfBackend.validateConfigFiles(
            args.workflowConfigFilename, args.securityContextsConfigFilename
        )
        sys.exit(retval)
    elif command in (WfExS_Commands.Stage, WfExS_Commands.Execute):
        wfInstance = wfBackend.fromFiles(
            args.workflowConfigFilename,
            args.securityContextsConfigFilename,
            nickname_prefix=args.nickname_prefix,
            public_key_filenames=args.public_key_files,
            private_key_filename=args.private_key_file,
            private_key_passphrase=private_key_passphrase,
            orcids=op_orcids,
            paranoidMode=args.secure,
        )
    elif command == WfExS_Commands.Import:
        wfInstance = wfBackend.fromPreviousROCrate(
            args.workflowROCrateFilenameOrURI,
            securityContextsConfigFilename=args.securityContextsConfigFilename,
            replaced_parameters_filename=args.workflowConfigFilename,
            nickname_prefix=args.nickname_prefix,
            public_key_filenames=args.public_key_files,
            private_key_filename=args.private_key_file,
            private_key_passphrase=private_key_passphrase,
            orcids=op_orcids,
            secure=args.secure,
            reproducibility_level=ReproducibilityLevel(args.reproducibility_level),
            strict_reproducibility_level=args.strict_reproducibility_level,
            retrospective_first=args.retrospective_first,
        )
    else:
        print(
            f"[ERROR] Unimplemented command {command.value}. Stopping.",
            file=sys.stderr,
        )
        sys.exit(1)

    # This is needed to be sure the encfs instance is unmounted
    if command != WfExS_Commands.MountWorkDir:
        atexit.register(wfInstance.cleanup)

    # The special case of re-staging
    if command == WfExS_Commands.ReStage:
        source_wfInstance = wfInstance
        source_wfSetup = source_wfInstance.getStagedSetup()
        print(
            f"\t- Source working directory is {source_wfSetup.work_dir}",
            file=sys.stderr,
        )
        print(
            "\t  Source instance {} (nickname '{}')".format(
                source_wfSetup.instance_id, source_wfSetup.nickname
            )
        )
        sys.stderr.flush()
        wfInstance = wfBackend.fromPreviousInstanceDeclaration(
            source_wfInstance,
            securityContextsConfigFilename=args.securityContextsConfigFilename,
            replaced_parameters_filename=args.workflowConfigFilename,
            nickname_prefix=args.nickname_prefix,
            public_key_filenames=args.public_key_files,
            private_key_filename=args.private_key_file,
            private_key_passphrase=private_key_passphrase,
            orcids=op_orcids,
            secure=args.secure,
            reproducibility_level=ReproducibilityLevel(args.reproducibility_level),
            strict_reproducibility_level=args.strict_reproducibility_level,
        )

        # This is needed to be sure the encfs instance is unmounted
        atexit.register(wfInstance.cleanup)

    wfSetup = wfInstance.getStagedSetup()
    print("\t- Working directory will be {}".format(wfSetup.work_dir), file=sys.stderr)
    sys.stderr.flush()

    # Export staged working directory contents commands
    if command == WfExS_Commands.Export:
        sys.exit(processExportCommand(wfInstance, args, logLevel))

    if command in (
        WfExS_Commands.Stage,
        WfExS_Commands.Import,
        WfExS_Commands.ReStage,
        WfExS_Commands.Execute,
    ):
        print(
            "\t  Instance {} (nickname '{}') (to be used with -J)".format(
                wfSetup.instance_id, wfSetup.nickname
            )
        )
        stagedSetup = wfInstance.stageWorkDir()
        if command != WfExS_Commands.Execute:
            print(
                "\t- Instance {} (nickname '{}') is {} ready".format(
                    wfSetup.instance_id,
                    wfSetup.nickname,
                    "NOT" if stagedSetup.is_damaged else "now",
                )
            )
            sys.exit(
                1
                if stagedSetup.is_damaged
                or not isinstance(wfInstance.stageMarshalled, datetime.datetime)
                else 0
            )

    # Depending on the parameters, it might not exist
    if getattr(args, "doMaterializedROCrate", None):
        doMaterializedROCrate = functools.reduce(
            lambda a, b: a | b, args.doMaterializedROCrate
        )
    else:
        doMaterializedROCrate = WF.ExportROCrate2Payloads[""]

    if command in (WfExS_Commands.ExportStage, WfExS_Commands.Execute):
        resolved_orcids = wfInstance._curate_orcid_list(op_orcids)
        wfInstance.createStageResearchObject(
            payloads=doMaterializedROCrate,
            licences=op_licences,
            resolved_orcids=resolved_orcids,
            crate_pid=op_crate_pid,
        )

    if command in (WfExS_Commands.OfflineExecute, WfExS_Commands.Execute):
        print(
            "\t- Instance {} (nickname '{}') is being run".format(
                wfSetup.instance_id,
                wfSetup.nickname,
            )
        )
        staged_exec = wfInstance.executeWorkflow(
            offline=command == WfExS_Commands.OfflineExecute
        )
        print(
            "\t- Instance {} (nickname '{}') exit value: {} ({})".format(
                wfSetup.instance_id,
                wfSetup.nickname,
                staged_exec.exitVal,
                "FAILED" if staged_exec.exitVal != 0 else "DONE",
            )
        )

    if command in (WfExS_Commands.ExportResults, WfExS_Commands.Execute):
        wfInstance.exportResults(op_licences=op_licences, op_orcids=op_orcids)

    if command in (WfExS_Commands.ExportCrate, WfExS_Commands.Execute):
        wfInstance.createResultsResearchObject(
            payloads=doMaterializedROCrate,
            licences=op_licences,
            crate_pid=op_crate_pid,
        )


if __name__ == "__main__":
    main()
