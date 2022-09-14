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
import atexit
import json
import logging
import os
import sys
import shutil
import tempfile
from typing import (
    cast,
    Callable,
    Sequence,
    Type,
    Union,
)

from typing_extensions import (
    NotRequired,
    TypedDict,
)

import yaml

# We have preference for the C based loader and dumper, but the code
# should fallback to default implementations when C ones are not present
YAMLLoader: Type[Union[yaml.Loader, yaml.CLoader]]
YAMLDumper: Type[Union[yaml.Dumper, yaml.CDumper]]
try:
    from yaml import CLoader as YAMLLoader, CDumper as YAMLDumper
except ImportError:
    from yaml import Loader as YAMLLoader, Dumper as YAMLDumper

from wfexs_backend.wfexs_backend import WfExSBackend
from wfexs_backend.workflow import WF
from wfexs_backend import get_WfExS_version
from wfexs_backend.common import (
    ArgsDefaultWithRawHelpFormatter,
    CacheType as WfExS_CacheType,
    StrDocEnum,
    SymbolicName,
)
from wfexs_backend.utils.misc import DatetimeEncoder

Callable_WfExS_CacheType = Callable[[str], WfExS_CacheType]


class WfExS_Commands(StrDocEnum):
    Init = ("init", "Init local setup")
    Cache = ("cache", "Cache handling subcommands")
    ConfigValidate = (
        "config-validate",
        "Validate the configuration files to be used for staging and execution",
    )
    Stage = (
        "stage",
        "Prepare the staging (working) directory for workflow execution, fetching dependencies and contents",
    )
    MountWorkDir = (
        "mount-workdir",
        "Mount the encrypted staging directory on secure staging scenarios",
    )
    StagedWorkDir = (
        "staged-workdir",
        "Staged working directories handling subcommands",
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


Callable_WfExS_Commands = Callable[[str], WfExS_Commands]


class WfExS_Cache_Commands(StrDocEnum):
    List = ("ls", "List the cache entries")
    Inject = ("inject", "Inject a new entry in the cache")
    Fetch = (
        "fetch",
        "Fetch a new cache entry, giving as input both the URI and optionally both a security context file and a security context name",
    )
    Remove = ("rm", "Remove an entry from the cache")
    Validate = ("validate", "Validate the consistency of the cache")


Callable_WfExS_Cache_Commands = Callable[[str], WfExS_Cache_Commands]


class WfExS_Staged_WorkDir_Commands(StrDocEnum):
    OfflineExecute = (
        "offline-exec",
        "Offline execute the staged instances which match the input pattern",
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


#    Validate = 'validate'
Callable_WfExS_Staged_WorkDir_Commands = Callable[[str], WfExS_Staged_WorkDir_Commands]


class WfExS_Export_Commands(StrDocEnum):
    List = ("ls", "List the public identifiers obtained from previous export actions")
    Run = (
        "run",
        "Run the different export actions, pushing the exported content and gathering the obtained permanent / public identifiers",
    )


Callable_WfExS_Export_Commands = Callable[[str], WfExS_Export_Commands]


class BasicLoggingConfigDict(TypedDict):
    filename: NotRequired[str]
    format: str
    level: int


DEFAULT_LOCAL_CONFIG_RELNAME = "wfexs_config.yml"
LOGGING_FORMAT = "%(asctime)-15s - [%(levelname)s] %(message)s"
DEBUG_LOGGING_FORMAT = (
    "%(asctime)-15s - [%(name)s %(funcName)s %(lineno)d][%(levelname)s] %(message)s"
)


def genParserSub(
    sp: "argparse._SubParsersAction[argparse.ArgumentParser]",
    command: WfExS_Commands,
    preStageParams: bool = False,
    postStageParams: bool = False,
    crateParams: bool = False,
    exportParams: bool = False,
) -> argparse.ArgumentParser:
    ap_ = sp.add_parser(
        command.value,
        formatter_class=ArgsDefaultWithRawHelpFormatter,
        help=command.description,
    )

    if preStageParams:
        ap_.add_argument(
            "-W",
            "--workflow-config",
            dest="workflowConfigFilename",
            required=True,
            help="Configuration file, describing workflow and inputs",
        )

    if preStageParams or exportParams:
        ap_.add_argument(
            "-Z",
            "--creds-config",
            dest="securityContextsConfigFilename",
            help="Configuration file, describing security contexts, which hold credentials and similar",
        )

    if exportParams:
        ap_.add_argument(
            "-E",
            "--exports-config",
            dest="exportsConfigFilename",
            help="Configuration file, describing exports which can be done",
        )

    if preStageParams:
        ap_.add_argument(
            "-n",
            "--nickname-prefix",
            dest="nickname_prefix",
            help="Nickname prefix to be used on staged workdir creation",
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
        ap_.add_argument(
            "--full",
            dest="doMaterializedROCrate",
            action="store_true",
            help="Should the RO-Crate contain a copy of the inputs (and outputs)?",
        )

    return ap_


def processCacheCommand(
    wfBackend: WfExSBackend, args: argparse.Namespace, logLevel: int
) -> int:
    """
    This method processes the cache subcommands, and returns the retval
    to be used with sys.exit
    """
    print(f"\t- Subcommand {args.cache_command} {args.cache_type}")

    cH, cPath = wfBackend.getCacheHandler(args.cache_type)
    assert cPath is not None
    retval = 0
    if args.cache_command == WfExS_Cache_Commands.List:
        if logLevel <= logging.INFO:
            contentsI = sorted(
                map(
                    lambda l: l[1],
                    cH.list(
                        *args.cache_command_args,
                        destdir=cPath,
                        acceptGlob=args.filesAsGlobs,
                        cascade=args.doCacheCascade,
                    ),
                ),
                key=lambda x: x["stamp"],
            )
            for entryI in contentsI:
                json.dump(
                    entryI, sys.stdout, cls=DatetimeEncoder, indent=4, sort_keys=True
                )
                print()
        else:
            contentsD = sorted(
                map(
                    lambda l: l[0],
                    cH.list(
                        *args.cache_command_args,
                        destdir=cPath,
                        acceptGlob=args.filesAsGlobs,
                        cascade=args.doCacheCascade,
                    ),
                ),
                key=lambda x: x.uri,
            )
            for entryD in contentsD:
                print(entryD)

    elif args.cache_command == WfExS_Cache_Commands.Remove:
        print(
            "\n".join(
                map(
                    lambda x: "\t".join([x[0].uri, x[1]]),
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
        if len(args.cache_command_args) == 2:
            injected_uri = args.cache_command_args[0]
            finalCachedFilename = args.cache_command_args[1]
            # # First, remove old occurrence
            # cH.remove(cPath, injected_uri)
            # Then, inject new occurrence
            cH.inject(
                injected_uri, destdir=cPath, finalCachedFilename=finalCachedFilename
            )
        else:
            print(
                f"ERROR: subcommand {args.cache_command} takes two positional parameters: the URI to be injected, and the path to the local content to be associated to that URI",
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
        if len(args.cache_command_args) == 1 or len(args.cache_command_args) == 3:
            uri_to_fetch = args.cache_command_args[0]
            secContext = None
            if len(args.cache_command_args) == 3:
                secContextFilename = args.cache_command_args[1]
                secContextName = args.cache_command_args[2]

                if os.path.exists(secContextFilename):
                    (
                        numErrors,
                        secContextBlock,
                    ) = wfBackend.parseAndValidateSecurityContextFile(
                        secContextFilename
                    )
                    if numErrors > 0:
                        print(
                            f"ERROR: security context file {secContextFilename} has {numErrors} errors",
                            file=sys.stderr,
                        )
                        retval = 1
                else:
                    print(
                        f"ERROR: security context file {secContextFilename} does not exist",
                        file=sys.stderr,
                    )
                    retval = 1

                if retval == 0:
                    secContext = secContextBlock.get(secContextName)
                    if secContext is None:
                        print(
                            f"ERROR: security context file {secContextFilename} does not contain the security context {secContextName}",
                            file=sys.stderr,
                        )
                        retval = 1

            if retval == 0:
                contentKind, abs_path, metadata, licences = wfBackend.cacheFetch(
                    uri_to_fetch, args.cache_type, offline=False, secContext=secContext
                )
                print(f"{contentKind}\t{abs_path}\t{licences}\t{metadata}")
        else:
            print(
                f"ERROR: subcommand {args.cache_command} takes either one or three positional parameters: the URI to be fetched, the path to a security context file and the security context to be used for the fetch operation",
                file=sys.stderr,
            )
            retval = 1

    return retval


def processStagedWorkdirCommand(
    wB: WfExSBackend, args: argparse.Namespace, loglevel: int
) -> int:
    """
    This method processes the cache subcommands, and returns the retval
    to be used with sys.exit
    """
    print(f"\t- Subcommand {args.staged_workdir_command}")

    retval = 0
    # This is needed to be sure the encfs instance is unmounted
    # if args.staged_workdir_command != WfExS_Staged_WorkDir_Commands.Mount:
    #    atexit.register(wfInstance.cleanup)

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
            ):
                if wfSetup is not None:
                    print(f"Mounted {instance_id} ({nickname}) at {wfSetup.work_dir}")
    elif args.staged_workdir_command == WfExS_Staged_WorkDir_Commands.List:
        contents = sorted(
            wB.listStagedWorkflows(
                *args.staged_workdir_command_args, acceptGlob=args.filesAsGlobs
            ),
            key=lambda x: x[2],
        )
        for instance_id, nickname, creation, wfSetup, _ in contents:
            is_encrypted: Union[bool, str]
            if wfSetup is None:
                is_damaged = True
                is_encrypted = "(unknown)"
            else:
                is_damaged = wfSetup.is_damaged
                is_encrypted = wfSetup.is_encrypted
            print(
                f"{instance_id}\t{nickname}\t{creation.isoformat()}\t{is_encrypted}\t{is_damaged}"
            )

    elif args.staged_workdir_command == WfExS_Staged_WorkDir_Commands.Remove:
        print(
            "\n".join(
                map(
                    lambda x: "Removed: " + "\t".join(x),
                    wB.removeStagedWorkflows(
                        *args.staged_workdir_command_args, acceptGlob=args.filesAsGlobs
                    ),
                )
            )
        )

    elif args.staged_workdir_command == WfExS_Staged_WorkDir_Commands.Shell:
        retval = wB.shellFirstStagedWorkflow(
            *args.staged_workdir_command_args, acceptGlob=args.filesAsGlobs
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
                        exit_val = wfInstance.executeWorkflow(offline=True)
                        print(
                            "\t- Instance {} (nickname '{}') exit value: {} ({})\n".format(
                                wfSetup.instance_id,
                                wfSetup.nickname,
                                exit_val,
                                "FAILED" if exit_val != 0 else "DONE",
                            )
                        )
                    except Exception as e:
                        logging.exception(
                            f"Error while executing {instance_id} ({nickname})"
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
                *args.staged_workdir_command_args, acceptGlob=args.filesAsGlobs
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
* Is damaged? {is_damaged}
* Created: {creation.isoformat()}
* Secure (encrypted)? {is_encrypted}
* {repr(mStatus)}
"""
                )

    # Thi
    return retval


def processExportCommand(
    wfInstance: WF, args: argparse.Namespace, loglevel: int
) -> int:
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
            action_ids=cast(Sequence[SymbolicName], args.export_contents_command_args),
        )
        print(f"{expval}")

    return retval


def main() -> None:
    wfexs_version = get_WfExS_version()
    if wfexs_version[1] is None:
        verstr = wfexs_version[0]
    else:
        verstr = "{0[0]} ({0[1]})".format(wfexs_version)

    defaultLocalConfigFilename = os.path.join(os.getcwd(), DEFAULT_LOCAL_CONFIG_RELNAME)
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
        help="Local installation configuration file",
    )
    ap.add_argument("--cache-dir", dest="cacheDir", help="Caching directory")

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

    ap_c = genParserSub(sp, WfExS_Commands.Cache)
    ap_c.add_argument(
        "cache_command",
        help="raw|Cache command to perform\n\n"
        + "\n".join(
            map(lambda c: f"{c.value:<12}{c.description}", WfExS_Cache_Commands)
        ),
        type=cast(Callable_WfExS_Cache_Commands, WfExS_Cache_Commands.argtype),
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
        help="raw|Cache type to perform the cache command\n\n"
        + "\n".join(map(lambda c: f"{c.value:<12}{c.description}", WfExS_CacheType)),
        type=cast(Callable_WfExS_CacheType, WfExS_CacheType.argtype),
        choices=WfExS_CacheType,
    )
    ap_c.add_argument(
        "cache_command_args", help="Optional cache element names", nargs="*"
    )

    ap_w = genParserSub(sp, WfExS_Commands.StagedWorkDir)
    ap_w.add_argument(
        "staged_workdir_command",
        help="raw|Staged working directory command to perform\n\n"
        + "\n".join(
            map(
                lambda c: f"{c.value:<16}{c.description}", WfExS_Staged_WorkDir_Commands
            )
        ),
        type=cast(
            Callable_WfExS_Staged_WorkDir_Commands,
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
        help="raw|Export operations from staged working directory to perform\n\n"
        + "\n".join(
            map(lambda c: f"{c.value:<16}{c.description}", WfExS_Export_Commands)
        ),
        type=cast(Callable_WfExS_Export_Commands, WfExS_Export_Commands.argtype),
        choices=WfExS_Export_Commands,
    )
    ap_expt.add_argument(
        "export_contents_command_args", help="Optional export names", nargs="*"
    )

    ap_cv = genParserSub(sp, WfExS_Commands.ConfigValidate, preStageParams=True)

    ap_s = genParserSub(sp, WfExS_Commands.Stage, preStageParams=True)

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

    loggingConf: BasicLoggingConfigDict = {"format": logFormat, "level": logLevel}

    if args.logFilename is not None:
        loggingConf["filename"] = args.logFilename
    #    loggingConf['encoding'] = 'utf-8'

    logging.basicConfig(**loggingConf)
    if logLevel >= logging.INFO:
        logging.getLogger("crypt4gh").setLevel(
            logLevel if logLevel > logging.WARNING else logging.WARNING
        )

    # First, try loading the configuration file
    localConfigFilename = args.localConfigFilename
    if localConfigFilename and os.path.exists(localConfigFilename):
        with open(localConfigFilename, mode="r", encoding="utf-8") as cf:
            local_config = yaml.load(cf, Loader=YAMLLoader)
    else:
        local_config = {}
        if localConfigFilename and not os.path.exists(localConfigFilename):
            print(
                "[WARNING] Configuration file {} does not exist".format(
                    localConfigFilename
                ),
                file=sys.stderr,
            )

    if args.cacheDir:
        local_config["cache-directory"] = args.cacheDir

    # In any case, assuring the cache directory does exist
    cacheDir = local_config.get("cacheDir")
    if cacheDir:
        os.makedirs(cacheDir, exist_ok=True)
    else:
        cacheDir = tempfile.mkdtemp(prefix="wfexs", suffix="tmpcache")
        local_config["cacheDir"] = cacheDir
        # Assuring this temporal directory is removed at the end
        atexit.register(shutil.rmtree, cacheDir)
        print(
            f"[WARNING] Cache directory not defined. Created a temporary one at {cacheDir}",
            file=sys.stderr,
        )

    # A filename is needed later, in order to initialize installation keys
    if not localConfigFilename:
        localConfigFilename = defaultLocalConfigFilename

    # Hints for the the default path for the Crypt4GH keys
    config_directory = os.path.dirname(localConfigFilename)
    config_relname = os.path.basename(localConfigFilename)

    # Initialize (and create config file)
    if command in (
        WfExS_Commands.Init,
        WfExS_Commands.Cache,
        WfExS_Commands.Stage,
        WfExS_Commands.Execute,
    ):
        updated_config, local_config = WfExSBackend.bootstrap(
            local_config, config_directory, key_prefix=config_relname
        )

        # Last, should config be saved back?
        if updated_config or not os.path.exists(localConfigFilename):
            print("* Storing updated configuration at {}".format(localConfigFilename))
            with open(localConfigFilename, mode="w", encoding="utf-8") as cf:
                yaml.dump(local_config, cf, Dumper=YAMLDumper)

        # We are finishing here!
        if command == WfExS_Commands.Init:
            sys.exit(0)

    # Is the work already staged?
    wfBackend = WfExSBackend(local_config, config_directory)

    # Cache handling commands
    print('* Command "{}".'.format(command), file=sys.stderr)
    if command == WfExS_Commands.Cache:
        sys.exit(processCacheCommand(wfBackend, args, logLevel))

    # Staged working directory handling commands
    if command == WfExS_Commands.StagedWorkDir:
        sys.exit(processStagedWorkdirCommand(wfBackend, args, logLevel))

    wfInstance = None
    if command in (
        WfExS_Commands.MountWorkDir,
        WfExS_Commands.Export,
        WfExS_Commands.ExportStage,
        WfExS_Commands.OfflineExecute,
        WfExS_Commands.ExportResults,
        WfExS_Commands.ExportCrate,
    ):
        wfInstance = wfBackend.fromWorkDir(
            args.workflowWorkingDirectory,
            fail_ok=command != WfExS_Commands.MountWorkDir,
        )
    elif not args.workflowConfigFilename:
        print("[ERROR] Workflow config was not provided! Stopping.", file=sys.stderr)
        sys.exit(1)
    elif command == WfExS_Commands.ConfigValidate:
        retval = wfBackend.validateConfigFiles(
            args.workflowConfigFilename, args.securityContextsConfigFilename
        )
        sys.exit(retval)
    else:
        wfInstance = wfBackend.fromFiles(
            args.workflowConfigFilename,
            args.securityContextsConfigFilename,
            nickname_prefix=args.nickname_prefix,
        )

    # This is needed to be sure the encfs instance is unmounted
    if command != WfExS_Commands.MountWorkDir:
        atexit.register(wfInstance.cleanup)

    wfSetup = wfInstance.getStagedSetup()
    print("\t- Working directory will be {}".format(wfSetup.work_dir), file=sys.stderr)
    sys.stderr.flush()

    # Export staged working directory contents commands
    if command == WfExS_Commands.Export:
        sys.exit(processExportCommand(wfInstance, args, logLevel))

    if command in (WfExS_Commands.Stage, WfExS_Commands.Execute):
        print(
            "\t- Instance {} (nickname '{}') (to be used with -J)".format(
                wfSetup.instance_id, wfSetup.nickname
            )
        )
        stagedSetup = wfInstance.stageWorkDir()
        if command == WfExS_Commands.Stage:
            print(
                "\t- Instance {} (nickname '{}') is {} ready".format(
                    wfSetup.instance_id,
                    wfSetup.nickname,
                    "NOT" if stagedSetup.is_damaged else "now",
                )
            )

    if command in (WfExS_Commands.ExportStage, WfExS_Commands.Execute):
        wfInstance.createStageResearchObject(args.doMaterializedROCrate)

    if command in (WfExS_Commands.OfflineExecute, WfExS_Commands.Execute):
        print(
            "\t- Instance {} (nickname '{}') is being run".format(
                wfSetup.instance_id,
                wfSetup.nickname,
            )
        )
        exit_val = wfInstance.executeWorkflow(
            offline=command == WfExS_Commands.OfflineExecute
        )
        print(
            "\t- Instance {} (nickname '{}') exit value: {} ({})".format(
                wfSetup.instance_id,
                wfSetup.nickname,
                exit_val,
                "FAILED" if exit_val != 0 else "DONE",
            )
        )

    if command in (WfExS_Commands.ExportResults, WfExS_Commands.Execute):
        wfInstance.exportResults()

    if command in (WfExS_Commands.ExportCrate, WfExS_Commands.Execute):
        wfInstance.createResultsResearchObject(args.doMaterializedROCrate)


if __name__ == "__main__":
    main()
