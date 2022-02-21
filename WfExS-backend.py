#!/usr/bin/env python
# -*- coding: utf-8 -*-

# Copyright 2020-2021 Barcelona Supercomputing Center (BSC), Spain
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
import enum

import yaml

# We have preference for the C based loader and dumper, but the code
# should fallback to default implementations when C ones are not present
try:
    from yaml import CLoader as YAMLLoader, CDumper as YAMLDumper
except ImportError:
    from yaml import Loader as YAMLLoader, Dumper as YAMLDumper

from wfexs_backend.wfexs_backend import WfExSBackend
from wfexs_backend import get_WfExS_version
from wfexs_backend.common import ArgTypeMixin, CacheType as WfExS_CacheType

class WfExS_Commands(ArgTypeMixin, enum.Enum):
    Init = 'init'
    Cache = 'cache'
    ConfigValidate = 'config-validate'
    Stage = 'stage'
    MountWorkDir = 'mount-workdir'
    StagedWorkDir = 'staged-workdir'
    ExportStage = 'export-stage'
    OfflineExecute = 'offline-execute'
    Execute = 'execute'
    ExportResults = 'export-results'
    ExportCrate = 'export-crate'

class WfExS_Cache_Commands(ArgTypeMixin, enum.Enum):
    List = 'ls'
    Inject = 'inject'
    Remove = 'rm'
    Validate = 'validate'

class WfExS_Staged_WorkDir_Commands(ArgTypeMixin, enum.Enum):
    Execute = 'exec'
    List = 'ls'
    Mount = 'mount'
    Remove = 'rm'
#    Validate = 'validate'

DEFAULT_LOCAL_CONFIG_RELNAME = 'wfexs_config.yml'
LOGGING_FORMAT = '%(asctime)-15s - [%(levelname)s] %(message)s'
DEBUG_LOGGING_FORMAT = '%(asctime)-15s - [%(name)s %(funcName)s %(lineno)d][%(levelname)s] %(message)s'

def genParserSub(sp:argparse.ArgumentParser, command:WfExS_Commands, help:str=None, preStageParams:bool=False, postStageParams:bool=False, crateParams:bool=False):
    ap_ = sp.add_parser(
        command.value,
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
        help=help
    )
    
    if preStageParams:
        ap_.add_argument(
            '-W',
            '--workflow-config',
            dest="workflowConfigFilename",
            required=True,
            help="Configuration file, describing workflow and inputs"
        )
        ap_.add_argument(
            '-Z',
            '--creds-config',
            dest="securityContextsConfigFilename",
            help="Configuration file, describing security contexts, which hold credentials and similar"
        )
    
    if postStageParams:
        ap_.add_argument(
            '-J',
            '--staged-job-dir',
            dest='workflowWorkingDirectory',
            required=True,
            help="Already staged job directory"
        )
    
    if crateParams:
        ap_.add_argument('--full', dest='doMaterializedROCrate', action='store_true',
                    help="Should the RO-Crate contain a copy of the inputs (and outputs)?")
    return ap_

def processCacheCommand(wfBackend:WfExSBackend, args: argparse.Namespace, logLevel) -> int:
    """
    This method processes the cache subcommands, and returns the retval
    to be used with sys.exit
    """
    cH , cPath = wfBackend.getCacheHandler(args.cache_type)
    retval = 0
    if args.cache_command == WfExS_Cache_Commands.List:
        if logLevel <= logging.INFO:
            contents = sorted(map(lambda l: l[1], cH.list(cPath, *args.cache_command_args, acceptGlob=args.filesAsGlobs, cascade=args.doCacheCascade)), key=lambda x: x['stamp'])
            for entry in contents:
                json.dump(entry, sys.stdout, indent=4, sort_keys=True)
                print()
        else:
            contents = sorted(map(lambda l: l[0], cH.list(cPath, *args.cache_command_args, acceptGlob=args.filesAsGlobs, cascade=args.doCacheCascade)))
            for entry in contents:
                print(entry)
            
    elif args.cache_command == WfExS_Cache_Commands.Remove:
        print('\n'.join(map(lambda x: '\t'.join(x), cH.remove(cPath, *args.cache_command_args, acceptGlob=args.filesAsGlobs, doRemoveFiles=args.doCacheRecursively, cascade=args.doCacheCascade))))
    elif args.cache_command == WfExS_Cache_Commands.Inject:
        injected_uri = args.cache_command_args[0]
        finalCachedFilename = args.cache_command_args[1]
        # # First, remove old occurrence
        # cH.remove(cPath, injected_uri)
        # Then, inject new occurrence
        cH.inject(cPath, injected_uri, finalCachedFilename=finalCachedFilename)
    elif args.cache_command == WfExS_Cache_Commands.Validate:
        for metaUri, validated, metaStructure in cH.validate(cPath, *args.cache_command_args, acceptGlob=args.filesAsGlobs, cascade=args.doCacheCascade):
            print(f"\t- {metaUri} {validated}")
    #    pass
    
    return retval

def processStagedWorkdirCommand(wfBackend:WfExSBackend, args: argparse.Namespace, loglevel) -> int:
    """
    This method processes the cache subcommands, and returns the retval
    to be used with sys.exit
    """
    
    retval = 0
    # This is needed to be sure the encfs instance is unmounted
    if args.staged_workdir_command != WfExS_Staged_WorkDir_Commands.Mount:
        atexit.register(wfInstance.cleanup)
    
    if args.staged_workdir_command == WfExS_Staged_WorkDir_Commands.Mount:
        if len(args.staged_workdir_command_args) > 0:
            # FIXME: This operation could not work for more than one call
            for stagedWorkDir in args.staged_workdir_command_args:
                wfInstance.fromWorkDir(args.staged_workdir_command_args[0])
    
    
    # Thi
    return retval

if __name__ == "__main__":
    
    wfexs_version = get_WfExS_version()
    if wfexs_version[1] is None:
        verstr = wfexs_version[0]
    else:
        verstr = "{0[0]} ({0[1]})".format(wfexs_version)
    
    defaultLocalConfigFilename = os.path.join(os.getcwd(), DEFAULT_LOCAL_CONFIG_RELNAME)
    ap = argparse.ArgumentParser(
        description="WfExS (workflow execution service) backend "+verstr,
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    ap.add_argument('--log-file', dest="logFilename", help='Store messages in a file instead of using standard error and standard output')
    ap.add_argument('-q', '--quiet', dest='logLevel', action='store_const', const=logging.WARNING, help='Only show engine warnings and errors')
    ap.add_argument('-v', '--verbose', dest='logLevel', action='store_const', const=logging.INFO, help='Show verbose (informational) messages')
    ap.add_argument('-d', '--debug', dest='logLevel', action='store_const', const=logging.DEBUG, help='Show debug messages (use with care, as it can disclose passphrases and passwords)')
    ap.add_argument('-L', '--local-config', dest="localConfigFilename", default=defaultLocalConfigFilename, help="Local installation configuration file")
    ap.add_argument('--cache-dir', dest="cacheDir", help="Caching directory")
    
    ap.add_argument('-V', '--version', action='version', version='%(prog)s version ' + verstr)
    ap.add_argument('--full-help', dest='fullHelp', action='store_true', default=False, help='It returns full help')
    
    sp = ap.add_subparsers(dest='command', title='commands', description='Command to run. It must be one of these')
    
    ap_i = genParserSub(
        sp,
        WfExS_Commands.Init,
        help='Init local setup'
    )
    
    ap_c = genParserSub(
        sp,
        WfExS_Commands.Cache,
        help='Cache handling subcommands'
    )
    ap_c.add_argument('cache_command', help='Cache command to perform', type=WfExS_Cache_Commands.argtype, choices=WfExS_Cache_Commands)
    ap_c.add_argument("-r", dest="doCacheRecursively", help='Try doing the operation recursively (i.e. both metadata and data)', action="store_true", default=False)
    ap_c.add_argument("--cascade", dest="doCacheCascade", help='Try doing the operation in cascade (including the URIs which resolve to other URIs)', action="store_true", default=False)
    ap_c.add_argument("-g", "--glob", dest="filesAsGlobs", help='Given cache element names are globs', action="store_true", default=False)
    ap_c.add_argument('cache_type', help='Cache type to perform the cache command', type=WfExS_CacheType.argtype, choices=WfExS_CacheType)
    ap_c.add_argument('cache_command_args', help='Optional cache element names', nargs='*')
    
    ap_w = genParserSub(
        sp,
        WfExS_Commands.StagedWorkDir,
        help='Staged working directories handling subcommands'
    )
    ap_w.add_argument('staged_workdir_command', help='Staged working directory command to perform', type=WfExS_Staged_WorkDir_Commands.argtype, choices=WfExS_Staged_WorkDir_Commands)
    ap_w.add_argument('staged_workdir_command_args', help='Optional staged working directory element names', nargs='*')
    
    ap_cv = genParserSub(
        sp,
        WfExS_Commands.ConfigValidate,
        help='Validate the configuration files to be used for staging and execution',
        preStageParams=True
    )
    
    ap_s = genParserSub(
        sp,
        WfExS_Commands.Stage,
        help='Prepare the staging (working) directory for workflow execution, fetching dependencies and contents',
        preStageParams=True
    )
    
    ap_m = genParserSub(
        sp,
        WfExS_Commands.MountWorkDir,
        help='Mount the encrypted staging directory on secure staging scenarios',
        postStageParams=True
    )
    
    ap_es = genParserSub(
        sp,
        WfExS_Commands.ExportStage,
        help='Export the staging directory as an RO-Crate',
        postStageParams=True,
        crateParams=True
    )
    
    ap_oe = genParserSub(
        sp,
        WfExS_Commands.OfflineExecute,
        help='Execute an already prepared workflow in the staging directory',
        postStageParams=True
    )
    
    ap_e = genParserSub(
        sp,
        WfExS_Commands.Execute,
        help='Execute the stage + offline-execute + export steps',
        preStageParams=True,
        crateParams=True
    )
    
    ap_er = genParserSub(
        sp,
        WfExS_Commands.ExportResults,
        help='Export the results to a remote location, gathering their public ids',
        postStageParams=True
    )
    
    ap_ec = genParserSub(
        sp,
        WfExS_Commands.ExportCrate,
        help='Export an already executed workflow in the staging directory as an RO-Crate',
        postStageParams=True,
        crateParams=True
    )
    
    args = ap.parse_args()
    
    fullHelp = args.fullHelp
    if args.command is None:
        fullHelp = True
    
    if fullHelp:
        print(ap.format_help())

        # retrieve subparsers from parser
        subparsers_actions = [
            action for action in ap._actions 
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
    
    loggingConf = {
        'format': logFormat,
        'level': logLevel
    }
    
    if args.logFilename is not None:
        loggingConf['filename'] = args.logFilename
    #    loggingConf['encoding'] = 'utf-8'
    
    logging.basicConfig(**loggingConf)
    
    # First, try loading the configuration file
    localConfigFilename = args.localConfigFilename
    if localConfigFilename and os.path.exists(localConfigFilename):
        with open(localConfigFilename, mode="r", encoding="utf-8") as cf:
            local_config = yaml.load(cf, Loader=YAMLLoader)
    else:
        local_config = {}
        if localConfigFilename and not os.path.exists(localConfigFilename):
            print("[WARNING] Configuration file {} does not exist".format(localConfigFilename), file=sys.stderr)
    
    if args.cacheDir:
        local_config['cache-directory'] = args.cacheDir

    # In any case, assuring the cache directory does exist
    cacheDir = local_config.get('cacheDir')
    if cacheDir:
        os.makedirs(cacheDir, exist_ok=True)
    else:
        cacheDir = tempfile.mkdtemp(prefix='wfexs', suffix='tmpcache')
        local_config['cacheDir'] = cacheDir
        # Assuring this temporal directory is removed at the end
        atexit.register(shutil.rmtree, cacheDir)
        print(f"[WARNING] Cache directory not defined. Created a temporary one at {cacheDir}", file=sys.stderr)
    
    # A filename is needed later, in order to initialize installation keys
    if not localConfigFilename:
        localConfigFilename = defaultLocalConfigFilename
    
    # Hints for the the default path for the Crypt4GH keys
    config_directory = os.path.dirname(localConfigFilename)
    config_relname = os.path.basename(localConfigFilename)
    
    # Initialize (and create config file)
    if command in (WfExS_Commands.Init, WfExS_Commands.Cache, WfExS_Commands.Stage, WfExS_Commands.Execute):
        updated_config, local_config = WfExSBackend.bootstrap(local_config, config_directory, key_prefix=config_relname)
        
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
    if command == WfExS_Commands.Cache:
        sys.exit(processCacheCommand(wfBackend, args, logLevel))
    
    # Staged working directory handling commands
    if command == WfExS_Commands.StagedWorkDir:
        sys.exit(processStagedWorkdirCommand(wfBackend, args, logLevel))
    
    wfInstance = None
    if command in (WfExS_Commands.MountWorkDir, WfExS_Commands.ExportStage, WfExS_Commands.OfflineExecute, WfExS_Commands.ExportResults, WfExS_Commands.ExportCrate):
        wfInstance = wfBackend.fromWorkDir(args.workflowWorkingDirectory)
    elif not args.workflowConfigFilename:
        print("[ERROR] Workflow config was not provided! Stopping.", file=sys.stderr)
        sys.exit(1)
    elif command == WfExS_Commands.ConfigValidate:
        retval = wfBackend.validateConfigFiles(args.workflowConfigFilename, args.securityContextsConfigFilename)
        sys.exit(retval)
    else:
        wfInstance = wfBackend.fromFiles(args.workflowConfigFilename, args.securityContextsConfigFilename)
    
    # This is needed to be sure the encfs instance is unmounted
    if command != WfExS_Commands.MountWorkDir:
        atexit.register(wfInstance.cleanup)
    
    print("* Command \"{}\". Working directory will be {}".format(command, wfInstance.workDir), file=sys.stderr)
    sys.stderr.flush()
    
    if command in (WfExS_Commands.Stage, WfExS_Commands.Execute):
        instanceId = wfInstance.stageWorkDir()
        
        print("* Instance {} (to be used with -J)".format(instanceId))
    
    if command in (WfExS_Commands.ExportStage, WfExS_Commands.Execute):
        wfInstance.createStageResearchObject(args.doMaterializedROCrate)
    
    if command in (WfExS_Commands.OfflineExecute, WfExS_Commands.Execute):
        wfInstance.executeWorkflow(offline=command == WfExS_Commands.OfflineExecute)
    
    if command in (WfExS_Commands.ExportResults, WfExS_Commands.Execute):
        wfInstance.exportResults()
    
    if command in (WfExS_Commands.ExportCrate, WfExS_Commands.Execute):
        wfInstance.createResultsResearchObject(args.doMaterializedROCrate)
