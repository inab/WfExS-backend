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

from wfexs_backend.workflow import WF
from wfexs_backend import get_WfExS_version

# Adapted from https://gist.github.com/ptmcg/23ba6e42d51711da44ba1216c53af4ea
# in order to show the value instead of the class name
class ArgTypeMixin(enum.Enum):
    @classmethod
    def argtype(cls, s: str) -> enum.Enum:
        try:
            return cls(s)
        except:
            raise argparse.ArgumentTypeError(
                f"{s!r} is not a valid {cls.__name__}")

    def __str__(self):
        return str(self.value)


class WfExS_Commands(ArgTypeMixin, enum.Enum):
    Init = 'init'
    ConfigValidate = 'config-validate'
    Stage = 'stage'
    MountWorkDir = 'mount-workdir'
    ExportStage = 'export-stage'
    OfflineExecute = 'offline-execute'
    Execute = 'execute'
    ExportResults = 'export-results'
    ExportCrate = 'export-crate'


DEFAULT_LOCAL_CONFIG_RELNAME = 'wfexs_config.yml'
LOGGING_FORMAT = '%(asctime)-15s - [%(levelname)s] %(message)s'

if __name__ == "__main__":
    
    wfexs_version = get_WfExS_version()
    if wfexs_version[1] is None:
        verstr = wfexs_version[0]
    else:
        verstr = "{0[0]} ({0[1]})".format(wfexs_version)
    
    defaultLocalConfigFilename = os.path.join(os.getcwd(), DEFAULT_LOCAL_CONFIG_RELNAME)
    ap = argparse.ArgumentParser(description="WfExS (workflow execution service) backend "+verstr)
    ap.add_argument('--log-file', dest="logFilename", help='Store messages in a file instead of using standard error and standard output')
    ap.add_argument('-q', '--quiet', dest='logLevel', action='store_const', const=logging.WARNING, help='Only show engine warnings and errors')
    ap.add_argument('-v', '--verbose', dest='logLevel', action='store_const', const=logging.INFO, help='Show verbose (informational) messages')
    ap.add_argument('-d', '--debug', dest='logLevel', action='store_const', const=logging.DEBUG, help='Show debug messages (use with care, as it can disclose passphrases and passwords)')
    ap.add_argument('-L', '--local-config', dest="localConfigFilename", default=defaultLocalConfigFilename, help="Local installation configuration file")
    ap.add_argument('--cache-dir', dest="cacheDir", help="Caching directory")
    ap.add_argument('-W', '--workflow-config', dest="workflowConfigFilename",
                    help="Configuration file, describing workflow and inputs")
    ap.add_argument('-Z', '--creds-config', dest="securityContextsConfigFilename",
                    help="Configuration file, describing security contexts, which hold credentials and similar")
    ap.add_argument('-J', '--staged-job-dir', dest='workflowWorkingDirectory',
                    help="Already staged job directory (to be used with {})".format(str(WfExS_Commands.OfflineExecute)))
    ap.add_argument('--full', dest='doMaterializedROCrate', action='store_true',
                    help="Should the RO-Crate contain a copy of the inputs (and outputs)? (to be used with {})".format(' or '.join(map(lambda command: str(command), (WfExS_Commands.ExportStage, WfExS_Commands.ExportCrate)))))
    ap.add_argument('command', help='Command to run', nargs='?', type=WfExS_Commands.argtype, choices=WfExS_Commands, default=WfExS_Commands.ConfigValidate)
    ap.add_argument('-V', '--version', action='version', version='%(prog)s version ' + verstr)
    
    args = ap.parse_args()
    
    # Setting up the log
    loggingConf = {
        'format': LOGGING_FORMAT,
    }
    
    if args.logLevel:
        loggingConf['level'] = args.logLevel
    
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
        cacheDir = tempfile.mkdtemp(prefix='wes', suffix='backend')
        local_config['cacheDir'] = cacheDir
        # Assuring this temporal directory is removed at the end
        atexit.register(shutil.rmtree, cacheDir)
    
    # A filename is needed later, in order to initialize installation keys
    if not localConfigFilename:
        localConfigFilename = defaultLocalConfigFilename
    
    # Hints for the the default path for the Crypt4GH keys
    config_directory = os.path.dirname(localConfigFilename)
    config_relname = os.path.basename(localConfigFilename)
    
    # Initialize (and create config file)
    if args.command in (WfExS_Commands.Init, WfExS_Commands.Stage, WfExS_Commands.Execute):
        updated_config, local_config = WF.bootstrap(local_config, config_directory, key_prefix=config_relname)
        
        # Last, should config be saved back?
        if updated_config or not os.path.exists(localConfigFilename):
            print("* Storing updated configuration at {}".format(localConfigFilename))
            with open(localConfigFilename, mode="w", encoding="utf-8") as cf:
                yaml.dump(local_config, cf, Dumper=YAMLDumper)
        
        # We are finishing here!
        if args.command == WfExS_Commands.Init:
            sys.exit(0)

    # Is the work already staged?
    wfInstance = WF(local_config, config_directory)
    
    # This is needed to be sure the encfs instance is unmounted
    if args.command != WfExS_Commands.MountWorkDir:
        atexit.register(wfInstance.cleanup)
    
    if args.command in (WfExS_Commands.MountWorkDir, WfExS_Commands.ExportStage, WfExS_Commands.OfflineExecute, WfExS_Commands.ExportResults, WfExS_Commands.ExportCrate):
        wfInstance.fromWorkDir(args.workflowWorkingDirectory)
    elif not args.workflowConfigFilename:
        print("[ERROR] Workflow config was not provided! Stopping.", file=sys.stderr)
        sys.exit(1)
    elif args.command == WfExS_Commands.ConfigValidate:
        retval = wfInstance.validateConfigFiles(args.workflowConfigFilename, args.securityContextsConfigFilename)
        sys.exit(retval)
    else:
        wfInstance.fromFiles(args.workflowConfigFilename, args.securityContextsConfigFilename)
    
    print("* Command \"{}\". Working directory will be {}".format(args.command, wfInstance.workDir), file=sys.stderr)
    sys.stderr.flush()
    
    if args.command in (WfExS_Commands.Stage, WfExS_Commands.Execute):
        instanceId = wfInstance.stageWorkDir()
        
        print("* Instance {} (to be used with -J)".format(instanceId))
    
    if args.command in (WfExS_Commands.ExportStage, WfExS_Commands.Execute):
        wfInstance.createStageResearchObject(args.doMaterializedROCrate)
    
    if args.command in (WfExS_Commands.OfflineExecute, WfExS_Commands.Execute):
        wfInstance.executeWorkflow(offline=args.command == WfExS_Commands.OfflineExecute)
    
    if args.command in (WfExS_Commands.ExportResults, WfExS_Commands.Execute):
        wfInstance.exportResults()
    
    if args.command in (WfExS_Commands.ExportCrate, WfExS_Commands.Execute):
        wfInstance.createResultsResearchObject(args.doMaterializedROCrate)
