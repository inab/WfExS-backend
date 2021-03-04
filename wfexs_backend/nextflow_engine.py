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
from __future__ import absolute_import

import os
import re
import subprocess
import tempfile

from typing import Dict, List, Tuple
from .common import *
from .engine import WorkflowEngine, WorkflowEngineException


class NextflowWorkflowEngine(WorkflowEngine):
    NEXTFLOW_REPO = 'https://github.com/nextflow-io/nextflow'
    DEFAULT_NEXTFLOW_VERSION = '19.04.1'
    DEFAULT_NEXTFLOW_DOCKER_IMAGE = 'nextflow/nextflow'

    DEFAULT_MAX_RETRIES = 5
    DEFAULT_MAX_CPUS = 4

    ENGINE_NAME = 'nextflow'

    def __init__(self,
            cacheDir=None,
            workflow_config=None,
            local_config=None,
            engineTweaksDir=None,
            cacheWorkflowDir=None,
            workDir=None,
            outputsDir=None,
            intermediateDir=None
        ):
        super().__init__(cacheDir=cacheDir, workflow_config=workflow_config, local_config=local_config,
                         engineTweaksDir=engineTweaksDir, cacheWorkflowDir=cacheWorkflowDir,
                         workDir=workDir, outputsDir=outputsDir, intermediateDir=intermediateDir)
        
        self.java_cmd = local_config.get('tools', {}).get('javaCommand', DEFAULT_JAVA_CMD)

        self.nxf_image = local_config.get(self.ENGINE_NAME, {}).get('dockerImage', self.DEFAULT_NEXTFLOW_DOCKER_IMAGE)
        self.nxf_version = local_config.get(self.ENGINE_NAME, {}).get('version', self.DEFAULT_NEXTFLOW_VERSION)
        self.max_retries = local_config.get(self.ENGINE_NAME, {}).get('maxRetries', self.DEFAULT_MAX_RETRIES)
        self.max_cpus = local_config.get(self.ENGINE_NAME, {}).get('maxCpus', self.DEFAULT_MAX_CPUS)

    @classmethod
    def WorkflowType(cls) -> WorkflowType:
        return WorkflowType(
            engineName=cls.ENGINE_NAME,
            clazz=cls,
            uri='https://www.nextflow.io/',
            trs_descriptor='NFL',
            rocrate_programming_language='#nextflow'
        )

    def identifyWorkflow(self, localWf: LocalWorkflow, engineVer: EngineVersion = None) -> Tuple[EngineVersion, LocalWorkflow]:
        """
        This method should return the effective engine version needed
        to run it when this workflow engine recognizes the workflow type
        """

        nfPath = localWf.dir
        if localWf.relPath is not None:
            engineVer = self.nxf_version
            nfPath = os.path.join(nfPath, localWf.relPath)

        if os.path.isdir(nfPath):
            nfDir = nfPath
            candidateNf = None
        else:
            nfDir = os.path.dirname(nfPath)
            candidateNf = os.path.basename(nfPath)

        nfConfig = os.path.join(nfDir, 'nextflow.config')
        verPat = re.compile(r"nextflowVersion *= *['\"][>=]*([^ ]+)['\"]")
        mainPat = re.compile(r"mainScript *= *['\"]([^\"]+)['\"]")
        if engineVer is None:
            engineVer = self.nxf_version
        else:
            # We are deactivating the engine version capture from the config
            verPat = None
        
        if os.path.isfile(nfConfig):
            # Now, let's guess the nextflow version and mainScript
            with open(nfConfig, "r") as nc_config:
                for line in nc_config:
                    if verPat is not None:
                        matched = verPat.search(line)
                        if matched:
                            engineVer = matched.group(1)
                            verPat = None

                    if mainPat is not None:
                        matched = mainPat.search(line)
                        if matched:
                            putativeCandidateNf = matched.group(1)
                            if candidateNf is not None:
                                if candidateNf != putativeCandidateNf:
                                    # This should be a warning
                                    raise WorkflowEngineException(
                                        'Nextflow mainScript in manifest {} differs from the one requested {}'.format(
                                            putativeCandidateNf, candidateNf))
                            else:
                                candidateNf = putativeCandidateNf
                            mainPat = None

        if candidateNf is None:
            # Default case
            candidateNf = 'main.nf'

        entrypoint = os.path.join(nfDir, candidateNf)
        # Checking that the workflow entrypoint does exist
        if not os.path.isfile(entrypoint):
            raise WorkflowEngineException(
                'Could not find mainScript {} in Nextflow workflow directory {} '.format(candidateNf, nfDir))
        
        if engineVer is None:
            engineVer = self.nxf_version
        
        return engineVer, LocalWorkflow(dir=nfDir, relPath=candidateNf, effectiveCheckout=localWf.effectiveCheckout)

    def materializeEngineVersion(self, engineVersion: EngineVersion) -> Tuple[EngineVersion, EnginePath, Fingerprint]:
        """
        Method to ensure the required engine version is materialized
        It should raise an exception when the exact version is unavailable,
        and no replacement could be fetched
        """
        
        nextflow_install_dir = os.path.join(self.weCacheDir,engineVersion)
        retval , nxf_install_stdout_v, nxf_install_stderr_v = self.runNextflowCommand(engineVersion,['info'],nextflow_path=nextflow_install_dir)
        if retval != 0:
            errstr = "Could not install Nextflow {} . Retval {}\n======\nSTDOUT\n======\n{}\n======\nSTDERR\n======\n{}".format(engineVersion,retval,nxf_install_stdout_v,nxf_install_stderr_v)
            raise WorkflowEngineException(errstr)
        
        # Getting the version label
        verPat = re.compile(r"Version: +(.*)$")
        verMatch = verPat.search(nxf_install_stdout_v)
        
        engineFingerprint = verMatch.group(1)  if verMatch  else None
        
        return engineVersion, nextflow_install_dir, engineFingerprint
    
    def runNextflowCommand(self,nextflow_version: EngineVersion, commandLine: List[str], workdir=None, nextflow_path:EnginePath=None) -> Tuple[ExitVal,str,str]:
        if self.engine_mode == EngineMode.Docker:
            retval , nxf_run_stdout_v, nxf_run_stderr_v = self.runNextflowCommandInDocker(nextflow_version, commandLine, workdir)
        elif self.engine_mode == EngineMode.Local:
            retval , nxf_run_stdout_v, nxf_run_stderr_v = self.runLocalNextflowCommand(nextflow_version, commandLine, workdir, nextflow_install_dir=nextflow_path)
        else:
            raise WorkflowEngineException('Unsupported engine mode {} for {} engine'.format(self.engine_mode, self.ENGINE_NAME))
        
        return retval , nxf_run_stdout_v, nxf_run_stderr_v
    
    def runLocalNextflowCommand(self,nextflow_version: EngineVersion, commandLine: List[str], workdir=None, nextflow_install_dir:EnginePath=None) -> Tuple[int,str,str]:
        if nextflow_install_dir is None:
            nextflow_install_dir = os.path.join(self.weCacheDir,nextflow_version)
        cachedScript = os.path.join(nextflow_install_dir, 'nextflow')
        if not os.path.exists(cachedScript):
            os.makedirs(nextflow_install_dir, exist_ok=True)
            nextflow_script_url = 'https://github.com/nextflow-io/nextflow/releases/download/v{0}/nextflow'.format(nextflow_version)
            print("Downloading Nextflow {}: {} => {}".format(nextflow_version,nextflow_script_url, cachedScript))
            fetchClassicURL(nextflow_script_url,cachedScript)
        
        # Checking the installer has execution permissions
        if not os.access(cachedScript, os.R_OK | os.X_OK):
            os.chmod(cachedScript,0o555)
        
        # Now, time to run it
        NXF_HOME = os.path.join(nextflow_install_dir,'.nextflow')
        instEnv = dict(os.environ)
        instEnv['NXF_HOME'] = NXF_HOME
        instEnv['JAVA_CMD'] = self.java_cmd
        
        # This is done only once
        retval = 0
        nxf_run_stdout_v = None
        nxf_run_stderr_v = None
        if not os.path.isdir(NXF_HOME):
            with tempfile.NamedTemporaryFile() as nxf_install_stdout:
                with tempfile.NamedTemporaryFile() as nxf_install_stderr:
                    retval = subprocess.Popen(
                        [cachedScript,'-download'],
                        stdout=nxf_install_stdout,
                        stderr=nxf_install_stderr,
                        cwd=nextflow_install_dir,
                        env=instEnv
                    ).wait()
                    
                # Reading the output and error for the report
                if retval != 0:
                    with open(nxf_install_stdout.name,"r") as c_stF:
                        nxf_run_stdout_v = c_stF.read()
                    with open(nxf_install_stderr.name,"r") as c_stF:
                        nxf_run_stderr_v = c_stF.read()
        
        # And now the command is run
        if retval == 0  and isinstance(commandLine,list) and len(commandLine)>0:
            with tempfile.NamedTemporaryFile() as nxf_run_stdout:
                with tempfile.NamedTemporaryFile() as nxf_run_stderr:
                    retval = subprocess.Popen(
                        [cachedScript,*commandLine],
                        stdout=nxf_run_stdout,
                        stderr=nxf_run_stderr,
                        cwd=nextflow_install_dir  if workdir is None  else workdir,
                        env=instEnv
                    ).wait()
                    
                    # Reading the output and error for the report
                    with open(nxf_run_stdout.name,"r") as c_stF:
                        nxf_run_stdout_v = c_stF.read()
                    with open(nxf_run_stderr.name,"r") as c_stF:
                        nxf_run_stderr_v = c_stF.read()
                        
        return retval, nxf_run_stdout_v, nxf_run_stderr_v
    
    def runNextflowCommandInDocker(self,nextflow_version: EngineVersion, commandLine: List[str], workdir=None) -> Tuple[ExitVal,str,str]:
        # Now, we have to assure the nextflow image is already here
        docker_tag = self.nxf_image + ':' + nextflow_version
        checkimage_params = [
            self.docker_cmd, "images", "--format", "{{.ID}}\t{{.Tag}}", docker_tag
        ]

        retval = 0
        nxf_run_stdout_v = None
        nxf_run_stderr_v = None
        with tempfile.NamedTemporaryFile() as checkimage_stdout:
            with tempfile.NamedTemporaryFile() as checkimage_stderr:
                retval = subprocess.call(checkimage_params, stdout=checkimage_stdout, stderr=checkimage_stderr)

                if retval != 0:
                    # Reading the output and error for the report
                    with open(checkimage_stdout.name, "r") as c_stF:
                        nxf_run_stdout_v = c_stF.read()
                    with open(checkimage_stderr.name, "r") as c_stF:
                        nxf_run_stderr_v = c_stF.read()

                    errstr = "ERROR: Nextflow Engine failed while checking Nextflow image (retval {}). Tag: {}\n======\nSTDOUT\n======\n{}\n======\nSTDERR\n======\n{}".format(
                        retval, docker_tag, nxf_run_stdout_v, nxf_run_stderr_v)
                    
                    nxf_run_stderr_v = errstr
            
            do_pull_image = os.path.getsize(checkimage_stdout.name) == 0

        if retval == 0 and do_pull_image:
            # The image is not here yet
            pullimage_params = [
                self.docker_cmd, "pull", docker_tag
            ]
            with tempfile.NamedTemporaryFile() as pullimage_stdout:
                with tempfile.NamedTemporaryFile() as pullimage_stderr:
                    retval = subprocess.call(pullimage_params, stdout=pullimage_stdout, stderr=pullimage_stderr)
                    if retval != 0:
                        # Reading the output and error for the report
                        with open(pullimage_stdout.name, "r") as c_stF:
                            nxf_run_stdout_v = c_stF.read()
                        with open(pullimage_stderr.name, "r") as c_stF:
                            nxf_run_stderr_v = c_stF.read()

                        # It failed!
                        errstr = "ERROR: Nextflow Engine failed while pulling Nextflow image (retval {}). Tag: {}\n======\nSTDOUT\n======\n{}\n======\nSTDERR\n======\n{}".format(
                            retval, docker_tag, nxf_run_stdout_v, nxf_run_stderr_v)
                        
                        nxf_run_stderr_v = errstr
        
        if retval == 0  and isinstance(commandLine,list) and len(commandLine)>0:
            # TODO: run it!!!!
            nxf_run_stdout_v = ''
            
            #try:
            #    if workdir is None:
            #        workdir = tempfile.mkdtemp(prefix="WfExS-nxf-",suffix="-job")
            #    else:
            #        os.makedirs(workdir, exist_ok=True)
            #except Exception as error:
            #    raise WorkflowEngineException("ERROR: Unable to create nextflow working directory. Error: "+str(error))
            #
            ## Value needed to compose the Nextflow docker call
            #uid = str(os.getuid())
            #gid = str(os.getgid())
            #
            ## Timezone is needed to get logs properly timed
            #try:
            #    with open("/etc/timezone","r") as tzreader:
            #        tzstring = tzreader.readline().rstrip()
            #except:
            #    # The default for the worst case
            #    tzstring = 'Europe/Madrid'
            #
            #homedir = os.path.expanduser("~")
            #
            #nextflow_install_dir = os.path.join(self.weCacheDir,nextflow_version)
            #nxf_home = os.path.join(nextflow_install_dir,'.nextflow')
            #nxf_assets_dir = os.path.join(nxf_home,"assets")
            #try:
            #    # Directories required by Nextflow in a Docker
            #    os.makedirs(nxf_assets_dir, exist_ok=True)
            #except Exception as error:
            #    raise WorkflowEngineException("ERROR: Unable to create nextflow assets directory. Error: "+str(error))
            #
            ## The fixed parameters
            #nextflow_cmd_pre_vol = [
            #    self.docker_cmd, "run", "--rm", "--net", "host",
            #    "-e", "USER",
            #    "-e", "NXF_DEBUG",
            #    "-e", "TZ="+tzstring,
            #    "-e", "HOME="+homedir,
            #    "-e", "NXF_ASSETS="+nxf_assets_dir,
            #    "-e", "NXF_USRMAP="+uid,
            #    #"-e", "NXF_DOCKER_OPTS=-u "+uid+":"+gid+" -e HOME="+homedir+" -e TZ="+tzstring+" -v "+workdir+":"+workdir+":rw,rprivate,z -v "+project_path+":"+project_path+":rw,rprivate,z",
            #    "-e", "NXF_DOCKER_OPTS=-u "+uid+":"+gid+" -e HOME="+homedir+" -e TZ="+tzstring+" -v "+workdir+":"+workdir+":rw,rprivate,z",
            #    "-v", "/var/run/docker.sock:/var/run/docker.sock:rw,rprivate,z"
            #]
            #
            #validation_cmd_post_vol = [
            #    "-w", workdir,
            #    docker_tag,
            #    "nextflow"
            #]
            #validation_cmd_post_vol.extend(commandLine)
            #
            #validation_cmd_post_vol_resume = [ *validation_cmd_post_vol , '-resume' ]
            #
            ## This one will be filled in by the volume parameters passed to docker
            ##docker_vol_params = []
            #
            ## This one will be filled in by the volume meta declarations, used
            ## to generate the volume parameters
            #volumes = [
            #    (homedir+'/',"ro,rprivate,z"),
            ##    (nxf_assets_dir,"rprivate,z"),
            #    (workdir+'/',"rw,rprivate,z"),
            #    (project_path+'/',"rw,rprivate,z"),
            #    (repo_dir+'/',"ro,rprivate,z")
            #]
            #
            ## These are the parameters, including input and output files and directories
            #
            ## Parameters which are not input or output files are in the configuration
            #variable_params = [
            ##    ('challenges_ids',challenges_ids),
            ##    ('participant_id',participant_id)
            #]
            #for conf_key in self.configuration.keys():
            #    if conf_key not in self.MASKED_KEYS:
            #        variable_params.append((conf_key,self.configuration[conf_key]))
            #
            #
            #variable_infile_params = [
            #    ('input',input_loc),
            #    ('goldstandard_dir',goldstandard_dir_loc),
            #    ('public_ref_dir',public_ref_dir_loc),
            #    ('assess_dir',assess_dir_loc)
            #]
            #
            #variable_outfile_params = [
            #    ('statsdir',stats_loc+'/'),
            #    ('outdir',results_loc+'/'),
            #    ('otherdir',other_loc+'/')
            #]
            #
            ## The list of populable outputs
            #variable_outfile_params.extend(self.populable_outputs.items())
            #
            ## Preparing the RO volumes
            #for ro_loc_id,ro_loc_val in variable_infile_params:
            #    if os.path.exists(ro_loc_val):
            #        if ro_loc_val.endswith('/') and os.path.isfile(ro_loc_val):
            #            ro_loc_val = ro_loc_val[:-1]
            #        elif not ro_loc_val.endswith('/') and os.path.isdir(ro_loc_val):
            #            ro_loc_val += '/'
            #    volumes.append((ro_loc_val,"ro,rprivate,z"))
            #    variable_params.append((ro_loc_id,ro_loc_val))
            #
            ## Preparing the RW volumes
            #for rw_loc_id,rw_loc_val in variable_outfile_params:
            #    # We can skip integrating subpaths of project_path
            #    if os.path.commonprefix([os.path.normpath(rw_loc_val),project_path]) != project_path:
            #        if os.path.exists(rw_loc_val):
            #            if rw_loc_val.endswith('/') and os.path.isfile(rw_loc_val):
            #                rw_loc_val = rw_loc_val[:-1]
            #            elif not rw_loc_val.endswith('/') and os.path.isdir(rw_loc_val):
            #                rw_loc_val += '/'
            #        elif rw_loc_val.endswith('/'):
            #            # Forcing the creation of the directory
            #            try:
            #                os.makedirs(rw_loc_val)
            #            except:
            #                pass
            #        else:
            #            # Forcing the creation of the file
            #            # so docker does not create it as a directory
            #            with open(rw_loc_val,mode="a") as pop_output_h:
            #                logger.debug("Pre-created empty output file (ownership purposes) "+rw_loc_val)
            #                pass
            #        
            #        volumes.append((rw_loc_val,"rprivate,z"))
            #
            #    variable_params.append((rw_loc_id,rw_loc_val))
            #
            ## Assembling the command line    
            #validation_params = []
            #validation_params.extend(validation_cmd_pre_vol)
            #
            #for volume_dir,volume_mode in volumes:
            #    validation_params.append("-v")
            #    validation_params.append(volume_dir+':'+volume_dir+':'+volume_mode)
            #
            #validation_params_resume = [ *validation_params ]
            #
            #validation_params.extend(validation_cmd_post_vol)
            #validation_params_resume.extend(validation_cmd_post_vol_resume)
            #
            ## Last, but not the least important
            #validation_params_flags = []
            #for param_id,param_val in variable_params:
            #    validation_params_flags.append("--" + param_id)
            #    validation_params_flags.append(param_val)
            #
            #validation_params.extend(validation_params_flags)
            #validation_params_resume.extend(validation_params_flags)
            #
            ## Retries system was introduced because an insidious
            ## bug happens sometimes
            ## https://forums.docker.com/t/any-known-problems-with-symlinks-on-bind-mounts/32138
            #retries = self.max_retries
            #retval = -1
            #validation_params_cmd = validation_params
            #while retries > 0 and retval != 0:
            #    logger.debug('"'+'" "'.join(validation_params_cmd)+'"')
            #    sys.stdout.flush()
            #    sys.stderr.flush()
            #    
            #    retval = subprocess.call(validation_params_cmd,stdout=sys.stdout,stderr=sys.stderr)
            #    if retval != 0:
            #        retries -= 1
            #        logger.debug("\nFailed with {} , left {} tries\n".format(retval,retries))
            #        validation_params_cmd = validation_params_resume
            
        return retval, nxf_run_stdout_v, nxf_run_stderr_v
    
    
    # Pattern for searching for process\..*container = ['"]([^'"]+)['"] in dumped config
    ContConfigPat = re.compile(r"process\..*container = '(.+)'$",flags=re.MULTILINE)
    # Pattern for searching for container ['"]([^'"]+)['"] in main workflow
    ContScriptPat = re.compile(r"^\s*container\s+['\"]([^'\"]+)['\"]")
    
    def materializeWorkflow(self, matWorkflowEngine: MaterializedWorkflowEngine) -> Tuple[MaterializedWorkflowEngine, List[ContainerTaggedName]]:
        """
        Method to ensure the workflow has been materialized. It returns the 
        localWorkflow directory, as well as the list of containers
        
        For Nextflow it is usually a no-op, but for CWL it requires resolution
        """

        # Default nextflow profile is 'standard'
        # parse
        # nextflow config -flat
        localWf = matWorkflowEngine.workflow
        flat_retval , flat_stdout, flat_stderr = self.runNextflowCommand(
            matWorkflowEngine.version,
            ['config','-flat',localWf.dir],
            workdir=localWf.dir,
            nextflow_path=matWorkflowEngine.engine_path
        )
        
        if flat_retval != 0:
            errstr = """Could not obtain the flat workflow config Nextflow (fingerprint {}) . Retval {}
======
STDOUT
======
{}

======
STDERR
======
{}""".format(matWorkflowEngine.fingerprint,flat_retval,flat_stdout,flat_stderr)
            raise WorkflowEngineException(errstr)
        
        # searching for process\..*container = ['"]([^'"]+)['"]
        containerTags = set()
        for contMatch in self.ContConfigPat.finditer(flat_stdout):
            containerTags.add(contMatch.group(1))
        
        # and main workflow for
        # container ['"]([^'"]+)['"]
        wfEntrypoint = localWf.relPath  if os.path.isabs(localWf.relPath)  else os.path.join(localWf.dir,localWf.relPath)
        with open(wfEntrypoint,encoding='utf-8') as wfH:
            for line in wfH:
                contMatch = self.ContScriptPat.search(line)
                if contMatch:
                    containerTags.add(contMatch.group(1))
        
        
        return matWorkflowEngine, list(containerTags)
    
    def simpleContainerFileName(self, imageUrl: URIType) -> RelPath:
        """
        This method was borrowed from
        https://github.com/nextflow-io/nextflow/blob/539a22b68c114c94eaf4a88ea8d26b7bfe2d0c39/modules/nextflow/src/main/groovy/nextflow/container/SingularityCache.groovy#L80
        and translated to Python
        """
        p = imageUrl.find('://')
        name = imageUrl[p+3:]  if p != -1   else imageUrl
        extension = '.img'
        if '.sif:' in name:
            extension = '.sif'
            name = name.replace('.sif:','-')
        elif name.endswith('.sif'):
            extension = '.sif'
            name = name[:-4]
        
        name = name.replace(':','-').replace('/','-')
        
        return name + extension
    
    def launchWorkflow(self, matWfEng: MaterializedWorkflowEngine, inputs: List[MaterializedInput], outputs: List[ExpectedOutput]) -> Tuple[ExitVal,List[MaterializedInput],List[MaterializedOutput]]:
        localWf = matWfEng.workflow
        launch_retval , launch_stdout, launch_stderr = self.runNextflowCommand(
            matWfEng.version,
            ['config','-flat',localWf.dir],
            workdir=localWf.dir,
            nextflow_path=matWfEng.engine_path
        )
        
        """
        docker.enabled = false
        singularity.enabled = true
        singularity.autoMounts = true
        """
        # TODO
        pass    
