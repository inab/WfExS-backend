# ![WfExS-backend:](docs/logo/WfExS-logo-final_paths.svg) Workflow Execution Service backend

WfExS (which could be pronounced like "why-fex", "why-fix" or "why-fixes") project aims to automate next steps:

* Fetch and cache a workflow from either:
  * A TRSv2-enabled [WorkflowHub](https://workflowhub.eu) instance (which provides RO-Crates).
  * A TRSv2 (2.0.0-beta2 or 2.0.0) enabled service. Currently tested with [Dockstore](https://dockstore.org).
  * A straight URL to an existing [RO-Crate](https://www.researchobject.org/ro-crate/) in ZIP archive describing a workflow.
  * A git repository ([using this syntax](https://pip.pypa.io/en/stable/cli/pip_install/#git) for the URI)
  * A public GitHub URL (like [this example](https://raw.githubusercontent.com/inab/ipc_workflows/cosifer-20210322/cosifer/cwl/cosifer-workflow.cwl)).
* Identify the kind of workflow.
* Fetch and set up workflow execution engine (currently supported [Nextflow](https://www.nextflow.io/)
and [cwltool](https://github.com/common-workflow-language/cwltool)).
* Identify the needed containers by the workflow, and fetch/cache them. Depending on the local setup, `singularity`, `docker`, `podman` or none of them will be used.
* Fetch and cache the inputs, represented either through an URL or a [CURIE-represented](https://en.wikipedia.org/wiki/CURIE) PID (public [persistent identifier](https://en.wikipedia.org/wiki/Persistent_identifier)).
* Execute the workflow in a secure way, if it was requested.
* Optionally describe the results through an [RO-Crate](https://www.researchobject.org/ro-crate/), and upload both RO-Crate and the results elsewhere in a secure way.

## Relevant docs:

* [INSTALL.md](INSTALL.md): In order to use WfExS-backend you have to install first at least core dependencies described there.

* [TODO.md](TODO.md): This development is relevant for projects like [EOSC-Life](https://www.eosc-life.eu/) or [EJP-RD](https://www.ejprarediseases.org/). The list of high level scheduled and pending developments can be seen at .

* [README_LIFECYCLE.md](README_LIFECYCLE.md): WfExS-backend analysis lifecycle and usage scenarios are briefly described with flowcharts there.

* [README_REPLICATOR.md](README_REPLICATOR.md): It briefly describes `WfExS-config-replicator.py` usage.

Additional present and future documentation is hosted at [docs](docs/index.md) subfolder, until it is migrated to a proper documentation service.

### Presentations and outreach

Laura Rodríguez-Navas (2021): 
[**WfExS: a software component to enable the use of RO-Crate in the EOSC-Life collaboratory**](https://osf.io/tb5ku/).  
_FAIR Digital Object Forum_, [CWFR & FDO SEM meeting](https://osf.io/v8xjz/), 2021-07-02
[[video recording](https://osf.io/wna42/)], [[slides](https://osf.io/tb5ku/)]

Laura Rodríguez-Navas (2021):  
[**WfExS: a software component to enable the use of RO-Crate in the EOSC-Life tools collaboratory**](https://repository.eoscsecretariat.eu/index.php/s/ERebmpJcyjFRqcx/download?path=%2F17%20June%2F1400%20-%20Technical%20challenges%20on%20EOSC%2FBreakout%203%20-%20Interoperability%20challenges%20for%20thematic%20communities&files=05%20-%20Laura%20Rodr%C3%ADguez-Navas%20-%20WfExS.pdf&downloadStartSecret=zwwx23xrow).  
_[EOSC Symposium 2021](https://www.eoscsecretariat.eu/eosc-symposium-2021-programme)_, 2021-06-17
[[video recording](https://youtu.be/x5lLEym-gug?list=PLbISfqJh3Tstmx6CgrBmYI7lyyVXiY5VE&t=3238)]
[[slides](https://drive.google.com/file/d/1LJkmI_gyl9VnuQ2_ZHBGeFkt_QTWFieg/view)

Salvador Capella-Gutierrez (2021):  
[**Demonstrator 7: Accessing human sensitive data from analytical workflows available to everyone in EOSC-Life**](https://www.eosc-life.eu/d7/)  
_Populating EOSC-Life: Success stories from the demonstrators_, 2021-01-19.
<https://www.eosc-life.eu/d7/>
[[video](https://www.youtube.com/watch?v=saLxJpejCj0)] [[slides](http://www.eosc-life.eu/wp-content/uploads/2021/02/D7_Wrap-up.pdf)]

Bietrix, Florence; Carazo, José Maria; Capella-Gutierrez, Salvador; Coppens, Frederik; Chiusano, Maria Luisa; David, Romain; Fernandez, Jose Maria; Fratelli, Maddalena; Heriche, Jean-Karim; Goble, Carole; Gribbon, Philip; Holub, Petr; P. Joosten, Robbie; Leo, Simone; Owen, Stuart; Parkinson, Helen; Pieruschka, Roland; Pireddu, Luca; Porcu, Luca; Raess, Michael; Rodriguez- Navas, Laura; Scherer, Andreas; Soiland-Reyes, Stian; Tang, Jing (2021):  
[**EOSC-Life Methodology framework to enhance reproducibility within EOSC-Life**](https://zenodo.org/record/4705078/files/EOSC-Life_D8.1_Methodology%20framework%20to%20enhance%20reproducibility%20within%20EOSC-Life_April-2021.pdf).  
EOSC-Life deliverable D8.1, _Zenodo_
<https://doi.org/10.5281/zenodo.4705078>


## WfExS-backend Usage

```bash
python WfExS-backend.py --full-help
```
```
usage: WfExS-backend.py [-h] [--log-file LOGFILENAME] [-q] [-v] [-d] [-L LOCALCONFIGFILENAME] [--cache-dir CACHEDIR] [-V]
                        [--full-help]
                        {init,cache,staged-workdir,config-validate,stage,mount-workdir,export-stage,offline-execute,execute,export-results,export-crate}
                        ...

WfExS (workflow execution service) backend 0.4.13-4-g8b97a32 (8b97a328d3163cb4295a09dae6def45341e2acca)

optional arguments:
  -h, --help            show this help message and exit
  --log-file LOGFILENAME
                        Store messages in a file instead of using standard error and standard output (default: None)
  -q, --quiet           Only show engine warnings and errors (default: None)
  -v, --verbose         Show verbose (informational) messages (default: None)
  -d, --debug           Show debug messages (use with care, as it can disclose passphrases and passwords) (default: None)
  -L LOCALCONFIGFILENAME, --local-config LOCALCONFIGFILENAME
                        Local installation configuration file (default: /home/jmfernandez/projects/WfExS-
                        backend/wfexs_config.yml)
  --cache-dir CACHEDIR  Caching directory (default: None)
  -V, --version         show program's version number and exit
  --full-help           It returns full help (default: False)

commands:
  Command to run. It must be one of these

  {init,cache,staged-workdir,config-validate,stage,mount-workdir,export-stage,offline-execute,execute,export-results,export-crate}
    init                Init local setup
    cache               Cache handling subcommands
    staged-workdir      Staged working directories handling subcommands
    config-validate     Validate the configuration files to be used for staging and execution
    stage               Prepare the staging (working) directory for workflow execution, fetching dependencies and contents
    mount-workdir       Mount the encrypted staging directory on secure staging scenarios
    export-stage        Export the staging directory as an RO-Crate
    offline-execute     Execute an already prepared workflow in the staging directory
    execute             Execute the stage + offline-execute + export steps
    export-results      Export the results to a remote location, gathering their public ids
    export-crate        Export an already executed workflow in the staging directory as an RO-Crate

Subparser 'init'
usage: WfExS-backend.py init [-h]

optional arguments:
  -h, --help  show this help message and exit

Subparser 'cache'
usage: WfExS-backend.py cache [-h] [-r] [--cascade] [-g]
                              {ls,inject,fetch,rm,validate} {input,ro-crate,ga4gh-trs,workflow}
                              [cache_command_args [cache_command_args ...]]

positional arguments:
  {ls,inject,fetch,rm,validate}
                        Cache command to perform
                        
                        ls          List the cache entries
                        inject      Inject a new entry in the cache
                        fetch       Fetch a new cache entry, giving as input both the URI and optionally both a security context file and a security context name
                        rm          Remove an entry from the cache
                        validate    Validate the consistency of the cache
  {input,ro-crate,ga4gh-trs,workflow}
                        Cache type to perform the cache command
                        
                        input       Cached or injected inputs
                        ro-crate    Cached RO-Crates (usually from WorkflowHub)
                        ga4gh-trs   Cached files from tools described at GA4GH TRS repositories
                        workflow    Cached workflows, which come from a git repository
  cache_command_args    Optional cache element names (default: None)

optional arguments:
  -h, --help            show this help message and exit
  -r                    Try doing the operation recursively (i.e. both metadata and data) (default: False)
  --cascade             Try doing the operation in cascade (including the URIs which resolve to other URIs) (default: False)
  -g, --glob            Given cache element names are globs (default: False)

Subparser 'staged-workdir'
usage: WfExS-backend.py staged-workdir [-h] [-g]
                                       {offline-exec,ls,mount,rm,shell,status}
                                       [staged_workdir_command_args [staged_workdir_command_args ...]]

positional arguments:
  {offline-exec,ls,mount,rm,shell,status}
                        Staged working directory command to perform
                        
                        offline-exec    Offline execute the staged instances which match the input pattern
                        ls              List the staged instances
                                It shows the instance id, nickname,
                                encryption and whether they are damaged
                        mount           Mount the staged instances which match the input pattern
                        rm              Removes the staged instances which match the input pattern
                        shell           Launches a command in the workdir
                                First parameter is either the staged instance id or the nickname.
                                It launches the command specified after the id.
                                If there is no additional parameters, it launches a shell
                                in the mounted working directory of the instance
                        status          Shows staged instances status
  staged_workdir_command_args
                        Optional staged working directory element names (default: None)

optional arguments:
  -h, --help            show this help message and exit
  -g, --glob            Given staged workflow names are globs (default: False)

Subparser 'config-validate'
usage: WfExS-backend.py config-validate [-h] -W WORKFLOWCONFIGFILENAME [-Z SECURITYCONTEXTSCONFIGFILENAME] [-n NICKNAME_PREFIX]

optional arguments:
  -h, --help            show this help message and exit
  -W WORKFLOWCONFIGFILENAME, --workflow-config WORKFLOWCONFIGFILENAME
                        Configuration file, describing workflow and inputs (default: None)
  -Z SECURITYCONTEXTSCONFIGFILENAME, --creds-config SECURITYCONTEXTSCONFIGFILENAME
                        Configuration file, describing security contexts, which hold credentials and similar (default: None)
  -n NICKNAME_PREFIX, --nickname-prefix NICKNAME_PREFIX
                        Nickname prefix to be used on staged workdir creation (default: None)

Subparser 'stage'
usage: WfExS-backend.py stage [-h] -W WORKFLOWCONFIGFILENAME [-Z SECURITYCONTEXTSCONFIGFILENAME] [-n NICKNAME_PREFIX]

optional arguments:
  -h, --help            show this help message and exit
  -W WORKFLOWCONFIGFILENAME, --workflow-config WORKFLOWCONFIGFILENAME
                        Configuration file, describing workflow and inputs (default: None)
  -Z SECURITYCONTEXTSCONFIGFILENAME, --creds-config SECURITYCONTEXTSCONFIGFILENAME
                        Configuration file, describing security contexts, which hold credentials and similar (default: None)
  -n NICKNAME_PREFIX, --nickname-prefix NICKNAME_PREFIX
                        Nickname prefix to be used on staged workdir creation (default: None)

Subparser 'mount-workdir'
usage: WfExS-backend.py mount-workdir [-h] -J WORKFLOWWORKINGDIRECTORY

optional arguments:
  -h, --help            show this help message and exit
  -J WORKFLOWWORKINGDIRECTORY, --staged-job-dir WORKFLOWWORKINGDIRECTORY
                        Already staged job directory (default: None)

Subparser 'export-stage'
usage: WfExS-backend.py export-stage [-h] -J WORKFLOWWORKINGDIRECTORY [--full]

optional arguments:
  -h, --help            show this help message and exit
  -J WORKFLOWWORKINGDIRECTORY, --staged-job-dir WORKFLOWWORKINGDIRECTORY
                        Already staged job directory (default: None)
  --full                Should the RO-Crate contain a copy of the inputs (and outputs)? (default: False)

Subparser 'offline-execute'
usage: WfExS-backend.py offline-execute [-h] -J WORKFLOWWORKINGDIRECTORY

optional arguments:
  -h, --help            show this help message and exit
  -J WORKFLOWWORKINGDIRECTORY, --staged-job-dir WORKFLOWWORKINGDIRECTORY
                        Already staged job directory (default: None)

Subparser 'execute'
usage: WfExS-backend.py execute [-h] -W WORKFLOWCONFIGFILENAME [-Z SECURITYCONTEXTSCONFIGFILENAME] [-n NICKNAME_PREFIX] [--full]

optional arguments:
  -h, --help            show this help message and exit
  -W WORKFLOWCONFIGFILENAME, --workflow-config WORKFLOWCONFIGFILENAME
                        Configuration file, describing workflow and inputs (default: None)
  -Z SECURITYCONTEXTSCONFIGFILENAME, --creds-config SECURITYCONTEXTSCONFIGFILENAME
                        Configuration file, describing security contexts, which hold credentials and similar (default: None)
  -n NICKNAME_PREFIX, --nickname-prefix NICKNAME_PREFIX
                        Nickname prefix to be used on staged workdir creation (default: None)
  --full                Should the RO-Crate contain a copy of the inputs (and outputs)? (default: False)

Subparser 'export-results'
usage: WfExS-backend.py export-results [-h] -J WORKFLOWWORKINGDIRECTORY

optional arguments:
  -h, --help            show this help message and exit
  -J WORKFLOWWORKINGDIRECTORY, --staged-job-dir WORKFLOWWORKINGDIRECTORY
                        Already staged job directory (default: None)

Subparser 'export-crate'
usage: WfExS-backend.py export-crate [-h] -J WORKFLOWWORKINGDIRECTORY [--full]

optional arguments:
  -h, --help            show this help message and exit
  -J WORKFLOWWORKINGDIRECTORY, --staged-job-dir WORKFLOWWORKINGDIRECTORY
                        Already staged job directory (default: None)
  --full                Should the RO-Crate contain a copy of the inputs (and outputs)? (default: False)

```

WfExS commands are:

![WfExS-backend commands](docs/wfexs-commands.svg)

* `init`: This command is used to initialize a WfExS installation. It takes a local configuration file through `-L` parameter, and it can both generate crypt4gh paired keys for installation work and identification purposes and update the path to them in case they are not properly defined. Those keys are needed to decrypt encrypted working directories, and in the future to decrypt secure requests and encrypt secure results.

* `config-validate`: This command is used to validate workflow staging configuration file, as well as its paired security context configuration file using the corresponding JSON Schemas. It honours `-L`, `-W` and `-Z` parameters. If command is not set, this is the default command to be run.

* `stage`: This command is used to first validate workflow staging and security context configuration files, then fetch all the workflow preconditions and files, staging them for an execution. It honours `-L`, `-W` and `-Z` parameters, and once the staging is finished it prints the path to the parent execution environment.

* `export-stage` _(to be done)_: This command is complementary to `stage`. It recognizes `-L` parameter, and depends on `-J` parameter to locate the execution environment directory to be used, properly staged through `stage`. It will bundle the description of the staged environment in an RO-Crate, in order to be reused later, or uploaded to places like WorkflowHub. All of this assuming there is an stage there.

* `offline-execute`: This command is complementary to `stage`. It recognizes `-L` parameter, and depends on `-J` parameter to locate the execution environment directory to be used, properly staged through `stage`. It executes the workflow, assuming all the preconditions are in place.

* `export-results` _(to be finished)_: This command is complementary to `offline-execute`. It recognizes `-L` parameter, and depends on `-J` parameter to locate the execution environment directory to be used, properly staged through `stage` and executed through `offline-execute`. It export the results from an execution at a working directory, assuming there is an execution there. Export rules should be described in the file used in `-W` parameter when the working directory was staged.

* `export-crate` _(to be finished)_: This command is complementary to `export-results`. It recognizes `-L` parameter, and depends on `-J` parameter to locate the execution environment directory to be used, properly staged through `stage` and executed through `offline-execute` and `export-results`. It bundles the metadata and provenance results from an execution at a working directory in an RO-Crate, assuming there is an execution there.

* `mount-workdir`: This command is a helper to inspect encrypted execution environments, as it mounts its working directory for a limited time. As `export-stage`, `offline-execute` or `export-results`, it recognizes `-L` parameter and depends on `-J` parameter.

* `execute`: This command's behaviour is equivalent to `stage` followed by `offline-execute`, `export-results` and `export-crate`.

When the execution has finished properly, the working directory `outputs` subdirectory should contain both the outputs and an `execution.crate.zip`, which can be used to create a workflow entry in <https://workflowhub.eu>.

## Configuration files

The program uses three different types of configuration files:

* Local configuration file: YAML formatted file which describes the local setup of the backend (example at [tests/local_config.yaml](tests/local_config.yaml)). JSON Schema describing the format (and used for validation) is available at [wfexs_backend/schemas/config.json](wfexs_backend/schemas/config.json) and there is also automatically generated documentation (see [config_schema.md](docs/schemas/config_schema.md)). Relative paths in this configuration file use as reference the directory where the local configuration file is living.
  
  - `cacheDir`: The path in this key sets up the place where all the contents which can be cached are hold. It contains downloaded RO-Crate,
     downloaded workflow git repositories, downloaded workflow engines. It is recommended to have it outside `/tmp` directory when
     Singularity is being used, due undesirable side interactions with the way workflow engines use Singularity.
  
  - `workDir`: The path in this key sets up the place where all the executions are going to store both intermediate and final results,
    having a separate directory for each execution. It is recommended to have it outside `/tmp` directory when Singularity is being
    used, due undesirable side interactions with the way workflow engines use Singularity.
  
  - `crypt4gh.key`: The path to the secret key used in this installation. It is paired to `crypt4gh.pub`.
  
  - `crypt4gh.pub`: The path to the public key used in this installation. It is paired to `crypt4gh.key`.
  
  - `crypt4gh.passphrase`: The passphrase needed to decrypt the contents of `crypt4gh.key`.
  
  - `tools.engineMode`: Currently, local mode only.
  
  - `tools.containerType`: Currently, `singularity`, `docker` or `podman`.
  
  - `tools.gitCommand`: Path to `git` command (only used when needed)

  - `tools.dockerCommand`: Path to `docker` command (only used when needed)

  - `tools.singularityCommand`: Path to `singularity` command (only used when needed)

  - `tools.podmanCommand`: Path to `podman` command (only used when needed)

  - `tools.javaCommand`: Path to `java` command (only used when needed)
  
  - `tools.encrypted_fs.type`: Kind of FUSE encryption filesystem to use for secure working directories. Currently, both `gocryptfs` and `encfs` are supported.
  
  - `tools.encrypted_fs.command`: Command path to be used to mount the secure working directory. The default depends on value of `tools.encrypted_fs.type`.
  
  - `tools.encrypted_fs.fusermount_command`: Command to be used to unmount the secure working directory. Defaults to `fusermount`.
  
  - `tools.encrypted_fs.idle`: Number of minutes of inactivity before the encrypted FUSE filesystem is automatically unmounted. The default is 5 minutes.
  
* Workflow configuration file: YAML formatted file which describes the workflow staging before being executed, like where inputs are located and can be fetched, the security contexts to be used on specific inputs to get those controlled access resources, the parameters, the outputs to capture, ... ([Nextflow example](tests/wetlab2variations_execution_nxf.wfex.stage), [CWL example](tests/wetlab2variations_execution_cwl.wfex.stage)). JSON Schema describing the format and valid keys (and used for validation), is available at [wfexs_backend/schemas/stage-definition.json](wfexs_backend/schemas/stage-definition.json) and there is also automatically generated documentation (see [stage-definition_schema.md](docs/schemas/stage-definition_schema.md)).

* Security contexts file: YAML formatted file which holds the `user`/`password` pairs, security tokens or keys needed on different steps, like input fetching. ([Nextflow example](tests/wetlab2variations_credentials_nxf.wfex.ctxt), [CWL example](tests/wetlab2variations_credentials_cwl.wfex.ctxt)). JSON Schema describing the format and valid keys (and used for validation), is available at [wfexs_backend/schemas/security-context.json](wfexs_backend/schemas/security-context.json) and there is also automatically generated documentation (see [security-context_schema.md](docs/schemas/security-context_schema.md)).

## License
* © 2020-2021 Barcelona Supercomputing Center (BSC), ES

Licensed under the Apache License, version 2.0 <https://www.apache.org/licenses/LICENSE-2.0>, see the file `LICENSE.txt` for details.
