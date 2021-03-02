# ![WfExS-backend:](docs/logo/WfExS-logo-final_paths.svg) Workflow Execution Service backend

WfExS (which is pronounced like "why-fex") project aims to fetch a workflow from a TRS-enabled [WorkflowHub](https://workflowhub.eu) instance,
fetch the inputs and workflow execution engine (currently working on [Nextflow](https://www.nextflow.io/)
and [cwltool](https://github.com/common-workflow-language/cwltool)), and execute the workflow in a
secure way.

This development is relevant for projects like [EOSC-Life](https://www.eosc-life.eu/) or [EJP-RD](https://www.ejprarediseases.org/). The list of high level scheduled and pending developments can be seen at [TODO.md](TODO.md).

In order to use it you have to install first the dependencies described at [INSTALL.md](INSTALL.md). The usage is:

```
python WfExS-backend.py -h
usage: WfExS-backend.py [-h] [-L LOCALCONFIGFILENAME] [--cache-dir CACHEDIR]
                        -W WORKFLOWCONFIGFILENAME
                        [-Z SECURITYCONTEXTSCONFIGFILENAME]
                        [{stage,offline-execute,execute}]

WfExS (workflow execution service) backend

positional arguments:
  {stage,offline-execute,execute}
                        Command to run

optional arguments:
  -h, --help            show this help message and exit
  -L LOCALCONFIGFILENAME, --local-config LOCALCONFIGFILENAME
                        Local installation configuration file
  --cache-dir CACHEDIR  Caching directory
  -W WORKFLOWCONFIGFILENAME, --workflow-config WORKFLOWCONFIGFILENAME
                        Configuration file, describing workflow and inputs
  -Z SECURITYCONTEXTSCONFIGFILENAME, --creds-config SECURITYCONTEXTSCONFIGFILENAME
                        Configuration file, describing security contexts,
                        which hold credentials and similar
```

There program takes three configuration files, being only one required:

* Local configuration file: It describes the local setup of the backend (example at [tests/local_config.yaml](tests/local_config.yaml)).
  
  - `cacheDir`: The path in this key sets up the place where all the contents which can be cached are hold. It contains downloaded RO-Crate,
     downloaded workflow git repositories, downloaded workflow engines.
  
  - `workDir`: The path in this key sets up the place where all the executions are going to store both intermediate and final results,
    having a separate directory for each execution.
  
  - `tools.engineMode`: Currently, local mode only.
  
  - `tools.containerType`: Currently, singulary.
  
  - `tools.gitCommand`: Path to git command

  - `tools.dockerCommand`: Path to docker command (only used when needed)

  - `tools.singularityCommand`: Path to singularity command (only used when needed)

  - `tools.javaCommand`: Path to java command (only used when needed)
  
* Workflow configuration file (required): _TO BE DOCUMENTED_ ([Nextflow example](tests/wetlab2variations_execution_nxf.yaml), [CWL example](tests/wetlab2variations_execution_cwl.yaml)).

* Security contexts file: _TO BE DOCUMENTED_ ([Nextflow example](tests/wetlab2variations_credentials_nxf.yaml), [CWL example](tests/wetlab2variations_credentials_cwl.yaml)).


# Flowchart

![WfExS-backend flowchart](docs/wfexs-flowchart.svg)
