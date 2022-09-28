# ![WfExS-backend:](docs/logo/WfExS-logo-final_paths.svg) Workflow Execution Service backend


## WfExS-config-replicator usage

Example and usage of this tool, which helps generating a bunch of workflow instantiation files
from a template one and an Excel or CSV file with the fields to substitute:

```bash
python WfExS-config-replicator.py -W workflow_examples/wetlab2variations_execution_nxf.wfex.stage --params-file workflow_examples/wetlab2variations_execution_nxf.variations.xlsx /tmp/generated
```

```
python WfExS-config-replicator.py -h
usage: WfExS-config-replicator.py [-h] -W WORKFLOWCONFIGFILENAME
                                  (-p PARAM_NAME VALUE | --params-file PARAMS_FILES)
                                  [--fname-template FILENAME_TEMPLATE]
                                  [--symbol-template PARAMSYMBOLTEMPLATE]
                                  [destdir]

WfExS config replicator

positional arguments:
  destdir               Directory where all the variations of the workflow
                        configuration file are going to be created

optional arguments:
  -h, --help            show this help message and exit
  -W WORKFLOWCONFIGFILENAME, --workflow-config WORKFLOWCONFIGFILENAME
                        Workflow configuration file, to be used as template
  -p PARAM_NAME VALUE, --param PARAM_NAME VALUE
                        Param to substitute. Repeat to tell arrays of values
  --params-file PARAMS_FILES
                        Tabular params file with the different variations
  --fname-template FILENAME_TEMPLATE
                        Filename template for the created workflows
  --symbol-template PARAMSYMBOLTEMPLATE
```

## License
* © 2020-2022 Barcelona Supercomputing Center (BSC), ES

Licensed under the Apache License, version 2.0 <https://www.apache.org/licenses/LICENSE-2.0>, see the file `LICENSE.txt` for details.
