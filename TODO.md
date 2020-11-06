# TODO

- [x] **Step 0**: Materialize Nextflow and CWL workflows from WorkflowHub. Downloading an RO-Crate using the TRS API of 
WorkflowHub to materialize workflows.

- [x] **Step 1**: Materialize remote repositories that contains the materialized workflows.

- [x] **Step 2**: Materialize inputs to launch the workflows. Using a file that contains the ids or data 
references to the inputs, that we are going to use to instantiate the workflows. For example: 
([wetlab2variations_execution_cwl.yaml](https://github.com/inab/WfExS-backend/blob/main/tests/wetlab2variations_execution_cwl.yaml))

- [x] **Step 3**: Setup Nextflow and CWL engines.

- [ ] **Step 4**: Validate workflows and materialize their containers. 

- [ ] **Step 5**: Launch the workflows in an execution environment.

## Next Steps

- Integrate GA4GH API [dockstore.org](https://dockstore.org/search?searchMode=files).
- Example:
  - https://dockstore.org/api/api/ga4gh/v2/tools/#workflow/github.com/smc-rna-challenge/zhanghj-8639902/zhanghj-8639902
  - https://dockstore.org/api/api/ga4gh/v2/tools/#workflow/github.com/smc-rna-challenge/zhanghj-8639902/zhanghj-8639902/versions/master/CWL/files
