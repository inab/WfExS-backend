# WfExS-backend official roadmap and informal TODO

- [x] **Step 0**: Materialize Nextflow and CWL workflows from WorkflowHub. Downloading an RO-Crate using the TRS API of 
WorkflowHub to materialize workflows.

- [x] **Step 1**: Materialize remote repositories that contains the materialized workflows.

- [x] **Step 2**: Materialize inputs to launch the workflows. Using a file that contains the ids or data 
references to the inputs, that we are going to use to instantiate the workflows. For example: 
([wetlab2variations_execution_cwl.yaml](https://github.com/inab/WfExS-backend/blob/main/tests/wetlab2variations_execution_cwl.yaml))

- [x] **Step 3**: Setup Nextflow and CWL engines.

- [x] **Step 4**: Validate workflows and materialize their containers. 

- [x] **Step 5**: Launch the workflows in an execution environment.

  - [x] **Step 5.a**: Launch workflows in a FUSE encrypted filesystem.
  
  - [x] **Step 5.b**: Launch CWL workflows in an execution environment.
  
  - [x] **Step 5.c**: Launch Nextlfow workflows in an execution environment.

- [ ] **Step 6**: Integrate the use of [Crypt4GH](https://crypt4gh.readthedocs.io/en/latest/) into the process when requested, so outputs are encrypted for the researcher, allowing moving them with no data disclose.

  - [x] **Step 6.a**: Use Crypt4GH to encrypt the passphrase of FUSE encrypted execution working directories.

  - [ ] **Step 6.b**: Use Crypt4GH to decrypt a secure request to the installation.

  - [ ] **Step 6.c**: Use Crypt4GH to decrypt EGA input files.

- [ ] **Step 7**: Add upload capabilities of results: Nextcloud / B2DROP.
  
  - [ ] **Step 7.future**: Add upload capabilities of results and metadata (RO-Crate): B2SHARE.

- [ ] **Step 8**: Create execution provenance, which includes uploading URLs of results and / or DOIs / URIs.

- [ ] **Step 9**: Generate RO-Crate from execution provenance.

  - [ ] **Step 9.a**: Use Crypt4GH to encrypt with crypt4gh the generated RO-Crate.

  - [x] **Step 9.b**: Generated RO-Crate should be consumable by WorkflowHub.

  - [ ] **Step 9.c**: Generated RO-Crate should be consumable by WfExS-backend.
  
  - [ ] **Step 9.d**: Add full circle capabilities. Re-execute workflow with the very same parameters from previously generated RO-Crate.

- [ ] **Step 10**: Add upload capabilities of metadata (RO-Crate): Nextcloud / B2DROP.

  - [ ] **Step 10.future**: Add upload capabilities of metadata (RO-Crate): B2SHARE.


## Other features

- [ ] Create a JSON Schema formally describing the different configuration files.

- [ ] Supporting `file` protocol and lean and mean paths, so WfExS can be used with local routes and paths. The main drawback is that RO-Crate provenance can suffer in these scenarios, as it is not provided a public URL/URI.

- [ ] Supporting post-process steps on inputs, which allow implementing decrypt crypt4gh encrypted files from EGA.

- [ ] Supporting post-process steps on outputs, which allow implementing encrypt as crypt4gh files the designated results.

- [ ] Generate an abstract CWL description of a workflow execution. In the case of CWL will be a no-op, in the case of Nextflow it will use execution provenance.

- [ ] Integrate GA4GH API providers which do not support returning an RO-Crate [dockstore.org](https://dockstore.org/search?searchMode=files).
  - Example:
    - https://dockstore.org/api/api/ga4gh/v2/tools/#workflow/github.com/smc-rna-challenge/zhanghj-8639902/zhanghj-8639902
    - https://dockstore.org/api/api/ga4gh/v2/tools/#workflow/github.com/smc-rna-challenge/zhanghj-8639902/zhanghj-8639902/versions/master/CWL/files
