# WfExS-backend official roadmap and informal TODO

- [x] **Step 0**: Materialize Nextflow and CWL workflows from WorkflowHub. Downloading an RO-Crate using the TRS API of 
WorkflowHub to materialize workflows.

- [x] **Step 1**: Materialize remote repositories that contains the materialized workflows.

- [x] **Step 2**: Materialize inputs to launch the workflows. Using a file that contains the ids or data 
references to the inputs, that we are going to use to instantiate the workflows. For example: 
([wetlab2variations_execution_cwl.yaml](https://github.com/inab/WfExS-backend/blob/main/workflow_examples/wetlab2variations_execution_cwl.yaml))

- [x] **Step 3**: Setup Nextflow and CWL engines.

- [x] **Step 4**: Validate workflows and materialize their containers. 

- [x] **Step 5**: Launch the workflows in an execution environment.

  - [x] **Step 5.a**: Launch workflows in a FUSE encrypted filesystem.
  
  - [x] **Step 5.b**: Launch CWL workflows in an execution environment.
  
  - [x] **Step 5.c**: Launch Nextflow workflows in an execution environment.

  - [ ] **Step 5.d**: Generalize the number of workflows which can share the same working directory, so outputs of one can feed inputs of others.

- [ ] **Step 6**: Integrate or delegate the use of [Crypt4GH](https://crypt4gh.readthedocs.io/en/latest/) into the process when requested, so outputs are encrypted for the researcher, allowing moving them with no data disclose.

  - [x] **Step 6.a**: Use Crypt4GH to encrypt the passphrase of FUSE encrypted execution working directories.

  - [ ] **Step 6.b**: Create a micro CWL workflow which uses Crypt4GH to decrypt one or more files (depends on `5.d`).

  - [ ] **Step 6.c**: Create a micro CWL workflow which uses Crypt4GH to encrypt one or more files (depends on `5.d`).

- [x] **Step 7**: Add upload capabilities of results, which generate permanent identifiers.

  - [x] **Step 7.a**: Upload to cache system.

  - [ ] **Step 7.b**: Upload to WebDAV server.

  - [ ] **Step 7.c**: Upload to FTP server.

  - [ ] **Step 7.d**: Upload to SFTP server.

  - [x] **Step 7.e**: Upload to Nextcloud and generate share link.

  - [ ] **Step 7.f**: Upload workflow to WorkflowHub.

  - [x] **Step 7.g**: Upload to Zenodo.

  - [x] **Step 7.h**: Upload to B2SHARE.

  - [ ] **Step 7.i**: Upload to osf.io .
  
  - [ ] **Setp 7.j**: Explore datacite doi service.

  - [x] **Step 7.k**: Upload to Dataverse.
  
- [x] **Step 8**: (partially implemented) Create execution provenance, which includes uploading URLs of results and / or DOIs / URIs.

- [x] **Step 9**: Generate RO-Crate from execution provenance and exported results.

  - [x] **Step 9.a**: Generated RO-Crate should be consumable by WorkflowHub.

  - [x] **Step 9.c**: Generated RO-Crate should be consumable by WfExS-backend.
  
  - [x] **Step 9.d**: Add full circle capabilities. Re-execute workflow with the very same parameters from previously generated RO-Crate (only metadata).

  - [x] **Step 9.e**: Add full circle capabilities. Re-execute workflow with the very same parameters from previously generated RO-Crate (reusing payloads).


## Other features

- [x] Create a JSON Schema formally describing the different configuration files.

- [x] Supporting `file` protocol and lean and mean paths, so WfExS can be used with local routes and paths. The main drawback is that RO-Crate provenance can suffer in these scenarios, as it is not provided a public URL/URI.

- [ ] Support conda-based workflows.

- [ ] Support Snakemake workflows.

- [ ] Support pre and post processing steps through the usage of side workflow executions.

- [ ] Generate an abstract CWL description of a workflow execution. In the case of CWL will be a no-op, in the case of Nextflow it will use execution provenance.

- [x] Integrate GA4GH API providers which do not support returning an RO-Crate [dockstore.org](https://dockstore.org/search?searchMode=files).
  - Incomplete example 1 at [workflow_examples/somatic_cnv_dockstore_cwl.yaml](workflow_examples/somatic_cnv_dockstore_cwl.yaml).
  - Example of the kind of entries being understood:
    - https://dockstore.org/api/api/ga4gh/v2/tools/#workflow/github.com/smc-rna-challenge/zhanghj-8639902/zhanghj-8639902
    - https://dockstore.org/api/api/ga4gh/v2/tools/#workflow/github.com/smc-rna-challenge/zhanghj-8639902/zhanghj-8639902/versions/master/CWL/files
    - trs://dockstore.org/api/%23workflow%2Fgithub.com%2Fnf-core%2Frnaseq/3.9