# <img src="development-docs/logo/WfExS-logo-final_paths.svg" alt="WfExS-backend:" height="48"> Workflow Execution Service backend [![DOI](https://zenodo.org/badge/301434294.svg)](https://zenodo.org/badge/latestdoi/301434294)


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
* Identify the needed containers by the workflow, and fetch/cache them. Depending on the local setup, `singularity`, `apptainer`, `docker`, `podman` or none of them will be used.
* Fetch and cache the inputs, represented either through an URL or a [CURIE-represented](https://en.wikipedia.org/wiki/CURIE) PID (public [persistent identifier](https://en.wikipedia.org/wiki/Persistent_identifier)).
* Execute the workflow in a secure way, if it was requested.
* Optionally describe the results through an [RO-Crate](https://www.researchobject.org/ro-crate/), and upload both RO-Crate and the results elsewhere in a secure way.

## Relevant docs:

* [INSTALL.md](INSTALL.md): In order to use WfExS-backend you have to install first at least core dependencies described there.

* [TODO.md](TODO.md): This development is relevant for projects like [EOSC-Life](https://www.eosc-life.eu/) or [EJP-RD](https://www.ejprarediseases.org/). The list of high level scheduled and pending developments can be seen at .

* [README_LIFECYCLE.md](README_LIFECYCLE.md): WfExS-backend analysis lifecycle and usage scenarios are briefly described with flowcharts there.

* [README_REPLICATOR.md](README_REPLICATOR.md): It briefly describes `WfExS-config-replicator.py` usage.

Additional present and future documentation is hosted at [development-docs](development-docs/index.md) subfolder, until it is migrated to a proper documentation service.

##  Cite as

José María Fernández, Laura Rodríguez-Navas, Adrián Muñoz-Cívico, Paula Iborra, Daniel Lea (2024):  
**WfExS-backend**.  
_Zenodo_  
<https://doi.org/10.5281/zenodo.6567591>

Visit the [Zenodo record](https://doi.org/10.5281/zenodo.6567591) for the latest versioned DOI and author list.

### Presentations and outreach

Paula Iborra, José M. Fernández, Salvador Capella-Gutierrez (2024):  
[**Onboarding Snakemake: Progress towards WfExS-backend integration**](https://doi.org/10.7490/f1000research.1119725.1).  
_F1000Research_ **13**(ELIXIR):551 (poster)  
<https://doi.org/10.7490/f1000research.1119725.1>

Eugenio Gonzalo1, Laia Codó, Jose María Fernandez, Stian Soiland-Reyes, Salvador Capella-Gutierrez, Emily Jefferson, Carole Goble, Tim Beck, Phil Quinlan, Tom Giles (2024):  
[**Five safes workflow RO-Crate and WfExS**. Closing the gap of federated analysis and Trusted Research Enviroments (TREs) in the health data context](https://doi.org/10.7490/f1000research.1119724.1).  
_F1000Research_ **13**(ELIXIR):550 (poster)  
<https://doi.org/10.7490/f1000research.1119724.1>

José M. Fernández, Paula Iborra, Sébastien Moretti, Arun Isaac, Paul De Geest, Stian Soiland-Reyes (2024):  
[**BioHackEU23: FAIR Workflow Execution with WfExS and Workflow Run Crate**](https://doi.org/10.37044/osf.io/7f94w).  
_BioHackrXiv_  
<https://doi.org/10.37044/osf.io/7f94w>

Simone Leo, Michael R. Crusoe, Laura Rodríguez-Navas, Raül Sirvent, Alexander Kanitz, Paul De Geest, Rudolf Wittner, Luca Pireddu, Daniel Garijo, José M. Fernández, Iacopo Colonnelli, Matej Gallo, Tazro Ohta, Hirotaka Suetake, Salvador Capella-Gutierrez, Renske de Wit, Bruno de Paula Kinoshita, Stian Soiland-Reyes (2024):  
[**Recording provenance of workflow runs with RO-Crate**](https://doi.org/10.48550/arXiv.2312.07852).  
_arXiv_:2312.07852  
<https://doi.org/10.48550/arXiv.2312.07852>

José M. Fernández1, Laura Rodriguez-Navas, Salvador Capella-Gutiérrez (2023):  
[**WfExS-backend in the WRROC world**?](https://doi.org/10.7490/f1000research.1119457.1)  
_F1000Research_ **12**(ELIXIR):616 (poster)
<https://doi.org/10.7490/f1000research.1119457.1>

Fernández JM, Rodríguez-Navas L and Capella-Gutiérrez S.  
[**Secured and annotated execution of workflows with WfExS-backend**](https://doi.org/10.7490/f1000research.1119198.1) [version 1; not peer reviewed].  
_F1000Research_ 2022, 11:1318 (poster)  
<https://doi.org/10.7490/f1000research.1119198.1>

Laura Rodríguez-Navas (2021):  
[**WfExS: a software component to enable the use of RO-Crate in the EOSC-Life collaboratory**](https://osf.io/tb5ku/).  
_FAIR Digital Object Forum_, [CWFR & FDO SEM meeting](https://osf.io/v8xjz/), 2021-07-02
[[video recording](https://osf.io/wna42/)], [[slides](https://osf.io/tb5ku/)]

Laura Rodríguez-Navas (2021):  
[**WfExS: a software component to enable the use of RO-Crate in the EOSC-Life tools collaboratory**](https://repository.eoscsecretariat.eu/index.php/s/ERebmpJcyjFRqcx/download?path=%2F17%20June%2F1400%20-%20Technical%20challenges%20on%20EOSC%2FBreakout%203%20-%20Interoperability%20challenges%20for%20thematic%20communities&files=05%20-%20Laura%20Rodr%C3%ADguez-Navas%20-%20WfExS.pdf&downloadStartSecret=zwwx23xrow).  
_[EOSC Symposium 2021](https://www.eoscsecretariat.eu/eosc-symposium-2021-programme)_, 2021-06-17
[[video recording](https://youtu.be/x5lLEym-gug?list=PLbISfqJh3Tstmx6CgrBmYI7lyyVXiY5VE&t=3238)]
[[slides](https://drive.google.com/file/d/1LJkmI_gyl9VnuQ2_ZHBGeFkt_QTWFieg/view)]

Salvador Capella-Gutierrez (2021):  
[**Demonstrator 7: Accessing human sensitive data from analytical workflows available to everyone in EOSC-Life**](https://www.eosc-life.eu/d7/)  
_Populating EOSC-Life: Success stories from the demonstrators_, 2021-01-19.
<https://www.eosc-life.eu/d7/>
[[video](https://www.youtube.com/watch?v=saLxJpejCj0)] [[slides](http://www.eosc-life.eu/wp-content/uploads/2021/02/D7_Wrap-up.pdf)]

Bietrix, Florence; Carazo, José Maria; Capella-Gutierrez, Salvador; Coppens, Frederik; Chiusano, Maria Luisa; David, Romain; Fernandez, Jose Maria; Fratelli, Maddalena; Heriche, Jean-Karim; Goble, Carole; Gribbon, Philip; Holub, Petr; P. Joosten, Robbie; Leo, Simone; Owen, Stuart; Parkinson, Helen; Pieruschka, Roland; Pireddu, Luca; Porcu, Luca; Raess, Michael; Rodriguez- Navas, Laura; Scherer, Andreas; Soiland-Reyes, Stian; Tang, Jing (2021):  
[**EOSC-Life Methodology framework to enhance reproducibility within EOSC-Life**](https://zenodo.org/record/4705078/files/EOSC-Life_D8.1_Methodology%20framework%20to%20enhance%20reproducibility%20within%20EOSC-Life_April-2021.pdf).  
EOSC-Life deliverable D8.1, _Zenodo_
<https://doi.org/10.5281/zenodo.4705078>

## Example RO-Crate outputs

* <https://doi.org/10.5281/zenodo.12588049> -- execution of [WOMBAT-Pipelines](https://github.com/wombat-p/WOMBAT-Pipelines) Nextflow workflow
* <https://doi.org/10.5281/zenodo.12622362> -- execution of [Wetlab2Variations](https://github.com/inab/Wetlab2Variations/) CWL workflow
 

## WfExS-backend Usage

An automatically generated description of the command line directives is available [at the CLI section of the documentation](https://wfexs-backend.readthedocs.io/en/latest/cli.html).

Also, a description about the different WfExS commands is available [at the command line section of the documentation](https://wfexs-backend.readthedocs.io/en/latest/command-line.html).

## Configuration files

The program uses three different types of configuration files:

* Local configuration file: YAML formatted file which describes the local setup of the backend (example at [workflow_examples/local_config.yaml](workflow_examples/local_config.yaml)). JSON Schema describing the format (and used for validation) is available at [wfexs_backend/schemas/config.json](wfexs_backend/schemas/config.json) and there is also automatically generated documentation (see [config_schema.md](development-docs/schemas/config_schema.md)). Relative paths in this configuration file use as reference the directory where the local configuration file is living.
  
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
  
* Workflow configuration file: YAML formatted file which describes the workflow staging before being executed, like where inputs are located and can be fetched, the security contexts to be used on specific inputs to get those controlled access resources, the parameters, the outputs to capture, ... ([Nextflow example](workflow_examples/wetlab2variations_execution_nxf.wfex.stage), [CWL example](workflow_examples/wetlab2variations_execution_cwl.wfex.stage)). JSON Schema describing the format and valid keys (and used for validation), is available at [wfexs_backend/schemas/stage-definition.json](wfexs_backend/schemas/stage-definition.json) and there is also automatically generated documentation (see [stage-definition_schema.md](development-docs/schemas/stage-definition_schema.md)).

* Security contexts file: YAML formatted file which holds the `user`/`password` pairs, security tokens or keys needed on different steps, like input fetching. ([Nextflow example](workflow_examples/wetlab2variations_credentials_nxf.wfex.ctxt), [CWL example](workflow_examples/wetlab2variations_credentials_cwl.wfex.ctxt)). JSON Schema describing the format and valid keys (and used for validation), is available at [wfexs_backend/schemas/security-context.json](wfexs_backend/schemas/security-context.json) and there is also automatically generated documentation (see [security-context_schema.md](development-docs/schemas/security-context_schema.md)).

## License
* © 2020-2024 Barcelona Supercomputing Center (BSC), ES

Licensed under the Apache License, version 2.0 <https://www.apache.org/licenses/LICENSE-2.0>, see the file `LICENSE` for details.
