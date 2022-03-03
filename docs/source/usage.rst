Usage
=====

WfExS (which can be pronounced like "why-fex", "why-fix" or "why-fixes" is used to import and execute workflows. It currently supports only workflows which are written in either Nextflow or CWL.
WfExS is written in Python. The workflows you want to use can be fetched from one of these places: the `WorkflowHub <https://workflowhub.eu/>`_, `Dockstore <https://dockstore.org>`_ and Github (either the URL or the git repository).

This document will give you more information about the installation of the software and how you can import and execute a certain workflow. In this document there is a small section with gearshift specific installation instructions. If you want to install WfExS on gearshift please first read this part and then proceed to the general installation of WFeXs.

General websites:
* https://github.com/inab/WfExS-backend/
* https://workflowhub.eu/
* https://www.nextflow.io/
* https://www.commonwl.org/user_guide/
* https://www.researchobject.org/ro-crate/

.. index::
   single: usage; first_steps

How to work with WfExS
----------------------

WfExS software needs at least two and sometimes three different input files to run your workflow:
- Local configuration file: This file contains the encryption keys  (necessary)
- Workflow configuration file: This file describes which workflow you want to run and with which input files and optional references  (necessary)
- Security contexts file: for some input files/references you need usernames and passwords to use them, they should be added to this file.  (optional)

All the different options for running WfExS (different commands/options)  and input file formats are also described on this page: https://github.com/inab/WfExS-backend  (you have to scroll down to find this information).
First of all we are going to explain running a very small NextFlow workflow, Cosifer test to give you an idea of how this software works.


.. index::
   single: usage; test_workflow

Running a test workflow to see the software in action
-----------------------------------------------------

For testing purposes, the Cosifer test workflow is an excellent choice, since this is a small workflow and downloading/executing this workflow will take the least amount of time.
Make sure the python environment is loaded (see installation procedure).
The shell prompt should start with: (.pyWEenv), f.e. (.pyWEenv) user@cluster my_install_folder $ 

The general command for executing a workflow with WfExs should look like this:
python WfExS-backend.py -d -L /PATH/TO/local_config_file.yaml execute -W /PATH/TO/workflow_configuration_file.stage 

Use this command for Running the Cosifer workflow:
cd WfExS-backend
python WfExS-backend.py -d -L tests/local_config_${USERNAME}.yaml execute -W tests/ipc/cosifer_test1_nxf.wfex.stage 

This will take some time (a couple of hours is normal)  since it has to download the workflow/containers, prepare the workflow and then execute the workflow.
When it's done it will give you the path to the results, the line starts with: createResultsResearchObject 1687][INFO] RO-Crate created: 

.. index::
   single: usage; own_workflow

How to work with WfExS to run your own workflow
-----------------------------------------------

Just to remind you, WfExS currently only supports workflows written in CWL and Nextflow.
Please keep in mind that any workflow/situation is different so we can't give you an exact manual on what to do here.

As explained in the section above, to run a workflow you need at least two/maybe three different input files.
Assuming you have run a workflow before (f.e. the Cosifer test workflow),  you already have the local configuration file so this section will only discuss making your own workflow configuration file: and the security contexts file.

General examples of a workflow configuration file can be found on the Github page of WfExs. 
 (https://github.com/inab/WfExS-backend/tree/main/tests )  
There are examples of workflow configuration files (files that end with ".stage") for CWL and Nextflow workflows.

.. index::
   single: usage; stage_config

Workflow staging configuration file
-----------------------------------

Here, we describe how to make your own workflow configuration file using this example:
https://github.com/inab/WfExS-backend/blob/main/tests/wetlab2variations_execution_nxf.wfex.stage

The first lines of the workflow configuration file points to the website where you want to import your workflow from and the exact workflow you want to import.

trs_endpoint: https://workflowhub.eu/ga4gh/trs/v2/tools/
workflow_id: 106
version: 3
workflow_config:
secure: false

In the example it refers to a workflow which is made available through the workflow hub website. The workflow it's importing is number 106. 

The lines after the workflow defining lines are used to describe the input files, in this case we are working with raw sequencing data, so there are fastq files defined. Furthermore there is a reference defined which is used in this workflow to align the fastq files.
Warning: you can only use urls to define your input files and references, local files are not yet supported by WfExS.

In order to write your own workflow configuration file, you need to know the specific steps which are performed in the workflow you are going to use. For each step it's possible that references are used and you need to define them all in the workflow configuration file. This is also done in the example for the BQSR and bwamem steps of this workflow.

When you have defined your input data and the references which need to be used for each step. Then you can move on to the output .  In this part of the configuration file, you can define what the output file type is ( this is  predefined by the workflow itself) and you can give the output a name . In this example the output file type is a gvcf file and they give it the name NA12878.g.vcf.gz . 

.. index::
   single: usage; stage_security_config

Security contexts file 
----------------------

For some websites, in order to download fastqs or reference files you need a username and a password. This is where the Security contexts file is for. In this file you can store the username and password to be able to download certain references/input data.
An example of a Security contexts file can be found here :  https://github.com/inab/WfExS-backend/blob/main/tests/wetlab2variations_credentials_nxf.wfex.ctxt 

Running the newly made workflow:
When you are done with making your own workflow configuration file and optional security contexts file, then you can try to execute this workflow with WfExS.

To do so make sure your Python environment is loaded and change this command to match with your newly made workflow configuration files:
python WfExS-backend.py -d -L /PATH/TO/local_config_file.yaml execute -W /PATH/TO/workflow_configuration_file.stage  

If you need a security  context file with your workflow configuration file the command looks like this:
python WfExS-backend.py -d -L /PATH/TO/local_config_file.yaml execute -W /PATH/TO/workflow_configuration_file.stage  -Z  /PATH/TO/lsecurity_context_file.ctxt
