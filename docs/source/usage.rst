Executing WfExS
===============

General websites:

* https://github.com/inab/WfExS-backend/
* https://workflowhub.eu/
* https://www.nextflow.io/
* https://www.commonwl.org/user_guide/
* https://www.researchobject.org/ro-crate/

.. index::
   single: usage; first_steps


All the different options for running WfExS (different commands/options)  and input file 
formats are also described on this page: https://github.com/inab/WfExS-backend  
(you have to scroll down to find this information).
First of all we are going to explain running a very small NextFlow workflow,
Cosifer test to give you an idea of how this software works.


.. index::
   single: usage; test_workflow

Testing the Software: Running a Test Workflow
----------------------------------------------

Testing the functionality of the software through a test workflow is crucial for understanding its 
capabilities. One recommended choice for this purpose is the Cosifer test workflow, due to its 
manageable size, ensuring a swift download and execution process.

To initiate the test workflow, ensure that the Python environment is loaded, as outlined in the 
installation procedure. Upon successful setup, your shell prompt should begin with ``(.pyWEenv)``.

Executing a workflow with WfExS typically follows a standard command format:

.. code-block:: bash

    python WfExS-backend.py -d -L /PATH/TO/local_config_file.yaml execute -W /PATH/TO/workflow_configuration_file.stage

For running the Cosifer workflow specifically, use to the following command sequence:

.. code-block:: bash

    cd WfExS-backend
    python WfExS-backend.py -d -L tests/local_config_${USERNAME}.yaml execute -W workflow_examples/ipc/cosifer_test1_nxf.wfex.stage

Be prepared for a moderate duration of execution, typically a couple of hours, as the process 
involves downloading the workflow and containers, preparing the workflow environment, 
and executing the workflow itself.

Upon completion, the software will provide the path to the results, beginning with the line: 
``createResultsResearchObject [INFO] RO-Crate created:``

By following these steps, you can effectively assess the software's performance and functionality using the Cosifer test workflow.


.. index::
   single: usage; own_workflow


Working with WfExS to Run Your Own Workflow
--------------------------------------------

Before proceeding, it's important to note that WfExS currently supports workflows written in 
CWL and Nextflow. Additionally, it's crucial to acknowledge that each workflow and situation 
may vary, so providing an exact manual for every scenario isn't feasible.

As explained in the section above, to run a workflow with WfExS, you'll need at least two, 
and possibly three, input files. 
Assuming you've previously executed a workflow (e.g., the Cosifer test workflow), you likely 
already have the local configuration file. 
Thus, this section will focus on creating your own workflow configuration file and, 
if applicable, the security contexts file.

You can find general examples of workflow configuration files on the WfExS GitHub page at the following link: https://github.com/inab/WfExS-backend/tree/main/tests. Here, you'll find examples of workflow configuration files (files ending with ".stage") tailored for both CWL and Nextflow workflows.



General examples of a workflow configuration file can be found on the Github page of WfExs.
(https://https://github.com/WfExS-backend/tree/main/workflow_examples )  
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
