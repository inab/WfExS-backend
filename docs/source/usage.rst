
⚙️ Executing WfExS
=================

As explained in the section above, to run a workflow with WfExS, you'll need at least two, 
and possibly three, configuration input files. 

To provide you with a practical overview of WfExS functionality, we will start by illustrating 
the execution of a minimal Nextflow workflow, the Cosifer test workflow. 
This example will offer insight into the operational dynamics of the software.

For a extended understanding of options for running WfExS, including its various commands, options, 
refer to the documentation available on the project's 
`GitHub repository <https://github.com/inab/WfExS-backend>`_.
Navigate through the page to locate detailed information on the software usage.


.. index::
   single: usage; test_workflow

Testing the Software: Running a Test Workflow
----------------------------------------------

Testing the functionality of the software through a test workflow is crucial for understanding its 
capabilities. For this purpose we will execute the Cosifer test workflow, due to its 
manageable size, ensuring a swift download and execution process.

To initiate the test workflow, ensure that the Python environment is loaded, as outlined in the 
installation procedure. Upon successful setup, your shell prompt should begin with ``(.pyWEenv)``.

Executing a workflow with WfExS typically follows a standard command format:

.. code-block:: bash

    python WfExS-backend.py -d -L /PATH/TO/local_config_file.yaml execute -W /PATH/TO/workflow_configuration_file.stage

For running the Cosifer workflow specifically, use to the following command sequence:

.. code-block:: bash

    cd WfExS-backend
    python WfExS-backend.py -d -L workflow_examples/local_config.yaml execute -W workflow_examples/ipc/cosifer_test1_nxf.wfex.stage

Be prepared for a moderate duration of execution, typically a couple of hours, as the process 
involves downloading the workflow and containers, preparing the workflow environment, 
and executing the workflow itself.

Upon completion, the software will provide the path to the results, beginning with the line: 
``createResultsResearchObject [INFO] RO-Crate created:``

By following these steps, you can effectively assess the software's performance and functionality 
using the Cosifer test workflow.


.. index::
   single: usage; own_workflow


Working with WfExS to Run Your Own Workflow
--------------------------------------------

Before proceeding, note that WfExS currently supports workflows written in CWL and Nextflow. 
Additionally, it's crucial to acknowledge that each workflow and situation may vary, 
so providing an exact manual for every scenario isn't feasible.

As explained in the :ref:`configuration section <configuration>` above, to run a workflow 
with WfExS, you'll need at least two, and possibly three, configuration input files. 
Assuming you've previously executed a workflow (e.g., the Cosifer test workflow), you likely 
already have the :ref:`local configuration <local_config>` file. 
Follow the configuration instructions to create your own :ref:`workflow confirguration <wf_stage_config>` 
files and, if applicable, the :ref:`security contexts file <secure_config>`.

When you are done making your own workflow configuration file and optional security contexts 
file, then you can try to execute the workflow with WfExS.

To do so make sure your Python environment (:ref:`.pyWEenv <py_env>`) is loaded and change this 
command to match with your newly made workflow configuration files:

.. code-block:: bash
   
   python WfExS-backend.py -d -L /PATH/TO/local_config_file.yaml execute -W /PATH/TO/workflow_configuration_file.stage  

If you need a security  context file with your workflow configuration file the command looks 
like this:

.. code-block:: bash
   
   python WfExS-backend.py -d -L /PATH/TO/local_config_file.yaml execute -W /PATH/TO/workflow_configuration_file.stage  -Z  /PATH/TO/security_context_file.ctxt
