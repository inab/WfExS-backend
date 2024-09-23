🚀 Getting Started
==================

WfExS-backend is a high-level workflow execution orchestrator able to secure workflow executions 
in isolated environments using containers. It also ensures reproducible executions by making use of 
`Workflow Run RO-Crate <https://www.researchobject.org/workflow-run-crate/>`_ representations.

WfExS-backend is a Python application and set of libraries acting through a command line program, 
which fetches and materializes all the elements needed to instantiate a workflow:
publically available workflow, workflow engine, software containers and reachable inputs 
(either public or under controlled access). Elements need to be identified either by URL or 
a stable permanent identifier (CURIE). 

As WfExS-backend is an orchestrator, support for each kind of workflow language and engine have to
be written, in order to gather all the required metadata which eases reproducibility for that kind.
So, currently `Nextflow DSL <https://www.nextflow.io/docs/latest/script.html>`_ and
`CWL <https://www.commonwl.org/>`_ workflow languages are supported, and
`Nextflow <https://www.nextflow.io/>`_ and
`cwltool <https://github.com/common-workflow-language/cwltool>`_ workflow engines.

Popular workflow registries and communities are `WorkflowHub <https://workflowhub.eu/>`_,
`Dockstore <https://dockstore.org>`_ , `nf-core <https://nf-co.re/pipelines/>`_
and in general `Github <https://github.com/>`_. Workflows can be fetched from these
places either through their URL or using the git repository.

Next sections will provide you more information about the installation of the
software to get it running.

.. index::
   single: getting-started; sys-requirements

System requirements
-------------------

WfExS-backend has been developed mainly tested on Linux system, with amd64 processor architecture.

There has been some point tests of using WfExS-backend in arm64 architecture.

WfExS developers have received reports of its usage on the following systems:

   - `Ubuntu <https://ubuntu.com/>`_
   - `Gentoo <https://www.gentoo.org/>`_
   - `Windows subsystem for Linux 2 <https://learn.microsoft.com/en-us/windows/wsl/install>`_
   - `openSUSE <https://www.opensuse.org/>`_
   - `Debian <https://www.debian.org/>`_

.. note:: 
   If you have problems installing it on a different system or
   processor architecture please open an `issue <https://github.com/inab/WfExS-backend/issues>`_
   describing the whole scenario.


.. toctree::
   :titlesonly:

   install/command_line
   install/containers
   install/gearshift_specifics
