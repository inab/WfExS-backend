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

WfExS-backend has been developed and mainly tested on Linux system, with amd64 processor architecture.

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

Core dependencies
-----------------

WfExS-backend 1.0 source code and its dependencies should be compatible with
Python 3.7 and later, including Python 3.12.

* In order to install the dependencies you need `pip` and `venv` Python modules, and the essential build dependencies.
	- `pip` is available in many Linux distributions (Ubuntu packages `python3-pip`, CentOS EPEL package `python-pip`), and also as [pip](https://pip.pypa.io/en/stable/) Python package.
	- `venv` is also available in many Linux distributions (Ubuntu package `python3-venv`). In some of them is integrated into the Python 3.5 (or later) installation.
	- Essential build dependencies (gcc, make, ...) are provided in Ubuntu with `build-essential` package.

* The creation of a virtual environment where to install WfExS backend dependencies can be done running:
  
.. code-block:: bash

   container_recipes/basic-installer.bash

* If you upgrade your Python installation (from version 3.8 to 3.9 or later, for instance), or you move the environment folder or any of its ancestors to a different location after following these instructions, you may need to remove and reinstall the virtual environment.

Additional Software Dependencies
--------------------------------

There are additional software dependencies beyond core ones. Depending on the local setup, some other external tools or container technologies are needed in several stages of the code. Please, install them, using either native packages (for instance, from your Linux distribution) or by hand and later set their path in the local configuration file you are using:


  * `git <https://git-scm.com/>`_ is used to fetch workflows from git repositories.
  
  * `libmagic.so` dynamic library from `file` package is needed by `python-magic <https://pypi.org/project/python-magic/>`_ package.
  
  * `dot` command (from `GraphViz <https://graphviz.org>`_) is needed to generate a graphical representation of workflows on Workflow Run RO-Crate generation.
  
  * `gocryptfs <https://nuetzlich.net/gocryptfs/>_ can be used for the feature of secure intermediate results. It has been tested since version v2.0-beta2 (`releases <https://github.com/rfjakob/gocryptfs/releases>`_ provide static binaries).

  * `java <https://openjdk.java.net/>`_: Needed to run Nextflow. Supported Java versions go from version 8 to any version below 15 (most of the Nextflow deployments do not support version 15 and above). Both OpenJDK and Sun/Oracle implementations should work.
  
  * `singularity <https://sylabs.io/singularity/>`_ or `apptainer <https://apptainer.org>`_: when local installation is set up to use singularity, version 3.5 or later is needed. Singularity and Apptainer themselves depend on `mksquashfs`, which is available in Ubuntu through `squashfs-tools` package.
  
  * `encfs <https://vgough.github.io/encfs/>`_ can be used for the feature of secure intermediate results. It has been tested with version 1.9.2 and 1.9.5 (`releases <https://github.com/vgough/encfs/releases>`_ have to be compiled or installed from your distro).

  * `docker <https://www.docker.com/>`_: when local installation is set up to use docker. Not all the combinations of workflow execution engines and secure or paranoid setups support it.
  
  * `podman <https://podman.io/>`_: when local installation is set up to use podman. Not all the combinations of workflow execution engines and secure or paranoid setups support it.


.. toctree::
   :titlesonly:

   install/command_line
   install/containers
   install/gearshift_specifics
