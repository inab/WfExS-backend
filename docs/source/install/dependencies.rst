.. index::
   single: getting-started; dependencies


Dependencies 
------------

WfExS-backend 1.0 source code and its dependencies should be compatible with
Python 3.7 and later, including Python 3.12.

.. index::
   single: getting-started; dependencies; local-dependencies

Local dependencies  
~~~~~~~~~~~~~~~~~~~

When installing WfExS-backend locally on your system, certain dependencies are required to 
ensure proper functionality. These dependencies include software, libraries, and tools that 
the application relies on for execution. 
This section outlines the requirements on your local environment before proceeding with 
the installation, helping to avoid compatibility issues or missing functionality.


Core dependencies 
^^^^^^^^^^^^^^^^^

Before starting the installation process, please check whether your system has all the 
necessary dependencies. 
In order to install the dependencies you need `pip`_ and `venv`_ Python modules, 
and the essential build dependencies.

Ensure the following prerequisites are installed: 

   - ``git``  
   - ``curl``
   - ``tar``
   - ``gzip`` 
   - ``build-essential`` package in Linux systems (installation steps `here <https://www.ochobitshacenunbyte.com/2014/12/10/que-es-y-como-se-instala-build-essentials/>`_). Essential build dependencies (gcc, make, ...) are provided in Ubuntu with `build-essential` package.
   - ``python3`` (Python 3.7 or later)
   - ``pip``: available in many Linux distributions (Ubuntu packages python3-pip, CentOS EPEL package python-pip), and also as ``pip`` Python package. 
   - ``venv``: available in many Linux distributions (Ubuntu package python3-venv). In some of them is integrated into the Python 3.5 (or later) installation.


These components are essential for the successful execution of the installation 
script. Once you have verified and installed all the required dependencies, you can 
proceed with the local installation of WfExS on your system. If any of the dependencies
is missing, install them on your system before proceeding further.

.. index::
   single: getting-started; installation; sof_dep

Software dependencies
^^^^^^^^^^^^^^^^^^^^^

WfExS-backend requires additional software dependencies beyond the core ones to facilitate 
various stages of the code execution. Depending on your workflow local configuration,
some other external tools or container technologies are needed in several stages of the 
code. Please, install them, using either native packages 
(for instance, from your Linux distribution) or by hand and later set their path in the 
local configuration file you are using. 
Ensure that these dependencies are properly configured.

.. list-table::

   * - `git`_
     - Required to fetch workflows from git repositories.
   * - ``libmagic.so``
     - Dynamic library from `file` package is needed by `python-magic <https://pypi.org/project/python-magic/>`_ package.
   * - ``dot``
     - Command (from `GraphViz`_) is needed to generate a graphical representation of workflows on Workflow Run RO-Crate generation.


**Container technologies:**

.. list-table::

   * - `docker`_
     - Required when local installation is set up to use Docker. Note that not all 
       combinations of workflow execution engines and secure or paranoid setups support Docker.
   * - `podman`_
     - Required when local installation is set up to use Podman. Note that not all 
       combinations of workflow execution engines and secure or paranoid setups support Podman.
   * - `singularity`_ or `apptainer`_ 
     - Required when local installation is set up to use Singularity. Needed version 3.5 
       or later. Singularity and Apptainer depend on *mksquashfs*, available in Ubuntu through the *squashfs-tools* package.

.. role:: red

To install `singularity`_ or `apptainer`_ at WfExS-backend virtual environment ``(.pyWEenv)``, 
if you use Ubuntu Linux, a rootless setup is achieved using either 
``singularity-local-installer.bash`` or ``apptainer-local-installer.bash``. At most **only one** 
of them can be locally installed, because as of September 2022 workflow engines like `cwltool`_ 
or `nextflow` still use the hardcoded name of `singularity`. So, the apptainer installer has to 
create a `singularity` symlink pointing to `apptainer`.

   .. code-block:: bash

      container_recipes/singularity-local-installer.bash
   
   .. code-block:: bash

      container_recipes/apptainer-local-installer.bash


**Workflow engines prerequisites:**

.. list-table::

   * - `java`_
     - Necessary for running Nextflow. Supported Java versions range from 8 to any version below 15 
       (Nextflow does not support version 15). Both OpenJDK and Sun implementations should work.

**Secure environment:**

.. list-table::

   * - `gocryptfs`_
     - Securing intermediate results. Tested since version v2.0-beta2; 
       releases provide static binaries. 
   * - `encfs`_
     - Securing intermediate results. Tested with versions 1.9.2 and 1.9.5; 
       `releases <https://github.com/vgough/encfs/releases>`_ need to be compiled or installed from your distribution.

.. index::
   single: getting-started; secure_dirs


Secure working directories limitations
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

Currently, both Nextflow and cwltool support secure and paranoid working directories 
when no container technology is set up.

   - When `singularity`_ / `apptainer`_ mode is set up, both Nextflow and cwltool support 
     secure working directories when either singularity was compiled and set up with user 
     namespaces support, or FUSE was set up at the system level in ``/etc/fuse.conf`` with 
     the flag ``user_allow_other``.

   - When `docker`_ or `podman`_ are set up, there is no support for secure or paranoid 
     working directories due technical and architectural limitations.


.. _git: https://git-scm.com/book/en/v2/Getting-Started-Installing-Git
.. _pip: https://pip.pypa.io/en/stable/ 
.. _GraphViz:  https://graphviz.org
.. _gocryptfs: https://nuetzlich.net/gocryptfs/
.. _java: https://openjdk.java.net/
.. _encfs: https://vgough.github.io/encfs/
.. _podman: https://podman.io/
.. _docker: https://www.docker.com/
.. _singularity: https://sylabs.io/singularity/
.. _apptainer: https://apptainer.org/
.. _nextflow: https://www.nextflow.io/docs/latest/index.html 
.. _cwltool: https://cwltool.readthedocs.io/en/stable/
.. _snakemake: https://snakemake.readthedocs.io/en/stable/
.. _OpenJDK: https://openjdk.org/