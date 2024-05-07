Getting Started
===============

WfExS-backend is a high-level workflow execution orchestrator able to secure workflow executions 
in isolated environments using containers. It also ensures reproducible executions by making use of 
Workflow Run RO-Crate representations.

WfExS is a Python application and set of libraries acting through a command line program, 
which fetches and materialize all the elements needed to instantiate a workflow:
publically available workflow, workflow engine, software containers and reachable inputs 
(either public or under controlled access). Elements need to be identified either by URL or 
a stable permanent identifier (CURIE). 

WfExS currently supports only workflows which are written in either Nextflow or CWL.
The workflows you want to use can be fetched from one of these places: 
`WorkflowHub <https://workflowhub.eu/>`_,
`Dockstore <https://dockstore.org>`_ and `Github <https://github.com/>`_ (either the URL or the git repository).

This document will give you more information about the installation of the
software to get it running.


.. index::
   single: getting-started; sys-requirments

System requirements
-------------------

It is recomended to use WfExS on Linux system. 
WfExS has been tested on the following systems:

   - Ubuntu
   - Gentoo
   - Windows subsystem for Linux 2
   - OPENSuse 

.. note:: 
   If you have problems installing it on a different system please write an 
   `issue <https://github.com/inab/WfExS-backend/issues>`_.


.. index::
   single: getting-started; installation


Installation 
-------------

This workflow execution service backend is written for Python 3.7 and later.
Follow the installation instructions to get WfExS running in your system. 

.. note:: 
   In this document there is a small section with :ref:`gearshift specific installation
   instructions<installation_gearshift>`. If you want to install WfExS on gearshift please 
   first read that part and then proceed to the :ref:`general installation<installation_wfexs>` 
   of WfExS.


.. index::
   single: getting-started; installation; prerequisites

Prerequisites 
~~~~~~~~~~~~~

Before starting the installation process, please check whether your system has all the 
necessary dependencies. Ensure the following prerequisites are installed: 

   - ``git``  
   - ``curl``
   - ``tar``
   - ``gzip`` 
   - ``build-essential`` package in Linux systems.
   - ``python3`` (Python 3.7 or later)
   - ``pip``: available in many Linux distributions (Ubuntu packages python3-pip, CentOS EPEL package python-pip), and also as ``pip`` Python package. 
   - ``venv``: available in many Linux distributions (Ubuntu package python3-venv). In some of them is integrated into the Python 3.5 (or later) installation.

.. note:: 
   ``build-essential`` installation in Linux systems `here <https://www.ochobitshacenunbyte.com/2014/12/10/que-es-y-como-se-instala-build-essentials/>`_.

These components are essential for the successful execution of the installation 
script. Once you have verified and installed all the required dependencies, you can 
proceed with the installation of WfExS on your system. If any of the dependencies
is missing, install them on your system before proceeding further.

.. index::
   single: getting-started; installation; easy-setup-wfexs

.. _installation_wfexs:

"Easy" setup WfExS
~~~~~~~~~~~~~~~~~~
The initial step for WfExS installation is cloning the Git repository. 
Assuming you are in the designated installation location, enter the following command:

.. code-block:: bash

   git clone https://github.com/inab/WfExS-backend.git


Navigate to the installed software folder and execute the ``full-installer.bash`` script.
This is an automated installer for an "easy" setup.

.. code-block:: bash
   
   cd WfExS-backend
   ./full-installer.bash

The automated installer handels core dependencies and some supplementary modules, 
libraries, or tools necessary for the complete functionality of WfExS. It fetches and installs:


.. list-table::

   * - `OpenJDK`_
     - Necessary for running Nextflow. 
   * - `gocryptfs`_
     - Securing intermediate results. 
   * - static ``bash``
     - Needed to patch buggy bash within singularity containers being run by Nextflow.
   * - static ``ps``
     - Necessray for Nextflow metrics recopilation. 

.. _py_env:

By default, installation creates and sources a new python virtual environment for WfExS ``.pyWEenv``, 
unless there is an activated one. If so, the installation is done inside the active 
virtual environment. 

Every time you want to work with WfExS make sure you first activate the python environment. 

.. code-block:: bash
   
   source "$INSTALLATIONDIR"/WfExS-backend/.pyWEenv/bin/activate

The shell prompt should now start with ``(.pyWEenv)``.
To test if the installation procedure went well you can try to run the ``help`` command:

.. code-block:: bash

   python WfExS-backend.py -h

If you get the help of the software you know it works!

.. warning::
   If Python runtime is upgraded (from version 3.8 to 3.9 or later, for instance), or 
   the main folder is moved to a different location after following these instructions,
   it may be needed to remove and reinstall the virtual environment.

.. note::
   It is possible to make a basic setup installation with the ``basic-installer.bash`` 
   installer.
   This installer only handels core dependencies. Users will need to install all the 
   additional software dependencies.  



.. index::
   single: getting-started; installation; sof_dep

Software dependencies
~~~~~~~~~~~~~~~~~~~~~

WfExS-backend requires additional software dependencies beyond the core ones to facilitate 
various stages of the code execution. Depending on your workflow local configuration, it may 
be necessary to install specific external tools or container technologies. 
Ensure that these dependencies are properly configured.
 
Container technologies:

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
of them can be locally installed, because as of September 2022 workflow engines like `cwltool` 
or `nextflow` still use the hardcoded name of `singularity`. So, the apptainer installer has to 
create a `singularity` symlink pointing to `apptainer`.

   .. code-block:: bash

      ./singularity-local-installer.bash
   
   .. code-block:: bash

      ./apptainer-local-installer.bash


Workflow engines prerequisites:

.. list-table::

   * - `java`_
     - Necessary for running Nextflow. Supported Java versions range from 8 to any version below 15 
       (Nextflow does not support version 15). Both OpenJDK and Sun implementations should work.

Secure environment:

.. list-table::

   * - `gocryptfs`_
     - Securing intermediate results. Tested since version v2.0-beta2; 
       releases provide static binaries. 
   * - `encfs`_
     - Securing intermediate results. Tested with versions 1.9.2 and 1.9.5; 
       releases need to be compiled or installed from your distribution.

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

.. index::
   single: getting-started; installation; devel

Development tips
~~~~~~~~~~~~~~~~~~

All the development dependencies are declared at `dev-requirements.txt` and 
`mypy-requirements.txt`. 

To install development requistites:

.. code-block:: bash
   
   python3 -m venv .pyWEenv
   source .pyWEenv/bin/activate
   pip install --upgrade pip wheel
   pip install -r requirements.txt --> this is installed with the basic installer 
   pip install -r dev-requirements.txt
   pip install -r mypy-requirements.txt



.. index::
   single: getting-started; inst-gearshift

.. _installation_gearshift:

Gearshift specific installation instructions
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The installation is not yet an easybuild recipe, so this procedure describes how you can 
install it in one of your own folders on gearshift.
In order for the software to be installed on gearshift you will first have to load some 
modules. These modules are also necessary for running the software each time. 

The first step of the installation procedure is to make a file with this name 
``enable-WfExS-env.bash`` so you can just source this file each time you want to work with the 
software.

.. code-block:: bash

   touch enable-WfExS-env.bash

This file needs to have the following content:

.. code-block:: bash

   #!/bin/bash
   
   module load Python/3.7.4-GCCcore-7.3.0-bare GCC/7.3.0-2.30 GCCcore/7.3.0 OpenSSL/1.1.1i-GCCcore-7.3.0
   
   basedir="$(dirname "${BASH_SOURCE[0]}")"
   case "$basedir" in
       /*)
           true
           ;;
       .)
           basedir="$PWD"
           ;;
       *)
           basedir="${PWD}/$basedir"
   esac
   
   source "$basedir"/WfExS-backend/.pyWEenv/bin/activate

For the installation procedure, make sure you comment out the last line by putting a ``#`` 
at the start of the line.

.. code-block:: bash

   # source "$basedir"/WfExS-backend/.pyWEenv/bin/activate

Follow the instructions for :ref:`installing WfExs<installation_wfexs>` as described above. 
When the installation is done you need to reopen ``enable-WfExS-env.bash`` file again to 
remove the ``#`` in the last line of the file.

This folder/files will be there after the installation so when you try to source it, you will 
produce an error. Make sure your file is **executable** and then source the ``enable-WfExS-env.bash`` 
file.

.. code-block:: bash

   chmod +x enable-WfExS-env.bash
   source enable-WfExS-env.bash


This file loads 3 modules (``python 3.7.4`` , ``GCC 7.3.0`` and ``OpenSSL 1.1.1``)  which are needed 
for working with WfExS, and it is sourcing the Python environment ``.pyWEenv`` which you need loaded 
everytime you work with WfExs.


.. _git: https://git-scm.com/book/en/v2/Getting-Started-Installing-Git
.. _pip: https://pip.pypa.io/en/stable/ 
.. _gocryptfs: https://nuetzlich.net/gocryptfs/
.. _java: https://openjdk.java.net/
.. _encfs: https://vgough.github.io/encfs/
.. _podman: https://podman.io/
.. _docker: https://www.docker.com/
.. _singularity: https://sylabs.io/singularity/
.. _apptainer: https://apptainer.org/
.. _nextflow: https://www.nextflow.io/docs/latest/index.html 
.. _cwl: https://cwltool.readthedocs.io/en/stable/
.. _snakemake: https://snakemake.readthedocs.io/en/stable/
.. _OpenJDK: https://openjdk.org/