.. index::
   single: getting-started; installation


Installation 
-------------

This workflow execution service backend is written for Python 3.7 and later.
Follow the installation instructions to get WfExS running in your system. 

.. asciinema:: 452311

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
   container_recipes/full-installer.bash

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

      container_recipes/singularity-local-installer.bash
   
   .. code-block:: bash

      container_recipes/apptainer-local-installer.bash


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
   pip install --require-virtualenv --upgrade pip wheel
   pip install --require-virtualenv -r requirements.txt -r dev-requirements.txt -r mypy-requirements.txt
