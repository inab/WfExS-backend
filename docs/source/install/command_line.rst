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
   single: getting-started; installation; easy-setup-wfexs

.. _installation_wfexs:

Setup WfExS locally in your system
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
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
   If you upgrade your Python installation (from version 3.8 to 3.9 or later, for instance), or 
   the main folder is moved to a different location after following these instructions,
   it may be needed to remove and reinstall the virtual environment.

.. note::
   It is possible to make a basic setup installation with the ``basic-installer.bash`` 
   installer.
   This installer only handels core dependencies. Users will need to install all the 
   additional software dependencies.  


.. index::
   single: getting-started; installation; devel

Development tips
~~~~~~~~~~~~~~~~

All the development dependencies are declared at `dev-requirements.txt` and 
`mypy-requirements.txt`. 

To install development requistites:

.. code-block:: bash
   
   python3 -m venv .pyWEenv
   source .pyWEenv/bin/activate
   pip install --require-virtualenv --upgrade pip wheel
   pip install --require-virtualenv -r requirements.txt -r dev-requirements.txt -r mypy-requirements.txt
