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