Installation
============

In order to install WfExs on there are several dependencies necessary:

* Singularity, with this package: squashfs-tools, which should contain the mksquashfs command
* Ubuntu build-essential package which should contain (gcc,make…).
* Python 3
* pip (python module)
* venv (python module)
* git
* bash
* gocryptfs
* java
* encfs
* docker
* podman
* OpenSSL
* nextflow
* cwl

More information about these dependencies can be found here:  https://github.com/inab/WfExS-backend/blob/main/INSTALL.md

The first step of the installation procedure is to check if your system/pc has all these dependencies installed.
If not, make sure you install them(or the missing ones) on your system.

When this is done we can proceed with installing WfExS on your system.

.. index::
   single: installation; first_steps

First steps installing WfExS on your system
-------------------------------------------

The first step for this installation is to clone the git repository:
Assuming you are in the location where the software needs to be installed, type the following command.
"git clone https://github.com/inab/WfExS-backend.git " 
After this, there are some dependencies which need to be installed.

This can be done by going into the installed software folder and run the installer.bash script like this: 

.. code-block:: bash

   cd WfExS-backend
   bash installer.bash

When the dependencies are installed without any problems, the installation procedure is done!

However we still need to make new Local configuration files: 

For this you just need to touch these files:

.. code-block:: bash

   touch ./tests/local_config_${USER}.yaml
   touch ./tests/local_config_${USER}.yaml.pub
   touch ./tests/local_config_${USER}.yaml.key


The first time you run the WfExS software the new encryption keys will be made in those files.
If you are not working on Gearshift please make sure every time you want to work with WfExs, you first source the python environment.
This should look something like this:  
source "$INSTALLATIONDIR"/WfExS-backend/.pyWEenv/bin/activate
The shell prompt should now start with: (.pyWEenv),

To test if the installation procedure went well you can try to run this command.

.. code-block:: bash

   python WfExS-backend.py -h

If you get the help of the software you know it works!

.. index::
   single: installation; gearshift

Gearshift Specific installation instructions
--------------------------------------------

The installation is not yet an easybuild recipe, so this procedure describes how you can install it in one of your own folders on gearshift (for example /groups/${GROUPNAME}/tmp01/umcg-${YOURUSERNAME}/ ).
In order for the software to be installed on gearshift you will first have to load some modules.
These modules are also necessary for running the software each time. So the first step of the installation procedure is to make a file with this name "enable-WfExS-env.bash"  so you can just source this file each time you want to work with the software
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

For the installation procedure, make sure you comment out the last line, starting with " source "$basedir … " by putting a # at the start of the line.
This folder/files will be there after the installation so when you try to source it, you will produce an error. Make sure your file is executable and then source the enable-WfExS-env.bash file.
Follow the instructions for installing WfExs as described above and when the installation is done, you need to reopen enable-WfExS-env.bash file again to remove the "#" in the last line of the file.

This file loads 3 modules (python 3.7.4 , GCC 7.3.0 and OpenSSL 1.1.1.)  which are needed for working with WfExS, and it is sourcing the Python environment which you need loaded everytime you work with WfExs.
