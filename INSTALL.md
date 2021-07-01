# Installing the Workflow Execution Service backend

This workflow execution service backend is written for Python 3.6 and later.

* In order to install the dependencies you need `pip` and `venv` modules.
	- `pip` is available in many Linux distributions (Ubuntu packages `python3-pip`, CentOS EPEL package `python-pip`), and also as [pip](https://pip.pypa.io/en/stable/) Python package.
	- `venv` is also available in many Linux distributions (Ubuntu package `python3-venv`). In some of them is integrated into the Python 3.5 (or later) installation.

* There is an automated installer at [installer.bash](installer.bash), which assumes both python3 and its pip and venv counterparts are properly installed.

* The creation of a virtual environment where to install WfExS backend dependencies is done running:
  
```bash
python3 -m venv .pyWEenv
source .pyWEenv/bin/activate
pip install --upgrade pip wheel
pip install -r requirements.txt
```

* If you upgrade your Python installation (from version 3.6 to 3.7, for instance), or you move this folder to a different location after following this instructions, you may need to remove and reinstall the virtual environment.

* External tools needed in several stages of the code. Please, install them, using either native packages (for instance, from your Linux distribution) or by hand and later set their path in the local configuration file you are using:

  * [encfs](https://vgough.github.io/encfs/) can be used for the feature of secure intermediate results. It has been tested with version 1.9.2 and 1.9.5 ([releases](https://github.com/vgough/encfs/releases) have to be compiled or installed from your distro).

  * [gocryptfs](https://nuetzlich.net/gocryptfs/) can be used for the feature of secure intermediate results. It has been tested with version v2.0-beta2 ([releases](https://github.com/rfjakob/gocryptfs/releases) provide static binaries).

  * [java](https://openjdk.java.net/): supported from version 8 to any version below 15.
  
  * [git](https://git-scm.com/) is used to fetch workflows from git repositories.
  
  * [singularity](https://sylabs.io/singularity/): when local installation is set up to use singularity, a version which supports user namespaces, 3.5 or later.
  
  * [docker](https://www.docker.com/): when local installation is set up to use docker. When docker is used, secure intermediate results feature will not work.
  
  * [podman](https://podman.io/): when local installation is set up to use podman. When docker is used, secure intermediate results feature will not work.