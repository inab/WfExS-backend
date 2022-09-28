# "Easy" install and setup a Workflow Execution Service backend instance

## "Easy" setup of core and main software dependencies

There is an automated installer at [full-installer.bash](full-installer.bash):

```bash
./full-installer.bash
```

which assumes both essential build dependencies
(package `build-essential` in Ubuntu), `curl`, `python3` and its `pip` and `venv` counterparts are properly installed.
The automated installer installs both core dependencies and it fetches and installs:

  * OpenJDK: needed by Nextflow.
  * gocryptfs: needed by secure directories feature.
  * A static bash copy: needed by Nextflow runner to monkey-patch some containers which do not have bash, or whose bash copy is buggy.

If you also want to install [singularity](https://sylabs.io/singularity/) or
[apptainer](https://apptainer.org) at the WfExS-backend virtual environment, and you are using Ubuntu Linux, a rootless setup is achieved using either [singularity-local-installer.bash](singularity-local-installer.bash)
or [apptainer-local-installer.bash](apptainer-local-installer.bash).
At most only one of them can be locally installed, because as of
September 2022 workflow engines like `cwltool` or `nextflow` still use the
hardcoded name of `singularity`. So, the apptainer installer has to create
a "singularity" symlink pointing to "apptainer".

```bash
# For singularity
./singularity-local-installer.bash
```

```bash
# For apptainer
./apptainer-local-installer.bash
```

This setup will only work on Linux systems with cgroups v2 enabled. You will also need to install the package which provides `mksquashfs`, which is `squashfs-tools` both in Debian and Ubuntu.

The scripts only install singularity or apptainer when it is not available. If you want to force the installation of singularity or apptainer in the WfExS backend environment, then you should run:

```bash
# For singularity
./singularity-local-installer.bash force
```

```bash
# For apptainer
./apptainer-local-installer.bash force
```

## Core Dependencies
This workflow execution service backend is written for Python 3.6 and later.

* In order to install the dependencies you need `pip` and `venv` Python modules, and the essential build dependencies.
	- `pip` is available in many Linux distributions (Ubuntu packages `python3-pip`, CentOS EPEL package `python-pip`), and also as [pip](https://pip.pypa.io/en/stable/) Python package.
	- `venv` is also available in many Linux distributions (Ubuntu package `python3-venv`). In some of them is integrated into the Python 3.5 (or later) installation.
	- Essential build dependencies (gcc, make, ...) are provided in Ubuntu with `build-essential` package.

* The creation of a virtual environment where to install WfExS backend dependencies can be done running:
  
```bash
./basic-installer.bash
```

* If you upgrade your Python installation (from version 3.6 to 3.7 or later, for instance), or you move this folder to a different location after following this instructions, you may need to remove and reinstall the virtual environment.

## Software Dependencies

There are additional software dependencies beyond core ones, which are needed depending on the setup of the instance:

There are additional software dependencies beyond core ones. Depending on the local setup, some other external tools or container technologies are needed in several stages of the code. Please, install them, using either native packages (for instance, from your Linux distribution) or by hand and later set their path in the local configuration file you are using:

  * [git](https://git-scm.com/) is used to fetch workflows from git repositories.
  
  * [gocryptfs](https://nuetzlich.net/gocryptfs/) can be used for the feature of secure intermediate results. It has been tested since version v2.0-beta2 ([releases](https://github.com/rfjakob/gocryptfs/releases) provide static binaries).

  * [java](https://openjdk.java.net/): Needed to run Nextflow. Supported Java versions go from version 8 to any version below 15 (Nextflow does not support this last one). Both OpenJDK and Sun implementations should work.
  
  * [singularity](https://sylabs.io/singularity/) or [apptainer](https://apptainer.org): when local installation is set up to use singularity, version 3.5 or later is needed. Singularity and Apptainer themselves depend on `mksquashfs`, which is available in Ubuntu through `squashfs-tools` package.
  
  * [encfs](https://vgough.github.io/encfs/) can be used for the feature of secure intermediate results. It has been tested with version 1.9.2 and 1.9.5 ([releases](https://github.com/vgough/encfs/releases) have to be compiled or installed from your distro).

  * [docker](https://www.docker.com/): when local installation is set up to use docker. Not all the combinations of workflow execution engines and secure or paranoid setups support it.
  
  * [podman](https://podman.io/): when local installation is set up to use podman. Not all the combinations of workflow execution engines and secure or paranoid setups support it.

## Secure working directories additional requirements and incompatibilities

Currently, both Nextflow and cwltool support secure and paranoid working directories when no container technology is set up.

* When [Singularity](https://sylabs.io/singularity/)/[Apptainer](https://apptainer.org) mode is set up, both Nextflow and cwltool support secure working directories when either singularity was compiled and set up with user namespaces support, or FUSE was set up at the system level in `/etc/fuse.conf` with the flag _`user_allow_other`_.

* When [Singularity](https://sylabs.io/singularity/)/[Apptainer](https://apptainer.org) is set up, both Nextflow and cwltool support paranoid working directories when singularity (or apptainer) was compiled and set up with user namespaces support.

* When [Docker](https://www.docker.com/) or [Podman](https://podman.io/) are set up, there is no support for secure or paranoid working directories due technical and architectural limitations.

# Development tips

All the development dependencies are declared at [dev-requirements.txt](dev-requirements.txt) and [mypy-requirements.txt](mypy-requirements.txt).

```bash
python3 -m venv .pyWEenv
source .pyWEenv/bin/activate
pip install --upgrade pip wheel
pip install -r requirements.txt
pip install -r dev-requirements.txt
```

One of these dependencies is [pre-commit](https://pre-commit.com/), whose rules are declared at [.pre-commit-config.yaml](.pre-commit-config.yaml) (there are special versions of these rules for GitHub).

The rules run both [pylint](https://pypi.org/project/pylint/) and
[mypy](http://mypy-lang.org/), and [black](https://black.readthedocs.io/en/stable/) in the near future.

The pre-commit development hook which runs these tools before any commit is installed just running:

```bash
pre-commit install
```

If you want to explicitly run the hooks at any moment, even before doing the commit itself, you only have to run:

```bash
pre-commit run -a
```

As these checks are applied only to the python version currently being used in the development,
there is a GitHub workflow at [.github/workflows/pre-commit.yml](.github/workflows/pre-commit.yml)
which runs them on several Python versions.

If you have lots of cores, fast disks and docker installed, you can locally run the pre-commit GitHub workflow using [act](https://github.com/nektos/act):

```bash
act -j pre-commit
```

# License
* © 2020-2022 Barcelona Supercomputing Center (BSC), ES

Licensed under the Apache License, version 2.0 <https://www.apache.org/licenses/LICENSE-2.0>, see the file `LICENSE.txt` for details.
