#!/bin/bash

# These are the software versions being installed
# in the virtual environment
SINGULARITY_VER=3.10.2
GO_VER=1.17.13

# These are placeholders
GO_OS=linux
GO_ARCH=amd64

# Getting the installation directory
wfexsDir="$(dirname "$0")"
case "${wfexsDir}" in
	/*)
		# Path is absolute
		true
	;;
	*)
		# Path is relative
		wfexsDir="$(readlink -f "${wfexsDir}")"
	;;
esac

downloadDir="$(mktemp -d --tmpdir wfexs_singularity_installer.XXXXXXXXXXX)"
echo "$0: ${downloadDir} will be used to download third party dependencies, and later removed"

cleanup() {
	set +e
	# This is needed in order to avoid
	# lots of "permission denied" messages
	chmod -R u+w "${downloadDir}"
	rm -rf "${downloadDir}"
}

trap cleanup EXIT ERR

set -e

if [ $# -gt 0 ]; then
	if [ "$1" == "force" ] ; then
		doForce=1
		if [ $# -gt 1 ] ; then
			SINGULARITY_VER="$2"
			if [ $# -gt 2 ] ; then
				GO_VER="$3"
			fi
		fi
	fi
fi

# Before installing, check whether singularity is already available
if [ -z "$doForce" ] ; then
	if type -a singularity >& /dev/null ; then
		echo "Singularity $(singularity version) is already available in the system. Skipping install"
		exit 0
	fi
fi

# First, be sure the environment is ready to be used
if [ $# -gt 0 ]; then
	shift $#
fi
source "$wfexsDir"/basic-installer.bash

# Second, let's load the environment in order to install
# singularity in the python profile
envDir="$(python -c 'import sys; print(""  if sys.prefix==sys.base_prefix  else  sys.prefix)')"
if [ -z "${envDir}" ] ; then
	envDir="${wfexsDir}/.pyWEenv"

	# Activating the python environment
	envActivate="${envDir}/bin/activate"
	source "${envActivate}"
fi

# Now, it is time to check singularity binaries availability
if [ -z "$doForce" ] ; then
	if [ -x "${envDir}/bin/singularity" ] ; then
		echo "Singularity $(singularity version) is already available in the environment. Skipping install"
		exit 0
	fi
fi

# Compilation artifacts should go to the temporary download directory
GOPATH="${downloadDir}/go"
export GOPATH
PATH="${GOPATH}/bin:${PATH}"

# Third, check whether there is an available go compiler
if type -a go >& /dev/null ; then
	goVer="$(go version)"
	case "$goVer" in
		"go version go1"*)
			# Go is available
			true
		;;
		*)
			doInstallGo=1
		;;
	esac
else
	doInstallGo=1
fi

if [ -n "$doInstallGo" ] ; then
	# Fetch and install go
	GO_OS="$(python -c 'import platform; print(platform.system().lower())')"
	GO_ARCH="$(python -c 'import platform; print(platform.machine())')"
	case "$GO_ARCH" in
		x86_64)
			# Deriving the right name
			GO_ARCH=amd64
		;;
		aarch64)
			# Deriving the right name
			GO_ARCH=arm64
		;;
	esac
	goSoftDir="${downloadDir}/soft"
	goBundle=go${GO_VER}.${GO_OS}-${GO_ARCH}.tar.gz
	# Fetching go
	( cd "${downloadDir}" && curl -L -O https://dl.google.com/go/"${goBundle}" )
	# Installing go in the temporary directory
	mkdir -p "${goSoftDir}"
	tar -x -z -C "${goSoftDir}" -f "${downloadDir}/${goBundle}"
	# Removing go bundle
	rm "${downloadDir}/${goBundle}"
	
	PATH="${goSoftDir}/go/bin:${PATH}"
fi

# Fetch and compile singularity
singularityBundlePrefix=singularity-ce-"${SINGULARITY_VER}"
singularityBundle="${singularityBundlePrefix}".tar.gz
( cd "${downloadDir}" && curl -L -O https://github.com/sylabs/singularity/releases/download/v"${SINGULARITY_VER}"/"${singularityBundle}" )
tar -x -z -C "${downloadDir}" -f "${downloadDir}/${singularityBundle}"
# Removing singularity bundle
rm "${downloadDir}/${singularityBundle}"
cd "${downloadDir}"/"${singularityBundlePrefix}"

# Now, the right moment to compile and install rootless singularity
./mconfig -b ./builddir --without-suid --prefix="${envDir}"
make -C ./builddir
make -C ./builddir install
