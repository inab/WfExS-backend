#!/bin/bash

# These are the software versions being installed
# in the virtual environment
JDK_VER=11
JDK_REV=28
GOCRYPTFS_VER=v2.0-beta2
STATIC_BASH_VER=5.1.004-1.2.2

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

downloadDir="$(mktemp -d --tmpdir wfexs_installer.XXXXXXXXXXX)"
echo "${downloadDir} will be used to download third party dependencies, and later removed"

cleanup() {
	rm -rf "${downloadDir}"
}

trap cleanup EXIT ERR

set -e

#if declare -F deactivate >& /dev/null ; then
envDir="$(python3 -c 'import sys; print(""  if sys.prefix==sys.base_prefix  else  sys.prefix)')"
if [ -n "${envDir}" ] ; then
	echo "Using currently active environment ${envDir} to install the dependencies"
else
	envDir="${wfexsDir}/.pyWEenv"

	echo "Creating WfExS-backend python virtual environment at ${envDir}"

	# Checking whether the environment exists
	if [ ! -f "${envActivate}" ] ; then
		python3 -m venv "${envDir}"
	fi

	# Activating the python environment
	envActivate="${envDir}/bin/activate"
	source "${envActivate}"
fi

# Checking whether the modules were already installed
echo "Installing WfExS-backend python dependencies"
pip install --upgrade pip wheel
pip install -r "${wfexsDir}"/requirements.txt


# Now, it is time to install the binaries
if [ -x "${envDir}/bin/java" ] ; then
	echo "OpenJDK already installed"
else
	echo "Installing openjdk ${JDK_VER}+${JDK_REV} in the environment (to be used with Nextflow)"
	( cd "${downloadDir}" && curl -L -O "https://download.java.net/openjdk/jdk${JDK_VER}/ri/openjdk-${JDK_VER}+${JDK_REV}_linux-x64_bin.tar.gz" )
	tar -x -C "${envDir}" -f "${downloadDir}"/openjdk*.tar.gz
	for path in bin lib ; do
		mv "${envDir}"/jdk-${JDK_VER}/${path}/* "${envDir}/${path}"
		rmdir "${envDir}"/jdk-${JDK_VER}/${path}
	done

	mv "${envDir}"/jdk-${JDK_VER}/* "${envDir}"
fi

if [ -x "${envDir}/bin/gocryptfs" ] ; then
	echo "GoCryptFS already installed"
else
	gocryptfs_url="https://github.com/rfjakob/gocryptfs/releases/download/${GOCRYPTFS_VER}/gocryptfs_${GOCRYPTFS_VER}_linux-static_amd64.tar.gz"
	echo "Installing static gocryptfs ${GOCRYPTFS_VER} from ${gocryptfs_url}"
	( cd "${downloadDir}" && curl -L -O "${gocryptfs_url}" )
	tar -x -C "${envDir}/bin" -f "${downloadDir}"/gocryptfs*.tar.gz
fi

if [ -x "${envDir}/bin/bash-linux-x86_64" ] ; then
	echo "Static bash copy (to patch buggy bash within singularity containers being run by Nextflow)"
else
	static_bash_url="https://github.com/robxu9/bash-static/releases/download/${STATIC_BASH_VER}/bash-linux-x86_64"
	echo "Installing static bash ${STATIC_BASH_VER} from ${static_bash_url}"
	( cd "${downloadDir}" && curl -L -O "${static_bash_url}" )
	mv "${downloadDir}/bash-linux-x86_64" "${envDir}/bin/bash-linux-x86_64"
	chmod +x "${envDir}/bin/bash-linux-x86_64"
fi
