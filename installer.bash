#!/bin/bash

# These are the software versions being installed
# in the virtual environment
JDK_VER=11
JDK_REV=28
GOCRYPTFS_VER=v2.0-beta2

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

envDir="${wfexsDir}/.pyWEenv"
envActivate="${envDir}/bin/activate"

echo "Creating WfExS-backend python virtual environment at ${envDir}"

# Checking whether the environment exists
if [ ! -f "${envActivate}" ] ; then
	python3 -m venv "${envDir}"
fi

# Activating the python environment
source "${envActivate}"

# Checking whether the modules were already installed
echo "Installing WfExS-backend python dependencies"
pip install --upgrade pip wheel
pip install -r "${wfexsDir}"/requirements.txt

# Now, it is time to install the binaries
if [ ! -x "${envDir}/bin/java" ] ; then
	echo "Installing openjdk ${JDK_VER}+${JDK_REV} in the environment (to be used with Nextflow)"
	( cd "${downloadDir}" && curl -L -O "https://download.java.net/openjdk/jdk${JDK_VER}/ri/openjdk-${JDK_VER}+${JDK_REV}_linux-x64_bin.tar.gz" )
	tar -x -C "${envDir}" -f "${downloadDir}"/openjdk*.tar.gz
	for path in bin lib ; do
		mv "${envDir}"/jdk-${JDK_VER}/${path}/* "${envDir}/${path}"
	done
	mv "${envDir}"/jdk-${JDK_VER}/* "${envDir}"
fi

if [ ! -x "${envDir}/bin/gocryptfs" ] ; then
	gocryptfs_url="https://github.com/rfjakob/gocryptfs/releases/download/${GOCRYPTFS_VER}/gocryptfs_${GOCRYPTFS_VER}_linux-static_amd64.tar.gz"
	echo "Installing static gocryptfs ${GOCRYPTFS_VER} from ${gocryptfs_url}"
	( cd "${downloadDir}" && curl -L -O "${gocryptfs_url}" )
	tar -x -C "${envDir}/bin" -f "${downloadDir}"/gocryptfs*.tar.gz
fi