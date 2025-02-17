#!/bin/bash

# SPDX-License-Identifier: Apache-2.0
# Copyright 2020-2024 Barcelona Supercomputing Center (BSC), Spain
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# These are the software versions being installed
# in the virtual environment
: ${APPTAINER_VER:=1.3.6}
: ${GO_VER:=1.23.4}

# These are placeholders
: ${GO_OS:=linux}
: ${GO_ARCH:=amd64}

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

downloadDir="$(mktemp -d --tmpdir wfexs_apptainer_installer.XXXXXXXXXXX)"
echo "$0: ${downloadDir} will be used to download third party dependencies, and later removed"

cleanup() {
	set +e
	# This is needed in order to avoid
	# lots of "permission denied" messages
	chmod -R u+w "${downloadDir}"
	rm -rf "${downloadDir}"
}

cleanuperr() {
	cleanup
	exit 1
}

trap cleanup EXIT
trap cleanuperr ERR

set -eu

doForce=
if [ $# -gt 0 ]; then
	if [ "$1" == "force" ] ; then
		doForce=1
		if [ $# -gt 1 ] ; then
			APPTAINER_VER="$2"
			if [ $# -gt 2 ] ; then
				GO_VER="$3"
			fi
		fi
	fi
fi

# Before installing, check whether apptainer is already available
if [ -z "$doForce" ] ; then
	if type -a apptainer >& /dev/null ; then
		echo "Apptainer $(apptainer version) is already available in the system. Skipping install"
		exit 0
	fi
fi

# First, be sure the environment is ready to be used
if [ $# -gt 0 ]; then
	shift $#
fi
# Second, let's load the environment in order to install
# apptainer in the python profile
trap - ERR
source "$wfexsDir"/basic-installer.bash

failed=
for cmd in mksquashfs squashfuse fuse2fs ; do
	set +e
	type -a "$cmd" 2> /dev/null
	retval=$?
	set -e
	if [ "$retval" -ne 0 ] ; then
		failed=1
		echo "ERROR: Command $cmd not found in PATH and needed for the installation"
	fi
done
trap cleanuperr ERR

if [ -n "$failed" ] ; then
	exit 1
fi


# Now, it is time to check apptainer binaries availability
if [ -z "$doForce" ] ; then
	if [ -x "${envDir}/bin/apptainer" ] ; then
		echo "Apptainer $(apptainer version) is already available in the environment. Skipping install"
		exit 0
	fi
fi

# Compilation artifacts should go to the temporary download directory
checkInstallGO "${GO_VER}" "${platformOS}" "${platformArchGO}" "${downloadDir}"

# Fetch and compile apptainer
apptainerBundlePrefix=apptainer-"${APPTAINER_VER}"
apptainerBundle="${apptainerBundlePrefix}".tar.gz

( cd "${downloadDir}" && curl -L -O https://github.com/apptainer/apptainer/releases/download/v"${APPTAINER_VER}"/"${apptainerBundle}" )
tar -x -z -C "${downloadDir}" -f "${downloadDir}/${apptainerBundle}"
# Removing apptainer bundle
rm "${downloadDir}/${apptainerBundle}"
cd "${downloadDir}"/"${apptainerBundlePrefix}"

# Now, the right moment to compile and install rootless apptainer
./mconfig -b ./builddir --without-suid --prefix="${envDir}"
make -C ./builddir
make -C ./builddir install

# Last, in order to keep compatibility, there should be a symlink called
# singularity pointing to apptainer
ln -sf apptainer "${envDir}"/bin/singularity
