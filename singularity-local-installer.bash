#!/bin/bash

# SPDX-License-Identifier: Apache-2.0
# Copyright 2020-2023 Barcelona Supercomputing Center (BSC), Spain
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
SINGULARITY_VER=3.10.4
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

doForce=
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
# Second, let's load the environment in order to install
# singularity in the python profile
source "$wfexsDir"/basic-installer.bash

failed=
for cmd in mksquashfs ; do
	type -a "$cmd" 2> /dev/null
	retval=$?
	if [ "$retval" -ne 0 ] ; then
		failed=1
		echo "ERROR: Command $cmd not found in PATH and needed for the installation"
	fi
done

if [ -n "$failed" ] ; then
	exit 1
fi

# Now, it is time to check singularity binaries availability
if [ -z "$doForce" ] ; then
	if [ -x "${envDir}/bin/singularity" ] ; then
		echo "Singularity $(singularity version) is already available in the environment. Skipping install"
		exit 0
	fi
fi

# Compilation artifacts should go to the temporary download directory
checkInstallGO "${GO_VER}" "${platformOS}" "${platformArchGO}" "${downloadDir}"

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
