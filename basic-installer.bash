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

set -eu

failed=
for cmd in curl tar gzip mktemp grep ; do
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

# This shared function is used by apptainer, singularity and gocryptfs
checkInstallGO() {
	local GO_VER="$1"
	local GO_OS="$2"
	local GO_ARCH="$3"
	local downloadDir="$4"

	# Compilation artifacts should go to the temporary download directory
	GOPATH="${downloadDir}/go"
	export GOPATH
	
	local doInstallGo=
	if type -a go >& /dev/null ; then
		local goVer="$(go version)"
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
		local goSoftDir="${downloadDir}/soft"
		local goBundle=go${GO_VER}.${GO_OS}-${GO_ARCH}.tar.gz
		# Fetching go https://go.dev/dl/go1.17.13.linux-amd64.tar.gz
		echo Fetching GO from https://go.dev/dl/"${goBundle}"
		( cd "${downloadDir}" && curl -L -O https://go.dev/dl/"${goBundle}" )
		# Installing go in the temporary directory
		mkdir -p "${goSoftDir}"
		tar -x -z -C "${goSoftDir}" -f "${downloadDir}/${goBundle}"
		# Removing go bundle
		rm "${downloadDir}/${goBundle}"
		
		PATH="${goSoftDir}/go/bin:${GOPATH}/bin:${PATH}"
		export PATH
	fi
}

for cmd in python3 pip ; do
	type -a "$cmd" 2> /dev/null
	retval=$?
	if [ "$retval" -ne 0 ] ; then
		failed=1
		echo "ERROR: Command $cmd not found in PATH and needed for the installation"
	fi
done

failed=
for lib in libmagic.so ; do
	ldconfig -p | grep -qF "/${lib}"
	retval=$?
	if [ "$retval" -ne 0 ] ; then
		failed=1
		echo "ERROR: Library $lib found in ldconfig cache and needed for the installation"
	fi
done

if [ -n "$failed" ] ; then
	exit 1
fi

#if declare -F deactivate >& /dev/null ; then
is_minimal_ver="$(python3 -c 'import sys; print("{}.{}".format(sys.version_info.major, sys.version_info.minor)  if tuple(sys.version_info) >= (3, 7, 0, "final", 0)  else  "")')"
if [ -z "$is_minimal_ver" ] ; then
	echo "ERROR: Python 3.7 or newer is required, but $(python3 -V) was detected" 1>&2
	exit 1
fi

envDir="$(python3 -c 'import sys; print(""  if sys.prefix==sys.base_prefix  else  sys.prefix)')"
if [ -n "${envDir}" ] ; then
	echo "Using currently active environment ${envDir} to install the dependencies"
else
	envDir="${wfexsDir}/.pyWEenv"

	echo "Creating WfExS-backend python virtual environment at ${envDir}"

	# Checking whether the environment exists
	if [ ! -f "${envDir}" ] ; then
		python3 -m venv "${envDir}"
	fi

	# Activating the python environment
	envActivate="${envDir}/bin/activate"
	source "${envActivate}"
	pip install --upgrade pip wheel
fi

# Checking whether the modules were already installed
echo "Installing WfExS-backend python dependencies"
pip install -r "${wfexsDir}"/requirements.txt

# Now, should we run something wrapped?
if [ $# != 0 ] ; then
	pip install -r "${wfexsDir}"/dev-requirements.txt -r "${wfexsDir}"/mypy-requirements.txt
	"$@"
fi

declare -a platformSuffixes=(
	$(python -c 'import platform; print("{0} {1}".format(platform.system().lower(), platform.machine()))')
)
platformOS="${platformSuffixes[0]}"
platformArch="${platformSuffixes[1]}"
platformSuffix="${platformOS}-${platformArch}"
platformSuffixRev="${platformArch}-${platformOS}"

declare -A archesGO=(
	[x86_64]=amd64
	[aarch64]=arm64
)

platformArchGO="${archesGO[$platformArch]:-$platformArch}"

