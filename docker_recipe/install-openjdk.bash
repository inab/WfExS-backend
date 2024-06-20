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

downloadDir="$(mktemp -d --tmpdir wfexs_installer.XXXXXXXXXXX)"
echo "${downloadDir} will be used to download third party dependencies, and later removed"

cleanup() {
	set +e
	# This is needed in order to avoid
	# potential "permission denied" messages
	chmod -R u+w "${downloadDir}"
	#echo "The downloadDir is ${downloadDir}"
	rm -rf "${downloadDir}"
}

trap cleanup EXIT ERR

set -eu

envDir=/usr/local
if [ $# -ge 4 ] ;then
	JDK_MAJOR_VER="$1"
	JDK_VER="$2"
	JDK_REV="$3"
	OPENJ9_VER="$4"
else
	JDK_MAJOR_VER=11
	JDK_VER=${JDK_MAJOR_VER}.0.11
	JDK_REV=9
	OPENJ9_VER=0.26.0
fi

declare -a platformSuffixes=(
	$(python -c 'import platform; print("{0} {1}".format(platform.system().lower(), platform.machine()))')
)
platformOS="${platformSuffixes[0]}"
platformArch="${platformSuffixes[1]}"
platformSuffix="${platformOS}-${platformArch}"
platformSuffixRev="${platformArch}-${platformOS}"

declare -A archesJDK=(
	[x86_64]=x64
)

platformArchJDK="${archesJDK[$platformArch]:-$platformArch}"

echo "Installing openjdk ${JDK_VER}+${JDK_REV} in the environment (to be used with Nextflow)"
# OBSOLETE: Obtained either from
# https://jdk.java.net/archive/
# or
# https://jdk.java.net/java-se-ri/${JDK_MAJOR_VER}
#if [ "${JDK_VER}" = "${JDK_MAJOR_VER}" ] ; then
#	OPENJDK_URL="https://download.java.net/openjdk/jdk${JDK_MAJOR_VER}/ri/openjdk-${JDK_VER}+${JDK_REV}_linux-x64_bin.tar.gz"
#else
#	OPENJDK_URL="https://download.java.net/java/GA/jdk${JDK_MAJOR_VER}/${JDK_REV}/GPL/openjdk-${JDK_VER}_linux-x64_bin.tar.gz"
#fi
#OPENJDK_URL="https://github.com/AdoptOpenJDK/openjdk${JDK_MAJOR_VER}-binaries/releases/download/jdk-${JDK_VER}%2B${JDK_REV}_openj9-${OPENJ9_VER}/OpenJDK${JDK_MAJOR_VER}U-jdk_x64_linux_openj9_${JDK_VER}_${JDK_REV}_openj9-${OPENJ9_VER}.tar.gz"
OPENJDK_URL="https://github.com/AdoptOpenJDK/openjdk${JDK_MAJOR_VER}-binaries/releases/download/jdk-${JDK_VER}%2B${JDK_REV}_openj9-${OPENJ9_VER}/OpenJDK${JDK_MAJOR_VER}U-jdk_${platformArchJDK}_${platformOS}_openj9_${JDK_VER}_${JDK_REV}_openj9-${OPENJ9_VER}.tar.gz"
( trap - EXIT ERR ; cd "${downloadDir}" && curl -f -L -O "${OPENJDK_URL}" )
tar -x -C "${envDir}" -f "${downloadDir}"/OpenJDK*.tar.gz
for path in bin lib ; do
	for elem in "${envDir}"/jdk-${JDK_VER}+${JDK_REV}/${path}/* ; do
		destelem="${envDir}/${path}/$(basename "$elem")"
		if [ -e "$destelem" ] ; then
			rm -rf "$destelem"
		fi
	done
	mv "${envDir}"/jdk-${JDK_VER}+${JDK_REV}/${path}/* "${envDir}/${path}"
	rmdir "${envDir}"/jdk-${JDK_VER}+${JDK_REV}/${path}
done

for elem in "${envDir}"/jdk-${JDK_VER}+${JDK_REV}/* ; do
	destelem="${envDir}/$(basename "$elem")"
	if [ -e "$destelem" ] ; then
		rm -rf "$destelem"
	fi
done
mv "${envDir}"/jdk-${JDK_VER}+${JDK_REV}/* "${envDir}"
