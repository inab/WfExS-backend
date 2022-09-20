#!/bin/bash

# These are the software versions being installed
# in the virtual environment
JDK_MAJOR_VER=11
JDK_VER=${JDK_MAJOR_VER}.0.11
JDK_REV=9
OPENJ9_VER=0.26.0
GOCRYPTFS_VER=v2.2.1
STATIC_BASH_VER=5.1.004-1.2.2
BUSYBOX_VER=1.35.0

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
	set +e
	# This is needed in order to avoid
	# potential "permission denied" messages
	chmod -R u+w "${downloadDir}"
	rm -rf "${downloadDir}"
}

trap cleanup EXIT ERR

set -e

# It is assumed that sourcing this script a python environment
# will be created with all the needed dependencies
declare -a input_params=( "$@" )
if [ $# -gt 0 ]; then
	shift $#
fi
source "${wfexsDir}/basic-installer.bash"

# Now, it is time to install the binaries
if [ -x "${envDir}/bin/java" ] ; then
	if "${envDir}/bin/java" -version 2>&1 | grep -qF "${JDK_VER}+${JDK_REV}" ; then
		OPENJDK_INSTALLED=1
	fi
fi

if [ -n "${OPENJDK_INSTALLED}" ] ; then
	echo "OpenJDK ${JDK_VER}+${JDK_REV} already installed"
else
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
	OPENJDK_URL="https://github.com/AdoptOpenJDK/openjdk${JDK_MAJOR_VER}-binaries/releases/download/jdk-${JDK_VER}%2B${JDK_REV}_openj9-${OPENJ9_VER}/OpenJDK${JDK_MAJOR_VER}U-jdk_x64_linux_openj9_${JDK_VER}_${JDK_REV}_openj9-${OPENJ9_VER}.tar.gz"
	( cd "${downloadDir}" && curl -L -O "${OPENJDK_URL}" )
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
fi

# Checking gocryptfs is installed and the latest version
if [ -x "${envDir}/bin/gocryptfs" ] ; then
	if "${envDir}/bin/gocryptfs" -version | grep -qF "${GOCRYPTFS_VER}" ; then
		GOCRYPTFS_INSTALLED=1
	fi
fi

if [ -n "${GOCRYPTFS_INSTALLED}" ] ; then
	echo "GoCryptFS ${GOCRYPTFS_VER} already installed"
else
	pythonSystem="$(python -c 'import platform; print(platform.system().lower())')"
	gocryptfs_url="https://github.com/rfjakob/gocryptfs/releases/download/${GOCRYPTFS_VER}/gocryptfs_${GOCRYPTFS_VER}_${pythonSystem}-static_amd64.tar.gz"
	echo "Installing static gocryptfs ${GOCRYPTFS_VER} from ${gocryptfs_url}"
	( cd "${downloadDir}" && curl -L -O "${gocryptfs_url}" )
	tar -x -C "${envDir}/bin" -f "${downloadDir}"/gocryptfs*.tar.gz
fi

declare -a platformSuffixes=(
	$(python -c 'import platform; print("{0}-{1} {1}-{0}".format(platform.system().lower(), platform.machine()))')
)
platformSuffix="${platformSuffixes[0]}"
platformSuffixRev="${platformSuffixes[1]}"

staticBash="bash-${platformSuffix}"
if [ -x "${envDir}/bin/${staticBash}" ] ; then
	echo "Static bash copy ${staticBash} already available (to patch buggy bash within singularity containers being run by Nextflow)"
else
	static_bash_url="https://github.com/robxu9/bash-static/releases/download/${STATIC_BASH_VER}/${staticBash}"
	echo "Installing static bash ${STATIC_BASH_VER} from ${static_bash_url}"
	( cd "${downloadDir}" && curl -L -O "${static_bash_url}" )
	mv "${downloadDir}/${staticBash}" "${envDir}/bin/${staticBash}"
	chmod +x "${envDir}/bin/${staticBash}"
fi

for binName in ps ; do
	staticBin="${binName}-${platformSuffix}"
	if [ -x "${envDir}/bin/${staticBin}" ] ; then
		echo "Static busybox ${binName} copy ${staticBin} already available (to patch missing ${binName} within singularity containers being run by Nextflow)"
	else
		static_bin_url="https://busybox.net/downloads/binaries/${BUSYBOX_VER}-${platformSuffixRev}-musl/busybox_${binName^^}"
		echo "Installing busybox ${binName} ${BUSYBOX_VER} from ${static_bin_url}"
		( cd "${downloadDir}" && curl -L -o "${staticBin}" "${static_bin_url}" )
		mv "${downloadDir}/${staticBin}" "${envDir}/bin/${staticBin}"
		chmod +x "${envDir}/bin/${staticBin}"
	fi
done
