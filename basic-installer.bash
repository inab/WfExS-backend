#!/bin/bash

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

set -e

for cmd in python3 pip ; do
	type -a "$cmd" 2> /dev/null
	retval=$?
	if [ "$retval" -ne 0 ] ; then
		failed=1
		echo "ERROR: Command $cmd not found in PATH and needed for the installation"
	fi
done

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
	if [ ! -f "${envActivate}" ] ; then
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
