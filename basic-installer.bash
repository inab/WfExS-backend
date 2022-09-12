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
