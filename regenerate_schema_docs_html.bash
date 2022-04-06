#!/bin/bash

set -e

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

if [ $# -gt 0 ] ; then
	case "$1" in
		force)
			doRebuild=1
			;;
	esac
fi

for schema in "${wfexsDir}"/wfexs_backend/schemas/*.json ; do
	destfile="${wfexsDir}"/docs/schemas/$(basename "$schema" .json)_schema.html
	if [ -n "$doRebuild" ] ; then
		rm -f "$destfile"
	fi
	if [ "$schema" -nt "$destfile" ] ; then
		generate-schema-doc --config template_name=js --config no_minify --config examples_as_yaml --config description_is_markdown --config no_collapse_long_descriptions "$schema" "$destfile"
	fi
done
