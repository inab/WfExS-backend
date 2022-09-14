#!/bin/bash

set -e

# Getting the installation directory
wfexsDir="$(dirname "$0")"/..
wfexsDir="$(readlink -f "${wfexsDir}")"

if [ $# -gt 0 ] ; then
	case "$1" in
		force)
			doRebuild=1
			;;
	esac
fi

for schema in "${wfexsDir}"/wfexs_backend/schemas/*.json ; do
	destfile="${wfexsDir}"/docs/schemas/$(basename "$schema" .json)_schema.md
	if [ -n "$doRebuild" ] ; then
		rm -f "$destfile"
	fi
	if [ "$schema" -nt "$destfile" ] ; then
		generate-schema-doc --config custom_template_path="${wfexsDir}/docs/schemas/templates/md/base.md" --config examples_as_yaml --config description_is_markdown --config no_collapse_long_descriptions "$schema" "$destfile"
	fi
done
