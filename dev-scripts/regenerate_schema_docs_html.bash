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

git_date() {
	local filename="$1"

	git log -1 --format=%ct "$filename" 2> /dev/null
}

for schema in "${wfexsDir}"/wfexs_backend/schemas/*.json ; do
	doregen=
	destfile="${wfexsDir}"/docs/schemas/$(basename "$schema" .json)_schema.html
	if [ -n "$doRebuild" ] ; then
		rm -f "$destfile"
	fi
	schemadate="$(git_date "$schema")"
	destfiledate="$(git_date "$destfile")"
	
	if [ -z "$destfiledate" ] ; then
		doregen=1
	elif [ "$schemadate" -gt "$destfiledate" ] ; then
		doregen=1
	fi

	if [ -n "$doregen" ] ; then
		generate-schema-doc --config template_name=js --config no_minify --config examples_as_yaml --config description_is_markdown --config no_collapse_long_descriptions "$schema" "$destfile"
	fi
done
