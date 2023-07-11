#!/bin/bash

set -e

# Getting the installation directory
wfexsDir="$(dirname "$0")"/..
wfexsDir="$(readlink -f "${wfexsDir}")"

if [ $# -ge 2 ] ; then
	schemas_path="$1"
	doc_schemas_path="$2"
	if [ $# -gt 2 ] ; then
		case "$3" in
			force)
				doRebuild=1
				;;
		esac
	fi
else
	schemas_path="wfexs_backend/schemas"
	doc_schemas_path="development-docs/schemas"
fi

git_date() {
	local filename="$1"

	git log -1 --format=%ct "$filename" 2> /dev/null
}

for schema in "${wfexsDir}"/"${schemas_path}"/*.json ; do
	doregen=
	destfile="${wfexsDir}"/"${doc_schemas_path}"/"$(basename "$schema" .json)"_schema.md
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
		generate-schema-doc --config custom_template_path="${wfexsDir}/${doc_schemas_path}/templates/md/base.md" --config examples_as_yaml --config description_is_markdown --config no_collapse_long_descriptions "$schema" "$destfile"
	fi
done
