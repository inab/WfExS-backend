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

for schema in "${wfexsDir}"/wfexs_backend/schemas/*.json ; do
	generate-schema-doc --config custom_template_path="${wfexsDir}/docs/schemas/templates/md/base.md" --config description_is_markdown --config no_collapse_long_descriptions "$schema" "${wfexsDir}"/docs/schemas/$(basename "$schema" .json)_schema.md
done
