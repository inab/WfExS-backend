#!/bin/bash

NODEJS_IMAGE='docker://node:lts-slim'
NODEJS_SIF='node-lts-slim.sif'

set -e


NODEWRAPPERSIFDIR="$(realpath "$(dirname "$0")" 2> /dev/null)"/../share
if [ ! -d "$NODEWRAPPERSIFDIR" ] ; then
	mkdir -p "$NODEWRAPPERSIFDIR"
fi
NODEWRAPPERSIFDIR="$(realpath -L "${NODEWRAPPERSIFDIR}")"
NODEWRAPPERSIF="${NODEWRAPPERSIFDIR}/${NODEJS_SIF}"

if [ ! -f "$NODEWRAPPERSIF" ] ; then
	singularity pull "$NODEWRAPPERSIF" "$NODEJS_IMAGE" > /dev/null 2>&1
fi

exec singularity exec -e "$NODEWRAPPERSIF" node "$@"
