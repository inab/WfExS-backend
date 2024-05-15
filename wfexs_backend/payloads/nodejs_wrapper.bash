#!/bin/bash

NODEJS_DOCKER_IMAGE='node:lts-slim'
NODEJS_SING_IMAGE="docker://${NODEJS_DOCKER_IMAGE}"
NODEJS_SIF='node-lts-slim.sif'

PROG="$(realpath "$0")"

for nativeNode in $(type -a -P node nodejs || true) ; do
	# Trying to avoiding a loop
	if [ "$PROG" != "$nativeNode" ] ; then
		# Checking it is working properly
		if [ "$("$nativeNode" -e 'process.stdout.write(2 + 2 + "\n")')" = 4 ] ; then
			exec "$nativeNode" "$@"
		fi
	fi
done

set -e
singCommand="$(type -P singularity || true)"
if [ -n "$singCommand" ] ; then
	NODEWRAPPERSIFDIR="$(realpath "$(dirname "$0")" 2> /dev/null)"/../share
	if [ ! -d "$NODEWRAPPERSIFDIR" ] ; then
		mkdir -p "$NODEWRAPPERSIFDIR"
	fi
	NODEWRAPPERSIFDIR="$(realpath -L "${NODEWRAPPERSIFDIR}")"
	NODEWRAPPERSIF="${NODEWRAPPERSIFDIR}/${NODEJS_SIF}"

	if [ ! -f "$NODEWRAPPERSIF" ] ; then
		"$singCommand" pull "$NODEWRAPPERSIF" "$NODEJS_SING_IMAGE" > /dev/null 2>&1
	fi

	exec "$singCommand" exec -e "$NODEWRAPPERSIF" node "$@"
else
	dockerCommand="$(type -P podman docker || true | head -n 1)"
	if [ -n "$dockerCommand" ] ; then
		"$dockerCommand" pull "$NODEJS_DOCKER_IMAGE" > /dev/null 2>&1
		exec "$dockerCommand" run --rm -ti "$NODEJS_DOCKER_IMAGE" node "$@"
	else
		exit 1
	fi
fi
