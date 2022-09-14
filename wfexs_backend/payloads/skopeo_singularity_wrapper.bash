#!/bin/bash

SKOPEO_BASE_IMAGE='alpine:3.13'
SKOPEO_IMAGE='docker://quay.io/containers/skopeo:v1.2.0'
SKOPEO_SIF='skopeo-alpine.sif'

set -e


WRAPPERSIFDIR="$(realpath "$(dirname "$0")" 2> /dev/null)"/../share
if [ ! -d "$WRAPPERSIFDIR" ] ; then
	mkdir -p "$WRAPPERSIFDIR"
fi
WRAPPERSIFDIR="$(realpath -L "${WRAPPERSIFDIR}")"
WRAPPERSIF="${WRAPPERSIFDIR}/${SKOPEO_SIF}"

if [ ! -f "$WRAPPERSIF" ] ; then
	# Coarse way to detect fakeroot support
	if [ -f /etc/subuid ] ; then
		singularity build --fakeroot "$WRAPPERSIF" /proc/self/fd/0 <<EOF
Bootstrap: docker
From: ${SKOPEO_BASE_IMAGE}

%post
    apk update
    apk --no-cache add skopeo
EOF
	else
		singularity pull "$WRAPPERSIF" "$SKOPEO_IMAGE" > /dev/null 2>&1
	fi
fi

exec singularity exec -e "$WRAPPERSIF" skopeo "$@"
