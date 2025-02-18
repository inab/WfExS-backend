#!/bin/sh

if [ $# = 0 ] ; then
	echo "Usage: $0 patched_seccomp.json [template_seccomp.json]"
	exit 1
fi

patched_seccomp="$1"
if [ $# = 1 ] ; then
	template_seccomp=/usr/share/containers/seccomp.json
else
	template_seccomp="$2"
fi

if [ ! -f "$template_seccomp" ] ; then
	# TODO
	echo TODO
	exit 1
	template_seccomp=
fi


# Inspired in https://wiki.alpinelinux.org/wiki/Build_with_abuild_rootbld_in_Docker_container
read -d '' -r BWRAP_PATCH <<'EOF'
. * {
	"syscalls": (.syscalls + [
		{
			"names": [
				"clone",
				"mount",
				"pivot_root",
				"setdomainname",
				"sethostname",
				"umount2"
			],
			"action": "SCMP_ACT_ALLOW"
		}
	]
	)
}
EOF

jq "${BWRAP_PATCH}" < "$template_seccomp" > "$patched_seccomp"