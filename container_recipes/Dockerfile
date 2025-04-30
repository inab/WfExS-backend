FROM	gcc:13 AS entr_build
# Arguments which help customizing what it is included in the generated image
# are spread over the whole dockerfile
ARG	suid_entrypoint_checkout=b47842ece910303b96bd708e73a53a95dfa3d8bc
WORKDIR	/
# hadolint ignore=DL3003
RUN	git clone --filter=blob:none --no-checkout https://github.com/jmfernandez/suid_entrypoint.git && \
	cd suid_entrypoint && \
	git checkout "$suid_entrypoint_checkout" && \
	gcc -static -o suid_entrypoint suid_entrypoint.c

# The default images of python are based on debian
FROM	pypy:3.11-slim AS podman_build
SHELL	["/bin/bash", "-o", "pipefail", "-c"]
# Install apptainer
# hadolint ignore=DL3008
RUN	DPKG_ARCH=$(dpkg --print-architecture) && \
	apt-get update && \
	apt-get install -y wget build-essential git libxml2-dev libxslt-dev zlib1g-dev && \
	wget -O /tmp/rust-installer.sh https://sh.rustup.rs && \
	chmod +x /tmp/rust-installer.sh && \
	/tmp/rust-installer.sh -y && \
	rm -f *.deb
# Install WfExS, trusting the installers in the commit rather than the
# one in the docker recipe
ARG	wfexs_checkout=70277f9708ecb338cfb192ddcbf24c7159d8f319
WORKDIR	/
# hadolint ignore=DL3003,DL3013
RUN	git clone --filter=blob:none --no-checkout https://github.com/inab/WfExS-backend.git && \
	cd WfExS-backend && \
	git sparse-checkout init --cone && \
	PYVER=$(python -c 'import sys; import platform ; print("{}{}.{}".format("pypy" if platform.python_implementation() == "PyPy" else "", sys.version_info.major, sys.version_info.minor))') && \
	git sparse-checkout set constraints-${PYVER}.txt \
	  podman_containers_nokeyring.conf \
	  container_recipes/basic-installer.bash \
	  container_recipes/full-installer.bash && \
	git checkout "${wfexs_checkout}" && \
	grep -vF git+ constraints-${PYVER}.txt > constraints-${PYVER}.txt-relaxed && \
	. ${HOME}/.cargo/env && \
	pip install --no-cache-dir --upgrade pip wheel && \
	pip install --no-cache-dir "git+https://github.com/inab/WfExS-backend.git@${wfexs_checkout}" -c constraints-${PYVER}.txt-relaxed && \
	python -m compileall "$(python -c 'import sys; print(sys.prefix)')" && \
	mv container_recipes/* /

# Install third party software
# JDK version parameters
ARG	JDK_MAJOR_VER=11
ARG	JDK_VER=${JDK_MAJOR_VER}.0.11
ARG	JDK_REV=9
ARG	OPENJ9_VER=0.26.0
# Go version to compile
ARG	GO_VER=1.20.14
# gocryptfs version
ARG	GOCRYPTFS_VER=v2.5.1
# static bash version
ARG	STATIC_BASH_VER=5.1.004-1.2.2
# static busybox version
ARG	BUSYBOX_VER=1.35.0
# hadolint ignore=DL3008
RUN	apt-get install -y --no-install-recommends curl libmagic1 graphviz && \
	JDK_MAJOR_VER="${JDK_MAJOR_VER}" \
	JDK_VER="${JDK_VER}" \
	JDK_REV="${JDK_REV}" \
	OPENJ9_VER="${OPENJ9_VER}" \
	GO_VER="${GO_VER}" \
	GOCRYPTFS_VER="${GOCRYPTFS_VER}" \
	STATIC_BASH_VER="${STATIC_BASH_VER}" \
	BUSYBOX_VER="${BUSYBOX_VER}" \
	bash /full-installer.bash

FROM	pypy:3.11-slim AS podman_image
COPY	--from=podman_build /podman_containers_nokeyring.conf /etc/containers/containers.conf
COPY	--from=podman_build /opt/pypy /opt/pypy
SHELL	["/bin/bash", "-o", "pipefail", "-c"]

# Python 3 is installed so it can be used with cwltool
ARG	apptainer_version=1.3.6
# hadolint ignore=DL3008
RUN	DPKG_ARCH=$(dpkg --print-architecture) && \
	python -c 'import urllib.request ; urllib.request.urlretrieve("https://download.docker.com/linux/debian/gpg", "/etc/apt/keyrings/docker.asc")' && \
	chmod a+r /etc/apt/keyrings/docker.asc && \
	echo \
	"deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/debian \
	$(. /etc/os-release && echo "$VERSION_CODENAME") stable" | \
	tee /etc/apt/sources.list.d/docker.list > /dev/null && \
	apt-get update && \
	apt-get install -y --no-install-recommends git libmagic1 libxml2 libxslt1.1 zlib1g python3-venv podman encfs graphviz docker-ce-cli wget && \
	wget -nv \
	https://github.com/apptainer/apptainer/releases/download/v${apptainer_version}/apptainer_${apptainer_version}_${DPKG_ARCH}.deb \
	https://github.com/apptainer/apptainer/releases/download/v${apptainer_version}/apptainer-suid_${apptainer_version}_${DPKG_ARCH}.deb && \
	apt-get install -y ./*.deb && \
	rm -f *.deb /var/cache/apt/archives/*.deb 

CMD	["/bin/bash"]

FROM podman_image AS docker_image
COPY	--from=entr_build /suid_entrypoint/suid_entrypoint /suid_entrypoint
RUN	chmod u+s /suid_entrypoint
ENTRYPOINT [ "/suid_entrypoint" ]
