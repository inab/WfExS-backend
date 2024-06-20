# The default images of python are based on debian
FROM	python:3.12
# These arguments help customizing what it is included in the generated image
ARG	wfexs_checkout=0.99.9
ARG	apptainer_version=1.3.2
# JDK version parameters
ARG	JDK_MAJOR_VER=11
ARG	JDK_VER=${JDK_MAJOR_VER}.0.11
ARG	JDK_REV=9
ARG	OPENJ9_VER=0.26.0
# Go version to compile
ARG	GO_VER=1.17.13
# gocryptfs version
ARG	GOCRYPTFS_VER=v2.4.0
# static bash version
ARG	STATIC_BASH_VER=5.1.004-1.2.2
# static busybox version
ARG	BUSYBOX_VER=1.35.0
SHELL	["/bin/bash", "-o", "pipefail", "-c"]
# Install apptainer
RUN	wget \
	https://github.com/apptainer/apptainer/releases/download/v${apptainer_version}/apptainer_${apptainer_version}_amd64.deb \
	https://github.com/apptainer/apptainer/releases/download/v${apptainer_version}/apptainer-suid_${apptainer_version}_amd64.deb && \
	apt-get update && \
	apt-get install -y ./*.deb && \
	rm -f *.deb
# Install docker-ce-cli
# hadolint ignore=DL3008
RUN	wget -o /etc/apt/keyrings/docker.asc https://download.docker.com/linux/debian/gpg && \
	chmod a+r /etc/apt/keyrings/docker.asc && \
	echo \
	"deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/debian \
	$(. /etc/os-release && echo "$VERSION_CODENAME") stable" | \
	tee /etc/apt/sources.list.d/docker.list > /dev/null && \
	apt-get update && \
	apt-get install -y --no-install-recommends docker-ce-cli
# Install both podman and encfs
# hadolint ignore=DL3008
RUN	apt-get install -y podman encfs
# Install WfExS
RUN	pip install --no-cache-dir "git+https://github.com/inab/WfExS-backend.git@${wfexs_checkout}"
# Transfer other third party installation script
WORKDIR	/
COPY	basic-installer.bash full-installer.bash ./
# Install third party software
RUN	JDK_MAJOR_VER="${JDK_MAJOR_VER}" \
	JDK_VER="${JDK_VER}" \
	JDK_REV="${JDK_REV}" \
	OPENJ9_VER="${OPENJ9_VER}" \
	GO_VER="${GO_VER}" \
	GOCRYPTFS_VER="${GOCRYPTFS_VER}" \
	STATIC_BASH_VER="${STATIC_BASH_VER}" \
	BUSYBOX_VER="${BUSYBOX_VER}" \
	bash full-installer.bash
CMD	["bash"]