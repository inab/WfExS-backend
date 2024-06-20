FROM	python:3.12
ARG	wfexs_checkout=0.99.9
ARG	apptainer_version=1.3.2
ARG	JDK_MAJOR_VER=11
ARG	JDK_VER=${JDK_MAJOR_VER}.0.11
ARG	JDK_REV=9
ARG	OPENJ9_VER=0.26.0
RUN	wget \
	https://github.com/apptainer/apptainer/releases/download/v${apptainer_version}/apptainer_${apptainer_version}_amd64.deb \
	https://github.com/apptainer/apptainer/releases/download/v${apptainer_version}/apptainer-suid_${apptainer_version}_amd64.deb && \
	apt-get update && \
	apt-get install -y ./*.deb && \
	rm -f *.deb
RUN	curl -fsSL https://download.docker.com/linux/debian/gpg -o /etc/apt/keyrings/docker.asc && \
	chmod a+r /etc/apt/keyrings/docker.asc && \
	echo \
	"deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/debian \
	$(. /etc/os-release && echo "$VERSION_CODENAME") stable" | \
	tee /etc/apt/sources.list.d/docker.list > /dev/null && \
	apt-get update && \
	apt-get install -y --no-install-recommends docker-ce-cli
RUN	apt-get install -y podman encfs
COPY	install-openjdk.bash .
RUN	bash install-openjdk.bash "${JDK_MAJOR_VER}" "${JDK_VER}" "${JDK_REV}" "${OPENJ9_VER}"
RUN	pip install --no-cache-dir "git+https://github.com/inab/WfExS-backend.git@${wfexs_checkout}"