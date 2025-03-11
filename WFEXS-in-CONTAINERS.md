# Running WfExS from within a container (alpha)!

## Singularity/Apptainer within Singularity/Apptainer (works also for encrypted workdirs)

For this approach we have been using both `-e` and `-c` parameters from Singularity/Apptainer. It is also possible to use `-u`.

### Steps

1. Build the SIF image. Let's assume the file is `wfexs-backend-latest.sif`.

2. First, create and populate a side caches directory:

   ```bash
   mkdir -p SING_dirs/side_caches
   singularity exec \
     -e -c \
     -B ./SING_dirs/side_caches:${HOME}/.cache \
     wfexs-backend-latest.sif \
     WfExS-backend populate-side-caches
   ```

3. Create two directories, one for WfExS caches, and another one for the
   working directories. Write down the absolute path of the latter.
   
   ```bash
   mkdir -p SING_dirs/wfexs-backend-container-cache
   mkdir -p SING_dirs/wfexs-backend-container-WORKDIR
   readlink -f SING_dirs/wfexs-backend-container-WORKDIR
   ```
   
   (let's suppose it is `/home/user/SING_dirs/wfexs-backend-container-WORKDIR`).

4. Create a configuration file which contains the relative or absolute paths
   to both the cache and working directories. For instance, let's suppose it
   is available at `/home/user/SING_dirs/local_container_wfexs.yaml` with next content:
   
   ```yaml
   cacheDir: wfexs-backend-container-cache
   tools:
     dockerCommand: docker
     encrypted_fs:
       type: gocryptfs
     engineMode: local
     gitCommand: git
     javaCommand: java
     pythonCommand: /usr/bin/python3
     singularityCommand: singularity
     staticBashCommand: bash-linux-x86_64
   workDir: wfexs-backend-container-WORKDIR
   ```

5. Initialize the pair of keys:

   ```bash
   singularity exec \
     -e -c \
     -B ./SING_dirs/side_caches:${HOME}/.cache \
     -B ./SING_dirs/:/home/${USER}/WfExS-instance-dirs/:rw \
     wfexs-backend-latest.sif \
     WfExS-backend -L /home/${USER}/WfExS-instance-dirs/local_container_wfexs.yaml init
   ```

6. Use it!

   ```bash
   singularity exec \
     -e -c \
     --add-caps SYS_ADMIN  \
     -B /dev/fuse \
     -B ./SING_dirs/side_caches/:${HOME}/.cache/:ro \
     -B ./SING_dirs/:/home/${USER}/WfExS-instance-dirs/:rw \
     -B ./workflow_examples/:/home/${USER}/workflow_examples/:ro \
     wfexs-backend-latest.sif \
     WfExS-backend -L /home/${USER}/WfExS-instance-dirs/local_container_wfexs.yaml \
       stage -W /home/${USER}/workflow_examples/hello/hellow_cwl_singularity.wfex.stage
   ```

   ```bash
   singularity exec \
     -e -c \
     --add-caps SYS_ADMIN  \
     -B /dev/fuse \
     -B ./SING_dirs/side_caches/:${HOME}/.cache/:ro \
     -B ./SING_dirs/:/home/${USER}/WfExS-instance-dirs/:rw \
     -B ./workflow_examples/:/home/${USER}/workflow_examples/:ro \
     wfexs-backend-latest.sif \
     WfExS-backend -L /home/${USER}/WfExS-instance-dirs/local_container_wfexs.yaml \
       staged-workdir offline-exec 'my funny jobname'
   ```

## Singularity/Apptainer within Podman (works also for encrypted workdirs)

1. Build the podman image following the instructions. Let's assume the tag is `inab/wfexs-backend:latest` (whose canonical representation is `localhost/inab/wfexs-backend:latest`).

2. First, create and populate a side caches directory:

   ```bash
   mkdir -p PODMAN_dirs/side_caches
   podman run --rm -ti \
     -v ./PODMAN_dirs/side_caches:/root/.cache \
     localhost/inab/wfexs-backend:latest \
     WfExS-backend populate-side-caches
   ```

3. Create two directories, one for WfExS caches, and another one for the
   working directories. Write down the absolute path of the latter.
   
   ```bash
   mkdir -p PODMAN_dirs/wfexs-backend-container-cache
   mkdir -p PODMAN_dirs/wfexs-backend-container-WORKDIR
   readlink -f PODMAN_dirs/wfexs-backend-container-WORKDIR
   ```
   
   (let's suppose it is `/home/user/PODMAN_dirs/wfexs-backend-WORKDIR`).

4. Create a configuration file which contains the relative or absolute paths
   to both the cache and working directories. For instance, let's suppose it
   is available at `/home/user/PODMAN_dirs/local_container_wfexs.yaml` with next content:
   
   ```yaml
   cacheDir: wfexs-backend-container-cache
   tools:
     dockerCommand: docker
     encrypted_fs:
       type: gocryptfs
     engineMode: local
     gitCommand: git
     javaCommand: java
     pythonCommand: /usr/bin/python3
     singularityCommand: singularity
     staticBashCommand: bash-linux-x86_64
   workDir: wfexs-backend-container-WORKDIR
   ```

5. Initialize the pair of keys:

   ```bash
   podman run --rm -ti \
     -v ./PODMAN_dirs/side_caches:/root/.cache \
     -v ./PODMAN_dirs/:/root/WfExS-instance-dirs/:rw \
     localhost/inab/wfexs-backend:latest \
     WfExS-backend -L /root/WfExS-instance-dirs/local_container_wfexs.yaml init
   ```

6. Use it!

   ```bash
   podman run --rm -ti \
     --cap-add SYS_ADMIN  \
     --device /dev/fuse \
     -v ./PODMAN_dirs/side_caches:/root/.cache:ro \
     -v ./PODMAN_dirs/:/root/WfExS-instance-dirs/:rw \
     -v ./workflow_examples/:/root/workflow_examples/:ro \
     localhost/inab/wfexs-backend:latest \
     WfExS-backend -L /root/WfExS-instance-dirs/local_container_wfexs.yaml \
       stage -W /root/workflow_examples/hello/hellow_cwl_singularity.wfex.stage
   ```

   ```bash
   podman run --rm -ti \
     --cap-add SYS_ADMIN  \
     --device /dev/fuse \
     -v ./PODMAN_dirs/side_caches:/root/.cache:ro \
     -v ./PODMAN_dirs/:/root/WfExS-instance-dirs/:rw \
     -v ./workflow_examples/:/root/workflow_examples/:ro \
     localhost/inab/wfexs-backend:latest \
     WfExS-backend -L /root/WfExS-instance-dirs/local_container_wfexs.yaml \
       staged-workdir offline-exec 'my funny jobname'
   ```

## Singularity/Apptainer within Docker (works also for encrypted workdirs)

(2025-03-11) Some new releases of docker and apptainer have tightened their security restrictions.
Although `--security-opt seccomp=unconfined` and `--security-opt systempaths=unconfined` are
currently used for workflow execution cases with Nextflow workflows, `--cap-add SYS_ADMIN` can
be used with cwltool workflows. The worst case scenario requires using `--privileged` flag.


1. Build the docker image following the instructions. Let's assume the tag is `inab/wfexs-backend:latest`.

2. First, create and populate a side caches directory:

   ```bash
   mkdir -p SING_in_DOCKER_dirs/side_caches
   docker run --rm -ti \
     -u $(id -u):$(id -g) \
     -v ./SING_in_DOCKER_dirs/side_caches:/.cache \
     inab/wfexs-backend:latest \
     WfExS-backend populate-side-caches
   ```

3. Create two directories, one for WfExS caches, and another one for the
   working directories. Write down the absolute path of the latter.
   
   ```bash
   mkdir -p SING_in_DOCKER_dirs/wfexs-backend-container-cache
   mkdir -p SING_in_DOCKER_dirs/wfexs-backend-container-WORKDIR
   readlink -f SING_in_DOCKER_dirs/wfexs-backend-container-WORKDIR
   ```
   
   (let's suppose it is `/home/${USER}/SING_in_DOCKER_dirs/wfexs-backend-WORKDIR`).

4. Create a configuration file which contains the relative or absolute paths
   to both the cache and working directories. For instance, let's suppose it
   is available at `/home/${USER}/SING_in_DOCKER_dirs/local_container_wfexs.yaml` with next content:
   
   ```yaml
   cacheDir: wfexs-backend-container-cache
   tools:
     dockerCommand: docker
     encrypted_fs:
       type: gocryptfs
     engineMode: local
     gitCommand: git
     javaCommand: java
     pythonCommand: /usr/bin/python3
     singularityCommand: singularity
     staticBashCommand: bash-linux-x86_64
   workDir: wfexs-backend-container-WORKDIR
   ```

5. Initialize the pair of keys:

   ```bash
   docker run --rm -ti \
     -u $(id -u):$(id -g) \
     -v ./SING_in_DOCKER_dirs/side_caches:/.cache \
     -v ./SING_in_DOCKER_dirs/:/WfExS-instance-dirs/:rw \
     inab/wfexs-backend:latest \
     WfExS-backend -L /WfExS-instance-dirs/local_container_wfexs.yaml init
   ```

6. Use it!

   ```bash
   docker run --rm -ti \
     -u $(id -u):$(id -g) \
     --cap-add SYS_ADMIN  \
     --device /dev/fuse \
     -v ./SING_in_DOCKER_dirs/side_caches:/.cache:ro \
     -v ./SING_in_DOCKER_dirs/:/WfExS-instance-dirs/:rw \
     -v ./workflow_examples/:/workflow_examples/:ro \
     inab/wfexs-backend:latest \
     WfExS-backend -L /WfExS-instance-dirs/local_container_wfexs.yaml \
       stage -W /workflow_examples/hello/hellow_cwl_singularity.wfex.stage
   ```

   ```bash
   docker run --rm -ti \
     -u $(id -u):$(id -g) \
     --security-opt seccomp=unconfined \
     --security-opt systempaths=unconfined  \
     --device /dev/fuse \
     -v ./SING_in_DOCKER_dirs/side_caches:/.cache:ro \
     -v ./SING_in_DOCKER_dirs/:/WfExS-instance-dirs/:rw \
     -v ./workflow_examples/:/workflow_examples/:ro \
     inab/wfexs-backend:latest \
     WfExS-backend -L /WfExS-instance-dirs/local_container_wfexs.yaml \
       staged-workdir offline-exec 'my funny jobname'
   ```

## Podman within Singularity/Apptainer

(Tested on 2024-08-31) It fails just materializing, due nesting limitations of user namespaces (used both by Podman and Singularity).

## Podman within Podman

(Tested on 2024-08-31) It fails just materializing, due nesting limitations of user namespaces (used by Podman).

## Podman within Docker

(Tested on 2024-09-09) It fails running the workflow due issues with crun. First issue arose next crun error:

```
crun: create keyring `e94eae775d1a0e71b067f98cd569d309a2fcf36c6afd505d0868a32d47629661`: Operation not permitted: OCI permission denied
```

which was skipped thanks to commit 9d935b20ba5d75d8d62488941c9c4a3c2c0c101d . But next issue cannot be skipped:

```
OCI runtime error: crun: open /proc/sys/net/ipv4/ping_group_range: Read-only file system
```

### Steps

1. Build the docker image following the instructions. Let's assume the tag is `inab/wfexs-backend:latest`.

2. First, create and populate a side caches directory:

   ```bash
   mkdir -p PODMAN_in_DOCKER_dirs/side_caches
   docker run --rm -ti \
     -u $(id -u):$(id -g) \
     -v ./PODMAN_in_DOCKER_dirs/side_caches:/.cache \
     inab/wfexs-backend:latest \
     WfExS-backend populate-side-caches
   ```

3. Create two directories, one for WfExS caches, and another one for the
   working directories. Write down the absolute path of the latter.
   
   ```bash
   mkdir -p PODMAN_in_DOCKER_dirs/wfexs-backend-container-cache
   mkdir -p PODMAN_in_DOCKER_dirs/wfexs-backend-container-WORKDIR
   readlink -f PODMAN_in_DOCKER_dirs/wfexs-backend-container-WORKDIR
   ```
   
   (let's suppose it is `/home/${USER}/PODMAN_in_DOCKER_dirs/wfexs-backend-WORKDIR`).

4. Create a configuration file which contains the relative or absolute paths
   to both the cache and working directories. For instance, let's suppose it
   is available at `/home/${USER}/PODMAN_in_DOCKER_dirs/local_container_wfexs.yaml` with next content:
   
   ```yaml
   cacheDir: wfexs-backend-container-cache
   tools:
     dockerCommand: docker
     encrypted_fs:
       type: gocryptfs
     engineMode: local
     gitCommand: git
     javaCommand: java
     pythonCommand: /usr/bin/python3
     singularityCommand: singularity
     staticBashCommand: bash-linux-x86_64
   workDir: wfexs-backend-container-WORKDIR
   ```

5. Initialize the pair of keys:

   ```bash
   docker run --rm -ti \
     -u $(id -u):$(id -g) \
     -v ./PODMAN_in_DOCKER_dirs/side_caches:/.cache \
     -v ./PODMAN_in_DOCKER_dirs/:/WfExS-instance-dirs/:rw \
     inab/wfexs-backend:latest \
     WfExS-backend -L /WfExS-instance-dirs/local_container_wfexs.yaml init
   ```

6. Use it!

   ```bash
   docker run --rm -ti \
     -u $(id -u):$(id -g) \
     --cap-add SYS_ADMIN  \
     --device /dev/fuse \
     -v ./PODMAN_in_DOCKER_dirs/side_caches:/.cache:ro \
     -v ./PODMAN_in_DOCKER_dirs/:/WfExS-instance-dirs/:rw \
     -v ./workflow_examples/:/workflow_examples/:ro \
     inab/wfexs-backend:latest \
     WfExS-backend -L /WfExS-instance-dirs/local_container_wfexs.yaml \
       stage -W /workflow_examples/hello/hellow_cwl_podman.wfex.stage
   ```

   ```bash
   docker run --rm -ti \
     --cap-add SYS_ADMIN  \
     --device /dev/fuse \
     -v ./PODMAN_in_DOCKER_dirs/side_caches:/.cache:ro \
     -v ./PODMAN_in_DOCKER_dirs/:/WfExS-instance-dirs/:rw \
     -v ./workflow_examples/:/workflow_examples/:ro \
     inab/wfexs-backend:latest \
     WfExS-backend -L /WfExS-instance-dirs/local_container_wfexs.yaml \
       staged-workdir offline-exec 'my funny jobname'
   ```

## Docker within Singularity/Apptainer

For this approach there must be a 1:1 volume mapping for the parent working directory (wfexs-backend-container-WORKDIR).
Otherwise the executions fail.

For this approach we have been using both `-e` and `-c` parameters from Singularity/Apptainer.

### Steps

1. Build the SIF image. Let's assume the file is `wfexs-backend-latest.sif`.

2. First, create and populate a side caches directory:

   ```bash
   mkdir -p DOCKER_in_SING_dirs/side_caches
   singularity exec \
     -e -c \
     -B ./DOCKER_in_SING_dirs/side_caches:${HOME}/.cache \
     wfexs-backend-latest.sif \
     WfExS-backend populate-side-caches
   ```

3. Create two directories, one for WfExS caches, and another one for the
   working directories. Write down the absolute path of the latter.
   
   ```bash
   mkdir -p DOCKER_in_SING_dirs/wfexs-backend-container-cache
   mkdir -p DOCKER_in_SING_dirs/wfexs-backend-container-WORKDIR
   readlink -f DOCKER_in_SING_dirs/wfexs-backend-container-WORKDIR
   ```
   
   (let's suppose it is `/home/${USER}/DOCKER_in_SING_dirs/wfexs-backend-container-WORKDIR`).

4. Create a configuration file which contains the relative or absolute paths
   to both the cache and working directories. For instance, let's suppose it
   is available at `/home/${USER}/DOCKER_in_SING_dirs/local_container_wfexs.yaml` with next content:
   
   ```yaml
   cacheDir: wfexs-backend-container-cache
   tools:
     dockerCommand: docker
     encrypted_fs:
       type: gocryptfs
     engineMode: local
     gitCommand: git
     javaCommand: java
     pythonCommand: /usr/bin/python3
     singularityCommand: singularity
     staticBashCommand: bash-linux-x86_64
   workDir: wfexs-backend-container-WORKDIR
   ```

5. Initialize the pair of keys:

   ```bash
   singularity exec \
     -e -c \
     -B ./DOCKER_in_SING_dirs/side_caches:${HOME}/.cache \
     -B /home/${USER}/DOCKER_in_SING_dirs/ \
     wfexs-backend-latest.sif \
     WfExS-backend -L /home/${USER}/DOCKER_in_SING_dirs/local_container_wfexs.yaml init
   ```

6. Use it!

   ```bash
   singularity exec \
     -e -c \
     --add-caps SYS_ADMIN  \
     -B /dev/fuse \
     -B /run/docker.sock \
     -B ./DOCKER_in_SING_dirs/side_caches/:${HOME}/.cache/:ro \
     -B /home/${USER}/DOCKER_in_SING_dirs/ \
     -B ./workflow_examples/:/home/${USER}/workflow_examples/:ro \
     wfexs-backend-latest.sif \
     WfExS-backend -L /home/${USER}/DOCKER_in_SING_dirs/local_container_wfexs.yaml \
       stage -W /home/${USER}/workflow_examples/hello/hellow_cwl_podman.wfex.stage
   ```

   ```bash
   singularity exec \
     -e -c \
     --add-caps SYS_ADMIN  \
     -B /dev/fuse \
     -B /run/docker.sock \
     -B ./DOCKER_in_SING_dirs/side_caches/:${HOME}/.cache/:ro \
     -B /home/${USER}/DOCKER_in_SING_dirs/:/home/${USER}/DOCKER_in_SING_dirs/:rw \
     -B ./workflow_examples/:/home/${USER}/workflow_examples/:ro \
     wfexs-backend-latest.sif \
     WfExS-backend -L /home/${USER}/DOCKER_in_SING_dirs/local_container_wfexs.yaml \
       staged-workdir offline-exec 'my funny jobname'
   ```

## Docker within Podman (does not work with encrypted workdirs feature)

For this approach there must be a 1:1 volume mapping for the parent working directory (wfexs-backend-container-WORKDIR).
Otherwise the executions fail.

Also, either next command

```bash
sudo setfacl -m u:$(id -u):rw -- /run/docker.sock
```

or next command are needed

```bash
sudo setfacl -m g:$(id -g):rw -- /run/docker.sock
```

to avoid next issue with almost any docker command within podman instance:

```
permission denied while trying to connect to the Docker daemon socket at unix:///var/run/docker.sock: Head "http://%2Fvar%2Frun%2Fdocker.sock/_ping": dial unix /var/run/docker.sock: connect: permission denied
```

### Steps

1. Build the docker image. Let's assume the tag is `inab/wfexs-backend:latest`.

2. First, create and populate a side caches directory:

   ```bash
   mkdir -p DOCKER_in_PODMAN_dirs/side_caches
   podman run --rm -ti \
     -v ./DOCKER_in_PODMAN_dirs/side_caches:/root/.cache \
     localhost/inab/wfexs-backend:latest \
     WfExS-backend populate-side-caches
   ```

3. Create two directories, one for WfExS caches, and another one for the
   working directories. Write down the absolute path of the latter.
   
   ```bash
   mkdir -p DOCKER_in_PODMAN_dirs/wfexs-backend-container-cache
   mkdir -p DOCKER_in_PODMAN_dirs/wfexs-backend-container-WORKDIR
   readlink -f DOCKER_in_PODMAN_dirs/wfexs-backend-container-WORKDIR
   ```
   
   (let's suppose it is `/home/${USER}/DOCKER_in_PODMAN_dirs/wfexs-backend-WORKDIR`).

4. Create a configuration file which contains the relative or absolute paths
   to both the cache and working directories. For instance, let's suppose it
   is available at `/home/${USER}/DOCKER_in_PODMAN_dirs/local_container_wfexs.yaml` with next content:
   
   ```yaml
   cacheDir: wfexs-backend-container-cache
   tools:
     dockerCommand: docker
     encrypted_fs:
       type: gocryptfs
     engineMode: local
     gitCommand: git
     javaCommand: java
     pythonCommand: /usr/bin/python3
     singularityCommand: singularity
     staticBashCommand: bash-linux-x86_64
   workDir: wfexs-backend-container-WORKDIR
   ```

5. Initialize the pair of keys:

   ```bash
   podman run --rm -ti \
     -v ./DOCKER_in_PODMAN_dirs/side_caches:/root/.cache \
     -v /home/${USER}/DOCKER_in_PODMAN_dirs/:/home/${USER}/DOCKER_in_PODMAN_dirs/:rw \
     localhost/inab/wfexs-backend:latest \
     WfExS-backend -L /home/${USER}/DOCKER_in_PODMAN_dirs/local_container_wfexs.yaml init
   ```

6. Use it!

   ```bash
   podman run --rm -ti \
     --cap-add SYS_ADMIN  \
     --device=/dev/fuse \
     -v /run/docker.sock:/run/docker.sock:rw,rprivate \
     -v ./DOCKER_in_PODMAN_dirs/side_caches/:/root/.cache/:ro \
     -v /home/${USER}/DOCKER_in_PODMAN_dirs/:/home/${USER}/DOCKER_in_PODMAN_dirs/:rw \
     -v ./workflow_examples/:/workflow_examples/:ro \
     localhost/inab/wfexs-backend:latest \
     WfExS-backend -L /home/${USER}/DOCKER_in_PODMAN_dirs/local_container_wfexs.yaml \
       stage -W /workflow_examples/hello/hellow_cwl_docker.wfex.stage
   ```
   ```bash
   podman run --rm -ti \
     --cap-add SYS_ADMIN  \
     --device=/dev/fuse \
     -v /run/docker.sock:/run/docker.sock:rw,rprivate \
     -v ./DOCKER_in_PODMAN_dirs/side_caches/:/root/.cache/:ro \
     -v /home/${USER}/DOCKER_in_PODMAN_dirs/:/home/${USER}/DOCKER_in_PODMAN_dirs/:rw \
     localhost/inab/wfexs-backend:latest \
     WfExS-backend -L /home/${USER}/DOCKER_in_PODMAN_dirs/local_container_wfexs.yaml \
       staged-workdir offline-exec 'my funny jobname'
   ```

## Docker besides Docker (does not work with encrypted workdirs feature)

For this approach there must be a 1:1 volume mapping for the parent working directory (wfexs-backend-container-WORKDIR).
Otherwise the executions fail.

### Steps

1. Build the docker image. Let's assume the tag is `inab/wfexs-backend:latest`.

2. First, create and populate a side caches directory:

   ```bash
   mkdir -p DOCKER_in_DOCKER_dirs/side_caches
   docker run --rm -ti \
     -u $(id -u):$(id -g) \
     -v ./DOCKER_in_DOCKER_dirs/side_caches:/.cache \
     inab/wfexs-backend:latest \
     WfExS-backend populate-side-caches
   ```

3. Create two directories, one for WfExS caches, and another one for the
   working directories. Write down the absolute path of the latter.
   
   ```bash
   mkdir -p DOCKER_in_DOCKER_dirs/wfexs-backend-container-cache
   mkdir -p DOCKER_in_DOCKER_dirs/wfexs-backend-container-WORKDIR
   readlink -f DOCKER_in_DOCKER_dirs/wfexs-backend-container-WORKDIR
   ```
   
   (let's suppose it is `/home/${USER}/DOCKER_in_DOCKER_dirs/wfexs-backend-WORKDIR`).

4. Create a configuration file which contains the relative or absolute paths
   to both the cache and working directories. For instance, let's suppose it
   is available at `/home/${USER}/DOCKER_in_DOCKER_dirs/local_container_wfexs.yaml` with next content:
   
   ```yaml
   cacheDir: wfexs-backend-container-cache
   tools:
     dockerCommand: docker
     encrypted_fs:
       type: gocryptfs
     engineMode: local
     gitCommand: git
     javaCommand: java
     pythonCommand: /usr/bin/python3
     singularityCommand: singularity
     staticBashCommand: bash-linux-x86_64
   workDir: wfexs-backend-container-WORKDIR
   ```

5. Initialize the pair of keys:

   ```bash
   docker run --rm -ti \
     -u $(id -u):$(id -g) \
     -v ./DOCKER_in_DOCKER_dirs/side_caches:/.cache \
     -v /home/${USER}/DOCKER_in_DOCKER_dirs/:/home/${USER}/DOCKER_in_DOCKER_dirs/:rw \
     inab/wfexs-backend:latest \
     WfExS-backend -L /home/${USER}/DOCKER_in_DOCKER_dirs/local_container_wfexs.yaml init
   ```

6. Use it!

   ```bash
   docker run --rm -ti \
     -u $(id -u):$(id -g) \
     --cap-add SYS_ADMIN  \
     --device=/dev/fuse \
     -v /run/docker.sock:/run/docker.sock:rw,rprivate \
     -v ./DOCKER_in_DOCKER_dirs/side_caches/:/.cache/:ro \
     -v /home/${USER}/DOCKER_in_DOCKER_dirs/:/home/${USER}/DOCKER_in_DOCKER_dirs/:rw \
     -v ./workflow_examples/:/workflow_examples/:ro \
     inab/wfexs-backend:latest \
     WfExS-backend -L /home/${USER}/DOCKER_in_DOCKER_dirs/local_container_wfexs.yaml \
       stage -W /workflow_examples/hello/hellow_cwl_docker.wfex.stage
   ```
   ```bash
   docker run --rm -ti \
     -u $(id -u):$(id -g) \
     --cap-add SYS_ADMIN  \
     --device=/dev/fuse \
     -v /run/docker.sock:/run/docker.sock:rw,rprivate \
     -v ./DOCKER_in_DOCKER_dirs/side_caches/:/.cache/:ro \
     -v /home/${USER}/DOCKER_in_DOCKER_dirs/:/home/${USER}/DOCKER_in_DOCKER_dirs/:rw \
     inab/wfexs-backend:latest \
     WfExS-backend -L /home/${USER}/DOCKER_in_DOCKER_dirs/local_container_wfexs.yaml \
       staged-workdir offline-exec 'my funny jobname'
   ```
