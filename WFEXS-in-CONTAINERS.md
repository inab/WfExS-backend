# Running WfExS from within a container (alpha)!

## Singularity/Apptainer within Singularity/Apptainer (works also for encrypted workdirs)

For this approach we have been using both `-e` and `-c` parameters from Singularity/Apptainer. It is also possible to use `-u`.

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

## Singularity within Docker (works also for encrypted workdirs)


1. Build the docker image following the instructions. Let's assume the tag is `inab/wfexs-backend:latest`.

2. First, create and populate a side caches directory:

   ```bash
   mkdir -p DOCKER_dirs/side_caches
   docker run --rm -ti \
     -u $(id -u):$(id -g) \
     -v ./DOCKER_dirs/side_caches:/.cache \
     inab/wfexs-backend:latest \
     WfExS-backend populate-side-caches
   ```

3. Create two directories, one for WfExS caches, and another one for the
   working directories. Write down the absolute path of the latter.
   
   ```bash
   mkdir -p DOCKER_dirs/wfexs-backend-container-cache
   mkdir -p DOCKER_dirs/wfexs-backend-container-WORKDIR
   readlink -f DOCKER_dirs/wfexs-backend-container-WORKDIR
   ```
   
   (let's suppose it is `/home/user/DOCKER_dirs/wfexs-backend-WORKDIR`).

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
     singularityCommand: singularity
     staticBashCommand: bash-linux-x86_64
   workDir: wfexs-backend-container-WORKDIR
   ```

5. Initialize the pair of keys:

   ```bash
   docker run --rm -ti \
     -u $(id -u):$(id -g) \
     -v ./DOCKER_dirs/side_caches:/.cache \
     -v ./DOCKER_dirs/:/WfExS-instance-dirs/:rw \
     inab/wfexs-backend:latest \
     WfExS-backend -L /WfExS-instance-dirs/local_container_wfexs.yaml init
   ```

6. Use it!

   ```bash
   docker run --rm -ti \
     -u $(id -u):$(id -g) \
     --cap-add SYS_ADMIN  \
     --device /dev/fuse \
     -v ./DOCKER_dirs/side_caches:/root/.cache:ro \
     -v ./DOCKER_dirs/:/WfExS-instance-dirs/:rw \
     -v ./workflow_examples/:/workflow_examples/:ro \
     inab/wfexs-backend:latest \
     WfExS-backend -L /WfExS-instance-dirs/local_container_wfexs.yaml \
       stage -W /workflow_examples/hello/hellow_cwl_singularity.wfex.stage
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

## Podman within Podman

(Tested on 2024-08-31) It fails, due nesting limitations of 

## Docker besides Docker (outdated, WIP)

For this approach there must be a 1:1 volume mapping for the parent working directory.
Otherwise the executions fail.

1. Build the docker image. Let's assume the tag is `inab/wfexs-backend:latest`.

2. First, create and populate a side caches directory:

   ```bash
   mkdir -p side_caches
   docker run --rm -ti \
     -u $(id -u):$(id -g) \
     -v ./side_caches:/.cache \
     inab/wfexs-backend:latest \
     WfExS-backend populate-side-caches
   ```

3. Create two directories, one for WfExS caches, and another one for the
   working directories. Write down the absolute path of the latter.
   
   ```bash
   mkdir -p wfexs-backend-container-cache
   mkdir -p wfexs-backend-container-WORKDIR
   readlink -f wfexs-backend-container-WORKDIR
   ```
   
   (let's suppose it is `/home/user/wfexs-backend-container-WORKDIR`).

4. Create a configuration file which contains the relative or absolute paths
   to both the cache and working directories. For instance, let's suppose it
   is available at `/home/user/local_container_wfexs.yaml` with next content:
   
   ```yaml
   cacheDir: /home/user/wfexs-backend-container-cache
   tools:
     dockerCommand: docker
     encrypted_fs:
       type: gocryptfs
     engineMode: local
     gitCommand: git
     javaCommand: java
     singularityCommand: singularity
     staticBashCommand: bash-linux-x86_64
   workDir: /home/user/wfexs-backend-container-WORKDIR
   ```

5. Initialize the pair of keys:

   ```bash
   docker run --rm -ti \
     -u $(id -u):$(id -g) \
     -v ./side_caches:/.cache \
     -v /home/user:/home/user:rw \
     -v /home/user/wfexs-backend-container-cache/:/home/user/wfexs-backend-container-cache/:rw,rprivate \
     -v /home/user/wfexs-backend-container-WORKDIR/:/home/user/wfexs-backend-container-WORKDIR/:rw,rprivate \
     inab/wfexs-backend:latest \
     WfExS-backend -L /home/user/local_container_wfexs.yaml init
   ```

6. Use it!

   ```bash
   docker run --rm -ti \
     -u $(id -u):$(id -g) \
     --cap-add SYS_ADMIN  \
     --device=/dev/fuse \
     -v /run/docker.sock:/run/docker.sock:rw,rprivate \
     -v ./side_caches/:/.cache/:ro \
     -v /home/user:/home/user:ro \
     -v /home/user/wfexs-backend-container-cache/:/home/user/wfexs-backend-container-cache/:rw,rprivate \
     -v /home/user/wfexs-backend-container-WORKDIR/:/home/user/wfexs-backend-container-WORKDIR/:rw,rprivate \
     inab/wfexs-backend:latest \
     -- \
     WfExS-backend -L /home/user/local_container_wfexs.yaml \
       stage -W /home/user/workflow_examples/hello/hellow_cwl_docker.wfex.stage
   ```
   ```bash
   docker run --rm -ti \
     -u $(id -u):$(id -g) \
     --cap-add SYS_ADMIN  \
     --device=/dev/fuse \
     -v /run/docker.sock:/run/docker.sock:rw,rprivate \
     -v ./side_caches/:/.cache/:ro \
     -v /home/user:/home/user:ro \
     -v /home/user/wfexs-backend-container-cache/:/home/user/wfexs-backend-container-cache/:rw,rprivate \
     -v /home/user/wfexs-backend-container-WORKDIR/:/home/user/wfexs-backend-container-WORKDIR/:rw,rprivate \
     inab/wfexs-backend:latest \
     -- \
     WfExS-backend -L /home/user/local_container_wfexs.yaml \
       staged-workdir offline-exec 'my funny jobname'
   ```
