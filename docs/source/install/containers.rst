.. _installation_container:


Easy creation of WfExS container image
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

This section describes how to build a container image containing WfExS and its preconditions.

.. _installation_container_docker:

Docker
^^^^^^
.. note::
   Prerequisites: ensure Docker is properly installed and running on your system.

You can build the Docker image for a specific version (release, tag, branch, or commit) 
without cloning the entire repository or downloading the Dockerfile. Use the following 
bash command pattern:

.. code-block:: bash

   # WFEXS_VER can be either a branch, a tag or a commit hash
   WFEXS_VER=574fe343c0b59eecd95afbc67894456359ebe649
   docker build -t inab/wfexs-backend:${WFEXS_VER} \
   --build-arg wfexs_checkout="${WFEXS_VER}" \
   https://raw.githubusercontent.com/inab/WfExS-backend/${WFEXS_VER}/container_recipes/Dockerfile


If the Docker client does not support URLs, you need a local copy of the Dockerfile. 
From the project root, use the following commands:

.. code-block:: bash
   # WFEXS_VER can be either a branch, a tag or a commit hash
   WFEXS_VER=574fe343c0b59eecd95afbc67894456359ebe649
   mkdir WfExS_docker_build
   cd WfExS_docker_build
   curl -O https://raw.githubusercontent.com/inab/WfExS-backend/${WFEXS_VER}/container_recipes/Dockerfile

   docker build -t inab/wfexs-backend:${WFEXS_VER} \
   --build-arg wfexs_checkout="${WFEXS_VER}" \
   Dockerfile

.. _installation_container_podman:

Podman
^^^^^^
.. note::
   Prerequisites: ensure Podman is properly installed and running on your system.


You can build the Podman image for a specific version (release, tag, branch, or commit) without cloning the entire repository or downloading the recipe. Use the following bash command pattern:

.. code-block:: bash

   # WFEXS_VER can be either a branch, a tag or a commit hash
   WFEXS_VER=574fe343c0b59eecd95afbc67894456359ebe649
   podman build -t inab/wfexs-backend:${WFEXS_VER} \
   --build-arg wfexs_checkout="${WFEXS_VER}" \
   https://raw.githubusercontent.com/inab/WfExS-backend/${WFEXS_VER}/container_recipes/Dockerfile
   

If the Podman client does not support URLs, you will need a local copy of the Dockerfile. 
From the project root, use the following commands:

.. code-block:: bash

   # WFEXS_VER can be either a branch, a tag or a commit hash
   WFEXS_VER=574fe343c0b59eecd95afbc67894456359ebe649
   mkdir WfExS_podman_build
   cd WfExS_podman_build
   curl -O https://raw.githubusercontent.com/inab/WfExS-backend/${WFEXS_VER}/container_recipes/Dockerfile

   podman build -t inab/wfexs-backend:${WFEXS_VER} \
   --build-arg wfexs_checkout="${WFEXS_VER}" \
   Dockerfile


SIF image
^^^^^^^^^

.. note::
   Prerequisites: ensure that either Apptainer or Singularity is properly installed and set up on your system.


There are three different methods to create a SIF (Singularity Image Format) image of WfExS:

1. **Using curl or a local copy of the repository**

   This method requires a modern enough version of either Apptainer (1.3 or later) or Singularity (4.0 or later). You can use `curl` or have a local copy of the repository.

   .. code-block:: bash

      # WFEXS_VER can be either a branch, a tag or a commit hash
      WFEXS_VER=574fe343c0b59eecd95afbc67894456359ebe649
      mkdir WfExS_SIF_build
      cd WfExS_SIF_build
      curl -O https://raw.githubusercontent.com/inab/WfExS-backend/${WFEXS_VER}/container_recipes/Singularity.def
      singularity build \
      --build-arg wfexs_checkout="${WFEXS_VER}" \
      wfexs-backend-${WFEXS_VER}.sif Singularity.def

   .. code-block:: bash

      # WFEXS_VER can be either a branch, a tag or a commit hash
      WFEXS_VER=574fe343c0b59eecd95afbc67894456359ebe649
      singularity build \
      --build-arg wfexs_checkout="${WFEXS_VER}" \
      wfexs-backend-${WFEXS_VER}.sif container_recipes/Singularity.def

2. **Building from a local Docker image**

   First, create the :ref:`WfExS Docker image<installation_container_docker>` locally, following the previously described instructions. Then, use Apptainer or Singularity to build the SIF image:

   .. code-block:: bash

      # Remember to use the correct tag!!!
      WFEXS_VER=574fe343c0b59eecd95afbc67894456359ebe649
      singularity build wfexs-${WFEXS_VER}.sif docker-daemon://inab/wfexs-backend:${WFEXS_VER}

3. **Building from a saved Docker or Podman image**

   First, create the local :ref:`Docker<installation_container_docker>` or :ref:`Podman<installation_container_podman>` image as described previously. Then, save it to an image file, which will be used to build the SIF image:

   .. code-block:: bash

      mkdir WfExS_SIF_build
      cd WfExS_SIF_build
      
      # Remember to use the correct tag!!!
      WFEXS_VER=574fe343c0b59eecd95afbc67894456359ebe649

      # Use the following command if you built the local image with Podman
      podman save -o wfexs-backend-${WFEXS_VER}.tar inab/wfexs-backend:${WFEXS_VER}

      # Use the following command if you built the local image with Docker
      docker save -o wfexs-backend-${WFEXS_VER}.tar inab/wfexs-backend:${WFEXS_VER}

      singularity build wfexs-${WFEXS_VER}.sif docker-archive:wfexs-backend-${WFEXS_VER}.tar


