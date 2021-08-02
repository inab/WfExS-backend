# WfExS-backend config

- [1. [Optional] Property `WfExS-backend config > cacheDir`](#cacheDir)
- [2. [Optional] Property `WfExS-backend config > crypt4gh`](#crypt4gh)
  - [2.1. [Required] Property `WfExS-backend config > crypt4gh > key`](#crypt4gh_key)
  - [2.2. [Required] Property `WfExS-backend config > crypt4gh > passphrase`](#crypt4gh_passphrase)
  - [2.3. [Required] Property `WfExS-backend config > crypt4gh > pub`](#crypt4gh_pub)
- [3. [Optional] Property `WfExS-backend config > tools`](#tools)
  - [3.1. [Optional] Property `WfExS-backend config > tools > containerType`](#tools_containerType)
  - [3.2. [Optional] Property `WfExS-backend config > tools > engineMode`](#tools_engineMode)
  - [3.3. [Optional] Property `WfExS-backend config > tools > encrypted_fs`](#tools_encrypted_fs)
    - [3.3.1. [Optional] Property `WfExS-backend config > tools > encrypted_fs > type`](#tools_encrypted_fs_type)
    - [3.3.2. [Optional] Property `WfExS-backend config > tools > encrypted_fs > command`](#tools_encrypted_fs_command)
    - [3.3.3. [Optional] Property `WfExS-backend config > tools > encrypted_fs > fusermount_command`](#tools_encrypted_fs_fusermount_command)
    - [3.3.4. [Optional] Property `WfExS-backend config > tools > encrypted_fs > idle`](#tools_encrypted_fs_idle)
  - [3.4. [Optional] Property `WfExS-backend config > tools > gitCommand`](#tools_gitCommand)
  - [3.5. [Optional] Property `WfExS-backend config > tools > javaCommand`](#tools_javaCommand)
  - [3.6. [Optional] Property `WfExS-backend config > tools > singularityCommand`](#tools_singularityCommand)
  - [3.7. [Optional] Property `WfExS-backend config > tools > dockerCommand`](#tools_dockerCommand)
  - [3.8. [Optional] Property `WfExS-backend config > tools > podmanCommand`](#tools_podmanCommand)
  - [3.9. [Optional] Property `WfExS-backend config > tools > staticBashCommand`](#tools_staticBashCommand)
  - [3.10. [Optional] Property `WfExS-backend config > tools > nextflow`](#tools_nextflow)
    - [3.10.1. [Optional] Property `WfExS-backend config > tools > nextflow > dockerImage`](#tools_nextflow_dockerImage)
    - [3.10.2. [Optional] Property `WfExS-backend config > tools > nextflow > version`](#tools_nextflow_version)
    - [3.10.3. [Optional] Property `WfExS-backend config > tools > nextflow > maxRetries`](#tools_nextflow_maxRetries)
    - [3.10.4. [Optional] Property `WfExS-backend config > tools > nextflow > maxProcesses`](#tools_nextflow_maxProcesses)
      - [3.10.4.1. Property `WfExS-backend config > tools > nextflow > maxProcesses > oneOf > item 0`](#tools_nextflow_maxProcesses_oneOf_i0)
      - [3.10.4.2. Property `WfExS-backend config > tools > nextflow > maxProcesses > oneOf > item 1`](#tools_nextflow_maxProcesses_oneOf_i1)
  - [3.11. [Optional] Property `WfExS-backend config > tools > cwl`](#tools_cwl)
    - [3.11.1. [Optional] Property `WfExS-backend config > tools > cwl > version`](#tools_cwl_version)
- [4. [Optional] Property `WfExS-backend config > workDir`](#workDir)

**Title:** WfExS-backend config

| Type                      | `object`                                                |
| ------------------------- | ------------------------------------------------------- |
| **Additional properties** | [[Not allowed]](# "Additional Properties not allowed.") |
|                           |                                                         |

**Description:** WfExS-backend configuration file (EOSC-Life Demonstrator 7 JSON Schemas)

| Property                 | Pattern | Type   | Deprecated | Definition | Title/Description                  |
| ------------------------ | ------- | ------ | ---------- | ---------- | ---------------------------------- |
| - [cacheDir](#cacheDir ) | No      | string | No         | -          | Caching directory                  |
| - [crypt4gh](#crypt4gh ) | No      | object | No         | -          | Installation Crypt4GH key setup    |
| - [tools](#tools )       | No      | object | No         | -          | External tools configuration block |
| - [workDir](#workDir )   | No      | string | No         | -          | Working directory                  |
|                          |         |        |            |            |                                    |

## <a name="cacheDir"></a>1. [Optional] Property `WfExS-backend config > cacheDir`

**Title:** Caching directory

| Type                      | `string`                                                                  |
| ------------------------- | ------------------------------------------------------------------------- |
| **Additional properties** | [[Any type: allowed]](# "Additional Properties of any type are allowed.") |
|                           |                                                                           |

**Description:** Directory where all the cache-able content will be hold.
This directory can be removed, as its contents should be available outside.
When it is not set, a temporary directory is created for the session, being destroyed when the program finishes.

| Restrictions   |   |
| -------------- | - |
| **Min length** | 1 |
|                |   |

## <a name="crypt4gh"></a>2. [Optional] Property `WfExS-backend config > crypt4gh`

**Title:** Installation Crypt4GH key setup

| Type                      | `object`                                                |
| ------------------------- | ------------------------------------------------------- |
| **Additional properties** | [[Not allowed]](# "Additional Properties not allowed.") |
|                           |                                                         |

**Description:** WfExS-backend needs an encryption key for several tasks, like encrypting and decrypting random keys of encrypted working directories. When this block does not exist, WfExS-backend.py creates the installation's keys, and updates the configuration file

| Property                              | Pattern | Type   | Deprecated | Definition | Title/Description                           |
| ------------------------------------- | ------- | ------ | ---------- | ---------- | ------------------------------------------- |
| + [key](#crypt4gh_key )               | No      | string | No         | -          | Secret key installation file                |
| + [passphrase](#crypt4gh_passphrase ) | No      | string | No         | -          | Passphrase used to work with the secret key |
| + [pub](#crypt4gh_pub )               | No      | string | No         | -          | Public key installation file                |
|                                       |         |        |            |            |                                             |

### <a name="crypt4gh_key"></a>2.1. [Required] Property `WfExS-backend config > crypt4gh > key`

**Title:** Secret key installation file

| Type                      | `string`                                                                  |
| ------------------------- | ------------------------------------------------------------------------- |
| **Additional properties** | [[Any type: allowed]](# "Additional Properties of any type are allowed.") |
|                           |                                                                           |

**Description:** The path to the Crypt4GH secret key file used by this installation. If the path is relative, the directory where the configuration file resides is used for the resolution

| Restrictions   |   |
| -------------- | - |
| **Min length** | 1 |
|                |   |

### <a name="crypt4gh_passphrase"></a>2.2. [Required] Property `WfExS-backend config > crypt4gh > passphrase`

**Title:** Passphrase used to work with the secret key

| Type                      | `string`                                                                  |
| ------------------------- | ------------------------------------------------------------------------- |
| **Additional properties** | [[Any type: allowed]](# "Additional Properties of any type are allowed.") |
|                           |                                                                           |

**Description:** Passphrase which has to be used to work with the secret key

| Restrictions   |   |
| -------------- | - |
| **Min length** | 0 |
|                |   |

### <a name="crypt4gh_pub"></a>2.3. [Required] Property `WfExS-backend config > crypt4gh > pub`

**Title:** Public key installation file

| Type                      | `string`                                                                  |
| ------------------------- | ------------------------------------------------------------------------- |
| **Additional properties** | [[Any type: allowed]](# "Additional Properties of any type are allowed.") |
|                           |                                                                           |

**Description:** The path to the Crypt4GH public key file used by this installation. If the path is relative, the directory where the configuration file resides is used for the resolution

| Restrictions   |   |
| -------------- | - |
| **Min length** | 1 |
|                |   |

## <a name="tools"></a>3. [Optional] Property `WfExS-backend config > tools`

**Title:** External tools configuration block

| Type                      | `object`                                                |
| ------------------------- | ------------------------------------------------------- |
| **Additional properties** | [[Not allowed]](# "Additional Properties not allowed.") |
|                           |                                                         |

**Description:** External tools configuration block

| Property                                           | Pattern | Type             | Deprecated | Definition | Title/Description                                                          |
| -------------------------------------------------- | ------- | ---------------- | ---------- | ---------- | -------------------------------------------------------------------------- |
| - [containerType](#tools_containerType )           | No      | enum (of string) | No         | -          | Container technology type in this installation                             |
| - [engineMode](#tools_engineMode )                 | No      | enum (of string) | No         | -          | Workflow engine invocation mode                                            |
| - [encrypted_fs](#tools_encrypted_fs )             | No      | object           | No         | -          | Working directory FUSE encrypted FS configuration block                    |
| - [gitCommand](#tools_gitCommand )                 | No      | string           | No         | -          | Git client path                                                            |
| - [javaCommand](#tools_javaCommand )               | No      | string           | No         | -          | Java path                                                                  |
| - [singularityCommand](#tools_singularityCommand ) | No      | string           | No         | -          | Singularity client path                                                    |
| - [dockerCommand](#tools_dockerCommand )           | No      | string           | No         | -          | Docker client path                                                         |
| - [podmanCommand](#tools_podmanCommand )           | No      | string           | No         | -          | Podman client path                                                         |
| - [staticBashCommand](#tools_staticBashCommand )   | No      | string           | No         | -          | Static bash command (used in singularity based Nextflow engine executions) |
| - [nextflow](#tools_nextflow )                     | No      | object           | No         | -          | -                                                                          |
| - [cwl](#tools_cwl )                               | No      | object           | No         | -          | -                                                                          |
|                                                    |         |                  |            |            |                                                                            |

### <a name="tools_containerType"></a>3.1. [Optional] Property `WfExS-backend config > tools > containerType`

**Title:** Container technology type in this installation

| Type                      | `enum (of string)`                                                        |
| ------------------------- | ------------------------------------------------------------------------- |
| **Additional properties** | [[Any type: allowed]](# "Additional Properties of any type are allowed.") |
| **Default**               | `"singularity"`                                                           |
|                           |                                                                           |

**Description:** Type of container technology to be used when any workflow is launched using this installation. Supported types are:
- Singularity (default).
- Docker.
- Podman
- No containerisation technology (discouraged)
Encrypted working directories are unsupported when Docker or Podman are used due technological limitations

Must be one of:
* "singularity"
* "docker"
* "podman"
* "none"

### <a name="tools_engineMode"></a>3.2. [Optional] Property `WfExS-backend config > tools > engineMode`

**Title:** Workflow engine invocation mode

| Type                      | `enum (of string)`                                                        |
| ------------------------- | ------------------------------------------------------------------------- |
| **Additional properties** | [[Any type: allowed]](# "Additional Properties of any type are allowed.") |
| **Default**               | `"local"`                                                                 |
|                           |                                                                           |

**Description:** Most of workflow engines are usually available both as installable executables and as containers, but when they are used inside a container usually do not support running containerised jobs, unless a very careful setup is done. Currently, WfExS-backend only partially supports Nextflow in its docker-in-docker mode.

Must be one of:
* "local"
* "docker"

### <a name="tools_encrypted_fs"></a>3.3. [Optional] Property `WfExS-backend config > tools > encrypted_fs`

**Title:** Working directory FUSE encrypted FS configuration block

| Type                      | `object`                                                |
| ------------------------- | ------------------------------------------------------- |
| **Additional properties** | [[Not allowed]](# "Additional Properties not allowed.") |
|                           |                                                         |

| Property                                                        | Pattern | Type             | Deprecated | Definition | Title/Description                |
| --------------------------------------------------------------- | ------- | ---------------- | ---------- | ---------- | -------------------------------- |
| - [type](#tools_encrypted_fs_type )                             | No      | enum (of string) | No         | -          | Type of encrypted FS             |
| - [command](#tools_encrypted_fs_command )                       | No      | string           | No         | -          | Path to encryption mount program |
| - [fusermount_command](#tools_encrypted_fs_fusermount_command ) | No      | string           | No         | -          | Path to unmount command          |
| - [idle](#tools_encrypted_fs_idle )                             | No      | integer          | No         | -          | Idle minutes before autoumount   |
|                                                                 |         |                  |            |            |                                  |

#### <a name="tools_encrypted_fs_type"></a>3.3.1. [Optional] Property `WfExS-backend config > tools > encrypted_fs > type`

**Title:** Type of encrypted FS

| Type                      | `enum (of string)`                                                        |
| ------------------------- | ------------------------------------------------------------------------- |
| **Additional properties** | [[Any type: allowed]](# "Additional Properties of any type are allowed.") |
| **Default**               | `"encfs"`                                                                 |
|                           |                                                                           |

**Description:** When an encrypted working directory is needed, the type of encrypted FS to be used is set up through this key. Currently, both encfs (default) and gocryptfs (recommended) are supported

Must be one of:
* "encfs"
* "gocryptfs"

#### <a name="tools_encrypted_fs_command"></a>3.3.2. [Optional] Property `WfExS-backend config > tools > encrypted_fs > command`

**Title:** Path to encryption mount program

| Type                      | `string`                                                                  |
| ------------------------- | ------------------------------------------------------------------------- |
| **Additional properties** | [[Any type: allowed]](# "Additional Properties of any type are allowed.") |
|                           |                                                                           |

**Description:** When this key is set, it overrides the default command to be used when an encrypted directory has to be created or mounted

#### <a name="tools_encrypted_fs_fusermount_command"></a>3.3.3. [Optional] Property `WfExS-backend config > tools > encrypted_fs > fusermount_command`

**Title:** Path to unmount command

| Type                      | `string`                                                                  |
| ------------------------- | ------------------------------------------------------------------------- |
| **Additional properties** | [[Any type: allowed]](# "Additional Properties of any type are allowed.") |
| **Default**               | `"fusermount"`                                                            |
|                           |                                                                           |

**Description:** Path to unmounting command to be used, being 'fusermount' by default

#### <a name="tools_encrypted_fs_idle"></a>3.3.4. [Optional] Property `WfExS-backend config > tools > encrypted_fs > idle`

**Title:** Idle minutes before autoumount

| Type                      | `integer`                                                                 |
| ------------------------- | ------------------------------------------------------------------------- |
| **Additional properties** | [[Any type: allowed]](# "Additional Properties of any type are allowed.") |
| **Default**               | `5`                                                                       |
|                           |                                                                           |

**Description:** Number of minutes before an idle, mounted encrypted directory will automatically unmount

### <a name="tools_gitCommand"></a>3.4. [Optional] Property `WfExS-backend config > tools > gitCommand`

**Title:** Git client path

| Type                      | `string`                                                                  |
| ------------------------- | ------------------------------------------------------------------------- |
| **Additional properties** | [[Any type: allowed]](# "Additional Properties of any type are allowed.") |
| **Default**               | `"git"`                                                                   |
|                           |                                                                           |

**Description:** Git is used to materialize workflows being hosted at git repositories, like GitHub. This key sets up custom paths to git command

### <a name="tools_javaCommand"></a>3.5. [Optional] Property `WfExS-backend config > tools > javaCommand`

**Title:** Java path

| Type                      | `string`                                                                  |
| ------------------------- | ------------------------------------------------------------------------- |
| **Additional properties** | [[Any type: allowed]](# "Additional Properties of any type are allowed.") |
| **Default**               | `"java"`                                                                  |
|                           |                                                                           |

**Description:** Java is needed to run Nextflow and future workflow engines. This key sets up custom paths to java installations

### <a name="tools_singularityCommand"></a>3.6. [Optional] Property `WfExS-backend config > tools > singularityCommand`

**Title:** Singularity client path

| Type                      | `string`                                                                  |
| ------------------------- | ------------------------------------------------------------------------- |
| **Additional properties** | [[Any type: allowed]](# "Additional Properties of any type are allowed.") |
| **Default**               | `"singularity"`                                                           |
|                           |                                                                           |

**Description:** Singularity is used when containerType is 'singularity'. This key sets up custom paths to singularity command

### <a name="tools_dockerCommand"></a>3.7. [Optional] Property `WfExS-backend config > tools > dockerCommand`

**Title:** Docker client path

| Type                      | `string`                                                                  |
| ------------------------- | ------------------------------------------------------------------------- |
| **Additional properties** | [[Any type: allowed]](# "Additional Properties of any type are allowed.") |
| **Default**               | `"docker"`                                                                |
|                           |                                                                           |

**Description:** Docker is used when containerType is 'docker'. This key sets up custom paths to docker command

### <a name="tools_podmanCommand"></a>3.8. [Optional] Property `WfExS-backend config > tools > podmanCommand`

**Title:** Podman client path

| Type                      | `string`                                                                  |
| ------------------------- | ------------------------------------------------------------------------- |
| **Additional properties** | [[Any type: allowed]](# "Additional Properties of any type are allowed.") |
| **Default**               | `"podman"`                                                                |
|                           |                                                                           |

**Description:** Podman is used when containerType is 'podman'. This key sets up custom paths to podman command

### <a name="tools_staticBashCommand"></a>3.9. [Optional] Property `WfExS-backend config > tools > staticBashCommand`

**Title:** Static bash command (used in singularity based Nextflow engine executions)

| Type                      | `string`                                                                  |
| ------------------------- | ------------------------------------------------------------------------- |
| **Additional properties** | [[Any type: allowed]](# "Additional Properties of any type are allowed.") |
| **Default**               | `"bash.static"`                                                           |
|                           |                                                                           |

**Description:** There is a bug in some bash versions which make them unsuitable to run the trace machinery from Nextflow, as the trace machinery enters in a live lock. As the images containing these faulty bash versions cannot be changed, a 'monkey patch' solution where an external, static bash version is injected on workflow execution is used. The injected static bash is found through this key, which is searched on PATH variable when it is not a full path.

### <a name="tools_nextflow"></a>3.10. [Optional] Property `WfExS-backend config > tools > nextflow`

| Type                      | `object`                                                                  |
| ------------------------- | ------------------------------------------------------------------------- |
| **Additional properties** | [[Any type: allowed]](# "Additional Properties of any type are allowed.") |
|                           |                                                                           |

| Property                                        | Pattern | Type        | Deprecated | Definition | Title/Description               |
| ----------------------------------------------- | ------- | ----------- | ---------- | ---------- | ------------------------------- |
| - [dockerImage](#tools_nextflow_dockerImage )   | No      | string      | No         | -          | Image for docker-in-docker mode |
| - [version](#tools_nextflow_version )           | No      | string      | No         | -          | Nextflow's version              |
| - [maxRetries](#tools_nextflow_maxRetries )     | No      | integer     | No         | -          | Retries in docker mode          |
| - [maxProcesses](#tools_nextflow_maxProcesses ) | No      | Combination | No         | -          | Max number of CPUs              |
|                                                 |         |             |            |            |                                 |

#### <a name="tools_nextflow_dockerImage"></a>3.10.1. [Optional] Property `WfExS-backend config > tools > nextflow > dockerImage`

**Title:** Image for docker-in-docker mode

| Type                      | `string`                                                                  |
| ------------------------- | ------------------------------------------------------------------------- |
| **Additional properties** | [[Any type: allowed]](# "Additional Properties of any type are allowed.") |
| **Default**               | `"nextflow/nextflow"`                                                     |
|                           |                                                                           |

**Description:** (unfinished) When `engineMode` is `docker`, the name of the image to be fetched and used. The used tag will depend on the workflow's metadata, being by default the `version`

#### <a name="tools_nextflow_version"></a>3.10.2. [Optional] Property `WfExS-backend config > tools > nextflow > version`

**Title:** Nextflow's version

| Type                      | `string`                                                                  |
| ------------------------- | ------------------------------------------------------------------------- |
| **Additional properties** | [[Any type: allowed]](# "Additional Properties of any type are allowed.") |
| **Default**               | `"19.04.1"`                                                               |
|                           |                                                                           |

**Description:** Version of Nextflow engine to be used when workflow's metadata does not provide hints about minimal version needed.

#### <a name="tools_nextflow_maxRetries"></a>3.10.3. [Optional] Property `WfExS-backend config > tools > nextflow > maxRetries`

**Title:** Retries in docker mode

| Type                      | `integer`                                                                 |
| ------------------------- | ------------------------------------------------------------------------- |
| **Additional properties** | [[Any type: allowed]](# "Additional Properties of any type are allowed.") |
| **Default**               | `5`                                                                       |
|                           |                                                                           |

**Description:** Retries when `engineMode` is `docker`.
Retries system was introduced when using docker-in-docker pattern because an insidious
bug happens sometimes. See https://forums.docker.com/t/any-known-problems-with-symlinks-on-bind-mounts/32138

| Restrictions |        |
| ------------ | ------ |
| **Minimum**  | &ge; 0 |
|              |        |

#### <a name="tools_nextflow_maxProcesses"></a>3.10.4. [Optional] Property `WfExS-backend config > tools > nextflow > maxProcesses`

**Title:** Max number of CPUs

| Type                      | `combining`                                                               |
| ------------------------- | ------------------------------------------------------------------------- |
| **Additional properties** | [[Any type: allowed]](# "Additional Properties of any type are allowed.") |
|                           |                                                                           |

**Description:** Number of CPUs to be used by Nextflow. When this key has an explicit value of `null`, it depends on Nextflow criteria, which tries creating as many processes as available CPUs, spawning jobs in parallel. Not declaring it, or declaring and explicit value, imposes a limitation in the number of concurrent processes

| One of(Option)                                  |
| ----------------------------------------------- |
| [item 0](#tools_nextflow_maxProcesses_oneOf_i0) |
| [item 1](#tools_nextflow_maxProcesses_oneOf_i1) |
|                                                 |

##### <a name="tools_nextflow_maxProcesses_oneOf_i0"></a>3.10.4.1. Property `WfExS-backend config > tools > nextflow > maxProcesses > oneOf > item 0`

| Type                      | `integer`                                                                 |
| ------------------------- | ------------------------------------------------------------------------- |
| **Additional properties** | [[Any type: allowed]](# "Additional Properties of any type are allowed.") |
| **Default**               | `4`                                                                       |
|                           |                                                                           |

| Restrictions |        |
| ------------ | ------ |
| **Minimum**  | &ge; 1 |
|              |        |

##### <a name="tools_nextflow_maxProcesses_oneOf_i1"></a>3.10.4.2. Property `WfExS-backend config > tools > nextflow > maxProcesses > oneOf > item 1`

| Type                      | `null`                                                                    |
| ------------------------- | ------------------------------------------------------------------------- |
| **Additional properties** | [[Any type: allowed]](# "Additional Properties of any type are allowed.") |
|                           |                                                                           |

### <a name="tools_cwl"></a>3.11. [Optional] Property `WfExS-backend config > tools > cwl`

| Type                      | `object`                                                                  |
| ------------------------- | ------------------------------------------------------------------------- |
| **Additional properties** | [[Any type: allowed]](# "Additional Properties of any type are allowed.") |
|                           |                                                                           |

| Property                         | Pattern | Type   | Deprecated | Definition | Title/Description |
| -------------------------------- | ------- | ------ | ---------- | ---------- | ----------------- |
| - [version](#tools_cwl_version ) | No      | string | No         | -          | cwltool's version |
|                                  |         |        |            |            |                   |

#### <a name="tools_cwl_version"></a>3.11.1. [Optional] Property `WfExS-backend config > tools > cwl > version`

**Title:** cwltool's version

| Type                      | `string`                                                                  |
| ------------------------- | ------------------------------------------------------------------------- |
| **Additional properties** | [[Any type: allowed]](# "Additional Properties of any type are allowed.") |
| **Default**               | `"3.1.20210628163208"`                                                    |
|                           |                                                                           |

**Description:** Version of cwltool engine to be used. WfExS is not currently guessing the minimal needed version, so it is either the value set up in this key or the default one

| Restrictions   |   |
| -------------- | - |
| **Min length** | 1 |
|                |   |

## <a name="workDir"></a>4. [Optional] Property `WfExS-backend config > workDir`

**Title:** Working directory

| Type                      | `string`                                                                  |
| ------------------------- | ------------------------------------------------------------------------- |
| **Additional properties** | [[Any type: allowed]](# "Additional Properties of any type are allowed.") |
|                           |                                                                           |

**Description:** Directory where all the working directories are going to be created.
When it is not set, a temporary directory is created, which will be removed when the program finishes (which avoids inspecting the working directory after the program has finished).

| Restrictions   |   |
| -------------- | - |
| **Min length** | 1 |
|                |   |

----------------------------------------------------------------------------------------------------------------------------
Generated using [json-schema-for-humans](https://github.com/coveooss/json-schema-for-humans) on 2021-07-28 at 22:36:23 +0200