# WfExS-backend staged working directories handling (and examples)

As WfExS-backend lifecycle keeps all the working directories in the very same place, some commands are needed to manage them. So, since version 0.4.13 some staged working directory sub commands have been added:

```bash
python WfExS-backend.py staged-workdir --help
```

```
usage: WfExS-backend.py staged-workdir [-h] [-g]
                                       {offline-exec,ls,mount,rm,shell,status}
                                       [staged_workdir_command_args [staged_workdir_command_args ...]]

positional arguments:
  {offline-exec,ls,mount,rm,shell,status}
                        Staged working directory command to perform
                        
                        offline-exec    Offline execute the staged instances which match the input pattern
                        ls              List the staged instances
                                It shows the instance id, nickname,
                                encryption and whether they are damaged
                        mount           Mount the staged instances which match the input pattern
                        rm              Removes the staged instances which match the input pattern
                        shell           Launches a command in the workdir
                                First parameter is either the staged instance id or the nickname.
                                It launches the command specified after the id.
                                If there is no additional parameters, it launches a shell
                                in the mounted working directory of the instance
                        status          Shows staged instances status
  staged_workdir_command_args
                        Optional staged working directory element names (default: None)

optional arguments:
  -h, --help            show this help message and exit
  -g, --glob            Given staged workflow names are globs (default: False)
```

Currently implemented operations are:

* `ls`: List all the working directories, or a part of them specified through the positional arguments, matching either
  the UUID or the nickname of the staged working directories. If `-g` argument is used, positional arguments are treated as
  [glob patterns](https://en.wikipedia.org/wiki/Glob_(programming)). It also provides brief information about whether the
  working directory is encrypted and whether the working directory is either minimally set up or corrupted.

* `status`: An extended version of the `ls` sub-command, as it provides additional information about the state of the
  analysis in the staged working directory.

* `mount`: It mounts all the working directories (if needed) matching the positional parameters.

* `shell`: It allows either opening an interactive shell in the first staged working directory matching the first
  positional parameter, or executing the commands specified in the second and subsequent positional parameters in
  all the staged working directories which match the first positional parameter.

* `offline-exec`: It executes each workflow in all the staged working directories matching the positional parameters.

* `rm`: It removes the staged working directories matching the positional parameters.