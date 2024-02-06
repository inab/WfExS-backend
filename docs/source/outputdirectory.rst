Each unencrypted staged workflow which has been run at least once has an "execution-state.yaml" file in the "meta" subdirectory. That file holds the serialized list of executions, which are modelled with the next named tuple https://github.com/inab/WfExS-backend/blob/54990c15e3dc150b53980cdf427819cebd007244/wfexs_backend/common.py#L877-L887 . As you can see, each execution contains when it started and ended, the exit value of the workflow execution process, the relative directory where the outputs are available, and additional details about the parameters, inputs, outputs, etc...


As "execution-state.yaml" file is either created or updated at the end of the execution, if you want to base the detection on it, the first time you are executing the staged scenario in the working directory you have to wait for its appearance.


Since several months, WfExS code is ruling that the "outputs" directory is holding a separated subdirectory for each execution. And the very same happens to the metadata associated to those executions. For instance, if there is an execution whose output is at "outputs/_1691494410", its metadata will be available at "meta/outputs/_1691494410".


For the case of Nextflow executions with the latest versions of WfExS, the output metadata directory contains:

* An "inputdeclarations.yaml" file, which is used to pass all the explicit parameters to Nextflow.
* Both "stdout.txt" and "stderr.txt" files with the output and error from Nextflow.
* A directory "stats" with the gathered log.txt , trace.tsv describing each process which was run, both the timeline and report, as well as the DAG representation of the execution.
* It also contains an "all-params.json" which is the list of the implicit parameters of the workflow execution, which was gathered just injecting a small piece of code at the end of the custom Nextflow configuration file created by WfExS.
* Due the way Nextflow manages relative directories, a copy of the workflow is placed under the name of "nxf_trojan", and that custom configuration file is placed inside it with the name "force-params-with-trojan.config" . The file is an augmentation of the original nextflow config file plus the setups to gather all the details plus the needed code to write the "all-params.json".

As a side note related to execution monitoring, I have not set up any timeout to the execution itself (yet). I'm explaining this because, in some ill corner cases I have found, which are a combination of specific versions of old or faulty versions of Nextflow, singularity, bash shell inside the container, etc... the scripting machinery used by nextflow to gather all the execution traces sometimes hangs in a livelock. I have partially mitigated these scenarios, but they can still happen with older versions of Nextflow.
