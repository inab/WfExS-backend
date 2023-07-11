# WfExS-backend cache handling (and examples)

As WfExS-backend lifecycle gathers and caches lots of contents from internet, it internally documents the cached elements using metadata files. So, since version 0.4.11 some cache handling sub commands have been added:

```bash
python WfExS-backend.py cache --help
```

```
usage: WfExS-backend.py cache [-h] [-r] [--cascade] [-g]
                              {ls,inject,fetch,rm,validate} {input,ro-crate,ga4gh-trs,workflow}
                              [cache_command_args [cache_command_args ...]]

positional arguments:
  {ls,inject,fetch,rm,validate}
                        Cache command to perform
                        
                        ls          List the cache entries
                        inject      Inject a new entry in the cache
                        fetch       Fetch a new cache entry, giving as input both the URI and optionally both a security context file and a security context name
                        rm          Remove an entry from the cache
                        validate    Validate the consistency of the cache
  {input,ro-crate,ga4gh-trs,workflow}
                        Cache type to perform the cache command
                        
                        input       Cached or injected inputs
                        ro-crate    Cached RO-Crates (usually from WorkflowHub)
                        ga4gh-trs   Cached files from tools described at GA4GH TRS repositories
                        workflow    Cached workflows, which come from a git repository
  cache_command_args    Optional cache element names (default: None)

optional arguments:
  -h, --help            show this help message and exit
  -r                    Try doing the operation recursively (i.e. both metadata and data) (default: False)
  --cascade             Try doing the operation in cascade (including the URIs which resolve to other URIs)
                        (default: False)
  -g, --glob            Given cache element names are globs (default: False)
```

Currently managed caches are:

* Inputs: Fetched files and directories, redirections and injected entries.
* RO-Crates: Fetched RO-Crates, either from [WorkflowHub](https://workflowhub.eu) or an understood URI.
* GA4GH TRS: Fetched contents from a GA4GH TRS service which does not support RO-Crates (for instance [Dockstore](https://dockstore.org/)).
* Workflows: Fetched using `git` from a git repository.

Currently implemented operations over these caches are:

* `ls`: List all the elements of the cache, or a part of them specified through the positional arguments, matching the URI
  of the resource. If `-g` argument is used, positional arguments are treated as
  [glob patterns](https://en.wikipedia.org/wiki/Glob_(programming)). If '--cascade' argument is used,
  those entries which resolve to other URIs are inspected in order to include these last ones.
  
* `rm`: Removes metadata elements from the cache, and optionally removes the fetched contents when
  `-r` argument is used. As in `ls` operation, if `-g` argument is used, positional arguments are
  treated as [glob patterns](https://en.wikipedia.org/wiki/Glob_(programming)). The same happens
  to '--cascade' argument, those entries which resolve to other URIs are inspected in order to
  also remove these last ones.
  
* `inject`: This operation allows injecting a new entry in the cache. This operation is needed to
  symbolically represent contents (hopefully with a valid public identifier) which cannot be
  automatically fetched by WfExS-backend, due implementation or legal limitations.
  
* `validate`: This operation checks that the recorded fingerprint on download matches the local contents.
  It accepts the very same arguments as `ls`

* `fetch`: This operation allows fetching any content which could be fetched from a staging definition
  file. It takes as input an URI to be fetched using WfExS-backend machinery. If the resource to be
  fetched requires authentication, then second element should be a security context file and the third
  one should be the name of the security context where the credentials to be used are available.

## Examples

### Injecting an entry

```bash
python WfExS-backend.py -L workflow_examples/local_config_gocryptfs.yaml cache inject input perrito:piloto /etc/passwd
```

### Listing an specific cached input

```bash
python WfExS-backend.py -L workflow_examples/local_config_gocryptfs.yaml cache ls input perrito:piloto
```
```
2021-12-15 16:56:22,265 - [INFO] Loading a Crypt4GH public key
2021-12-15 16:56:22,265 - [INFO] Loading a Crypt4GH private key
2021-12-15 16:56:22,265 - [INFO] KDF: b'scrypt'
2021-12-15 16:56:22,265 - [INFO] Ciphername: b'chacha20_poly1305'
{
    "fingerprint": "sha256~eXN74hlxzipiZDtIRLY7_NVGbUo6DayeB0mvnXG18PA=",
    "kind": "file",
    "metadata_array": [
        {
            "metadata": {
                "injected": true
            },
            "preferredName": null,
            "uri": "perrito:piloto"
        }
    ],
    "path": {
        "absolute": "/etc/passwd",
        "meta": {
            "absolute": "/home/jmfernandez/projects/WfExS-backend/wfexs-backend-test/wf-inputs/uri_hashes/beafc10f7f6b677442525bc4c6741ca26a99627d_meta.json",
            "relative": "beafc10f7f6b677442525bc4c6741ca26a99627d_meta.json"
        },
        "relative": "../../../../../../../etc/passwd"
    },
    "stamp": "2021-12-11T04:05:28.023601Z"
}
```

### Listing workflows

```bash
python WfExS-backend.py -L workflow_examples/local_config_gocryptfs.yaml cache ls workflow
```
```
2021-12-15 16:55:14,742 - [INFO] Loading a Crypt4GH public key
2021-12-15 16:55:14,742 - [INFO] Loading a Crypt4GH private key
2021-12-15 16:55:14,742 - [INFO] KDF: b'scrypt'
2021-12-15 16:55:14,742 - [INFO] Ciphername: b'chacha20_poly1305'
{
    "fingerprint": "sha256~nXGslnJm60eD39mm3cLt93guoqMPniwUZkPHvESo20s=",
    "kind": "dir",
    "metadata_array": [
        {
            "metadata": {
                "checkout": "3ce4a14c942bbea653e0b35e72f7cfdacdce4db0",
                "repo": "https://github.com/inab/Wetlab2Variations.git",
                "tag": "20210521"
            },
            "preferredName": null,
            "uri": "git+https://github.com/inab/Wetlab2Variations.git@20210521"
        }
    ],
    "path": {
        "absolute": "/home/jmfernandez/projects/WfExS-backend/wfexs-backend-test/wf-cache/3d226c47dd0d8450f01c082b77f21d96f30fc174/21e455774a5e71c5acb4942343dbbacc827e710a",
        "meta": {
            "absolute": "/home/jmfernandez/projects/WfExS-backend/wfexs-backend-test/wf-cache/uri_hashes/0d477a028b9626f632ac3017592d4ac4123e791f_meta.json",
            "relative": "0d477a028b9626f632ac3017592d4ac4123e791f_meta.json"
        },
        "relative": "../3d226c47dd0d8450f01c082b77f21d96f30fc174/21e455774a5e71c5acb4942343dbbacc827e710a"
    },
    "stamp": "2021-12-15T12:32:43.254933Z"
}
```

### Listing all the inputs in a quiet way (`-q` flag)

```bash
python WfExS-backend.py -q -L workflow_examples/local_config_gocryptfs.yaml cache ls input
```
```
ftp://ftp.1000genomes.ebi.ac.uk/vol1/ftp/technical/reference/phase2_reference_assembly_sequence/hs37d5.fa.gz
ftp://ftp.broadinstitute.org/bundle/b37/Mills_and_1000G_gold_standard.indels.b37.vcf.gz
ftp://ftp.broadinstitute.org/bundle/b37/Mills_and_1000G_gold_standard.indels.b37.vcf.idx.gz
ftp://ftp.broadinstitute.org/bundle/b37/dbsnp_138.b37.vcf.gz
ftp://ftp.broadinstitute.org/bundle/b37/dbsnp_138.b37.vcf.idx.gz
git+https://github.com/inab/TCGA_benchmarking_workflow.git@1.0.6#subdirectory=TCGA_sample_data/All_Together.txt
git+https://github.com/inab/TCGA_benchmarking_workflow.git@1.0.6#subdirectory=TCGA_sample_data/data
git+https://github.com/inab/TCGA_benchmarking_workflow.git@1.0.6#subdirectory=TCGA_sample_data/metrics_ref_datasets
git+https://github.com/inab/TCGA_benchmarking_workflow.git@1.0.6#subdirectory=TCGA_sample_data/public_ref
https://raw.githubusercontent.com/PhosphorylatedRabbits/cosifer/f2e2a259d218b9a56a01d84bc9d6a7cd7c8d9bf1/examples/interactive/data_matrix.csv
perrito:piloto
pride.project:PXD001819
```

### Removing both cache metadata and its fetched content using glob patterns

```bash
python WfExS-backend.py -v -L workflow_examples/local_config_gocryptfs.yaml cache rm -r -g input 'ftp://ftp-trace.ncbi.nih.gov/giab/ftp/data/NA12878/NIST_NA12878_HG001_HiSeq_300x/140407_D00360_0017_BH947YADXX/Project_RM8398/Sample_U5c/*.gz'
```
```
2021-12-15 16:43:52,489 - [INFO] Loading a Crypt4GH public key
2021-12-15 16:43:52,489 - [INFO] Loading a Crypt4GH private key
2021-12-15 16:43:52,489 - [INFO] KDF: b'scrypt'
2021-12-15 16:43:52,490 - [INFO] Ciphername: b'chacha20_poly1305'
2021-12-15 16:43:52,556 - [INFO] Removing cache sha256~TNiuY7tftn5xTDGCuzA1350Og-3SbMUdRDnNRMMBUxY= physical path /home/jmfernandez/projects/WfExS-backend/wfexs-backend-test/wf-inputs/sha256~TNiuY7tftn5xTDGCuzA1350Og-3SbMUdRDnNRMMBUxY=
2021-12-15 16:43:52,652 - [INFO] Removing cache sha256~TNiuY7tftn5xTDGCuzA1350Og-3SbMUdRDnNRMMBUxY= metadata /home/jmfernandez/projects/WfExS-backend/wfexs-backend-test/wf-inputs/uri_hashes/42be63ef9b0fc7d80d09513bfd3fa42b2288fd9b_meta.json
ftp://ftp-trace.ncbi.nih.gov/giab/ftp/data/NA12878/NIST_NA12878_HG001_HiSeq_300x/140407_D00360_0017_BH947YADXX/Project_RM8398/Sample_U5c/U5c_CCGTCC_L001_R1_001.fastq.gz    /home/jmfernandez/projects/WfExS-backend/wfexs-backend-test/wf-inputs/uri_hashes/42be63ef9b0fc7d80d09513bfd3fa42b2288fd9b_meta.json /home/jmfernandez/projects/WfExS-backend/wfexs-backend-test/wf-inputs/sha256~TNiuY7tftn5xTDGCuzA1350Og-3SbMUdRDnNRMMBUxY=
```

### Fetching contents

There are a couple of self-contained examples at [../fetchers-tests/test-recipes.md](../fetchers-tests/test-recipes.md) .