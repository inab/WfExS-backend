1. Create environment and install packages

    ```bash
    python3 -m venv .test
    source .test/bin/activate
    pip install --upgrade pip wheel
    pip install -r requirements.txt
    ```

2. Testing basic HTTP auth would be possible launching here next:

    ```bash
    davserver -D /etc -u wfexs -p 123.qwe
    ```

    and in a WfExS profile next command to fetch the test copy:

    ```bash
    python WfExS-backend.py -L workflow_examples/local_config_gocryptfs.yaml cache fetch input http://127.0.0.1:8008/hosts fetchers-tests/tests.wfex.ctxt localtest
    ```

3. Testing FTP auth would be possible launching here next:

    ```bash
    python -m pyftpdlib -u wfexs -P 123.qwe -d /etc
    ```

    and in a WfExS profile next command to fetch the test copy:

    ```bash
    python WfExS-backend.py -L workflow_examples/local_config_gocryptfs.yaml cache fetch input ftp://127.0.0.1:2121/hosts fetchers-tests/tests.wfex.ctxt localtest
    ```

4. Testing FASP auth with EGA:

    First, obtain IBM Aspera client, install it and add it to PATH. For instance:

    ```bash
    PATH="$HOME/.aspera/connect/bin:$PATH"
    ```

    Then, next command should work, fetching the test file from EGA.

    ```bash
    python WfExS-backend.py -L workflow_examples/local_config_gocryptfs.yaml cache fetch input fasp://xfer.ega-archive.org/file fetchers-tests/tests.wfex.ctxt fasp-ega
    ```
