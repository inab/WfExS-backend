import os

from lib.workflow import WF

if __name__ == '__main__':

    current_path = os.getcwd() + "/"

    # workflow proprieties
    id = 126
    version_id = 1
    descriptor_type = "NFL"  # Nextflow

    # workflow object
    wf = WF(id, version_id, descriptor_type)

    # download RO-Crate from WorkflowHub
    wf.downloadROcrate(current_path)

    # unzip RO-Crate
    wf.unzipROcrate(current_path)
