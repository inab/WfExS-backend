import shutil
import zipfile
import platform

from urllib import request

if platform.system() == "Darwin":
    import ssl

    ssl._create_default_https_context = ssl._create_unverified_context


class WF:
    """
    Workflow class
    """

    filename = "crate.zip"
    root_url = "https://dev.workflowhub.eu/ga4gh/trs/v2/tools/"  # the root of GA4GH TRS API

    def __init__(self, id, version_id, descriptor_type):
        """
        Init function

        :param id: A unique identifier of the workflow
        :param version_id: An identifier of the workflow version
        :param descriptor_type: The type of descriptor that represents this version of the workflow
        (e.g. CWL, WDL, NFL, or GALAXY)
        :type id: int
        :type version_id: int
        :type descriptor_type: str
        """
        self.id = id
        self.version_id = version_id
        self.descriptor_type = descriptor_type

    def downloadROcrate(self, path):
        """
        Download RO-crate from WorkflowHub (https://dev.workflowhub.eu/)
        using GA4GH TRS API and save RO-Crate in path

        :param path: location path to save RO-Crate
        :type path: str
        """
        try:
            endpoint = "{}{}/versions/{}/{}/files?format=zip".format(self.root_url,
                                                                     self.id,
                                                                     self.version_id,
                                                                     self.descriptor_type)

            with request.urlopen(endpoint) as url_response, open(path + self.filename, "wb") as download_file:
                shutil.copyfileobj(url_response, download_file)

        except Exception as e:
            raise Exception("Cannot download RO-Crate from WorkflowHub, {}".format(e))

    def unzipROcrate(self, path):
        """
        Unzip RO-crate

        :param path: location path of RO-Crate zip file
        :type path: str
        """
        try:
            with zipfile.ZipFile(path + self.filename, "r") as zip_file:
                zip_file.extractall()

        except Exception as e:
            raise Exception("Cannot unzip RO-Crate, {}".format(e))
