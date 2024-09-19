# Configuration file for the Sphinx documentation builder.

import os
import shutil
import sys
sys.path.insert(0, os.path.normpath(os.path.join(os.path.dirname(__file__), '../..')))

# print("HOLA")
# print(sys.path)
# print("HOLAERR", file=sys.stderr)
# print(sys.path, file=sys.stderr)

# -- Project information

import wfexs_backend

from wfexs_backend.utils.misc import SCHEMAS_REL_DIR as WFEXS_SCHEMAS_REL_DIR

from json_schema_for_humans.generate import generate_from_filename
from json_schema_for_humans.generation_configuration import GenerationConfiguration

def generate_json_schema_docs(destdir: "str"):
    project_source_dir = os.path.dirname(os.path.realpath(__file__))
    if not os.path.isabs(destdir):
        destdir = os.path.join(project_source_dir, destdir)

    if os.path.exists(destdir):
        shutil.rmtree(destdir)
    os.makedirs(destdir, exist_ok=True)

    wfexs_schemas_path = os.path.join(os.path.dirname(wfexs_backend.__file__), WFEXS_SCHEMAS_REL_DIR)

    custom_template_path = os.path.join(os.path.dirname(project_source_dir), "jsfh_templates", "md", "base.md")

    config = GenerationConfiguration(
        # template_name="md",
        custom_template_path=custom_template_path,
        examples_as_yaml=True,
        description_is_markdown=True,
        collapse_long_descriptions=False,
    )

    docschemas = []
    with os.scandir(wfexs_schemas_path) as wfit:
        for entry in wfit:
            if not entry.name.startswith(".") and entry.is_file():
                docschema = entry.name + ".md"
                docschemas.append(docschema)
                destfiledoc = os.path.join(destdir, docschema)
                generate_from_filename(entry.path, destfiledoc, config=config)

    with open(os.path.join(destdir, "index.md"), mode="w", encoding="utf-8") as idH:
        linedocschemas = '\n'.join(docschemas)
        idH.write(f"""\
# JSON Schema Reference


This page contains auto-generated JSON Schema reference documentation [^f1].

```{{toctree}}
:titlesonly:

{linedocschemas}
```

[^f1]: Created with [json-schema-for-humans](https://github.com/coveooss/json-schema-for-humans)
""")

jsfh_output_dir = "schemadocs"

generate_json_schema_docs(jsfh_output_dir)

project = 'WfExS-backend'
copyright = wfexs_backend.__copyright__
author = wfexs_backend.__author__

release = wfexs_backend.__version__
version = wfexs_backend.get_WfExS_version_str()

# -- General configuration

extensions = [
    'autodoc2',
    'sphinx.ext.duration',
    'sphinx.ext.doctest',
    'sphinx.ext.autodoc',
    'sphinx.ext.autosummary',
    'sphinx.ext.intersphinx',
    'sphinx_copybutton',
    'sphinxarg.ext',
    'sphinxcontrib.datatemplates',
    'myst_parser',
    'sphinxcontrib.asciinema',
    'sphinx_design',
]

autodoc2_packages = [
    {
        "path": os.path.relpath(os.path.dirname(wfexs_backend.__file__)),
        "module": "wfexs_backend",
    },
]

autodoc2_output_dir = "apidocs"

autodoc2_hidden_regexes = [
    r".*\.logger$",
    r".*\.magic$",
    r".*\.YAMLDumper$",
    r".*\.YAMLLoader$",
    r".*\.KT$",
    r".*\.VT$",
    r".*\.SCHEME_HANDLERS$",
]

intersphinx_mapping = {
    'python': ('https://docs.python.org/3/', None),
    'sphinx': ('https://www.sphinx-doc.org/en/master/', None),
}
intersphinx_disabled_domains = ['std']

templates_path = ['_templates']

source_suffix = {
    '.rst': 'restructuredtext',
    '.md': 'markdown',
}

myst_enable_extensions = ['colon_fence']

# -- Options for HTML output

html_theme = 'sphinx_book_theme'
html_logo = "images/WfExS-logo-final_paths.svg"
html_favicon = "images/WfExS-logo-final_paths.svg"

html_theme_options = {
    "logo": {
        # "text": f"{project} {version} {os.environ.get('READTHEDOCS_GIT_COMMIT_HASH', '')}",
        "text": f"{project} {version}",
    },
    "repository_url": os.environ.get("READTHEDOCS_GIT_CLONE_URL", "https://github.com/inab/WfExS-backend"),
    "repository_branch": os.environ.get("READTHEDOCS_GIT_IDENTIFIER", "readthedocs_merge"),
    "path_to_docs": "docs/source",
    "use_repository_button": True,
    "use_issues_button": True,
    "use_edit_page_button": True,
}



# -- Options for EPUB output
epub_show_urls = 'footnote'
