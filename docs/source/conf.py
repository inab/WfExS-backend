# Configuration file for the Sphinx documentation builder.

import os
import sys
sys.path.insert(0, os.path.normpath(os.path.join(os.path.dirname(__file__), '../..')))

# print("HOLA")
# print(sys.path)
# print("HOLAERR", file=sys.stderr)
# print(sys.path, file=sys.stderr)

# -- Project information

import wfexs_backend

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
