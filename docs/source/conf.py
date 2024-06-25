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
    'sphinx.ext.duration',
    'sphinx.ext.doctest',
    'sphinx.ext.autodoc',
    'sphinx.ext.autosummary',
    'sphinx.ext.intersphinx',
    'sphinx_copybutton',
    'sphinxarg.ext',
    'sphinxcontrib.datatemplates',
    'myst_parser',
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

html_theme = 'sphinx_rtd_theme'

# -- Options for EPUB output
epub_show_urls = 'footnote'
