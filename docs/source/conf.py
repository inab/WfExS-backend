# Configuration file for the Sphinx documentation builder.

import os
import sys
sys.path.insert(0, os.path.normpath(os.path.join(os.path.dirname(__file__), '../..')))

print("HOLA")
print(sys.path)
print("HOLAERR", file=sys.stderr)
print(sys.path, file=sys.stderr)

# -- Project information

project = 'WfExS-backend'
copyright = '2022-2023, Barcelona Supercomputing Center'
author = 'José Mª Fernández, Laura Rodríguez-Navas'

release = '0.1'
version = '0.1.0'

# -- General configuration

extensions = [
    'sphinx.ext.duration',
    'sphinx.ext.doctest',
    'sphinx.ext.autodoc',
    'sphinx.ext.autosummary',
    'sphinx.ext.intersphinx',
    'sphinx_copybutton',
    'sphinxarg.ext',
]

intersphinx_mapping = {
    'python': ('https://docs.python.org/3/', None),
    'sphinx': ('https://www.sphinx-doc.org/en/master/', None),
}
intersphinx_disabled_domains = ['std']

templates_path = ['_templates']

# -- Options for HTML output

html_theme = 'sphinx_rtd_theme'

# -- Options for EPUB output
epub_show_urls = 'footnote'
