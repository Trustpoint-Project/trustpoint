# Configuration file for the Sphinx documentation builder.
#
# For the full list of built-in configuration values, see the documentation:
# https://www.sphinx-doc.org/en/master/usage/configuration.html

import os
import sys
from pathlib import Path

import django

sys.path.insert(0, os.path.abspath('../../trustpoint'))
os.environ['DJANGO_SETTINGS_MODULE'] = 'trustpoint.settings'
django.setup()

PLANTUML_PATH = Path(__file__).parent.absolute() / Path('plantuml-mit-1.2025.2.jar')

# -- Project information -----------------------------------------------------
# https://www.sphinx-doc.org/en/master/usage/configuration.html#project-information

project = 'Trustpoint'
copyright = '2025, Trustpoint Project'
author = 'Trustpoint Project'
release = '0.2.0'

# -- General configuration ---------------------------------------------------
# https://www.sphinx-doc.org/en/master/usage/configuration.html#general-configuration

extensions = [
    'sphinx.ext.autodoc',
    'sphinx.ext.inheritance_diagram',
    'sphinx.ext.napoleon',  # For Google/NumPy docstrings
    'sphinx.ext.viewcode',  # Adds links to the source code
    'sphinxcontrib.plantuml',
    'autoapi.extension',
]

autoapi_dirs = ['../../trustpoint']
autodoc_typehints = 'description'

templates_path = ['_templates']
exclude_patterns = ['_build', '_templates']

# -- Options for HTML output -------------------------------------------------
# https://www.sphinx-doc.org/en/master/usage/configuration.html#options-for-html-output

html_theme = 'furo'
html_static_path = ['_static']

plantuml = f'java -jar {PLANTUML_PATH}'
