# Sphinx configuration file for the Trustpoint documentation.  # noqa: D100, INP001
# For full details, see:
# https://www.sphinx-doc.org/en/master/usage/configuration.html

import os
import sys
from pathlib import Path

import django

BUILD_AUTODOCS = True

# -- Path setup -------------------------------------------------------------
# Ensures Sphinx can find the project's modules for autodoc and autoapi.
# Get absolute path to project root
project_root = Path(__file__).parents[2].resolve()

# Add the `trustpoint/features` directory to the Sphinx path
feature_path = project_root / 'trustpoint' / 'features'

sys.path.insert(0, str(feature_path))

# -- Django setup (only required if using Django models in documentation) --
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'trustpoint.settings')  # Set Django settings
django.setup()  # Initialize Django

# -- PlantUML Configuration -------------------------------------------------
# Define the path to the PlantUML JAR file for diagram generation.
PLANTUML_PATH = Path(__file__).parent / 'plantuml-mit-1.2025.2.jar'
plantuml = f'java -jar {PLANTUML_PATH}'

# -- Project information ----------------------------------------------------
project = 'Trustpoint'
copyright = '2025, Trustpoint Project'
author = 'Trustpoint Project'
release = '0.3.0.dev1'  # Project version

# -- General configuration --------------------------------------------------
extensions = [
    'sphinx.ext.inheritance_diagram',  # Generates class inheritance diagrams
    'sphinx.ext.viewcode',  # Adds links to highlighted source code
    'sphinxcontrib.plantuml',  # Enables PlantUML diagrams
]

if BUILD_AUTODOCS:
    autodoc_extensions = [
        'sphinx.ext.autodoc',  # Auto-generate documentation from docstrings
        'sphinx.ext.napoleon',  # Supports Google & NumPy docstring formats
        'autoapi.extension',  # Automatically documents the API
    ]
    extensions.extend(autodoc_extensions)
    autoapi_dirs = ['../../trustpoint']  # Directories for autoapi to scan
    autodoc_typehints = 'description'  # Display type hints in descriptions

# -- Templates and exclusions -----------------------------------------------
templates_path = ['_templates']  # Custom templates directory
exclude_patterns = ['_build', '_templates']  # Ignore these directories

# -- HTML output options ----------------------------------------------------
html_theme = 'furo'  # Modern, responsive theme
html_static_path = ['_static']  # Directory for static assets
