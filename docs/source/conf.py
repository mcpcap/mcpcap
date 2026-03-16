# Configuration file for the Sphinx documentation builder.

import os
import sys

import tomllib

# Add the src directory to the path for autodoc
sys.path.insert(0, os.path.abspath("../../src"))

# Read version from pyproject.toml
with open("../../pyproject.toml", "rb") as f:
    pyproject = tomllib.load(f)

# Project information
project = pyproject["project"]["name"]
author = ", ".join([author["name"] for author in pyproject["project"]["authors"]])
copyright = f"2024, {author}"

# The version info from setuptools_scm
try:
    from mcpcap import __version__

    version = __version__
    release = __version__
except ImportError:
    version = "0.1.0-dev"
    release = "0.1.0-dev"

# General configuration
extensions = [
    "sphinx.ext.autodoc",
    "sphinx.ext.autosummary",
    "sphinx.ext.viewcode",
    "sphinx.ext.napoleon",
    "sphinx.ext.intersphinx",
    "sphinx_autodoc_typehints",
    "myst_parser",
    "sphinx_copybutton",
]

# Templates path
templates_path = ["_templates"]

# List of patterns to ignore when looking for source files
exclude_patterns = []

# Options for HTML output
html_theme = "sphinx_rtd_theme"
html_static_path = ["_static"]
html_baseurl = "https://docs.mcpcap.ai/en/stable/"
html_extra_path = ["robots.txt"]
html_theme_options = {
    "canonical_url": html_baseurl,
    "analytics_id": "",
    "logo_only": False,
    "prev_next_buttons_location": "bottom",
    "style_external_links": False,
    "vcs_pageview_mode": "",
    "style_nav_header_background": "#2980B9",
    # Toc options
    "collapse_navigation": True,
    "sticky_navigation": True,
    "navigation_depth": 4,
    "includehidden": True,
    "titles_only": False,
}

# Add any paths that contain custom static files (such as style sheets)
html_logo = None
html_favicon = None

# AutoDoc configuration
autodoc_default_options = {
    "members": True,
    "member-order": "bysource",
    "special-members": "__init__",
    "undoc-members": True,
    "exclude-members": "__weakref__",
}

# Napoleon settings for parsing Google and NumPy style docstrings
napoleon_google_docstring = True
napoleon_numpy_docstring = True
napoleon_include_init_with_doc = False
napoleon_include_private_with_doc = False
napoleon_include_special_with_doc = True
napoleon_use_admonition_for_examples = False
napoleon_use_admonition_for_notes = False
napoleon_use_admonition_for_references = False
napoleon_use_ivar = False
napoleon_use_param = True
napoleon_use_rtype = True
napoleon_preprocess_types = False
napoleon_type_aliases = None
napoleon_attr_annotations = True

# Intersphinx mappings
intersphinx_mapping = {
    "python": ("https://docs.python.org/3", None),
    "scapy": ("https://scapy.readthedocs.io/en/latest/", None),
}

# MyST parser configuration
myst_enable_extensions = [
    "amsmath",
    "colon_fence",
    "deflist",
    "dollarmath",
    "html_admonition",
    "html_image",
    "linkify",
    "replacements",
    "smartquotes",
    "substitution",
    "tasklist",
]

# Copy button configuration
copybutton_prompt_text = r">>> |\.\.\. |\$ |In \[\d*\]: | {2,5}\.\.\.: | {5,8}: "
copybutton_prompt_is_regexp = True
