"""Sphinx configuration for MemDiver documentation."""

from __future__ import annotations

import os
import sys
from importlib.metadata import PackageNotFoundError
from importlib.metadata import version as _version

sys.path.insert(0, os.path.abspath(".."))

project = "MemDiver"
author = "Anonymous"
copyright = "2026, Anonymous"

try:
    release = _version("memdiver")
except PackageNotFoundError:
    release = "0.0.0+unknown"
version = ".".join(release.split(".")[:2])

language = "en"
locale_dirs = ["locales/"]
gettext_compact = False

extensions = [
    "myst_parser",
    "sphinx.ext.autodoc",
    "sphinx.ext.autosummary",
    "sphinx.ext.napoleon",
    "sphinx.ext.viewcode",
    "sphinx.ext.intersphinx",
    "sphinx.ext.githubpages",
    "sphinx.ext.extlinks",
    "sphinx_copybutton",
    "sphinx_design",
    "sphinxarg.ext",
    "sphinxcontrib.mermaid",
]

source_suffix = {".rst": "restructuredtext", ".md": "markdown"}
exclude_patterns = ["_build", "Thumbs.db", ".DS_Store", "screenshots"]

myst_enable_extensions = [
    "colon_fence",
    "deflist",
    "attrs_inline",
    "attrs_block",
    "fieldlist",
    "tasklist",
    "substitution",
    "linkify",
    "smartquotes",
]
myst_heading_anchors = 3

html_theme = "sphinx_rtd_theme"
html_theme_options = {
    "logo_only": False,
    "prev_next_buttons_location": "bottom",
    "collapse_navigation": False,
    "sticky_navigation": True,
    "navigation_depth": 4,
    "style_nav_header_background": "#0b0d10",
}
html_static_path = ["_static"]
html_css_files = ["custom.css"]
html_logo = "_static/logo_simple.svg"
html_favicon = "_static/favicon.ico"
html_title = "MemDiver Documentation"
html_baseurl = "https://memoryslice.github.io/MemDiver/"
html_show_sphinx = False
html_copy_source = False

napoleon_google_docstring = True
napoleon_numpy_docstring = False
napoleon_use_rtype = False
napoleon_include_init_with_doc = False

autodoc_default_options = {
    "members": True,
    "undoc-members": False,
    "show-inheritance": True,
    "member-order": "bysource",
    "exclude-members": "__weakref__,__dict__,__module__",
}
autodoc_typehints = "description"
autodoc_class_signature = "separated"
autodoc_preserve_defaults = True
autodoc_mock_imports = [
    "frida_tools",
    "memslicer",
    "duckdb",
    "ibis",
    "polars",
    "blake3",
    "zstandard",
    "lz4",
    "pyahocorasick",
    "kaitaistruct",
    "nicegui",
    "marimo",
    "uvicorn",
    "fastapi",
    "mcp",
]
autosummary_generate = True
add_module_names = False

intersphinx_mapping = {
    "python": ("https://docs.python.org/3", None),
    "numpy": ("https://numpy.org/doc/stable/", None),
    "pydantic": ("https://docs.pydantic.dev/latest/", None),
}
extlinks = {
    "gh": ("https://github.com/MemorySlice/MemDiver/blob/main/%s", "%s"),
    "issue": ("https://github.com/MemorySlice/MemDiver/issues/%s", "#%s"),
}
