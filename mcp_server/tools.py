"""Deprecated location — relocated to memdiver.app.tools (presentation-separation refactor).

Re-exported here so existing imports keep working; prefer memdiver.app.tools.
"""
import sys as _sys

from memdiver.app import tools as _relocated

_sys.modules[__name__] = _relocated
