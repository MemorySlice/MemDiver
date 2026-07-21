"""Deprecated location — relocated to memdiver.app.tools_xref (presentation-separation refactor).

Re-exported here so existing imports keep working; prefer memdiver.app.tools_xref.
"""
import sys as _sys

from memdiver.app import tools_xref as _relocated

_sys.modules[__name__] = _relocated
