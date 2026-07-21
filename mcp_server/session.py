"""Deprecated location — relocated to memdiver.app.session (presentation-separation refactor).

Re-exported here so existing imports keep working; prefer memdiver.app.session.
"""
import sys as _sys

from memdiver.app import session as _relocated

_sys.modules[__name__] = _relocated
