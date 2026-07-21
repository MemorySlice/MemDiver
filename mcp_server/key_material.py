"""Deprecated location — relocated to memdiver.app.key_material (presentation-separation refactor).

Re-exported here so existing imports keep working; prefer memdiver.app.key_material.
"""
import sys as _sys

from memdiver.app import key_material as _relocated

_sys.modules[__name__] = _relocated
