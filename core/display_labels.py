"""Deprecated location — display strings relocated to memdiver.presentation.labels
(presentation-separation refactor).

Re-exported here so existing imports keep working; prefer
memdiver.presentation.labels.
"""
import sys as _sys

from memdiver.presentation import labels as _relocated

_sys.modules[__name__] = _relocated
