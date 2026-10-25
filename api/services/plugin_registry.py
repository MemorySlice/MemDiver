"""Plugin source registry for the web plugin editor (plan T2.5).

The implementation is :mod:`memdiver.analysis.plugin_store` (the ``app`` layer
may not import ``api``); this module is the ``api/services`` entry point for it,
like the other shims here.
"""

from memdiver.analysis.plugin_store import (  # noqa: F401
    MAX_SOURCE_BYTES,
    NAME_PATTERN,
    PluginStore,
    sha256_text,
    validate_name,
)

__all__ = ["MAX_SOURCE_BYTES", "NAME_PATTERN", "PluginStore", "sha256_text", "validate_name"]
