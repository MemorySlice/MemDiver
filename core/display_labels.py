"""Maps raw secret type strings to human-readable display labels.

Delegates to the protocol registry for label lookups, falling back to
the raw secret_type string if no mapping exists.
"""

from .protocols import REGISTRY


def get_display_label(secret_type: str, version: str) -> str:
    """Return a human-readable display label for the given secret type and version.

    Falls back to the raw secret_type string if no mapping exists.
    """
    return REGISTRY.lookup_label(secret_type, version) or secret_type


def get_short_label(secret_type: str, version: str) -> str:
    """Return a short display label for the given secret type and version.

    Falls back to the raw secret_type string if no mapping exists.
    """
    return REGISTRY.lookup_label(secret_type, version, short=True) or secret_type
