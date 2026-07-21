"""Maps raw secret type strings to human-readable display labels.

Presentation-layer catalog: human-readable DISPLAY STRINGS live at the
presentation edge, while the stable secret-type CODES stay in core. Relocated
here from ``memdiver.core.display_labels`` in the presentation-separation
refactor (a re-export shim remains at the old location so existing imports keep
working).

Delegates to the core protocol registry for label lookups (a presentation->core
import, the correct direction), falling back to the raw secret_type string if no
mapping exists. The registry's embedded ``display_labels``/``short_labels`` dicts
are the default (English) catalog; localization, when added, would override at
this presentation layer.
"""

from memdiver.core.protocols import REGISTRY


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
