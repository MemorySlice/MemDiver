"""Registry mapping detected format names to Kaitai Struct parsers.

Provides lazy loading of compiled Kaitai parsers so the rest of MemDiver
never needs to import ``kaitaistruct`` directly.  If the runtime is not
installed, all operations degrade gracefully (returning ``None`` or empty
lists).
"""

from __future__ import annotations

import logging
from typing import Any

from memdiver.core.binary_formats.format_descriptor import get_default_registry

logger = logging.getLogger("memdiver.kaitai_registry")


def _build_format_map() -> dict[str, tuple[str, str]]:
    """Derive the name -> (module_path, class_name) map from the registry.

    Every descriptor that declares a Kaitai parser contributes an entry for its
    canonical name and each alias, reproducing the former hardcoded table.
    """
    format_map: dict[str, tuple[str, str]] = {}
    for descriptor in get_default_registry().all():
        if descriptor.kaitai is None:
            continue
        for name in descriptor.names:
            format_map[name] = descriptor.kaitai
    return format_map


# Import-time SNAPSHOT of the name -> (module_path, class_name) map, kept as a
# module-level name for backward compatibility (e.g. tests asserting agreement
# with the registry).  It is NOT consulted for live lookups: `parse()` and
# `available_formats()` re-derive from the registry on every call so a format
# registered via `register_format()` AFTER this module is imported is still
# picked up (matching navigator.build_nav_tree and format_detect.detect_format,
# which also re-derive per call).  To add a parser, register a FormatDescriptor
# with a ``kaitai`` field instead of editing anything here.
_FORMAT_MAP: dict[str, tuple[str, str]] = _build_format_map()

_KAITAI_AVAILABLE: bool | None = None


def kaitai_available() -> bool:
    """Return True if the ``kaitaistruct`` runtime is installed."""
    global _KAITAI_AVAILABLE  # noqa: PLW0603
    if _KAITAI_AVAILABLE is None:
        try:
            import kaitaistruct  # noqa: F401

            _KAITAI_AVAILABLE = True
        except ImportError:
            _KAITAI_AVAILABLE = False
    return _KAITAI_AVAILABLE


class KaitaiFormatRegistry:
    """Lazy-loading registry that maps format names to Kaitai parser classes."""

    def __init__(self) -> None:
        self._loaded: dict[str, type] = {}

    def parse(self, format_name: str, data: bytes) -> Any | None:
        """Parse *data* using the Kaitai parser registered for *format_name*.

        Returns the parsed object tree, or ``None`` if:
        - ``kaitaistruct`` is not installed,
        - no parser is registered for *format_name*, or
        - parsing fails.
        """
        if not kaitai_available():
            logger.debug("kaitaistruct not installed; skipping parse")
            return None

        entry = _build_format_map().get(format_name)
        if entry is None:
            logger.debug("No Kaitai parser registered for %s", format_name)
            return None

        parser_cls = self._load_parser(format_name, entry)
        if parser_cls is None:
            return None

        return self._run_parser(parser_cls, data, format_name)

    def available_formats(self) -> list[str]:
        """Return format names that have a registered Kaitai parser."""
        if not kaitai_available():
            return []
        return list(_build_format_map().keys())

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _load_parser(
        self,
        format_name: str,
        entry: tuple[str, str],
    ) -> type | None:
        """Lazy-import and cache the parser class for *format_name*."""
        if format_name in self._loaded:
            return self._loaded[format_name]

        module_path, class_name = entry
        try:
            import importlib

            mod = importlib.import_module(module_path)
            cls = getattr(mod, class_name)
            self._loaded[format_name] = cls
            return cls
        except Exception:  # noqa: BLE001
            logger.warning(
                "Failed to load Kaitai parser for %s from %s",
                format_name,
                module_path,
            )
            return None

    @staticmethod
    def _run_parser(parser_cls: type, data: bytes, format_name: str) -> Any | None:
        """Instantiate the parser on *data*, returning None on failure."""
        try:
            from io import BytesIO

            from kaitaistruct import KaitaiStream

            stream = KaitaiStream(BytesIO(data))
            return parser_cls(stream)
        except Exception:  # noqa: BLE001
            logger.warning("Kaitai parse failed for %s", format_name)
            return None


# ------------------------------------------------------------------
# Singleton accessor
# ------------------------------------------------------------------

_registry: KaitaiFormatRegistry | None = None


def get_kaitai_registry() -> KaitaiFormatRegistry:
    """Return the singleton :class:`KaitaiFormatRegistry`."""
    global _registry  # noqa: PLW0603
    if _registry is None:
        _registry = KaitaiFormatRegistry()
    return _registry
