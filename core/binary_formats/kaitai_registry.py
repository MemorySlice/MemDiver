"""Registry mapping detected format names to Kaitai Struct parsers.

Provides lazy loading of compiled Kaitai parsers so the rest of MemDiver
never needs to import ``kaitaistruct`` directly.  If the runtime is not
installed, all operations degrade gracefully (returning ``None`` or empty
lists).
"""

from __future__ import annotations

import logging
from typing import Any

logger = logging.getLogger("memdiver.kaitai_registry")

# Mapping from format_detect.py names to (module_path, class_name).
# Extend this dict as new compiled parsers are added.
_FORMAT_MAP: dict[str, tuple[str, str]] = {
    "elf64": ("core.binary_formats.kaitai_compiled.elf", "Elf"),
    "elf32": ("core.binary_formats.kaitai_compiled.elf", "Elf"),
    "elf": ("core.binary_formats.kaitai_compiled.elf", "Elf"),
    "pe": ("core.binary_formats.kaitai_compiled.microsoft_pe", "MicrosoftPe"),
    "pe32": ("core.binary_formats.kaitai_compiled.microsoft_pe", "MicrosoftPe"),
    "pe64": ("core.binary_formats.kaitai_compiled.microsoft_pe", "MicrosoftPe"),
    "macho": ("core.binary_formats.kaitai_compiled.mach_o", "MachO"),
    "macho32": ("core.binary_formats.kaitai_compiled.mach_o", "MachO"),
    "macho64": ("core.binary_formats.kaitai_compiled.mach_o", "MachO"),
    "macho64_le": ("core.binary_formats.kaitai_compiled.mach_o", "MachO"),
    "macho32_le": ("core.binary_formats.kaitai_compiled.mach_o", "MachO"),
    "macho64_be": ("core.binary_formats.kaitai_compiled.mach_o", "MachO"),
    "macho32_be": ("core.binary_formats.kaitai_compiled.mach_o", "MachO"),
    "macho_fat": ("core.binary_formats.kaitai_compiled.mach_o", "MachO"),
}

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

        entry = _FORMAT_MAP.get(format_name)
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
        return list(_FORMAT_MAP.keys())

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
