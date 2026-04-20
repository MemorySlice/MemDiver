"""Adapter converting Kaitai Struct parsed objects to field overlays.

Bridges Kaitai Struct's parsed object tree (with ``_debug`` metadata) into
MemDiver's flat overlay list so the Hex Viewer can highlight parsed fields.

No Kaitai-specific imports at module level -- works without ``kaitaistruct``.
"""

from __future__ import annotations

import logging
from enum import IntEnum
from typing import Any

logger = logging.getLogger("memdiver.kaitai_adapter")

_MAX_BYTES_DISPLAY = 8


class KaitaiFieldOverlay:
    """Single field overlay produced from a Kaitai-parsed object."""

    __slots__ = (
        "field_name",
        "offset",
        "length",
        "display",
        "description",
        "valid",
        "path",
    )

    def __init__(
        self,
        field_name: str,
        offset: int,
        length: int,
        display: str,
        description: str = "",
        valid: bool = True,
        path: str = "",
    ) -> None:
        self.field_name = field_name
        self.offset = offset
        self.length = length
        self.display = display
        self.description = description
        self.valid = valid
        self.path = path

    def to_dict(self) -> dict[str, Any]:
        """Serialize to plain dict for JSON / overlay consumption."""
        return {
            "field_name": self.field_name,
            "offset": self.offset,
            "length": self.length,
            "display": self.display,
            "description": self.description,
            "valid": self.valid,
            "path": self.path,
        }


def _is_kaitai_struct(obj: Any) -> bool:
    """Check if *obj* is a KaitaiStruct instance without importing the class."""
    return type(obj).__name__ == "KaitaiStruct" or hasattr(obj, "_debug")


def _format_value(value: Any) -> str:
    """Return a human-readable display string for a parsed field value."""
    if isinstance(value, IntEnum):
        return f"{int(value)} ({value.name})"
    if isinstance(value, bytes):
        if len(value) <= _MAX_BYTES_DISPLAY:
            return value.hex()
        return value[:_MAX_BYTES_DISPLAY].hex() + "..."
    if isinstance(value, int):
        return str(value)
    return str(value)


def _build_path(prefix: str, name: str) -> str:
    """Join *prefix* and *name* with a dot separator."""
    return f"{prefix}.{name}" if prefix else name


class KaitaiOverlayAdapter:
    """Converts a Kaitai Struct parsed object tree to a flat overlay list."""

    def walk_fields(
        self,
        obj: Any,
        base_offset: int = 0,
        path_prefix: str = "",
    ) -> list[KaitaiFieldOverlay]:
        """Recursively extract field overlays from a Kaitai object.

        Returns a flat list of overlays sorted by offset.  *base_offset* is
        added to debug positions; *path_prefix* tracks the dot-separated
        hierarchy path.
        """
        overlays = self._collect_fields(obj, base_offset, path_prefix)
        overlays.sort(key=lambda o: o.offset)
        return overlays

    def _collect_fields(
        self,
        obj: Any,
        base_offset: int,
        path_prefix: str,
    ) -> list[KaitaiFieldOverlay]:
        """Internal recursive collector (no sorting)."""
        debug = getattr(obj, "_debug", None)
        if not isinstance(debug, dict):
            return []

        overlays: list[KaitaiFieldOverlay] = []

        for field_name, span in debug.items():
            if not isinstance(span, dict):
                continue
            start = span.get("start")
            end = span.get("end")
            if start is None or end is None:
                continue

            abs_offset = base_offset + int(start)
            length = int(end) - int(start)
            if length <= 0:
                continue

            value = getattr(obj, field_name, None)
            current_path = _build_path(path_prefix, field_name)

            try:
                overlays.extend(
                    self._process_value(
                        field_name, value, abs_offset, length, current_path,
                    ),
                )
            except Exception:  # noqa: BLE001
                logger.warning(
                    "Failed to process field %s at offset %d",
                    current_path,
                    abs_offset,
                )

        return overlays

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _process_value(
        self,
        field_name: str,
        value: Any,
        offset: int,
        length: int,
        path: str,
    ) -> list[KaitaiFieldOverlay]:
        """Dispatch a single field value to the correct handler."""

        # Nested struct -- recurse
        if _is_kaitai_struct(value):
            return self._collect_fields(value, base_offset=offset, path_prefix=path)

        # Array of structs -- iterate with indexed paths
        if isinstance(value, list):
            return self._process_array(field_name, value, offset, path)

        # Primitive / enum / bytes -- leaf overlay
        return [
            KaitaiFieldOverlay(
                field_name=field_name,
                offset=offset,
                length=length,
                display=_format_value(value),
                path=path,
            ),
        ]

    def _process_array(
        self,
        field_name: str,
        items: list[Any],
        parent_offset: int,
        path: str,
    ) -> list[KaitaiFieldOverlay]:
        """Handle array fields, recursing into struct elements."""
        overlays: list[KaitaiFieldOverlay] = []
        for idx, item in enumerate(items):
            indexed_path = f"{path}[{idx}]"
            if _is_kaitai_struct(item):
                overlays.extend(
                    self._collect_fields(item, base_offset=0, path_prefix=indexed_path),
                )
            else:
                overlays.append(
                    KaitaiFieldOverlay(
                        field_name=f"{field_name}[{idx}]",
                        offset=parent_offset,
                        length=0,
                        display=_format_value(item),
                        path=indexed_path,
                    ),
                )
        return overlays
