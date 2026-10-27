"""Wire <-> effective classification of IMPORT_PROVENANCE ``source_format``.

Spec v1.1.0 Table 40 fixes 0x0001 raw, 0x0002 ELF core, 0x0003 minidump,
0x0004 macOS core dump, 0x0005 ProcDump, 0xFFFF Other. MemDiver's earlier
files used 0x0004 for "an existing .msl" and 0x0005 for "regioned raw".

New files write 0xFFFF plus an origin field in the provenance note
(``source_format=msl`` / ``source_format=regioned_raw``). On read, 0x0004 /
0x0005 keep the legacy MemDiver meaning ONLY when the provenance
``tool_name`` is ``memdiver`` (every MemDiver writer sets it); from any other
writer they are the spec's macOS core / ProcDump. This module is the single
place that rule lives: consumers get the *effective* format from
:func:`effective_source_format` (via ``msl.import_preview``).
"""

from __future__ import annotations

from typing import Optional

from .enums import SourceFormat

MEMDIVER_TOOL_NAME = "memdiver"
ORIGIN_NOTE_KEY = "source_format"
_ORIGIN_NAMES = {SourceFormat.MSL: "msl",
                 SourceFormat.REGIONED_RAW: "regioned_raw"}
_ORIGIN_BY_NAME = {v: k for k, v in _ORIGIN_NAMES.items()}
_SPEC_CODES = {SourceFormat.MACOS_CORE: 0x0004, SourceFormat.PROCDUMP: 0x0005}


def _is_memdiver(tool_name: Optional[str]) -> bool:
    return (tool_name or "").strip().lower() == MEMDIVER_TOOL_NAME


def note_origin_format(note: Optional[str]) -> Optional[SourceFormat]:
    """First ``source_format=<origin>`` field of *note* (MSL / REGIONED_RAW).

    The FIRST occurrence wins: materialize appends its own ``source_format=msl``
    after the original note, so the earliest value is the real origin.
    """
    for segment in (note or "").replace(";", "; ").split("; "):
        key, sep, value = segment.partition("=")
        if sep and key.strip() == ORIGIN_NOTE_KEY:
            origin = _ORIGIN_BY_NAME.get(value.strip())
            if origin is not None:
                return origin
    return None


def effective_source_format(source_format: Optional[int], tool_name: str = "",
                            note: str = "") -> Optional[SourceFormat]:
    """MemDiver's classification of a provenance ``source_format``.

    ``None`` stays ``None`` (no provenance). Unknown codes also give ``None``.
    """
    if source_format is None:
        return None
    code = int(source_format)
    memdiver = _is_memdiver(tool_name)
    if code == SourceFormat.OTHER:
        return (note_origin_format(note) if memdiver else None) \
            or SourceFormat.OTHER
    if code in (0x0004, 0x0005):
        if memdiver:
            return SourceFormat(code)  # legacy MemDiver MSL / REGIONED_RAW
        return (SourceFormat.MACOS_CORE if code == 0x0004
                else SourceFormat.PROCDUMP)
    try:
        return SourceFormat(code)
    except ValueError:
        return None


def wire_source_format(fmt: int) -> int:
    """Code to WRITE for *fmt*: MemDiver-internal origins become 0xFFFF.

    The classification-only members (outside the u16 wire range) map back to
    their spec codes, so no caller can ever pack 0x1000x into the field.
    """
    if fmt in _ORIGIN_NAMES:
        return int(SourceFormat.OTHER)
    if fmt in _SPEC_CODES:
        return _SPEC_CODES[SourceFormat(fmt)]
    return int(fmt)


def origin_note_field(fmt: int) -> str:
    """``source_format=<origin>`` note field for an origin format."""
    return f"{ORIGIN_NOTE_KEY}={_ORIGIN_NAMES[SourceFormat(fmt)]}"


def strip_origin_fields(note: Optional[str]) -> str:
    """*note* without any ``source_format=<msl|regioned_raw>`` origin field.

    Used when a copy's effective origin is OTHER: a stale origin field left
    in the note would otherwise make the copy read back as MSL / regioned raw.
    """
    kept = []
    for segment in (note or "").split(";"):
        key, sep, value = segment.partition("=")
        if sep and key.strip() == ORIGIN_NOTE_KEY and \
                value.strip() in _ORIGIN_BY_NAME:
            continue
        kept.append(segment)
    return ";".join(kept)
