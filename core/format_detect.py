"""Binary format detection from magic bytes.

Detection logic now lives in the shared :class:`FormatRegistry`
(``core.binary_formats.format_descriptor``), the single source of truth for
every format.  This module keeps its historical public API -- ``detect_format``,
``suggest_formats``, ``MAGIC_SIGNATURES`` and the ``_classify_*`` helpers -- but
derives/delegates to the registry so results stay identical.
"""

from __future__ import annotations
import struct
from typing import Optional

from memdiver.core.binary_formats.format_descriptor import (
    classify_elf as _classify_elf_impl,
    classify_pe as _classify_pe_impl,
    get_default_registry,
)


def _build_magic_signatures() -> dict[str, tuple[int, bytes]]:
    """Reconstruct the legacy ``{name: (offset, magic)}`` table from the registry.

    Only fixed magic signatures are included (in registration order), matching
    the original ``MAGIC_SIGNATURES`` content exactly.  Custom detectors (PE,
    the CAFEBABE fat/java split, ASN.1 DER) are intentionally excluded, just as
    before.
    """
    signatures: dict[str, tuple[int, bytes]] = {}
    for descriptor in get_default_registry().all():
        for result_name, offset, magic in descriptor.magics:
            signatures[result_name] = (offset, magic)
    return signatures


# Magic byte signatures: (offset, expected_bytes).  Kept as a module-level
# shim (derived from the registry) for backward compatibility; used by
# ``suggest_formats``.
MAGIC_SIGNATURES: dict[str, tuple[int, bytes]] = _build_magic_signatures()


def detect_format(data: bytes) -> Optional[str]:
    """Detect binary format from magic bytes at offset 0."""
    if len(data) < 4:
        return None
    return get_default_registry().detect(data)


def _classify_elf(data: bytes) -> str:
    return _classify_elf_impl(data)


def _classify_pe(data: bytes, pe_offset: int) -> str:
    """Classify PE as pe32 or pe64 based on optional header magic."""
    return _classify_pe_impl(data, pe_offset)


def detect_format_at_offset(data: bytes, offset: int) -> Optional[str]:
    """Detect format at an arbitrary offset within a dump."""
    if offset < 0 or offset >= len(data):
        return None
    return detect_format(data[offset:])


def _detector_suggestion_reason(descriptor, data: bytes) -> Optional[str]:
    """Historical ``suggest_formats`` reason text for a detector-matched format.

    The detection *logic* is single-sourced in each descriptor's ``detector``
    callable; this only supplies the human-readable ``reason`` string, which is
    data-dependent and cannot be recovered from a detector's return value.

    Returns ``None`` for detector-only formats that ``suggest_formats`` never
    surfaced historically (e.g. ``asn1_der``), so the output contract for
    built-in inputs is preserved exactly.
    """
    if descriptor.name == "pe":
        # PE's historical reason exposes the PE-header offset (``e_lfanew``); it
        # is display-only and not recoverable from the detector's return value.
        try:
            e_lfanew = struct.unpack_from("<I", data, 0x3C)[0]
        except struct.error:
            return None
        return f"PE signature at 0x{e_lfanew:X}"
    if descriptor.name == "macho":
        # Shared 0xCAFEBABE fat/java magic is matched at offset 0.
        return "magic at 0x0"
    return None


def suggest_formats(data: bytes) -> list[dict]:
    """Ranked parser suggestions. Magic-matched entries first (magic_ok=True).

    Derived live from :func:`get_default_registry` (the descriptors' magic
    signatures, classifiers and detectors) rather than a frozen snapshot, so
    formats registered at runtime -- e.g. via the ``memdiver.formats``
    entry-point group -- are suggested too, and the PE / CAFEBABE detection
    logic is single-sourced in the descriptors instead of duplicated here.

    TODO: future work should include deep embedded-scan secondary suggestions
    (e.g. ELF embedded in a larger binary container).
    """
    suggestions: list[dict] = []
    if not data:
        return suggestions

    registry = get_default_registry()

    # Fixed magic signatures (registration order), refined by any classifier.
    for descriptor in registry.all():
        for result_name, off, magic in descriptor.magics:
            end = off + len(magic)
            if len(data) >= end and data[off:end] == magic:
                classified = (
                    descriptor.classifier(data)
                    if descriptor.classifier is not None
                    else result_name
                )
                suggestions.append({
                    "format": classified,
                    "reason": f"magic at 0x{off:X}",
                    "magic_ok": True,
                })

    # Detector-based formats. The byte-level detection logic lives on the
    # descriptors (no more hand-duplicated MZ/PE or CAFEBABE compares here); we
    # only attach the historical, data-dependent ``reason`` string per format.
    for descriptor in registry.all():
        if descriptor.detector is None:
            continue
        try:
            result = descriptor.detector(data)
        except Exception:  # noqa: BLE001 - a faulty detector must not break suggestions
            continue
        if result is None:
            continue
        reason = _detector_suggestion_reason(descriptor, data)
        if reason is None:
            # Detector-only formats that suggest_formats never surfaced
            # historically (e.g. asn1_der) are intentionally omitted to preserve
            # the exact output contract for built-in inputs.
            continue
        suggestions.append({
            "format": result,
            "reason": reason,
            "magic_ok": True,
        })

    return suggestions
