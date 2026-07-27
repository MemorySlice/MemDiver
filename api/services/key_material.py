"""Decode HTTP key-material fields into ``open_dump()`` kwargs (spec §10).

Thin HTTP-surface adapter over the canonical decoder in
:mod:`memdiver.core.key_material`: it turns the wire representation used by
``POST /api/inspect/tag-status`` (``passphrase`` / ``key_hex`` / ``kem_key_hex``)
into the ``key`` / ``passphrase`` / ``kem_private_key`` byte kwargs that
:func:`core.dump_source.open_dump` and :class:`msl.reader.MslReader` accept.
Reused by every inspect/analysis endpoint that can open an encrypted container
so the request shape never drifts between routes.
"""

from __future__ import annotations

from typing import Any, Dict, Optional

from memdiver.core.key_material import from_hex


def decode_key_material(
    passphrase: Optional[str] = None,
    key_hex: Optional[str] = None,
    kem_key_hex: Optional[str] = None,
) -> Optional[Dict[str, Any]]:
    """Return ``open_dump`` key kwargs from the wire fields, or ``None``.

    Thin HTTP-surface adapter over :func:`core.key_material.from_hex`; preserves
    the wire field names (``passphrase`` / ``key_hex`` / ``kem_key_hex``), the
    None-when-empty contract callers splat as ``**(km or {})``, and the
    ``CapabilityError`` (HTTP 400) raised on malformed hex.
    """
    return from_hex(passphrase, key_hex, kem_key_hex)
