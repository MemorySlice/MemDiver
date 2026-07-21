"""Decode HTTP key-material fields into ``open_dump()`` kwargs (spec §10).

Single source of truth for turning the wire representation used by
``POST /api/inspect/tag-status`` (``passphrase`` / ``key_hex`` /
``kem_key_hex``) into the ``key`` / ``passphrase`` / ``kem_private_key``
byte kwargs that :func:`core.dump_source.open_dump` and
:class:`msl.reader.MslReader` accept. Reused by every inspect/analysis
endpoint that can open an encrypted container so the request shape never
drifts between routes.
"""

from __future__ import annotations

from typing import Any, Dict, Optional

from memdiver.core.service_errors import CapabilityError, ErrorCategory


def decode_key_material(
    passphrase: Optional[str] = None,
    key_hex: Optional[str] = None,
    kem_key_hex: Optional[str] = None,
) -> Optional[Dict[str, Any]]:
    """Return ``open_dump`` key kwargs from the wire fields, or ``None``.

    Mirrors the key-material shape of ``POST /api/inspect/tag-status``:
    ``passphrase`` (utf-8 text), ``key_hex`` (raw symmetric key, hex), and
    ``kem_key_hex`` (KEM private key, hex). Returns ``None`` when no secret
    was supplied so callers can splat ``**(km or {})`` into ``open_dump``
    without changing the plaintext path. Raises HTTP 400 on malformed hex.
    """
    if not (passphrase or key_hex or kem_key_hex):
        return None
    try:
        key = bytes.fromhex(key_hex) if key_hex else None
        kem_private = bytes.fromhex(kem_key_hex) if kem_key_hex else None
    except ValueError as exc:
        raise CapabilityError(
            "Invalid key material encoding",
            category=ErrorCategory.INVALID_INPUT,
        ) from exc
    return {
        "key": key,
        "passphrase": passphrase.encode("utf-8") if passphrase else None,
        "kem_private_key": kem_private,
    }
