"""Canonical key-material decoders for opening encrypted ``.msl`` containers.

Single source of truth for turning a surface's decryption inputs into the byte
kwargs that :func:`core.dump_source.open_dump` and :class:`msl.reader.MslReader`
accept, namely the dict ``{"key", "passphrase", "kem_private_key"}``.

Two input idioms are supported, one per calling surface:

* :func:`from_files` — file-path inputs (CLI flags, MCP params, app tools):
  ``key_file`` / ``kem_key_file`` are read as raw bytes and ``passphrase`` is
  utf-8 encoded. Always returns a dict (every value ``None`` when nothing was
  supplied).
* :func:`from_hex` — wire inputs (HTTP request fields): ``key_hex`` /
  ``kem_key_hex`` are hex-decoded and ``passphrase`` is utf-8 encoded. Returns
  ``None`` when nothing was supplied so callers can splat ``**(km or {})``, and
  raises :class:`core.service_errors.CapabilityError` on malformed hex.

This module lives in ``core`` and depends only on the same-layer
``core.service_errors``; it never imports up into app/api/engine/cli. Which of
key vs passphrase vs KEM material is actually used is decided later, by the
container's own header at decrypt time — this module only forwards the bytes.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, Optional

from memdiver.core.service_errors import CapabilityError, ErrorCategory


def _build(
    key: Optional[bytes],
    passphrase: Optional[str],
    kem_private: Optional[bytes],
) -> Dict[str, Any]:
    """Assemble the canonical key-material dict.

    ``passphrase`` is utf-8 encoded here; an empty/absent passphrase becomes
    ``None`` so it never reaches the reader as empty bytes.
    """
    return {
        "key": key,
        "passphrase": passphrase.encode("utf-8") if passphrase else None,
        "kem_private_key": kem_private,
    }


def from_files(
    key_file: Optional[str] = None,
    passphrase: Optional[str] = None,
    kem_key_file: Optional[str] = None,
) -> Dict[str, Any]:
    """Decode file-path key inputs into ``open_dump`` kwargs.

    Reads ``key_file`` / ``kem_key_file`` as raw bytes and utf-8 encodes
    ``passphrase``. Always returns the three-key dict, with every value ``None``
    when no input was supplied.
    """
    key = Path(key_file).read_bytes() if key_file else None
    kem_private = Path(kem_key_file).read_bytes() if kem_key_file else None
    return _build(key, passphrase, kem_private)


def from_hex(
    passphrase: Optional[str] = None,
    key_hex: Optional[str] = None,
    kem_key_hex: Optional[str] = None,
) -> Optional[Dict[str, Any]]:
    """Decode hex/wire key inputs into ``open_dump`` kwargs, or ``None``.

    ``key_hex`` / ``kem_key_hex`` are hex-decoded to bytes and ``passphrase`` is
    utf-8 encoded. Returns ``None`` when no secret was supplied so callers can
    splat ``**(km or {})`` without changing the plaintext path. Raises
    :class:`CapabilityError` (``INVALID_INPUT``) on malformed hex.
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
    return _build(key, passphrase, kem_private)
