#!/usr/bin/env python3
"""Generate the committed verify-key e2e fixture (``verify-fixture.json``).

This fixture drives the "verify a recovered key decrypts a known ciphertext"
flow against the committed synthetic MSL at
``tests/e2e/fixtures/synthetic_msl/sample.msl``.

That sample .msl (built by ``synthetic_msl/generate.py`` ->
``generate_msl_fixtures.generate_msl_file``) begins its single memory region's
page with ``0xAA * 32`` followed by ``0xBB * 32`` then random bytes. In the
``view="vas"`` projection (a flattened concatenation of CAPTURED page runs,
which for this all-CAPTURED single-page region is just the page) the ``0xAA*32``
key therefore lands at **vas offset 0** — confirmed here by ``find_all`` +
``read_range`` before anything is written.

We then build a genuine AES-256-GCM ciphertext under that same 32-byte key so a
caller can prove "the key at ``offset`` decrypts ``ciphertext`` to nothing-in-
particular but with a valid tag":

    key       = 0xAA * 32
    nonce     = bytes(range(12))
    plaintext = bytes(range(32))
    ct_tag    = AESGCM(key).encrypt(nonce, plaintext, None)
    ciphertext, tag = ct_tag[:-16], ct_tag[-16:]

Deterministic + re-runnable (fixed key/nonce/plaintext). Run from anywhere:

    /path/to/python tests/e2e/fixtures/verify_key/generate.py
"""

from __future__ import annotations

import json
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from memdiver.app.composition import open_dump

HERE = Path(__file__).resolve().parent
REPO_ROOT = HERE.parents[3]  # .../tests/e2e/fixtures/verify_key -> repo root
SAMPLE_MSL = REPO_ROOT / "tests" / "e2e" / "fixtures" / "synthetic_msl" / "sample.msl"

OUT = HERE / "verify-fixture.json"

KEY = bytes([0xAA]) * 32
NONCE = bytes(range(12))
PLAINTEXT = bytes(range(32))
_TAG_LEN = 16


def _locate_key_offset() -> int:
    """Return the vas offset of KEY in sample.msl; assert it round-trips."""
    with open_dump(SAMPLE_MSL) as src:
        offsets = src.find_all(KEY)  # view="vas"
        if not offsets:
            raise AssertionError(f"{KEY.hex()} not found in {SAMPLE_MSL}")
        offset = offsets[0]
        if src.read_range(offset, len(KEY)) != KEY:
            raise AssertionError("read_range(offset, 32) did not return the key")
    return offset


def main() -> None:
    if not SAMPLE_MSL.is_file():
        raise SystemExit(
            f"missing {SAMPLE_MSL}; run synthetic_msl/generate.py first"
        )

    offset = _locate_key_offset()

    ct_tag = AESGCM(KEY).encrypt(NONCE, PLAINTEXT, None)
    ciphertext, tag = ct_tag[:-_TAG_LEN], ct_tag[-_TAG_LEN:]

    # Sanity: the key really does authenticate/decrypt this ciphertext.
    if AESGCM(KEY).decrypt(NONCE, ciphertext + tag, None) != PLAINTEXT:
        raise AssertionError("AES-256-GCM round-trip failed")

    fixture = {
        "offset": offset,
        "length": len(KEY),
        "cipher": "AES-256-GCM",
        "ciphertext_hex": ciphertext.hex(),
        "nonce_hex": NONCE.hex(),
        "tag_hex": tag.hex(),
        "key_hex": KEY.hex(),
    }
    OUT.write_text(json.dumps(fixture, indent=2) + "\n")

    print("SELF-VERIFY OK")
    print(f"offset = {offset}  (read_range(offset, 32) == key)")
    print(f"wrote {OUT}  ({OUT.stat().st_size} bytes)")


if __name__ == "__main__":
    main()
