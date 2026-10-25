"""Bundled detector fixtures for the built-in key finders (plan T3.7, D13).

Generated in code, not shipped as data files: every sample is deterministic noise
(``random.Random(seed).randbytes``) with a SYNTHETIC AES schedule planted at an
odd offset, so no wheel package-data is involved and the fixtures cannot drift
from :mod:`memdiver.algorithms.keyfinders.aes_tables`.

Positives: forward, inverse (``inverse_layout``) and ``swapped32`` layouts of an
AES-128 key, plus an AES-256 forward schedule. Decoys (expected ``no_match``): an
all-zero buffer, a ``0x09`` fill (constant bytes the S-box term must reject), and a
schedule whose first derived word is corrupted.
"""

from __future__ import annotations

import random
from typing import Any, Dict, List

from memdiver.algorithms.keyfinders.aes_tables import expand_key, inverse_layout

FINDER = "aes_schedule"
SAMPLE_SIZE = 512
_KEY128 = bytes(range(0x10, 0x20))
_KEY256 = bytes((7 * i + 3) % 256 for i in range(32))


def _noise(seed: int) -> bytearray:
    return bytearray(random.Random(seed).randbytes(SAMPLE_SIZE))


def _swapped32(blob: bytes) -> bytes:
    return b"".join(blob[i:i + 4][::-1] for i in range(0, len(blob), 4))


def _planted(seed: int, offset: int, blob: bytes) -> bytes:
    buf = _noise(seed)
    buf[offset:offset + len(blob)] = blob
    return bytes(buf)


def _positive(name: str, seed: int, offset: int, blob: bytes, key: bytes, label: str) -> Dict[str, Any]:
    return _fixture(name, _planted(seed, offset, blob),
                    {"matches": [{"offset": offset, "length": len(blob), "label": label,
                                  "key_hex": key.hex()}]})


def _fixture(name: str, sample: bytes, expect: Dict[str, Any]) -> Dict[str, Any]:
    return {"name": name, "artifact_kind": "keyfinder", "artifact": FINDER, "params": {},
            "sample": {"hex": sample.hex()}, "expect": expect, "source": "bundled"}


def _corrupted_first_derived_word() -> bytes:
    schedule = bytearray(expand_key(_KEY128))
    schedule[16] ^= 0xFF   # byte 0 of w[4]: the word the finder's prefilter checks
    return bytes(schedule)


def aes_schedule_fixtures() -> List[Dict[str, Any]]:
    """The bundled fixtures of the ``aes_schedule`` finder."""
    forward = expand_key(_KEY128)
    return [
        _positive("aes128_forward", 11, 37, forward, _KEY128, "aes128_schedule"),
        _positive("aes128_inverse_layout", 12, 53, inverse_layout(forward), _KEY128,
                  "aes128_schedule"),
        _positive("aes128_swapped32", 13, 101, _swapped32(forward), _KEY128, "aes128_schedule"),
        _positive("aes256_forward", 14, 71, expand_key(_KEY256), _KEY256, "aes256_schedule"),
        _fixture("decoy_zeros", bytes(SAMPLE_SIZE), {"no_match": True}),
        _fixture("decoy_fill_09", b"\x09" * SAMPLE_SIZE, {"no_match": True}),
        _fixture("decoy_corrupted_schedule",
                 _planted(15, 45, _corrupted_first_derived_word()), {"no_match": True}),
    ]


def bundled_fixtures(artifact_kind: str, artifact: str) -> List[Dict[str, Any]]:
    """Bundled fixtures for one detector (empty when none ship for it)."""
    if artifact_kind == "keyfinder" and artifact == FINDER:
        return aes_schedule_fixtures()
    return []
