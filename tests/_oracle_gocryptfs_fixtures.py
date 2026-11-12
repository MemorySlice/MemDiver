"""Shared gocryptfs fixtures for the ``memdiver.oracles`` tests.

Synthetic vault files are sealed here with ``cryptography`` plus a textbook
HChaCha20, deliberately WITHOUT any helper from the oracle under test: a bug
shared by builder and verifier would otherwise make both sides agree and the
test pass for nothing. The HKDF info strings are typed out again for the
same reason.

Corpus helpers locate the real gocryptfs runs (``MEMDIVER_GOCRYPTFS_CORPUS``,
defaulting to the machine-local dataset); tests skip cleanly without them.
"""

from __future__ import annotations

import hashlib
import json
import os
import struct
from pathlib import Path

GOCRYPTFS_CORPUS = Path(os.environ.get("MEMDIVER_GOCRYPTFS_CORPUS", "") or "/nonexistent")
HAVE_CORPUS = (GOCRYPTFS_CORPUS / "run_0001" / "cipher" / "gocryptfs.conf").is_file()
RUN_0001_MASTER_HEX = "ee2813d66ee64fd0a1eb7b2efa58b92f5315fd27e6017d81693e552bf57859a2"

FEATURE_FLAGS = {
    "aes-gcm": ["HKDF", "GCMIV128", "DirIV", "EMENames", "LongNames", "Raw64"],
    "xchacha": ["HKDF", "XChaCha20Poly1305", "DirIV", "EMENames", "LongNames", "Raw64"],
    "aes-siv": ["HKDF", "GCMIV128", "AESSIV", "DirIV", "EMENames", "LongNames", "Raw64"],
}
NONCE_LEN = {"aes-gcm": 16, "xchacha": 24, "aes-siv": 16}
CONTENT_KEY_LEN = {"aes-gcm": 32, "xchacha": 32, "aes-siv": 64}
HKDF_INFO = {
    "aes-gcm": b"AES-GCM file content encryption",
    "xchacha": b"XChaCha20-Poly1305 file content encryption",
    "aes-siv": b"AES-SIV file content encryption",
}
# A conf secret that must never reach a sample blob.
CONF_SECRET = "Q09ORl9TRUNSRVRfRU5DUllQVEVEX0tFWQ=="

_MASK = 0xFFFFFFFF
_QUARTER_ROUNDS = (
    (0, 4, 8, 12), (1, 5, 9, 13), (2, 6, 10, 14), (3, 7, 11, 15),
    (0, 5, 10, 15), (1, 6, 11, 12), (2, 7, 8, 13), (3, 4, 9, 14),
)


def conf_json(flags: list[str] | None) -> bytes:
    """A gocryptfs.conf with the given FeatureFlags and a dummy secret."""
    return json.dumps({
        "Creator": "gocryptfs 2.4.0",
        "EncryptedKey": CONF_SECRET,
        "ScryptObject": {"Salt": "c2FsdA==", "N": 65536, "R": 8, "P": 1, "KeyLen": 32},
        "Version": 2,
        "FeatureFlags": flags or [],
    }).encode()


def hkdf_ref(master: bytes, info: bytes, length: int) -> bytes:
    """HKDF-SHA256, salt None -- via cryptography, not the oracle's stdlib copy."""
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF

    return HKDF(algorithm=hashes.SHA256(), length=length, salt=None, info=info).derive(master)


def content_key_ref(master: bytes, cipher: str) -> bytes:
    return hkdf_ref(master, HKDF_INFO[cipher], CONTENT_KEY_LEN[cipher])


def _rotl(value: int, count: int) -> int:
    return ((value << count) & _MASK) | (value >> (32 - count))


def _quarter_round(s: list[int], a: int, b: int, c: int, d: int) -> None:
    s[a] = (s[a] + s[b]) & _MASK
    s[d] = _rotl(s[d] ^ s[a], 16)
    s[c] = (s[c] + s[d]) & _MASK
    s[b] = _rotl(s[b] ^ s[c], 12)
    s[a] = (s[a] + s[b]) & _MASK
    s[d] = _rotl(s[d] ^ s[a], 8)
    s[c] = (s[c] + s[d]) & _MASK
    s[b] = _rotl(s[b] ^ s[c], 7)


def hchacha20_ref(key: bytes, nonce16: bytes) -> bytes:
    """Textbook HChaCha20 (draft-irtf-cfrg-xchacha-03 section 2.2)."""
    state = list(
        struct.unpack("<4I", b"expand 32-byte k")
        + struct.unpack("<8I", key)
        + struct.unpack("<4I", nonce16)
    )
    for _ in range(10):
        for quarter in _QUARTER_ROUNDS:
            _quarter_round(state, *quarter)
    return struct.pack("<8I", *(state[0:4] + state[12:16]))


def seal_block(cipher: str, key: bytes, nonce: bytes, plaintext: bytes, aad: bytes) -> bytes:
    """One on-disk gocryptfs block: nonce || AEAD output as gocryptfs lays it out."""
    from cryptography.hazmat.primitives.ciphers import aead

    if cipher == "aes-gcm":
        return nonce + aead.AESGCM(key).encrypt(nonce, plaintext, aad)
    if cipher == "xchacha":
        subkey = hchacha20_ref(key, nonce[:16])
        return nonce + aead.ChaCha20Poly1305(subkey).encrypt(b"\x00" * 4 + nonce[16:], plaintext, aad)
    if cipher == "aes-siv":
        return nonce + aead.AESSIV(key).encrypt(plaintext, [aad, nonce])
    raise ValueError(cipher)


def encrypt_file(
    cipher: str, content_key: bytes, plaintext: bytes,
    file_id: bytes = bytes(range(16)), nonce_len: int | None = None,
) -> bytes:
    """A whole gocryptfs content file: header || block_0 || block_1 ..."""
    nonce_len = nonce_len or NONCE_LEN[cipher]
    out = struct.pack(">H", 2) + file_id
    for block_no in range(0, max(1, -(-len(plaintext) // 4096))):
        chunk = plaintext[block_no * 4096:(block_no + 1) * 4096]
        nonce = hashlib.sha256(b"nonce" + bytes([block_no])).digest()[:nonce_len]
        out += seal_block(cipher, content_key, nonce, chunk, struct.pack(">Q", block_no) + file_id)
    return out


def corpus_runs(cipher: str | None = None) -> list[Path]:
    """Corpus run dirs (sorted), optionally only those whose meta.json cipher matches."""
    if not HAVE_CORPUS:
        return []
    runs = sorted(p for p in GOCRYPTFS_CORPUS.glob("run_*") if (p / "meta.json").is_file())
    return [r for r in runs if cipher is None or run_meta(r).get("cipher") == cipher]


def run_meta(run_dir: Path) -> dict:
    return json.loads((run_dir / "meta.json").read_text())
