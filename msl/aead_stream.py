"""Incremental (streaming) AEAD encryption for MSL containers (spec §10).

The MSL encrypted layout is ONE AEAD over the whole block stream
(``[Header 128B | KEM ct | ciphertext | Tag 16B]``). The one-shot helpers in
:mod:`memdiver.msl.crypto` need the full plaintext in memory; the encryptors
here produce byte-identical output for the same key/nonce/AAD while holding
only the piece being encrypted:

* AES-256-GCM — ``cryptography`` hazmat ``Cipher(AES, GCM)`` encryptor
  (``authenticate_additional_data`` / ``update`` / ``finalize`` / ``tag``).
* XChaCha20-Poly1305 (IETF, libsodium ``crypto_aead_xchacha20poly1305_ietf``)
  — composed from HChaCha20 (sub-key derivation, one block, pure Python),
  the ``cryptography`` ChaCha20 stream cipher and its incremental Poly1305
  MAC, following draft-irtf-cfrg-xchacha / RFC 8439 §2.8. PyNaCl exposes no
  incremental AEAD (``secretstream`` is a different, chunked format).

Equivalence with the one-shot path is pinned by ``tests/test_msl_aead_stream.py``.
"""

import struct
from typing import List

from .enums import EncAlgo
from .types import MslCryptoError

_MASK32 = 0xFFFFFFFF
_SIGMA = (0x61707865, 0x3320646E, 0x79622D32, 0x6B206574)  # "expand 32-byte k"


def _rotl32(v: int, c: int) -> int:
    return ((v << c) & _MASK32) | (v >> (32 - c))


def _quarter_round(s: List[int], a: int, b: int, c: int, d: int) -> None:
    s[a] = (s[a] + s[b]) & _MASK32
    s[d] = _rotl32(s[d] ^ s[a], 16)
    s[c] = (s[c] + s[d]) & _MASK32
    s[b] = _rotl32(s[b] ^ s[c], 12)
    s[a] = (s[a] + s[b]) & _MASK32
    s[d] = _rotl32(s[d] ^ s[a], 8)
    s[c] = (s[c] + s[d]) & _MASK32
    s[b] = _rotl32(s[b] ^ s[c], 7)


def hchacha20(key: bytes, nonce16: bytes) -> bytes:
    """HChaCha20 (draft-irtf-cfrg-xchacha §2.2): 32-byte sub-key."""
    if len(key) != 32 or len(nonce16) != 16:
        raise MslCryptoError("HChaCha20 needs a 32-byte key and 16-byte nonce")
    state = [*_SIGMA, *struct.unpack("<8I", key), *struct.unpack("<4I", nonce16)]
    for _ in range(10):  # 20 rounds = 10 column/diagonal double rounds
        _quarter_round(state, 0, 4, 8, 12)
        _quarter_round(state, 1, 5, 9, 13)
        _quarter_round(state, 2, 6, 10, 14)
        _quarter_round(state, 3, 7, 11, 15)
        _quarter_round(state, 0, 5, 10, 15)
        _quarter_round(state, 1, 6, 11, 12)
        _quarter_round(state, 2, 7, 8, 13)
        _quarter_round(state, 3, 4, 9, 14)
    return struct.pack("<8I", *state[0:4], *state[12:16])


class _AesGcmStream:
    def __init__(self, key: bytes, nonce: bytes, aad: bytes):
        from cryptography.hazmat.primitives.ciphers import (Cipher, algorithms,
                                                            modes)
        self._enc = Cipher(algorithms.AES(key), modes.GCM(nonce)).encryptor()
        self._enc.authenticate_additional_data(aad)

    def update(self, data) -> bytes:
        return self._enc.update(data)

    def finalize(self) -> bytes:
        self._enc.finalize()
        return self._enc.tag


class _XChaCha20Poly1305Stream:
    """IETF XChaCha20-Poly1305, encrypt direction, fed incrementally."""

    def __init__(self, key: bytes, nonce: bytes, aad: bytes):
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms
        from cryptography.hazmat.primitives.poly1305 import Poly1305
        if len(nonce) != 24:
            raise MslCryptoError("XChaCha20-Poly1305 needs a 24-byte nonce")
        subkey = hchacha20(key, nonce[:16])
        # cryptography's 16-byte ChaCha20 "nonce" = LE32 block counter || 96-bit
        # IETF nonce; the XChaCha IETF nonce is 4 zero bytes || nonce[16:24].
        iv = b"\x00" * 8 + nonce[16:24]
        self._stream = Cipher(algorithms.ChaCha20(subkey, iv), mode=None).encryptor()
        poly_key = self._stream.update(b"\x00" * 64)[:32]  # block 0; data from 1
        self._mac = Poly1305(poly_key)
        self._mac.update(aad)
        self._mac.update(_pad16(len(aad)))
        self._aad_len = len(aad)
        self._ct_len = 0

    def update(self, data) -> bytes:
        ct = self._stream.update(data)
        self._mac.update(ct)
        self._ct_len += len(ct)
        return ct

    def finalize(self) -> bytes:
        self._stream.finalize()
        self._mac.update(_pad16(self._ct_len))
        self._mac.update(struct.pack("<QQ", self._aad_len, self._ct_len))
        return self._mac.finalize()


def _pad16(n: int) -> bytes:
    return b"\x00" * (-n % 16)


def aead_stream_encryptor(algo: EncAlgo, key: bytes, nonce: bytes, aad: bytes):
    """Return an object with ``update(bytes) -> bytes`` and ``finalize() -> tag``.

    ``b"".join(update(p) for p in pieces) + finalize()`` equals
    :func:`memdiver.msl.crypto.aead_encrypt` over ``b"".join(pieces)``.
    """
    if algo == EncAlgo.AES_256_GCM:
        return _AesGcmStream(key, nonce, aad)
    if algo == EncAlgo.XCHACHA20_POLY1305:
        return _XChaCha20Poly1305Stream(key, nonce, aad)
    raise MslCryptoError(f"Unsupported cipher suite: {algo}")
