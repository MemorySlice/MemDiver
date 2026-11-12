"""ChaCha20, HChaCha20, Poly1305 and (X)ChaCha20-Poly1305 in pure Python.

The pure-Python tier behind the gocryptfs format oracle: it opens XChaCha20-Poly1305
vault blocks on a host where neither ``cryptography`` nor ``pycryptodome`` is installed
(a bare ``pip install volatility3``).  Library backends are chosen by the caller, so this
module has no accelerated path: ``backend()`` is always ``"pure-python"``.

Self-contained on purpose: at module level this file imports only the Python standard
library (no MemDiver, no Volatility 3, no sibling module, no relative import) and it never
reads ``__file__``, so it can be pasted verbatim into a generated single-file plugin.
Private names carry the ``_chacha_`` prefix.  Python 3.8 compatible.

Specifications
--------------
* ChaCha20 block function and encryption: RFC 8439 sections 2.3 and 2.4
  (32-bit block counter, 96-bit nonce).
* Poly1305: RFC 8439 section 2.5; one-time key generation: section 2.6.
* ChaCha20-Poly1305 AEAD: RFC 8439 section 2.8.
* HChaCha20 and XChaCha20-Poly1305: draft-irtf-cfrg-xchacha-03 sections 2.2 and 2.3
  (subkey = HChaCha20(key, nonce[:16]); inner nonce = 4 zero bytes || nonce[16:24]).

Decryption authenticates FIRST: the Poly1305 tag is computed over the ciphertext and
compared in constant time (``hmac.compare_digest``) before any byte is decrypted, so a
wrong key -- the common case when a memory sweep tries candidates -- costs two ChaCha20
blocks (HChaCha20 and the one-time key) plus Poly1305, never the keystream.
"""

import hmac
import struct
from typing import Optional, Tuple

_CHACHA_MASK32 = 0xFFFFFFFF
_CHACHA_CONSTANTS = struct.unpack("<4I", b"expand 32-byte k")
_CHACHA_STATE = struct.Struct("<16I")
_CHACHA_KEY_LEN = 32
_CHACHA_NONCE_LEN = 12
_CHACHA_XNONCE_LEN = 24
_CHACHA_HNONCE_LEN = 16
_CHACHA_TAG_LEN = 16
_CHACHA_BLOCK_LEN = 64
_CHACHA_POLY_P = (1 << 130) - 5
_CHACHA_POLY_R_CLAMP = 0x0FFFFFFC0FFFFFFC0FFFFFFC0FFFFFFF  # RFC 8439 section 2.5.1
_CHACHA_MASK128 = (1 << 128) - 1


def backend() -> str:
    """Always ``"pure-python"``: this module has no library-accelerated path."""
    return "pure-python"


# --------------------------------------------------------------------------- block function


def _chacha_rounds(state):
    """The 20 ChaCha rounds (10 column + 10 diagonal double rounds) WITHOUT the final add.

    Unrolled into local variables because this is the hot loop of a candidate sweep; each
    four-line group is one quarter round QR(a, b, c, d) of RFC 8439 section 2.1.
    """
    x0, x1, x2, x3, x4, x5, x6, x7, x8, x9, x10, x11, x12, x13, x14, x15 = state
    m = _CHACHA_MASK32
    for _ in range(10):
        # column rounds
        x0 = (x0 + x4) & m; x12 ^= x0; x12 = (x12 << 16 & m) | (x12 >> 16)
        x8 = (x8 + x12) & m; x4 ^= x8; x4 = (x4 << 12 & m) | (x4 >> 20)
        x0 = (x0 + x4) & m; x12 ^= x0; x12 = (x12 << 8 & m) | (x12 >> 24)
        x8 = (x8 + x12) & m; x4 ^= x8; x4 = (x4 << 7 & m) | (x4 >> 25)
        x1 = (x1 + x5) & m; x13 ^= x1; x13 = (x13 << 16 & m) | (x13 >> 16)
        x9 = (x9 + x13) & m; x5 ^= x9; x5 = (x5 << 12 & m) | (x5 >> 20)
        x1 = (x1 + x5) & m; x13 ^= x1; x13 = (x13 << 8 & m) | (x13 >> 24)
        x9 = (x9 + x13) & m; x5 ^= x9; x5 = (x5 << 7 & m) | (x5 >> 25)
        x2 = (x2 + x6) & m; x14 ^= x2; x14 = (x14 << 16 & m) | (x14 >> 16)
        x10 = (x10 + x14) & m; x6 ^= x10; x6 = (x6 << 12 & m) | (x6 >> 20)
        x2 = (x2 + x6) & m; x14 ^= x2; x14 = (x14 << 8 & m) | (x14 >> 24)
        x10 = (x10 + x14) & m; x6 ^= x10; x6 = (x6 << 7 & m) | (x6 >> 25)
        x3 = (x3 + x7) & m; x15 ^= x3; x15 = (x15 << 16 & m) | (x15 >> 16)
        x11 = (x11 + x15) & m; x7 ^= x11; x7 = (x7 << 12 & m) | (x7 >> 20)
        x3 = (x3 + x7) & m; x15 ^= x3; x15 = (x15 << 8 & m) | (x15 >> 24)
        x11 = (x11 + x15) & m; x7 ^= x11; x7 = (x7 << 7 & m) | (x7 >> 25)
        # diagonal rounds
        x0 = (x0 + x5) & m; x15 ^= x0; x15 = (x15 << 16 & m) | (x15 >> 16)
        x10 = (x10 + x15) & m; x5 ^= x10; x5 = (x5 << 12 & m) | (x5 >> 20)
        x0 = (x0 + x5) & m; x15 ^= x0; x15 = (x15 << 8 & m) | (x15 >> 24)
        x10 = (x10 + x15) & m; x5 ^= x10; x5 = (x5 << 7 & m) | (x5 >> 25)
        x1 = (x1 + x6) & m; x12 ^= x1; x12 = (x12 << 16 & m) | (x12 >> 16)
        x11 = (x11 + x12) & m; x6 ^= x11; x6 = (x6 << 12 & m) | (x6 >> 20)
        x1 = (x1 + x6) & m; x12 ^= x1; x12 = (x12 << 8 & m) | (x12 >> 24)
        x11 = (x11 + x12) & m; x6 ^= x11; x6 = (x6 << 7 & m) | (x6 >> 25)
        x2 = (x2 + x7) & m; x13 ^= x2; x13 = (x13 << 16 & m) | (x13 >> 16)
        x8 = (x8 + x13) & m; x7 ^= x8; x7 = (x7 << 12 & m) | (x7 >> 20)
        x2 = (x2 + x7) & m; x13 ^= x2; x13 = (x13 << 8 & m) | (x13 >> 24)
        x8 = (x8 + x13) & m; x7 ^= x8; x7 = (x7 << 7 & m) | (x7 >> 25)
        x3 = (x3 + x4) & m; x14 ^= x3; x14 = (x14 << 16 & m) | (x14 >> 16)
        x9 = (x9 + x14) & m; x4 ^= x9; x4 = (x4 << 12 & m) | (x4 >> 20)
        x3 = (x3 + x4) & m; x14 ^= x3; x14 = (x14 << 8 & m) | (x14 >> 24)
        x9 = (x9 + x14) & m; x4 ^= x9; x4 = (x4 << 7 & m) | (x4 >> 25)
    return (x0, x1, x2, x3, x4, x5, x6, x7, x8, x9, x10, x11, x12, x13, x14, x15)


def _chacha_checked(value, length: int, what: str) -> bytes:
    value = bytes(value)
    if len(value) != length:
        raise ValueError("%s must be %d bytes, got %d" % (what, length, len(value)))
    return value


def _chacha_key_words(key) -> Tuple[int, ...]:
    return struct.unpack("<8I", _chacha_checked(key, _CHACHA_KEY_LEN, "ChaCha20 key"))


def _chacha_block_from_words(key_words, counter: int, nonce_words) -> bytes:
    state = _CHACHA_CONSTANTS + key_words + (counter,) + nonce_words
    mixed = _chacha_rounds(state)
    return _CHACHA_STATE.pack(*[(a + b) & _CHACHA_MASK32 for a, b in zip(mixed, state)])


def _chacha_check_counter(counter: int, blocks: int) -> None:
    if counter < 0 or counter + blocks > 1 << 32:
        raise ValueError("ChaCha20 block counter must stay within 32 bits")


def chacha20_block(key, counter: int, nonce) -> bytes:
    """One 64-byte ChaCha20 block (RFC 8439 section 2.3): 32-bit counter, 12-byte nonce."""
    _chacha_check_counter(counter, 1)
    nonce_words = struct.unpack("<3I", _chacha_checked(nonce, _CHACHA_NONCE_LEN, "nonce"))
    return _chacha_block_from_words(_chacha_key_words(key), counter, nonce_words)


def chacha20_xor(key, counter: int, nonce, data) -> bytes:
    """ChaCha20 encryption = decryption (RFC 8439 section 2.4), starting at block ``counter``."""
    data = bytes(data)
    blocks = -(-len(data) // _CHACHA_BLOCK_LEN)
    _chacha_check_counter(counter, blocks)
    key_words = _chacha_key_words(key)
    nonce_words = struct.unpack("<3I", _chacha_checked(nonce, _CHACHA_NONCE_LEN, "nonce"))
    if not data:
        return b""
    stream = b"".join(_chacha_block_from_words(key_words, counter + i, nonce_words)
                      for i in range(blocks))
    mixed = int.from_bytes(data, "little") ^ int.from_bytes(stream[:len(data)], "little")
    return mixed.to_bytes(len(data), "little")


def hchacha20(key, nonce) -> bytes:
    """HChaCha20 (draft-irtf-cfrg-xchacha-03 section 2.2): 32-byte subkey from a 16-byte nonce.

    The ChaCha20 rounds over constants || key || nonce, WITHOUT the final addition of the
    input state; the output is state words 0-3 and 12-15.
    """
    nonce_words = struct.unpack("<4I", _chacha_checked(nonce, _CHACHA_HNONCE_LEN, "HChaCha20 nonce"))
    mixed = _chacha_rounds(_CHACHA_CONSTANTS + _chacha_key_words(key) + nonce_words)
    return struct.pack("<8I", *(mixed[0:4] + mixed[12:16]))


# --------------------------------------------------------------------------- Poly1305


def poly1305_mac(key, message) -> bytes:
    """The 16-byte Poly1305 tag of ``message`` under a 32-byte one-time key (RFC 8439 2.5)."""
    key = _chacha_checked(key, 32, "Poly1305 key")
    message = bytes(message)
    r = int.from_bytes(key[:16], "little") & _CHACHA_POLY_R_CLAMP
    s = int.from_bytes(key[16:], "little")
    accumulator, p = 0, _CHACHA_POLY_P
    for offset in range(0, len(message), 16):
        block = message[offset: offset + 16]
        accumulator = ((accumulator + int.from_bytes(block + b"\x01", "little")) * r) % p
    return ((accumulator + s) & _CHACHA_MASK128).to_bytes(16, "little")


def _chacha_pad16(data: bytes) -> bytes:
    return b"\x00" * (-len(data) % 16)


def _chacha_aead_tag(otk: bytes, aad: bytes, ciphertext: bytes) -> bytes:
    """RFC 8439 section 2.8: Poly1305 over aad || pad16 || ct || pad16 || le64 lengths."""
    mac_data = (aad + _chacha_pad16(aad) + ciphertext + _chacha_pad16(ciphertext)
                + struct.pack("<QQ", len(aad), len(ciphertext)))
    return poly1305_mac(otk, mac_data)


# --------------------------------------------------------------------------- AEAD


def chacha20_poly1305_encrypt(key, nonce, plaintext, aad=b"") -> Tuple[bytes, bytes]:
    """ChaCha20-Poly1305 (RFC 8439 section 2.8) returning ``(ciphertext, tag)``."""
    otk = chacha20_block(key, 0, nonce)[:32]
    ciphertext = chacha20_xor(key, 1, nonce, plaintext)
    return ciphertext, _chacha_aead_tag(otk, bytes(aad), ciphertext)


def chacha20_poly1305_decrypt(key, nonce, ciphertext, tag, aad=b"") -> Optional[bytes]:
    """ChaCha20-Poly1305 decryption; ``None`` when the tag does not verify.

    The tag is checked before anything is decrypted (see the module docstring).
    """
    tag = _chacha_checked(tag, _CHACHA_TAG_LEN, "Poly1305 tag")
    ciphertext = bytes(ciphertext)
    otk = chacha20_block(key, 0, nonce)[:32]
    if not hmac.compare_digest(_chacha_aead_tag(otk, bytes(aad), ciphertext), tag):
        return None
    return chacha20_xor(key, 1, nonce, ciphertext)


def _chacha_xsplit(key, nonce) -> Tuple[bytes, bytes]:
    """``(subkey, inner 12-byte nonce)`` of XChaCha20 (draft-irtf-cfrg-xchacha-03 2.3)."""
    nonce = _chacha_checked(nonce, _CHACHA_XNONCE_LEN, "XChaCha20 nonce")
    return hchacha20(key, nonce[:16]), b"\x00" * 4 + nonce[16:]


def xchacha20_poly1305_encrypt(key, nonce, plaintext, aad=b"") -> Tuple[bytes, bytes]:
    """XChaCha20-Poly1305 with a 24-byte nonce, returning ``(ciphertext, tag)``."""
    subkey, inner_nonce = _chacha_xsplit(key, nonce)
    return chacha20_poly1305_encrypt(subkey, inner_nonce, plaintext, aad)


def xchacha20_poly1305_decrypt(key, nonce, ciphertext, tag, aad=b"") -> Optional[bytes]:
    """XChaCha20-Poly1305 decryption with a 24-byte nonce; ``None`` on a bad tag."""
    subkey, inner_nonce = _chacha_xsplit(key, nonce)
    return chacha20_poly1305_decrypt(subkey, inner_nonce, ciphertext, tag, aad)
