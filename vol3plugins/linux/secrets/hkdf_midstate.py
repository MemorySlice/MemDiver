"""HKDF-SHA512 resumed from HMAC midstates, for proving fscrypt v2 master keys from memory.

fscrypt does not keep its HKDF pseudorandom key (PRK); it keeps an HMAC-SHA512 transform
keyed with it, i.e. only the two SHA-512 chaining states after absorbing ``PRK ^ ipad`` and
``PRK ^ opad``.  Those midstates are enough to run HKDF-Expand, so a candidate found in
memory can be proven by recomputing the 16-byte key identifier the kernel stores next to it.
No library can resume SHA-512 from a chaining state, so this module carries its own
FIPS 180-4 compression function; ``backend()`` is therefore always ``"pure-python"``.
The plain ``hkdf_extract``/``hkdf_expand`` helpers use the standard library's ``hmac``.

Self-contained on purpose: at module level this file imports only the Python standard
library (no MemDiver, no Volatility 3, no sibling module, no relative import) and it never
reads ``__file__``, so it can be pasted verbatim into a generated single-file plugin.

Where the kernel keeps the two midstates (``parse_sha512_state`` layouts)
------------------------------------------------------------------------
* ``"hmac_pads"`` -- <= v6.6, crypto/hmac.c: the tfm context starts with
  ``ipad[statesize] || opad[statesize]`` and the ``struct hmac_ctx { hash; }`` follows.
* ``"hmac_ctx"`` -- v6.7 to v6.16, crypto/hmac.c ``struct hmac_ctx { struct crypto_shash
  *hash; u8 pads[]; }``: a pointer, then the same two pads.  Each pad is the ``export`` of
  the inner sha512 after one block, ``struct sha512_state { u64 state[8]; u64 count[2];
  u8 buf[128]; }`` = 208 bytes up to v6.15; v6.16's block-only hashing appends a length
  byte (statesize 80 + 128 + 1 = 209).  ``count`` is ``(128, 0)``, which is checked.
* ``"hmac_sha512_key"`` -- the lib/crypto ``struct hmac_sha512_key { istate; ostate; }`` of
  bare ``u64 h[8]`` (include/crypto/sha2.h).  v6.17 still asks the crypto API for
  ``"hmac(sha512)"`` but crypto/sha512.c now serves it as ``hmac-sha512-lib`` whose tfm
  context is this struct; from v6.18 fscrypt embeds it directly
  (fs/crypto/fscrypt_private.h ``struct fscrypt_master_key_secret.hkdf``).
"""

import hashlib
import hmac
import struct
from typing import Optional, Sequence, Tuple

HKDF_CONTEXT_KEY_IDENTIFIER = 1  # renamed ..._KEY_IDENTIFIER_FOR_RAW_KEY in newer kernels
HKDF_CONTEXT_KEY_IDENTIFIER_FOR_RAW_KEY = 1
HKDF_CONTEXT_PER_FILE_ENC_KEY = 2  # info = file nonce
HKDF_CONTEXT_DIRECT_KEY = 3  # info = mode number
HKDF_CONTEXT_IV_INO_LBLK_64_KEY = 4  # info = mode number || fs uuid
HKDF_CONTEXT_DIRHASH_KEY = 5  # info = file nonce
HKDF_CONTEXT_IV_INO_LBLK_32_KEY = 6  # info = mode number || fs uuid
HKDF_CONTEXT_INODE_HASH_KEY = 7  # info = <empty>
HKDF_CONTEXT_KEY_IDENTIFIER_FOR_HW_WRAPPED_KEY = 8  # info = <empty>
FSCRYPT_KEY_IDENTIFIER_SIZE = 16  # include/uapi/linux/fscrypt.h

SHA512_LAYOUT_HMAC_PADS = "hmac_pads"
SHA512_LAYOUT_HMAC_CTX = "hmac_ctx"
SHA512_LAYOUT_HMAC_SHA512_KEY = "hmac_sha512_key"

_SHA512_BLOCK_SIZE = 128
_SHA512_DIGEST_SIZE = 64
_SHA512_MASK = (1 << 64) - 1
_SHA512_STATE_SIZES = (208, 209)  # sizeof(struct sha512_state); v6.16 block-only export
_SHA512_FSCRYPT_PREFIX = b"fscrypt\0"

_SHA512_IV = (
    0x6a09e667f3bcc908, 0xbb67ae8584caa73b, 0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1,
    0x510e527fade682d1, 0x9b05688c2b3e6c1f, 0x1f83d9abfb41bd6b, 0x5be0cd19137e2179,
)
_SHA512_K = (
    0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc,
    0x3956c25bf348b538, 0x59f111f1b605d019, 0x923f82a4af194f9b, 0xab1c5ed5da6d8118,
    0xd807aa98a3030242, 0x12835b0145706fbe, 0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2,
    0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235, 0xc19bf174cf692694,
    0xe49b69c19ef14ad2, 0xefbe4786384f25e3, 0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65,
    0x2de92c6f592b0275, 0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5,
    0x983e5152ee66dfab, 0xa831c66d2db43210, 0xb00327c898fb213f, 0xbf597fc7beef0ee4,
    0xc6e00bf33da88fc2, 0xd5a79147930aa725, 0x06ca6351e003826f, 0x142929670a0e6e70,
    0x27b70a8546d22ffc, 0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed, 0x53380d139d95b3df,
    0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6, 0x92722c851482353b,
    0xa2bfe8a14cf10364, 0xa81a664bbc423001, 0xc24b8b70d0f89791, 0xc76c51a30654be30,
    0xd192e819d6ef5218, 0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8,
    0x19a4c116b8d2d0c8, 0x1e376c085141ab53, 0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8,
    0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb, 0x5b9cca4f7763e373, 0x682e6ff3d6b2b8a3,
    0x748f82ee5defb2fc, 0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec,
    0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915, 0xc67178f2e372532b,
    0xca273eceea26619c, 0xd186b8c721c0c207, 0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178,
    0x06f067aa72176fba, 0x0a637dc5a2c898a6, 0x113f9804bef90dae, 0x1b710b35131c471b,
    0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc, 0x431d67c49c100d4c,
    0x4cc5d4becb3e42b6, 0x597f299cfc657e2a, 0x5fcb6fab3ad6faec, 0x6c44198c4a475817,
)

Sha512State = Tuple[int, int, int, int, int, int, int, int]


def backend() -> str:
    """Always ``"pure-python"``: no accelerator can resume SHA-512 from a midstate."""
    return "pure-python"


# --------------------------------------------------------------------------- SHA-512 core


def _sha512_schedule(block: bytes) -> list:
    """FIPS 180-4 section 6.4.2 step 1: the 80-word message schedule."""
    w = list(struct.unpack(">16Q", block))
    mask = _SHA512_MASK
    for t in range(16, 80):
        x, y = w[t - 15], w[t - 2]
        s0 = ((x >> 1) | (x << 63)) ^ ((x >> 8) | (x << 56)) ^ (x >> 7)
        s1 = ((y >> 19) | (y << 45)) ^ ((y >> 61) | (y << 3)) ^ (y >> 6)
        w.append((w[t - 16] + (s0 & mask) + w[t - 7] + (s1 & mask)) & mask)
    return w


def sha512_compress(h: Sequence[int], block: bytes) -> Sha512State:
    """One FIPS 180-4 SHA-512 compression: chaining state ``h`` (8 words) + 128-byte block."""
    if len(h) != 8 or len(block) != _SHA512_BLOCK_SIZE:
        raise ValueError("sha512_compress needs 8 state words and a 128-byte block")
    w = _sha512_schedule(bytes(block))
    mask = _SHA512_MASK
    a, b, c, d, e, f, g, hh = h
    for t in range(80):
        big_s1 = (((e >> 14) | (e << 50)) ^ ((e >> 18) | (e << 46)) ^ ((e >> 41) | (e << 23))) & mask
        t1 = hh + big_s1 + ((e & f) ^ (~e & g)) + _SHA512_K[t] + w[t]
        big_s0 = (((a >> 28) | (a << 36)) ^ ((a >> 34) | (a << 30)) ^ ((a >> 39) | (a << 25))) & mask
        t2 = big_s0 + ((a & b) ^ (a & c) ^ (b & c))
        a, b, c, d, e, f, g, hh = (t1 + t2) & mask, a, b, c, (d + t1) & mask, e, f, g
    return tuple((x + y) & mask for x, y in zip(h, (a, b, c, d, e, f, g, hh)))


def _sha512_finish(h: Sequence[int], absorbed: int, tail: bytes) -> bytes:
    """Digest of a message whose first ``absorbed`` bytes (whole blocks) are already in ``h``."""
    total_bits = (absorbed + len(tail)) * 8
    padded = tail + b"\x80" + bytes((111 - len(tail)) % _SHA512_BLOCK_SIZE)
    padded += total_bits.to_bytes(16, "big")
    state = tuple(h)
    for offset in range(0, len(padded), _SHA512_BLOCK_SIZE):
        state = sha512_compress(state, padded[offset: offset + _SHA512_BLOCK_SIZE])
    return struct.pack(">8Q", *state)


def _sha512_checked_state(h, what: str) -> Sha512State:
    state = tuple(int(word) for word in h)
    if len(state) != 8 or any(not 0 <= word <= _SHA512_MASK for word in state):
        raise ValueError("%s must be 8 unsigned 64-bit words" % what)
    return state


# --------------------------------------------------------------------------- HMAC / HKDF from midstates


def midstates_from_key(key) -> Tuple[Sha512State, Sha512State]:
    """``(ipad_h, opad_h)``: SHA-512 states after the ``K^ipad`` / ``K^opad`` block.

    Keys longer than 128 bytes are hashed first (RFC 2104), as lib/crypto/sha512.c
    ``__hmac_sha512_preparekey()`` and crypto/hmac.c ``hmac_setkey()`` do.
    """
    key = bytes(key)
    if len(key) > _SHA512_BLOCK_SIZE:
        key = hashlib.sha512(key).digest()
    key = key.ljust(_SHA512_BLOCK_SIZE, b"\0")
    ipad_block = bytes(byte ^ 0x36 for byte in key)
    opad_block = bytes(byte ^ 0x5C for byte in key)
    return sha512_compress(_SHA512_IV, ipad_block), sha512_compress(_SHA512_IV, opad_block)


def hmac_sha512_from_midstates(ipad_h, opad_h, msg) -> bytes:
    """HMAC-SHA512 of ``msg`` finished from the two midstates (each already absorbed 128 B)."""
    ipad_h = _sha512_checked_state(ipad_h, "ipad_h")
    opad_h = _sha512_checked_state(opad_h, "opad_h")
    inner = _sha512_finish(ipad_h, _SHA512_BLOCK_SIZE, bytes(msg))
    return _sha512_finish(opad_h, _SHA512_BLOCK_SIZE, inner)


def hkdf_expand_sha512_from_midstates(ipad_h, opad_h, info, length: int) -> bytes:
    """RFC 5869 HKDF-Expand with the PRK's HMAC given only by its midstates."""
    if not 0 <= length <= 255 * _SHA512_DIGEST_SIZE:
        raise ValueError("HKDF-SHA512 output length must be 0..16320, got %r" % (length,))
    info = bytes(info)
    okm, block, counter = b"", b"", 1
    while len(okm) < length:
        block = hmac_sha512_from_midstates(ipad_h, opad_h, block + info + bytes((counter,)))
        okm += block
        counter += 1
    return okm[:length]


def _sha512_u64s(blob: bytes, offset: int, count: int, byteorder: str) -> Tuple[int, ...]:
    prefix = {"little": "<", "big": ">"}.get(byteorder)
    if prefix is None:
        raise ValueError("byteorder must be 'little' or 'big', got %r" % (byteorder,))
    return struct.unpack_from("%s%dQ" % (prefix, count), blob, offset)


def _sha512_pads_valid(blob: bytes, start: int, state_size: int, byteorder: str) -> bool:
    """Both exported pads present and each reporting exactly one absorbed block."""
    if len(blob) < start + state_size + 80:
        return False
    for pad in (start, start + state_size):
        if _sha512_u64s(blob, pad + 64, 2, byteorder) != (_SHA512_BLOCK_SIZE, 0):
            return False
    return True


def _sha512_parse_pads(blob: bytes, start: int, byteorder: str, state_size: Optional[int]):
    candidates = _SHA512_STATE_SIZES if state_size is None else (state_size,)
    for size in candidates:
        if _sha512_pads_valid(blob, start, size, byteorder):
            ipad_h = _sha512_u64s(blob, start, 8, byteorder)
            return ipad_h, _sha512_u64s(blob, start + size, 8, byteorder)
    raise ValueError(
        "no exported ipad/opad sha512_state with count == (128, 0) at offset %d "
        "(state sizes tried: %s)" % (start, ", ".join(str(size) for size in candidates))
    )


def parse_sha512_state(
    blob, layout: str, byteorder: str = "little", *, state_size: Optional[int] = None,
    pointer_size: int = 8,
) -> Tuple[Sha512State, Sha512State]:
    """``(ipad_h, opad_h)`` from kernel memory holding a prepared HMAC-SHA512 key.

    ``layout`` is one of ``"hmac_pads"``, ``"hmac_ctx"`` (skips the ``pointer_size``-byte
    ``hash`` pointer) or ``"hmac_sha512_key"`` -- see the module docstring for which kernel
    uses which.  For the two crypto/hmac.c layouts ``state_size`` (208 or 209) is detected
    from the exported ``count`` fields when not given, and a blob whose pads do not report
    exactly one absorbed 128-byte block is rejected with ``ValueError``.
    """
    blob = bytes(blob)
    if layout == SHA512_LAYOUT_HMAC_SHA512_KEY:
        if len(blob) < 2 * _SHA512_DIGEST_SIZE:
            raise ValueError("struct hmac_sha512_key needs 128 bytes, got %d" % len(blob))
        return _sha512_u64s(blob, 0, 8, byteorder), _sha512_u64s(blob, 64, 8, byteorder)
    if layout == SHA512_LAYOUT_HMAC_CTX:
        return _sha512_parse_pads(blob, pointer_size, byteorder, state_size)
    if layout == SHA512_LAYOUT_HMAC_PADS:
        return _sha512_parse_pads(blob, 0, byteorder, state_size)
    raise ValueError(
        "unknown layout %r (expected %r, %r or %r)"
        % (layout, SHA512_LAYOUT_HMAC_PADS, SHA512_LAYOUT_HMAC_CTX, SHA512_LAYOUT_HMAC_SHA512_KEY)
    )


# --------------------------------------------------------------------------- plain HKDF (stdlib hmac)


def hkdf_extract(salt, ikm, hash_name: str = "sha512") -> bytes:
    """RFC 5869 HKDF-Extract; an empty/None salt means HashLen zero bytes."""
    digest_size = hashlib.new(hash_name).digest_size
    salt = bytes(salt) if salt else bytes(digest_size)
    return hmac.new(salt, bytes(ikm), hash_name).digest()


def hkdf_expand(prk, info, length: int, hash_name: str = "sha512") -> bytes:
    """RFC 5869 HKDF-Expand."""
    digest_size = hashlib.new(hash_name).digest_size
    if not 0 <= length <= 255 * digest_size:
        raise ValueError("HKDF output length must be 0..%d, got %r" % (255 * digest_size, length))
    prk, info = bytes(prk), bytes(info)
    okm, block, counter = b"", b"", 1
    while len(okm) < length:
        block = hmac.new(prk, block + info + bytes((counter,)), hash_name).digest()
        okm += block
        counter += 1
    return okm[:length]


# --------------------------------------------------------------------------- fscrypt v2


def fscrypt_hkdf_info(context: int, info=b"") -> bytes:
    """The HKDF info fscrypt feeds to HKDF-Expand: ``"fscrypt\\0" || context || info``.

    fs/crypto/hkdf.c ``fscrypt_hkdf_expand()`` (v5.4-v6.17 builds a 9-byte ``prefix`` of
    ``"fscrypt\\0"`` plus the context byte; v6.18+ updates the HMAC with the same bytes).
    """
    if not 0 <= context <= 255:
        raise ValueError("fscrypt HKDF context is one byte, got %r" % (context,))
    return _SHA512_FSCRYPT_PREFIX + bytes((context,)) + bytes(info)


def fscrypt_v2_prk(master_key) -> bytes:
    """fscrypt's HKDF-Extract: HMAC-SHA512 keyed with a zero 64-byte salt over the key.

    fs/crypto/hkdf.c ``fscrypt_init_hkdf()``: ``static const u8 default_salt[HKDF_HASHLEN]``
    (64 zero bytes) is the HMAC key and the master key the message, in every version.
    """
    return hkdf_extract(bytes(_SHA512_DIGEST_SIZE), master_key, "sha512")


def fscrypt_v2_hkdf_midstates(master_key) -> Tuple[Sha512State, Sha512State]:
    """The ``(ipad_h, opad_h)`` the kernel keeps for a raw v2 master key."""
    return midstates_from_key(fscrypt_v2_prk(master_key))


def fscrypt_v2_identifier(master_key) -> bytes:
    """The 16-byte v2 key identifier (fs/crypto/keyring.c ``add_master_key()``).

    ``HKDF-SHA512(salt=0^64, ikm=master_key, info="fscrypt\\0\\x01", L=16)`` for raw keys.
    """
    info = fscrypt_hkdf_info(HKDF_CONTEXT_KEY_IDENTIFIER, b"")
    return hkdf_expand(fscrypt_v2_prk(master_key), info, FSCRYPT_KEY_IDENTIFIER_SIZE, "sha512")


def fscrypt_v2_identifier_from_midstates(ipad_h, opad_h) -> bytes:
    """The v2 key identifier recomputed from midstates found in memory (the proof)."""
    info = fscrypt_hkdf_info(HKDF_CONTEXT_KEY_IDENTIFIER, b"")
    return hkdf_expand_sha512_from_midstates(ipad_h, opad_h, info, FSCRYPT_KEY_IDENTIFIER_SIZE)
