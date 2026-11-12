"""AES primitives for proving dm-crypt, fscrypt and gocryptfs keys recovered from memory.

ECB, CBC, XTS (dm-crypt), GCM (any nonce length) and SIV (RFC 5297, as gocryptfs uses it).

Self-contained on purpose: at module level this file imports only the Python standard
library (no MemDiver, no Volatility 3, no sibling module, no relative import) and it never
reads ``__file__``, so it can be pasted verbatim into a generated single-file plugin.
``cryptography`` is an optional accelerator imported lazily on first use; every operation
has a pure-Python path that returns byte-identical results.  ``MEMDIVER_PUREPY_CRYPTO=1``
in the environment forces the pure path (read on every call); ``backend()`` says which
path is active.  Key schedules are always computed in pure Python (no library exposes them).

Kernel layouts reproduced here
------------------------------
``struct crypto_aes_ctx`` (include/crypto/aes.h, unchanged from v5.4 to v7.4-rc1)::

    u32 key_enc[60];   /* AES_MAX_KEYLENGTH_U32: FIPS-197 encryption schedule      */
    u32 key_dec[60];   /* Equivalent Inverse Cipher schedule (see kernel_key_dec) */
    u32 key_length;    /* 16, 24 or 32                                            */

Each u32 is ``get_unaligned_le32()`` of four key-schedule bytes, so on little-endian CPUs
(x86-64, arm64) the bytes of ``key_enc`` in memory are exactly ``expand_key(key)``.  Words
past the used schedule (176/208 of 240 bytes for AES-128/192) are zero after the first
``setkey`` because transforms are allocated with ``kzalloc_node()`` (crypto/api.c
``crypto_create_tfm_node()``); a re-key with a shorter key would leave stale words there.
Only this generic ``crypto_aes_ctx`` layout (filled by lib/crypto/aes.c, and identically
by x86 AES-NI in v6.12) is guaranteed.  Newer kernels add ``struct aes_enckey``/``struct
aes_key`` (``u32 len; u32 nrounds; u32 padding[2]; k; inv_k``); only the generic code puts
the same round-key words there -- arch implementations may store other forms (raw key,
OpenSSL-style schedules, ...) and may leave ``inv_k`` uninitialised, so do not rely on a
match in those structs.
"""

import hashlib
import hmac
import os
import struct
from functools import lru_cache
from typing import List, Optional, Sequence, Tuple

_AES_PUREPY_ENV = "MEMDIVER_PUREPY_CRYPTO"
_AES_BLOCK_SIZE = 16
_AES_KEY_SIZES = (16, 24, 32)
_AES_XTS_KEY_SIZES = (32, 64)
_AES_MAX_KEYLENGTH = 240  # include/crypto/aes.h: AES_MAX_KEYLENGTH (15 * 16)
_AES_MASK32 = 0xFFFFFFFF
_AES_MASK128 = (1 << 128) - 1
_AES_GHASH_R = 0xE1 << 120  # NIST SP 800-38D section 6.3, the GHASH reduction constant
_AES_GHASH_WIDE_TABLES_FROM = 4096  # GHASH input bytes from which 8-bit tables pay off
_AES_XTS_ALPHA_REDUCTION = 0x87  # IEEE 1619-2007 section 5.2, multiplication by alpha
_AES_CMAC_RB = 0x87  # RFC 4493 section 2.3 / RFC 5297 section 2.3: the dbl() reduction R_128
_AES_U32X4 = struct.Struct(">4I")

# FIPS-197 Figure 7 (generated from the GF(2^8) inverse + affine map, checked by the tests).
_AES_SBOX = bytes.fromhex(
    "637c777bf26b6fc53001672bfed7ab76ca82c97dfa5947f0add4a2af9ca472c0"
    "b7fd9326363ff7cc34a5e5f171d8311504c723c31896059a071280e2eb27b275"
    "09832c1a1b6e5aa0523bd6b329e32f8453d100ed20fcb15b6acbbe394a4c58cf"
    "d0efaafb434d338545f9027f503c9fa851a3408f929d38f5bcb6da2110fff3d2"
    "cd0c13ec5f974417c4a77e3d645d197360814fdc222a908846eeb814de5e0bdb"
    "e0323a0a4906245cc2d3ac629195e479e7c8376d8dd54ea96c56f4ea657aae08"
    "ba78252e1ca6b4c6e8dd741f4bbd8b8a703eb5664803f60e613557b986c11d9e"
    "e1f8981169d98e949b1e87e9ce5528df8ca1890dbfe6426841992d0fb054bb16"
)
SBOX = _AES_SBOX  # public: linux.dmcrypt's key-schedule prefilter reads it


# --------------------------------------------------------------------------- backend


def _aes_purepy_forced() -> bool:
    value = os.environ.get(_AES_PUREPY_ENV, "")
    return value.strip().lower() in ("1", "true", "yes", "on")


@lru_cache(maxsize=1)
def _aes_probe_cryptography():
    """Import ``cryptography`` once; ``None`` when it is missing or broken."""
    try:
        from cryptography.exceptions import InvalidTag
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    except Exception:  # ImportError, or a partial install without its Rust backend
        return None
    return Cipher, algorithms, modes, InvalidTag


def _aes_cryptography(pure: bool = False):
    """``(Cipher, algorithms, modes, InvalidTag)`` for the fast path, else ``None``.

    ``pure=True`` (the ``pure`` keyword of ``gcm_*`` / ``siv_*``) refuses the fast path for
    this one call, so a caller that reports "pure-python" really runs pure Python.
    """
    if pure or _aes_purepy_forced():
        return None
    return _aes_probe_cryptography()


def backend() -> str:
    """``"cryptography"`` when the accelerated path is active, else ``"pure-python"``."""
    return "cryptography" if _aes_cryptography() is not None else "pure-python"


# --------------------------------------------------------------------------- tables


def _aes_xtime(value: int) -> int:
    """Multiply a byte by x in GF(2^8) modulo x^8 + x^4 + x^3 + x + 1 (FIPS-197 4.2.1)."""
    return (value << 1) ^ 0x11B if value & 0x80 else value << 1


def _aes_gmul(a: int, b: int) -> int:
    product = 0
    while b:
        if b & 1:
            product ^= a
        a = _aes_xtime(a)
        b >>= 1
    return product


def _aes_ror8(word: int) -> int:
    return ((word >> 8) | (word << 24)) & _AES_MASK32


def _aes_round_tables(box: bytes, coefficients: Sequence[int]) -> Tuple[Tuple[int, ...], ...]:
    """The four rotated T-tables combining ``box`` with one MixColumns matrix column."""
    first = []
    for value in box:
        word = 0
        for coefficient in coefficients:
            word = (word << 8) | _aes_gmul(value, coefficient)
        first.append(word)
    tables = [first]
    for _ in range(3):
        tables.append([_aes_ror8(word) for word in tables[-1]])
    return tuple(tuple(table) for table in tables)


@lru_cache(maxsize=1)
def _aes_tables():
    """``(te, td, inverse_sbox)``, built on first use so importing this file stays cheap."""
    inverse = bytearray(256)
    for index, value in enumerate(_AES_SBOX):
        inverse[value] = index
    inverse_sbox = bytes(inverse)
    te = _aes_round_tables(_AES_SBOX, (2, 1, 1, 3))
    td = _aes_round_tables(inverse_sbox, (14, 9, 13, 11))
    return te, td, inverse_sbox


# --------------------------------------------------------------------------- schedules


def _aes_checked_key(key) -> bytes:
    key = bytes(key)
    if len(key) not in _AES_KEY_SIZES:
        raise ValueError("AES key must be 16, 24 or 32 bytes, got %d" % len(key))
    return key


def _aes_sub_word(word: int) -> int:
    sbox = _AES_SBOX
    return (
        (sbox[word >> 24] << 24)
        | (sbox[(word >> 16) & 255] << 16)
        | (sbox[(word >> 8) & 255] << 8)
        | sbox[word & 255]
    )


def _aes_expand_words(key: bytes) -> List[int]:
    """FIPS-197 section 5.2 KeyExpansion as big-endian column words."""
    nk = len(key) // 4
    words = list(struct.unpack(">%dI" % nk, key))
    rcon = 1
    for i in range(nk, 4 * (nk + 7)):
        temp = words[i - 1]
        if i % nk == 0:
            temp = _aes_sub_word(((temp << 8) | (temp >> 24)) & _AES_MASK32) ^ (rcon << 24)
            rcon = _aes_xtime(rcon)
        elif nk > 6 and i % nk == 4:
            temp = _aes_sub_word(temp)
        words.append(words[i - nk] ^ temp)
    return words


def _aes_inv_mix_word(word: int) -> int:
    """InvMixColumns of one column: Td[S[b]] cancels the inverse S-box folded into Td."""
    td, sbox = _aes_tables()[1], _AES_SBOX
    return (
        td[0][sbox[word >> 24]]
        ^ td[1][sbox[(word >> 16) & 255]]
        ^ td[2][sbox[(word >> 8) & 255]]
        ^ td[3][sbox[word & 255]]
    )


def _aes_inverse_words(enc: Sequence[int], rounds: int) -> List[int]:
    """FIPS-197 section 5.3.5 Equivalent Inverse Cipher schedule.

    Round keys in reverse order, InvMixColumns applied to all but the first and the last --
    the same words the kernel writes to ``key_dec`` (see ``kernel_key_dec``).
    """
    dec = []
    for rnd in range(rounds, -1, -1):
        round_key = enc[4 * rnd: 4 * rnd + 4]
        if 0 < rnd < rounds:
            round_key = [_aes_inv_mix_word(word) for word in round_key]
        dec.extend(round_key)
    return dec


@lru_cache(maxsize=64)
def _aes_schedules(key: bytes) -> Tuple[Tuple[int, ...], Tuple[int, ...], int]:
    """``(encryption words, equivalent-inverse words, rounds)`` for a checked key."""
    enc = _aes_expand_words(key)
    rounds = len(key) // 4 + 6
    return tuple(enc), tuple(_aes_inverse_words(enc, rounds)), rounds


def _aes_words_to_bytes(words: Sequence[int], byteorder: str) -> bytes:
    if byteorder == "little":
        return struct.pack(">%dI" % len(words), *words)
    if byteorder == "big":  # the kernel's u32 is the LE value of the column; BE stores it swapped
        return struct.pack("<%dI" % len(words), *words)
    raise ValueError("byteorder must be 'little' or 'big', got %r" % (byteorder,))


def expand_key(key) -> bytes:
    """FIPS-197 encryption key schedule: 176/208/240 bytes for 16/24/32-byte keys.

    Round key 0 is the key itself, so a raw AES key found in memory immediately followed by
    the rest of this schedule is a schedule match.  The result is also the in-memory bytes
    of the kernel's ``crypto_aes_ctx.key_enc`` on little-endian CPUs.
    """
    enc, _, _ = _aes_schedules(_aes_checked_key(key))
    return _aes_words_to_bytes(enc, "little")


def kernel_key_dec(key, byteorder: str = "little") -> bytes:
    """The used part (176/208/240 bytes) of the kernel's ``crypto_aes_ctx.key_dec``.

    lib/crypto/aes.c ``aes_expandkey()`` (v5.4-v6.18; the same body is
    ``aes_expandkey_generic()`` in v7.4-rc1) fills ``key_dec`` for the Equivalent Inverse
    Cipher: ``key_dec[0..3] = key_enc[key_len + 24..27]`` (the last round key), then for
    ``j = key_len + 20`` down to 4 ``key_dec[i..i+3] = inv_mix_columns(key_enc[j..j+3])``,
    and finally ``key_enc[0..3]`` (round key 0: the key's first 16 bytes) last.  The x86
    AES-NI ``aesni_set_key()`` (arch/x86/crypto/aesni-intel_asm.S, v6.12) writes the
    identical layout with AESIMC.  ``byteorder="big"`` gives the bytes on big-endian CPUs.
    """
    key = _aes_checked_key(key)
    _, dec, _ = _aes_schedules(key)
    return _aes_words_to_bytes(dec, byteorder)


def kernel_crypto_aes_ctx(key, byteorder: str = "little") -> bytes:
    """The 484-byte ``struct crypto_aes_ctx`` the kernel builds for ``key``.

    ``key_enc[60] || key_dec[60] || u32 key_length``, unused words zero (see module doc).
    """
    key = _aes_checked_key(key)
    enc, dec, _ = _aes_schedules(key)
    length_format = "<I" if byteorder == "little" else ">I"
    return (
        _aes_words_to_bytes(enc, byteorder).ljust(_AES_MAX_KEYLENGTH, b"\0")
        + _aes_words_to_bytes(dec, byteorder).ljust(_AES_MAX_KEYLENGTH, b"\0")
        + struct.pack(length_format, len(key))
    )


# --------------------------------------------------------------------------- pure block cipher


def _aes_last_round(box: bytes, rk: Sequence[int], k: int, state, shifts) -> bytes:
    """SubBytes/ShiftRows (or their inverses) plus the final AddRoundKey."""
    a, b, c = shifts
    out = []
    for col in range(4):
        word = (
            (box[state[col] >> 24] << 24)
            | (box[(state[(col + a) % 4] >> 16) & 255] << 16)
            | (box[(state[(col + b) % 4] >> 8) & 255] << 8)
            | box[state[(col + c) % 4] & 255]
        )
        out.append(word ^ rk[k + col])
    return _AES_U32X4.pack(*out)


class _AesPureCipher:
    """One expanded key; ``encrypt``/``decrypt`` transform a single 16-byte block."""

    __slots__ = ("_enc", "_dec", "_rounds", "_te", "_td", "_inv_sbox")

    def __init__(self, key: bytes) -> None:
        self._enc, self._dec, self._rounds = _aes_schedules(key)
        self._te, self._td, self._inv_sbox = _aes_tables()

    def encrypt(self, block: bytes) -> bytes:
        rk = self._enc
        te0, te1, te2, te3 = self._te
        s0, s1, s2, s3 = _AES_U32X4.unpack(block)
        s0, s1, s2, s3 = s0 ^ rk[0], s1 ^ rk[1], s2 ^ rk[2], s3 ^ rk[3]
        for k in range(4, 4 * self._rounds, 4):
            s0, s1, s2, s3 = (
                te0[s0 >> 24] ^ te1[(s1 >> 16) & 255] ^ te2[(s2 >> 8) & 255] ^ te3[s3 & 255] ^ rk[k],
                te0[s1 >> 24] ^ te1[(s2 >> 16) & 255] ^ te2[(s3 >> 8) & 255] ^ te3[s0 & 255] ^ rk[k + 1],
                te0[s2 >> 24] ^ te1[(s3 >> 16) & 255] ^ te2[(s0 >> 8) & 255] ^ te3[s1 & 255] ^ rk[k + 2],
                te0[s3 >> 24] ^ te1[(s0 >> 16) & 255] ^ te2[(s1 >> 8) & 255] ^ te3[s2 & 255] ^ rk[k + 3],
            )
        return _aes_last_round(_AES_SBOX, rk, 4 * self._rounds, (s0, s1, s2, s3), (1, 2, 3))

    def decrypt(self, block: bytes) -> bytes:
        dk = self._dec
        td0, td1, td2, td3 = self._td
        s0, s1, s2, s3 = _AES_U32X4.unpack(block)
        s0, s1, s2, s3 = s0 ^ dk[0], s1 ^ dk[1], s2 ^ dk[2], s3 ^ dk[3]
        for k in range(4, 4 * self._rounds, 4):
            s0, s1, s2, s3 = (
                td0[s0 >> 24] ^ td1[(s3 >> 16) & 255] ^ td2[(s2 >> 8) & 255] ^ td3[s1 & 255] ^ dk[k],
                td0[s1 >> 24] ^ td1[(s0 >> 16) & 255] ^ td2[(s3 >> 8) & 255] ^ td3[s2 & 255] ^ dk[k + 1],
                td0[s2 >> 24] ^ td1[(s1 >> 16) & 255] ^ td2[(s0 >> 8) & 255] ^ td3[s3 & 255] ^ dk[k + 2],
                td0[s3 >> 24] ^ td1[(s2 >> 16) & 255] ^ td2[(s1 >> 8) & 255] ^ td3[s0 & 255] ^ dk[k + 3],
            )
        return _aes_last_round(self._inv_sbox, dk, 4 * self._rounds, (s0, s1, s2, s3), (3, 2, 1))


def _aes_xor(data: bytes, pad: bytes) -> bytes:
    """``data XOR pad[:len(data)]``."""
    size = len(data)
    mixed = int.from_bytes(data, "big") ^ int.from_bytes(pad[:size], "big")
    return mixed.to_bytes(size, "big")


def _aes_whole_blocks(data, what: str = "data") -> bytes:
    data = bytes(data)
    if len(data) % _AES_BLOCK_SIZE:
        raise ValueError("%s must be a multiple of 16 bytes, got %d" % (what, len(data)))
    return data


def _aes_fast(ops, key: bytes, mode, data: bytes, encrypt: bool) -> bytes:
    cipher_class, algorithms, _, _ = ops
    cipher = cipher_class(algorithms.AES(key), mode)
    context = cipher.encryptor() if encrypt else cipher.decryptor()
    return context.update(data) + context.finalize()


# --------------------------------------------------------------------------- ECB / CBC


def _aes_ecb(key, data, encrypt: bool, pure: bool = False) -> bytes:
    key = _aes_checked_key(key)
    data = _aes_whole_blocks(data)
    ops = _aes_cryptography(pure)
    if ops is not None:
        return _aes_fast(ops, key, ops[2].ECB(), data, encrypt)
    cipher = _AesPureCipher(key)
    transform = cipher.encrypt if encrypt else cipher.decrypt
    return b"".join(transform(data[i: i + 16]) for i in range(0, len(data), 16))


def ecb_encrypt(key, data) -> bytes:
    """AES-ECB encryption, no padding (``data`` is whole 16-byte blocks)."""
    return _aes_ecb(key, data, True)


def ecb_decrypt(key, data) -> bytes:
    """AES-ECB decryption, no padding (``data`` is whole 16-byte blocks)."""
    return _aes_ecb(key, data, False)


def _aes_single_block(block) -> bytes:
    block = bytes(block)
    if len(block) != _AES_BLOCK_SIZE:
        raise ValueError("AES block must be 16 bytes, got %d" % len(block))
    return block


def encrypt_block(key, block) -> bytes:
    """Encrypt one 16-byte block."""
    return _aes_ecb(key, _aes_single_block(block), True)


def decrypt_block(key, block) -> bytes:
    """Decrypt one 16-byte block."""
    return _aes_ecb(key, _aes_single_block(block), False)


def _aes_cbc_pure(key: bytes, iv: bytes, data: bytes, encrypt: bool) -> bytes:
    cipher = _AesPureCipher(key)
    previous, out = iv, []
    for offset in range(0, len(data), 16):
        block = data[offset: offset + 16]
        if encrypt:
            previous = cipher.encrypt(_aes_xor(block, previous))
            out.append(previous)
        else:
            out.append(_aes_xor(cipher.decrypt(block), previous))
            previous = block
    return b"".join(out)


def _aes_cbc(key, iv, data, encrypt: bool, pure: bool = False) -> bytes:
    key = _aes_checked_key(key)
    iv = _aes_single_block(iv)
    data = _aes_whole_blocks(data)
    ops = _aes_cryptography(pure)
    if ops is not None:
        return _aes_fast(ops, key, ops[2].CBC(iv), data, encrypt)
    return _aes_cbc_pure(key, iv, data, encrypt)


def cbc_encrypt(key, iv, data) -> bytes:
    """AES-CBC encryption, no padding (``data`` is whole 16-byte blocks)."""
    return _aes_cbc(key, iv, data, True)


def cbc_decrypt(key, iv, data) -> bytes:
    """AES-CBC decryption, no padding (``data`` is whole 16-byte blocks)."""
    return _aes_cbc(key, iv, data, False)


# --------------------------------------------------------------------------- XTS (dm-crypt plain64)


def _aes_xts_unit_pure(data_cipher, tweak_cipher, tweak: bytes, unit: bytes, encrypt: bool) -> bytes:
    """IEEE 1619-2007 XTS over one data unit of whole blocks (no ciphertext stealing)."""
    t = int.from_bytes(tweak_cipher.encrypt(tweak), "little")
    transform = data_cipher.encrypt if encrypt else data_cipher.decrypt
    out = []
    for offset in range(0, len(unit), 16):
        x = int.from_bytes(unit[offset: offset + 16], "little") ^ t
        y = int.from_bytes(transform(x.to_bytes(16, "little")), "little") ^ t
        out.append(y.to_bytes(16, "little"))
        t = ((t << 1) & _AES_MASK128) ^ _AES_XTS_ALPHA_REDUCTION if t >> 127 else t << 1
    return b"".join(out)


def _aes_xts_checked(key, sector: int, data, sector_size: int) -> Tuple[bytes, bytes]:
    key = bytes(key)
    if len(key) not in _AES_XTS_KEY_SIZES:
        raise ValueError("AES-XTS key must be 32 or 64 bytes (key1||key2), got %d" % len(key))
    if sector_size <= 0 or sector_size % _AES_BLOCK_SIZE:
        raise ValueError("sector_size must be a positive multiple of 16, got %r" % (sector_size,))
    data = bytes(data)
    if len(data) % sector_size:
        raise ValueError("data must be whole %d-byte sectors, got %d bytes" % (sector_size, len(data)))
    last_sector = sector + max(len(data) // sector_size - 1, 0)
    if sector < 0 or last_sector > _AES_MASK128:
        raise ValueError("sector numbers must fit in an unsigned 128-bit tweak")
    return key, data


def _aes_xts(key, sector: int, data, sector_size: int, encrypt: bool) -> bytes:
    key, data = _aes_xts_checked(key, sector, data, sector_size)
    half = len(key) // 2
    key1, key2 = key[:half], key[half:]
    ops = _aes_cryptography()
    # OpenSSL refuses key1 == key2 (a weak-key policy, not part of IEEE 1619): go pure then.
    use_fast = ops is not None and key1 != key2
    if not use_fast:
        data_cipher, tweak_cipher = _AesPureCipher(key1), _AesPureCipher(key2)
    out = []
    for index, offset in enumerate(range(0, len(data), sector_size)):
        tweak = (sector + index).to_bytes(16, "little")
        unit = data[offset: offset + sector_size]
        if use_fast:
            out.append(_aes_fast(ops, key, ops[2].XTS(tweak), unit, encrypt))
        else:
            out.append(_aes_xts_unit_pure(data_cipher, tweak_cipher, tweak, unit, encrypt))
    return b"".join(out)


def xts_decrypt(key, sector: int, data, sector_size: int = 512) -> bytes:
    """AES-XTS decryption the way dm-crypt ``aes-xts-plain64`` lays out a device.

    ``key`` is key1||key2 (32 bytes for AES-128-XTS, 64 for AES-256-XTS).  ``data`` is a
    whole number of ``sector_size`` data units; unit ``i`` uses the tweak
    ``LE128(sector + i)``.  Data units are whole AES blocks, so no ciphertext stealing is
    needed.  dm-crypt counts IV sectors in 512-byte units unless the table sets
    ``iv_large_sectors``: with 4096-byte sectors without it, decrypt one sector per call
    with ``sector = byte_offset // 512``.
    """
    return _aes_xts(key, sector, data, sector_size, False)


def xts_encrypt(key, sector: int, data, sector_size: int = 512) -> bytes:
    """AES-XTS encryption; the inverse of ``xts_decrypt`` (same tweak rule)."""
    return _aes_xts(key, sector, data, sector_size, True)


def essiv_iv(key, sector: int, hash_name: str = "sha256") -> bytes:
    """dm-crypt ESSIV IV: ``AES_{H(key)}(LE64(sector) || 0^64)``.

    ``key`` is the whole volume key of e.g. ``aes-cbc-essiv:sha256``; the salt ``H(key)``
    is the ESSIV cipher key, so ``hash_name``'s digest must be 16, 24 or 32 bytes
    (crypto/essiv.c ``essiv_skcipher_setkey()``; dm-crypt ``crypt_iv_essiv_gen()`` puts the
    little-endian 64-bit sector number in an otherwise zero IV).
    """
    if not 0 <= sector < 1 << 64:
        raise ValueError("ESSIV sector must fit in an unsigned 64-bit integer")
    salt = hashlib.new(hash_name, bytes(key)).digest()
    if len(salt) not in _AES_KEY_SIZES:
        raise ValueError("%s digest (%d bytes) is not an AES key size" % (hash_name, len(salt)))
    return encrypt_block(salt, struct.pack("<Q", sector) + bytes(8))


# --------------------------------------------------------------------------- GCM


def _aes_ghash_tables(h: int, bits: int = 8) -> List[List[int]]:
    """Per-chunk multiplication tables for ``X * H`` in GF(2^128) (SP 800-38D 6.3).

    ``powers[i]`` is ``H`` times the field element with only bit ``i`` set (bit 0 being the
    most significant bit of the block); table ``j`` maps chunk ``j`` (``bits`` wide, 4 or 8,
    most significant first) of ``X`` to its part of the product.  8-bit tables multiply
    about twice as fast but cost ~6x more to build, so short messages use 4-bit ones.
    """
    powers = []
    for _ in range(128):
        powers.append(h)
        h = (h >> 1) ^ _AES_GHASH_R if h & 1 else h >> 1
    size, tables = 1 << bits, []
    for j in range(128 // bits):
        table = [0] * size
        for value in range(1, size):
            lowest = value & -value
            table[value] = table[value ^ lowest] ^ powers[bits * j + bits - lowest.bit_length()]
        tables.append(table)
    return tables


def _aes_gf_mul(tables: List[List[int]], x: int) -> int:
    bits = 128 // len(tables)
    mask, shift, product = (1 << bits) - 1, 128 - bits, 0
    for table in tables:
        product ^= table[(x >> shift) & mask]
        shift -= bits
    return product


def _aes_ghash_absorb(tables: List[List[int]], y: int, data: bytes) -> int:
    for offset in range(0, len(data), 16):
        block = data[offset: offset + 16].ljust(16, b"\0")
        y = _aes_gf_mul(tables, y ^ int.from_bytes(block, "big"))
    return y


def _aes_inc32(counter: int) -> int:
    return (counter & ~_AES_MASK32) | ((counter + 1) & _AES_MASK32)


def _aes_gcm_j0(tables: List[List[int]], nonce: bytes) -> int:
    """Pre-counter block: ``IV || 0^31 || 1`` for 96-bit IVs, else GHASH of the padded IV."""
    if len(nonce) == 12:
        return int.from_bytes(nonce + b"\0\0\0\1", "big")
    y = _aes_ghash_absorb(tables, 0, nonce)
    return _aes_gf_mul(tables, y ^ (len(nonce) * 8))


def _aes_gctr(cipher: _AesPureCipher, counter: int, data: bytes) -> bytes:
    out = []
    for offset in range(0, len(data), 16):
        keystream = cipher.encrypt(counter.to_bytes(16, "big"))
        out.append(_aes_xor(data[offset: offset + 16], keystream))
        counter = _aes_inc32(counter)
    return b"".join(out)


def _aes_gcm_setup(key: bytes, nonce: bytes, ghash_bytes: int):
    """``(cipher, GHASH tables, J0)`` for one key and nonce (SP 800-38D algorithm 4, steps 1-2).

    ``ghash_bytes`` (AAD + ciphertext) picks the table width: below
    ``_AES_GHASH_WIDE_TABLES_FROM`` the cheaper-to-build 4-bit tables win (measured
    break-even ~4 KiB), which is what a key sweep over one short sample needs.
    """
    cipher = _AesPureCipher(key)
    bits = 8 if ghash_bytes + len(nonce) >= _AES_GHASH_WIDE_TABLES_FROM else 4
    tables = _aes_ghash_tables(int.from_bytes(cipher.encrypt(bytes(16)), "big"), bits)
    return cipher, tables, _aes_gcm_j0(tables, nonce)


def _aes_gcm_tag(cipher: _AesPureCipher, tables, j0: int, aad: bytes, ciphertext: bytes) -> bytes:
    """The full 16-byte tag: ``E(K, J0) XOR GHASH(aad, ciphertext, lengths)``."""
    y = _aes_ghash_absorb(tables, _aes_ghash_absorb(tables, 0, aad), ciphertext)
    s = _aes_gf_mul(tables, y ^ ((len(aad) * 8) << 64) ^ (len(ciphertext) * 8))
    return _aes_xor(cipher.encrypt(j0.to_bytes(16, "big")), s.to_bytes(16, "big"))


def _aes_gcm_pure(key: bytes, nonce: bytes, data: bytes, aad: bytes, decrypt: bool) -> Tuple[bytes, bytes]:
    """``(output, full 16-byte tag)`` per SP 800-38D algorithms 4 and 5."""
    cipher, tables, j0 = _aes_gcm_setup(key, nonce, len(aad) + len(data))
    output = _aes_gctr(cipher, _aes_inc32(j0), data)
    ciphertext = data if decrypt else output
    return output, _aes_gcm_tag(cipher, tables, j0, aad, ciphertext)


def _aes_gcm_open_pure(key: bytes, nonce: bytes, ct: bytes, tag: bytes, aad: bytes) -> Optional[bytes]:
    """Authenticate FIRST, decrypt only on a match: a wrong key never pays for GCTR."""
    cipher, tables, j0 = _aes_gcm_setup(key, nonce, len(aad) + len(ct))
    expected = _aes_gcm_tag(cipher, tables, j0, aad, ct)
    if not hmac.compare_digest(expected[: len(tag)], tag):
        return None
    return _aes_gctr(cipher, _aes_inc32(j0), ct)


def _aes_gcm_checked(nonce, tag_length: int) -> bytes:
    nonce = bytes(nonce)
    if not nonce:
        raise ValueError("GCM nonce must not be empty")
    if not 4 <= tag_length <= 16:
        raise ValueError("GCM tag must be 4..16 bytes, got %d" % tag_length)
    return nonce


def _aes_gcm_fast_ok(ops, nonce: bytes) -> bool:
    return ops is not None and 8 <= len(nonce) <= 128  # cryptography's GCM IV range


def gcm_encrypt(key, nonce, plaintext, aad=b"", tag_length: int = 16,
                pure: bool = False) -> Tuple[bytes, bytes]:
    """AES-GCM encryption returning ``(ciphertext, tag)``; any non-empty nonce length.

    ``pure=True`` never touches ``cryptography`` (as if ``MEMDIVER_PUREPY_CRYPTO=1``).
    """
    key = _aes_checked_key(key)
    nonce = _aes_gcm_checked(nonce, tag_length)
    plaintext, aad = bytes(plaintext), bytes(aad)
    ops = _aes_cryptography(pure)
    if _aes_gcm_fast_ok(ops, nonce):
        cipher_class, algorithms, modes, _ = ops
        encryptor = cipher_class(algorithms.AES(key), modes.GCM(nonce)).encryptor()
        encryptor.authenticate_additional_data(aad)
        ciphertext = encryptor.update(plaintext) + encryptor.finalize()
        return ciphertext, encryptor.tag[:tag_length]
    ciphertext, tag = _aes_gcm_pure(key, nonce, plaintext, aad, decrypt=False)
    return ciphertext, tag[:tag_length]


def gcm_decrypt(key, nonce, ct, tag, aad=b"", pure: bool = False) -> Optional[bytes]:
    """AES-GCM decryption; ``None`` when the tag does not verify.

    Supports 96-bit nonces and any other non-empty length through the GHASH-derived J0
    (gocryptfs uses 16-byte IVs).  ``tag`` may be truncated to 4..16 bytes.  The pure path
    checks the tag before decrypting (constant-time compare), so a wrong key costs no GCTR.
    ``pure=True`` never touches ``cryptography`` (as if ``MEMDIVER_PUREPY_CRYPTO=1``).
    """
    key = _aes_checked_key(key)
    tag = bytes(tag)
    nonce = _aes_gcm_checked(nonce, len(tag))
    ct, aad = bytes(ct), bytes(aad)
    ops = _aes_cryptography(pure)
    if _aes_gcm_fast_ok(ops, nonce):
        cipher_class, algorithms, modes, invalid_tag = ops
        mode = modes.GCM(nonce, tag, min_tag_length=len(tag))
        decryptor = cipher_class(algorithms.AES(key), mode).decryptor()
        decryptor.authenticate_additional_data(aad)
        try:
            return decryptor.update(ct) + decryptor.finalize()
        except invalid_tag:
            return None
    return _aes_gcm_open_pure(key, nonce, ct, tag, aad)


# --------------------------------------------------------------------------- SIV (RFC 5297)


def _aes_dbl(value: int) -> int:
    """RFC 5297 section 2.3 ``dbl``: multiply by x in GF(2^128) (RFC 4493's subkey shift)."""
    return ((value << 1) & _AES_MASK128) ^ (_AES_CMAC_RB if value >> 127 else 0)


def _aes_cmac_subkeys(key: bytes, pure: bool = False) -> Tuple[int, int]:
    """RFC 4493 section 2.3: ``K1 = dbl(L)``, ``K2 = dbl(K1)`` with ``L = AES(key, 0^128)``."""
    k1 = _aes_dbl(int.from_bytes(_aes_ecb(key, bytes(16), True, pure), "big"))
    return k1, _aes_dbl(k1)


def _aes_cmac(key: bytes, subkeys: Tuple[int, int], data: bytes, pure: bool = False) -> int:
    """RFC 4493 AES-CMAC of ``data`` as a 128-bit integer (CBC-MAC with the last block masked)."""
    complete = bool(data) and len(data) % 16 == 0
    split = len(data) - 16 if complete else len(data) - len(data) % 16
    last = data[split:]
    if not complete:
        last = last + b"\x80" + bytes(15 - len(last))
    masked = (int.from_bytes(last, "big") ^ subkeys[0 if complete else 1]).to_bytes(16, "big")
    return int.from_bytes(_aes_cbc(key, bytes(16), data[:split] + masked, True, pure)[-16:], "big")


def _aes_s2v(key: bytes, strings: Sequence[bytes], pure: bool = False) -> bytes:
    """RFC 5297 section 2.4 S2V over ``strings`` (the associated data, then the plaintext)."""
    subkeys = _aes_cmac_subkeys(key, pure)
    if not strings:
        return _aes_cmac(key, subkeys, bytes(15) + b"\x01", pure).to_bytes(16, "big")
    d = _aes_cmac(key, subkeys, bytes(16), pure)
    for item in strings[:-1]:
        d = _aes_dbl(d) ^ _aes_cmac(key, subkeys, item, pure)
    last = strings[-1]
    if len(last) >= 16:  # T = Sn xorend D
        tail = (int.from_bytes(last[-16:], "big") ^ d).to_bytes(16, "big")
        final = last[:-16] + tail
    else:  # T = dbl(D) xor pad(Sn)
        padded = int.from_bytes(last + b"\x80" + bytes(15 - len(last)), "big")
        final = (_aes_dbl(d) ^ padded).to_bytes(16, "big")
    return _aes_cmac(key, subkeys, final, pure).to_bytes(16, "big")


def _aes_siv_ctr(key: bytes, siv: bytes, data: bytes, pure: bool = False) -> bytes:
    """RFC 5297 section 2.5 CTR: counter ``Q = V`` with bits 63 and 31 cleared, +1 mod 2^128."""
    q = int.from_bytes(siv, "big") & ~((1 << 63) | (1 << 31))
    blocks = -(-len(data) // 16)
    counters = b"".join(((q + i) & _AES_MASK128).to_bytes(16, "big") for i in range(blocks))
    return _aes_xor(data, _aes_ecb(key, counters, True, pure)) if data else b""


def _aes_siv_key(key) -> Tuple[bytes, bytes]:
    """``(K1 for S2V, K2 for CTR)``: the left and right halves of a 32/48/64-byte SIV key."""
    key = bytes(key)
    if len(key) not in (32, 48, 64):
        raise ValueError("AES-SIV key must be 32, 48 or 64 bytes, got %d" % len(key))
    half = len(key) // 2
    return key[:half], key[half:]


def _aes_siv_strings(associated_data) -> List[bytes]:
    strings = [bytes(item) for item in associated_data]
    if len(strings) > 126:  # RFC 5297 section 7: at most 126 associated-data components
        raise ValueError("AES-SIV takes at most 126 associated-data components")
    return strings


def siv_encrypt(key, plaintext, associated_data: Sequence[bytes] = (), pure: bool = False) -> bytes:
    """RFC 5297 SIV-ENCRYPT: ``V || C`` (the 16-byte synthetic IV, then the ciphertext).

    ``associated_data`` is the list of components; for nonce-based use the nonce is the
    LAST component (gocryptfs passes ``[aad, nonce]``).  Pure Python on top of this file's
    ECB/CBC, so ``cryptography`` (when present and not forced off) speeds up the AES calls;
    ``pure=True`` never touches it.
    """
    k1, k2 = _aes_siv_key(key)
    plaintext = bytes(plaintext)
    siv = _aes_s2v(k1, _aes_siv_strings(associated_data) + [plaintext], pure)
    return siv + _aes_siv_ctr(k2, siv, plaintext, pure)


def siv_decrypt(key, sealed, associated_data: Sequence[bytes] = (),
                pure: bool = False) -> Optional[bytes]:
    """RFC 5297 SIV-DECRYPT of ``sealed = V || C``; ``None`` when ``V`` does not verify.

    SIV authenticates the PLAINTEXT, so unlike GCM it must decrypt before it can check;
    the comparison is constant-time.  ``pure=True`` never touches ``cryptography``.

    Caveat (inherent to SIV, not to this code): with an EMPTY plaintext ``K2`` (the CTR
    half of the key) is never used, so any key with the right ``K1`` opens it.  A caller
    proving a whole key must therefore never accept an empty-plaintext proof; the
    gocryptfs oracle refuses such a block 0 (``_block0_span``).
    """
    k1, k2 = _aes_siv_key(key)
    sealed = bytes(sealed)
    if len(sealed) < 16:
        raise ValueError("AES-SIV input must hold the 16-byte synthetic IV")
    strings = _aes_siv_strings(associated_data)
    siv, ciphertext = sealed[:16], sealed[16:]
    plaintext = _aes_siv_ctr(k2, siv, ciphertext, pure)
    return plaintext if hmac.compare_digest(_aes_s2v(k1, strings + [plaintext], pure), siv) else None


# --------------------------------------------------------------------------- dm-crypt data units
#
# drivers/md/dm-crypt.c (v5.4 .. v6.12) numbers IVs like this.  ``crypt_map()`` hands the
# conversion ``dm_target_offset(ti, bio->bi_iter.bi_sector)``, the bio's sector RELATIVE TO
# THE TARGET in 512-byte units (``ti->begin`` removed; the table's ``<offset>`` = ``cc->start``
# is where the ciphertext starts on the backing device and never enters the IV).
# ``crypt_convert_init()`` sets ``ctx->cc_sector = sector + cc->iv_offset``; every
# encryption unit of ``cc->sector_size`` bytes (table option ``sector_size:<bytes>``, a power
# of two in 512..4096, default 512) advances ``cc_sector`` by ``sector_size >> 9``, and
# ``crypt_convert_block_skcipher()`` sets ``dmreq->iv_sector = ctx->cc_sector`` and shifts it
# right by ``cc->sector_shift = __ffs(sector_size) - 9`` only when ``CRYPT_IV_LARGE_SECTORS``
# is set (table option ``iv_large_sectors``; cryptsetup sets it for LUKS2 / sector_size >
# 512).  Without it a 4096-byte unit at target sector 8 has IV sector 8, with it 1.

_AES_DM_SECTOR_SHIFT = 9
_AES_DM_MAX_SECTOR_SIZE = 4096
_AES_DM_MASK64 = (1 << 64) - 1
_AES_DM_MASK32 = _AES_MASK32


def dm_iv_sector(dm_sector: int, iv_offset: int = 0, sector_size: int = 512,
                 iv_large: bool = False) -> int:
    """The IV sector dm-crypt uses for the unit starting at target sector ``dm_sector``.

    ``dm_sector`` is in 512-byte units relative to the start of the dm target (aligned to
    ``sector_size // 512``, as dm-crypt rejects unaligned bios); ``iv_offset`` is the table's
    ``<iv_offset>``.  Returns ``(dm_sector + iv_offset) >> log2(sector_size / 512)`` when
    ``iv_large`` (``iv_large_sectors``) is set, else ``dm_sector + iv_offset``.
    """
    if sector_size < 512 or sector_size > _AES_DM_MAX_SECTOR_SIZE or sector_size & (sector_size - 1):
        raise ValueError("dm-crypt sector_size must be a power of two in 512..4096, got %r"
                         % (sector_size,))
    if dm_sector < 0 or iv_offset < 0:
        raise ValueError("dm-crypt sectors and iv_offset are unsigned")
    per_unit = sector_size >> _AES_DM_SECTOR_SHIFT
    if dm_sector & (per_unit - 1):
        raise ValueError("dm_sector %d is not aligned to a %d-byte unit" % (dm_sector, sector_size))
    cc_sector = dm_sector + iv_offset
    return cc_sector >> (per_unit.bit_length() - 1) if iv_large else cc_sector


def _aes_dm_parse(spec: str) -> Tuple[str, str, str]:
    """``"aes-xts-plain64"`` -> ``("xts", "plain64", "")``; ``essiv:<hash>`` -> hash in [2]."""
    parts = str(spec).strip().lower().split("-", 2)
    if len(parts) != 3 or parts[0] != "aes":
        raise ValueError("unsupported dm-crypt cipher spec %r" % (spec,))
    chain, ivmode = parts[1], parts[2]
    ivname, _, ivopts = ivmode.partition(":")
    supported = {"xts": ("plain64", "plain"), "cbc": ("plain64", "plain", "essiv")}
    if ivname not in supported.get(chain, ()) or (ivname == "essiv") != bool(ivopts):
        raise ValueError("unsupported dm-crypt cipher spec %r" % (spec,))
    return chain, ivname, ivopts


def _aes_dm_iv(key: bytes, ivname: str, ivopts: str, iv_sector: int) -> bytes:
    """The 16-byte IV of dm-crypt's ``plain`` / ``plain64`` / ``essiv:<hash>`` generators."""
    if iv_sector < 0:
        raise ValueError("IV sector must be non-negative")
    if ivname == "plain":
        return struct.pack("<I", iv_sector & _AES_DM_MASK32) + bytes(12)
    if ivname == "plain64":
        return struct.pack("<Q", iv_sector & _AES_DM_MASK64) + bytes(8)
    return essiv_iv(key, iv_sector & _AES_DM_MASK64, ivopts)


def dm_decrypt_unit(key, spec: str, iv_sector: int, unit) -> bytes:
    """Decrypt one dm-crypt encryption unit (``sector_size`` bytes) with IV sector ``iv_sector``.

    ``spec`` is the dm table cipher: ``aes-xts-plain64``, ``aes-xts-plain``,
    ``aes-cbc-essiv:sha256``, ``aes-cbc-plain64`` or ``aes-cbc-plain``.  ``key`` is the whole
    volume key: key1||key2 for XTS (key2 encrypts the tweak); for ESSIV the salt is
    ``H(key)`` of the whole key (dm-crypt ``crypt_iv_essiv_ctr()`` / crypto/essiv.c).  Use
    ``dm_iv_sector`` for ``iv_sector``.  ``plain`` keeps only the low 32 bits of the sector.
    """
    chain, ivname, ivopts = _aes_dm_parse(spec)
    unit = _aes_whole_blocks(unit, "dm-crypt unit")
    if not unit:
        raise ValueError("dm-crypt unit must not be empty")
    if chain == "xts":
        mask = _AES_DM_MASK32 if ivname == "plain" else _AES_DM_MASK64
        return xts_decrypt(key, iv_sector & mask, unit, sector_size=len(unit))
    key = _aes_checked_key(key)
    return cbc_decrypt(key, _aes_dm_iv(key, ivname, ivopts, iv_sector), unit)


def _aes_xts_alpha_power(t: int, power: int) -> int:
    """``t * alpha^power`` in GF(2^128) (IEEE 1619 little-endian convention)."""
    for _ in range(power):
        t = ((t << 1) & _AES_MASK128) ^ _AES_XTS_ALPHA_REDUCTION if t >> 127 else t << 1
    return t


def dm_decrypt_block(key, spec: str, iv_sector: int, unit, block_index: int) -> bytes:
    """Decrypt only block ``block_index`` (16 bytes) of a dm-crypt unit: the cheap prefilter.

    Equal to ``dm_decrypt_unit(...)[16 * block_index: 16 * block_index + 16]``.  XTS uses the
    tweak ``E_key2(IV) * alpha^block_index``; CBC XORs the previous ciphertext block (the IV
    for block 0).  Costs two AES block operations whatever the unit size.
    """
    chain, ivname, ivopts = _aes_dm_parse(spec)
    unit = _aes_whole_blocks(unit, "dm-crypt unit")
    if not 0 <= block_index < len(unit) // _AES_BLOCK_SIZE:
        raise ValueError("block_index %r outside a %d-byte unit" % (block_index, len(unit)))
    start = block_index * _AES_BLOCK_SIZE
    block = unit[start: start + _AES_BLOCK_SIZE]
    if chain == "xts":
        key = bytes(key)
        if len(key) not in _AES_XTS_KEY_SIZES:
            raise ValueError("AES-XTS key must be 32 or 64 bytes (key1||key2), got %d" % len(key))
        half = len(key) // 2
        tweak = encrypt_block(key[half:], _aes_dm_iv(key, ivname, ivopts, iv_sector))
        pad = _aes_xts_alpha_power(int.from_bytes(tweak, "little"), block_index).to_bytes(16, "little")
        return _aes_xor(decrypt_block(key[:half], _aes_xor(block, pad)), pad)
    key = _aes_checked_key(key)
    previous = unit[start - _AES_BLOCK_SIZE: start] if block_index else _aes_dm_iv(key, ivname, ivopts, iv_sector)
    return _aes_xor(decrypt_block(key, block), previous)


def swap_words(blob) -> bytes:
    """Reverse the bytes of every 4-byte word (keys loaded as big-endian u32 words).

    A trailing partial word is kept as is.  ``ssh_kdf.swap_words`` is the same function: that
    module is inlined into plugins on its own and cannot import this one.
    """
    blob = bytes(blob)
    whole = len(blob) - len(blob) % 4
    return b"".join(blob[i:i + 4][::-1] for i in range(0, whole, 4)) + blob[whole:]
