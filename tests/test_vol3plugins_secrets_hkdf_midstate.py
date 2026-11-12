"""Tests for vol3plugins/linux/secrets/hkdf_midstate.py.

The module has a single (pure-Python) path, so there is no backend matrix; instead every
result is checked against an independent implementation (``hashlib``/``hmac`` or
``cryptography``'s HKDF) and against published vectors: FIPS 180-4 "abc", RFC 4231
HMAC-SHA512 cases 1-7 computed through the midstate path, RFC 5869 A.1, and the xfstests
fscrypt key identifier for the raw key 0x01..0x40.
"""

import hashlib
import hmac
import random
import struct

import pytest

from memdiver.vol3plugins.linux.secrets import hkdf_midstate as hm

RNG = random.Random(0xF5C)
SHA512_IV = (
    0x6A09E667F3BCC908, 0xBB67AE8584CAA73B, 0x3C6EF372FE94F82B, 0xA54FF53A5F1D36F1,
    0x510E527FADE682D1, 0x9B05688C2B3E6C1F, 0x1F83D9ABFB41BD6B, 0x5BE0CD19137E2179,
)


def _rand(size):
    return bytes(RNG.getrandbits(8) for _ in range(size))


def _single_block(message):
    """FIPS 180-4 5.1.2 padding of a short (<= 111 byte) message into one block."""
    return message + b"\x80" + bytes(111 - len(message)) + (8 * len(message)).to_bytes(16, "big")


# --------------------------------------------------------------------------- SHA-512 core


def test_sha512_compress_fips180_abc():
    digest = struct.pack(">8Q", *hm.sha512_compress(SHA512_IV, _single_block(b"abc")))
    assert digest.hex() == (
        "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a"
        "2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"
    )


def test_sha512_compress_chains_like_hashlib():
    for size in (0, 1, 111, 112, 127, 128, 129, 255, 256, 1000):
        message = _rand(size)
        padded = message + b"\x80" + bytes((111 - size) % 128) + (8 * size).to_bytes(16, "big")
        state = SHA512_IV
        for offset in range(0, len(padded), 128):
            state = hm.sha512_compress(state, padded[offset: offset + 128])
        assert struct.pack(">8Q", *state) == hashlib.sha512(message).digest()


def test_sha512_compress_rejects_bad_shapes():
    with pytest.raises(ValueError):
        hm.sha512_compress(SHA512_IV[:7], bytes(128))
    with pytest.raises(ValueError):
        hm.sha512_compress(SHA512_IV, bytes(127))


# --------------------------------------------------------------------------- HMAC via midstates

_A131 = "aa" * 131
RFC4231 = [  # (key, data, HMAC-SHA-512); case 5 is truncated to 128 bits
    pytest.param("0b" * 20, b"Hi There".hex(),
                 "87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec2787ad0b30545e17cde"
                 "daa833b7d6b8a702038b274eaea3f4e4be9d914eeb61f1702e696c203a126854", id="case1"),
    pytest.param(b"Jefe".hex(), b"what do ya want for nothing?".hex(),
                 "164b7a7bfcf819e2e395fbe73b56e0a387bd64222e831fd610270cd7ea250554"
                 "9758bf75c05a994a6d034f65f8f0e6fdcaeab1a34d4a6b4b636e070a38bce737", id="case2"),
    pytest.param("aa" * 20, "dd" * 50,
                 "fa73b0089d56a284efb0f0756c890be9b1b5dbdd8ee81a3655f83e33b2279d39"
                 "bf3e848279a722c806b485a47e67c807b946a337bee8942674278859e13292fb", id="case3"),
    pytest.param("0102030405060708090a0b0c0d0e0f10111213141516171819", "cd" * 50,
                 "b0ba465637458c6990e5a8c5f61d4af7e576d97ff94b872de76f8050361ee3db"
                 "a91ca5c11aa25eb4d679275cc5788063a5f19741120c4f2de2adebeb10a298dd", id="case4"),
    pytest.param("0c" * 20, b"Test With Truncation".hex(),
                 "415fad6271580a531d4179bc891d87a6", id="case5-truncated"),
    pytest.param(_A131, b"Test Using Larger Than Block-Size Key - Hash Key First".hex(),
                 "80b24263c7c1a3ebb71493c1dd7be8b49b46d1f41b4aeec1121b013783f8f352"
                 "6b56d037e05f2598bd0fd2215d6a1e5295e64f73f63f0aec8b915a985d786598", id="case6"),
    pytest.param(
        _A131,
        b"This is a test using a larger than block-size key and a larger than block-size "
        b"data. The key needs to be hashed before being used by the HMAC algorithm.".hex(),
        "e37b6a775dc87dbaa4dfa9f96e5e3ffddebd71f8867289865df5a32d20cdc944"
        "b6022cac3c4982b10d5eeb55c3e4de15134676fb6de0446065c97440fa8c6a58", id="case7"),
]


@pytest.mark.parametrize("key,data,expected", RFC4231)
def test_rfc4231_hmac_sha512_through_midstates(key, data, expected):
    ipad_h, opad_h = hm.midstates_from_key(bytes.fromhex(key))
    mac = hm.hmac_sha512_from_midstates(ipad_h, opad_h, bytes.fromhex(data))
    assert mac.hex()[: len(expected)] == expected


def test_midstate_hmac_matches_stdlib_for_random_inputs():
    for _ in range(40):
        key, message = _rand(RNG.randint(0, 300)), _rand(RNG.randint(0, 400))
        ipad_h, opad_h = hm.midstates_from_key(key)
        assert hm.hmac_sha512_from_midstates(ipad_h, opad_h, message) == hmac.new(
            key, message, "sha512").digest()


def test_midstates_reject_malformed_state():
    with pytest.raises(ValueError):
        hm.hmac_sha512_from_midstates(SHA512_IV[:7], SHA512_IV, b"")
    with pytest.raises(ValueError):
        hm.hmac_sha512_from_midstates((1 << 64,) * 8, SHA512_IV, b"")


# --------------------------------------------------------------------------- HKDF


def test_rfc5869_a1_plain_helpers():
    ikm, salt, info = bytes([0x0B] * 22), bytes(range(13)), bytes(range(0xF0, 0xFA))
    prk = hm.hkdf_extract(salt, ikm, "sha256")
    assert prk.hex() == "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5"
    assert hm.hkdf_expand(prk, info, 42, "sha256").hex() == (
        "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865"
    )


def test_hkdf_matches_cryptography_for_random_inputs():
    hashes = pytest.importorskip("cryptography.hazmat.primitives.hashes")
    hkdf = pytest.importorskip("cryptography.hazmat.primitives.kdf.hkdf")
    for _ in range(20):
        ikm, salt, info = _rand(RNG.randint(1, 100)), _rand(RNG.randint(0, 200)), _rand(RNG.randint(0, 80))
        length = RNG.randint(1, 300)
        expected = hkdf.HKDF(hashes.SHA512(), length, salt or None, info).derive(ikm)
        prk = hm.hkdf_extract(salt, ikm)
        assert hm.hkdf_expand(prk, info, length) == expected
        assert hm.hkdf_expand_sha512_from_midstates(*hm.midstates_from_key(prk), info, length) == expected
        assert hkdf.HKDFExpand(hashes.SHA512(), length, info).derive(prk) == expected


def test_hkdf_length_limits():
    ipad_h, opad_h = hm.midstates_from_key(b"k")
    assert hm.hkdf_expand_sha512_from_midstates(ipad_h, opad_h, b"", 0) == b""
    with pytest.raises(ValueError):
        hm.hkdf_expand_sha512_from_midstates(ipad_h, opad_h, b"", 255 * 64 + 1)
    with pytest.raises(ValueError):
        hm.hkdf_expand(b"k", b"", 255 * 64 + 1)


# --------------------------------------------------------------------------- fscrypt v2

XFSTESTS_RAW_KEY = bytes(range(1, 65))  # xfstests common/encrypt TEST_RAW_KEY
XFSTESTS_KEY_IDENTIFIER = "69b2f6edeee720cce0577937eb8a6751"  # ... TEST_KEY_IDENTIFIER


def test_fscrypt_info_layout_and_context_values():
    assert hm.fscrypt_hkdf_info(hm.HKDF_CONTEXT_KEY_IDENTIFIER) == b"fscrypt\x00\x01"
    assert hm.fscrypt_hkdf_info(hm.HKDF_CONTEXT_PER_FILE_ENC_KEY, b"N" * 16) == b"fscrypt\x00\x02" + b"N" * 16
    contexts = [hm.HKDF_CONTEXT_KEY_IDENTIFIER_FOR_RAW_KEY, hm.HKDF_CONTEXT_PER_FILE_ENC_KEY,
                hm.HKDF_CONTEXT_DIRECT_KEY, hm.HKDF_CONTEXT_IV_INO_LBLK_64_KEY,
                hm.HKDF_CONTEXT_DIRHASH_KEY, hm.HKDF_CONTEXT_IV_INO_LBLK_32_KEY,
                hm.HKDF_CONTEXT_INODE_HASH_KEY, hm.HKDF_CONTEXT_KEY_IDENTIFIER_FOR_HW_WRAPPED_KEY]
    assert contexts == list(range(1, 9))
    with pytest.raises(ValueError):
        hm.fscrypt_hkdf_info(256)


def test_fscrypt_identifier_matches_xfstests():
    assert hm.fscrypt_v2_identifier(XFSTESTS_RAW_KEY).hex() == XFSTESTS_KEY_IDENTIFIER


def test_fscrypt_identifier_from_midstates_equals_raw_key_path():
    for size in (16, 32, 64, 17, 48):
        key = _rand(size)
        ipad_h, opad_h = hm.fscrypt_v2_hkdf_midstates(key)
        assert hm.fscrypt_v2_identifier_from_midstates(ipad_h, opad_h) == hm.fscrypt_v2_identifier(key)
    ipad_h, opad_h = hm.fscrypt_v2_hkdf_midstates(XFSTESTS_RAW_KEY)
    assert hm.fscrypt_v2_identifier_from_midstates(ipad_h, opad_h).hex() == XFSTESTS_KEY_IDENTIFIER


def test_fscrypt_extract_uses_a_zero_64_byte_salt():
    key = _rand(64)
    assert hm.fscrypt_v2_prk(key) == hmac.new(bytes(64), key, "sha512").digest()
    assert hm.fscrypt_v2_prk(key) == hm.hkdf_extract(b"", key)  # RFC 5869 default salt


# --------------------------------------------------------------------------- kernel layouts


def _export(state, count, state_size, byteorder):
    """A crypto_shash sha512 export: state[8], count[2], buf[128] (+ v6.16 length byte)."""
    fmt = "<" if byteorder == "little" else ">"
    body = struct.pack(fmt + "8Q", *state) + struct.pack(fmt + "2Q", count, 0)
    return body + _rand(state_size - len(body))  # buffer contents are irrelevant


def _hmac_pads(key, state_size, byteorder="little", count=128):
    ipad_h, opad_h = hm.fscrypt_v2_hkdf_midstates(key)
    return (_export(ipad_h, count, state_size, byteorder)
            + _export(opad_h, count, state_size, byteorder))


@pytest.mark.parametrize("state_size", [208, 209])
@pytest.mark.parametrize("byteorder", ["little", "big"])
def test_parse_crypto_hmac_template_layouts(state_size, byteorder):
    key = _rand(64)
    expected = hm.fscrypt_v2_hkdf_midstates(key)
    pads = _hmac_pads(key, state_size, byteorder)
    hash_pointer = struct.pack("<Q", 0xFFFF888012345678)
    new_ctx = hash_pointer + pads  # v6.7-v6.16 struct hmac_ctx { hash; pads[]; }
    old_ctx = pads + hash_pointer  # <= v6.6: pads first, struct hmac_ctx after them
    assert hm.parse_sha512_state(new_ctx, "hmac_ctx", byteorder) == expected
    assert hm.parse_sha512_state(old_ctx, "hmac_pads", byteorder) == expected
    assert hm.parse_sha512_state(new_ctx, "hmac_ctx", byteorder, state_size=state_size) == expected
    parsed = hm.parse_sha512_state(new_ctx, "hmac_ctx", byteorder)
    assert hm.fscrypt_v2_identifier_from_midstates(*parsed) == hm.fscrypt_v2_identifier(key)


@pytest.mark.parametrize("byteorder", ["little", "big"])
def test_parse_lib_hmac_sha512_key_layout(byteorder):
    key = XFSTESTS_RAW_KEY
    ipad_h, opad_h = hm.fscrypt_v2_hkdf_midstates(key)
    fmt = "<16Q" if byteorder == "little" else ">16Q"
    blob = struct.pack(fmt, *ipad_h, *opad_h)  # struct hmac_sha512_key { istate; ostate; }
    parsed = hm.parse_sha512_state(blob + b"tail", "hmac_sha512_key", byteorder)
    assert parsed == (ipad_h, opad_h)
    assert hm.fscrypt_v2_identifier_from_midstates(*parsed).hex() == XFSTESTS_KEY_IDENTIFIER


def test_parse_rejects_wrong_counts_layouts_and_short_blobs():
    key = _rand(32)
    with pytest.raises(ValueError):
        hm.parse_sha512_state(_hmac_pads(key, 208, count=256), "hmac_pads")
    with pytest.raises(ValueError):
        hm.parse_sha512_state(_hmac_pads(key, 209), "hmac_pads", state_size=208)
    with pytest.raises(ValueError):
        hm.parse_sha512_state(bytes(100), "hmac_sha512_key")
    with pytest.raises(ValueError):
        hm.parse_sha512_state(_hmac_pads(key, 208), "hmac_pads", byteorder="pdp")
    with pytest.raises(ValueError):
        hm.parse_sha512_state(_hmac_pads(key, 208), "sha512_state")


def test_backend_is_pure_python():
    assert hm.backend() == "pure-python"
