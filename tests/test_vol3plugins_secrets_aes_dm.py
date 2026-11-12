"""dm-crypt data-unit helpers of vol3plugins/linux/secrets/aes.py: IV sector numbering,
whole-unit and single-block decryption for every supported cipher spec, and ``swap_words``.

Every reference ciphertext is made with ``cryptography`` directly (not through aes.py) and
each helper runs under BOTH aes.py backends (cryptography and forced pure-Python).
"""

import hashlib
import random
import struct

import pytest

from memdiver.vol3plugins.linux.secrets import aes, ssh_kdf
from tests.test_vol3plugins_secrets_aes import XTS_VECTORS

PUREPY_ENV = "MEMDIVER_PUREPY_CRYPTO"
RNG = random.Random(0xD3C2)
SPECS = ("aes-xts-plain64", "aes-xts-plain", "aes-cbc-essiv:sha256", "aes-cbc-plain64", "aes-cbc-plain")


@pytest.fixture(params=("cryptography", "pure-python"))
def crypto_backend(request, monkeypatch):
    if request.param == "pure-python":
        monkeypatch.setenv(PUREPY_ENV, "1")
    else:
        pytest.importorskip("cryptography")
        monkeypatch.delenv(PUREPY_ENV, raising=False)
    assert aes.backend() == request.param
    return request.param


def _rand(size):
    return bytes(RNG.getrandbits(8) for _ in range(size))


def _reference_iv(key, spec, iv_sector):
    """The IV dm-crypt feeds the cipher, computed with cryptography's ECB for ESSIV."""
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    ivmode = spec.split("-", 2)[2]
    if ivmode == "plain":
        return struct.pack("<I", iv_sector & 0xFFFFFFFF) + bytes(12)
    plain64 = struct.pack("<Q", iv_sector & (2 ** 64 - 1)) + bytes(8)
    if ivmode == "plain64":
        return plain64
    salt = hashlib.sha256(key).digest()
    enc = Cipher(algorithms.AES(salt), modes.ECB()).encryptor()
    return enc.update(plain64) + enc.finalize()


def _reference_encrypt(key, spec, iv_sector, plaintext):
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    iv = _reference_iv(key, spec, iv_sector)
    mode = modes.XTS(iv) if "-xts-" in spec else modes.CBC(iv)
    enc = Cipher(algorithms.AES(key), mode).encryptor()
    return enc.update(plaintext) + enc.finalize()


def _key_for(spec, size):
    return _rand(2 * size if "-xts-" in spec else size)


# --------------------------------------------------------------------------- dm_iv_sector


@pytest.mark.parametrize("dm_sector,iv_offset,sector_size,iv_large,expected", [
    (0, 0, 512, False, 0),
    (7, 0, 512, True, 7),           # 512-byte units: iv_large is a no-op
    (8, 0, 4096, False, 8),         # 4K units, IV still counted in 512-byte sectors
    (8, 0, 4096, True, 1),          # iv_large_sectors: counted in 4K units
    (16, 8, 4096, True, 3),         # iv_offset is added BEFORE the shift
    (16, 3, 4096, True, 2),         # (16 + 3) >> 3
    (4, 0, 2048, True, 1),
    (2, 5, 1024, False, 7),
])
def test_dm_iv_sector_follows_crypt_convert_init(dm_sector, iv_offset, sector_size, iv_large, expected):
    assert aes.dm_iv_sector(dm_sector, iv_offset, sector_size, iv_large) == expected


@pytest.mark.parametrize("args", [(1, 0, 4096, True), (0, 0, 8192, True), (0, 0, 3072, False),
                                  (0, 0, 256, False), (-8, 0, 4096, True), (0, -1, 512, False)])
def test_dm_iv_sector_rejects_bad_geometry(args):
    with pytest.raises(ValueError):
        aes.dm_iv_sector(*args)


# --------------------------------------------------------------------------- dm_decrypt_unit / block


@pytest.mark.parametrize("spec", SPECS)
@pytest.mark.parametrize("key_size", (16, 32))
@pytest.mark.parametrize("sector_size", (512, 4096))
@pytest.mark.parametrize("iv_sector", (0, 1, 0x3333333333, 2 ** 32 + 5))
def test_dm_decrypt_unit_and_block_match_cryptography(crypto_backend, spec, key_size, sector_size, iv_sector):
    pytest.importorskip("cryptography")
    key, plaintext = _key_for(spec, key_size), _rand(sector_size)
    unit = _reference_encrypt(key, spec, iv_sector, plaintext)
    assert aes.dm_decrypt_unit(key, spec, iv_sector, unit) == plaintext
    for block_index in (0, 1, 2, sector_size // 16 - 1):
        want = plaintext[16 * block_index: 16 * block_index + 16]
        assert aes.dm_decrypt_block(key, spec, iv_sector, unit, block_index) == want


def test_plain_truncates_to_32_bits_and_plain64_does_not(crypto_backend):
    key, unit = _rand(64), _rand(512)
    low = aes.dm_decrypt_unit(key, "aes-xts-plain", 5, unit)
    assert aes.dm_decrypt_unit(key, "aes-xts-plain", 2 ** 32 + 5, unit) == low
    assert aes.dm_decrypt_unit(key, "aes-xts-plain64", 2 ** 32 + 5, unit) != low
    assert aes.dm_decrypt_unit(key, "aes-xts-plain64", 5, unit) == low


@pytest.mark.parametrize("key_hex,sector,plaintext,ciphertext_hex", XTS_VECTORS)
def test_ieee1619_vectors_through_dm_helpers(crypto_backend, key_hex, sector, plaintext, ciphertext_hex):
    key, ciphertext = bytes.fromhex(key_hex), bytes.fromhex(ciphertext_hex)
    assert aes.dm_decrypt_unit(key, "aes-xts-plain64", sector, ciphertext) == plaintext
    for j in range(len(ciphertext) // 16):
        assert aes.dm_decrypt_block(key, "aes-xts-plain64", sector, ciphertext, j) == plaintext[16 * j: 16 * j + 16]


def test_essiv_uses_the_existing_essiv_iv(crypto_backend):
    key, sector = _rand(32), 77
    iv = aes.essiv_iv(key, sector)
    unit = aes.cbc_encrypt(key, iv, _rand(512))
    assert aes.dm_decrypt_unit(key, "aes-cbc-essiv:sha256", sector, unit) == aes.cbc_decrypt(key, iv, unit)


def test_a_4k_device_with_iv_large_sectors_decrypts_unit_by_unit(crypto_backend):
    """A target of three 4 KiB units starting at target sector 8, iv_offset 0, iv_large."""
    pytest.importorskip("cryptography")
    key, spec = _rand(64), "aes-xts-plain64"
    plain = [_rand(4096) for _ in range(3)]
    device = b"".join(_reference_encrypt(key, spec, 1 + i, p) for i, p in enumerate(plain))
    for i in range(3):
        iv_sector = aes.dm_iv_sector(8 + 8 * i, 0, 4096, True)
        assert aes.dm_decrypt_unit(key, spec, iv_sector, device[4096 * i: 4096 * (i + 1)]) == plain[i]


@pytest.mark.parametrize("spec", SPECS)
def test_both_backends_agree_on_random_units(monkeypatch, spec):
    pytest.importorskip("cryptography")
    for _ in range(3):
        key, unit, sector = _key_for(spec, RNG.choice((16, 32))), _rand(4096), RNG.getrandbits(40)
        results = []
        for pure in (False, True):
            if pure:
                monkeypatch.setenv(PUREPY_ENV, "1")
            else:
                monkeypatch.delenv(PUREPY_ENV, raising=False)
            results.append((aes.dm_decrypt_unit(key, spec, sector, unit),
                            aes.dm_decrypt_block(key, spec, sector, unit, 200)))
        assert results[0] == results[1]


@pytest.mark.parametrize("call", [
    lambda: aes.dm_decrypt_unit(bytes(64), "aes-xts-essiv:sha256", 0, bytes(512)),
    lambda: aes.dm_decrypt_unit(bytes(64), "twofish-xts-plain64", 0, bytes(512)),
    lambda: aes.dm_decrypt_unit(bytes(32), "aes-cbc-essiv", 0, bytes(512)),
    lambda: aes.dm_decrypt_unit(bytes(32), "aes-ecb", 0, bytes(512)),
    lambda: aes.dm_decrypt_unit(bytes(64), "aes-xts-plain64", 0, bytes(500)),
    lambda: aes.dm_decrypt_unit(bytes(64), "aes-xts-plain64", 0, b""),
    lambda: aes.dm_decrypt_unit(bytes(48), "aes-xts-plain64", 0, bytes(512)),
    lambda: aes.dm_decrypt_unit(bytes(20), "aes-cbc-plain64", 0, bytes(512)),
    lambda: aes.dm_decrypt_unit(bytes(32), "aes-cbc-plain64", -1, bytes(512)),
    lambda: aes.dm_decrypt_block(bytes(64), "aes-xts-plain64", 0, bytes(512), 32),
    lambda: aes.dm_decrypt_block(bytes(64), "aes-xts-plain64", 0, bytes(512), -1),
    lambda: aes.dm_decrypt_block(bytes(48), "aes-xts-plain64", 0, bytes(512), 0),
])
def test_dm_helpers_reject_bad_input(call):
    with pytest.raises(ValueError):
        call()


def test_spec_is_case_and_space_insensitive():
    key, unit = _rand(64), _rand(512)
    assert aes.dm_decrypt_unit(key, " AES-XTS-Plain64 ", 3, unit) == aes.dm_decrypt_unit(key, "aes-xts-plain64", 3, unit)


# --------------------------------------------------------------------------- swap_words


@pytest.mark.parametrize("blob", [b"", b"\x01", b"\x01\x02\x03\x04", b"\x01\x02\x03\x04\x05", bytes(range(37))])
def test_swap_words_matches_the_ssh_kdf_copy(blob):
    assert aes.swap_words(blob) == ssh_kdf.swap_words(blob)
    assert aes.swap_words(aes.swap_words(blob)) == blob


def test_swap_words_reverses_each_word_and_keeps_the_tail():
    assert aes.swap_words(bytearray(b"\x01\x02\x03\x04\x05")) == b"\x04\x03\x02\x01\x05"
