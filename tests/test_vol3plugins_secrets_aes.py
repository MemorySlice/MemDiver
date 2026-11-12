"""Tests for vol3plugins/linux/secrets/aes.py, plus the secrets-directory self-contained rule.

Every known-answer test runs under BOTH backends (``cryptography`` and the forced pure-Python
path); the cross-backend tests feed random inputs to each public function and require
byte-identical results.  The kernel-layout tests check ``kernel_key_dec`` against a direct
port of lib/crypto/aes.c ``aes_expandkey()`` and by decrypting with the kernel schedule.
"""

import ast
import functools
import hashlib
import os
import random
import shutil
import struct
import subprocess
import sys
from pathlib import Path

import pytest

from memdiver.vol3plugins.linux.secrets import aes

PUREPY_ENV = "MEMDIVER_PUREPY_CRYPTO"
BACKENDS = ("cryptography", "pure-python")
SECRETS_DIR = Path(aes.__file__).resolve().parent
RNG = random.Random(0x5EC2E75)


def _use_backend(monkeypatch, name):
    if name == "pure-python":
        monkeypatch.setenv(PUREPY_ENV, "1")
    else:
        pytest.importorskip("cryptography")
        monkeypatch.delenv(PUREPY_ENV, raising=False)
    assert aes.backend() == name


@pytest.fixture(params=BACKENDS)
def crypto_backend(request, monkeypatch):
    _use_backend(monkeypatch, request.param)
    return request.param


def _on_both_backends(monkeypatch, function, *args):
    """Run ``function(*args)`` under each backend and require identical results."""
    results = []
    for name in BACKENDS:
        _use_backend(monkeypatch, name)
        results.append(function(*args))
    assert results[0] == results[1]
    return results[0]


def _rand(size):
    return bytes(RNG.getrandbits(8) for _ in range(size))


# --------------------------------------------------------------------------- FIPS-197

FIPS_PLAINTEXT = bytes.fromhex("00112233445566778899aabbccddeeff")
FIPS_C = [  # FIPS-197 Appendix C.1-C.3
    ("000102030405060708090a0b0c0d0e0f", "69c4e0d86a7b0430d8cdb78070b4c55a"),
    ("000102030405060708090a0b0c0d0e0f1011121314151617", "dda97ca4864cdfe06eaf70a0ec0d7191"),
    ("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
     "8ea2b7ca516745bfeafc49904b496089"),
]
FIPS_A = [  # FIPS-197 Appendix A.1-A.3: key, first derived round key words, last round key
    ("2b7e151628aed2a6abf7158809cf4f3c",
     "a0fafe1788542cb123a339392a6c7605", "d014f9a8c9ee2589e13f0cc8b6630ca6"),
    ("8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b",
     "fe0c91f72402f5a5ec12068e6c827f6b", "e98ba06f448c773c8ecc720401002202"),
    ("603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4",
     "9ba354118e6925afa51a8b5f2067fcde", "fe4890d1e6188d0b046df344706c631e"),
]


@pytest.mark.parametrize("key_hex,ciphertext_hex", FIPS_C)
def test_fips197_appendix_c(crypto_backend, key_hex, ciphertext_hex):
    key = bytes.fromhex(key_hex)
    assert aes.encrypt_block(key, FIPS_PLAINTEXT).hex() == ciphertext_hex
    assert aes.decrypt_block(key, bytes.fromhex(ciphertext_hex)) == FIPS_PLAINTEXT


@pytest.mark.parametrize("key_hex,derived_hex,last_hex", FIPS_A)
def test_fips197_appendix_a_key_expansion(crypto_backend, key_hex, derived_hex, last_hex):
    key = bytes.fromhex(key_hex)
    schedule = aes.expand_key(key)
    assert len(schedule) == {16: 176, 24: 208, 32: 240}[len(key)]
    assert schedule[: len(key)] == key  # round key 0 == the raw key
    assert schedule[len(key): len(key) + 16].hex() == derived_hex
    assert schedule[-16:].hex() == last_hex


def test_sbox_matches_the_fips197_construction():
    """S-box = affine map of the GF(2^8) inverse (FIPS-197 5.1.1), built independently."""
    assert bytes(_reference_sbox()) == aes._AES_SBOX


# --------------------------------------------------------------------------- SP 800-38A ECB/CBC

SP800_38A_KEY = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")
SP800_38A_PLAINTEXT = bytes.fromhex(
    "6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e51"
    "30c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710"
)


def test_sp800_38a_ecb_and_cbc(crypto_backend):
    ecb = bytes.fromhex(
        "3ad77bb40d7a3660a89ecaf32466ef97f5d3d58503b9699de785895a96fdbaaf"
        "43b1cd7f598ece23881b00e3ed0306887b0c785e27e8ad3f8223207104725dd4"
    )
    cbc = bytes.fromhex(
        "7649abac8119b246cee98e9b12e9197d5086cb9b507219ee95db113a917678b2"
        "73bed6b8e3c1743b7116e69e222295163ff1caa1681fac09120eca307586e1a7"
    )
    iv = bytes(range(16))
    assert aes.ecb_encrypt(SP800_38A_KEY, SP800_38A_PLAINTEXT) == ecb
    assert aes.ecb_decrypt(SP800_38A_KEY, ecb) == SP800_38A_PLAINTEXT
    assert aes.cbc_encrypt(SP800_38A_KEY, iv, SP800_38A_PLAINTEXT) == cbc
    assert aes.cbc_decrypt(SP800_38A_KEY, iv, cbc) == SP800_38A_PLAINTEXT


# --------------------------------------------------------------------------- IEEE 1619 XTS

# IEEE 1619-2007 Annex B vectors 1-4 (AES-128) and 10 (AES-256), as carried by the kernel's
# crypto/testmgr.h aes_xts_tv_template (v6.12).  Vector 1 has key1 == key2, which OpenSSL
# refuses, so it also exercises the pure fallback on the cryptography backend.
XTS_VECTORS = [
    pytest.param(
        "0000000000000000000000000000000000000000000000000000000000000000", 0x0,
        bytes(32), "917cf69ebd68b2ec9b9fe9a3eadda692cd43d2f59598ed858c02c2652fbf922e",
        id="XTS-AES-1",
    ),
    pytest.param(
        "1111111111111111111111111111111122222222222222222222222222222222", 0x3333333333,
        b"\x44" * 32, "c454185e6a16936e39334038acef838bfb186fff7480adc4289382ecd6d394f0",
        id="XTS-AES-2",
    ),
    pytest.param(
        "fffefdfcfbfaf9f8f7f6f5f4f3f2f1f022222222222222222222222222222222", 0x3333333333,
        b"\x44" * 32, "af85336b597afc1a900b2eb21ec949d292df4c047e0b21532186a5971a227a89",
        id="XTS-AES-3",
    ),
    pytest.param(
        "2718281828459045235360287471352631415926535897932384626433832795", 0x0,
        bytes(range(256)) * 2,
        "27a7479befa1d476489f308cd4cfa6e2a96e4bbe3208ff25287dd3819616e89c"
        "c78cf7f5e543445f8333d8fa7f56000005279fa5d8b5e4ad40e736ddb4d35412"
        "328063fd2aab53e5ea1e0a9f332500a5df9487d07a5c92cc512c8866c7e860ce"
        "93fdf166a24912b422976146ae20ce846bb7dc9ba94a767aaef20c0d61ad0265"
        "5ea92dc4c4e41a8952c651d33174be51a10c421110e6d81588ede82103a252d8"
        "a750e8768defffed9122810aaeb99f9172af82b604dc4b8e51bcb08235a6f434"
        "1332e4ca60482a4ba1a03b3e65008fc5da76b70bf1690db4eae29c5f1badd03c"
        "5ccf2a55d705ddcd86d449511ceb7ec30bf12b1fa35b913f9f747a8afd1b130e"
        "94bff94effd01a91735ca1726acd0b197c4e5b03393697e126826fb6bbde8ecc"
        "1e08298516e2c9ed03ff3c1b7860f6de76d4cecd94c8119855ef5297ca67e9f3"
        "e7ff72b1e99785ca0a7e7720c5b36dc6d72cac9574c8cbbc2f801e23e56fd344"
        "b07f22154beba0f08ce8891e643ed995c94d9a69c9f1b5f499027a78572aeebd"
        "74d20cc39881c213ee770b1010e4bea718846977ae119f7a023ab58cca0ad752"
        "afe656bb3c17256a9f6e9bf19fdd5a38fc82bbe872c5539edb609ef4f79c203e"
        "bb140f2e583cb2ad15b4aa5b655016a8449277dbd477ef2c8d6c017db738b18d"
        "eb4a427d1923ce3ff262735779a418f20a282df920147beabe421ee5319d0568",
        id="XTS-AES-4",
    ),
    pytest.param(
        "2718281828459045235360287471352662497757247093699959574966967627"
        "3141592653589793238462643383279502884197169399375105820974944592", 0xFF,
        bytes(range(256)) * 2,
        "1c3b3a102f770386e4836c99e370cf9bea00803f5e482357a4ae12d414a3e63b"
        "5d31e276f8fe4a8d66b317f9ac683f44680a86ac35adfc3345befecb4bb188fd"
        "5776926c49a3095eb108fd1098baec70aaa66999a72a82f27d848b21d4a741b0"
        "c5cd4d5fff9dac89aeba122961d03a757123e9870f8acf1000020887891429ca"
        "2a3e7a7d7df7b10355165c8b9a6d0a7de8b062c4500dc4cd120c0f7418dae3d0"
        "b5781c34803fa75421c790dfe1de1834f280d7667b327f6c8cd7557e12ac3a0f"
        "93ec05c52e0493ef31a12d3d9260f79a289d6a379bc70c50841473d1a8cc81ec"
        "583e9645e07b8d9670655ba5bbcfecc6dc3966380ad8fecb17b6ba02469a020a"
        "84e18e8f84252070c13e9f1f289be54fbc481457778f616015e1327a02b140f1"
        "505eb309326d68378f8374595c849d84f4c333ec4423885143cb47bd71c5edae"
        "9be69a2ffeceb1bec9de244fbe15992b11b77c040f12bd8f6a975a44a0f90c29"
        "a9abc3d4d893927284c58754cce294529f8614dcd2aba991925fedc4ae74ffac"
        "6e333b93eb4aff0479da9a410e4450e0dd7ae4c6e2910900575da401fc07059f"
        "645e8b7e9bfdef33943054ff84011493c27b3429eaedb4ed5376441a77ed4385"
        "1ad77f16f541dfd269d50d6a5f14fb0aab1cbb4c1550be97f7ab4066193c4caa"
        "773dad38014bd2092fa755c824bb5e54c4f36ffda9fcea70b9c6e693e148c151",
        id="XTS-AES-10",
    ),
]


@pytest.mark.parametrize("key_hex,sector,plaintext,ciphertext_hex", XTS_VECTORS)
def test_ieee1619_xts_vectors(crypto_backend, key_hex, sector, plaintext, ciphertext_hex):
    key, ciphertext = bytes.fromhex(key_hex), bytes.fromhex(ciphertext_hex)
    unit = len(plaintext)  # each vector is one data unit
    assert aes.xts_encrypt(key, sector, plaintext, sector_size=unit) == ciphertext
    assert aes.xts_decrypt(key, sector, ciphertext, sector_size=unit) == plaintext


def test_xts_multi_sector_uses_consecutive_tweaks(crypto_backend):
    key, data = _rand(64), _rand(4 * 512)
    whole = aes.xts_decrypt(key, 1000, data)
    per_sector = b"".join(
        aes.xts_decrypt(key, 1000 + i, data[i * 512: (i + 1) * 512]) for i in range(4)
    )
    assert whole == per_sector
    assert aes.xts_encrypt(key, 1000, whole) == data
    big_sector = aes.xts_decrypt(key, 7, data[:2048], sector_size=2048)
    assert big_sector != aes.xts_decrypt(key, 7, data[:2048])  # one tweak vs four
    assert aes.xts_encrypt(key, 7, big_sector, sector_size=2048) == data[:2048]


def test_xts_rejects_bad_shapes():
    with pytest.raises(ValueError):
        aes.xts_decrypt(bytes(48), 0, bytes(512))  # AES-192-XTS is not a dm-crypt key size
    with pytest.raises(ValueError):
        aes.xts_decrypt(_rand(32), 0, bytes(500))  # not whole sectors (no ciphertext stealing)
    with pytest.raises(ValueError):
        aes.xts_decrypt(_rand(32), -1, bytes(512))
    with pytest.raises(ValueError):
        aes.xts_decrypt(_rand(32), 0, bytes(512), sector_size=100)


# --------------------------------------------------------------------------- ESSIV


def test_essiv_iv_is_aes_of_le64_sector_under_hashed_key(crypto_backend):
    key = bytes(range(32))
    salt = hashlib.sha256(key).digest()
    expected = _reference_ecb_encrypt(salt, struct.pack("<Q", 0x1234) + bytes(8))
    assert aes.essiv_iv(key, 0x1234) == expected
    assert aes.essiv_iv(key, 0, "md5") == _reference_ecb_encrypt(hashlib.md5(key).digest(), bytes(16))
    with pytest.raises(ValueError):
        aes.essiv_iv(key, 0, "sha512")  # 64-byte digest is no AES key
    with pytest.raises(ValueError):
        aes.essiv_iv(key, 1 << 64)


# --------------------------------------------------------------------------- GCM

# McGrew & Viega, "The Galois/Counter Mode of Operation", test cases 1-6, 17 and 18
# (aad, plaintext, ciphertext, tag, key, iv).  5 and 17 use 64-bit IVs, 6 and 18 480-bit.
_GCM_P = (
    "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a72"
    "1c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39"
)
_GCM_AAD = "feedfacedeadbeeffeedfacedeadbeefabaddad2"
_GCM_K = "feffe9928665731c6d6a8f9467308308"
_GCM_K192 = _GCM_K + _GCM_K[:16]
_GCM_IV60 = (
    "9313225df88406e555909c5aff5269aa6a7a9538534f7da1e4c303d2a318a728"
    "c3c0c95156809539fcf0e2429a6b525416aedbf5a0de6a57a637b39b"
)
GCM_VECTORS = [
    pytest.param("", "", "", "58e2fccefa7e3061367f1d57a4e7455a", "00" * 16, "00" * 12, id="tc1"),
    pytest.param("", "00" * 16, "0388dace60b6a392f328c2b971b2fe78",
                 "ab6e47d42cec13bdf53a67b21257bddf", "00" * 16, "00" * 12, id="tc2"),
    pytest.param(
        "", _GCM_P + "1aafd255",
        "42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e"
        "21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091473f5985",
        "4d5c2af327cd64a62cf35abd2ba6fab4", _GCM_K, "cafebabefacedbaddecaf888", id="tc3"),
    pytest.param(
        _GCM_AAD, _GCM_P,
        "42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e"
        "21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091",
        "5bc94fbc3221a5db94fae95ae7121a47", _GCM_K, "cafebabefacedbaddecaf888", id="tc4"),
    pytest.param(
        _GCM_AAD, _GCM_P,
        "61353b4c2806934a777ff51fa22a4755699b2a714fcdc6f83766e5f97b6c7423"
        "73806900e49f24b22b097544d4896b424989b5e1ebac0f07c23f4598",
        "3612d2e79e3b0785561be14aaca2fccb", _GCM_K, "cafebabefacedbad", id="tc5-64bit-iv"),
    pytest.param(
        _GCM_AAD, _GCM_P,
        "8ce24998625615b603a033aca13fb894be9112a5c3a211a8ba262a3cca7e2ca7"
        "01e4a9a4fba43c90ccdcb281d48c7c6fd62875d2aca417034c34aee5",
        "619cc5aefffe0bfa462af43c1699d050", _GCM_K, _GCM_IV60, id="tc6-480bit-iv"),
    pytest.param(
        _GCM_AAD, _GCM_P,
        "c3762df1ca787d32ae47c13bf19844cbaf1ae14d0b976afac52ff7d79bba9de0"
        "feb582d33934a4f0954cc2363bc73f7862ac430e64abe499f47c9b1f",
        "3a337dbf46a792c45e454913fe2ea8f2", _GCM_K * 2, "cafebabefacedbad", id="tc17-aes256"),
    pytest.param(
        _GCM_AAD, _GCM_P,
        "5a8def2f0c9e53f1f75d7853659e2a20eeb2b22aafde6419a058ab4f6f746bf4"
        "0fc0c3b780f244452da3ebf1c5d82cdea2418997200ef82e44ae7e3f",
        "a44a8266ee1c8eb0c8b5d4cf5ae9f19a", _GCM_K * 2, _GCM_IV60, id="tc18-aes256"),
    # Test cases 7-12 (AES-192) and 13-16 (AES-256), same paper.
    pytest.param("", "", "", "cd33b28ac773f74ba00ed1f312572435", "00" * 24, "00" * 12, id="tc7"),
    pytest.param("", "00" * 16, "98e7247c07f0fe411c267e4384b0f600",
                 "2ff58d80033927ab8ef4d4587514f0fb", "00" * 24, "00" * 12, id="tc8"),
    pytest.param(
        "", _GCM_P + "1aafd255",
        "3980ca0b3c00e841eb06fac4872a2757859e1ceaa6efd984628593b40ca1e19c"
        "7d773d00c144c525ac619d18c84a3f4718e2448b2fe324d9ccda2710acade256",
        "9924a7c8587336bfb118024db8674a14", _GCM_K192, "cafebabefacedbaddecaf888", id="tc9"),
    pytest.param(
        _GCM_AAD, _GCM_P,
        "3980ca0b3c00e841eb06fac4872a2757859e1ceaa6efd984628593b40ca1e19c"
        "7d773d00c144c525ac619d18c84a3f4718e2448b2fe324d9ccda2710",
        "2519498e80f1478f37ba55bd6d27618c", _GCM_K192, "cafebabefacedbaddecaf888", id="tc10"),
    pytest.param(
        _GCM_AAD, _GCM_P,
        "0f10f599ae14a154ed24b36e25324db8c566632ef2bbb34f8347280fc4507057"
        "fddc29df9a471f75c66541d4d4dad1c9e93a19a58e8b473fa0f062f7",
        "65dcc57fcf623a24094fcca40d3533f8", _GCM_K192, "cafebabefacedbad", id="tc11-64bit-iv"),
    pytest.param(
        _GCM_AAD, _GCM_P,
        "d27e88681ce3243c4830165a8fdcf9ff1de9a1d8e6b447ef6ef7b79828666e45"
        "81e79012af34ddd9e2f037589b292db3e67c036745fa22e7e9b7373b",
        "dcf566ff291c25bbb8568fc3d376a6d9", _GCM_K192, _GCM_IV60, id="tc12-480bit-iv"),
    pytest.param("", "", "", "530f8afbc74536b9a963b4f1c4cb738b", "00" * 32, "00" * 12,
                 id="tc13-aes256"),
    pytest.param("", "00" * 16, "cea7403d4d606b6e074ec5d3baf39d18",
                 "d0d1c8a799996bf0265b98b5d48ab919", "00" * 32, "00" * 12, id="tc14-aes256"),
    pytest.param(
        "", _GCM_P + "1aafd255",
        "522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa"
        "8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662898015ad",
        "b094dac5d93471bdec1a502270e3cc6c", _GCM_K * 2, "cafebabefacedbaddecaf888",
        id="tc15-aes256"),
    pytest.param(
        _GCM_AAD, _GCM_P,
        "522dc1f099567d07f47f37a32a84427d643a8cdcbfe5c0c97598a2bd2555d1aa"
        "8cb08e48590dbb3da7b08b1056828838c5f61e6393ba7a0abcc9f662",
        "76fc6ece0f4e1768cddf8853bb2d551b", _GCM_K * 2, "cafebabefacedbaddecaf888",
        id="tc16-aes256"),
]


@pytest.mark.parametrize("aad,pt,ct,tag,key,iv", GCM_VECTORS)
def test_gcm_mcgrew_viega_vectors(crypto_backend, aad, pt, ct, tag, key, iv):
    aad, pt, ct, tag, key, iv = (bytes.fromhex(x) for x in (aad, pt, ct, tag, key, iv))
    assert aes.gcm_decrypt(key, iv, ct, tag, aad) == pt
    assert aes.gcm_encrypt(key, iv, pt, aad) == (ct, tag)
    assert aes.gcm_decrypt(key, iv, ct, tag[:12], aad) == pt  # truncated tag
    bad = bytes([tag[0] ^ 1]) + tag[1:]
    assert aes.gcm_decrypt(key, iv, ct, bad, aad) is None
    if ct:
        assert aes.gcm_decrypt(key, iv, bytes([ct[0] ^ 1]) + ct[1:], tag, aad) is None


def test_gcm_16_byte_nonce_matches_an_independent_implementation(crypto_backend):
    """gocryptfs-style 16-byte IV, checked against pycryptodome's GCM."""
    pycryptodome_aes = pytest.importorskip("Crypto.Cipher.AES")
    for nonce_size in (1, 16, 33):
        key, nonce, pt, aad = _rand(32), _rand(nonce_size), _rand(4096 + 7), _rand(19)
        reference = pycryptodome_aes.new(key, pycryptodome_aes.MODE_GCM, nonce=nonce)
        reference.update(aad)
        ct, tag = reference.encrypt_and_digest(pt)
        assert aes.gcm_encrypt(key, nonce, pt, aad) == (ct, tag)
        assert aes.gcm_decrypt(key, nonce, ct, tag, aad) == pt


def test_gcm_random_inputs_match_cryptography_and_pycryptodome(monkeypatch):
    """Pure path vs both libraries: 12/16-byte nonces, AAD, plaintext 0..300, tampering."""
    aead = pytest.importorskip("cryptography.hazmat.primitives.ciphers.aead")
    invalid_tag = pytest.importorskip("cryptography.exceptions").InvalidTag
    pycryptodome_aes = pytest.importorskip("Crypto.Cipher.AES")
    monkeypatch.setenv(PUREPY_ENV, "1")
    for length in range(301):
        key, nonce = _rand(RNG.choice((16, 24, 32))), _rand(RNG.choice((12, 16)))
        aad, pt = _rand(RNG.choice((0, 16, 24, 33))), _rand(length)
        sealed = aead.AESGCM(key).encrypt(nonce, pt, aad)
        engine = pycryptodome_aes.new(key, pycryptodome_aes.MODE_GCM, nonce=nonce)
        engine.update(aad)
        assert engine.encrypt_and_digest(pt) == (sealed[:-16], sealed[-16:])
        assert aes.gcm_encrypt(key, nonce, pt, aad) == (sealed[:-16], sealed[-16:])
        assert aes.gcm_decrypt(key, nonce, sealed[:-16], sealed[-16:], aad) == pt
        if length % 10:
            continue
        tampered = [(sealed[:-1] + bytes([sealed[-1] ^ 1]), aad), (sealed, aad + b"\0")]
        if length:
            tampered.append((bytes([sealed[0] ^ 1]) + sealed[1:], aad))
        for bad, bad_aad in tampered:
            assert aes.gcm_decrypt(key, nonce, bad[:-16], bad[-16:], bad_aad) is None
            with pytest.raises(invalid_tag):
                aead.AESGCM(key).decrypt(nonce, bad, bad_aad)
            engine = pycryptodome_aes.new(key, pycryptodome_aes.MODE_GCM, nonce=nonce)
            engine.update(bad_aad)
            with pytest.raises(ValueError):
                engine.decrypt_and_verify(bad[:-16], bad[-16:])


def test_gcm_4_and_8_bit_ghash_tables_agree():
    """Short messages use 4-bit tables (cheap to build), long ones 8-bit; same products."""
    h = int.from_bytes(_rand(16), "big")
    narrow, wide = aes._aes_ghash_tables(h, 4), aes._aes_ghash_tables(h, 8)
    for _ in range(64):
        x = int.from_bytes(_rand(16), "big")
        assert aes._aes_gf_mul(narrow, x) == aes._aes_gf_mul(wide, x)


def test_gcm_pure_path_checks_the_tag_before_decrypting(monkeypatch):
    monkeypatch.setenv(PUREPY_ENV, "1")
    key, nonce, aad = _rand(32), _rand(16), _rand(24)
    ct, tag = aes.gcm_encrypt(key, nonce, b"block 0 of a vault file" * 6, aad)

    def refuse(*_args):
        raise AssertionError("GCTR ran for an unauthenticated ciphertext")

    monkeypatch.setattr(aes, "_aes_gctr", refuse)
    assert aes.gcm_decrypt(_rand(32), nonce, ct, tag, aad) is None
    with pytest.raises(AssertionError):
        aes.gcm_decrypt(key, nonce, ct, tag, aad)


def test_gcm_rejects_bad_parameters():
    with pytest.raises(ValueError):
        aes.gcm_decrypt(bytes(16), b"", b"", bytes(16))
    with pytest.raises(ValueError):
        aes.gcm_decrypt(bytes(16), bytes(12), b"", bytes(3))


# --------------------------------------------------------------------------- SIV (RFC 5297)

# RFC 5297 Appendix A.1 (deterministic) and A.2 (nonce-based: the nonce is the LAST of the
# three associated-data components) -- (key, [associated data], plaintext, V || C).
SIV_VECTORS = [
    pytest.param(
        "fffefdfcfbfaf9f8f7f6f5f4f3f2f1f0f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff",
        ["101112131415161718191a1b1c1d1e1f2021222324252627"],
        "112233445566778899aabbccddee",
        "85632d07c6e8f37f950acd320a2ecc93" "40c02b9690c4dc04daef7f6afe5c", id="A.1"),
    pytest.param(
        "7f7e7d7c7b7a79787776757473727170404142434445464748494a4b4c4d4e4f",
        ["00112233445566778899aabbccddeeffdeaddadadeaddadaffeeddccbbaa99887766554433221100",
         "102030405060708090a0", "09f911029d74e35bd84156c5635688c0"],
        "7468697320697320736f6d6520706c61696e7465787420746f20656e6372797074207573696e67"
        "205349562d414553",
        "7bdb6e3b432667eb06f4d14bff2fbd0f"
        "cb900f2fddbe404326601965c889bf17dba77ceb094fa663b7a3f748ba8af829"
        "ea64ad544a272e9c485b62a3fd5c0d", id="A.2"),
]


@pytest.mark.parametrize("key,ad,pt,sealed", SIV_VECTORS)
def test_siv_rfc5297_vectors(crypto_backend, key, ad, pt, sealed):
    key, pt, sealed = bytes.fromhex(key), bytes.fromhex(pt), bytes.fromhex(sealed)
    ad = [bytes.fromhex(item) for item in ad]
    assert aes.siv_encrypt(key, pt, ad) == sealed
    assert aes.siv_decrypt(key, sealed, ad) == pt
    assert aes.siv_decrypt(key, sealed[:-1] + bytes([sealed[-1] ^ 1]), ad) is None
    assert aes.siv_decrypt(key, bytes([sealed[0] ^ 1]) + sealed[1:], ad) is None
    assert aes.siv_decrypt(key, sealed, ad[:-1] + [ad[-1] + b"\0"]) is None


def _siv_references():
    aead = pytest.importorskip("cryptography.hazmat.primitives.ciphers.aead")
    return aead.AESSIV, pytest.importorskip("Crypto.Cipher.AES")


def test_siv_matches_cryptography_and_pycryptodome_gocryptfs_style(crypto_backend):
    """gocryptfs seals with AESSIV(key).encrypt(pt, [aad, nonce]); pycryptodome's MODE_SIV
    feeds its ``nonce=`` to S2V as the last component after every update() -- the same."""
    aes_siv, pycryptodome_aes = _siv_references()
    for length in range(0, 301, 3):
        key, nonce, aad, pt = _rand(RNG.choice((32, 48, 64))), _rand(16), _rand(24), _rand(length)
        sealed = aes_siv(key).encrypt(pt, [aad, nonce])
        engine = pycryptodome_aes.new(key, pycryptodome_aes.MODE_SIV, nonce=nonce)
        engine.update(aad)
        ct, tag = engine.encrypt_and_digest(pt)
        assert tag + ct == sealed
        assert aes.siv_encrypt(key, pt, [aad, nonce]) == sealed
        assert aes.siv_decrypt(key, sealed, [aad, nonce]) == pt


def test_siv_tampering_is_rejected_by_every_backend(crypto_backend):
    aes_siv, pycryptodome_aes = _siv_references()
    invalid_tag = pytest.importorskip("cryptography.exceptions").InvalidTag
    for length in (0, 1, 15, 16, 17, 149, 300):
        key, nonce, aad = _rand(64), _rand(16), _rand(24)
        sealed = aes.siv_encrypt(key, _rand(length), [aad, nonce])
        bad_cases = [(sealed[:5] + bytes([sealed[5] ^ 1]) + sealed[6:], aad),
                     (sealed, aad[:-1] + bytes([aad[-1] ^ 1]))]
        if length:
            bad_cases.append((sealed[:-1] + bytes([sealed[-1] ^ 1]), aad))
        for bad_sealed, bad_aad in bad_cases:
            assert aes.siv_decrypt(key, bad_sealed, [bad_aad, nonce]) is None
            with pytest.raises(invalid_tag):
                aes_siv(key).decrypt(bad_sealed, [bad_aad, nonce])
            engine = pycryptodome_aes.new(key, pycryptodome_aes.MODE_SIV, nonce=nonce)
            engine.update(bad_aad)
            with pytest.raises(ValueError):
                engine.decrypt_and_verify(bad_sealed[16:], bad_sealed[:16])


def test_siv_without_associated_data_and_bad_parameters(crypto_backend):
    aes_siv, _ = _siv_references()
    key, pt = _rand(32), _rand(40)
    assert aes.siv_encrypt(key, pt) == aes_siv(key).encrypt(pt, None)
    with pytest.raises(ValueError):
        aes.siv_encrypt(bytes(16), b"")
    with pytest.raises(ValueError):
        aes.siv_decrypt(bytes(32), bytes(15))
    with pytest.raises(ValueError):
        aes.siv_encrypt(bytes(32), b"", [b""] * 127)


# --------------------------------------------------------------------------- kernel layouts


def _ror32(word, shift):
    return ((word >> shift) | (word << (32 - shift))) & 0xFFFFFFFF


def _kernel_mul_by_x(w):
    return ((w & 0x7F7F7F7F) << 1) ^ (((w & 0x80808080) >> 7) * 0x1B)


def _kernel_mul_by_x2(w):
    x, y, z = w & 0x3F3F3F3F, w & 0x80808080, w & 0x40404040
    return (x << 2) ^ ((y >> 7) * 0x36) ^ ((z >> 6) * 0x1B)


def _kernel_mix_columns(x):
    y = _kernel_mul_by_x(x) ^ _ror32(x, 16)
    return y ^ _ror32(x ^ y, 8)


def _kernel_inv_mix_columns(x):
    y = _kernel_mul_by_x2(x)
    return _kernel_mix_columns(x ^ y ^ _ror32(y, 16))


def _kernel_subw(word, sbox):
    return sbox[word & 0xFF] ^ (sbox[(word >> 8) & 0xFF] << 8) ^ (
        sbox[(word >> 16) & 0xFF] << 16) ^ (sbox[(word >> 24) & 0xFF] << 24)


def _kernel_aes_expandkey(in_key):
    """Line-by-line port of lib/crypto/aes.c aes_expandkey() (v6.12) -> crypto_aes_ctx bytes."""
    sbox, key_len = _reference_sbox(), len(in_key)
    kwords = key_len // 4
    key_enc, key_dec = [0] * 60, [0] * 60
    for i in range(kwords):
        key_enc[i] = struct.unpack_from("<I", in_key, 4 * i)[0]
    rc = 1
    for i in range(10):
        rki = i * kwords
        rko = rki + kwords
        key_enc[rko] = _ror32(_kernel_subw(key_enc[rki + kwords - 1], sbox), 8) ^ rc ^ key_enc[rki]
        for n in range(1, 4):
            key_enc[rko + n] = key_enc[rko + n - 1] ^ key_enc[rki + n]
        if key_len == 24:
            if i >= 7:
                break
            key_enc[rko + 4] = key_enc[rko + 3] ^ key_enc[rki + 4]
            key_enc[rko + 5] = key_enc[rko + 4] ^ key_enc[rki + 5]
        elif key_len == 32:
            if i >= 6:
                break
            key_enc[rko + 4] = _kernel_subw(key_enc[rko + 3], sbox) ^ key_enc[rki + 4]
            for n in range(5, 8):
                key_enc[rko + n] = key_enc[rko + n - 1] ^ key_enc[rki + n]
        rc = _kernel_mul_by_x(rc)
    key_dec[0:4] = key_enc[key_len + 24: key_len + 28]
    i, j = 4, key_len + 20
    while j > 0:
        for n in range(4):
            key_dec[i + n] = _kernel_inv_mix_columns(key_enc[j + n])
        i, j = i + 4, j - 4
    key_dec[i: i + 4] = key_enc[0:4]
    return struct.pack("<60I", *key_enc) + struct.pack("<60I", *key_dec) + struct.pack("<I", key_len)


@pytest.mark.parametrize("key_size", [16, 24, 32])
def test_kernel_crypto_aes_ctx_matches_a_port_of_aes_expandkey(key_size):
    for key in [bytes(range(key_size))] + [_rand(key_size) for _ in range(10)]:
        ctx = aes.kernel_crypto_aes_ctx(key)
        assert len(ctx) == 484
        assert ctx == _kernel_aes_expandkey(key)
        used = 16 * (key_size // 4 + 7)
        assert ctx[:used] == aes.expand_key(key)
        assert ctx[240: 240 + used] == aes.kernel_key_dec(key)
        assert ctx[used:240] == bytes(240 - used)  # kzalloc'd, never written


@pytest.mark.parametrize("key_size", [16, 24, 32])
def test_kernel_key_dec_decrypts_like_decrypt_block(crypto_backend, key_size):
    for _ in range(10):
        key, block = _rand(key_size), _rand(16)
        key_dec = aes.kernel_key_dec(key)
        assert key_dec[:16] == aes.expand_key(key)[-16:]  # last encryption round key first
        assert key_dec[-16:] == key[:16]  # round key 0 (the key's first 16 bytes) last
        assert _equivalent_inverse_decrypt(key_dec, block) == aes.decrypt_block(key, block)


def test_kernel_layout_big_endian_swaps_each_word():
    key = _rand(32)
    little, big = aes.kernel_crypto_aes_ctx(key), aes.kernel_crypto_aes_ctx(key, byteorder="big")
    words = struct.unpack("<121I", little)
    assert big == struct.pack(">121I", *words)
    with pytest.raises(ValueError):
        aes.kernel_key_dec(key, byteorder="middle")


# --------------------------------------------------------------------------- cross-backend equality


@pytest.mark.parametrize("key_size", [16, 24, 32])
def test_random_inputs_give_identical_results_on_both_backends(monkeypatch, key_size):
    for _ in range(5):
        key, iv, data = _rand(key_size), _rand(16), _rand(16 * RNG.randint(1, 40))
        block = data[:16]
        _on_both_backends(monkeypatch, aes.encrypt_block, key, block)
        _on_both_backends(monkeypatch, aes.decrypt_block, key, block)
        ecb = _on_both_backends(monkeypatch, aes.ecb_encrypt, key, data)
        assert _on_both_backends(monkeypatch, aes.ecb_decrypt, key, ecb) == data
        cbc = _on_both_backends(monkeypatch, aes.cbc_encrypt, key, iv, data)
        assert _on_both_backends(monkeypatch, aes.cbc_decrypt, key, iv, cbc) == data
        _on_both_backends(monkeypatch, aes.essiv_iv, key, RNG.getrandbits(64))


@pytest.mark.parametrize("xts_key_size,sector_size", [(32, 512), (64, 512), (64, 4096)])
def test_random_xts_identical_on_both_backends(monkeypatch, xts_key_size, sector_size):
    for _ in range(3):
        key, sector = _rand(xts_key_size), RNG.getrandbits(64)
        data = _rand(sector_size * RNG.randint(1, 3))
        ct = _on_both_backends(monkeypatch, aes.xts_encrypt, key, sector, data, sector_size)
        pt = _on_both_backends(monkeypatch, aes.xts_decrypt, key, sector, ct, sector_size)
        assert pt == data
    same_halves = _rand(xts_key_size // 2) * 2  # key1 == key2: OpenSSL refuses, pure runs
    _on_both_backends(monkeypatch, aes.xts_decrypt, same_halves, 3, _rand(sector_size), sector_size)


@pytest.mark.parametrize("nonce_size", [8, 12, 16, 60])
@pytest.mark.parametrize("tag_length", [16, 12, 4])
def test_random_gcm_identical_on_both_backends(monkeypatch, nonce_size, tag_length):
    key, nonce = _rand(RNG.choice((16, 24, 32))), _rand(nonce_size)
    pt, aad = _rand(RNG.randint(0, 300)), _rand(RNG.randint(0, 40))
    ct, tag = _on_both_backends(monkeypatch, aes.gcm_encrypt, key, nonce, pt, aad, tag_length)
    assert len(tag) == tag_length
    assert _on_both_backends(monkeypatch, aes.gcm_decrypt, key, nonce, ct, tag, aad) == pt
    forged = bytes([tag[0] ^ 0x80]) + tag[1:]
    assert _on_both_backends(monkeypatch, aes.gcm_decrypt, key, nonce, ct, forged, aad) is None


def test_backend_follows_the_environment_switch(monkeypatch):
    monkeypatch.setenv(PUREPY_ENV, "1")
    assert aes.backend() == "pure-python"
    monkeypatch.setenv(PUREPY_ENV, "0")
    pytest.importorskip("cryptography")
    assert aes.backend() == "cryptography"


def test_invalid_key_and_block_sizes_raise():
    for bad in (b"", bytes(15), bytes(20), bytes(33)):
        with pytest.raises(ValueError):
            aes.expand_key(bad)
    with pytest.raises(ValueError):
        aes.encrypt_block(bytes(16), bytes(15))
    with pytest.raises(ValueError):
        aes.cbc_decrypt(bytes(16), bytes(16), bytes(17))


# --------------------------------------------------------------------------- self-contained rule


def _secrets_modules():
    return sorted(path for path in SECRETS_DIR.glob("*.py") if path.name != "__init__.py")


def _module_level_imports(node):
    """Imports executed at import time: everywhere except inside function bodies."""
    for child in ast.iter_child_nodes(node):
        if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
            continue
        if isinstance(child, ast.Import):
            for alias in child.names:
                yield child, alias.name
        elif isinstance(child, ast.ImportFrom):
            yield child, child.module or ""
        yield from _module_level_imports(child)


@pytest.mark.parametrize("path", _secrets_modules() + [SECRETS_DIR / "__init__.py"], ids=lambda p: p.name)
def test_secrets_module_imports_only_stdlib_at_module_level(path):
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    for node, name in _module_level_imports(tree):
        assert getattr(node, "level", 0) == 0, "%s: relative import at line %d" % (path.name, node.lineno)
        assert name != "__future__", "%s: __future__ breaks pasting the file inline" % path.name
        top = name.split(".")[0]
        assert top in sys.stdlib_module_names, "%s imports non-stdlib %r at module level" % (path.name, name)


@pytest.mark.parametrize("path", _secrets_modules(), ids=lambda p: p.name)
def test_secrets_module_is_paste_safe_everywhere(path):
    """No relative import, no ``__file__``, and lazy imports only of stdlib or cryptography."""
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    for node in ast.walk(tree):
        if isinstance(node, ast.Name):
            assert node.id != "__file__", "%s uses __file__" % path.name
        if isinstance(node, ast.ImportFrom):
            assert node.level == 0, "%s: relative import at line %d" % (path.name, node.lineno)
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            names = [a.name for a in node.names] if isinstance(node, ast.Import) else [node.module]
            for name in names:
                top = name.split(".")[0]
                assert top in sys.stdlib_module_names or top == "cryptography", (
                    "%s imports %r" % (path.name, name))


STANDALONE_PRELUDE = r"""
import importlib.util, sys
for blocked in ("cryptography", "memdiver", "volatility3"):
    sys.modules[blocked] = None  # import of any of them now raises ImportError
spec = importlib.util.spec_from_file_location("pasted", sys.argv[1])
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
print(module.backend())
"""
STANDALONE_CHECKS = {  # module -> (driver lines printing results, expected stdout tokens)
    "aes.py": (
        'print(module.encrypt_block(bytes(range(16)), bytes.fromhex("00112233445566778899aabbccddeeff")).hex())\n'
        'print(module.xts_decrypt(bytes(32), 0, bytes.fromhex('
        '"917cf69ebd68b2ec9b9fe9a3eadda692cd43d2f59598ed858c02c2652fbf922e"), 32).hex())\n'
        'print(module.siv_encrypt(bytes.fromhex("fffefdfcfbfaf9f8f7f6f5f4f3f2f1f0f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff"), '
        'bytes.fromhex("112233445566778899aabbccddee"), '
        '[bytes.fromhex("101112131415161718191a1b1c1d1e1f2021222324252627")]).hex())\n',
        ["69c4e0d86a7b0430d8cdb78070b4c55a", "00" * 32,
         "85632d07c6e8f37f950acd320a2ecc9340c02b9690c4dc04daef7f6afe5c"],
    ),
    "chacha.py": (
        'print(module.hchacha20(bytes(range(32)), bytes.fromhex("000000090000004a0000000031415927")).hex())\n'
        'ct, tag = module.xchacha20_poly1305_encrypt(bytes(32), bytes(24), b"memdiver", b"aad")\n'
        'print(module.xchacha20_poly1305_decrypt(bytes(32), bytes(24), ct, tag, b"aad").decode())\n',
        ["82413b4227b27bfed30e42508a877d73a0f9e4d58a74a853c12ec41326d3ecdc", "memdiver"],
    ),
    "x25519.py": (
        'print(module.public_key(bytes.fromhex('
        '"77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a")).hex())\n',
        ["8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a"],
    ),
    "hkdf_midstate.py": (
        "states = module.fscrypt_v2_hkdf_midstates(bytes(range(1, 65)))\n"
        "print(module.fscrypt_v2_identifier_from_midstates(*states).hex())\n",
        ["69b2f6edeee720cce0577937eb8a6751"],
    ),
}


@pytest.mark.parametrize("module_name", sorted(STANDALONE_CHECKS))
def test_module_runs_alone_without_cryptography_or_memdiver(tmp_path, module_name):
    """A lone copy of the file in a fresh ``-I`` interpreter that cannot import cryptography."""
    driver, expected = STANDALONE_CHECKS[module_name]
    solo = tmp_path / "solo"
    solo.mkdir()
    copied = solo / ("copied_" + module_name)
    shutil.copy(SECRETS_DIR / module_name, copied)
    env = {key: value for key, value in os.environ.items() if key != PUREPY_ENV}
    result = subprocess.run(
        [sys.executable, "-I", "-c", STANDALONE_PRELUDE + driver, str(copied)],
        capture_output=True, text=True, cwd=str(solo), env=env, timeout=60,
    )
    assert result.returncode == 0, result.stderr
    assert result.stdout.split() == ["pure-python"] + expected


# --------------------------------------------------------------------------- independent references


@functools.lru_cache(maxsize=None)
def _reference_sbox():
    def xtime(a):
        return ((a << 1) ^ 0x1B) & 0xFF if a & 0x80 else a << 1

    def gmul(a, b):
        out = 0
        for _ in range(8):
            if b & 1:
                out ^= a
            a, b = xtime(a), b >> 1
        return out

    def inverse(a):
        return next((b for b in range(1, 256) if gmul(a, b) == 1), 0)

    def rotl(b, n):
        return ((b << n) | (b >> (8 - n))) & 0xFF

    def affine(b):
        return b ^ rotl(b, 1) ^ rotl(b, 2) ^ rotl(b, 3) ^ rotl(b, 4) ^ 0x63

    return tuple(affine(inverse(a)) for a in range(256))


def _reference_ecb_encrypt(key, block):
    ciphers = pytest.importorskip("cryptography.hazmat.primitives.ciphers")
    Cipher, algorithms, modes = ciphers.Cipher, ciphers.algorithms, ciphers.modes
    encryptor = Cipher(algorithms.AES(key), modes.ECB()).encryptor()
    return encryptor.update(block) + encryptor.finalize()


def _gf_mul(a, b):
    out = 0
    while b:
        if b & 1:
            out ^= a
        a = ((a << 1) ^ 0x11B) if a & 0x80 else a << 1
        b >>= 1
    return out


def _equivalent_inverse_decrypt(key_dec, block):
    """FIPS-197 5.3.5 EqInvCipher driven directly by the kernel ``key_dec`` bytes."""
    sbox = _reference_sbox()
    inv_sbox = [0] * 256
    for i, s in enumerate(sbox):
        inv_sbox[s] = i
    rounds = len(key_dec) // 16 - 1
    state = [b ^ k for b, k in zip(block, key_dec[:16])]
    for rnd in range(1, rounds + 1):
        state = [inv_sbox[b] for b in state]
        state = [state[(4 * ((c - r) % 4)) + r] for c in range(4) for r in range(4)]  # InvShiftRows
        if rnd < rounds:
            state = _inv_mix_columns(state)
        state = [b ^ k for b, k in zip(state, key_dec[16 * rnd: 16 * rnd + 16])]
    return bytes(state)


def _inv_mix_columns(state):
    out = []
    for c in range(4):
        a0, a1, a2, a3 = state[4 * c: 4 * c + 4]
        out += [
            _gf_mul(a0, 14) ^ _gf_mul(a1, 11) ^ _gf_mul(a2, 13) ^ _gf_mul(a3, 9),
            _gf_mul(a0, 9) ^ _gf_mul(a1, 14) ^ _gf_mul(a2, 11) ^ _gf_mul(a3, 13),
            _gf_mul(a0, 13) ^ _gf_mul(a1, 9) ^ _gf_mul(a2, 14) ^ _gf_mul(a3, 11),
            _gf_mul(a0, 11) ^ _gf_mul(a1, 13) ^ _gf_mul(a2, 9) ^ _gf_mul(a3, 14),
        ]
    return out
