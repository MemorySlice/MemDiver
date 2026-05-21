"""Tests for msl.crypto — AEAD, KDF, KEM, and CEK orchestration (spec §10)."""

import os

import pytest

from msl import crypto
from msl.enums import EncAlgo, KdfType, KeyEncap
from msl.types import MslAuthError, MslCryptoError

CEK_SIZE = crypto.CEK_SIZE

_AEAD_ALGOS = [EncAlgo.AES_256_GCM, EncAlgo.XCHACHA20_POLY1305]


# -- AEAD --

@pytest.mark.parametrize("algo", _AEAD_ALGOS, ids=lambda a: a.name)
def test_aead_roundtrip(algo):
    if not crypto.cipher_is_available(algo):
        pytest.skip(f"{algo.name} backend not installed")
    key = os.urandom(32)
    nonce = crypto.nonce_for_cipher(algo, crypto.random_nonce(algo))
    aad = b"file-header-and-kem-ct"
    plaintext = b"sensitive block stream" * 64
    blob = crypto.aead_encrypt(algo, key, nonce, aad, plaintext)
    assert blob != plaintext
    assert len(blob) == len(plaintext) + 16  # 16-byte tag appended
    assert crypto.aead_decrypt(algo, key, nonce, aad, blob) == plaintext


@pytest.mark.parametrize("algo", _AEAD_ALGOS, ids=lambda a: a.name)
def test_aead_wrong_aad_fails(algo):
    if not crypto.cipher_is_available(algo):
        pytest.skip(f"{algo.name} backend not installed")
    key = os.urandom(32)
    nonce = crypto.nonce_for_cipher(algo, crypto.random_nonce(algo))
    blob = crypto.aead_encrypt(algo, key, nonce, b"aad-A", b"data")
    with pytest.raises(MslAuthError):
        crypto.aead_decrypt(algo, key, nonce, b"aad-B", blob)


@pytest.mark.parametrize("algo", _AEAD_ALGOS, ids=lambda a: a.name)
def test_aead_tampered_ciphertext_fails(algo):
    if not crypto.cipher_is_available(algo):
        pytest.skip(f"{algo.name} backend not installed")
    key = os.urandom(32)
    nonce = crypto.nonce_for_cipher(algo, crypto.random_nonce(algo))
    blob = bytearray(crypto.aead_encrypt(algo, key, nonce, b"aad", b"data" * 8))
    blob[0] ^= 0xFF
    with pytest.raises(MslAuthError):
        crypto.aead_decrypt(algo, key, nonce, b"aad", bytes(blob))


@pytest.mark.parametrize("algo", _AEAD_ALGOS, ids=lambda a: a.name)
def test_aead_wrong_key_fails(algo):
    if not crypto.cipher_is_available(algo):
        pytest.skip(f"{algo.name} backend not installed")
    nonce = crypto.nonce_for_cipher(algo, crypto.random_nonce(algo))
    blob = crypto.aead_encrypt(algo, os.urandom(32), nonce, b"aad", b"data" * 8)
    with pytest.raises(MslAuthError):
        crypto.aead_decrypt(algo, os.urandom(32), nonce, b"aad", blob)


def test_random_nonce_sizes():
    n_aes = crypto.random_nonce(EncAlgo.AES_256_GCM)
    n_xc = crypto.random_nonce(EncAlgo.XCHACHA20_POLY1305)
    assert len(n_aes) == 24 and n_aes[12:] == b"\x00" * 12  # 12 used, rest zero
    assert len(n_xc) == 24
    assert len(crypto.nonce_for_cipher(EncAlgo.AES_256_GCM, n_aes)) == 12
    assert len(crypto.nonce_for_cipher(EncAlgo.XCHACHA20_POLY1305, n_xc)) == 24


# -- HKDF-BLAKE3 --

def test_hkdf_blake3_deterministic_and_salt_sensitive():
    ikm = b"shared-secret-from-kem"
    a = crypto.hkdf_blake3(ikm, salt=b"\x11" * 16, info=b"MSL-CEK-v1")
    b = crypto.hkdf_blake3(ikm, salt=b"\x11" * 16, info=b"MSL-CEK-v1")
    c = crypto.hkdf_blake3(ikm, salt=b"\x22" * 16, info=b"MSL-CEK-v1")
    assert a == b and len(a) == CEK_SIZE  # deterministic, 32 bytes
    assert a != c                          # salt changes the output


# -- Argon2id KDF --

@pytest.mark.skipif(not crypto.kdf_is_available(KdfType.ARGON2ID),
                    reason="argon2-cffi not installed")
def test_argon2id_passphrase_derivation():
    salt = os.urandom(16)
    k1 = crypto.derive_key_argon2id(b"correct horse", salt)
    k2 = crypto.derive_key_argon2id(b"correct horse", salt)
    k3 = crypto.derive_key_argon2id(b"correct horse", os.urandom(16))
    assert k1 == k2 and len(k1) == CEK_SIZE  # deterministic given salt
    assert k1 != k3                           # salt changes the key


@pytest.mark.skipif(not crypto.kdf_is_available(KdfType.ARGON2ID),
                    reason="argon2-cffi not installed")
def test_argon2id_enforces_minimum_params():
    """Requesting weaker-than-spec params is silently raised to the minimum,
    so the derived key matches the minimum-param derivation."""
    salt = os.urandom(16)
    weak = crypto.derive_key_argon2id(b"pw", salt, time_cost=1, memory_kib=8, lanes=1)
    floor = crypto.derive_key_argon2id(b"pw", salt, time_cost=3, memory_kib=65536, lanes=4)
    assert weak == floor


# -- X25519 KEM --

@pytest.mark.skipif(not crypto.kem_is_available(KeyEncap.X25519),
                    reason="cryptography not installed")
def test_x25519_kem_roundtrip():
    pub, priv = crypto.kem_generate_keypair(KeyEncap.X25519)
    assert len(pub) == 32 and len(priv) == 32
    kem_ct, ss_sender = crypto.kem_encapsulate(KeyEncap.X25519, pub)
    ss_recipient = crypto.kem_decapsulate(KeyEncap.X25519, priv, kem_ct)
    assert len(kem_ct) == 32
    assert ss_sender == ss_recipient  # both sides agree on the shared secret


# -- ML-KEM / hybrid (gated on liboqs-python) --

@pytest.mark.skipif(not crypto.kem_is_available(KeyEncap.ML_KEM_768),
                    reason="liboqs-python ([crypto] extra) not installed")
def test_mlkem768_kem_roundtrip():
    pub, priv = crypto.kem_generate_keypair(KeyEncap.ML_KEM_768)
    kem_ct, ss_sender = crypto.kem_encapsulate(KeyEncap.ML_KEM_768, pub)
    ss_recipient = crypto.kem_decapsulate(KeyEncap.ML_KEM_768, priv, kem_ct)
    assert len(kem_ct) == 1088
    assert ss_sender == ss_recipient


@pytest.mark.skipif(not crypto.kem_is_available(KeyEncap.X25519_ML_KEM_768),
                    reason="hybrid requires cryptography + liboqs-python")
def test_hybrid_kem_roundtrip():
    pub, priv = crypto.kem_generate_keypair(KeyEncap.X25519_ML_KEM_768)
    kem_ct, ss_sender = crypto.kem_encapsulate(KeyEncap.X25519_ML_KEM_768, pub)
    ss_recipient = crypto.kem_decapsulate(KeyEncap.X25519_ML_KEM_768, priv, kem_ct)
    assert len(kem_ct) == 1120          # 32 (X25519) + 1088 (ML-KEM-768)
    assert ss_sender == ss_recipient
    assert len(ss_sender) == 64          # x25519_ss(32) || mlkem_ss(32)


# -- CEK orchestration --

def test_cek_raw_key_passthrough():
    key = os.urandom(32)
    cek, kem_ct = crypto.derive_cek_producer(
        key_encap=KeyEncap.NONE, kdf_type=KdfType.NONE,
        dump_uuid_bytes=b"\x00" * 16, raw_key=key,
    )
    assert cek == key and kem_ct == b""
    recovered = crypto.derive_cek_consumer(
        key_encap=KeyEncap.NONE, kdf_type=KdfType.NONE,
        dump_uuid_bytes=b"\x00" * 16, raw_key=key,
    )
    assert recovered == key


def test_cek_raw_key_wrong_length_raises():
    with pytest.raises(MslCryptoError, match="32-byte raw key"):
        crypto.derive_cek_producer(
            key_encap=KeyEncap.NONE, kdf_type=KdfType.NONE,
            dump_uuid_bytes=b"\x00" * 16, raw_key=b"too-short",
        )


@pytest.mark.skipif(not crypto.kdf_is_available(KdfType.ARGON2ID),
                    reason="argon2-cffi not installed")
def test_cek_passphrase_producer_consumer_match():
    salt = os.urandom(16)
    common = dict(key_encap=KeyEncap.NONE, kdf_type=KdfType.ARGON2ID,
                  dump_uuid_bytes=b"\x00" * 16, passphrase=b"hunter2", kdf_salt=salt)
    cek_p, kem_ct = crypto.derive_cek_producer(**common)
    cek_c = crypto.derive_cek_consumer(**common)
    assert kem_ct == b"" and cek_p == cek_c and len(cek_p) == CEK_SIZE


@pytest.mark.skipif(not crypto.kem_is_available(KeyEncap.X25519),
                    reason="cryptography not installed")
def test_cek_x25519_producer_consumer_match():
    pub, priv = crypto.kem_generate_keypair(KeyEncap.X25519)
    dump_uuid = os.urandom(16)
    cek_p, kem_ct = crypto.derive_cek_producer(
        key_encap=KeyEncap.X25519, kdf_type=KdfType.NONE,
        dump_uuid_bytes=dump_uuid, recipient_public=pub,
    )
    cek_c = crypto.derive_cek_consumer(
        key_encap=KeyEncap.X25519, kdf_type=KdfType.NONE,
        dump_uuid_bytes=dump_uuid, recipient_private=priv, kem_ciphertext=kem_ct,
    )
    assert len(kem_ct) == 32 and cek_p == cek_c and len(cek_p) == CEK_SIZE


def test_unsupported_cipher_raises():
    with pytest.raises(MslCryptoError):
        crypto.aead_encrypt(0x99, b"\x00" * 32, b"\x00" * 12, b"", b"data")
