"""Incremental AEAD encryptors equal the one-shot MSL AEAD (spec §10)."""

import os

import pytest

from memdiver.msl.aead_stream import aead_stream_encryptor, hchacha20
from memdiver.msl.crypto import (aead_decrypt, aead_encrypt, nonce_for_cipher,
                                 random_nonce)
from memdiver.msl.enums import EncAlgo
from memdiver.msl.types import MslCryptoError

ALGOS = [EncAlgo.AES_256_GCM, EncAlgo.XCHACHA20_POLY1305]


def _stream_encrypt(algo, key, nonce, aad, plaintext, step):
    sealer = aead_stream_encryptor(algo, key, nonce, aad)
    out = [sealer.update(plaintext[i:i + step])
           for i in range(0, len(plaintext), step)]
    return b"".join(out) + sealer.finalize()


@pytest.mark.parametrize("algo", ALGOS)
@pytest.mark.parametrize("length", [0, 1, 15, 16, 17, 63, 64, 65, 4099])
@pytest.mark.parametrize("step", [1, 7, 64, 1000])
def test_stream_matches_one_shot(algo, length, step):
    key = os.urandom(32)
    nonce = nonce_for_cipher(algo, random_nonce(algo))
    aad = os.urandom(length % 150)
    plaintext = os.urandom(length)
    streamed = _stream_encrypt(algo, key, nonce, aad, plaintext, step)
    assert streamed == aead_encrypt(algo, key, nonce, aad, plaintext)
    assert aead_decrypt(algo, key, nonce, aad, streamed) == plaintext


def test_hchacha20_test_vector():
    # draft-irtf-cfrg-xchacha-03 §2.2.1
    key = bytes(range(32))
    nonce = bytes.fromhex("000000090000004a0000000031415927")
    assert hchacha20(key, nonce).hex() == (
        "82413b4227b27bfed30e42508a877d73a0f9e4d58a74a853c12ec41326d3ecdc")


def test_bad_inputs_rejected():
    with pytest.raises(MslCryptoError):
        hchacha20(b"short", bytes(16))
    with pytest.raises(MslCryptoError):
        aead_stream_encryptor(EncAlgo.XCHACHA20_POLY1305, bytes(32), bytes(12), b"")
