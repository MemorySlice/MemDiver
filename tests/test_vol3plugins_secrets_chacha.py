"""Tests for vol3plugins/linux/secrets/chacha.py (the pure-Python XChaCha20-Poly1305 tier).

Known-answer tests come from RFC 8439 (sections 2.3.2, 2.5.2, 2.8.2 and Appendix A.5) and
draft-irtf-cfrg-xchacha-03 (sections 2.2.1 and A.3.1).  The randomized differential tests
seal with ``cryptography`` 46.x and pycryptodome 3.x and require this module to agree byte
for byte, and every backend to reject the same tampered inputs.
"""

import os
import random
import struct

import pytest

from memdiver.vol3plugins.linux.secrets import chacha
from tests._oracle_gocryptfs_fixtures import hchacha20_ref

RNG = random.Random(0xC4AC4A)
LADIES = (
    "4c616469657320616e642047656e746c656d656e206f662074686520636c6173"
    "73206f66202739393a204966204920636f756c64206f6666657220796f75206f"
    "6e6c79206f6e652074697020666f7220746865206675747572652c2073756e73"
    "637265656e20776f756c642062652069742e"
)
KEY_80 = "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f"
AAD_50 = "50515253c0c1c2c3c4c5c6c7"


def _rand(size):
    return bytes(RNG.getrandbits(8) for _ in range(size))


def _flip(data, index=0):
    return data[:index] + bytes([data[index] ^ 1]) + data[index + 1:]


# --------------------------------------------------------------------------- known answers


def test_backend_is_always_pure_python():
    assert chacha.backend() == "pure-python"


def test_rfc8439_2_3_2_block_function():
    block = chacha.chacha20_block(bytes(range(32)), 1, bytes.fromhex("000000090000004a00000000"))
    assert block.hex() == (
        "10f1e7e4d13b5915500fdd1fa32071c4c7d1f4c733c068030422aa9ac3d46c4e"
        "d2826446079faa0914c2d705d98b02a2b5129cd1de164eb9cbd083e8a2503c4e")


def test_rfc8439_2_5_2_poly1305():
    key = bytes.fromhex("85d6be7857556d337f4452fe42d506a80103808afb0db2fd4abff6af4149f51b")
    tag = chacha.poly1305_mac(key, b"Cryptographic Forum Research Group")
    assert tag.hex() == "a8061dc1305136c6c22b8baf0c0127a9"


def test_rfc8439_2_8_2_aead_encrypt_and_decrypt():
    key, nonce = bytes.fromhex(KEY_80), bytes.fromhex("070000004041424344454647")
    aad, pt = bytes.fromhex(AAD_50), bytes.fromhex(LADIES)
    ct = bytes.fromhex(
        "d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d6"
        "3dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b36"
        "92ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc"
        "3ff4def08e4b7a9de576d26586cec64b6116")
    tag = bytes.fromhex("1ae10b594f09e26a7e902ecbd0600691")
    assert chacha.chacha20_poly1305_encrypt(key, nonce, pt, aad) == (ct, tag)
    assert chacha.chacha20_poly1305_decrypt(key, nonce, ct, tag, aad) == pt


def test_rfc8439_a5_aead_decryption():
    key = bytes.fromhex("1c9240a5eb55d38af333888604f6b5f0473917c1402b80099dca5cbc207075c0")
    nonce, aad = bytes.fromhex("000000000102030405060708"), bytes.fromhex("f33388860000000000004e91")
    ct = bytes.fromhex(
        "64a0861575861af460f062c79be643bd5e805cfd345cf389f108670ac76c8cb2"
        "4c6cfc18755d43eea09ee94e382d26b0bdb7b73c321b0100d4f03b7f355894cf"
        "332f830e710b97ce98c8a84abd0b948114ad176e008d33bd60f982b1ff37c855"
        "9797a06ef4f0ef61c186324e2b3506383606907b6a7c02b0f9f6157b53c867e4"
        "b9166c767b804d46a59b5216cde7a4e99040c5a40433225ee282a1b0a06c523e"
        "af4534d7f83fa1155b0047718cbc546a0d072b04b3564eea1b422273f548271a"
        "0bb2316053fa76991955ebd63159434ecebb4e466dae5a1073a6727627097a10"
        "49e617d91d361094fa68f0ff77987130305beaba2eda04df997b714d6c6f2c29"
        "a6ad5cb4022b02709b")
    tag = bytes.fromhex("eead9d67890cbb22392336fea1851f38")
    plaintext = chacha.chacha20_poly1305_decrypt(key, nonce, ct, tag, aad)
    assert plaintext == (
        "Internet-Drafts are draft documents valid for a maximum of six months and may be "
        "updated, replaced, or obsoleted by other documents at any time. It is inappropriate "
        "to use Internet-Drafts as reference material or to cite them other than as "
        "/\u201cwork in progress./\u201d").encode("utf-8")
    assert chacha.chacha20_poly1305_decrypt(key, nonce, ct, _flip(tag), aad) is None


def test_xchacha_draft_2_2_1_hchacha20():
    nonce = bytes.fromhex("000000090000004a0000000031415927")
    subkey = chacha.hchacha20(bytes(range(32)), nonce)
    assert subkey.hex() == "82413b4227b27bfed30e42508a877d73a0f9e4d58a74a853c12ec41326d3ecdc"


def test_xchacha_draft_a_3_1_aead():
    key, aad, pt = bytes.fromhex(KEY_80), bytes.fromhex(AAD_50), bytes.fromhex(LADIES)
    nonce = bytes.fromhex("404142434445464748494a4b4c4d4e4f5051525354555657")
    ct = bytes.fromhex(
        "bd6d179d3e83d43b9576579493c0e939572a1700252bfaccbed2902c21396cbb"
        "731c7f1b0b4aa6440bf3a82f4eda7e39ae64c6708c54c216cb96b72e1213b452"
        "2f8c9ba40db5d945b11b69b982c1bb9e3f3fac2bc369488f76b2383565d3fff9"
        "21f9664c97637da9768812f615c68b13b52e")
    tag = bytes.fromhex("c0875924c1c7987947deafd8780acf49")
    assert chacha.xchacha20_poly1305_encrypt(key, nonce, pt, aad) == (ct, tag)
    assert chacha.xchacha20_poly1305_decrypt(key, nonce, ct, tag, aad) == pt


# --------------------------------------------------------------------------- differential


def _cryptography_chacha():
    aead = pytest.importorskip("cryptography.hazmat.primitives.ciphers.aead")
    return aead.ChaCha20Poly1305


def _pycryptodome_chacha():
    return pytest.importorskip("Crypto.Cipher.ChaCha20_Poly1305")


def _cases():
    """(key, plaintext, aad) for plaintext lengths 0..300 with random AAD lengths."""
    for length in range(301):
        yield _rand(32), _rand(length), _rand(RNG.choice((0, 1, 15, 16, 17, 24, 40)))


def test_chacha20_poly1305_matches_cryptography_and_pycryptodome():
    reference_cls, pycryptodome = _cryptography_chacha(), _pycryptodome_chacha()
    for key, pt, aad in _cases():
        nonce = _rand(12)
        sealed = reference_cls(key).encrypt(nonce, pt, aad)
        engine = pycryptodome.new(key=key, nonce=nonce)
        engine.update(aad)
        assert engine.encrypt_and_digest(pt) == (sealed[:-16], sealed[-16:])
        assert chacha.chacha20_poly1305_encrypt(key, nonce, pt, aad) == (sealed[:-16], sealed[-16:])
        assert chacha.chacha20_poly1305_decrypt(key, nonce, sealed[:-16], sealed[-16:], aad) == pt


def test_xchacha20_poly1305_matches_cryptography_and_pycryptodome():
    """cryptography has no XChaCha: HChaCha20 (textbook copy in the fixtures) + its ChaCha20Poly1305."""
    reference_cls, pycryptodome = _cryptography_chacha(), _pycryptodome_chacha()
    for key, pt, aad in _cases():
        nonce = _rand(24)
        subkey = hchacha20_ref(key, nonce[:16])
        sealed = reference_cls(subkey).encrypt(b"\x00" * 4 + nonce[16:], pt, aad)
        engine = pycryptodome.new(key=key, nonce=nonce)
        engine.update(aad)
        assert engine.encrypt_and_digest(pt) == (sealed[:-16], sealed[-16:])
        assert chacha.xchacha20_poly1305_encrypt(key, nonce, pt, aad) == (sealed[:-16], sealed[-16:])
        assert chacha.xchacha20_poly1305_decrypt(key, nonce, sealed[:-16], sealed[-16:], aad) == pt


def _tampered(ct, tag, aad):
    """(ct, tag, aad) variants that must never authenticate."""
    yield ct, _flip(tag, 15), aad
    if ct:
        yield _flip(ct, len(ct) // 2), tag, aad
    yield ct, tag, aad + b"\x00"
    if aad:
        yield ct, tag, _flip(aad)


def test_tampered_inputs_are_rejected_by_every_backend():
    reference_cls, pycryptodome = _cryptography_chacha(), _pycryptodome_chacha()
    invalid_tag = pytest.importorskip("cryptography.exceptions").InvalidTag
    for key, pt, aad in list(_cases())[::7]:
        nonce = _rand(24)
        ct, tag = chacha.xchacha20_poly1305_encrypt(key, nonce, pt, aad)
        subkey, inner = hchacha20_ref(key, nonce[:16]), b"\x00" * 4 + nonce[16:]
        for bad_ct, bad_tag, bad_aad in _tampered(ct, tag, aad):
            assert chacha.xchacha20_poly1305_decrypt(key, nonce, bad_ct, bad_tag, bad_aad) is None
            with pytest.raises(invalid_tag):
                reference_cls(subkey).decrypt(inner, bad_ct + bad_tag, bad_aad)
            engine = pycryptodome.new(key=key, nonce=nonce)
            engine.update(bad_aad)
            with pytest.raises(ValueError):
                engine.decrypt_and_verify(bad_ct, bad_tag)


def test_wrong_key_is_rejected_before_any_decryption(monkeypatch):
    key, nonce = _rand(32), _rand(24)
    ct, tag = chacha.xchacha20_poly1305_encrypt(key, nonce, b"x" * 149, b"aad")

    def refuse(*_args):
        raise AssertionError("keystream computed for an unauthenticated ciphertext")

    monkeypatch.setattr(chacha, "chacha20_xor", refuse)
    assert chacha.xchacha20_poly1305_decrypt(_rand(32), nonce, ct, tag, b"aad") is None
    with pytest.raises(AssertionError):
        chacha.xchacha20_poly1305_decrypt(key, nonce, ct, tag, b"aad")


@pytest.mark.parametrize("call", [
    lambda: chacha.chacha20_block(bytes(31), 0, bytes(12)),
    lambda: chacha.chacha20_block(bytes(32), 0, bytes(8)),
    lambda: chacha.chacha20_block(bytes(32), 1 << 32, bytes(12)),
    lambda: chacha.chacha20_xor(bytes(32), (1 << 32) - 1, bytes(12), bytes(65)),
    lambda: chacha.hchacha20(bytes(32), bytes(12)),
    lambda: chacha.poly1305_mac(bytes(16), b""),
    lambda: chacha.xchacha20_poly1305_decrypt(bytes(32), bytes(12), b"", bytes(16)),
    lambda: chacha.chacha20_poly1305_decrypt(bytes(32), bytes(12), b"", bytes(15)),
])
def test_bad_parameters_raise_value_error(call):
    with pytest.raises(ValueError):
        call()


def test_poly1305_wraps_modulo_2_130_minus_5():
    """With r = 0 the accumulator stays 0, so the tag is s for any message."""
    s = struct.pack("<QQ", 0x0123456789ABCDEF, 0xFEDCBA9876543210)
    assert chacha.poly1305_mac(bytes(16) + s, os.urandom(77)) == s
