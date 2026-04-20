"""Tests for engine.verification — decryption verification module."""

import pytest
from engine.verification import (
    AesCbcVerifier,
    VerificationResult,
    extract_and_verify,
    VERIFICATION_PLAINTEXT,
    VERIFICATION_IV,
    VERIFIER_REGISTRY,
    HAS_CRYPTO,
)

pytestmark = pytest.mark.skipif(not HAS_CRYPTO, reason="cryptography not installed")


class TestAesCbcVerifier:
    def setup_method(self):
        self.verifier = AesCbcVerifier()
        self.key = bytes(range(32))
        self.ct = self.verifier.create_ciphertext(
            self.key, VERIFICATION_PLAINTEXT, VERIFICATION_IV
        )

    def test_cipher_name(self):
        assert self.verifier.cipher_name == "AES-256-CBC"

    def test_key_length(self):
        assert self.verifier.key_length == 32

    def test_verify_correct_key(self):
        assert self.verifier.verify(
            self.key, self.ct, VERIFICATION_IV, VERIFICATION_PLAINTEXT
        ) is True

    def test_verify_wrong_key(self):
        wrong = bytes(32)
        assert self.verifier.verify(
            wrong, self.ct, VERIFICATION_IV, VERIFICATION_PLAINTEXT
        ) is False

    def test_verify_short_key(self):
        assert self.verifier.verify(
            b"short", self.ct, VERIFICATION_IV, VERIFICATION_PLAINTEXT
        ) is False

    def test_create_ciphertext_wrong_key_length(self):
        with pytest.raises(ValueError):
            self.verifier.create_ciphertext(b"short", VERIFICATION_PLAINTEXT, VERIFICATION_IV)

    def test_roundtrip(self):
        """Encrypt then verify is True."""
        key = bytes(range(32, 64))
        ct = self.verifier.create_ciphertext(key, VERIFICATION_PLAINTEXT, VERIFICATION_IV)
        assert self.verifier.verify(key, ct, VERIFICATION_IV, VERIFICATION_PLAINTEXT) is True


class TestExtractAndVerify:
    def test_finds_key_in_dump(self):
        verifier = AesCbcVerifier()
        key = bytes(range(32))
        ct = verifier.create_ciphertext(key, VERIFICATION_PLAINTEXT, VERIFICATION_IV)
        # Place key at offset 0x100 in a 1KB dump
        dump = bytearray(1024)
        dump[0x100:0x120] = key
        result = extract_and_verify(dump, [0x100], ct)
        assert result is not None
        assert result.offset == 0x100
        assert result.verified is True
        assert result.key_hex == key.hex()

    def test_skips_wrong_offsets(self):
        verifier = AesCbcVerifier()
        key = bytes(range(32))
        ct = verifier.create_ciphertext(key, VERIFICATION_PLAINTEXT, VERIFICATION_IV)
        dump = bytearray(1024)
        dump[0x100:0x120] = key
        # Try wrong offsets first, correct one last
        result = extract_and_verify(dump, [0x000, 0x080, 0x100], ct)
        assert result is not None
        assert result.offset == 0x100

    def test_returns_none_no_match(self):
        verifier = AesCbcVerifier()
        key = bytes(range(32))
        ct = verifier.create_ciphertext(key, VERIFICATION_PLAINTEXT, VERIFICATION_IV)
        dump = bytearray(1024)  # key not in dump
        result = extract_and_verify(dump, [0x000, 0x100], ct)
        assert result is None

    def test_handles_offset_past_end(self):
        dump = bytearray(64)
        result = extract_and_verify(dump, [0x100], b"ct")
        assert result is None


class TestVerifierRegistry:
    def test_aes_in_registry(self):
        assert "AES-256-CBC" in VERIFIER_REGISTRY

    def test_registry_verifier_works(self):
        v = VERIFIER_REGISTRY["AES-256-CBC"]
        key = bytes(range(32))
        ct = v.create_ciphertext(key, VERIFICATION_PLAINTEXT, VERIFICATION_IV)
        assert v.verify(key, ct, VERIFICATION_IV, VERIFICATION_PLAINTEXT) is True
