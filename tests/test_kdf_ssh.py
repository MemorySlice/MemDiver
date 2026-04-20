"""Tests for SSH-2 KDF implementation (core/kdf_ssh.py)."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

import hashlib
import pytest
from core.kdf_ssh import SSH2KDF


class TestSSH2KDF:
    """Unit tests for RFC 4253 Section 7.2 key derivation."""

    def _sample_inputs(self):
        """Common test inputs."""
        shared_secret = bytes(range(32))
        exchange_hash = bytes(range(32, 64))
        session_id = bytes(range(64, 96))
        return shared_secret, exchange_hash, session_id

    def test_derive_key_deterministic(self):
        """Same inputs produce same output."""
        K, H, sid = self._sample_inputs()
        key1 = SSH2KDF.derive_key(K, H, "A", sid, 32)
        key2 = SSH2KDF.derive_key(K, H, "A", sid, 32)
        assert key1 == key2
        assert len(key1) == 32

    def test_derive_key_different_types(self):
        """Different X chars produce different keys."""
        K, H, sid = self._sample_inputs()
        keys = {c: SSH2KDF.derive_key(K, H, c, sid, 32) for c in "ABCDEF"}
        # All 6 should be unique
        assert len(set(keys.values())) == 6

    def test_derive_key_extension(self):
        """key_length > hash output triggers extension loop."""
        K, H, sid = self._sample_inputs()
        # SHA-256 produces 32 bytes; request 64 to force extension
        key = SSH2KDF.derive_key(K, H, "A", sid, 64)
        assert len(key) == 64
        # First 32 bytes should match the non-extended version
        short_key = SSH2KDF.derive_key(K, H, "A", sid, 32)
        assert key[:32] == short_key

    def test_derive_all_keys_returns_six(self):
        """derive_all_keys returns all 6 key types."""
        K, H, sid = self._sample_inputs()
        keys = SSH2KDF.derive_all_keys(K, H, sid)
        assert set(keys.keys()) == {"A", "B", "C", "D", "E", "F"}
        for char, key in keys.items():
            assert len(key) == 32
            # Each should match individual derivation
            assert key == SSH2KDF.derive_key(K, H, char, sid, 32)

    def test_mpint_encoding_no_high_bit(self):
        """mpint encoding without high-bit padding."""
        value = b"\x01\x02\x03"
        encoded = SSH2KDF._encode_mpint(value)
        assert encoded == b"\x00\x00\x00\x03\x01\x02\x03"

    def test_mpint_encoding_high_bit(self):
        """mpint encoding with high-bit requires zero-padding."""
        value = b"\x80\x01\x02"
        encoded = SSH2KDF._encode_mpint(value)
        assert encoded == b"\x00\x00\x00\x04\x00\x80\x01\x02"

    def test_mpint_encoding_empty(self):
        """mpint encoding of empty bytes."""
        encoded = SSH2KDF._encode_mpint(b"")
        assert encoded == b"\x00\x00\x00\x00"

    def test_derive_key_different_hash_algo(self):
        """SHA-384 produces longer initial hash (48 bytes)."""
        K, H, sid = self._sample_inputs()
        key = SSH2KDF.derive_key(K, H, "A", sid, 48, hash_algo="sha384")
        assert len(key) == 48


# ------------------------------------------------------------------ #
#  SSH2KDFPlugin tests
# ------------------------------------------------------------------ #

from core.kdf_ssh import SSH2KDFPlugin
from core.kdf_base import KDFParams
from core.models import CryptoSecret


class TestSSH2KDFPlugin:
    """Tests for the SSH2KDFPlugin (BaseKDF subclass)."""

    def test_ssh2_plugin_derive(self):
        """derive() produces deterministic output matching SSH2KDF."""
        plugin = SSH2KDFPlugin()
        secret = bytes(range(32))
        exchange_hash = bytes(range(32, 64))
        session_id = bytes(range(64, 96))
        params = KDFParams(
            context=exchange_hash,
            key_lengths=(32,),
            extra={"key_type_char": "C", "session_id": session_id},
        )
        result = plugin.derive(secret, params)
        expected = SSH2KDF.derive_key(secret, exchange_hash, "C", session_id, 32)
        assert result == expected
        assert len(result) == 32

    def test_ssh2_plugin_validate_pair_no_match(self):
        """Two unrelated random candidates return 0.0."""
        plugin = SSH2KDFPlugin()
        a = b"\xaa" * 32
        b = b"\xbb" * 32
        score = plugin.validate_pair(a, b, b"")
        assert score == 0.0

    def test_ssh2_plugin_expand_traffic_secret(self):
        """Expanding SSH2_SESSION_KEY produces 6 derived keys."""
        plugin = SSH2KDFPlugin()
        secret = CryptoSecret(
            secret_type="SSH2_SESSION_KEY",
            identifier=b"\x01" * 32,
            secret_value=bytes(range(32)),
            protocol="SSH",
        )
        derived = plugin.expand_traffic_secret(secret)
        assert len(derived) == 6
        names = {s.secret_type for s in derived}
        assert names == {
            "SSH2_IV_CS", "SSH2_IV_SC",
            "SSH2_ENCRYPTION_KEY_CS", "SSH2_ENCRYPTION_KEY_SC",
            "SSH2_INTEGRITY_KEY_CS", "SSH2_INTEGRITY_KEY_SC",
        }
        # All derived secrets should preserve the identifier
        for s in derived:
            assert s.identifier == b"\x01" * 32
            assert len(s.secret_value) == 32
            assert s.protocol == "SSH"

    def test_ssh2_plugin_supported_types(self):
        """supported_secret_types returns SSH2_SESSION_KEY."""
        plugin = SSH2KDFPlugin()
        assert plugin.supported_secret_types() == {"SSH2_SESSION_KEY"}
