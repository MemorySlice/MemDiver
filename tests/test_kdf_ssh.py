"""Tests for SSH-2 KDF implementation (core/kdf_ssh.py)."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

import hashlib
import pytest
from memdiver.core.kdf_ssh import SSH2KDF


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

from memdiver.core.kdf_ssh import SSH2KDFPlugin
from memdiver.core.kdf_base import KDFParams
from memdiver.core.models import CryptoSecret


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

    def test_ssh2_plugin_validate_pair_compares_at_peer_length(self):
        """validate_pair derives/compares at the PEER candidate's length.

        Regression: previously the probe always derived 32 bytes and compared
        at full length, so a related 20-byte (HMAC) or 16-byte (IV) output
        could never match -- a 32-byte derivation is never equal to a 20-byte
        candidate. This test pins the corrected length plumbing: for a 20-byte
        peer candidate, the value validate_pair derives in direction 1 is
        exactly 20 bytes (the peer's length), so a true 20-byte match is now
        representable. (The probe uses the peer as H/session_id, so a positive
        link is exercised end-to-end via the SSH probe-in-dump path in
        test_constraint_validator.)
        """
        plugin = SSH2KDFPlugin()
        a = bytes(range(32))
        b20 = b"\x07" * 20

        # The probe's direction-1 derivation must now produce a 20-byte value
        # (matching the peer), not a fixed 32-byte one.
        direction1 = SSH2KDF.derive_key(a, b20, "A", b20, len(b20))
        assert len(direction1) == 20
        # Old buggy length would have been 32 and could never equal a 20-byte b.
        assert len(SSH2KDF.derive_key(a, b20, "A", b20, 32)) == 32

        # Unrelated 32-vs-20 candidates still score 0 (no spurious truncation).
        assert plugin.validate_pair(a, b20, b"") == 0.0

    def test_ssh2_plugin_validate_pair_no_match_mixed_lengths(self):
        """Unrelated candidates of differing lengths return 0.0 (no crash)."""
        plugin = SSH2KDFPlugin()
        assert plugin.validate_pair(b"\xaa" * 32, b"\xbb" * 16, b"") == 0.0
        assert plugin.validate_pair(b"\xcc" * 20, b"\xdd" * 12, b"") == 0.0


# ------------------------------------------------------------------ #
#  Honest SSH-2 validation: discovery + H/session_id-driven pairing
# ------------------------------------------------------------------ #


class TestSSH2DiscoverHashCandidates:
    """Tests for SSH2KDFPlugin.discover_hash_candidates."""

    def test_keeps_hash_sized_not_zero_blobs(self):
        """Keeps 20/32/64-byte non-zero blobs (the SSH hash sizes)."""
        H = bytes(range(32, 64))         # 32 bytes (SHA-256)
        session_id = bytes(range(64, 96))  # 32 bytes
        sha1_blob = bytes(range(20))       # 20 bytes (SHA-1)
        sha512_blob = bytes(range(64))     # 64 bytes (SHA-512)
        found = SSH2KDFPlugin.discover_hash_candidates(
            [H, session_id, sha1_blob, sha512_blob]
        )
        assert H in found
        assert session_id in found
        assert sha1_blob in found
        assert sha512_blob in found

    def test_excludes_all_zero_blob(self):
        """All-zero blobs violate the not_zero constraint and are dropped."""
        H = bytes(range(1, 33))
        zero = b"\x00" * 32
        found = SSH2KDFPlugin.discover_hash_candidates([H, zero])
        assert H in found
        assert zero not in found

    def test_excludes_wrong_size_blobs(self):
        """Blobs whose length is not an SSH hash size are dropped."""
        H = bytes(range(1, 33))            # 32 -> kept
        wrong = bytes(range(1, 17))        # 16 -> dropped
        wrong2 = bytes(range(1, 49))       # 48 -> dropped
        found = SSH2KDFPlugin.discover_hash_candidates([H, wrong, wrong2])
        assert found == [H]

    def test_dedupes_preserving_order(self):
        """Duplicate blobs are removed, first-seen order preserved."""
        a = bytes(range(1, 33))
        b = bytes(range(33, 65))
        found = SSH2KDFPlugin.discover_hash_candidates([a, b, a, b])
        assert found == [a, b]

    def test_caps_count(self):
        """The result is capped at *cap*."""
        blobs = [bytes([i]) + bytes(range(1, 32)) for i in range(50)]
        found = SSH2KDFPlugin.discover_hash_candidates(blobs, cap=8)
        assert len(found) == 8


class TestSSH2ValidatePairHonest:
    """validate_pair with discovered H/session_id (the real fix)."""

    def _handshake(self):
        K = bytes(range(100, 132))           # shared secret
        H = bytes(range(32, 64))             # exchange hash (not zero, 32 bytes)
        session_id = bytes(range(64, 96))    # session_id (not zero, 32 bytes)
        derived = SSH2KDF.derive_all_keys(K, H, session_id, 32)
        return K, H, session_id, derived

    def test_validates_pair_with_hash_candidates(self):
        """K and a true derived key validate when H/session_id are supplied."""
        plugin = SSH2KDFPlugin()
        K, H, session_id, derived = self._handshake()
        score = plugin.validate_pair(
            K, derived["C"], b"", hash_candidates=[H, session_id]
        )
        assert score > 0.0
        assert score == plugin._CONFIDENCE

    def test_no_match_without_hash_candidates(self):
        """Honest 0.0 when no H/session_id are discovered (cannot validate)."""
        plugin = SSH2KDFPlugin()
        K, H, session_id, derived = self._handshake()
        assert plugin.validate_pair(K, derived["C"], b"") == 0.0
        assert plugin.validate_pair(
            K, derived["C"], b"", hash_candidates=[]
        ) == 0.0

    def test_no_false_positive_on_unrelated_blobs(self):
        """Two unrelated random 32-byte blobs return 0.0 even with candidates."""
        plugin = SSH2KDFPlugin()
        _, H, session_id, _ = self._handshake()
        a = b"\x11" * 32
        b = b"\x22" * 32
        assert plugin.validate_pair(
            a, b, b"", hash_candidates=[H, session_id]
        ) == 0.0

    def test_validates_via_dump_presence(self):
        """A derived value present in dump_data also confirms the link."""
        plugin = SSH2KDFPlugin()
        K, H, session_id, derived = self._handshake()
        # candidate_b is unrelated, but a real derived key sits in the dump.
        dump = b"\x00" * 16 + derived["D"] + b"\x00" * 16
        score = plugin.validate_pair(
            K, b"\x33" * 32, dump, hash_candidates=[H, session_id]
        )
        assert score == plugin._CONFIDENCE
