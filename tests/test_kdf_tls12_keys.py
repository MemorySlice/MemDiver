"""Tests for TLS 1.2 key-block derivation (core.kdf_tls.derive_tls12_keys).

Verifies the cipher-suite geometry table and that derived write keys actually
decrypt records produced by the C1 AEAD verifiers — the round-trip the pcap
oracle (Workstream P) relies on.
"""

import pytest

from memdiver.core.kdf_tls import (
    TLS12_CIPHER_SUITES,
    Tls12Keys,
    derive_tls12_keys,
    resolve_tls12_suite,
)
from memdiver.engine.verification import HAS_CRYPTO, VERIFIER_REGISTRY

MS = bytes(range(48))            # a stand-in 48-byte master secret
CLIENT_RANDOM = bytes(range(32))
SERVER_RANDOM = bytes(range(32, 64))


class TestSuiteTable:
    def test_resolve_by_code(self):
        p = resolve_tls12_suite(0xC02F)
        assert p.name == "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"
        assert (p.enc_key_len, p.fixed_iv_len, p.mac_key_len) == (16, 4, 0)

    def test_resolve_by_name(self):
        p = resolve_tls12_suite("TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384")
        assert p.enc_key_len == 32 and p.prf_hash == "sha384"

    def test_unknown_suite_raises(self):
        with pytest.raises(KeyError):
            resolve_tls12_suite(0xDEAD)

    def test_every_suite_names_a_real_verifier(self):
        for p in TLS12_CIPHER_SUITES.values():
            assert p.verifier in VERIFIER_REGISTRY


class TestDeriveKeyBlockGeometry:
    def test_gcm_key_lengths(self):
        keys = derive_tls12_keys(MS, CLIENT_RANDOM, SERVER_RANDOM, 0xC02F)
        assert isinstance(keys, Tls12Keys)
        assert len(keys.client_write_key) == 16
        assert len(keys.server_write_key) == 16
        assert len(keys.client_write_iv) == 4   # GCM salt
        assert len(keys.server_write_iv) == 4
        assert keys.client_mac_key == b""        # AEAD → no MAC key
        # client/server material must differ
        assert keys.client_write_key != keys.server_write_key

    def test_cbc_key_block_includes_mac_keys(self):
        keys = derive_tls12_keys(MS, CLIENT_RANDOM, SERVER_RANDOM, 0xC013)  # AES-128-CBC-SHA
        assert len(keys.client_write_key) == 16
        assert len(keys.client_mac_key) == 20    # SHA-1 HMAC key
        assert len(keys.server_mac_key) == 20
        assert keys.client_write_iv == b""       # CBC IV is explicit per record


@pytest.mark.skipif(not HAS_CRYPTO, reason="cryptography not installed")
class TestRoundTripThroughVerifier:
    """The derived write key must decrypt a record it encrypted (GCM)."""

    @pytest.mark.parametrize("code", [0xC02F, 0xC030, 0xCCA8])
    def test_derived_key_decrypts_gcm_record(self, code):
        keys = derive_tls12_keys(MS, CLIENT_RANDOM, SERVER_RANDOM, code)
        verifier = VERIFIER_REGISTRY[keys.suite.verifier]
        plaintext = b"GET / HTTP/1.1\r\n\r\n"
        # 12-byte AEAD nonce = fixed salt/iv || explicit nonce (pad to 12)
        nonce = (keys.client_write_iv + bytes(12))[:12]
        aad = b"\x17\x03\x03\x00\x20"  # a plausible TLS1.2 app-data record header
        blob = verifier.create_ciphertext(
            keys.client_write_key, plaintext, b"", nonce=nonce, aad=aad
        )
        assert verifier.verify(
            keys.client_write_key, blob, b"", None, nonce=nonce, aad=aad
        ) is True
        # wrong server key must not validate
        assert verifier.verify(
            keys.server_write_key, blob, b"", None, nonce=nonce, aad=aad
        ) is False
