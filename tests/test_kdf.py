"""Tests for core.kdf module.

Covers TLS12PRF and TLS13HKDF with RFC 5869 test vectors and
determinism/boundary checks.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from core.kdf import TLS12PRF, TLS13HKDF


# -- RFC 5869 Appendix A Test Case 1 vectors --

_RFC5869_IKM = bytes.fromhex("0b" * 22)
_RFC5869_SALT = bytes(range(13))  # 0x00..0x0c
_RFC5869_PRK = bytes.fromhex(
    "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5"
)
_RFC5869_INFO = bytes(range(0xF0, 0xFA))  # 0xf0..0xf9
_RFC5869_OKM = bytes.fromhex(
    "3cb25f25faacd57a90434f64d0362f2a"
    "2d2d0a90cf1a5a4c5db02d56ecc4c5bf"
    "34007208d5b887185865"
)


def test_hkdf_extract_rfc5869():
    """HKDF-Extract with RFC 5869 Test Case 1 inputs produces expected PRK."""
    prk = TLS13HKDF.hkdf_extract(salt=_RFC5869_SALT, ikm=_RFC5869_IKM, hash_algo="sha256")
    assert prk == _RFC5869_PRK


def test_hkdf_expand_rfc5869():
    """HKDF-Expand with RFC 5869 Test Case 1 PRK and info produces expected OKM."""
    okm = TLS13HKDF.hkdf_expand(prk=_RFC5869_PRK, info=_RFC5869_INFO, length=42, hash_algo="sha256")
    assert okm == _RFC5869_OKM


def test_hkdf_extract_empty_salt():
    """Empty salt uses zero-padded salt of hash length (32 bytes for sha256)."""
    prk_empty = TLS13HKDF.hkdf_extract(salt=b"", ikm=_RFC5869_IKM, hash_algo="sha256")
    prk_zeros = TLS13HKDF.hkdf_extract(salt=b"\x00" * 32, ikm=_RFC5869_IKM, hash_algo="sha256")
    assert prk_empty == prk_zeros
    assert len(prk_empty) == 32


def test_hkdf_expand_max_length_ok():
    """Requesting exactly 255 * hash_len bytes succeeds without error."""
    max_len = 255 * 32  # 8160 bytes for sha256
    okm = TLS13HKDF.hkdf_expand(prk=_RFC5869_PRK, info=b"", length=max_len, hash_algo="sha256")
    assert len(okm) == max_len


def test_hkdf_expand_exceeds_max():
    """Requesting more than 255 * hash_len bytes raises ValueError."""
    too_long = 255 * 32 + 1
    try:
        TLS13HKDF.hkdf_expand(prk=_RFC5869_PRK, info=b"", length=too_long, hash_algo="sha256")
        assert False, "Expected ValueError was not raised"
    except ValueError:
        pass


def test_tls12_prf_deterministic():
    """TLS 1.2 PRF is deterministic and derive_master_secret returns 48 bytes."""
    pms = b"\xab" * 48
    client_random = b"\x01" * 32
    server_random = b"\x02" * 32
    ms1 = TLS12PRF.derive_master_secret(pms, client_random, server_random)
    ms2 = TLS12PRF.derive_master_secret(pms, client_random, server_random)
    assert ms1 == ms2
    assert len(ms1) == 48


def test_tls12_derive_key_block():
    """derive_key_block returns the requested number of bytes."""
    master_secret = b"\xcc" * 48
    server_random = b"\x03" * 32
    client_random = b"\x04" * 32
    for length in (72, 104, 128):
        kb = TLS12PRF.derive_key_block(master_secret, server_random, client_random, length)
        assert len(kb) == length


def test_tls13_expand_label_deterministic():
    """hkdf_expand_label with fixed inputs produces deterministic output."""
    secret = b"\xdd" * 32
    label = "derived"
    context = b""
    out1 = TLS13HKDF.hkdf_expand_label(secret, label, context, 32, hash_algo="sha256")
    out2 = TLS13HKDF.hkdf_expand_label(secret, label, context, 32, hash_algo="sha256")
    assert out1 == out2
    assert len(out1) == 32


def test_tls13_derive_secret():
    """derive_secret returns hash-length (32 for sha256) output."""
    secret = b"\xee" * 32
    label = "c hs traffic"
    messages_hash = b"\xff" * 32
    result = TLS13HKDF.derive_secret(secret, label, messages_hash, hash_algo="sha256")
    assert len(result) == 32
    # Deterministic check
    result2 = TLS13HKDF.derive_secret(secret, label, messages_hash, hash_algo="sha256")
    assert result == result2
