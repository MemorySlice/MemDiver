"""Tests for TLS KDF plugins (TLS12KDF, TLS13KDF)."""

import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from core.kdf_base import KDFParams
from core.kdf_tls import TLS12KDF, TLS13KDF
from core.models import CryptoSecret


def test_tls12_derive():
    """TLS12KDF.derive produces deterministic output."""
    kdf = TLS12KDF()
    params = KDFParams(
        hash_algo="sha256",
        key_lengths=(48,),
        labels=(b"master secret",),
        context=b"\x00" * 64,
    )
    secret = os.urandom(48)
    result_a = kdf.derive(secret, params)
    result_b = kdf.derive(secret, params)
    assert result_a == result_b
    assert len(result_a) == 48
    assert result_a != secret


def test_tls12_validate_pair_no_match():
    """Two random 48-byte candidates return 0.0 confidence."""
    kdf = TLS12KDF()
    a = os.urandom(48)
    b = os.urandom(48)
    score = kdf.validate_pair(a, b, b"")
    assert score == 0.0


def test_tls12_expand_returns_empty():
    """TLS12KDF.expand_traffic_secret returns empty list."""
    kdf = TLS12KDF()
    secret = CryptoSecret(
        secret_type="MASTER_SECRET",
        identifier=b"\x00" * 32,
        secret_value=os.urandom(48),
    )
    result = kdf.expand_traffic_secret(secret)
    assert result == []


def test_tls13_derive():
    """TLS13KDF.derive produces deterministic output."""
    kdf = TLS13KDF()
    params = KDFParams(
        hash_algo="sha256",
        key_lengths=(32,),
        labels=("derived",),
        context=b"",
    )
    secret = os.urandom(32)
    result_a = kdf.derive(secret, params)
    result_b = kdf.derive(secret, params)
    assert result_a == result_b
    assert len(result_a) == 32
    assert result_a != secret


def test_tls13_validate_pair_no_match():
    """Two random 32-byte candidates return 0.0 confidence."""
    kdf = TLS13KDF()
    a = os.urandom(32)
    b = os.urandom(32)
    score = kdf.validate_pair(a, b, b"")
    assert score == 0.0


def test_tls13_expand_traffic_secret():
    """Expanding a traffic secret produces KEY_128, KEY_256, IV, FINISHED."""
    kdf = TLS13KDF()
    raw = os.urandom(32)
    secret = CryptoSecret(
        secret_type="CLIENT_TRAFFIC_SECRET_0",
        identifier=b"\x00" * 32,
        secret_value=raw,
    )
    derived = kdf.expand_traffic_secret(secret)
    assert len(derived) == 4

    types = [d.secret_type for d in derived]
    assert "CLIENT_TRAFFIC_SECRET_0_KEY_128" in types
    assert "CLIENT_TRAFFIC_SECRET_0_KEY_256" in types
    assert "CLIENT_TRAFFIC_SECRET_0_IV" in types
    assert "CLIENT_TRAFFIC_SECRET_0_FINISHED" in types

    # Check key sizes match expectations.
    by_type = {d.secret_type: d for d in derived}
    assert len(by_type["CLIENT_TRAFFIC_SECRET_0_KEY_128"].secret_value) == 16
    assert len(by_type["CLIENT_TRAFFIC_SECRET_0_KEY_256"].secret_value) == 32
    assert len(by_type["CLIENT_TRAFFIC_SECRET_0_IV"].secret_value) == 12
    assert len(by_type["CLIENT_TRAFFIC_SECRET_0_FINISHED"].secret_value) == 32

    # All derived secrets should preserve the identifier.
    for d in derived:
        assert d.identifier == secret.identifier
