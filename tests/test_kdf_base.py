"""Tests for core.kdf_base — BaseKDF ABC and KDFParams."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

import pytest

from core.kdf_base import BaseKDF, KDFParams
from core.models import CryptoSecret


class _StubKDF(BaseKDF):
    """Concrete stub used to test instantiation."""

    name = "stub"
    protocol = "TEST"
    versions = {"1"}

    def derive(self, secret, params):
        return b"\x00" * 16

    def expand_traffic_secret(self, secret, key_lengths=None, hash_algo="sha256"):
        return []

    def validate_pair(self, a, b, dump, hash_algo="sha256"):
        return 0.0


def test_abc_cannot_instantiate():
    """BaseKDF cannot be instantiated directly."""
    with pytest.raises(TypeError):
        BaseKDF()


def test_stub_instantiation():
    """A concrete subclass can be instantiated and has correct attrs."""
    kdf = _StubKDF()
    assert kdf.name == "stub"
    assert kdf.protocol == "TEST"
    assert "1" in kdf.versions


def test_kdf_params_defaults():
    """KDFParams has sensible defaults."""
    p = KDFParams()
    assert p.hash_algo == "sha256"
    assert p.key_lengths == (16, 32)
    assert p.context == b""


def test_supported_secret_types_default():
    """Default supported_secret_types returns empty set."""
    kdf = _StubKDF()
    assert kdf.supported_secret_types() == set()


def test_repr():
    """Repr includes name and protocol."""
    kdf = _StubKDF()
    r = repr(kdf)
    assert "stub" in r
    assert "TEST" in r
