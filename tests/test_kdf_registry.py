"""Tests for core.kdf_registry — KDF auto-discovery and lookup."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from core.kdf_registry import KDFRegistry, get_kdf_registry


def _fresh_registry():
    """Create and populate a fresh registry (bypasses singleton)."""
    reg = KDFRegistry()
    reg.discover()
    return reg


def test_discover_finds_kdfs():
    """Auto-discovery finds at least TLS12, TLS13, and SSH2 plugins."""
    reg = _fresh_registry()
    names = {k.name for k in reg.list_all()}
    assert "tls12_prf" in names
    assert "tls13_hkdf" in names
    assert "ssh2" in names


def test_get_by_name():
    """Lookup by name returns the correct plugin."""
    reg = _fresh_registry()
    kdf = reg.get("tls13_hkdf")
    assert kdf is not None
    assert kdf.protocol == "TLS"


def test_get_for_protocol_tls13():
    """get_for_protocol finds the TLS 1.3 KDF."""
    reg = _fresh_registry()
    kdf = reg.get_for_protocol("TLS", "13")
    assert kdf is not None
    assert kdf.name == "tls13_hkdf"


def test_get_for_protocol_ssh2():
    """get_for_protocol finds the SSH 2 KDF."""
    reg = _fresh_registry()
    kdf = reg.get_for_protocol("SSH", "2")
    assert kdf is not None
    assert kdf.name == "ssh2"


def test_unknown_protocol_returns_none():
    """Unknown protocol/version returns None."""
    reg = _fresh_registry()
    assert reg.get_for_protocol("WPA", "2") is None


def test_get_unknown_name_returns_none():
    """Unknown name returns None."""
    reg = _fresh_registry()
    assert reg.get("nonexistent") is None
