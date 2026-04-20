"""Tests for core.protocols module.

Covers ProtocolDescriptor, ProtocolRegistry, TLS registration,
and label lookups via the registry.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from core.protocols import REGISTRY, ProtocolDescriptor, ProtocolRegistry, TLS_DESCRIPTOR


def test_tls_descriptor_name():
    """TLS descriptor has correct name."""
    assert TLS_DESCRIPTOR.name == "TLS"


def test_tls_descriptor_versions():
    """TLS descriptor lists versions 12 and 13."""
    assert "12" in TLS_DESCRIPTOR.versions
    assert "13" in TLS_DESCRIPTOR.versions


def test_tls_descriptor_dir_prefix():
    """TLS descriptor dir_prefix is 'TLS'."""
    assert TLS_DESCRIPTOR.dir_prefix == "TLS"


def test_tls_descriptor_secret_types():
    """TLS 1.2 has CLIENT_RANDOM; TLS 1.3 has 5 secret types."""
    assert "CLIENT_RANDOM" in TLS_DESCRIPTOR.secret_types["12"]
    assert len(TLS_DESCRIPTOR.secret_types["13"]) == 5
    assert "EXPORTER_SECRET" in TLS_DESCRIPTOR.secret_types["13"]


def test_tls_descriptor_all_secret_types():
    """all_secret_types() returns union of all versions."""
    all_types = TLS_DESCRIPTOR.all_secret_types()
    assert "CLIENT_RANDOM" in all_types
    assert "EXPORTER_SECRET" in all_types
    assert len(all_types) == 6


def test_tls_descriptor_display_label():
    """Display label lookup for known type returns correct string."""
    label = TLS_DESCRIPTOR.get_display_label("CLIENT_RANDOM", "12")
    assert label == "Master Secret (via CLIENT_RANDOM)"


def test_tls_descriptor_display_label_unknown():
    """Display label lookup for unknown type returns None."""
    assert TLS_DESCRIPTOR.get_display_label("UNKNOWN", "99") is None


def test_tls_descriptor_short_label():
    """Short label lookup for known type returns correct string."""
    label = TLS_DESCRIPTOR.get_short_label("EXPORTER_SECRET", "13")
    assert label == "Exporter"


def test_registry_singleton_has_tls():
    """Module-level REGISTRY has TLS registered."""
    assert "TLS" in REGISTRY.list_protocols()


def test_registry_get():
    """REGISTRY.get('TLS') returns TLS_DESCRIPTOR."""
    desc = REGISTRY.get("TLS")
    assert desc is TLS_DESCRIPTOR


def test_registry_get_unknown():
    """REGISTRY.get() for unknown protocol returns None."""
    assert REGISTRY.get("WPA") is None


def test_registry_get_by_dir_prefix():
    """get_by_dir_prefix('TLS') returns TLS descriptor."""
    desc = REGISTRY.get_by_dir_prefix("TLS")
    assert desc is TLS_DESCRIPTOR


def test_registry_get_by_dir_prefix_unknown():
    """get_by_dir_prefix for unknown prefix returns None."""
    assert REGISTRY.get_by_dir_prefix("WPA") is None


def test_registry_register_custom():
    """Register and retrieve a custom protocol descriptor."""
    reg = ProtocolRegistry()
    custom = ProtocolDescriptor(
        name="SSH",
        versions=["2"],
        secret_types={"2": {"SESSION_KEY"}},
        dir_prefix="SSH",
    )
    reg.register(custom)
    assert "SSH" in reg.list_protocols()
    assert reg.get("SSH") is custom
