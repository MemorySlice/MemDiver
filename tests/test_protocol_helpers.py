"""Tests for protocol helper edge cases — deprecated_kwarg, registry lookup, backward compat."""

import sys
from dataclasses import dataclass
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from core.models import CryptoSecret, deprecated_kwarg
from core.protocols import ProtocolDescriptor, ProtocolRegistry, TLS_DESCRIPTOR
from core.discovery import DatasetInfo


# --- Test dataclass for deprecated_kwarg isolation ---

@dataclass
class _TestWidget:
    name: str
    value: int = 0

deprecated_kwarg(_TestWidget, "old_val", "value")


# --- deprecated_kwarg tests ---

def test_deprecated_kwarg_old_maps_to_new():
    w = _TestWidget(name="x", old_val=42)
    assert w.value == 42


def test_deprecated_kwarg_both_old_and_new_raises():
    """Providing both old and new kwarg raises TypeError (old stays as unexpected arg)."""
    import pytest
    with pytest.raises(TypeError):
        _TestWidget(name="x", old_val=10, value=99)


def test_deprecated_kwarg_positional_still_works():
    w = _TestWidget("hello", 7)
    assert w.name == "hello"
    assert w.value == 7


def test_deprecated_kwarg_default_applies():
    w = _TestWidget(name="x")
    assert w.value == 0


# --- ProtocolRegistry.lookup_label tests ---

def test_lookup_label_display():
    reg = ProtocolRegistry()
    reg.register(TLS_DESCRIPTOR)
    label = reg.lookup_label("CLIENT_RANDOM", "12", short=False)
    assert label == "Master Secret (via CLIENT_RANDOM)"


def test_lookup_label_short():
    reg = ProtocolRegistry()
    reg.register(TLS_DESCRIPTOR)
    label = reg.lookup_label("CLIENT_RANDOM", "12", short=True)
    assert label == "Master Secret"


def test_lookup_label_unknown_type():
    reg = ProtocolRegistry()
    reg.register(TLS_DESCRIPTOR)
    assert reg.lookup_label("NONEXISTENT", "12") is None


def test_lookup_label_cross_protocol():
    reg = ProtocolRegistry()
    reg.register(TLS_DESCRIPTOR)
    ssh = ProtocolDescriptor(
        name="SSH", versions=["2"],
        secret_types={"2": {"SESSION_KEY"}},
        dir_prefix="SSH",
        display_labels={("SESSION_KEY", "2"): "SSH Session Key"},
        short_labels={("SESSION_KEY", "2"): "Session"},
    )
    reg.register(ssh)
    assert reg.lookup_label("SESSION_KEY", "2") == "SSH Session Key"
    assert reg.lookup_label("CLIENT_RANDOM", "12") == "Master Secret (via CLIENT_RANDOM)"


# --- DatasetInfo backward compat tests ---

def test_dataset_info_tls_versions_getter():
    info = DatasetInfo(protocol_versions={"12", "13"})
    assert info.tls_versions == {"12", "13"}


def test_dataset_info_tls_versions_setter():
    info = DatasetInfo()
    info.tls_versions = {"12"}
    assert info.protocol_versions == {"12"}


# --- CryptoSecret.client_random setter ---

def test_crypto_secret_client_random_setter():
    s = CryptoSecret("T", b"\x00" * 32, b"\x01" * 32)
    s.client_random = b"\xff" * 32
    assert s.identifier == b"\xff" * 32


def test_crypto_secret_client_random_roundtrip():
    s = CryptoSecret("T", b"\x00" * 32, b"\x01" * 32)
    new_id = b"\xab" * 32
    s.client_random = new_id
    assert s.client_random == new_id
    assert s.identifier == new_id
