"""Tests for core.structure_library."""

import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from core.structure_defs import FieldDef, FieldType, StructureDef
from core.structure_library import StructureLibrary, get_structure_library


def test_register_and_get():
    """Register a custom struct and retrieve it by name."""
    lib = StructureLibrary()
    custom = StructureDef(
        name="custom_block",
        total_size=16,
        fields=(
            FieldDef("data", FieldType.BYTES, offset=0, size=16),
        ),
        protocol="TEST",
        tags=("test",),
    )
    lib.register(custom)
    result = lib.get("custom_block")
    assert result is not None
    assert result.name == "custom_block"
    assert result.protocol == "TEST"
    assert lib.get("nonexistent") is None


def test_list_all():
    """Built-in library contains >= 25 entries after polymorphic collapse."""
    lib = get_structure_library()
    assert len(lib.list_all()) >= 25


def test_list_by_protocol_tls():
    """Filtering by TLS protocol returns exactly 17 structures (12 TLS 1.3
    polymorphic + 4 TLS 1.2 + 1 boringssl experimental composite)."""
    lib = get_structure_library()
    tls = lib.list_by_protocol("TLS")
    assert len(tls) == 17
    names = {s.name for s in tls}
    for expected in (
        "tls13_client_handshake_traffic_secret",
        "tls13_server_handshake_traffic_secret",
        "tls12_master_secret",
        "tls12_key_block_aes128_gcm",
        "tls12_key_block_aes256_gcm",
        "boringssl_tls13_handshake_traffic_secrets_sha256",
    ):
        assert expected in names, f"Missing TLS struct: {expected}"


def test_list_by_tag():
    """The 'crypto' tag should cover plenty of built-ins."""
    lib = get_structure_library()
    crypto = lib.list_by_tag("crypto")
    assert len(crypto) >= 4


def test_builtins_present():
    """Verify all expected built-in names exist."""
    lib = get_structure_library()
    expected = [
        "tls13_handshake_secret",
        "tls13_master_secret",
        "tls13_client_application_traffic_secret_0",
        "tls12_master_secret",
        "tls12_key_block_aes128_gcm",
        "ssh2_session_id",
        "ssh2_exchange_hash",
        "aes256_key",
        "aes_gcm_iv",
    ]
    for name in expected:
        assert lib.get(name) is not None, f"Missing built-in: {name}"


def test_tls13_polymorphic_sizes():
    """Every tls13_* polymorphic struct has one BYTES field with
    size_choices=(48, 32) and not_zero constraint."""
    lib = get_structure_library()
    checked = 0
    for s in lib.list_all():
        if not s.name.startswith("tls13_"):
            continue
        if s.name.startswith("tls13_") and s.auto_offsets is False:
            # e.g. boringssl composite is not polymorphic
            continue
        assert len(s.fields) == 1, f"{s.name} should have exactly 1 field"
        f = s.fields[0]
        assert f.field_type == FieldType.BYTES
        assert f.size_choices == (48, 32), (
            f"{s.name} size_choices {f.size_choices} != (48, 32)"
        )
        assert f.constraints.get("not_zero") is True
        assert s.auto_offsets is True
        checked += 1
    assert checked == 12  # 12 TLS 1.3 polymorphic secrets


def test_tls12_key_block_sizes():
    """TLS 1.2 key blocks have correct total_size and 4 fields."""
    lib = get_structure_library()
    kb128 = lib.get("tls12_key_block_aes128_gcm")
    assert kb128 is not None
    assert kb128.total_size == 40
    assert len(kb128.fields) == 4

    kb256 = lib.get("tls12_key_block_aes256_gcm")
    assert kb256 is not None
    assert kb256.total_size == 72
    assert len(kb256.fields) == 4


def test_ssh2_polymorphic():
    """SSH-2 structures are collapsed to 2 polymorphic defs with hash probing."""
    lib = get_structure_library()
    for name in ("ssh2_session_id", "ssh2_exchange_hash"):
        s = lib.get(name)
        assert s is not None, f"Missing {name}"
        assert s.auto_offsets is True
        assert len(s.fields) == 1
        assert s.fields[0].size_choices == (64, 32, 20)


def test_boringssl_experimental_metadata():
    """The boringssl composite is marked experimental with library metadata."""
    lib = get_structure_library()
    s = lib.get("boringssl_tls13_handshake_traffic_secrets_sha256")
    assert s is not None
    assert s.stability == "experimental"
    assert s.library == "boringssl"
    assert s.library_version == "~1.x"
    assert len(s.fields) == 2
