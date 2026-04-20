"""Tests for msl/key_extract.py — MSL key hint to CryptoSecret conversion."""

import sys
import tempfile
from pathlib import Path
from uuid import UUID

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import pytest
from msl.enums import MslKeyType, MslProtocol, Confidence, KeyState
from msl.key_extract import (
    extract_key_bytes,
    extract_secrets_from_msl,
    extract_secrets_from_path,
    map_key_type,
    map_protocol,
)
from msl.reader import MslReader
from tests.fixtures.generate_msl_fixtures import generate_msl_file


@pytest.fixture
def msl_path(tmp_path):
    p = tmp_path / "test.msl"
    p.write_bytes(generate_msl_file())
    return p


# -- map_key_type tests --

def test_map_key_type_pre_master():
    assert map_key_type(MslKeyType.PRE_MASTER_SECRET) == "PRE_MASTER_SECRET"


def test_map_key_type_session():
    assert map_key_type(MslKeyType.SESSION_KEY) == "SESSION_KEY"


def test_map_key_type_handshake():
    assert map_key_type(MslKeyType.HANDSHAKE_SECRET) == "HANDSHAKE_SECRET"


def test_map_key_type_app_traffic():
    assert map_key_type(MslKeyType.APP_TRAFFIC_SECRET) == "APP_TRAFFIC_SECRET"


def test_map_key_type_ssh():
    assert map_key_type(MslKeyType.SSH_SESSION_KEY) == "SSH2_SESSION_KEY"


def test_map_key_type_unknown_value():
    result = map_key_type(0x9999)
    assert "UNKNOWN" in result or "9999" in result


# -- map_protocol tests --

def test_map_protocol_tls12():
    assert map_protocol(MslProtocol.TLS_12) == "TLS"


def test_map_protocol_tls13():
    assert map_protocol(MslProtocol.TLS_13) == "TLS"


def test_map_protocol_ssh():
    assert map_protocol(MslProtocol.SSH) == "SSH"


def test_map_protocol_quic():
    assert map_protocol(MslProtocol.QUIC) == "TLS"


def test_map_protocol_wireguard():
    assert map_protocol(MslProtocol.WIREGUARD) == "WireGuard"


def test_map_protocol_ipsec():
    assert map_protocol(MslProtocol.IKEV2_IPSEC) == "IPsec"


def test_map_protocol_unknown():
    assert map_protocol(MslProtocol.OTHER) == "UNKNOWN"


# -- extract_key_bytes tests --

def test_extract_key_bytes_success(msl_path):
    """Key hint in fixture references region at offset 0, length 32 => 0xAA * 32."""
    with MslReader(msl_path) as reader:
        hints = reader.collect_key_hints()
        assert len(hints) == 1
        key_bytes = extract_key_bytes(reader, hints[0])
        assert key_bytes is not None
        assert len(key_bytes) == 32
        assert key_bytes == b"\xAA" * 32


def test_extract_key_bytes_bad_region(msl_path):
    """Hint with wrong region UUID returns None."""
    with MslReader(msl_path) as reader:
        hints = reader.collect_key_hints()
        hint = hints[0]
        # Replace region_uuid with a bogus UUID
        from dataclasses import replace
        from msl.types import MslKeyHint
        bad_hint = MslKeyHint(
            block_header=hint.block_header,
            region_uuid=UUID(int=0),
            region_offset=hint.region_offset,
            key_length=hint.key_length,
            key_type=hint.key_type,
            protocol=hint.protocol,
            confidence=hint.confidence,
            key_state=hint.key_state,
            note=hint.note,
        )
        assert extract_key_bytes(reader, bad_hint) is None


def test_extract_key_bytes_out_of_bounds(msl_path):
    """Hint with offset exceeding region size returns None."""
    with MslReader(msl_path) as reader:
        hints = reader.collect_key_hints()
        hint = hints[0]
        from msl.types import MslKeyHint
        oob_hint = MslKeyHint(
            block_header=hint.block_header,
            region_uuid=hint.region_uuid,
            region_offset=999999,
            key_length=hint.key_length,
            key_type=hint.key_type,
            protocol=hint.protocol,
            confidence=hint.confidence,
            key_state=hint.key_state,
            note=hint.note,
        )
        assert extract_key_bytes(reader, oob_hint) is None


# -- extract_secrets_from_msl tests --

def test_extract_secrets_from_msl_roundtrip(msl_path):
    """Full round-trip: MSL with key hint => CryptoSecret."""
    with MslReader(msl_path) as reader:
        secrets = extract_secrets_from_msl(reader)
        assert len(secrets) == 1
        s = secrets[0]
        assert s.secret_type == "SESSION_KEY"  # key_type=0x0003
        assert s.protocol == "TLS"  # protocol=0x0002 (TLS_13)
        assert s.secret_value == b"\xAA" * 32
        assert len(s.identifier) == 32


def test_extract_secrets_dedup(msl_path):
    """Calling twice on same reader returns same count (cached hints)."""
    with MslReader(msl_path) as reader:
        s1 = extract_secrets_from_msl(reader)
        s2 = extract_secrets_from_msl(reader)
        assert len(s1) == len(s2)


def test_extract_secrets_from_path(msl_path):
    """Convenience function opens, extracts, closes."""
    secrets = extract_secrets_from_path(msl_path)
    assert len(secrets) == 1
    assert secrets[0].secret_type == "SESSION_KEY"
