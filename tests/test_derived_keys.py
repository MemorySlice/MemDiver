"""Tests for engine.derived_keys module."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from core.models import TLSSecret
from engine.derived_keys import DerivedKeyExpander


def test_expand_traffic_secrets():
    secret = TLSSecret(
        "CLIENT_HANDSHAKE_TRAFFIC_SECRET",
        b"\x00" * 32,
        b"\x42" * 32,
    )
    expander = DerivedKeyExpander()
    derived = expander.expand_secrets([secret])
    # Should produce: 2 keys (AES-128, AES-256) + 1 IV + 1 finished = 4
    assert len(derived) == 4
    types = [d.secret_type for d in derived]
    assert any("KEY_128" in t for t in types)
    assert any("KEY_256" in t for t in types)
    assert any("IV" in t for t in types)
    assert any("FINISHED" in t for t in types)


def test_expand_non_traffic_secret():
    """Non-traffic secrets should not be expanded."""
    secret = TLSSecret("EXPORTER_SECRET", b"\x00" * 32, b"\x42" * 32)
    expander = DerivedKeyExpander()
    derived = expander.expand_secrets([secret])
    assert len(derived) == 0


def test_expand_preserves_client_random():
    cr = b"\xAA" * 32
    secret = TLSSecret("SERVER_TRAFFIC_SECRET_0", cr, b"\xBB" * 32)
    expander = DerivedKeyExpander()
    derived = expander.expand_secrets([secret])
    for d in derived:
        assert d.client_random == cr


def test_ssh_expansion():
    """SSH session keys should be expanded via the SSH KDF plugin."""
    from core.models import CryptoSecret

    secret = CryptoSecret(
        secret_type="SSH2_SESSION_KEY",
        identifier=b"\x00" * 32,
        secret_value=b"\xCC" * 32,
        protocol="SSH",
    )
    expander = DerivedKeyExpander()
    derived = expander.expand_secrets([secret])
    # SSH2KDFPlugin produces 6 keys (A-F)
    assert len(derived) == 6
    types = {d.secret_type for d in derived}
    assert "SSH2_IV_CS" in types
    assert "SSH2_IV_SC" in types
    assert "SSH2_ENCRYPTION_KEY_CS" in types
    assert "SSH2_ENCRYPTION_KEY_SC" in types
    assert "SSH2_INTEGRITY_KEY_CS" in types
    assert "SSH2_INTEGRITY_KEY_SC" in types
    for d in derived:
        assert d.protocol == "SSH"


def test_protocol_dispatch():
    """Both TLS and SSH secrets should be expanded in one call."""
    from core.models import CryptoSecret

    tls_secret = CryptoSecret(
        secret_type="CLIENT_HANDSHAKE_TRAFFIC_SECRET",
        identifier=b"\x00" * 32,
        secret_value=b"\x42" * 32,
        protocol="TLS",
    )
    ssh_secret = CryptoSecret(
        secret_type="SSH2_SESSION_KEY",
        identifier=b"\x00" * 32,
        secret_value=b"\xDD" * 32,
        protocol="SSH",
    )
    expander = DerivedKeyExpander()
    derived = expander.expand_secrets([tls_secret, ssh_secret])
    # TLS: 2 keys + 1 IV + 1 finished = 4; SSH: 6 keys = total 10
    assert len(derived) == 10
    tls_derived = [d for d in derived if d.protocol == "TLS"]
    ssh_derived = [d for d in derived if d.protocol == "SSH"]
    assert len(tls_derived) == 4
    assert len(ssh_derived) == 6


def test_backward_compat_traffic_secret_types():
    """TRAFFIC_SECRET_TYPES class attribute is still accessible."""
    expected = {
        "CLIENT_HANDSHAKE_TRAFFIC_SECRET",
        "SERVER_HANDSHAKE_TRAFFIC_SECRET",
        "CLIENT_TRAFFIC_SECRET_0",
        "SERVER_TRAFFIC_SECRET_0",
    }
    assert DerivedKeyExpander.TRAFFIC_SECRET_TYPES == expected
