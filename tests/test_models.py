"""Tests for core.models module."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from core.models import CryptoSecret, TLSSecret, DumpFile, RunDirectory, ComparisonRegion, KeyOccurrence


def test_tls_secret_hash_equality():
    s1 = TLSSecret("CLIENT_RANDOM", b"\x00" * 32, b"\x01" * 32)
    s2 = TLSSecret("CLIENT_RANDOM", b"\x00" * 32, b"\x01" * 32)
    assert s1 == s2
    assert hash(s1) == hash(s2)


def test_tls_secret_protocol_field():
    """CryptoSecret has protocol field; is_tls13 removed per Phase 9."""
    s = TLSSecret("CLIENT_RANDOM", b"\x00" * 32, b"\x01" * 48)
    assert s.protocol == "TLS"
    assert not hasattr(s, "is_tls13") or not callable(getattr(type(s), "is_tls13", None))


def test_dump_file_full_phase():
    df = DumpFile(path=Path("/tmp/test.dump"), timestamp="20240101_120000_0", phase_prefix="pre", phase_name="abort")
    assert df.full_phase == "pre_abort"


def test_dump_file_canonical_or_raw():
    df = DumpFile(path=Path("/tmp/test.dump"), timestamp="20240101_120000_0", phase_prefix="pre", phase_name="abort")
    assert df.canonical_or_raw == "pre_abort"
    df.canonical_phase = "pre_handshake_end"
    assert df.canonical_or_raw == "pre_handshake_end"


def test_run_directory_available_phases():
    run = RunDirectory(path=Path("/tmp/run"), library="test", tls_version="13", run_number=1)
    d1 = DumpFile(path=Path("/tmp/1.dump"), timestamp="20240101_120000_0", phase_prefix="pre", phase_name="abort")
    d2 = DumpFile(path=Path("/tmp/2.dump"), timestamp="20240101_120001_0", phase_prefix="post", phase_name="abort")
    run.dumps = [d1, d2]
    phases = run.available_phases()
    assert "post_abort" in phases
    assert "pre_abort" in phases


def test_run_directory_get_dump_for_phase():
    run = RunDirectory(path=Path("/tmp/run"), library="test", tls_version="13", run_number=1)
    d1 = DumpFile(path=Path("/tmp/1.dump"), timestamp="20240101_120000_0", phase_prefix="pre", phase_name="abort")
    run.dumps = [d1]
    assert run.get_dump_for_phase("pre_abort") is d1
    assert run.get_dump_for_phase("post_abort") is None


def test_comparison_region():
    region = ComparisonRegion(secret_type="CLIENT_RANDOM", key_length=32, context_size=16)
    region.run_data.append((b"\x00" * 16, b"\x01" * 32, b"\x00" * 16))
    region.run_labels.append("run_1")
    assert len(region.run_data) == 1
    assert region.key_length == 32


def test_key_occurrence_context_start():
    occ = KeyOccurrence(offset=256, secret=TLSSecret("X", b"", b"\x01" * 32), context_before=b"\x00" * 16, key_bytes=b"\x01" * 32, context_after=b"\x00" * 16)
    assert occ.context_start_offset == 240


# --- Phase 9: Protocol abstraction tests ---


def test_tls_secret_alias():
    """TLSSecret is an alias for CryptoSecret."""
    assert TLSSecret is CryptoSecret


def test_crypto_secret_new_constructor():
    """CryptoSecret can be constructed with 'identifier' kwarg."""
    s = CryptoSecret("TYPE", identifier=b"\xaa" * 32, secret_value=b"\xbb" * 32)
    assert s.identifier == b"\xaa" * 32
    assert s.client_random == b"\xaa" * 32  # backward-compat property


def test_crypto_secret_client_random_kwarg():
    """CryptoSecret can still be constructed with deprecated 'client_random' kwarg."""
    s = CryptoSecret("TYPE", client_random=b"\xcc" * 32, secret_value=b"\xdd" * 32)
    assert s.identifier == b"\xcc" * 32
    assert s.client_random == b"\xcc" * 32


def test_crypto_secret_protocol_default():
    """CryptoSecret defaults protocol to 'TLS'."""
    s = CryptoSecret("TYPE", b"\x00" * 32, b"\x01" * 32)
    assert s.protocol == "TLS"


def test_crypto_secret_custom_protocol():
    """CryptoSecret accepts a custom protocol."""
    s = CryptoSecret("TYPE", b"\x00" * 32, b"\x01" * 32, protocol="SSH")
    assert s.protocol == "SSH"


def test_run_directory_protocol_version():
    """RunDirectory can be constructed with protocol_version kwarg."""
    run = RunDirectory(path=Path("/tmp/run"), library="test", protocol_version="13", run_number=1)
    assert run.protocol_version == "13"
    assert run.tls_version == "13"


def test_run_directory_tls_version_kwarg():
    """RunDirectory backward compat: tls_version kwarg sets protocol_version."""
    run = RunDirectory(path=Path("/tmp/run"), library="test", tls_version="12", run_number=1)
    assert run.protocol_version == "12"
    assert run.tls_version == "12"


def test_run_directory_tls_version_setter():
    """RunDirectory.tls_version setter updates protocol_version."""
    run = RunDirectory(path=Path("/tmp/run"), library="test", protocol_version="13", run_number=1)
    run.tls_version = "12"
    assert run.protocol_version == "12"
