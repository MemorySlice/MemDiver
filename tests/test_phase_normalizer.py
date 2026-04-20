"""Tests for core.phase_normalizer module.

Covers PhaseNormalizer.normalize_run, available_canonical_phases,
and get_canonical_display with various dump configurations.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from core.models import DumpFile, RunDirectory
from core.phase_normalizer import PhaseNormalizer, PhaseMapping


def _dump(prefix, name, ts="20240101_120000_000001"):
    """Create a DumpFile with the given prefix, phase name, and timestamp."""
    return DumpFile(
        path=Path(f"/tmp/{prefix}_{name}.dump"),
        timestamp=ts,
        phase_prefix=prefix,
        phase_name=name,
    )


def _run(dumps):
    """Create a RunDirectory containing the given dumps."""
    return RunDirectory(
        path=Path("/tmp/test_run"),
        library="testlib",
        tls_version="13",
        run_number=1,
        dumps=dumps,
    )


def test_normalize_empty_run():
    """Run with no dumps returns empty mapping."""
    normalizer = PhaseNormalizer()
    run = _run([])
    result = normalizer.normalize_run(run)
    assert result == {}


def test_normalize_single_pair():
    """One pre/post pair (abort) maps to pre/post_handshake_end."""
    normalizer = PhaseNormalizer()
    dumps = [
        _dump("pre", "abort", ts="20240101_120000_000001"),
        _dump("post", "abort", ts="20240101_120000_000002"),
    ]
    run = _run(dumps)
    result = normalizer.normalize_run(run)
    assert result["pre_abort"].canonical_phase == "pre_handshake_end"
    assert result["post_abort"].canonical_phase == "post_handshake_end"


def test_normalize_key_update():
    """Phase named 'server_key_update' maps to pre/post_key_update."""
    normalizer = PhaseNormalizer()
    dumps = [
        _dump("pre", "server_key_update", ts="20240101_120000_000001"),
        _dump("post", "server_key_update", ts="20240101_120000_000002"),
    ]
    run = _run(dumps)
    result = normalizer.normalize_run(run)
    assert result["pre_server_key_update"].canonical_phase == "pre_key_update"
    assert result["post_server_key_update"].canonical_phase == "post_key_update"


def test_normalize_cleanup():
    """Phase named 'cleanup' maps to pre/post_cleanup."""
    normalizer = PhaseNormalizer()
    dumps = [
        _dump("pre", "cleanup", ts="20240101_120000_000001"),
        _dump("post", "cleanup", ts="20240101_120000_000002"),
    ]
    run = _run(dumps)
    result = normalizer.normalize_run(run)
    assert result["pre_cleanup"].canonical_phase == "pre_cleanup"
    assert result["post_cleanup"].canonical_phase == "post_cleanup"


def test_normalize_two_generic_pairs():
    """Two generic pairs ordered by timestamp: first=handshake_end, second=second_event."""
    normalizer = PhaseNormalizer()
    dumps = [
        _dump("pre", "abort", ts="20240101_120000_000001"),
        _dump("post", "abort", ts="20240101_120000_000002"),
        _dump("pre", "shutdown", ts="20240101_120000_000003"),
        _dump("post", "shutdown", ts="20240101_120000_000004"),
    ]
    run = _run(dumps)
    result = normalizer.normalize_run(run)
    assert result["pre_abort"].canonical_phase == "pre_handshake_end"
    assert result["post_abort"].canonical_phase == "post_handshake_end"
    assert result["pre_shutdown"].canonical_phase == "pre_second_event"
    assert result["post_shutdown"].canonical_phase == "post_second_event"


def test_normalize_reverse_timestamp_order():
    """Pre dump with higher timestamp than post -- normalizer sorts internally."""
    normalizer = PhaseNormalizer()
    # Deliberately reversed: post timestamp is earlier than pre
    dumps = [
        _dump("post", "abort", ts="20240101_120000_000001"),
        _dump("pre", "abort", ts="20240101_120000_000002"),
    ]
    run = _run(dumps)
    result = normalizer.normalize_run(run)
    # Both should still be grouped under abort and mapped to handshake_end
    assert "post_abort" in result
    assert "pre_abort" in result
    assert result["post_abort"].canonical_phase == "post_handshake_end"
    assert result["pre_abort"].canonical_phase == "pre_handshake_end"


def test_available_canonical_phases():
    """available_canonical_phases returns phases in canonical order."""
    normalizer = PhaseNormalizer()
    run = _run([
        _dump("pre", "abort", ts="20240101_120000_000001"),
        _dump("post", "abort", ts="20240101_120000_000002"),
        _dump("pre", "cleanup", ts="20240101_120000_000003"),
        _dump("post", "cleanup", ts="20240101_120000_000004"),
    ])
    phases = normalizer.available_canonical_phases([run])
    # handshake_end should appear before cleanup in canonical order
    he_pre = phases.index("pre_handshake_end")
    cl_pre = phases.index("pre_cleanup")
    assert he_pre < cl_pre


def test_get_canonical_display():
    """pre_handshake_end displays as 'Pre Handshake End'."""
    assert PhaseNormalizer.get_canonical_display("pre_handshake_end") == "Pre Handshake End"


def test_get_canonical_display_generic():
    """Title-casing works for various canonical names."""
    assert PhaseNormalizer.get_canonical_display("post_key_update") == "Post Key Update"
    assert PhaseNormalizer.get_canonical_display("pre_second_event") == "Pre Second Event"
    assert PhaseNormalizer.get_canonical_display("post_cleanup") == "Post Cleanup"
