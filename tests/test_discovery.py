"""Tests for core.discovery module."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from core.discovery import RunDiscovery, DatasetScanner
from tests.fixtures.generate_msl_fixtures import generate_msl_file


def test_parse_dump_filename():
    result = RunDiscovery.parse_dump_filename("20240101_120000_000001_pre_abort.dump")
    assert result is not None
    assert result.phase_prefix == "pre"
    assert result.phase_name == "abort"
    assert result.timestamp == "20240101_120000_000001"


def test_parse_dump_filename_invalid():
    assert RunDiscovery.parse_dump_filename("invalid.dump") is None
    assert RunDiscovery.parse_dump_filename("not_a_dump.txt") is None


def test_parse_run_dirname():
    result = RunDiscovery.parse_run_dirname("boringssl_run_13_1")
    assert result is not None
    assert result == ("boringssl", "13", 1)


def test_parse_run_dirname_tls12():
    result = RunDiscovery.parse_run_dirname("openssl_run_12_5")
    assert result == ("openssl", "12", 5)


def test_parse_run_dirname_invalid():
    assert RunDiscovery.parse_run_dirname("not_a_run_dir") is None


# -- MSL-aware discovery tests --

def test_parse_msl_filename():
    """MSL files with standard naming are parsed correctly."""
    result = RunDiscovery.parse_dump_filename("20240101_120000_000001_pre_handshake.msl")
    assert result is not None
    assert result.phase_prefix == "pre"
    assert result.phase_name == "handshake"
    assert result.timestamp == "20240101_120000_000001"


def test_parse_dump_still_works():
    """Regression: .dump extension still works after regex change."""
    result = RunDiscovery.parse_dump_filename("20240101_120000_000001_post_cleanup.dump")
    assert result is not None
    assert result.phase_prefix == "post"
    assert result.phase_name == "cleanup"


def _make_run_dir(tmp_path, name="testlib_run_13_1", dump_ext=".dump"):
    """Create a minimal run directory with one dump file."""
    run_dir = tmp_path / name
    run_dir.mkdir()
    dump_file = run_dir / f"20240101_120000_000001_pre_handshake{dump_ext}"
    if dump_ext == ".msl":
        dump_file.write_bytes(generate_msl_file())
    else:
        dump_file.write_bytes(b"\x00" * 256)
    return run_dir


def test_load_run_with_msl(tmp_path):
    """Run directory with .msl files is discovered correctly."""
    run_dir = _make_run_dir(tmp_path, dump_ext=".msl")
    run = RunDiscovery.load_run_directory(run_dir)
    assert run is not None
    assert len(run.dumps) == 1
    assert run.dumps[0].path.suffix == ".msl"


def test_load_run_mixed_formats(tmp_path):
    """Run directory with both .dump and .msl files finds both."""
    run_dir = tmp_path / "testlib_run_13_1"
    run_dir.mkdir()
    (run_dir / "20240101_120000_000001_pre_handshake.dump").write_bytes(b"\x00" * 256)
    msl_file = run_dir / "20240101_120001_000002_post_handshake.msl"
    msl_file.write_bytes(generate_msl_file())
    run = RunDiscovery.load_run_directory(run_dir)
    assert run is not None
    assert len(run.dumps) == 2
    suffixes = {d.path.suffix for d in run.dumps}
    assert suffixes == {".dump", ".msl"}


def test_msl_secret_fallback(tmp_path):
    """Without keylog.csv, secrets are extracted from MSL key hints."""
    run_dir = _make_run_dir(tmp_path, dump_ext=".msl")
    run = RunDiscovery.load_run_directory(run_dir)
    assert run is not None
    assert len(run.secrets) == 1
    assert run.secrets[0].secret_type == "SESSION_KEY"
    assert run.secret_source == "msl_hints"


def test_keylog_priority(tmp_path):
    """When keylog.csv exists, it takes priority over MSL key hints."""
    run_dir = _make_run_dir(tmp_path, dump_ext=".msl")
    keylog = run_dir / "keylog.csv"
    keylog.write_text(
        "line\n"
        "CLIENT_RANDOM "
        + "aa" * 32 + " " + "bb" * 48 + "\n"
    )
    run = RunDiscovery.load_run_directory(run_dir)
    assert run is not None
    assert run.secret_source == "keylog"
    assert any(s.secret_type == "CLIENT_RANDOM" for s in run.secrets)


def test_secret_source_none(tmp_path):
    """Run with no keylog and no MSL files has secret_source='none'."""
    run_dir = _make_run_dir(tmp_path, dump_ext=".dump")
    run = RunDiscovery.load_run_directory(run_dir)
    assert run is not None
    assert run.secret_source == "none"
