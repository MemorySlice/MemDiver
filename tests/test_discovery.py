"""Tests for core.discovery module."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from memdiver.core.discovery import RunDiscovery, DatasetScanner
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


def test_dataset_scanner_missing_root_raises_clear_error(tmp_path):
    """Regression: a deleted/replaced scan root must raise a clear
    NotADirectoryError instead of an opaque FileNotFoundError from a deep
    iterdir() call (TOCTOU race)."""
    import pytest

    missing = tmp_path / "gone"  # never created
    scanner = DatasetScanner(missing)
    with pytest.raises(NotADirectoryError, match="not a directory"):
        scanner.fast_scan()


def test_dataset_scanner_root_replaced_by_file_raises(tmp_path):
    """Regression: root replaced by a regular file must also be guarded."""
    import pytest

    not_a_dir = tmp_path / "afile"
    not_a_dir.write_text("data")
    scanner = DatasetScanner(not_a_dir)
    with pytest.raises(NotADirectoryError, match="not a directory"):
        scanner.fast_scan()


def test_fast_scan_reports_capture_counters(tmp_path):
    """DatasetInfo counts the runs that own a packet capture (run_data/)."""
    lib_dir = tmp_path / "TLS13" / "scenario_a" / "openssl"
    lib_dir.mkdir(parents=True)
    for run_num, with_capture in ((1, True), (2, False)):
        run_dir = _make_run_dir(lib_dir, name=f"openssl_run_13_{run_num}")
        if with_capture:
            capture_dir = run_dir / "run_data"
            capture_dir.mkdir()
            (capture_dir / "traffic.pcap").write_bytes(b"\xd4\xc3\xb2\xa1")

    info = DatasetScanner(tmp_path).fast_scan()
    assert info.total_runs == 2
    assert info.runs_with_capture == 1
    assert info.captures == {"13/scenario_a/openssl": 1}


def test_load_run_directory_attaches_capture(tmp_path):
    """load_run_directory pairs a run with its own capture."""
    run_dir = _make_run_dir(tmp_path)
    capture_dir = run_dir / "run_data"
    capture_dir.mkdir()
    (capture_dir / "traffic.pcap").write_bytes(b"\xd4\xc3\xb2\xa1")

    run = RunDiscovery.load_run_directory(run_dir)
    assert run is not None
    assert run.capture_status == "present"
    assert run.capture_path == capture_dir / "traffic.pcap"
