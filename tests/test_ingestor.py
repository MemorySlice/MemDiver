"""Tests for harvester.ingestor module - DumpIngestor dataset loading."""
import shutil
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from harvester.ingestor import DumpIngestor


def _create_synthetic_dataset(tmp_dir):
    """Create minimal synthetic dataset: TLS13/default/openssl/openssl_run_13_1/ with dump + keylog."""
    run_dir = Path(tmp_dir) / "TLS13" / "default" / "openssl" / "openssl_run_13_1"
    run_dir.mkdir(parents=True)

    # Create a dump file with recognizable content
    dump_path = run_dir / "20240101_120000_000001_pre_abort.dump"
    dump_path.write_bytes(b"\x00" * 256 + b"\xff" * 32 + b"\x00" * 224)

    # Create keylog.csv with a CLIENT_RANDOM entry
    keylog = run_dir / "keylog.csv"
    secret_hex = "ff" * 32
    client_random_hex = "aa" * 32
    keylog.write_text(f"line\nCLIENT_RANDOM {client_random_hex} {secret_hex}\n")

    return Path(tmp_dir)


def test_scan_empty_root():
    """Scanning an empty directory should return DatasetInfo with total_runs == 0."""
    tmp_dir = tempfile.mkdtemp()
    try:
        ingestor = DumpIngestor(Path(tmp_dir))
        info = ingestor.scan()
        assert info.total_runs == 0
    finally:
        shutil.rmtree(tmp_dir)


def test_scan_synthetic_dataset():
    """Scanning synthetic dataset should find TLS version '13', scenario 'default', library 'openssl'."""
    tmp_dir = tempfile.mkdtemp()
    try:
        root = _create_synthetic_dataset(tmp_dir)
        ingestor = DumpIngestor(root)
        info = ingestor.scan()
        assert "13" in info.tls_versions
        assert "default" in info.scenarios.get("13", [])
        assert "openssl" in info.libraries.get("default", set())
    finally:
        shutil.rmtree(tmp_dir)


def test_load_library_runs():
    """Loading runs for openssl should return a list with 1 RunDirectory."""
    tmp_dir = tempfile.mkdtemp()
    try:
        root = _create_synthetic_dataset(tmp_dir)
        ingestor = DumpIngestor(root)
        runs = ingestor.load_library_runs("13", "default", "openssl")
        assert len(runs) == 1
        assert runs[0].library == "openssl"
        assert runs[0].tls_version == "13"
        assert runs[0].run_number == 1
    finally:
        shutil.rmtree(tmp_dir)


def test_load_dump_data():
    """Loading dump bytes should match the written content (512 bytes)."""
    tmp_dir = tempfile.mkdtemp()
    try:
        root = _create_synthetic_dataset(tmp_dir)
        dump_path = root / "TLS13" / "default" / "openssl" / "openssl_run_13_1" / "20240101_120000_000001_pre_abort.dump"
        ingestor = DumpIngestor(root)
        data = ingestor.load_dump_data(dump_path)
        assert len(data) == 512
        assert data[256:288] == b"\xff" * 32
    finally:
        shutil.rmtree(tmp_dir)


def test_get_dump_paths_for_phase():
    """Getting paths for 'pre_abort' phase should return 1 path."""
    tmp_dir = tempfile.mkdtemp()
    try:
        root = _create_synthetic_dataset(tmp_dir)
        ingestor = DumpIngestor(root)
        runs = ingestor.load_library_runs("13", "default", "openssl")
        paths = ingestor.get_dump_paths_for_phase(runs, "pre_abort")
        assert len(paths) == 1
        assert paths[0].name == "20240101_120000_000001_pre_abort.dump"
    finally:
        shutil.rmtree(tmp_dir)
