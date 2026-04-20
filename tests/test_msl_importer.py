"""Tests for msl/importer.py — raw-to-MSL import."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import pytest
from core.models import CryptoSecret
from msl.importer import ImportResult, import_raw_dump, import_run_directory
from msl.reader import MslReader


@pytest.fixture
def raw_dump(tmp_path):
    """Create a minimal 512-byte raw dump file."""
    p = tmp_path / "test.dump"
    p.write_bytes(b"\x00" * 512)
    return p


def test_import_minimal(tmp_path, raw_dump):
    """Import a 512-byte dump, verify output .msl exists."""
    out = tmp_path / "output.msl"
    result = import_raw_dump(raw_dump, out)
    assert out.exists()
    assert isinstance(result, ImportResult)
    assert result.regions_written == 1
    assert result.total_bytes == 512
    assert result.key_hints_written == 0


def test_import_with_secrets(tmp_path):
    """Import dump with known secret bytes, verify key hint written."""
    secret_bytes = b"\xDE\xAD\xBE\xEF" * 8  # 32-byte secret
    data = b"\x00" * 100 + secret_bytes + b"\x00" * (512 - 100 - 32)
    dump_path = tmp_path / "keyed.dump"
    dump_path.write_bytes(data)

    secret = CryptoSecret(
        secret_type="CLIENT_TRAFFIC_SECRET_0",
        identifier=b"\x00" * 32,
        secret_value=secret_bytes,
    )
    out = tmp_path / "keyed.msl"
    result = import_raw_dump(dump_path, out, secrets=[secret])
    assert result.key_hints_written == 1

    with MslReader(out) as reader:
        hints = reader.collect_key_hints()
        assert len(hints) == 1
        assert hints[0].key_length == 32


def test_import_run_directory(tmp_path):
    """Create temp dir with 2 .dump files, import all, verify 2 results."""
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    (run_dir / "phase1.dump").write_bytes(b"\xAA" * 256)
    (run_dir / "phase2.dump").write_bytes(b"\xBB" * 256)

    out_dir = tmp_path / "msl_out"
    results = import_run_directory(run_dir, out_dir)
    assert len(results) == 2
    assert all(r.output_path.exists() for r in results)
    assert all(r.output_path.suffix == ".msl" for r in results)


def test_roundtrip_readback(tmp_path):
    """Import, read back with MslReader, verify region data matches."""
    data = b"\xCA\xFE" * 256  # 512 bytes
    dump_path = tmp_path / "roundtrip.dump"
    dump_path.write_bytes(data)

    out = tmp_path / "roundtrip.msl"
    import_raw_dump(dump_path, out)

    with MslReader(out) as reader:
        regions = reader.collect_regions()
        assert len(regions) == 1
        r = regions[0]
        assert r.base_addr == 0
        assert r.region_size == len(data)
        # Read the actual data bytes from the region
        # Writer uses ceiling division for page count
        num_pages = (r.region_size + r.page_size - 1) // r.page_size
        psm_bytes = ((num_pages * 2 + 7) // 8 + 7) & ~7
        data_offset = r.block_header.payload_offset + 0x20 + psm_bytes
        read_data = reader.read_bytes(data_offset, len(data))
        assert read_data == data


def test_provenance_present(tmp_path, raw_dump):
    """Import, verify import provenance block is present."""
    out = tmp_path / "prov.msl"
    import_raw_dump(raw_dump, out)

    with MslReader(out) as reader:
        prov = reader.collect_import_provenance()
        assert len(prov) == 1
        assert prov[0].tool_name == "memdiver"
        assert prov[0].orig_file_size == 512


def test_output_path_handling(tmp_path, raw_dump):
    """Import to a subdirectory that doesn't exist yet."""
    out = tmp_path / "deep" / "nested" / "dir" / "output.msl"
    result = import_raw_dump(raw_dump, out)
    assert out.exists()
    assert result.output_path == out
