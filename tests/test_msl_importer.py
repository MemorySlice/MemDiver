"""Tests for msl/importer.py — raw-to-MSL import."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import pytest
from memdiver.core.models import CryptoSecret
from memdiver.msl.importer import ImportResult, import_raw_dump, import_run_directory
from memdiver.msl.reader import MslReader


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


def test_import_run_directory_no_filename_collision(tmp_path):
    """Dumps sharing a stem across suffixes (.dump/.dmp) must not collide.

    Regression test: the output path used to be derived from
    ``dump_file.with_suffix(".msl")``, which drops the original suffix and
    made e.g. ``proc.dump`` and ``proc.dmp`` both map to ``proc.msl`` —
    silently overwriting one result with the other.
    """
    run_dir = tmp_path / "run"
    run_dir.mkdir()
    (run_dir / "proc.dump").write_bytes(b"\xAA" * 256)
    (run_dir / "proc.dmp").write_bytes(b"\xBB" * 256)

    out_dir = tmp_path / "msl_out"
    results = import_run_directory(run_dir, out_dir)

    assert len(results) == 2
    output_paths = {r.output_path for r in results}
    assert output_paths == {out_dir / "proc.dump.msl", out_dir / "proc.dmp.msl"}
    assert all(p.exists() for p in output_paths)


def test_roundtrip_readback(tmp_path):
    """Import, read back with MslReader, verify region data matches."""
    data = b"\xCA\xFE" * 256  # 512 bytes — not page-aligned
    dump_path = tmp_path / "roundtrip.dump"
    dump_path.write_bytes(data)

    out = tmp_path / "roundtrip.msl"
    import_raw_dump(dump_path, out)

    with MslReader(out) as reader:
        regions = reader.collect_regions()
        assert len(regions) == 1
        r = regions[0]
        assert r.base_addr == 0
        # MSL Specification v1.0.0 §5.1: region_size MUST be a multiple of
        # page_size. The importer zero-pads to the next page boundary; the
        # original file size is preserved in IMPORT_PROVENANCE.orig_file_size.
        assert r.region_size == 4096  # padded from 512 to one 4096 page
        prov = reader.collect_import_provenance()
        assert prov[0].orig_file_size == len(data)
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


# --- page-map allocation cap (OOM protection on untrusted dumps) ---

def test_check_region_pages_boundary():
    """The guard fails closed above the cap and passes exactly at it."""
    from memdiver.msl.importer import MAX_REGION_PAGES, _check_region_pages

    _check_region_pages(MAX_REGION_PAGES, 0x1000, "committed")  # at cap: allowed
    with pytest.raises(ValueError, match="refusing to allocate"):
        _check_region_pages(MAX_REGION_PAGES + 1, 0x1000, "committed")


def test_committed_region_spec_caps_hostile_region_size():
    """A crafted minidump MEMORY_INFO.region_size must fail closed, not OOM.

    ~1 PiB / 4 KiB ≈ 2.7e11 pages; the guard raises before the per-page state
    list is allocated (reader is never touched).
    """
    import types

    from memdiver.msl.importer import _committed_region_spec

    mem_info = types.SimpleNamespace(base=0, region_size=1 << 50)
    with pytest.raises(ValueError, match="refusing to allocate"):
        _committed_region_spec(
            reader=None, mem_info=mem_info, spans=[], consumed=[], page=4096,
        )
