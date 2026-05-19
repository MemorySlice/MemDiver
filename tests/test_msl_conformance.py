"""Conformance tests against the Memory Slice Specification v1.0.0.

These tests directly exercise the MUST/SHOULD-level requirements from
specification sections §3.1, §3.4, §5.1, §7, §9 and §14.

Spec source: https://github.com/MemorySlice/memslice-spec
"""

import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import pytest

from msl.enums import (BLOCK_HEADER_SIZE, FILE_HEADER_SIZE, FILE_MAGIC,
                       BlockType, PageState)
from msl.reader import MslReader
from msl.types import MslEncryptedError, MslParseError
from msl.writer import (CapBit, ConnectionTableEntry, HandleTableEntry,
                        ModuleEntrySpec, MslWriter, ProcessTableEntry)


# ---------------------------------------------------------------------------
# §3.1 File header — Endianness MUST be 0x01; other values MUST be rejected
# ---------------------------------------------------------------------------

def _craft_header(
    *,
    endianness: int = 0x01,
    version: int = 0x0101,
    flags: int = 0,
    cap_bitmap: int = 0,
) -> bytes:
    """Build a valid 64-byte file header with overrides for negative tests."""
    return struct.pack(
        "<8sBBHIQ16sQHHIB7x",
        FILE_MAGIC, endianness, FILE_HEADER_SIZE, version,
        flags, cap_bitmap, b"\x00" * 16,
        0, 0xFFFF, 0xFFFF, 0, 0,
    )


@pytest.mark.parametrize("bad_endianness", [0x00, 0x02, 0x03, 0xFF])
def test_reject_invalid_endianness(tmp_path, bad_endianness):
    """Spec §3.1: 'v1.1: MUST be 0x01. Other values MUST cause rejection.'"""
    p = tmp_path / "bad_endian.msl"
    p.write_bytes(_craft_header(endianness=bad_endianness))
    with pytest.raises(MslParseError, match="Endianness"):
        with MslReader(p) as _:
            pass


# ---------------------------------------------------------------------------
# §3.4 Version compatibility — unknown major SHOULD be rejected
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("bad_version", [
    0x0200,  # major 2, minor 0
    0x0202,  # major 2, minor 2
    0xFF00,  # major 255, minor 0
])
def test_reject_unknown_major_version(tmp_path, bad_version):
    """Spec §3.4: 'Unknown major version: SHOULD reject.'"""
    p = tmp_path / "bad_version.msl"
    p.write_bytes(_craft_header(version=bad_version))
    with pytest.raises(MslParseError, match="major version"):
        with MslReader(p) as _:
            pass


def test_accept_unknown_minor_with_warning(tmp_path, caplog):
    """Spec §3.4: 'Unknown minor of known major: MAY parse.'

    A version 0x0105 (major 1, minor 5) should parse successfully. The
    reader logs a forward-compat warning per spec §3.4.
    """
    p = tmp_path / "future_minor.msl"
    p.write_bytes(_craft_header(version=0x0105))
    import logging
    with caplog.at_level(logging.WARNING, logger="memdiver.msl.reader"):
        with MslReader(p) as r:
            assert r.file_header.version_major == 1
            assert r.file_header.version_minor == 5
    assert any("minor" in rec.message.lower() for rec in caplog.records)


# ---------------------------------------------------------------------------
# §3.1 ENCRYPTED flag — reader rejects (writer does not emit)
# ---------------------------------------------------------------------------

def test_reject_encrypted_files(tmp_path):
    """Spec §3.1 + §10: ENCRYPTED flag means full-container AEAD; we don't
    decrypt, so reader raises MslEncryptedError per project policy."""
    p = tmp_path / "encrypted.msl"
    # Bit 2 = ENCRYPTED in HeaderFlag
    p.write_bytes(_craft_header(flags=1 << 2))
    with pytest.raises(MslEncryptedError):
        with MslReader(p) as _:
            pass


# ---------------------------------------------------------------------------
# §5.1 Memory Region — PageSizeLog2 ∈ [10, 40]
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("bad_log2", [0, 5, 9, 41, 50, 255])
def test_writer_rejects_pagesizelog2_out_of_range(tmp_path, bad_log2):
    """Spec §5.1: PageSizeLog2 in [10, 40]. Writer §14.1(13)."""
    w = MslWriter(tmp_path / "x.msl")
    with pytest.raises(ValueError, match="page_size_log2"):
        w.add_memory_region(0, b"", page_size_log2=bad_log2)


# ---------------------------------------------------------------------------
# §5.1 Memory Region — RegionSize MUST be a multiple of PageSize
# ---------------------------------------------------------------------------

def test_writer_rejects_unaligned_region_size(tmp_path):
    """Spec §5.1: RegionSize MUST be a multiple of PageSize."""
    w = MslWriter(tmp_path / "x.msl")
    # 4096-byte page; 5000 bytes is not aligned.
    with pytest.raises(ValueError, match="multiple of"):
        w.add_memory_region(0, b"\x00" * 5000)


# ---------------------------------------------------------------------------
# §9 Capability Bitmap — Producers MUST set bits accurately
# ---------------------------------------------------------------------------

def test_capability_bitmap_set_for_emitted_categories(tmp_path):
    """Spec §9: writer must OR the appropriate CapBitmap bits for each
    data category it emits."""
    out = tmp_path / "caps.msl"
    w = MslWriter(out, imported=True)
    region_uuid = w.add_memory_region(0, b"\x00" * 4096)
    w.add_key_hint(region_uuid=region_uuid, offset=0,
                   key_length=32, key_type=0x0001, protocol=0x0002)
    w.add_related_dump(related_uuid=region_uuid, related_pid=0, relationship=1)
    w.add_import_provenance(source_format=0x01, tool_name="t", orig_file_size=0)
    w.add_end_of_capture()
    w.write()

    with MslReader(out) as r:
        cb = r.file_header.cap_bitmap
        assert cb & CapBit.MEMORY_REGIONS, "CapBit.MEMORY_REGIONS not set"
        assert cb & CapBit.CRYPTO_HINTS, "CapBit.CRYPTO_HINTS not set"
        assert cb & CapBit.RELATED_DUMPS, "CapBit.RELATED_DUMPS not set"
        # Import provenance is metadata, not a data category — no bit.


def test_capability_bitmap_zero_when_no_data(tmp_path):
    """A writer that emits no spec-listed data categories writes 0."""
    out = tmp_path / "empty.msl"
    w = MslWriter(out, imported=False)  # no add_* of data categories
    w.add_end_of_capture()
    w.write()
    with MslReader(out) as r:
        assert r.file_header.cap_bitmap == 0


# ---------------------------------------------------------------------------
# §7 Three-state page model — round-trip CAPTURED/FAILED/UNMAPPED
# ---------------------------------------------------------------------------

def test_three_state_page_roundtrip(tmp_path):
    """Spec §7: pages can be CAPTURED, FAILED, or UNMAPPED. The writer
    must encode all three; the reader must decode them."""
    out = tmp_path / "three_state.msl"
    w = MslWriter(out)
    page_size_log2 = 12
    page_size = 1 << page_size_log2
    # 4 pages: CAPTURED, FAILED, UNMAPPED, CAPTURED
    states = [
        PageState.CAPTURED,
        PageState.FAILED,
        PageState.UNMAPPED,
        PageState.CAPTURED,
    ]
    captured_data = b"\xAA" * page_size + b"\xBB" * page_size
    w.add_memory_region(
        base_addr=0x4000,
        data=captured_data,
        page_size_log2=page_size_log2,
        page_states=states,
    )
    w.add_end_of_capture()
    w.write()

    with MslReader(out) as r:
        regions = r.collect_regions()
        assert len(regions) == 1
        reg = regions[0]
        # Region size covers all 4 pages (16 KB).
        assert reg.region_size == 4 * page_size
        # page_intervals returns RLE; reconstruct per-page list and compare.
        per_page = []
        for iv in reg.page_intervals:
            per_page.extend([iv.state] * iv.count)
        assert per_page == states


# ---------------------------------------------------------------------------
# §6.1 Investigation mode — block ordering enforced at write()
# ---------------------------------------------------------------------------

def test_investigation_mode_block_ordering(tmp_path):
    """Spec §6.1: live acquisition emits Process Identity (Block 0), Module
    List Index (Block 1), and System Context (Block 2) in order."""
    out = tmp_path / "investigation.msl"
    w = MslWriter(out, pid=4242, imported=False, investigation=True)
    w.add_process_identity(
        ppid=1, session_id=2, start_time_ns=10_000_000,
        exe_path="/usr/bin/target", cmd_line="/usr/bin/target --x",
    )
    w.add_module_list_index([
        ModuleEntrySpec(base_addr=0x4000, module_size=4096,
                        path="/lib/libc.so", version="2.39"),
        ModuleEntrySpec(base_addr=0x5000, module_size=4096,
                        path="/lib/libssl.so", version="3.2"),
    ])
    sc_uuid = w.add_system_context(
        boot_time_ns=1_000_000, target_count=1,
        acq_user="analyst", hostname="forensic-host",
        os_detail="Linux 6.7",
    )
    w.add_process_table([
        ProcessTableEntry(pid=4242, ppid=1, uid=1000, is_target=True,
                          exe_name="target", cmd_line="target --x", user="analyst"),
    ])
    w.add_connection_table([
        ConnectionTableEntry(pid=4242, family=0x02, protocol=0x06, state=0x01,
                             local_addr=b"\x7f\x00\x00\x01", local_port=4433,
                             remote_addr=b"\x7f\x00\x00\x01", remote_port=22000),
    ])
    w.add_handle_table([
        HandleTableEntry(pid=4242, fd=3, handle_type=0x01, path="/etc/passwd"),
    ])
    w.add_memory_region(0x6000, b"\x00" * 4096)
    w.add_end_of_capture()
    w.write()

    with MslReader(out) as r:
        # File-level: Investigation flag set; SystemContext bit set in cap.
        assert r.file_header.investigation
        assert r.file_header.cap_bitmap & CapBit.SYSTEM_CONTEXT
        assert r.file_header.cap_bitmap & CapBit.PROCESS_IDENTITY
        assert r.file_header.cap_bitmap & CapBit.MODULE_LIST
        assert r.file_header.cap_bitmap & CapBit.SYSTEM_PROCESS_TABLE
        assert r.file_header.cap_bitmap & CapBit.SYSTEM_NETWORK_TABLE
        assert r.file_header.cap_bitmap & CapBit.SYSTEM_HANDLE_TABLE
        assert r.file_header.cap_bitmap & CapBit.MEMORY_REGIONS

        block_types = [hdr.block_type for hdr, _ in r.iter_blocks()]
        # Block ordering per spec §6.1.
        assert block_types[0] == BlockType.PROCESS_IDENTITY
        assert block_types[1] == BlockType.MODULE_LIST_INDEX
        # Module entries follow Module List Index.
        assert block_types[2] == BlockType.MODULE_ENTRY
        assert block_types[3] == BlockType.MODULE_ENTRY
        # Block 2 (positionally, after 2 Module Entries) = System Context.
        sc_idx = block_types.index(BlockType.SYSTEM_CONTEXT)
        # Process/Connection/Handle tables follow System Context.
        for child_type in (BlockType.PROCESS_TABLE,
                           BlockType.CONNECTION_TABLE,
                           BlockType.HANDLE_TABLE):
            assert child_type in block_types
            assert block_types.index(child_type) > sc_idx
        # End-of-Capture is last.
        assert block_types[-1] == BlockType.END_OF_CAPTURE

        # Cross-references resolve.
        sc_blocks = r.collect_system_context()
        assert len(sc_blocks) == 1
        assert sc_blocks[0].acq_user == "analyst"
        assert sc_blocks[0].hostname == "forensic-host"

        procs = r.collect_processes()
        assert len(procs) == 1
        assert procs[0].entries[0].pid == 4242
        assert procs[0].entries[0].is_target is True

        conns = r.collect_connections()
        assert len(conns) == 1
        assert conns[0].entries[0].local_port == 4433

        handles = r.collect_handles()
        assert len(handles) == 1
        assert handles[0].entries[0].path == "/etc/passwd"

        modules_idx = r.collect_module_list_index()
        assert len(modules_idx) == 1
        assert modules_idx[0].entry_count == 2

        modules = r.collect_modules()
        assert len(modules) == 2
        assert modules[0].path == "/lib/libc.so"
        assert modules[1].path == "/lib/libssl.so"

        pid_blocks = r.collect_process_identity()
        assert len(pid_blocks) == 1
        assert pid_blocks[0].exe_path == "/usr/bin/target"


def test_investigation_block_chain_integrity(tmp_path):
    """Investigation files round-trip through the BLAKE3 chain verifier."""
    from msl.integrity import verify_chain

    out = tmp_path / "investigation_chain.msl"
    w = MslWriter(out, pid=1, imported=False, investigation=True)
    w.add_process_identity(exe_path="/bin/x", cmd_line="x")
    w.add_module_list_index([])
    w.add_system_context(boot_time_ns=0, target_count=1,
                         acq_user="u", hostname="h")
    w.add_memory_region(0, b"\x00" * 4096)
    w.add_end_of_capture()
    w.write()

    with MslReader(out) as r:
        report = verify_chain(r)
        assert report.valid, f"chain broken: {report.errors}"


# ---------------------------------------------------------------------------
# §6.2 System Context: only valid when investigation=True
# ---------------------------------------------------------------------------

def test_system_context_requires_investigation_flag(tmp_path):
    w = MslWriter(tmp_path / "x.msl", investigation=False)
    with pytest.raises(ValueError, match="investigation"):
        w.add_system_context(boot_time_ns=0, target_count=1,
                             acq_user="u", hostname="h")


def test_table_blocks_require_system_context(tmp_path):
    w = MslWriter(tmp_path / "x.msl", investigation=True)
    # System Context not yet added.
    with pytest.raises(ValueError, match="System Context"):
        w.add_process_table([])
    with pytest.raises(ValueError, match="System Context"):
        w.add_connection_table([])
    with pytest.raises(ValueError, match="System Context"):
        w.add_handle_table([])
