"""Opt-in materialize for .msl input: a region-filtered rewritten copy."""

from __future__ import annotations

import struct
from pathlib import Path
from uuid import UUID

import pytest

from memdiver.core.models import CryptoSecret
from memdiver.msl.enums import (BlockType, CompAlgo, HeaderFlag, Protection,
                                RegionType, SourceFormat)
from memdiver.msl.import_preview import preview_import
from memdiver.msl.importer import (import_dump, import_msl_passthrough,
                                   import_run_directory)
from memdiver.msl.integrity import verify_chain
from memdiver.msl.page_map import count_captured_pages
from memdiver.msl.reader import MslReader
from memdiver.msl.region_select import (RegionSelection, parse_selection,
                                        selection_from_provenance_note)
from memdiver.msl.types import (MslPointerGraphEdge, MslPointerGraphNode,
                                MslVasEntry)
from memdiver.msl.writer import (CapBit, ConnectionTableEntry,
                                 HandleTableEntry, ModuleEntrySpec,
                                 MslEncryptionConfig, MslWriter,
                                 ProcessTableEntry)

from tests.fixtures import generate_msl_fixtures as gen
from tests.fixtures import synth_elf_core
from tests.test_region_select import _STACK_SP

HEAP_STACK = parse_selection("heap,stack")
PAGE = 4096
# Block types the rewrite re-creates; everything else is copied as stored.
_RECREATED = {BlockType.MEMORY_REGION, BlockType.KEY_HINT, BlockType.VAS_MAP,
              BlockType.IMPORT_PROVENANCE, BlockType.END_OF_CAPTURE}


# -- helpers ------------------------------------------------------------------


def _region_data(reader, region) -> bytes:
    payload = reader.read_block_payload(region.block_header)
    map_bytes = ((region.num_pages + 3) // 4 + 7) & ~7
    captured = count_captured_pages(region.page_intervals) * region.page_size
    return payload[0x20 + map_bytes:0x20 + map_bytes + captured]


def _regions_by_base(path: Path) -> dict:
    with MslReader(path) as reader:
        return {r.base_addr: (r.region_size, r.protection, r.region_type,
                              [int(s) for s in r.page_states],
                              _region_data(reader, r))
                for r in reader.collect_regions()}


def _hint_vas(path: Path) -> list:
    """(VA, key_length, key_type, note) per key hint, resolved via its region."""
    with MslReader(path) as reader:
        base = {r.block_header.block_uuid: r.base_addr
                for r in reader.collect_regions()}
        return sorted((base[h.region_uuid] + h.region_offset, h.key_length,
                       h.key_type, h.note)
                      for h in reader.collect_key_hints())


def _copied_blocks(path: Path) -> list:
    """(type, uuid, parent, flags, on-disk payload) of non-recreated blocks."""
    with MslReader(path) as reader:
        return [(h.block_type, h.block_uuid, h.parent_uuid, h.flags,
                 reader.read_bytes(h.payload_offset, h.payload_length))
                for h in reader._iter_raw_block_headers()
                if h.block_type not in _RECREATED]


def _provenance(path: Path):
    with MslReader(path) as reader:
        (prov,) = reader.collect_import_provenance()
        return prov


def _elf_msl(tmp_path: Path) -> Path:
    """ELF core (with threads) imported in full, with one hint per segment."""
    core = tmp_path / "t.core"
    core.write_bytes(synth_elf_core.build_core_bytes(
        threads=[(101, _STACK_SP), (102, 0xDEAD0000)]))
    secrets = [CryptoSecret("CLIENT_RANDOM", b"\x00" * 32,
                            synth_elf_core._load_body(i)[:16])
               for i in range(synth_elf_core._NUM_LOAD)]
    out = tmp_path / "full.msl"
    import_dump(core, out, secrets=secrets)
    return out


def _rich_generated_msl(tmp_path: Path) -> Path:
    """generate_msl_fixtures blob (live capture, every table/ext block) plus
    a stack and an image region, each with a key hint."""
    blob = gen.generate_msl_file()
    eoc, _ = gen._build_end_of_capture(0)
    body = blob[:-len(eoc)]
    stack_payload = struct.pack("<QQBBB5xQ", 0x7FFFFFFDE000, PAGE, 0x03,
                                RegionType.STACK, 12, 0)
    stack_block, stack_uuid = gen._build_block(
        0x0001, stack_payload + b"\x00" * 8 + b"\x5A" * PAGE)
    image_payload = struct.pack("<QQBBB5xQ", 0x00400000, PAGE, 0x05,
                                RegionType.IMAGE, 12, 0)
    image_block, image_uuid = gen._build_block(
        0x0001, image_payload + b"\x00" * 8 + b"\x11" * PAGE)
    stack_hint, _ = gen._build_key_hint(stack_uuid, offset=0x40,
                                        note="stack_key")
    image_hint, _ = gen._build_key_hint(image_uuid, offset=0x10,
                                        note="image_key")
    eoc_block, _ = gen._build_end_of_capture(1_700_000_001_000_000_000)
    path = tmp_path / "rich.msl"
    path.write_bytes(body + stack_block + image_block + stack_hint
                     + image_hint + eoc_block)
    return path


def _writer_built_msl(tmp_path: Path, **writer_kwargs) -> Path:
    """Writer-made investigation capture: modules, tables, compressed heap,
    split stack, pointer-graph appendix, hints in every region."""
    path = tmp_path / "built.msl"
    w = MslWriter(path, pid=4242, imported=False, investigation=True,
                  **writer_kwargs)
    w.add_process_identity(ppid=1, exe_path="/usr/bin/app", cmd_line="app -x")
    w.add_module_list_index([
        ModuleEntrySpec(base_addr=0x400000, module_size=PAGE,
                        path="/usr/bin/app", version="1.0"),
    ])
    w.add_system_context(boot_time_ns=1, target_count=1, acq_user="u",
                         hostname="h", os_detail="Linux")
    w.add_process_table([ProcessTableEntry(pid=4242, ppid=1, uid=0,
                                           is_target=True, start_time_ns=0,
                                           rss=0, exe_name="app",
                                           cmd_line="app", user="root")])
    w.add_connection_table([ConnectionTableEntry(
        pid=4242, family=2, protocol=6, state=1, local_addr=b"\x7f\0\0\1",
        local_port=1, remote_addr=b"\x7f\0\0\1", remote_port=2)])
    w.add_handle_table([HandleTableEntry(pid=4242, fd=3, handle_type=1,
                                         path="/tmp/x")])
    image = w.add_memory_region(0x400000, b"\x11" * PAGE,
                                protection=0x05, region_type=RegionType.IMAGE)
    heap_kwargs = {"compression": CompAlgo.ZSTD} if "encryption" not in \
        writer_kwargs else {}
    heap = w.add_memory_region(0x10000000, bytes(range(256)) * 32,
                               region_type=RegionType.HEAP, **heap_kwargs)
    stack = w.add_memory_region(
        0x7FFF0000, b"\x22" * PAGE + b"\x33" * PAGE, region_type=RegionType.STACK,
        page_states=[0, 0, 2])  # two captured pages, one unmapped
    w.add_key_hint(image, 0x20, 32, 0x0003, 0x0002, note="img")
    w.add_key_hint(heap, 0x1000 + 8, 32, 0x0003, 0x0002, note="heap")
    w.add_key_hint(stack, PAGE + 4, 16, 0x0003, 0x0002, note="stk")
    w.add_related_dump(UUID(int=7), related_pid=9, relationship=1)
    w.add_vas_map([MslVasEntry(0x400000, PAGE, 0x05, RegionType.IMAGE,
                               "/usr/bin/app")])
    w.add_pointer_graph([MslPointerGraphNode(1, 0x10000008, "a"),
                         MslPointerGraphNode(1, 0x400020, "b")],
                        [MslPointerGraphEdge(0, 1, 1, "x")])
    w.add_end_of_capture()
    w.write()
    return path


# -- default / verbatim paths -------------------------------------------------


def test_default_passthrough_unchanged_with_selection(tmp_path):
    src = _elf_msl(tmp_path)
    out = tmp_path / "copy.msl"
    result = import_msl_passthrough(src, out, selection=HEAP_STACK)
    assert out.read_bytes() == src.read_bytes()
    assert not result.materialized
    assert len(result.warnings) == 1 and "materialize" in result.warnings[0]


@pytest.mark.parametrize("selection", [None, RegionSelection.all()])
def test_materialize_without_filter_is_verbatim(tmp_path, selection):
    src = _elf_msl(tmp_path)
    out = tmp_path / "copy.msl"
    result = import_dump(src, out, selection=selection, materialize=True)
    assert out.read_bytes() == src.read_bytes()
    assert result.warnings == [] and not result.materialized


def test_materialize_excluding_nothing_is_verbatim(tmp_path):
    src = _elf_msl(tmp_path)
    out = tmp_path / "copy.msl"
    present = frozenset(r.category for r in preview_import(src).regions)
    selection = RegionSelection(categories=present)
    assert not selection.is_all
    result = import_dump(src, out, materialize=True, selection=selection)
    assert out.read_bytes() == src.read_bytes()
    assert result.excluded_region_count == 0 and not result.materialized


def test_materialize_zero_byte_selection_falls_back_verbatim(tmp_path):
    src = _rich_generated_msl(tmp_path)
    out = tmp_path / "copy.msl"
    result = import_dump(src, out, selection=parse_selection("shared"),
                         materialize=True)
    assert out.read_bytes() == src.read_bytes()
    assert len(result.warnings) == 1 and "keep 0" in result.warnings[0]


def test_encrypted_source_without_key_raises(tmp_path):
    # Materializing an encrypted source now works WITH key material (see
    # tests/test_msl_materialize_encrypted.py); without it the error says so.
    src = _writer_built_msl(tmp_path, encryption=MslEncryptionConfig(
        raw_key=b"\x01" * 32))
    with pytest.raises(ValueError, match="encrypted.*key material required"):
        import_dump(src, tmp_path / "out.msl", selection=HEAP_STACK,
                    materialize=True)
    assert not (tmp_path / "out.msl").exists()
    # Without materialize the encrypted container is still staged verbatim.
    import_dump(src, tmp_path / "copy.msl", selection=HEAP_STACK)
    assert (tmp_path / "copy.msl").read_bytes() == src.read_bytes()


# -- ELF-derived .msl ---------------------------------------------------------


def test_elf_materialize_heap_stack(tmp_path):
    src = _elf_msl(tmp_path)
    out = tmp_path / "mat.msl"
    result = import_dump(src, out, selection=HEAP_STACK, materialize=True)

    preview = preview_import(src)
    kept = {r.base_addr for r in preview.regions if HEAP_STACK.includes(r)}
    dropped = [r for r in preview.regions if not HEAP_STACK.includes(r)]
    assert dropped and kept

    src_regions, out_regions = _regions_by_base(src), _regions_by_base(out)
    assert set(out_regions) == kept
    assert all(out_regions[b] == src_regions[b] for b in kept)

    assert result.materialized
    assert result.regions_written == len(kept)
    assert result.excluded_region_count == len(dropped)
    assert result.excluded_bytes == sum(r.captured_bytes for r in dropped)
    assert result.dropped_key_hints == len(dropped)  # one hint per segment
    assert any("key hint" in w for w in result.warnings)
    assert result.selection_summary()["dropped_key_hints"] == len(dropped)

    src_hints = _hint_vas(src)
    kept_ranges = [(b, b + src_regions[b][0]) for b in kept]
    expected = [h for h in src_hints
                if any(lo <= h[0] < hi for lo, hi in kept_ranges)]
    assert _hint_vas(out) == expected
    assert result.key_hints_written == len(expected)

    with MslReader(src) as a, MslReader(out) as b:
        fa, fb = a.file_header, b.file_header
        assert fb.dump_uuid == fa.dump_uuid
        assert (fb.flags, fb.os_type, fb.arch_type, fb.pid, fb.timestamp_ns) \
            == (fa.flags, fa.os_type, fa.arch_type, fa.pid, fa.timestamp_ns)
        assert fb.cap_bitmap == fa.cap_bitmap
        assert verify_chain(b).valid
        assert any(b.collect_end_of_capture()[0].file_hash)
        assert [(m.base_addr, m.module_size, m.path)
                for m in b.collect_modules()] == \
            [(m.base_addr, m.module_size, m.path) for m in a.collect_modules()]
        vas = [e for vm in b.collect_vas_map() for e in vm.entries]
        orig_eoc = a.collect_end_of_capture()[0].file_hash.hex()
    assert sorted(e.base_addr for e in vas) == sorted(
        r.base_addr for r in preview.regions)

    prov = _provenance(out)
    assert prov.source_format == SourceFormat.ELF_CORE
    assert prov.note.startswith("Imported from ELF core")
    assert "source_format=msl" in prov.note
    assert f"orig_eoc_hash={orig_eoc}" in prov.note
    assert f"excluded_regions={len(dropped)}" in prov.note
    assert selection_from_provenance_note(prov.note) == HEAP_STACK
    assert prov.source_hash != b"\x00" * 32


def test_materialize_in_place(tmp_path):
    src = _elf_msl(tmp_path)
    before = _regions_by_base(src)
    import_dump(src, src, selection=HEAP_STACK, materialize=True)
    after = _regions_by_base(src)
    assert set(after) < set(before)
    with MslReader(src) as reader:
        assert verify_chain(reader).valid


def test_import_run_directory_threads_materialize(tmp_path):
    run = tmp_path / "run"
    run.mkdir()
    staged = run / "x.dump"
    staged.write_bytes(_elf_msl(tmp_path).read_bytes())
    (default,) = import_run_directory(run, tmp_path / "a", selection=HEAP_STACK)
    (mat,) = import_run_directory(run, tmp_path / "b", selection=HEAP_STACK,
                                  materialize=True)
    assert default.output_path.read_bytes() == staged.read_bytes()
    assert mat.materialized and mat.excluded_region_count > 0


# -- generated rich fixture (live capture, every block kind) -------------------


def test_generated_fixture_preserves_blocks_and_remaps_hints(tmp_path):
    src = _rich_generated_msl(tmp_path)
    out = tmp_path / "mat.msl"
    result = import_dump(src, out, selection=HEAP_STACK, materialize=True)

    assert set(_regions_by_base(out)) == {0x7FFF00000000, 0x7FFFFFFDE000}
    assert result.excluded_region_count == 1  # the image region
    assert result.dropped_key_hints == 1
    assert [h[3] for h in _hint_vas(out)] == ["test_key", "stack_key"]
    assert _hint_vas(out) == [h for h in _hint_vas(src) if h[3] != "image_key"]

    # Every non-region block survives byte-for-byte, UUIDs/parents included.
    assert _copied_blocks(out) == _copied_blocks(src)

    with MslReader(src) as a, MslReader(out) as b:
        assert b.file_header.dump_uuid == a.file_header.dump_uuid
        assert b.file_header.flags == a.file_header.flags == 0  # live capture
        assert verify_chain(b).valid
        first = next(b._iter_raw_block_headers())
        assert first.block_type == BlockType.PROCESS_IDENTITY
        assert len(b.collect_related_dumps()) == 1
        assert len(b.collect_system_context()) == 1
        (vas,) = b.collect_vas_map()
        bases = {e.base_addr for e in vas.entries}
    # Source VAS entries kept, region at 0x400000 already covered by one.
    assert bases == {0x00400000, 0x7FFF00000000, 0x7FFFFFFDE000}

    prov = _provenance(out)
    assert prov.source_format == SourceFormat.MSL
    assert "orig_eoc_hash" not in prov.note  # source EoC hash was zero
    assert "dropped_key_hints=1" in prov.note


# -- writer-built fixture (investigation, compression, appendix) --------------


def test_writer_fixture_compressed_tables_and_appendix(tmp_path):
    src = _writer_built_msl(tmp_path)
    out = tmp_path / "mat.msl"
    result = import_dump(src, out, selection=parse_selection("heap"),
                         materialize=True)

    src_regions, out_regions = _regions_by_base(src), _regions_by_base(out)
    assert set(out_regions) == {0x10000000}
    assert out_regions[0x10000000] == src_regions[0x10000000]  # decompressed
    assert result.dropped_key_hints == 2
    assert [h[3] for h in _hint_vas(out)] == ["heap"]
    assert _hint_vas(out) == [h for h in _hint_vas(src) if h[3] == "heap"]
    assert _copied_blocks(out) == _copied_blocks(src)

    with MslReader(src) as a, MslReader(out) as b:
        assert b.file_header.flags == a.file_header.flags
        assert b.file_header.flags & HeaderFlag.INVESTIGATION
        assert b.file_header.cap_bitmap == a.file_header.cap_bitmap
        assert verify_chain(b).valid
        assert len(b.collect_processes()) == 1
        assert len(b.collect_handles()) == 1
        sc_uuid = b.collect_system_context()[0].block_header.block_uuid
        assert b.collect_processes()[0].block_header.parent_uuid == sc_uuid
        mli = b.collect_module_list_index()[0]
        assert {m.block_header.parent_uuid for m in b.collect_modules()} == {
            mli.block_header.block_uuid}
        (pg_a,), (pg_b,) = a.collect_pointer_graphs(), b.collect_pointer_graphs()
        assert pg_b.nodes == pg_a.nodes and pg_b.edges == pg_a.edges
        vas = sorted(e.base_addr for vm in b.collect_vas_map()
                     for e in vm.entries)
    assert vas == [0x400000, 0x10000000, 0x7FFF0000]


def test_split_stack_region_keeps_page_states(tmp_path):
    src = _writer_built_msl(tmp_path)
    out = tmp_path / "mat.msl"
    import_dump(src, out, selection=parse_selection("stack"), materialize=True)
    region = _regions_by_base(out)[0x7FFF0000]
    assert region[3] == [0, 0, 2]
    assert region[4] == b"\x22" * PAGE + b"\x33" * PAGE
    assert [h[3] for h in _hint_vas(out)] == ["stk"]


# -- writer options used by materialize ----------------------------------------


def test_writer_header_overrides(tmp_path):
    path = tmp_path / "w.msl"
    w = MslWriter(path, dump_uuid=UUID(int=5), timestamp_ns=123,
                  clock_source=2)
    w.add_memory_region(0x1000, b"\x00" * PAGE)
    w.add_end_of_capture(acq_end_ns=456)
    w.write()
    with MslReader(path) as reader:
        fh = reader.file_header
        assert (fh.dump_uuid, fh.timestamp_ns, fh.clock_source) == (
            UUID(int=5), 123, 2)
        assert reader.collect_end_of_capture()[0].acq_end_ns == 456


def test_writer_raw_block_capabilities_and_appendix(tmp_path):
    path = tmp_path / "w.msl"
    w = MslWriter(path)
    parent = w.add_raw_block(0x7777, b"parent\x00\x00", block_uuid=UUID(int=1))
    child = w.add_raw_block(0x7777, b"child\x00\x00\x00", parent_uuid=parent,
                            flags=0x10)
    w.add_capabilities(CapBit.MODULE_LIST)
    w.add_raw_appendix(b"")
    with pytest.raises(ValueError):
        w.add_raw_appendix(b"")
    w.add_end_of_capture()
    w.write()
    with MslReader(path) as reader:
        headers = [h for h in reader._iter_raw_block_headers()
                   if h.block_type == 0x7777]
        assert reader.file_header.cap_bitmap & CapBit.MODULE_LIST
        assert verify_chain(reader).valid
    assert [(h.block_uuid, h.parent_uuid, h.flags) for h in headers] == [
        (UUID(int=1), UUID(int=0), 0), (child, parent, 0x10)]
