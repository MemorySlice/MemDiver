"""Region selection wired into conversion imports (ELF core, minidump, raw)."""

from __future__ import annotations

from pathlib import Path

import pytest

from memdiver.core.models import CryptoSecret
from memdiver.msl.enums import Protection, RegionType, SourceFormat
from memdiver.msl.import_preview import preview_import
from memdiver.msl.importer import ImportResult, import_dump, import_raw_dump
from memdiver.msl.reader import MslReader
from memdiver.msl.region_select import (
    RegionCategory as C, RegionSelection, classify_stored, parse_selection,
    selection_from_provenance_note, split_provenance_note,
)
from memdiver.msl.types import MslVasEntry
from memdiver.msl.writer import MslWriter

from tests.fixtures import synth_elf_core
from tests.test_region_select import (_elf_core, _imported_regions,
                                      _minidump)

HEAP_STACK = parse_selection("heap,stack")


def _provenance(path: Path):
    with MslReader(path) as reader:
        (prov,) = reader.collect_import_provenance()
        return prov


def _vas_entries(path: Path):
    with MslReader(path) as reader:
        return [e for vm in reader.collect_vas_map() for e in vm.entries]


def _region_bases(path: Path):
    with MslReader(path) as reader:
        return sorted(r.base_addr for r in reader.collect_regions())


def _expected_split(src: Path, selection: RegionSelection):
    preview = preview_import(src)
    kept = sorted(r.base_addr for r in preview.regions if selection.includes(r))
    dropped = [r for r in preview.regions if not selection.includes(r)]
    return preview, kept, dropped


def _seg_secret(index: int) -> CryptoSecret:
    """16 bytes unique to PT_LOAD segment *index* of the synthetic core."""
    value = synth_elf_core._load_body(index)[:16]
    return CryptoSecret("CLIENT_RANDOM", b"\x00" * 32, value)


# -- ELF core ---------------------------------------------------------------


def test_elf_heap_stack_writes_only_selected(tmp_path):
    core = _elf_core(tmp_path)
    out = tmp_path / "sel.msl"
    result = import_dump(core, out, selection=HEAP_STACK)
    preview, kept, dropped = _expected_split(core, HEAP_STACK)

    assert dropped, "fixture must exclude something"
    assert _region_bases(out) == kept
    assert result.regions_written == len(kept)
    assert result.excluded_region_count == len(dropped)
    assert result.excluded_bytes == sum(r.captured_bytes for r in dropped)
    assert result.selection == HEAP_STACK.to_note()
    assert result.warnings == []

    vas = _vas_entries(out)
    assert sorted(e.base_addr for e in vas) == sorted(
        r.base_addr for r in preview.regions)
    by_base = {e.base_addr: e for e in vas}
    for r in preview.regions:
        e = by_base[r.base_addr]
        assert (e.region_size, e.protection, e.region_type) == (
            r.size, r.protection, r.region_type)
        assert e.mapped_path == (r.module_path or "")


def _assert_vas_mirrors_regions(path) -> None:
    """Nothing excluded: one VAS entry per stored region, same base/size."""
    with MslReader(path) as reader:
        regions = sorted((r.base_addr, r.region_size)
                         for r in reader.collect_regions())
    assert sorted((e.base_addr, e.region_size)
                  for e in _vas_entries(path)) == regions


def test_elf_provenance_note_parseable(tmp_path):
    core = _elf_core(tmp_path)
    out = tmp_path / "sel.msl"
    result = import_dump(core, out, selection=HEAP_STACK)
    note = _provenance(out).note
    base, sel_note = split_provenance_note(note)
    # ELF imports always mark their (always written) VAS_MAP names.
    assert base == f"Imported from ELF core {core.name}; region_names=1"
    assert RegionSelection.from_note(sel_note) == HEAP_STACK
    assert selection_from_provenance_note(note) == HEAP_STACK
    assert f"excluded_regions={result.excluded_region_count}" in sel_note
    assert f"excluded_bytes={result.excluded_bytes}" in sel_note


def test_elf_secret_only_in_excluded_counted(tmp_path):
    core = _elf_core(tmp_path)
    out = tmp_path / "sel.msl"
    # Segment 0 is the main executable (MAPPED_FILE: excluded); segment 3 is
    # anonymous (HEAP: kept).
    secrets = [_seg_secret(0), _seg_secret(3)]
    result = import_dump(core, out, secrets=secrets, selection=HEAP_STACK)
    assert result.secrets_only_in_excluded == 1
    assert result.key_hints_written == 1
    assert any("only in excluded regions" in w for w in result.warnings)


def test_elf_none_selection_identical(tmp_path):
    core = _elf_core(tmp_path)
    plain, again = tmp_path / "a.msl", tmp_path / "b.msl"
    r1 = import_dump(core, plain)
    r2 = import_dump(core, again, selection=None)
    assert _imported_regions(plain) == _imported_regions(again)
    # ELF imports now ALWAYS write the named VAS_MAP (W1a: names persist
    # for classification); with nothing excluded it mirrors the regions.
    _assert_vas_mirrors_regions(again)
    assert _vas_entries(again) == _vas_entries(plain)
    assert _provenance(again).note == (
        f"Imported from ELF core {core.name}; region_names=1")
    assert (r2.selection, r2.excluded_region_count, r2.warnings) == (None, 0, [])
    assert r1.regions_written == r2.regions_written == 12


def test_elf_all_selection_same_regions_no_vas(tmp_path):
    core = _elf_core(tmp_path)
    plain, everything = tmp_path / "a.msl", tmp_path / "b.msl"
    import_dump(core, plain)
    result = import_dump(core, everything, selection=RegionSelection.all())
    assert _imported_regions(plain) == _imported_regions(everything)
    _assert_vas_mirrors_regions(everything)  # always written (W1a)
    assert result.excluded_region_count == 0
    assert selection_from_provenance_note(
        _provenance(everything).note) == RegionSelection.all()


def test_zero_byte_selection_falls_back_to_all(tmp_path):
    core = _elf_core(tmp_path)
    plain, shared = tmp_path / "a.msl", tmp_path / "b.msl"
    import_dump(core, plain)
    result = import_dump(core, shared, selection=parse_selection("shared"))
    assert _imported_regions(plain) == _imported_regions(shared)
    _assert_vas_mirrors_regions(shared)  # always written (W1a)
    assert result.excluded_region_count == 0
    assert result.selection == RegionSelection.all().to_note()
    assert any("0 captured bytes" in w for w in result.warnings)
    assert "fallback=all" in _provenance(shared).note


# -- minidump ---------------------------------------------------------------


def test_minidump_heap_stack(tmp_path):
    dmp = _minidump(tmp_path)
    out = tmp_path / "sel.msl"
    secrets = [CryptoSecret("CLIENT_RANDOM", b"\x00" * 32, b"C" * 32)]
    result = import_dump(dmp, out, secrets=secrets, selection=HEAP_STACK)
    assert _region_bases(out) == [0x20000, 0x30000]
    assert result.excluded_region_count == 2
    assert sorted(e.base_addr for e in _vas_entries(out)) == [
        0x10000, 0x20000, 0x30000, 0x90000]
    assert selection_from_provenance_note(_provenance(out).note) == HEAP_STACK
    # "C" bytes live only in the IMAGE region (excluded).
    assert result.secrets_only_in_excluded == 1
    assert result.warnings


def test_minidump_none_and_all_identical(tmp_path):
    dmp = _minidump(tmp_path)
    plain, everything = tmp_path / "a.msl", tmp_path / "b.msl"
    import_dump(dmp, plain)
    import_dump(dmp, everything, selection=RegionSelection.all())
    assert _imported_regions(plain) == _imported_regions(everything)
    assert _vas_entries(plain) == _vas_entries(everything) == []


# -- raw / .msl -------------------------------------------------------------


def test_raw_selection_keeps_region_type_and_falls_back(tmp_path):
    raw = tmp_path / "x.dump"
    raw.write_bytes(b"\x41" * 5000)
    plain, heap = tmp_path / "a.msl", tmp_path / "b.msl"
    import_raw_dump(raw, plain)
    result = import_dump(raw, heap, selection=parse_selection("heap"))
    assert _imported_regions(plain) == _imported_regions(heap)
    assert result.warnings and result.excluded_region_count == 0
    kept = import_dump(raw, tmp_path / "c.msl",
                       selection=parse_selection("unclassified"))
    assert kept.warnings == [] and kept.selection == "regions=unclassified"


def test_msl_passthrough_warns_and_copies(tmp_path):
    core = _elf_core(tmp_path)
    src, out = tmp_path / "s.msl", tmp_path / "o.msl"
    import_dump(core, src)
    result = import_dump(src, out, selection=HEAP_STACK)
    assert out.read_bytes() == src.read_bytes()
    assert any("materialize" in w for w in result.warnings)


def test_raw_provenance_preview_unclassified(tmp_path):
    raw = tmp_path / "x.dump"
    raw.write_bytes(b"\x41" * 5000)
    out = tmp_path / "x.msl"
    import_raw_dump(raw, out)
    (region,) = preview_import(out).regions
    assert region.region_type == RegionType.ANONYMOUS  # stored type unchanged
    assert region.category is C.UNCLASSIFIED


def test_classify_stored_rule():
    rw = int(Protection.READ | Protection.WRITE)
    anon = int(RegionType.ANONYMOUS)
    assert classify_stored(anon, rw, 0, 4096) is C.HEAP
    assert classify_stored(anon, rw, 0, 4096,
                           source_format=SourceFormat.RAW_DUMP) is C.UNCLASSIFIED
    assert classify_stored(anon, rw, 0, 4096,
                           source_format=SourceFormat.ELF_CORE) is C.HEAP


# -- writer VAS_MAP round trip ---------------------------------------------


def test_vas_map_round_trip(tmp_path):
    out = tmp_path / "v.msl"
    entries = [
        MslVasEntry(0x1000, 0x2000, 0x05, int(RegionType.IMAGE), "/lib/libc.so.6"),
        MslVasEntry(0x8000, 0x1000, 0x03, int(RegionType.ANONYMOUS), ""),
        MslVasEntry(0x9000, 0x1000, 0x01, int(RegionType.MAPPED_FILE), "a" * 7),
    ]
    writer = MslWriter(out)
    writer.add_memory_region(0x8000, b"\x00" * 0x1000)
    writer.add_vas_map(entries)
    writer.write()
    with MslReader(out) as reader:
        (vm,) = reader.collect_vas_map()
    assert vm.entry_count == 3
    assert vm.entries == entries


def test_import_result_old_constructor_defaults():
    r = ImportResult(Path("a"), Path("b"), 1, 0, 10)
    assert (r.selection, r.excluded_region_count, r.excluded_bytes,
            r.secrets_only_in_excluded, r.warnings) == (None, 0, 0, 0, [])
    assert not r.has_selection_info
    assert set(r.selection_summary()) == {
        "selection", "excluded_region_count", "excluded_bytes",
        "secrets_only_in_excluded", "warnings"}


@pytest.mark.parametrize("bad", ["Imported from x", ""])
def test_selection_from_note_absent(bad):
    assert selection_from_provenance_note(bad) is None
