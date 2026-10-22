"""Tests for :mod:`msl.region_select` and :mod:`msl.import_preview`."""

from __future__ import annotations

from pathlib import Path

import pytest

from memdiver.core.binary_formats.minidump_reader import (
    MEM_COMMIT, MEM_FREE, MEM_IMAGE, MEM_PRIVATE, PAGE_EXECUTE_READ,
    PAGE_READWRITE,
)
from memdiver.msl.enums import CompAlgo, PageState, Protection, RegionType
from memdiver.msl.import_preview import ImportPreview, preview_import
from memdiver.msl.importer import import_dump
from memdiver.msl.page_map import count_captured_pages
from memdiver.msl.reader import MslReader
from memdiver.msl.region_select import (
    RegionCategory as C, RegionInfo, RegionSelection, classify,
    parse_selection,
)
from memdiver.msl.writer import MslWriter

from tests.fixtures import synth_elf_core
from tests.test_minidump_reader import AMD64, _build_minidump

R, W, X = int(Protection.READ), int(Protection.WRITE), int(Protection.EXECUTE)
PAGE = 4096


def _info(category, protection=R | W, path=None, rtype=RegionType.ANONYMOUS):
    return RegionInfo(0x1000, PAGE, protection, int(rtype), category, path, PAGE)


def _imported_regions(msl_path: Path):
    with MslReader(msl_path) as reader:
        return sorted(
            (r.base_addr, r.region_size, r.protection, r.region_type,
             count_captured_pages(r.page_intervals) * r.page_size)
            for r in reader.collect_regions())


def _previewed_regions(preview: ImportPreview):
    return sorted((r.base_addr, r.size, r.protection, r.region_type,
                   r.captured_bytes) for r in preview.regions)


# -- parse_selection ----------------------------------------------------------


def test_parse_none_returns_none():
    assert parse_selection(None) is None


def test_parse_list_and_aliases():
    sel = parse_selection(" Heap , stack,image-data")
    assert sel.categories == {C.HEAP, C.STACK, C.IMAGE_DATA}
    assert parse_selection("image").categories == {C.IMAGE_CODE, C.IMAGE_DATA}


def test_parse_all_and_is_all():
    sel = parse_selection("all")
    assert sel.is_all and sel == RegionSelection.all()


def test_parse_exclude():
    # "all" includes the name-only RUNTIME category (appended last).
    assert parse_selection("all", exclude="image,mapped_file").categories == {
        C.HEAP, C.STACK, C.SHARED, C.UNCLASSIFIED, C.RUNTIME}
    assert C.STACK not in parse_selection(None, exclude="stack").categories


@pytest.mark.parametrize("spec,exclude", [("bogus", None), ("heap", "nope"),
                                          (",", None)])
def test_parse_invalid_lists_valid_names(spec, exclude):
    with pytest.raises(ValueError, match="valid names: heap"):
        parse_selection(spec, exclude)


def test_parse_empty_result_rejected():
    with pytest.raises(ValueError, match="excludes every"):
        parse_selection("heap", exclude="heap")


# -- classify -----------------------------------------------------------------


@pytest.mark.parametrize("rtype,prot,stacks,expected", [
    (RegionType.SHARED_MEM, R | W, (), C.SHARED),
    (RegionType.STACK, R | W, (), C.STACK),
    (RegionType.ANONYMOUS, R | W, [(0x1800, 0x10)], C.STACK),
    (RegionType.UNKNOWN, R | W, [(0x1000, PAGE)], C.STACK),
    # A thread SP never turns a file-backed or shared mapping into a stack.
    (RegionType.MAPPED_FILE, R | W, [(0x1800, 0x10)], C.IMAGE_DATA),
    (RegionType.IMAGE, R | X, [(0x1800, 0x10)], C.IMAGE_CODE),
    (RegionType.SHARED_MEM, R | W, [(0x1800, 0x10)], C.SHARED),
    (RegionType.ANONYMOUS, R | W, [(0x3000, 0x100)], C.HEAP),
    (RegionType.HEAP, R | W, (), C.HEAP),
    (RegionType.ANONYMOUS, R, (), C.HEAP),
    (RegionType.IMAGE, R | W, (), C.IMAGE_DATA),
    (RegionType.MAPPED_FILE, R | W, (), C.IMAGE_DATA),
    (RegionType.IMAGE, R | X, (), C.IMAGE_CODE),
    (RegionType.MAPPED_FILE, R, (), C.MAPPED_FILE),
    (RegionType.UNKNOWN, R | W, (), C.UNCLASSIFIED),
    (RegionType.OTHER, 0, (), C.UNCLASSIFIED),
])
def test_classify_table(rtype, prot, stacks, expected):
    assert classify(int(rtype), prot, 0x1000, PAGE, stacks, None) is expected


# -- RegionSelection.includes ---------------------------------------------------


def test_default_interactive():
    sel = RegionSelection.default_interactive()
    assert sel.includes(_info(C.HEAP)) and sel.includes(_info(C.STACK))
    assert not sel.includes(_info(C.IMAGE_DATA))
    assert not sel.is_all


def test_writable_only_filters_but_keeps_unknown_protection():
    sel = RegionSelection(frozenset(C), writable_only=True)
    assert sel.includes(_info(C.HEAP, R | W))
    assert not sel.includes(_info(C.HEAP, R))
    assert not sel.includes(_info(C.IMAGE_CODE, R | X))
    assert sel.includes(_info(C.UNCLASSIFIED, 0, rtype=RegionType.UNKNOWN))
    assert not sel.includes(_info(C.UNCLASSIFIED, R, rtype=RegionType.UNKNOWN))
    assert not sel.is_all


def test_module_globs_full_path_and_basename():
    sel = RegionSelection(frozenset({C.HEAP}),
                          module_globs=("libssl.so*", "/opt/*/libfoo.so"))
    assert sel.includes(_info(C.IMAGE_CODE, R | X, "/usr/lib/libssl.so.3"))
    assert sel.includes(_info(C.IMAGE_DATA, R | W, "/opt/app/libfoo.so"))
    assert not sel.includes(_info(C.IMAGE_CODE, R | X, "/usr/lib/libc.so.6"))
    assert not sel.includes(_info(C.IMAGE_CODE, R | X, None))


def test_module_globs_still_honour_writable_only():
    sel = RegionSelection(frozenset(), writable_only=True,
                          module_globs=("libssl*",))
    assert sel.includes(_info(C.IMAGE_DATA, R | W, "/lib/libssl.so.3"))
    assert not sel.includes(_info(C.IMAGE_CODE, R | X, "/lib/libssl.so.3"))


# -- to_note / from_note --------------------------------------------------------


@pytest.mark.parametrize("sel", [
    RegionSelection.default_interactive(),
    RegionSelection.all(),
    RegionSelection(frozenset({C.STACK}), writable_only=True,
                    module_globs=("libssl*", "*/libcrypto.so.3")),
])
def test_note_round_trip(sel):
    assert RegionSelection.from_note(sel.to_note()) == sel


def test_note_is_stable_and_sorted():
    assert RegionSelection.default_interactive().to_note() == \
        "regions=heap,stack,unclassified"
    assert RegionSelection.all().to_note() == "regions=all"


@pytest.mark.parametrize("note", ["", "heap", "writable=1", "regions=nope"])
def test_from_note_rejects_garbage(note):
    with pytest.raises(ValueError):
        RegionSelection.from_note(note)


# -- preview: raw -------------------------------------------------------------


def test_preview_raw(tmp_path):
    path = tmp_path / "x.dump"
    path.write_bytes(b"\x41" * 5000)
    preview = preview_import(path)
    assert not preview.is_msl
    (region,) = preview.regions
    assert region.category is C.UNCLASSIFIED
    assert (region.base_addr, region.size, region.captured_bytes) == (0, 8192, 8192)
    assert preview.totals == {C.UNCLASSIFIED: (1, 8192)}
    assert preview.summarize(RegionSelection.default_interactive()) == (1, 8192, 0, 0)


# -- preview: ELF core ----------------------------------------------------------

_STACK_SP = synth_elf_core._ASLR_BASE + 5 * 0x1000 + 0x80


def _elf_core(tmp_path: Path) -> Path:
    path = tmp_path / "t.core"
    path.write_bytes(synth_elf_core.build_core_bytes(
        threads=[(101, _STACK_SP), (102, 0xDEAD0000)]))
    return path


def test_preview_elf_categories(tmp_path):
    preview = preview_import(_elf_core(tmp_path))
    assert preview.format == "elf_core" and len(preview.regions) == 12
    by_base = {r.base_addr: r for r in preview.regions}
    base = synth_elf_core._ASLR_BASE
    assert by_base[base + 5 * 0x1000].category is C.STACK
    # The import stores the thread stack as STACK (promoted from ANONYMOUS).
    assert by_base[base + 5 * 0x1000].region_type == RegionType.STACK
    # Main executable is MAPPED_FILE (_looks_like_image only matches .so/lib).
    assert by_base[base].category is C.MAPPED_FILE
    assert by_base[base].module_path == "/usr/bin/gocryptfs"
    assert by_base[base + 3 * 0x1000].category is C.HEAP
    assert by_base[base + 2 * 0x1000].module_path is None


def test_preview_elf_matches_import(tmp_path):
    core = _elf_core(tmp_path)
    out = tmp_path / "t.msl"
    import_dump(core, out)
    assert _previewed_regions(preview_import(core)) == _imported_regions(out)


def test_preview_elf_summary_and_dict(tmp_path):
    preview = preview_import(_elf_core(tmp_path))
    inc_n, inc_b, exc_n, exc_b = preview.summarize(
        parse_selection("stack"))
    assert (inc_n, exc_n) == (1, 11) and inc_b == PAGE
    assert inc_b + exc_b == sum(b for _, b in preview.totals.values())
    data = preview.to_dict(parse_selection("stack"))
    assert data["totals"]["stack"] == {"count": 1, "bytes": PAGE}
    assert data["summary"]["included_count"] == 1
    assert data["regions"][0]["category"] in {c.value for c in C}


# -- preview: minidump ----------------------------------------------------------


def _minidump(tmp_path: Path) -> Path:
    mem_infos = [
        (0x10000, 0x10000, PAGE_EXECUTE_READ, 0x2000, MEM_COMMIT,
         PAGE_EXECUTE_READ, MEM_IMAGE),
        (0x20000, 0x20000, PAGE_READWRITE, 0x3000, MEM_COMMIT,
         PAGE_READWRITE, MEM_PRIVATE),
        (0x30000, 0x30000, PAGE_READWRITE, 0x2000, MEM_COMMIT,
         PAGE_READWRITE, MEM_PRIVATE),
        (0x40000, 0, 0, 0x10000, MEM_FREE, 0, 0),
    ]
    descriptors = [(0x10000, b"C" * 0x1000), (0x20800, b"H" * 0x1000),
                   (0x30000, b"S" * 0x2000), (0x90000, b"Z" * 0x100)]
    threads = [(7, 0x7FF000, 0x30000, 0x2000)]
    path = tmp_path / "t.dmp"
    path.write_bytes(_build_minidump(descriptors, mem_infos=mem_infos,
                                     arch=AMD64, threads=threads))
    return path


def test_preview_minidump_categories(tmp_path):
    preview = preview_import(_minidump(tmp_path))
    cats = {r.base_addr: r.category for r in preview.regions}
    assert cats == {0x10000: C.IMAGE_CODE, 0x20000: C.HEAP,
                    0x30000: C.STACK, 0x90000: C.UNCLASSIFIED}
    heap = next(r for r in preview.regions if r.base_addr == 0x20000)
    assert heap.captured_bytes == 2 * PAGE  # span straddles two pages


def test_preview_minidump_matches_import(tmp_path):
    dmp = _minidump(tmp_path)
    out = tmp_path / "t.msl"
    import_dump(dmp, out)
    assert _previewed_regions(preview_import(dmp)) == _imported_regions(out)


# -- preview: .msl ------------------------------------------------------------


def _forbid_payload_reads(monkeypatch):
    def _boom(*_a, **_k):
        raise AssertionError("preview must not copy region payloads")
    monkeypatch.setattr(MslReader, "collect_regions", _boom)
    monkeypatch.setattr(MslReader, "_iter_raw_blocks", _boom)


def test_preview_msl_header_only(tmp_path, monkeypatch):
    core = _elf_core(tmp_path)
    out = tmp_path / "t.msl"
    import_dump(core, out)
    expected = _imported_regions(out)
    _forbid_payload_reads(monkeypatch)
    preview = preview_import(out)
    assert preview.is_msl and preview.format == "msl"
    assert _previewed_regions(preview) == expected
    paths = {r.module_path for r in preview.regions}
    assert "/usr/bin/gocryptfs" in paths
    # No thread ranges in .msl, but the import stored the stack as STACK.
    stack_base = synth_elf_core._ASLR_BASE + 5 * 0x1000
    assert [r.base_addr for r in preview.regions
            if r.category is C.STACK] == [stack_base]
    assert {r.category for r in preview.regions} <= {
        C.HEAP, C.STACK, C.IMAGE_CODE, C.IMAGE_DATA, C.MAPPED_FILE}


def test_preview_msl_compressed_region(tmp_path):
    out = tmp_path / "c.msl"
    writer = MslWriter(out)
    try:
        writer.add_memory_region(
            0x5000, b"\x11" * PAGE, protection=R | W,
            region_type=int(RegionType.SHARED_MEM),
            page_states=[PageState.CAPTURED, PageState.FAILED],
            compression=CompAlgo.ZSTD)
    except Exception as exc:  # noqa: BLE001 — optional codec missing
        pytest.skip(f"zstd unavailable: {exc}")
    writer.add_end_of_capture()
    writer.write()
    (region,) = preview_import(out).regions
    assert (region.base_addr, region.size, region.captured_bytes) == (
        0x5000, 2 * PAGE, PAGE)
    assert region.category is C.SHARED
