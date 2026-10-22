"""Thread stacks survive ELF-core / minidump conversion as ``RegionType.STACK``.

The importers classify a region as STACK from side information (a thread's
saved SP / the minidump ThreadList) that a ``.msl`` does not carry, so the
written MEMORY_REGION records it as ``region_type=STACK``. Alignment keys
fold such importer-derived STACK regions back into the ANONYMOUS key class,
so a ``.msl`` imported before stacks were recorded (stack stored ANONYMOUS)
aligns key-for-key with one imported now.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from memdiver.core.dump_source import MslDumpSource
from memdiver.core.region_align import align_dumps, build_dump_region_map
from memdiver.core.region_view_filter import region_filter_mask
from memdiver.msl import import_preview
from memdiver.msl.enums import RegionType, SourceFormat
from memdiver.msl.import_preview import preview_import
from memdiver.msl.importer import import_dump
from memdiver.msl.reader import MslReader
from memdiver.msl.region_select import RegionCategory as C
from memdiver.msl.region_select import (alignment_region_type, parse_selection,
                                        stored_region_type)
from tests.test_region_select import _STACK_SP, _elf_core, _minidump

STACK_BASE = _STACK_SP & ~0xFFF
STACK_ONLY = parse_selection("stack")


def _stored_types(msl_path: Path) -> dict:
    with MslReader(msl_path) as reader:
        return {r.base_addr: r.region_type for r in reader.collect_regions()}


def _import_old_style(src: Path, out: Path, monkeypatch) -> Path:
    """Import as before stacks were recorded: stack stays ANONYMOUS."""
    with monkeypatch.context() as m:
        m.setattr(import_preview, "stored_region_type",
                  lambda rtype, category: rtype)
        import_dump(src, out)
    return out


def _region_keys(msl_path: Path, region_filter=None) -> dict:
    with MslDumpSource(msl_path) as src:
        rmap = build_dump_region_map(0, src.get_reader(),
                                     region_filter=region_filter)
    return {k: r.source_base_addr for k, r in rmap.regions.items()}


# -- stored type -----------------------------------------------------------------


def test_stored_region_type_promotes_only_anonymous_stacks():
    assert stored_region_type(RegionType.ANONYMOUS, C.STACK) == RegionType.STACK
    assert stored_region_type(RegionType.ANONYMOUS, C.HEAP) == RegionType.ANONYMOUS
    assert stored_region_type(RegionType.UNKNOWN, C.STACK) == RegionType.UNKNOWN
    assert stored_region_type(RegionType.IMAGE, C.STACK) == RegionType.IMAGE


@pytest.mark.parametrize("fmt,expected", [
    (SourceFormat.ELF_CORE, RegionType.ANONYMOUS),
    (SourceFormat.MINIDUMP, RegionType.ANONYMOUS),
    (SourceFormat.MSL, RegionType.STACK),
    (None, RegionType.STACK),
])
def test_alignment_region_type_folds_only_derived_stacks(fmt, expected):
    assert alignment_region_type(RegionType.STACK, fmt) == expected
    assert alignment_region_type(RegionType.HEAP, fmt) == RegionType.HEAP


def test_elf_import_stores_stack_type(tmp_path):
    out = tmp_path / "t.msl"
    import_dump(_elf_core(tmp_path), out)
    types = _stored_types(out)
    assert types[STACK_BASE] == RegionType.STACK
    assert sum(t == RegionType.STACK for t in types.values()) == 1


def test_minidump_import_stores_stack_type(tmp_path):
    out = tmp_path / "t.msl"
    import_dump(_minidump(tmp_path), out)
    types = _stored_types(out)
    assert types[0x30000] == RegionType.STACK
    assert types[0x20000] == RegionType.ANONYMOUS


# -- preview / view filter on the converted .msl -------------------------------------


def test_msl_preview_shows_stack_category(tmp_path):
    out = tmp_path / "t.msl"
    import_dump(_elf_core(tmp_path), out)
    cats = {r.base_addr: r.category for r in preview_import(out).regions}
    assert cats[STACK_BASE] is C.STACK
    assert [b for b, c in cats.items() if c is C.STACK] == [STACK_BASE]


def test_stack_view_filter_selects_only_the_stack(tmp_path):
    out = tmp_path / "t.msl"
    import_dump(_elf_core(tmp_path), out)
    with MslReader(out) as reader:
        regions = reader.collect_regions()
        mask = region_filter_mask(reader, STACK_ONLY, regions)
    assert [r.base_addr for r, keep in zip(regions, mask) if keep] == [STACK_BASE]
    assert list(_region_keys(out, STACK_ONLY).values()) == [STACK_BASE]


# -- alignment keys: old-style vs new-style imports -----------------------------------


def test_old_and_new_elf_imports_share_alignment_keys(tmp_path, monkeypatch):
    core = _elf_core(tmp_path)
    old = _import_old_style(core, tmp_path / "old.msl", monkeypatch)
    new = tmp_path / "new.msl"
    import_dump(core, new)
    assert _stored_types(old)[STACK_BASE] == RegionType.ANONYMOUS
    assert _stored_types(new)[STACK_BASE] == RegionType.STACK

    old_keys, new_keys = _region_keys(old), _region_keys(new)
    assert old_keys == new_keys  # same keys, same ordinals, same bases
    stack_key = next(k for k, base in new_keys.items() if base == STACK_BASE)
    assert stack_key.startswith("anon:ANONYMOUS:")


def test_old_and_new_minidump_imports_share_alignment_keys(tmp_path,
                                                          monkeypatch):
    dmp = _minidump(tmp_path)
    old = _import_old_style(dmp, tmp_path / "old.msl", monkeypatch)
    new = tmp_path / "new.msl"
    import_dump(dmp, new)
    assert _region_keys(old) == _region_keys(new)


def test_old_and_new_imports_align_page_for_page(tmp_path, monkeypatch):
    core = _elf_core(tmp_path)
    old = _import_old_style(core, tmp_path / "old.msl", monkeypatch)
    new = tmp_path / "new.msl"
    import_dump(core, new)
    with MslDumpSource(old) as so, MslDumpSource(new) as sn:
        maps = [build_dump_region_map(i, s.get_reader())
                for i, s in enumerate((so, sn))]
    slices = align_dumps(maps)
    assert {s.key for s in slices} == set(maps[0].regions)
    stack = [s for s in slices if s.source_vaddrs[0] == STACK_BASE]
    assert stack and stack[0].source_vaddrs == [STACK_BASE, STACK_BASE]
    assert stack[0].data[0] == stack[0].data[1]
