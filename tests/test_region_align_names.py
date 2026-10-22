"""Alignment keys stay stable when mapping names are stored (W1a).

* MemDiver imports keep their stored types, so unfiltered keys equal those
  of the same import with names stripped.
* Live memslicer captures: old releases stored path-rule types and no names;
  new ones store name-based types plus a named VAS_MAP. The legacy fold
  (``region_names.legacy_live_region_type``) gives both identical keys.
* A filtered alignment mixing name-classified and stored-type dumps warns.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path

from memdiver.core.region_align import (BASIS_MAPPING_NAMES,
                                        BASIS_STORED_TYPE, DumpRegionMap,
                                        align_dumps, build_dump_region_map,
                                        classification_basis_warning)
from memdiver.msl import importer as importer_mod
from memdiver.msl.enums import RegionType
from memdiver.msl.importer import import_dump, import_msl_passthrough
from memdiver.msl.reader import MslReader
from memdiver.msl.region_names import legacy_live_region_type
from memdiver.msl.region_select import RegionSelection, parse_selection
from memdiver.msl.types import MslVasEntry
from memdiver.msl.writer import MslWriter

from tests.fixtures.android.generate_app_process_bin import \
    write_app_process_bin

VECTORS = json.loads((Path(__file__).parent / "fixtures"
                      / "region_name_vectors.json").read_text("utf-8"))
DEFAULT = RegionSelection.default_interactive()
PAGE = 4096
_MEMSLICER_TYPES = {
    "Unknown": RegionType.UNKNOWN, "Heap": RegionType.HEAP,
    "Stack": RegionType.STACK, "Image": RegionType.IMAGE,
    "MappedFile": RegionType.MAPPED_FILE, "Anon": RegionType.ANONYMOUS,
    "SharedMem": RegionType.SHARED_MEM, "Other": RegionType.OTHER,
}


def _keys(path: Path, region_filter=None):
    with MslReader(path) as reader:
        rmap = build_dump_region_map(0, reader, metadata_only=True,
                                     region_filter=region_filter)
    return sorted(rmap.regions), rmap


def _android_import(tmp_path: Path, name: str) -> Path:
    src = write_app_process_bin(tmp_path / f"{name}.bin")
    out = tmp_path / f"{name}.msl"
    import_dump(src, out, maps_path=src.with_suffix(".maps"))
    return out


def _strip_names(monkeypatch) -> None:
    """Make the importer behave as before W1a (no names, no marker)."""
    monkeypatch.setattr(importer_mod, "_named_base_note", lambda note: note)
    monkeypatch.setattr(importer_mod, "_add_named_vas_map",
                        importer_mod._add_vas_map_if_excluded)


# -- MemDiver imports ------------------------------------------------------------


def test_unfiltered_keys_unchanged_by_names(tmp_path, monkeypatch):
    named_keys, named_map = _keys(_android_import(tmp_path, "named"))
    _strip_names(monkeypatch)
    plain_keys, plain_map = _keys(_android_import(tmp_path, "plain"))
    assert named_keys == plain_keys
    assert any(k.startswith("anon:") for k in named_keys)
    assert named_map.classification_basis == BASIS_MAPPING_NAMES
    assert plain_map.classification_basis == BASIS_STORED_TYPE
    assert not named_map.filtered


# -- live memslicer captures -----------------------------------------------------


def _memslicer_msl(path: Path, new_style: bool) -> Path:
    """One page per vector name; old style: legacy types, no VAS_MAP."""
    writer = MslWriter(path, imported=False)
    entries = []
    for idx, row in enumerate(VECTORS):
        base = 0x10000000 + idx * 2 * PAGE
        rtype = (_MEMSLICER_TYPES[row["memslicer_region_type"]] if new_style
                 else legacy_live_region_type(row["name"]))
        writer.add_memory_region(base, bytes([idx & 0xFF]) * PAGE,
                                 region_type=int(rtype))
        entries.append(MslVasEntry(base, PAGE, 3, int(rtype), row["name"]))
    if new_style:
        writer.add_vas_map(entries)
    writer.add_end_of_capture()
    writer.write()
    return path


def test_old_and_new_memslicer_files_have_identical_anon_keys(tmp_path):
    old_keys, old_map = _keys(_memslicer_msl(tmp_path / "old.msl", False))
    new_keys, new_map = _keys(_memslicer_msl(tmp_path / "new.msl", True))
    assert all(k.startswith("anon:") for k in new_keys)
    assert new_keys == old_keys
    assert old_map.classification_basis == BASIS_STORED_TYPE
    assert new_map.classification_basis == BASIS_MAPPING_NAMES


def test_new_memslicer_types_really_differ_from_legacy():
    """Guard: the fold is exercised (types differ for many vector names)."""
    differing = [r for r in VECTORS
                 if int(_MEMSLICER_TYPES[r["memslicer_region_type"]])
                 != legacy_live_region_type(r["name"])]
    assert len(differing) > 20


def test_materialized_memslicer_copy_keeps_keys(tmp_path):
    src = _memslicer_msl(tmp_path / "new.msl", True)
    copy = tmp_path / "copy.msl"
    import_msl_passthrough(src, copy, selection=parse_selection(
        "all", exclude="runtime"), materialize=True)
    src_keys, _ = _keys(src, parse_selection("all", exclude="runtime"))
    copy_keys, _ = _keys(copy)
    assert copy_keys == src_keys


# -- mixed-basis warning ---------------------------------------------------------


def test_mixed_basis_warning_when_filtered(tmp_path, monkeypatch, caplog):
    named = _android_import(tmp_path, "named")
    _strip_names(monkeypatch)
    plain = _android_import(tmp_path, "plain")
    maps = [_keys(p, DEFAULT)[1] for p in (named, plain)]
    assert all(m.filtered for m in maps)
    message = classification_basis_warning(maps)
    assert message and "1 of 2" in message
    with caplog.at_level(logging.WARNING, logger="memdiver"):
        align_dumps(maps)
    assert any("classification bases" in r.getMessage()
               for r in caplog.records)


def test_no_basis_warning_unfiltered_or_uniform(tmp_path):
    named = DumpRegionMap(0, classification_basis=BASIS_MAPPING_NAMES)
    plain = DumpRegionMap(1)
    assert classification_basis_warning([named, plain]) is None
    named.filtered = plain.filtered = True
    assert classification_basis_warning([named, plain])
    plain.classification_basis = BASIS_MAPPING_NAMES
    assert classification_basis_warning([named, plain]) is None


def test_align_dumps_filter_marks_maps_filtered():
    rm = DumpRegionMap(0)
    # region_filter re-application path keeps basis and marks filtered
    from memdiver.core.region_align import _filter_region_map
    out = _filter_region_map(rm, DEFAULT)
    assert out.filtered and out.classification_basis == BASIS_STORED_TYPE
