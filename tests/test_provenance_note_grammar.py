"""IMPORT_PROVENANCE ``note`` grammar, as documented in msl_v1_0_0.md.

Parses notes produced by real imports / materialize with a parser written
from the spec text (independent of ``msl.region_select``), then cross-checks
it against the library's own ``split_provenance_note``.

    note       = base-note *( "; " field-list )
    field-list = field *( ";" field )
    field      = key "=" value
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Dict, List, Tuple

from memdiver.msl.importer import import_dump, import_msl_passthrough
from memdiver.msl.reader import MslReader
from memdiver.msl.region_select import (RegionSelection, parse_selection,
                                        split_provenance_note)

from tests.fixtures import synth_elf_core

_SEGMENT_SEP = "; "
_FIELD_RE = re.compile(r"^[a-z_]+=[^;]*$")
_SELECTION_KEYS = {"regions", "writable", "modules", "excluded_regions",
                   "excluded_bytes", "fallback"}
_MATERIALIZE_KEYS = {"source_format", "materialized", "dropped_key_hints",
                     "orig_eoc_hash", "region_names"}
# ELF / regioned imports append this field list to their base note.
_NAMES_MARKER = {"region_names": "1"}


def _is_field_list(segment: str) -> bool:
    return all(_FIELD_RE.match(part) for part in segment.split(";"))


def parse_note(note: str) -> Tuple[str, List[Dict[str, str]]]:
    """Split *note* into (base note, [field-list dicts]) per the spec."""
    segments = note.split(_SEGMENT_SEP)
    base_parts: List[str] = []
    while segments and not _is_field_list(segments[0]):
        base_parts.append(segments.pop(0))
    assert all(_is_field_list(s) for s in segments), note
    field_lists = [dict(p.split("=", 1) for p in s.split(";"))
                   for s in segments]
    return _SEGMENT_SEP.join(base_parts), field_lists


def _note(path: Path) -> str:
    with MslReader(path) as reader:
        (prov,) = reader.collect_import_provenance()
        return prov.note


def _eoc_hash(path: Path) -> str:
    with MslReader(path) as reader:
        return reader.collect_end_of_capture()[0].file_hash.hex()


def _core(tmp_path: Path) -> Path:
    core = tmp_path / "t.core"
    core.write_bytes(synth_elf_core.build_core_bytes(
        threads=[(101, synth_elf_core._ASLR_BASE + 5 * 0x1000 + 0x800)]))
    return core


def test_selection_note_matches_grammar(tmp_path):
    core = _core(tmp_path)
    out = tmp_path / "sel.msl"
    result = import_dump(core, out, selection=parse_selection("heap,stack"))
    note = _note(out)

    base, (marker, fields) = parse_note(note)
    assert marker == _NAMES_MARKER
    assert base == f"Imported from ELF core {core.name}"
    assert set(fields) <= _SELECTION_KEYS
    assert list(fields)[0] == "regions"
    assert fields["regions"] == "heap,stack"
    assert int(fields["excluded_regions"]) == result.excluded_region_count > 0
    assert int(fields["excluded_bytes"]) == result.excluded_bytes > 0
    assert "fallback" not in fields
    assert split_provenance_note(note) == (base + "; region_names=1", ";".join(
        f"{k}={v}" for k, v in fields.items()))


def test_fallback_note_matches_grammar(tmp_path):
    core = _core(tmp_path)
    out = tmp_path / "fb.msl"
    nothing = RegionSelection(parse_selection("image").categories,
                              writable_only=True,
                              module_globs=("no-such-lib*",))
    import_dump(core, out, selection=nothing)

    _, (marker, fields) = parse_note(_note(out))
    assert marker == _NAMES_MARKER
    assert fields == {"regions": "all", "excluded_regions": "0",
                      "excluded_bytes": "0", "fallback": "all"}


def test_materialize_note_matches_grammar(tmp_path):
    core = _core(tmp_path)
    full = tmp_path / "full.msl"
    import_dump(core, full)
    out = tmp_path / "mat.msl"
    result = import_msl_passthrough(full, out,
                                    selection=parse_selection("heap"),
                                    materialize=True)
    assert result.materialized
    note = _note(out)

    base, (marker, mat, sel) = parse_note(note)
    assert marker == _NAMES_MARKER
    assert base == f"Imported from ELF core {core.name}"
    assert _note(full) == f"Imported from ELF core {core.name}; region_names=1"
    assert mat["region_names"] == "1"  # trusted names stay trusted
    assert set(mat) <= _MATERIALIZE_KEYS
    assert (mat["source_format"], mat["materialized"]) == ("msl", "1")
    assert int(mat["dropped_key_hints"]) == 0
    assert mat["orig_eoc_hash"] == _eoc_hash(full)
    assert len(mat["orig_eoc_hash"]) == 64
    assert sel["regions"] == "heap"
    assert int(sel["excluded_regions"]) == result.excluded_region_count > 0
    # The library's splitter finds the same (last) selection segment.
    _, lib_sel = split_provenance_note(note)
    assert lib_sel == ";".join(f"{k}={v}" for k, v in sel.items())
