"""Spec Table 40 source_format collision: 0xFFFF + note origin, legacy-aware read."""

from __future__ import annotations

import pytest

from memdiver.msl.enums import SourceFormat
from memdiver.msl.import_preview import msl_classification_context, msl_source_format
from memdiver.msl.reader import MslReader
from memdiver.msl.region_select import alignment_region_type
from memdiver.msl.enums import RegionType
from memdiver.msl.source_format import (effective_source_format,
                                        note_origin_format, origin_note_field,
                                        wire_source_format)
from memdiver.msl.writer import MslWriter

SF = SourceFormat


def _write(path, code, tool, note):
    w = MslWriter(path)
    w.add_memory_region(0x1000, b"\xAA" * 4096)
    w.add_import_provenance(source_format=code, tool_name=tool,
                            orig_file_size=4096, note=note)
    w.add_end_of_capture()
    w.write()
    return path


def test_new_files_write_other_plus_note_and_read_back_as_origin(tmp_path):
    for fmt in (SF.MSL, SF.REGIONED_RAW):
        note = f"Imported from x; {origin_note_field(fmt)}"
        out = _write(tmp_path / f"{fmt.name}.msl", wire_source_format(fmt),
                     "memdiver", note)
        with MslReader(out) as r:
            (prov,) = r.collect_import_provenance()
            assert prov.source_format == 0xFFFF
            assert note_origin_format(prov.note) == fmt
            assert msl_source_format(r) == fmt
            assert msl_classification_context(r)[0] == fmt


def test_legacy_memdiver_0x04_is_msl(tmp_path):
    out = _write(tmp_path / "legacy.msl", 0x04, "memdiver",
                 "src; source_format=msl;materialized=1")
    with MslReader(out) as r:
        assert msl_source_format(r) == SF.MSL


def test_legacy_memdiver_0x05_is_regioned_raw(tmp_path):
    out = _write(tmp_path / "legacy5.msl", 0x05, "memdiver", "Imported")
    with MslReader(out) as r:
        assert msl_source_format(r) == SF.REGIONED_RAW


def test_foreign_writer_0x04_0x05_are_macos_core_and_procdump(tmp_path):
    a = _write(tmp_path / "a.msl", 0x04, "othertool", "")
    b = _write(tmp_path / "b.msl", 0x05, "othertool", "")
    with MslReader(a) as r:
        assert msl_source_format(r) == SF.MACOS_CORE
    with MslReader(b) as r:
        assert msl_source_format(r) == SF.PROCDUMP


@pytest.mark.parametrize("code,tool,note,expected", [
    (None, "", "", None),
    (0x01, "x", "", SF.RAW_DUMP), (0x02, "x", "", SF.ELF_CORE),
    (0x03, "x", "", SF.MINIDUMP),
    (0xFFFF, "memdiver", "physical-image extraction; pid=1", SF.OTHER),
    (0xFFFF, "other", "source_format=msl", SF.OTHER),  # foreign: no origin
    (0xFFFF, "memdiver", "a; source_format=regioned_raw; source_format=msl;materialized=1",
     SF.REGIONED_RAW),  # first origin wins
    (0x1234, "memdiver", "", None),
])
def test_effective_table(code, tool, note, expected):
    assert effective_source_format(code, tool, note) == expected


def test_stack_rule_follows_effective_not_wire():
    # derived-stack folding applies to ELF/minidump only; MSL/foreign untouched
    assert alignment_region_type(RegionType.STACK, int(SF.MSL)) == RegionType.STACK
    assert alignment_region_type(RegionType.STACK, int(SF.MACOS_CORE)) == RegionType.STACK
    assert alignment_region_type(RegionType.STACK, int(SF.ELF_CORE)) == RegionType.ANONYMOUS


def test_wire_code_is_always_a_u16():
    # classification-only members (0x1000x) map back to their spec codes on write
    assert wire_source_format(SF.MACOS_CORE) == 0x0004
    assert wire_source_format(SF.PROCDUMP) == 0x0005
    assert wire_source_format(SF.MSL) == 0xFFFF
    assert wire_source_format(SF.REGIONED_RAW) == 0xFFFF
    assert all(0 <= wire_source_format(f) <= 0xFFFF for f in SF)


def _rematerialize(src, out):
    from memdiver.msl.materialize import materialize_msl, stored_regions
    with MslReader(src) as reader:
        regions = stored_regions(reader, None)
        materialize_msl(reader, src, out, regions, [True] * len(regions),
                        "selection=all")
    with MslReader(out) as r:
        (prov,) = r.collect_import_provenance()
        return prov, msl_source_format(r)


def test_rematerialized_legacy_regioned_raw_keeps_its_origin(tmp_path):
    src = _write(tmp_path / "legacy.msl", 0x05, "memdiver",
                 "Imported from x.bin; source_format=msl;materialized=1")
    prov, fmt = _rematerialize(src, tmp_path / "copy.msl")
    assert prov.source_format == 0xFFFF
    assert fmt == SF.REGIONED_RAW
    again, fmt2 = _rematerialize(tmp_path / "copy.msl", tmp_path / "copy2.msl")
    assert fmt2 == SF.REGIONED_RAW


def test_materialized_other_origin_stays_other(tmp_path):
    src = _write(tmp_path / "extract.msl", 0xFFFF, "memdiver", "pid=1")
    prov, fmt = _rematerialize(src, tmp_path / "copy.msl")
    assert prov.source_format == 0xFFFF
    assert fmt == SF.OTHER
    assert note_origin_format(prov.note) is None
    _, fmt2 = _rematerialize(tmp_path / "copy.msl", tmp_path / "copy2.msl")
    assert fmt2 == SF.OTHER
