"""Physical Memory Map (0x0059, spec 5.9 Table 25): writer -> reader round trip."""

import struct

import pytest

from memdiver.core.dump_source import open_dump
from memdiver.msl.enums import BlockType
from memdiver.msl.reader import MslReader
from memdiver.msl.types import PhysicalRange
from memdiver.msl.writer import MslWriter, _build_physical_memory_map_payload

LABELS = ["", "a", "1234567", "123456789", "System RAM", "Reserviert äöü € \U0001F512"]


def _write(path, rows, region=True):
    w = MslWriter(path, pid=1)
    if region:
        w.add_memory_region(0x1000, b"\xAB" * 4096)
    w.add_physical_memory_map(rows)
    w.add_end_of_capture()
    w.write()


def test_round_trip_with_odd_and_utf8_labels(tmp_path):
    rows = [PhysicalRange(i * 0x1000, i * 0x1000 + 0xFFF, lab) for i, lab in enumerate(LABELS)]
    out = tmp_path / "p.msl"
    _write(out, rows)
    with MslReader(out) as r:
        blocks = r.collect_physical_memory_map()
        assert len(blocks) == 1 and blocks[0].row_count == len(rows)
        assert list(blocks[0].rows) == rows
        assert blocks[0].block_header.block_type == BlockType.PHYSICAL_MEMORY_MAP


@pytest.mark.parametrize("label", LABELS)
def test_payload_is_padded_to_8_and_rows_are_unpadded(label):
    payload = _build_physical_memory_map_payload([PhysicalRange(0, 7, label)])
    raw = 8 + 0x14 + len(label.encode())
    assert len(payload) == (raw + 7) // 8 * 8
    assert struct.unpack_from("<II", payload, 0) == (1, 0)
    assert struct.unpack_from("<QQHH", payload, 8) == (0, 7, len(label.encode()), 0)
    assert payload[8 + 0x14:raw] == label.encode()
    assert payload[raw:] == b"\x00" * (len(payload) - raw)


def test_empty_map_and_validation(tmp_path):
    out = tmp_path / "e.msl"
    _write(out, [])
    with MslReader(out) as r:
        assert r.collect_physical_memory_map()[0].rows == ()
    with pytest.raises(ValueError):
        _build_physical_memory_map_payload([PhysicalRange(10, 9, "x")])
    with pytest.raises(ValueError):
        _build_physical_memory_map_payload([PhysicalRange(0, 1, "x" * 65536)])
    _build_physical_memory_map_payload([PhysicalRange(0, 0, "x" * 65535)])


def test_file_with_block_opens_with_existing_paths(tmp_path):
    out = tmp_path / "o.msl"
    _write(out, [PhysicalRange(0, 0xFFFFF, "System RAM")])
    with open_dump(out) as src:
        assert src.read_range(0, 4, "vas") == b"\xAB" * 4
    with MslReader(out) as r:
        assert r.file_header.version_minor == 1
        assert len(r.collect_regions()) == 1


def test_unknown_block_type_is_skipped_by_reader_paths(tmp_path):
    """An old reader sees 0x0059 as an unknown block: iter_blocks still walks it."""
    out = tmp_path / "u.msl"
    _write(out, [PhysicalRange(0, 1, "x")])
    with MslReader(out) as r:
        types = [h.block_type for h, _ in r.iter_blocks()]
        assert int(BlockType.PHYSICAL_MEMORY_MAP) in types
        assert int(BlockType.MEMORY_REGION) in types
