"""Tests for core.structure_defs module."""

import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from core.structure_defs import (
    FieldDef,
    FieldType,
    StructureDef,
    parse_structure,
)

# Shared test structure: 12 bytes total
# [magic:u32le][length:u16le][padding:2bytes][key_data:4bytes]
TEST_STRUCT = StructureDef(
    name="test_struct",
    total_size=12,
    fields=(
        FieldDef("magic", FieldType.UINT32_LE, offset=0, size=4,
                 constraints={"equals": 0xDEADBEEF}),
        FieldDef("length", FieldType.UINT16_LE, offset=4, size=2,
                 constraints={"min": 1, "max": 1000}),
        FieldDef("padding", FieldType.BYTES, offset=6, size=2),
        FieldDef("key_data", FieldType.BYTES, offset=8, size=4),
    ),
)

# Build valid data: magic=0xDEADBEEF, length=42, padding=0x0000, key=0xCAFEBABE
VALID_DATA = struct.pack("<IH", 0xDEADBEEF, 42) + b"\x00\x00" + b"\xCA\xFE\xBA\xBE"


def test_field_def_frozen():
    """FieldDef is frozen/immutable."""
    fd = FieldDef("x", FieldType.UINT8, offset=0, size=1)
    try:
        fd.name = "y"
        assert False, "Should have raised"
    except AttributeError:
        pass


def test_structure_def_field_by_name():
    """field_by_name returns correct field or None for missing."""
    f = TEST_STRUCT.field_by_name("magic")
    assert f is not None
    assert f.offset == 0
    assert f.field_type == FieldType.UINT32_LE

    assert TEST_STRUCT.field_by_name("nonexistent") is None


def test_validate_data_pass():
    """All constraints pass for valid data."""
    results = TEST_STRUCT.validate_data(VALID_DATA)
    assert results["magic"] is True
    assert results["length"] is True
    # Fields without constraints default to True
    assert results["padding"] is True
    assert results["key_data"] is True


def test_validate_data_fail():
    """Constraint fails when value is outside min/max range."""
    # length=2000 exceeds max=1000
    bad_data = struct.pack("<IH", 0xDEADBEEF, 2000) + b"\x00\x00" + b"\x00" * 4
    results = TEST_STRUCT.validate_data(bad_data)
    assert results["magic"] is True
    assert results["length"] is False


def test_parse_structure_uint32():
    """Parse a struct with uint32_le field, verify correct value."""
    parsed = parse_structure(VALID_DATA, TEST_STRUCT)
    assert parsed["magic"] == 0xDEADBEEF
    assert parsed["length"] == 42


def test_parse_structure_bytes():
    """Parse a struct with BYTES field, verify correct bytes."""
    parsed = parse_structure(VALID_DATA, TEST_STRUCT)
    assert parsed["padding"] == b"\x00\x00"
    assert parsed["key_data"] == b"\xCA\xFE\xBA\xBE"


def test_parse_structure_string():
    """Parse a struct with UTF8_STRING field, verify correct string."""
    str_struct = StructureDef(
        name="str_test",
        total_size=8,
        fields=(
            FieldDef("label", FieldType.UTF8_STRING, offset=0, size=8),
        ),
    )
    data = b"hello\x00\x00\x00"
    parsed = parse_structure(data, str_struct)
    assert parsed["label"] == "hello"


def test_constraints_equals():
    """The 'equals' constraint works correctly."""
    # Wrong magic value
    wrong_magic = struct.pack("<IH", 0x12345678, 42) + b"\x00\x00" + b"\x00" * 4
    results = TEST_STRUCT.validate_data(wrong_magic)
    assert results["magic"] is False

    # Correct magic value
    results = TEST_STRUCT.validate_data(VALID_DATA)
    assert results["magic"] is True


def test_not_zero_bytes_all_zeros():
    """not_zero constraint rejects all-zero bytes fields."""
    from core.structure_defs import _check_constraints

    assert _check_constraints(b"\x00" * 32, {"not_zero": True}) is False


def test_not_zero_bytes_nonzero():
    """not_zero constraint passes for non-zero bytes fields."""
    from core.structure_defs import _check_constraints

    assert _check_constraints(b"\x01" + b"\x00" * 31, {"not_zero": True}) is True


def test_not_zero_integer_still_works():
    """not_zero constraint still works for integer fields (regression)."""
    from core.structure_defs import _check_constraints

    assert _check_constraints(0, {"not_zero": True}) is False
    assert _check_constraints(42, {"not_zero": True}) is True


def test_byte_equals_constraint():
    """byte_equals checks individual byte positions."""
    from core.structure_defs import _check_constraints

    assert _check_constraints(
        b"\x03\x03AB", {"byte_equals": {"0": 0x03, "1": 0x03}}
    ) is True
    assert _check_constraints(
        b"\x03\x04AB", {"byte_equals": {"0": 0x03, "1": 0x03}}
    ) is False
    # Out of range index fails
    assert _check_constraints(
        b"\x03", {"byte_equals": {"5": 0x00}}
    ) is False


def test_byte_in_constraint():
    """byte_in checks byte is in allowed list."""
    from core.structure_defs import _check_constraints

    assert _check_constraints(
        b"\x03\x02", {"byte_in": {"0": [0x03], "1": [0x00, 0x01, 0x02, 0x03]}}
    ) is True
    assert _check_constraints(
        b"\x03\x05", {"byte_in": {"1": [0x00, 0x01, 0x02, 0x03, 0x04]}}
    ) is False


def test_field_def_size_choices_default():
    """FieldDef.size_choices defaults to empty tuple."""
    fd = FieldDef("x", FieldType.BYTES, offset=0, size=32)
    assert fd.size_choices == ()


def test_structure_def_metadata_defaults():
    """StructureDef new metadata defaults: library=None, stability='stable'."""
    sd = StructureDef(name="x", total_size=4, fields=())
    assert sd.library is None
    assert sd.library_version is None
    assert sd.stability == "stable"
    assert sd.auto_offsets is False
