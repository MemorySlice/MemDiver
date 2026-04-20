"""Tests for core.structure_overlay."""

import struct
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from core.structure_defs import FieldDef, FieldType, StructureDef
from core.structure_library import get_structure_library
from core.structure_overlay import FieldOverlay, best_match_structure, overlay_structure


def _simple_struct() -> StructureDef:
    """Two-field struct: uint32_le + 4 bytes."""
    return StructureDef(
        name="test_simple",
        total_size=8,
        fields=(
            FieldDef("magic", FieldType.UINT32_LE, offset=0, size=4,
                     description="magic number"),
            FieldDef("payload", FieldType.BYTES, offset=4, size=4,
                     description="payload bytes"),
        ),
        protocol="TEST",
        description="simple test structure",
    )


def test_overlay_basic():
    """Overlay a simple struct, verify offsets and field names."""
    sd = _simple_struct()
    data = struct.pack("<I", 0xDEADBEEF) + b"\x01\x02\x03\x04"
    overlays, total = overlay_structure(data, base_offset=0, struct_def=sd)
    assert total == 8

    assert len(overlays) == 2
    assert overlays[0].field_name == "magic"
    assert overlays[0].offset == 0
    assert overlays[0].length == 4
    assert overlays[0].parsed_value == 0xDEADBEEF

    assert overlays[1].field_name == "payload"
    assert overlays[1].offset == 4
    assert overlays[1].length == 4
    assert overlays[1].parsed_value == b"\x01\x02\x03\x04"


def test_field_validation():
    """Overlay with constraints, verify valid flags."""
    sd = StructureDef(
        name="test_constrained",
        total_size=8,
        fields=(
            FieldDef("version", FieldType.UINT16_BE, offset=0, size=2,
                     constraints={"min": 1, "max": 5}),
            FieldDef("flags", FieldType.UINT16_BE, offset=2, size=2,
                     constraints={"equals": 0x00FF}),
            FieldDef("padding", FieldType.BYTES, offset=4, size=4),
        ),
        protocol="TEST",
    )
    # version=3 (passes), flags=0x0100 (fails equals 0x00FF)
    data = struct.pack(">HH", 3, 0x0100) + b"\x00" * 4
    overlays, _ = overlay_structure(data, base_offset=0, struct_def=sd)

    assert overlays[0].field_name == "version"
    assert overlays[0].valid is True

    assert overlays[1].field_name == "flags"
    assert overlays[1].valid is False

    # padding has no constraints, defaults to True
    assert overlays[2].valid is True


def test_best_match_finds_correct():
    """Buffer of nonzero bytes should match a built-in structure."""
    lib = get_structure_library()
    # 96 bytes of 0xFF -- large enough for all built-in structs.
    # not_zero constraints will pass for all-0xFF data.
    data = b"\xff" * 96
    result = best_match_structure(data, offset=0, library=lib)

    assert result is not None
    struct_def, overlays, confidence = result
    assert confidence > 0.0
    assert len(overlays) > 0
    # Should match one of the built-in names
    known_names = {s.name for s in lib.list_all()}
    assert struct_def.name in known_names


def test_best_match_no_match():
    """Buffer too small for any structure returns None."""
    lib = get_structure_library()
    # Smallest built-in is aes_key_block at 44 bytes; use 2 bytes
    data = b"\x00\x01"
    result = best_match_structure(data, offset=0, library=lib)
    assert result is None


def test_offset_boundary():
    """Overlay at non-zero base_offset produces correct absolute offsets."""
    sd = _simple_struct()
    data = struct.pack("<I", 42) + b"\xAA\xBB\xCC\xDD"
    base = 0x1000
    overlays, _ = overlay_structure(data, base_offset=base, struct_def=sd)

    assert overlays[0].offset == base + 0  # field offset 0
    assert overlays[1].offset == base + 4  # field offset 4


def _polymorphic_secret() -> StructureDef:
    """Single polymorphic BYTES field probing (48, 32)."""
    return StructureDef(
        name="test_poly",
        total_size=32,
        fields=(
            FieldDef("secret", FieldType.BYTES, 0, 32,
                     constraints={"not_zero": True},
                     size_choices=(48, 32)),
        ),
        protocol="TEST",
        auto_offsets=True,
    )


def test_overlay_probes_largest_when_possible():
    """48 nonzero bytes: probe picks 48."""
    sd = _polymorphic_secret()
    data = b"\xAA" * 48
    overlays, total = overlay_structure(data, base_offset=0, struct_def=sd)
    assert len(overlays) == 1
    assert overlays[0].length == 48
    assert overlays[0].resolved_size == 48
    assert total == 48


def test_overlay_probes_falls_back_when_out_of_bounds():
    """Exactly 32 bytes of buffer: 48 probe can't fit, picks 32."""
    sd = _polymorphic_secret()
    data = b"\xAA" * 32
    overlays, total = overlay_structure(data, base_offset=0, struct_def=sd)
    assert overlays[0].length == 32
    assert overlays[0].resolved_size == 32
    assert total == 32


def test_overlay_auto_offsets_shifts_subsequent_fields():
    """2-field auto_offsets struct: field 1 has size_choices, field 2 shifts."""
    sd = StructureDef(
        name="test_two",
        total_size=64,
        fields=(
            FieldDef("a", FieldType.BYTES, 0, 32,
                     constraints={"not_zero": True},
                     size_choices=(48, 32)),
            FieldDef("b", FieldType.BYTES, 0, 16,
                     constraints={"not_zero": True}),
        ),
        auto_offsets=True,
    )
    data = b"\x01" * 64  # 48 + 16 fits
    overlays, total = overlay_structure(data, base_offset=0, struct_def=sd)
    assert overlays[0].length == 48
    assert overlays[0].offset == 0
    assert overlays[1].length == 16
    assert overlays[1].offset == 48  # shifted past field a
    assert total == 64


def test_byte_equals_constraint():
    """byte_equals: byte at given offset must equal expected."""
    sd = StructureDef(
        name="test_be",
        total_size=4,
        fields=(
            FieldDef("data", FieldType.BYTES, 0, 4,
                     constraints={"byte_equals": {"0": 0x03, "1": 0x03}}),
        ),
    )
    ok, _ = overlay_structure(b"\x03\x03\xFF\xFF", 0, sd)
    assert ok[0].valid is True
    bad, _ = overlay_structure(b"\x03\x04\xFF\xFF", 0, sd)
    assert bad[0].valid is False


def test_byte_in_constraint():
    """byte_in: byte at given offset must be in allowed list."""
    sd = StructureDef(
        name="test_bi",
        total_size=2,
        fields=(
            FieldDef("data", FieldType.BYTES, 0, 2,
                     constraints={"byte_in": {"0": [0x03], "1": [0x00, 0x01, 0x02, 0x03, 0x04]}}),
        ),
    )
    ok, _ = overlay_structure(b"\x03\x03", 0, sd)
    assert ok[0].valid is True
    ok2, _ = overlay_structure(b"\x03\x04", 0, sd)
    assert ok2[0].valid is True
    bad, _ = overlay_structure(b"\x04\x00", 0, sd)
    assert bad[0].valid is False


def test_pre_master_secret_version_check():
    """tls12_pre_master_secret_rsa validates 0x03 0x03 but not 0x04 0x00."""
    lib = get_structure_library()
    sd = lib.get("tls12_pre_master_secret_rsa")
    assert sd is not None

    valid_pms = b"\x03\x03" + b"\xAB" * 46
    ok, _ = overlay_structure(valid_pms, 0, sd)
    assert ok[0].valid is True

    bad_pms = b"\x04\x00" + b"\xAB" * 46
    bad, _ = overlay_structure(bad_pms, 0, sd)
    assert bad[0].valid is False


def test_variant_label_sha_sizes():
    """variant_label maps total resolved size to hash name."""
    from core.structure_overlay import variant_label

    sd = StructureDef(name="x", total_size=32, fields=())
    assert variant_label(sd, {"secret": 32}) == "SHA-256"
    assert variant_label(sd, {"secret": 48}) == "SHA-384"
    assert variant_label(sd, {"secret": 64}) == "SHA-512"
    assert variant_label(sd, {"secret": 20}) == "SHA-1"
