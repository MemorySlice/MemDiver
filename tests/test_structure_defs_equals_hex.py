"""``equals`` constraints on BYTES fields accept hex strings (ELF/PE magic)."""

from memdiver.core.structure_defs import _check_constraints, _equals


def test_hex_string_matches_bytes():
    assert _equals(b"\x7fELF", "7f454c46")
    assert _equals(bytearray(b"\x7fELF"), "7F454C46")


def test_hex_string_mismatch_and_invalid_hex():
    assert not _equals(b"\x7fELG", "7f454c46")
    assert not _equals(b"\x7fELF", "not-hex")


def test_non_bytes_values_compare_directly():
    assert _equals(0x0303, 0x0303)
    assert not _equals(0x0303, 0x0304)


def test_check_constraints_uses_hex_equals():
    assert _check_constraints(b"\x7fELF", {"equals": "7f454c46"})
    assert not _check_constraints(b"MZ\x00\x00", {"equals": "7f454c46"})
