"""Tests for core.strings module."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from core.strings import StringMatch, extract_strings


def test_extract_empty_data():
    assert extract_strings(b"") == []


def test_extract_no_printable():
    assert extract_strings(b"\x00\x00\x00\x00\x00") == []


def test_extract_below_min_length():
    result = extract_strings(b"\x00Hi\x00", min_length=4)
    assert result == []


def test_extract_single_string():
    data = b"\x00\x00Hello\x00\x00"
    result = extract_strings(data)
    assert len(result) == 1
    assert result[0].value == "Hello"
    assert result[0].offset == 2


def test_extract_multiple_strings():
    data = b"\x00Hello\x00\x00World\x00"
    result = extract_strings(data)
    assert len(result) == 2
    assert result[0].value == "Hello"
    assert result[1].value == "World"


def test_extract_min_length_custom():
    data = b"\x00Hey\x00LongerString\x00"
    result = extract_strings(data, min_length=8)
    assert len(result) == 1
    assert result[0].value == "LongerString"


def test_extract_offset_correct():
    data = b"\x00\x00\x00\x00\x00ABCDE"
    result = extract_strings(data, min_length=4)
    assert len(result) == 1
    assert result[0].offset == 5
    assert data[result[0].offset:result[0].offset + result[0].length] == b"ABCDE"


def test_extract_encoding_ascii():
    data = b"\x00TestString\x00"
    result = extract_strings(data, encoding="ascii")
    assert len(result) == 1
    assert result[0].encoding == "ascii"


def test_extract_tab_newline_included():
    data = b"\x00line1\tline2\nline3\x00"
    result = extract_strings(data, min_length=4)
    assert len(result) == 1
    assert "\t" in result[0].value
    assert "\n" in result[0].value


def test_extract_boundary_start():
    data = b"Hello\x00\x00\x00"
    result = extract_strings(data)
    assert len(result) == 1
    assert result[0].offset == 0
    assert result[0].value == "Hello"


def test_extract_boundary_end():
    data = b"\x00\x00\x00Hello"
    result = extract_strings(data)
    assert len(result) == 1
    assert result[0].value == "Hello"
    assert result[0].offset == 3


def test_extract_long_string():
    long_str = "A" * 500
    data = b"\x00" + long_str.encode("ascii") + b"\x00"
    result = extract_strings(data)
    assert len(result) == 1
    assert result[0].value == long_str
    assert result[0].length == 500


def test_string_match_hashable():
    m1 = StringMatch(offset=0, value="test", encoding="ascii", length=4)
    m2 = StringMatch(offset=0, value="test", encoding="ascii", length=4)
    m3 = StringMatch(offset=5, value="other", encoding="ascii", length=5)
    s = {m1, m2, m3}
    assert len(s) == 2


def test_string_match_equality():
    m1 = StringMatch(offset=10, value="hello", encoding="ascii", length=5)
    m2 = StringMatch(offset=10, value="hello", encoding="utf-8", length=5)
    m3 = StringMatch(offset=20, value="hello", encoding="ascii", length=5)
    # Same offset and value -> equal (encoding differs but eq uses offset+value)
    assert m1 == m2
    # Different offset -> not equal
    assert m1 != m3


def test_extract_utf8_mode():
    text = "caf\u00e9"  # cafe with accent
    data = b"\x00\x00" + text.encode("utf-8") + b"\x00\x00"
    result = extract_strings(data, min_length=4, encoding="utf-8")
    assert len(result) == 1
    assert result[0].value == text
    assert result[0].encoding == "utf-8"


def test_extract_real_world_paths():
    path = b"/usr/lib/libssl.so.3"
    data = b"\x00\x01\x02" + path + b"\x00\x03\x04"
    result = extract_strings(data, min_length=4)
    assert len(result) == 1
    assert result[0].value == "/usr/lib/libssl.so.3"
    assert result[0].offset == 3
