"""``core.needle`` — turning what an analyst typed into bytes to search for.

The parse step is the only part of byte search that was ever format-specific
(``DumpSource.find_all`` has always taken plain ``bytes``), so this module is
where a search box that accepts hex, text, wide strings, base64 and integers
either works or quietly searches for the wrong thing.

TWO KINDS OF TEST LIVE HERE, and the split matters:

* the SHARED table (``tests/fixtures/needle_vectors.json``), replayed below and
  replayed again by ``tests/frontend/utils/needle.test.ts``. The web search box
  previews the resolved bytes locally — a round trip per keystroke is not an
  option — so ``core/needle.py`` and ``frontend/src/utils/needle.ts`` are one
  contract written twice. The table is the only thing that turns a drift
  between them into a failing test rather than a preview that disagrees with
  the search it just ran.
* Python-only behaviour: error categories, the exception TYPE the surfaces
  funnel on, and the de-duplication of the three hex parsers this module
  replaced.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from memdiver.core.needle import (  # noqa: E402
    CONCRETE_FORMATS,
    NEEDLE_FORMATS,
    detect_needle_format,
    looks_like_base64,
    looks_like_hex,
    normalize_hex,
    parse_needle,
    plausible_alternatives,
)
from memdiver.core.service_errors import (  # noqa: E402
    CapabilityError,
    ErrorCategory,
)

_VECTORS = json.loads(
    (Path(__file__).parent / "fixtures" / "needle_vectors.json")
    .read_text(encoding="utf-8")
)


def _ids(cases, *keys):
    return [" ".join(str(c[k]) for k in keys) for c in cases]


# --------------------------------------------------------------------------
# The shared table — mirrored verbatim by the vitest suite.
# --------------------------------------------------------------------------

@pytest.mark.parametrize(
    "case", _VECTORS["parse"], ids=_ids(_VECTORS["parse"], "format", "input"))
def test_parse_matches_the_shared_vector_table(case):
    assert parse_needle(case["input"], case["format"]).hex() == case["expect_hex"]


@pytest.mark.parametrize(
    "case", _VECTORS["detect"], ids=_ids(_VECTORS["detect"], "input"))
def test_auto_detection_matches_the_shared_vector_table(case):
    assert detect_needle_format(case["input"]) == case["expect"]


@pytest.mark.parametrize(
    "case", _VECTORS["alternatives"], ids=_ids(_VECTORS["alternatives"], "input"))
def test_alternatives_match_the_shared_vector_table(case):
    assert plausible_alternatives(case["input"]) == case["expect"]


@pytest.mark.parametrize(
    "case", _VECTORS["invalid"], ids=_ids(_VECTORS["invalid"], "format", "why"))
def test_invalid_input_is_refused_as_invalid_input(case):
    """Every rejection is a CapabilityError in the INVALID_INPUT category.

    The category is not decoration: it is what makes the web surface answer
    400 instead of 500, and what keeps a typo in the search box from reading
    like a server fault.
    """
    with pytest.raises(CapabilityError) as excinfo:
        parse_needle(case["input"], case["format"])
    assert excinfo.value.category is ErrorCategory.INVALID_INPUT


# --------------------------------------------------------------------------
# Auto-detection: the ambiguity is SURFACED, never guessed at.
# --------------------------------------------------------------------------

@pytest.mark.parametrize("word", ["dead", "cafe", "face", "beef", "decade"])
def test_hex_looking_words_resolve_to_hex_and_offer_text(word):
    """``dead`` is a word AND a byte pair. There is no reading that is right
    every time, so ``auto`` keeps what the box has always done — pure hex
    input is hex — and names the other reading instead of silently picking it.
    """
    assert detect_needle_format(word) == "hex"
    assert "text" in plausible_alternatives(word)


def test_base64_is_never_auto_detected_only_offered():
    """Its charset is a superset of ordinary words, so auto-detecting it would
    make ``auto`` unpredictable — the one thing it must not be. It stays one
    click away instead.
    """
    blob = "aGVsbG8gd29ybGQxMjM0"
    assert detect_needle_format(blob) == "text"
    assert "base64" in plausible_alternatives(blob)


def test_integer_formats_are_never_auto_detected():
    """``1234`` is as good a string as it is a number."""
    for text in ("1234", "0x1000", "99"):
        assert detect_needle_format(text) in ("hex", "text")


def test_alternatives_never_offer_the_format_already_chosen():
    """The hint exists to offer a reading the user is NOT getting; echoing the
    current one back would be noise that trains people to ignore it."""
    for text in ("dead", "password", "aGVsbG8gd29ybGQxMjM0", "deadbeef"):
        assert detect_needle_format(text) not in plausible_alternatives(text)


def test_blank_input_has_no_alternatives_and_no_detection():
    assert plausible_alternatives("   ") == []
    with pytest.raises(CapabilityError):
        detect_needle_format("   ")


# --------------------------------------------------------------------------
# Hex normalisation — the contract the byte-search box has always had.
# --------------------------------------------------------------------------

@pytest.mark.parametrize("spelling", [
    "deadbeef", "0xdeadbeef", "0XDEADBEEF", "DEADBEEF",
    "de ad be ef", " deadbeef ", "dead beef", "de\tad\nbe ef",
])
def test_every_spelling_of_the_same_key_gives_the_same_bytes(spelling):
    """An analyst pastes the same key out of the hex viewer, an NSS key-log
    line and a paper. All three spellings must find the same bytes — this is
    the property ``test_api_locate_key`` pins across ``locate_key`` too."""
    assert parse_needle(spelling, "hex") == b"\xde\xad\xbe\xef"


def test_odd_hex_says_why_rather_than_echoing_binascii():
    """"non-hexadecimal number found in fromhex() arg" tells nobody that they
    typed half a byte."""
    with pytest.raises(CapabilityError, match="odd number of hex digits"):
        parse_needle("dea", "hex")


def test_normalize_hex_and_looks_like_hex_agree_with_parse():
    assert normalize_hex(" 0xDE AD ") == "DEAD"
    assert looks_like_hex("0xdead")
    assert not looks_like_hex("dea")     # odd -> half a byte
    assert not looks_like_hex("d")       # too short to be a byte
    assert not looks_like_hex("nothex")
    assert looks_like_base64("aGVsbG8gd29ybGQxMjM0")
    assert not looks_like_base64("dead")  # too short to be worth offering


# --------------------------------------------------------------------------
# Empty needles: refused LOUDLY, because the scan cannot report them.
# --------------------------------------------------------------------------

@pytest.mark.parametrize("text,fmt", [
    ("", "hex"), ("   ", "hex"), ("", "text"), ("  ", "auto"), ("", "base64"),
])
def test_empty_needle_is_refused_rather_than_silently_finding_nothing(text, fmt):
    """``find_all_offsets`` returns ``[]`` for an empty needle — it must, or
    ``mmap.find(b"", ...)`` clamps and loops forever. So an empty pattern that
    reached the scan would come back as a confident "0 hits" for a query that
    was never searchable. Refuse it where the user can still see why.
    """
    with pytest.raises(CapabilityError, match="[Ee]mpty byte pattern"):
        parse_needle(text, fmt)


def test_bare_base64_padding_is_refused_as_invalid_not_as_empty():
    """``"===="`` is all padding and no data. ``b64decode(validate=True)``
    rejects it outright rather than returning ``b""``, so the user is told the
    pattern is malformed — which is truer than "empty" — and either way it
    never reaches the scan as a zero-byte needle."""
    with pytest.raises(CapabilityError, match="Invalid base64 pattern"):
        parse_needle("====", "base64")


# --------------------------------------------------------------------------
# Integers: width and endianness live in the format name.
# --------------------------------------------------------------------------

@pytest.mark.parametrize("fmt,width", [
    ("u32le", 4), ("u32be", 4), ("u64le", 8), ("u64be", 8)])
def test_integer_formats_have_fixed_width(fmt, width):
    assert len(parse_needle("1", fmt)) == width


def test_endianness_is_the_only_difference_between_le_and_be():
    assert (parse_needle("0x7f9c1234", "u32le")
            == parse_needle("0x7f9c1234", "u32be")[::-1])


def test_a_value_too_wide_for_the_format_says_so():
    with pytest.raises(CapabilityError, match="does not fit in 4 bytes"):
        parse_needle("0x1FFFFFFFF", "u32le")


def test_decimal_and_prefixed_spellings_agree():
    """``base=0``: an analyst reads a pointer off one pane as hex and a length
    off another as decimal, and should not have to convert either."""
    assert parse_needle("0x10", "u32be") == parse_needle("16", "u32be")


# --------------------------------------------------------------------------
# Vocabulary + the callers that used to carry their own copy.
# --------------------------------------------------------------------------

def test_unknown_format_names_the_ones_that_exist():
    with pytest.raises(CapabilityError, match="Unknown pattern format"):
        parse_needle("dead", "rot13")


def test_concrete_formats_is_every_format_but_auto():
    assert set(CONCRETE_FORMATS) == set(NEEDLE_FORMATS) - {"auto"}
    assert all(detect_needle_format(t) in CONCRETE_FORMATS
               for t in ("dead", "password", "0x10"))


def test_region_analysis_delegates_and_keeps_its_none_contract():
    """``parse_hex_pattern`` was a THIRD copy of the hex normalisation. It now
    delegates, but its callers treat an unparseable pattern as "no pattern"
    rather than an error, so the ``None`` return has to survive."""
    from memdiver.core.region_analysis import parse_hex_pattern

    assert parse_hex_pattern("de ad") == b"\xde\xad"
    assert parse_hex_pattern("0xdead") == b"\xde\xad"
    assert parse_hex_pattern("dea") is None
    assert parse_hex_pattern("") is None


def test_locate_key_needle_delegates_but_keeps_its_own_wording():
    """``_needle_from_key_hex`` was a VERBATIM copy whose docstring said so.
    It delegates now — but the caller pasted a KEY, and saying "byte pattern"
    would send them looking at the wrong field."""
    from memdiver.app.tools_pipeline import _needle_from_key_hex

    assert _needle_from_key_hex(" 0xDE AD ") == b"\xde\xad"
    with pytest.raises(CapabilityError, match="Invalid hex key"):
        _needle_from_key_hex("dea")
    with pytest.raises(CapabilityError, match="Empty hex key"):
        _needle_from_key_hex("   ")
