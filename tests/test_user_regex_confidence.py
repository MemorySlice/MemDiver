"""Tests for confidence calibration of the user_regex algorithm."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from algorithms.base import AnalysisContext
from algorithms.confidence import count_confidence, density_penalty, regex_specificity
from algorithms.unknown_key.user_regex import UserRegexAlgorithm


def _run(dump_bytes: bytes, regex: str, name: str = "n"):
    return UserRegexAlgorithm().run(
        dump_bytes,
        AnalysisContext(
            library="x",
            protocol_version="1.3",
            phase="p",
            extra={"user_patterns": [{"name": name, "regex": regex}]},
        ),
    )


# --- algorithm result-level tests ---------------------------------------


def test_specific_pattern_outranks_broad():
    # A specific literal token appears a few times within filler bytes.
    dump = b"\x00\x11\x22SECRETKEY1234\x33\x44SECRETKEY1234\x55\x66SECRETKEY1234\x77" + b"\x90" * 200

    specific = _run(dump, "SECRETKEY1234")
    broad = _run(dump, ".")

    assert specific.confidence > broad.confidence


def test_single_precise_match_is_confident():
    dump = b"\x00" * 100 + b"SUPERSECRETTOKEN" + b"\x00" * 100
    result = _run(dump, "SUPERSECRETTOKEN")
    assert result.confidence > 0.4


def test_broad_pattern_low_confidence():
    dump = b"abcdefghij" * 50
    result = _run(dump, ".")
    assert result.confidence < 0.2


def test_no_matches_zero_confidence():
    dump = b"nothing interesting here at all"
    result = _run(dump, "DOESNOTOCCUR")
    assert result.confidence == 0.0


def test_invalid_regex_skipped():
    dump = b"some data"
    result = _run(dump, "(")
    skipped = result.metadata.get("skipped_patterns", [])
    assert any("(" in s or "n:" in s for s in skipped)
    assert result.confidence == 0.0


# --- confidence helper unit tests ----------------------------------------


def test_regex_specificity_ordering():
    assert regex_specificity(".") < regex_specificity("literalkey")


def test_density_penalty_bounds():
    assert density_penalty(0, 100) == 1.0
    assert density_penalty(60, 100) == 0.0  # 0.6 >= ceiling 0.5
    mid = density_penalty(25, 100)  # density 0.25, ceiling 0.5 -> 0.5
    assert 0.0 < mid < 1.0


def test_count_confidence_legacy_scale():
    assert count_confidence(5) == 0.5
    assert count_confidence(20) == 1.0
    assert count_confidence(0) == 0.0
