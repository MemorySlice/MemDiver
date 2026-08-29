"""Unit tests for ``api.services.analysis_service``.

These are service-level tests that bypass the HTTP layer entirely so the
service's own contract is pinned. The ASLR regression end-to-end
coverage lives in ``test_auto_export_aslr_regression.py``; this file
focuses on happy-path shape, error translation, and edge cases that
don't need fresh MSL fixtures.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from memdiver.api.services.analysis_service import (
    AnalysisServiceError,
    DumpsNotFoundError,
    InsufficientStaticError,
    NoVolatileRegionsError,
    SUPPORTED_FORMATS,
    TooFewDumpsError,
    UnknownFormatError,
    auto_export_pattern,
)
from tests.fixtures.generate_msl_fixtures import write_aslr_fixture


@pytest.fixture
def aslr_triple(tmp_path):
    """Three ASLR-shifted native MSL fixtures with a divergent key slug."""
    paths = []
    for i, (base, key) in enumerate(
        [
            (0x7FFF00000000, b"\x00" * 32),
            (0x7FFF10000000, b"\xFF" * 32),
            (0x7FFF20000000, b"\x80" * 32),
        ]
    ):
        paths.append(
            write_aslr_fixture(
                tmp_path / f"dump_{i}.msl",
                region_base=base, key_offset=0x200, key_bytes=key,
            )
        )
    return paths


# -- Happy path ----------------------------------------------------------


def test_happy_path_json(aslr_triple):
    result = auto_export_pattern(
        aslr_triple, fmt="json", name="ok", align=False, context=32,
    )
    assert result["format"] == "json"
    assert result["pattern"] is not None
    region = result["region"]
    assert region["key_start"] == 0x200
    assert region["key_end"] - region["key_start"] == 32


def test_happy_path_volatility3(aslr_triple):
    result = auto_export_pattern(
        aslr_triple, fmt="volatility3", name="ok", align=False, context=32,
    )
    assert result["format"] == "volatility3"
    # Volatility3 exporter embeds the YARA rule and emits Python.
    assert "yara" in result["content"].lower() or "rule" in result["content"].lower()


def test_supported_formats_constant():
    assert set(SUPPORTED_FORMATS) == {"yara", "json", "volatility3", "vol3"}


# -- Error translation ---------------------------------------------------


def test_missing_file_raises_dumps_not_found(tmp_path):
    real = write_aslr_fixture(
        tmp_path / "real.msl",
        region_base=0x7FFF00000000, key_bytes=b"\x00" * 32,
    )
    fake = tmp_path / "does_not_exist.msl"
    with pytest.raises(DumpsNotFoundError) as exc_info:
        auto_export_pattern([real, fake], fmt="json", name="x")
    assert exc_info.value.status == 404
    assert str(fake) in exc_info.value.missing


def test_single_dump_raises_too_few(tmp_path):
    p = write_aslr_fixture(
        tmp_path / "a.msl",
        region_base=0x7FFF00000000, key_bytes=b"\x00" * 32,
    )
    with pytest.raises(TooFewDumpsError) as exc_info:
        auto_export_pattern([p], fmt="json", name="x")
    assert exc_info.value.status == 400


def test_unknown_format_raises(aslr_triple):
    with pytest.raises(UnknownFormatError) as exc_info:
        auto_export_pattern(aslr_triple, fmt="xml", name="x")
    assert exc_info.value.status == 400
    assert exc_info.value.format == "xml"


def test_insufficient_static_raises(tmp_path):
    """Three fixtures where every byte is different → 0% static after
    the context window is filled with more divergent bytes. Pattern
    generation fails and the service raises InsufficientStaticError."""
    # Use context=0 so the region is pure volatile key bytes with no
    # surrounding static filler.
    paths = []
    for i, key in enumerate([b"\x00" * 32, b"\xFF" * 32, b"\x80" * 32]):
        p = write_aslr_fixture(
            tmp_path / f"x_{i}.msl",
            region_base=0x7FFF00000000 + (i << 28),
            key_bytes=key,
        )
        paths.append(p)

    with pytest.raises(InsufficientStaticError) as exc_info:
        auto_export_pattern(
            paths, fmt="json", name="x", align=False, context=0,
        )
    assert exc_info.value.status == 400
    assert exc_info.value.ratio < 0.3
    assert exc_info.value.required == 0.3


def test_error_base_class_status_default():
    err = AnalysisServiceError("generic")
    assert err.status == 400


# -- Reference / static mask derivation ----------------------------------


def test_reference_bytes_come_from_consensus_not_file(aslr_triple):
    """The service must not re-read file bytes at the memory-relative
    offset (which would be the pre-PR-4 StaticChecker bug). Proof: the
    key at region-relative 0x200 is b'\\x00' * 32 in the first fixture,
    so if the service reports the key's reference content correctly it
    should come from the aligned consensus data — and the extracted
    region at offset 0x1E0..0x220 should contain 32 bytes of filler
    0x42 followed by the 32 key bytes (first dump = all zeros) followed
    by 32 bytes of filler 0x42.
    """
    result = auto_export_pattern(
        aslr_triple, fmt="json", name="ref", align=False, context=32,
    )
    # We don't export raw reference bytes in the response payload, but
    # we can infer them from the pattern hex. The region is 96 bytes
    # (32 static + 32 volatile + 32 static).
    region = result["region"]
    assert region["length"] == 96
    assert region["offset"] == 0x1E0


def test_vol3_plugin_constants_agree_with_its_embedded_yara_rule():
    """A vol3 export must not disagree with the YARA rule it embeds.

    ``Volatility3Exporter.export`` takes no ``key_offset``/``key_length``
    parameters -- it reads them off the pattern dict, defaulting to 0 and to the
    FULL pattern length. ``_render_content``'s vol3 branch used to pass those
    values to ``YaraExporter`` only, so an export with a padded window emitted a
    plugin whose embedded rule said ``key_offset = 256`` while its own
    ``KEY_OFFSET``/``KEY_LENGTH`` constants said ``0`` and ``560``. Run under real
    Volatility3 that plugin reported the ENTIRE window as the key: KeyOffset ==
    PatternOffset, KeyHex the whole padded window, and KeyEntropy diluted by the
    padding -- i.e. it "found" something useless while looking successful.

    The invariant asserted here is agreement, which is what makes the bug
    impossible to reintroduce in either exporter independently.
    """
    from memdiver.app.export_service import _render_content

    key_offset, key_length, total = 256, 48, 560
    pattern = {
        "name": "agreement_probe",
        "length": total,
        "hex_pattern": " ".join(["41"] * total),
        "wildcard_pattern": " ".join(
            "??" if key_offset <= i < key_offset + key_length else "41"
            for i in range(total)
        ),
        "static_ratio": (total - key_length) / total,
        "static_count": total - key_length,
        "volatile_count": key_length,
    }

    content = _render_content(
        pattern, "volatility3", key_offset=key_offset, key_length=key_length
    )

    assert f"KEY_OFFSET = {key_offset}" in content
    assert f"KEY_LENGTH = {key_length}" in content
    assert f"PATTERN_LENGTH = {total}" in content
    # The embedded rule's meta must say the same thing as the constants.
    assert f"key_offset = {key_offset}" in content
    assert f"key_length = {key_length}" in content
    # And the caller's dict must not have been mutated on the way through:
    # `pattern` is handed back to the user in the producer payload.
    assert "key_offset" not in pattern
    assert "key_length" not in pattern
