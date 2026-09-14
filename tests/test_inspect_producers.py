"""Unit tests for the step-2a ServiceResult producers in tools_inspect.

The nine ``<publicname>_result`` producers ALWAYS carry a status block: where
the legacy ``get_*`` / ``read_hex`` siblings returned an error dict for an
encrypted-but-unkeyed container, the producers still perform the read and
report the lock purely through ``status.key`` / ``status.resolution``. Hard
errors (missing file, wrong format) are RAISED as CapabilityError subclasses.

These call the PURE ``mcp_server.tools_inspect`` producers directly (never via
FastMCP) and reuse the encrypted-.msl fixture style from
``tests/test_mcp_new_tools.py`` (MslWriter + MslEncryptionConfig(raw_key=...)).
"""

import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from memdiver.core.service_errors import (  # noqa: E402
    CapabilityError,
    ErrorCategory,
    FileNotFoundServiceError,
    OffsetOutOfRangeError,
    UnsupportedFormatError,
)
from memdiver.core.service_result import Resolution  # noqa: E402
from memdiver.mcp_server import tools_inspect  # noqa: E402
from memdiver.mcp_server.session import ToolSession  # noqa: E402
from memdiver.msl.enums import TagStatus  # noqa: E402


@pytest.fixture
def session():
    return ToolSession()


def _write_plain_msl(path: Path, *, data=b"\xAB" * 4096, base=0x1000):
    from memdiver.msl.writer import MslWriter

    w = MslWriter(path, pid=7)
    w.add_memory_region(base, data)
    w.add_end_of_capture()
    w.write()


def _write_encrypted_msl(path: Path, key: bytes, *, data=b"\xCD" * 4096):
    from memdiver.msl.writer import MslEncryptionConfig, MslWriter

    cfg = MslEncryptionConfig(raw_key=key)
    w = MslWriter(path, pid=7, encryption=cfg)
    w.add_memory_region(0x1000, data)
    w.add_end_of_capture()
    w.write()


@pytest.fixture
def encrypted_msl(tmp_path):
    from memdiver.msl import crypto
    from memdiver.msl.enums import EncAlgo

    if not crypto.cipher_is_available(EncAlgo.AES_256_GCM):
        pytest.skip("AES-256-GCM backend not installed")
    key = os.urandom(32)
    keyfile = tmp_path / "cek.bin"
    keyfile.write_bytes(key)
    msl = tmp_path / "enc.msl"
    _write_encrypted_msl(msl, key)
    return str(msl), str(keyfile)


@pytest.fixture
def plain_msl(tmp_path):
    msl = tmp_path / "plain.msl"
    _write_plain_msl(msl)
    return str(msl)


@pytest.fixture
def raw_dump(tmp_path):
    """A plain (non-MSL) raw dump file, for the VA-on-non-msl raise path."""
    dump = tmp_path / "plain.dump"
    dump.write_bytes(b"\x00" * 1024)
    return str(dump)


# The six producers that today return an error dict for an unkeyed encrypted
# container. read_hex_result must be exercised with view="vas" (the raw view
# is keyless and never gates).
_MSL_METADATA_PRODUCERS = [
    "session_info_result",
    "vas_regions_result",
    "page_states_result",
    "processes_result",
    "modules_result",
    "handles_result",
]


@pytest.mark.parametrize("fn_name", _MSL_METADATA_PRODUCERS)
def test_metadata_producer_without_key_reports_missing_key(session, encrypted_msl, fn_name):
    msl_path, _ = encrypted_msl
    result = getattr(tools_inspect, fn_name)(session, msl_path)
    assert result.status.key.tag_status == TagStatus.MISSING_KEY
    assert result.status.key.decrypted is False
    assert result.status.resolution == Resolution.UNRESOLVED


def test_read_hex_result_vas_without_key_reports_missing_key(session, encrypted_msl):
    msl_path, _ = encrypted_msl
    result = tools_inspect.read_hex_result(
        session, msl_path, offset=0, length=64, view="vas")
    assert result.status.key.tag_status == TagStatus.MISSING_KEY
    assert result.status.key.decrypted is False
    assert result.status.resolution == Resolution.UNRESOLVED


@pytest.mark.parametrize("fn_name", ["read_hex_result", "read_hex_raw_result"])
def test_read_hex_locked_vas_nonzero_offset_reports_missing_key(
    session, encrypted_msl, fn_name
):
    """Regression (code-review): a locked ``vas`` view must surface the key lock
    BEFORE the offset-bounds check. ``size_for("vas")`` is 0 for an unkeyed
    encrypted dump, so a nonzero offset previously raised a misleading
    ``OffsetOutOfRangeError`` on CLI/MCP instead of reporting ``missing_key``
    (the legacy ``read_hex`` ran the tag-status guard first)."""
    msl_path, _ = encrypted_msl
    result = getattr(tools_inspect, fn_name)(
        session, msl_path, offset=64, length=64, view="vas")
    assert result.status.key.tag_status == TagStatus.MISSING_KEY
    assert result.status.key.decrypted is False
    assert result.status.resolution == Resolution.UNRESOLVED


@pytest.mark.parametrize("fn_name", _MSL_METADATA_PRODUCERS)
def test_metadata_producer_with_wrong_key_reports_corrupted(session, encrypted_msl, tmp_path, fn_name):
    msl_path, _ = encrypted_msl
    wrong = tmp_path / "wrong.bin"
    wrong.write_bytes(b"\x00" * 32)
    result = getattr(tools_inspect, fn_name)(session, msl_path, key_file=str(wrong))
    assert result.status.key.tag_status == TagStatus.CORRUPTED
    assert result.status.key.decrypted is False
    assert result.status.resolution == Resolution.UNRESOLVED


def test_read_hex_result_raw_view_without_key_is_decrypted(session, encrypted_msl):
    """The raw container view is keyless by design: no lock, resolution OK."""
    msl_path, _ = encrypted_msl
    result = tools_inspect.read_hex_result(
        session, msl_path, offset=0, length=64, view="raw")
    assert result.status.key.decrypted is True
    assert result.status.resolution == Resolution.OK


def test_metadata_producer_with_key_is_ok(session, encrypted_msl):
    msl_path, keyfile = encrypted_msl
    result = tools_inspect.session_info_result(session, msl_path, key_file=keyfile)
    assert result.status.key.decrypted is True
    assert result.status.resolution == Resolution.OK
    assert result.payload["region_count"] == 1
    assert result.payload["pid"] == 7


def test_plaintext_msl_producer_is_ok(session, plain_msl):
    result = tools_inspect.session_info_result(session, plain_msl)
    assert result.status.resolution == Resolution.OK
    assert result.status.key.decrypted is True
    assert result.payload["pid"] == 7


@pytest.fixture
def msl_with_vas(tmp_path):
    """A complete synthetic .msl carrying a VAS_MAP block (three entries)."""
    from tests.fixtures.generate_msl_fixtures import write_msl_fixture

    return str(write_msl_fixture(tmp_path / "vas.msl"))


def test_vas_regions_result_emits_full_five_field_entries(session, msl_with_vas):
    """The VAS producer emits the FULL five-field entries the VasChart consumes,
    plus the region_count / total_region_size / vas_coverage summary fields."""
    result = tools_inspect.vas_regions_result(session, msl_with_vas)
    assert result.status.resolution == Resolution.OK
    assert result.status.key.decrypted is True

    payload = result.payload
    assert payload["region_count"] >= 1
    assert isinstance(payload["total_region_size"], int)
    assert isinstance(payload["vas_coverage"], dict)

    entries = payload["vas_entries"]
    assert len(entries) >= 1
    # The summary counts describe the VAS entries themselves (not the captured
    # regions session_info counts), so they stay consistent with the array.
    assert payload["region_count"] == len(entries)
    assert payload["total_region_size"] == sum(e["region_size"] for e in entries)
    for entry in entries:
        assert set(entry) == {
            "base_addr", "region_size", "region_type", "protection", "mapped_path",
        }
    # The fixture seeds a libssl mapping at the canonical base (base/size/type/prot).
    libssl = next(e for e in entries if e["mapped_path"] == "/usr/lib/libssl.so")
    assert libssl["base_addr"] == 0x00400000
    assert libssl["region_size"] == 0x10000
    assert libssl["region_type"] == 0x03
    assert libssl["protection"] == 0x05


def test_read_hex_result_plaintext_vas_is_ok(session, plain_msl):
    result = tools_inspect.read_hex_result(
        session, plain_msl, offset=0, length=64, view="vas")
    assert result.status.resolution == Resolution.OK
    assert result.status.key.decrypted is True


def test_producer_file_not_found_raises(session):
    with pytest.raises(FileNotFoundServiceError):
        tools_inspect.session_info_result(session, "/nonexistent/path.msl")


def test_producer_non_msl_suffix_raises(session, tmp_path):
    txt = tmp_path / "not_a_dump.txt"
    txt.write_text("hello")
    with pytest.raises(UnsupportedFormatError):
        tools_inspect.session_info_result(session, str(txt))


# ── hard-error raise paths (missing file / bad format / offset / pattern) ──


@pytest.mark.parametrize(
    "fn_name",
    ["read_hex_result", "read_hex_raw_result", "search_bytes_result"],
)
def test_dump_producer_file_not_found_raises(session, fn_name):
    fn = getattr(tools_inspect, fn_name)
    kwargs = {"pattern_hex": "ab"} if fn_name == "search_bytes_result" else {}
    with pytest.raises(FileNotFoundServiceError):
        fn(session, "/nonexistent/path.dump", **kwargs)


def test_resolve_va_result_file_not_found_raises(session):
    with pytest.raises(FileNotFoundServiceError):
        tools_inspect.resolve_va_result(session, "/nonexistent/path.msl", va=0x1000)


def test_resolve_va_result_non_msl_raises(session, raw_dump):
    """VA translation on a non-MSL dump raises UnsupportedFormatError,
    mirroring the legacy ``{"error": "VA translation requires an MSL dump"}``."""
    with pytest.raises(UnsupportedFormatError, match="VA translation requires an MSL dump"):
        tools_inspect.resolve_va_result(session, raw_dump, va=0x1000)


def test_read_hex_result_offset_out_of_range_raises(session, plain_msl):
    with pytest.raises(OffsetOutOfRangeError) as exc_info:
        tools_inspect.read_hex_result(session, plain_msl, offset=10**9, length=64, view="vas")
    err = exc_info.value
    assert err.message == "offset out of range"
    assert set(err.details) == {"offset", "file_size", "view", "format"}
    assert err.details["offset"] == 10**9
    assert err.details["view"] == "vas"


def test_read_hex_raw_result_offset_out_of_range_raises(session, plain_msl):
    with pytest.raises(OffsetOutOfRangeError) as exc_info:
        tools_inspect.read_hex_raw_result(session, plain_msl, offset=10**9, length=64, view="vas")
    err = exc_info.value
    assert err.message == "offset out of range"
    assert set(err.details) == {"offset", "file_size", "view", "format"}


def test_read_hex_result_negative_offset_raises(session, plain_msl):
    with pytest.raises(OffsetOutOfRangeError):
        tools_inspect.read_hex_result(session, plain_msl, offset=-1, length=64, view="vas")


@pytest.mark.parametrize("pattern_hex", ["", "   ", "0x"])
def test_search_bytes_result_empty_pattern_raises(session, plain_msl, pattern_hex):
    with pytest.raises(CapabilityError, match="Empty byte pattern"):
        tools_inspect.search_bytes_result(session, plain_msl, pattern_hex=pattern_hex)


def test_search_bytes_result_invalid_hex_raises(session, plain_msl):
    with pytest.raises(CapabilityError, match="Invalid hex byte pattern"):
        tools_inspect.search_bytes_result(session, plain_msl, pattern_hex="zz")


def test_search_bytes_result_file_not_found_raises(session):
    with pytest.raises(FileNotFoundServiceError):
        tools_inspect.search_bytes_result(session, "/nonexistent/path.dump", pattern_hex="ab")


# ── producer/legacy payload parity (plaintext MSL, no lock in play) ────────


def test_session_info_result_payload_matches_legacy(session, plain_msl):
    """Locks producer/legacy equivalence: the ServiceResult payload is
    byte-for-byte identical to the legacy dict (minus report_key_status)."""
    result = tools_inspect.session_info_result(session, plain_msl)
    legacy = tools_inspect.get_session_info(session, plain_msl, report_key_status=False)
    assert result.payload == legacy


def test_read_hex_result_vas_payload_matches_legacy(session, plain_msl):
    result = tools_inspect.read_hex_result(
        session, plain_msl, offset=0, length=64, view="vas")
    legacy = tools_inspect.read_hex(
        session, plain_msl, offset=0, length=64, view="vas", report_key_status=False)
    assert result.payload == legacy


def test_read_hex_raw_result_vas_payload_matches_legacy(session, plain_msl):
    result = tools_inspect.read_hex_raw_result(
        session, plain_msl, offset=0, length=64, view="vas")
    legacy = tools_inspect._read_hex_raw(
        session, plain_msl, offset=0, length=64, view="vas", report_key_status=False)
    assert result.payload == legacy


def test_search_bytes_result_payload_matches_legacy(session, plain_msl):
    result = tools_inspect.search_bytes_result(
        session, plain_msl, pattern_hex="ab", view="vas")
    legacy = tools_inspect.search_bytes(
        session, plain_msl, pattern_hex="ab", view="vas", report_key_status=False)
    assert result.payload == legacy


def test_resolve_va_result_payload_matches_legacy(session, plain_msl):
    result = tools_inspect.resolve_va_result(session, plain_msl, va=0x1000)
    legacy = tools_inspect._resolve_va(
        session, plain_msl, va=0x1000, report_key_status=False)
    assert result.payload == legacy


@pytest.mark.parametrize(
    "result_fn_name, legacy_fn_name",
    [
        ("page_states_result", "get_page_states"),
        ("processes_result", "get_processes"),
        ("modules_result", "get_modules"),
        ("handles_result", "get_handles"),
    ],
)
def test_metadata_producer_payload_matches_legacy(
    session, plain_msl, result_fn_name, legacy_fn_name
):
    result_fn = getattr(tools_inspect, result_fn_name)
    legacy_fn = getattr(tools_inspect, legacy_fn_name)
    result = result_fn(session, plain_msl)
    legacy = legacy_fn(session, plain_msl, report_key_status=False)
    assert result.payload == legacy


# ── analyze_region_result (new producer) ───────────────────────────────────


@pytest.fixture
def region_dump(tmp_path):
    """A raw dump with a printable string embedded near the middle."""
    data = bytes(range(256)) * 2 + b"PRIVATE_KEY_MARKER" + b"\xff" * 100
    dump = tmp_path / "region.dump"
    dump.write_bytes(data)
    return str(dump), data


def test_analyze_region_result_payload_matches_core(session, region_dump):
    """Single-source parity: the producer payload equals a direct
    core.region_analysis.analyze_region run over the same bytes."""
    from memdiver.core.region_analysis import analyze_region

    dump_path, data = region_dump
    offset = len(data) // 2
    result = tools_inspect.analyze_region_result(session, dump_path, offset)

    report = analyze_region(data, offset, window=64)
    assert result.payload["offset"] == report.offset
    assert result.payload["byte_value"] == report.byte_value
    assert result.payload["entropy"] == round(report.entropy, 4)
    assert result.payload["entropy_level"] == report.entropy_level
    assert result.payload["neighborhood_hex"] == report.neighborhood.hex()
    assert result.payload["strings"] == [
        {"offset": st.offset, "value": st.value,
         "encoding": st.encoding, "length": st.length}
        for st in report.strings
    ]
    # No variance/hits supplied on the path-based producer.
    assert result.payload["variance_at_offset"] is None
    assert result.payload["matching_secrets"] == []


def test_analyze_region_result_status_is_ok_for_raw(session, region_dump):
    dump_path, _ = region_dump
    result = tools_inspect.analyze_region_result(session, dump_path, 0)
    assert result.status.resolution == Resolution.OK
    assert result.status.key.decrypted is True


def test_analyze_region_result_file_not_found_raises(session):
    with pytest.raises(FileNotFoundServiceError):
        tools_inspect.analyze_region_result(session, "/nonexistent/path.dump", 0)


def test_analyze_region_result_offset_out_of_range_raises(session, region_dump):
    dump_path, data = region_dump
    with pytest.raises(OffsetOutOfRangeError):
        tools_inspect.analyze_region_result(session, dump_path, len(data))


def test_analyze_region_result_negative_offset_raises(session, region_dump):
    dump_path, _ = region_dump
    with pytest.raises(OffsetOutOfRangeError):
        tools_inspect.analyze_region_result(session, dump_path, -1)


# ── view="va" capability gating ───────────────────────────────────────────
#
# The "va" (sparse full virtual-address) view is served by .msl only. Every
# region-backed source raises a bare ``ValueError`` from ``size_for("va")``,
# and ``_http_inspect`` funnels only ``CapabilityError`` — so before the
# ``_require_supported_view`` guard that ValueError escaped as a 500 with
# nothing naming the real problem. This is reachable without anyone typing a
# search: the frontend persists ``viewMode`` in localStorage, so opening a
# gcore dump after using VA on an .msl carries ``view="va"`` straight in.


@pytest.fixture
def gcore_dump(tmp_path):
    """A synthetic ELF ``gcore.core`` — a region-backed source with no "va"."""
    from tests.fixtures import synth_elf_core

    return str(synth_elf_core.build(tmp_path / "run_0001") / "gcore.core")


@pytest.fixture
def regioned_raw_dump(tmp_path):
    """A synthetic gdb_raw ``.bin`` + ``.maps`` pair — the OTHER family of
    region-backed sources, which reaches the guard through a different class
    (``_RegionedRawSource``) than gcore does."""
    from tests.fixtures import synth_raw_regions

    return str(synth_raw_regions.build(tmp_path / "regions") / "gdb_raw.bin")


_VA_GATED_PRODUCERS = ["read_hex_result", "read_hex_raw_result", "search_bytes_result"]


@pytest.mark.parametrize("fn_name", _VA_GATED_PRODUCERS)
@pytest.mark.parametrize("fixture_name", ["gcore_dump", "regioned_raw_dump"])
def test_va_view_on_a_region_backed_source_raises_unsupported_format(
    session, request, fn_name, fixture_name,
):
    """Not a bare ValueError — that is the whole point.

    ``pytest.raises(ValueError)`` would pass against the pre-guard behaviour
    (``UnsupportedFormatError`` is not a ValueError, but the old code's
    ValueError is), so the assertion has to name the capability type
    explicitly and additionally deny ValueError, or this test cannot fail for
    the reason it exists.
    """
    dump_path = request.getfixturevalue(fixture_name)
    fn = getattr(tools_inspect, fn_name)
    kwargs = {"pattern_hex": "ab"} if fn_name == "search_bytes_result" else {}
    with pytest.raises(UnsupportedFormatError) as exc_info:
        fn(session, dump_path, view="va", **kwargs)
    err = exc_info.value
    assert not isinstance(err, ValueError), "must be a capability error, not a ValueError"
    assert err.details["view"] == "va"
    assert "va" not in err.details["supported_views"]
    # The operator is told which views DO work, not just that this one did not.
    assert err.details["supported_views"] == ["raw", "vas"]
    assert err.details["format"] in ("gcore", "gdb_raw")


def test_analyze_region_result_va_view_raises_unsupported_format(session, gcore_dump):
    """``analyze_region_result`` reads through the same ``size_for(view)`` and
    is reachable with the same persisted ``viewMode``, so it is gated too."""
    with pytest.raises(UnsupportedFormatError):
        tools_inspect.analyze_region_result(session, gcore_dump, 0, view="va")


@pytest.mark.parametrize("fn_name", _VA_GATED_PRODUCERS)
def test_va_view_on_an_msl_is_not_gated(session, plain_msl, fn_name):
    """The negative control: the guard must reject only what is genuinely
    unavailable. An .msl declares "va", so the same call has to succeed —
    otherwise a guard that refused every "va" request would pass the tests
    above."""
    fn = getattr(tools_inspect, fn_name)
    kwargs = {"pattern_hex": "abab"} if fn_name == "search_bytes_result" else {}
    result = fn(session, plain_msl, view="va", **kwargs)
    assert result.payload["view"] == "va"


def test_search_bytes_result_va_view_returns_real_hits(session, plain_msl):
    """And the hits are real: ``_write_plain_msl`` fills one 4096-byte region
    with 0xAB, so a two-byte 0xABAB needle must be found from offset 0 — a
    producer that merely returned an empty offsets list would satisfy the
    "not gated" test above."""
    result = tools_inspect.search_bytes_result(
        session, plain_msl, pattern_hex="abab", view="va",
    )
    offsets = result.payload["offsets"]
    assert offsets[:3] == [0, 1, 2]
    assert result.payload["count"] == 4096 - 1
    assert result.status.resolution == Resolution.OK


# ── multi-format needles (pattern_format) ─────────────────────────────────
#
# One search box, several spellings. These tests exist because the ONLY thing
# that was ever hex-specific about a byte search is the parse step: the same
# dump offset has to be reachable whether the analyst holds the needle as a
# string, a wide string, hex digits, a base64 blob or a pointer value. A
# producer that accepted `pattern_format` but ignored it would still pass every
# pre-existing test in this file, so each format is proven against a byte run
# planted at a KNOWN offset.


_MULTIFORMAT_WORD = "SECRET"
_MULTIFORMAT_HEX_RUN = "deadbeef"
#: The same four bytes as ``_MULTIFORMAT_HEX_RUN``, spelled base64.
_MULTIFORMAT_BASE64 = "3q2+7w=="
_MULTIFORMAT_U32 = 0x11223344


@pytest.fixture
def multiformat_dump(tmp_path):
    """A raw dump carrying four needles, each in exactly one spelling.

    Returns ``(path, offsets)`` where ``offsets`` maps a format name to the one
    offset that format's needle occupies. The chunks are separated by NUL
    padding and chosen so no needle is a substring of another — an ASCII
    ``SECRET`` does not occur inside ``S\\0E\\0C\\0R\\0E\\0T\\0`` — which is
    what lets each assertion name an exact offset instead of "at least one hit".
    """
    chunks = [
        ("pad", b"\x00" * 8),
        ("text", _MULTIFORMAT_WORD.encode("utf-8")),
        ("pad", b"\x00" * 8),
        ("utf16le", _MULTIFORMAT_WORD.encode("utf-16-le")),
        ("pad", b"\x00" * 8),
        ("hex", bytes.fromhex(_MULTIFORMAT_HEX_RUN)),
        ("pad", b"\x00" * 8),
        ("u32le", _MULTIFORMAT_U32.to_bytes(4, "little")),
        ("pad", b"\x00" * 8),
    ]
    blob = bytearray()
    offsets = {}
    for name, chunk in chunks:
        if name != "pad":
            offsets[name] = len(blob)
        blob += chunk
    dump = tmp_path / "multiformat.dump"
    dump.write_bytes(bytes(blob))
    return str(dump), offsets


@pytest.mark.parametrize(
    "fmt, pattern, offset_key",
    [
        ("text", _MULTIFORMAT_WORD, "text"),
        ("utf16le", _MULTIFORMAT_WORD, "utf16le"),
        ("hex", _MULTIFORMAT_HEX_RUN, "hex"),
        ("base64", _MULTIFORMAT_BASE64, "hex"),
        ("u32le", str(_MULTIFORMAT_U32), "u32le"),
        ("u32le", hex(_MULTIFORMAT_U32), "u32le"),
    ],
)
def test_search_bytes_result_finds_each_format_at_its_planted_offset(
    session, multiformat_dump, fmt, pattern, offset_key
):
    """Every spelling reaches the bytes it names, and only those bytes.

    The ``base64`` row is the cross-check that all six go through ONE parse
    step: ``3q2+7w==`` and ``deadbeef`` are the same four bytes, so they must
    land on the same offset. Both integer rows are the same value written two
    ways (``int(text, 0)``), so a parser that forgot the ``0x`` prefix would
    fail exactly one of them.
    """
    dump_path, offsets = multiformat_dump
    result = tools_inspect.search_bytes_result(
        session, dump_path, pattern_hex=pattern, pattern_format=fmt)
    assert result.payload["offsets"] == [offsets[offset_key]]
    assert result.payload["count"] == 1
    assert result.payload["pattern_format"] == fmt


def test_search_bytes_result_echoes_the_resolved_bytes_not_the_typed_text(
    session, multiformat_dump
):
    """``pattern_hex`` on the way OUT is the bytes that were searched for.

    For a text, base64 or integer needle this is the only place a caller can
    see what the box actually looked for, and it is what the hex viewer
    highlights. Echoing the typed text back instead would be indistinguishable
    from a correct response for a hex search and wrong for every other format.
    """
    dump_path, _ = multiformat_dump
    result = tools_inspect.search_bytes_result(
        session, dump_path, pattern_hex="AB", pattern_format="text")
    assert result.payload["pattern_hex"] == "4142"
    assert result.payload["pattern_len"] == 2


def test_search_bytes_result_auto_echoes_both_the_request_and_the_resolution(
    session, multiformat_dump
):
    """``auto`` must report what it RESOLVED to, plus what was asked.

    "What did this actually search for?" is the question a multi-format box has
    to keep answering: echoing ``auto`` back in ``pattern_format`` would tell
    the caller only what they already typed. ``deadbeef`` is the interesting
    input because it is valid hex AND a valid word — the two fields together
    are what make the choice visible (and one-click reversible) instead of a
    silent guess.
    """
    dump_path, offsets = multiformat_dump
    result = tools_inspect.search_bytes_result(
        session, dump_path, pattern_hex=_MULTIFORMAT_HEX_RUN,
        pattern_format="auto")
    assert result.payload["pattern_format"] == "hex"
    assert result.payload["pattern_format_requested"] == "auto"
    assert result.payload["offsets"] == [offsets["hex"]]

    as_text = tools_inspect.search_bytes_result(
        session, dump_path, pattern_hex=_MULTIFORMAT_WORD, pattern_format="auto")
    assert as_text.payload["pattern_format"] == "text"
    assert as_text.payload["pattern_format_requested"] == "auto"
    assert as_text.payload["offsets"] == [offsets["text"]]


def test_search_bytes_result_concrete_format_is_echoed_as_requested(
    session, multiformat_dump
):
    """The negative control for the pair above: with no ``auto`` in play the
    two fields agree, so a producer that hard-coded ``"auto"`` into either one
    cannot pass both tests."""
    dump_path, _ = multiformat_dump
    result = tools_inspect.search_bytes_result(
        session, dump_path, pattern_hex=_MULTIFORMAT_WORD, pattern_format="text")
    assert result.payload["pattern_format"] == "text"
    assert result.payload["pattern_format_requested"] == "text"


def test_search_bytes_result_wrong_format_finds_nothing(session, tmp_path):
    """Why UTF-16LE earns its place as a separate format.

    An ASCII-only buffer does NOT contain the wide spelling of the same word,
    and a wide buffer does not contain the narrow one. If the formats collapsed
    into each other (say, by stripping NULs), an analyst searching a dump for a
    wide string would get hits that are not there — and, worse, would trust a
    "0 hits" answer that never asked the right question. Both directions are
    asserted so a format that matched EVERYTHING would fail too.
    """
    dump = tmp_path / "ascii_only.dump"
    dump.write_bytes(b"\x00" * 8 + b"SECRET" + b"\x00" * 8)

    narrow = tools_inspect.search_bytes_result(
        session, str(dump), pattern_hex="SECRET", pattern_format="text")
    assert narrow.payload["offsets"] == [8]

    wide = tools_inspect.search_bytes_result(
        session, str(dump), pattern_hex="SECRET", pattern_format="utf16le")
    assert wide.payload["offsets"] == []
    assert wide.payload["count"] == 0
    # A real answer, not an error: the search ran and found nothing.
    assert wide.payload["pattern_format"] == "utf16le"
    assert wide.status.resolution == Resolution.OK


def test_search_bytes_result_count_is_exact_for_a_normal_search(
    session, multiformat_dump
):
    """``count_exact`` is the promise that ``count`` is a TOTAL, not a floor.

    Every sane query must carry ``True``; the flag only drops for a scan that
    hit the OOM valve (next test). Without this control, hard-wiring it to
    ``False`` — which would make every hit count in the UI read "1,000,000+" —
    would go unnoticed.
    """
    dump_path, _ = multiformat_dump
    result = tools_inspect.search_bytes_result(
        session, dump_path, pattern_hex=_MULTIFORMAT_HEX_RUN)
    assert result.payload["count_exact"] is True


def test_search_bytes_result_count_is_a_lower_bound_at_the_scan_valve(
    session, tmp_path, monkeypatch
):
    """A one-byte needle must not be able to OOM the process.

    ``MAX_SEARCH_SCAN_HITS`` caps how many offsets are COLLECTED (the page cap
    used to be applied by slicing a list that was already fully materialised —
    fine for a 32-byte key, fatal for a one-byte pattern over a multi-gigabyte
    dump). When the valve fires, ``count`` is a lower bound and the payload has
    to say so, or the UI would report a number the search never checked.
    The real valve is deliberately far above any real query, so it is lowered
    here rather than fed a million-hit dump.
    """
    monkeypatch.setattr(tools_inspect, "MAX_SEARCH_SCAN_HITS", 4)
    dump = tmp_path / "many.dump"
    dump.write_bytes(b"\xaa" * 64)
    result = tools_inspect.search_bytes_result(
        session, str(dump), pattern_hex="aa")
    assert result.payload["count"] == 4
    assert result.payload["count_exact"] is False


# ── invalid needles are capability errors, never crashes ──────────────────


@pytest.mark.parametrize(
    "pattern, fmt, message",
    [
        pytest.param("abc", "hex", "odd number of hex digits",
                     id="odd-length-hex"),
        pytest.param("not base64!", "base64", "Invalid base64 pattern",
                     id="bad-base64"),
        pytest.param("-1", "u32le", "must not be negative",
                     id="negative-integer"),
        pytest.param("4294967296", "u32le", "does not fit in 4 bytes",
                     id="u32-overflow"),
        pytest.param("18446744073709551616", "u64be", "does not fit in 8 bytes",
                     id="u64-overflow"),
        pytest.param("ten", "u32le", "Invalid integer pattern",
                     id="non-numeric-integer"),
        pytest.param("41", "rot13", "Unknown pattern format",
                     id="unknown-format"),
    ],
)
def test_search_bytes_result_invalid_needle_raises_capability_error(
    session, multiformat_dump, pattern, fmt, message
):
    """Bad input is the CALLER's, and every surface already knows how to
    present a CapabilityError: the web route turns it into a 200 error body,
    the CLI into a non-zero exit, MCP into an ``{"error": ...}`` dict. A raw
    ValueError or OverflowError escaping here is a 500 on the web surface and a
    traceback on the others — so the category is asserted too, not just the
    type: only INVALID_INPUT tells a UI to blame the search box rather than the
    dump.
    """
    dump_path, _ = multiformat_dump
    with pytest.raises(CapabilityError, match=message) as exc_info:
        tools_inspect.search_bytes_result(
            session, dump_path, pattern_hex=pattern, pattern_format=fmt)
    assert exc_info.value.category is ErrorCategory.INVALID_INPUT


def test_search_bytes_result_unknown_format_names_the_valid_ones(
    session, multiformat_dump
):
    """An operator who typed ``--format=utf16`` must be told the spelling that
    works, not merely that theirs did not."""
    dump_path, _ = multiformat_dump
    with pytest.raises(CapabilityError) as exc_info:
        tools_inspect.search_bytes_result(
            session, dump_path, pattern_hex="41", pattern_format="utf16")
    assert "utf16le" in str(exc_info.value)


# ── back-compat: the default is hex, and stays hex ────────────────────────


def test_search_bytes_result_defaults_to_hex_not_auto(session, multiformat_dump):
    """The property that keeps scripts and MCP agents predictable.

    ``auto`` is offered for convenience but is deliberately NOT the default on
    this layer: under ``auto`` an odd-length hex string — an ERROR today, and
    almost always a typo — would quietly become a TEXT search that returns a
    confident "0 hits" for a needle the caller never asked for. Only the web UI
    resolves ``auto``, because only it can show the resolved bytes first.
    """
    dump_path, offsets = multiformat_dump
    # A pure-hex needle still means hex, with no format argument at all.
    hex_hit = tools_inspect.search_bytes_result(
        session, dump_path, pattern_hex=_MULTIFORMAT_HEX_RUN)
    assert hex_hit.payload["offsets"] == [offsets["hex"]]
    assert hex_hit.payload["pattern_format"] == "hex"
    assert hex_hit.payload["pattern_format_requested"] == "hex"

    # And an odd-length one is still an error, NOT a silent text search.
    with pytest.raises(CapabilityError, match="Invalid hex byte pattern"):
        tools_inspect.search_bytes_result(session, dump_path, pattern_hex="abc")


def test_search_bytes_result_legacy_hex_callers_are_byte_for_byte_unchanged(
    session, multiformat_dump
):
    """A caller that passes only ``pattern_hex`` gets exactly the old payload.

    ``pattern_hex`` kept its historical name when it became the raw pattern
    TEXT, so every pinned script and every stored query keeps working — the
    0x-prefix and whitespace spellings included. Comparing an explicit
    ``pattern_format="hex"`` call against the bare one locks the default in
    place: flipping it to ``auto`` would not fail the assertions above for this
    input, but would fail this one the moment the default stopped being hex.
    """
    dump_path, offsets = multiformat_dump
    bare = tools_inspect.search_bytes_result(
        session, dump_path, pattern_hex=" 0xDE AD be ef ")
    explicit = tools_inspect.search_bytes_result(
        session, dump_path, pattern_hex="deadbeef", pattern_format="hex")
    assert bare.payload == explicit.payload
    assert bare.payload["pattern_hex"] == _MULTIFORMAT_HEX_RUN
    assert bare.payload["offsets"] == [offsets["hex"]]
