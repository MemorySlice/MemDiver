"""D1 — ``analysis.yara_scan`` on all four surfaces.

MemDiver could EMIT a YARA rule from the day the architect layer landed, and
``engine/yara_scan.py`` could RUN one. Between the two sat nothing: the engine
module was 793 lines, fully tested, and reachable from NO surface, so every
detector the product emitted was unevaluated by construction — you could
publish a rule and never learn whether it fires on the corpus it came from.
``scan_yara_rule`` is that missing middle, and this module is its four-surface
proof.

What these tests pin, in order:

* the exactly-one-of guard over ``rule_source`` / ``rule_paths`` — both forms,
  and neither, are refused BY NAME rather than resolved by precedence, because
  silently preferring one hands the caller a confident census produced by rules
  they did not intend;
* the closed loop itself: a rule built by the REAL emitter chain
  (``PatternGenerator.generate`` -> ``YaraExporter.export``) matching at a
  KNOWN planted offset. Hand-written rule text would prove the scanner works
  and say nothing about whether the product's own output is scannable;
* ONE compile for N dumps — the whole point of the engine's content-addressed
  rule cache, and what makes the per-dump rows comparable;
* the two-valued row model and the FOUR-valued verdict, which together are the
  capability. "Scanned and clean" (we looked at every byte and it is not there)
  must stay distinguishable from "scanned but degraded" (libyara ran out of
  budget, or a chunk errored) and from "never scanned at all". Collapse any of
  those into a zero and every detection rate computed from the result is over a
  silently deflated denominator;
* that a locked encrypted ``.msl`` RAISES rather than scanning. This is the
  single most consequential assertion in the file: a locked container reads back
  EMPTY instead of failing, so without the guard every locked dump comes back as
  a perfectly ordinary ``verdict: "clean"`` with no diagnostic and nothing to
  audit afterwards;
* the four surfaces routing to one producer, MCP and web byte-for-byte included.

``import yara`` is a hard import, deliberately NOT ``pytest.importorskip``:
yara-python is a declared BASE dependency (see ``tests/test_install_contract.py``
and ``pyproject.toml``), so its absence is a broken environment that must fail
loudly. Quiet skipping is how a dependency goes undeclared in the first place.
"""

from __future__ import annotations

import json
import os
import random
import sys
from pathlib import Path

import pytest
import yara  # noqa: F401  — see the module docstring: a HARD import, on purpose

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from memdiver.app.tools_pipeline import (  # noqa: E402
    DEFAULT_INCLUDE_MATCHES,
    YARA_CLEAN,
    YARA_INCONCLUSIVE,
    YARA_INTAKE_PATHS,
    YARA_INTAKE_SOURCE,
    YARA_MATCHED,
    YARA_NOT_SCANNED,
    YARA_SCAN_CLEAN_CODE,
    YARA_SCAN_COUNT_ONLY_CODE,
    YARA_SCAN_ERRORS_CODE,
    YARA_SCAN_INCONCLUSIVE_CODE,
    YARA_SCAN_NOT_SCANNED_CODE,
    YARA_SCAN_PARTIAL_CODE,
    YARA_SCAN_STATUSES,
    YARA_SCAN_TRUNCATED_CODE,
    YARA_SCAN_UNREADABLE_CODE,
    YARA_SCAN_VERDICTS,
    YARA_SCAN_ZERO_BYTES_CODE,
    YARA_SCANNED,
    YARA_UNREADABLE,
    scan_yara_rule,
)
from memdiver.architect.pattern_generator import PatternGenerator  # noqa: E402
from memdiver.architect.yara_exporter import YaraExporter  # noqa: E402
from memdiver.core.dump_source import open_dump  # noqa: E402
from memdiver.core.service_errors import (  # noqa: E402
    CapabilityError,
    EncryptedDumpLockedError,
    ErrorCategory,
    FileNotFoundServiceError,
)
from memdiver.engine.yara_scan import (  # noqa: E402
    DEFAULT_MAX_MATCHES,
    DEFAULT_TIMEOUT_S,
    clear_rule_cache,
)
from tests.fixtures.generate_msl_fixtures import write_msl_fixture  # noqa: E402

_ROUTE = "/api/scan/yara"

#: Where a planted pattern is written into a synthetic dump. Non-zero on
#: purpose: an offset of 0 would let a bug that reports "matched at 0" for every
#: dump pass, and 0 is also what a half-initialised result looks like.
_PLANT_OFFSET = 4096
_DUMP_SIZE = 65536


@pytest.fixture(autouse=True)
def _fresh_rule_cache():
    """Compile from scratch in every test.

    The engine memoises compiled rule sets on the BLAKE3 of their normalized
    source, keyed content-addressably and never on a path. That is exactly what
    makes a corpus sweep affordable — and it also means one test's rules can
    satisfy another's compile, hiding a compile-path regression behind a cache
    hit. Clearing between tests keeps every assertion about compilation honest.
    """
    clear_rule_cache()
    yield
    clear_rule_cache()


# --------------------------------------------------------------------------- #
# Rules built the way the PRODUCT builds them, and dumps to find them in
# --------------------------------------------------------------------------- #

def _keyish_window(seed: int, *, total: int = 48, key_len: int = 16):
    """A window whose middle bytes are the volatile "key".

    Static ratio 32/48 = 0.667, comfortably over the generator's 0.3 floor, and
    the first and last bytes stay static so the emitted hex string neither
    begins nor ends with a wildcard. Copied in spirit from
    ``tests/test_yara_scan.py::_keyish_reference`` so both modules exercise the
    emitter on the same shape of input.
    """
    rng = random.Random(seed)
    reference = bytes(rng.randrange(256) for _ in range(total))
    key_at = (total - key_len) // 2
    mask = [True] * total
    for i in range(key_at, key_at + key_len):
        mask[i] = False
    return reference, mask, key_at, key_len


def emitted_rule(seed: int, *, name: str = "planted_pattern", drop_length: bool = False):
    """Run the REAL emitter chain and return ``(rule_text, reference_bytes)``.

    ``PatternGenerator.generate`` -> ``YaraExporter.export``, never hand-written
    text: the assertion this module exists to make is about the product's own
    output being scannable, and a hand-rolled rule would prove only that
    libyara works.

    ``drop_length`` removes the pattern dict's ``length`` before export, which
    is the emitter's own documented path to a rule with NO ``pattern_length``
    meta (``architect/yara_exporter.py`` omits the meta rather than emitting a
    false ``0``). That is the only way to reach the engine's "we do not know how
    wide your patterns are" degraded state through real code, and
    :func:`test_producer_surfaces_scan_errors_from_a_rule_without_pattern_length`
    is what needs it.
    """
    reference, mask, key_at, key_len = _keyish_window(seed)
    pattern = PatternGenerator.generate(reference, mask, name=name)
    assert pattern is not None, "pattern generator rejected the fixture mask"
    if drop_length:
        pattern = {k: v for k, v in pattern.items() if k != "length"}
    return YaraExporter.export(
        pattern, key_offset=key_at, key_length=key_len
    ), reference


def write_dump(path: Path, plants: dict, *, seed: int = 7, size: int = _DUMP_SIZE) -> Path:
    """Write a random-filled raw dump with *plants* = ``{offset: bytes}``."""
    rng = random.Random(seed)
    path.parent.mkdir(parents=True, exist_ok=True)
    buf = bytearray(rng.randrange(256) for _ in range(size))
    for offset, blob in plants.items():
        buf[offset:offset + len(blob)] = blob
    path.write_bytes(bytes(buf))
    return path


def _write_encrypted_msl(path: Path, key: bytes, *, data=b"\xCD" * 4096) -> None:
    """An AES-256-GCM ``.msl``. Same helper shape as the G9 invariant test's."""
    from memdiver.msl.writer import MslEncryptionConfig, MslWriter

    cfg = MslEncryptionConfig(raw_key=key)
    writer = MslWriter(str(path), pid=7, encryption=cfg)
    writer.add_memory_region(0x1000, data)
    writer.add_end_of_capture()
    writer.write()


@pytest.fixture
def encrypted_msl(tmp_path):
    """A locked encrypted container plus the key file that would open it."""
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


# --------------------------------------------------------------------------- #
# (a) the rule-intake guard — exactly one form, named in the refusal
# --------------------------------------------------------------------------- #

def test_producer_refuses_both_rule_forms(tmp_path):
    """No precedence. Silently preferring one form would produce a complete,
    confident census from rules the caller did not intend."""
    rule, _ = emitted_rule(1)
    rule_file = tmp_path / "r.yar"
    rule_file.write_text(rule)
    dump = write_dump(tmp_path / "a.dump", {})

    with pytest.raises(CapabilityError) as excinfo:
        scan_yara_rule(
            dump_paths=[str(dump)],
            rule_source=rule,
            rule_paths=[str(rule_file)],
        )

    assert excinfo.value.category is ErrorCategory.INVALID_INPUT
    message = str(excinfo.value)
    # BOTH names appear, so the caller learns which two things collided rather
    # than being told one of them is wrong.
    assert "rule_source" in message and "rule_paths" in message
    assert "both were supplied" in message


def test_producer_refuses_neither_rule_form(tmp_path):
    dump = write_dump(tmp_path / "a.dump", {})

    with pytest.raises(CapabilityError) as excinfo:
        scan_yara_rule(dump_paths=[str(dump)])

    assert excinfo.value.category is ErrorCategory.INVALID_INPUT
    assert "neither was" in str(excinfo.value)


def test_producer_refuses_an_empty_dump_set(tmp_path):
    """PRECONDITION, matching ``locate_key``'s own empty-set refusal: there is
    nothing to be clean about."""
    rule, _ = emitted_rule(1)

    with pytest.raises(CapabilityError) as excinfo:
        scan_yara_rule(dump_paths=[], rule_source=rule)

    assert excinfo.value.category is ErrorCategory.PRECONDITION


def test_producer_404s_a_missing_dump(tmp_path):
    rule, _ = emitted_rule(1)

    with pytest.raises(FileNotFoundServiceError) as excinfo:
        scan_yara_rule(dump_paths=[str(tmp_path / "nope.dump")], rule_source=rule)

    assert "nope.dump" in str(excinfo.value)


def test_producer_404s_a_missing_rule_file_before_reading_any_dump(tmp_path):
    """Existence is checked over BOTH sides up front, so a typo is reported
    before N dumps are swept — the same posture ``locate_field_across_pairs``
    takes over its (dump, capture) pairs."""
    dump = write_dump(tmp_path / "a.dump", {})

    with pytest.raises(FileNotFoundServiceError) as excinfo:
        scan_yara_rule(
            dump_paths=[str(dump)], rule_paths=[str(tmp_path / "gone.yar")])

    assert "gone.yar" in str(excinfo.value)


def test_producer_propagates_a_libyara_compile_error(tmp_path):
    """The engine's own words, uncategorised and unwrapped. All four surfaces
    report a bad rule identically because none of them re-phrases it."""
    dump = write_dump(tmp_path / "a.dump", {})

    with pytest.raises(CapabilityError) as excinfo:
        scan_yara_rule(dump_paths=[str(dump)], rule_source="rule broken {")

    assert excinfo.value.category is ErrorCategory.INVALID_INPUT
    assert excinfo.value.code is not None and "yara" in excinfo.value.code


# --------------------------------------------------------------------------- #
# (b) the closed loop — an emitted rule found at a KNOWN offset
# --------------------------------------------------------------------------- #

def test_an_emitted_rule_matches_at_the_planted_offset(tmp_path):
    """THE point of the capability: the product's own output is scannable.

    The rule comes out of ``PatternGenerator`` -> ``YaraExporter``, the window
    is planted at a known non-zero offset, and the match's ``offset`` must be
    that offset exactly.
    """
    rule, reference = emitted_rule(11, name="closed_loop")
    dump = write_dump(tmp_path / "a.dump", {_PLANT_OFFSET: reference})

    payload = scan_yara_rule(dump_paths=[str(dump)], rule_source=rule)

    assert payload["verdict"] == YARA_MATCHED
    assert payload["intake"] == YARA_INTAKE_SOURCE
    assert payload["rules"]["names"] == ["closed_loop"]
    row = payload["dumps"][0]
    assert row["status"] == YARA_SCANNED
    assert row["scan"]["match_count"] == 1
    assert [m["offset"] for m in row["scan"]["matches"]] == [_PLANT_OFFSET]


def test_the_match_carries_the_key_metas_so_the_key_is_locatable(tmp_path):
    """``offset`` is the matched WINDOW's start, not the key's. The emitted
    ``key_offset`` / ``key_length`` metas are what turn a window hit into a key
    location, and the producer must carry them through untouched."""
    rule, reference = emitted_rule(12)
    _, _, key_at, key_len = _keyish_window(12)
    dump = write_dump(tmp_path / "a.dump", {_PLANT_OFFSET: reference})

    payload = scan_yara_rule(dump_paths=[str(dump)], rule_source=rule)

    match = payload["dumps"][0]["scan"]["matches"][0]
    assert match["key_offset"] == key_at
    assert match["key_length"] == key_len
    # The key itself sits at offset + key_offset, and this is where it was
    # planted.
    assert match["offset"] + match["key_offset"] == _PLANT_OFFSET + key_at


def test_rule_files_are_the_other_intake(tmp_path):
    """The ``rule_paths`` form, and its ``intake`` marker. Two files may define
    the same rule name because each is compiled into its own namespace."""
    rule_a, reference = emitted_rule(13, name="same_name")
    rule_b, _ = emitted_rule(14, name="same_name")
    (tmp_path / "first.yar").write_text(rule_a)
    (tmp_path / "second.yar").write_text(rule_b)
    dump = write_dump(tmp_path / "a.dump", {_PLANT_OFFSET: reference})

    payload = scan_yara_rule(
        dump_paths=[str(dump)],
        rule_paths=[str(tmp_path / "first.yar"), str(tmp_path / "second.yar")],
    )

    assert payload["intake"] == YARA_INTAKE_PATHS
    # Both survive compilation despite the identical identifier — that is what
    # the per-file namespace buys.
    assert payload["rules"]["count"] == 2
    assert payload["rules"]["paths"] == [
        str(tmp_path / "first.yar"), str(tmp_path / "second.yar")]
    assert payload["verdict"] == YARA_MATCHED


def test_no_precompiled_rule_blob_is_accepted(tmp_path):
    """A ``.yarc`` is executable libyara bytecode, so loading one has the trust
    properties of importing a module. The producer has NO parameter for it, and
    handing a compiled blob to the text intake fails at compile time rather
    than being helpfully detected and loaded."""
    import inspect

    params = inspect.signature(scan_yara_rule).parameters
    # The guard that matters most: no widening of the intake, ever.
    assert not any("yarc" in p or "compiled" in p for p in params)

    rule, _ = emitted_rule(15)
    compiled = tmp_path / "rules.yarc"
    yara.compile(source=rule).save(str(compiled))
    dump = write_dump(tmp_path / "a.dump", {})

    # ``(CapabilityError, ValueError)`` because a compiled blob carries NUL
    # bytes and libyara's own binding rejects a NUL-bearing source string
    # ("embedded null character") before the engine's ``yara.Error`` funnel ever
    # sees it. Which of the two lands is not the point: the point is that the
    # blob is REFUSED rather than helpfully detected and ``yara.load()``ed.
    with pytest.raises((CapabilityError, ValueError)):
        scan_yara_rule(
            dump_paths=[str(dump)],
            rule_source=compiled.read_bytes().decode("latin-1"),
        )


# --------------------------------------------------------------------------- #
# (c) N dumps, ONE compile, and the row / verdict model
# --------------------------------------------------------------------------- #

def test_one_rule_set_scans_many_dumps_and_rows_keep_the_supplied_order(tmp_path):
    """Compile once, scan N. The rows come back in the SUPPLIED order so they
    can be zipped against ``dump_paths``."""
    rule, reference = emitted_rule(21)
    dumps = [
        write_dump(tmp_path / "hit_a.dump", {_PLANT_OFFSET: reference}, seed=1),
        write_dump(tmp_path / "miss.dump", {}, seed=2),
        write_dump(tmp_path / "hit_b.dump", {_PLANT_OFFSET: reference}, seed=3),
    ]

    payload = scan_yara_rule(
        dump_paths=[str(d) for d in dumps], rule_source=rule)

    assert [r["name"] for r in payload["dumps"]] == [
        "hit_a.dump", "miss.dump", "hit_b.dump"]
    assert payload["verdict"] == YARA_MATCHED
    assert payload["counts"]["dumps_matched"] == 2
    assert payload["counts"]["dumps_clean"] == 1
    assert payload["counts"]["matches_total"] == 2
    # Every row was produced by the SAME compiled rule set, which is what makes
    # them comparable at all.
    assert {tuple(r["scan"]["rule_names"]) for r in payload["dumps"]} == {
        tuple(payload["rules"]["names"])}


def test_the_rule_cache_serves_the_second_scan_of_the_same_source(tmp_path):
    """Content-addressed, so two calls with byte-identical rule text compile
    once. A sweep of thousands of dumps pays the compile cost one time; without
    this the recompile dominates the runtime."""
    from memdiver.engine import yara_scan as engine_yara_scan

    rule, reference = emitted_rule(22)
    dump = write_dump(tmp_path / "a.dump", {_PLANT_OFFSET: reference})

    compiles = []
    real_compile = yara.compile

    def _counting_compile(*args, **kwargs):
        compiles.append(kwargs)
        return real_compile(*args, **kwargs)

    engine_yara_scan.yara.compile = _counting_compile  # type: ignore[attr-defined]
    try:
        scan_yara_rule(dump_paths=[str(dump)], rule_source=rule)
        scan_yara_rule(dump_paths=[str(dump)], rule_source=rule)
    finally:
        engine_yara_scan.yara.compile = real_compile  # type: ignore[attr-defined]

    assert len(compiles) == 1, compiles


def test_a_clean_scan_is_a_MEASURED_absence_and_says_so(tmp_path):
    """``"clean"`` is the ONE verdict that may be read as an absence, and it is
    reachable only when every scanned byte really was compared."""
    rule, _ = emitted_rule(23)
    dump = write_dump(tmp_path / "a.dump", {})

    payload = scan_yara_rule(dump_paths=[str(dump)], rule_source=rule)

    assert payload["verdict"] == YARA_CLEAN
    assert payload["counts"]["dumps_clean"] == 1
    assert payload["counts"]["dumps_inconclusive"] == 0
    assert payload["dumps"][0]["scan"]["match_count"] == 0
    assert payload["dumps"][0]["scan"]["scanned_bytes"] == _DUMP_SIZE
    codes = [d["code"] for d in payload["diagnostics"]]
    # A clean scan of an emitted key signature is a RECALL result, not an
    # error, and the diagnostic says which.
    assert YARA_SCAN_CLEAN_CODE in codes


def test_an_unreadable_dump_is_a_TYPED_ROW_not_an_absence(tmp_path):
    """A directory where a dump was expected. It becomes a row with
    ``status="unreadable"`` and ``scan=None`` — NOT a zero-match row, and not an
    omission: dropping it would shrink the denominator every rate is over."""
    rule, _ = emitted_rule(24)
    not_a_dump = tmp_path / "a_directory"
    not_a_dump.mkdir()

    payload = scan_yara_rule(dump_paths=[str(not_a_dump)], rule_source=rule)

    assert payload["verdict"] == YARA_NOT_SCANNED
    row = payload["dumps"][0]
    assert row["status"] == YARA_UNREADABLE
    # THE assertion: there is no ``match_count: 0`` here for a falsy check to
    # misread as "we looked and it was not there".
    assert row["scan"] is None
    assert row["detail"]
    assert payload["counts"]["dumps_scanned"] == 0
    assert payload["counts"]["dumps_unreadable"] == 1
    codes = [d["code"] for d in payload["diagnostics"]]
    assert YARA_SCAN_NOT_SCANNED_CODE in codes
    assert YARA_SCAN_UNREADABLE_CODE in codes


def test_partial_coverage_is_reported_as_the_normal_shape_it_is(tmp_path):
    rule, reference = emitted_rule(25)
    dumps = [
        write_dump(tmp_path / "hit.dump", {_PLANT_OFFSET: reference}, seed=1),
        write_dump(tmp_path / "miss.dump", {}, seed=2),
    ]

    payload = scan_yara_rule(
        dump_paths=[str(d) for d in dumps], rule_source=rule)

    codes = [d["code"] for d in payload["diagnostics"]]
    assert YARA_SCAN_PARTIAL_CODE in codes
    partial = next(d for d in payload["diagnostics"]
                   if d["code"] == YARA_SCAN_PARTIAL_CODE)
    assert partial["severity"] == "info"


def test_the_row_status_and_scan_payload_are_a_biconditional(tmp_path):
    """Every row is one of exactly two shapes, and the roll-up trusts that."""
    rule, reference = emitted_rule(26)
    directory = tmp_path / "not_a_dump"
    directory.mkdir()
    dumps = [
        write_dump(tmp_path / "ok.dump", {_PLANT_OFFSET: reference}),
        directory,
    ]

    payload = scan_yara_rule(
        dump_paths=[str(d) for d in dumps], rule_source=rule)

    for row in payload["dumps"]:
        assert row["status"] in YARA_SCAN_STATUSES
        assert (row["status"] == YARA_SCANNED) == (row["scan"] is not None)
        assert (row["status"] == YARA_UNREADABLE) == bool(row["detail"])
    assert payload["verdict"] in YARA_SCAN_VERDICTS


# --------------------------------------------------------------------------- #
# (d) the caps, and the degraded channels the engine reports rather than hides
# --------------------------------------------------------------------------- #

def _repeated(reference: bytes, count: int, *, stride: int = 4096) -> dict:
    return {_PLANT_OFFSET + i * stride: reference for i in range(count)}


def test_max_matches_truncates_and_SAYS_it_truncated(tmp_path):
    """The cap is reported, never hidden: with it in force ``matches_total`` is
    a floor rather than a total, and the diagnostic says so."""
    rule, reference = emitted_rule(31)
    dump = write_dump(tmp_path / "a.dump", _repeated(reference, 3))

    payload = scan_yara_rule(
        dump_paths=[str(dump)], rule_source=rule, max_matches=1)

    row = payload["dumps"][0]
    assert row["scan"]["match_count"] == 1
    assert row["scan"]["truncated"] is True
    assert payload["counts"]["dumps_truncated"] == 1
    assert payload["caps"]["max_matches"] == 1
    codes = [d["code"] for d in payload["diagnostics"]]
    assert YARA_SCAN_TRUNCATED_CODE in codes
    # Truncation is NOT degradation: it can only happen when matches were
    # found, so it never manufactures a zero and never makes a result
    # inconclusive.
    assert payload["verdict"] == YARA_MATCHED
    assert payload["counts"]["dumps_inconclusive"] == 0


def test_max_matches_none_is_the_uncapped_census(tmp_path):
    """``None`` — spelled out, not arrived at — asks for every match. A recall
    measurement legitimately wants them all."""
    rule, reference = emitted_rule(32)
    dump = write_dump(tmp_path / "a.dump", _repeated(reference, 3))

    payload = scan_yara_rule(
        dump_paths=[str(dump)], rule_source=rule, max_matches=None)

    row = payload["dumps"][0]
    assert row["scan"]["match_count"] == 3
    assert row["scan"]["truncated"] is False
    assert payload["caps"]["max_matches"] is None


@pytest.mark.parametrize("cap", [0, -1])
def test_a_non_positive_max_matches_is_REFUSED_not_read_as_unlimited(tmp_path, cap):
    """A cap computed as ``limit - already_seen`` that reaches 0 means STOP.
    Being handed the whole multi-GB match list instead is the opposite of what
    the caller asked for, so a zero is an error and ``None`` is the spelling for
    "no cap"."""
    rule, _ = emitted_rule(33)
    dump = write_dump(tmp_path / "a.dump", {})

    with pytest.raises(CapabilityError) as excinfo:
        scan_yara_rule(
            dump_paths=[str(dump)], rule_source=rule, max_matches=cap)

    assert excinfo.value.category is ErrorCategory.INVALID_INPUT
    assert excinfo.value.code == "yara.bad_max_matches"
    # The remedy is named in the engine's own message, on every surface.
    assert "max_matches=None" in str(excinfo.value)


def test_a_negative_overlap_is_refused_by_the_engine(tmp_path):
    rule, _ = emitted_rule(34)
    msl = write_msl_fixture(tmp_path / "capture.msl")

    with pytest.raises(CapabilityError) as excinfo:
        scan_yara_rule(
            dump_paths=[str(msl)], rule_source=rule, overlap_bytes=-1)

    assert excinfo.value.code == "yara.bad_overlap"


def test_every_scanned_row_carries_all_three_degraded_channels(tmp_path):
    """``truncated`` / ``timed_out`` / ``errors`` are always PRESENT on a
    scanned row, so "not degraded" stays distinguishable from "this payload
    predates the fields"."""
    rule, reference = emitted_rule(35)
    dump = write_dump(tmp_path / "a.dump", {_PLANT_OFFSET: reference})

    payload = scan_yara_rule(dump_paths=[str(dump)], rule_source=rule)

    scan = payload["dumps"][0]["scan"]
    assert scan["truncated"] is False
    assert scan["timed_out"] is False
    assert scan["errors"] == []
    assert scan["strategy"] == "filepath"
    for key in ("dumps_truncated", "dumps_timed_out", "dumps_with_errors"):
        assert payload["counts"][key] == 0


def test_producer_surfaces_scan_errors_from_a_rule_without_pattern_length(tmp_path):
    """The engine's quiet degraded state, made loud.

    A rule with no ``pattern_length`` meta leaves the automatic chunk overlap
    nothing to size itself from, so it sits at the flat 4 KiB floor and a wider
    pattern becomes missable at a boundary. The engine records that in
    ``ScanResult.errors``; this producer must carry it into the payload AND
    count it, because a caller reading a rendered result cannot ignore what it
    never sees.

    The rule is still built by the real emitter — ``YaraExporter`` omits the
    meta (rather than emitting a false ``0``) when the pattern dict carries no
    ``length``, which is exactly this path.
    """
    rule, _ = emitted_rule(36, drop_length=True)
    # An ``.msl`` so the CHUNKED strategy runs: the filepath strategy hands the
    # whole file to libyara and has no chunk boundary to warn about.
    msl = write_msl_fixture(tmp_path / "capture.msl")

    payload = scan_yara_rule(dump_paths=[str(msl)], rule_source=rule)

    row = payload["dumps"][0]
    assert row["scan"]["strategy"] == "chunked"
    assert row["scan"]["errors"], "the overlap warning was swallowed"
    assert "pattern_length" in row["scan"]["errors"][0]
    assert payload["counts"]["dumps_with_errors"] == 1
    # And the absence of the meta is visible on the rule set itself, which is
    # the signal a caller can act on before scanning anything.
    assert payload["rules"]["max_pattern_length"] is None
    codes = [d["code"] for d in payload["diagnostics"]]
    assert YARA_SCAN_ERRORS_CODE in codes


def test_a_degraded_zero_is_INCONCLUSIVE_never_clean(tmp_path):
    """The silent-miss guard, and the reason the verdict is four-valued.

    Nothing matched, but the one scan that produced that zero could not
    guarantee boundary recall. Folding this into ``dumps_clean`` is exactly how
    a scan reports an unproven zero as an all-clear.
    """
    rule, _ = emitted_rule(37, drop_length=True)
    msl = write_msl_fixture(tmp_path / "capture.msl")

    payload = scan_yara_rule(dump_paths=[str(msl)], rule_source=rule)

    assert payload["dumps"][0]["scan"]["match_count"] == 0
    assert payload["verdict"] == YARA_INCONCLUSIVE
    assert payload["counts"]["dumps_clean"] == 0
    assert payload["counts"]["dumps_inconclusive"] == 1
    codes = [d["code"] for d in payload["diagnostics"]]
    assert YARA_SCAN_INCONCLUSIVE_CODE in codes
    # And crucially NOT the clean diagnostic, which would read as an absence.
    assert YARA_SCAN_CLEAN_CODE not in codes


def test_a_ZERO_BYTE_scan_is_inconclusive_never_clean(tmp_path):
    """The quietest degraded channel, and the hole this test was written for.

    A view that sizes to 0 runs the chunk loop zero times (or, on the filepath
    strategy, stats 0 bytes), so the row comes back with ``scanned_bytes: 0``,
    NO ``errors`` entry and NO timeout — and before ``_yara_row_degraded``
    accounted for it, it fell straight through into ``dumps_clean``. Declaring
    a dump clean having compared zero bytes against the rules is the same false
    all-clear the four-valued verdict exists to prevent, and it is the worst
    instance of it: not "we missed a chunk" but "we looked at nothing".

    An empty file is the smallest faithful reproduction; a garbage ``.msl``
    whose container projects no bytes into the requested view arrives at the
    identical row.
    """
    rule, _ = emitted_rule(40)
    empty = tmp_path / "empty.dump"
    empty.write_bytes(b"")

    payload = scan_yara_rule(dump_paths=[str(empty)], rule_source=rule)

    row = payload["dumps"][0]
    # The row is genuinely "scanned": the dump opened and a view was handed to
    # the scanner, so demoting it to an ``unreadable`` row with ``scan: null``
    # would misreport what happened (and break the status/scan biconditional).
    assert row["status"] == YARA_SCANNED
    assert row["scan"]["scanned_bytes"] == 0
    # None of the OTHER two degraded channels fired — which is exactly why this
    # case needs its own accounting rather than being inferred from them.
    assert row["scan"]["errors"] == []
    assert row["scan"]["timed_out"] is False

    assert payload["verdict"] == YARA_INCONCLUSIVE
    assert payload["counts"]["dumps_clean"] == 0
    assert payload["counts"]["dumps_inconclusive"] == 1
    assert payload["counts"]["dumps_zero_bytes"] == 1
    codes = [d["code"] for d in payload["diagnostics"]]
    assert YARA_SCAN_ZERO_BYTES_CODE in codes
    assert YARA_SCAN_INCONCLUSIVE_CODE in codes
    # And crucially NOT the clean diagnostic, which would read as an absence.
    assert YARA_SCAN_CLEAN_CODE not in codes


def test_a_scanned_dump_with_bytes_still_reports_zero_zero_byte_rows(tmp_path):
    """The other side of the guard: an ordinary scan must not be swept up by it.

    Without this, tightening ``_yara_row_degraded`` could be "fixed" by making
    every zero inconclusive, which would delete the one verdict value that is
    allowed to mean an absence.
    """
    rule, _ = emitted_rule(41)
    dump = write_dump(tmp_path / "real.dump", {})

    payload = scan_yara_rule(dump_paths=[str(dump)], rule_source=rule)

    assert payload["counts"]["scanned_bytes"] == _DUMP_SIZE
    assert payload["counts"]["dumps_zero_bytes"] == 0
    assert payload["verdict"] == YARA_CLEAN
    assert payload["counts"]["dumps_clean"] == 1


def test_a_timed_out_zero_is_also_inconclusive(tmp_path, monkeypatch):
    """``timed_out`` is the other half of the degraded channel: at least one
    chunk's bytes were never handed to libyara at all.

    A real libyara timeout is not reproducible in a unit test (it needs a
    multi-GB dump and a pathological rule), so the engine's OUTPUT is
    substituted here — the producer's roll-up is what is under test, and it must
    treat a timed-out zero exactly as it treats an errored one.
    """
    from memdiver.app import tools_pipeline
    from memdiver.engine import yara_scan as engine_yara_scan

    rule, _ = emitted_rule(38)
    dump = write_dump(tmp_path / "a.dump", {})
    real_scan = engine_yara_scan.scan_source

    def _timed_out(source, rules, **kwargs):
        result = real_scan(source, rules, **kwargs)
        return engine_yara_scan.ScanResult(
            **{**result.__dict__, "timed_out": True,
               "errors": ("scan of a.dump timed out after 60s",)})

    monkeypatch.setattr(engine_yara_scan, "scan_source", _timed_out)
    assert tools_pipeline is not None  # the producer imports the engine lazily

    payload = scan_yara_rule(dump_paths=[str(dump)], rule_source=rule)

    row = payload["dumps"][0]
    assert row["scan"]["timed_out"] is True
    assert payload["verdict"] == YARA_INCONCLUSIVE
    assert payload["counts"]["dumps_timed_out"] == 1
    assert payload["counts"]["dumps_clean"] == 0


def test_a_match_alongside_a_timeout_still_counts_as_matched(tmp_path, monkeypatch):
    """Degradation qualifies a ZERO. A dump that matched AND timed out has a
    real (if incomplete) match list, so it must not be demoted."""
    from memdiver.engine import yara_scan as engine_yara_scan

    rule, reference = emitted_rule(39)
    dump = write_dump(tmp_path / "a.dump", {_PLANT_OFFSET: reference})
    real_scan = engine_yara_scan.scan_source

    def _timed_out(source, rules, **kwargs):
        result = real_scan(source, rules, **kwargs)
        return engine_yara_scan.ScanResult(
            **{**result.__dict__, "timed_out": True})

    monkeypatch.setattr(engine_yara_scan, "scan_source", _timed_out)

    payload = scan_yara_rule(dump_paths=[str(dump)], rule_source=rule)

    assert payload["verdict"] == YARA_MATCHED
    assert payload["counts"]["dumps_matched"] == 1
    assert payload["counts"]["dumps_timed_out"] == 1
    assert payload["counts"]["dumps_inconclusive"] == 0


# --------------------------------------------------------------------------- #
# (e) the encrypted container — the silent false negative this guard prevents
# --------------------------------------------------------------------------- #

def test_a_locked_msl_RAISES_rather_than_scanning_clean(encrypted_msl, tmp_path):
    """THE assertion. A locked encrypted ``.msl`` reads back EMPTY instead of
    failing, so without the guard this call returns a perfectly ordinary
    ``verdict: "clean"`` over bytes nobody decrypted — a silent false negative
    with no diagnostic and nothing to audit afterwards.

    ``tests/test_architecture_invariants.py::test_g9_producers_surface_locked_dump``
    enumerates the producers that must do this; ``scan_yara_rule`` is in it.
    """
    rule, _ = emitted_rule(41)
    msl_path, _keyfile = encrypted_msl

    with pytest.raises(EncryptedDumpLockedError):
        scan_yara_rule(dump_paths=[msl_path], rule_source=rule)


def test_one_locked_dump_aborts_the_whole_set(encrypted_msl, tmp_path):
    """Not degraded into a row, unlike an unreadable dump: a forgotten key means
    every answer in the set is suspect, so it is a raise rather than N rows."""
    rule, reference = emitted_rule(42)
    msl_path, _keyfile = encrypted_msl
    readable = write_dump(tmp_path / "ok.dump", {_PLANT_OFFSET: reference})

    with pytest.raises(EncryptedDumpLockedError):
        scan_yara_rule(
            dump_paths=[str(readable), msl_path], rule_source=rule)


def test_the_supplied_key_unlocks_the_container_and_the_scan_proceeds(
    encrypted_msl, tmp_path,
):
    """The other side of the guard: with key material the container opens and
    the plaintext is scanned. The needle is read back out of the decrypted VAS
    view, so a match proves the scanner saw the PLAINTEXT rather than the
    container bytes libyara would have mapped off disk."""
    msl_path, keyfile = encrypted_msl
    with open_dump(Path(msl_path), key=Path(keyfile).read_bytes()) as source:
        needle_at = 128
        window = source.read_range(needle_at, 48, "vas")
    assert len(window) == 48
    # The fixture's region is a constant fill, so a static mask over it is the
    # only pattern the generator will accept here.
    pattern = PatternGenerator.generate(window, [True] * 48, name="enc_window")
    assert pattern is not None
    rule = YaraExporter.export(pattern)

    payload = scan_yara_rule(
        dump_paths=[msl_path], rule_source=rule, key_file=keyfile)

    row = payload["dumps"][0]
    assert row["status"] == YARA_SCANNED
    assert row["scan"]["view"] == "vas"
    assert payload["verdict"] == YARA_MATCHED
    assert needle_at in [m["offset"] for m in row["scan"]["matches"]]


# --------------------------------------------------------------------------- #
# (f) the web surface — POST /api/scan/yara
# --------------------------------------------------------------------------- #

@pytest.fixture(scope="module")
def client():
    from fastapi.testclient import TestClient

    from memdiver.api.main import create_app

    return TestClient(create_app())


def test_route_returns_the_producer_payload(client, tmp_path):
    """The route hands back the producer's dict verbatim."""
    rule, reference = emitted_rule(51)
    dump = write_dump(tmp_path / "web_a.dump", {_PLANT_OFFSET: reference})

    resp = client.post(_ROUTE, json={
        "dump_paths": [str(dump)], "rule_source": rule})

    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["verdict"] == YARA_MATCHED
    assert [m["offset"] for m in body["dumps"][0]["scan"]["matches"]] == [
        _PLANT_OFFSET]


def test_route_returns_200_for_a_clean_scan(client, tmp_path):
    """A measured absence is a RESULT, not an error, so the route must not turn
    it into a 4xx."""
    rule, _ = emitted_rule(52)
    dump = write_dump(tmp_path / "web_clean.dump", {})

    resp = client.post(_ROUTE, json={
        "dump_paths": [str(dump)], "rule_source": rule})

    assert resp.status_code == 200, resp.text
    assert resp.json()["verdict"] == YARA_CLEAN


def test_route_returns_200_and_a_typed_row_for_an_unreadable_dump(client, tmp_path):
    rule, _ = emitted_rule(53)
    directory = tmp_path / "web_dir"
    directory.mkdir()

    resp = client.post(_ROUTE, json={
        "dump_paths": [str(directory)], "rule_source": rule})

    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["verdict"] == YARA_NOT_SCANNED
    assert body["dumps"][0]["status"] == YARA_UNREADABLE
    assert body["dumps"][0]["scan"] is None


def test_route_rejects_both_rule_forms(client, tmp_path):
    """The exactly-one-of guard reaches the transport through the app's single
    global CapabilityError handler — there is no try/except in the route, and
    the body is ``{error, code, category}`` rather than FastAPI's ``detail``."""
    rule, _ = emitted_rule(54)
    rule_file = tmp_path / "web.yar"
    rule_file.write_text(rule)
    dump = write_dump(tmp_path / "web_both.dump", {})

    resp = client.post(_ROUTE, json={
        "dump_paths": [str(dump)],
        "rule_source": rule,
        "rule_paths": [str(rule_file)],
    })

    assert resp.status_code == 400, resp.text
    body = resp.json()
    assert body["category"] == "INVALID_INPUT"
    assert "exactly ONE" in body["error"]


def test_route_404s_a_missing_dump(client, tmp_path):
    rule, _ = emitted_rule(55)

    resp = client.post(_ROUTE, json={
        "dump_paths": [str(tmp_path / "web_nope.dump")], "rule_source": rule})

    assert resp.status_code == 404, resp.text
    body = resp.json()
    assert body["category"] == "NOT_FOUND"
    assert "web_nope.dump" in body["error"]


def test_route_lets_the_engine_own_the_non_positive_cap_refusal(client, tmp_path):
    """No ``Field(ge=1)`` on ``max_matches``, unlike ``LocateFieldPairsRequest``'s
    caps: the engine already has a coded error for it whose message names the
    ``None`` remedy, so pre-empting it with a 422 would answer in FastAPI's
    words where the other three surfaces answer in the engine's."""
    rule, _ = emitted_rule(56)
    dump = write_dump(tmp_path / "web_cap.dump", {})

    resp = client.post(_ROUTE, json={
        "dump_paths": [str(dump)], "rule_source": rule, "max_matches": 0})

    assert resp.status_code == 400, resp.text
    body = resp.json()
    assert body["code"] == "yara.bad_max_matches"
    assert "max_matches=None" in body["error"]


def test_route_accepts_a_null_max_matches_as_uncapped(client, tmp_path):
    """``None`` has to survive the wire, or the uncapped census is unreachable
    from the web surface."""
    rule, reference = emitted_rule(57)
    dump = write_dump(tmp_path / "web_uncapped.dump", _repeated(reference, 3))

    resp = client.post(_ROUTE, json={
        "dump_paths": [str(dump)], "rule_source": rule, "max_matches": None})

    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["caps"]["max_matches"] is None
    assert body["dumps"][0]["scan"]["match_count"] == 3
    assert body["dumps"][0]["scan"]["truncated"] is False


def test_route_advertises_the_engine_defaults(client, tmp_path):
    """The model's defaults are the imported constants, so the web surface
    cannot advertise a different cap or budget from the library's."""
    rule, _ = emitted_rule(58)
    dump = write_dump(tmp_path / "web_defaults.dump", {})

    resp = client.post(_ROUTE, json={
        "dump_paths": [str(dump)], "rule_source": rule})

    caps = resp.json()["caps"]
    assert caps["max_matches"] == DEFAULT_MAX_MATCHES
    assert caps["timeout_s"] == DEFAULT_TIMEOUT_S
    assert caps["overlap_bytes"] == 0


# --------------------------------------------------------------------------- #
# (g) the MCP surface
# --------------------------------------------------------------------------- #

@pytest.fixture(scope="module")
def mcp_tool():
    """The registered MCP tool's callable, funnel and all."""
    pytest.importorskip("mcp")
    from memdiver.mcp_server.server import create_server

    tools = {t.name: t for t in create_server()._tool_manager.list_tools()}
    assert "scan_yara_rule" in tools, sorted(tools)
    return tools["scan_yara_rule"].fn


def test_mcp_tool_returns_json_payload(mcp_tool, tmp_path):
    """A JSON STRING (the MCP transport contract) carrying the producer's dict."""
    rule, reference = emitted_rule(61)
    dump = write_dump(tmp_path / "mcp_a.dump", {_PLANT_OFFSET: reference})

    raw = mcp_tool(dump_paths=[str(dump)], rule_source=rule)

    assert isinstance(raw, str)
    payload = json.loads(raw)
    assert "error" not in payload, payload
    assert payload["verdict"] == YARA_MATCHED
    assert payload["counts"]["dumps_matched"] == 1


def test_mcp_tool_funnels_the_both_forms_error(mcp_tool, tmp_path):
    """A CapabilityError escaping the body is rendered as the structured
    ``{error, code, category}`` dict — an agent gets machine-readable text."""
    rule, _ = emitted_rule(62)
    rule_file = tmp_path / "mcp.yar"
    rule_file.write_text(rule)
    dump = write_dump(tmp_path / "mcp_both.dump", {})

    payload = json.loads(mcp_tool(
        dump_paths=[str(dump)],
        rule_source=rule,
        rule_paths=[str(rule_file)],
    ))

    assert payload["category"] == "INVALID_INPUT"
    assert "exactly ONE" in payload["error"]


def test_mcp_tool_funnels_not_found(mcp_tool, tmp_path):
    rule, _ = emitted_rule(63)

    payload = json.loads(mcp_tool(
        dump_paths=[str(tmp_path / "mcp_nope.dump")], rule_source=rule))

    assert payload["category"] == "NOT_FOUND"
    assert payload["error"].startswith("File not found:")


def test_mcp_tool_funnels_the_non_positive_cap(mcp_tool, tmp_path):
    rule, _ = emitted_rule(64)
    dump = write_dump(tmp_path / "mcp_cap.dump", {})

    payload = json.loads(mcp_tool(
        dump_paths=[str(dump)], rule_source=rule, max_matches=0))

    assert payload["code"] == "yara.bad_max_matches"


def test_mcp_and_web_return_byte_identical_payloads(mcp_tool, client, tmp_path):
    """Cross-surface parity, and the load-bearing test of this whole file.

    Both adapters dispatch through the ONE producer, so identical input must
    yield the identical payload — not merely a compatible one. Any future change
    that inlines the compile or the roll-up in one adapter fails here.

    ``elapsed_s`` is dropped from both sides before comparing: it is a wall-clock
    measurement, so it is the one key that MUST differ between two runs, and
    keeping it would make this assertion vacuous-by-failure rather than
    meaningful.
    """
    rule, reference = emitted_rule(65)
    dumps = [
        write_dump(tmp_path / "parity_hit.dump",
                   {_PLANT_OFFSET: reference}, seed=1),
        write_dump(tmp_path / "parity_miss.dump", {}, seed=2),
    ]
    request = {"dump_paths": [str(d) for d in dumps], "rule_source": rule}

    from_mcp = json.loads(mcp_tool(**request))
    resp = client.post(_ROUTE, json=request)

    assert resp.status_code == 200, resp.text
    from_web = resp.json()
    from_mcp.pop("elapsed_s")
    from_web.pop("elapsed_s")
    assert from_mcp == from_web
    # And the payload actually said something, so the equality above is not two
    # empty dicts agreeing.
    assert from_web["verdict"] == YARA_MATCHED
    assert from_web["counts"]["dumps_scanned"] == 2


# --------------------------------------------------------------------------- #
# (h) the CLI surface
# --------------------------------------------------------------------------- #

def _run_cli(argv, tmp_path):
    """Invoke the ``scan-yara`` handler and return ``(exit, payload)``."""
    from memdiver.cli import _cmd_scan_yara, build_parser

    out = tmp_path / f"cli_{abs(hash(tuple(argv))) % 10**8}.json"
    args = build_parser().parse_args(["scan-yara", *argv, "-o", str(out)])
    code = _cmd_scan_yara(args)
    return code, json.loads(out.read_text())


def test_cli_is_a_TOP_LEVEL_command_not_an_inspect_action():
    """``inspect`` is single-dump, session-first and ``ServiceResult``-shaped,
    none of which an N-dump scan can express — and its 13 handlers are pinned by
    an exact-set assertion. ``scan-yara`` follows the ``locate-field-pairs`` /
    ``inspect-pcap`` precedent instead."""
    from memdiver.cli import _INSPECT_HANDLERS, build_parser

    assert "scan_yara" not in _INSPECT_HANDLERS
    assert "yara" not in _INSPECT_HANDLERS
    args = build_parser().parse_args(
        ["scan-yara", "/a.dump", "--rule-source", "rule r { condition: true }"])
    assert args.command == "scan-yara"


def test_cli_exits_zero_on_matched(tmp_path, capsys):
    """Exit 0 = matched, and the verdict line plus every diagnostic go to STDERR
    so an operator piping the JSON onward still sees the qualifications."""
    rule, reference = emitted_rule(71)
    dump = write_dump(tmp_path / "cli_hit.dump", {_PLANT_OFFSET: reference})

    code, payload = _run_cli([str(dump), "--rule-source", rule], tmp_path)

    assert code == 0
    assert payload["verdict"] == YARA_MATCHED
    err = capsys.readouterr().err
    assert "verdict=matched" in err
    assert "rules=planted_pattern" in err


def test_cli_exits_three_on_a_proven_clean_scan(tmp_path):
    """Exit 3 is ``_CLI_EXIT[NOT_FOUND]``, reused rather than reinvented — and
    the full payload is still written, because a non-zero exit is a verdict."""
    rule, _ = emitted_rule(72)
    dump = write_dump(tmp_path / "cli_clean.dump", {})

    code, payload = _run_cli([str(dump), "--rule-source", rule], tmp_path)

    assert code == 3
    assert payload["verdict"] == YARA_CLEAN


def test_cli_exits_two_when_nothing_was_scanned(tmp_path):
    """Exit 2 is the caller-correctable code, which is what an all-unreadable
    set is: nothing was read, and the inputs need fixing."""
    rule, _ = emitted_rule(73)
    # A DIRECTORY named ``*.dump`` inside a run directory. ``_resolve_dump_paths``
    # expands the run directory by glob and passes the entry through, so the
    # producer is handed a path it cannot open — which is exactly the shape of
    # the real failure (a half-copied or permission-denied dump), reached without
    # depending on filesystem permissions.
    run = tmp_path / "cli_nothing"
    (run / "a.dump").mkdir(parents=True)

    code, payload = _run_cli([str(run), "--rule-source", rule], tmp_path)

    assert code == 2
    assert payload["verdict"] == YARA_NOT_SCANNED


def test_cli_exits_two_on_an_inconclusive_scan(tmp_path):
    """Exit 2, NOT 3: an unproven zero is precisely not an absence, and the fix
    is in the invocation (a bigger --timeout, a wider --overlap-bytes)."""
    rule, _ = emitted_rule(74, drop_length=True)
    msl = write_msl_fixture(tmp_path / "cli_capture.msl")

    code, payload = _run_cli([str(msl), "--rule-source", rule], tmp_path)

    assert code == 2
    assert payload["verdict"] == YARA_INCONCLUSIVE


def test_cli_reads_rules_from_repeatable_rule_file_flags(tmp_path):
    """The ordinary way to pass rules — a real rule set lives in a file."""
    rule_a, reference = emitted_rule(75, name="from_file_a")
    rule_b, _ = emitted_rule(76, name="from_file_b")
    (tmp_path / "a.yar").write_text(rule_a)
    (tmp_path / "b.yar").write_text(rule_b)
    dump = write_dump(tmp_path / "cli_files.dump", {_PLANT_OFFSET: reference})

    code, payload = _run_cli([
        str(dump),
        "--rule-file", str(tmp_path / "a.yar"),
        "--rule-file", str(tmp_path / "b.yar"),
    ], tmp_path)

    assert code == 0
    assert payload["intake"] == YARA_INTAKE_PATHS
    assert payload["rules"]["count"] == 2


def test_cli_no_max_matches_asks_for_the_uncapped_census(tmp_path):
    """A flag of its own rather than ``--max-matches 0``, because 0 is REFUSED:
    a cap arithmetic'd down to zero means stop."""
    rule, reference = emitted_rule(77)
    dump = write_dump(
        tmp_path / "cli_uncapped.dump", _repeated(reference, 3))

    code, payload = _run_cli(
        [str(dump), "--rule-source", rule, "--no-max-matches"], tmp_path)

    assert code == 0
    assert payload["caps"]["max_matches"] is None
    assert payload["dumps"][0]["scan"]["match_count"] == 3


def test_cli_leaves_the_both_forms_refusal_to_the_producer(tmp_path):
    """Deliberately NOT an argparse mutually-exclusive group: the producer owns
    the message so all four surfaces report the mistake in the same words."""
    rule, _ = emitted_rule(78)
    rule_file = tmp_path / "cli_both.yar"
    rule_file.write_text(rule)
    dump = write_dump(tmp_path / "cli_both.dump", {})
    from memdiver.cli import _cmd_scan_yara, build_parser

    args = build_parser().parse_args([
        "scan-yara", str(dump),
        "--rule-source", rule,
        "--rule-file", str(rule_file),
    ])
    with pytest.raises(CapabilityError) as excinfo:
        _cmd_scan_yara(args)

    assert excinfo.value.category is ErrorCategory.INVALID_INPUT
    assert "rule_source" in str(excinfo.value)


def test_cli_parser_defaults_are_the_imported_engine_constants():
    """A re-literalled default is how a surface starts advertising a cap the
    library does not apply."""
    from memdiver.cli import build_parser

    args = build_parser().parse_args(["scan-yara", "/a.dump"])
    assert args.max_matches == DEFAULT_MAX_MATCHES
    assert args.timeout == DEFAULT_TIMEOUT_S
    assert args.overlap_bytes == 0


# --------------------------------------------------------------------------- #
# (i) the four surfaces are ONE producer
# --------------------------------------------------------------------------- #

def test_the_library_surface_reaches_the_same_object():
    """``memdiver.scan_yara_rule`` / ``memdiver.services.scan_yara_rule`` are
    the SAME object as the app producer, not a wrapper that could drift."""
    import memdiver
    import memdiver.services as services
    from memdiver.app import tools_pipeline

    assert services.scan_yara_rule is tools_pipeline.scan_yara_rule
    assert memdiver.scan_yara_rule is tools_pipeline.scan_yara_rule
    assert "scan_yara_rule" in services.__all__
    assert "scan_yara_rule" in memdiver.__all__


def test_the_capability_claims_all_four_surfaces():
    """No ``KNOWN_PARITY_GAPS`` entry, and none possible: that baseline is
    shrink-only, so a capability that needed one could never be added."""
    from memdiver.app.capabilities import (
        CAPABILITIES,
        IN_SCOPE_SURFACES,
        KNOWN_PARITY_GAPS,
    )

    cap = next(c for c in CAPABILITIES if c.name == "analysis.yara_scan")
    assert cap.producer == "memdiver.app.tools_pipeline.scan_yara_rule"
    assert IN_SCOPE_SURFACES <= cap.surfaces
    assert not any(name == "analysis.yara_scan" for name, _ in KNOWN_PARITY_GAPS)


def test_cli_and_library_agree_on_the_same_dumps(tmp_path):
    """The last of the four pairings: the CLI handler adds presentation and an
    exit code on top of the producer's payload, and changes nothing else."""
    rule, reference = emitted_rule(81)
    dumps = [
        write_dump(tmp_path / "both_hit.dump", {_PLANT_OFFSET: reference}, seed=1),
        write_dump(tmp_path / "both_miss.dump", {}, seed=2),
    ]
    paths = [str(d) for d in dumps]

    code, from_cli = _run_cli([*paths, "--rule-source", rule], tmp_path)
    from_lib = scan_yara_rule(dump_paths=paths, rule_source=rule)

    assert code == 0
    from_cli.pop("elapsed_s")
    from_lib.pop("elapsed_s")
    assert from_cli == from_lib


# --------------------------------------------------------------------------- #
# (j) the COUNT-ONLY census — bounding the PAYLOAD, which max_matches never did
# --------------------------------------------------------------------------- #
#
# The measurement that forced this section: ``scan-yara`` over the reference
# corpus's 8 dumps with the default 64-byte pad rule and ``--no-max-matches``
# wrote a 4.0 GB JSON file. 6,621,373 matches, each carrying a ``matched_hex``
# of up to 512 bytes (352+ hex characters), and 825,779 of them in a single
# 11 MB dump. ``max_matches`` bounds how many matches are HELD, so it bounds
# memory — it has never bounded the per-match serialized cost, and capping it
# is also the wrong answer to "how selective is this rule?", whose answer is a
# number rather than 6.6 million records.
#
# What the tests below pin, in order: that the default form did not move a byte;
# that the count-only form keeps every count and flag and reaches the identical
# verdict; that its ``matches`` key is ABSENT rather than empty; that a
# count-only run under a cap still says its total is a floor; that all four
# surfaces take the parameter; and that MCP and web stay byte-identical in the
# new form too.


def _many_matches(tmp_path: Path, seed: int, *, count: int = 6):
    """A dump with *count* copies of one emitted rule's window planted in it."""
    rule, reference = emitted_rule(seed)
    dump = write_dump(tmp_path / f"count_{seed}.dump", _repeated(reference, count))
    return rule, str(dump), count


def test_the_default_is_include_matches_and_it_is_the_old_payload(tmp_path):
    """The regression pin: passing ``include_matches`` explicitly at its default
    must produce the SAME payload as not passing it at all — values, not merely
    keys. A new parameter whose default perturbs the payload is a silent
    breaking change to three surfaces and a library API at once.

    ``elapsed_s`` is the one key that must differ between two runs (it is a
    wall-clock measurement), so it is dropped from both sides for the reason
    :func:`test_mcp_and_web_return_byte_identical_payloads` drops it.
    """
    assert DEFAULT_INCLUDE_MATCHES is True
    rule, dump, count = _many_matches(tmp_path, 91)

    implicit = scan_yara_rule(dump_paths=[dump], rule_source=rule)
    explicit = scan_yara_rule(
        dump_paths=[dump], rule_source=rule,
        include_matches=DEFAULT_INCLUDE_MATCHES)

    implicit.pop("elapsed_s")
    explicit.pop("elapsed_s")
    assert implicit == explicit
    # And the payload said something, so the equality is not two empty dicts
    # agreeing: the full form carries the match LIST, in full.
    assert implicit["verdict"] == YARA_MATCHED
    assert len(implicit["dumps"][0]["scan"]["matches"]) == count
    assert "matches_omitted" not in implicit["dumps"][0]["scan"]
    # No new key on the default payload either — not in caps, not at top level.
    assert "include_matches" not in implicit["caps"]
    assert set(implicit["caps"]) == {"max_matches", "timeout_s", "overlap_bytes"}
    assert YARA_SCAN_COUNT_ONLY_CODE not in [
        d["code"] for d in implicit["diagnostics"]]


def test_count_only_keeps_every_count_and_flag_and_drops_only_the_lists(tmp_path):
    """The capability itself. Everything a selectivity question needs survives;
    the 6.6-million-record list is what goes."""
    rule, dump, count = _many_matches(tmp_path, 92)

    full = scan_yara_rule(
        dump_paths=[dump], rule_source=rule, max_matches=None)
    counted = scan_yara_rule(
        dump_paths=[dump], rule_source=rule, max_matches=None,
        include_matches=False)

    full_scan = full["dumps"][0]["scan"]
    counted_scan = counted["dumps"][0]["scan"]
    # Every COUNT and every flag, byte-for-byte the full form's.
    for key in ("match_count", "truncated", "timed_out", "errors",
                "scanned_bytes", "chunks", "strategy", "view", "rule_names",
                "dump_path"):
        assert counted_scan[key] == full_scan[key], key
    assert counted_scan["match_count"] == count
    # The roll-up reads counts, never the lists, so it cannot move.
    assert counted["counts"] == full["counts"]
    assert counted["counts"]["matches_total"] == count
    assert counted["verdict"] == full["verdict"] == YARA_MATCHED
    assert counted["caps"] == full["caps"]
    assert counted["rules"] == full["rules"]
    # And the only difference is the list.
    assert set(full_scan) - set(counted_scan) == {"matches"}
    assert set(counted_scan) - set(full_scan) == {"matches_omitted"}


def test_count_only_omits_the_matches_key_rather_than_emptying_it(tmp_path):
    """ABSENT, never ``[]``. This is the load-bearing assertion of the section:
    an empty list would make a count-only row with hundreds of thousands of
    hits indistinguishable from a proven-clean one to any caller that checks
    ``len(scan["matches"])`` — the same silent false absence the ``scan: None``
    nesting exists to prevent. A ``KeyError`` is a question; ``[]`` is a
    confident wrong answer."""
    rule, dump, count = _many_matches(tmp_path, 93)

    payload = scan_yara_rule(
        dump_paths=[dump], rule_source=rule, max_matches=None,
        include_matches=False)

    scan = payload["dumps"][0]["scan"]
    assert "matches" not in scan
    assert scan.get("matches") is None  # not [] — nothing to misread as empty
    assert scan["matches_omitted"] is True
    # The count is still there and still non-zero, which is the whole point:
    # the row is loud about having found things it is not listing.
    assert scan["match_count"] == count


def test_count_only_is_MUCH_smaller_on_the_wire_than_the_full_form(tmp_path):
    """The size claim, measured on a synthetic planted dump rather than by
    re-scanning the corpus (``tests/test_detector_loop_corpus.py`` already pays
    ~21 s for the real pad-64 sweep, and this shape is what that sweep's 4.0 GB
    is made of).

    Each omitted match costs 300+ JSON bytes, dominated by ``matched_hex``, so
    the count-only payload's size is independent of the match count while the
    full form's grows linearly with it. Asserting the RATIO rather than an
    absolute byte count keeps this honest if a field is ever added elsewhere.
    """
    rule, dump, count = _many_matches(tmp_path, 94, count=40)

    full = json.dumps(scan_yara_rule(
        dump_paths=[dump], rule_source=rule, max_matches=None))
    counted = json.dumps(scan_yara_rule(
        dump_paths=[dump], rule_source=rule, max_matches=None,
        include_matches=False))

    assert len(counted) < len(full)
    # 40 matches already halve it; the corpus run has 6.6 million.
    assert len(full) > 2 * len(counted), (len(full), len(counted))
    # The count survived the shrink — a small payload that lost the answer
    # would pass a size assertion and fail the caller.
    assert json.loads(counted)["counts"]["matches_total"] == count


def test_count_only_ALWAYS_carries_its_diagnostic(tmp_path):
    """Emitted whatever the verdict, because the omission is a property of the
    ANSWER: a reader handed a row with no ``matches`` key must not have to
    wonder whether the payload was requested that way or truncated."""
    rule, _ = emitted_rule(95)
    clean_dump = write_dump(tmp_path / "count_clean.dump", {})

    payload = scan_yara_rule(
        dump_paths=[str(clean_dump)], rule_source=rule, max_matches=None,
        include_matches=False)

    assert payload["verdict"] == YARA_CLEAN
    diagnostic = next(d for d in payload["diagnostics"]
                      if d["code"] == YARA_SCAN_COUNT_ONLY_CODE)
    # Uncapped: the census is honest, and the diagnostic says so rather than
    # leaving a cautious reader to discount a real number.
    assert diagnostic["details"]["matches_total_is_floor"] is False
    assert diagnostic["details"]["max_matches"] is None
    assert "uncapped" in diagnostic["message"]
    assert diagnostic["severity"] == "info"
    # And it says what count-only does NOT do, because "smaller output" is
    # routinely misread as "faster scan".
    assert "libyara still finds every match" in diagnostic["message"]


def test_count_only_UNDER_A_CAP_still_says_the_total_is_a_floor(tmp_path):
    """The interaction decision, pinned. ``include_matches`` and ``max_matches``
    are ORTHOGONAL — asking for counts does not silently uncap a scan the caller
    sized on purpose — so a count-only run under a cap reports a floor, and it
    must say so twice as loudly as the full form does: there is not even a match
    list whose length betrays the cap."""
    rule, dump, count = _many_matches(tmp_path, 96)
    assert count > 2

    payload = scan_yara_rule(
        dump_paths=[dump], rule_source=rule, max_matches=2,
        include_matches=False)

    scan = payload["dumps"][0]["scan"]
    # The cap still bit: count-only changed nothing about the scan.
    assert scan["match_count"] == 2
    assert scan["truncated"] is True
    assert payload["caps"]["max_matches"] == 2
    assert payload["counts"]["matches_total"] == 2  # a FLOOR, not the 6 there
    codes = [d["code"] for d in payload["diagnostics"]]
    # BOTH diagnostics: the pre-existing truncation warning and the count-only
    # one, which is the one that names the remedy for this combination.
    assert YARA_SCAN_TRUNCATED_CODE in codes
    diagnostic = next(d for d in payload["diagnostics"]
                      if d["code"] == YARA_SCAN_COUNT_ONLY_CODE)
    assert diagnostic["severity"] == "warning"
    assert diagnostic["details"]["matches_total_is_floor"] is True
    assert diagnostic["details"]["max_matches"] == 2
    assert "FLOOR" in diagnostic["message"]
    assert "--no-max-matches" in diagnostic["message"]


def test_count_only_does_not_change_a_degraded_verdict(tmp_path):
    """The four-valued verdict is computed from counts and flags, none of which
    count-only touches, so an inconclusive result stays inconclusive rather
    than becoming a clean-looking small payload."""
    rule, _ = emitted_rule(97)
    empty = write_dump(tmp_path / "count_empty.dump", {}, size=0)

    payload = scan_yara_rule(
        dump_paths=[str(empty)], rule_source=rule, include_matches=False)

    assert payload["verdict"] == YARA_INCONCLUSIVE
    assert payload["counts"]["dumps_zero_bytes"] == 1
    codes = [d["code"] for d in payload["diagnostics"]]
    assert YARA_SCAN_ZERO_BYTES_CODE in codes
    assert YARA_SCAN_COUNT_ONLY_CODE in codes


def test_count_only_leaves_an_unreadable_row_exactly_as_it_was(tmp_path):
    """An unreadable row has no ``scan`` to shape, so ``matches_omitted`` must
    not appear on it — ``scan: None`` is still the whole story there."""
    rule, reference = emitted_rule(98)
    good = write_dump(tmp_path / "count_good.dump", {_PLANT_OFFSET: reference})
    missing_dir = tmp_path / "count_dir"
    missing_dir.mkdir()

    payload = scan_yara_rule(
        dump_paths=[str(good), str(missing_dir)], rule_source=rule,
        include_matches=False)

    assert payload["dumps"][1]["status"] == YARA_UNREADABLE
    assert payload["dumps"][1]["scan"] is None
    assert payload["dumps"][0]["scan"]["matches_omitted"] is True


def test_route_accepts_include_matches_false(client, tmp_path):
    """The web surface, whose response IS the payload: a 4 GB body is not a
    response, it is an outage."""
    rule, dump, count = _many_matches(tmp_path, 99)

    resp = client.post(_ROUTE, json={
        "dump_paths": [dump], "rule_source": rule,
        "max_matches": None, "include_matches": False})

    assert resp.status_code == 200, resp.text
    body = resp.json()
    scan = body["dumps"][0]["scan"]
    assert "matches" not in scan
    assert scan["matches_omitted"] is True
    assert scan["match_count"] == count
    assert body["counts"]["matches_total"] == count
    assert body["verdict"] == YARA_MATCHED


def test_route_defaults_include_matches_to_the_producer_constant(client, tmp_path):
    """Omitting the field must keep the historical body, so no existing client
    changes shape under it."""
    rule, dump, count = _many_matches(tmp_path, 100)

    resp = client.post(_ROUTE, json={
        "dump_paths": [dump], "rule_source": rule, "max_matches": None})

    scan = resp.json()["dumps"][0]["scan"]
    assert len(scan["matches"]) == count
    assert "matches_omitted" not in scan


def test_mcp_tool_accepts_include_matches_false(mcp_tool, tmp_path):
    """The surface with the sharpest need for it: a tool result is one JSON
    string an agent has to hold in its context."""
    rule, dump, count = _many_matches(tmp_path, 101)

    payload = json.loads(mcp_tool(
        dump_paths=[dump], rule_source=rule, max_matches=None,
        include_matches=False))

    scan = payload["dumps"][0]["scan"]
    assert "matches" not in scan
    assert scan["match_count"] == count
    assert payload["counts"]["matches_total"] == count


def test_mcp_and_web_stay_byte_identical_in_the_count_only_form(
        mcp_tool, client, tmp_path):
    """The cross-surface invariant, re-asserted in the new shape. Adding a
    parameter to one adapter and not the other is exactly how the two drift,
    and this is where that would show."""
    rule, reference = emitted_rule(102)
    dumps = [
        write_dump(tmp_path / "count_parity_hit.dump",
                   _repeated(reference, 3), seed=1),
        write_dump(tmp_path / "count_parity_miss.dump", {}, seed=2),
    ]
    request = {
        "dump_paths": [str(d) for d in dumps],
        "rule_source": rule,
        "max_matches": None,
        "include_matches": False,
    }

    from_mcp = json.loads(mcp_tool(**request))
    resp = client.post(_ROUTE, json=request)

    assert resp.status_code == 200, resp.text
    from_web = resp.json()
    from_mcp.pop("elapsed_s")
    from_web.pop("elapsed_s")
    assert from_mcp == from_web
    # And it said something: a hit row with counts but no list, plus a miss.
    assert from_web["verdict"] == YARA_MATCHED
    assert from_web["dumps"][0]["scan"]["match_count"] == 3
    assert "matches" not in from_web["dumps"][0]["scan"]
    assert from_web["counts"]["dumps_scanned"] == 2


def test_cli_count_only_flag_asks_for_the_counts_without_the_lists(tmp_path):
    """``--count-only``, combined with ``--no-max-matches``: the invocation the
    4.0 GB measurement was taken with, and the one it exists to make usable."""
    rule, reference = emitted_rule(103)
    dump = write_dump(tmp_path / "cli_count.dump", _repeated(reference, 3))

    code, payload = _run_cli(
        [str(dump), "--rule-source", rule, "--no-max-matches",
         "--count-only"],
        tmp_path)

    assert code == 0
    assert payload["caps"]["max_matches"] is None
    scan = payload["dumps"][0]["scan"]
    assert "matches" not in scan
    assert scan["matches_omitted"] is True
    assert scan["match_count"] == 3
    # The verdict line the handler prints reads only from ``counts``, which
    # count-only keeps in full, so the operator's summary is unchanged.
    assert payload["counts"]["matches_total"] == 3


def test_cli_count_only_defaults_to_the_full_payload(tmp_path):
    """The flag's default is the NEGATION of the producer's constant, never a
    re-literalled ``False``: that is how a surface starts advertising a shape
    the library does not produce."""
    from memdiver.cli import build_parser

    args = build_parser().parse_args(["scan-yara", "/a.dump"])
    assert args.count_only is not DEFAULT_INCLUDE_MATCHES
    assert args.count_only is False


def test_cli_and_library_agree_in_the_count_only_form(tmp_path):
    """The fourth pairing again, in the new shape."""
    rule, reference = emitted_rule(104)
    dumps = [
        write_dump(tmp_path / "count_both_hit.dump",
                   _repeated(reference, 2), seed=1),
        write_dump(tmp_path / "count_both_miss.dump", {}, seed=2),
    ]
    paths = [str(d) for d in dumps]

    code, from_cli = _run_cli(
        [*paths, "--rule-source", rule, "--count-only"], tmp_path)
    from_lib = scan_yara_rule(
        dump_paths=paths, rule_source=rule, include_matches=False)

    assert code == 0
    from_cli.pop("elapsed_s")
    from_lib.pop("elapsed_s")
    assert from_cli == from_lib


def test_the_library_surface_takes_include_matches_too(tmp_path):
    """``memdiver.scan_yara_rule`` is the same object, so this cannot drift —
    but the fourth surface is a surface, and the parameter is pinned on it."""
    import inspect

    import memdiver

    params = inspect.signature(memdiver.scan_yara_rule).parameters
    assert "include_matches" in params
    assert params["include_matches"].default is DEFAULT_INCLUDE_MATCHES
