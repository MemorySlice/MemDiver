"""libyara silently matches NOTHING above its regexp verification limit.

The defect, in one sentence: a hex string containing ``??`` compiles to a
regexp, libyara verifies a regexp outward from one chosen atom with each
direction clamped to the compile-time constant ``YR_RE_SCAN_LIMIT``, and past
that clamp it reports **no match** -- with no error, no warning and no
diagnostic -- for a pattern that is present in the data byte for byte.

Measured on this machine, on a pattern planted verbatim in the buffer::

    pattern  1000 bytes -> matches: 1
    pattern  1024 bytes -> matches: 1
    pattern  1056 bytes -> matches: 0
    pattern  2048 bytes -> matches: 0
    pattern  4096 bytes -> matches: 0

``YR_RE_SCAN_LIMIT`` regressed 4096 -> 1024 in yara-python 4.5.3/4.5.4
(upstream PR #2144). **No dependency bump can fix this**: 4.5.4 is the newest
wheel published on PyPI and the upstream revert is unreleased, so there is no
4.5.5 to floor ``pyproject.toml`` against. ``yara.set_config`` exposes
``stack_size`` / ``max_strings_per_rule`` / ``max_match_data`` and NOT the
scan limit, and a compiled ``Rule`` exposes ``identifier`` / ``tags`` /
``meta`` and NOT its strings -- so the limit can be neither raised nor
introspected, only measured. Hence the probe.

Why this file exists rather than a constant somewhere. Two consequences of the
limit are real and both are false all-clears:

* At the default ``--context 64`` an emitted key pattern is 176 bytes and safe.
  At ``--context 512`` it is 1072 bytes and **dead** -- so an analyst raising
  the context to make a rule MORE selective silently gets one that matches
  nothing, including in the dump the bytes were read from.
* ``scan_yara_rule`` then reported ``verdict: "clean"``, which is the one
  verdict it is not entitled to. Same class as the zero-byte row and the
  ``matches: []``-vs-removed distinction that the four-valued verdict already
  closes.

``tests/test_degenerate_anchor_calibration.py`` characterises 7 pad-512 corpus
cells against the real dataset and is the empirical half of this story; this
file is the synthetic half, so the guard is exercised on every machine rather
than only where the corpus is mounted.

``import yara`` is a hard import for the reason
``tests/test_yara_scan_surfaces.py`` gives: yara-python is a declared BASE
dependency, so its absence is a broken environment and must fail loudly.
"""

from __future__ import annotations

import logging
import random
from pathlib import Path

import pytest
import yara

from memdiver.app.tools_pipeline import (
    PATTERN_OVER_SCAN_LIMIT_CODE,
    YARA_SCAN_OVER_SCAN_LIMIT_CODE,
    YARA_SCAN_WIDTH_UNKNOWN_CODE,
    _scan_limit_diagnostic,
    scan_yara_rule,
)
from memdiver.architect.pattern_generator import PatternGenerator
from memdiver.architect.yara_exporter import YaraExporter
from memdiver.core.variance import CHUNK_BYTES
from memdiver.engine import yara_scan as engine
from memdiver.engine.yara_scan import (
    DEFAULT_OVERLAP_BYTES,
    clear_rule_cache,
    clear_scan_limit_cache,
    compile_rules,
    measure_hex_string_widths,
    pattern_exceeds_scan_limit,
    regexp_scan_limit,
)

from tests.test_yara_scan_surfaces import write_dump

#: Room on either side of a 1 KiB-plus pattern inside the dump.
_DUMP_SIZE = 65536


@pytest.fixture(autouse=True)
def _fresh_caches():
    """Both caches cleared around every test.

    The rule cache is content-addressed, so one test's compile can satisfy
    another's and hide a compile-path regression (see
    ``tests/test_yara_scan_surfaces.py::_fresh_rule_cache``). The scan-limit
    memo matters for the opposite reason: several tests below monkeypatch the
    probe, and a value left cached would leak a fake limit into the next test.
    """
    clear_rule_cache()
    clear_scan_limit_cache()
    yield
    clear_rule_cache()
    clear_scan_limit_cache()


# --------------------------------------------------------------------------- #
# Fixtures: patterns of a chosen WIDTH, built by the real emitter
# --------------------------------------------------------------------------- #

def _window(total: int, *, key_len: int = 48, seed: int = 11):
    """A ``total``-byte window with a volatile ``key_len`` run in the middle.

    Deliberately the same shape ``export_key_pattern`` produces -- context,
    then the key span the mask wildcards, then context -- so ``total`` stands
    in for ``2 * context + key_length`` without needing a corpus. The first and
    last bytes stay static so the emitted hex string neither begins nor ends
    with a wildcard.
    """
    rng = random.Random(seed)
    reference = bytes(rng.randrange(256) for _ in range(total))
    key_at = (total - key_len) // 2
    mask = [True] * total
    for i in range(key_at, key_at + key_len):
        mask[i] = False
    return reference, mask, key_at, key_len


def _emit(total: int, *, name: str = "planted", drop_length: bool = False):
    """``PatternGenerator`` -> ``YaraExporter``, never hand-written rule text.

    The claim this file makes is about the PRODUCT's own output being
    scannable, so the rule has to come off the real emitter chain; a
    hand-rolled hex string would only prove that libyara works.

    ``drop_length`` removes the pattern dict's ``length`` before export, which
    is the emitter's documented route to a rule carrying no ``pattern_length``
    meta (``yara_exporter`` omits the meta rather than emit a false ``0``) --
    i.e. what a third-party ``.yar`` looks like to the producer.
    """
    reference, mask, key_at, key_len = _window(total)
    pattern = PatternGenerator.generate(reference, mask, name=name)
    assert pattern is not None, "pattern generator rejected the fixture mask"
    if drop_length:
        pattern = {k: v for k, v in pattern.items() if k != "length"}
    rule = YaraExporter.export(pattern, key_offset=key_at, key_length=key_len)
    return rule, reference, pattern


def _over_limit_width() -> int:
    """A width safely past the probed limit, rounded to the emitter's shape."""
    limit = regexp_scan_limit()
    assert limit is not None
    return limit + 48  # 1072 on this machine: exactly the --context 512 width


# --------------------------------------------------------------------------- #
# The probe
# --------------------------------------------------------------------------- #

def test_the_probe_returns_a_sane_limit():
    """A positive power of two inside the bracket it searched."""
    limit = regexp_scan_limit()
    assert limit is not None, (
        "yara-python is installed, so the limit must be measurable")
    assert engine._PROBE_MIN_BYTES <= limit <= engine._PROBE_MAX_BYTES
    # ``YR_RE_SCAN_LIMIT`` has only ever been a power of two, and the probe
    # floors to one deliberately (right above the true limit libyara is flaky
    # rather than cleanly monotone, so a bisect can land a few bytes high).
    assert limit & (limit - 1) == 0, f"{limit} is not a power of two"


def test_the_probe_agrees_with_a_direct_measurement_of_the_cliff():
    """Independent of MemDiver: ask libyara, twice, and bracket the answer.

    This is the assertion that keeps the probe honest. It does not trust
    ``regexp_scan_limit``'s search at all -- it plants a pattern AT the
    reported limit and one at twice the limit and checks that libyara finds the
    first and misses the second. If the probe ever drifts from what libyara
    actually does, this fails.
    """
    limit = regexp_scan_limit()
    assert limit is not None

    def matches_at(width: int) -> int:
        rng = random.Random(4242 ^ width)
        body = bytes(rng.randrange(256) for _ in range(width))
        tokens = ["%02x" % b for b in body]
        tokens[width // 2] = "??"  # makes it a regexp rather than a literal
        rule = yara.compile(
            source="rule probe { strings: $a = { %s } condition: $a }"
                   % " ".join(tokens))
        return len(rule.match(data=bytes(64) + body + bytes(64)))

    assert matches_at(limit) == 1, (
        f"a {limit}-byte pattern planted verbatim must match")
    assert matches_at(limit * 2) == 0, (
        f"a {limit * 2}-byte pattern must be past the verification limit")


def test_the_probe_is_lazy_and_memoized():
    """Probed at most once per process, and never at import.

    The probe costs a few dozen small ``yara.compile`` calls. That is nothing
    once and is not something to spend in every process that merely imports the
    module, whether or not a rule is ever scanned.
    """
    clear_scan_limit_cache()
    calls = []
    real = engine._probe_regexp_scan_limit

    def counting():
        calls.append(1)
        return real()

    engine._probe_regexp_scan_limit = counting  # type: ignore[assignment]
    try:
        first = regexp_scan_limit()
        second = regexp_scan_limit()
        third = regexp_scan_limit()
    finally:
        engine._probe_regexp_scan_limit = real  # type: ignore[assignment]
    assert first == second == third
    assert len(calls) == 1, f"probed {len(calls)} times, expected 1"


def test_an_unknown_limit_never_reads_as_a_clean_bill_of_health():
    """``None`` from the probe means "unknown", and unknown accuses nothing.

    ``pattern_exceeds_scan_limit`` must not fire on an unmeasurable limit -- a
    warning nobody can substantiate is worse than none. The callers that must
    not conclude "fine" from an unknown say so with their OWN diagnostic; see
    :func:`test_an_unmeasurable_rule_width_is_reported_not_assumed_fine`.
    """
    clear_scan_limit_cache()
    engine._SCAN_LIMIT_PROBED = True
    engine._SCAN_LIMIT = None
    try:
        assert regexp_scan_limit() is None
        assert pattern_exceeds_scan_limit(1 << 20) is False
    finally:
        clear_scan_limit_cache()


def test_a_pattern_at_or_under_the_limit_is_not_flagged():
    limit = regexp_scan_limit()
    assert limit is not None
    assert pattern_exceeds_scan_limit(176) is False       # --context 64
    assert pattern_exceeds_scan_limit(limit) is False     # exactly at it
    assert pattern_exceeds_scan_limit(limit + 1) is True
    assert pattern_exceeds_scan_limit(None) is False      # unknown width


# --------------------------------------------------------------------------- #
# Measuring a rule's patterns off its own source text
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("source,expected", [
    # The emitted shape: a flat run of hex pairs and wildcards.
    ('rule r { strings: $k = { 41 ?? 42 43 } condition: $k }', ((4,), 0)),
    # No wildcard -> a LITERAL, to which the regexp limit does not apply, so it
    # is neither measured nor counted as unmeasured.
    ('rule r { strings: $k = { 41 42 43 } condition: $k }', ((), 0)),
    # Nibble wildcards make it a regexp just as ?? does.
    ('rule r { strings: $k = { 4? 42 } condition: $k }', ((2,), 0)),
    # Variable-width or non-flat syntax: declined, and SAID to be declined.
    ('rule r { strings: $k = { 41 ?? [4-6] 42 } condition: $k }', ((), 1)),
    ('rule r { strings: $k = { 41 ?? ( 42 | 43 ) } condition: $k }', ((), 1)),
    # A text string is quote-delimited; its braces must not be mistaken for a
    # hex block.
    ('rule r { strings: $k = "hello {world}" condition: $k }', ((), 0)),
    # A commented-out block is not a live string.
    ('rule r { strings: /* $a = { 41 ?? 42 } */ $b = { 41 ?? } condition: $b }',
     ((2,), 0)),
    # Widest wins; both are reported.
    ('rule r { strings: $a = { 41 ?? 42 } $b = { 41 ?? 42 43 44 } '
     'condition: any of them }', ((3, 5), 0)),
])
def test_hex_string_widths_are_measured_conservatively(source, expected):
    """Measured for the shapes it understands, DECLINED (not guessed) otherwise.

    A wrong width here would produce exactly the confident-wrong answer the
    whole mechanism exists to replace, so anything carrying a jump, alternation
    or negation is counted as unmeasured rather than parsed with a half-right
    grammar whose mistakes would be invisible.
    """
    assert measure_hex_string_widths(source) == expected


def test_the_emitters_own_output_is_measurable():
    """The measurement agrees with the emitter's own ``pattern_length`` meta.

    Two independent routes to the same number: without this, a drift in either
    the emitter's meta or the text measurement would go unnoticed.
    """
    width = _over_limit_width()
    rule, _, pattern = _emit(width)
    assert pattern["length"] == width
    measured, unmeasured = measure_hex_string_widths(rule)
    assert unmeasured == 0
    assert measured == (width,)


# --------------------------------------------------------------------------- #
# Scan time: never "clean" when the rule cannot match
# --------------------------------------------------------------------------- #

def test_an_over_limit_rule_is_inconclusive_and_never_clean(tmp_path):
    """THE regression test. Fails before the fix with ``verdict == "clean"``.

    The bytes are planted VERBATIM at a known offset, so a miss is libyara's
    and not the fixture's. Before the fix this scan returned a confident
    ``clean`` over a fully-scanned dump with no timeout, no read error and no
    diagnostic -- the worst shape of the bug, because every coverage signal
    reads perfect while the recall is structurally zero.
    """
    width = _over_limit_width()
    rule, reference, _ = _emit(width)
    dump = write_dump(tmp_path / "planted.bin", {4096: reference},
                      size=_DUMP_SIZE)

    result = scan_yara_rule(dump_paths=[str(dump)], rule_source=rule)

    # The premise: libyara really does miss it, so this test is about a real
    # miss rather than a fixture that never contained the bytes.
    assert result["counts"]["matches_total"] == 0
    assert Path(dump).read_bytes()[4096:4096 + width] == reference

    # The fix.
    assert result["verdict"] == "inconclusive", (
        "a rule libyara cannot verify must never be reported clean")
    assert result["counts"]["dumps_clean"] == 0
    assert result["counts"]["dumps_inconclusive"] == 1
    # ...and for a NAMED reason, not by accident: none of the pre-existing
    # degraded channels fired here.
    assert result["counts"]["dumps_timed_out"] == 0
    assert result["counts"]["dumps_with_errors"] == 0
    assert result["counts"]["dumps_zero_bytes"] == 0

    codes = [d["code"] for d in result["diagnostics"]]
    assert YARA_SCAN_OVER_SCAN_LIMIT_CODE in codes
    diagnostic = next(d for d in result["diagnostics"]
                      if d["code"] == YARA_SCAN_OVER_SCAN_LIMIT_CODE)
    assert diagnostic["severity"] == "warning"
    assert diagnostic["details"]["widest_pattern_length"] == width
    assert diagnostic["details"]["scan_limit"] == regexp_scan_limit()

    assert result["rules"]["exceeds_scan_limit"] is True
    assert result["rules"]["widest_pattern_length"] == width
    assert result["rules"]["scan_limit"] == regexp_scan_limit()


def test_the_generic_inconclusive_message_does_not_claim_a_timeout(tmp_path):
    """The over-limit reason replaces the degraded-channel census, not adds to it.

    The pre-existing ``inconclusive`` diagnostic enumerates "N timed out, N
    reported read/overlap errors, N scanned ZERO bytes". With an over-limit
    rule every one of those is 0, and printing that sentence would send the
    reader to raise ``timeout_s`` for a problem no timeout caused.
    """
    rule, reference, _ = _emit(_over_limit_width())
    dump = write_dump(tmp_path / "planted.bin", {4096: reference},
                      size=_DUMP_SIZE)
    result = scan_yara_rule(dump_paths=[str(dump)], rule_source=rule)
    codes = [d["code"] for d in result["diagnostics"]]
    assert YARA_SCAN_OVER_SCAN_LIMIT_CODE in codes
    assert "analysis.yara_scan.inconclusive" not in codes


def test_a_pattern_under_the_limit_is_completely_unaffected(tmp_path):
    """The default ``--context 64`` shape: byte-identical payload, no new noise.

    This adds detection and honesty, not behaviour. A 176-byte pattern -- what
    the unchanged default emits -- must match exactly as it always did, produce
    the same ``matched`` verdict, and gain no diagnostic.
    """
    rule, reference, pattern = _emit(176)
    assert pattern["length"] == 176
    dump = write_dump(tmp_path / "planted.bin", {4096: reference},
                      size=_DUMP_SIZE)

    result = scan_yara_rule(dump_paths=[str(dump)], rule_source=rule)

    assert result["verdict"] == "matched"
    assert result["counts"]["matches_total"] >= 1
    assert result["counts"]["dumps_inconclusive"] == 0
    assert result["rules"]["exceeds_scan_limit"] is False
    assert result["rules"]["pattern_width_unknown"] is False

    codes = [d["code"] for d in result["diagnostics"]]
    assert YARA_SCAN_OVER_SCAN_LIMIT_CODE not in codes
    assert YARA_SCAN_WIDTH_UNKNOWN_CODE not in codes

    # The matched window is byte-identical to what was planted, at the offset
    # it was planted at -- the payload the caller has always received.
    row = result["dumps"][0]["scan"]
    assert row["matches"][0]["offset"] == 4096
    assert row["matches"][0]["length"] == 176
    assert row["timed_out"] is False
    assert row["errors"] == []


def test_a_matching_rule_in_a_mixed_set_keeps_its_hits(tmp_path):
    """``widest_pattern_length`` is a MAXIMUM, so hits stay real.

    One over-limit pattern and one usable one in the same rule set: the usable
    one's matches are facts and must survive. Only the ZEROS are in doubt, so
    the verdict stays ``matched`` while the diagnostic still warns that part of
    the set cannot fire.
    """
    dead_rule, dead_ref, _ = _emit(_over_limit_width(), name="dead")
    live_rule, live_ref, _ = _emit(176, name="live")
    dump = write_dump(tmp_path / "planted.bin",
                      {4096: dead_ref, 32768: live_ref}, size=_DUMP_SIZE)

    result = scan_yara_rule(dump_paths=[str(dump)],
                            rule_source=dead_rule + "\n" + live_rule)

    assert result["verdict"] == "matched"
    assert result["counts"]["matches_total"] >= 1
    # The live rule is the one that fired; the dead one contributed nothing.
    fired = {m["rule"] for m in result["dumps"][0]["scan"]["matches"]}
    assert fired == {"live"}
    # ...and the reader is still told half the set is unverifiable.
    assert result["rules"]["exceeds_scan_limit"] is True
    assert YARA_SCAN_OVER_SCAN_LIMIT_CODE in [
        d["code"] for d in result["diagnostics"]]


def test_a_pure_literal_over_the_limit_is_exempt_and_still_matches(tmp_path):
    """The limit applies to REGEXPS, and a wildcard-free hex string is not one.

    Verified against libyara directly: an 8 KiB literal matches fine. Flagging
    it would be a false alarm, and a false alarm on the honest case teaches the
    reader to ignore the real one.
    """
    limit = regexp_scan_limit()
    assert limit is not None
    rng = random.Random(99)
    body = bytes(rng.randrange(256) for _ in range(limit * 2))
    rule = ("rule literal_only { meta: pattern_length = %d strings: "
            "$k = { %s } condition: $k }" % (len(body), body.hex()))
    dump = write_dump(tmp_path / "literal.bin", {4096: body}, size=_DUMP_SIZE)

    result = scan_yara_rule(dump_paths=[str(dump)], rule_source=rule)

    assert result["verdict"] == "matched"
    assert result["rules"]["exceeds_scan_limit"] is False, (
        "a literal is not clamped, so it must not be flagged")


# --------------------------------------------------------------------------- #
# What happens when ``pattern_length`` is ABSENT (a third-party rule)
# --------------------------------------------------------------------------- #

def test_an_over_limit_rule_without_pattern_length_is_still_caught(tmp_path):
    """No meta, no problem: the width is MEASURED off the rule text.

    ``max_pattern_length`` reads the ``pattern_length`` meta, which only rules
    MemDiver emitted carry -- so on the meta alone a hand-written ``.yar`` with
    a 2 KiB wildcard pattern would be waved through as "we do not know, assume
    fine", reopening the hole for exactly the rules MemDiver did not write.
    The text measurement is what closes it.
    """
    width = _over_limit_width()
    rule, reference, _ = _emit(width, drop_length=True)
    assert "pattern_length" not in rule, "fixture must have no meta to read"
    dump = write_dump(tmp_path / "planted.bin", {4096: reference},
                      size=_DUMP_SIZE)

    result = scan_yara_rule(dump_paths=[str(dump)], rule_source=rule)

    assert result["rules"]["max_pattern_length"] is None, "no meta to read"
    assert result["rules"]["widest_pattern_length"] == width, "measured instead"
    assert result["rules"]["exceeds_scan_limit"] is True
    assert result["verdict"] == "inconclusive"
    assert YARA_SCAN_OVER_SCAN_LIMIT_CODE in [
        d["code"] for d in result["diagnostics"]]


def test_an_unmeasurable_rule_width_is_reported_not_assumed_fine(tmp_path):
    """The residual unknown is NAMED, on the only verdict where it costs anything.

    A rule with no ``pattern_length`` meta AND a jump/alternation the measurer
    declines to parse leaves the width genuinely unknown. Silently treating
    that as "fine" is the hole; so a CLEAN verdict in that state carries a
    warning saying the zero is unverified.
    """
    rule = ("rule third_party { strings: "
            "$k = { 41 42 ?? [8-16] 43 44 } condition: $k }")
    assert measure_hex_string_widths(rule) == ((), 1)
    dump = write_dump(tmp_path / "nothing.bin", {}, seed=3, size=_DUMP_SIZE)

    result = scan_yara_rule(dump_paths=[str(dump)], rule_source=rule)

    assert result["verdict"] == "clean", "fixture must reach the clean verdict"
    assert result["rules"]["max_pattern_length"] is None
    assert result["rules"]["widest_pattern_length"] is None
    assert result["rules"]["pattern_width_unknown"] is True
    assert result["rules"]["exceeds_scan_limit"] is False, (
        "an unknown width must not be reported as a proven over-limit rule")

    diagnostic = next(d for d in result["diagnostics"]
                      if d["code"] == YARA_SCAN_WIDTH_UNKNOWN_CODE)
    assert diagnostic["severity"] == "warning"
    assert diagnostic["details"]["scan_limit"] == regexp_scan_limit()


def test_the_unknown_width_warning_stays_quiet_when_the_width_is_known(tmp_path):
    """It fires on the unknown, not on every scan.

    A measurable rule that simply matched nothing is a PROVEN absence, and
    attaching an "unverified" caveat to it would devalue the real one.
    """
    rule, _, _ = _emit(176, drop_length=True)
    dump = write_dump(tmp_path / "nothing.bin", {}, seed=3, size=_DUMP_SIZE)
    result = scan_yara_rule(dump_paths=[str(dump)], rule_source=rule)
    assert result["verdict"] == "clean"
    assert result["rules"]["pattern_width_unknown"] is False
    assert YARA_SCAN_WIDTH_UNKNOWN_CODE not in [
        d["code"] for d in result["diagnostics"]]


def test_rule_files_are_measured_the_same_way_as_inline_text(tmp_path):
    """The ``rule_paths`` intake reaches the same measurement as ``rule_source``.

    Two intakes, one guard: a rule read off disk must not be the quiet way past
    it.
    """
    width = _over_limit_width()
    rule, reference, _ = _emit(width, drop_length=True)
    rule_file = tmp_path / "third_party.yar"
    rule_file.write_text(rule)
    dump = write_dump(tmp_path / "planted.bin", {4096: reference},
                      size=_DUMP_SIZE)

    result = scan_yara_rule(dump_paths=[str(dump)],
                            rule_paths=[str(rule_file)])

    assert result["rules"]["widest_pattern_length"] == width
    assert result["verdict"] == "inconclusive"


# --------------------------------------------------------------------------- #
# The overlap interaction
# --------------------------------------------------------------------------- #

def test_an_over_limit_pattern_does_not_distort_the_auto_overlap():
    """Orthogonal mechanisms, and this pins that they stay orthogonal.

    ``_resolve_overlap`` sizes the chunk overlap from the SAME
    ``pattern_length`` meta, so it is fair to ask whether an over-limit pattern
    also corrupts the sweep geometry. It does not: the auto overlap starts at
    the flat ``DEFAULT_OVERLAP_BYTES`` (4096) floor and only rises above it for
    a pattern wider than that floor -- and every over-limit width up to 4096 is
    BELOW it, so the overlap is byte-for-byte what a harmless rule would get.
    Above 4096 the overlap does rise, and that sizing is still correct (it is
    the true width a straddling match can reach); the work is merely wasted on
    a rule that cannot fire. Either way the two faults do not compound.
    """
    def overlap_for(pattern_length: int) -> int:
        rules = compile_rules(
            source="rule r { meta: pattern_length = %d strings: "
                   "$a = { 41 ?? 42 } condition: $a }" % pattern_length)
        overlap, notes = _resolve(rules)
        assert notes == [], notes
        return overlap

    def _resolve(rules):
        return engine._resolve_overlap(0, CHUNK_BYTES, rules)

    baseline = overlap_for(176)
    assert baseline == DEFAULT_OVERLAP_BYTES
    # 1072 == the --context 512 width, dead but under the overlap floor.
    assert overlap_for(1072) == baseline
    assert overlap_for(DEFAULT_OVERLAP_BYTES) == baseline
    # Past the floor the overlap tracks the declared width, as designed.
    assert overlap_for(DEFAULT_OVERLAP_BYTES + 2) == DEFAULT_OVERLAP_BYTES + 1


# --------------------------------------------------------------------------- #
# Emit time: warn BEFORE a dead artifact is written
# --------------------------------------------------------------------------- #

def test_the_emit_warning_fires_for_a_context_512_pattern():
    """1072 bytes -- what ``--context 512`` produces -- is refused a clean bill.

    Emit-time rather than scan-time is the point: ``scan_yara_rule`` can only
    decline to call a dead rule clean AFTER someone runs it, and a signature
    written to disk outlives the session that made it.
    """
    limit = regexp_scan_limit()
    _, _, pattern = _emit(_over_limit_width())
    diagnostic = _scan_limit_diagnostic(pattern, context=512)

    assert diagnostic is not None
    assert diagnostic.code == PATTERN_OVER_SCAN_LIMIT_CODE
    assert diagnostic.severity.value == "warning"
    assert diagnostic.details["pattern_length"] == _over_limit_width()
    assert diagnostic.details["scan_limit"] == limit
    assert diagnostic.details["context_requested"] == 512
    # Names the knob that caused it and the ceiling, so the message is
    # actionable without reading this file.
    assert "--context 512" in diagnostic.message
    assert str(limit) in diagnostic.message
    # And records that upgrading is NOT the way out, so nobody "fixes" it by
    # bumping to a version that does not exist.
    assert "unreleased" in diagnostic.message


def test_the_emit_warning_advises_a_context_that_actually_fits():
    """The advised ``--context`` must be SMALLER than the one that failed.

    Regression test for a bug in the message itself, caught by running the real
    CLI: the advice was derived from ``pattern["key_length"]``, which the
    pattern dict does not carry (``YaraExporter.export`` takes it as a separate
    argument). ``None`` became a key span of 0 and the diagnostic told the
    analyst to "re-emit with --context 512 or less" -- the very value that had
    just produced the dead rule. Advice that recreates the fault is worse than
    no advice: it burns the one chance the reader gives the warning.
    """
    import re

    limit = regexp_scan_limit()
    assert limit is not None
    width = _over_limit_width()          # 1072 == 2 * 512 + 48
    _, _, pattern = _emit(width)
    diagnostic = _scan_limit_diagnostic(pattern, context=512)
    assert diagnostic is not None

    advised = int(re.search(r"re-emit with --context (\d+)",
                            diagnostic.message).group(1))
    assert advised < 512, "advising the failing context recreates the bug"
    # The key span is what the window holds besides the two context sides, so
    # the advised window must land at or under the limit.
    key_span = width - 2 * 512
    assert 2 * advised + key_span <= limit
    # And it must be the LARGEST such context -- advising 0 would technically
    # fit and would throw away every static anchor.
    assert 2 * (advised + 1) + key_span > limit


def test_the_emit_warning_stays_quiet_at_the_default_context():
    """``--context 64`` -> 176 bytes -> silence. The default does not change."""
    _, _, pattern = _emit(176)
    assert _scan_limit_diagnostic(pattern, context=64) is None


def test_the_emit_warning_is_exempt_for_a_wildcard_free_pattern():
    """A fully-static pattern is a literal, and literals are not clamped."""
    limit = regexp_scan_limit()
    assert limit is not None
    total = limit * 2
    reference = bytes(random.Random(5).randrange(256) for _ in range(total))
    pattern = PatternGenerator.generate(reference, [True] * total, name="lit")
    assert pattern is not None
    assert "?" not in pattern["wildcard_pattern"]
    assert _scan_limit_diagnostic(pattern, context=512) is None


def test_the_emit_warning_measures_a_pattern_with_no_declared_length():
    """A pattern dict whose ``length`` is missing is measured, not skipped."""
    width = _over_limit_width()
    _, _, pattern = _emit(width)
    stripped = {k: v for k, v in pattern.items() if k != "length"}
    diagnostic = _scan_limit_diagnostic(stripped, context=512)
    assert diagnostic is not None
    assert diagnostic.details["pattern_length"] == width


def test_the_exporter_itself_logs_the_warning(caplog):
    """``YaraExporter.export`` is a public static method other paths call.

    It returns a bare string and has no diagnostics channel, so the log is the
    only voice it has -- but it is worth having, because code and tests call
    ``export`` directly without going through a producer.
    """
    width = _over_limit_width()
    with caplog.at_level(logging.WARNING,
                         logger="memdiver.architect.yara_exporter"):
        _emit(width, name="dead_on_arrival")
    warnings = [r for r in caplog.records if r.levelno == logging.WARNING]
    assert warnings, "an over-limit export must warn"
    assert "match NOTHING" in warnings[0].getMessage()
    assert str(width) in warnings[0].getMessage()


def test_the_exporter_stays_quiet_for_a_normal_pattern(caplog):
    with caplog.at_level(logging.WARNING,
                         logger="memdiver.architect.yara_exporter"):
        _emit(176, name="perfectly_fine")
    assert [r for r in caplog.records if r.levelno == logging.WARNING] == []
