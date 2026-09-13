"""The emit -> scan -> score loop, closed on the REAL corpus.

Everything else in this family is proven on synthetic fixtures, where the
background is chosen to carry entropy on purpose (``_BACKGROUND_ALPHABET`` in
``tests/test_api_locate_key.py``) and every emitted rule therefore looks fine.
Real process memory does not cooperate: the TLS 1.2 master secret in

    TLS12/100_iterations_Abort/openssl/openssl_run_12_1/

sits at offset 370,672 inside a **zero run** — ``[370601, 371184)``, so 71
zero bytes before the key and 464 after. At the DEFAULT ``context=64`` the
whole 176-byte window therefore lies inside that run, and the rule the emitter
publishes is, byte for byte, ``00{64} ??{48} 00{64}``: a non-detector.

This module measures how bad that is, with the real producers, and pins the
qualitative claim. The numbers below were measured on this corpus (the two
scans were also run uncapped from the terminal; see ``max_matches`` note in
:func:`test_pad_64_is_a_non_detector_and_pad_128_is_precise`):

===================================  ==========  ===========
fact                                 context=64  context=128
===================================  ==========  ===========
pattern_length                              176          304
static_ratio (the emitter's own)         0.7273       0.7961
anchor distinct byte values                   1           17
anchor entropy (bits/byte)                  0.0       0.6502
firings in ONE dump, libyara            825,779            1
firings over all 8 dumps, libyara     6,621,373            8
precision, key_offset criterion       1.21e-06          1.0
recall, key_offset criterion                1.0          1.0
===================================  ==========  ===========

Three things in that table are worth stating out loud, because each of them
contradicts a signal the tree already publishes:

* ``static_ratio`` **RISES** with the pad (0.7273 -> 0.7961) while the detector
  goes from useless to perfect. It is a plain count, ``sum(mask)/len(mask)``,
  and 128 bytes of ``0x00`` count exactly as much as 128 structural ones — so
  the emitter's headline health number is *inverted* with respect to reality
  here. The scored precision is the honest signal.
* ``export.key_pattern.degenerate_anchors`` **used to fire at BOTH pads** (0.0
  and 0.6502 bits/byte were both under the old ``KEY_PATTERN_MIN_ANCHOR_BITS ==
  1.0``), so it did not separate them either -- and, worse, the pad-128 firing
  was a WARNING ON A RULE OF PRECISION 1.0. It was not "a correct warning that
  happens not to be a discriminator"; it was a false alarm. The floor has since
  been re-calibrated on 99 measured (run, pad) cells across all 13 corpus TLS
  libraries and both TLS versions -- see
  ``tests/test_degenerate_anchor_calibration.py`` and the constants block in
  ``app/tools_pipeline.py`` -- and the gate is now ``distinct_bytes < 3``
  (``shannon_bits`` was measured to be a poor predictor: its failing and
  passing ranges OVERLAP, so its floor is retired at 0.0). It fires on pad 64
  and is silent on pad 128, so on THIS run it now agrees with the scored
  precision. ``static_ratio`` above remains the inverted one.
* The true site is reported RELIABLY, in all 8 dumps, with ``delta == 0``
  against the key-log truth in the two that hold the key. There is no
  "alignment accident" to worry about: overlapping matches mean there is no
  non-overlapping walk to step over the real one.

``tests/test_vol3_verify.py`` measured the same rule through the emitted
Volatility3 plugin and pinned **5,311** matches on this dump. That number and
the 825,779 here are BOTH right, and the 155x gap between them is the finding:
vol3's ``RegExScanner`` walks with ``re.finditer``, which is NON-overlapping,
so it reports one hit per ~176-byte stride through each zero run; libyara
reports every match, overlapping ones included. Same signature, same dump, two
scanners, two censuses — so a selectivity number is meaningless without
naming the engine that produced it. This module is the libyara half, over all
eight dumps rather than one, with the 2-of-8 truth split scored.

The criterion that means something here is **key_offset**, not raw ``exact``:
a YARA match reports the PATTERN window start (370,608 at pad 64; 370,544 at
pad 128), and ``RuleMatch.key_offset`` is what turns that back into the key
position. On this corpus all three criteria happen to agree, because the
pattern is anchored so tightly that the one true firing is the only one within
tolerance of the key under any of them.

Gating and runtime: everything here is ``requires_dataset``, so a machine
without the corpus gets the shared informative skip. The four bounded tests run
in under 0.2 s each and therefore stay in a plain ``pytest``; only the one
full-corpus pass also carries ``slow`` (measured 21.0 s of the module's 21.3 s
— libyara finds all ~826k pad-64 matches per dump before ``max_matches`` drops
any, so the cap bounds memory, not time). Bring it back with
``pytest -m requires_dataset`` or ``make test-corpus``.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from memdiver.app.tools_pipeline import (  # noqa: E402
    export_key_pattern,
    scan_yara_rule,
    score_detector_matches,
)

#: The run every fact in the module docstring was measured on.
_RUN = "TLS12/100_iterations_Abort/openssl/openssl_run_12_1"

#: Ground truth, from the run's own ``keylog.csv`` (asserted, never assumed --
#: :func:`test_the_master_secret_survives_the_abort_and_is_wiped_by_cleanup`
#: re-derives the offset from the dumps through the real locator, so a moved
#: key fails there first instead of surfacing as a mystery in the scores).
_KEY_OFFSET = 370_672
_KEY_LENGTH = 48

#: Matches KEPT per dump on the pad-64 scan. The uncapped census is ~826k per
#: dump and every ``RuleMatch`` carries 352 hex characters of ``matched_hex``,
#: so an uncapped 8-dump run holds ~3 GB of match objects in memory -- fine
#: from the CLI writing straight to disk, not fine inside a test process.
#:
#: The cap is chosen ABOVE the true firing's measured index (27,653 in
#: ``pre_abort``, 27,551 in ``post_abort``) so the true site survives it, and
#: :func:`test_pad_64_is_a_non_detector_and_pad_128_is_precise` asserts the
#: site is present rather than trusting that. Under the cap the reported
#: ``match_count`` is a FLOOR and ``truncated`` says so -- which is all the
#: "matches >> 1" claim needs, and it makes precision look BETTER than the
#: uncapped 1.21e-06, so the assertions below stay conservative.
_PAD64_MAX_MATCHES = 50_000

#: The pad-128 scan is uncapped: its whole point is that the census is 8.
_EXPECTED_PAD128_MATCHES = 8


def _run_dir() -> Path:
    from tests.fixtures.tls_ground_truth import tls_dumps_dir

    return Path(tls_dumps_dir()) / _RUN


def _keylog_line(run_dir: Path) -> str:
    """The run's single NSS key-log row, out of its ``keylog.csv``.

    The file is ``id,line`` with the NSS row in the second column, so the split
    is on the FIRST comma only -- the row itself contains no comma, but slicing
    the last field would break the moment a column is added.
    """
    rows = run_dir.joinpath("keylog.csv").read_text().strip().splitlines()
    return rows[1].split(",", 1)[1].strip()


def _corpus() -> tuple[Path, list[Path], str, bytes]:
    """Resolve the run, or skip informatively. Returns (dir, dumps, line, key)."""
    run_dir = _run_dir()
    dumps = sorted(run_dir.glob("*.dump"))
    keylog = run_dir / "keylog.csv"
    if len(dumps) != 8 or not keylog.is_file():
        pytest.skip(f"TLS 1.2 reference run not present under {run_dir}")
    line = _keylog_line(run_dir)
    fields = line.split()
    if len(fields) != 3 or fields[0] != "CLIENT_RANDOM":
        pytest.skip(f"unexpected key-log shape in {keylog}: {fields[:1]}")
    return run_dir, dumps, line, bytes.fromhex(fields[2])


def _emit(dumps: list[Path], line: str, *, context: int, name: str) -> dict:
    """Emit through the REAL chain -- never hand-written rule text.

    ``export_key_pattern`` is the producer the CLI ``export-key-pattern``
    command, the HTTP route and the MCP tool all route through, and it owns the
    ``PatternGenerator`` -> ``YaraExporter`` path, so what comes back is the
    rule an operator would actually publish.
    """
    return export_key_pattern(
        dump_paths=[str(p) for p in dumps],
        keylog_line=line,
        context=context,
        fmt="yara",
        name=name,
    )


def _truths_for(dump: Path) -> list[dict]:
    """The key-log truth for one dump: one interval, or none.

    The 2-of-8 presence split IS the ground truth (the secret survives the
    abort and is wiped by cleanup), so the six cleanup dumps get an EMPTY truth
    list -- which ``score_detector_matches`` reports as ``unscorable`` rather
    than as six perfect zeros. See the caveat in
    :func:`test_a_precise_rule_still_fires_where_the_key_is_gone`.
    """
    if "abort" in dump.name:
        return [{"start": _KEY_OFFSET, "length": _KEY_LENGTH,
                 "source": "keylog"}]
    return []


def _rows(dumps: list[Path], scan: dict, detector: str) -> list[dict]:
    """A ``score_detector_matches(rows=...)`` intake straight off a scan.

    Rows are built per dump and scored independently -- pooling the intervals
    first would let a firing in one dump pair with a truth in another whose
    offsets line up, which on this corpus (all eight dumps agreeing on 370,672)
    would invent seven true positives.
    """
    assert len(scan["dumps"]) == len(dumps)
    rows = []
    for dump, row in zip(dumps, scan["dumps"]):
        assert row["name"] == dump.name
        rows.append({
            "detector": detector,
            "dump": dump.name,
            "matches": row["scan"]["matches"],
            "truths": _truths_for(dump),
        })
    return rows


def _key_offset_metrics(score: dict) -> dict:
    """The micro-averaged ``key_offset`` block -- THE criterion here.

    A match reports the pattern WINDOW start, so raw ``exact`` on the match
    offset would be the wrong question; ``key_offset`` is the criterion that
    asks whether ``match.offset + match.key_offset`` landed on the key.
    """
    return score["report"]["overall"]["metrics"]["key_offset"]


# --------------------------------------------------------------------------- #
# (a) the ground truth, re-derived rather than trusted
# --------------------------------------------------------------------------- #

@pytest.mark.requires_dataset
def test_the_master_secret_survives_the_abort_and_is_wiped_by_cleanup():
    """The 2-of-8 split, read off the corpus through the real locator.

    Every scored number in this module rests on this: the 48-byte master
    secret from ``keylog.csv`` is at offset 370,672 in BOTH ``*_abort`` dumps
    and provably absent from all six ``*_cleanup`` ones. If that ever changes,
    this test says so before the scoring tests report a mystery.
    """
    _, dumps, line, secret = _corpus()
    assert len(secret) == _KEY_LENGTH

    emitted = _emit(dumps, line, context=64, name="ground_truth")
    location = emitted["location"]

    assert location["verdict"] == "found"
    assert location["needle_length"] == _KEY_LENGTH
    assert (location["dumps_present"], location["dumps_absent"]) == (2, 6)
    assert location["dumps_unreadable"] == 0
    assert location["offsets_agree"] is True
    assert location["common_offset"] == _KEY_OFFSET

    present = {r["name"]: r for r in location["dumps"] if r["present"]}
    assert len(present) == 2
    assert all("abort" in name for name in present)
    # ONE occurrence each -- no truncated offset list is hiding copies, which
    # is what makes "one firing per dump is perfect precision" a fair test.
    assert all(r["hit_count"] == 1 for r in present.values())
    assert all(r["first_offset"] == _KEY_OFFSET for r in present.values())

    absent = [r["name"] for r in location["dumps"] if not r["present"]]
    assert len(absent) == 6
    assert all("cleanup" in name for name in absent)

    # The absences are what wildcard the key: a mask over only the two dumps
    # that hold it would be 100% static and would ship the secret verbatim.
    assert (emitted["key_static_count"], emitted["key_wildcard_count"]) == (
        0, _KEY_LENGTH)


# --------------------------------------------------------------------------- #
# (b) the emitted rules, before anything is scanned
# --------------------------------------------------------------------------- #

@pytest.mark.requires_dataset
def test_the_default_pad_emits_a_window_of_nothing_but_zeros():
    """At ``context=64`` the emitted rule IS ``00{64} ??{48} 00{64}``.

    Asserted on the rule text the emitter publishes, so this cannot pass
    against a hand-written approximation of it. The window is 176 bytes and
    starts at 370,608 -- the offset a YARA match will report, 64 bytes below
    the key, which is the whole reason ``key_offset`` exists as a meta.
    """
    _, dumps, line, _ = _corpus()

    emitted = _emit(dumps, line, context=64, name="corpus_pad64")
    region, pattern = emitted["region"], emitted["pattern"]

    assert region["length"] == pattern["length"] == 176
    assert region["offset"] == _KEY_OFFSET - 64 == 370_608
    assert region["key_start"] == _KEY_OFFSET
    assert region["key_offset_in_pattern"] == 64
    assert (region["context_before"], region["context_after"]) == (64, 64)

    tokens = emitted["pattern"]["wildcard_pattern"].split()
    assert len(tokens) == 176
    assert tokens[:64] == ["00"] * 64            # the 71-byte zero run before
    assert tokens[64:112] == ["??"] * 48         # the key itself
    assert tokens[112:] == ["00"] * 64           # the 464-byte run after

    # The metas a scan needs to get back from the window to the key.
    assert "key_offset = 64" in emitted["content"]
    assert f"key_length = {_KEY_LENGTH}" in emitted["content"]
    assert "pattern_length = 176" in emitted["content"]


@pytest.mark.requires_dataset
def test_static_ratio_does_not_separate_the_two_pads_but_the_warning_now_does():
    """``static_ratio`` is still INVERTED; ``degenerate_anchors`` was FIXED.

    **This test used to assert the bug.** It read ``degenerate_anchors`` fires
    at BOTH pads and called that a negative result -- but the pad-128 rule has
    precision 1.0 (see the module table), so what the assertion actually pinned
    was a WARNING ON A PERFECT RULE. That firing came from
    ``KEY_PATTERN_MIN_ANCHOR_BITS = 1.0``, a floor reasoned from pad 64 (0.0
    bits) and pad 256 (1.26 bits) without anyone measuring pad 128, which is
    0.6502 and perfect. The floor has since been re-derived from a 99-cell
    sweep over all 13 corpus TLS libraries
    (``tests/test_degenerate_anchor_calibration.py`` re-derives it) and is now
    ``distinct_bytes < 3`` -- how many DIFFERENT byte values the anchors carry
    was the only property that ordered the sweep's outcomes, and
    ``shannon_bits`` was refuted outright (its failing range [0.0, 0.2623]
    overlaps its passing range [0.0521, 6.7383], so no floor separates them).

    So the standing claim splits in two, and each half is asserted below:

    * ``static_ratio`` remains inverted -- it RISES from 0.7273 to 0.7961 while
      the detector goes from 825,779 firings to 1. It is a plain count,
      ``sum(mask)/len(mask)``, so 128 bytes of ``0x00`` weigh as much as 128
      structural ones. Still no discriminator.
    * ``degenerate_anchors`` now DOES separate them: it fires on pad 64
      (``distinct_bytes == 1``) and is silent on pad 128
      (``distinct_bytes == 17``). The emit-time gate and the scored precision
      finally agree on this run.

    The scan-and-score loop is not thereby made redundant: the calibration that
    fixed this gate was only derivable BY scanning and scoring, and one signal
    agreeing with the truth on one run is not a substitute for measuring.
    """
    _, dumps, line, _ = _corpus()

    narrow = _emit(dumps, line, context=64, name="health_pad64")
    wide = _emit(dumps, line, context=128, name="health_pad128")

    # INVERTED with respect to reality: the useless rule scores LOWER.
    assert narrow["pattern"]["static_ratio"] == 0.7273
    assert wide["pattern"]["static_ratio"] == 0.7961
    assert narrow["pattern"]["static_ratio"] < wide["pattern"]["static_ratio"]

    codes = {"export.key_pattern.degenerate_anchors"}
    narrow_codes = {d["code"] for d in narrow["diagnostics"]}
    wide_codes = {d["code"] for d in wide["diagnostics"]}
    assert codes <= narrow_codes, "pad 64 IS a non-detector; it must warn"
    # The assertion this line replaced was ``codes <= wide_codes``. Flipping it
    # is the whole fix: pad 128 fires once per dump with precision 1.0, so a
    # WARNING on it is a false alarm, and false alarms are what teach an
    # operator to skip the true one above.
    assert not (codes <= wide_codes), (
        f"pad 128 has precision 1.0 and must NOT warn; got {sorted(wide_codes)}")

    # The wider window DOES reach structural bytes -- "9-cnt-12!" from the
    # run's own allocation -- which is why it is precise, and now also why the
    # gate stays quiet: those bytes are what lift distinct_bytes from 1 to 17.
    assert b"9-cnt-12!" in bytes.fromhex(
        "".join(t for t in wide["pattern"]["wildcard_pattern"].split()
                if t != "??"))


# --------------------------------------------------------------------------- #
# (c) the loop: emit -> scan -> score, over all eight dumps
# --------------------------------------------------------------------------- #

# The ONE full-corpus pass, and the only test in here that carries `slow`:
# ~21 s, because libyara finds every one of the ~826k pad-64 matches per dump
# before `max_matches` drops any. That is a COST gate, so `addopts` deselects
# it from a plain `pytest` and `-m requires_dataset` (or `make test-corpus`)
# brings it back. The other four tests in this module are bounded slices --
# under 0.2 s each -- and stay in the default run on purpose, exactly as the
# `requires_dataset` note in pyproject.toml describes.
@pytest.mark.slow
@pytest.mark.requires_dataset
def test_pad_64_is_a_non_detector_and_pad_128_is_precise():
    """THE acceptance test. Order-of-magnitude claims, not brittle counts.

    Measured here, and printed so a run records its own numbers:

    * pad 64 keeps ``_PAD64_MAX_MATCHES`` firings per dump and reports
      ``truncated`` -- the uncapped census is 825,779 in ``pre_abort`` alone
      and 6,621,373 over the eight dumps -- against ONE key. Precision under
      the ``key_offset`` criterion collapses to ~2e-05 capped (1.21e-06
      uncapped) while recall stays 1.0: the rule finds the key and also
      everything else.
    * pad 128 fires exactly ONCE per dump, at 370,544, and
      ``offset + key_offset == 370,672`` -- precision 1.0, recall 1.0.

    The assertions are inequalities and orders of magnitude on purpose. The
    exact firing counts differ between the two abort dumps already (825,779 vs
    825,500) and would move again with any libyara version, but "five orders of
    magnitude apart" is a property of the data.
    """
    _, dumps, line, _ = _corpus()
    paths = [str(p) for p in dumps]

    narrow = _emit(dumps, line, context=64, name="corpus_pad64")
    wide = _emit(dumps, line, context=128, name="corpus_pad128")

    narrow_scan = scan_yara_rule(
        dump_paths=paths,
        rule_source=narrow["content"],
        max_matches=_PAD64_MAX_MATCHES,
    )
    wide_scan = scan_yara_rule(dump_paths=paths, rule_source=wide["content"])

    assert narrow_scan["verdict"] == wide_scan["verdict"] == "matched"
    assert narrow_scan["counts"]["dumps_unreadable"] == 0
    assert wide_scan["counts"]["dumps_unreadable"] == 0
    assert narrow_scan["rules"]["max_pattern_length"] == 176
    assert wide_scan["rules"]["max_pattern_length"] == 304

    # -- the census -------------------------------------------------------- #
    # Every pad-64 row hit the cap, so each count is a floor and the scan says
    # so. The FLOOR is already four orders of magnitude past one key.
    assert narrow_scan["counts"]["dumps_truncated"] == 8
    assert all(row["scan"]["truncated"] for row in narrow_scan["dumps"])
    assert all(row["scan"]["match_count"] == _PAD64_MAX_MATCHES
               for row in narrow_scan["dumps"])

    # The pad-128 census is EXACT: one firing per dump, nothing truncated.
    assert wide_scan["counts"]["dumps_truncated"] == 0
    assert wide_scan["counts"]["matches_total"] == _EXPECTED_PAD128_MATCHES
    for row in wide_scan["dumps"]:
        assert row["scan"]["match_count"] == 1
        hit = row["scan"]["matches"][0]
        assert hit["offset"] == 370_544
        assert hit["key_offset"] == 128
        assert hit["key_length"] == _KEY_LENGTH
        # The subtlety the metas exist for: the match is 128 bytes BELOW the
        # key, and this is the arithmetic that recovers it.
        assert hit["offset"] + hit["key_offset"] == _KEY_OFFSET

    # libyara reports the true window start RELIABLY at pad 64, in every dump.
    # (It reports overlapping matches, so there is no non-overlapping walk to
    # step over it -- which is also why the census is ~826k and not ~5.3k.)
    for row in narrow_scan["dumps"]:
        offsets = {m["offset"] for m in row["scan"]["matches"]}
        assert 370_608 in offsets, row["name"]

    # -- the score --------------------------------------------------------- #
    narrow_score = score_detector_matches(
        rows=_rows(dumps, narrow_scan, "corpus_pad64"))
    wide_score = score_detector_matches(
        rows=_rows(dumps, wide_scan, "corpus_pad128"))

    assert narrow_score["verdict"] == wide_score["verdict"] == "scored"
    # Two scorable rows (the abort dumps) and six unscorable ones, on BOTH.
    for score in (narrow_score, wide_score):
        assert score["counts"]["rows_scored"] == 2
        assert score["counts"]["rows_unscorable"] == 6
        assert score["counts"]["truths_total"] == 2

    narrow_metrics = _key_offset_metrics(narrow_score)
    wide_metrics = _key_offset_metrics(wide_score)

    # Recall is PERFECT on both: the non-detector does find the key. That is
    # exactly why recall alone would have certified it.
    assert narrow_metrics["recall"] == wide_metrics["recall"] == 1.0
    assert narrow_metrics["tp_matches"] == wide_metrics["tp_matches"] == 2
    assert narrow_metrics["missed_truths"] == wide_metrics["missed_truths"] == 0

    # Precision is where it dies. pad 128 is exact; pad 64 is off by four
    # orders of magnitude even with the cap suppressing 94% of its firings.
    assert wide_metrics["precision"] == 1.0
    assert wide_metrics["fp_matches"] == 0
    assert narrow_metrics["precision"] < 1e-3
    assert narrow_metrics["fp_matches"] > 10_000
    assert narrow_metrics["precision"] * 1_000 < wide_metrics["precision"]

    # ... and F1 follows precision, so the summary number is not fooled either.
    assert narrow_metrics["f1"] < 1e-3 < wide_metrics["f1"]

    # All three criteria agree on this corpus: the window is anchored tightly
    # enough that the one true firing is the only one within tolerance under
    # any of them. Asserted so a future divergence is visible rather than
    # silently averaged away.
    for score, expected in ((narrow_score, narrow_metrics),
                            (wide_score, wide_metrics)):
        for criterion in ("containment", "key_offset", "exact"):
            block = score["report"]["overall"]["metrics"][criterion]
            assert block["precision"] == expected["precision"], criterion
            assert block["recall"] == expected["recall"], criterion

    print(
        f"\nemit -> scan -> score on {_RUN}"
        f"\n  pad  64: static_ratio {narrow['pattern']['static_ratio']}, "
        f"{narrow_scan['counts']['matches_total']} firing(s) over 8 dumps "
        f"(CAPPED at {_PAD64_MAX_MATCHES}/dump; uncapped census 6,621,373), "
        f"key_offset precision {narrow_metrics['precision']:.3e}, "
        f"recall {narrow_metrics['recall']}"
        f"\n  pad 128: static_ratio {wide['pattern']['static_ratio']}, "
        f"{wide_scan['counts']['matches_total']} firing(s) over 8 dumps, "
        f"key_offset precision {wide_metrics['precision']:.3e}, "
        f"recall {wide_metrics['recall']}"
    )


@pytest.mark.requires_dataset
def test_a_precise_rule_still_fires_where_the_key_is_gone():
    """The caveat the score CANNOT charge, stated as its own test.

    The pad-128 rule wildcards the key span, so it matches the key's SLOT --
    the surrounding allocation -- which survives ``cleanup`` even though the
    secret does not. It therefore fires in all EIGHT dumps while only two hold
    the key: six alarms that are false in the only sense an operator cares
    about.

    ``score_detector_matches`` reports those six rows as ``unscorable`` with
    ``metrics: None`` rather than charging their firings, and it is RIGHT to:
    "this dump provably holds no key" is not expressible as a truth interval,
    so pooling them in would assert a claim the input cannot support. The
    producer publishes ``matches_unscorable`` precisely so a caller who knows
    the absences can compute the stricter rate -- 2/8 = 0.25 here -- and this
    test pins that escape hatch, because the headline precision of 1.0 is
    otherwise easy to over-read.
    """
    _, dumps, line, _ = _corpus()

    wide = _emit(dumps, line, context=128, name="slot_pad128")
    scan = scan_yara_rule(
        dump_paths=[str(p) for p in dumps], rule_source=wide["content"])
    score = score_detector_matches(rows=_rows(dumps, scan, "slot_pad128"))

    # Fires in all eight, at the same offset, on a key present in two.
    assert scan["counts"]["dumps_matched"] == 8
    assert {row["scan"]["matches"][0]["offset"] for row in scan["dumps"]} == {
        370_544}

    counts = score["counts"]
    assert counts["matches_scored"] == 2
    assert counts["matches_unscorable"] == 6
    assert counts["matches_total"] == 8
    # The six carry NO metrics block -- not a block of zeros.
    unscorable = [r for r in score["rows"] if r["status"] == "unscorable"]
    assert len(unscorable) == 6
    assert all(r["metrics"] is None for r in unscorable)
    assert all("cleanup" in r["dump"] for r in unscorable)

    # And the warning is raised rather than left for the reader to notice.
    codes = {d["code"] for d in score["diagnostics"]}
    assert "analysis.score_detector.unscorable_rows" in codes

    # The stricter rate a caller can compute from what IS published.
    strict_precision = counts["matches_scored"] / counts["matches_total"]
    assert strict_precision == 0.25
    assert _key_offset_metrics(score)["precision"] == 1.0
