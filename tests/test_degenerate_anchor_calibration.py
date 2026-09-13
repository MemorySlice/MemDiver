"""The CALIBRATION behind ``export.key_pattern.degenerate_anchors``, pinned.

``KEY_PATTERN_MIN_ANCHOR_BYTES`` and ``KEY_PATTERN_MIN_ANCHOR_BITS`` decide
whether an operator is told a signature is worthless. Their first values -- 4
distinct bytes and 1.0 bit/byte -- were *reasoned*, from two points on one run:
pad 64 on the OpenSSL TLS 1.2 anchor key carries 0.0 bits and pad 256 carries
1.26, so 1.0 looked like a boundary. Nobody measured pad 128. It is **0.6502
bits and its rule is PERFECT** -- one firing per dump, ``key_offset`` precision
1.0 -- so the floor warned about a flawless rule. That is the worst failure mode
a diagnostic has: it trains the reader to skip the firing that matters.

The repo has a scar exactly here. ``engine/candidate_stats.py`` calibrated its
gates on synthetic uniform-random data and its own docstring admits they do not
transfer. So this floor was re-derived by MEASURING, and this module is the pin
that keeps it honest.

How the calibration was measured
--------------------------------
99 ``(run, pad)`` cells: pads 64 / 128 / 256 / 512 over 25 runs covering all 13
corpus TLS libraries (openssl, boringssl, libressl, libretls, wolfssl, mbedtls,
gnutls, nss, rustls, gotls, botanssl, s2ntls, matrixssl) and both TLS 1.2 and
TLS 1.3, including two second-iteration runs to check run-to-run stability. Each
cell was

1. emitted through the REAL chain -- ``export_key_pattern`` with the run's own
   ``keylog.csv`` line, so ``PatternGenerator`` and ``YaraExporter`` produce the
   rule an operator would actually publish (a 100th cell, TLS 1.3 botanssl at
   pad 64, was REFUSED by ``min_static_ratio`` at 20 % static -- the emitter's
   other floor doing its job, and not part of this calibration);
2. scanned with ``scan_yara_rule(max_matches=None, include_matches=False)`` --
   the **uncapped count-only census**. Count-only is not an optimisation here,
   it is the only way to ask the question: an uncapped pad-64 scan of the eight
   OpenSSL dumps materialises 6.6M matches carrying 352 hex characters each,
   which is a 4.0 GB JSON. The count is one integer per dump;
3. scored with ``score_detector_matches`` on the **key_offset** criterion --
   a YARA match reports the pattern WINDOW start, and the ``key_offset`` /
   ``key_length`` metas are what turn that back into the key position. Only the
   dumps that HOLD the key carry a truth interval; a row without truths is
   reported ``unscorable``, so it cannot move precision either way.

92 cells were judgeable. The other 7 are excluded because libyara declines to
match their pattern at all -- see :func:`test_the_excluded_cells_are_an_engine_
limit_not_a_selectivity_result`.

What the numbers say
--------------------
Selectivity is governed by ``distinct_bytes``, and the outcome falls into three
sharply separated groups. **Nothing lands between 6 firings and 750,000.**

============  =====  ===================  ===============  ==============
distinct       cells  firings / dump       precision        verdict
============  =====  ===================  ===============  ==============
1                20  752,908 - 1,000,000  ~1.0e-06         non-detector
2                 2  2 and 6              0.5 and 0.167    imprecise
>= 3             70  exactly 1, all 70    1.0              perfect
============  =====  ===================  ===============  ==============

So ``distinct_bytes < 3`` is a PERFECT classifier over all 92 judgeable cells:
22 true alarms, **0 false alarms**, 0 missed, 70 correctly quiet. The old gate
scored 22 true and **21 FALSE** on the same cells -- it cried wolf on nearly
half of everything it said. And the boundary is measured on BOTH sides:
``distinct_bytes == 2`` fires 2-6 times per dump and ``== 3`` fires exactly once.

**Is ``shannon_bits`` a good predictor? No, and not for want of tuning.** The
failing cells span ``[0.0, 0.2623]`` bits/byte and the passing ones span
``[0.0521, 6.7383]``: the ranges OVERLAP, so no floor of any value separates
them. A rule at 0.2623 bits/byte is unselective while one at 0.0521 is perfect.
Per-byte entropy says nothing about how much anchor there is, nor about whether
a real process image happens to contain the same filler. The floor is therefore
set to 0.0 -- not a tuned value but the RETIREMENT of the signal; see
:func:`test_no_fixed_positive_bits_floor_can_express_more_than_one_value`.

A narrower sweep would have got this wrong
------------------------------------------
The first pass covered 36 cells over 9 runs. It saw ``distinct_bytes`` of only 1
and >= 3, showed a clean bimodal split, and would have justified a floor of
**2**. Widening to every library produced the two ``distinct_bytes == 2`` cells,
which are imprecise -- so 2 would have gone silent on them. The number moved
because the sweep grew, which is the whole argument for measuring rather than
reasoning, and is why :func:`test_the_separation_the_thresholds_were_drawn_from_
still_holds` asserts the SHAPE and not just the cells.

Gating and runtime: every corpus test here is ``requires_dataset`` and skips
per-cell when a run is missing, so a machine holding part of the corpus still
gets what it has. The emit-side pins are bounded (no scanning; all 20 cells in
under a second) and stay in a plain ``pytest``. The two tests that re-measure a
census carry ``slow`` as well, exactly as ``tests/test_detector_loop_corpus.py``
does -- libyara enumerates all ~826k pad-64 matches before it can return a
count, so ``include_matches=False`` bounds the OUTPUT (~559,000x smaller), not
the time. Bring them back with ``pytest -m requires_dataset``.
"""

from __future__ import annotations

import math
import sys
from pathlib import Path
from typing import NamedTuple

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from memdiver.app.tools_pipeline import (  # noqa: E402
    KEY_PATTERN_DEGENERATE_ANCHORS_CODE,
    KEY_PATTERN_MIN_ANCHOR_BITS,
    KEY_PATTERN_MIN_ANCHOR_BYTES,
    export_key_pattern,
    scan_yara_rule,
)
from memdiver.architect.pattern_generator import PatternGenerator  # noqa: E402

_T12 = "TLS12/100_iterations_Abort"
_T13 = "TLS13/100_iterations_Abort_KeyUpdate"


class _Cell(NamedTuple):
    """One measured ``(run, pad)`` point of the calibration sweep.

    ``firings`` is the LOWEST uncapped libyara count observed over the dumps
    that hold the key, so ``firings == 1`` means every present dump fired
    exactly once. It is provenance for the emit-side pins and re-measured, as an
    order of magnitude, by the ``slow`` census test.
    """

    run: str
    nss: str
    pad: int
    distinct_bytes: int
    bits: float
    firings: int

    @property
    def unselective(self) -> bool:
        """More than one firing per dump, i.e. at least one false positive.

        The strictest outcome criterion available, deliberately: it puts the
        2-firing cell on the same side as the 986,115-firing one, so a threshold
        that separates under THIS definition needs no argument about where
        "usable" ends.
        """
        return self.firings > 1


#: The pinned subset of the 99-cell sweep: eight of the twenty non-detectors,
#: BOTH ``distinct_bytes == 2`` cells (the pair that set the floor at 3 rather
#: than 2), and ten selective cells spanning the bits axis from the lowest value
#: that passed (0.0521) to the highest measured (6.7383). Ten of the twenty sit
#: in the band the OLD gate warned about -- eight of them selective, which is
#: what makes this table a regression guard rather than a decoration.
_CALIBRATION = (
    # -- distinct_bytes == 1: the anchors are ONE repeated value, so the rule is
    #    a lattice through every run of that filler. Six digits of firings, in
    #    six libraries and both TLS versions.
    _Cell(f"{_T13}/s2ntls/s2ntls_run_13_1",
          "CLIENT_TRAFFIC_SECRET_0", 64, 1, 0.0, 1000000),
    _Cell(f"{_T12}/s2ntls/s2ntls_run_12_1",
          "CLIENT_RANDOM", 64, 1, 0.0, 986115),
    _Cell(f"{_T13}/gnutls/gnutls_run_13_1",
          "CLIENT_HANDSHAKE_TRAFFIC_SECRET", 64, 1, 0.0, 893585),
    _Cell(f"{_T12}/libretls/libretls_run_12_1",
          "CLIENT_RANDOM", 64, 1, 0.0, 825552),
    _Cell(f"{_T12}/openssl/openssl_run_12_1",
          "CLIENT_RANDOM", 64, 1, 0.0, 825500),
    # Widening the pad does NOT always rescue it: gnutls is still one repeated
    # value at 256, because its zero run is longer than the window.
    _Cell(f"{_T13}/gnutls/gnutls_run_13_1",
          "CLIENT_HANDSHAKE_TRAFFIC_SECRET", 256, 1, 0.0, 812248),
    _Cell(f"{_T12}/mbedtls/mbedtls_run_12_1",
          "CLIENT_RANDOM", 64, 1, 0.0, 766357),
    _Cell(f"{_T13}/mbedtls/mbedtls_run_13_1",
          "CLIENT_TRAFFIC_SECRET_0", 128, 1, 0.0, 752908),

    # -- distinct_bytes == 2: THE PAIR THAT DECIDED THE THRESHOLD. Imprecise
    #    but not catastrophic -- 6 and 2 firings against one key. A floor of 2
    #    (which the first, narrower sweep would have justified) goes silent on
    #    exactly these, which is why the floor is 3. Note the bits values,
    #    0.2623 and 0.2448: both are ABOVE the lowest bits value that passed
    #    (0.0521 below), and that inversion is what refutes a bits floor.
    _Cell(f"{_T13}/libressl/libressl_run_13_1",
          "CLIENT_TRAFFIC_SECRET_0", 64, 2, 0.2623, 6),
    _Cell(f"{_T13}/libressl/libressl_run_13_1",
          "CLIENT_TRAFFIC_SECRET_0", 128, 2, 0.2448, 2),

    # -- distinct_bytes >= 3 and BELOW the old 1.0-bit floor: the false alarms
    #    the retune removed. mbedtls TLS12 pad 256 (0.0521) is the lowest bits
    #    value measured that still gave precision 1.0. The first four also sit
    #    under the old distinct_bytes floor of 4, which is what moved it too.
    _Cell(f"{_T12}/mbedtls/mbedtls_run_12_1",
          "CLIENT_RANDOM", 256, 3, 0.0521, 1),
    _Cell(f"{_T13}/mbedtls/mbedtls_run_13_1",
          "CLIENT_TRAFFIC_SECRET_0", 512, 5, 0.0538, 1),
    _Cell(f"{_T12}/libressl/libressl_run_12_1",
          "CLIENT_RANDOM", 512, 4, 0.0873, 1),
    _Cell(f"{_T12}/mbedtls/mbedtls_run_12_1",
          "CLIENT_RANDOM", 128, 3, 0.1161, 1),
    _Cell(f"{_T12}/libressl/libressl_run_12_1",
          "CLIENT_RANDOM", 64, 3, 0.1956, 1),
    _Cell(f"{_T13}/rustls/rustls_run_13_1",
          "CLIENT_TRAFFIC_SECRET_0", 512, 42, 0.6054, 1),
    # The cell the whole defect was reported on.
    _Cell(f"{_T12}/openssl/openssl_run_12_1",
          "CLIENT_RANDOM", 128, 17, 0.6502, 1),
    _Cell(f"{_T12}/botanssl/botanssl_run_12_1",
          "CLIENT_RANDOM", 256, 47, 0.8936, 1),

    # -- selective and above the old floor too: unaffected by the retune, kept
    #    so a future change that only probes the boundary still sees the far end.
    _Cell(f"{_T12}/openssl/openssl_run_12_1",
          "CLIENT_RANDOM", 256, 38, 1.2597, 1),
    _Cell(f"{_T13}/gotls/gotls_run_13_1",
          "CLIENT_TRAFFIC_SECRET_0", 256, 172, 6.7383, 1),
)

#: The run every other fact in this family is anchored to.
_ANCHOR_RUN = f"{_T12}/openssl/openssl_run_12_1"

#: Cells whose emitted pattern libyara reports ZERO matches for, even in the
#: dump the bytes were read from. NOT a selectivity result -- a yara-python
#: 4.5.3/4.5.4 regression of ``YR_RE_SCAN_LIMIT`` from 4096 to 1024. They are
#: excluded from the calibration and characterised on their own below.
_ENGINE_LIMIT_CELLS = (
    (f"{_T12}/openssl/openssl_run_12_1", "CLIENT_RANDOM", 512, 1072),
    (f"{_T13}/gnutls/gnutls_run_13_1",
     "CLIENT_HANDSHAKE_TRAFFIC_SECRET", 512, 1056),
)


def _corpus_root() -> Path:
    from tests.fixtures.tls_ground_truth import tls_dumps_dir

    return Path(tls_dumps_dir())


def _resolve(run: str, nss: str) -> tuple[list[str], str]:
    """Dumps + key-log line for one run, or ``skip`` if that run is absent.

    Per-CELL skipping rather than per-module: the corpus is machine-local and a
    developer may hold only some libraries. A cell that cannot be measured must
    not be silently treated as passing, and must not take the others down.
    """
    run_dir = _corpus_root() / run
    dumps = sorted(run_dir.glob("*.dump"))
    keylog = run_dir / "keylog.csv"
    if len(dumps) < 2 or not keylog.is_file():
        pytest.skip(f"run not present (or single-dump): {run_dir}")
    for row in keylog.read_text().strip().splitlines()[1:]:
        line = row.split(",", 1)[1].strip()
        if line.split()[:1] == [nss]:
            return [str(p) for p in dumps], line
    pytest.skip(f"no {nss} row in {keylog}")


def _emit(run: str, nss: str, pad: int) -> dict:
    paths, line = _resolve(run, nss)
    return export_key_pattern(
        dump_paths=paths, keylog_line=line, context=pad, fmt="yara",
        name=f"cal_{run.rsplit('/', 1)[-1]}_{pad}")


def _distinctiveness(payload: dict) -> dict:
    """Rebuild the gate's input from the PUBLISHED pattern.

    Read from the pattern rather than out of the diagnostic's ``details``,
    because ``details`` exists only when the gate fires -- rebuilding is what
    lets one table row assert the numbers for a cell that must stay QUIET. It
    goes through the same ``anchor_distinctiveness`` the producer calls, on the
    same two inputs, so the two cannot disagree.
    """
    tokens = payload["pattern"]["wildcard_pattern"].split()
    reference = bytes.fromhex(payload["pattern"]["hex_pattern"].replace(" ", ""))
    return PatternGenerator.anchor_distinctiveness(
        reference, [t != "??" for t in tokens])


def _fires(payload: dict) -> bool:
    return KEY_PATTERN_DEGENERATE_ANCHORS_CODE in {
        d["code"] for d in payload["diagnostics"]}


# --------------------------------------------------------------------------- #
# (a) the constants themselves -- corpus-free, so they are guarded everywhere
# --------------------------------------------------------------------------- #

def test_the_constants_are_the_calibrated_values():
    """A bare pin, so moving a constant fails HERE first, with the reason.

    Not a tautology: these two numbers are the conclusion of a 99-cell
    measurement, and the point of the module docstring is that they were once
    set by reasoning instead. If this fails, read that docstring before editing
    it -- and re-run the sweep rather than nudging the number.
    """
    assert KEY_PATTERN_MIN_ANCHOR_BYTES == 3, (
        "3, measured on both sides: distinct_bytes == 2 fires 2-6 times per "
        "dump (TLS13 libressl pads 64/128) while == 3 fires exactly once in "
        "five cells across mbedtls and libressl. Not 4 -- that warned about "
        "six measured precision-1.0 rules. Not 2 -- that goes silent on the "
        "two imprecise cells a narrower sweep never saw."
    )
    assert KEY_PATTERN_MIN_ANCHOR_BITS == 0.0, (
        "0.0 RETIRES the bits clause rather than tuning it: failing cells span "
        "[0.0, 0.2623] bits/byte and passing ones span [0.0521, 6.7383], so "
        "the ranges overlap and no floor of any value separates them."
    )


def test_shannon_bits_is_not_a_predictor_because_the_ranges_overlap():
    """The refutation, as arithmetic on the measured table.

    This is the finding that decides the SHAPE of the gate, so it is asserted
    without needing the corpus: two cells in ``_CALIBRATION`` are unselective at
    a HIGHER bits/byte than a cell that is perfect. One inversion is enough --
    a monotone threshold cannot separate a set that is not ordered.
    """
    bad = [c for c in _CALIBRATION if c.unselective]
    good = [c for c in _CALIBRATION if not c.unselective]

    worst_pass = min(c.bits for c in good)
    best_fail = max(c.bits for c in bad)
    assert best_fail > worst_pass, (
        f"expected the bits ranges to OVERLAP; failing max {best_fail} vs "
        f"passing min {worst_pass}")

    # Name the offenders, so a future corpus change shows up as a changed
    # explanation rather than a changed truth value.
    inverted = [(c.run.rsplit("/", 1)[-1], c.pad, c.bits)
                for c in bad if c.bits > worst_pass]
    assert len(inverted) == 2, inverted
    assert all(c.distinct_bytes == 2 for c in bad if c.bits > worst_pass)

    # distinct_bytes, by contrast, DOES order them -- with a gap the floor sits
    # in. This is the positive half of the same finding.
    assert max(c.distinct_bytes for c in bad) == 2
    assert min(c.distinct_bytes for c in good) == 3
    assert (max(c.distinct_bytes for c in bad)
            < KEY_PATTERN_MIN_ANCHOR_BYTES
            <= min(c.distinct_bytes for c in good))


def test_no_fixed_positive_bits_floor_can_express_more_than_one_value():
    """WHY the floor is 0.0 with ``<=`` and not some small positive number.

    Even setting the overlap above aside, a positive constant could not mean
    "more than one distinct value". ``shannon_bits`` is per-byte entropy over
    ``static_bytes`` anchor bytes, so the least a NON-degenerate anchor can
    carry is the two-value split where one value appears once:
    ``H = -(p log2 p + q log2 q)`` with ``q = 1/S``. That minimum shrinks
    towards 0 as the anchor grows, while ``--context`` is unbounded (the
    producer rejects only a NEGATIVE context) -- so for every positive floor
    there is a window width at which it fires on a legitimate two-value anchor.

    Corpus-free on purpose: this is arithmetic, so it guards the constant on a
    machine with no dumps at all.
    """
    def min_positive_bits(static_bytes: int) -> float:
        p, q = (static_bytes - 1) / static_bytes, 1 / static_bytes
        return -(p * math.log2(p) + q * math.log2(q))

    # Real anchor sizes from the sweep, smallest window to largest.
    for static_bytes, expected in {71: 0.1068, 128: 0.0659,
                                   385: 0.0261, 1072: 0.0107}.items():
        assert min_positive_bits(static_bytes) == pytest.approx(
            expected, abs=5e-4), static_bytes

    # The floor spans a full order of magnitude across ONE emitter's own pad
    # range, which is the point: it is not a property a constant can capture.
    assert min_positive_bits(71) > 9 * min_positive_bits(1072)

    # For each candidate a reader might reach for, the anchor width at which it
    # starts lying -- computed, not asserted from intuition.
    breaks_at = {}
    for candidate in (0.05, 0.02, 0.01, 0.001):
        size = next(s for s in range(8, 2_000_000)
                    if min_positive_bits(s) < candidate)
        breaks_at[candidate] = size
        assert min_positive_bits(size) < candidate <= min_positive_bits(size - 1)
    # 0.05 already lies inside a pad-128 window and 0.01 needs only ~pad 600.
    # Both are ordinary values an analyst types, which is what makes "pick
    # something small and positive" unsound rather than merely imprecise.
    assert breaks_at[0.05] <= 304, breaks_at
    assert breaks_at[0.01] <= 1_300, breaks_at
    assert breaks_at[0.05] < breaks_at[0.02] < breaks_at[0.01] < breaks_at[0.001]

    # 0.0 with ``<=`` is exact and scale-free: entropy is 0.0 if and only if
    # every anchor byte carries the same value.
    assert PatternGenerator.anchor_distinctiveness(
        bytes(64), [True] * 64)["shannon_bits"] == 0.0
    assert PatternGenerator.anchor_distinctiveness(
        bytes(63) + b"\x01", [True] * 64)["shannon_bits"] > 0.0


def test_the_gate_classifies_every_pinned_cell_correctly():
    """The confusion matrix, evaluated on the table without touching a dump.

    Zero false alarms is the property being defended -- the defect was a WARNING
    ON A PERFECT RULE -- so it is asserted as a count, and the retired
    thresholds are run through the same loop to show what they would score.
    """
    def confusion(min_bytes: int, min_bits: float, inclusive: bool) -> dict:
        out = {"true": 0, "false_alarm": 0, "missed": 0, "quiet": 0}
        for cell in _CALIBRATION:
            fires = cell.distinct_bytes < min_bytes or (
                cell.bits <= min_bits if inclusive else cell.bits < min_bits)
            if fires and cell.unselective:
                out["true"] += 1
            elif fires:
                out["false_alarm"] += 1
            elif cell.unselective:
                out["missed"] += 1
            else:
                out["quiet"] += 1
        return out

    live = confusion(KEY_PATTERN_MIN_ANCHOR_BYTES,
                     KEY_PATTERN_MIN_ANCHOR_BITS, inclusive=True)
    assert live == {"true": 10, "false_alarm": 0, "missed": 0, "quiet": 10}, live

    # The retired gate: it warns about eight of the ten perfect rules here.
    retired = confusion(4, 1.0, inclusive=False)
    assert retired["true"] == 10
    assert retired["false_alarm"] == 8, retired
    # And the floor of 2 a narrower sweep would have justified: no false alarm,
    # but it misses both distinct_bytes == 2 cells.
    too_low = confusion(2, 0.0, inclusive=True)
    assert too_low["false_alarm"] == 0 and too_low["missed"] == 2, too_low


# --------------------------------------------------------------------------- #
# (b) the measured table, re-derived through the real emitter
# --------------------------------------------------------------------------- #

@pytest.mark.requires_dataset
@pytest.mark.parametrize(
    "cell", _CALIBRATION,
    ids=[f"{c.run.rsplit('/', 1)[-1]}-pad{c.pad}" for c in _CALIBRATION])
def test_each_calibration_cell_still_measures_what_it_did(cell: _Cell):
    """``distinct_bytes`` / ``shannon_bits`` / warn-or-not, per measured cell.

    Emit only -- no scanning -- so all twenty cells together cost under a
    second and stay in the default run. Any drift in the emitter's windowing,
    masking or anchor accounting lands here as a concrete number, and any change
    to the two constants flips a ``fires`` expectation.
    """
    payload = _emit(cell.run, cell.nss, cell.pad)
    d = _distinctiveness(payload)

    assert d["distinct_bytes"] == cell.distinct_bytes, (
        f"{cell.run} pad {cell.pad}: anchor distinct byte values moved")
    assert d["shannon_bits"] == pytest.approx(cell.bits, abs=5e-5), (
        f"{cell.run} pad {cell.pad}: anchor entropy moved")

    # The gate, as the operator sees it. An unselective cell MUST warn; a
    # selective one MUST NOT -- the false alarm is the defect this fixed.
    assert _fires(payload) is cell.unselective, (
        f"{cell.run} pad {cell.pad}: distinct_bytes={d['distinct_bytes']}, "
        f"bits={d['shannon_bits']}, measured {cell.firings} firing(s)/dump -- "
        f"warning {'missing' if cell.unselective else 'is a FALSE ALARM'}")

    # Still a WARNING that returns the pattern, never a refusal.
    assert payload["pattern"]["length"] > 0
    if cell.unselective:
        warning = next(x for x in payload["diagnostics"]
                       if x["code"] == KEY_PATTERN_DEGENERATE_ANCHORS_CODE)
        assert warning["severity"] == "warning"
        # The message must not hand out a bare selectivity figure any more: the
        # same rule on the same dump is 825,779 under libyara and 5,311 under
        # vol3's non-overlapping RegExScanner, so a number with no engine beside
        # it cannot be reconciled by whoever reads it. It points at the
        # count-only scan instead, which measures the reader's OWN rule.
        assert "libyara" in warning["message"]
        assert "RegExScanner" in warning["message"]
        assert "--count-only" in warning["message"]
        assert "5,311" not in warning["message"].replace(
            "5,311 times under Volatility3's non-overlapping RegExScanner", "")


@pytest.mark.requires_dataset
def test_the_separation_the_thresholds_were_drawn_from_still_holds():
    """The SHAPE of the calibration, re-derived from the corpus, not the table.

    Individual cells are checked above against recorded numbers; this asserts
    the property that made a threshold choosable at all, over every cell whose
    run resolves:

    * ``distinct_bytes <= 2`` on every unselective cell and ``>= 3`` on every
      selective one -- so a floor of 3 separates them exactly;
    * the bits ranges OVERLAP, so no bits floor could.

    If a future corpus produces an unselective rule with three or more distinct
    anchor values, THIS is the test that has to fail, because that observation
    invalidates the threshold rather than merely moving it.
    """
    bad, good = [], []
    for cell in _CALIBRATION:
        if len(sorted((_corpus_root() / cell.run).glob("*.dump"))) < 2:
            continue
        d = _distinctiveness(_emit(cell.run, cell.nss, cell.pad))
        (bad if cell.unselective else good).append((cell, d))

    if not bad or not good:
        pytest.skip("need at least one cell on each side of the separation")

    assert max(d["distinct_bytes"] for _, d in bad) <= 2, [
        (c.run, c.pad, d["distinct_bytes"]) for c, d in bad]
    assert min(d["distinct_bytes"] for _, d in good) >= 3, [
        (c.run, c.pad, d["distinct_bytes"]) for c, d in good]
    # The floor sits in the gap, and the gap is closed on both sides -- unlike
    # the retired 4, which had measured successes below it.
    assert (max(d["distinct_bytes"] for _, d in bad)
            < KEY_PATTERN_MIN_ANCHOR_BYTES
            <= min(d["distinct_bytes"] for _, d in good))

    # ... and the bits axis stays refuted against freshly measured values.
    assert (max(d["shannon_bits"] for _, d in bad)
            > min(d["shannon_bits"] for _, d in good))
    # The retired 1.0-bit floor sits above measured precision-1.0 rules, which
    # is exactly how it came to cry wolf. Asserted so nobody restores it
    # thinking the two are interchangeable.
    assert min(d["shannon_bits"] for _, d in good) < 1.0


# --------------------------------------------------------------------------- #
# (c) the loop closed again: the census the thresholds were drawn from
# --------------------------------------------------------------------------- #

# The only tests here that SCAN, and therefore the only ones marked `slow`:
# libyara enumerates every one of the ~826k pad-64 matches before it can return
# a count, so `include_matches=False` bounds the OUTPUT (~559,000x smaller) and
# not the time. Measured ~30 s for the pair. `addopts` deselects `slow`;
# `pytest -m requires_dataset` and `make test-corpus` bring it back.
@pytest.mark.slow
@pytest.mark.requires_dataset
@pytest.mark.parametrize("cell", [
    # One from each side, on the run every other fact is anchored to: the two
    # pads whose only difference is 64 bytes of context, and which the OLD gate
    # could not tell apart.
    next(c for c in _CALIBRATION if c.run == _ANCHOR_RUN and c.pad == 64),
    next(c for c in _CALIBRATION if c.run == _ANCHOR_RUN and c.pad == 128),
], ids=["pad64-non-detector", "pad128-perfect"])
def test_the_census_behind_the_calibration_is_re_measurable(cell: _Cell):
    """Re-derive the firing count with the real count-only scan.

    Orders of magnitude, not exact counts: the two abort dumps already disagree
    (825,779 vs 825,500) and any libyara version would move them again. "Five
    orders of magnitude apart" is the property of the data; 825,779 is not.
    """
    paths, line = _resolve(cell.run, cell.nss)
    payload = export_key_pattern(
        dump_paths=paths, keylog_line=line, context=cell.pad, fmt="yara",
        name=f"census_pad{cell.pad}")

    census = scan_yara_rule(dump_paths=paths, rule_source=payload["content"],
                            max_matches=None, include_matches=False)
    assert census["verdict"] == "matched"
    assert census["counts"]["dumps_unreadable"] == 0
    # Uncapped: no row may be a floor, or "the census" is not a census.
    assert census["counts"]["dumps_truncated"] == 0
    counts = [row["scan"]["match_count"] for row in census["dumps"]]

    if cell.unselective:
        assert min(counts) > 100_000, counts
        assert _fires(payload), "a rule firing >100k times per dump must warn"
    else:
        assert counts == [1] * len(counts), counts
        assert not _fires(payload), (
            "a rule firing exactly once per dump must NOT warn -- that false "
            "alarm is the defect this calibration fixed")


@pytest.mark.slow
@pytest.mark.requires_dataset
@pytest.mark.parametrize("run,nss,pad,length", _ENGINE_LIMIT_CELLS,
                         ids=["openssl-1072B", "gnutls-1056B"])
def test_the_excluded_cells_are_an_engine_limit_not_a_selectivity_result(
        run: str, nss: str, pad: int, length: int):
    """Seven pad-512 cells match ZERO times. That is libyara, not the emitter.

    ``YR_RE_SCAN_LIMIT`` is **1024** in yara-python 4.5.3/4.5.4 (an upstream
    regression of the 4096 that held before and returns in 4.5.5). A hex string
    containing ``??`` compiles to a regexp; libyara picks one atom and verifies
    backward and forward from it with each direction clamped to that limit, then
    silently reports no match on overrun. So a rule matches only while both
    ``atom_offset`` and ``pattern_length - atom_offset`` stay under 1024 -- and
    the atom's position is content-chosen, which is why pad 512 works on wolfssl
    (its atom lands at ~496) and fails here.

    Asserted rather than skipped, because the underlying miss is INVISIBLE to
    libyara's own reporting: the emitted pattern's static bytes are
    byte-identical to the dump at ``region.offset`` (checked below), yet
    libyara returns zero matches with no error of any kind. Recall 0 is worse
    than a false-positive storm, which is why these cells are excluded from the
    calibration instead of counted as "selective".

    What CHANGED, and it is the reason the verdict below is no longer ``clean``:
    the miss is now detected and named. ``engine.yara_scan.regexp_scan_limit``
    probes the installed libyara for the limit (rather than hardcoding 1024,
    which would be wrong the day a fixed release lands), ``scan_yara_rule``
    refuses to call a rule it cannot verify ``clean`` and reports
    ``inconclusive`` with ``analysis.yara_scan.pattern_over_scan_limit``, and
    the emitters warn with ``export.pattern.over_scan_limit`` BEFORE a dead
    artifact is written. The "no emit-time signal sees it" that this docstring
    used to record was accurate when the cells were characterised and is no
    longer true; ``tests/test_libyara_scan_limit.py`` is the guard, and this
    test is now the real-corpus half of the same claim. The MEASUREMENT here is
    untouched -- same pads, same lengths, same zero match count.

    If this test starts failing, yara-python was upgraded past 4.5.4 and the
    reachable span went back to 4096. That is good news: widen the pattern
    length in the parameters to re-probe the new ceiling, do not delete the
    test -- ``context`` is unbounded, so the same class of false negative
    returns above 4096.
    """
    paths, line = _resolve(run, nss)
    payload = export_key_pattern(
        dump_paths=paths, keylog_line=line, context=pad, fmt="yara",
        name=f"limit_pad{pad}")
    assert payload["pattern"]["length"] == length

    # The bytes ARE there: every static position matches the source dump, so
    # nothing is wrong with the rule the emitter published.
    tokens = payload["pattern"]["wildcard_pattern"].split()
    reference = bytes.fromhex(payload["pattern"]["hex_pattern"].replace(" ", ""))
    offset = payload["region"]["offset"]
    raw = Path(paths[0]).read_bytes()[offset:offset + len(reference)]
    mismatched = [i for i, (t, a, b) in enumerate(zip(tokens, reference, raw))
                  if t != "??" and a != b]
    assert mismatched == [], len(mismatched)

    census = scan_yara_rule(dump_paths=paths, rule_source=payload["content"],
                            max_matches=None, include_matches=False)
    assert census["counts"]["matches_total"] == 0, "expected the engine miss"
    # NOT "clean" -- that was the false all-clear. The zeros are real and are
    # now reported as UNPROVEN, for a named reason, over dumps that were read
    # end to end with no timeout and no error.
    assert census["verdict"] == "inconclusive"
    assert census["counts"]["dumps_clean"] == 0
    assert census["rules"]["exceeds_scan_limit"] is True
    assert census["rules"]["widest_pattern_length"] == length
    assert "analysis.yara_scan.pattern_over_scan_limit" in [
        d["code"] for d in census["diagnostics"]]
    assert census["counts"]["dumps_unreadable"] == 0
    assert not any(row["scan"]["timed_out"] for row in census["dumps"])

    # The EMIT-time signal, on the real corpus: the analyst is warned before
    # this rule is ever written to disk, which is the only signal that arrives
    # in time to matter.
    assert "export.pattern.over_scan_limit" in [
        d["code"] for d in payload["diagnostics"]]

    # Halving the pad brings the pattern back under the limit and the rule back
    # to life -- the proof that length, not content, is what broke it.
    narrower = export_key_pattern(
        dump_paths=paths, keylog_line=line, context=pad // 2, fmt="yara",
        name=f"limit_pad{pad // 2}")
    assert narrower["pattern"]["length"] < 1024
    revived = scan_yara_rule(dump_paths=paths, rule_source=narrower["content"],
                             max_matches=None, include_matches=False)
    assert revived["counts"]["matches_total"] > 0
