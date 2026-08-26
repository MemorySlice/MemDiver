"""Memory + wall-time bench for the auto-floor candidate-enumeration path.

Answers one question with numbers instead of intuition: at the ~700k-candidate
scale a stride-1 sweep reaches on a realistic high-entropy slab, how much
memory and how much time does :func:`memdiver.engine.auto_floor.run_auto_floor`
spend BEFORE the oracle sweep starts, and how large does the sweep's
duplicate-suppression ``seen`` set get?

The four suspected terms, in call order:

  1. ``floor_policy.enumerate_candidates`` materialises a Python
     ``List[Tuple[int, int]]`` of every candidate.
  2. ``floor_policy.enumerate_maximal`` converts that list to two int64 arrays
     and (on the first pass) runs ``window_variance`` over all of them.
  3. ``auto_floor._maximal_candidates`` calls ``enumerate_maximal`` TWICE
     (min_variance=0.0, then DEFAULT_FLOOR) and builds a ``set`` of the second.
  4. The best-first sweep keeps ``seen: set[bytes]`` of every distinct window
     for the whole sweep.

Measurement points (each records wall_ms, tracemalloc current/peak, ru_maxrss):

  1. ``entry``                  -- baseline, synthetic case already built
  2. ``enumerate_maximal_phi0`` -- after the first pass (min_variance=0.0)
  3. ``enumerate_maximal_dflt`` -- after the second pass (compute_wvar=False);
                                   isolates the marginal cost of pass two
  4. ``default_set``            -- after ``set(zip(...))`` is built
  5. ``sweep_done``             -- after the sweep loop exits; isolates ``seen``

===========================================================================
DECISION RULE -- fixed BEFORE the first measurement, applied verbatim after.
===========================================================================

  (M) OPTIMISE if the peak RSS attributable to steps 2-5, i.e.
      ``ru_maxrss(step 5) - ru_maxrss(step 1)``, exceeds 500 MB.

  (T) OPTIMISE if the wall time of steps 2-4 (all enumeration work, i.e.
      everything before the sweep) exceeds 10% of the total
      ``run_auto_floor`` wall time.

  If NEITHER fires, nothing in ``engine/`` changes: the bench lands together
  with a ``@pytest.mark.slow`` regression test pinning the measured ceiling.

  If (M) or (T) fires, only the term the measurement blames is fixed, in
  ascending risk: (a) ``default_set`` -> sorted int64 array + searchsorted,
  (b) a streaming ``iter_candidates()`` sibling fed to ``np.fromiter`` with a
  ``count_region_grid`` pre-count, (c) sharing the entropy profile between the
  two ``reduce_search_space`` calls. ``seen`` is NEVER hashed or bounded (a
  collision silently drops a real candidate) and the double enumeration is
  NEVER removed (it is required for bit-exact density-gate parity).

===========================================================================
MEASURED 2026-08-25 (macOS/arm64, CPython 3.11, 700k candidates, cold run,
``--no-tracemalloc`` for time, traced for the Python-object columns)
===========================================================================

  (M) did NOT fire.  RSS growth steps 2-5 = 392.7 MB, under the 500 MB bar.
  (T) FIRED.         Steps 2-4 = 573 ms of 1260 ms = 45.5% with the null
                     oracle; 17.6% against the real AES-GCM reject path
                     (2.8 us/candidate, measured) -- still over 10%.

  Blame, from the inner attribution:
      enumerate_candidates + list->array   ~286 ms, +238 MB RSS at step 2
      default_set = set(zip(...))          ~104 ms, ~85 MB of Python tuples
      compute_entropy_profile (run TWICE)  ~158 ms

  All three sanctioned fixes were therefore applied, in the stated ascending
  risk order:
      1. ``floor_policy.PairMembership``  -- default_set is a sorted int64
         array + searchsorted instead of a tuple set (lossless encoding, so
         membership answers are bit-identical).
      2. ``floor_policy.iter_candidates`` / ``count_candidates`` -- the arrays
         are filled by ``np.fromiter(count=...)`` straight from the generator;
         the eager ``enumerate_candidates`` is KEPT and now delegates to the
         streaming form.
      3. ``reduce_search_space(entropy_cache=...)`` -- opt-in, caller-owned;
         ``auto_floor._maximal_candidates`` hands one dict to both passes so
         the min_variance-independent entropy profile is built once.

  After (same box, same case):
      steps 2-4 wall        573 ms  ->  337 ms   (-41%)
      step 4 (default_set)  104 ms  ->   23 ms   (-78%)
      total RSS growth    392.7 MB  -> 289.7 MB  (-26%)
      step 4 live objects  106.8 MB ->  21.5 MB  (-80%)
      step 3 peak objects  156.6 MB ->  37.8 MB  (-76%)
      sweep live peak      187.3 MB -> 102.0 MB  (-46%; the residue is `seen`)
      (T) vs real oracle     17.6%  ->   10.4%

  (T) is still marginally over its bar, and that is where this stops: the
  sanctioned fix list is exhausted, and the remaining terms are the entropy
  profile's own list-of-tuples inside ``core.entropy`` and ``seen`` itself,
  which must NOT be hashed or bounded. Note also that rule (T) compares
  enumeration against a sweep whose per-candidate cost is set by the ORACLE;
  at any oracle slower than ~4 us/candidate the ratio clears 10% on its own
  with no further code change.

  ``tests/test_benchmarks.py`` pins these numbers as ``@pytest.mark.slow``
  per-candidate ceilings.

===========================================================================

Two caveats the numbers must be read with:

* ``tracemalloc`` only sees the CPython allocator, so numpy buffers (the int64
  offset/size arrays, the variance array) are invisible to it. They do show up
  in ``ru_maxrss``. Read tracemalloc for the Python-object terms (the pair
  list, ``default_set``, ``seen``) and ru_maxrss for the total.
* ``ru_maxrss`` is a process high-water mark: it never decreases, so per-step
  deltas attribute GROWTH, not live size. It is reported in BYTES on macOS and
  in KILOBYTES on Linux; :func:`_rss_bytes` normalises both to bytes.

Usage::

    python tools/bench_auto_floor_memory.py                  # ~700k candidates
    python tools/bench_auto_floor_memory.py --candidates 200000
    python tools/bench_auto_floor_memory.py --json-out out.json
    python tools/bench_auto_floor_memory.py --self-test      # no measurement

The input is synthetic and dataset-free, so the bench runs on any clone.
"""

from __future__ import annotations

import argparse
import json
import logging
import platform
import sys
import time
import tracemalloc
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Callable, List, Optional, Tuple

logger = logging.getLogger("bench_auto_floor_memory")

# Make the memdiver package importable regardless of cwd.
_THIS = Path(__file__).resolve()
_PKG_ROOT = _THIS.parent.parent
if str(_PKG_ROOT) not in sys.path:
    sys.path.insert(0, str(_PKG_ROOT))

try:
    import resource as _resource
except ImportError:  # pragma: no cover - Windows
    _resource = None

import numpy as np

from memdiver.engine import auto_floor, candidate_pipeline, floor_policy

MB = 1024.0 * 1024.0

# Decision-rule constants (see module docstring; do not tune after measuring).
RULE_M_RSS_MB = 500.0
RULE_T_ENUM_FRACTION = 0.10

# Synthetic-case defaults.
DEFAULT_CANDIDATES = 700_000
DEFAULT_KEY_SIZE = 32
DEFAULT_NUM_DUMPS = 5
# The reduce chain's entropy gate defaults to 4.5 over a 32-byte window whose
# ceiling is log2(32) = 5.0; uniform random bytes sit right on that edge, which
# would shred the synthetic slab into a noisy region set. 4.0 keeps the slab
# solid so the candidate count is a controlled input, not a coin flip.
DEFAULT_ENTROPY_THRESHOLD = 4.0


# ---------------------------------------------------------------------------
# Platform-normalised RSS
# ---------------------------------------------------------------------------


def rss_unit_divisor(system: Optional[str] = None) -> int:
    """Bytes per ``ru_maxrss`` unit for ``system`` (``platform.system()``).

    macOS/Darwin reports ``ru_maxrss`` in BYTES; Linux and the BSDs report it
    in KILOBYTES. Getting this wrong is a silent 1024x error, so it is a named,
    unit-tested function rather than an inline ternary.
    """
    return 1 if (system or platform.system()) == "Darwin" else 1024


def _rss_bytes() -> Optional[float]:
    """Process high-water RSS in bytes, or None where unavailable."""
    if _resource is None:  # pragma: no cover - Windows
        return None
    raw = _resource.getrusage(_resource.RUSAGE_SELF).ru_maxrss
    return float(raw) * rss_unit_divisor()


# ---------------------------------------------------------------------------
# Data containers
# ---------------------------------------------------------------------------


@dataclass
class StepSample:
    """One instrumentation point inside ``run_auto_floor``."""

    name: str
    wall_ms: float          # cumulative, from the entry sample
    delta_ms: float         # since the previous sample
    traced_current_mb: float   # live Python-object bytes at this point
    traced_peak_mb: float      # peak Python-object bytes SINCE the prev sample
    maxrss_mb: Optional[float]      # process high-water mark
    maxrss_delta_mb: Optional[float]  # growth since the previous sample


@dataclass
class BenchResult:
    traced: bool
    oracle: str
    candidates_requested: int
    key_size: int
    stride: int
    num_dumps: int
    dump_len: int
    maximal: int
    tried: int
    verdict: str
    total_wall_ms: float
    steps: List[StepSample] = field(default_factory=list)
    # Max LIVE traced memory observed while the sweep loop was running, sampled
    # from inside the oracle. This is the only direct read on ``seen``'s size;
    # the step-5 peak also covers it but cannot separate it from the transient.
    sweep_live_peak_mb: float = 0.0
    # Accumulated wall ms per inner callee, so steps 2-4 can be attributed to a
    # specific fix instead of "enumeration is slow".
    breakdown_ms: dict = field(default_factory=dict)
    platform: str = field(default_factory=platform.system)

    def step(self, name: str) -> StepSample:
        for s in self.steps:
            if s.name == name:
                return s
        raise KeyError(name)

    # -- decision-rule inputs -------------------------------------------
    def rss_growth_mb(self) -> Optional[float]:
        """(M): ru_maxrss growth attributable to steps 2-5."""
        first, last = self.steps[0].maxrss_mb, self.steps[-1].maxrss_mb
        if first is None or last is None:
            return None
        return last - first

    def enumeration_ms(self) -> float:
        """(T): wall time of steps 2-4 (everything before the sweep)."""
        return sum(s.delta_ms for s in self.steps[1:4])

    def enumeration_fraction(self) -> float:
        return self.enumeration_ms() / self.total_wall_ms if self.total_wall_ms else 0.0


@dataclass
class Verdict:
    rule_m_fired: bool
    rule_t_fired: bool
    detail: str

    @property
    def optimise(self) -> bool:
        return self.rule_m_fired or self.rule_t_fired


@dataclass
class SyntheticCase:
    """Dataset-free auto-floor input sized to a target candidate count."""

    variance: np.ndarray
    reference_data: bytes
    num_dumps: int
    reduce_kwargs: dict
    key_sizes: Tuple[int, ...]
    stride: int


# ---------------------------------------------------------------------------
# Synthetic input
# ---------------------------------------------------------------------------


def build_case(
    candidates: int = DEFAULT_CANDIDATES,
    *,
    key_size: int = DEFAULT_KEY_SIZE,
    num_dumps: int = DEFAULT_NUM_DUMPS,
    entropy_threshold: float = DEFAULT_ENTROPY_THRESHOLD,
    seed: int = 20260825,
) -> SyntheticCase:
    """A high-entropy, high-variance slab yielding ~``candidates`` windows.

    At ``stride=1`` with a single key size, a solid region of length ``L``
    yields ``L - key_size + 1`` candidates, so the slab is sized directly from
    the target. Every byte is given variance above ``DEFAULT_FLOOR`` on
    purpose: that makes the DEFAULT_FLOOR pass keep the whole slab, which is
    the WORST CASE for ``default_set`` and therefore the right case to test a
    memory ceiling against.
    """
    dump_len = int(candidates) + int(key_size) - 1
    rng = np.random.default_rng(seed)
    reference_data = rng.integers(0, 256, size=dump_len, dtype=np.uint8).tobytes()
    # Centre on SIGMA_K2 (the full-entropy ceiling) with enough spread that the
    # window-variance ranking has something to sort, but never below the floor.
    variance = (auto_floor.SIGMA_K2 * 0.9
                + rng.random(dump_len) * auto_floor.SIGMA_K2 * 0.1)
    return SyntheticCase(
        variance=variance.astype(np.float64),
        reference_data=reference_data,
        num_dumps=num_dumps,
        reduce_kwargs={"entropy_threshold": entropy_threshold},
        key_sizes=(key_size,),
        stride=1,
    )


# ---------------------------------------------------------------------------
# Oracles
# ---------------------------------------------------------------------------

ORACLE_CHOICES = ("null", "aesgcm")


def make_oracle(kind: str) -> Callable[[bytes], bool]:
    """An always-rejecting oracle of the requested per-candidate cost.

    ``null`` is a bare ``return False`` -- it isolates the engine's own sweep
    overhead but makes the sweep ~4x cheaper than production, which INFLATES
    the enumeration share that rule (T) measures. ``aesgcm`` runs the repo's
    real :class:`engine.verification.AesGcmVerifier` reject path, so rule (T)
    can also be read against the ratio a real run actually sees.
    """
    if kind == "null":
        return lambda _window: False
    if kind == "aesgcm":
        from memdiver.engine.verification import AesGcmVerifier
        verifier = AesGcmVerifier()
        # A ciphertext under a key that is NOT in the dump: every candidate
        # takes the tag-rejection path, which is the sweep's hot path.
        ciphertext = verifier.create_ciphertext(bytes(range(32)), b"A" * 64, b"")

        def aesgcm_oracle(window: bytes) -> bool:
            return bool(verifier.verify(window, ciphertext, b"", None))

        return aesgcm_oracle
    raise ValueError(f"unknown oracle {kind!r}; choose from {ORACLE_CHOICES}")


# ---------------------------------------------------------------------------
# Instrumentation
# ---------------------------------------------------------------------------


class _Recorder:
    """Collects :class:`StepSample` points against a single time/memory origin."""

    def __init__(self, traced: bool = True) -> None:
        self.steps: List[StepSample] = []
        self.traced = traced
        self._t0 = time.perf_counter_ns()
        self._prev_ms = 0.0
        self._prev_rss: Optional[float] = None

    def snap(self, name: str) -> None:
        cur, peak = tracemalloc.get_traced_memory() if self.traced else (0, 0)
        rss = _rss_bytes()
        wall_ms = (time.perf_counter_ns() - self._t0) / 1e6
        self.steps.append(StepSample(
            name=name,
            wall_ms=wall_ms,
            delta_ms=wall_ms - self._prev_ms,
            traced_current_mb=cur / MB,
            traced_peak_mb=peak / MB,
            maxrss_mb=None if rss is None else rss / MB,
            maxrss_delta_mb=(None if rss is None or self._prev_rss is None
                             else (rss - self._prev_rss) / MB),
        ))
        self._prev_ms = wall_ms
        self._prev_rss = rss
        # Peak is reported PER STEP, so rearm it for the next interval.
        if self.traced:
            tracemalloc.reset_peak()


def _timed(name: str, fn, sink: dict):
    """Wrap ``fn`` so its accumulated wall ms lands in ``sink[name]``."""

    def wrapper(*args, **kwargs):
        t0 = time.perf_counter_ns()
        try:
            return fn(*args, **kwargs)
        finally:
            sink[name] = sink.get(name, 0.0) + (time.perf_counter_ns() - t0) / 1e6

    return wrapper


def measure(case: SyntheticCase, *, sample_every: int = 4096,
            traced: bool = True, oracle_kind: str = "null") -> BenchResult:
    """Run ``run_auto_floor`` on ``case`` with the five points instrumented.

    ``engine/auto_floor.py`` is NOT modified: the two enumeration points are
    captured by wrapping ``floor_policy.enumerate_maximal`` (which auto_floor
    resolves through the module object at call time) and the ``default_set``
    point by wrapping ``auto_floor._maximal_candidates``. Both are restored in
    a ``finally``. The sweep point is taken after ``run_auto_floor`` returns --
    ``seen`` is local to it, so its size is read via the per-step tracemalloc
    peak plus live sampling from inside the oracle.

    ``traced=False`` skips tracemalloc entirely. tracemalloc taxes every
    CPython allocation, and the enumeration steps are allocation-dense (700k
    tuples/ints) while the sweep is allocation-light, so the TIME split must be
    confirmed untraced before rule (T) is believed.
    """
    started_here = traced and not tracemalloc.is_tracing()
    if started_here:
        tracemalloc.start()

    rec = _Recorder(traced=traced)
    state = {"calls": 0, "sweep_live_peak": 0.0, "enum_calls": 0}
    breakdown: dict = {}

    orig_enumerate_maximal = floor_policy.enumerate_maximal
    orig_maximal_candidates = auto_floor._maximal_candidates
    orig_reduce = floor_policy.reduce_search_space
    orig_enumerate_candidates = floor_policy.enumerate_candidates
    orig_window_variance = floor_policy.window_variance
    orig_entropy_profile = candidate_pipeline.compute_entropy_profile

    def wrapped_enumerate_maximal(*args, **kwargs):
        out = orig_enumerate_maximal(*args, **kwargs)
        state["enum_calls"] += 1
        rec.snap("2_enumerate_maximal_phi0" if state["enum_calls"] == 1
                 else "3_enumerate_maximal_dflt")
        return out

    def wrapped_maximal_candidates(*args, **kwargs):
        out = orig_maximal_candidates(*args, **kwargs)
        rec.snap("4_default_set")
        return out

    inner_oracle = make_oracle(oracle_kind)

    def oracle(window: bytes) -> bool:
        # Always-reject: forces the FULL sweep, which is the only run in which
        # ``seen`` reaches its true maximum.
        state["calls"] += 1
        if traced and state["calls"] % sample_every == 0:
            cur, _ = tracemalloc.get_traced_memory()
            state["sweep_live_peak"] = max(state["sweep_live_peak"], cur / MB)
        return inner_oracle(window)

    floor_policy.enumerate_maximal = wrapped_enumerate_maximal
    auto_floor._maximal_candidates = wrapped_maximal_candidates
    floor_policy.reduce_search_space = _timed("reduce_search_space", orig_reduce, breakdown)
    floor_policy.enumerate_candidates = _timed(
        "enumerate_candidates", orig_enumerate_candidates, breakdown)
    floor_policy.window_variance = _timed(
        "window_variance", orig_window_variance, breakdown)
    candidate_pipeline.compute_entropy_profile = _timed(
        "compute_entropy_profile", orig_entropy_profile, breakdown)
    try:
        rec.snap("1_entry")
        result = auto_floor.run_auto_floor(
            case.variance, case.reference_data, case.num_dumps, oracle,
            reduce_kwargs=dict(case.reduce_kwargs),
            key_sizes=case.key_sizes,
            stride=case.stride,
            self_test_trials=2,
        )
        rec.snap("5_sweep_done")
    finally:
        floor_policy.enumerate_maximal = orig_enumerate_maximal
        auto_floor._maximal_candidates = orig_maximal_candidates
        floor_policy.reduce_search_space = orig_reduce
        floor_policy.enumerate_candidates = orig_enumerate_candidates
        floor_policy.window_variance = orig_window_variance
        candidate_pipeline.compute_entropy_profile = orig_entropy_profile
        if started_here:
            tracemalloc.stop()

    return BenchResult(
        traced=traced,
        oracle=oracle_kind,
        candidates_requested=len(case.reference_data) - case.key_sizes[0] + 1,
        key_size=case.key_sizes[0],
        stride=case.stride,
        num_dumps=case.num_dumps,
        dump_len=len(case.reference_data),
        maximal=int(result.maximal_candidates),
        tried=int(result.tried),
        verdict=result.verdict,
        total_wall_ms=rec.steps[-1].wall_ms - rec.steps[0].wall_ms,
        steps=rec.steps,
        sweep_live_peak_mb=float(state["sweep_live_peak"]),
        breakdown_ms=dict(breakdown),
    )


# ---------------------------------------------------------------------------
# Decision rule
# ---------------------------------------------------------------------------


def decide(result: BenchResult) -> Verdict:
    """Apply the module-docstring decision rule verbatim."""
    rss_growth = result.rss_growth_mb()
    frac = result.enumeration_fraction()
    m_fired = rss_growth is not None and rss_growth > RULE_M_RSS_MB
    t_fired = frac > RULE_T_ENUM_FRACTION
    rss_txt = "unavailable" if rss_growth is None else f"{rss_growth:.1f} MB"
    detail = (
        f"(M) RSS growth steps 2-5 = {rss_txt} "
        f"(threshold {RULE_M_RSS_MB:.0f} MB) -> {'FIRED' if m_fired else 'clear'}\n"
        f"(T) enumeration steps 2-4 = {result.enumeration_ms():.1f} ms of "
        f"{result.total_wall_ms:.1f} ms = {frac * 100:.2f}% "
        f"(threshold {RULE_T_ENUM_FRACTION * 100:.0f}%) -> "
        f"{'FIRED' if t_fired else 'clear'}"
    )
    return Verdict(rule_m_fired=m_fired, rule_t_fired=t_fired, detail=detail)


# ---------------------------------------------------------------------------
# Rendering
# ---------------------------------------------------------------------------


def render_terminal(result: BenchResult, verdict: Verdict) -> str:
    header = ("Step", "wall ms", "Δ ms", "traced cur MB",
              "traced peak MB", "maxrss MB", "Δ maxrss MB")
    rows = [header]
    for s in result.steps:
        rows.append((
            s.name,
            f"{s.wall_ms:.1f}",
            f"{s.delta_ms:.1f}",
            f"{s.traced_current_mb:.1f}",
            f"{s.traced_peak_mb:.1f}",
            "N/A" if s.maxrss_mb is None else f"{s.maxrss_mb:.1f}",
            "N/A" if s.maxrss_delta_mb is None else f"{s.maxrss_delta_mb:+.1f}",
        ))
    widths = [max(len(r[i]) for r in rows) for i in range(len(header))]
    sep = "+" + "+".join("-" * (w + 2) for w in widths) + "+"
    lines = [
        f"auto-floor enumeration cost  ({result.platform}, "
        f"oracle={result.oracle}, maximal={result.maximal}, "
        f"tried={result.tried}, verdict={result.verdict})",
        sep,
    ]
    for i, row in enumerate(rows):
        lines.append("| " + " | ".join(row[j].ljust(widths[j])
                                       for j in range(len(row))) + " |")
        if i == 0:
            lines.append(sep)
    lines.append(sep)

    per = (result.rss_growth_mb() or 0.0) * MB / max(1, result.maximal)
    lines += [
        "",
        f"sweep live traced peak (``seen`` high-water): "
        f"{result.sweep_live_peak_mb:.1f} MB",
        f"per-candidate RSS growth: {per:.1f} bytes/candidate",
        f"tracemalloc active during this run: {result.traced}",
    ]
    if result.breakdown_ms:
        lines.append("")
        lines.append("inner attribution (accumulated over BOTH enumerate passes)")
        for name, ms in sorted(result.breakdown_ms.items(), key=lambda kv: -kv[1]):
            lines.append(f"  {name:<26} {ms:9.1f} ms")
    lines += [
        "",
        "DECISION RULE",
        verdict.detail,
        "",
        ("VERDICT: OPTIMISE (see docstring for the ascending-risk fix list)"
         if verdict.optimise else
         "VERDICT: under both thresholds -- no engine change warranted"),
    ]
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Self-test
# ---------------------------------------------------------------------------


def run_self_test() -> int:
    """Exercise the instrumentation on a tiny case; measure nothing real."""
    assert rss_unit_divisor("Darwin") == 1, "macOS ru_maxrss is in BYTES"
    assert rss_unit_divisor("Linux") == 1024, "Linux ru_maxrss is in KILOBYTES"
    assert rss_unit_divisor("FreeBSD") == 1024

    case = build_case(4000, key_size=32)
    assert len(case.reference_data) == 4000 + 31, len(case.reference_data)
    assert case.variance.size == len(case.reference_data)
    assert float(case.variance.min()) > auto_floor.DEFAULT_FLOOR, (
        "worst-case default_set requires every byte above DEFAULT_FLOOR")

    before_enum = floor_policy.enumerate_maximal
    before_maximal = auto_floor._maximal_candidates
    result = measure(case, sample_every=64)
    assert floor_policy.enumerate_maximal is before_enum, "patch not restored"
    assert auto_floor._maximal_candidates is before_maximal, "patch not restored"

    names = [s.name for s in result.steps]
    assert names == ["1_entry", "2_enumerate_maximal_phi0",
                     "3_enumerate_maximal_dflt", "4_default_set",
                     "5_sweep_done"], names
    assert all(b.wall_ms >= a.wall_ms
               for a, b in zip(result.steps, result.steps[1:])), names
    assert result.maximal > 0, result.maximal
    assert result.tried == result.maximal, (result.tried, result.maximal)
    assert result.verdict == auto_floor.VERDICT_ABSENT, result.verdict
    assert result.enumeration_ms() >= 0.0
    assert 0.0 <= result.enumeration_fraction() <= 1.0

    v = decide(result)
    assert isinstance(v.optimise, bool)
    print(render_terminal(result, v))
    print("self-test: OK")
    return 0


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--candidates", type=int, default=DEFAULT_CANDIDATES,
                   help="Target candidate-window count (default: 700000)")
    p.add_argument("--key-size", type=int, default=DEFAULT_KEY_SIZE)
    p.add_argument("--num-dumps", type=int, default=DEFAULT_NUM_DUMPS)
    p.add_argument("--entropy-threshold", type=float,
                   default=DEFAULT_ENTROPY_THRESHOLD)
    p.add_argument("--repeat", type=int, default=1,
                   help="Run the measurement N times and report each run")
    p.add_argument("--oracle", choices=ORACLE_CHOICES, default="null",
                   help="Per-candidate oracle cost model (default: null)")
    p.add_argument("--no-tracemalloc", action="store_true",
                   help="Skip tracemalloc; time-only control run (rule (T))")
    p.add_argument("--json-out", type=Path, default=None)
    p.add_argument("--self-test", action="store_true")
    p.add_argument("--verbose", action="store_true")
    return p


def main(argv: Optional[List[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    logging.basicConfig(level=logging.INFO if args.verbose else logging.WARNING)

    if args.self_test:
        return run_self_test()

    runs: List[Tuple[BenchResult, Verdict]] = []
    for i in range(max(1, args.repeat)):
        print(f"building synthetic case (~{args.candidates} candidates)...",
              file=sys.stderr)
        case = build_case(
            args.candidates, key_size=args.key_size, num_dumps=args.num_dumps,
            entropy_threshold=args.entropy_threshold, seed=20260825 + i,
        )
        result = measure(case, traced=not args.no_tracemalloc,
                         oracle_kind=args.oracle)
        verdict = decide(result)
        runs.append((result, verdict))
        print(render_terminal(result, verdict))
        print()

    if args.json_out:
        args.json_out.parent.mkdir(parents=True, exist_ok=True)
        args.json_out.write_text(json.dumps(
            {
                "platform": platform.system(),
                "rule_m_rss_mb": RULE_M_RSS_MB,
                "rule_t_enum_fraction": RULE_T_ENUM_FRACTION,
                "runs": [
                    {
                        "result": _asdict_result(r),
                        "verdict": asdict(v),
                    }
                    for r, v in runs
                ],
            },
            indent=2,
        ))
        print(f"Wrote JSON: {args.json_out}", file=sys.stderr)

    return 0


def _asdict_result(result: BenchResult) -> dict:
    d = asdict(result)
    d["rss_growth_mb"] = result.rss_growth_mb()
    d["enumeration_ms"] = result.enumeration_ms()
    d["enumeration_fraction"] = result.enumeration_fraction()
    return d


# A stable alias so tests/test_benchmarks.py can express the regression as
# "run the bench's own measurement", not a reimplementation of it.
run_measurement: Callable[..., BenchResult] = measure


if __name__ == "__main__":
    raise SystemExit(main())
