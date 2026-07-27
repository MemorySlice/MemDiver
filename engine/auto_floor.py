"""Automated, ground-truth-free variance-floor selection (``memdiver auto-floor``).

Reframes ``phi_search`` from a *correctness gate* into a *search-ordering
cursor*: the decryption oracle (AEAD tag ⇒ false-accept ≈ 2**-128) is the real
correctness arbiter, so the variance floor only decides the ORDER in which
candidates are oracle-tested — never whether a tested candidate is accepted.
Every variance-estimation error therefore degrades to extra latency, not a miss.

The procedure computes the *maximal* candidate set once (the entropy+alignment
set, i.e. variance floor disabled), ranks candidates by window variance, and
oracle-tests best-first until a hit or exhaustion. It emits exactly one verdict:

    RECOVERED           - key verified at variance >= the shipped default floor
    FLOOR_WAS_TOO_HIGH  - key verified only BELOW the default floor (footnote-2)
    ABSENT              - oracle rejected the ENTIRE maximal set (qualified by
                          coverage + filter-recall when known)
    INCONCLUSIVE        - a diagnostic gate failed (oracle / coverage / target)

``phi*`` (the hit's variance) and a data-driven recommended floor ``phi0`` are
reported so the analyst never has to guess a floor.  See the paper section
"Robustness of the offset-correspondence assumption".
"""
from __future__ import annotations

import logging
import math
from dataclasses import dataclass, field
from typing import List, Optional, Sequence, Tuple

import numpy as np

from memdiver.engine import floor_policy
# Re-exported so callers/tests keep importing ``_enumerate_candidates`` from
# here after the region->pairs helper moved into floor_policy (Phase 4).
from memdiver.engine.floor_policy import enumerate_candidates as _enumerate_candidates
from memdiver.engine.oracle import OracleFn
from memdiver.engine.progress import ProgressEvent, ProgressFn, noop_progress, safe_emit

logger = logging.getLogger("memdiver.engine.auto_floor")

# Population variance of a uniform byte over [0,255]: the ceiling a fresh
# full-entropy key byte approaches as N -> inf.  = (256**2 - 1)/12.
SIGMA_K2 = (256 ** 2 - 1) / 12.0  # 5461.25

# The shipped default variance floor (== POINTER_MAX / tau_high). A hit at or
# above this means the default would already have found the key.
DEFAULT_FLOOR = 3000.0

VERDICT_RECOVERED = "RECOVERED"
VERDICT_FLOOR_TOO_HIGH = "FLOOR_WAS_TOO_HIGH"
VERDICT_ABSENT = "ABSENT"
VERDICT_INCONCLUSIVE = "INCONCLUSIVE"

EXIT_HIT = 0          # RECOVERED or FLOOR_WAS_TOO_HIGH
EXIT_ABSENT = 2
EXIT_INCONCLUSIVE = 3

NEIGHBORHOOD_PAD = 64
_ORACLE_FALSE_ACCEPT = 2.0 ** -128


# ─────────────────────────────────────────────────────────────────────
# Result dataclasses
# ─────────────────────────────────────────────────────────────────────
@dataclass
class OracleHealth:
    negatives_ok: bool = True
    positive_ok: Optional[bool] = None
    deterministic: bool = True
    healthy: bool = True
    detail: str = ""

    def to_dict(self) -> dict:
        return {
            "negatives_ok": self.negatives_ok,
            "positive_ok": self.positive_ok,
            "deterministic": self.deterministic,
            "healthy": self.healthy,
            "detail": self.detail,
        }


@dataclass
class Phi0Result:
    phi0: float
    method: str
    v_lo: float = 0.0            # lower edge of the high-variance component
    lcb_deflation: float = 1.0   # (1 - z*CV(N)) factor applied
    detail: str = ""

    def to_dict(self) -> dict:
        return {
            "phi0": self.phi0, "method": self.method, "v_lo": self.v_lo,
            "lcb_deflation": self.lcb_deflation, "detail": self.detail,
        }


@dataclass
class FloorPoint:
    phi: float          # variance floor
    candidates: int     # candidate windows with window-variance >= phi
    hit: bool = False

    def to_dict(self) -> dict:
        return {"phi": self.phi, "candidates": self.candidates, "hit": self.hit}


@dataclass
class AutoFloorResult:
    verdict: str
    key_hex: Optional[str] = None
    offset: Optional[int] = None
    phi_star: Optional[float] = None
    phi0: Optional[float] = None
    coverage: Optional[float] = None
    correspondence: Optional[float] = None
    confidence: Optional[float] = None
    tried: int = 0
    maximal_candidates: int = 0
    neighborhood_start: int = 0
    neighborhood_variance: List[float] = field(default_factory=list)
    sweep: List[FloorPoint] = field(default_factory=list)
    oracle_health: Optional[OracleHealth] = None
    phi0_detail: Optional[Phi0Result] = None
    envelope: dict = field(default_factory=dict)
    inconclusive_reason: Optional[str] = None
    # Reachability assumptions a negative verdict is CONDITIONED on (B1): an
    # ABSENT/INCONCLUSIVE means "no key reachable UNDER THESE", never an
    # unconditional "no key resident".
    assumptions: List[str] = field(default_factory=list)

    @property
    def exit_code(self) -> int:
        if self.verdict in (VERDICT_RECOVERED, VERDICT_FLOOR_TOO_HIGH):
            return EXIT_HIT
        if self.verdict == VERDICT_ABSENT:
            return EXIT_ABSENT
        return EXIT_INCONCLUSIVE

    def to_dict(self) -> dict:
        return {
            "verdict": self.verdict,
            "key_hex": self.key_hex,
            "offset": self.offset,
            "phi_star": self.phi_star,
            "phi0": self.phi0,
            "coverage": self.coverage,
            "correspondence": self.correspondence,
            "confidence": self.confidence,
            "tried": self.tried,
            "maximal_candidates": self.maximal_candidates,
            "neighborhood_start": self.neighborhood_start,
            "neighborhood_variance": list(self.neighborhood_variance),
            "sweep": [p.to_dict() for p in self.sweep],
            "oracle_health": self.oracle_health.to_dict() if self.oracle_health else None,
            "phi0_detail": self.phi0_detail.to_dict() if self.phi0_detail else None,
            "envelope": dict(self.envelope),
            "inconclusive_reason": self.inconclusive_reason,
            "assumptions": list(self.assumptions),
            "exit_code": self.exit_code,
        }


def hit_tier(result: "AutoFloorResult") -> Optional[str]:
    """Map an escalation verdict to the floor tier its hit came from.

    ``None`` for any negative verdict (ABSENT / INCONCLUSIVE) so a
    conditional-absence claim never carries a fabricated tier. Keyed on
    ``phi_star`` thresholds (robust to the density-gate edge case where a
    ``phi_star >= DEFAULT_FLOOR`` window is excluded from the default_set):

        phi_star >= DEFAULT_FLOOR   -> "default"    (the shipped floor's band)
        phi0 <= phi_star < default  -> "phi0"       (data-driven floor band)
        phi_star < phi0             -> "below_phi0"
    """
    if result.verdict not in (VERDICT_RECOVERED, VERDICT_FLOOR_TOO_HIGH):
        return None
    phi = result.phi_star
    if phi is None:
        return None
    if phi >= DEFAULT_FLOOR:
        return "default"
    if result.phi0 is not None and phi >= result.phi0:
        return "phi0"
    return "below_phi0"


def escalation_verdict(result: "AutoFloorResult") -> dict:
    """The canonical escalation payload: the verdict dict plus its hit tier.

    Single source of truth for the ``escalation`` envelope shape emitted by both
    the pipeline escalation stage and the n-sweep terminal-N fall-through.
    """
    return {**result.to_dict(), "hit_tier": hit_tier(result)}


# ─────────────────────────────────────────────────────────────────────
# Diagnostics
# ─────────────────────────────────────────────────────────────────────
def oracle_self_test(
    oracle: OracleFn,
    reference_data: bytes,
    *,
    key_size: int = 32,
    trials: int = 8,
    positive_control: Optional[bytes] = None,
) -> OracleHealth:
    """Gate a misconfigured oracle before trusting any no-hit result.

    Feeds random buffers (expect all-reject), checks determinism, and — if a
    caller-controlled known key is supplied — checks the accept path. An oracle
    that always-accepts, always-rejects a known key, or is nondeterministic is
    unhealthy: every downstream ABSENT would be meaningless.
    """
    health = OracleHealth()
    # Deterministic pseudo-random probes (no Math.random / os.urandom so the
    # self-test is reproducible across resume): derive from the reference bytes.
    seed = int.from_bytes((reference_data[:8] or b"\x00" * 8), "little") ^ 0x9E3779B97F4A7C15
    rng = np.random.default_rng(seed)
    negatives_ok = True
    for _ in range(max(1, trials)):
        buf = bytes(rng.integers(0, 256, size=key_size, dtype=np.uint8).tolist())
        try:
            if oracle(buf):  # a random 32-byte buffer must not verify
                negatives_ok = False
                break
        except Exception as exc:
            health.detail = f"oracle raised on random input: {exc}"
            health.negatives_ok = False
            health.healthy = False
            return health
    health.negatives_ok = negatives_ok

    # Determinism: same input twice → same answer.
    probe = bytes(rng.integers(0, 256, size=key_size, dtype=np.uint8).tolist())
    try:
        health.deterministic = bool(oracle(probe)) == bool(oracle(probe))
    except Exception:
        health.deterministic = False

    if positive_control is not None:
        try:
            health.positive_ok = bool(oracle(positive_control))
        except Exception as exc:
            health.positive_ok = False
            health.detail = f"oracle raised on positive control: {exc}"

    health.healthy = (
        health.negatives_ok
        and health.deterministic
        and (health.positive_ok is not False)
    )
    if not health.detail:
        if not health.negatives_ok:
            health.detail = "oracle accepts random input (always-True?)"
        elif not health.deterministic:
            health.detail = "oracle is nondeterministic"
        elif health.positive_ok is False:
            health.detail = "oracle rejects the known positive control (misconfigured?)"
    return health


def _otsu_threshold(values: np.ndarray, bins: int = 256) -> float:
    """Otsu's between-class-variance threshold on a 1-D sample."""
    hist, edges = np.histogram(values, bins=bins)
    hist = hist.astype(np.float64)
    total = hist.sum()
    if total == 0:
        return float(edges[-1])
    p = hist / total
    centers = 0.5 * (edges[:-1] + edges[1:])
    omega = np.cumsum(p)
    mu = np.cumsum(p * centers)
    mu_t = mu[-1]
    denom = omega * (1.0 - omega)
    with np.errstate(divide="ignore", invalid="ignore"):
        sigma_b = (mu_t * omega - mu) ** 2 / denom
    sigma_b[~np.isfinite(sigma_b)] = -1.0
    return float(centers[int(np.argmax(sigma_b))])


def compute_phi0(
    variance: np.ndarray,
    *,
    method: str = "otsu",
    num_dumps: Optional[int] = None,
    z: float = 1.645,
    clamp: Tuple[float, float] = (0.0, DEFAULT_FLOOR),
) -> Phi0Result:
    """Data-driven recommended variance floor from the variance distribution.

    Fits Otsu's break on log-variance over the nonzero offsets to locate the
    boundary below the high-variance component, then deflates by the finite-N
    sampling error of the sample variance (CV(N) ≈ 0.894/sqrt(N)) so a truly
    diluted key byte still survives with ~1-alpha confidence.  On the gocryptfs
    consensus this lands near ~1500, reproducing the manual floor.
    """
    variance = np.asarray(variance, dtype=np.float64)
    nz = variance[variance > 0.0]
    if nz.size == 0:
        return Phi0Result(phi0=float(clamp[0]), method=method, detail="no nonzero variance")
    y = np.log(nz)
    # Otsu splits the log-variance into a low bulk and a high (crypto) tail; the
    # break is the ANTIMODE. The recommended floor is the LOWER EDGE of the high
    # component (5th percentile of values above the break), deflated by the
    # finite-N sampling error so a diluted key at that edge still survives.
    t_y = _otsu_threshold(y)
    break_v = float(math.exp(t_y))
    high = np.sort(nz[nz >= break_v])
    if high.size >= 20:
        # Isolate the crypto component: if there is a dominant spectral gap in
        # log-space above the antimode (bulk upper-edge -> crypto lower-edge),
        # cut there so the structural remnant just above the break is excluded.
        logh = np.log(high)
        gaps = np.diff(logh)
        if gaps.size:
            gi = int(np.argmax(gaps))
            med = float(np.median(gaps[gaps > 0])) if np.any(gaps > 0) else 0.0
            if med > 0 and gaps[gi] > 5.0 * med:
                high = high[gi + 1:]
        v_lo = float(np.percentile(high, 5)) if high.size else break_v
    else:
        v_lo = break_v
    deflation = 1.0
    if num_dumps and num_dumps > 1:
        cv = 0.894 / math.sqrt(num_dumps)
        deflation = max(0.1, 1.0 - z * cv)
    phi0 = v_lo * deflation
    phi0 = float(min(max(phi0, clamp[0]), clamp[1]))
    return Phi0Result(
        phi0=phi0, method=method, v_lo=v_lo, lcb_deflation=deflation,
        detail=(f"otsu(log-var) antimode exp={break_v:.1f}; high-component lower "
                f"edge (p5)={v_lo:.1f}; CV-deflated x{deflation:.3f}"),
    )


def _sigma_k2_interior(
    variance: np.ndarray, offsets: np.ndarray, sizes: np.ndarray,
    *, min_bytes: int = 50,
) -> Optional[float]:
    """P90 of interior (least-diluted) candidate byte variances, clamped to
    [0.5*ceiling, ceiling].  Interior bytes have p_i -> 1, so their variance
    approximates sigma_k^2.  Returns None when too few interior bytes exist.
    """
    var = np.asarray(variance, dtype=np.float64)
    vals: List[float] = []
    for off, size in zip(np.asarray(offsets).tolist(), np.asarray(sizes).tolist()):
        pad = max(0, int(size) // 4)
        seg = var[int(off) + pad:int(off) + int(size) - pad]
        vals.extend(seg[seg > 0].tolist())
    if len(vals) < min_bytes:
        return None
    return float(min(max(np.percentile(vals, 90), 0.5 * SIGMA_K2), SIGMA_K2))


def compute_phi_from_pmin(
    variance: np.ndarray,
    offsets: np.ndarray,
    sizes: np.ndarray,
    *,
    p_min: float = 0.35,
    num_dumps: Optional[int] = None,
    key_size: int = 32,
    k_presence: int = 5,
) -> Phi0Result:
    """Policy-parameterized floor ``phi = p_min * sigma_k^2`` (deterministic).

    Instead of fitting a valley in the variance marginal (unstable — the diluted
    key sits in the bulk, not a separable mode), the analyst picks a retention
    policy ``p_min`` ("retain keys whose per-run correspondence >= p_min") and
    the floor follows.  ``sigma_k^2`` is estimated from the least-diluted
    interior of candidate windows, else the uniform-byte ceiling ``SIGMA_K2``.

    This is a search-ordering RECOMMENDATION, not a correctness gate: under an
    exhaustive best-first oracle sweep it changes zero oracle calls; the oracle
    still arbitrates.  Reported so the analyst never has to guess a floor.
    """
    p_min = float(max(0.0, min(1.0, p_min)))
    n_needed = math.ceil(k_presence / p_min) if p_min > 0 else 0
    enough_n = num_dumps is not None and num_dumps >= n_needed
    sigma = _sigma_k2_interior(variance, offsets, sizes) if enough_n else None
    used_ceiling = sigma is None
    if sigma is None:
        sigma = float(SIGMA_K2)
    phi = float(p_min * sigma)
    detail = (
        f"phi = p_min*sigma_k2: p_min={p_min:.2f}, "
        f"sigma_k2_hat={sigma:.1f}{' (ceiling fallback)' if used_ceiling else ''} "
        f"(ceiling {SIGMA_K2:.1f}); need N>={n_needed} (have {num_dumps}); "
        f"phi={phi:.1f}. Search-ordering recommendation; oracle arbitrates."
    )
    return Phi0Result(phi0=phi, method="pmin", v_lo=sigma, lcb_deflation=1.0,
                      detail=detail)


def recall_lower_bound(successes: int, trials: int, alpha: float = 0.05) -> float:
    """Conservative LOWER bound on the filter-recall proportion (C3).

    ``successes`` known/synthetic keys survived the entropy+alignment gates out
    of ``trials``.  We report the (1-alpha) LOWER confidence bound, not the
    point estimate, so the ABSENT confidence can only ever be *lowered* vs the
    old hardcoded 0.95 — never inflated.  Clopper-Pearson (exact) when scipy is
    present, else the Wilson score lower bound (closed-form).
    """
    if trials <= 0:
        return 0.0
    successes = max(0, min(int(successes), int(trials)))
    if successes == 0:
        return 0.0
    try:
        from scipy.stats import beta  # exact Clopper-Pearson lower bound
        return float(beta.ppf(alpha / 2.0, successes, trials - successes + 1))
    except Exception:
        # Wilson score interval lower bound (no scipy dependency).
        from math import sqrt
        z = 1.959963984540054  # ~alpha=0.05 two-sided
        phat = successes / trials
        denom = 1.0 + z * z / trials
        centre = phat + z * z / (2 * trials)
        margin = z * sqrt((phat * (1 - phat) + z * z / (4 * trials)) / trials)
        return float(max(0.0, (centre - margin) / denom))


def absence_confidence(
    coverage: Optional[float],
    filter_recall: Optional[float],
) -> Optional[float]:
    """Absence confidence = coverage * filter_recall (both in [0,1]).

    Honest bound: you can only be as confident in absence as the fraction of
    the plausible region actually captured across all N runs (coverage) times
    the probability a resident key survives the entropy/alignment pre-filters
    (recall). ``filter_recall`` should be a LOWER bound (see
    :func:`recall_lower_bound`), so this confidence is conservative — it can
    only be lowered, never inflated. Returns None when coverage is unknown.
    """
    if coverage is None:
        return None
    r = 1.0 if filter_recall is None else float(filter_recall)
    return float(max(0.0, min(1.0, coverage)) * max(0.0, min(1.0, r)))


# ─────────────────────────────────────────────────────────────────────
# Core: maximal candidate set + best-first oracle sweep
# ─────────────────────────────────────────────────────────────────────
def _maximal_candidates(
    variance: np.ndarray,
    reference_data: bytes,
    num_dumps: int,
    reduce_kwargs: dict,
    key_sizes: Sequence[int],
    stride: int,
) -> Tuple[np.ndarray, np.ndarray, np.ndarray, set]:
    """Return (offsets, sizes, window_variance, default_set).

    A thin composition over :func:`floor_policy.enumerate_maximal` (the single
    shared enumeration core). The maximal set is entropy+alignment only
    (variance floor disabled), i.e. every candidate the oracle could ever be
    asked about; window_variance is the mean per-byte variance over each window
    (used only to RANK). ``default_set`` is the (offset,size) set the SHIPPED
    default floor (search-reduce at DEFAULT_FLOOR, incl. its density gate) would
    test — used to decide RECOVERED vs FLOOR_WAS_TOO_HIGH. Kept as a SECOND
    enumeration at DEFAULT_FLOOR for bit-exact parity with the default's
    nonlinear density gate (a wvar>=DEFAULT_FLOOR threshold would drift the
    verdict label at density-gated region edges).

    Already reconciled / minimal: the second pass runs in cheap mode
    (``compute_wvar=False``, no window-variance cumsum). The density gate keys
    off the per-byte ``variance >= min_variance`` mask, so its variance mask,
    alignment/density filter and region extraction MUST re-run at DEFAULT_FLOOR
    regardless -- they cannot be recovered from the min_variance=0.0 output. The
    only cost the two passes share is enumeration over the in-memory variance
    array (plus the min_variance-independent entropy profile), not I/O.
    """
    offsets, sizes, wvar = floor_policy.enumerate_maximal(
        variance, reference_data, num_dumps, reduce_kwargs, key_sizes, stride,
        min_variance=0.0)
    d_off, d_sz, _ = floor_policy.enumerate_maximal(
        variance, reference_data, num_dumps, reduce_kwargs, key_sizes, stride,
        min_variance=DEFAULT_FLOOR, compute_wvar=False)
    default_set = set(zip(d_off.tolist(), d_sz.tolist()))
    return offsets, sizes, wvar, default_set


def _absence_assumptions(*, stride: int, coverage: Optional[float],
                         entropy_threshold: float) -> List[str]:
    """The reachability preconditions any negative verdict is CONDITIONED on.

    Stated explicitly so an ABSENT is never read as an unconditional "no key
    resident" — the failure modes it cannot see (secret-sharing, off-grid
    headers, derive-on-use, uncaptured regions) are named here.
    """
    cov = "unverified" if coverage is None else f"{coverage:.3f}"
    return [
        "target process resident in all N captures",
        "key stored contiguously (not secret-shared / boolean-masked)",
        "key materialized in memory (not derived-on-use / wiped before capture)",
        f"key aligned to the stride={stride} grid (off-grid keys, e.g. behind "
        f"object headers, are not enumerated)",
        f"key window passes entropy>= {entropy_threshold} + alignment/density gates",
        f"key lies within captured coverage (C_intersection={cov})",
        "offset correspondence established across captures",
    ]


def _sweep_curve(wvar: np.ndarray, phi0: float, hit_phi: Optional[float],
                 steps: int = 20) -> List[FloorPoint]:
    """Candidate-count-vs-floor curve C(phi) for the report (monotone)."""
    if wvar.size == 0:
        return []
    lo, hi = 0.0, float(max(DEFAULT_FLOOR, wvar.max()))
    grid = sorted({round(float(x), 3) for x in np.linspace(hi, lo, steps)}
                  | {float(DEFAULT_FLOOR), float(phi0)}, reverse=True)
    pts = []
    for phi in grid:
        c = int((wvar >= phi).sum())
        pts.append(FloorPoint(phi=float(phi), candidates=c,
                              hit=bool(hit_phi is not None and hit_phi >= phi)))
    return pts


def run_auto_floor(
    variance: np.ndarray,
    reference_data: bytes,
    num_dumps: int,
    oracle: OracleFn,
    *,
    reduce_kwargs: Optional[dict] = None,
    key_sizes: Sequence[int] = (32,),
    stride: int = 8,
    coverage: Optional[float] = None,
    correspondence: Optional[float] = None,
    filter_recall: Optional[float] = None,
    min_coverage: float = 0.80,
    positive_control: Optional[bytes] = None,
    phi0_method: str = "pmin",
    p_min: float = 0.35,
    exhaustive_absent: bool = True,
    self_test_trials: int = 8,
    oracle_budget: Optional[int] = None,
    alignment_quality: Optional[float] = None,
    min_alignment: float = 0.5,
    managed_region: bool = False,
    progress_callback: ProgressFn = noop_progress,
) -> AutoFloorResult:
    """Automated oracle-arbitrated floor selection → single verdict.

    coverage/correspondence/filter_recall are optional diagnostics; when
    ``coverage`` is None the ABSENT verdict is reported as unqualified (the
    caller could not verify what was captured).

    A no-hit is only ABSENT when the maximal set was FULLY swept under
    established preconditions; otherwise it degrades to INCONCLUSIVE (B1):
      - ``oracle_budget`` exhausted before the sweep completes → reason ``cost``
        (never a false ABSENT for expensive/one-shot oracles);
      - ``alignment_quality < min_alignment`` → reason ``alignment`` (offsets
        not reliably comparable across captures);
      - ``managed_region`` (moving-GC / off-grid object headers) → reason
        ``regime`` (the stride grid may not have enumerated the key).
    Byte-identical candidate windows are de-duplicated before the oracle sees
    them (B3): identical bytes give identical results, so testing once is free.
    """
    variance = np.asarray(variance, dtype=np.float64)
    reduce_kwargs = dict(reduce_kwargs or {})

    # ---- Stage 0: diagnostics (fail fast) ----
    health = oracle_self_test(
        oracle, reference_data, key_size=int(key_sizes[0]),
        trials=self_test_trials, positive_control=positive_control,
    )
    # Oracle calls the self-test consumed (B4): `trials` negatives + 2
    # determinism probes + one optional positive control.
    self_test_cost = max(1, self_test_trials) + 2 + (1 if positive_control else 0)
    if not health.healthy:
        return AutoFloorResult(
            verdict=VERDICT_INCONCLUSIVE, inconclusive_reason="oracle",
            oracle_health=health, coverage=coverage, correspondence=correspondence,
        )
    if coverage is not None and coverage < min_coverage:
        return AutoFloorResult(
            verdict=VERDICT_INCONCLUSIVE, inconclusive_reason="coverage",
            oracle_health=health, coverage=coverage, correspondence=correspondence,
        )

    # ---- Stage 2: maximal set (phi=0) — computed before phi0 so the ----
    # data-driven floor is fit on the CANDIDATE window variances (the
    # high-entropy regions where keys live), not the low-variance background
    # glut that would mass-bias Otsu.
    offsets, sizes, wvar, default_set = _maximal_candidates(
        variance, reference_data, num_dumps, reduce_kwargs, key_sizes, stride
    )
    maximal = int(offsets.size)

    # ---- Stage 1 (reported): recommended floor phi0 ----
    # Default 'pmin' = deterministic policy floor phi = p_min*sigma_k^2; 'otsu'
    # keeps the legacy data-driven valley fit for comparison/back-compat.
    if phi0_method == "pmin":
        phi0_res = compute_phi_from_pmin(
            variance, offsets, sizes, p_min=p_min,
            num_dumps=num_dumps, key_size=int(key_sizes[0]))
    else:
        phi0_sample = wvar[wvar > 0] if wvar.size else variance[variance > 0]
        phi0_res = compute_phi0(phi0_sample, method=phi0_method, num_dumps=num_dumps)
    safe_emit(progress_callback, ProgressEvent(
        stage="auto_floor:maximal", pct=0.0, msg=f"maximal candidates={maximal}",
        extra={"maximal_candidates": maximal}))

    order = np.argsort(-wvar, kind="stable")  # descending window variance
    budget_left = (None if oracle_budget is None
                   else max(0, int(oracle_budget) - self_test_cost))
    seen: set = set()          # B3: skip byte-identical windows
    tried = 0                  # actual oracle calls in the sweep
    hit_idx = None
    truncated = False          # B4: budget ran out before the set was exhausted
    for rank, idx in enumerate(order):
        off = int(offsets[idx]); size = int(sizes[idx])
        win = reference_data[off:off + size]
        if win in seen:
            continue           # duplicate content → same oracle answer
        seen.add(win)
        if budget_left is not None and budget_left <= 0:
            truncated = True
            break
        tried += 1
        if budget_left is not None:
            budget_left -= 1
        try:
            ok = bool(oracle(win))
        except Exception as exc:
            logger.debug("oracle raised at 0x%x: %s", off, exc)
            ok = False
        if ok:
            hit_idx = int(idx)
            break
        if tried % 4096 == 0:
            safe_emit(progress_callback, ProgressEvent(
                stage="auto_floor:sweep", pct=tried / max(1, maximal),
                msg=f"tried={tried}/{maximal}", extra={"tried": tried}))
        if not exhaustive_absent and tried >= maximal:
            break

    envelope = {
        "entropy_threshold": reduce_kwargs.get("entropy_threshold", 4.5),
        "alignment": reduce_kwargs.get("alignment", stride),
        "phi_min": 0.0, "stride": stride, "key_sizes": list(key_sizes),
    }

    if hit_idx is not None:
        off = int(offsets[hit_idx]); size = int(sizes[hit_idx])
        phi_star = float(wvar[hit_idx])
        start = max(0, off - NEIGHBORHOOD_PAD)
        end = min(variance.size, off + size + NEIGHBORHOOD_PAD)
        # RECOVERED iff the shipped default floor (with its density gate) would
        # itself have tested this candidate; else the default would have MISSED
        # it and only the lowered/oracle-arbitrated search found it (footnote-2).
        verdict = (VERDICT_RECOVERED if (off, size) in default_set
                   else VERDICT_FLOOR_TOO_HIGH)
        return AutoFloorResult(
            verdict=verdict, key_hex=reference_data[off:off + size].hex(),
            offset=off, phi_star=phi_star, phi0=phi0_res.phi0,
            coverage=coverage, correspondence=correspondence,
            tried=tried, maximal_candidates=maximal,
            neighborhood_start=start,
            neighborhood_variance=variance[start:end].astype(np.float32).tolist(),
            sweep=_sweep_curve(wvar, phi0_res.phi0, phi_star),
            oracle_health=health, phi0_detail=phi0_res, envelope=envelope,
        )

    # ---- Stage 3: no hit — the reachability assumptions a negative rests on ----
    assumptions = _absence_assumptions(
        stride=stride, coverage=coverage,
        entropy_threshold=reduce_kwargs.get("entropy_threshold", 4.5),
    )
    common = dict(
        phi0=phi0_res.phi0, coverage=coverage, correspondence=correspondence,
        tried=tried, maximal_candidates=maximal,
        sweep=_sweep_curve(wvar, phi0_res.phi0, None),
        oracle_health=health, phi0_detail=phi0_res, envelope=envelope,
        assumptions=assumptions,
    )
    # B1/B2/B4 forbidden gates: a no-hit is ABSENT only when the maximal set was
    # FULLY swept under established preconditions; else it is INCONCLUSIVE.
    reason = None
    if truncated:
        reason = "cost"            # budget exhausted before exhausting the set
    elif alignment_quality is not None and alignment_quality < min_alignment:
        reason = "alignment"       # offsets not reliably comparable
    elif managed_region:
        reason = "regime"          # off-grid header / moving-GC risk
    if reason is not None:
        return AutoFloorResult(verdict=VERDICT_INCONCLUSIVE,
                               inconclusive_reason=reason, **common)

    # ---- Absence: oracle rejected the ENTIRE maximal set, preconditions met ----
    conf = absence_confidence(coverage, filter_recall)
    return AutoFloorResult(verdict=VERDICT_ABSENT, confidence=conf, **common)
