"""Phase-A offline experiments for the auto-floor redesign (zero oracle calls).

Two ground-truth-anchored measurements over an already-computed consensus
(per-byte ``variance`` array + one ``reference`` buffer) plus the KNOWN key
offset.  Neither touches the decryption oracle; both are decision gates for the
larger redesign and evidence artifacts for the paper.

A1 — ordering gate (R_c).  Score every maximal candidate (incl. the key window)
with a *composite* key-likeness statistic and report

    R_c   = #{candidates : composite >= composite(key)}     (oracle calls a
            composite-ordered sweep would need to reach the key)
    R_var = #{candidates : window_variance >= wvar(key)}     (today's baseline)

so a Phase-D ordering rework is only worth building if R_c << R_var (and both
<< the observed 5,825).  The composite here is the consensus-only variant
(single-dump uniformity gate x descending window variance); the full
dilution-tolerant ``Sigma_r KeyLike`` needs the N individual dumps and is
provided by :func:`composite_rank_from_dumps` for callers that have them.

A2 — floor-selection validation (the user's corrected 5-step direction).
Trimmed-mean window floor retention, the candidate-count-vs-floor curve C(phi),
the *descending* Kneedle knee phi_knee (heap-noise onset), and phi_theory =
p_min * sigma_k^2 — reporting whether phi_knee and phi_theory RETAIN the key and
AGREE near the manual region (the paper's two-independent-routes cross-check).

Master-equation caveats this harness makes measurable rather than assumed:
per-run-fresh non-key clutter (nonces / other keys / urandom) sits at the
uniform ceiling sigma_k^2 and is *more* extreme than the diluted key, so no
variance- or uniformity-ordering can rank the key first — only the oracle can.
The numbers here quantify exactly how much clutter that is.
"""
from __future__ import annotations

import json
import logging
import math
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Dict, List, Optional, Sequence, Tuple

import numpy as np

if TYPE_CHECKING:
    from memdiver.engine.subsample_stability import SubsampleStabilityResult

from memdiver.engine import floor_policy
from memdiver.engine.auto_floor import (
    SIGMA_K2, _sigma_k2_interior,
)

logger = logging.getLogger("memdiver.engine.candidate_stats")

# Default descending floor ladder for A2 (matches the user's proposal + noise
# floor). phi decreases; the knee marks heap-noise onset.
DEFAULT_LADDER: Tuple[float, ...] = (3000.0, 2500.0, 2000.0, 1750.0, 1500.0, 1200.0)
DEFAULT_PMINS: Tuple[float, ...] = (0.55, 0.40, 0.35, 0.27)


# ─────────────────────────────────────────────────────────────────────
# Per-window features (computed only for enumerated candidates → cheap)
# ─────────────────────────────────────────────────────────────────────
@dataclass
class WindowFeatures:
    """Per-candidate window features, one row per (offset, size) candidate."""
    min_entropy: np.ndarray      # bits: -log2(max_count / W)
    shannon: np.ndarray          # bits
    chi2_uniform: np.ndarray     # Pearson chi^2 vs uniform-256
    abs_autocorr: np.ndarray     # |lag-1 Pearson r| over the window bytes
    ascii_frac: np.ndarray       # fraction of bytes in [0x20,0x7e]
    max_repeat_frac: np.ndarray  # max_count / W  (dominant-byte share)


def _histogram_rows(windows: np.ndarray) -> np.ndarray:
    """(n, W) uint8 window rows -> (n, 256) int32 per-row byte histograms."""
    n = windows.shape[0]
    counts = np.zeros((n, 256), dtype=np.int32)
    rows = np.repeat(np.arange(n), windows.shape[1])
    np.add.at(counts, (rows, windows.reshape(-1).astype(np.intp)), 1)
    return counts


def _lag1_abs_autocorr(windows: np.ndarray) -> np.ndarray:
    """Vectorized |lag-1 Pearson correlation| per window row."""
    x = windows[:, :-1].astype(np.float64)
    y = windows[:, 1:].astype(np.float64)
    m = x.shape[1]
    sx = x.sum(1); sy = y.sum(1)
    sxx = (x * x).sum(1); syy = (y * y).sum(1)
    sxy = (x * y).sum(1)
    num = m * sxy - sx * sy
    den = np.sqrt(np.clip((m * sxx - sx * sx) * (m * syy - sy * sy), 0.0, None))
    with np.errstate(divide="ignore", invalid="ignore"):
        r = np.where(den > 0, num / den, 0.0)
    return np.abs(np.nan_to_num(r, nan=0.0))


def _features_for_windows(windows: np.ndarray) -> WindowFeatures:
    n, W = windows.shape
    counts = _histogram_rows(windows)
    maxc = counts.max(1).astype(np.float64)
    max_repeat = maxc / W
    min_ent = -np.log2(np.clip(max_repeat, 1e-12, 1.0))
    p = counts.astype(np.float64) / W
    with np.errstate(divide="ignore", invalid="ignore"):
        shannon = -np.where(p > 0, p * np.log2(p), 0.0).sum(1)
    exp = W / 256.0
    chi2 = ((counts.astype(np.float64) - exp) ** 2 / exp).sum(1)
    ascii_frac = ((windows >= 0x20) & (windows <= 0x7e)).mean(1)
    return WindowFeatures(
        min_entropy=min_ent, shannon=shannon, chi2_uniform=chi2,
        abs_autocorr=_lag1_abs_autocorr(windows), ascii_frac=ascii_frac,
        max_repeat_frac=max_repeat,
    )


def compute_window_features(
    reference: np.ndarray, offsets: np.ndarray, sizes: np.ndarray,
    *, chunk: int = 20000,
) -> WindowFeatures:
    """Features for every (offset, size) candidate, chunked to cap memory."""
    ref = np.frombuffer(reference, dtype=np.uint8) if isinstance(reference, (bytes, bytearray)) \
        else np.asarray(reference, dtype=np.uint8)
    uniq = np.unique(sizes)
    parts: Dict[int, WindowFeatures] = {}
    order_idx: List[np.ndarray] = []
    feats_accum: List[WindowFeatures] = []
    for size in uniq:
        sel = np.nonzero(sizes == size)[0]
        offs = offsets[sel]
        rows: List[WindowFeatures] = []
        for start in range(0, offs.size, chunk):
            blk = offs[start:start + chunk]
            windows = ref[blk[:, None] + np.arange(int(size))]
            rows.append(_features_for_windows(windows))
        feats_accum.append(_concat_features(rows))
        order_idx.append(sel)
    # Reassemble into original candidate order.
    idx = np.concatenate(order_idx)
    merged = _concat_features(feats_accum)
    inv = np.argsort(idx, kind="stable")
    return _index_features(merged, inv)


def _concat_features(rows: Sequence[WindowFeatures]) -> WindowFeatures:
    if not rows:
        z = np.empty(0, dtype=np.float64)
        return WindowFeatures(z, z.copy(), z.copy(), z.copy(), z.copy(), z.copy())
    return WindowFeatures(
        np.concatenate([r.min_entropy for r in rows]),
        np.concatenate([r.shannon for r in rows]),
        np.concatenate([r.chi2_uniform for r in rows]),
        np.concatenate([r.abs_autocorr for r in rows]),
        np.concatenate([r.ascii_frac for r in rows]),
        np.concatenate([r.max_repeat_frac for r in rows]),
    )


def _index_features(f: WindowFeatures, idx: np.ndarray) -> WindowFeatures:
    return WindowFeatures(
        f.min_entropy[idx], f.shannon[idx], f.chi2_uniform[idx],
        f.abs_autocorr[idx], f.ascii_frac[idx], f.max_repeat_frac[idx],
    )


# ─────────────────────────────────────────────────────────────────────
# Uniform-key threshold calibration (empirical W=32 distribution)
# ─────────────────────────────────────────────────────────────────────
@dataclass
class KeyLikeThresholds:
    min_entropy: float       # accept min_entropy >= this
    chi2: float              # accept chi2 <= this
    abs_autocorr: float      # accept |autocorr| <= this
    ascii_frac: float        # accept ascii_frac <= this


def calibrate_thresholds(size: int, *, samples: int = 4000,
                         seed: int = 0x5EED) -> KeyLikeThresholds:
    """Thresholds from the empirical distribution of uniform-random W-byte keys.

    At W=32 the χ²/min-entropy tests are weak (32 samples / 256 bins), so the
    gate is set to accept the vast majority of true uniform keys (loose tails):
    its job is to demote clearly-structured windows (counters, pointers, text),
    NOT to separate keys from other uniform-random data.
    """
    rng = np.random.default_rng(seed)
    windows = rng.integers(0, 256, size=(samples, size), dtype=np.uint8)
    f = _features_for_windows(windows)
    return KeyLikeThresholds(
        min_entropy=float(np.percentile(f.min_entropy, 1)),   # keep bottom 1% of keys
        chi2=float(np.percentile(f.chi2_uniform, 99)),
        abs_autocorr=float(np.percentile(f.abs_autocorr, 99)),
        ascii_frac=float(np.percentile(f.ascii_frac, 99)),
    )


def keylike_gate(f: WindowFeatures, thr: KeyLikeThresholds) -> np.ndarray:
    """Boolean per-candidate: does the single-dump window look like a uniform key?"""
    return (
        (f.min_entropy >= thr.min_entropy)
        & (f.chi2_uniform <= thr.chi2)
        & (f.abs_autocorr <= thr.abs_autocorr)
        & (f.ascii_frac <= thr.ascii_frac)
    )


# ─────────────────────────────────────────────────────────────────────
# A1 — ordering gate (R_c)
# ─────────────────────────────────────────────────────────────────────
@dataclass
class OrderingResult:
    key_index: int
    r_var: int                    # baseline: #candidates with wvar >= wvar(key)
    r_composite: int              # composite: #candidates ranked >= key
    maximal: int
    key_passes_gate: bool
    gate_pass_count: int          # #candidates passing the uniformity gate
    distinct_windows: int         # dedup potential in the maximal set
    key_features: Dict[str, float]
    clutter_at_ceiling: int       # #candidates with wvar >= 0.9*sigma_k^2 (fresh clutter proxy)
    detail: str = ""

    def to_dict(self) -> dict:
        return {k: (v if not isinstance(v, np.generic) else v.item())
                for k, v in self.__dict__.items()}


def _composite_rank_key(gate: np.ndarray, wvar: np.ndarray) -> np.ndarray:
    """Lexicographic composite score: gate-pass bucket first, then wvar.

    Encoded as a single float so ``>=`` comparisons give R_c directly:
    passing candidates occupy [max(wvar), 2*max]; failing occupy [0, max].
    """
    span = float(wvar.max()) + 1.0 if wvar.size else 1.0
    return wvar + gate.astype(np.float64) * span


def ordering_experiment(
    offsets: np.ndarray, sizes: np.ndarray, wvar: np.ndarray,
    features: WindowFeatures, thr: KeyLikeThresholds, key_index: int,
    reference: np.ndarray,
) -> OrderingResult:
    gate = keylike_gate(features, thr)
    composite = _composite_rank_key(gate, wvar)
    r_var = int((wvar >= wvar[key_index]).sum())
    r_comp = int((composite >= composite[key_index]).sum())
    ref = np.frombuffer(reference, dtype=np.uint8) if isinstance(reference, (bytes, bytearray)) \
        else np.asarray(reference, dtype=np.uint8)
    # dedup potential: distinct window byte-content among the maximal set
    distinct = _distinct_window_count(ref, offsets, sizes)
    kf = {
        "wvar": float(wvar[key_index]),
        "min_entropy": float(features.min_entropy[key_index]),
        "shannon": float(features.shannon[key_index]),
        "chi2_uniform": float(features.chi2_uniform[key_index]),
        "abs_autocorr": float(features.abs_autocorr[key_index]),
        "ascii_frac": float(features.ascii_frac[key_index]),
    }
    return OrderingResult(
        key_index=int(key_index), r_var=r_var, r_composite=r_comp,
        maximal=int(offsets.size), key_passes_gate=bool(gate[key_index]),
        gate_pass_count=int(gate.sum()),
        distinct_windows=int(distinct), key_features=kf,
        clutter_at_ceiling=int((wvar >= 0.9 * SIGMA_K2).sum()),
        detail=("R_composite < R_var means the uniformity gate demotes structured "
                "high-variance clutter above the key; R_composite is still bounded "
                "below by clutter_at_ceiling (fresh uniform non-key), which only the "
                "oracle can separate."),
    )


def _distinct_window_count(ref: np.ndarray, offsets: np.ndarray,
                           sizes: np.ndarray, *, chunk: int = 20000) -> int:
    seen: set = set()
    for size in np.unique(sizes):
        offs = offsets[sizes == size]
        for start in range(0, offs.size, chunk):
            blk = offs[start:start + chunk]
            windows = ref[blk[:, None] + np.arange(int(size))]
            seen.update(map(bytes, windows))
    return len(seen)


# ─────────────────────────────────────────────────────────────────────
# A2 — floor-selection (trimmed-mean floor, ladder, descending knee, phi_theory)
# ─────────────────────────────────────────────────────────────────────
def trimmed_mean_window(variance: np.ndarray, offset: int, size: int,
                        trim: float = 0.1) -> float:
    """Trimmed mean of the per-byte variance over one window (robust to
    isolated low bytes from minor misalignment)."""
    w = np.sort(np.asarray(variance[offset:offset + size], dtype=np.float64))
    k = int(math.floor(trim * w.size))
    core = w[k:w.size - k] if w.size - 2 * k > 0 else w
    return float(core.mean()) if core.size else 0.0


def sigma_k2_interior(variance: np.ndarray, offsets: np.ndarray,
                      sizes: np.ndarray, *, min_bytes: int = 50) -> float:
    """P90 of interior (least-diluted) candidate byte variances, clamped to
    [0.5*ceiling, ceiling]; falls back to the ceiling when data is thin.

    Thin wrapper over the canonical estimator in ``engine.auto_floor`` (which
    returns None on too-few bytes) so both paths share one implementation.
    """
    est = _sigma_k2_interior(variance, offsets, sizes, min_bytes=min_bytes)
    return float(SIGMA_K2) if est is None else est


def phi_theory(p_min: float, sigma_k2: float = SIGMA_K2) -> float:
    return float(p_min * sigma_k2)


def floor_ladder(wvar: np.ndarray, ladder: Sequence[float] = DEFAULT_LADDER,
                 key_wvar: Optional[float] = None) -> List[dict]:
    """C(phi): candidate count (and key-retained flag) at each ladder floor."""
    out = []
    for phi in ladder:
        c = int((wvar >= phi).sum())
        row = {"phi": float(phi), "candidates": c}
        if key_wvar is not None:
            row["key_retained"] = bool(key_wvar >= phi)
        out.append(row)
    return out


def kneedle_descending(ladder: Sequence[float], counts: Sequence[int]) -> float:
    """Return the DEEPEST floor just ABOVE the heap-noise explosion.

    As phi descends the candidate count is non-decreasing; the heap-noise onset
    is the step with the largest count gain. We return the higher-phi side of
    that step — the deepest practical floor that still excludes the explosion,
    while retaining everything above it (incl. a diluted key in the bulk).

    Corrects the user's original 'highest floor with stable candidates' rule,
    which would lock onto fresh clutter at the ceiling and exclude the diluted
    key (which lives below it, in the bulk).
    """
    phis = np.asarray(ladder, dtype=np.float64)
    counts = np.asarray(counts, dtype=np.float64)
    order = np.argsort(-phis)              # descending phi → non-decreasing count
    phis, counts = phis[order], counts[order]
    if phis.size < 2:
        return float(phis[-1])
    gains = np.diff(counts)                # gain of each descending step
    step = int(np.argmax(gains))           # the explosion step
    return float(phis[step])               # floor just ABOVE the explosion


@dataclass
class FloorSelectionResult:
    ladder: List[dict]
    phi_knee: float
    sigma_k2_hat: float
    phi_theory: Dict[str, float]     # p_min -> phi
    key_wvar: float
    key_trimmed_mean: float
    key_retained_at_knee: bool
    key_retained_at_theory: Dict[str, bool]
    agree: bool                      # phi_knee within a factor of phi_theory(0.35)
    detail: str = ""

    def to_dict(self) -> dict:
        return {
            "ladder": self.ladder, "phi_knee": self.phi_knee,
            "sigma_k2_hat": self.sigma_k2_hat, "phi_theory": self.phi_theory,
            "key_wvar": self.key_wvar, "key_trimmed_mean": self.key_trimmed_mean,
            "key_retained_at_knee": self.key_retained_at_knee,
            "key_retained_at_theory": self.key_retained_at_theory,
            "agree": self.agree, "detail": self.detail,
        }


def floor_selection_experiment(
    variance: np.ndarray, offsets: np.ndarray, sizes: np.ndarray,
    wvar: np.ndarray, key_index: int, *,
    ladder: Sequence[float] = DEFAULT_LADDER, pmins: Sequence[float] = DEFAULT_PMINS,
) -> FloorSelectionResult:
    key_wvar = float(wvar[key_index])
    rows = floor_ladder(wvar, ladder, key_wvar=key_wvar)
    knee = kneedle_descending(ladder, [r["candidates"] for r in rows])
    sk2 = sigma_k2_interior(variance, offsets, sizes)
    theory = {f"{p:.2f}": phi_theory(p, sk2) for p in pmins}
    key_off = int(offsets[key_index]); key_sz = int(sizes[key_index])
    tmean = trimmed_mean_window(variance, key_off, key_sz)
    retained_theory = {k: bool(key_wvar >= v) for k, v in theory.items()}
    phi35 = theory.get("0.35", phi_theory(0.35, sk2))
    agree = bool(0.5 <= (knee / phi35 if phi35 else 0) <= 2.0)
    return FloorSelectionResult(
        ladder=rows, phi_knee=knee, sigma_k2_hat=sk2, phi_theory=theory,
        key_wvar=key_wvar, key_trimmed_mean=tmean,
        key_retained_at_knee=bool(key_wvar >= knee),
        key_retained_at_theory=retained_theory, agree=agree,
        detail=("phi_knee is the descending-Kneedle heap-noise onset (deepest "
                "practical floor); phi_theory=p_min*sigma_k2. Agreement near the "
                "manual region is the paper's two-independent-routes cross-check."),
    )


# ─────────────────────────────────────────────────────────────────────
# Optional: full dilution-tolerant composite from the N individual dumps
# ─────────────────────────────────────────────────────────────────────
def composite_rank_from_dumps(
    dumps: np.ndarray, offsets: np.ndarray, sizes: np.ndarray,
    thr: KeyLikeThresholds, *, w_tol: int = 8,
) -> np.ndarray:
    """Corrected dilution-tolerant statistic (needs the N individual dumps).

    A *persistent* secret (e.g. a master key) is the SAME content across runs
    but its offset JITTERS; per-run-*fresh* clutter (nonces/IVs) is DIFFERENT
    content each run; a *static table* is the same content at the SAME offset.
    The discriminating score for the diluted key is therefore:

        score(i) = #{runs r : reference-content recurs within +/-w_tol of i}
                   IF (uniform) AND (displaced OR fixed-offset varies) ELSE 0

    - recurrence kills per-run-fresh clutter (run-0 content is not found in the
      other runs → recurrence ~ 1);
    - the displaced/varies requirement kills a static table (recurs at d=0 with
      zero fixed-offset variance);
    - the uniform gate kills structured windows (ramps/counters/pointers).

    This separates the key even from *fresh* clutter — something the
    consensus-only :func:`ordering_experiment` cannot do — which is why it is
    worth the cost of holding the per-dump matrix.  Returns a per-candidate score.
    """
    N, total = dumps.shape
    scores = np.zeros(offsets.size, dtype=np.float64)
    window = 2 * w_tol + 1
    for ci, (off, size) in enumerate(zip(offsets.tolist(), sizes.tolist())):
        ref_content = dumps[0, off:off + size]
        if ref_content.size < size or not bool(
                keylike_gate(_features_for_windows(ref_content[None, :]), thr)[0]):
            continue
        # For each displacement d in [-w_tol, +w_tol] compare the shifted
        # window against ref_content across ALL runs at once (vectorized over
        # the run axis), replacing the former per-run ``np.array_equal`` scan.
        # ``matches[k, r]`` is True iff run r's window at d = k - w_tol equals
        # ref_content; invalid (out-of-bounds) displacements stay False.
        matches = np.zeros((window, N), dtype=bool)
        for k in range(window):
            lo = off + (k - w_tol)
            if lo < 0 or lo + size > total:
                continue
            matches[k] = (dumps[:, lo:lo + size] == ref_content).all(axis=1)
        matched_any = matches.any(axis=0)
        recur = int(matched_any.sum())
        # ``argmax`` over the displacement axis returns the FIRST True index,
        # matching the original break-on-first-match (ascending d) semantics.
        first_k = matches.argmax(axis=0)
        displaced = bool(np.any(matched_any & (first_k != w_tol)))
        # d = 0 is always in-bounds here (it is ref_content's own window), so
        # row ``w_tol`` is a real comparison: all runs identical at fixed offset.
        fixed_offset_identical = bool(matches[w_tol].all())
        varies = displaced or not fixed_offset_identical
        scores[ci] = float(recur) if (recur >= 2 and varies) else 0.0
    return scores


# ─────────────────────────────────────────────────────────────────────
# Orchestration + I/O
# ─────────────────────────────────────────────────────────────────────
@dataclass
class PhaseAResult:
    ordering: OrderingResult
    floor: FloorSelectionResult
    thresholds: KeyLikeThresholds
    key_offset: int
    key_size: int
    subsample: Optional["SubsampleStabilityResult"] = None  # A3, only when halves given

    def to_dict(self) -> dict:
        d = {
            "ordering": self.ordering.to_dict(),
            "floor": self.floor.to_dict(),
            "thresholds": self.thresholds.__dict__,
            "key_offset": self.key_offset, "key_size": self.key_size,
        }
        if self.subsample is not None:
            d["subsample"] = self.subsample.to_dict()
        return d


def run_phase_a(
    variance: np.ndarray, reference: bytes, num_dumps: int, key_offset: int,
    *, key_size: int = 32, stride: int = 8, reduce_kwargs: Optional[dict] = None,
    var_a: Optional[np.ndarray] = None, var_b: Optional[np.ndarray] = None,
    num_a: int = 0, num_b: int = 0,
) -> PhaseAResult:
    """Run A1 + A2 (+ optional experimental A3) on a consensus (variance +
    reference) with a KNOWN key offset. When both ``var_a`` and ``var_b``
    complementary-half variance arrays are supplied, the experimental
    subsample-stability instrument (A3) is also computed."""
    reduce_kwargs = dict(reduce_kwargs or {})
    # Phase-A only needs the maximal set (floor disabled); no default_set.
    offsets, sizes, wvar = floor_policy.enumerate_maximal(
        variance, reference, num_dumps, reduce_kwargs, (key_size,), stride,
        min_variance=0.0,
    )
    if offsets.size == 0:
        raise ValueError("maximal candidate set is empty (check reduce_kwargs/data)")
    key_index = _locate_key_index(offsets, sizes, key_offset, key_size)
    feats = compute_window_features(reference, offsets, sizes)
    thr = calibrate_thresholds(key_size)
    ref_u8 = np.frombuffer(reference, dtype=np.uint8)
    ordering = ordering_experiment(offsets, sizes, wvar, feats, thr, key_index, ref_u8)
    floor = floor_selection_experiment(variance, offsets, sizes, wvar, key_index)
    subsample = None
    if var_a is not None and var_b is not None:
        from memdiver.engine.subsample_stability import subsample_experiment
        subsample = subsample_experiment(
            var_a, var_b, offsets, sizes, wvar, key_index, num_a, num_b
        )
    return PhaseAResult(ordering=ordering, floor=floor, thresholds=thr,
                        key_offset=int(key_offset), key_size=int(key_size),
                        subsample=subsample)


def _locate_key_index(offsets: np.ndarray, sizes: np.ndarray,
                      key_offset: int, key_size: int) -> int:
    """Index of the candidate whose window contains the key at ``key_offset``.

    The stride grid may not land exactly on the key; pick the candidate window
    that starts closest at or before the key and fully covers it, else the
    nearest by start offset.
    """
    exact = np.nonzero((offsets == key_offset) & (sizes == key_size))[0]
    if exact.size:
        return int(exact[0])
    covers = np.nonzero((offsets <= key_offset)
                        & (offsets + sizes >= key_offset + key_size))[0]
    if covers.size:
        return int(covers[np.argmax(offsets[covers])])
    return int(np.argmin(np.abs(offsets - key_offset)))


def render_report(result: PhaseAResult) -> str:
    # Text/markdown logic lives in the presentation layer; lazy import keeps
    # engine free of a module-load cycle.
    from memdiver.presentation.reports import candidate_report_md
    return candidate_report_md(result)


def load_consensus(artifact_dir: Path) -> Tuple[np.ndarray, bytes, int]:
    """Load (variance, reference, num_dumps) from a pipeline consensus dir."""
    artifact_dir = Path(artifact_dir)
    variance = np.load(artifact_dir / "variance.npy")
    reference = (artifact_dir / "reference.bin").read_bytes()
    num_dumps = 0
    meta = artifact_dir / "meta.json"
    if meta.exists():
        num_dumps = int(json.loads(meta.read_text()).get("num_dumps", 0))
    return variance, reference, num_dumps
