"""Held-out validation of an exported artifact-model plugin (P4, memo §9/§10).

The plugin is run exactly as it would be deployed — one capture, no corpus,
no agent — and its rows are scored against ground truth the plugin never saw.

**Memory-access contract.** A ``structure`` plugin decodes fields at fixed
deltas, which is only sound on a virtually contiguous layer. A capture's
CAPTURED VA runs are exactly that, so each run is materialized as its own
buffer and scanned with ``contiguous=True``. Runs are never concatenated:
gluing two non-adjacent runs would fabricate contiguity at the seam (and a
"field" read across it). Uncaptured memory is reported, never scanned as zeros.

**Scoring.** Ground truth is a set of ``(label, owner_hex, value_hex)``
triples, e.g. NSS keylog lines ``(CLIENT_TRAFFIC_SECRET_0, client_random,
secret)``. A recovered row is a true positive when ``(label, value)`` is
expected; its relationship is correct when the owner matches too. Every
other ``ok`` row of an expected label is a false positive.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Mapping, Optional, Sequence, Set, Tuple

from memdiver.architect.artifact_model import HeldOutResult, Validation

Triple = Tuple[str, str, str]  # (label, owner_hex, value_hex)


@dataclass
class CaptureRun:
    """The plugin's rows on one capture, with what was and wasn't scanned."""

    capture: str
    rows: List[Dict[str, Any]] = field(default_factory=list)
    scanned_bytes: int = 0
    scanned_runs: int = 0
    seconds: float = 0.0


def run_plugin_on_capture(plugin_source: str, source: Any, capture: str, *,
                          min_run: int = 64) -> CaptureRun:
    """Scan every captured VA run of an OPENED VA-bearing *source* separately."""
    from memdiver.engine.vol3_verify import run_rows_over_buffer
    span = source.va_span_start()
    if span is None:
        raise ValueError(f"{capture}: no open VA view; open the source first")
    out, started = CaptureRun(capture=capture), time.monotonic()
    for run_va, data in _captured_buffers(source, span, min_run):
        rows = run_rows_over_buffer(plugin_source, data, extra_config={"contiguous": True})
        out.rows += [_with_va(row, run_va) for row in rows]
        out.scanned_bytes += len(data)
        out.scanned_runs += 1
    out.seconds = round(time.monotonic() - started, 3)
    return out


def _captured_buffers(source: Any, span: int, min_run: int) -> Iterable[Tuple[int, bytes]]:
    """``(va, bytes)`` per captured sub-run (a truncated run yields only its captured part)."""
    for run_va, length, _vas in source.captured_runs():
        if length < min_run:
            continue
        data, valid = source.read_range_valid(run_va - span, length, "va")
        for start, n in valid:
            if n >= min_run:
                yield run_va + start, data[start:start + n]


def _with_va(row: Dict[str, Any], run_va: int) -> Dict[str, Any]:
    out = dict(row)
    for key in ("StructOffset", "PatternOffset"):
        if isinstance(out.get(key), int):
            out[key.replace("Offset", "VA")] = run_va + out[key]
    return out


def score_capture(run: CaptureRun, expected: Set[Triple],
                  labels: Optional[Sequence[str]] = None,
                  owned_labels: Optional[Set[str]] = None) -> HeldOutResult:
    """Score one capture; only *labels* (default: the expected labels) count.

    Relationships are checked only for *owned_labels* (the labels whose field
    is the source of an ``owned_by`` relationship); ``None`` checks none."""
    owned = set(owned_labels or ())
    wanted = set(labels) if labels is not None else {t[0] for t in expected}
    found = _recovered_triples(run.rows, wanted)
    by_value = {(label, value): owner for label, owner, value in expected}
    hits = {(label, value) for label, _owner, value in found if (label, value) in by_value}
    owners_ok = {t for t in found if t[0] in owned and by_value.get((t[0], t[2])) == t[1]}
    return HeldOutResult(
        capture=run.capture, expected=len(expected), true_positives=len(hits),
        false_positives=len({(t[0], t[2]) for t in found} - hits),
        false_negatives=len(set(by_value) - hits),
        relationships_correct=len(owners_ok), relationships_checked=len({h for h in hits if h[0] in owned}),
        detail=f"{run.scanned_runs} runs / {run.scanned_bytes} bytes scanned in {run.seconds}s")


def _recovered_triples(rows: Sequence[Dict[str, Any]], labels: Set[str]) -> Set[Triple]:
    return {(str(r.get("Label")), str(r.get("OwnerHex") or "").lower(), str(r.get("ValueHex")).lower())
            for r in rows if r.get("Status") == "ok" and r.get("Label") in labels}


def capture_verdict(result: HeldOutResult, scanned_runs: int) -> str:
    """One capture's verdict. Nothing expected or nothing scanned proves nothing
    (``indeterminate``); else ``pass`` only when exact: all expected found, no
    false positive, every checked relationship right."""
    if result.expected == 0 or scanned_runs <= 0:
        return "indeterminate"
    exact = (result.false_negatives == 0 and result.false_positives == 0
             and result.relationships_correct == result.relationships_checked)
    return "pass" if exact else "fail"


def verdict(results: Sequence[HeldOutResult], scanned_runs: Mapping[str, int]) -> str:
    """``fail`` if any capture fails; else ``indeterminate`` if any capture (or
    the whole set) is indeterminate; else ``pass``. A capture missing from
    *scanned_runs* counts as nothing scanned."""
    if not results:
        return "indeterminate"
    each = [capture_verdict(r, scanned_runs.get(r.capture, 0)) for r in results]
    if "fail" in each:
        return "fail"
    return "indeterminate" if "indeterminate" in each else "pass"


def validation_record(learned_on: Sequence[str], results: Sequence[HeldOutResult],
                      scanned_runs: Mapping[str, int]) -> Validation:
    held = {r.capture for r in results}
    leaked = held & set(learned_on)
    if leaked:
        raise ValueError(f"held-out captures were used for learning: {sorted(leaked)}")
    return Validation(learned_on=tuple(learned_on), held_out=tuple(results),
                      verdict=verdict(results, scanned_runs))
