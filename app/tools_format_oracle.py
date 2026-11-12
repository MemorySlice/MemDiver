"""Format oracles as a BYO-oracle source: list, suggest, build a spec.

The shipped format oracles (:mod:`memdiver.oracles.formats`) prove a key from
an artefact alone (a vault file, a LUKS header, ...). These producers make them
usable through MemDiver's existing BYO-oracle stage on every surface:

* :func:`list_format_oracles_result` -- what exists (kind, candidate lengths,
  cost per call, the evidence it needs, whether one sample admits one key);
* :func:`suggest_format_oracle_result` -- which kind fits a dump, with the
  sample derived from the dump's own run where possible, and always WHY;
* :func:`format_oracle_spec_result` -- build and validate one format oracle and
  return the Shape-2 ``oracle_path`` + ``oracle_config`` pair that
  ``brute_force`` / ``n_sweep`` / the web registry accept, optionally grading
  candidate keys (a dry run).

The web registry (``POST /api/oracles/formats/{kind}``) registers the spec as
an UNARMED entry so arm / dry-run / smoke-test apply unchanged.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional, Sequence

from memdiver.core.service_errors import CapabilityError, ErrorCategory
from memdiver.core.service_result import ServiceResult

#: Most candidates one spec call grades: each can cost a KDF (LUKS: ~0.1 s).
MAX_GRADED_CANDIDATES = 64


def list_format_oracles_result() -> ServiceResult:
    """Every format oracle with its static facts, sorted by kind."""
    from memdiver.engine.resources.format_oracle import describe_format, list_format_kinds

    formats = [describe_format(kind) for kind in list_format_kinds()]
    return ServiceResult.ok({"formats": formats, "count": len(formats)})


def suggest_format_oracle_result(dump_path: str) -> ServiceResult:
    """The format oracle that fits *dump_path*, with its reason (or why none fits)."""
    from pathlib import Path

    from memdiver.app.oracle_autoconfig import suggest_format_oracle

    if not dump_path or not Path(dump_path).expanduser().exists():
        raise CapabilityError(
            f"dump_path {dump_path!r} does not exist",
            category=ErrorCategory.NOT_FOUND,
        )
    suggestion, reason = suggest_format_oracle(dump_path)
    return ServiceResult.ok({
        "dump_path": str(dump_path),
        "suggestion": suggestion.to_dict() if suggestion is not None else None,
        "reason": reason,
    })


def format_oracle_spec_result(
    kind: str,
    oracle_sample_path: Optional[str] = None,
    sample_b64: Optional[str] = None,
    params: Optional[Dict[str, Any]] = None,
    candidates_hex: Optional[Sequence[str]] = None,
) -> ServiceResult:
    """Build format oracle *kind* and return its Shape-2 spec (+ graded candidates).

    The returned ``oracle_config`` carries the sample inline (``sample_b64``),
    so it can be handed straight to ``brute_force(oracle_path=...,
    oracle_config=...)``. ``candidates_hex`` are graded without ever being
    echoed: each row reports only index, length, status and detail.
    """
    from memdiver.engine.resources.builtin_oracle import BUILTIN_ORACLE_PATH
    from memdiver.engine.resources.format_oracle import describe_format, format_oracle_config

    try:
        facts = describe_format(kind)
        config, adapter = format_oracle_config(
            kind, params=params, sample_path=oracle_sample_path, sample_b64=sample_b64,
        )
    except (OSError, ValueError) as exc:
        raise CapabilityError(
            f"format oracle {kind!r} could not be built: {exc}",
            category=ErrorCategory.INVALID_INPUT,
        ) from exc
    try:
        graded = _grade(adapter, candidates_hex or ())
        payload = {
            **facts,
            "candidate_lengths": [int(n) for n in adapter.candidate_lengths],
            "cost_us": adapter.cost_us,
            "unique": adapter.unique,
            "sample_bytes": adapter.sample_size,
            "oracle_path": BUILTIN_ORACLE_PATH,
            "oracle_config": config,
            "graded": graded,
            "proven": sum(1 for row in graded if row["status"] == "proven"),
        }
    finally:
        adapter.close()
    return ServiceResult.ok(payload)


def _grade(adapter: Any, candidates_hex: Sequence[str]) -> List[Dict[str, Any]]:
    if len(candidates_hex) > MAX_GRADED_CANDIDATES:
        raise CapabilityError(
            f"{len(candidates_hex)} candidates; grade at most {MAX_GRADED_CANDIDATES} per call",
            category=ErrorCategory.INVALID_INPUT,
        )
    rows: List[Dict[str, Any]] = []
    for index, text in enumerate(candidates_hex):
        try:
            candidate = bytes.fromhex(str(text).strip())
        except ValueError:
            raise CapabilityError(
                f"candidate {index} is not hex", category=ErrorCategory.INVALID_INPUT,
            ) from None
        adapter.verify(candidate)
        verdict = adapter.last_verdict
        rows.append({"index": index, "length": len(candidate),
                     "status": verdict.status, "detail": verdict.detail})
    return rows
