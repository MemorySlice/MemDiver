"""JSON serialization for MemDiver result types."""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING, Any, Dict, Union

if TYPE_CHECKING:
    from .results import AnalysisResult


def _convert_value(value: Any) -> Any:
    """Recursively convert non-JSON-serializable values."""
    if isinstance(value, Path):
        return str(value)
    if isinstance(value, bytes):
        return value.hex()
    if isinstance(value, set):
        return sorted(value)
    if isinstance(value, dict):
        return {str(k): _convert_value(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_convert_value(item) for item in value]
    return value


def serialize_hit(hit) -> Dict[str, Any]:
    """Serialize a SecretHit to a JSON-compatible dict.

    APPEND-ONLY. ``frontend/src/api/types.ts`` consumes this exact shape, and
    so does :func:`engine.project_db._finding_row_from_hit`; keys may be added
    but never reordered, renamed or dropped.

    THE SERIALIZER PROMOTES, THE READER DOES NOT DIG. ``_finding_row_from_hit``
    reads ``value_hex``, ``canonical_phase``, ``cipher`` and ``confirmed_by``
    at the TOP LEVEL of the hit dict. ``cipher`` / ``confirmed_by`` are produced
    by the verification path inside ``metadata``, so on the serialized path
    (``engine/batch.py`` -> ``serialize_result`` -> ``persist_report``, which
    is supported but dormant — see :func:`serialize_report`) the reader found
    neither and every confirmed key persisted with an empty
    ``value_hex`` and no confirmation marker. The fix is HERE rather than in the
    reader: the reader is shared with hit dicts that never had a ``metadata``
    sub-dict at all (the brute-force / oracle producers pass these keys flat),
    so teaching it to dig would only add a second spelling. The metadata copy is
    KEPT as well -- this mirrors, it does not move.
    """
    metadata = _convert_value(hit.metadata)
    return {
        "secret_type": hit.secret_type,
        "offset": hit.offset,
        "length": hit.length,
        "dump_path": str(hit.dump_path),
        "library": hit.library,
        "phase": hit.phase,
        "run_id": hit.run_id,
        "confidence": hit.confidence,
        "verified": hit.verified,
        "metadata": metadata,
        "value_hex": hit.value_hex,
        "canonical_phase": hit.canonical_phase,
        # Mirrors of the two verification labels, promoted out of `metadata`
        # so the shared findings/ground_truth reader sees them.
        "cipher": metadata.get("cipher") if isinstance(metadata, dict) else None,
        "confirmed_by": (metadata.get("confirmed_by")
                         if isinstance(metadata, dict) else None),
    }


def serialize_static_region(region) -> Dict[str, Any]:
    """Serialize a StaticRegion to a JSON-compatible dict."""
    return {
        "start": region.start,
        "end": region.end,
        "length": region.length,
        "mean_variance": region.mean_variance,
        "classification": region.classification,
    }


def serialize_report(report) -> Dict[str, Any]:
    """Serialize a LibraryReport to a JSON-compatible dict.

    APPEND-ONLY, for the same reason as :func:`serialize_hit`.

    The five appended keys are the corpus axes
    :meth:`engine.project_db.ProjectDB.persist_report` reads. That writer's
    axis columns were all default-valued because the serializer dropped the
    keys — and, until :meth:`engine.pipeline.AnalysisPipeline.analyze_library`
    was taught to populate them, because no production constructor set them
    either. The tests hid both by hand-building the wide dict.

    WHICH PATH IS LIVE. ``persist_report`` is SUPPORTED BUT DORMANT, not "the
    ONLY production path into the project database" as this docstring and its
    neighbours used to say. It has no production caller at all: it is reached
    only from ``engine/batch.py``, and only when ``BatchRunner`` was handed a
    ``project_db`` — which neither production construction
    (``app/pipeline/batch_task_runner.py``, ``cli/dataset.py``) does, and
    ``run_analysis_request`` builds its ``AnalysisPipeline`` with
    ``project_db=None``. The writer that actually runs today is
    ``engine.pipeline.AnalysisPipeline._persist_report``, which reads the same
    axes straight off the :class:`engine.results.LibraryReport`. Both must
    carry them, so this serializer stays in lockstep.
    """
    return {
        "library": report.library,
        "protocol_version": report.protocol_version,
        "phase": report.phase,
        "num_runs": report.num_runs,
        "hits": [serialize_hit(h) for h in report.hits],
        "static_regions": [serialize_static_region(r) for r in report.static_regions],
        "metadata": _convert_value(report.metadata),
        "canonical_phase": report.canonical_phase,
        "library_version": report.library_version,
        "scenario": report.scenario,
        "protocol": report.protocol,
        "version_axis": report.version_axis,
    }


def serialize_result(result) -> Dict[str, Any]:
    """Serialize an AnalysisResult to a JSON-compatible dict."""
    return {
        "libraries": [serialize_report(lib) for lib in result.libraries],
        "total_hits": result.total_hits,
        "metadata": _convert_value(result.metadata),
    }


def summarize_result(result: Union["AnalysisResult", Dict[str, Any]]) -> Dict[str, Any]:
    """Project an analysis result into a compact terminal/API summary.

    This is the single source of truth for the ``{library_count, total_hits,
    libraries: [{library, phase, num_runs, hit_count}]}`` shape consumed by
    the analysis task runner. It accepts either an :class:`AnalysisResult`
    dataclass or its already-serialized dict; a dataclass is first routed
    through :func:`serialize_result` so both inputs produce identical,
    JSON-safe output.
    """
    if not isinstance(result, dict):
        result = serialize_result(result)
    libraries = result.get("libraries", []) or []
    total_hits = sum(len(lib.get("hits", []) or []) for lib in libraries)
    return {
        "library_count": len(libraries),
        "total_hits": total_hits,
        "libraries": [
            {
                "library": lib.get("library"),
                "phase": lib.get("phase"),
                "num_runs": lib.get("num_runs", 0),
                "hit_count": len(lib.get("hits", []) or []),
            }
            for lib in libraries
        ],
    }


# ---------------------------------------------------------------------------
# Deserialization (inverse of above)
# ---------------------------------------------------------------------------


def deserialize_hit(data: Dict[str, Any]):
    """Deserialize a dict into a SecretHit.

    Widened in lockstep with :func:`serialize_hit` -- a key added to one and
    not the other is silently lost on every round trip.

    ``cipher`` / ``confirmed_by`` are deliberately NOT read back: they are
    mirrors of ``metadata`` entries, which round-trip through ``metadata``
    itself, and :class:`engine.results.SecretHit` has no field for them.

    WARNING FOR ANY FUTURE CALLER — a promote-then-not-read-back round trip
    LOSES a top-level-only label. ``serialize_hit(deserialize_hit(d))`` turns
    ``confirmed_by="pcap"`` into ``None`` whenever the label was stamped at
    the top level WITHOUT a matching ``metadata`` entry, because this function
    reconstructs the labels from ``metadata`` alone — a pcap proof would come
    back out relabelled as a plain verifier guess. That is not live today
    (this function has no production caller), but ``app/tools_pipeline.py``
    already stamps ``hit["confirmed_by"]`` top-level-only on brute-force hit
    dicts, so a caller that ever routes those through here would hit it. Fix
    it by mirroring the label INTO ``metadata`` at the producer, not by
    inventing a ``SecretHit`` field the writers do not read.
    """
    from .results import SecretHit
    return SecretHit(
        secret_type=data.get("secret_type", ""),
        offset=data.get("offset", 0),
        length=data.get("length", 0),
        dump_path=Path(data.get("dump_path", "")),
        library=data.get("library", ""),
        phase=data.get("phase", ""),
        run_id=data.get("run_id", 0),
        confidence=data.get("confidence", 1.0),
        verified=data.get("verified"),
        metadata=data.get("metadata", {}),
        value_hex=data.get("value_hex"),
        canonical_phase=data.get("canonical_phase", "") or "",
    )


def deserialize_report(data: Dict[str, Any]):
    """Deserialize a dict into a LibraryReport.

    Widened in lockstep with :func:`serialize_report`. Each fallback is the
    column default, so a narrow (pre-axis) dict deserializes to exactly the
    report it used to.
    """
    from .results import LibraryReport
    return LibraryReport(
        library=data.get("library", ""),
        protocol_version=data.get("protocol_version", ""),
        phase=data.get("phase", ""),
        num_runs=data.get("num_runs", 0),
        hits=[deserialize_hit(h) for h in data.get("hits", [])],
        static_regions=[],  # StaticRegion reconstruction deferred
        metadata=data.get("metadata", {}),
        canonical_phase=data.get("canonical_phase", "") or "",
        library_version=data.get("library_version", "unknown") or "unknown",
        version_axis=(data.get("version_axis", "protocol_version")
                      or "protocol_version"),
        scenario=data.get("scenario", "") or "",
        protocol=data.get("protocol", "") or "",
    )


def deserialize_result(data: Dict[str, Any]):
    """Deserialize a dict into an AnalysisResult."""
    from .results import AnalysisResult
    result = AnalysisResult()
    for lib_data in data.get("libraries", []):
        result.libraries.append(deserialize_report(lib_data))
    result.metadata = data.get("metadata", {})
    return result


def serialize_convergence_point(point) -> Dict[str, Any]:
    """Serialize a ConvergencePoint to a JSON-compatible dict."""
    def _metrics(m):
        if m is None:
            return None
        return {"tp": m.tp, "fp": m.fp, "precision": m.precision,
                "recall": m.recall, "candidates": m.candidates}
    return {
        "n": point.n,
        "variance": _metrics(point.variance),
        "combined": _metrics(point.combined),
        "aligned": _metrics(point.aligned),
        "decryption_verified": point.decryption_verified,
    }


def serialize_convergence_result(result) -> Dict[str, Any]:
    """Serialize a ConvergenceSweepResult to a JSON-compatible dict."""
    return {
        "points": [serialize_convergence_point(p) for p in result.points],
        "first_detection_n": result.first_detection_n,
        "first_decryption_n": result.first_decryption_n,
        "first_fp_target_n": result.first_fp_target_n,
        "total_dumps": result.total_dumps,
        "max_fp": result.max_fp,
    }


def serialize_verification_result(result) -> Dict[str, Any]:
    """Serialize a VerificationResult to a JSON-compatible dict."""
    return {
        "offset": result.offset,
        "key_hex": result.key_hex,
        "cipher_name": result.cipher_name,
        "verified": result.verified,
    }


def serialize_dataset_info(info) -> Dict[str, Any]:
    """Serialize a DatasetInfo to a JSON-compatible dict."""
    return {
        "root": str(info.root),
        "protocol_versions": sorted(info.protocol_versions),
        "scenarios": _convert_value(info.scenarios),
        "libraries": {k: sorted(v) for k, v in info.libraries.items()},
        "phases": _convert_value(info.phases),
        "normalized_phases": _convert_value(info.normalized_phases),
        "total_runs": info.total_runs,
        "runs_with_capture": info.runs_with_capture,
        "captures": _convert_value(info.captures),
    }
