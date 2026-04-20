"""JSON serialization for MemDiver result types."""

from pathlib import Path
from typing import Any, Dict


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
    """Serialize a SecretHit to a JSON-compatible dict."""
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
        "metadata": _convert_value(hit.metadata),
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
    """Serialize a LibraryReport to a JSON-compatible dict."""
    return {
        "library": report.library,
        "protocol_version": report.protocol_version,
        "phase": report.phase,
        "num_runs": report.num_runs,
        "hits": [serialize_hit(h) for h in report.hits],
        "static_regions": [serialize_static_region(r) for r in report.static_regions],
        "metadata": _convert_value(report.metadata),
    }


def serialize_result(result) -> Dict[str, Any]:
    """Serialize an AnalysisResult to a JSON-compatible dict."""
    return {
        "libraries": [serialize_report(lib) for lib in result.libraries],
        "total_hits": result.total_hits,
        "metadata": _convert_value(result.metadata),
    }


# ---------------------------------------------------------------------------
# Deserialization (inverse of above)
# ---------------------------------------------------------------------------


def deserialize_hit(data: Dict[str, Any]):
    """Deserialize a dict into a SecretHit."""
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
    )


def deserialize_report(data: Dict[str, Any]):
    """Deserialize a dict into a LibraryReport."""
    from .results import LibraryReport
    return LibraryReport(
        library=data.get("library", ""),
        protocol_version=data.get("protocol_version", ""),
        phase=data.get("phase", ""),
        num_runs=data.get("num_runs", 0),
        hits=[deserialize_hit(h) for h in data.get("hits", [])],
        static_regions=[],  # StaticRegion reconstruction deferred
        metadata=data.get("metadata", {}),
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
    }
