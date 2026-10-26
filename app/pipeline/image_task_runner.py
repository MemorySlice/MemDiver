"""TaskManager worker entry for the slow ``image.*`` capabilities.

``image_profile`` (pakunoda maps the whole image), ``image_open_view`` (first
sha256 of a multi-GB file) and ``image_extract_process`` (walks every VMA) and ``case_export`` (walks a view's
runs / an ``.msl``'s heap) run
as jobs on REST. One top-level runner dispatches on ``params["job"]`` and reuses
the shared producers, so the job result is exactly the producer payload; it is
written as the ``image_result`` artifact (``image/result.json``) and also sent
as the terminal ``summary``.

The function stays top-level and imports lazily so the spawn worker can pickle
it and an import problem surfaces as a reported task failure.
"""

from __future__ import annotations

import json
from typing import Any, Dict

from memdiver.app.pipeline.artifact_paths import resolve_artifact_dir

STAGE = "image"
JOBS = ("profile", "open_view", "extract_process", "case_export", "isf_probe", "isf_try",
        "code_evidence")


def _pakunoda_progress(ctx):
    """Adapter: pakunoda ``(stage, elapsed_s)`` -> a ``progress`` event (frontend contract)."""
    def emit(stage: str, elapsed: float) -> None:
        ctx.emit("progress", stage=STAGE, pct=0.0, msg=f"{stage}",
                 extra={"pakunoda_stage": stage, "elapsed_s": round(elapsed, 1)})
    return emit


def _job_controls(job: str, ctx) -> Dict[str, Any]:
    """Job controls: profile and the ISF jobs take progress + cancel (same event shape)."""
    if job == "profile":
        return {"progress": _pakunoda_progress(ctx), "cancel": ctx.is_cancelled}
    if job in ("isf_probe", "isf_try"):
        return {"progress": _pakunoda_progress(ctx), "cancel": ctx.is_cancelled}
    return {}


def _call_producer(job: str, args: Dict[str, Any], **controls: Any) -> Dict[str, Any]:
    from memdiver.app import tools_case, tools_code_evidence, tools_image, tools_isf
    producers = {"code_evidence": tools_code_evidence.code_evidence_result,
"profile": tools_image.image_profile_result,
                 "open_view": tools_image.image_open_view_result,
                 "extract_process": tools_image.image_extract_process_result,
                 "case_export": tools_case.case_export_result,
                 "isf_probe": tools_isf.isf_probe_result,
                 "isf_try": tools_isf.isf_try_result}
    return dict(producers[job](**args, **controls).payload)


def _write_artifact(payload: Dict[str, Any], params: Dict[str, Any], ctx) -> Dict[str, Any]:
    from memdiver.core.artifact_util import sha256_streamed
    relpath = "image/result.json"
    out = resolve_artifact_dir(params, ctx, fallback_subdir="./image_output") / relpath
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(payload, indent=2))
    return {"name": "image_result", "relpath": relpath, "media_type": "application/json",
            "size": out.stat().st_size, "sha256": sha256_streamed(out)}


def run_image_job(params: Dict[str, Any], ctx) -> Dict[str, Any]:
    """Worker entry. ``params``: ``job`` (one of :data:`JOBS`), ``args`` (producer kwargs),
    ``task_root`` / ``artifact_dir``. Returns ``{"artifacts": [...], "summary": {...}}``."""
    from memdiver.core.service_errors import CapabilityError
    job = params.get("job")
    if job not in JOBS:
        raise ValueError(f"unknown image job: {job!r}")
    ctx.emit("stage_start", stage=STAGE, pct=0.0, msg=f"image {job}")
    try:
        payload = _call_producer(job, dict(params.get("args", {})), **_job_controls(job, ctx))
    except CapabilityError as exc:
        if exc.code == "cancelled":
            ctx.emit("error", error="cancelled")
            raise RuntimeError(f"image {job} cancelled") from exc
        ctx.emit("error", error=exc.message)
        raise ValueError(exc.message) from exc
    artifact = _write_artifact(payload, params, ctx)
    ctx.emit("stage_end", stage=STAGE, pct=1.0, msg=f"image {job} done", extra=payload)
    return {"artifacts": [artifact], "summary": payload}
