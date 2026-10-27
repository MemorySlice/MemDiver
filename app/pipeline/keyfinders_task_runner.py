"""TaskManager worker entry for a long ``keyfinders.scan``.

A scan over a multi-GB capture outlives a sensible HTTP request, so REST submits
it as a job when the captured bytes to read exceed the inline budget or the
caller sets ``async``. The worker reuses the shared producer
:func:`memdiver.app.tools_keyfinders.keyfinders_scan_result`, forwards its progress
callback as ``progress`` events, writes the producer payload as the
``keyfinders_result`` artifact (``keyfinders/result.json``) and sends it as the
terminal ``summary``.

Top-level and lazily importing so the spawn worker can pickle it and an import
problem surfaces as a reported task failure.
"""

from __future__ import annotations

from typing import Any, Dict

from memdiver.app.pipeline.artifact_paths import task_result_artifact
from memdiver.app.pipeline.progress_emitter import progress_emitter

STAGE = "keyfinders"


def run_keyfinders_job(params: Dict[str, Any], ctx) -> Dict[str, Any]:
    """Worker entry. ``params``: ``args`` (``keyfinders_scan_result`` kwargs),
    ``task_root`` / ``artifact_dir``. Returns ``{"artifacts": [...], "summary": {...}}``."""
    from memdiver.app.tools_keyfinders import keyfinders_scan_result
    from memdiver.core.service_errors import CapabilityError
    args = dict(params.get("args", {}))
    ctx.emit("stage_start", stage=STAGE, pct=0.0,
             msg=f"key-finder scan {','.join(args.get('finders', ()))}")
    try:
        payload = dict(keyfinders_scan_result(
            progress=progress_emitter(ctx, STAGE, "key-finder scan"), **args).payload)
    except CapabilityError as exc:
        ctx.emit("error", error=exc.message)
        raise ValueError(exc.message) from exc
    artifact = task_result_artifact(payload, params, ctx, "keyfinders")
    ctx.emit("stage_end", stage=STAGE, pct=1.0, msg="key-finder scan done",
             extra={"row_count": payload["row_count"], "truncated": payload["truncated"]})
    return {"artifacts": [artifact], "summary": payload}
