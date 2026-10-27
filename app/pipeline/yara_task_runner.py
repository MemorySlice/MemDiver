"""TaskManager worker entry for a long ``yara.scan``.

A YARA scan over a multi-GB capture outlives a sensible HTTP request, so REST submits it
as a job when the captured bytes to read exceed the inline budget or the caller sets
``async``. The worker reuses the shared producer
:func:`memdiver.app.tools_yara.yara_scan_dump_result`, forwards its per-window progress
(bytes scanned over captured bytes in scope: an honest fraction) as ``progress`` events,
polls ``ctx.is_cancelled`` between windows (a cancelled scan ends the task as cancelled,
never as ``complete``), writes the producer payload as the ``yara_result`` artifact
(``yara/result.json``) and sends it as the terminal ``summary``.

Top-level and lazily importing so the spawn worker can pickle it and an import problem
surfaces as a reported task failure.
"""

from __future__ import annotations

from typing import Any, Dict

from memdiver.app.pipeline.artifact_paths import task_result_artifact
from memdiver.app.pipeline.progress_emitter import progress_emitter

STAGE = "yara"


def run_yara_job(params: Dict[str, Any], ctx) -> Dict[str, Any]:
    """Worker entry. ``params``: ``args`` (``yara_scan_dump_result`` kwargs),
    ``task_root`` / ``artifact_dir``. Returns ``{"artifacts": [...], "summary": {...}}``."""
    from memdiver.app.tools_yara import yara_scan_dump_result
    from memdiver.core.service_errors import CapabilityError
    args = dict(params.get("args", {}))
    ctx.emit("stage_start", stage=STAGE, pct=0.0, msg="YARA scan")
    try:
        payload = dict(yara_scan_dump_result(
            progress=progress_emitter(ctx, STAGE, "YARA scan"),
            cancel=ctx.is_cancelled, **args).payload)
    except CapabilityError as exc:
        ctx.emit("error", error="cancelled" if exc.code == "cancelled" else exc.message)
        if exc.code == "cancelled":
            raise RuntimeError("yara scan cancelled") from exc
        raise ValueError(exc.message) from exc
    artifact = task_result_artifact(payload, params, ctx, "yara")
    ctx.emit("stage_end", stage=STAGE, pct=1.0, msg="YARA scan done",
             extra={"row_count": payload["row_count"], "complete": payload["complete"],
                    "truncated": payload["truncated"]})
    return {"artifacts": [artifact], "summary": payload}
