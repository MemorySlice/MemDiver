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

import json
from typing import Any, Dict

from memdiver.app.pipeline.artifact_paths import resolve_artifact_dir

STAGE = "yara"


def _progress_emitter(ctx):
    def emit(fraction: float, description: str) -> None:
        ctx.emit("progress", stage=STAGE, pct=max(0.0, min(float(fraction), 0.99)),
                 msg=description or "YARA scan")
    return emit


def _write_artifact(payload: Dict[str, Any], params: Dict[str, Any], ctx) -> Dict[str, Any]:
    from memdiver.core.artifact_util import sha256_streamed
    relpath = "yara/result.json"
    out = resolve_artifact_dir(params, ctx, fallback_subdir="./yara_output") / relpath
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(payload, indent=2))
    return {"name": "yara_result", "relpath": relpath, "media_type": "application/json",
            "size": out.stat().st_size, "sha256": sha256_streamed(out)}


def run_yara_job(params: Dict[str, Any], ctx) -> Dict[str, Any]:
    """Worker entry. ``params``: ``args`` (``yara_scan_dump_result`` kwargs),
    ``task_root`` / ``artifact_dir``. Returns ``{"artifacts": [...], "summary": {...}}``."""
    from memdiver.app.tools_yara import yara_scan_dump_result
    from memdiver.core.service_errors import CapabilityError
    args = dict(params.get("args", {}))
    ctx.emit("stage_start", stage=STAGE, pct=0.0, msg="YARA scan")
    try:
        payload = dict(yara_scan_dump_result(
            progress=_progress_emitter(ctx), cancel=ctx.is_cancelled, **args).payload)
    except CapabilityError as exc:
        ctx.emit("error", error="cancelled" if exc.code == "cancelled" else exc.message)
        if exc.code == "cancelled":
            raise RuntimeError("yara scan cancelled") from exc
        raise ValueError(exc.message) from exc
    artifact = _write_artifact(payload, params, ctx)
    ctx.emit("stage_end", stage=STAGE, pct=1.0, msg="YARA scan done",
             extra={"row_count": payload["row_count"], "complete": payload["complete"],
                    "truncated": payload["truncated"]})
    return {"artifacts": [artifact], "summary": payload}
