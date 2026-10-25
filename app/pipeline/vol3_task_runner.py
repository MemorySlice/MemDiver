"""TaskManager worker entry for a long ``vol3.run``.

A plugin run over a multi-GB view (psscan, a full-image scan) outlives a sensible
HTTP request, so REST submits it as a job when the caller asks for a long budget
(``timeout_s`` > 30, ``limit`` > 10000) or sets ``async``. The worker reuses the
shared producer :func:`memdiver.app.tools_vol3.vol3_run_result`, forwards the
plugin's progress callback as ``progress`` events, writes the producer payload as
the ``vol3_result`` artifact (``vol3/result.json``) and sends it as the terminal
``summary``.

The function stays top-level and imports lazily so the spawn worker can pickle it
and an import problem surfaces as a reported task failure.
"""

from __future__ import annotations

import json
from typing import Any, Dict

from memdiver.app.pipeline.artifact_paths import resolve_artifact_dir

STAGE = "vol3"


def _progress_emitter(ctx):
    """Adapt vol3's ``(percent, description)`` callback to ``progress`` events."""
    def emit(percent: float, description: str) -> None:
        pct = max(0.0, min(float(percent) / 100.0, 0.99))
        ctx.emit("progress", stage=STAGE, pct=pct, msg=description or "vol3 run")
    return emit


def _write_artifact(payload: Dict[str, Any], params: Dict[str, Any], ctx) -> Dict[str, Any]:
    from memdiver.core.artifact_util import sha256_streamed
    relpath = "vol3/result.json"
    out = resolve_artifact_dir(params, ctx, fallback_subdir="./vol3_output") / relpath
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(payload, indent=2))
    return {"name": "vol3_result", "relpath": relpath, "media_type": "application/json",
            "size": out.stat().st_size, "sha256": sha256_streamed(out)}


def run_vol3_job(params: Dict[str, Any], ctx) -> Dict[str, Any]:
    """Worker entry. ``params``: ``args`` (``vol3_run_result`` kwargs), ``task_root`` /
    ``artifact_dir``. Returns ``{"artifacts": [...], "summary": {...}}``."""
    from memdiver.app.tools_vol3 import vol3_run_result
    from memdiver.core.service_errors import CapabilityError
    args = dict(params.get("args", {}))
    ctx.emit("stage_start", stage=STAGE, pct=0.0, msg=f"vol3 run {args.get('plugin', '')}")
    try:
        payload = dict(vol3_run_result(progress=_progress_emitter(ctx), **args).payload)
    except CapabilityError as exc:
        ctx.emit("error", error=exc.message)
        raise ValueError(exc.message) from exc
    artifact = _write_artifact(payload, params, ctx)
    ctx.emit("stage_end", stage=STAGE, pct=1.0, msg="vol3 run done", extra=payload)
    return {"artifacts": [artifact], "summary": payload}
