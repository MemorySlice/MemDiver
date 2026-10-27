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

from typing import Any, Dict

from memdiver.app.pipeline.artifact_paths import task_result_artifact
from memdiver.app.pipeline.progress_emitter import progress_emitter

STAGE = "vol3"


def run_vol3_job(params: Dict[str, Any], ctx) -> Dict[str, Any]:
    """Worker entry. ``params``: ``args`` (``vol3_run_result`` kwargs), ``task_root`` /
    ``artifact_dir``. Returns ``{"artifacts": [...], "summary": {...}}``."""
    from memdiver.app.tools_vol3 import vol3_run_result
    from memdiver.core.service_errors import CapabilityError
    args = dict(params.get("args", {}))
    ctx.emit("stage_start", stage=STAGE, pct=0.0, msg=f"vol3 run {args.get('plugin', '')}")
    try:
        payload = dict(vol3_run_result(
            progress=progress_emitter(ctx, STAGE, "vol3 run", scale=100.0),
            cancel=ctx.is_cancelled, **args).payload)
    except CapabilityError as exc:
        ctx.emit("error", error=exc.message)
        raise ValueError(exc.message) from exc
    artifact = task_result_artifact(payload, params, ctx, "vol3")
    ctx.emit("stage_end", stage=STAGE, pct=1.0, msg="vol3 run done", extra=payload)
    return {"artifacts": [artifact], "summary": payload}
