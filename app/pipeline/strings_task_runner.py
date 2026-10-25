"""TaskManager worker entry for a long ``strings.table``.

A scan over a multi-GB capture outlives a sensible HTTP request, so REST submits
it as a job when the captured bytes to read exceed the inline budget or the
caller sets ``async``. The worker reuses the shared producer
:func:`memdiver.app.tools_strings.strings_table_result`, forwards its progress
callback as ``progress`` events, writes the producer payload as the
``strings_result`` artifact (``strings/result.json``) and sends it as the
terminal ``summary``.

Top-level and lazily importing so the spawn worker can pickle it and an import
problem surfaces as a reported task failure.
"""

from __future__ import annotations

import json
from typing import Any, Dict

from memdiver.app.pipeline.artifact_paths import resolve_artifact_dir

STAGE = "strings"


def _progress_emitter(ctx):
    def emit(fraction: float, description: str) -> None:
        ctx.emit("progress", stage=STAGE, pct=max(0.0, min(float(fraction), 0.99)),
                 msg=description or "strings table")
    return emit


def _write_artifact(payload: Dict[str, Any], params: Dict[str, Any], ctx) -> Dict[str, Any]:
    from memdiver.core.artifact_util import sha256_streamed
    relpath = "strings/result.json"
    out = resolve_artifact_dir(params, ctx, fallback_subdir="./strings_output") / relpath
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(payload, indent=2))
    return {"name": "strings_result", "relpath": relpath, "media_type": "application/json",
            "size": out.stat().st_size, "sha256": sha256_streamed(out)}


def run_strings_job(params: Dict[str, Any], ctx) -> Dict[str, Any]:
    """Worker entry. ``params``: ``args`` (``strings_table_result`` kwargs),
    ``task_root`` / ``artifact_dir``. Returns ``{"artifacts": [...], "summary": {...}}``."""
    from memdiver.app.tools_strings import strings_table_result
    from memdiver.core.service_errors import CapabilityError
    args = dict(params.get("args", {}))
    ctx.emit("stage_start", stage=STAGE, pct=0.0,
             msg=f"strings table {','.join(args.get('encodings', ()))}")
    try:
        payload = dict(strings_table_result(progress=_progress_emitter(ctx), **args).payload)
    except CapabilityError as exc:
        ctx.emit("error", error=exc.message)
        raise ValueError(exc.message) from exc
    artifact = _write_artifact(payload, params, ctx)
    ctx.emit("stage_end", stage=STAGE, pct=1.0, msg="strings table done",
             extra={"row_count": payload["row_count"], "truncated": payload["truncated"]})
    return {"artifacts": [artifact], "summary": payload}
