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

from typing import Any, Dict

from memdiver.app.pipeline.artifact_paths import task_result_artifact
from memdiver.app.pipeline.progress_emitter import progress_emitter

STAGE = "strings"


def run_strings_job(params: Dict[str, Any], ctx) -> Dict[str, Any]:
    """Worker entry. ``params``: ``args`` (``strings_table_result`` kwargs),
    ``task_root`` / ``artifact_dir``. Returns ``{"artifacts": [...], "summary": {...}}``."""
    from memdiver.app.tools_strings import strings_table_result
    from memdiver.core.service_errors import CapabilityError
    args = dict(params.get("args", {}))
    ctx.emit("stage_start", stage=STAGE, pct=0.0,
             msg=f"strings table {','.join(args.get('encodings', ()))}")
    try:
        payload = dict(strings_table_result(
            progress=progress_emitter(ctx, STAGE, "strings table"), **args).payload)
    except CapabilityError as exc:
        ctx.emit("error", error=exc.message)
        raise ValueError(exc.message) from exc
    artifact = task_result_artifact(payload, params, ctx, "strings")
    ctx.emit("stage_end", stage=STAGE, pct=1.0, msg="strings table done",
             extra={"row_count": payload["row_count"], "truncated": payload["truncated"]})
    return {"artifacts": [artifact], "summary": payload}
