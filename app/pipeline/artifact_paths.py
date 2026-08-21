"""Shared per-task artifact-directory resolution for the pipeline runners.

Every task runner (analysis, experiment, batch, and the pipeline runner)
resolved the per-task artifact directory the same way; this is the single
source they now share.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, Optional


def resolve_artifact_dir(
    params: Dict[str, Any], ctx, fallback_subdir: Optional[str] = None
) -> Path:
    """Resolve (and create) the per-task artifact directory.

    Resolution order:
      * an explicit ``artifact_dir`` in ``params`` (callers that already know
        the absolute directory, e.g. tests);
      * otherwise ``task_root / ctx.task_id`` (production: the TaskManager mints
        the task id inside ``submit()`` and passes ``task_root``);
      * otherwise, only if ``fallback_subdir`` is given, ``fallback_subdir /
        ctx.task_id`` (ad-hoc invocations of the analysis/experiment runners
        that pass neither).

    When ``fallback_subdir`` is None the caller must supply ``artifact_dir`` or
    ``task_root`` — a missing ``task_root`` raises ``KeyError``, matching the
    historical inline behavior in the pipeline/batch runners.
    """
    if "artifact_dir" in params:
        artifact_dir = Path(params["artifact_dir"]).expanduser()
    elif "task_root" in params:
        artifact_dir = Path(params["task_root"]).expanduser() / ctx.task_id
    elif fallback_subdir is not None:
        artifact_dir = Path(fallback_subdir).expanduser() / ctx.task_id
    else:
        # Preserve the historical KeyError from params["task_root"].
        artifact_dir = Path(params["task_root"]).expanduser() / ctx.task_id
    artifact_dir.mkdir(parents=True, exist_ok=True)
    return artifact_dir
