"""Shared per-task artifact-directory resolution for the pipeline runners.

Every task runner (analysis, experiment, batch, and the pipeline runner)
resolved the per-task artifact directory the same way; this is the single
source they now share. :func:`write_json_artifact` / :func:`task_result_artifact`
are the shared "write the JSON result and return its artifact spec" step.
"""

from __future__ import annotations

import hashlib
import json
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


def write_json_artifact(
    payload: Dict[str, Any], artifact_dir: Path, *, name: str, relpath: str
) -> Dict[str, Any]:
    """Write ``payload`` as indented JSON at ``artifact_dir / relpath``; return its spec.

    The spec is the dict shape ``TaskManager._on_success`` consumes; ``size``
    and ``sha256`` describe the exact bytes written (no re-read of the file).
    """
    out_path = artifact_dir / relpath
    out_path.parent.mkdir(parents=True, exist_ok=True)
    data = json.dumps(payload, indent=2).encode("utf-8")
    out_path.write_bytes(data)
    return {"name": name, "relpath": relpath, "media_type": "application/json",
            "size": len(data), "sha256": hashlib.sha256(data).hexdigest()}


def task_result_artifact(
    payload: Dict[str, Any], params: Dict[str, Any], ctx, kind: str
) -> Dict[str, Any]:
    """The ``<kind>_result`` artifact (``<kind>/result.json``) of a capability job runner."""
    artifact_dir = resolve_artifact_dir(params, ctx, fallback_subdir=f"./{kind}_output")
    return write_json_artifact(payload, artifact_dir, name=f"{kind}_result",
                               relpath=f"{kind}/result.json")

