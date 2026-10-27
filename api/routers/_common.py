"""Building blocks shared by the capability routers (image, case, isf, strings, ...).

* :class:`StrictModel` — request-body base that rejects unknown fields.
* :data:`SYNC_MAX_BYTES` — the inline budget of the byte-scanning routes.
* :func:`submit_job` — submit a worker job and return its ``{"task_id", "status"}``
  handle.
"""

from __future__ import annotations

from typing import Any, Dict

from pydantic import BaseModel, ConfigDict

#: A scan reading at most this many captured bytes is answered inline.
SYNC_MAX_BYTES = 64 * 1024 * 1024


class StrictModel(BaseModel):
    # A misspelled field must be a 422, never a silent default with a 200.
    model_config = ConfigDict(extra="forbid")


def submit_job(manager, kind: str, runner_dotted: str,
               params: Dict[str, Any]) -> Dict[str, Any]:
    """Submit a one-stage job (stage named ``kind``) under the manager's artifact root.

    ``manager`` is passed in (not looked up here) so each router keeps its own
    ``task_manager_or_503`` seam. ``task_root`` is appended to ``params``.
    """
    record = manager.submit(
        kind=kind, params={**params, "task_root": str(manager.artifact_store.root)},
        runner_dotted=runner_dotted, stage_names=[kind])
    return {"task_id": record.task_id, "status": record.status.value}
