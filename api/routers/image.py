"""Image router — memory-image views (``image.*`` capabilities).

The web face of :mod:`memdiver.app.tools_image`:

* ``GET  /api/image/probe``           — size, layer chain, profile status (inline).
* ``POST /api/image/profile``         — resolve the kernel profile (JOB: pakunoda maps the image).
* ``POST /api/image/open-view``       — write a ``.mdview`` descriptor (JOB: sha256 of the image).
* ``GET  /api/image/processes``       — task list of a kernel/process view (inline, cached context).
* ``POST /api/image/extract-process`` — process view -> ``.msl`` (JOB).

A job returns ``{"task_id", "status"}`` immediately; progress streams over
``/ws/tasks/{task_id}`` and the producer payload is the ``image_result`` artifact
(``GET /api/pipeline/runs/{task_id}/artifacts/image_result``), also sent as the
terminal ``done`` event's ``extra``.

Image, descriptor and ISF inputs go through the opt-in READ sandbox
(``image_path`` / ``view_path`` / ``isf`` are in ``READ_PATH_KEYS``). Every path
the server WRITES (``out_path``, ``case_dir``) is contained like the case
router's: inside the upload directory or ``~/.memdiver``.
"""

from __future__ import annotations

from typing import Any, Dict, Optional

from fastapi import APIRouter
from pydantic import BaseModel, ConfigDict

from memdiver.api.dependencies import task_manager_or_503
from memdiver.api.routers.annotations import contained_case_dir
from memdiver.app import tools_image

router = APIRouter()

_RUNNER = "memdiver.app.pipeline.image_task_runner.run_image_job"


class _Strict(BaseModel):
    # A misspelled field must be a 422, never a silent default with a 200.
    model_config = ConfigDict(extra="forbid")


class ProfileRequest(_Strict):
    image_path: str
    isf: Optional[str] = None
    allow_pakunoda: bool = True


class OpenViewRequest(_Strict):
    image_path: str
    view: str
    pid: Optional[int] = None
    isf: Optional[str] = None
    case_dir: Optional[str] = None
    out_path: Optional[str] = None


class ExtractRequest(_Strict):
    view_path: str
    out_path: str


def _contained(path: Optional[str]) -> Optional[str]:
    """A write target, or ``None``; raises 403 outside the write roots."""
    return contained_case_dir(path) if path else None


def _case_target(case_dir: Optional[str]) -> Optional[str]:
    """Like the case router: a bare name stays a name (filed under the cases root)."""
    if case_dir and "/" not in case_dir and "\\" not in case_dir \
            and not case_dir.startswith((".", "~")):
        return case_dir
    return _contained(case_dir)


def _submit(job: str, args: Dict[str, Any]) -> Dict[str, Any]:
    manager = task_manager_or_503()
    record = manager.submit(
        kind="image", params={"job": job, "args": args,
                              "task_root": str(manager.artifact_store.root)},
        runner_dotted=_RUNNER, stage_names=["image"])
    return {"task_id": record.task_id, "status": record.status.value}


@router.get("/probe")
def probe_image(image_path: str, banners: bool = False, isf: Optional[str] = None):
    """Cheap facts about an image; never hashes it and never runs pakunoda."""
    return tools_image.image_probe_result(image_path, banners, isf).payload


@router.post("/profile")
def profile_image(req: ProfileRequest):
    """Submit the profile-resolution job; returns its task id."""
    return _submit("profile", {"image_path": req.image_path, "isf": req.isf,
                               "allow_pakunoda": req.allow_pakunoda})


@router.post("/open-view")
def open_view(req: OpenViewRequest):
    """Submit the job that writes a ``.mdview`` for one view of the image."""
    return _submit("open_view", {
        "image_path": req.image_path, "view": req.view, "pid": req.pid, "isf": req.isf,
        "case_dir": _case_target(req.case_dir), "out_path": _contained(req.out_path)})


@router.get("/processes")
def list_processes(view_path: str, limit: int = tools_image.DEFAULT_PROCESS_LIMIT):
    """The task list (``pslist``) of a kernel or process view."""
    return tools_image.image_processes_result(view_path, limit).payload


@router.post("/extract-process")
def extract_process(req: ExtractRequest):
    """Submit the job that extracts a process view into an ``.msl``."""
    return _submit("extract_process", {"view_path": req.view_path,
                                       "out_path": _contained(req.out_path)})
