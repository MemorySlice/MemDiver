"""Image router — memory-image views (``image.*`` capabilities).

The web face of :mod:`memdiver.app.tools_image`:

* ``GET  /api/image/probe``           — size, layer chain, profile status (inline).
* ``POST /api/image/profile``         — resolve the kernel profile (JOB: pakunoda maps the image).
* ``POST /api/image/open-view``       — write a ``.mdview`` descriptor (JOB: sha256 of the image).
* ``GET  /api/image/processes``       — task list of a kernel/process view (inline, cached context).
* ``POST /api/image/extract-process`` — process view -> ``.msl`` (JOB).
* ``GET  /api/image/siblings``        — sibling groups + frame accounting (inline; writes nothing).
* ``POST /api/image/siblings``        — the same, optionally writing a ``.mdview`` per member (JOB).

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

from memdiver.api.dependencies import task_manager_or_503
from memdiver.api.routers._common import StrictModel, submit_job
from memdiver.api.routers.annotations import contained_case_dir
from memdiver.app import tools_image
from memdiver.core.path_sandbox import is_bare_case_name

router = APIRouter()

_RUNNER = "memdiver.app.pipeline.image_task_runner.run_image_job"


class ProfileRequest(StrictModel):
    image_path: str
    isf: Optional[str] = None
    allow_pakunoda: bool = True


class OpenViewRequest(StrictModel):
    image_path: str
    view: str
    pid: Optional[int] = None
    isf: Optional[str] = None
    case_dir: Optional[str] = None
    out_path: Optional[str] = None
    no_profile: bool = False
    paging: Optional[Dict[str, Any]] = None
    draft: Optional[str] = None
    draft_version: Optional[str] = None


class ExtractRequest(StrictModel):
    view_path: str
    out_path: str


class SiblingsRequest(StrictModel):
    image_path: str
    isf: Optional[str] = None
    comm: Optional[str] = None
    min_members: int = 2
    include_parent: bool = False
    accounting: bool = True
    open_views: bool = False
    case_dir: Optional[str] = None
    split_families: bool = True


def _contained(path: Optional[str]) -> Optional[str]:
    """A write target, or ``None``; raises 403 outside the write roots."""
    return contained_case_dir(path) if path else None


def _case_target(case_dir: Optional[str]) -> Optional[str]:
    """Like the case router: a bare name stays a name (filed under the cases root).

    Blank stays blank (the producer decides whether a case is required); any
    other non-bare value is a write target contained like ``out_path``.
    """
    if not case_dir or not case_dir.strip() or is_bare_case_name(case_dir):
        return case_dir or None
    return _contained(case_dir)


def _submit(job: str, args: Dict[str, Any]) -> Dict[str, Any]:
    return submit_job(task_manager_or_503(), "image", _RUNNER, {"job": job, "args": args})


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
        "case_dir": _case_target(req.case_dir), "out_path": _contained(req.out_path),
        "no_profile": req.no_profile, "paging": req.paging, "draft": req.draft,
        "draft_version": req.draft_version})


@router.get("/processes")
def list_processes(view_path: str, limit: int = tools_image.DEFAULT_PROCESS_LIMIT):
    """The task list (``pslist``) of a kernel or process view."""
    return tools_image.image_processes_result(view_path, limit).payload


@router.post("/extract-process")
def extract_process(req: ExtractRequest):
    """Submit the job that extracts a process view into an ``.msl``."""
    return _submit("extract_process", {"view_path": req.view_path,
                                       "out_path": _contained(req.out_path)})


@router.get("/siblings")
def list_siblings(image_path: str, isf: Optional[str] = None, comm: Optional[str] = None,
                  min_members: int = 2, include_parent: bool = False,
                  accounting: bool = True, split_families: bool = True):
    """Sibling groups of an image (cached context; walks the members' page tables)."""
    return tools_image.image_siblings_result(
        image_path, isf, comm, min_members, include_parent, accounting,
        split_families=split_families).payload


@router.post("/siblings")
def siblings_job(req: SiblingsRequest):
    """Submit the sibling job (may write one ``.mdview`` per member with ``open_views``)."""
    return _submit("siblings", {
        "image_path": req.image_path, "isf": req.isf, "comm": req.comm,
        "min_members": req.min_members, "include_parent": req.include_parent,
        "accounting": req.accounting, "open_views": req.open_views,
        "case_dir": _case_target(req.case_dir), "split_families": req.split_families})
