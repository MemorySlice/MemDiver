"""Detector-fixture router — YARA / key-finder fixtures (``detector_fixtures.*`` capabilities).

The web face of :mod:`memdiver.app.tools_detector_fixtures`:

* ``GET    /api/detector-fixtures``          — bundled + stored fixtures (``last_verdict``).
* ``POST   /api/detector-fixtures/run``      — run a detector's fixtures; ``pass|fail|indeterminate``.
* ``PUT    /api/detector-fixtures/{name}``   — store a fixture in a case.
* ``DELETE /api/detector-fixtures/{name}``   — retire one (archived under ``history/``).

Reads (``case_dir`` and a capture sample's ``dump_path``) go through the opt-in read
sandbox; the ``case_dir`` the server WRITES is contained like the case router's.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from fastapi import APIRouter
from pydantic import BaseModel, ConfigDict, Field

from memdiver.api.routers.image import _case_target
from memdiver.app import tools_detector_fixtures as fixtures

router = APIRouter()


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")


class RunRequest(_Strict):
    artifact_kind: str
    artifact: str
    fixtures: Optional[List[Dict[str, Any]]] = None
    params: Dict[str, Any] = Field(default_factory=dict)
    case_dir: Optional[str] = None


class AddRequest(_Strict):
    case_dir: str
    artifact_kind: str
    artifact: str
    sample: Dict[str, Any]
    expect: Dict[str, Any]
    params: Dict[str, Any] = Field(default_factory=dict)


@router.get("")
def list_fixtures(case_dir: Optional[str] = None, artifact_kind: Optional[str] = None,
                  artifact: Optional[str] = None):
    """Bundled fixtures, and the stored ones of ``case_dir``, each with ``last_verdict``."""
    return fixtures.detector_fixtures_list_result(
        _case_target(case_dir), artifact_kind, artifact).payload


@router.post("/run")
def run_fixtures(req: RunRequest):
    """Run the fixtures of one detector inline (small byte samples; no job needed)."""
    return fixtures.detector_fixtures_run_result(
        req.artifact_kind, req.artifact, req.fixtures, req.params,
        _case_target(req.case_dir)).payload


@router.put("/{name}")
def add_fixture(name: str, req: AddRequest):
    """Store a validated fixture; an overwrite keeps the old version in ``history/``."""
    return fixtures.detector_fixtures_add_result(
        _case_target(req.case_dir) or "", name, req.artifact_kind, req.artifact,
        req.sample, req.expect, req.params).payload


@router.delete("/{name}")
def remove_fixture(name: str, case_dir: str):
    """Retire a stored fixture (archived, not lost)."""
    return fixtures.detector_fixtures_remove_result(_case_target(case_dir) or "", name).payload
