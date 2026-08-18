"""Tests for app.pipeline.batch_task_runner.run_batch.

Drives the in-process batch worker entry directly (no ProcessPool) inside a
fake ``WorkerContext`` that captures the progress events the TaskManager would
publish, with the inner ``run_analysis_request`` patched to a canned result
(mirrors ``tests/test_batch.py``). Asserts the ``{"artifacts": [...],
"summary": {...}}`` contract ``TaskManager._on_success`` consumes.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List
from unittest.mock import patch

import pytest

from memdiver.app.pipeline.batch_task_runner import run_batch


# ------------------------------------------------------------------
# fake WorkerContext (mirrors tests/test_pipeline_runner.py::_FakeCtx)
# ------------------------------------------------------------------


@dataclass
class _FakeCtx:
    task_id: str = "test-batch"
    cancel: bool = False
    events: List[Dict[str, Any]] = field(default_factory=list)

    def emit(self, event_type: str, **fields: Any) -> None:
        self.events.append({"type": event_type, **fields})

    def is_cancelled(self) -> bool:
        return self.cancel


# ------------------------------------------------------------------
# fixtures + helpers
# ------------------------------------------------------------------


def _mock_run_analysis(request, **kwargs):
    """Canned run_analysis_request returning one LibraryReport per lib dir."""
    from memdiver.engine.results import AnalysisResult, LibraryReport

    result = AnalysisResult()
    for lib_dir in request.library_dirs:
        result.libraries.append(
            LibraryReport(
                library=lib_dir.name,
                protocol_version=request.protocol_version,
                phase=request.phase,
                num_runs=1,
            )
        )
    return result


@pytest.fixture
def lib_dir(tmp_path: Path) -> Path:
    d = tmp_path / "lib1"
    d.mkdir()
    return d


def _job(lib_dir: Path) -> Dict[str, Any]:
    return {
        "library_dirs": [str(lib_dir)],
        "phase": "pre_abort",
        "protocol_version": "13",
    }


# ------------------------------------------------------------------
# empty jobs (cheap ValueError guard)
# ------------------------------------------------------------------


def test_run_batch_empty_jobs_raises(tmp_path):
    ctx = _FakeCtx()
    params = {"artifact_dir": str(tmp_path / "task"), "jobs": []}
    with pytest.raises(ValueError, match="jobs list is empty"):
        run_batch(params, ctx)


# ------------------------------------------------------------------
# happy path (json)
# ------------------------------------------------------------------


def test_run_batch_happy_path_json(tmp_path, lib_dir):
    ctx = _FakeCtx()
    artifact_dir = tmp_path / "task"
    params = {
        "artifact_dir": str(artifact_dir),
        "jobs": [_job(lib_dir)],
        "output_format": "json",
    }
    with patch("memdiver.engine.batch.run_analysis_request", _mock_run_analysis):
        ret = run_batch(params, ctx)

    # Returned dict shape.
    assert set(ret) == {"artifacts", "summary"}
    assert ret["summary"]["total_jobs"] == 1
    assert ret["summary"]["succeeded_count"] == 1
    assert ret["summary"]["failed_count"] == 0
    assert ret["summary"]["output_format"] == "json"

    # Artifact registered + persisted on disk.
    spec = ret["artifacts"][0]
    assert spec["name"] == "batch_result"
    assert spec["relpath"] == "batch/result.json"
    assert spec["media_type"] == "application/json"
    out_path = artifact_dir / spec["relpath"]
    assert out_path.is_file()
    payload = json.loads(out_path.read_text())
    assert payload["succeeded_count"] == 1

    # Progress events emitted on the batch stage.
    types = [e["type"] for e in ctx.events]
    assert types[0] == "stage_start"
    assert types[-1] == "stage_end"
    assert any(
        e["type"] == "progress" and e.get("stage") == "batch" for e in ctx.events
    )
    assert all(e.get("stage") == "batch" for e in ctx.events if "stage" in e)


# ------------------------------------------------------------------
# jsonl output branch
# ------------------------------------------------------------------


def test_run_batch_jsonl_output(tmp_path, lib_dir):
    ctx = _FakeCtx()
    artifact_dir = tmp_path / "task"
    params = {
        "artifact_dir": str(artifact_dir),
        "jobs": [_job(lib_dir)],
        "output_format": "jsonl",
    }
    with patch("memdiver.engine.batch.run_analysis_request", _mock_run_analysis):
        ret = run_batch(params, ctx)

    spec = ret["artifacts"][0]
    assert spec["relpath"] == "batch/result.jsonl"
    assert spec["media_type"] == "application/x-ndjson"
    out_path = artifact_dir / spec["relpath"]
    lines = out_path.read_text().strip().splitlines()
    # Last line is the summary record appended after the per-job records.
    summary_rec = json.loads(lines[-1])
    assert summary_rec["_type"] == "summary"
    assert ret["summary"]["output_format"] == "jsonl"


# ------------------------------------------------------------------
# task_root fallback (no explicit artifact_dir)
# ------------------------------------------------------------------


def test_run_batch_task_root_uses_task_id(tmp_path, lib_dir):
    """Without artifact_dir, run_batch derives ``<task_root>/<task_id>``."""
    ctx = _FakeCtx(task_id="tid-123")
    task_root = tmp_path / "tasks"
    params = {"task_root": str(task_root), "jobs": [_job(lib_dir)]}
    with patch("memdiver.engine.batch.run_analysis_request", _mock_run_analysis):
        ret = run_batch(params, ctx)
    out_path = task_root / "tid-123" / "batch" / "result.json"
    assert out_path.is_file()
    assert ret["summary"]["succeeded_count"] == 1


# ------------------------------------------------------------------
# cancellation observed inside the BatchRunner progress bridge
# ------------------------------------------------------------------


def test_run_batch_cancelled_context_suppresses_progress_events(tmp_path, lib_dir):
    """A pre-cancelled ctx makes ``_progress`` a no-op (best-effort signal).

    ``run_batch`` has no cancel hook into ``BatchRunner`` itself — the job
    still runs to completion — but the ``_progress`` bridge closure checks
    ``ctx.is_cancelled()`` on every callback and returns before emitting,
    per the module's "same as nsweep / brute_force" comment. So a
    cancelled context still yields a full batch result, just without any
    ``progress`` events between ``stage_start`` and ``stage_end``.
    """
    ctx = _FakeCtx(cancel=True)
    artifact_dir = tmp_path / "task"
    params = {
        "artifact_dir": str(artifact_dir),
        "jobs": [_job(lib_dir)],
        "output_format": "json",
    }
    with patch("memdiver.engine.batch.run_analysis_request", _mock_run_analysis):
        ret = run_batch(params, ctx)

    assert ret["summary"]["succeeded_count"] == 1
    types = [e["type"] for e in ctx.events]
    assert types[0] == "stage_start"
    assert types[-1] == "stage_end"
    assert "progress" not in types


# ------------------------------------------------------------------
# register_artifact (memdiver.core.artifact_util): defensive stat() OSError
# branch.
#
# NOTE: register_artifact used to be defined locally in
# batch_task_runner.py as `_register_artifact`; it was promoted to the
# shared `memdiver.core.artifact_util` module (P3.2 dedup) since
# pipeline_runner and batch_task_runner both had byte-identical copies.
# This test was repointed to the new canonical location; behavior is
# unchanged.
# ------------------------------------------------------------------


def test_register_artifact_stat_oserror_falls_back_to_zero_size(tmp_path):
    """If ``stat()`` on the artifact file raises, size falls back to 0.

    sha256 is still computed via the streamed hasher independently of
    ``stat()``, so only the ``size`` field is affected.
    """
    from memdiver.core.artifact_util import register_artifact

    artifact_dir = tmp_path / "task"
    artifact_dir.mkdir()
    relpath = "batch/result.json"
    out_path = artifact_dir / relpath
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text('{"ok": true}')

    original_stat = Path.stat
    # Only the *first* stat() call (the explicit size lookup at line 51)
    # should fail — later internal stat() calls (e.g. inside is_file())
    # must behave normally so the sha256 branch still runs.
    raised = {"once": False}

    def flaky_stat(self, *args, **kwargs):
        if self.name == "result.json" and not raised["once"]:
            raised["once"] = True
            raise OSError("stat blocked for test")
        return original_stat(self, *args, **kwargs)

    with patch.object(Path, "stat", flaky_stat):
        artifacts: List[Dict[str, Any]] = []
        spec = register_artifact(
            artifacts, artifact_dir, name="batch_result", relpath=relpath
        )

    assert spec["size"] == 0
    assert spec["sha256"] is not None
    assert len(spec["sha256"]) == 64
