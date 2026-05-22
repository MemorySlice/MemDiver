"""End-to-end tests for ``api.routers.experiment`` — the SPA experiment
runner's ``POST /api/experiment/run`` endpoint.

Uses the same TestClient(create_app()) pattern as
``tests/test_api_analysis.py`` / ``tests/test_api_pipeline.py`` so the
lifespan + TaskManager ProcessPool substrate is exercised here too.

The happy-path test deliberately submits a non-existent target: the
endpoint accepts it (the worker fails fast over the WebSocket per the
endpoint docstring), so submission still returns 200 with a task_id.
That keeps the test light — we never wait for the worker to finish.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from api.config import get_settings
from api.main import create_app


@pytest.fixture
def tmp_env(tmp_path: Path, monkeypatch):
    """Isolate oracle dir + task root into tmp_path so the test never
    touches the real ``~/.memdiver`` paths.

    Mirrors the fixture in ``tests/test_api_analysis.py``.
    """
    oracle_dir = tmp_path / "oracles"
    task_root = tmp_path / "tasks"
    oracle_dir.mkdir()
    task_root.mkdir()
    monkeypatch.setenv("MEMDIVER_ORACLE_DIR", str(oracle_dir))
    monkeypatch.setenv("MEMDIVER_TASK_ROOT", str(task_root))
    monkeypatch.setenv("MEMDIVER_TASK_QUOTA_BYTES", "10485760")  # 10 MiB
    monkeypatch.setenv("MEMDIVER_PIPELINE_MAX_WORKERS", "1")
    get_settings.cache_clear()
    yield tmp_path
    get_settings.cache_clear()


@pytest.fixture
def client(tmp_env):
    app = create_app()
    with TestClient(app) as c:
        yield c


# ------------------------------------------------------------------
# happy path
# ------------------------------------------------------------------


def test_experiment_happy_path(client):
    """POST a minimal experiment request and confirm task_id + early status.

    We do not wait for completion: spawning a real target is heavy and
    the early contract we care about is "submit returns 200 with a
    task_id and a non-terminal status". The bad target makes the worker
    fail fast, which is the documented behaviour of the endpoint.
    """
    r = client.post(
        "/api/experiment/run",
        json={"target": "/nonexistent/target", "num_runs": 1},
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert isinstance(body["task_id"], str) and body["task_id"]
    assert body["status"] in {"pending", "running", "succeeded", "failed"}

    # Best-effort: cancel so we don't leave the worker holding the
    # single ProcessPool slot longer than necessary. Experiment, batch
    # and pipeline tasks share one TaskManager, so the read/cancel path
    # is the pipeline router's.
    client.delete(f"/api/pipeline/runs/{body['task_id']}")


# ------------------------------------------------------------------
# validation errors
# ------------------------------------------------------------------


def test_experiment_empty_target_400(client):
    """A blank/whitespace target hits the endpoint's pre-flight guard
    and returns 400 (not a Pydantic 422) — see experiment.py:82."""
    r = client.post("/api/experiment/run", json={"target": "   "})
    assert r.status_code == 400


def test_experiment_validation_missing_target(client):
    """``target`` is required, so omitting it must trigger 422."""
    r = client.post("/api/experiment/run", json={"num_runs": 1})
    assert r.status_code == 422


def test_experiment_validation_num_runs_too_low(client):
    """``num_runs`` below 1 must be rejected by Pydantic (ge=1)."""
    r = client.post(
        "/api/experiment/run",
        json={"target": "/x", "num_runs": 0},
    )
    assert r.status_code == 422


def test_experiment_validation_num_runs_too_high(client):
    """``num_runs`` above 200 must be rejected by Pydantic (le=200)."""
    r = client.post(
        "/api/experiment/run",
        json={"target": "/x", "num_runs": 201},
    )
    assert r.status_code == 422
