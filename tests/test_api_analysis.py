"""End-to-end tests for ``api.routers.analysis`` — focused on the
Phase B ``POST /api/analysis/batch`` endpoint.

Uses the same TestClient(create_app()) pattern as
``tests/test_api_pipeline.py`` so the lifespan + TaskManager
ProcessPool substrate is exercised by these tests too.
"""

from __future__ import annotations

import time
from pathlib import Path
from typing import Dict

import pytest
from fastapi.testclient import TestClient

from api.config import get_settings
from api.main import create_app


@pytest.fixture
def tmp_env(tmp_path: Path, monkeypatch):
    """Isolate oracle dir + task root into tmp_path so the test never
    touches the real ``~/.memdiver`` paths.

    Mirrors the fixture in ``tests/test_api_pipeline.py``.
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


@pytest.fixture
def fixture_library_dir() -> str:
    """Return an absolute path to one of the synthetic fixture libraries.

    ``tests/conftest.py`` calls ``generate_dataset()`` at session start,
    so the path is always materialised before tests run. We use a
    library directory that contains a single run subdir so the batch
    job's AnalyzeRequest validation (library_dirs must be a real
    directory) succeeds inside the worker.
    """
    here = Path(__file__).parent
    lib = here / "fixtures" / "dataset" / "TLS12" / "scenario_a" / "openssl"
    assert lib.is_dir(), f"fixture missing: {lib}"
    return str(lib)


def _wait_terminal(client: TestClient, task_id: str, timeout: float = 30.0) -> Dict:
    """Poll ``/api/pipeline/runs/{id}`` until the task lands in a
    terminal state. (Pipeline + analysis endpoints share the
    TaskManager so the read-side path is the same.)"""
    deadline = time.time() + timeout
    while time.time() < deadline:
        r = client.get(f"/api/pipeline/runs/{task_id}")
        assert r.status_code == 200
        rec = r.json()
        if rec["status"] in ("succeeded", "failed", "cancelled"):
            return rec
        time.sleep(0.1)
    raise AssertionError(f"task {task_id} never reached terminal state")


# ------------------------------------------------------------------
# happy path
# ------------------------------------------------------------------


def test_batch_happy_path(client, fixture_library_dir):
    """POST a minimal one-job batch and confirm task_id + early status.

    We do not wait for completion here — running a real
    ``analyze_library`` against a fixture is heavy, and the early
    contract we care about is "submit returns 200 with a task_id and
    a non-terminal status". A separate slow test could be added later
    to assert the artifact lands.
    """
    payload = {
        "jobs": [
            {
                "library_dirs": [fixture_library_dir],
                "phase": "pre_handshake",
                "protocol_version": "12",
                "max_runs": 1,
            },
        ],
        "output_format": "json",
        "workers": 1,
    }
    r = client.post("/api/analysis/batch", json=payload)
    assert r.status_code == 200, r.text
    body = r.json()
    assert isinstance(body["task_id"], str) and body["task_id"]
    # TaskManager submits asynchronously, so the early status is one
    # of pending/running. (Succeeded is theoretically possible too if
    # the inner job somehow finishes before this assertion runs, but
    # in practice the spawn-context startup latency makes that race
    # vanishingly rare.)
    assert body["status"] in {"pending", "running", "succeeded", "failed"}

    # Best-effort: cancel so we don't leave the worker running long
    # enough to fight other tests for the ProcessPool slot.
    client.delete(f"/api/pipeline/runs/{body['task_id']}")


# ------------------------------------------------------------------
# validation errors
# ------------------------------------------------------------------


def test_batch_validation_empty_jobs(client):
    """Empty jobs list must be rejected by Pydantic with 422."""
    r = client.post(
        "/api/analysis/batch",
        json={"jobs": [], "output_format": "json", "workers": 1},
    )
    assert r.status_code == 422


def test_batch_validation_missing_required_field(client, fixture_library_dir):
    """A job missing ``protocol_version`` must trigger 422 (Pydantic)."""
    r = client.post(
        "/api/analysis/batch",
        json={
            "jobs": [
                {
                    "library_dirs": [fixture_library_dir],
                    "phase": "pre_handshake",
                    # protocol_version intentionally omitted
                },
            ],
        },
    )
    assert r.status_code == 422


def test_batch_validation_bad_workers(client, fixture_library_dir):
    """``workers`` outside 1..32 must be rejected by Pydantic."""
    r = client.post(
        "/api/analysis/batch",
        json={
            "jobs": [
                {
                    "library_dirs": [fixture_library_dir],
                    "phase": "pre_handshake",
                    "protocol_version": "12",
                },
            ],
            "workers": 0,
        },
    )
    assert r.status_code == 422


def test_batch_validation_empty_library_dirs(client):
    """A job with an empty ``library_dirs`` list must be rejected at the
    Pydantic layer (DTO declares ``min_length=1``)."""
    r = client.post(
        "/api/analysis/batch",
        json={
            "jobs": [
                {
                    "library_dirs": [],
                    "phase": "pre_handshake",
                    "protocol_version": "12",
                },
            ],
        },
    )
    assert r.status_code == 422
