"""HTTP-layer tests for api.routers.tasks (prefix ``/api/tasks``).

The tasks router is a thin adapter over the ``TaskManager`` singleton
installed during the FastAPI lifespan. We redirect every settings-
controlled directory into ``tmp_path`` so the tests never touch the real
``~/.memdiver`` paths.

For the ``/result`` endpoint we need a real task id; the cheapest way to
mint one is to drive the pipeline router exactly like
``tests/test_api_pipeline.py`` does (upload + arm an oracle, POST a run).
For the 409 terminal-state DELETE we reach into the running singleton via
``get_task_manager()`` and register a record already in a terminal state.
"""

from __future__ import annotations

import time
from pathlib import Path
from typing import List

import numpy as np
import pytest
from fastapi.testclient import TestClient

from memdiver.api.config import get_settings
from memdiver.api.main import create_app


# ---------------------------------------------------------------------------
# Fixtures (copied verbatim from tests/test_api_sessions.py)
# ---------------------------------------------------------------------------


@pytest.fixture
def isolated_env(tmp_path: Path, monkeypatch):
    """Redirect every settings-controlled directory into tmp_path."""
    for sub, env in [
        ("oracles", "MEMDIVER_ORACLE_DIR"),
        ("tasks", "MEMDIVER_TASK_ROOT"),
        ("uploads", "MEMDIVER_UPLOAD_DIR"),
        ("sessions", "MEMDIVER_SESSION_DIR"),
    ]:
        d = tmp_path / sub
        d.mkdir()
        monkeypatch.setenv(env, str(d))
    monkeypatch.setenv("MEMDIVER_PIPELINE_MAX_WORKERS", "1")
    get_settings.cache_clear()
    yield tmp_path
    get_settings.cache_clear()


@pytest.fixture
def client(isolated_env):
    app = create_app()
    with TestClient(app) as c:
        yield c


# ---------------------------------------------------------------------------
# helpers — mirror tests/test_api_pipeline.py for minting a real task
# ---------------------------------------------------------------------------

ORACLE_SOURCE = (
    "KEY = bytes(range(32))\n"
    "def verify(candidate):\n"
    "    return candidate == KEY\n"
)


@pytest.fixture
def synthetic_dumps(tmp_path: Path) -> List[str]:
    """Four tiny raw dumps — first has the sentinel key at offset 256."""
    key = bytes(range(32))
    paths: List[str] = []
    padding_rng = np.random.default_rng(42)
    padding = padding_rng.integers(0, 256, 1024, dtype=np.uint8).tobytes()
    for i in range(4):
        buf = bytearray(padding)
        high = np.random.default_rng(1000 + i).integers(
            0, 256, 32, dtype=np.uint8
        ).tobytes()
        buf[64:96] = high
        buf[512:544] = high
        if i == 0:
            buf[256:288] = key
        else:
            rng = np.random.default_rng(2000 + i)
            buf[256:288] = rng.integers(0, 256, 32, dtype=np.uint8).tobytes()
        p = tmp_path / f"dump_{i}.bin"
        p.write_bytes(bytes(buf))
        paths.append(str(p))
    return paths


def _upload_and_arm(client: TestClient) -> tuple[str, str]:
    r = client.post(
        "/api/oracles/upload",
        files={"file": ("t.py", ORACLE_SOURCE.encode(), "text/x-python")},
    )
    assert r.status_code == 200, r.text
    body = r.json()
    oracle_id, sha = body["id"], body["sha256"]
    r = client.post(f"/api/oracles/{oracle_id}/arm", json={"sha256": sha})
    assert r.status_code == 200
    return oracle_id, sha


def _start_pipeline_task(client: TestClient, source_paths: List[str]) -> str:
    """Kick off a pipeline run and return its task id."""
    oracle_id, _ = _upload_and_arm(client)
    r = client.post("/api/pipeline/run", json={
        "source_paths": source_paths,
        "oracle_id": oracle_id,
        "reduce": {
            "min_variance": 100.0,
            "entropy_window": 16,
            "entropy_threshold": 3.5,
            "min_region": 8,
            "alignment": 8,
            "block_size": 16,
        },
        "brute_force": {"key_sizes": [32], "stride": 8, "jobs": 1},
    })
    assert r.status_code == 200, r.text
    return r.json()["task_id"]


# ---------------------------------------------------------------------------
# GET /api/tasks/
# ---------------------------------------------------------------------------


def test_list_tasks_empty(client):
    """A fresh isolated env has no tasks → ``{"tasks": []}``."""
    r = client.get("/api/tasks/")
    assert r.status_code == 200
    assert r.json() == {"tasks": []}


# ---------------------------------------------------------------------------
# GET / DELETE on unknown ids → 404
# ---------------------------------------------------------------------------


def test_get_unknown_task_is_404(client):
    r = client.get("/api/tasks/nonexistent_task_id_xyz")
    assert r.status_code == 404
    assert "unknown task" in r.json()["detail"].lower()


def test_delete_unknown_task_is_404(client):
    r = client.delete("/api/tasks/nonexistent_task_id_xyz")
    assert r.status_code == 404
    assert "unknown task" in r.json()["detail"].lower()


# ---------------------------------------------------------------------------
# GET /api/tasks/{id}/result
# ---------------------------------------------------------------------------


def test_get_task_result_shape(client, synthetic_dumps):
    """A real task id yields a result envelope with the expected keys."""
    task_id = _start_pipeline_task(client, synthetic_dumps)
    r = client.get(f"/api/tasks/{task_id}/result")
    assert r.status_code == 200, r.text
    body = r.json()
    assert set(body) >= {"task_id", "status", "result"}
    assert body["task_id"] == task_id


# ---------------------------------------------------------------------------
# DELETE /api/tasks/{id} on an already-terminal task → 409
# ---------------------------------------------------------------------------


def test_delete_terminal_task_is_409(client):
    """A task already in a terminal state cannot be cancelled → 409.

    We register a SUCCEEDED record directly on the live singleton so the
    test is deterministic and never depends on a worker process running to
    completion within a timeout.
    """
    from memdiver.api.services.task_manager import (
        get_task_manager,
        TaskRecord,
        TaskStatus,
    )

    mgr = get_task_manager()
    record = TaskRecord(
        task_id="terminal-fixture-task",
        kind="pipeline",
        status=TaskStatus.SUCCEEDED,
        ended_at=time.time(),
    )
    with mgr._lock:  # noqa: SLF001 — test-only direct registration
        mgr._records[record.task_id] = record

    r = client.delete(f"/api/tasks/{record.task_id}")
    assert r.status_code == 409
    assert "terminal" in r.json()["detail"].lower()
