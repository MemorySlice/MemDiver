"""End-to-end tests for api.routers.pipeline.

Uses a real FastAPI TestClient with the lifespan running, so the
ProcessPool + TaskManager + OracleRegistry substrate is exercised.
Each test uploads + arms a small Shape-1 oracle, POSTs a pipeline
request against four tiny synthetic dumps, polls until terminal,
then asserts on the TaskRecord + downloadable artifacts.

These tests spawn worker processes and take a couple of seconds
each — they're slower than the pure-Python pipeline_runner tests
but catch everything from Pydantic serialization to queue drain
semantics.
"""

from __future__ import annotations

import json
import os
import time
from pathlib import Path
from typing import List

import numpy as np
import pytest
from fastapi.testclient import TestClient

from api.config import get_settings
from api.main import create_app

ORACLE_SOURCE = (
    "KEY = bytes(range(32))\n"
    "def verify(candidate):\n"
    "    return candidate == KEY\n"
)


@pytest.fixture
def tmp_env(tmp_path: Path, monkeypatch):
    """Isolate the oracle dir + task root into tmp_path so the test
    never writes to the real ~/.memdiver paths."""
    oracle_dir = tmp_path / "oracles"
    task_root = tmp_path / "tasks"
    oracle_dir.mkdir()
    task_root.mkdir()
    monkeypatch.setenv("MEMDIVER_ORACLE_DIR", str(oracle_dir))
    monkeypatch.setenv("MEMDIVER_TASK_ROOT", str(task_root))
    monkeypatch.setenv("MEMDIVER_TASK_QUOTA_BYTES", "10485760")  # 10 MiB
    monkeypatch.setenv("MEMDIVER_PIPELINE_MAX_WORKERS", "1")
    # Clear cached Settings so env vars take effect.
    get_settings.cache_clear()
    yield tmp_path
    get_settings.cache_clear()


@pytest.fixture
def synthetic_dumps(tmp_path: Path) -> List[str]:
    """Four tiny raw dumps — first has sentinel at offset 256."""
    key = bytes(range(32))
    paths: List[str] = []
    padding_rng = np.random.default_rng(42)
    padding = padding_rng.integers(0, 256, 1024, dtype=np.uint8).tobytes()
    for i in range(4):
        buf = bytearray(padding)
        # Add variance sprinkles so entropy filter has targets.
        high = np.random.default_rng(1000 + i).integers(0, 256, 32, dtype=np.uint8).tobytes()
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


@pytest.fixture
def client(tmp_env):
    app = create_app()
    with TestClient(app) as client:
        yield client


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


def _wait_terminal(client: TestClient, task_id: str, timeout: float = 30.0) -> dict:
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


def test_pipeline_full_round_trip(client, synthetic_dumps):
    oracle_id, sha = _upload_and_arm(client)
    r = client.post("/api/pipeline/run", json={
        "source_paths": synthetic_dumps,
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
    body = r.json()
    task_id = body["task_id"]
    assert body["oracle_sha256"] == sha

    record = _wait_terminal(client, task_id)
    assert record["status"] == "succeeded", record
    names = {a["name"] for a in record["artifacts"]}
    assert {"consensus_variance", "consensus_reference",
            "candidates", "hits"} <= names

    # Download each artifact.
    for spec in record["artifacts"]:
        r = client.get(f"/api/pipeline/runs/{task_id}/artifacts/{spec['name']}")
        assert r.status_code == 200, (spec, r.text)
        assert len(r.content) == spec["size"]


# ------------------------------------------------------------------
# validation errors
# ------------------------------------------------------------------


def test_pipeline_rejects_unknown_oracle(client, synthetic_dumps):
    r = client.post("/api/pipeline/run", json={
        "source_paths": synthetic_dumps,
        "oracle_id": "no-such-oracle",
    })
    assert r.status_code == 404


def test_pipeline_rejects_unarmed_oracle(client, synthetic_dumps):
    r = client.post(
        "/api/oracles/upload",
        files={"file": ("t.py", ORACLE_SOURCE.encode(), "text/x-python")},
    )
    assert r.status_code == 200
    oracle_id = r.json()["id"]
    r = client.post("/api/pipeline/run", json={
        "source_paths": synthetic_dumps,
        "oracle_id": oracle_id,
    })
    assert r.status_code == 409


def test_pipeline_rejects_missing_source(client):
    oracle_id, _ = _upload_and_arm(client)
    r = client.post("/api/pipeline/run", json={
        "source_paths": ["/definitely/not/a/real/path.bin"],
        "oracle_id": oracle_id,
    })
    assert r.status_code == 400


# ------------------------------------------------------------------
# not found
# ------------------------------------------------------------------


def test_get_unknown_task_is_404(client):
    r = client.get("/api/pipeline/runs/nope")
    assert r.status_code == 404


def test_download_unknown_artifact_is_404(client, synthetic_dumps):
    oracle_id, _ = _upload_and_arm(client)
    r = client.post("/api/pipeline/run", json={
        "source_paths": synthetic_dumps,
        "oracle_id": oracle_id,
        "reduce": {
            "min_variance": 100.0,
            "entropy_window": 16,
            "entropy_threshold": 3.5,
            "min_region": 8,
            "alignment": 8,
            "block_size": 16,
        },
    })
    task_id = r.json()["task_id"]
    _wait_terminal(client, task_id)
    r = client.get(f"/api/pipeline/runs/{task_id}/artifacts/does-not-exist")
    assert r.status_code == 404
