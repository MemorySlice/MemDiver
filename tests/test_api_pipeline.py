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

from memdiver.api.config import get_settings
from memdiver.api.main import create_app
from memdiver.engine.brute_force import DEFAULT_NEIGHBORHOOD_PAD

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


# ------------------------------------------------------------------
# download_artifact fallback security (regression for symlink bypass)
# ------------------------------------------------------------------


class _FakeRecord:
    def __init__(self, artifacts):
        self.artifacts = artifacts


class _FakeManager:
    """Minimal stand-in exposing only what download_artifact touches."""

    def __init__(self, record, store):
        self._record = record
        self.artifact_store = store

    def get(self, task_id):
        return self._record


def test_download_fallback_rejects_in_tree_symlink(tmp_path, monkeypatch):
    """The fallback resolve path (store has no registered spec) must still
    refuse an in-tree symlink that escapes the task dir — previously it
    used a bare resolve()+relative_to and would happily serve it."""
    import os

    from fastapi import HTTPException

    from memdiver.api.routers import pipeline as pipeline_mod
    from memdiver.api.services.artifact_store import ArtifactSpec, ArtifactStore

    # Secret file living OUTSIDE the store root.
    secret = tmp_path / "secret.txt"
    secret.write_bytes(b"top-secret")

    store_root = tmp_path / "tasks"
    store = ArtifactStore(store_root, max_total_bytes=0)
    task_dir = store.task_dir("task-symlink")

    # An in-tree symlink whose target escapes the task dir.
    link = task_dir / "leak.bin"
    os.symlink(secret, link)

    # Spec is on the TaskRecord but NOT registered in the store, so
    # store.open() raises ArtifactNotFound and we hit the fallback.
    spec = ArtifactSpec(name="leak", relpath="leak.bin",
                        media_type="application/octet-stream")
    record = _FakeRecord([spec])
    manager = _FakeManager(record, store)
    monkeypatch.setattr(pipeline_mod, "_task_manager_or_503", lambda: manager)

    with pytest.raises(HTTPException) as exc_info:
        pipeline_mod.download_artifact("task-symlink", "leak")
    assert exc_info.value.status_code == 400


def test_download_fallback_serves_regular_in_tree_file(tmp_path, monkeypatch):
    """Sanity: the hardened fallback still serves a genuine regular file."""
    from memdiver.api.routers import pipeline as pipeline_mod
    from memdiver.api.services.artifact_store import ArtifactSpec, ArtifactStore

    store_root = tmp_path / "tasks"
    store = ArtifactStore(store_root, max_total_bytes=0)
    task_dir = store.task_dir("task-ok")
    (task_dir / "report.bin").write_bytes(b"hello")

    spec = ArtifactSpec(name="report", relpath="report.bin")
    record = _FakeRecord([spec])
    manager = _FakeManager(record, store)
    monkeypatch.setattr(pipeline_mod, "_task_manager_or_503", lambda: manager)

    resp = pipeline_mod.download_artifact("task-ok", "report")
    assert Path(resp.path).read_bytes() == b"hello"


# ------------------------------------------------------------------
# refine_consensus neighborhood variance (regression for stale m2)
# ------------------------------------------------------------------


def test_refine_neighborhood_variance_uses_post_fold_state(tmp_path, monkeypatch):
    """After folding new dumps, hit_neighborhood variance must reflect the
    POST-fold Welford state, not the stale pre-fold local m2 array divided
    by the new (larger) dump count."""
    import asyncio

    import numpy as np

    from memdiver.core.variance import WelfordVariance
    from memdiver.api.routers import pipeline as pipeline_mod

    size = 256

    def _make_dump(seed):
        rng = np.random.default_rng(seed)
        return rng.integers(0, 256, size, dtype=np.uint8).tobytes()

    base_dumps = [_make_dump(s) for s in (1, 2)]
    extra_dumps = [_make_dump(s) for s in (3, 4)]

    # Build + persist the pre-fold Welford state (2 base dumps).
    base = WelfordVariance(size)
    for d in base_dumps:
        base.add_dump(d)
    mean, m2, n = base.state_arrays()

    consensus_dir = tmp_path / "art" / "consensus"
    consensus_dir.mkdir(parents=True)
    mean_path = consensus_dir / "mean.npy"
    m2_path = consensus_dir / "m2.npy"
    np.save(mean_path, mean)
    np.save(m2_path, m2)
    state = {
        "mean_path": str(mean_path),
        "m2_path": str(m2_path),
        "num_dumps": int(n),
    }
    (consensus_dir / "state.json").write_text(json.dumps(state))

    # A hit at offset 96, length 16 so its neighborhood is non-trivial.
    hit_offset, hit_len = 96, 16
    bf_dir = tmp_path / "art" / "brute_force"
    bf_dir.mkdir(parents=True)
    (bf_dir / "hits.json").write_text(
        json.dumps({"hits": [{"offset": hit_offset, "length": hit_len}]})
    )

    # Write the extra dumps to disk so open_dump can read them.
    extra_paths = []
    for i, d in enumerate(extra_dumps):
        p = tmp_path / f"extra_{i}.bin"
        p.write_bytes(d)
        extra_paths.append(str(p))

    # Compute the expected POST-fold variance independently.
    expected = WelfordVariance(size)
    for d in base_dumps + extra_dumps:
        expected.add_dump(d)
    expected_var = expected.variance()

    record = {"artifact_dir": str(tmp_path / "art")}
    manager = _FakeManager(record, store=None)
    monkeypatch.setattr(pipeline_mod, "_task_manager_or_503", lambda: manager)

    body = pipeline_mod.RefineRequest(additional_paths=extra_paths)
    resp = asyncio.run(pipeline_mod.refine_consensus("t", body))

    assert resp.num_dumps == 4
    assert len(resp.hit_neighborhoods) == 1
    nb = resp.hit_neighborhoods[0]
    # Import the pad, never re-literal it: a local ``64`` here pinned this
    # handler's *copy* of the constant and would have silently agreed with a
    # regression that moved the engine's default.
    nb_pad = DEFAULT_NEIGHBORHOOD_PAD
    start = max(0, hit_offset - nb_pad)
    end = min(size, hit_offset + hit_len + nb_pad)
    got = np.array(nb["neighborhood_variance"], dtype=np.float32)
    np.testing.assert_allclose(got, expected_var[start:end], rtol=1e-5, atol=1e-3)

    # And confirm it is NOT the buggy stale-m2 / new_n value.
    stale = (m2[start:end].astype(np.float32) / 4.0)
    assert not np.allclose(got, stale, rtol=1e-5, atol=1e-3)


# ------------------------------------------------------------------
# refine / neighborhood locate state.json from a real TaskRecord
# (regression for the phantom ``artifact_dir`` 400)
# ------------------------------------------------------------------


def _seed_consensus_on_disk(store_root: Path, task_id: str, size: int = 256):
    """Materialise a real consensus/state.json (+ mean/m2 + hits) under the
    artifact store's task dir, exactly where the pipeline worker writes it.

    Returns ``(TaskRecord, m2_array)``. The TaskRecord carries the genuine
    ``consensus_state`` artifact spec and — like the production record — has
    NO ``artifact_dir`` attribute, so the handlers must resolve the path via
    ``artifact_store.root / task_id``.
    """
    from memdiver.api.services.artifact_store import ArtifactSpec, ArtifactStore
    from memdiver.api.services.task_manager import TaskRecord, TaskStatus
    from memdiver.core.variance import WelfordVariance

    store = ArtifactStore(store_root, max_total_bytes=0)
    task_dir = store.task_dir(task_id)
    consensus_dir = task_dir / "consensus"
    consensus_dir.mkdir(parents=True, exist_ok=True)

    welford = WelfordVariance(size)
    for seed in (1, 2, 3):
        rng = np.random.default_rng(seed)
        welford.add_dump(rng.integers(0, 256, size, dtype=np.uint8).tobytes())
    mean, m2, n = welford.state_arrays()

    mean_path = consensus_dir / "mean.npy"
    m2_path = consensus_dir / "m2.npy"
    np.save(mean_path, mean)
    np.save(m2_path, m2)
    (consensus_dir / "state.json").write_text(json.dumps({
        "size": int(size),
        "num_dumps": int(n),
        "mean_path": str(mean_path),
        "m2_path": str(m2_path),
    }))

    bf_dir = task_dir / "brute_force"
    bf_dir.mkdir(parents=True, exist_ok=True)
    (bf_dir / "hits.json").write_text(
        json.dumps({"hits": [{"offset": 96, "length": 16}]})
    )

    record = TaskRecord(
        task_id=task_id,
        kind="pipeline",
        status=TaskStatus.SUCCEEDED,
        artifacts=[
            ArtifactSpec(
                name="consensus_state",
                relpath="consensus/state.json",
                media_type="application/json",
            ),
        ],
    )
    return store, record, m2


def test_refine_locates_state_from_taskrecord(tmp_path, monkeypatch):
    """POST /runs/{id}/refine must find consensus/state.json via the artifact
    store (root/task_id), NOT the phantom ``artifact_dir`` — which always
    made a genuine TaskRecord 400 'consensus state not found'."""
    import asyncio

    from memdiver.api.routers import pipeline as pipeline_mod

    task_id = "task-refine-regression"
    store, record, _ = _seed_consensus_on_disk(tmp_path / "tasks", task_id)

    # Sanity: the production record genuinely has no artifact_dir field.
    assert not hasattr(record, "artifact_dir")

    manager = _FakeManager(record, store)
    monkeypatch.setattr(pipeline_mod, "_task_manager_or_503", lambda: manager)

    # An additional dump to fold (same size as the consensus state).
    extra = tmp_path / "extra.bin"
    extra.write_bytes(
        np.random.default_rng(99).integers(0, 256, 256, dtype=np.uint8).tobytes()
    )

    body = pipeline_mod.RefineRequest(additional_paths=[str(extra)])
    resp = asyncio.run(pipeline_mod.refine_consensus(task_id, body))

    # Was 3 dumps on disk; folding one more -> 4. Reaching here at all means
    # we did NOT raise the 400.
    assert resp.num_dumps == 4
    assert len(resp.hit_neighborhoods) == 1


def test_neighborhood_locates_state_from_taskrecord(tmp_path, monkeypatch):
    """GET /runs/{id}/neighborhood must likewise resolve state.json from the
    artifact store rather than raising 400."""
    import asyncio

    from memdiver.api.routers import pipeline as pipeline_mod

    task_id = "task-neighborhood-regression"
    store, record, m2 = _seed_consensus_on_disk(tmp_path / "tasks", task_id)

    manager = _FakeManager(record, store)
    monkeypatch.setattr(pipeline_mod, "_task_manager_or_503", lambda: manager)

    result = asyncio.run(
        pipeline_mod.get_neighborhood(task_id, offset=96, length=16)
    )

    assert result["num_dumps"] == 3
    assert len(result["variance"]) > 0


def test_neighborhood_pad_defaults_to_the_engine_constant(tmp_path, monkeypatch):
    """The endpoint's window is the one brute-force would have attached.

    Both the default and an explicit non-default pad are checked, so the query
    param is proven live rather than accepted and ignored.
    """
    import asyncio

    from memdiver.api.routers import pipeline as pipeline_mod

    task_id = "task-neighborhood-pad"
    store, record, m2 = _seed_consensus_on_disk(tmp_path / "tasks", task_id)
    monkeypatch.setattr(
        pipeline_mod, "_task_manager_or_503", lambda: _FakeManager(record, store)
    )

    offset, length = 96, 16
    default = asyncio.run(
        pipeline_mod.get_neighborhood(task_id, offset=offset, length=length)
    )
    explicit = asyncio.run(pipeline_mod.get_neighborhood(
        task_id, offset=offset, length=length,
        neighborhood_pad=DEFAULT_NEIGHBORHOOD_PAD,
    ))
    assert default == explicit
    # The state is only 256 bytes wide, so the window is clamped at both ends;
    # assert the bounds the handler computed, derived from the constant.
    expected_start = max(0, offset - DEFAULT_NEIGHBORHOOD_PAD)
    expected_end = min(len(m2), offset + length + DEFAULT_NEIGHBORHOOD_PAD)
    assert default["neighborhood_start"] == expected_start
    assert len(default["variance"]) == expected_end - expected_start

    narrow = asyncio.run(pipeline_mod.get_neighborhood(
        task_id, offset=offset, length=length, neighborhood_pad=8,
    ))
    assert narrow["neighborhood_start"] == offset - 8
    assert len(narrow["variance"]) == 8 + length + 8


def test_neighborhood_rejects_negative_pad(tmp_path, monkeypatch):
    """A negative pad would invert the slice bounds -> 400, before any I/O."""
    import asyncio

    from fastapi import HTTPException

    from memdiver.api.routers import pipeline as pipeline_mod

    with pytest.raises(HTTPException) as exc:
        asyncio.run(pipeline_mod.get_neighborhood(
            "task-does-not-matter", offset=0, length=32, neighborhood_pad=-1,
        ))
    assert exc.value.status_code == 400
    assert "neighborhood_pad" in exc.value.detail


def test_refine_and_neighborhood_end_to_end(client, synthetic_dumps):
    """Full round trip: run the real pipeline, then hit refine + neighborhood
    over HTTP and assert 200 (they were dead-on-arrival returning 400)."""
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
        "brute_force": {"key_sizes": [32], "stride": 8, "jobs": 1},
    })
    assert r.status_code == 200, r.text
    task_id = r.json()["task_id"]
    record = _wait_terminal(client, task_id)
    assert record["status"] == "succeeded", record

    # neighborhood
    r = client.get(
        f"/api/pipeline/runs/{task_id}/neighborhood",
        params={"offset": 256, "length": 32},
    )
    assert r.status_code == 200, r.text
    assert r.json()["num_dumps"] >= 1

    # refine: fold the same dumps back in (they exist + are the right size).
    r = client.post(
        f"/api/pipeline/runs/{task_id}/refine",
        json={"additional_paths": synthetic_dumps},
    )
    assert r.status_code == 200, r.text
    assert r.json()["num_dumps"] >= len(synthetic_dumps)
