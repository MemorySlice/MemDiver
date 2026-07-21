"""End-to-end test for ``POST /api/pipeline/auto-floor``.

Uploads + arms a Shape-1 oracle, builds a variance ``.npy`` + reference
dump from four tiny synthetic dumps, then runs auto-floor over HTTP and
asserts the verdict matches ``engine.auto_floor.run_auto_floor`` called
directly on the very same inputs (the endpoint must not drift from the
engine's single source of truth).
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import List, Tuple

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import numpy as np
import pytest
from fastapi.testclient import TestClient

from memdiver.api.config import get_settings
from memdiver.api.main import create_app
from memdiver.api.routers.pipeline import ReduceParams

_KEY = bytes(range(32))
_KEY_OFFSET = 256
_SIZE = 1024

ORACLE_SOURCE = (
    "KEY = bytes(range(32))\n"
    "def verify(candidate):\n"
    "    return candidate == KEY\n"
)


@pytest.fixture
def tmp_env(tmp_path: Path, monkeypatch):
    oracle_dir = tmp_path / "oracles"
    task_root = tmp_path / "tasks"
    oracle_dir.mkdir()
    task_root.mkdir()
    monkeypatch.setenv("MEMDIVER_ORACLE_DIR", str(oracle_dir))
    monkeypatch.setenv("MEMDIVER_TASK_ROOT", str(task_root))
    monkeypatch.setenv("MEMDIVER_PIPELINE_MAX_WORKERS", "1")
    get_settings.cache_clear()
    yield tmp_path
    get_settings.cache_clear()


@pytest.fixture
def client(tmp_env):
    app = create_app()
    with TestClient(app) as client:
        yield client


@pytest.fixture
def auto_floor_inputs(tmp_path: Path) -> Tuple[str, str]:
    """Build four dumps, persist variance.npy + reference dump.

    dump_0 carries the real key at ``_KEY_OFFSET``; the other three carry
    random bytes there, so the window variance is high. Sprinkled high-
    entropy regions keep the entropy/alignment filter's targets realistic.
    Returns ``(variance_path, reference_path)``.
    """
    padding = np.random.default_rng(42).integers(0, 256, _SIZE, dtype=np.uint8).tobytes()
    dumps: List[bytes] = []
    for i in range(4):
        buf = bytearray(padding)
        high = np.random.default_rng(1000 + i).integers(0, 256, 32, dtype=np.uint8).tobytes()
        buf[64:96] = high
        buf[512:544] = high
        if i == 0:
            buf[_KEY_OFFSET:_KEY_OFFSET + 32] = _KEY
        else:
            rng = np.random.default_rng(2000 + i)
            buf[_KEY_OFFSET:_KEY_OFFSET + 32] = rng.integers(0, 256, 32, dtype=np.uint8).tobytes()
        dumps.append(bytes(buf))

    stack = np.stack([np.frombuffer(d, dtype=np.uint8).astype(np.float64) for d in dumps])
    variance = stack.var(axis=0)  # population variance == consensus variance
    variance_path = tmp_path / "variance.npy"
    np.save(variance_path, variance)

    reference_path = tmp_path / "reference.bin"
    reference_path.write_bytes(dumps[0])
    return str(variance_path), str(reference_path)


def _upload_and_arm(client: TestClient) -> str:
    r = client.post(
        "/api/oracles/upload",
        files={"file": ("t.py", ORACLE_SOURCE.encode(), "text/x-python")},
    )
    assert r.status_code == 200, r.text
    body = r.json()
    oracle_id, sha = body["id"], body["sha256"]
    r = client.post(f"/api/oracles/{oracle_id}/arm", json={"sha256": sha})
    assert r.status_code == 200
    return oracle_id


_REDUCE = {
    "min_variance": 100.0,
    "entropy_window": 16,
    "entropy_threshold": 3.5,
    "min_region": 8,
    "alignment": 8,
    "block_size": 16,
}


def _direct_verdict(variance_path: str, reference_path: str) -> dict:
    """Run run_auto_floor directly on the same inputs the endpoint uses."""
    from memdiver.engine.auto_floor import run_auto_floor

    variance = np.load(variance_path)
    reference = Path(reference_path).read_bytes()[: len(variance)]
    reduce_kwargs = ReduceParams(**_REDUCE).model_dump()
    reduce_kwargs.pop("min_variance", None)

    return run_auto_floor(
        variance, reference, 4, lambda w: w == _KEY,
        reduce_kwargs=reduce_kwargs, key_sizes=(32,), stride=8,
        phi0_method="pmin", p_min=0.35,
    ).to_dict()


def test_auto_floor_over_http_matches_direct(client, auto_floor_inputs):
    variance_path, reference_path = auto_floor_inputs
    oracle_id = _upload_and_arm(client)

    r = client.post("/api/pipeline/auto-floor", json={
        "variance_path": variance_path,
        "reference_dump": reference_path,
        "oracle_id": oracle_id,
        "num_dumps": 4,
        "reduce": _REDUCE,
        "key_sizes": [32],
        "stride": 8,
    })
    assert r.status_code == 200, r.text
    body = r.json()
    assert "verdict" in body

    direct = _direct_verdict(variance_path, reference_path)

    # The key is present, so both paths must recover it at the same offset.
    assert body["verdict"] == direct["verdict"]
    assert body["verdict"] in ("RECOVERED", "FLOOR_WAS_TOO_HIGH")
    assert body["offset"] == direct["offset"] == _KEY_OFFSET
    assert body["key_hex"] == direct["key_hex"] == _KEY.hex()
    assert body["phi_star"] == pytest.approx(direct["phi_star"])
    assert body["oracle_sha256"]


def test_auto_floor_rejects_unknown_oracle(client, auto_floor_inputs):
    variance_path, reference_path = auto_floor_inputs
    r = client.post("/api/pipeline/auto-floor", json={
        "variance_path": variance_path,
        "reference_dump": reference_path,
        "oracle_id": "no-such-oracle",
        "num_dumps": 4,
    })
    assert r.status_code == 404


def test_auto_floor_rejects_missing_variance(client):
    oracle_id = _upload_and_arm(client)
    r = client.post("/api/pipeline/auto-floor", json={
        "variance_path": "/definitely/not/here.npy",
        "reference_dump": "/definitely/not/here.bin",
        "oracle_id": oracle_id,
        "num_dumps": 4,
    })
    assert r.status_code == 400
