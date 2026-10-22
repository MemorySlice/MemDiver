"""REST memory-budget guard: 507 refusal with a structured body, and the
``force_memory`` override that lets the same request through.

The budget is shrunk to 1 MiB with ``MEMDIVER_MEMORY_BUDGET_MB=1`` and the
synthetic dumps are sized so every flat consensus estimate exceeds it.
"""

from __future__ import annotations

import numpy as np
import pytest
from fastapi.testclient import TestClient

from memdiver.api.config import get_settings
from memdiver.api.main import create_app
from memdiver.api.memory_budget_errors import (
    MEMORY_BUDGET_EXCEEDED_CODE,
    memory_budget_error_body,
    reraise_if_memory_budget,
)
from memdiver.api.services.task_manager import TaskRecord, _task_failure
from memdiver.core.service_errors import CapabilityError, ErrorCategory

DUMP_SIZE = 2 * 1024 * 1024  # 2 MiB each: well over a 1 MiB budget


@pytest.fixture(autouse=True)
def tiny_budget(tmp_path, monkeypatch):
    monkeypatch.setenv("MEMDIVER_MEMORY_BUDGET_MB", "1")
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "xdg"))


@pytest.fixture
def big_dumps(tmp_path):
    rng = np.random.default_rng(5)
    background = rng.integers(0, 4, DUMP_SIZE, dtype=np.uint8)
    paths = []
    for i in range(2):
        body = background.copy()
        body[4096:4144] = rng.integers(0, 256, 48, dtype=np.uint8)
        p = tmp_path / f"big_{i}.dump"
        p.write_bytes(body.tobytes())
        paths.append(str(p))
    return paths


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("MEMDIVER_ORACLE_DIR", str(tmp_path / "oracles"))
    monkeypatch.setenv("MEMDIVER_TASK_ROOT", str(tmp_path / "tasks"))
    monkeypatch.setenv("MEMDIVER_PIPELINE_MAX_WORKERS", "1")
    get_settings.cache_clear()
    with TestClient(create_app()) as c:
        yield c
    get_settings.cache_clear()


def _assert_507(resp):
    assert resp.status_code == 507, resp.text
    body = resp.json()
    assert body["code"] == MEMORY_BUDGET_EXCEEDED_CODE
    assert body["category"] == "PRECONDITION"
    assert body["error"] == body["message"] and body["message"]
    assert body["estimate_bytes"] > body["budget_bytes"] == 1024 * 1024
    assert body["details"]["estimate_bytes"] == body["estimate_bytes"]
    return body


def _bodies(paths):
    return {
        "/api/analysis/consensus": {"dump_paths": paths},
        "/api/analysis/consensus/aligned-window": {
            "dump_paths": paths, "anchor_path": paths[0], "view": "raw",
            "offset": 0, "length": 64,
        },
        "/api/analysis/consensus/regions": {"dump_paths": paths},
        "/api/analysis/candidates": {"dump_paths": paths},
        "/api/analysis/convergence": {"dump_paths": paths, "n_values": [2]},
    }


@pytest.mark.parametrize("route", list(_bodies(["a", "b"])))
def test_over_budget_is_507_with_structured_body(client, big_dumps, route):
    _assert_507(client.post(route, json=_bodies(big_dumps)[route]))


@pytest.mark.parametrize("route", list(_bodies(["a", "b"])))
def test_force_memory_overrides_the_guard(client, big_dumps, route):
    body = dict(_bodies(big_dumps)[route], force_memory=True)
    resp = client.post(route, json=body)
    assert resp.status_code == 200, resp.text


def test_auto_export_refusal_is_not_downgraded(client, big_dumps):
    _assert_507(client.post("/api/analysis/auto-export",
                            json={"dump_paths": big_dumps}))


def test_consensus_begin_accepts_force_memory_alias(client):
    size = 1024 * 1024
    _assert_507(client.post("/api/consensus/begin", json={"size": size}))
    forced = client.post("/api/consensus/begin",
                         json={"size": size, "force_memory": True})
    assert forced.status_code == 200, forced.text


def test_other_capability_errors_keep_their_status(client):
    resp = client.post("/api/analysis/candidates", json={"dump_paths": ["/x"]})
    assert resp.status_code in (400, 404)
    assert resp.json().get("code") != MEMORY_BUDGET_EXCEEDED_CODE


def _budget_error():
    return CapabilityError(
        "too big", category=ErrorCategory.PRECONDITION,
        code=MEMORY_BUDGET_EXCEEDED_CODE,
        details={"estimate_bytes": 10, "budget_bytes": 5, "operation": "x"},
    )


def test_error_body_flattens_estimate_and_budget():
    body = memory_budget_error_body(_budget_error())
    assert body == {
        "error": "too big", "code": MEMORY_BUDGET_EXCEEDED_CODE,
        "category": "PRECONDITION", "message": "too big",
        "estimate_bytes": 10, "budget_bytes": 5,
        "details": {"estimate_bytes": 10, "budget_bytes": 5, "operation": "x"},
    }


def test_reraise_only_for_budget_errors():
    with pytest.raises(CapabilityError):
        reraise_if_memory_budget(_budget_error())
    reraise_if_memory_budget(CapabilityError("other"))  # no raise


def test_task_failure_carries_code_and_numbers():
    message, info = _task_failure(_budget_error())
    assert message == "too big"
    assert info["code"] == MEMORY_BUDGET_EXCEEDED_CODE
    assert (info["estimate_bytes"], info["budget_bytes"]) == (10, 5)
    other_message, other_info = _task_failure(ValueError("boom"))
    assert other_message == "ValueError('boom')" and other_info is None


def test_task_record_round_trips_error_info():
    record = TaskRecord(task_id="t", kind="pipeline", error="too big",
                        error_info={"code": MEMORY_BUDGET_EXCEEDED_CODE})
    again = TaskRecord.from_dict(record.to_dict())
    assert again.error_info == {"code": MEMORY_BUDGET_EXCEEDED_CODE}


def test_pipeline_worker_params_carry_force_memory(tmp_path):
    from memdiver.api.routers.pipeline import (
        PipelineRunRequest,
        _build_worker_params,
    )
    req = PipelineRunRequest(source_paths=["a"], pcap_path="p.pcap",
                             force_memory=True)
    params = _build_worker_params(req, None, tmp_path)
    assert params["force_memory"] is True
    default = _build_worker_params(
        PipelineRunRequest(source_paths=["a"], pcap_path="p.pcap"),
        None, tmp_path)
    assert default["force_memory"] is False


def test_analysis_run_params_carry_force_memory():
    from memdiver.api.adapters import analyze_run_params
    from memdiver.api.models import AnalyzeRequestAPI
    model = AnalyzeRequestAPI(library_dirs=["x"], phase="p",
                              protocol_version="12", force_memory=True)
    assert analyze_run_params(model, task_root="/t")["force_memory"] is True
