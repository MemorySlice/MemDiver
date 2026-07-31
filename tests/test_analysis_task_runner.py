"""Tests for app.pipeline.analysis_task_runner.

Two layers:

1. In-process runner tests drive ``run_file`` / ``run_analysis`` directly
   inside a fake ``WorkerContext`` (no ProcessPool), assert the emitted
   progress events, and — crucially — assert the ``analysis_result``
   artifact the runner writes is byte-for-byte identical to what the old
   synchronous route bodies produced on the same input. The "golden"
   reference is computed inline the exact way the former
   ``api.routers.analysis.run_file_analysis`` /
   ``mcp_server.tools.analyze_library`` code paths did.

2. An end-to-end API test submits ``POST /api/analysis/run-file`` through
   a real TestClient (lifespan + TaskManager ProcessPool), polls the task
   to completion, downloads the artifact, and confirms the parsed
   ``AnalysisResult`` matches the in-process result.
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List

import pytest
from fastapi.testclient import TestClient

from memdiver.api.config import get_settings
from memdiver.api.main import create_app
from memdiver.app.pipeline.analysis_task_runner import run_analysis, run_file


# ------------------------------------------------------------------
# fake WorkerContext (mirrors tests/test_pipeline_runner.py::_FakeCtx)
# ------------------------------------------------------------------


@dataclass
class _FakeCtx:
    task_id: str = "test-analysis"
    cancel: bool = False
    events: List[Dict[str, Any]] = field(default_factory=list)

    def emit(self, event_type: str, **fields: Any) -> None:
        self.events.append({"type": event_type, **fields})

    def is_cancelled(self) -> bool:
        return self.cancel


# ------------------------------------------------------------------
# fixtures
# ------------------------------------------------------------------


FILE_ALGORITHMS = ["entropy_scan", "pattern_match", "structure_scan"]


@pytest.fixture
def dump_file(tmp_path: Path) -> Path:
    """A small raw dump with a mix of stable + high-entropy content."""
    import numpy as np

    buf = bytearray(np.random.default_rng(7).integers(0, 256, 512, dtype=np.uint8).tobytes())
    # A clearly-structured stable region so pattern/structure scans have
    # something deterministic to chew on.
    buf[0:16] = b"MEMDIVER_HEADER!"
    p = tmp_path / "sample.bin"
    p.write_bytes(bytes(buf))
    return p


def _golden_run_file(dump_path: Path, algorithms: List[str]) -> Dict[str, Any]:
    """Reproduce the former synchronous run_file_analysis body exactly."""
    from memdiver.algorithms.base import AnalysisContext
    from memdiver.algorithms.registry import get_registry
    from memdiver.core.dump_source import open_dump

    filename = dump_path.name
    with open_dump(dump_path) as source:
        dump_data = source.read_all()

    context = AnalysisContext(
        library=filename,
        protocol_version="unknown",
        phase="file",
        extra={},
    )
    registry = get_registry()
    hits: List[dict] = []
    algorithm_metadata: dict = {}
    for algo_name in algorithms:
        try:
            algorithm = registry.get(algo_name)
        except KeyError:
            algorithm_metadata[algo_name] = {"error": f"unknown algorithm: {algo_name}"}
            continue
        result = algorithm.run(dump_data, context)
        algorithm_metadata[algo_name] = {
            "confidence": result.confidence,
            "match_count": len(result.matches),
        }
        for match in result.matches:
            hits.append({
                "secret_type": algo_name,
                "offset": match.offset,
                "length": match.length,
                "dump_path": str(dump_path),
                "library": filename,
                "phase": "file",
                "run_id": 0,
                "confidence": match.confidence,
            })

    library_report = {
        "library": filename,
        "protocol_version": "unknown",
        "phase": "file",
        "num_runs": 1,
        "hits": hits,
        "static_regions": [],
        "metadata": {
            "algorithms": algorithms,
            "dump_path": str(dump_path),
            "algorithm_results": algorithm_metadata,
        },
    }
    return {"libraries": [library_report], "metadata": {}}


# ------------------------------------------------------------------
# in-process runner: run_file
# ------------------------------------------------------------------


def test_run_file_matches_synchronous_output(dump_file, tmp_path):
    ctx = _FakeCtx()
    params = {
        "artifact_dir": str(tmp_path / "task"),
        "dump_path": str(dump_file),
        "algorithms": FILE_ALGORITHMS,
        "user_regex": None,
        "custom_patterns": None,
        "passphrase": None,
        "key_hex": None,
        "kem_key_hex": None,
    }
    ret = run_file(params, ctx)

    # The runner writes the full AnalysisResult as the analysis_result artifact.
    assert len(ret["artifacts"]) == 1
    spec = ret["artifacts"][0]
    assert spec["name"] == "analysis_result"
    result_path = Path(params["artifact_dir"]) / spec["relpath"]
    produced = json.loads(result_path.read_text())

    expected = _golden_run_file(dump_file, FILE_ALGORITHMS)
    assert produced == expected, "runner output diverged from old sync path"


def test_run_file_emits_stage_and_per_algorithm_progress(dump_file, tmp_path):
    ctx = _FakeCtx()
    params = {
        "artifact_dir": str(tmp_path / "task"),
        "dump_path": str(dump_file),
        "algorithms": FILE_ALGORITHMS,
    }
    run_file(params, ctx)
    types = [e["type"] for e in ctx.events]
    assert types[0] == "stage_start"
    assert types[-1] == "stage_end"
    progress = [e for e in ctx.events if e["type"] == "progress"]
    # One progress event per algorithm.
    assert len(progress) == len(FILE_ALGORITHMS)
    assert all(e["stage"] == "analyze" for e in ctx.events if "stage" in e)


def test_run_file_missing_path_raises(tmp_path):
    ctx = _FakeCtx()
    params = {
        "artifact_dir": str(tmp_path / "task"),
        "dump_path": str(tmp_path / "does_not_exist.bin"),
        "algorithms": FILE_ALGORITHMS,
    }
    with pytest.raises(FileNotFoundError):
        run_file(params, ctx)


def test_run_file_cancellation(dump_file, tmp_path):
    ctx = _FakeCtx(cancel=True)
    params = {
        "artifact_dir": str(tmp_path / "task"),
        "dump_path": str(dump_file),
        "algorithms": FILE_ALGORITHMS,
    }
    with pytest.raises(RuntimeError, match="cancelled"):
        run_file(params, ctx)


# ------------------------------------------------------------------
# in-process runner: run_analysis (library path)
# ------------------------------------------------------------------


@pytest.fixture
def fixture_library_dir() -> str:
    here = Path(__file__).parent
    lib = here / "fixtures" / "dataset" / "TLS12" / "scenario_a" / "openssl"
    assert lib.is_dir(), f"fixture missing: {lib}"
    return str(lib)


def test_run_analysis_matches_analyze_library(fixture_library_dir, tmp_path):
    from memdiver.mcp_server.session import ToolSession
    from memdiver.mcp_server.tools import analyze_library

    params = {
        "artifact_dir": str(tmp_path / "task"),
        "library_dirs": [fixture_library_dir],
        "phase": "pre_handshake",
        "protocol_version": "12",
        "max_runs": 1,
        "algorithms": ["entropy_scan"],
    }
    ctx = _FakeCtx()
    ret = run_analysis(params, ctx)

    spec = ret["artifacts"][0]
    produced = json.loads((Path(params["artifact_dir"]) / spec["relpath"]).read_text())

    expected = analyze_library(
        ToolSession(),
        [fixture_library_dir],
        "pre_handshake",
        "12",
        max_runs=1,
        algorithms=["entropy_scan"],
    )
    assert produced == expected
    assert ctx.events[0]["type"] == "stage_start"
    assert ctx.events[-1]["type"] == "stage_end"


def test_run_analysis_missing_dir_raises(tmp_path):
    params = {
        "artifact_dir": str(tmp_path / "task"),
        "library_dirs": [str(tmp_path / "nope")],
        "phase": "pre_handshake",
        "protocol_version": "12",
    }
    with pytest.raises(ValueError):
        run_analysis(params, _FakeCtx())


# ------------------------------------------------------------------
# end-to-end API: run-file submit -> poll -> download artifact
# ------------------------------------------------------------------


@pytest.fixture
def api_env(tmp_path: Path, monkeypatch):
    oracle_dir = tmp_path / "oracles"
    task_root = tmp_path / "tasks"
    oracle_dir.mkdir()
    task_root.mkdir()
    monkeypatch.setenv("MEMDIVER_ORACLE_DIR", str(oracle_dir))
    monkeypatch.setenv("MEMDIVER_TASK_ROOT", str(task_root))
    monkeypatch.setenv("MEMDIVER_TASK_QUOTA_BYTES", "10485760")
    monkeypatch.setenv("MEMDIVER_PIPELINE_MAX_WORKERS", "1")
    get_settings.cache_clear()
    yield tmp_path
    get_settings.cache_clear()


@pytest.fixture
def client(api_env):
    app = create_app()
    with TestClient(app) as c:
        yield c


def _wait_terminal(client: TestClient, task_id: str, timeout: float = 60.0) -> Dict:
    deadline = time.time() + timeout
    while time.time() < deadline:
        r = client.get(f"/api/pipeline/runs/{task_id}")
        assert r.status_code == 200
        rec = r.json()
        if rec["status"] in ("succeeded", "failed", "cancelled"):
            return rec
        time.sleep(0.1)
    raise AssertionError(f"task {task_id} never reached terminal state")


def test_run_file_endpoint_submits_and_completes(client, tmp_path):
    import numpy as np

    buf = bytearray(np.random.default_rng(7).integers(0, 256, 512, dtype=np.uint8).tobytes())
    buf[0:16] = b"MEMDIVER_HEADER!"
    dump = tmp_path / "sample.bin"
    dump.write_bytes(bytes(buf))

    r = client.post(
        "/api/analysis/run-file",
        json={"dump_path": str(dump), "algorithms": ["structure_scan"]},
    )
    assert r.status_code == 200, r.text
    body = r.json()
    task_id = body["task_id"]
    assert isinstance(task_id, str) and task_id
    assert body["status"] in {"pending", "running", "succeeded"}

    rec = _wait_terminal(client, task_id)
    assert rec["status"] == "succeeded", rec.get("error")

    spec = next(a for a in rec["artifacts"] if a["name"] == "analysis_result")
    dl = client.get(
        f"/api/pipeline/runs/{task_id}/artifacts/{spec['name']}"
    )
    assert dl.status_code == 200, dl.text
    result = dl.json()
    assert "libraries" in result
    assert result["libraries"][0]["library"] == "sample.bin"


def test_run_file_endpoint_missing_file_returns_404(client, tmp_path):
    r = client.post(
        "/api/analysis/run-file",
        json={"dump_path": str(tmp_path / "ghost.bin"), "algorithms": ["structure_scan"]},
    )
    assert r.status_code == 404
