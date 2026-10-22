"""The memory-guard override ``force`` reaches the budget-gated consensus builders.

Covers the app/engine callers and background task runners that sit between a
surface (CLI / MCP / REST) and ``ConsensusVector.build_from_sources`` /
``build_consensus``: each must forward ``force`` (params key ``force_memory``
for the task runners) and default to ``False`` so the guard stays on.
"""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import numpy as np
import pytest

from memdiver.core.service_errors import CapabilityError, ErrorCategory

BUDGET_CODE = "memory_budget_exceeded"


class _Stop(Exception):
    """Raised by spies to short-circuit the rest of a producer."""


class _FakeCtx:
    task_id = "t-force"

    def __init__(self):
        self.events = []

    def emit(self, event, **fields):
        self.events.append((event, fields))

    def is_cancelled(self):
        return False


def _budget_error():
    return CapabilityError(
        "estimated 9 MiB exceeds budget 1 MiB",
        category=ErrorCategory.PRECONDITION, code=BUDGET_CODE,
        details={"estimate_bytes": 9, "budget_bytes": 1},
    )


def _write_dumps(root: Path, n: int = 3, size: int = 2 * 1024 * 1024):
    rng = np.random.default_rng(1)
    base = rng.integers(0, 256, size, dtype=np.uint8)
    paths = []
    for i in range(n):
        data = base.copy()
        data[4096:4096 + 32] = rng.integers(0, 256, 32, dtype=np.uint8)
        p = root / f"run_{i}" / "dump.dump"
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(data.tobytes())
        paths.append(p)
    return paths


# --- core.input_schemas / engine.pipeline -----------------------------------


def test_analyze_request_force_defaults_false(tmp_path):
    from memdiver.core.input_schemas import AnalyzeRequest

    req = AnalyzeRequest(library_dirs=[tmp_path], phase="p", protocol_version="13")
    assert req.force is False
    assert AnalyzeRequest(library_dirs=[tmp_path], phase="p",
                          protocol_version="13", force=True).force is True


@pytest.mark.parametrize("force", [False, True])
def test_pipeline_run_threads_request_force(tmp_path, monkeypatch, force):
    from memdiver.core.input_schemas import AnalyzeRequest
    from memdiver.engine.pipeline import AnalysisPipeline

    seen = {}

    def fake_analyze(self, *args, **kwargs):
        seen["force"] = kwargs.get("force")
        raise _Stop

    monkeypatch.setattr(AnalysisPipeline, "analyze_library", fake_analyze)
    req = AnalyzeRequest(library_dirs=[tmp_path], phase="p",
                         protocol_version="13", force=force,
                         template=object())
    with pytest.raises(_Stop):
        AnalysisPipeline(auto_persist=False).run(req)
    assert seen["force"] is force


@pytest.mark.parametrize("force", [False, True])
def test_pipeline_analyze_library_forwards_force_to_builder(
        tmp_path, monkeypatch, force):
    from memdiver.engine import pipeline as pl

    dumps = _write_dumps(tmp_path, n=2, size=8192)
    runs = [SimpleNamespace(library="lib", path=p.parent) for p in dumps]
    by_run = {id(r): SimpleNamespace(path=p) for r, p in zip(runs, dumps)}
    monkeypatch.setattr(pl.RunDiscovery, "discover_library_runs",
                        staticmethod(lambda *a, **k: runs))
    monkeypatch.setattr(pl, "_resolve_dump",
                        lambda run, phase, normalize: by_run[id(run)])
    seen = {}

    def spy(self, sources, **kwargs):
        seen["force"] = kwargs.get("force")
        raise _Stop

    monkeypatch.setattr(pl.ConsensusVector, "build_from_sources", spy)
    pipe = pl.AnalysisPipeline(auto_persist=False)
    with pytest.raises(_Stop):
        pipe.analyze_library(tmp_path, "p", "13", force=force)
    assert seen["force"] is force


# --- app.tools.analyze_library ----------------------------------------------


@pytest.mark.parametrize("force", [False, True])
def test_tools_analyze_library_sets_request_force(tmp_path, monkeypatch, force):
    from memdiver.app import tools

    seen = {}

    def fake_run(request):
        seen["force"] = request.force
        raise _Stop

    monkeypatch.setattr(tools, "run_analysis_request", fake_run)
    with pytest.raises(_Stop):
        tools.analyze_library(None, [str(tmp_path)], "p", "13", force=force)
    assert seen["force"] is force


def test_tools_analyze_library_default_force_false(tmp_path, monkeypatch):
    from memdiver.app import tools

    seen = {}

    def fake_run(request):
        seen["force"] = request.force
        raise _Stop

    monkeypatch.setattr(tools, "run_analysis_request", fake_run)
    with pytest.raises(_Stop):
        tools.analyze_library(None, [str(tmp_path)], "p", "13")
    assert seen["force"] is False


# --- app.experiment_orchestration -------------------------------------------


@pytest.mark.parametrize("force", [False, True])
def test_experiment_consensus_phase_forwards_force(tmp_path, monkeypatch, force):
    from memdiver.app import experiment_orchestration as eo
    from memdiver.engine import consensus_service

    tool_dir = tmp_path / "toolA"
    _write_dumps(tool_dir, n=2, size=8192)
    seen = {}

    def spy(dumps, **kwargs):
        seen["force"] = kwargs.get("force")
        raise _Stop

    monkeypatch.setattr(consensus_service, "build_consensus", spy)
    with pytest.raises(_Stop):
        eo._experiment_consensus_phase(
            {"toolA": tool_dir}, None, None, None, force=force)
    assert seen["force"] is force


@pytest.mark.parametrize("force", [False, True])
def test_experiment_result_forwards_force(tmp_path, monkeypatch, force):
    from memdiver.app import experiment_orchestration as eo
    from memdiver.core import dump_driver

    target = tmp_path / "target.bin"
    target.write_bytes(b"x")

    class FakeOrch:
        available_tools = ["fake"]

        def __init__(self, tools=None):
            pass

    monkeypatch.setattr(dump_driver, "DumpOrchestrator", FakeOrch)
    monkeypatch.setattr(eo, "_experiment_capture",
                        lambda *a, **k: SimpleNamespace(tool_dirs={}, metadata={}))
    seen = {}

    def spy(*args, **kwargs):
        seen["force"] = kwargs.get("force")
        raise _Stop

    monkeypatch.setattr(eo, "_experiment_consensus_phase", spy)
    with pytest.raises(_Stop):
        eo.experiment_result(target=str(target), output_dir=str(tmp_path / "o"),
                             force=force)
    assert seen["force"] is force


@pytest.mark.parametrize("force", [False, True])
def test_experiment_result_forwards_force_to_verify_phase(
        tmp_path, monkeypatch, force):
    """The convergence sweep in the verify phase gets the same ``force``."""
    from memdiver.app import experiment_orchestration as eo
    from memdiver.core import dump_driver

    target = tmp_path / "target.bin"
    target.write_bytes(b"x")

    class FakeOrch:
        available_tools = ["fake"]

        def __init__(self, tools=None):
            pass

    monkeypatch.setattr(dump_driver, "DumpOrchestrator", FakeOrch)
    monkeypatch.setattr(eo, "_experiment_capture",
                        lambda *a, **k: SimpleNamespace(tool_dirs={}, metadata={}))
    monkeypatch.setattr(eo, "_experiment_consensus_phase", lambda *a, **k: {})
    seen = {}

    def spy(*args, **kwargs):
        seen["force"] = kwargs.get("force")
        raise _Stop

    monkeypatch.setattr(eo, "_experiment_verify_phase", spy)
    with pytest.raises(_Stop):
        eo.experiment_result(target=str(target), output_dir=str(tmp_path / "o"),
                             convergence=True, force=force)
    assert seen["force"] is force


# --- app.export_service / tools_pipeline.export_pattern (real guard) ---------


def test_auto_export_pattern_refuses_over_budget_then_force_proceeds(
        tmp_path, monkeypatch):
    from memdiver.app.export_service import auto_export_pattern

    monkeypatch.setenv("MEMDIVER_MEMORY_BUDGET_MB", "1")
    dumps = _write_dumps(tmp_path)
    with pytest.raises(CapabilityError) as info:
        auto_export_pattern(dumps, fmt="json")
    assert info.value.code == BUDGET_CODE
    try:
        auto_export_pattern(dumps, fmt="json", force=True)
    except CapabilityError as exc:  # e.g. no volatile region: not the guard
        assert exc.code != BUDGET_CODE


@pytest.mark.parametrize("force", [False, True])
def test_export_pattern_forwards_force(tmp_path, monkeypatch, force):
    from memdiver.app import export_service, tools_pipeline

    dumps = _write_dumps(tmp_path, n=2, size=8192)
    seen = {}

    def spy(paths, **kwargs):
        seen["force"] = kwargs.get("force")
        raise _Stop

    monkeypatch.setattr(export_service, "auto_export_pattern", spy)
    with pytest.raises(_Stop):
        tools_pipeline.export_pattern(dump_paths=[str(p) for p in dumps],
                                      force=force)
    assert seen["force"] is force


# --- background task runners -------------------------------------------------


@pytest.mark.parametrize("params_force,expected", [({}, False),
                                                   ({"force_memory": True}, True)])
def test_run_analysis_reads_force_memory(tmp_path, monkeypatch,
                                         params_force, expected):
    from memdiver.app import tools
    from memdiver.app.pipeline.analysis_task_runner import run_analysis

    seen = {}

    def spy(*args, **kwargs):
        seen["force"] = kwargs.get("force")
        raise _budget_error()

    monkeypatch.setattr(tools, "analyze_library", spy)
    params = {"library_dirs": [str(tmp_path)], "phase": "p",
              "protocol_version": "13", "artifact_dir": str(tmp_path / "a"),
              **params_force}
    with pytest.raises(CapabilityError) as info:
        run_analysis(params, _FakeCtx())
    assert info.value.code == BUDGET_CODE
    assert info.value.details["budget_bytes"] == 1
    assert seen["force"] is expected


def test_run_analysis_other_capability_errors_stay_value_error(tmp_path,
                                                               monkeypatch):
    from memdiver.app import tools
    from memdiver.app.pipeline.analysis_task_runner import run_analysis

    def boom(*args, **kwargs):
        raise CapabilityError("Directory not found: x")

    monkeypatch.setattr(tools, "analyze_library", boom)
    params = {"library_dirs": [str(tmp_path)], "phase": "p",
              "protocol_version": "13", "artifact_dir": str(tmp_path / "a")}
    with pytest.raises(ValueError, match="Directory not found"):
        run_analysis(params, _FakeCtx())


@pytest.mark.parametrize("params_force,expected", [({}, False),
                                                   ({"force_memory": True}, True)])
def test_run_pipeline_consensus_stage_reads_force_memory(
        tmp_path, monkeypatch, params_force, expected):
    from memdiver.app import tools_pipeline
    from memdiver.app.pipeline.pipeline_runner import run_pipeline

    seen = {}

    def spy(**kwargs):
        seen["force"] = kwargs.get("force")
        raise _budget_error()

    monkeypatch.setattr(tools_pipeline, "consensus", spy)
    params = {"artifact_dir": str(tmp_path / "a"), "source_paths": ["x", "y"],
              **params_force}
    with pytest.raises(CapabilityError) as info:
        run_pipeline(params, _FakeCtx())
    assert info.value.code == BUDGET_CODE
    assert info.value.details["estimate_bytes"] == 9
    assert seen["force"] is expected


@pytest.mark.parametrize("params_force,expected", [({}, False),
                                                   ({"force_memory": True}, True)])
def test_run_experiment_reads_force_memory(tmp_path, monkeypatch,
                                           params_force, expected):
    from memdiver.app import experiment_orchestration as eo
    from memdiver.app.pipeline.experiment_task_runner import run_experiment

    seen = {}

    def spy(**kwargs):
        seen["force"] = kwargs.get("force")
        raise _budget_error()

    monkeypatch.setattr(eo, "experiment_result", spy)
    params = {"target": "t", "artifact_dir": str(tmp_path / "a"), **params_force}
    with pytest.raises(CapabilityError) as info:
        run_experiment(params, _FakeCtx())
    assert info.value.code == BUDGET_CODE
    assert seen["force"] is expected


def test_batch_job_dict_force_memory(tmp_path):
    from memdiver.app.pipeline.batch_task_runner import _job_dict_to_request

    job = {"library_dirs": [str(tmp_path)], "phase": "p", "protocol_version": "13"}
    assert _job_dict_to_request(job).force is False
    assert _job_dict_to_request(job, force_memory=True).force is True
    assert _job_dict_to_request({**job, "force_memory": True}).force is True
    assert _job_dict_to_request({**job, "force_memory": False},
                                force_memory=True).force is False
