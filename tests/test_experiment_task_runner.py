"""Tests for app.pipeline.experiment_task_runner.run_experiment.

Drives the thin streaming adapter directly (no ProcessPool) inside a fake
``WorkerContext``, patching the shared ``app.experiment_orchestration.experiment_result``
producer at the boundary the runner calls. Exercises the three
``CapabilityError`` branches (missing_backend -> graceful summary, cancelled ->
RuntimeError, other -> propagate) plus the happy path.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List
from unittest.mock import patch

import pytest

from memdiver.app.pipeline.experiment_task_runner import run_experiment
from memdiver.core.service_errors import CapabilityError


# ------------------------------------------------------------------
# fake WorkerContext (mirrors tests/test_pipeline_runner.py::_FakeCtx)
# ------------------------------------------------------------------


@dataclass
class _FakeCtx:
    task_id: str = "test-experiment"
    cancel: bool = False
    events: List[Dict[str, Any]] = field(default_factory=list)

    def emit(self, event_type: str, **fields: Any) -> None:
        self.events.append({"type": event_type, **fields})

    def is_cancelled(self) -> bool:
        return self.cancel


def _params(tmp_path: Path, **overrides: Any) -> Dict[str, Any]:
    params = {
        "artifact_dir": str(tmp_path / "task"),
        "target": str(tmp_path / "target.bin"),
        "num_runs": 3,
    }
    params.update(overrides)
    return params


# ------------------------------------------------------------------
# CapabilityError(code="missing_backend") -> graceful summary
# ------------------------------------------------------------------


def test_run_experiment_missing_backend_returns_graceful_summary(tmp_path):
    ctx = _FakeCtx()

    def _raise(**kwargs):
        raise CapabilityError("frida not installed", code="missing_backend")

    with patch("memdiver.app.experiment_orchestration.experiment_result", _raise):
        ret = run_experiment(_params(tmp_path), ctx)

    assert ret["artifacts"] == []
    assert ret["summary"]["status"] == "missing_backend"
    assert ret["summary"]["message"] == "frida not installed"
    assert ret["summary"]["tool_results"] == {}
    # The graceful notice is emitted on the capture stage.
    assert any(
        e["type"] == "progress" and e.get("extra", {}).get("missing_backend")
        for e in ctx.events
    )


# ------------------------------------------------------------------
# CapabilityError(code="cancelled") -> RuntimeError
# ------------------------------------------------------------------


def test_run_experiment_cancelled_raises_runtime_error(tmp_path):
    ctx = _FakeCtx()

    def _raise(**kwargs):
        raise CapabilityError("aborted", code="cancelled")

    with patch("memdiver.app.experiment_orchestration.experiment_result", _raise):
        with pytest.raises(RuntimeError, match="cancelled"):
            run_experiment(_params(tmp_path), ctx)


# ------------------------------------------------------------------
# any other CapabilityError -> propagates unchanged
# ------------------------------------------------------------------


def test_run_experiment_other_capability_error_propagates(tmp_path):
    ctx = _FakeCtx()

    def _raise(**kwargs):
        raise CapabilityError("bad input", code="something_else")

    with patch("memdiver.app.experiment_orchestration.experiment_result", _raise):
        with pytest.raises(CapabilityError):
            run_experiment(_params(tmp_path), ctx)


# ------------------------------------------------------------------
# happy path -> ok summary from the producer's canned result
# ------------------------------------------------------------------


def test_run_experiment_happy_path(tmp_path):
    ctx = _FakeCtx()
    canned = {
        "target": str(tmp_path / "target.bin"),
        "num_runs": 3,
        "tools_used": ["memslicer"],
        "tool_results": {},
    }

    def _ok(**kwargs):
        return canned

    with patch("memdiver.app.experiment_orchestration.experiment_result", _ok):
        ret = run_experiment(
            _params(
                tmp_path,
                protocol_version="13",
                phase="pre_abort",
                oracle_id="o1",
            ),
            ctx,
        )

    # No plugins in the canned result -> no artifacts registered.
    assert ret["artifacts"] == []
    summary = ret["summary"]
    assert summary["status"] == "ok"
    assert summary["target"] == canned["target"]
    assert summary["num_runs"] == 3
    assert summary["tools_used"] == ["memslicer"]
    assert summary["tool_results"] == {}
    assert summary["protocol_version"] == "13"
    assert summary["phase"] == "pre_abort"
    assert summary["oracle_id"] == "o1"


def test_run_experiment_registers_saved_plugin_artifact(tmp_path):
    """A tool_result carrying a saved plugin is copied in + registered."""
    ctx = _FakeCtx()
    # A plugin the producer "saved" outside the artifact dir, so the runner
    # copies it into ``<artifact_dir>/plugins`` and registers it.
    plugin_src = tmp_path / "generated" / "memslicer_aes256_key.py"
    plugin_src.parent.mkdir(parents=True)
    plugin_src.write_text("# vol3 plugin\n")

    canned = {
        "target": str(tmp_path / "target.bin"),
        "num_runs": 3,
        "tools_used": ["memslicer"],
        "tool_results": {
            "memslicer": {
                "tool": "memslicer",
                "plugin_saved": str(plugin_src),
            }
        },
    }

    def _ok(**kwargs):
        return canned

    with patch("memdiver.app.experiment_orchestration.experiment_result", _ok):
        ret = run_experiment(_params(tmp_path), ctx)

    spec = next(a for a in ret["artifacts"] if a["name"] == "plugin_memslicer")
    assert spec["media_type"] == "text/x-python"
    copied = (tmp_path / "task") / spec["relpath"]
    assert copied.is_file()
    assert copied.read_text() == "# vol3 plugin\n"
