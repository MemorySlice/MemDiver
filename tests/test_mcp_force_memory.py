"""MCP surface of the memory-budget override.

Every MCP tool whose backing producer takes ``force`` exposes it as
``force_memory: bool = False`` and forwards it as ``force=``; a refused build
reaches the agent as a structured ``memory_budget_exceeded`` payload carrying
the estimate and the budget.
"""

import inspect
import json
from types import SimpleNamespace

import pytest

from memdiver.core.service_errors import CapabilityError, ErrorCategory
from memdiver.mcp_server.presenters import mcp_error_funnel

#: MCP tool name -> (producer module path, producer attribute, minimal kwargs).
_FORCE_TOOLS = {
    "analyze_library": ("memdiver.app.tools", "analyze_library",
                        {"library_dirs": ["/x"], "phase": "p",
                         "protocol_version": "TLS13"}),
    "analyze_candidates": ("memdiver.app.tools_pipeline", "analyze_candidates",
                           {"dump_paths": ["/a", "/b"]}),
    "consensus": ("memdiver.app.tools_pipeline", "consensus",
                  {"dump_paths": ["/a", "/b"], "output_dir": "/o"}),
    "aligned_window": ("memdiver.app.tools_consensus", "aligned_window_result",
                       {"dump_paths": ["/a", "/b"]}),
    "consensus_regions": ("memdiver.app.tools_consensus", "class_regions_result",
                          {"dump_paths": ["/a", "/b"]}),
    "export_pattern": ("memdiver.app.tools_pipeline", "export_pattern",
                       {"dump_paths": ["/a", "/b"]}),
    "experiment": ("memdiver.app.experiment_orchestration", "experiment_result",
                   {"target": "/bin/true", "output_dir": "/o"}),
}


@pytest.fixture(scope="module")
def mcp_tools():
    pytest.importorskip("mcp")
    from memdiver.mcp_server.server import create_server

    server = create_server()
    return {t.name: t for t in server._tool_manager.list_tools()}


@pytest.mark.parametrize("tool_name", sorted(_FORCE_TOOLS))
def test_tool_exposes_force_memory_default_false(mcp_tools, tool_name):
    param = inspect.signature(mcp_tools[tool_name].fn).parameters["force_memory"]
    assert param.default is False


@pytest.mark.parametrize("force_memory", [False, True])
@pytest.mark.parametrize("tool_name", sorted(_FORCE_TOOLS))
def test_tool_forwards_force_memory_as_force(
    mcp_tools, monkeypatch, tool_name, force_memory,
):
    import importlib

    module_path, attr, kwargs = _FORCE_TOOLS[tool_name]
    seen = {}

    def fake_producer(*_a, **kw):
        seen.update(kw)
        return SimpleNamespace(payload={"ok": True}) if module_path.endswith(
            "tools_consensus") else {"ok": True}

    monkeypatch.setattr(importlib.import_module(module_path), attr, fake_producer)
    out = mcp_tools[tool_name].fn(**kwargs, force_memory=force_memory)
    assert json.loads(out) == {"ok": True}
    assert seen["force"] is force_memory


def _budget_error() -> CapabilityError:
    return CapabilityError(
        "consensus: estimated peak memory 9 GiB exceeds the memory budget 1 MiB.",
        category=ErrorCategory.PRECONDITION,
        code="memory_budget_exceeded",
        details={"estimate_bytes": 9 << 30, "budget_bytes": 1 << 20,
                 "operation": "consensus", "breakdown": {"vector": 9 << 30},
                 "source": "env"},
    )


def test_funnel_carries_budget_code_and_details():
    @mcp_error_funnel
    def tool() -> str:
        raise _budget_error()

    payload = json.loads(tool())
    assert payload["code"] == "memory_budget_exceeded"
    assert payload["category"] == "PRECONDITION"
    assert payload["estimate_bytes"] == 9 << 30
    assert payload["budget_bytes"] == 1 << 20
    assert payload["details"]["operation"] == "consensus"


def test_funnel_without_details_keeps_legacy_shape():
    @mcp_error_funnel
    def tool() -> str:
        raise CapabilityError("bad", category=ErrorCategory.INVALID_INPUT, code="x.y")

    assert set(json.loads(tool())) == {"error", "code", "category"}


def test_refused_tool_call_reaches_agent_structured(mcp_tools, monkeypatch):
    from memdiver.app import tools_pipeline

    def refusing(**kw):
        if not kw["force"]:
            raise _budget_error()
        return {"ok": True}

    monkeypatch.setattr(tools_pipeline, "consensus", refusing)
    fn = mcp_tools["consensus"].fn
    refused = json.loads(fn(dump_paths=["/a"], output_dir="/o"))
    assert refused["code"] == "memory_budget_exceeded"
    assert refused["budget_bytes"] == 1 << 20
    assert json.loads(fn(dump_paths=["/a"], output_dir="/o", force_memory=True)) == {"ok": True}
