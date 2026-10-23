"""MCP ``allocator`` / ``heap_policy`` params reach their producer kwargs.

Signature parity is already guarded by
``test_architecture_invariants::test_mcp_pipeline_tools_expose_all_producer_params``;
this pins that each tool actually FORWARDS the value it accepts.
"""

import json
from types import SimpleNamespace

import pytest

pytest.importorskip("mcp")

from memdiver.app import tools_consensus, tools_pipeline  # noqa: E402
from memdiver.mcp_server.server import create_server  # noqa: E402


@pytest.fixture(scope="module")
def tools():
    return {t.name: t for t in create_server()._tool_manager.list_tools()}


def _recorder(monkeypatch, module, name, result):
    captured = {}

    def fake(*_args, **kwargs):
        captured.update(kwargs)
        return result

    monkeypatch.setattr(module, name, fake)
    return captured


@pytest.mark.parametrize("tool, producer, args, extra", [
    ("consensus", "consensus", {"dump_paths": ["a", "b"], "output_dir": "o"},
     {"allocator": "scudo"}),
    ("analyze_candidates", "analyze_candidates", {"dump_paths": ["a", "b"]},
     {"allocator": "jemalloc", "heap_policy": "mask"}),
    ("search_reduce", "search_reduce",
     {"variance_path": "v", "reference_path": "r", "num_dumps": 2,
      "output_dir": "o"},
     {"heap_policy": "off"}),
    ("locate_key", "locate_key", {"dump_paths": ["a"], "key_hex": "aa"},
     {"allocator": "off"}),
])
def test_pipeline_tools_forward_heap_params(tools, monkeypatch, tool, producer,
                                            args, extra):
    captured = _recorder(monkeypatch, tools_pipeline, producer, {})
    json.loads(tools[tool].fn(**args, **extra))
    for name, value in extra.items():
        assert captured[name] == value


@pytest.mark.parametrize("tool, producer", [
    ("aligned_window", "aligned_window_result"),
    ("consensus_regions", "class_regions_result"),
])
def test_consensus_view_tools_forward_allocator(tools, monkeypatch, tool, producer):
    captured = _recorder(monkeypatch, tools_consensus, producer,
                         SimpleNamespace(payload={}))
    tools[tool].fn(dump_paths=["a", "b"], allocator="ptmalloc2")
    assert captured["allocator"] == "ptmalloc2"


def test_defaults_match_the_producers(tools, monkeypatch):
    captured = _recorder(monkeypatch, tools_pipeline, "analyze_candidates", {})
    tools["analyze_candidates"].fn(dump_paths=["a", "b"])
    assert captured["heap_policy"] == "annotate"
    assert captured["allocator"] == "auto"
