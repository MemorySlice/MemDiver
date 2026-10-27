"""SdkAgentBackend + ScriptedCliTransport: the REAL ClaudeSDKClient with NO model/CLI.

The scripted transport plays the CLI side of the SDK control protocol and executes
tools on a REAL ``memdiver mcp`` stdio child (sandboxed to a synthetic case in tmp_path).
"""

from __future__ import annotations

import asyncio
import json
import os
import sys
from pathlib import Path

import pytest

pytest.importorskip("claude_agent_sdk")
pytest.importorskip("mcp")

from memdiver.analysis.case import Case  # noqa: E402
from memdiver.app.agent_chat import contracts as c  # noqa: E402
from memdiver.app.agent_chat.scripted_transport import (  # noqa: E402
    EXHAUSTED_TEXT, ScriptedCliTransport, load_script)
from memdiver.app.agent_chat.sdk_backend import (  # noqa: E402
    SdkAgentBackend, build_options, make_backend)
from memdiver.app.tools_annotations import annotations_list_result  # noqa: E402

CAP = "cap1"
READ_TOOLS = [c.TOOL_PREFIX + "case_manifest", c.TOOL_PREFIX + "annotations_list"]
ACCESS = {"case_manifest": "read", "annotations_add": "write"}


class StubGate:
    """Minimal contracts.PermissionGate: records decisions, answers a fixed verdict."""

    def __init__(self, allow: bool = True, message: str = "analyst said no") -> None:
        self.allow, self.message, self.decided = allow, message, []

    async def decide(self, tool_name, tool_input):
        self.decided.append((tool_name, dict(tool_input)))
        return c.Decision(self.allow, "" if self.allow else self.message)

    def resolve(self, request_id, allow, message="", scope="once"):
        return True

    async def close(self):
        return None


@pytest.fixture
def case(tmp_path, monkeypatch):
    uploads = tmp_path / "uploads"
    case_dir = Case.init(uploads / "case").dir
    env = {**os.environ, "MEMDIVER_ALLOWED_ROOTS": str(tmp_path),
           "MEMDIVER_UPLOAD_DIR": str(uploads), "MEMDIVER_MCP_RESULT_BUDGET": "20000",
           "XDG_DATA_HOME": str(tmp_path / "xdg")}
    return str(case_dir), env


def _spec(tmp_path, env, max_turns=8) -> c.ChatSpec:
    settings = c.AgentSettings(max_turns=max_turns)
    mcp = c.McpChild(sys.executable, ["-m", "memdiver.cli", "mcp"], env)
    return c.ChatSpec(system_prompt="SYSTEM", settings=settings, mcp=mcp,
                      allowed_tools=list(READ_TOOLS), cwd=str(tmp_path),
                      config_dir=str(tmp_path / "cfg"))


async def _run(tmp_path, env, turns, gate, max_turns=8, user_messages=("go",)):
    events = []

    async def emit(event):
        events.append(event)

    backend = SdkAgentBackend(
        transport_factory=lambda: ScriptedCliTransport({"turns": turns}), tool_access=ACCESS)
    await backend.start(_spec(tmp_path, env, max_turns), gate, emit)
    try:
        for text in user_messages:
            await asyncio.wait_for(backend.send(text), 120)
    finally:
        await backend.close()
    return events


def _types(events):
    return [e.type for e in events]


def _of(events, type_):
    return [e.data for e in events if e.type == type_]


# -- options --------------------------------------------------------------------------


def test_options_are_locked_down(tmp_path):
    spec = _spec(tmp_path, {"MEMDIVER_ALLOWED_ROOTS": "/x"})
    opts = build_options(spec, StubGate())
    assert opts.tools == [] and opts.setting_sources == []
    assert opts.strict_mcp_config is True and opts.permission_mode == "default"
    assert opts.system_prompt == "SYSTEM" and opts.include_partial_messages is True
    assert opts.allowed_tools == READ_TOOLS
    assert "Bash" in opts.disallowed_tools
    assert opts.env["CLAUDE_CONFIG_DIR"] == str(tmp_path / "cfg")
    assert opts.env["CLAUDE_CODE_DISABLE_AUTO_MEMORY"] == "1"
    assert not [k for k in opts.env if k.startswith("ANTHROPIC")]
    assert opts.max_turns == 8 and opts.max_budget_usd == 0.5 and opts.effort == "low"
    server = opts.mcp_servers[c.MCP_SERVER_NAME]
    assert server["type"] == "stdio" and server["env"]["MEMDIVER_ALLOWED_ROOTS"] == "/x"
    assert opts.cwd == str(tmp_path) and opts.resume is None


def test_can_use_tool_maps_gate_decisions(tmp_path):
    async def go():
        allow = build_options(_spec(tmp_path, {}), StubGate(True))
        deny = build_options(_spec(tmp_path, {}), StubGate(False, "nope"))
        a = await allow.can_use_tool("mcp__memdiver__x", {}, None)
        d = await deny.can_use_tool("mcp__memdiver__x", {}, None)
        return a, d

    a, d = asyncio.run(go())
    assert type(a).__name__ == "PermissionResultAllow"
    assert type(d).__name__ == "PermissionResultDeny" and d.message == "nope"


def test_make_backend_selection(monkeypatch, tmp_path):
    assert isinstance(make_backend("sdk"), SdkAgentBackend)
    monkeypatch.delenv("MEMDIVER_AGENT_SCRIPT", raising=False)
    with pytest.raises(Exception, match="MEMDIVER_AGENT_SCRIPT"):
        make_backend("scripted")
    script = tmp_path / "s.json"
    script.write_text(json.dumps({"turns": [[{"text": "hi"}]]}))
    monkeypatch.setenv("MEMDIVER_AGENT_SCRIPT", str(script))
    assert isinstance(make_backend("scripted"), SdkAgentBackend)
    assert load_script(str(script))["turns"][0][0]["text"] == "hi"
    with pytest.raises(Exception, match="unknown agent backend"):
        make_backend("nope")


# -- real end-to-end runs ---------------------------------------------------------------


def _annotation_entries(case_dir):
    return annotations_list_result(case_dir, CAP).payload["entries"]


def test_read_then_approved_write_round_trip(tmp_path, case):
    case_dir, env = case
    turns = [[
        {"text": "Looking at the case."},
        {"tool": "case_manifest", "input": {"case_dir": case_dir}},
        {"tool": "annotations_add", "input": {
            "case_dir": case_dir, "capture_id": CAP, "kind": "annotation",
            "label": "seen", "locations": [{"space": "physical", "value": 4096}]}},
        {"text": "[seen] recorded."},
    ]]
    gate = StubGate(allow=True)
    events = asyncio.run(_run(tmp_path, env, turns, gate))

    calls = _of(events, "tool_call")
    assert [(k["name"], k["access"]) for k in calls] == [
        ("case_manifest", "read"), ("annotations_add", "write")]
    results = _of(events, "tool_result")
    assert [r["ok"] for r in results] == [True, True]
    assert results[0]["summary"].startswith("{")  # real JSON from the MCP server
    assert results[0]["bytes"] > 0 and results[0]["truncated"] is False
    # only the WRITE tool reached the gate (READ is pre-approved via allowed_tools)
    assert [name for name, _ in gate.decided] == [c.TOOL_PREFIX + "annotations_add"]
    entries = _entries_labelled(case_dir, "seen")
    assert len(entries) == 1
    assert "".join(d["text"] for d in _of(events, "text_delta")).startswith("Looking")
    assert [m["text"] for m in _of(events, "assistant_message")] == [
        "Looking at the case.", "[seen] recorded."]
    result = _of(events, "result")[0]
    assert result["stop_reason"] == "success" and result["is_error"] is False
    assert result["num_turns"] == 4 and result["session_id"].startswith("scripted-")
    assert _of(events, "usage")[0]["max_turns"] == 8
    assert _types(events)[0] == "status" and _types(events)[-1] == "status"


def _entries_labelled(case_dir, label):
    return [e for e in _annotation_entries(case_dir) if e.get("label") == label]


def test_denied_write_does_not_run(tmp_path, case):
    case_dir, env = case
    turns = [[
        {"tool": "annotations_add", "input": {
            "case_dir": case_dir, "capture_id": CAP, "kind": "annotation", "label": "nope"}},
        {"text": "understood"},
    ]]
    gate = StubGate(allow=False, message="analyst said no")
    events = asyncio.run(_run(tmp_path, env, turns, gate))
    result = _of(events, "tool_result")[0]
    assert result["ok"] is False and "analyst said no" in result["summary"]
    assert len(gate.decided) == 1
    assert _entries_labelled(case_dir, "nope") == []
    assert _of(events, "result")[0]["is_error"] is False


def test_sandbox_error_payload_is_not_ok(tmp_path, case):
    _case_dir, env = case
    turns = [[{"tool": "case_manifest", "input": {"case_dir": "/etc"}}]]
    events = asyncio.run(_run(tmp_path, env, turns, StubGate()))
    result = _of(events, "tool_result")[0]
    assert result["ok"] is False and "sandbox" in result["summary"]


def test_max_turns_stops_the_run(tmp_path, case):
    case_dir, env = case
    step = {"tool": "case_manifest", "input": {"case_dir": case_dir}}
    events = asyncio.run(_run(tmp_path, env, [[step, step, step]], StubGate(), max_turns=2))
    assert len(_of(events, "tool_result")) == 2
    result = _of(events, "result")[0]
    assert result["stop_reason"] == "error_max_turns" and result["is_error"] is True


def test_script_exhausted_second_message(tmp_path, case):
    _case_dir, env = case
    events = asyncio.run(_run(tmp_path, env, [[{"text": "one"}]], StubGate(),
                              user_messages=("a", "b")))
    assert [m["text"] for m in _of(events, "assistant_message")] == ["one", EXHAUSTED_TEXT]
    assert len(_of(events, "result")) == 2


def test_missing_sdk_is_a_capability_error(monkeypatch, tmp_path):
    import builtins

    real_import = builtins.__import__

    def fake_import(name, *a, **k):
        if name == "claude_agent_sdk":
            raise ImportError(name)
        return real_import(name, *a, **k)

    monkeypatch.setattr(builtins, "__import__", fake_import)
    from memdiver.core.service_errors import CapabilityError

    async def go():
        async def emit(_e):
            return None

        await SdkAgentBackend().start(_spec(tmp_path, {}), StubGate(), emit)

    with pytest.raises(CapabilityError, match="agent"):
        asyncio.run(go())
