"""``code_evidence.field_accesses`` reaches the library, CLI, REST and MCP surfaces.

The producer is covered by tests/test_code_evidence.py; here the kernel-image session is
replaced by a fake so no image corpus is needed, and the real surface adapters run.
"""
from __future__ import annotations

import json

import pytest

from memdiver.app import tools_code_evidence as tce

PAYLOAD = {"accesses": [{"base": "current", "offset": 0x4D0}], "isf_join": {"checked": 1, "matched": 1}}


class _FakeSession:
    def close(self):
        pass


@pytest.fixture
def fake(monkeypatch):
    calls = []

    def produce(session, function, max_bytes, base, types):
        calls.append({"function": function, "max_bytes": max_bytes, "base": base,
                      "isf": types is not None})
        return dict(PAYLOAD)

    monkeypatch.setattr(tce, "require_pakunoda", lambda: None)
    monkeypatch.setattr(tce, "_image_file", lambda p: p)
    monkeypatch.setattr(tce, "_Session", lambda *a, **k: _FakeSession())
    monkeypatch.setattr(tce, "_produce", produce)
    return calls


@pytest.fixture
def isf_file(tmp_path):
    path = tmp_path / "k.isf.json"
    path.write_text(json.dumps({"user_types": {}}))
    return str(path)


def test_capability_is_registered_on_all_surfaces():
    from memdiver.app.capabilities import CAPABILITIES
    cap = next(c for c in CAPABILITIES if c.name == "code_evidence.field_accesses")
    assert set(cap.surfaces) == {"library", "cli", "web", "mcp"}


def test_library_export(fake):
    from memdiver import services
    assert "code_evidence_result" in services.__all__
    res = services.code_evidence_result(image_path="img", function="f", max_bytes=64)
    assert res.payload == PAYLOAD and fake[-1]["max_bytes"] == 64


def test_cli_subcommand(fake, isf_file, capsys):
    from memdiver.cli import _build_parser, _cmd_isf
    args = _build_parser().parse_args(
        ["isf", "code-evidence", "img", "f", "--max-bytes", "128", "--isf", isf_file,
         "--base", "current"])
    assert _cmd_isf(args) == 0
    assert json.loads(capsys.readouterr().out) == PAYLOAD
    assert fake[-1] == {"function": "f", "max_bytes": 128, "base": "current", "isf": True}


def test_rest_route_inline_and_async(fake, isf_file, monkeypatch, tmp_path):
    from fastapi.testclient import TestClient

    from memdiver.api.config import get_settings
    from memdiver.api.main import create_app
    monkeypatch.delenv("MEMDIVER_ALLOWED_ROOTS", raising=False)
    monkeypatch.setenv("MEMDIVER_UPLOAD_DIR", str(tmp_path / "uploads"))
    get_settings.cache_clear()
    client = TestClient(create_app())
    r = client.post("/api/isf/code-evidence",
                    json={"image_path": "img", "function": "f", "isf": isf_file})
    assert r.status_code == 200 and r.json() == PAYLOAD and fake[-1]["isf"] is True
    assert client.post("/api/isf/code-evidence",
                       json={"image_path": "img", "function": "f", "bogus": 1}
                       ).status_code == 422
    get_settings.cache_clear()


def test_image_job_runner_knows_the_job(fake, tmp_path):
    from types import SimpleNamespace

    from memdiver.app.pipeline.image_task_runner import JOBS, run_image_job
    assert "code_evidence" in JOBS
    ctx = SimpleNamespace(emit=lambda *a, **k: None, is_cancelled=lambda: False)
    out = run_image_job({"job": "code_evidence", "artifact_dir": str(tmp_path / "a"),
                         "args": {"image_path": "img", "function": "f"}}, ctx)
    assert out["summary"] == PAYLOAD


def test_mcp_tool(fake, isf_file):
    pytest.importorskip("mcp")
    from memdiver.mcp_server.server import create_server
    tools = {t.name: t for t in create_server()._tool_manager.list_tools()}
    out = json.loads(tools["code_evidence"].fn(image_path="img", function="f", isf=isf_file))
    assert out == PAYLOAD and fake[-1]["isf"] is True
