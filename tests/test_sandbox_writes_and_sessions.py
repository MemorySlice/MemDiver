"""Sandbox-ON: MCP writes confined to the write roots; session paths read-checked."""

from __future__ import annotations

import json

import pytest
from fastapi.testclient import TestClient

from memdiver.api.config import get_settings
from memdiver.core import path_sandbox


@pytest.fixture()
def env(tmp_path, monkeypatch):
    """Read root ``ok``, upload dir + home outside it; sandbox ON by default."""
    ok, uploads, home = tmp_path / "ok", tmp_path / "uploads", tmp_path / "home"
    sessions = tmp_path / "home" / "sessions"
    for d in (ok, uploads, home, sessions):
        d.mkdir(parents=True, exist_ok=True)
    monkeypatch.setenv("MEMDIVER_ALLOWED_ROOTS", str(ok))
    monkeypatch.setenv("MEMDIVER_UPLOAD_DIR", str(uploads))
    monkeypatch.setenv("MEMDIVER_SESSION_DIR", str(sessions))
    monkeypatch.setattr(path_sandbox, "STARTUP_CWD", str(ok))
    monkeypatch.setattr("memdiver.core.constants.memdiver_home", lambda: home)
    monkeypatch.setattr("memdiver.analysis.case.memdiver_home", lambda: home)
    get_settings.cache_clear()
    yield {"ok": ok, "uploads": uploads, "home": home}
    get_settings.cache_clear()


def _tool(out_path: str = "", out_dir: str = ""):
    return "ran"


def _call(**kw):
    from memdiver.mcp_server.path_guard import guard_tool
    return guard_tool(_tool)(**kw)


def test_write_roots_are_home_plus_upload(env):
    from memdiver.api.read_roots import write_roots
    assert set(write_roots()) == {env["home"].resolve(), env["uploads"].resolve()}


def test_mcp_write_inside_write_roots_ok(env):
    assert _call(out_path=str(env["uploads"] / "r.json")) == "ran"
    assert _call(out_dir=str(env["home"] / "out")) == "ran"


def test_mcp_write_in_read_root_but_outside_write_roots_refused(env):
    out = json.loads(_call(out_path=str(env["ok"] / "r.json")))
    assert out["error"] or out.get("code")
    blob = json.dumps(out)
    assert "path.outside_sandbox" in blob
    assert str(env["ok"] / "r.json") in blob
    assert "Allowed write locations" in blob and str(env["uploads"].resolve()) in blob
    assert "Example of an accepted path" in blob


def _case_tool(case_dir: str = ""):
    return "ran"


def _call_case(case_dir: str):
    from memdiver.mcp_server.path_guard import guard_tool
    return guard_tool(_case_tool)(case_dir=case_dir)


def test_mcp_case_dir_confined_to_write_roots(env):
    """REST confines a path-shaped case dir (contained_case_dir); so does MCP."""
    blob = _call_case(str(env["ok"] / "case1"))
    assert "path.outside_sandbox" in blob and "Allowed write locations" in blob
    assert _call_case(str(env["home"] / "cases" / "c1")) == "ran"
    assert _call_case("bare_case_name") == "ran"


def test_mcp_write_sandbox_off_unchanged(env, monkeypatch):
    monkeypatch.delenv("MEMDIVER_ALLOWED_ROOTS")
    get_settings.cache_clear()
    assert _call(out_path="/definitely/elsewhere/x.json") == "ran"


def test_annotations_write_roots_delegates(env):
    from memdiver.api.routers.annotations import _write_roots
    assert set(_write_roots()) == {env["home"].resolve(), env["uploads"].resolve()}


# -- sessions ---------------------------------------------------------------------

def _payload(**over):
    base = {"session_name": "s1", "input_path": "", "dataset_root": ""}
    base.update(over)
    return base


@pytest.fixture()
def client(env):
    from memdiver.api.main import create_app
    with TestClient(create_app()) as c:
        yield c


BAD = "/definitely/not/admitted"


@pytest.mark.parametrize("over", [
    {"input_path": BAD}, {"dataset_root": BAD},
    {"dumps": [{"path": BAD}]}, {"active_dump_path": BAD},
    {"selected_dump_paths": [BAD]}, {"collapsed_dump_paths": [BAD]},
    {"origin_dump_path": BAD}, {"excluded_dump_paths": [BAD]},
    {"solo_dump_path": BAD}, {"dump_weights": {BAD: 1.0}},
])
def test_session_save_refused_for_each_path_field(client, over):
    r = client.post("/api/sessions/", json=_payload(**over))
    assert r.status_code == 403
    assert BAD in r.json()["detail"] and "MEMDIVER_ALLOWED_ROOTS" in r.json()["detail"]


def test_session_save_and_load_admitted(client, env):
    good = str(env["ok"] / "a.dump")
    r = client.post("/api/sessions/", json=_payload(
        input_path=good, dumps=[{"path": good}], dump_weights={good: 1.0}))
    assert r.status_code == 200
    assert client.get("/api/sessions/s1").status_code == 200


def test_session_load_refused_when_stored_path_outside(client, env, monkeypatch):
    monkeypatch.delenv("MEMDIVER_ALLOWED_ROOTS")
    get_settings.cache_clear()
    assert client.post("/api/sessions/", json=_payload(input_path=BAD)).status_code == 200
    monkeypatch.setenv("MEMDIVER_ALLOWED_ROOTS", str(env["ok"]))
    get_settings.cache_clear()
    r = client.get("/api/sessions/s1")
    assert r.status_code == 403 and BAD in r.json()["detail"]


def test_session_sandbox_off_unchanged(client, monkeypatch):
    monkeypatch.delenv("MEMDIVER_ALLOWED_ROOTS")
    get_settings.cache_clear()
    assert client.post("/api/sessions/", json=_payload(input_path=BAD)).status_code == 200
    assert client.get("/api/sessions/s1").status_code == 200


def case_query(case_dir: str = ""):
    return "ran"


def test_mcp_read_only_case_tool_needs_read_roots_only(env):
    """A read-only case tool (REST parity: read routes) is not write-confined."""
    from memdiver.mcp_server.path_guard import guard_tool
    assert guard_tool(case_query)(case_dir=str(env["ok"] / "case1")) == "ran"


# -- review fixes: case_init, output, bare-name resolution -------------------------

def _init_tool(case: str = ""):
    return "ran"


def test_mcp_case_init_confined(env):
    from memdiver.mcp_server.path_guard import guard_tool
    tool = guard_tool(_init_tool)
    assert "path.outside_sandbox" in tool(case=str(env["ok"] / "c"))
    assert tool(case=str(env["home"] / "cases" / "c")) == "ran"
    assert tool(case="bare") == "ran"


def test_mcp_case_init_sandbox_off_unchanged(env, monkeypatch):
    monkeypatch.delenv("MEMDIVER_ALLOWED_ROOTS")
    get_settings.cache_clear()
    from memdiver.mcp_server.path_guard import guard_tool
    assert guard_tool(_init_tool)(case="/anywhere/c") == "ran"


def test_mcp_capture_output_confined(env, monkeypatch):
    def capture_dump(target: str = "", output: str = ""):
        return "ran"
    from memdiver.mcp_server.path_guard import guard_tool
    tool = guard_tool(capture_dump)
    assert "path.outside_sandbox" in tool(target="1", output="/elsewhere/x.msl")
    assert tool(target="1", output=str(env["uploads"] / "x.msl")) == "ran"
    monkeypatch.delenv("MEMDIVER_ALLOWED_ROOTS")
    get_settings.cache_clear()
    assert tool(target="1", output="/elsewhere/x.msl") == "ran"


def test_rest_capture_output_confined(client, env):
    r = client.post("/api/experiment/capture", json={"target": "1", "output": "/elsewhere/x.msl"})
    assert r.status_code == 403 and "/elsewhere/x.msl" in r.json()["detail"]


def _make_case(parent, name):
    from memdiver.analysis.case import Case
    return Case.init(parent / name).dir


def test_bare_case_name_resolving_to_cwd_is_confined(env, monkeypatch):
    """A bare name that Case.open finds under the CWD is judged by its resolved dir."""
    from memdiver.analysis.case import resolve_case_dir
    _make_case(env["ok"], "foo")
    monkeypatch.chdir(env["ok"])
    assert resolve_case_dir("foo").resolve() == (env["ok"] / "foo").resolve()
    blob = _call_case("foo")                       # writing tool: cwd is no write root
    assert "path.outside_sandbox" in blob
    from memdiver.mcp_server.path_guard import guard_tool

    def case_status(case_dir: str = ""):
        return "ran"
    assert guard_tool(case_status)(case_dir="foo") == "ran"     # read root: ok


def test_bare_case_read_only_outside_read_roots_refused(env, tmp_path, monkeypatch):
    from memdiver.mcp_server.path_guard import guard_tool
    outside = tmp_path / "elsewhere"
    outside.mkdir()
    _make_case(outside, "foo")
    monkeypatch.chdir(outside)

    def case_status(case_dir: str = ""):
        return "ran"
    assert "path.outside_sandbox" in guard_tool(case_status)(case_dir="foo")


def test_bare_case_name_sandbox_off_unchanged(env, monkeypatch):
    monkeypatch.delenv("MEMDIVER_ALLOWED_ROOTS")
    get_settings.cache_clear()
    assert _call_case("foo") == "ran"
