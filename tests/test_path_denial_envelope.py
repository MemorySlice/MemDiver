"""Every REST path-rule denial answers with ONE coded body.

``{"detail", "error", "code": "path.outside_sandbox", "category": "PRECONDITION"}``:
``detail`` for the clients that always read it, the rest is the CapabilityError
envelope the web UI keys its localized hint off. The read denial (the
``enforce_request_read_paths`` dependency) and every converted write-denial site
must agree, whichever layer raised it.
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from memdiver.api.config import get_settings
from memdiver.core import path_sandbox
from memdiver.core.service_errors import CapabilityError, ErrorCategory

BAD = "/definitely/not/admitted"
CODE = "path.outside_sandbox"


@pytest.fixture()
def env(tmp_path, monkeypatch):
    """Sandbox ON: read root ``ok`` (also the cwd), write roots = home + uploads."""
    ok, uploads, home = tmp_path / "ok", tmp_path / "uploads", tmp_path / "home"
    for d in (ok, uploads, home):
        d.mkdir(parents=True, exist_ok=True)
    monkeypatch.setenv("MEMDIVER_ALLOWED_ROOTS", str(ok))
    monkeypatch.setenv("MEMDIVER_UPLOAD_DIR", str(uploads))
    monkeypatch.setattr(path_sandbox, "STARTUP_CWD", str(ok))
    monkeypatch.setattr("memdiver.core.constants.memdiver_home", lambda: home)
    monkeypatch.setattr("memdiver.analysis.case.memdiver_home", lambda: home)
    monkeypatch.chdir(ok)
    get_settings.cache_clear()
    yield {"ok": ok, "uploads": uploads, "home": home}
    get_settings.cache_clear()


@pytest.fixture()
def app(env):
    from memdiver.api.main import create_app

    return create_app()


@pytest.fixture()
def client(app):
    with TestClient(app, base_url="http://127.0.0.1") as c:
        yield c


def assert_coded_denial(resp, status: int = 403, *, mentions: str = "") -> dict:
    """The one body shape: ``detail`` and ``error`` are the same message."""
    assert resp.status_code == status, resp.text
    body = resp.json()
    assert set(body) == {"detail", "error", "code", "category"}, body
    assert body["code"] == CODE
    assert body["category"] == ErrorCategory.PRECONDITION.name
    assert isinstance(body["detail"], str) and body["detail"]
    assert body["error"] == body["detail"]
    assert mentions in body["detail"]
    return body


# -- read denials (the request dependency) ---------------------------------------------


def test_read_denial_in_the_query_string_is_coded(client):
    resp = client.get("/api/inspect/hex", params={"dump_path": BAD})
    body = assert_coded_denial(resp, mentions=BAD)
    assert "MEMDIVER_ALLOWED_ROOTS" in body["detail"]


def test_read_denial_in_a_json_body_is_coded(client):
    resp = client.post("/api/image/profile", json={"image_path": BAD})
    body = assert_coded_denial(resp, mentions=BAD)
    assert "MEMDIVER_ALLOWED_ROOTS" in body["detail"]


def test_read_denial_nested_in_a_json_body_is_coded(client):
    resp = client.post("/api/sessions/", json={
        "name": "s1", "input_path": BAD, "dumps": [], "dump_weights": {}})
    assert_coded_denial(resp, mentions=BAD)


def test_an_admitted_read_path_is_not_a_denial(client, env):
    resp = client.get("/api/inspect/hex", params={"dump_path": str(env["ok"] / "nope.dump")})
    assert resp.status_code != 403, resp.text


# -- write denials: each converted site ------------------------------------------------


def test_annotations_write_outside_the_write_roots_is_coded(client, env):
    """``contained_case_dir``: inside the READ root but outside every WRITE root."""
    resp = client.post("/api/annotations/add", json={
        "case_dir": str(env["ok"] / "case"), "capture_id": "c" * 64})
    body = assert_coded_denial(resp, mentions="Allowed write locations")
    assert str(env["ok"] / "case") in body["detail"]


def test_image_write_target_outside_the_write_roots_is_coded(client, env):
    """``image._contained`` shares ``contained_case_dir``."""
    resp = client.post("/api/image/open-view", json={
        "image_path": str(env["ok"] / "x.lime"), "view": "physical",
        "out_path": str(env["ok"] / "v.mdview")})
    assert_coded_denial(resp, mentions="Allowed write locations")


def test_experiment_capture_output_outside_the_write_roots_is_coded(client, env):
    """``experiment._confine_capture_output``."""
    resp = client.post("/api/experiment/capture", json={
        "target": "1", "output": str(env["ok"] / "dump.msl")})
    body = assert_coded_denial(resp, mentions="Allowed write locations")
    assert "output path" in body["detail"]


def test_dumps_import_output_dir_outside_the_upload_dir_is_coded(client, env):
    """``dumps._import_dir`` keeps the 400 this route has always answered."""
    raw = env["ok"] / "r.dump"
    raw.write_bytes(b"\xAA" * 4096)
    resp = client.post("/api/dumps/import-path", json={
        "path": str(raw), "output_dir": str(env["ok"] / "elsewhere")})
    body = assert_coded_denial(resp, status=400, mentions="output_dir")
    assert "upload directory" in body["detail"]


def test_key_pattern_output_dir_outside_the_upload_dir_is_coded(client, env):
    """``analysis._contained_output_dir`` (400, as before)."""
    resp = client.post("/api/analysis/key-pattern", json={
        "dump_paths": [str(env["ok"] / "a.dump")], "secret_hex": "00" * 32,
        "output_dir": "/etc"})
    body = assert_coded_denial(resp, status=400, mentions="output_dir")
    assert "upload directory" in body["detail"]


def test_export_keylog_output_path_outside_the_upload_dir_is_coded(client):
    """``analysis.export_keylog`` (400, as before)."""
    resp = client.post("/api/analysis/export-keylog", json={
        "secrets": [{"label": "CLIENT_RANDOM", "client_random": "00" * 32,
                     "secret_hex": "11" * 48}],
        "output_path": "../escape.log"})
    body = assert_coded_denial(resp, status=400, mentions="output_path")
    assert "escapes" in body["detail"]


# -- a denial raised in the core layer gets the same body -------------------------------


def _handler_app(raiser):
    """A bare app with the REST CapabilityError handler and one route raising *raiser*."""
    from fastapi import FastAPI

    from memdiver.api.main import _capability_error_handler

    mini = FastAPI()
    mini.add_exception_handler(CapabilityError, _capability_error_handler)
    mini.add_api_route("/raise", raiser)
    return TestClient(mini)


def test_a_core_raised_denial_now_carries_detail(env):
    """Denials raised straight from ``core.path_sandbox`` (no router adapter)."""
    def read():
        path_sandbox.admit(BAD, [env["ok"].resolve()])

    def write():
        path_sandbox.contain_write_target(BAD, [env["uploads"]], field="out_path")

    assert_coded_denial(_handler_app(read).get("/raise"), mentions=BAD)
    assert_coded_denial(_handler_app(write).get("/raise"), mentions="out_path")


def test_only_the_path_denial_code_gains_detail():
    def other():
        raise CapabilityError("not a path rule", category=ErrorCategory.PRECONDITION,
                              status=409, code="something.else")

    resp = _handler_app(other).get("/raise")
    assert resp.status_code == 409
    assert resp.json() == {"error": "not a path rule", "code": "something.else",
                           "category": "PRECONDITION"}


def test_write_denial_helper_builds_the_same_error_as_contain_write_target(tmp_path):
    root = tmp_path / "root"
    root.mkdir()
    with pytest.raises(CapabilityError) as raised:
        path_sandbox.contain_write_target("/etc/evil", [root], field="out_path",
                                          example_name="r", where="here")
    built = path_sandbox.write_denial("out_path", "/etc/evil", [root], "r", "here")
    assert (built.message, built.code, built.category, built.status) == (
        raised.value.message, raised.value.code, raised.value.category, raised.value.status)
    assert path_sandbox.write_denial("f", "/x", [root], status=400).status == 400


# -- the MCP guard already hands the same code to MCP clients ---------------------------


def test_mcp_guard_denial_carries_the_same_code_and_message(env):
    import json

    from memdiver.mcp_server.path_guard import guard_tool

    def tool(dump_path: str) -> str:
        return "ran"

    out = json.loads(guard_tool(tool)(BAD))
    assert out["code"] == CODE and out["category"] == ErrorCategory.PRECONDITION.name
    assert BAD in out["error"]
