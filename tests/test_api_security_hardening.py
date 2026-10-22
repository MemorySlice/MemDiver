"""Always-on request-origin hardening, write containment, opt-in read roots.

Covers api/security.HostAllowListMiddleware (DNS rebinding),
api/security.CrossSiteRequestGuard (CSRF / cross-site websocket), the
``/api/analysis/key-pattern`` + ``/api/structures/import-ksy`` write
containment, and the opt-in read-path sandbox in api/path_policy.py.

TestClient sends ``Host: testserver``; tests/conftest.py admits that name via
``MEMDIVER_ALLOWED_HOSTS`` and these tests override ``Host`` explicitly where
the header itself is under test.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from fastapi import WebSocketDisconnect
from fastapi.testclient import TestClient

from memdiver.api.config import Settings, get_settings
from memdiver.api.main import create_app
from memdiver.api.security import _host_name, allowed_host_names, dev_frontend_origins
from memdiver.app.tools_pipeline import _require_bare_name
from memdiver.core.service_errors import CapabilityError

LOCAL = {"host": "127.0.0.1:8080"}
CROSS_SITE_ORIGIN = "https://evil.example"


@pytest.fixture
def isolated_env(tmp_path: Path, monkeypatch):
    """Redirect every settings-controlled directory into tmp_path."""
    for sub, env in [
        ("oracles", "MEMDIVER_ORACLE_DIR"),
        ("tasks", "MEMDIVER_TASK_ROOT"),
        ("uploads", "MEMDIVER_UPLOAD_DIR"),
        ("sessions", "MEMDIVER_SESSION_DIR"),
    ]:
        d = tmp_path / sub
        d.mkdir()
        monkeypatch.setenv(env, str(d))
    monkeypatch.setenv("MEMDIVER_PIPELINE_MAX_WORKERS", "1")
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "xdg"))
    monkeypatch.delenv("MEMDIVER_ALLOWED_ROOTS", raising=False)
    # A developer's own dev-port export would widen the trusted origins.
    monkeypatch.delenv("MEMDIVER_FRONTEND_PORT", raising=False)
    monkeypatch.delenv("FRONTEND_PORT", raising=False)
    monkeypatch.delenv("MEMDIVER_CORS_ORIGINS", raising=False)
    get_settings.cache_clear()
    yield tmp_path
    get_settings.cache_clear()


@pytest.fixture
def client(isolated_env):
    with TestClient(create_app()) as c:
        yield c


@pytest.fixture
def sandbox(isolated_env, monkeypatch):
    """A client with the read-path sandbox on, rooted at tmp_path/allowed."""
    allowed = isolated_env / "allowed"
    (allowed / "sub").mkdir(parents=True)
    (allowed / "a.dump").write_bytes(b"\0" * 64)
    outside = isolated_env / "outside"
    outside.mkdir()
    (outside / "b.dump").write_bytes(b"\0" * 64)
    monkeypatch.setenv("MEMDIVER_ALLOWED_ROOTS", str(allowed))
    get_settings.cache_clear()
    with TestClient(create_app()) as c:
        yield c, allowed, outside


# ---------------------------------------------------------------------------
# Host allow-list
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("host", ["127.0.0.1:8080", "localhost:5173", "[::1]:8080",
                                  "localhost", "LOCALHOST:1"])
def test_loopback_hosts_allowed(client, host):
    assert client.get("/health", headers={"host": host}).status_code == 200


@pytest.mark.parametrize("host", ["evil.com", "evil.com:8080", "127.0.0.1.evil.com",
                                  "attacker.localhost.example:8080"])
def test_rebinding_hosts_rejected(client, host):
    resp = client.get("/api/path/browse", headers={"host": host})
    assert resp.status_code == 421
    assert "Host" in resp.json()["detail"]


def test_bad_host_rejected_on_websocket(client):
    with pytest.raises(WebSocketDisconnect):
        with client.websocket_connect("/ws/tasks/x", headers={"host": "evil.com"}) as ws:
            ws.receive_json()


def test_host_name_parsing():
    assert _host_name("[::1]:8080") == "::1"
    assert _host_name("::1") == "::1"
    assert _host_name("Example.COM:80") == "example.com"


def test_allowed_hosts_env_and_guarded_bind_host():
    s = Settings(allowed_hosts="a.lan, b.lan", host="10.0.0.5", api_token="t")
    names = allowed_host_names(s)
    assert {"a.lan", "b.lan", "10.0.0.5", "127.0.0.1", "localhost", "::1"} <= names
    # Without a token (guardrail would refuse the bind) the bind host is NOT added.
    assert "10.0.0.5" not in allowed_host_names(Settings(host="10.0.0.5"))


# ---------------------------------------------------------------------------
# Cross-site guard + Content-Type
# ---------------------------------------------------------------------------


def _post_last_dir(client, tmp_path, **headers):
    return client.put("/api/settings/last-dir", json={"path": str(tmp_path)},
                      headers={**LOCAL, **headers})


def test_cross_site_origin_post_refused(client, isolated_env):
    resp = _post_last_dir(client, isolated_env, origin=CROSS_SITE_ORIGIN)
    assert resp.status_code == 403


def test_null_origin_refused(client, isolated_env):
    assert _post_last_dir(client, isolated_env, origin="null").status_code == 403


def test_sec_fetch_site_cross_site_refused(client, isolated_env):
    resp = _post_last_dir(client, isolated_env, **{"sec-fetch-site": "cross-site"})
    assert resp.status_code == 403


def test_same_origin_post_ok(client, isolated_env):
    resp = _post_last_dir(client, isolated_env, origin="http://127.0.0.1:8080",
                          **{"sec-fetch-site": "same-origin"})
    assert resp.status_code == 200


def test_vite_dev_origin_ok(client, isolated_env):
    """The Vite proxy forwards Host localhost:5173 + Origin http://localhost:5173."""
    resp = client.put("/api/settings/last-dir", json={"path": str(isolated_env)},
                      headers={"host": "localhost:5173", "origin": "http://localhost:5173"})
    assert resp.status_code == 200


def test_vite_proxy_same_origin_ok(client, isolated_env):
    """The proxy runs with changeOrigin: false, so Host stays Vite's (any port)."""
    resp = client.put("/api/settings/last-dir", json={"path": str(isolated_env)},
                      headers={"host": "127.0.0.1:5191", "origin": "http://127.0.0.1:5191",
                               "sec-fetch-site": "same-origin"})
    assert resp.status_code == 200


@pytest.mark.parametrize("origin", ["http://127.0.0.1:5191", "http://localhost:8888",
                                    "http://[::1]:3000"])
def test_loopback_origin_other_port_refused(client, isolated_env, origin):
    """Another local web service (notebook, dev server) must not drive MemDiver."""
    resp = client.put("/api/settings/last-dir", json={"path": str(isolated_env)},
                      headers={"host": "127.0.0.1:8091", "origin": origin,
                               "sec-fetch-site": "same-site"})
    assert resp.status_code == 403


@pytest.mark.parametrize("origin", ["http://localhost:5173", "http://127.0.0.1:5173"])
def test_default_dev_origin_allow_listed(client, isolated_env, origin):
    resp = client.put("/api/settings/last-dir", json={"path": str(isolated_env)},
                      headers={"host": "127.0.0.1:8091", "origin": origin})
    assert resp.status_code == 200


@pytest.mark.parametrize("env", ["MEMDIVER_FRONTEND_PORT", "FRONTEND_PORT"])
def test_dev_frontend_port_env_allow_listed(isolated_env, monkeypatch, env):
    monkeypatch.delenv("MEMDIVER_FRONTEND_PORT", raising=False)
    monkeypatch.setenv(env, "5191")
    assert dev_frontend_origins() == ("http://localhost:5191", "http://127.0.0.1:5191")
    with TestClient(create_app()) as c:
        resp = c.put("/api/settings/last-dir", json={"path": str(isolated_env)},
                     headers={"host": "127.0.0.1:8091", "origin": "http://localhost:5191"})
    assert resp.status_code == 200


def test_dev_frontend_port_env_non_numeric_ignored(monkeypatch):
    monkeypatch.setenv("MEMDIVER_FRONTEND_PORT", "5191/evil")
    assert dev_frontend_origins() == ()


def test_cors_origins_env_allow_listed(isolated_env, monkeypatch):
    monkeypatch.setenv("MEMDIVER_CORS_ORIGINS", '["http://localhost:3000"]')
    get_settings.cache_clear()
    with TestClient(create_app()) as c:
        resp = c.put("/api/settings/last-dir", json={"path": str(isolated_env)},
                     headers={"host": "127.0.0.1:8091", "origin": "http://localhost:3000"})
    assert resp.status_code == 200


def test_loopback_origin_to_non_loopback_host_refused(client, isolated_env):
    resp = client.put("/api/settings/last-dir", json={"path": str(isolated_env)},
                      headers={"host": "testserver", "origin": "http://127.0.0.1:5191"})
    assert resp.status_code == 403


def test_no_origin_post_ok(client, isolated_env):
    assert _post_last_dir(client, isolated_env).status_code == 200


def test_get_with_cross_site_origin_not_blocked(client):
    resp = client.get("/api/settings/favourites",
                      headers={**LOCAL, "origin": CROSS_SITE_ORIGIN})
    assert resp.status_code == 200


@pytest.mark.parametrize("ctype", ["text/plain", "application/x-www-form-urlencoded", None])
def test_simple_request_body_types_refused(client, isolated_env, ctype):
    headers = {**LOCAL}
    if ctype:
        headers["content-type"] = ctype
    body = json.dumps({"path": str(isolated_env)}).encode()
    resp = client.put("/api/settings/last-dir", content=body, headers=headers)
    assert resp.status_code == 415


def test_multipart_upload_cross_site_refused(client):
    files = {"file": ("x.pcap", b"\xd4\xc3\xb2\xa1" + b"\0" * 20)}
    resp = client.post("/api/pcaps/upload", files=files,
                       headers={**LOCAL, "sec-fetch-site": "cross-site"})
    assert resp.status_code == 403
    resp = client.post("/api/pcaps/upload", files=files,
                       headers={**LOCAL, "origin": CROSS_SITE_ORIGIN})
    assert resp.status_code == 403


def test_multipart_upload_same_origin_passes_guard(client):
    files = {"file": ("x.pcap", b"\xd4\xc3\xb2\xa1" + b"\0" * 20)}
    resp = client.post("/api/pcaps/upload", files=files,
                       headers={**LOCAL, "origin": "http://127.0.0.1:8080",
                                "sec-fetch-site": "same-origin"})
    assert resp.status_code not in (403, 415, 421)


def test_cross_site_websocket_refused(client):
    with pytest.raises(WebSocketDisconnect):
        with client.websocket_connect(
            "/ws/tasks/x", headers={"origin": CROSS_SITE_ORIGIN}
        ) as ws:
            ws.receive_json()


@pytest.mark.parametrize("method,url,body", [
    ("POST", "/api/settings/upload-dir", {"path": "/tmp/evil"}),
    ("POST", "/api/settings/favourites", {"path": "/"}),
    ("DELETE", "/api/settings/favourites", None),
])
def test_settings_mutations_refuse_cross_site(client, method, url, body):
    resp = client.request(method, url, json=body, params={"path": "/"},
                          headers={**LOCAL, "origin": CROSS_SITE_ORIGIN})
    assert resp.status_code == 403


# ---------------------------------------------------------------------------
# Write containment
# ---------------------------------------------------------------------------


def _key_pattern(client, **overrides):
    body = {"dump_paths": ["/nonexistent.dump"], "secret_hex": "00" * 32, **overrides}
    return client.post("/api/analysis/key-pattern", json=body)


@pytest.mark.parametrize("output_dir", ["/etc", "../../..", "~/.ssh"])
def test_key_pattern_output_dir_outside_upload_dir_rejected(client, output_dir):
    resp = _key_pattern(client, output_dir=output_dir)
    assert resp.status_code == 400
    assert "upload directory" in resp.json()["detail"]


@pytest.mark.parametrize("name", ["../../.bashrc", "a/b", ".."])
def test_key_pattern_name_must_be_bare(client, isolated_env, name):
    resp = _key_pattern(client, output_dir=str(isolated_env / "uploads"), name=name)
    assert resp.status_code == 400
    assert "bare filename" in resp.json()["detail"]


def test_key_pattern_contained_output_dir_passes_containment(client, isolated_env):
    resp = _key_pattern(client, output_dir=str(isolated_env / "uploads" / "pat"))
    # Containment passed; the (absent) dump then fails in the producer.
    assert resp.status_code != 400 or "upload directory" not in resp.text


@pytest.mark.parametrize("name", ["../x", "a/b", "a\\b", "", "..", "x\x00"])
def test_producer_rejects_non_bare_pattern_name(name):
    with pytest.raises(CapabilityError):
        _require_bare_name(name)


def test_import_ksy_meta_id_traversal_rejected(client):
    ksy = b"meta:\n  id: ../../evil\nseq: []\n"
    resp = client.post("/api/structures/import-ksy",
                       files={"file": ("x.ksy", ksy)})
    assert resp.status_code == 400


# ---------------------------------------------------------------------------
# Opt-in read roots
# ---------------------------------------------------------------------------


def test_roots_policy_outside_path_forbidden(sandbox):
    c, _allowed, outside = sandbox
    for url, params in [
        ("/api/path/info", {"path": str(outside / "b.dump")}),
        ("/api/path/browse", {"path": str(outside)}),
        ("/api/path/discover-dumps", {"path": str(outside)}),
        ("/api/inspect/hex", {"dump_path": str(outside / "b.dump")}),
    ]:
        resp = c.get(url, params=params)
        assert resp.status_code == 403, url
        assert "MEMDIVER_ALLOWED_ROOTS" in resp.json()["detail"]


def test_roots_policy_json_body_checked(sandbox):
    c, _allowed, outside = sandbox
    resp = c.post("/api/dumps/preview", json={"path": str(outside / "b.dump")})
    assert resp.status_code == 403


def test_roots_policy_symlink_escape_forbidden(sandbox):
    c, allowed, outside = sandbox
    link = allowed / "link"
    link.symlink_to(outside)
    assert c.get("/api/path/browse", params={"path": str(link)}).status_code == 403


def test_roots_policy_traversal_forbidden(sandbox):
    c, allowed, _outside = sandbox
    sneaky = f"{allowed}/../outside"
    assert c.get("/api/path/browse", params={"path": sneaky}).status_code == 403


def test_roots_policy_inside_ok_and_parent_clamped(sandbox):
    c, allowed, _outside = sandbox
    info = c.get("/api/path/info", params={"path": str(allowed / "a.dump")})
    assert info.status_code == 200 and info.json()["is_file"]
    root = c.get("/api/path/browse", params={"path": str(allowed)}).json()
    assert root["parent"] is None
    sub = c.get("/api/path/browse", params={"path": str(allowed / "sub")}).json()
    assert sub["parent"] == str(allowed.resolve())


def test_roots_policy_default_browse_opens_inside(sandbox, monkeypatch, tmp_path):
    c, allowed, _outside = sandbox
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: tmp_path / "outside"))
    body = c.get("/api/path/browse").json()
    assert body["current"] == str(allowed.resolve())


def test_roots_policy_favourite_admits(sandbox):
    c, _allowed, outside = sandbox
    assert c.post("/api/settings/favourites", json={"path": str(outside)}).status_code == 200
    assert c.get("/api/path/browse", params={"path": str(outside)}).status_code == 200


def test_roots_policy_upload_dir_admitted(sandbox, isolated_env):
    c, _allowed, _outside = sandbox
    resp = c.get("/api/path/browse", params={"path": str(isolated_env / "uploads")})
    assert resp.status_code == 200


def test_policy_off_unchanged(client, isolated_env):
    resp = client.get("/api/path/browse", params={"path": str(isolated_env)})
    assert resp.status_code == 200
    body = resp.json()
    assert body["parent"] == str(isolated_env.resolve().parent)
