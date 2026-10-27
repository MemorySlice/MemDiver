"""One write-containment check and one bare-case-name rule, shared by REST and MCP.

``core.path_sandbox.contain_write_target`` / ``is_bare_case_name`` back the REST
routers (``annotations.contained_case_dir``, ``image._case_target`` /
``_contained``, ``case._init_target``), the MCP guard (``mcp_server.path_guard``)
and ``analysis.case.case_path``. These tests pin that the surfaces decide
identically.
"""

from __future__ import annotations

import json
import os

import pytest
from fastapi.testclient import TestClient

from memdiver.api.config import get_settings
from memdiver.core import path_sandbox
from memdiver.core.path_sandbox import contain_write_target, is_bare_case_name
from memdiver.core.service_errors import CapabilityError

# -- is_bare_case_name ----------------------------------------------------------


@pytest.mark.parametrize("name", [
    "/", "\\", "..", ".", "", "   ", "a/b", "a\\b", "/abs/case", "~", "~/case",
    ".hidden", "../escape", "C:\\cases\\x",
])
def test_is_bare_case_name_rejects_paths_and_blanks(name):
    assert is_bare_case_name(name) is False


@pytest.mark.parametrize("name", ["case1", "my-case", "tls_2026.10", "Case 7"])
def test_is_bare_case_name_accepts_plain_slugs(name):
    assert is_bare_case_name(name) is True


def test_analysis_case_uses_the_shared_rule():
    from memdiver.analysis import case as case_mod
    assert case_mod.is_bare_case_name is is_bare_case_name


posix_only = pytest.mark.skipif(os.sep == "\\", reason="backslash is os.sep on Windows")


@posix_only
@pytest.mark.parametrize("name", ["a\\b", "lab\\run1", "C:\\cases\\x", "\\"])
def test_case_path_refuses_posix_backslash_name(tmp_path, monkeypatch, name):
    """On POSIX ``lab\\run1`` is no bare name and no path: refused, not cwd-relative."""
    from memdiver.analysis.case import Case, case_path
    home, work = tmp_path / "home", tmp_path / "work"
    work.mkdir()
    monkeypatch.setattr("memdiver.analysis.case.memdiver_home", lambda: home)
    monkeypatch.chdir(work)
    with pytest.raises(CapabilityError) as info:
        case_path(name)
    assert info.value.code == "case.invalid"
    assert "backslashes are not allowed" in info.value.message
    with pytest.raises(CapabilityError) as info:
        Case.init(name)
    assert info.value.code == "case.invalid"
    assert list(work.iterdir()) == [] and not home.exists()


@posix_only
def test_case_init_tool_refuses_posix_backslash_name(tmp_path, monkeypatch):
    """``case_init`` (MCP/REST producer) with the sandbox OFF: an error, no directory in the cwd."""
    from memdiver.app.tools_case import case_init_result
    monkeypatch.delenv("MEMDIVER_ALLOWED_ROOTS", raising=False)
    monkeypatch.setattr("memdiver.analysis.case.memdiver_home", lambda: tmp_path / "home")
    monkeypatch.chdir(tmp_path)
    with pytest.raises(CapabilityError) as info:
        case_init_result("lab\\run1")
    assert info.value.code == "case.invalid"
    assert list(tmp_path.iterdir()) == []


def test_case_path_plain_slug_and_forward_slash_path(tmp_path, monkeypatch):
    from memdiver.analysis.case import Case, case_path, cases_root
    monkeypatch.setattr("memdiver.analysis.case.memdiver_home", lambda: tmp_path / "home")
    assert case_path("plain") == cases_root() / "plain"
    assert Case.init("plain").dir == (tmp_path / "home" / "cases" / "plain").resolve()
    target = tmp_path / "elsewhere" / "c1"
    assert case_path(str(target)) == target
    assert (Case.init(str(target)).dir / "case.json").is_file()
    tilde = case_path("~/lab\\run1")  # explicit path prefix: still a path
    assert tilde == __import__("pathlib").Path("~/lab\\run1").expanduser()


@pytest.mark.parametrize("blank", ["", "  "])
def test_case_path_refuses_blank(blank):
    from memdiver.analysis.case import case_path
    with pytest.raises(CapabilityError):
        case_path(blank)


def test_is_path_shaped_follows_the_bare_rule():
    assert path_sandbox.is_path_shaped("case_dir", "a\\b")
    assert not path_sandbox.is_path_shaped("case_dir", "plain")
    assert not path_sandbox.is_path_shaped("case_dir", "  ")
    assert path_sandbox.is_path_shaped("out_path", "plain")


# -- contain_write_target ---------------------------------------------------------


def test_contain_write_target_admits_and_resolves(tmp_path):
    inside = tmp_path / "root" / "sub" / ".." / "x.json"
    (tmp_path / "root").mkdir()
    got = contain_write_target(str(inside), [tmp_path / "root"])
    assert got == str((tmp_path / "root" / "x.json").resolve())


def test_contain_write_target_refuses_with_403_code(tmp_path):
    root = tmp_path / "root"
    root.mkdir()
    with pytest.raises(CapabilityError) as ei:
        contain_write_target("/etc/evil", [root], field="out_path")
    err = ei.value
    assert err.status == 403 and err.code == "path.outside_sandbox"
    assert "'/etc/evil'" in err.message and "Allowed write locations" in err.message
    assert str(root.resolve() / "out/result") in err.message


def test_contain_write_target_refuses_symlink_escape(tmp_path):
    root, outside = tmp_path / "root", tmp_path / "outside"
    root.mkdir()
    outside.mkdir()
    os.symlink(outside, root / "link")
    with pytest.raises(CapabilityError):
        contain_write_target(str(root / "link" / "x"), [root])


def test_contain_write_target_no_roots_admits_nothing(tmp_path):
    with pytest.raises(CapabilityError):
        contain_write_target(str(tmp_path / "x"), [])


def test_old_import_paths_still_work():
    from memdiver.api import path_safety, read_roots
    from memdiver.core import sandbox_roots
    assert path_safety.write_denial_detail is path_sandbox.write_denial_detail
    assert read_roots.sandbox_roots is sandbox_roots.sandbox_roots
    assert read_roots.write_roots is sandbox_roots.write_roots


def test_mcp_guard_no_longer_imports_the_rest_package():
    import ast
    import inspect

    from memdiver.mcp_server import path_guard
    tree = ast.parse(inspect.getsource(path_guard))
    modules = [n.module or "" for n in ast.walk(tree) if isinstance(n, ast.ImportFrom)]
    assert not [m for m in modules if m.startswith("memdiver.api")]


# -- REST and MCP decide identically ---------------------------------------------


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
def client(env):
    from memdiver.api.main import create_app
    with TestClient(create_app()) as c:
        yield c


def _mcp_case_init(case: str):
    from memdiver.mcp_server.path_guard import guard_tool

    def case_init(case: str = ""):
        return "ran"
    return guard_tool(case_init)(case=case)


def _mcp_annotations_add(case_dir: str):
    from memdiver.mcp_server.path_guard import guard_tool

    def annotations_add(case_dir: str = ""):
        return "ran"
    return guard_tool(annotations_add)(case_dir=case_dir)


#: Non-bare names that resolve outside the write roots (cwd = the read root).
REFUSED = ["/etc/evil", "../escape", "a\\b", "./in_cwd", "sub/dir"]


@pytest.mark.parametrize("case", REFUSED)
def test_case_init_refused_by_rest_and_mcp(client, env, case):
    rest = client.post("/api/case/init", json={"case": case})
    assert rest.status_code == 403, rest.text
    assert "Allowed write locations" in rest.json()["detail"]
    mcp = json.loads(_mcp_case_init(case))
    assert mcp["code"] == "path.outside_sandbox"
    assert "Allowed write locations" in mcp["error"]
    for root in (env["home"], env["uploads"]):
        assert str(root.resolve()) in rest.json()["detail"]
        assert str(root.resolve()) in mcp["error"]


@pytest.mark.parametrize("case_dir", REFUSED)
def test_case_dir_write_refused_by_rest_and_mcp(client, env, case_dir):
    rest = client.post("/api/annotations/add", json={
        "case_dir": case_dir, "capture_id": "c" * 64})
    # Outside the READ roots too, so the read sandbox may refuse first: either
    # way both surfaces refuse with 403 / ``path.outside_sandbox``.
    assert rest.status_code == 403, rest.text
    assert repr(case_dir) in rest.json()["detail"]
    assert "path.outside_sandbox" in _mcp_annotations_add(case_dir)


def test_bare_name_admitted_by_rest_and_mcp(client, env):
    rest = client.post("/api/case/init", json={"case": "plain_case"})
    assert rest.status_code == 200, rest.text
    assert _mcp_case_init("plain_case") == "ran"
    assert (env["home"] / "cases" / "plain_case" / "case.json").is_file()


def test_path_inside_write_roots_admitted_by_rest_and_mcp(client, env):
    target = env["uploads"] / "c1"
    assert client.post("/api/case/init", json={"case": str(target)}).status_code == 200
    assert _mcp_case_init(str(target)) == "ran"


def test_blank_case_keeps_the_producer_error(client, env):
    rest = client.post("/api/case/init", json={"case": "  "})
    assert rest.status_code == 400 and "case_required" in rest.text


def test_image_case_target_and_contained(env):
    from fastapi import HTTPException

    from memdiver.api.routers.image import _case_target, _contained
    assert _case_target(None) is None and _case_target("") is None
    assert _case_target("plain") == "plain"
    assert _contained(None) is None
    inside = env["uploads"] / "out.json"
    assert _contained(str(inside)) == str(inside.resolve())
    for bad in REFUSED:
        with pytest.raises(HTTPException) as ei:
            _case_target(bad)
        assert ei.value.status_code == 403
