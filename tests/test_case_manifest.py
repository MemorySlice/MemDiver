"""``case.manifest``: the inventory of a case on all four surfaces."""
from __future__ import annotations

import json

import pytest

from memdiver.analysis.case import Case
from memdiver.app import tools_case as tc
from memdiver.core.image.view_descriptor import ViewDescriptor, ViewKind
from memdiver.isf.draft import IsfDraftStore, Provenance

CAP = "a" * 64


@pytest.fixture
def case_dir(tmp_path):
    import pyarrow as pa
    case = Case.init(tmp_path / "uploads" / "case")
    image = tmp_path / "img.lime"
    image.write_bytes(b"\0" * 64)
    ViewDescriptor(str(image), CAP, ViewKind.PHYSICAL).write(case.dir / "views" / "phys.mdview")
    ViewDescriptor(str(tmp_path / "gone.lime"), "b" * 64, ViewKind.PHYSICAL).write(
        case.dir / "views" / "gone.mdview")
    (case.dir / "cap1.msl").write_bytes(b"MSL" * 10)
    (case.dir / "plugins" / "p.py").write_text("x = 1\n")
    (case.dir / "isf" / "kernel.isf.json").write_text("{}")
    case.register_table("vmas", pa.table({"addr": pa.array([1, 2], pa.uint64())}),
                        capture_id=CAP, producer="test", locations={"addr": "physical"})
    store = IsfDraftStore(case.dir)
    store.create(CAP, "d1", arch="x86_64")
    store.set_symbol(CAP, "d1", "init_task", 0x1000, Provenance("kallsyms", "manual"))
    return str(case.dir)


def _check(m):
    assert m["name"] == "case" and m["version"] == 1 and m["created"]
    assert {v["path"]: v["kind"] for v in m["views"]} == {
        "views/phys.mdview": "physical", "views/gone.mdview": "physical"}
    imgs = {i["path"].rsplit("/", 1)[-1]: i for i in m["images"]}
    assert imgs["img.lime"]["exists"] and imgs["img.lime"]["size"] == 64
    assert not imgs["gone.lime"]["exists"] and imgs["gone.lime"]["size"] is None
    assert m["captures"] == [{"path": "cap1.msl", "size": 30}]
    assert m["annotations"] == [{"capture": CAP, "entries": 2}]
    assert m["isf"]["drafts"] == [{"capture": CAP, "name": "d1", "ops": 2, "arch": "x86_64"}]
    assert [e["path"] for e in m["isf"]["exports"]] == ["isf/kernel.isf.json"]
    assert [p["path"] for p in m["plugins"]] == ["plugins/p.py"]
    assert m["tables"] == [{"name": "vmas", "runs": 1, "rows": 2}]
    assert m["record_counts"]["views"] == 2 and m["truncated"] == {} and m["warnings"] == []


def test_producer_inventory(case_dir):
    _check(tc.case_manifest_result(case_dir).payload)


def test_producer_truncates_and_warns(case_dir, monkeypatch):
    monkeypatch.setattr(tc, "MANIFEST_LIST_CAP", 1)
    (tc.Path(case_dir) / "views" / "bad.mdview").write_text("junk")
    m = tc.case_manifest_result(case_dir).payload
    assert m["truncated"]["views"] and len(m["views"]) == 1
    assert m["record_counts"]["views"] == 3 and m["warnings"]


def test_producer_bad_input():
    from memdiver.core.service_errors import CapabilityError
    for bad in ("", "/nonexistent-case-xyz"):
        with pytest.raises(CapabilityError):
            tc.case_manifest_result(bad)


def test_cli_json_and_table(case_dir, capsys):
    from memdiver.cli import _build_parser, _cmd_case
    assert _cmd_case(_build_parser().parse_args(["case", "manifest", "--case", case_dir, "--json"])) == 0
    _check(json.loads(capsys.readouterr().out))
    assert _cmd_case(_build_parser().parse_args(["case", "manifest", "--case", case_dir])) == 0
    out = capsys.readouterr().out
    assert "MISSING" in out and "cap1.msl" in out and "draft   d1" in out


def test_rest(case_dir, monkeypatch, tmp_path):
    from fastapi.testclient import TestClient

    from memdiver.api.config import get_settings
    from memdiver.api.main import create_app
    monkeypatch.delenv("MEMDIVER_ALLOWED_ROOTS", raising=False)
    monkeypatch.setenv("MEMDIVER_UPLOAD_DIR", str(tmp_path / "uploads"))
    get_settings.cache_clear()
    client = TestClient(create_app())
    _check(client.get("/api/case/manifest", params={"case_dir": case_dir}).json())
    allowed = tmp_path / "allowed"
    allowed.mkdir()
    monkeypatch.setenv("MEMDIVER_ALLOWED_ROOTS", str(allowed))
    get_settings.cache_clear()
    assert client.get("/api/case/manifest", params={"case_dir": str(tmp_path / "other")}).status_code == 403
    get_settings.cache_clear()


def test_mcp(case_dir, monkeypatch):
    monkeypatch.delenv("MEMDIVER_ALLOWED_ROOTS", raising=False)
    from memdiver.api.config import get_settings
    get_settings.cache_clear()
    pytest.importorskip("mcp")
    from memdiver.mcp_server.server import create_server
    tools = {t.name: t for t in create_server()._tool_manager.list_tools()}
    _check(json.loads(tools["case_manifest"].fn(case_dir=case_dir)))


def test_manifest_does_not_stat_images_outside_sandbox(case_dir, tmp_path, monkeypatch):
    from memdiver.api.config import get_settings
    from memdiver.core import path_sandbox
    monkeypatch.setenv("MEMDIVER_ALLOWED_ROOTS", str(tmp_path / "uploads"))
    monkeypatch.setattr(path_sandbox, "STARTUP_CWD", str(tmp_path / "uploads"))
    get_settings.cache_clear()
    try:
        from memdiver.api.read_roots import sandbox_roots
        m = tc.case_manifest_result(case_dir, read_roots=sandbox_roots()).payload
    finally:
        get_settings.cache_clear()
    imgs = {i["path"].rsplit("/", 1)[-1]: i for i in m["images"]}
    assert imgs["img.lime"]["exists"] is None and imgs["img.lime"]["size"] is None
    assert any("outside the sandbox" in w for w in m["warnings"])


def test_manifest_stat_unchanged_with_sandbox_off(case_dir, monkeypatch):
    monkeypatch.delenv("MEMDIVER_ALLOWED_ROOTS", raising=False)
    from memdiver.api.config import get_settings
    get_settings.cache_clear()
    m = tc.case_manifest_result(case_dir).payload
    assert {i["path"].rsplit("/", 1)[-1]: i["exists"] for i in m["images"]} == {
        "img.lime": True, "gone.lime": False}
