"""The P4 ISF workbench + ``disasm`` + image-open ``no_profile``/``paging``/``draft`` on all surfaces.

Producers are covered by tests/test_tools_isf.py and tests/test_tools_disasm.py; this file
proves the CLI (real argv), REST (real JSON), MCP and library entry points reach them and
agree. The pakunoda probe session is replaced by a fake (no image corpus needed).
"""
from __future__ import annotations

import json
from types import SimpleNamespace

import pytest

from memdiver.app import tools_isf as T

CAP = "b" * 64
INT = {"kind": "base", "name": "int"}


# -- fixtures ------------------------------------------------------------------------


@pytest.fixture
def client(monkeypatch, tmp_path):
    from fastapi.testclient import TestClient

    from memdiver.api.config import get_settings
    from memdiver.api.main import create_app
    monkeypatch.delenv("MEMDIVER_ALLOWED_ROOTS", raising=False)
    monkeypatch.setenv("MEMDIVER_UPLOAD_DIR", str(tmp_path / "uploads"))
    get_settings.cache_clear()
    yield TestClient(create_app())
    get_settings.cache_clear()


@pytest.fixture
def mcp_tools():
    pytest.importorskip("mcp")
    from memdiver.mcp_server.server import create_server
    return {t.name: t for t in create_server()._tool_manager.list_tools()}


@pytest.fixture
def case_dir(tmp_path):
    """A case inside the upload dir, so REST's write containment admits it."""
    path = tmp_path / "uploads" / "case"
    path.mkdir(parents=True)
    return str(path)


def _run(command, argv, capsys):
    from memdiver.cli import _build_parser, _cmd_disasm, _cmd_image, _cmd_isf
    handler = {"isf": _cmd_isf, "disasm": _cmd_disasm, "image": _cmd_image}[command]
    rc = handler(_build_parser().parse_args([command, *argv]))
    out = capsys.readouterr().out
    return rc, (json.loads(out) if out.strip() else None)


class FakeSession:
    capture = CAP
    arch_name, arch_source = "x86_64", "banner_string"

    def __init__(self, image, arch, params, on_stage=None):
        self.params, self.timings, self.warnings = params, {"open": 0.0}, []
        self.syms = {f"sym{i}": 0xFFFFFFFF81000000 + i * 16 for i in range(10)}

    def close(self):
        pass

    def kallsyms(self):
        return SimpleNamespace(metadata={"num_symbols": 10, "symbols": self.syms})

    def symbols(self):
        return self.syms


@pytest.fixture
def image(monkeypatch, tmp_path):
    pytest.importorskip("pakunoda")
    monkeypatch.setattr(T, "_Session", FakeSession)
    path = tmp_path / "img.lime"
    path.write_bytes(b"x")
    return str(path)


class _Manager:
    def __init__(self, tmp_path):
        self.artifact_store = SimpleNamespace(root=tmp_path / "tasks")
        self.submitted = []

    def submit(self, *, kind, params, runner_dotted, stage_names=None):
        self.submitted.append((kind, params, runner_dotted))
        return SimpleNamespace(task_id="t" * 32, status=SimpleNamespace(value="pending"))


@pytest.fixture
def manager(monkeypatch, tmp_path):
    mgr = _Manager(tmp_path)
    monkeypatch.setattr("memdiver.api.routers.image.task_manager_or_503", lambda: mgr)
    return mgr


# -- CLI: draft lifecycle -------------------------------------------------------------


def test_cli_draft_lifecycle(case_dir, tmp_path, capsys):
    rc, created = _run("isf", ["draft", "create", case_dir, CAP, "d", "x86_64",
                               "--banner", "Linux version 5.10"], capsys)
    assert rc == 0 and created["draft"] == "d" and created["entry"]["entry_id"]
    rc, st = _run("isf", ["draft", "set", case_dir, CAP, "d", "struct", "--args",
                          '{"name": "task", "size": 64}'], capsys)
    assert rc == 0 and st["op"] == "struct"
    _run("isf", ["draft", "set", case_dir, CAP, "d", "field", "--args", json.dumps(
        {"struct": "task", "field": "pid", "offset": 8, "type": INT})], capsys)
    _, listed = _run("isf", ["draft", "list", case_dir, CAP], capsys)
    assert listed["count"] == 1 and listed["drafts"][0]["name"] == "d"
    _, got = _run("isf", ["draft", "get", case_dir, CAP, "d", "--only",
                          '{"user_types": ["task"]}'], capsys)
    assert "task" in got["sections"]["user_types"]["items"]
    _, versions = _run("isf", ["draft", "versions", case_dir, CAP, "d"], capsys)
    assert versions["total"] >= 3
    out = tmp_path / "out.isf.json"
    _, exported = _run("isf", ["draft", "export", case_dir, CAP, "d", "--out", str(out)], capsys)
    assert exported["path"] == str(out) and out.is_file() and len(exported["sha256"]) == 64
    _, diff = _run("isf", ["draft", "diff", case_dir, CAP, "d", "--against-isf", str(out)],
                   capsys)
    assert diff["counts"]["added"] == 0
    first = created["entry"]["entry_id"]
    _, retracted = _run("isf", ["draft", "retract", case_dir, CAP, "d", st["entry"]["entry_id"],
                                "--reason", "oops"], capsys)
    assert retracted["retracted"] == st["entry"]["entry_id"] and first


def test_cli_bad_json_is_a_usage_error(case_dir, capsys):
    _run("isf", ["draft", "create", case_dir, CAP, "d", "x86_64"], capsys)
    with pytest.raises(SystemExit) as exc:
        _run("isf", ["draft", "set", case_dir, CAP, "d", "struct", "--args", "{nope"], capsys)
    assert exc.value.code == 2


def test_cli_without_an_action_lists_the_actions(capsys):
    from memdiver.cli import _build_parser, _cmd_isf
    assert _cmd_isf(_build_parser().parse_args(["isf"])) == 1
    assert _cmd_isf(_build_parser().parse_args(["isf", "draft"])) == 1


def test_cli_import_and_validate_and_try_guard(case_dir, tmp_path, capsys):
    donor = tmp_path / "donor.isf.json"
    donor.write_text(json.dumps({
        "metadata": {}, "base_types": {"int": {"size": 4, "signed": True, "kind": "int",
                                               "endian": "little"}},
        "user_types": {}, "enums": {}, "symbols": {"init_task": {"address": 4096}}}))
    _run("isf", ["draft", "create", case_dir, CAP, "d", "x86_64"], capsys)
    _, imported = _run("isf", ["draft", "import", case_dir, CAP, "d", str(donor)], capsys)
    assert len(imported["isf_sha256"]) == 64
    from memdiver.core.service_errors import CapabilityError
    with pytest.raises(CapabilityError) as exc:      # neither a draft nor an ISF file
        _run("isf", ["try", str(donor)], capsys)
    assert exc.value.code == "isf.try_target"


# -- REST: draft lifecycle ------------------------------------------------------------


def test_rest_draft_lifecycle_matches_the_producers(client, case_dir, tmp_path):
    body = {"case_dir": case_dir, "capture_id": CAP}
    r = client.post("/api/isf/drafts", json={**body, "name": "d", "arch": "x86_64"})
    assert r.status_code == 200 and r.json()["draft"] == "d"
    r = client.post("/api/isf/drafts/d/set", json={
        **body, "op": "struct", "args": {"name": "task", "size": 64}})
    assert r.status_code == 200
    entry_id = r.json()["entry"]["entry_id"]
    r = client.get("/api/isf/drafts", params=body)
    assert r.json() == T.isf_draft_list_result(case_dir, CAP).payload
    r = client.get("/api/isf/drafts/d", params={**body, "only": '{"user_types": []}'})
    assert r.json() == json.loads(json.dumps(
        T.isf_draft_get_result(case_dir, CAP, "d", only={"user_types": []}).payload))
    r = client.get("/api/isf/drafts/d/versions", params=body)
    assert r.json()["total"] == 2
    out = tmp_path / "uploads" / "out.isf.json"
    r = client.post("/api/isf/drafts/d/export", json={**body, "out_path": str(out)})
    assert r.status_code == 200 and out.is_file()
    r = client.post("/api/isf/drafts/d/diff", json={**body, "against_isf": str(out)})
    assert r.status_code == 200 and r.json()["counts"]["added"] == 0
    r = client.post("/api/isf/drafts/d/import", json={**body, "isf_path": str(out)})
    assert r.status_code == 200 and len(r.json()["isf_sha256"]) == 64
    r = client.post("/api/isf/drafts/d/retract", json={**body, "entry_id": entry_id})
    assert r.status_code == 200 and r.json()["retracted"] == entry_id


def test_rest_validate_reports_plugin_readiness(client, case_dir):
    pytest.importorskip("pakunoda")
    body = {"case_dir": case_dir, "capture_id": CAP}
    client.post("/api/isf/drafts", json={**body, "name": "d", "arch": "x86_64"})
    r = client.post("/api/isf/drafts/d/validate", json=body)
    assert r.status_code == 200 and "plugins" in r.json() and "is_valid" in r.json()


def test_rest_errors_and_containment(client, case_dir, tmp_path):
    body = {"case_dir": case_dir, "capture_id": CAP}
    assert client.post("/api/isf/drafts", json={**body, "name": "d", "arch": "x86_64",
                                                "typo": 1}).status_code == 422
    assert client.get("/api/isf/drafts/d", params={**body, "only": "{bad"}).status_code == 422
    outside = tmp_path / "elsewhere"
    r = client.post("/api/isf/drafts", json={"case_dir": str(outside), "capture_id": CAP,
                                             "name": "d", "arch": "x86_64"})
    assert r.status_code == 403 and not outside.exists()
    r = client.post("/api/isf/drafts/zz/set", json={**body, "op": "nope", "args": {}})
    assert r.status_code == 400


def test_rest_read_path_policy_covers_isf_inputs(client, case_dir, tmp_path, monkeypatch):
    from memdiver.api.config import get_settings
    monkeypatch.setenv("MEMDIVER_ALLOWED_ROOTS", str(tmp_path / "uploads"))
    get_settings.cache_clear()
    body = {"case_dir": case_dir, "capture_id": CAP}
    r = client.post("/api/isf/drafts/d/import", json={**body, "isf_path": "/etc/hosts"})
    assert r.status_code == 403
    r = client.post("/api/isf/try", json={"image_path": case_dir, "ground_truth": "/etc/hosts"})
    assert r.status_code == 403
    get_settings.cache_clear()


# -- probe / try: CLI, REST (inline + job), MCP, job runner ---------------------------


def test_probe_four_surfaces_agree(image, client, mcp_tools, capsys):
    expected = json.loads(json.dumps(
        T.isf_probe_result(image, "kallsyms", params={"limit": 3}).payload))
    assert len(expected["rows"]) == 3 and expected["truncated"]
    rc, cli = _run("isf", ["probe", image, "kallsyms", "--params", '{"limit": 3}'], capsys)
    assert rc == 0 and cli == expected
    r = client.post("/api/isf/probe", json={"image_path": image, "probe": "kallsyms",
                                            "params": {"limit": 3}})
    assert r.status_code == 200 and r.json() == expected
    mcp = json.loads(mcp_tools["isf_probe"].fn(image_path=image, probe="kallsyms",
                                               params={"limit": 3}))
    assert mcp == expected


def test_probe_feeds_a_draft_on_every_surface(image, client, mcp_tools, case_dir, capsys):
    T.isf_draft_create_result(case_dir, CAP, "d", "x86_64")
    _, cli = _run("isf", ["probe", image, "kallsyms", "--case", case_dir, "--draft", "d"],
                  capsys)
    assert cli["imported"]["symbols"] == 10
    r = client.post("/api/isf/probe", json={"image_path": image, "probe": "kallsyms",
                                            "case_dir": case_dir, "draft": "d"})
    assert r.json()["imported"]["symbols"] == 10
    mcp = json.loads(mcp_tools["isf_probe"].fn(image_path=image, probe="kallsyms",
                                               case_dir=case_dir, draft="d"))
    assert mcp["imported"]["symbols"] == 10


def test_rest_probe_and_try_submit_image_jobs_when_async(image, client, manager, case_dir):
    r = client.post("/api/isf/probe", json={"image_path": image, "probe": "kallsyms",
                                            "async": True, "params": {"limit": 5}})
    assert r.json() == {"task_id": "t" * 32, "status": "pending"}
    kind, params, runner = manager.submitted[-1]
    assert kind == "image" and params["job"] == "isf_probe" and runner.endswith("run_image_job")
    assert params["args"]["probe"] == "kallsyms" and params["args"]["params"] == {"limit": 5}
    r = client.post("/api/isf/try", json={"image_path": image, "case_dir": case_dir,
                                          "draft": "d", "async": True})
    assert r.json()["task_id"] == "t" * 32
    assert manager.submitted[-1][1]["job"] == "isf_try"
    assert manager.submitted[-1][1]["args"]["draft"] == "d"


def _in_process_killable(target, kwargs, *, cancel, on_progress=None, **_):
    """Stand-in for ``run_killable`` so this file's in-process fakes stay visible (a real
    spawned child re-imports pakunoda and never sees them); ``tests/test_killable.py`` and
    the gated real tests cover the real child."""
    import importlib
    module, _, name = target.partition(":")
    return getattr(importlib.import_module(module), name)(
        **kwargs, **({"progress": on_progress} if on_progress else {}))


def test_image_job_runner_runs_the_isf_probe(image, tmp_path, monkeypatch):
    from memdiver.app.pipeline.image_task_runner import JOBS, run_image_job
    monkeypatch.setattr("memdiver.engine.killable.run_killable", _in_process_killable)
    assert "isf_probe" in JOBS and "isf_try" in JOBS
    events = []
    ctx = SimpleNamespace(emit=lambda kind, **kw: events.append(kind), is_cancelled=lambda: False)
    out = run_image_job({"job": "isf_probe", "artifact_dir": str(tmp_path / "art"),
                         "args": {"image_path": image, "probe": "kallsyms",
                                  "params": {"limit": 2}}}, ctx)
    assert len(out["summary"]["rows"]) == 2 and events[0] == "stage_start"


def test_try_needs_a_target_on_rest_and_mcp(image, client, mcp_tools):
    r = client.post("/api/isf/try", json={"image_path": image})
    assert r.status_code == 400
    out = json.loads(mcp_tools["isf_try"].fn(image_path=image))
    assert "exactly one of draft" in out["error"]


def test_try_runs_an_isf_file_through_the_loop(image, client, mcp_tools, tmp_path, monkeypatch,
                                               capsys):
    outcome = {"verdict": "pass", "stage": "compared", "implicated": [], "comparison": None}
    seen = []

    def fake_try(image_path, target, **kw):
        seen.append((str(target), kw["plugin"]))
        return dict(outcome)

    monkeypatch.setattr("memdiver.isf.tryloop.try_isf", fake_try)
    isf = tmp_path / "x.isf.json"
    isf.write_text("{}")
    _, cli = _run("isf", ["try", image, "--isf", str(isf), "--plugin", "linux.psaux"], capsys)
    assert cli["verdict"] == "pass" and seen[-1] == (str(isf), "linux.psaux")
    r = client.post("/api/isf/try", json={"image_path": image, "isf_path": str(isf)})
    assert r.json()["verdict"] == "pass"
    mcp = json.loads(mcp_tools["isf_try"].fn(image_path=image, isf_path=str(isf)))
    assert mcp["verdict"] == "pass" and len(seen) == 3


# -- MCP: draft tools ------------------------------------------------------------------


def test_mcp_draft_tools_round_trip_and_stamp_the_agent(mcp_tools, case_dir, tmp_path):
    call = lambda tool, **kw: json.loads(mcp_tools[tool].fn(**kw))   # noqa: E731
    base = {"case_dir": case_dir, "capture_id": CAP}
    assert call("isf_draft_create", **base, name="d", arch="x86_64")["draft"] == "d"
    st = call("isf_draft_set", **base, name="d", op="symbol",
              args={"name": "init_task", "address": "0xffff0000"}, evidence=["probe"])
    assert st["entry"]["entry_id"]
    assert call("isf_draft_list", **base)["count"] == 1
    got = call("isf_draft_get", **base, name="d", only={"symbols": []}, include_origins=True)
    assert "init_task" in got["sections"]["symbols"]["items"]
    assert got["sections"]["symbols"]["origins"]["init_task"]["provenance"]["author"] == "agent"
    assert call("isf_draft_versions", **base, name="d")["total"] == 2
    out = call("isf_draft_export", **base, name="d", out_path=str(tmp_path / "e.isf.json"))
    assert out["size"] > 0
    assert call("isf_draft_import", **base, name="d", isf_path=out["path"])["isf_sha256"]
    assert call("isf_draft_diff", **base, name="d", against_isf=out["path"])["draft"] == "d"
    assert call("isf_draft_retract", **base, name="d",
                entry_id=st["entry"]["entry_id"])["retracted"] == st["entry"]["entry_id"]
    if __import__("importlib").util.find_spec("pakunoda"):
        assert "plugins" in call("isf_draft_validate", **base, name="d")


def test_library_exports_every_new_producer():
    from memdiver import services
    for name in ("isf_probe_result", "isf_draft_create_result", "isf_draft_list_result",
                 "isf_draft_get_result", "isf_draft_set_result", "isf_draft_import_result",
                 "isf_draft_retract_result", "isf_draft_versions_result",
                 "isf_draft_diff_result", "isf_draft_validate_result",
                 "isf_draft_export_result", "isf_try_result", "disasm_result"):
        assert name in services.__all__ and callable(getattr(services, name))


# -- disasm -----------------------------------------------------------------------------

X64 = bytes.fromhex("554889e5c3")


def test_disasm_four_surfaces_agree(client, mcp_tools, tmp_path, capsys):
    pytest.importorskip("capstone")
    from memdiver.app.tools_disasm import disasm_result
    flat = tmp_path / "code.bin"
    flat.write_bytes(b"\x00" * 16 + X64)
    expected = json.loads(json.dumps(disasm_result(str(flat), 16, 5, arch="x86_64").payload))
    assert [row["mnemonic"] for row in expected["rows"]] == ["push", "mov", "ret"]
    rc, cli = _run("disasm", [str(flat), "0x10", "5", "--arch", "x86_64"], capsys)
    assert rc == 0 and cli == expected
    r = client.post("/api/disasm", json={"dump_path": str(flat), "address": 16, "length": 5,
                                         "arch": "x86_64"})
    assert r.status_code == 200 and r.json() == expected
    mcp = json.loads(mcp_tools["disasm"].fn(dump_path=str(flat), address=16, length=5,
                                            arch="x86_64"))
    assert mcp == expected


def test_disasm_rest_errors(client, tmp_path):
    flat = tmp_path / "code.bin"
    flat.write_bytes(X64)
    missing = client.post("/api/disasm", json={"dump_path": str(tmp_path / "no"), "address": 0,
                                               "length": 4})
    assert missing.status_code == 404
    assert client.post("/api/disasm", json={"dump_path": str(flat), "address": 0, "length": 4,
                                            "typo": 1}).status_code == 422
    outside = tmp_path / "elsewhere"
    r = client.post("/api/disasm", json={"dump_path": str(flat), "address": 0, "length": 5,
                                         "arch": "x86_64", "case_dir": str(outside)})
    assert r.status_code == 403 and not outside.exists()


# -- image open: no_profile / paging / draft ---------------------------------------------


@pytest.fixture
def raw_image(tmp_path):
    path = tmp_path / "raw.lime"
    path.write_bytes(b"\x00" * 64)
    return str(path)


def test_image_open_no_profile_with_explicit_paging_on_cli_and_mcp(
        raw_image, mcp_tools, tmp_path, capsys):
    rc, cli = _run("image", ["open", raw_image, "--view", "kernel", "--no-profile",
                             "--pgd", "0x1000", "--arch", "x86_64", "--va-bits", "48",
                             "--out", str(tmp_path / "cli.mdview")], capsys)
    paging = cli["descriptor"]["paging"]
    assert rc == 0 and paging["pgd_phys"] == 0x1000 and paging["va_bits"] == 48
    assert not cli["descriptor"].get("profile")
    mcp = json.loads(mcp_tools["image_open_view"].fn(
        image_path=raw_image, view="kernel", no_profile=True,
        paging={"pgd_phys": 0x1000, "arch": "x86_64", "va_bits": 48},
        out_path=str(tmp_path / "mcp.mdview")))
    assert mcp["descriptor"]["paging"] == paging


def test_image_open_paging_json_flag_and_conflicts(raw_image, tmp_path, capsys):
    _, cli = _run("image", ["open", raw_image, "--view", "kernel", "--no-profile", "--paging",
                            '{"pgd_phys": 8192, "arch": "x86_64", "va_bits": 48}',
                            "--out", str(tmp_path / "j.mdview")], capsys)
    assert cli["descriptor"]["paging"]["pgd_phys"] == 8192
    from memdiver.core.service_errors import CapabilityError
    with pytest.raises(CapabilityError) as missing:     # va_bits is required without a format
        _run("image", ["open", raw_image, "--view", "kernel", "--no-profile", "--paging",
                       '{"pgd_phys": 8192, "arch": "x86_64"}',
                       "--out", str(tmp_path / "k.mdview")], capsys)
    assert missing.value.code == "paging_va_bits_required"
    with pytest.raises(CapabilityError) as exc:
        _run("image", ["open", raw_image, "--view", "physical", "--no-profile"], capsys)
    assert exc.value.code == "no_profile_view"


def test_image_open_rest_forwards_the_new_fields_to_the_job(raw_image, client, manager,
                                                           case_dir):
    r = client.post("/api/image/open-view", json={
        "image_path": raw_image, "view": "kernel", "no_profile": True,
        "paging": {"pgd_phys": 4096}, "draft": None, "draft_version": "v1",
        "case_dir": case_dir})
    assert r.json()["task_id"] == "t" * 32
    args = manager.submitted[-1][1]["args"]
    assert args["no_profile"] is True and args["paging"] == {"pgd_phys": 4096}
    assert args["draft_version"] == "v1" and args["draft"] is None
    bad = client.post("/api/image/open-view", json={"image_path": raw_image, "view": "kernel",
                                                    "nope": 1})
    assert bad.status_code == 422


def test_draft_get_search_offset_parity_across_surfaces(client, mcp_tools, case_dir, capsys):
    for i, n in enumerate(["alpha", "beta", "alps", "alpine", "gamma"]):
        T.isf_draft_set_result(case_dir, CAP, "d", "symbol", {"name": n, "address": i}) \
            if i else (T.isf_draft_create_result(case_dir, CAP, "d", "x86_64"),
                       T.isf_draft_set_result(case_dir, CAP, "d", "symbol",
                                              {"name": n, "address": i}))
    want = json.loads(json.dumps(T.isf_draft_get_result(
        case_dir, CAP, "d", only={"symbols": []}, search="AL", limit=2, offset=1).payload))
    sec = want["sections"]["symbols"]
    assert list(sec["items"]) == ["alpine", "alps"] and sec["total"] == 3
    assert sec["truncated"] is False and want["truncated"] is False
    r = client.get("/api/isf/drafts/d", params={
        "case_dir": case_dir, "capture_id": CAP, "only": '{"symbols": []}',
        "search": "AL", "limit": 2, "offset": 1})
    assert r.json() == want
    _, cli = _run("isf", ["draft", "get", case_dir, CAP, "d", "--only", '{"symbols": []}',
                          "--search", "AL", "--limit", "2", "--offset", "1"], capsys)
    assert cli == want
    mcp = json.loads(mcp_tools["isf_draft_get"].fn(
        case_dir=case_dir, capture_id=CAP, name="d", only={"symbols": []},
        search="AL", limit=2, offset=1))
    assert mcp == want
