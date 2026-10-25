"""The ``vol3.*`` capabilities on all four surfaces (plan T2.2).

Anything that needs a real Volatility 3 image is faked at the producer boundary
(``vol3_run_result``); the CLI parsing, REST models, path policy, job plumbing,
MCP registration and the producers that need no image (scaffold, saved-query
listing, import, query) run for real.
"""
from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from memdiver.app import tools_vol3
from memdiver.core.service_result import ServiceResult

CASE_TABLE = "vol3__linux_pslist"


@pytest.fixture(autouse=True)
def _isolated_home(tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "xdg"))
    monkeypatch.setenv("MEMDIVER_HOME", str(tmp_path / "home"))


# -- CLI ---------------------------------------------------------------------------

def _cli(argv, capsys):
    from memdiver.cli import _build_parser, _cmd_vol3
    rc = _cmd_vol3(_build_parser().parse_args(["vol3", *argv]))
    return rc, capsys.readouterr().out


def test_cli_registers_every_action():
    from memdiver.cli.vol3 import _VOL3_HANDLERS
    assert set(_VOL3_HANDLERS) == {"list", "describe", "run", "query", "annotate",
                                   "scaffold", "check", "import", "write-config",
                                   "source", "fixture"}


def test_cli_without_action_prints_choices(capsys):
    from memdiver.cli import _build_parser, _cmd_vol3
    assert _cmd_vol3(_build_parser().parse_args(["vol3"])) == 1
    assert "pick an action" in capsys.readouterr().err


def test_cli_run_parses_args_as_json_or_string(monkeypatch, capsys, tmp_path):
    seen = {}

    def fake_run(view, plugin, args, **kw):
        seen.update(view=view, plugin=plugin, args=args, **kw)
        return ServiceResult.ok({"ran": True})
    monkeypatch.setattr(tools_vol3, "vol3_run_result", fake_run)
    source = tmp_path / "p.py"
    source.write_text("# plugin", encoding="utf-8")
    rc, out = _cli(["run", "--view", "v.mdview", "--plugin", "linux.pslist",
                    "--arg", "pid=[1,2]", "--arg", "name=sshd", "--arg", "dump=true",
                    "--case", "c", "--limit", "5", "--timeout", "9", "--max-rows", "3",
                    "--column-map", '{"Offset": "physical"}', "--source", str(source),
                    "--out-dir", "o"], capsys)
    assert rc == 0 and json.loads(out) == {"ran": True}
    assert seen["args"] == {"pid": [1, 2], "name": "sshd", "dump": True}
    assert (seen["case_dir"], seen["limit"], seen["timeout_s"], seen["max_rows"]) == ("c", 5, 9.0, 3)
    assert seen["column_map"] == {"Offset": "physical"} and seen["source"] == "# plugin"
    assert seen["out_dir"] == "o"


def test_cli_rejects_a_malformed_arg():
    from memdiver.cli import _build_parser
    with pytest.raises(SystemExit):
        _build_parser().parse_args(["vol3", "run", "--view", "v", "--arg", "novalue"])


def test_cli_scaffold_and_query_listing(capsys, tmp_path):
    _, out = _cli(["scaffold", "My Plugin", "--kernel-only"], capsys)
    scaffold = json.loads(out)
    assert scaffold["per_process"] is False and "class" in scaffold["source"]
    from memdiver.app.tools_case import case_init_result
    case_init_result(str(tmp_path / "case"))
    out_file = tmp_path / "saved.json"
    _cli(["query", "--case", str(tmp_path / "case"), "-o", str(out_file)], capsys)
    listing = json.loads(out_file.read_text())
    assert listing["count"] >= 1 and "hidden_processes" in {
        q["name"] for q in listing["saved_queries"]}


def test_cli_import_then_query(capsys, tmp_path):
    from memdiver.app.tools_case import case_init_result
    case = str(tmp_path / "case")
    case_init_result(case)
    csv = tmp_path / "ps.csv"
    csv.write_text("pid,comm\n1,init\n7,sshd\n", encoding="utf-8")
    rc, out = _cli(["import", str(csv), "--case", case, "--table", CASE_TABLE,
                    "--capture-id", "cap1"], capsys)
    assert rc == 0 and json.loads(out)["name"] == CASE_TABLE
    _, out = _cli(["query", "--case", case, "--sql",
                   f"SELECT comm FROM {CASE_TABLE} WHERE pid = ?", "--param", "7"], capsys)
    assert json.loads(out)["rows"] == [["sshd"]]


# -- REST --------------------------------------------------------------------------

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


class FakeManager:
    def __init__(self, root):
        self.artifact_store = SimpleNamespace(root=root)
        self.submitted = []

    def submit(self, *, kind, params, runner_dotted, stage_names=None):
        self.submitted.append(dict(kind=kind, params=params, runner=runner_dotted))
        return SimpleNamespace(task_id="t" * 32, status=SimpleNamespace(value="pending"))


@pytest.fixture
def manager(monkeypatch, tmp_path):
    fake = FakeManager(tmp_path / "tasks")
    monkeypatch.setattr("memdiver.api.routers.vol3.task_manager_or_503", lambda: fake)
    return fake


@pytest.fixture
def fake_run(monkeypatch):
    calls = []

    def run(**kwargs):
        calls.append(kwargs)
        return ServiceResult.ok({"ran": True})
    monkeypatch.setattr(tools_vol3, "vol3_run_result", run)
    return calls


def test_rest_run_is_inline_within_the_sync_budget(client, manager, fake_run):
    r = client.post("/api/vol3/run", json={"view_path": "v.mdview", "plugin": "linux.pslist",
                                           "args": {"pid": [1]}})
    assert r.status_code == 200 and r.json() == {"ran": True}
    assert not manager.submitted
    assert fake_run[0]["limit"] == 10_000 and fake_run[0]["timeout_s"] == 30.0


@pytest.mark.parametrize("extra", [{"timeout_s": 31}, {"limit": 10_001}, {"async": True}])
def test_rest_run_becomes_a_job_beyond_the_budget(client, manager, fake_run, extra):
    r = client.post("/api/vol3/run", json={"view_path": "v.mdview",
                                           "plugin": "linux.psscan", **extra})
    assert r.status_code == 200 and r.json() == {"task_id": "t" * 32, "status": "pending"}
    assert not fake_run
    (job,) = manager.submitted
    assert job["kind"] == "vol3" and job["runner"].endswith("vol3_task_runner.run_vol3_job")
    assert job["params"]["args"]["plugin"] == "linux.psscan"
    assert job["params"]["task_root"] == str(manager.artifact_store.root)


@pytest.mark.parametrize("url,body", [
    ("/api/vol3/run", {"view_path": "v", "plugin": "p", "timeout": 5}),
    ("/api/vol3/run", {"plugin": "p"}),
    ("/api/vol3/query", {"case_dir": "c", "sqll": "SELECT 1"}),
    ("/api/vol3/describe", {"plugin": "p", "src": "x"}),
    ("/api/vol3/annotate", {"case_dir": "c", "table": "t", "run_id": "r"}),
    ("/api/vol3/scaffold", {"name": "n", "per_proces": True}),
    ("/api/vol3/check", {"sourse": "x"}),
    ("/api/vol3/import", {"case_dir": "c", "path": "p", "table": "t"}),
    ("/api/vol3/write-config", {"view_path": "v", "out_path": "o", "plugins": "x"}),
])
def test_rest_misspelled_or_missing_fields_are_422(client, manager, fake_run, url, body):
    assert client.post(url, json=body).status_code == 422
    assert not manager.submitted and not fake_run


def test_rest_writes_outside_the_write_roots_are_refused(client, manager, fake_run, tmp_path):
    outside = str(tmp_path / "elsewhere")
    for url, body in [
        ("/api/vol3/run", {"view_path": "v", "plugin": "p", "case_dir": outside}),
        ("/api/vol3/run", {"view_path": "v", "plugin": "p", "out_dir": outside}),
        ("/api/vol3/run", {"view_path": "v", "plugin": "p", "case_dir": outside,
                           "async": True}),
        ("/api/vol3/write-config", {"view_path": "v", "out_path": outside + "/c.json"}),
        ("/api/vol3/annotate", {"case_dir": outside, "table": "t", "run_id": "r",
                                "column": "c"}),
        ("/api/vol3/import", {"case_dir": outside, "path": "p", "table": "vol3__x",
                              "capture_id": "c"}),
    ]:
        assert client.post(url, json=body).status_code == 403, url
    assert not manager.submitted and not fake_run and not Path(outside).exists()


def test_rest_read_sandbox_applies_to_vol3_paths(client, manager, monkeypatch, tmp_path):
    from memdiver.api.config import get_settings
    allowed = tmp_path / "allowed"
    allowed.mkdir()
    monkeypatch.setenv("MEMDIVER_ALLOWED_ROOTS", str(allowed))
    get_settings.cache_clear()
    other = str(tmp_path / "other")
    assert client.post("/api/vol3/run", json={"view_path": other + "/v.mdview",
                                              "plugin": "p"}).status_code == 403
    assert client.post("/api/vol3/query", json={"case_dir": other}).status_code == 403
    assert client.post("/api/vol3/check", json={"source": "x",
                                                "view_path": other}).status_code == 403
    assert client.post("/api/vol3/import", json={
        "case_dir": str(allowed / "c"), "path": other + "/x.csv", "table": "vol3__x",
        "capture_id": "c"}).status_code == 403
    assert not manager.submitted


def test_rest_scaffold_query_listing_and_import(client, tmp_path):
    from memdiver.app.tools_case import case_init_result
    case = str(tmp_path / "uploads" / "case")
    case_init_result(case)
    scaffold = client.post("/api/vol3/scaffold", json={"name": "demo"}).json()
    assert scaffold["per_process"] is True and "class" in scaffold["source"]
    listing = client.post("/api/vol3/query", json={"case_dir": case}).json()
    assert "hidden_processes" in {q["name"] for q in listing["saved_queries"]}
    csv = tmp_path / "ps.csv"
    csv.write_text("pid,comm\n7,sshd\n", encoding="utf-8")
    r = client.post("/api/vol3/import", json={"case_dir": case, "path": str(csv),
                                              "table": CASE_TABLE, "capture_id": "cap1"})
    assert r.status_code == 200 and r.json()["name"] == CASE_TABLE
    r = client.post("/api/vol3/query", json={"case_dir": case,
                                             "sql": f"SELECT comm FROM {CASE_TABLE}"})
    assert r.json()["rows"] == [["sshd"]]
    r = client.post("/api/vol3/query", json={"case_dir": case, "sql": "SELECT 1",
                                             "saved": "hidden_processes"})
    assert r.status_code == 400


# -- job runner --------------------------------------------------------------------

class _Ctx:
    task_id = "abc"

    def __init__(self):
        self.events = []

    def emit(self, kind, **fields):
        self.events.append((kind, fields))


def test_job_runner_forwards_progress_and_writes_the_artifact(monkeypatch, tmp_path):
    from memdiver.app.pipeline.vol3_task_runner import run_vol3_job

    def run(*, progress=None, **kwargs):
        progress(50.0, "scanning")
        return ServiceResult.ok({"ran": True, "plugin": kwargs["plugin"]})
    monkeypatch.setattr(tools_vol3, "vol3_run_result", run)
    ctx = _Ctx()
    out = run_vol3_job({"task_root": str(tmp_path / "tasks"),
                        "args": {"view_path": "v", "plugin": "linux.psscan"}}, ctx)
    assert out["summary"] == {"ran": True, "plugin": "linux.psscan"}
    (artifact,) = out["artifacts"]
    assert artifact["name"] == "vol3_result" and artifact["relpath"] == "vol3/result.json"
    stored = json.loads((tmp_path / "tasks" / "abc" / "vol3" / "result.json").read_text())
    assert stored == out["summary"]
    kinds = [k for k, _ in ctx.events]
    assert kinds == ["stage_start", "progress", "stage_end"]
    assert ctx.events[1][1]["pct"] == 0.5 and ctx.events[1][1]["msg"] == "scanning"


def test_job_runner_turns_capability_errors_into_value_errors(tmp_path):
    from memdiver.app.pipeline.vol3_task_runner import run_vol3_job
    ctx = _Ctx()
    with pytest.raises(ValueError):
        run_vol3_job({"task_root": str(tmp_path),
                      "args": {"view_path": str(tmp_path / "gone.mdview"), "plugin": "p"}}, ctx)
    assert ctx.events[-1][0] == "error"


# -- user source is logged ---------------------------------------------------------

def test_user_source_sha256_is_logged_before_it_runs(monkeypatch, caplog):
    import hashlib
    seen = []
    monkeypatch.setattr(tools_vol3, "_runner", lambda: SimpleNamespace(
        plugin_from_source=lambda s: seen.append(s) or "info",
        describe_plugin=lambda info: {"name": "x"}))
    with caplog.at_level("WARNING", logger="memdiver.app.tools_vol3"):
        tools_vol3.vol3_describe_result("", "print('hi')")
    digest = hashlib.sha256(b"print('hi')").hexdigest()
    assert seen == ["print('hi')"] and digest in caplog.text


# -- write-config accepts a user plugin on every surface ----------------------------

def _stub_write_config(monkeypatch):
    from memdiver.app import tools_vol3_dev
    seen = {}

    def fake(view, out, plugin="linux.pslist.PsList", **kw):
        seen.update(view=view, out=out, plugin=plugin, **kw)
        return ServiceResult.ok({"written": True})
    monkeypatch.setattr(tools_vol3_dev, "vol3_write_config_result", fake)
    return seen


def test_cli_write_config_forwards_the_plugin_source(monkeypatch, capsys, tmp_path):
    seen = _stub_write_config(monkeypatch)
    source = tmp_path / "p.py"
    source.write_text("# plugin", encoding="utf-8")
    rc, out = _cli(["write-config", "--view", "v.mdview", "--out", "c.json",
                    "--source", str(source), "--source-name", "n", "--case", "cd"], capsys)
    assert rc == 0 and json.loads(out) == {"written": True}
    assert (seen["source"], seen["source_name"], seen["case_dir"]) == ("# plugin", "n", "cd")


def test_rest_write_config_forwards_the_plugin_source(client, monkeypatch, tmp_path):
    seen = _stub_write_config(monkeypatch)
    r = client.post("/api/vol3/write-config", json={
        "view_path": "v", "out_path": str(tmp_path / "uploads" / "c.json"), "source": "# plugin",
        "source_name": "n"})
    assert r.status_code == 200 and r.json() == {"written": True}
    assert seen["source"] == "# plugin" and seen["source_name"] == "n"
    assert seen["case_dir"] is None


def test_mcp_write_config_forwards_the_plugin_source(monkeypatch):
    from memdiver.mcp_server.server import create_server
    seen = _stub_write_config(monkeypatch)
    tools = {t.name: t for t in create_server()._tool_manager.list_tools()}
    out = json.loads(tools["vol3_write_config"].fn(
        "v.mdview", "c.json", source="# plugin", source_name="n", case_dir="cd"))
    assert out == {"written": True}
    assert (seen["source"], seen["source_name"], seen["case_dir"]) == ("# plugin", "n", "cd")


def test_rest_sources_and_fixtures_accept_a_bare_case_name(client):
    """Found in the browser: the Image/Vol3 panel's case "alma9_browser" (a bare name,
    filed under cases_root() by Case.init) made GET /api/vol3/sources and /fixtures
    answer 400 case.not_a_case because Case.open took the name as a cwd path."""
    from memdiver.analysis.case import Case, cases_root
    Case.init("bare_case")
    assert (cases_root() / "bare_case" / "case.json").is_file()
    for route in ("/api/vol3/sources", "/api/vol3/fixtures"):
        resp = client.get(route, params={"case_dir": "bare_case"})
        assert resp.status_code == 200, resp.text
        assert resp.json()["count"] == 0


def test_case_open_still_refuses_an_unknown_bare_name():
    from memdiver.analysis.case import Case
    from memdiver.core.service_errors import CapabilityError
    with pytest.raises(CapabilityError):
        Case.open("no_such_case")
