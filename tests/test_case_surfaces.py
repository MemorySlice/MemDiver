"""The ``case.*`` capabilities on all four surfaces (plan T1.8 / T1.9).

Producer, CLI (real argv through the top-level parser), REST (real JSON bodies
over TestClient) and MCP (registered tool functions and the schema resource).
"""
from __future__ import annotations

import asyncio
import io
import json
from urllib.parse import quote

from types import SimpleNamespace

import pyarrow as pa
import pytest

from memdiver.analysis.case import Case
from memdiver.app import tools_case as tc
from memdiver.core.location import Coverage
from memdiver.core.service_errors import CapabilityError, ErrorCategory

CAP = "d" * 64
LOC = {"space": "kernel_va", "value": 0x1010, "capture_id": CAP}


@pytest.fixture
def case_dir(tmp_path):
    case = Case.init(tmp_path / "uploads" / "case")
    table = pa.table({"addr": pa.array([0x1000, 0x1000], pa.uint64()),
                      "size": pa.array([0x100, 0x2000], pa.uint64()),
                      "space": ["kernel_va"] * 2, "label": ["inner", "outer"]})
    case.register_table("vmas", table, capture_id=CAP, producer="test")
    return str(case.dir)


# -- producers -------------------------------------------------------------------


def test_producer_init_status_schema(tmp_path, monkeypatch, case_dir):
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "xdg"))
    made = tc.case_init_result("named").payload
    assert made["dir"].endswith("cases/named") and made["name"] == "named"
    status = tc.case_status_result(case_dir).payload
    assert status["tables"]["vmas"]["rows"] == 2 and status["tables"]["vmas"]["run_count"] == 1
    assert status["annotation_captures"] == {}
    schema = tc.case_schema_result(case_dir).payload
    assert "vmas" in schema["tables"] and "annotations" in schema


def test_producer_query(case_dir):
    out = tc.case_query_result(
        case_dir, "SELECT label FROM vmas WHERE size > ? ORDER BY label", 1, [0x200]).payload
    assert out["columns"] == ["label"] and out["rows"] == [["outer"]]
    assert out["truncated"] is False and out["elapsed_s"] >= 0
    cut = tc.case_query_result(case_dir, "SELECT label FROM vmas", 1).payload
    assert cut["truncated"] is True and cut["row_count"] == 1
    big = tc.case_query_result(case_dir, "SELECT addr FROM vmas LIMIT 1").payload
    assert isinstance(big["rows"][0][0], int)


@pytest.mark.parametrize("call", [
    lambda d: tc.case_query_result(d, "DROP TABLE vmas"),
    lambda d: tc.case_query_result(d, "  "),
    lambda d: tc.case_query_result(d, "SELECT 1", limit=0),
    lambda d: tc.case_status_result(""),
    lambda d: tc.case_status_result(d + "-missing"),
    lambda d: tc.case_init_result(""),
    lambda d: tc.context_at_result(d, {"space": "bogus", "value": 1}),
    lambda d: tc.context_at_result(d, {"space": "kernel_va", "value": 1}),
    lambda d: tc.context_at_result(d, LOC, length=0),
])
def test_producer_bad_input_is_capability_error(case_dir, call):
    with pytest.raises(CapabilityError) as err:
        call(case_dir)
    assert err.value.category is ErrorCategory.INVALID_INPUT


def test_producer_context_at(case_dir):
    out = tc.context_at_result(case_dir, LOC).payload
    assert [layer["row"]["label"] for layer in out["layers"]] == ["outer", "inner"]
    assert out["coverage"] is None
    only = tc.context_at_result(case_dir, LOC, tables=[]).payload
    assert only["layers"] == []


def test_producer_context_at_with_dump_adds_coverage(case_dir, monkeypatch, tmp_path):
    closed = []

    class Source:
        """Mirrors the real lifecycle: open_dump returns it UNOPENED, and
        read_location raises unless the caller opened it (Vol3LayerSource does)."""
        opened = False

        def __enter__(self):
            self.opened = True
            return self

        def __exit__(self, *exc):
            self.close()

        def read_location(self, value, length):
            if not self.opened:
                raise RuntimeError("not open")
            return type("R", (), {"coverage": Coverage(value, length, length)})()

        def close(self):
            closed.append(True)

    monkeypatch.setattr("memdiver.core.dump_source.open_dump", lambda path, **kw: Source())
    out = tc.context_at_result(case_dir, LOC, length=8, dump_path=str(tmp_path / "d")).payload
    assert out["coverage"]["requested"] == 8 and closed == [True]


def test_producer_context_at_real_raw_dump_has_no_coverage(case_dir, tmp_path):
    dump = tmp_path / "x.raw"
    dump.write_bytes(b"\0" * 64)
    out = tc.context_at_result(case_dir, LOC, dump_path=str(dump)).payload
    assert len(out["layers"]) == 2


# -- CLI -------------------------------------------------------------------------


def _cli(argv, capsys):
    from memdiver.cli import _build_parser, _cmd_case
    rc = _cmd_case(_build_parser().parse_args(["case", *argv]))
    return rc, capsys.readouterr().out


def test_cli_round_trip(case_dir, capsys, tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "xdg"))
    rc, out = _cli(["init", str(tmp_path / "fresh")], capsys)
    assert rc == 0 and json.loads(out)["name"] == "fresh"
    _, out = _cli(["status", "--case", case_dir], capsys)
    assert json.loads(out)["tables"]["vmas"]["rows"] == 2
    _, out = _cli(["schema", "--case", case_dir], capsys)
    assert "vmas" in json.loads(out)["tables"]
    _, out = _cli(["context-at", "--case", case_dir, "--location", json.dumps(LOC),
                   "--length", "0x10", "--table", "vmas"], capsys)
    assert len(json.loads(out)["layers"]) == 2


def test_cli_query_sql_stdin_and_int_params(case_dir, capsys, monkeypatch):
    _, out = _cli(["query", "--case", case_dir, "--sql",
                   "SELECT label FROM vmas WHERE size = ?", "--param", "0x100"], capsys)
    assert json.loads(out)["rows"] == [["inner"]]
    monkeypatch.setattr("sys.stdin", io.StringIO("SELECT count(*) AS n FROM vmas"))
    _, out = _cli(["query", "--case", case_dir, "--sql", "-"], capsys)
    assert json.loads(out)["rows"] == [[2]]
    monkeypatch.setattr("sys.stdin", io.StringIO("SELECT label FROM vmas WHERE label = ?"))
    _, out = _cli(["query", "--case", case_dir, "--param", "outer"], capsys)
    assert json.loads(out)["rows"] == [["outer"]]


def test_cli_errors_and_no_action(case_dir, capsys):
    from memdiver.cli import _build_parser, _cmd_case
    with pytest.raises(CapabilityError):
        _cli(["query", "--case", case_dir, "--sql", "DELETE FROM vmas"], capsys)
    with pytest.raises(SystemExit):
        _build_parser().parse_args(["case", "status"])
    assert _cmd_case(_build_parser().parse_args(["case"])) == 1


# -- REST ------------------------------------------------------------------------


@pytest.fixture
def client(monkeypatch, tmp_path):
    from fastapi.testclient import TestClient

    from memdiver.api.config import get_settings
    from memdiver.api.main import create_app
    monkeypatch.delenv("MEMDIVER_ALLOWED_ROOTS", raising=False)
    monkeypatch.setenv("MEMDIVER_UPLOAD_DIR", str(tmp_path / "uploads"))
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "xdg"))
    get_settings.cache_clear()
    yield TestClient(create_app())
    get_settings.cache_clear()


def test_rest_round_trip_with_real_json_bodies(client, case_dir, tmp_path):
    fresh = str(tmp_path / "uploads" / "fresh")
    r = client.post("/api/case/init", json={"case": fresh})
    assert r.status_code == 200 and r.json()["name"] == "fresh"
    r = client.post("/api/case/init", json={"case": "barename"})
    assert r.status_code == 200 and r.json()["dir"].endswith("cases/barename")
    r = client.get("/api/case/status", params={"case_dir": case_dir})
    assert r.json()["tables"]["vmas"]["rows"] == 2
    r = client.get("/api/case/schema", params={"case_dir": case_dir})
    assert "vmas" in r.json()["tables"]
    r = client.post("/api/case/query", json={
        "case_dir": case_dir, "sql": "SELECT label FROM vmas WHERE size > ?",
        "params": [0x200], "limit": 10})
    assert r.status_code == 200 and r.json()["rows"] == [["outer"]]
    r = client.post("/api/case/context-at", json={
        "case_dir": case_dir, "location": LOC, "length": 4, "tables": ["vmas"]})
    assert [x["row"]["label"] for x in r.json()["layers"]] == ["outer", "inner"]


def test_rest_misspelled_field_is_422(client, case_dir):
    r = client.post("/api/case/query", json={"case_dir": case_dir, "sql": "SELECT 1",
                                             "lmit": 5})
    assert r.status_code == 422
    r = client.post("/api/case/context-at", json={
        "case_dir": case_dir, "location": LOC, "dump_pth": "x"})
    assert r.status_code == 422
    assert client.post("/api/case/init", json={"case": "x", "dir": "y"}).status_code == 422


def test_rest_non_select_is_refused(client, case_dir):
    r = client.post("/api/case/query", json={"case_dir": case_dir, "sql": "DROP TABLE vmas"})
    assert r.status_code == 400 and r.json()["category"] == "INVALID_INPUT"
    r = client.post("/api/case/query", json={
        "case_dir": case_dir, "sql": "SELECT 1; SELECT 2"})
    assert r.status_code == 400


def test_rest_init_outside_roots_is_refused(client, tmp_path):
    outside = tmp_path / "elsewhere"
    r = client.post("/api/case/init", json={"case": str(outside)})
    assert r.status_code == 403 and not outside.exists()
    r = client.post("/api/case/init", json={"case": ".."})
    assert r.status_code == 403


def test_rest_read_sandbox_applies_to_case_dir(client, monkeypatch, tmp_path):
    from memdiver.api.config import get_settings
    allowed = tmp_path / "allowed"
    allowed.mkdir()
    monkeypatch.setenv("MEMDIVER_ALLOWED_ROOTS", str(allowed))
    get_settings.cache_clear()
    assert client.get("/api/case/schema", params={
        "case_dir": str(tmp_path / "other")}).status_code == 403
    assert client.post("/api/case/query", json={
        "case_dir": str(tmp_path / "other"), "sql": "SELECT 1"}).status_code == 403


# -- MCP -------------------------------------------------------------------------


@pytest.fixture(scope="module")
def server():
    pytest.importorskip("mcp")
    from memdiver.mcp_server.server import create_server
    return create_server()


@pytest.fixture
def tools(server):
    return {t.name: t for t in server._tool_manager.list_tools()}


def _mcp(tools, name, **kw):
    return json.loads(tools[name].fn(**kw))


def test_mcp_tools_match_producers(tools, case_dir, tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "xdg"))
    assert _mcp(tools, "case_init", case=str(tmp_path / "m"))["name"] == "m"
    assert _mcp(tools, "case_status", case_dir=case_dir)["tables"]["vmas"]["rows"] == 2
    assert "vmas" in _mcp(tools, "case_schema", case_dir=case_dir)["tables"]
    out = _mcp(tools, "case_query", case_dir=case_dir,
               sql="SELECT label FROM vmas WHERE size = ?", params=[0x100])
    assert out["rows"] == [["inner"]] and out["limit"] == 200
    out = _mcp(tools, "context_at", case_dir=case_dir, location=LOC)
    assert len(out["layers"]) == 2


def test_mcp_query_is_read_only_and_errors_are_structured(tools, case_dir):
    out = _mcp(tools, "case_query", case_dir=case_dir, sql="DROP TABLE vmas")
    assert out == {"error": "only a single SELECT statement is allowed"}


def test_mcp_schema_resource_registered_and_returns_schema(server, case_dir):
    templates = asyncio.run(server.list_resource_templates())
    assert "memdiver://case/{case_dir}/schema" in {t.uri_template for t in templates}
    uri = f"memdiver://case/{quote(case_dir, safe='')}/schema"
    contents = asyncio.run(server.read_resource(uri))
    body = json.loads(contents[0].content)
    assert "vmas" in body["tables"] and contents[0].mime_type == "application/json"
    assert body == Case.open(case_dir).schema()


# -- library ---------------------------------------------------------------------


def test_open_case_returns_case_without_eager_import(case_dir):
    import memdiver
    assert "open_case" in memdiver.__all__
    case = memdiver.open_case(case_dir)
    assert isinstance(case, Case) and "vmas" in case.tables()
    with pytest.raises(CapabilityError):
        memdiver.open_case(case_dir + "-missing")


# -- case.export -----------------------------------------------------------------

@pytest.fixture
def fake_adapter(monkeypatch):
    """open_dump of a .mdview builds its Vol3LayerSource around the fake adapter."""
    from tests import test_case_exporters as tce
    from memdiver.core.image import sources
    real = sources.Vol3LayerSource.__init__

    def init(self, path, *a, **kw):
        kw.setdefault("adapter_factory", lambda d, p: tce._Adapter(tce.RUNS, tce.VMAS))
        real(self, path, *a, **kw)

    monkeypatch.setattr(sources.Vol3LayerSource, "__init__", init)


def _view(tmp_path):
    from tests import test_case_exporters as tce
    from memdiver.core.image.view_descriptor import ProfileRef, ViewDescriptor, ViewKind
    (tmp_path / "img.bin").write_bytes(b"\0" * 64)
    return str(ViewDescriptor("img.bin", tce.SHA, ViewKind.PROCESS, pid=42,
                              profile=ProfileRef("p.json")).write(tmp_path / "v.mdview"))


def test_export_auto_view(case_dir, tmp_path, fake_adapter):
    out = tc.case_export_result(case_dir, _view(tmp_path), run_id="r1").payload
    assert [e["table"] for e in out["exports"]] == ["view_runs", "proc_maps"]
    assert all(e["run_id"] == "r1" and e["rows"] == 2 for e in out["exports"])
    assert out["skipped"] == []


def test_export_auto_msl_skips_heap_without_allocator(case_dir, tmp_path):
    from tests import test_case_exporters as tce
    msl = tce._write_msl(tmp_path / "a.msl")
    out = tc.case_export_result(case_dir, msl).payload
    assert [e["table"] for e in out["exports"]] == ["msl_regions", "msl_page_states"]
    assert [s["what"] for s in out["skipped"]] == ["heap_chunks"]
    assert Case.open(case_dir).tables().count("msl_regions") == 1


def test_export_explicit_and_not_applicable(case_dir, tmp_path, fake_adapter):
    from tests import test_case_exporters as tce
    msl = tce._write_msl(tmp_path / "a.msl")
    out = tc.case_export_result(case_dir, msl, ("page_states",)).payload
    assert [e["table"] for e in out["exports"]] == ["msl_page_states"]
    with pytest.raises(CapabilityError) as err:
        tc.case_export_result(case_dir, msl, ("view_regions",))
    assert err.value.category == ErrorCategory.INVALID_INPUT
    assert "view_regions" in err.value.message
    with pytest.raises(CapabilityError) as err:
        tc.case_export_result(case_dir, _view(tmp_path), ("msl_regions",))
    assert "msl_regions" in err.value.message
    with pytest.raises(CapabilityError) as err:
        tc.case_export_result(case_dir, msl, ("bogus",))
    assert err.value.category == ErrorCategory.INVALID_INPUT
    with pytest.raises(CapabilityError) as err:
        tc.case_export_result(case_dir, str(tmp_path / "nope.msl"))
    assert err.value.category == ErrorCategory.NOT_FOUND


def test_export_with_real_heap_msl(case_dir, tmp_path):
    from tests.test_case_exporters import MslWriter, MslVasEntry, OSType, ArchType, sh
    heap = sh.glibc_heap()
    path = tmp_path / "h.msl"
    w = MslWriter(str(path), os_type=OSType.LINUX, arch_type=ArchType.X86_64, imported=True)
    vas = []
    for idx, (va, size, name) in enumerate(heap.regions):
        w.add_memory_region(va, heap.region_bytes(idx), protection=0x03)
        vas.append(MslVasEntry(va, size, 0x03, 0, name))
    w.add_vas_map(vas)
    w.add_end_of_capture()
    w.write()
    out = tc.case_export_result(case_dir, str(path)).payload
    assert "heap_chunks" in [e["table"] for e in out["exports"]] and out["skipped"] == []


def test_cli_export(case_dir, capsys, tmp_path):
    from tests import test_case_exporters as tce
    msl = tce._write_msl(tmp_path / "a.msl")
    rc, out = _cli(["export", "--case", case_dir, msl, "--what", "msl_regions",
                    "--what", "page_states", "--run-id", "cli1"], capsys)
    assert rc == 0
    payload = json.loads(out)
    assert [(e["table"], e["run_id"]) for e in payload["exports"]] == [
        ("msl_regions", "cli1"), ("msl_page_states", "cli1")]


def test_rest_export_submits_a_job(client, case_dir, tmp_path, monkeypatch):
    from types import SimpleNamespace
    submitted = []

    class Manager:
        artifact_store = SimpleNamespace(root=tmp_path / "tasks")

        def submit(self, *, kind, params, runner_dotted, stage_names=None):
            submitted.append((kind, params, runner_dotted))
            return SimpleNamespace(task_id="t" * 32, status=SimpleNamespace(value="pending"))

    monkeypatch.setattr("memdiver.api.routers.case.task_manager_or_503", lambda: Manager())
    r = client.post("/api/case/export", json={
        "case_dir": case_dir, "dump_path": "/x/a.msl", "what": ["msl_regions"]})
    assert r.status_code == 200 and r.json() == {"task_id": "t" * 32, "status": "pending"}
    kind, params, runner = submitted[0]
    assert params["job"] == "case_export" and params["args"]["what"] == ["msl_regions"]
    assert runner.endswith("image_task_runner.run_image_job")
    r = client.post("/api/case/export", json={"case_dir": case_dir, "dump_path": "x", "wat": 1})
    assert r.status_code == 422
    r = client.post("/api/case/export", json={"case_dir": "/etc/evil", "dump_path": "x"})
    assert r.status_code == 403


def test_runner_case_export_job_payload(case_dir, tmp_path):
    from memdiver.app.pipeline.image_task_runner import run_image_job
    from tests import test_case_exporters as tce
    msl = tce._write_msl(tmp_path / "a.msl")
    emitted = []
    ctx = SimpleNamespace(task_id="job1", emit=lambda *a, **k: emitted.append((a, k)))
    out = run_image_job({"job": "case_export", "task_root": str(tmp_path / "tasks"),
                         "args": {"case_dir": case_dir, "dump_path": msl,
                                  "what": ["page_states"]}}, ctx)
    assert out["summary"]["exports"][0]["table"] == "msl_page_states"
    assert out["artifacts"][0]["name"] == "image_result"


def test_mcp_case_export(tools, case_dir, tmp_path):
    from tests import test_case_exporters as tce
    msl = tce._write_msl(tmp_path / "a.msl")
    out = _mcp(tools, "case_export", case_dir=case_dir, dump_path=msl, what=["msl_regions"])
    assert out["exports"][0]["table"] == "msl_regions" and out["skipped"] == []
    out = _mcp(tools, "case_export", case_dir=case_dir, dump_path=msl, what=["view_regions"])
    assert "view_regions" in out["error"]
