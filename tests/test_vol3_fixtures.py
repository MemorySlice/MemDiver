"""Plugin fixtures (plan T2.8, D13): predicates, the store, the verdict producer, surfaces."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from memdiver.analysis.case import Case
from memdiver.analysis.fixture_predicates import evaluate_predicate, validate_predicate
from memdiver.analysis.fixture_store import FixtureStore
from memdiver.analysis.record import FIXTURE_VERDICT
from memdiver.analysis.record_store import AnalysisRecord
from memdiver.app import tools_vol3, tools_vol3_fixtures as fx
from memdiver.core.service_errors import CapabilityError, ErrorCategory
from memdiver.core.service_result import ServiceResult

CAPTURE = "c" * 64
ROWS = [{"COMM": "sshd", "PID": 22176}, {"COMM": "bash", "PID": 5}, {"COMM": "sshd", "PID": 9}]


def _ok(predicate, rows=ROWS):
    return evaluate_predicate(predicate, rows)["ok"]


# -- predicates ----------------------------------------------------------------

def test_row_count_predicates():
    assert _ok({"min_rows": 3}) and not _ok({"min_rows": 4})
    assert _ok({"max_rows": 3}) and not _ok({"max_rows": 2})


def test_row_where_counts_and_bounds():
    assert _ok({"row_where": {"COMM": "sshd", "PID": 22176}})
    assert not _ok({"row_where": {"COMM": "sshd", "PID": 99999}})
    assert _ok({"row_where": {"COMM": "sshd"}, "count_at_least": 2})
    assert not _ok({"row_where": {"COMM": "sshd"}, "count_at_least": 3})
    assert _ok({"row_where": {"COMM": "nginx"}, "count_at_most": 0})
    assert not _ok({"row_where": {"COMM": "sshd"}, "count_at_most": 1})
    assert _ok({"row_where": {"comm": "bash"}})            # column names fold case
    assert _ok({"row_where": {"PID": "5"}})                # text vs number compares by text


def test_column_all_and_any():
    assert _ok({"column_all": {"column": "PID", "op": ">=", "value": 0}})
    assert not _ok({"column_all": {"column": "PID", "op": ">", "value": 5}})
    assert _ok({"column_any": {"column": "COMM", "op": "contains", "value": "ash"}})
    missing = evaluate_predicate({"column_all": {"column": "NOPE", "op": "==", "value": 1}}, ROWS)
    assert not missing["ok"] and "not in the result" in missing["detail"]
    empty = evaluate_predicate({"column_all": {"column": "PID", "op": ">", "value": 0}}, [])
    assert not empty["ok"] and empty["detail"] == "no rows"   # never vacuously true


@pytest.mark.parametrize("bad", [
    {}, {"min_rows": 1, "max_rows": 2}, {"min_rows": -1}, {"min_rows": True},
    {"row_where": {}}, {"row_where": {"a": 1}, "bogus": 1},
    {"column_all": {"column": "a", "op": "~", "value": 1}}, {"column_all": {"column": "a"}},
    "min_rows", {"nope": 1}])
def test_malformed_predicates_are_refused(bad):
    with pytest.raises(ValueError):
        validate_predicate(bad)


# -- store ---------------------------------------------------------------------

@pytest.fixture
def case(tmp_path):
    return Case.init(tmp_path / "case")


def _put(case, name="f1", **kw):
    body = dict(plugin="linux.pslist", view_path="v.mdview",
                expect=[{"row_where": {"COMM": "sshd", "PID": 22176}}])
    body.update(kw)
    return fx.vol3_fixture_put_result(str(case.dir), name, **body).payload


def test_put_list_overwrite_keeps_history(case):
    first = _put(case)
    assert first["version"] == 1 and (case.dir / "fixtures" / "vol3" / "f1.json").is_file()
    second = _put(case, expect=[{"min_rows": 1}])
    assert second["version"] == 2
    assert len(list((case.dir / "fixtures" / "vol3" / "history").glob("f1-*.json"))) == 1
    listing = fx.vol3_fixture_list_result(str(case.dir)).payload
    assert listing["count"] == 1 and listing["fixtures"][0]["expect"] == [{"min_rows": 1}]


@pytest.mark.parametrize("kw,code", [
    ({"plugin": "", "source_name": None}, "fixture.bad_target"),
    ({"plugin": "linux.pslist", "source_name": "x"}, "fixture.bad_target"),
    ({"expect": []}, "fixture.bad_expect"),
    ({"expect": [{"min_rows": -1}]}, "fixture.bad_predicate"),
    ({"view_path": " "}, "fixture.view_required"),
    ({"source_name": "../x", "plugin": ""}, "plugin.bad_name"),
])
def test_bad_fixtures_are_refused(case, kw, code):
    with pytest.raises(CapabilityError) as exc:
        _put(case, **kw)
    assert exc.value.code == code


def test_bad_fixture_name_and_missing_fixture(case):
    with pytest.raises(CapabilityError) as exc:
        _put(case, name="a/b")
    assert exc.value.code == "fixture.bad_name"
    with pytest.raises(CapabilityError) as exc:
        FixtureStore(case.dir).get("nope")
    assert exc.value.category is ErrorCategory.NOT_FOUND


# -- run -----------------------------------------------------------------------

def _payload(rows, truncated=False, run_id=None):
    names = ["COMM", "PID"]
    return {"columns": [{"name": n} for n in names],
            "rows": [{"values": [r["COMM"], r["PID"]]} for r in rows],
            "row_count": len(rows), "truncated": truncated,
            "stop_reason": "timeout" if truncated else None, "run_id": run_id}


@pytest.fixture
def runner(monkeypatch):
    state = {"payload": _payload(ROWS), "calls": [], "raise": None}

    def fake(view_path, plugin, args=None, **kw):
        state["calls"].append(dict(view_path=view_path, plugin=plugin, args=args, **kw))
        if state["raise"]:
            raise state["raise"]
        return ServiceResult.ok(state["payload"])
    monkeypatch.setattr(tools_vol3, "vol3_run_result", fake)
    monkeypatch.setattr(fx, "_capture_id", lambda view: CAPTURE)
    return state


def _run(case, name="f1", **kw):
    return fx.vol3_fixture_run_result(str(case.dir), name, **kw).payload


def test_pass_records_a_fixture_verdict(case, runner):
    _put(case)
    out = _run(case)
    assert out["verdict"] == "pass" and out["recorded"] and out["capture_id"] == CAPTURE
    assert out["predicates"][0]["ok"] is True
    (entry,) = [e for e in AnalysisRecord(case.dir).entries(CAPTURE) if e.kind == FIXTURE_VERDICT]
    assert entry.id == out["entry_id"] and entry.payload["verdict"] == "pass"
    assert entry.payload["fixture"] == "f1" and entry.support == ()
    assert runner["calls"][0]["plugin"] == "linux.pslist" and runner["calls"][0]["case_dir"] is None


def test_fail_names_the_failed_predicate(case, runner):
    _put(case, expect=[{"min_rows": 1}, {"row_where": {"COMM": "sshd", "PID": 99999}}])
    out = _run(case)
    assert out["verdict"] == "fail"
    assert [p["ok"] for p in out["predicates"]] == [True, False]


def test_truncated_run_is_indeterminate_even_if_predicates_hold(case, runner):
    _put(case)
    runner["payload"] = _payload(ROWS, truncated=True)
    out = _run(case)
    assert out["verdict"] == "indeterminate" and "timeout" in out["reason"]
    assert out["predicates"][0]["ok"] is True


def test_unreadable_view_is_indeterminate_and_unrecorded(case, runner, monkeypatch):
    _put(case)
    runner["raise"] = CapabilityError("no such view", category=ErrorCategory.NOT_FOUND,
                                      code="view.missing")
    monkeypatch.setattr(fx, "_capture_id", lambda view: None)
    out = _run(case)
    assert out["verdict"] == "indeterminate" and out["reason_code"] == "view.missing"
    assert out["recorded"] is False and out["entry_id"] is None


def test_unexpected_error_category_propagates(case, runner):
    _put(case)
    runner["raise"] = CapabilityError("boom", category=ErrorCategory.INTERNAL, code="x")
    with pytest.raises(CapabilityError):
        _run(case)


def test_register_run_links_the_verdict_to_the_run(case, runner):
    _put(case)
    runner["payload"] = _payload(ROWS, run_id="run123")
    out = _run(case, register_run=True)
    assert runner["calls"][0]["case_dir"] == str(case.dir)
    (entry,) = [e for e in AnalysisRecord(case.dir).entries(CAPTURE) if e.kind == FIXTURE_VERDICT]
    assert [(s.kind, s.ref) for s in entry.support] == [("vol3_run", "run123")]
    assert out["run_id"] == "run123"


def test_stored_source_is_resolved_for_the_run(case, runner):
    from memdiver.analysis.plugin_store import PluginStore
    PluginStore(case.dir).put("mine", "# src\n")
    _put(case, plugin="", source_name="mine", args={"pid": [1]})
    _run(case)
    call = runner["calls"][0]
    assert call["source"] == "# src\n" and call["args"] == {"pid": [1]}


def test_view_override(case, runner):
    _put(case)
    out = _run(case, view_path="other.mdview")
    assert runner["calls"][0]["view_path"] == "other.mdview" and out["view_path"] == "other.mdview"


# -- surfaces ------------------------------------------------------------------

def test_cli_source_and_fixture_actions(case, runner, capsys, monkeypatch):
    from memdiver.app import tools_vol3_dev
    monkeypatch.setattr(tools_vol3_dev, "vol3_check_result",
                        lambda *a, **k: ServiceResult.ok({"ok": True}))
    from memdiver.cli import _build_parser, _cmd_vol3

    def cli(*argv):
        rc = _cmd_vol3(_build_parser().parse_args(["vol3", *argv]))
        return rc, capsys.readouterr().out
    src = case.dir.parent / "p.py"
    src.write_text("# p\n")
    rc, out = cli("source", "put", "p", "--case", str(case.dir), "--file", str(src))
    assert rc == 0 and json.loads(out)["stored"]["name"] == "p"
    assert json.loads(cli("source", "list", "--case", str(case.dir))[1])["count"] == 1
    assert json.loads(cli("source", "get", "p", "--case", str(case.dir))[1])["source"] == "# p\n"
    rc, out = cli("fixture", "put", "f", "--case", str(case.dir), "--view", "v.mdview",
                  "--plugin", "linux.pslist", "--expect", '{"min_rows": 1}')
    assert rc == 0 and json.loads(out)["expect"] == [{"min_rows": 1}]
    assert json.loads(cli("fixture", "list", "--case", str(case.dir))[1])["count"] == 1
    assert json.loads(cli("fixture", "run", "f", "--case", str(case.dir))[1])["verdict"] == "pass"
    assert cli("source")[0] == 1 and cli("fixture")[0] == 1


@pytest.fixture
def client(monkeypatch, tmp_path):
    from fastapi.testclient import TestClient

    from memdiver.api.config import get_settings
    from memdiver.api.main import create_app
    monkeypatch.delenv("MEMDIVER_ALLOWED_ROOTS", raising=False)
    monkeypatch.setenv("MEMDIVER_UPLOAD_DIR", str(tmp_path / "uploads"))
    monkeypatch.setenv("MEMDIVER_HOME", str(tmp_path / "home"))
    get_settings.cache_clear()
    yield TestClient(create_app())
    get_settings.cache_clear()


def test_rest_sources_and_fixtures(client, runner, tmp_path, monkeypatch):
    from memdiver.app import tools_vol3_dev
    monkeypatch.setattr(tools_vol3_dev, "vol3_check_result",
                        lambda *a, **k: ServiceResult.ok({"ok": True}))
    case = Case.init(tmp_path / "uploads" / "case")
    cd = str(case.dir)
    r = client.put("/api/vol3/sources/demo", json={"case_dir": cd, "source": "# s\n"})
    assert r.status_code == 200 and r.json()["check"] == {"ok": True}
    assert client.get("/api/vol3/sources", params={"case_dir": cd}).json()["count"] == 1
    assert client.get("/api/vol3/sources/demo", params={"case_dir": cd}).json()["source"] == "# s\n"
    assert client.get("/api/vol3/sources/none", params={"case_dir": cd}).status_code == 404
    assert client.put("/api/vol3/sources/a.b", json={"case_dir": cd, "source": "x"}).status_code == 400
    r = client.put("/api/vol3/fixtures/f", json={
        "case_dir": cd, "view_path": "v.mdview", "plugin": "linux.pslist",
        "expect": [{"min_rows": 1}]})
    assert r.status_code == 200 and r.json()["version"] == 1
    assert client.get("/api/vol3/fixtures", params={"case_dir": cd}).json()["count"] == 1
    r = client.post("/api/vol3/fixtures/f/run", json={"case_dir": cd})
    assert r.status_code == 200 and r.json()["verdict"] == "pass"
    assert client.put("/api/vol3/fixtures/g", json={
        "case_dir": cd, "view_path": "v", "expect": [{"min_rows": 1}],
        "bogus": 1}).status_code == 422


def test_rest_writes_outside_the_write_roots_are_refused(client, tmp_path):
    outside = str(tmp_path / "elsewhere")
    assert client.put("/api/vol3/sources/x", json={"case_dir": outside,
                                                   "source": "x"}).status_code == 403
    assert client.put("/api/vol3/fixtures/x", json={
        "case_dir": outside, "view_path": "v", "plugin": "p",
        "expect": [{"min_rows": 1}]}).status_code == 403
    assert client.post("/api/vol3/fixtures/x/run", json={"case_dir": outside}).status_code == 403
    assert not Path(outside).exists()


# -- real alma-9 image ---------------------------------------------------------

ALMA_VIEW = Path("/private/tmp/claude-501/-Users-danielbaier-research-projects-github-issues-"
                 "2024-fritap-issues-2026-success-memory-slice-git-MemDiver/"
                 "5bdc82f6-3f6f-4afb-b122-28de170adcc9/scratchpad/views/alma9_kernel.mdview")


@pytest.mark.skipif(not ALMA_VIEW.is_file(), reason="alma-9 kernel view not available")
def test_real_alma_pass_and_fail(case):
    pytest.importorskip("volatility3")
    _put(case, "alive", view_path=str(ALMA_VIEW),
         expect=[{"row_where": {"COMM": "sshd", "PID": 22176}}])
    _put(case, "ghost", view_path=str(ALMA_VIEW),
         expect=[{"row_where": {"COMM": "sshd", "PID": 99999}}])
    assert _run(case, "alive")["verdict"] == "pass"
    assert _run(case, "ghost")["verdict"] == "fail"


# -- last_verdict on list --------------------------------------------------------

def _file_verdict(case, fixture, verdict, created, capture=CAPTURE, supersedes=None):
    from memdiver.analysis.record import AnalysisEntry
    return AnalysisRecord(case.dir).append(AnalysisEntry(
        capture_id=capture, kind=FIXTURE_VERDICT, author="tool:vol3", created=created,
        payload={"fixture": fixture, "verdict": verdict}, supersedes=supersedes))


def _listed(case, name="f1"):
    got = fx.vol3_fixture_list_result(str(case.dir)).payload["fixtures"]
    return next(f for f in got if f["name"] == name)


def test_last_verdict_none_without_runs(case):
    _put(case)
    assert _listed(case)["last_verdict"] is None


def test_last_verdict_from_a_real_run(case, runner):
    _put(case)
    out = _run(case)
    assert _listed(case)["last_verdict"] == {
        "verdict": "pass", "created": _listed(case)["last_verdict"]["created"],
        "entry_id": out["entry_id"], "capture_id": CAPTURE}


def test_last_verdict_is_newest_across_captures_and_fixtures(case):
    _put(case)
    _put(case, "f2")
    _file_verdict(case, "f1", "fail", "2026-01-01T00:00:00Z")
    newest = _file_verdict(case, "f1", "pass", "2026-03-01T00:00:00Z", capture="d" * 64)
    _file_verdict(case, "f1", "fail", "2026-02-01T00:00:00Z")
    _file_verdict(case, "f2", "fail", "2026-04-01T00:00:00Z")
    last = _listed(case)["last_verdict"]
    assert last["entry_id"] == newest.id and last["verdict"] == "pass"
    assert last["capture_id"] == "d" * 64
    assert _listed(case, "f2")["last_verdict"]["verdict"] == "fail"


def test_last_verdict_ignores_retracted(case):
    from memdiver.analysis.record import RETRACTION, AnalysisEntry
    _put(case)
    old = _file_verdict(case, "f1", "pass", "2026-01-01T00:00:00Z")
    new = _file_verdict(case, "f1", "fail", "2026-02-01T00:00:00Z")
    AnalysisRecord(case.dir).append(AnalysisEntry(
        capture_id=CAPTURE, kind=RETRACTION, author="human", supersedes=new.id))
    assert _listed(case)["last_verdict"]["entry_id"] == old.id
