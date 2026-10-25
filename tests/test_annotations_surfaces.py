"""The ``annotations.*`` capabilities on all four surfaces (plan T1.5).

Producer, CLI (real argv through the top-level parser), REST (real JSON bodies
over TestClient) and MCP (registered tool functions) must agree on one record.
"""
from __future__ import annotations

import json

import pytest

from memdiver.app import tools_annotations as ta
from memdiver.core.service_errors import CapabilityError, ErrorCategory

CAP = "b" * 64
LOC = {"space": "physical", "value": 4096}


@pytest.fixture
def case(tmp_path):
    return str(tmp_path / "case")


# -- producers -------------------------------------------------------------------


def test_producer_add_list_supersede_retract(case):
    added = ta.annotations_add_result(
        case, CAP, "annotation", "human", [LOC], "k", {"n": 1},
        [{"kind": "oracle", "ref": "gocryptfs"}], 32).payload["entry"]
    assert added["locations"] == [LOC] and added["length"] == 32
    sup = ta.annotations_supersede_result(case, CAP, added["id"], "agent",
                                          label="k2").payload
    assert sup["supersedes"] == added["id"]
    assert sup["entry"]["label"] == "k2"
    assert sup["entry"]["payload"] == {"n": 1}  # inherited
    listed = ta.annotations_list_result(case, CAP).payload
    assert [e["id"] for e in listed["entries"]] == [sup["entry"]["id"]]
    ta.annotations_retract_result(case, CAP, sup["entry"]["id"], "human", "oops")
    assert ta.annotations_list_result(case, CAP).payload["count"] == 0
    everything = ta.annotations_list_result(case, CAP, include_superseded=True).payload
    assert everything["count"] == 3
    assert [e["superseded"] for e in everything["entries"]] == [True, True, False]


@pytest.mark.parametrize("call", [
    lambda c: ta.annotations_add_result("", CAP, "annotation", "human"),
    lambda c: ta.annotations_add_result(c, CAP, "annotation", "robot"),
    lambda c: ta.annotations_add_result(c, CAP, "retraction", "human"),
    lambda c: ta.annotations_add_result(c, CAP, "annotation", "human", [{"space": "bogus", "value": 1}]),
    lambda c: ta.annotations_add_result(c, CAP, "annotation", "human", [{"space": "process_va", "value": 1}]),
    lambda c: ta.annotations_add_result(c, CAP, "annotation", "human", support=[{"kind": "x"}]),
    lambda c: ta.annotations_supersede_result(c, CAP, "x", "human", author_x=1),
])
def test_producer_bad_input_is_capability_error(case, call):
    with pytest.raises(CapabilityError) as err:
        call(case)
    assert err.value.category is ErrorCategory.INVALID_INPUT


def test_producer_unknown_entry_not_found(case):
    with pytest.raises(CapabilityError) as err:
        ta.annotations_retract_result(case, CAP, "nope", "human")
    assert err.value.category is ErrorCategory.NOT_FOUND


# -- CLI -------------------------------------------------------------------------


def _cli(argv, capsys):
    from memdiver.cli import _build_parser, _cmd_annotations
    args = _build_parser().parse_args(["annotations", *argv])
    rc = _cmd_annotations(args)
    return rc, capsys.readouterr().out


def test_cli_round_trip(case, capsys):
    rc, out = _cli(["add", "--case", case, "--capture", CAP, "--label", "hi",
                    "--location", json.dumps(LOC), "--payload", '{"a": 1}',
                    "--support", "oracle:gocryptfs", "--length", "0x20"], capsys)
    assert rc == 0
    entry = json.loads(out)["entry"]
    assert entry["length"] == 32 and entry["support"] == [{"kind": "oracle", "ref": "gocryptfs"}]
    _, out = _cli(["supersede", "--case", case, "--capture", CAP,
                   "--entry", entry["id"], "--label", "bye"], capsys)
    new = json.loads(out)["entry"]
    assert new["label"] == "bye" and new["payload"] == {"a": 1}
    _, out = _cli(["list", "--case", case, "--capture", CAP], capsys)
    assert [e["id"] for e in json.loads(out)["entries"]] == [new["id"]]
    _, out = _cli(["retract", "--case", case, "--capture", CAP, "--entry", new["id"],
                   "--reason", "no"], capsys)
    assert json.loads(out)["retracted"] == new["id"]
    _, out = _cli(["list", "--case", case, "--capture", CAP], capsys)
    assert json.loads(out)["count"] == 0


def test_cli_requires_case_and_reports_errors(case, capsys):
    from memdiver.cli import _build_parser
    with pytest.raises(SystemExit):
        _build_parser().parse_args(["annotations", "list", "--capture", CAP])
    with pytest.raises(CapabilityError):
        _cli(["retract", "--case", case, "--capture", CAP, "--entry", "nope"], capsys)


def test_cli_no_action_returns_1(capsys):
    from memdiver.cli import _build_parser, _cmd_annotations
    assert _cmd_annotations(_build_parser().parse_args(["annotations"])) == 1


# -- REST ------------------------------------------------------------------------


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


def test_rest_round_trip_with_real_json_bodies(client, tmp_path):
    case = str(tmp_path / "uploads" / "case1")
    r = client.post("/api/annotations/add", json={
        "case_dir": case, "capture_id": CAP, "author": "agent", "label": "k",
        "locations": [LOC], "payload": {"a": [1, 2]},
        "support": [{"kind": "pcap", "ref": "x.pcap"}], "length": 16})
    assert r.status_code == 200, r.text
    entry = r.json()["entry"]
    r = client.post("/api/annotations/supersede", json={
        "case_dir": case, "capture_id": CAP, "entry_id": entry["id"], "label": "k2"})
    assert r.status_code == 200, r.text
    new = r.json()["entry"]
    assert new["payload"] == {"a": [1, 2]} and new["author"] == "human"
    r = client.get("/api/annotations", params={"case_dir": case, "capture_id": CAP})
    assert [e["id"] for e in r.json()["entries"]] == [new["id"]]
    r = client.post("/api/annotations/retract", json={
        "case_dir": case, "capture_id": CAP, "entry_id": new["id"], "reason": "r"})
    assert r.json()["retracted"] == new["id"]
    r = client.get("/api/annotations", params={
        "case_dir": case, "capture_id": CAP, "include_superseded": "true"})
    assert r.json()["count"] == 3


def test_rest_errors_use_global_handler_status(client, tmp_path):
    case = str(tmp_path / "uploads" / "c")
    r = client.post("/api/annotations/retract", json={
        "case_dir": case, "capture_id": CAP, "entry_id": "nope"})
    assert r.status_code == 404 and r.json()["category"] == "NOT_FOUND"
    r = client.post("/api/annotations/add", json={
        "case_dir": case, "capture_id": CAP, "author": "robot"})
    assert r.status_code == 400
    r = client.post("/api/annotations/add", json={"capture_id": CAP})
    assert r.status_code == 422


def test_rest_write_outside_roots_is_refused(client, tmp_path):
    outside = tmp_path / "elsewhere"
    r = client.post("/api/annotations/add", json={
        "case_dir": str(outside), "capture_id": CAP})
    assert r.status_code == 403
    assert not outside.exists()
    r = client.post("/api/annotations/add", json={
        "case_dir": str(tmp_path / "uploads" / ".." / "elsewhere"), "capture_id": CAP})
    assert r.status_code == 403


def test_rest_read_sandbox_applies_to_case_dir(client, monkeypatch, tmp_path):
    from memdiver.api.config import get_settings
    allowed = tmp_path / "allowed"
    allowed.mkdir()
    monkeypatch.setenv("MEMDIVER_ALLOWED_ROOTS", str(allowed))
    get_settings.cache_clear()
    r = client.get("/api/annotations", params={
        "case_dir": str(tmp_path / "other"), "capture_id": CAP})
    assert r.status_code == 403


# -- MCP -------------------------------------------------------------------------


@pytest.fixture(scope="module")
def tools():
    pytest.importorskip("mcp")
    from memdiver.mcp_server.server import create_server
    return {t.name: t for t in create_server()._tool_manager.list_tools()}


def _mcp(tools, name, **kw):
    return json.loads(tools[name].fn(**kw))


def test_mcp_round_trip_matches_producer(tools, case):
    added = _mcp(tools, "annotations_add", case_dir=case, capture_id=CAP,
                 locations=[LOC], label="m", payload={"z": 1})["entry"]
    assert added["author"] == "agent"
    new = _mcp(tools, "annotations_supersede", case_dir=case, capture_id=CAP,
               entry_id=added["id"], label="m2")["entry"]
    listed = _mcp(tools, "annotations_list", case_dir=case, capture_id=CAP)
    assert listed == ta.annotations_list_result(case, CAP).payload
    assert [e["id"] for e in listed["entries"]] == [new["id"]]
    _mcp(tools, "annotations_retract", case_dir=case, capture_id=CAP, entry_id=new["id"])
    assert _mcp(tools, "annotations_list", case_dir=case, capture_id=CAP)["count"] == 0


def test_mcp_errors_are_structured_bodies(tools, case):
    body = _mcp(tools, "annotations_retract", case_dir=case, capture_id=CAP, entry_id="nope")
    assert "error" in body
    body = _mcp(tools, "annotations_add", case_dir=case, capture_id=CAP, author="robot")
    assert "error" in body


def test_rest_add_rejects_a_misspelled_field(client, tmp_path):
    """A wrong wire name must be a 422, never silently dropped into a default."""
    case = str(tmp_path / "uploads" / "case1")
    r = client.post("/api/annotations/add", json={
        "case_dir": case, "capture_id": CAP, "kind": "annotation",
        "locations": [], "lable": "typo"})
    assert r.status_code == 422
