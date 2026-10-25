"""T3.7: detector fixtures (YARA rules / key finders) — verdicts, store, four surfaces."""
from __future__ import annotations

import json

import pytest

from memdiver.analysis.case import Case
from memdiver.analysis.detector_fixtures_bundled import aes_schedule_fixtures
from memdiver.app import tools_detector_fixtures as tdf
from memdiver.core.service_errors import CapabilityError

RULE = "rule demo_rule { strings: $a = { de ad be ef } condition: $a }"
HIT = {"name": "hit", "sample": {"hex": "00000000deadbeef00"},
       "expect": {"matches": [{"offset": 4, "length": 4, "label": "demo_rule"}]}}
MISS = {"name": "miss", "sample": {"hex": "00" * 8}, "expect": {"no_match": True}}


def _run(kind, artifact, **kw):
    return tdf.detector_fixtures_run_result(kind, artifact, **kw).payload


# -- key finders --------------------------------------------------------------


def test_bundled_aes_fixtures_cover_layouts_and_decoys():
    names = {f["name"] for f in aes_schedule_fixtures()}
    assert {"aes128_forward", "aes128_inverse_layout", "aes128_swapped32",
            "decoy_zeros", "decoy_fill_09", "decoy_corrupted_schedule"} <= names


def test_aes_fixtures_all_pass():
    out = _run("keyfinder", "aes_schedule")
    assert out["verdict"] == "pass" and out["counts"]["fail"] == 0
    assert out["counts"]["total"] == len(aes_schedule_fixtures())
    assert all(r["source"] == "bundled" for r in out["results"])


def test_broken_finder_params_fail_the_positives_not_the_decoys():
    out = _run("keyfinder", "aes_schedule", params={"aes_min_confidence": 1.1})
    assert out["verdict"] == "fail"
    failed = {r["fixture"] for r in out["results"] if r["verdict"] == "fail"}
    assert failed == {"aes128_forward", "aes128_inverse_layout", "aes128_swapped32",
                      "aes256_forward"}
    assert all(r["missing"] for r in out["results"] if r["verdict"] == "fail")


def test_restricted_layout_fails_only_the_other_layout():
    out = _run("keyfinder", "aes_schedule",
               params={"aes_byte_orders": ["natural"], "aes_orientations": ["forward"]})
    failed = {r["fixture"] for r in out["results"] if r["verdict"] == "fail"}
    assert failed == {"aes128_inverse_layout", "aes128_swapped32"}


def test_a_decoy_that_matches_is_a_failure_with_unexpected_rows():
    schedule_hex = next(f for f in aes_schedule_fixtures()
                        if f["name"] == "aes128_forward")["sample"]["hex"]
    out = _run("keyfinder", "aes_schedule",
               fixtures=[{"name": "bad_decoy", "sample": {"hex": schedule_hex},
                          "expect": {"no_match": True}}])
    assert out["verdict"] == "fail" and out["results"][0]["unexpected"][0]["offset"] == 37


def test_unknown_finder_is_invalid_input():
    with pytest.raises(CapabilityError):
        _run("keyfinder", "nope")


def test_finder_without_fixtures_is_indeterminate_never_pass():
    out = _run("keyfinder", "pem_scan")
    assert out["verdict"] == "indeterminate" and out["reason_code"] == "no_fixtures"
    assert out["results"] == []


# -- YARA ---------------------------------------------------------------------


def test_yara_inline_fixtures_pass():
    out = _run("yara", RULE, fixtures=[HIT, MISS])
    assert out["verdict"] == "pass" and out["counts"] == {"pass": 2, "fail": 0,
                                                          "indeterminate": 0, "total": 2}


def test_yara_wrong_offset_fails_and_names_the_gap():
    wrong = {**HIT, "name": "wrong", "expect": {"matches": [{"offset": 5}]}}
    out = _run("yara", RULE, fixtures=[wrong])
    assert out["verdict"] == "fail"
    assert out["results"][0]["missing"] and out["results"][0]["unexpected"]


def test_yara_rule_that_fires_on_a_decoy_fails():
    decoy = {"name": "d", "sample": {"hex": "deadbeef"}, "expect": {"no_match": True}}
    assert _run("yara", RULE, fixtures=[decoy])["verdict"] == "fail"


def test_yara_without_fixtures_is_indeterminate():
    out = _run("yara", RULE)
    assert out["verdict"] == "indeterminate" and out["reason_code"] == "no_fixtures"


def test_yara_compile_error_is_a_failure():
    out = _run("yara", "rule broken {")
    assert out["verdict"] == "fail" and out["reason_code"] == "yara.compile_failed"


def test_yara_fixture_naming_a_missing_rule_fails():
    out = _run("yara", RULE, fixtures=[{**HIT, "artifact": "other_rule"}])
    assert out["verdict"] == "fail" and out["results"][0]["reason_code"] == "yara.rule_missing"


# -- samples ------------------------------------------------------------------


def test_capture_range_sample_reads_the_file(tmp_path):
    dump = tmp_path / "flat.raw"
    dump.write_bytes(b"\x00" * 10 + bytes.fromhex("deadbeef") + b"\x00" * 10)
    fixture = {"name": "cap", "sample": {"dump_path": str(dump), "offset": 8, "length": 10},
               "expect": {"matches": [{"offset": 2}]}}
    assert _run("yara", RULE, fixtures=[fixture])["verdict"] == "pass"


def test_capture_range_past_the_end_is_indeterminate_not_a_pass(tmp_path):
    dump = tmp_path / "flat.raw"
    dump.write_bytes(b"\x00" * 16)
    fixture = {"name": "cap", "sample": {"dump_path": str(dump), "offset": 8, "length": 64},
               "expect": {"no_match": True}}
    out = _run("yara", RULE, fixtures=[fixture])
    assert out["verdict"] == "indeterminate"
    assert out["results"][0]["reason_code"] == "detector_fixture.sample_padded"


def test_missing_capture_is_indeterminate(tmp_path):
    fixture = {"name": "cap", "sample": {"dump_path": str(tmp_path / "gone"), "offset": 0,
                                         "length": 4}, "expect": {"no_match": True}}
    assert _run("yara", RULE, fixtures=[fixture])["verdict"] == "indeterminate"


@pytest.mark.parametrize("sample,expect", [
    ({"hex": "zz"}, {"no_match": True}),
    ({"hex": "00", "base64": "AA=="}, {"no_match": True}),
    ({"hex": "00"}, {"matches": []}),
    ({"hex": "00"}, {"no_match": True, "matches": [{"offset": 0}]}),
    ({"hex": "00"}, {"matches": [{"offset": -1}]}),
    ({"hex": "00"}, {"matches": [{"offset": 0, "bogus": 1}]}),
])
def test_invalid_fixture_definitions_are_rejected(tmp_path, sample, expect):
    case = Case.init(tmp_path / "case")
    with pytest.raises(CapabilityError):
        tdf.detector_fixtures_add_result(str(case.dir), "bad", "keyfinder", "aes_schedule",
                                         sample, expect)


# -- store + last_verdict -----------------------------------------------------


@pytest.fixture
def case_dir(tmp_path):
    return str(Case.init(tmp_path / "case").dir)


def test_stored_fixture_is_selected_run_and_its_verdict_recorded(case_dir):
    tdf.detector_fixtures_add_result(case_dir, "my_hit", "yara", "demo_rule", HIT["sample"],
                                     HIT["expect"])
    out = _run("yara", RULE, case_dir=case_dir)
    assert out["verdict"] == "pass" and out["recorded"] and out["results"][0]["source"] == "stored"
    listed = tdf.detector_fixtures_list_result(case_dir, "yara").payload
    row = next(r for r in listed["fixtures"] if r["name"] == "my_hit")
    assert row["last_verdict"]["verdict"] == "pass" and row["version"] == 1


def test_overwrite_archives_and_remove_retires_without_losing(case_dir, tmp_path):
    add = lambda expect: tdf.detector_fixtures_add_result(  # noqa: E731
        case_dir, "f", "yara", "demo_rule", HIT["sample"], expect).payload
    add(HIT["expect"])
    assert add({"matches": [{"offset": 4}]})["version"] == 2
    tdf.detector_fixtures_remove_result(case_dir, "f")
    history = list((tmp_path / "case" / "fixtures" / "detectors" / "history").glob("f-*.json"))
    assert len(history) == 2
    assert tdf.detector_fixtures_list_result(case_dir, "yara").payload["count"] == 0
    with pytest.raises(CapabilityError):
        tdf.detector_fixtures_remove_result(case_dir, "f")


def test_stored_broken_fixture_turns_the_verdict_to_fail(case_dir):
    tdf.detector_fixtures_add_result(case_dir, "wrong", "yara", "demo_rule", HIT["sample"],
                                     {"matches": [{"offset": 0}]})
    assert _run("yara", RULE, case_dir=case_dir)["verdict"] == "fail"
    row = next(r for r in tdf.detector_fixtures_list_result(case_dir).payload["fixtures"]
               if r["name"] == "wrong")
    assert row["last_verdict"]["verdict"] == "fail"


def test_a_bundled_name_is_reserved(case_dir):
    with pytest.raises(CapabilityError):
        tdf.detector_fixtures_add_result(case_dir, "decoy_zeros", "keyfinder", "aes_schedule",
                                         {"hex": "00"}, {"no_match": True})


def test_list_without_case_is_bundled_only():
    out = tdf.detector_fixtures_list_result().payload
    assert out["count"] == len(aes_schedule_fixtures())
    assert all(r["source"] == "bundled" and r["last_verdict"] is None for r in out["fixtures"])


# -- four surfaces ------------------------------------------------------------


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


@pytest.fixture(scope="module")
def mcp_tools():
    pytest.importorskip("mcp")
    from memdiver.mcp_server.server import create_server
    return {t.name: t for t in create_server()._tool_manager.list_tools()}


def _cli(argv, capsys):
    from memdiver.cli import _build_parser, _cmd_fixtures
    rc = _cmd_fixtures(_build_parser().parse_args(["fixtures", *argv]))
    return rc, capsys.readouterr().out


def test_run_parity_across_four_surfaces(client, mcp_tools, capsys):
    expected = json.loads(json.dumps(_run("keyfinder", "aes_schedule")))
    rc, out = _cli(["run", "--kind", "keyfinder", "aes_schedule"], capsys)
    assert rc == 0 and json.loads(out) == expected
    r = client.post("/api/detector-fixtures/run",
                    json={"artifact_kind": "keyfinder", "artifact": "aes_schedule"})
    assert r.status_code == 200 and r.json() == expected
    mcp = mcp_tools["detector_fixtures_run"].fn(artifact_kind="keyfinder", artifact="aes_schedule")
    assert json.loads(mcp) == expected


def test_cli_exit_code_follows_the_verdict(tmp_path, capsys):
    rule = tmp_path / "r.yar"
    rule.write_text(RULE)
    rc, out = _cli(["run", "--kind", "yara", str(rule)], capsys)
    assert rc == 2 and json.loads(out)["reason_code"] == "no_fixtures"
    rc, _ = _cli(["run", "--kind", "keyfinder", "aes_schedule", "--params",
                  '{"aes_min_confidence": 1.1}'], capsys)
    assert rc == 1


def test_cli_add_list_remove_roundtrip(case_dir, capsys):
    rc, _ = _cli(["add", "cli_hit", "--kind", "yara", "--case", case_dir, "--artifact",
                  "demo_rule", "--sample-hex", "00000000deadbeef",
                  "--expect", '{"matches": [{"offset": 4}]}'], capsys)
    assert rc == 0
    _, out = _cli(["list", "--case", case_dir, "--kind", "yara"], capsys)
    assert [f["name"] for f in json.loads(out)["fixtures"]] == ["cli_hit"]
    _cli(["remove", "cli_hit", "--case", case_dir], capsys)
    _, out = _cli(["list", "--case", case_dir, "--kind", "yara"], capsys)
    assert json.loads(out)["count"] == 0


def test_cli_without_action_prints_usage(capsys):
    from memdiver.cli import _build_parser, _cmd_fixtures
    assert _cmd_fixtures(_build_parser().parse_args(["fixtures"])) == 1


def test_rest_add_list_run_remove_and_strict_fields(client, tmp_path):
    case_dir = str(Case.init(tmp_path / "uploads" / "case").dir)
    body = {"case_dir": case_dir, "artifact_kind": "yara", "artifact": "demo_rule",
            "sample": HIT["sample"], "expect": HIT["expect"]}
    assert client.put("/api/detector-fixtures/rest_hit", json=body).status_code == 200
    listed = client.get("/api/detector-fixtures", params={"case_dir": case_dir,
                                                          "artifact_kind": "yara"}).json()
    assert [f["name"] for f in listed["fixtures"]] == ["rest_hit"]
    run = client.post("/api/detector-fixtures/run", json={
        "artifact_kind": "yara", "artifact": RULE, "case_dir": case_dir}).json()
    assert run["verdict"] == "pass"
    assert client.delete("/api/detector-fixtures/rest_hit",
                         params={"case_dir": case_dir}).json()["removed"] is True
    assert client.put("/api/detector-fixtures/x", json={**body, "bogus": 1}).status_code == 422
    assert client.post("/api/detector-fixtures/run", json={
        "artifact_kind": "keyfinder", "artifact": "nope"}).status_code == 400


def test_mcp_add_list_remove(mcp_tools, case_dir):
    added = json.loads(mcp_tools["detector_fixtures_add"].fn(
        case_dir=case_dir, name="m", artifact_kind="yara", artifact="demo_rule",
        sample=HIT["sample"], expect=HIT["expect"]))
    assert added["name"] == "m"
    listed = json.loads(mcp_tools["detector_fixtures_list"].fn(case_dir=case_dir,
                                                               artifact_kind="yara"))
    assert listed["count"] == 1
    assert json.loads(mcp_tools["detector_fixtures_remove"].fn(case_dir=case_dir,
                                                               name="m"))["removed"]


# -- verdict namespaces -------------------------------------------------------


def _last(case_dir, name):
    rows = tdf.detector_fixtures_list_result(case_dir).payload["fixtures"]
    return next(r for r in rows if r["name"] == name)["last_verdict"]


def test_inline_run_never_overwrites_a_stored_fixtures_last_verdict(case_dir):
    tdf.detector_fixtures_add_result(case_dir, "inline_0", "yara", "demo_rule", HIT["sample"],
                                     HIT["expect"])
    _run("yara", RULE, case_dir=case_dir)
    assert _last(case_dir, "inline_0")["verdict"] == "pass"
    bad = {"sample": HIT["sample"], "expect": {"matches": [{"offset": 0}]}}
    out = _run("yara", RULE, case_dir=case_dir, fixtures=[bad])
    assert out["verdict"] == "fail" and out["recorded"] is False
    assert _last(case_dir, "inline_0")["verdict"] == "pass"


def test_params_override_run_never_overwrites_stored_verdicts(case_dir):
    forward = next(f for f in aes_schedule_fixtures() if f["name"] == "aes128_forward")
    tdf.detector_fixtures_add_result(case_dir, "mine", "keyfinder", "aes_schedule",
                                     forward["sample"], forward["expect"])
    _run("keyfinder", "aes_schedule", case_dir=case_dir)
    assert _last(case_dir, "mine")["verdict"] == "pass"
    _run("keyfinder", "aes_schedule", case_dir=case_dir, params={"aes_min_confidence": 1.1})
    assert _last(case_dir, "mine")["verdict"] == "pass"


def test_overall_verdict_cannot_collide_with_a_fixture_name(case_dir):
    tdf.detector_fixtures_add_result(case_dir, "overall_keyfinder_aes_schedule", "yara",
                                     "demo_rule", HIT["sample"], HIT["expect"])
    _run("keyfinder", "aes_schedule", case_dir=case_dir)
    assert _last(case_dir, "overall_keyfinder_aes_schedule") is None
    from memdiver.analysis.detector_fixture_store import DetectorFixtureStore
    assert "overall_keyfinder_aes_schedule" in DetectorFixtureStore(case_dir).overall_verdicts()
