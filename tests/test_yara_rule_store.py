"""Stored YARA rules: the store, the producers, and the four surfaces.

Every test runs against an isolated MemDiver home (``XDG_DATA_HOME``) so the library never
touches the developer's real ``~/.memdiver``.
"""
from __future__ import annotations

import json
import os

import pytest

from memdiver.analysis.yara_rule_store import RULES_DIR, YaraRuleStore
from memdiver.app import tools_yara as ty
from memdiver.app import tools_yara_rules as tr
from memdiver.core.service_errors import CapabilityError, ErrorCategory

NEEDLE = b"SSLKEYLOGFILE"
RULE = 'rule keylog { strings: $a = "SSLKEYLOGFILE" condition: $a }'
RULE_V2 = 'rule keylog2 { strings: $a = "SSLKEYLOGFILE" condition: $a }'
BAD = "rule broken {\n  condition: $nope\n}"


@pytest.fixture(autouse=True)
def home(monkeypatch, tmp_path):
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "xdg"))
    return tmp_path / "xdg" / "memdiver"


@pytest.fixture
def case(tmp_path):
    path = tmp_path / "case"
    path.mkdir()
    os.chmod(path, 0o700)
    return str(path)


@pytest.fixture
def raw_dump(tmp_path):
    path = tmp_path / "flat.bin"
    path.write_bytes(bytes(range(1, 200)) + NEEDLE + bytes(range(1, 100)) + NEEDLE + b"\x01" * 50)
    return str(path)


def _code(exc) -> str:
    return exc.value.code


# -- store ---------------------------------------------------------------------------


def test_put_get_list_delete_roundtrip(tmp_path):
    store = YaraRuleStore(tmp_path)
    meta = store.put("keylog", RULE, {"valid": True, "rule_names": ["keylog"], "errors": []})
    assert meta["version"] == 1 and meta["compiles"] is True
    got = store.get("keylog")
    assert got["source"] == RULE and got["modified_externally"] is False
    assert got["rule_names"] == ["keylog"]
    assert [r["name"] for r in store.list()] == ["keylog"] and "source" not in store.list()[0]
    out = store.delete("keylog")
    assert out["deleted"] is True and store.list() == []
    with pytest.raises(CapabilityError) as exc:
        store.get("keylog")
    assert exc.value.category is ErrorCategory.NOT_FOUND


def test_overwrite_versions_and_archives_history(tmp_path):
    store = YaraRuleStore(tmp_path)
    store.put("r", RULE)
    meta = store.put("r", RULE_V2)
    assert meta["version"] == 2
    history = list((tmp_path / RULES_DIR / "history").glob("r-*.yar"))
    assert [h.read_text() for h in history] == [RULE]


def test_delete_archives_instead_of_hard_deleting(tmp_path):
    store = YaraRuleStore(tmp_path)
    store.put("r", RULE)
    store.delete("r")
    assert not (tmp_path / RULES_DIR / "r.yar").exists()
    assert [h.read_text() for h in (tmp_path / RULES_DIR / "history").glob("r-*.yar")] == [RULE]


@pytest.mark.parametrize("name", ["../x", "a/b", "a.b", "", "1abc", "x" * 65])
def test_bad_names_are_rejected(tmp_path, name):
    store = YaraRuleStore(tmp_path)
    for call in (lambda: store.put(name, RULE), lambda: store.get(name),
                 lambda: store.delete(name)):
        with pytest.raises(CapabilityError) as exc:
            call()
        assert exc.value.category is ErrorCategory.INVALID_INPUT


def test_symlinked_rule_file_is_refused(tmp_path):
    store = YaraRuleStore(tmp_path)
    store.put("r", RULE)
    target = tmp_path / "secret.yar"
    target.write_text("rule s { condition: true }")
    live = tmp_path / RULES_DIR / "r.yar"
    live.unlink()
    live.symlink_to(target)
    with pytest.raises(CapabilityError) as exc:
        store.get("r")
    assert exc.value.code == "store.symlink"
    assert store.list() == []


def test_symlinked_directory_leaving_root_is_refused(tmp_path):
    outside = tmp_path / "outside"
    outside.mkdir()
    root = tmp_path / "root"
    root.mkdir()
    (root / RULES_DIR).symlink_to(outside)
    with pytest.raises(CapabilityError):
        YaraRuleStore(root).put("r", RULE)
    assert list(outside.iterdir()) == []


def test_size_cap_and_empty_source(tmp_path):
    store = YaraRuleStore(tmp_path)
    with pytest.raises(CapabilityError) as exc:
        store.put("r", "x" * (256 * 1024 + 1))
    assert exc.value.code == "yara_rule.too_large"
    with pytest.raises(CapabilityError):
        store.put("r", "  ")


def test_modified_externally_on_hash_drift(tmp_path):
    store = YaraRuleStore(tmp_path)
    store.put("r", RULE, {"valid": True, "rule_names": ["keylog"]})
    (tmp_path / RULES_DIR / "r.yar").write_text(RULE_V2)
    got = store.get("r")
    assert got["modified_externally"] is True and got["compiles"] is None
    assert got["source"] == RULE_V2


# -- producers: scopes ---------------------------------------------------------------


def test_put_library_lands_in_the_isolated_home(home):
    out = tr.yara_rule_put_result("keylog", RULE).payload
    assert out["stored"]["scope"] == "library" and out["check"]["valid"] is True
    assert (home / RULES_DIR / "keylog.yar").read_text() == RULE
    assert out["stored"]["rule_names"] == ["keylog"]


def test_non_compiling_draft_is_saved_and_flagged():
    out = tr.yara_rule_put_result("draft", BAD).payload
    assert out["stored"]["compiles"] is False and out["stored"]["errors"]
    assert out["check"]["valid"] is False
    row = tr.yara_rule_get_result("draft").payload
    assert row["compiles"] is False and row["source"] == BAD


def test_case_scope_needs_case_dir_and_existing_case(tmp_path):
    with pytest.raises(CapabilityError) as exc:
        tr.yara_rule_put_result("r", RULE, "case")
    assert _code(exc) == "yara_rule.case_required"
    with pytest.raises(CapabilityError) as exc:
        tr.yara_rule_put_result("r", RULE, "case", str(tmp_path / "nope"))
    assert exc.value.category is ErrorCategory.NOT_FOUND
    with pytest.raises(CapabilityError) as exc:
        tr.yara_rule_put_result("r", RULE, "galaxy")
    assert _code(exc) == "yara_rule.bad_scope"


def test_get_prefers_case_then_falls_back_to_library(case):
    tr.yara_rule_put_result("shared", RULE)
    tr.yara_rule_put_result("shared", RULE_V2, "case", case)
    tr.yara_rule_put_result("only_lib", RULE)
    assert tr.yara_rule_get_result("shared").payload["scope"] == "library"
    case_hit = tr.yara_rule_get_result("shared", case).payload
    assert case_hit["scope"] == "case" and case_hit["source"] == RULE_V2
    assert tr.yara_rule_get_result("only_lib", case).payload["scope"] == "library"
    with pytest.raises(CapabilityError) as exc:
        tr.yara_rule_get_result("missing", case)
    assert exc.value.category is ErrorCategory.NOT_FOUND


def test_list_marks_shadowing(case):
    tr.yara_rule_put_result("shared", RULE)
    tr.yara_rule_put_result("shared", RULE_V2, "case", case)
    tr.yara_rule_put_result("only_lib", RULE)
    rows = {(r["scope"], r["name"]): r for r in tr.yara_rule_list_result(case).payload["rules"]}
    assert rows[("case", "shared")]["shadows"] is True
    assert rows[("library", "shared")]["shadowed"] is True
    assert rows[("library", "only_lib")]["shadowed"] is False
    assert [r["scope"] for r in tr.yara_rule_list_result().payload["rules"]] == ["library"] * 2


def test_delete_by_scope(case):
    tr.yara_rule_put_result("r", RULE)
    tr.yara_rule_put_result("r", RULE_V2, "case", case)
    assert tr.yara_rule_delete_result("r", "case", case).payload["scope"] == "case"
    assert tr.yara_rule_get_result("r", case).payload["scope"] == "library"
    tr.yara_rule_delete_result("r")
    with pytest.raises(CapabilityError):
        tr.yara_rule_get_result("r")


# -- check / scan by rule_name -------------------------------------------------------


def test_resolve_rule_source_is_exclusive():
    tr.yara_rule_put_result("keylog", RULE)
    assert tr.resolve_rule_source(RULE, None, None) == (RULE, None)
    assert tr.resolve_rule_source(None, "keylog", None) == (
        RULE, {"rule_name": "keylog", "scope": "library"})
    with pytest.raises(CapabilityError) as exc:
        tr.resolve_rule_source(RULE, "keylog", None)
    assert _code(exc) == "yara_rule.source_ambiguous"


def test_check_by_rule_name_echoes_scope(case):
    tr.yara_rule_put_result("keylog", RULE, "case", case)
    out = ty.yara_check_result(rule_name="keylog", case_dir=case).payload
    assert out["valid"] is True and out["rule_name"] == "keylog" and out["scope"] == "case"


def test_scan_by_rule_name_finds_the_planted_string(raw_dump, case):
    tr.yara_rule_put_result("keylog", RULE)
    by_name = ty.yara_scan_dump_result(raw_dump, rule_name="keylog", case_dir=case).payload
    inline = ty.yara_scan_dump_result(raw_dump, RULE).payload
    assert by_name["row_count"] == 2 and by_name["rule_name"] == "keylog"
    assert by_name["scope"] == "library"
    assert by_name["rows"] == inline["rows"]


def test_scan_without_any_rule_is_invalid_input(raw_dump):
    with pytest.raises(CapabilityError) as exc:
        ty.yara_scan_dump_result(raw_dump)
    assert exc.value.category is ErrorCategory.INVALID_INPUT


# -- four surfaces -------------------------------------------------------------------


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


def _cli(argv, capsys):
    from memdiver.cli import _build_parser, _cmd_yara
    rc = _cmd_yara(_build_parser().parse_args(["yara", *argv]))
    return rc, capsys.readouterr().out


def _stable(payload):
    """Drop the per-write timestamps so two stores of the same rule compare equal."""
    return json.loads(json.dumps(payload, default=str))


def test_four_surfaces_store_and_read_the_same_rule(client, mcp_tools, capsys, tmp_path):
    rule_file = tmp_path / "k.yar"
    rule_file.write_text(RULE)
    rc, out = _cli(["rules", "put", "from_cli", str(rule_file)], capsys)
    assert rc == 0 and json.loads(out)["stored"]["name"] == "from_cli"
    r = client.put("/api/yara/rules/from_rest", json={"rule_source": RULE})
    assert r.status_code == 200 and r.json()["stored"]["scope"] == "library"
    mcp = json.loads(mcp_tools["yara_rule_put"].fn(name="from_mcp", rule_source=RULE))
    assert mcp["check"]["valid"] is True

    expected = _stable(tr.yara_rule_list_result().payload)
    assert [r["name"] for r in expected["rules"]] == ["from_cli", "from_mcp", "from_rest"]
    rc, out = _cli(["rules", "list"], capsys)
    assert rc == 0 and json.loads(out) == expected
    assert client.get("/api/yara/rules").json() == expected
    assert json.loads(mcp_tools["yara_rule_list"].fn()) == expected

    one = _stable(tr.yara_rule_get_result("from_rest").payload)
    assert client.get("/api/yara/rules/from_rest").json() == one
    assert json.loads(mcp_tools["yara_rule_get"].fn(name="from_rest")) == one
    assert json.loads(_cli(["rules", "get", "from_rest"], capsys)[1]) == one


def test_four_surfaces_delete_and_scan_by_name(client, mcp_tools, capsys, raw_dump):
    tr.yara_rule_put_result("keylog", RULE)
    expected = _stable(ty.yara_scan_dump_result(raw_dump, rule_name="keylog").payload)
    assert expected["row_count"] == 2
    rc, out = _cli(["scan", "--rule-name", "keylog", raw_dump], capsys)
    assert rc == 0 and json.loads(out) == expected
    r = client.post("/api/yara/scan", json={"dump_path": raw_dump, "rule_name": "keylog"})
    assert r.status_code == 200 and r.json() == expected
    mcp = json.loads(mcp_tools["yara_scan_dump"].fn(dump_path=raw_dump, rule_name="keylog"))
    assert {**mcp, "limit": expected["limit"]} == expected
    assert client.post("/api/yara/check", json={"rule_name": "keylog"}).json()["scope"] == "library"

    assert client.delete("/api/yara/rules/keylog").json()["deleted"] is True
    assert client.get("/api/yara/rules/keylog").status_code == 404
    tr.yara_rule_put_result("a", RULE)
    tr.yara_rule_put_result("b", RULE)
    assert json.loads(mcp_tools["yara_rule_delete"].fn(name="a"))["deleted"] is True
    assert json.loads(_cli(["rules", "delete", "b"], capsys)[1])["deleted"] is True
    assert tr.yara_rule_list_result().payload["count"] == 0


def test_rest_bad_name_is_422_or_400_never_a_write(client, home):
    r = client.put("/api/yara/rules/bad.name", json={"rule_source": RULE})
    assert r.status_code in (400, 422)
    assert not (home / RULES_DIR).exists() or not list((home / RULES_DIR).glob("*.yar"))
    assert client.put("/api/yara/rules/x", json={"rule_source": RULE, "typo": 1}).status_code == 422


def test_rest_case_scope_goes_through_the_write_sandbox(client, case, monkeypatch, tmp_path):
    monkeypatch.setenv("MEMDIVER_ALLOWED_ROOTS", str(tmp_path / "elsewhere"))
    from memdiver.api.config import get_settings
    get_settings.cache_clear()
    r = client.put("/api/yara/rules/x", json={"rule_source": RULE, "scope": "case",
                                              "case_dir": case})
    assert r.status_code == 403
    assert client.get("/api/yara/rules", params={"case_dir": case}).status_code == 403
    get_settings.cache_clear()


def test_mcp_registers_the_four_rule_tools(mcp_tools):
    assert {"yara_rule_list", "yara_rule_get", "yara_rule_put", "yara_rule_delete"} <= set(mcp_tools)


# --- review-fix regressions -------------------------------------------------

def test_list_survives_unreadable_entries(tmp_path):
    store = YaraRuleStore(tmp_path)
    store.put("good", RULE)
    directory = tmp_path / RULES_DIR
    (directory / "binary.yar").write_bytes(b"\xff\xfe\x00bad")
    (directory / "adir.yar").mkdir()
    rows = {r["name"]: r for r in store.list()}
    assert "error" in rows["binary"] and "error" not in rows["good"]
    assert "adir" not in rows


def test_put_delete_scope_defaults_and_exactness(case):
    tr.yara_rule_put_result("r", RULE, None, case)
    assert tr.yara_rule_get_result("r", case, "case").payload["scope"] == "case"
    with pytest.raises(CapabilityError):
        tr.yara_rule_get_result("r", None, "library")
    tr.yara_rule_put_result("r", RULE_V2, "library")
    with pytest.raises(CapabilityError) as exc:
        tr.yara_rule_delete_result("nope", "case", case)
    assert _code(exc) == "yara_rule.not_found"
    tr.yara_rule_delete_result("r", None, case)          # defaults to case
    assert tr.yara_rule_get_result("r", case).payload["scope"] == "library"
    with pytest.raises(CapabilityError):
        tr.yara_rule_delete_result("r", "case", case)    # must not touch the library
    assert tr.yara_rule_get_result("r", None, "library").payload["name"] == "r"


def test_version_continues_after_delete(tmp_path):
    store = YaraRuleStore(tmp_path)
    assert store.put("r", RULE)["version"] == 1
    store.delete("r")
    again = store.put("r", RULE_V2)
    assert again["version"] == 2 and store.list()[0]["version"] == 2


def test_concurrent_puts_keep_every_source(tmp_path):
    import threading
    store = YaraRuleStore(tmp_path)
    store.put("r", RULE)
    sources = [f'rule k{i} {{ strings: $a = "X{i}" condition: $a }}' for i in range(8)]
    results = []
    threads = [threading.Thread(target=lambda s=s: results.append(store.put("r", s)))
               for s in sources]
    [t.start() for t in threads]
    [t.join() for t in threads]
    assert sorted(r["version"] for r in results) == list(range(2, 10))
    archived = "".join(p.read_text() for p in (tmp_path / RULES_DIR / "history").glob("*.yar"))
    current = store.get("r")["source"]
    assert all(s in archived or s == current for s in sources + [RULE])


def test_list_with_missing_case_keeps_library():
    tr.yara_rule_put_result("lib", RULE)
    payload = tr.yara_rule_list_result("/nonexistent/case-dir-xyz").payload
    assert payload["case_error"] and [r["name"] for r in payload["rules"]] == ["lib"]
    with pytest.raises(CapabilityError):
        tr.yara_rule_get_result("lib", "/nonexistent/case-dir-xyz", "case")
