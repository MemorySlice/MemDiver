"""Opt-in MCP result budget (MEMDIVER_MCP_RESULT_BUDGET): off by default, bounded, never silent."""

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from memdiver.mcp_server import result_budget as rb  # noqa: E402


def _big(n=2000):
    return json.dumps({"ok": True, "name": "x", "rows": [{"i": i, "s": "y" * 40} for i in range(n)],
                       "nested": {"inner": list(range(n))}})


def test_budget_from_env_off_by_default():
    assert rb.budget_from_env({}) == 0
    assert rb.budget_from_env({rb.ENV_VAR: "0"}) == 0
    assert rb.budget_from_env({rb.ENV_VAR: "junk"}) == 0
    assert rb.budget_from_env({rb.ENV_VAR: "20000"}) == 20000
    assert rb.budget_from_env({rb.ENV_VAR: "5"}) == rb.MIN_BUDGET


def test_budget_zero_returns_function_itself():
    def tool():
        return _big()
    assert rb.budget_tool(tool, 0) is tool


def test_big_list_truncated_with_markers_and_bound():
    def tool(limit: int = 5, offset: int = 0):
        return _big()
    original = _big()
    out = rb.budget_tool(tool, 5000)()
    data = json.loads(out)
    assert len(out.encode()) <= 5000  # exact bound: returned <= budget
    assert data["ok"] is True and data["name"] == "x"
    assert data["rows__truncated"]["total"] == 2000
    assert data["rows__truncated"]["kept"] == len(data["rows"]) >= 1
    assert data["nested"]["inner__truncated"]["total"] == 2000
    meta = data["_result_budget"]
    assert meta["budget"] == 5000
    assert meta["original_bytes"] == len(original.encode())
    assert meta["returned_bytes"] == len(out.encode())
    assert "limit/offset/filters" in meta["hint"] and "case_query" in meta["hint"]


def test_small_result_untouched_and_unmarked():
    small = json.dumps({"a": [1, 2, 3]})
    assert rb.budget_tool(lambda: small, 5000)() == small


def test_huge_scalar_is_omitted_not_silent():
    out = rb.budget_tool(lambda: json.dumps({"blob": "z" * 50000, "k": 1}), 2000)()
    data = json.loads(out)
    assert len(out.encode()) <= 2000
    assert data["blob"]["omitted_bytes"] > 50000 and data["k"] == 1
    assert "_result_budget" in data


def test_non_json_text_truncated_with_marker():
    out = rb.budget_tool(lambda: "line\n" * 5000, 2000)()
    assert len(out.encode()) <= 2000
    assert "_result_budget" in out and "original_bytes=25000" in out


def test_small_error_passes_through_byte_identical():
    err = json.dumps({"error": "e" * 500, "code": "x.y", "category": "PRECONDITION"})
    assert rb.budget_tool(lambda: err, 2000)() == err


def test_oversized_error_is_truncated_but_keeps_error_and_code():
    err = json.dumps({"error": "e" * 90000, "code": "x.y", "category": "PRECONDITION",
                      "detail": {"trace": "t" * 50000}})
    out = rb.budget_tool(lambda: err, 2000)()
    data = json.loads(out)
    assert len(out.encode()) <= 2000
    assert data["code"] == "x.y" and data["category"] == "PRECONDITION"
    assert data["error"].startswith("eee") and data["error"].endswith("...[truncated]")
    assert data["_result_budget"]["original_bytes"] == len(err.encode())
    assert data["_result_budget"]["returned_bytes"] == len(out.encode())


def test_top_level_list_wrapped():
    out = rb.budget_tool(lambda: json.dumps(list(range(10000))), 3000)()
    data = json.loads(out)
    assert len(out.encode()) <= 3000 and data["items__truncated"]["total"] == 10000


@pytest.fixture
def _fresh_settings():
    """``get_settings`` is lru-cached: a sandbox read under this test's env must not
    outlive it (it once switched the sandbox ON for every later test in the run)."""
    from memdiver.api.config import get_settings

    get_settings.cache_clear()
    yield
    get_settings.cache_clear()


def test_composes_with_path_guard_denial_still_denies(monkeypatch, tmp_path, _fresh_settings):
    from memdiver.mcp_server.path_guard import guard_tool

    monkeypatch.setenv("MEMDIVER_ALLOWED_ROOTS", str(tmp_path / "allowed"))
    (tmp_path / "allowed").mkdir()
    ran = []

    def read_hex(path: str):
        ran.append(path)
        return _big()

    out = rb.budget_tool(guard_tool(read_hex), 5000)("/etc/passwd")
    data = json.loads(out)
    assert data.get("error") and data.get("code") and not ran
    assert "_result_budget" not in data
    ok = json.loads(rb.budget_tool(guard_tool(read_hex), 5000)(str(tmp_path / "allowed" / "f")))
    assert "_result_budget" in ok and ran


def test_server_default_off_registration_unchanged(monkeypatch):
    pytest.importorskip("mcp")
    from memdiver.mcp_server.server import create_server

    monkeypatch.delenv(rb.ENV_VAR, raising=False)
    off = create_server()
    monkeypatch.setenv(rb.ENV_VAR, "20000")
    on = create_server()
    name = "list_protocols"
    f_off = off._tool_manager.get_tool(name).fn if hasattr(off, "_tool_manager") else None
    f_on = on._tool_manager.get_tool(name).fn if hasattr(on, "_tool_manager") else None
    if f_off is None:
        pytest.skip("tool manager layout differs")
    assert f_off() == f_on()  # small result: byte-identical even with the budget ON
