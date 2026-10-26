"""Read sandbox (REST + MCP), actionable write/VA refusals, CLI cohort guard."""

from __future__ import annotations

import argparse
import json
import os

import numpy as np
import pytest

from memdiver.core import path_sandbox
from memdiver.core.service_errors import CapabilityError


_REAL_TEMP_ROOTS = path_sandbox.temp_roots  # tests/conftest.py blanks it per test


@pytest.fixture()
def sandbox(tmp_path, monkeypatch):
    """Sandbox ON with one configured root OUTSIDE the temp dir's tree."""
    root = tmp_path / "ok"
    root.mkdir()
    monkeypatch.setenv("MEMDIVER_ALLOWED_ROOTS", str(root))
    monkeypatch.setattr(path_sandbox, "STARTUP_CWD", str(root))
    from memdiver.api.config import get_settings
    get_settings.cache_clear()
    yield root
    get_settings.cache_clear()


# -- A: key coverage + implicit roots ------------------------------------------------

def test_walker_covers_model_path_needles_related():
    body = {
        "model_path": "/m.json",
        "needles": {"/d1": "aa", "/d2": "bb"},
        "related": {"x": {"/d3": "cc"}},
        "key_material_by_path": {"/d4": {"key_file": "/k"}},
    }
    got = sorted(path_sandbox.iter_path_values(body, False))
    assert got == ["/d1", "/d2", "/d3", "/d4", "/k", "/m.json"]


def test_hex_values_of_needles_are_not_paths():
    assert list(path_sandbox.iter_path_values({"needles": ["aa"]}, False)) == []


def test_policy_off_admits_everything(monkeypatch):
    monkeypatch.delenv("MEMDIVER_ALLOWED_ROOTS", raising=False)
    from memdiver.api import path_policy
    from memdiver.api.config import get_settings
    get_settings.cache_clear()
    assert path_policy.allowed_roots() == []
    assert path_policy.admit_read_path("/etc/passwd")


def test_implicit_roots_include_cwd_and_tmp(sandbox, monkeypatch):
    from memdiver.api import path_policy
    import tempfile
    monkeypatch.setattr(path_sandbox, "temp_roots", _REAL_TEMP_ROOTS)
    roots = path_policy.allowed_roots()
    assert sandbox.resolve() in roots
    assert os.path.realpath(tempfile.gettempdir()) in {str(r) for r in roots}


def test_denial_detail_is_actionable(sandbox):
    from fastapi import HTTPException
    from memdiver.api import path_policy
    with pytest.raises(HTTPException) as ei:
        path_policy.admit_read_path("/definitely/not/admitted.bin")
    d = ei.value.detail
    assert ei.value.status_code == 403
    assert "/definitely/not/admitted.bin" in d and "MEMDIVER_ALLOWED_ROOTS" in d
    assert str(sandbox.resolve()) in d and "favourite" in d


# -- B: MCP central hook -------------------------------------------------------------

def test_mcp_guard_denies_with_same_message_when_on(sandbox):
    from memdiver.mcp_server.path_guard import guard_tool

    def tool(dump_path: str, offset: int = 0) -> str:
        return "ran"

    out = json.loads(guard_tool(tool)("/definitely/not/admitted.bin"))
    assert out["code"] == "path.outside_sandbox"
    assert "/definitely/not/admitted.bin" in out["error"] and str(sandbox.resolve()) in out["error"]
    assert guard_tool(tool)(str(sandbox / "x.bin")) == "ran"


def test_mcp_guard_checks_nested_needles(sandbox):
    from memdiver.mcp_server.path_guard import guard_tool

    def tool(needles: dict) -> str:
        return "ran"

    out = json.loads(guard_tool(tool)(needles={"/nope/x.dump": "aa"}))
    assert out["code"] == "path.outside_sandbox"


def test_mcp_guard_is_noop_when_policy_off(monkeypatch):
    monkeypatch.delenv("MEMDIVER_ALLOWED_ROOTS", raising=False)
    from memdiver.api.config import get_settings
    get_settings.cache_clear()
    from memdiver.mcp_server.path_guard import guard_tool

    def tool(dump_path: str) -> str:
        return "ran"

    assert guard_tool(tool)("/etc/passwd") == "ran"


# -- C: write refusals ---------------------------------------------------------------

def test_write_denial_lists_roots_and_example(tmp_path):
    from memdiver.api.path_safety import write_denial_detail
    msg = write_denial_detail("out_path", "/etc/x", [tmp_path], "out/result")
    assert "/etc/x" in msg and str(tmp_path.resolve()) in msg
    assert str(tmp_path.resolve() / "out/result") in msg and "escapes" in msg


def test_contained_case_dir_403_is_meaningful(tmp_path, monkeypatch):
    from fastapi import HTTPException
    from memdiver.api.routers.annotations import contained_case_dir
    with pytest.raises(HTTPException) as ei:
        contained_case_dir("/etc/evil")
    assert ei.value.status_code == 403
    assert "/etc/evil" in ei.value.detail and "Allowed write locations" in ei.value.detail


# -- D: no VA view -------------------------------------------------------------------

def test_no_va_view_message_raw_vs_regioned():
    from memdiver.app.tools_semantic import _no_va_view_message
    from memdiver.core.dump_source import RawDumpSource

    raw = RawDumpSource.__new__(RawDumpSource)
    msg = _no_va_view_message("/d/a.dump", raw)
    assert "/d/a.dump" in msg and "RawDumpSource" in msg
    assert "memdiver import /d/a.dump --maps <proc maps file> -o <out>.msl" in msg
    assert "anchor consensus still works" in msg

    class GCoreDumpSource:
        pass

    other = _no_va_view_message("/d/c.core", GCoreDumpSource())
    assert "memdiver import /d/c.core`" in other and "VA map is preserved" in other


# -- E: CLI incremental cohort guard ------------------------------------------------

def _dump(parent, name, cohort, seed, size=256):
    run = parent / name
    run.mkdir(parents=True)
    rng = np.random.default_rng(seed)
    (run / "d.bin").write_bytes(rng.integers(1, 256, size, dtype=np.uint8).tobytes())
    if cohort is not None:
        (run / "meta.json").write_text(json.dumps({"cohort": cohort}))
    return str(run / "d.bin")


def _add_ns(state, dump, **kw):
    return argparse.Namespace(state=str(state), dump=dump, key_file=None,
                              passphrase=None, kem_key_file=None, **kw)


def test_begin_records_cohort_and_add_refuses_other(tmp_path):
    from memdiver.cli import _cmd_consensus_add, _cmd_consensus_begin
    a1, a2 = _dump(tmp_path, "a1", "a", 1), _dump(tmp_path, "a2", "a", 2)
    b1 = _dump(tmp_path, "b1", "b", 3)
    state = tmp_path / "s.json"
    assert _cmd_consensus_begin(argparse.Namespace(
        state=str(state), size=256, dumps=[a1, a2])) == 0
    assert json.loads(state.read_text())["cohort"] == "a"
    assert _cmd_consensus_add(_add_ns(state, a1)) == 0
    with pytest.raises(CapabilityError) as ei:
        _cmd_consensus_add(_add_ns(state, b1))
    assert ei.value.code == "cohort.mixed"
    assert _cmd_consensus_add(_add_ns(state, b1, mixed_ok=True)) == 0
    assert json.loads(state.read_text())["cohort"] == "a"


def test_begin_refuses_mixed_dumps_unless_mixed_ok(tmp_path):
    from memdiver.cli import _cmd_consensus_begin
    a, b = _dump(tmp_path, "a", "a", 1), _dump(tmp_path, "b", "b", 2)
    with pytest.raises(CapabilityError) as ei:
        _cmd_consensus_begin(argparse.Namespace(
            state=str(tmp_path / "s.json"), size=256, dumps=[a, b]))
    assert ei.value.code == "cohort.mixed"
    assert _cmd_consensus_begin(argparse.Namespace(
        state=str(tmp_path / "s.json"), size=256, dumps=[a, b], mixed_ok=True)) == 0


def test_state_without_cohort_adopts_first_known_and_cohortless_never_refuses(tmp_path):
    from memdiver.cli import _cmd_consensus_add, _cmd_consensus_begin
    bare, a, b = (_dump(tmp_path, "n", None, 1), _dump(tmp_path, "a", "a", 2),
                  _dump(tmp_path, "b", "b", 3))
    state = tmp_path / "s.json"
    assert _cmd_consensus_begin(argparse.Namespace(state=str(state), size=256)) == 0
    assert "cohort" not in json.loads(state.read_text())
    assert _cmd_consensus_add(_add_ns(state, bare)) == 0
    # one cohort-less dump is already folded: a cohorted dump must NOT be
    # silently adopted over it (see test_prefolded_state_*); --mixed-ok does.
    with pytest.raises(CapabilityError) as ei:
        _cmd_consensus_add(_add_ns(state, a))
    assert ei.value.code == "cohort.unknown_state"
    assert _cmd_consensus_add(_add_ns(state, a, mixed_ok=True)) == 0
    assert json.loads(state.read_text())["cohort"] == "a"
    assert _cmd_consensus_add(_add_ns(state, bare)) == 0
    with pytest.raises(CapabilityError):
        _cmd_consensus_add(_add_ns(state, b))


def test_prefolded_state_without_cohort_refuses_unless_mixed_ok(tmp_path):
    from memdiver.cli import _cmd_consensus_add, _cmd_consensus_begin
    bare, a = _dump(tmp_path, "n", None, 1), _dump(tmp_path, "a", "a", 2)
    state = tmp_path / "s.json"
    _cmd_consensus_begin(argparse.Namespace(state=str(state), size=256))
    _cmd_consensus_add(_add_ns(state, bare))
    with pytest.raises(CapabilityError) as ei:
        _cmd_consensus_add(_add_ns(state, a))
    assert "predates cohort recording" in str(ei.value)
    assert "cohort" not in json.loads(state.read_text())


def test_prefolded_state_with_listed_paths_computes_their_cohort(tmp_path):
    from memdiver.cli import _cmd_consensus_add, _cmd_consensus_begin
    a1, a2 = _dump(tmp_path, "a1", "a", 1), _dump(tmp_path, "a2", "a", 2)
    b1 = _dump(tmp_path, "b1", "b", 3)
    state = tmp_path / "s.json"
    _cmd_consensus_begin(argparse.Namespace(state=str(state), size=256))
    _cmd_consensus_add(_add_ns(state, a1))
    doc = json.loads(state.read_text())
    doc["dump_paths"] = [a1]
    state.write_text(json.dumps(doc))
    with pytest.raises(CapabilityError) as ei:
        _cmd_consensus_add(_add_ns(state, b1))
    assert ei.value.code == "cohort.mixed"
    assert _cmd_consensus_add(_add_ns(state, a2)) == 0
    assert json.loads(state.read_text())["cohort"] == "a"
