"""The ``yara.*`` editor capabilities on all four surfaces.

Synthetic ``.msl`` dumps: a needle planted in one region, a needle SPLIT across a
capture gap (must not be found, must never be read as zeros), and a zero-run rule
that would match invented padding. Producer, windowing, truncation, compile errors
with their line, CLI (real argv), REST (real JSON) and MCP parity.
"""
from __future__ import annotations

import json
from types import SimpleNamespace

import pytest

from memdiver.app import tools_yara as ty
from memdiver.core.service_errors import CapabilityError, ErrorCategory
from memdiver.msl.enums import ArchType, OSType, PageState
from memdiver.msl.types import MslVasEntry
from memdiver.msl.writer import MslWriter

PAGE = 0x1000
NEEDLE = b"SSLKEYLOGFILE"
RULE = 'rule keylog { strings: $a = "SSLKEYLOGFILE" condition: $a }'
BASE = 0x400000
C, F = PageState.CAPTURED, PageState.FAILED


def _filler(length: int, seed: int) -> bytes:
    return bytes(((seed + i * 7) % 251) + 1 for i in range(length))   # never a zero byte


def _write_msl(path, regions, page_states=None) -> str:
    writer = MslWriter(str(path), os_type=OSType.LINUX, arch_type=ArchType.X86_64, imported=True)
    for va, data in regions:
        writer.add_memory_region(va, data, protection=0x03,
                                 page_states=(page_states or {}).get(va))
    writer.add_vas_map([MslVasEntry(va, len(data) if not (page_states or {}).get(va)
                                    else PAGE * len(page_states[va]), 0x03, 0, "r")
                        for va, data in regions])
    writer.add_end_of_capture()
    writer.write()
    return str(path)


@pytest.fixture
def needle_msl(tmp_path):
    buf = bytearray(_filler(PAGE, 1))
    buf[0x40:0x40 + len(NEEDLE)] = NEEDLE
    buf[0x800:0x800 + len(NEEDLE)] = NEEDLE
    return SimpleNamespace(path=_write_msl(tmp_path / "n.msl", [(BASE, bytes(buf))]))


# -- check -------------------------------------------------------------------------


def test_check_valid_rule_names_its_rules():
    out = ty.yara_check_result(RULE).payload
    assert out["valid"] is True and out["rule_names"] == ["keylog"] and out["errors"] == []


def test_check_reports_the_failing_line():
    bad = 'rule x {\n  strings:\n    $a = "x"\n  condition: $b\n}'
    out = ty.yara_check_result(bad).payload
    assert out["valid"] is False
    assert out["errors"][0]["line"] in (4, 5)   # libyara reports where the rule ends
    assert "$b" in out["errors"][0]["message"]


def test_check_syntax_error_is_an_answer_not_an_exception():
    out = ty.yara_check_result("rule {").payload
    assert out["valid"] is False and out["errors"][0]["line"] == 1


def test_check_empty_source_is_invalid_input():
    with pytest.raises(CapabilityError) as exc:
        ty.yara_check_result("   ")
    assert exc.value.category is ErrorCategory.INVALID_INPUT


def test_check_warns_about_a_pattern_the_installed_libyara_cannot_verify():
    from memdiver.engine.yara_scan import regexp_scan_limit
    limit = regexp_scan_limit()
    if limit is None:
        pytest.skip("scan limit not established")
    wide = " ".join(["AA"] * (limit + 8)) + " ??"
    rule = "rule w { strings: $a = { " + wide + " } condition: $a }"
    out = ty.yara_check_result(rule).payload
    assert out["valid"] and any(w["code"] == "yara.pattern_over_scan_limit" for w in out["warnings"])


# -- scan ----------------------------------------------------------------------------


def test_scan_finds_every_needle_with_va_and_coverage(needle_msl):
    out = ty.yara_scan_dump_result(needle_msl.path, RULE).payload
    assert [r["addr"] for r in out["rows"]] == [BASE + 0x40, BASE + 0x800]
    row = out["rows"][0]
    assert (row["rule"], row["string_id"], row["length"]) == ("keylog", "$a", len(NEEDLE))
    assert row["space"] == "msl_va" and row["va"] == BASE + 0x40 and row["vas_offset"] == 0x40
    assert row["matched_hex"] == NEEDLE.hex()
    assert out["view"] == "va" and out["matched_rules"] == ["keylog"]
    assert out["complete"] is True and out["truncated"] is False
    assert out["coverage"]["bytes_scanned"] == PAGE and out["coverage"]["runs_scanned"] == 1


def test_scan_window_restricts_to_the_requested_range(needle_msl):
    out = ty.yara_scan_dump_result(needle_msl.path, RULE, offset=BASE + 0x100, length=0x800).payload
    assert [r["addr"] for r in out["rows"]] == [BASE + 0x800]
    assert out["coverage"]["requested_offset"] == BASE + 0x100


def test_scan_window_ending_inside_a_needle_does_not_report_it(needle_msl):
    out = ty.yara_scan_dump_result(needle_msl.path, RULE, offset=BASE, length=0x40 + 5).payload
    assert out["rows"] == []


def test_scan_limit_truncates_and_says_so(needle_msl):
    out = ty.yara_scan_dump_result(needle_msl.path, RULE, limit=1).payload
    assert out["row_count"] == 1 and out["truncated"] is True
    assert out["complete"] is False and out["incomplete_reason"] == "truncated"


def test_needle_split_across_a_capture_gap_is_not_found(tmp_path):
    half = len(NEEDLE) // 2
    first = bytearray(_filler(PAGE, 2))
    first[-half:] = NEEDLE[:half]
    second = bytearray(_filler(PAGE, 3))
    second[:len(NEEDLE) - half] = NEEDLE[half:]
    path = _write_msl(tmp_path / "gap.msl", [(BASE, bytes(first)), (BASE + 2 * PAGE, bytes(second))])
    out = ty.yara_scan_dump_result(path, RULE).payload
    assert out["rows"] == [] and out["coverage"]["gaps_skipped"] == 1
    assert out["coverage"]["runs_scanned"] == 2


def test_absent_bytes_are_never_zeros(tmp_path):
    """A zero-run rule must not match the page the capture FAILED to read."""
    states = {BASE: [C, F, C]}
    data = _filler(PAGE * 2, 4)           # two captured pages, no zero byte anywhere
    path = _write_msl(tmp_path / "f.msl", [(BASE, data)], page_states=states)
    zeros = "rule z { strings: $a = { 00 00 00 00 00 00 00 00 } condition: $a }"
    out = ty.yara_scan_dump_result(path, zeros).payload
    assert out["rows"] == [] and out["coverage"]["gaps_skipped"] == 1
    assert out["coverage"]["captured_bytes"] == 2 * PAGE


def test_scan_bad_arguments_are_invalid_input(needle_msl):
    for kw in ({"limit": 0}, {"offset": -1}, {"length": 0}):
        with pytest.raises(CapabilityError) as exc:
            ty.yara_scan_dump_result(needle_msl.path, RULE, **kw)
        assert exc.value.category is ErrorCategory.INVALID_INPUT


def test_scan_missing_dump_is_not_found(tmp_path):
    with pytest.raises(CapabilityError) as exc:
        ty.yara_scan_dump_result(str(tmp_path / "nope.msl"), RULE)
    assert exc.value.category is ErrorCategory.NOT_FOUND


def test_scan_non_compiling_rule_is_invalid_input(needle_msl):
    with pytest.raises(CapabilityError) as exc:
        ty.yara_scan_dump_result(needle_msl.path, "rule {")
    assert exc.value.code == "yara.compile_failed"


def test_scan_flat_file_uses_raw_coordinates(tmp_path):
    flat = tmp_path / "flat.bin"
    flat.write_bytes(_filler(100, 5) + NEEDLE + _filler(50, 6))
    out = ty.yara_scan_dump_result(str(flat), RULE).payload
    assert out["view"] == "raw" and [r["addr"] for r in out["rows"]] == [100]


# -- surfaces: CLI / REST / MCP parity -----------------------------------------------


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


def test_scan_four_surfaces_return_the_same_rows(needle_msl, tmp_path, client, mcp_tools, capsys):
    rule_file = tmp_path / "r.yar"
    rule_file.write_text(RULE)
    expected = json.loads(json.dumps(ty.yara_scan_dump_result(needle_msl.path, RULE).payload))
    assert len(expected["rows"]) == 2
    rc, out = _cli(["scan", str(rule_file), needle_msl.path], capsys)
    assert rc == 0 and json.loads(out) == expected
    r = client.post("/api/yara/scan", json={"dump_path": needle_msl.path, "rule_source": RULE})
    assert r.status_code == 200 and r.json() == expected
    mcp = json.loads(mcp_tools["yara_scan_dump"].fn(dump_path=needle_msl.path, rule_source=RULE))
    assert {**mcp, "limit": expected["limit"]} == expected   # MCP defaults a smaller row cap


def test_check_four_surfaces_agree_and_cli_exits_nonzero_on_a_bad_rule(
        tmp_path, client, mcp_tools, capsys):
    bad = "rule x {\n condition: $nope\n}"
    rule_file = tmp_path / "bad.yar"
    rule_file.write_text(bad)
    expected = json.loads(json.dumps(ty.yara_check_result(bad).payload))
    assert expected["valid"] is False
    rc, out = _cli(["check", str(rule_file)], capsys)
    assert rc == 1 and json.loads(out) == expected
    assert client.post("/api/yara/check", json={"rule_source": bad}).json() == expected
    assert json.loads(mcp_tools["yara_check"].fn(rule_source=bad)) == expected


def test_rest_rejects_unknown_fields(client):
    assert client.post("/api/yara/check", json={"rule_source": RULE, "typo": 1}).status_code == 422


def test_rest_missing_dump_is_404(client, tmp_path):
    r = client.post("/api/yara/scan", json={"dump_path": str(tmp_path / "x.msl"),
                                            "rule_source": RULE})
    assert r.status_code == 404


# -- job route: progress, cancel, async / large -> task id ----------------------------


class _JobCtx:
    task_id = "yarajob"

    def __init__(self, cancel_after=None):
        self.events = []
        self._polls = 0
        self._cancel_after = cancel_after

    def emit(self, kind, **kw):
        self.events.append((kind, kw))

    def is_cancelled(self):
        self._polls += 1
        return self._cancel_after is not None and self._polls > self._cancel_after


@pytest.fixture
def multi_window_msl(tmp_path, monkeypatch):
    """Needles in three 4 KiB-windowed pages so the scan has several windows."""
    from memdiver.app import tools_keyfinders as tk
    monkeypatch.setattr(tk, "WINDOW_BYTES", PAGE)
    monkeypatch.setattr(tk, "WINDOW_OVERLAP", 64)
    data = bytearray(_filler(PAGE * 6, 3))
    for at in (0x100, PAGE * 2 + 0x200, PAGE * 5 + 0x300):
        data[at:at + len(NEEDLE)] = NEEDLE
    return _write_msl(tmp_path / "multi.msl", [(BASE, bytes(data))])


def test_job_runner_progress_matches_inline_rows(multi_window_msl, tmp_path):
    from memdiver.app.pipeline.yara_task_runner import run_yara_job
    inline = ty.yara_scan_dump_result(multi_window_msl, RULE).payload
    ctx = _JobCtx()
    out = run_yara_job({"args": {"dump_path": multi_window_msl, "rule_source": RULE},
                        "artifact_dir": str(tmp_path / "art")}, ctx)
    assert out["summary"]["rows"] == inline["rows"] and inline["row_count"] == 3
    (artifact,) = out["artifacts"]
    assert artifact["name"] == "yara_result" and artifact["relpath"] == "yara/result.json"
    kinds = [k for k, _ in ctx.events]
    progress = [kw["pct"] for k, kw in ctx.events if k == "progress"]
    assert kinds[0] == "stage_start" and kinds[-1] == "stage_end" and len(progress) >= 5
    assert progress == sorted(progress) and 0 < progress[0] and progress[-1] < 1.0


def test_job_runner_cancel_is_never_complete(multi_window_msl, tmp_path):
    from memdiver.app.pipeline.yara_task_runner import run_yara_job
    ctx = _JobCtx(cancel_after=2)
    with pytest.raises(RuntimeError, match="cancelled"):
        run_yara_job({"args": {"dump_path": multi_window_msl, "rule_source": RULE},
                      "artifact_dir": str(tmp_path / "art")}, ctx)
    assert ctx.events[-1] == ("error", {"error": "cancelled"})
    assert not [k for k, _ in ctx.events if k == "stage_end"]
    assert not (tmp_path / "art" / "yara").exists()


def test_scan_cancel_callback_raises_cancelled(multi_window_msl):
    with pytest.raises(CapabilityError) as exc:
        ty.yara_scan_dump_result(multi_window_msl, RULE, cancel=lambda: True)
    assert exc.value.code == "cancelled"


def test_job_runner_turns_a_bad_rule_into_a_value_error(needle_msl, tmp_path):
    from memdiver.app.pipeline.yara_task_runner import run_yara_job
    ctx = _JobCtx()
    with pytest.raises(ValueError):
        run_yara_job({"args": {"dump_path": needle_msl.path, "rule_source": "rule {"},
                      "artifact_dir": str(tmp_path / "art")}, ctx)
    assert ctx.events[-1][0] == "error"


def test_rest_scan_is_inline_when_small_and_a_job_when_async_or_large(
        needle_msl, client, monkeypatch, tmp_path):
    from types import SimpleNamespace

    class Manager:
        artifact_store = SimpleNamespace(root=tmp_path / "tasks")
        submitted = []

        def submit(self, *, kind, params, runner_dotted, stage_names=None):
            self.submitted.append((kind, params, runner_dotted))
            return SimpleNamespace(task_id="t" * 32, status=SimpleNamespace(value="pending"))

    manager = Manager()
    monkeypatch.setattr("memdiver.api.routers.yara.task_manager_or_503", lambda: manager)
    body = {"dump_path": needle_msl.path, "rule_source": RULE}
    assert "rows" in client.post("/api/yara/scan", json=body).json() and not manager.submitted
    assert client.post("/api/yara/scan", json={**body, "async": True}).json() == {
        "task_id": "t" * 32, "status": "pending"}
    monkeypatch.setattr("memdiver.api.routers.yara.SYNC_MAX_BYTES", 1)
    assert client.post("/api/yara/scan", json=body).json()["task_id"] == "t" * 32
    kind, params, runner = manager.submitted[-1]
    assert kind == "yara" and runner.endswith("yara_task_runner.run_yara_job")
    assert params["args"]["rule_source"] == RULE and params["args"]["dump_path"] == needle_msl.path
