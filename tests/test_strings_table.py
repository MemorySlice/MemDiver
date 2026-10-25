"""The ``strings.table`` capability on all four surfaces (plan T3.6).

Synthetic flat and ``.msl`` dumps with planted ASCII / UTF-16LE strings, one
straddling a capture gap (must be split, never joined across it), the ``strings``
case table and the ``strings_iocs`` saved query (DuckDB RE2 regexes checked against
their Python twins), CLI (real argv), REST (real JSON) and MCP parity.
"""
from __future__ import annotations

import json
from types import SimpleNamespace

import pytest

from memdiver.analysis.case import Case
from memdiver.analysis.queries import saved_queries
from memdiver.analysis.queries.strings import IOC_PATTERNS, ioc_kinds, ioc_matches
from memdiver.app import tools_strings as ts
from memdiver.app.tools_vol3 import vol3_query_result
from memdiver.core.service_errors import CapabilityError
from memdiver.msl.enums import PageState
from tests.test_keyfinders_surfaces import FakeManager, _write_msl  # noqa: F401

PAGE = 0x1000
C, F = PageState.CAPTURED, PageState.FAILED
QUIET = b"\x01"      # unprintable filler: never a string, never joined to one


def _blank(length: int) -> bytearray:
    return bytearray(QUIET * length)


def _plant(buf: bytearray, offset: int, blob: bytes) -> None:
    buf[offset:offset + len(blob)] = blob


def _wide(text: str) -> bytes:
    return text.encode("utf-16-le")


@pytest.fixture(autouse=True)
def _xdg(tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "xdg"))


@pytest.fixture
def flat(tmp_path):
    buf = _blank(0x400)
    _plant(buf, 0x100, b"hello_world")
    _plant(buf, 0x201, _wide("C:\\Windows\\a.exe"))     # odd offset on purpose
    _plant(buf, 0x300, b"abc")                           # below min_len
    path = tmp_path / "flat.raw"
    path.write_bytes(bytes(buf))
    return str(path)


@pytest.fixture
def gap_msl(tmp_path):
    """``ABCDE`` ends region a, ``FGHIJ`` starts region b; the VA gap is one page."""
    a, b = _blank(PAGE), _blank(PAGE)
    _plant(a, PAGE - 5, b"ABCDE")
    _plant(b, 0, b"FGHIJ")
    _plant(a, 0x10, b"see https://srv.example.org/x and 10.1.2.3")
    return _write_msl(tmp_path / "gap.msl", [(0x400000, bytes(a), "/lib/libssl.so"),
                                             (0x402000, bytes(b), "[heap]")])


def _table(**kw):
    return ts.strings_table_result(**kw).payload


# -- raw dumps ----------------------------------------------------------------------


def test_flat_rows_carry_space_encoding_and_extent(flat):
    out = _table(dump_path=flat)
    rows = {(r["encoding"], r["value"]): r for r in out["rows"]}
    assert set(rows) == {("ascii", "hello_world"), ("utf16le", "C:\\Windows\\a.exe")}
    ascii_row = rows[("ascii", "hello_world")]
    assert (ascii_row["addr"], ascii_row["space"]) == (0x100, "file_offset")
    assert ascii_row["location"]["space"] == "file_offset" and ascii_row["byte_length"] == 11
    wide = rows[("utf16le", "C:\\Windows\\a.exe")]
    assert (wide["addr"], wide["length"], wide["byte_length"]) == (0x201, 16, 32)
    assert wide["iocs"] == ["windows_paths", "executables"] and wide["va"] is None
    assert out["row_count"] == 2 and out["complete"] is True and out["view"] == "raw"
    assert out["coverage"]["bytes_scanned"] == 0x400 and out["rows"] == sorted(
        out["rows"], key=lambda r: (r["addr"], r["encoding"]))


def test_encodings_and_min_len_select_rows(flat):
    only_ascii = _table(dump_path=flat, encodings=("ascii",))
    assert [r["value"] for r in only_ascii["rows"]] == ["hello_world"]
    short = _table(dump_path=flat, encodings=("ascii",), min_len=3)
    assert {r["value"] for r in short["rows"]} == {"hello_world", "abc"}


def test_region_clips_the_scan(flat):
    out = _table(dump_path=flat, region=(0x180, 0x200))
    assert [r["addr"] for r in out["rows"]] == [0x201]
    assert out["coverage"]["bytes_scanned"] == 0x200 and out["coverage"]["requested_offset"] == 0x180


def test_limit_truncates_and_says_so(flat):
    out = _table(dump_path=flat, limit=1)
    assert out["truncated"] is True and out["complete"] is False and out["row_count"] == 1
    exact = _table(dump_path=flat, limit=2)
    assert exact["truncated"] is False and exact["row_count"] == 2


def test_a_cut_value_says_so(tmp_path):
    path = tmp_path / "long.raw"
    path.write_bytes(b"A" * (ts.MAX_VALUE_CHARS + 50))
    (row,) = _table(dump_path=str(path))["rows"]
    assert row["length"] == ts.MAX_VALUE_CHARS + 50 and row["value_truncated"] is True
    assert len(row["value"]) == ts.MAX_VALUE_CHARS


# -- .msl: coordinates, region, gaps ---------------------------------------------------


def test_msl_va_rows_have_region_and_a_string_never_crosses_a_gap(gap_msl):
    out = _table(dump_path=gap_msl)
    values = {r["value"]: r for r in out["rows"]}
    assert "ABCDEFGHIJ" not in values
    assert values["ABCDE"]["addr"] == 0x400000 + PAGE - 5 and values["FGHIJ"]["addr"] == 0x402000
    assert values["ABCDE"]["space"] == "msl_va" and values["ABCDE"]["va"] == values["ABCDE"]["addr"]
    assert values["ABCDE"]["region"]["path"] == "/lib/libssl.so"
    assert values["ABCDE"]["region"]["perms"] == "rw-"
    assert values["FGHIJ"]["region"]["path"] == "[heap]"
    assert out["coverage"]["gaps_skipped"] == 1 and out["coverage"]["runs_scanned"] == 2
    url = next(r for r in out["rows"] if r["value"].startswith("see https"))
    assert url["iocs"] == ["urls", "ipv4", "unix_paths"] or {"urls", "ipv4"} <= set(url["iocs"])


def test_vas_view_reports_packed_offsets(gap_msl):
    out = _table(dump_path=gap_msl, view="vas")
    assert out["space"] == "msl_vas"
    by_value = {r["value"]: r for r in out["rows"]}
    assert "ABCDEFGHIJ" in by_value or "ABCDE" in by_value
    for row in out["rows"]:
        assert row["addr"] == row["vas_offset"] and row["location"]["space"] == "msl_vas"


def test_failed_page_is_a_gap_not_zeros(tmp_path):
    data = _blank(2 * PAGE)               # only the CAPTURED pages carry bytes
    _plant(data, PAGE - 4, b"WXYZ")        # ends page 0
    _plant(data, PAGE, b"QRST")            # starts page 2 (page 1 FAILED, absent)
    path = _write_msl(tmp_path / "f.msl", [(0x500000, bytes(data), "r")],
                      page_states={0x500000: [C, F, C]})
    out = _table(dump_path=path)
    assert {r["value"] for r in out["rows"]} == {"WXYZ", "QRST"}
    assert out["coverage"]["gaps_skipped"] == 1


# -- validation ------------------------------------------------------------------------


@pytest.mark.parametrize("kwargs,code", [
    ({"encodings": ("ebcdic",)}, "strings.bad_encoding"),
    ({"encodings": ()}, "strings.bad_encoding"),
    ({"min_len": 0}, "strings.bad_min_len"),
    ({"limit": 0}, "invalid_limit"),
    ({"region": (-1, 4)}, "strings.bad_range"),
    ({"view": "va"}, "strings.bad_view"),
])
def test_bad_arguments_are_structured_errors(flat, kwargs, code):
    with pytest.raises(CapabilityError) as err:
        ts.strings_table_result(flat, **kwargs)
    assert err.value.code == code


def test_missing_dump_is_not_found(tmp_path):
    with pytest.raises(CapabilityError) as err:
        ts.strings_table_result(str(tmp_path / "nope.msl"))
    assert err.value.code == "dump_not_found"


# -- IOC patterns --------------------------------------------------------------------------

SAMPLES = {
    "urls": ("GET https://api.example.com/v1/x?a=1 HTTP/1.1", ["https://api.example.com/v1/x?a=1"]),
    "emails": ("mail root@mail.example.org now", ["root@mail.example.org"]),
    "ipv4": ("connect 192.168.10.25:443", ["192.168.10.25"]),
    "unix_paths": ("/usr/lib/x86_64-linux-gnu/libssl.so.3", ["/usr/lib/x86_64-linux-gnu/libssl.so.3"]),
    "windows_paths": ("C:\\Windows\\System32\\kernel32.dll", ["C:\\Windows\\System32\\kernel32.dll"]),
    "executables": ("run notepad.exe and libssl.so.3", ["notepad.exe", "libssl.so.3"]),
    "archives": ("drop payload.tar.gz then a.zip", ["payload.tar.gz", "a.zip"]),
    "pem_markers": ("-----BEGIN RSA PRIVATE KEY-----", ["-----BEGIN RSA PRIVATE KEY-----"]),
    "base64": ("Zk9vQmFyMTIzNDU2Nzg5MGFiY2RlZg==", ["Zk9vQmFyMTIzNDU2Nzg5MGFiY2RlZg=="]),
}


@pytest.mark.parametrize("kind", sorted(SAMPLES))
def test_each_ioc_pattern_matches_its_sample(kind):
    text, expected = SAMPLES[kind]
    assert ioc_matches(text)[kind] == expected


def test_non_iocs_match_nothing():
    for text in ("hello world", "version 1.2", "999.1.1.1", "/foo", "short", "AAAA="):
        assert ioc_kinds(text) == [], text


def test_ioc_query_is_registered_and_lists_its_dependency():
    query = saved_queries()["strings_iocs"]
    assert query.requires == {"strings": "memdiver strings table --case"}
    assert all(f"AS {name}" in query.sql for name in IOC_PATTERNS)


# -- case table + saved query ---------------------------------------------------------------


def test_case_table_and_saved_query_match_the_python_twins(gap_msl, tmp_path):
    case = Case.init(tmp_path / "case")
    out = _table(dump_path=gap_msl, case_dir=str(case.dir))
    assert out["case"]["table"] == "strings" and out["case"]["rows"] == out["row_count"]
    res = vol3_query_result(str(case.dir), saved="strings_iocs").payload
    assert res["saved"] == "strings_iocs"
    cols = [c if isinstance(c, str) else c["name"] for c in res["columns"]]
    row = dict(zip(cols, res["rows"][0])) if not isinstance(res["rows"][0], dict) \
        else res["rows"][0]
    assert row["urls"] == ["https://srv.example.org/x"] and row["ipv4"] == ["10.1.2.3"]
    assert len(res["rows"]) == sum(1 for r in out["rows"] if r["iocs"])


def test_saved_query_refuses_a_truncated_strings_table(gap_msl, tmp_path):
    case = Case.init(tmp_path / "case")
    _table(dump_path=gap_msl, case_dir=str(case.dir), limit=1)
    with pytest.raises(CapabilityError):
        vol3_query_result(str(case.dir), saved="strings_iocs")


def test_saved_query_without_the_table_names_the_producer(tmp_path):
    case = Case.init(tmp_path / "case")
    with pytest.raises(CapabilityError) as err:
        vol3_query_result(str(case.dir), saved="strings_iocs")
    assert "memdiver strings table --case" in str(err.value)


# -- surfaces ------------------------------------------------------------------------------------


def _cli(argv, capsys):
    from memdiver.cli import _build_parser, _cmd_strings
    rc = _cmd_strings(_build_parser().parse_args(["strings", *argv]))
    return rc, capsys.readouterr().out


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
def manager(monkeypatch, tmp_path):
    fake = FakeManager(tmp_path / "tasks")
    monkeypatch.setattr("memdiver.api.routers.strings.task_manager_or_503", lambda: fake)
    return fake


@pytest.fixture(scope="module")
def mcp_tools():
    pytest.importorskip("mcp")
    from memdiver.mcp_server.server import create_server
    return {t.name: t for t in create_server()._tool_manager.list_tools()}


def test_four_surfaces_return_the_same_rows(gap_msl, client, mcp_tools, capsys):
    expected = _table(dump_path=gap_msl)
    _, out = _cli(["table", gap_msl], capsys)
    cli = json.loads(out)
    rest = client.post("/api/strings/table", json={"dump_path": gap_msl}).json()
    mcp = json.loads(mcp_tools["strings_table"].fn(dump_path=gap_msl))
    mcp_payload = mcp.get("data", mcp)
    for payload in (cli, rest, mcp_payload):
        assert payload["rows"] == json.loads(json.dumps(expected["rows"]))
        assert payload["coverage"] == expected["coverage"]


def test_cli_registers_case_and_writes_output(gap_msl, capsys, tmp_path):
    case = Case.init(tmp_path / "case")
    target = tmp_path / "out.json"
    rc, _ = _cli(["table", gap_msl, "--case", str(case.dir), "-o", str(target),
                  "--encoding", "ascii", "--min-len", "5"], capsys)
    payload = json.loads(target.read_text())
    assert rc == 0 and payload["case"]["rows"] == payload["row_count"]
    assert payload["encodings"] == ["ascii"] and payload["min_len"] == 5


def test_cli_no_action_and_bad_args(capsys):
    from memdiver.cli import _build_parser, _cmd_strings
    assert _cmd_strings(_build_parser().parse_args(["strings"])) == 1
    with pytest.raises(SystemExit):
        _build_parser().parse_args(["strings", "table", "d", "--encoding", "ebcdic"])


def test_inspect_strings_is_unchanged(capsys):
    from memdiver.cli import _build_parser
    args = _build_parser().parse_args(["inspect", "strings", "d"])
    assert args.inspect_action == "strings"


def test_rest_is_inline_for_small_and_a_job_when_large_or_async(
        gap_msl, client, manager, monkeypatch):
    r = client.post("/api/strings/table", json={"dump_path": gap_msl})
    assert r.status_code == 200 and "rows" in r.json() and not manager.submitted
    for body in ({"async": True}, {}):
        if not body:
            monkeypatch.setattr("memdiver.api.routers.strings.SYNC_MAX_BYTES", 1)
        r = client.post("/api/strings/table", json={"dump_path": gap_msl, **body})
        assert r.json() == {"task_id": "t" * 32, "status": "pending"}
    job = manager.submitted[-1]
    assert job["kind"] == "strings" and job["runner"].endswith("run_strings_job")
    assert job["params"]["args"]["encodings"] == ("ascii", "utf16le")


def test_rest_region_and_errors(gap_msl, client):
    r = client.post("/api/strings/table", json={"dump_path": gap_msl, "view": "va",
                                                "offset": 0x402000})
    assert [x["value"] for x in r.json()["rows"]] == ["FGHIJ"]
    assert client.post("/api/strings/table",
                       json={"dump_path": gap_msl, "min_lenn": 3}).status_code == 422
    assert client.post("/api/strings/table", json={"dump_path": gap_msl,
                                                   "encodings": ["x"]}).status_code == 400


def test_mcp_errors_are_structured(mcp_tools, gap_msl):
    out = json.loads(mcp_tools["strings_table"].fn(dump_path=gap_msl, encodings=["x"]))
    assert "error" in json.dumps(out).lower()


def test_job_runner_writes_the_artifact_and_emits_progress(gap_msl, tmp_path):
    from memdiver.app.pipeline.strings_task_runner import run_strings_job

    events = []
    ctx = SimpleNamespace(emit=lambda kind, **kw: events.append((kind, kw)),
                          artifact_dir=str(tmp_path / "art"))
    done = run_strings_job({"args": {"dump_path": gap_msl}, "artifact_dir": str(tmp_path / "art")},
                           ctx)
    assert done["artifacts"][0]["name"] == "strings_result"
    assert done["summary"]["row_count"] >= 3
    assert [k for k, _ in events][0] == "stage_start" and events[-1][0] == "stage_end"


def test_rest_keeps_a_kernel_va_string_exact_on_the_wire(tmp_path, client):
    kernel_va = 0xFFFF_FFFF_8100_0000
    page = _blank(PAGE)
    _plant(page, 0x41, b"kernel banner text")
    path = _write_msl(tmp_path / "kernel.msl", [(kernel_va, bytes(page), "[kernel]")])
    r = client.post("/api/strings/table", json={"dump_path": path, "view": "va"})
    assert r.status_code == 200
    expected = kernel_va + 0x41
    assert expected > 2 ** 53
    assert f'"addr":{expected}' in r.text.replace(" ", "")
    assert any(row["addr"] == expected for row in r.json()["rows"])


# -- review fixes: seams, short reads, hex flags, IOC/value agreement ----------------


@pytest.fixture
def small_windows(monkeypatch):
    from memdiver.app import tools_keyfinders as tk
    monkeypatch.setattr(tk, "WINDOW_BYTES", 1024)
    monkeypatch.setattr(tk, "WINDOW_OVERLAP", 128)


def _raw(tmp_path, buf) -> str:
    path = tmp_path / "w.raw"
    path.write_bytes(bytes(buf))
    return str(path)


def test_a_string_crossing_the_seam_is_reported_once_whole(tmp_path, small_windows):
    step = 1024 - 128
    buf = _blank(3 * step)
    _plant(buf, step - 50, b"S" * 100)            # crosses the seam, ends inside window 1
    out = _table(dump_path=_raw(tmp_path, buf), encodings=("ascii",))
    assert [(r["addr"], r["length"]) for r in out["rows"]] == [(step - 50, 100)]
    assert out["coverage"]["clipped_strings"] == 0


def test_a_wide_string_crossing_the_seam_is_reported_once(tmp_path, small_windows):
    step = 1024 - 128
    buf = _blank(3 * step)
    _plant(buf, step - 40, _wide("W" * 40))
    out = _table(dump_path=_raw(tmp_path, buf), encodings=("utf16le",))
    assert [(r["addr"], r["length"]) for r in out["rows"]] == [(step - 40, 40)]


def test_a_string_longer_than_the_window_is_one_clipped_row(tmp_path, small_windows):
    step = 1024 - 128
    buf = _blank(4 * step)
    _plant(buf, step - 50, b"L" * 2000)
    out = _table(dump_path=_raw(tmp_path, buf), encodings=("ascii",))
    (row,) = out["rows"]
    assert row["addr"] == step - 50 and row["length"] == 1024 - (step - 50)
    assert out["coverage"]["clipped_strings"] == 1


def test_a_short_read_makes_the_table_incomplete(tmp_path, monkeypatch):
    from memdiver.core.dump_source import open_dump
    path = _raw(tmp_path, _blank(0x400))
    with open_dump(path) as source:
        cls, real = type(source), type(source).read_range
    monkeypatch.setattr(cls, "read_range", lambda self, o, n, *a, **k: real(self, o, n, *a, **k)[:-4])
    out = _table(dump_path=path)
    assert out["coverage"]["short_reads"] == 1
    assert out["complete"] is False and out["incomplete_reason"] == "short_reads"


def test_cli_offset_and_length_accept_hex(flat, capsys):
    from memdiver.cli import _build_parser, _cmd_strings
    args = _build_parser().parse_args(["strings", "table", flat, "--offset", "0x180",
                                       "--length", "0x200"])
    assert _cmd_strings(args) == 0
    assert [r["addr"] for r in json.loads(capsys.readouterr().out)["rows"]] == [0x201]


def test_ioc_badges_agree_with_the_stored_value(tmp_path):
    tail = "x" * ts.MAX_VALUE_CHARS + " http://late.example.org/p"
    cut = _table(dump_path=_raw(tmp_path, tail.encode()), encodings=("ascii",))["rows"][0]
    assert cut["value_truncated"] is True and cut["iocs"] == ioc_kinds(cut["value"])
    assert "urls" not in cut["iocs"]
