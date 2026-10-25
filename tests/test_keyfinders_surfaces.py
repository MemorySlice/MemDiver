"""The ``keyfinders.*`` capabilities on all four surfaces (plan T3.3).

Synthetic dumps with a planted AES key schedule: a flat raw file, and ``.msl``
captures (a glibc heap region, a non-heap region, and schedules planted across a
capture gap that must NOT be found and must never be read as zeros). Producer,
heap policies, truncation, the ``key_hits`` case table joined to ``heap_chunks`` /
``msl_regions``, CLI (real argv), REST (real JSON) and MCP parity.
"""
from __future__ import annotations

import json
import random
from types import SimpleNamespace

import pytest

from memdiver.algorithms.keyfinders.aes_tables import expand_key
from memdiver.analysis.case import Case
from memdiver.analysis.record_store import AnalysisRecord
from memdiver.app import tools_case, tools_keyfinders as tk
from memdiver.core.service_errors import CapabilityError, ErrorCategory
from memdiver.msl.enums import ArchType, OSType, PageState
from memdiver.msl.types import MslVasEntry
from memdiver.msl.writer import MslWriter
from tests.fixtures import synth_heap as sh

PAGE = 0x1000
KEY = bytes(range(16, 32))
KEY2 = bytes(range(40, 56))
KEY3 = bytes(range(80, 96))
SCHEDULE, SCHEDULE2, SCHEDULE3 = (expand_key(k) for k in (KEY, KEY2, KEY3))
OTHER_VA = 0x7F00_0000_0000
C, F = PageState.CAPTURED, PageState.FAILED


def _noise(length: int, seed: int) -> bytes:
    """Deterministic non-constant filler that is not a key schedule."""
    return bytes((seed * 31 + i * 7 + (i >> 3) * 13) & 0xFF for i in range(length))


def _plant(buf: bytearray, offset: int, blob: bytes) -> None:
    buf[offset:offset + len(blob)] = blob


def _write_msl(path, regions, page_states=None) -> str:
    """``regions``: (va, bytes, name); one VAS entry per region."""
    writer = MslWriter(str(path), os_type=OSType.LINUX, arch_type=ArchType.X86_64,
                       imported=True)
    for va, data, _name in regions:
        states = (page_states or {}).get(va)
        writer.add_memory_region(va, data, protection=0x03, page_states=states)
    writer.add_vas_map([MslVasEntry(va, len(data) if not (page_states or {}).get(va)
                                    else PAGE * len(page_states[va]), 0x03, 0, name)
                        for va, data, name in regions])
    writer.add_end_of_capture()
    writer.write()
    return str(path)


def _heap_region(schedule_chunks=(SCHEDULE,)):
    """glibc heap region with schedules planted in the 0x100 in-use chunk's data."""
    heap = sh.glibc_heap()
    buf = bytearray(heap.region_bytes(0))
    chunk = heap.chunks[-2]
    assert chunk.user_len >= len(SCHEDULE) + 8
    _plant(buf, chunk.va + chunk.header_len + 8 - heap.base_va, schedule_chunks[0])
    return heap, bytes(buf)


@pytest.fixture(autouse=True)
def _xdg(tmp_path, monkeypatch):
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "xdg"))


@pytest.fixture
def heap_msl(tmp_path):
    """Heap (schedule in chunk user data) + a non-heap region with a second schedule."""
    heap, heap_bytes = _heap_region()
    other = bytearray(_noise(PAGE, 3))
    _plant(other, 0x200, SCHEDULE2)
    path = _write_msl(tmp_path / "heap.msl", [(heap.base_va, heap_bytes, "[heap]"),
                                              (OTHER_VA, bytes(other), "/lib/libssl.so")])
    return SimpleNamespace(path=path, heap=heap, other_va=OTHER_VA)


def _rows(**kw):
    return tk.keyfinders_scan_result(**kw).payload


# -- finder discovery ---------------------------------------------------------------


def test_list_discovers_finders_in_the_keyfinders_package():
    out = tk.keyfinders_list_result().payload
    names = {f["name"] for f in out["finders"]}
    assert "aes_schedule" in names and out["count"] == len(names)
    assert all(f["module"].startswith(tk.FINDERS_PACKAGE) for f in out["finders"])
    aes = next(f for f in out["finders"] if f["name"] == "aes_schedule")
    assert {p["name"] for p in aes["parameters"]} >= {"stride", "aes_min_confidence"}
    assert next(p for p in aes["parameters"] if p["name"] == "stride")["default"] == 1
    assert out["heap_policies"] == ["off", "annotate", "mask"]


# -- raw dumps -----------------------------------------------------------------------


def test_raw_dump_hit_carries_file_offset_space(tmp_path):
    buf = bytearray(_noise(0x3000, 1))
    _plant(buf, 0x1235, SCHEDULE)           # unaligned on purpose
    dump = tmp_path / "flat.raw"
    dump.write_bytes(bytes(buf))
    out = _rows(dump_path=str(dump))
    (row,) = out["rows"]
    assert (row["addr"], row["space"]) == (0x1235, "file_offset")
    assert row["location"]["space"] == "file_offset" and row["length"] == len(SCHEDULE)
    assert row["metadata"]["key_hex"] == KEY.hex() and row["va"] is None
    assert row["heap"] is None and row["region"] is None
    assert out["coverage"]["bytes_scanned"] == 0x3000 and out["complete"] is True


def test_raw_zero_fill_is_never_a_finding(tmp_path):
    dump = tmp_path / "zeros.raw"
    dump.write_bytes(bytes(0x4000))
    assert _rows(dump_path=str(dump))["rows"] == []


def test_offset_length_window_clips_the_scan(tmp_path):
    buf = bytearray(_noise(0x3000, 2))
    _plant(buf, 0x100, SCHEDULE)
    _plant(buf, 0x2000, SCHEDULE2)
    dump = tmp_path / "flat.raw"
    dump.write_bytes(bytes(buf))
    out = _rows(dump_path=str(dump), offset=0x1000, length=0x2000)
    assert [r["addr"] for r in out["rows"]] == [0x2000]
    assert out["coverage"]["bytes_scanned"] == 0x2000


# -- .msl: coordinates, heap, region -------------------------------------------------


def test_msl_va_hit_has_coordinates_heap_and_region(heap_msl):
    out = _rows(dump_path=heap_msl.path)
    assert out["view"] == "va" and out["space"] == "msl_va" and out["heap"]["status"] == "ok"
    by_key = {r["metadata"]["key_hex"]: r for r in out["rows"]}
    assert set(by_key) == {KEY.hex(), KEY2.hex()}
    row = by_key[KEY.hex()]
    chunk = heap_msl.heap.chunks[-2]
    assert row["addr"] == row["va"] == chunk.va + chunk.header_len + 8
    assert row["location"]["space"] == "msl_va" and row["location"]["capture_id"]
    assert row["heap"]["chunk_va"] == chunk.va and row["heap"]["role"] == "user_data"
    assert row["heap"]["spans_chunks"] is False
    assert row["region"]["path"] == "[heap]" and row["region"]["perms"] == "rw-"
    other = by_key[KEY2.hex()]
    assert other["addr"] == heap_msl.other_va + 0x200 and other["heap"] is None
    assert other["region"]["path"] == "/lib/libssl.so"


def test_candidates_use_the_candidates_json_shape_and_point_at_the_key(heap_msl, tmp_path):
    from memdiver.core.dump_source import open_dump
    out = _rows(dump_path=heap_msl.path, candidates_out=str(tmp_path / "c" / "candidates.json"))
    written = json.loads((tmp_path / "c" / "candidates.json").read_text())
    assert written["regions"] == out["candidates"] and out["candidates_path"]
    with open_dump(heap_msl.path) as source:
        for cand, row in zip(out["candidates"], out["rows"]):
            assert {"offset", "length"} <= set(cand)
            assert source.read_range(cand["offset"], cand["length"], "vas").hex() \
                == row["metadata"]["key_hex"]


def test_vas_view_reports_packed_offsets(heap_msl):
    out = _rows(dump_path=heap_msl.path, view="vas")
    assert out["space"] == "msl_vas"
    for row in out["rows"]:
        assert row["addr"] == row["vas_offset"] and row["va"] is not None
        assert row["location"]["space"] == "msl_vas"
    assert {r["metadata"]["key_hex"] for r in out["rows"]} == {KEY.hex(), KEY2.hex()}


# -- capture gaps --------------------------------------------------------------------


def _gap_msl(tmp_path, split: int):
    """A schedule split ``split`` bytes into the first of two regions with a VA gap."""
    first, second = bytearray(_noise(PAGE, 5)), bytearray(_noise(PAGE, 6))
    _plant(first, PAGE - split, SCHEDULE[:split])
    _plant(second, 0, SCHEDULE[split:])
    return _write_msl(tmp_path / "gap.msl", [(0x400000, bytes(first), "a"),
                                             (0x402000, bytes(second), "b")])


@pytest.mark.parametrize("view", ["va", "vas"])
def test_schedule_straddling_a_region_gap_is_not_found(tmp_path, view):
    from memdiver.core.dump_source import open_dump
    path = _gap_msl(tmp_path, 88)
    with open_dump(path) as source:        # the two runs ARE contiguous in the packed view
        packed = source.read_range(0, source.size_for("vas"), "vas")
    assert SCHEDULE in packed
    out = _rows(dump_path=path, view=view)
    assert out["rows"] == [] and out["coverage"]["gaps_skipped"] == 1
    assert out["coverage"]["gap_bytes"] == PAGE and out["coverage"]["runs_scanned"] == 2


def test_failed_page_inside_a_region_is_a_gap_not_zeros(tmp_path):
    first = bytearray(_noise(PAGE, 7))
    second = bytearray(_noise(PAGE, 8))
    _plant(first, PAGE - 88, SCHEDULE[:88])
    _plant(second, 0, SCHEDULE[88:])
    path = _write_msl(tmp_path / "failed.msl",
                      [(0x400000, bytes(first) + bytes(second), "r")],
                      page_states={0x400000: [C, F, C]})
    out = _rows(dump_path=path)
    assert out["rows"] == [] and out["coverage"]["gaps_skipped"] == 1
    assert out["coverage"]["captured_bytes"] == 2 * PAGE


def test_schedule_inside_one_run_next_to_a_gap_is_found(tmp_path):
    page = bytearray(_noise(PAGE, 9))
    _plant(page, 0x40, SCHEDULE)
    path = _write_msl(tmp_path / "ok.msl", [(0x400000, bytes(page), "a"),
                                            (0x402000, _noise(PAGE, 4), "b")])
    out = _rows(dump_path=path)
    assert [r["addr"] for r in out["rows"]] == [0x400040]
    assert out["coverage"]["gaps_skipped"] == 1


# -- heap policies / truncation ------------------------------------------------------


def test_heap_policy_off_annotate_mask(heap_msl):
    off = _rows(dump_path=heap_msl.path, heap_policy="off")
    assert off["heap"]["status"] == "off" and all(r["heap"] is None for r in off["rows"])
    assert len(off["rows"]) == 2
    mask = _rows(dump_path=heap_msl.path, heap_policy="mask")
    assert [r["metadata"]["key_hex"] for r in mask["rows"]] == [KEY.hex()]
    assert mask["heap"]["masked_out"] == 1 and mask["complete"] is True
    annotate = _rows(dump_path=heap_msl.path, heap_policy="annotate")
    assert len(annotate["rows"]) == 2 and annotate["heap"]["masked_out"] == 0


def test_mask_without_a_heap_reports_it_instead_of_pretending(tmp_path):
    page = bytearray(_noise(PAGE, 11))
    _plant(page, 0x80, SCHEDULE)
    path = _write_msl(tmp_path / "noheap.msl", [(0x400000, bytes(page), "a")])
    out = _rows(dump_path=path, heap_policy="mask")
    assert out["rows"] == [] and out["heap"]["status"] == "no_heap_detected"


def test_limit_truncates_visibly_and_stops_the_scan(tmp_path):
    page = bytearray(_noise(3 * PAGE, 12))
    for i, blob in enumerate((SCHEDULE, SCHEDULE2, SCHEDULE3)):
        _plant(page, i * PAGE + 0x10, blob)
    dump = tmp_path / "three.raw"
    dump.write_bytes(bytes(page))
    full = _rows(dump_path=str(dump))
    assert full["row_count"] == 3 and full["truncated"] is False
    cut = _rows(dump_path=str(dump), limit=2)
    assert cut["row_count"] == 2 and cut["truncated"] is True and cut["complete"] is False
    assert [r["addr"] for r in cut["rows"]] == [r["addr"] for r in full["rows"][:2]]
    exact = _rows(dump_path=str(dump), limit=3)
    assert exact["row_count"] == 3 and exact["truncated"] is False


@pytest.mark.parametrize("kwargs,code", [
    ({"finders": ("nope",)}, "keyfinders.unknown_finder"),
    ({"heap_policy": "wild"}, "keyfinders.bad_heap_policy"),
    ({"limit": 0}, "invalid_limit"),
    ({"offset": -1}, "keyfinders.bad_range"),
    ({"view": "vas"}, "keyfinders.bad_view"),
])
def test_bad_input_is_a_capability_error(tmp_path, kwargs, code):
    dump = tmp_path / "x.raw"
    dump.write_bytes(_noise(64, 1))
    with pytest.raises(CapabilityError) as err:
        tk.keyfinders_scan_result(str(dump), **kwargs)
    assert err.value.category == ErrorCategory.INVALID_INPUT and err.value.code == code


def test_missing_dump_is_not_found(tmp_path):
    with pytest.raises(CapabilityError) as err:
        tk.keyfinders_scan_result(str(tmp_path / "nope.msl"))
    assert err.value.category == ErrorCategory.NOT_FOUND


# -- case integration -----------------------------------------------------------------


def test_case_table_annotations_and_join_with_heap_and_regions(heap_msl, tmp_path):
    case = Case.init(tmp_path / "case")
    out = _rows(dump_path=heap_msl.path, case_dir=str(case.dir))
    assert out["case"]["table"] == "key_hits" and out["case"]["rows"] == 2
    assert out["case"]["annotations"] == 2
    tools_case.case_export_result(str(case.dir), heap_msl.path)
    sql = ("SELECT k.key_hex, k.finder, k.heap_role, h.addr AS chunk_va, h.state, "
           "r.protection, r.mapped_path FROM key_hits k "
           "JOIN heap_chunks h ON k.va >= h.addr AND k.va < h.addr + h.size "
           "JOIN msl_regions r ON k.va >= r.addr AND k.va < r.addr + r.size")
    rows = tools_case.case_query_result(str(case.dir), sql).payload["rows"]
    assert len(rows) == 1                   # only the heap hit lies in a heap chunk
    key_hex, finder, role, chunk_va, state, _prot, path = rows[0]
    assert (key_hex, finder, role) == (KEY.hex(), "aes_schedule", "user_data")
    assert chunk_va == heap_msl.heap.chunks[-2].va and state == "in_use"
    assert path == "[heap]"
    schema = tools_case.case_schema_result(str(case.dir)).payload["tables"]["key_hits"]
    assert {"addr", "space", "size", "finder", "key_hex", "va", "heap_chunk_va",
            "region_start", "capture_id", "run_id"} <= {c["name"] for c in schema["columns"]}
    entries = AnalysisRecord(case.dir).latest(out["capture_id"], "key_hit")
    assert len(entries) == 2 and {e.payload["finder"] for e in entries} == {"aes_schedule"}
    assert all(e.locations[0].space.value == "msl_va" for e in entries)


def test_case_without_annotate_registers_the_table_only(heap_msl, tmp_path):
    case = Case.init(tmp_path / "case")
    out = _rows(dump_path=heap_msl.path, case_dir=str(case.dir), annotate=False)
    assert out["case"]["annotations"] == 0
    assert AnalysisRecord(case.dir).captures() == []


def test_truncation_is_recorded_on_the_case_run(tmp_path):
    page = bytearray(_noise(2 * PAGE, 13))
    _plant(page, 0x10, SCHEDULE)
    _plant(page, PAGE + 0x10, SCHEDULE2)
    dump = tmp_path / "two.raw"
    dump.write_bytes(bytes(page))
    case = Case.init(tmp_path / "case")
    out = _rows(dump_path=str(dump), case_dir=str(case.dir), limit=1)
    (ref,) = Case.open(case.dir).runs("key_hits")
    assert out["truncated"] is True and ref.truncated is True


# -- surfaces: CLI / REST / MCP parity -----------------------------------------------


def _cli(argv, capsys):
    from memdiver.cli import _build_parser, _cmd_keys
    rc = _cmd_keys(_build_parser().parse_args(["keys", *argv]))
    return rc, capsys.readouterr().out


class FakeManager:
    def __init__(self, root):
        self.artifact_store = SimpleNamespace(root=root)
        self.submitted = []

    def submit(self, *, kind, params, runner_dotted, stage_names=None):
        self.submitted.append(dict(kind=kind, params=params, runner=runner_dotted))
        return SimpleNamespace(task_id="t" * 32, status=SimpleNamespace(value="pending"))


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
    monkeypatch.setattr("memdiver.api.routers.keyfinders.task_manager_or_503", lambda: fake)
    return fake


@pytest.fixture(scope="module")
def mcp_tools():
    pytest.importorskip("mcp")
    from memdiver.mcp_server.server import create_server
    return {t.name: t for t in create_server()._tool_manager.list_tools()}


def test_four_surfaces_return_the_same_rows(heap_msl, client, mcp_tools, capsys):
    expected = json.loads(json.dumps(_rows(dump_path=heap_msl.path)["rows"]))
    assert len(expected) == 2
    rc, out = _cli(["scan", heap_msl.path, "--finder", "aes_schedule",
                    "--heap-policy", "annotate"], capsys)
    assert rc == 0 and json.loads(out)["rows"] == expected
    r = client.post("/api/keyfinders/scan", json={"dump_path": heap_msl.path})
    assert r.status_code == 200 and r.json()["rows"] == expected
    mcp = json.loads(mcp_tools["keyfinders_scan"].fn(dump_path=heap_msl.path))
    assert mcp["rows"] == expected


def test_list_parity_across_surfaces(client, mcp_tools, capsys):
    expected = tk.keyfinders_list_result().payload
    _, out = _cli(["list"], capsys)
    assert json.loads(out) == expected
    assert client.get("/api/keyfinders").json() == expected
    assert json.loads(mcp_tools["keyfinders_list"].fn()) == expected


def test_cli_scan_registers_case_and_candidates(heap_msl, capsys, tmp_path):
    case = Case.init(tmp_path / "case")
    cands = tmp_path / "cands.json"
    _, out = _cli(["scan", heap_msl.path, "--case", str(case.dir), "--candidates-out",
                   str(cands), "--heap-policy", "mask"], capsys)
    payload = json.loads(out)
    assert payload["case"]["rows"] == 1 and json.loads(cands.read_text())["regions"]


def test_cli_no_action_and_bad_args(capsys):
    from memdiver.cli import _build_parser, _cmd_keys
    assert _cmd_keys(_build_parser().parse_args(["keys"])) == 1
    with pytest.raises(SystemExit):
        _build_parser().parse_args(["keys", "scan", "d", "--heap-policy", "wild"])


def test_rest_is_inline_for_a_small_scan_and_a_job_when_large_or_async(
        heap_msl, client, manager, monkeypatch):
    r = client.post("/api/keyfinders/scan", json={"dump_path": heap_msl.path})
    assert r.status_code == 200 and "rows" in r.json() and not manager.submitted
    for body in ({"async": True}, {}):
        if not body:
            monkeypatch.setattr("memdiver.api.routers.keyfinders.SYNC_MAX_BYTES", 1)
        r = client.post("/api/keyfinders/scan", json={"dump_path": heap_msl.path, **body})
        assert r.json() == {"task_id": "t" * 32, "status": "pending"}
    job = manager.submitted[-1]
    assert job["kind"] == "keyfinders"
    assert job["runner"].endswith("keyfinders_task_runner.run_keyfinders_job")
    assert job["params"]["args"]["finders"] == ("aes_schedule",)


def test_rest_misspelled_field_is_422_and_errors_are_structured(heap_msl, client):
    assert client.post("/api/keyfinders/scan",
                       json={"dump_path": heap_msl.path, "heap_polcy": "off"}).status_code == 422
    r = client.post("/api/keyfinders/scan", json={"dump_path": heap_msl.path,
                                                  "finders": ["nope"]})
    assert r.status_code == 400


def test_mcp_errors_are_structured(mcp_tools, heap_msl):
    out = json.loads(mcp_tools["keyfinders_scan"].fn(dump_path=heap_msl.path,
                                                     finders=["nope"]))
    assert "error" in json.dumps(out).lower()


def test_job_runner_writes_the_artifact_and_emits_progress(heap_msl, tmp_path):
    from memdiver.app.pipeline.keyfinders_task_runner import run_keyfinders_job

    class Ctx:
        def __init__(self):
            self.events = []

        def emit(self, kind, **kw):
            self.events.append((kind, kw))

    ctx = Ctx()
    result = run_keyfinders_job({"args": {"dump_path": heap_msl.path},
                                 "artifact_dir": str(tmp_path / "art")}, ctx)
    assert result["summary"]["row_count"] == 2
    (artifact,) = result["artifacts"]
    assert artifact["name"] == "keyfinders_result"
    assert [k for k, _ in ctx.events][0] == "stage_start" and ctx.events[-1][0] == "stage_end"
    assert any(k == "progress" for k, _ in ctx.events)
    with pytest.raises(ValueError):
        run_keyfinders_job({"args": {"dump_path": heap_msl.path, "finders": ["nope"]},
                            "artifact_dir": str(tmp_path / "art")}, Ctx())


def test_dump_without_a_vas_map_still_gets_region_context_and_table(tmp_path):
    page = bytearray(_noise(PAGE, 14))
    _plant(page, 0x20, SCHEDULE)
    path = tmp_path / "novas.msl"
    writer = MslWriter(str(path), os_type=OSType.LINUX, arch_type=ArchType.X86_64,
                       imported=True)
    writer.add_memory_region(0x400000, bytes(page), protection=0x05)
    writer.add_end_of_capture()
    writer.write()
    out = _rows(dump_path=str(path), heap_policy="off")
    assert out["rows"][0]["region"] == {"start": 0x400000, "end": 0x400000 + PAGE,
                                        "perms": "r-x", "path": None,
                                        "type": out["rows"][0]["region"]["type"]}
    case = Case.init(tmp_path / "case")
    tools_case.case_export_result(str(case.dir), str(path), ("msl_regions",))
    rows = tools_case.case_query_result(
        str(case.dir), "SELECT addr, size FROM msl_regions").payload["rows"]
    assert rows == [[0x400000, PAGE]]


KERNEL_VA = 0xFFFF_FFFF_8100_0000


def test_rest_keeps_a_kernel_va_hit_exact_on_the_wire(tmp_path, client):
    """A kernel VA exceeds 2**53: the response TEXT must carry every digit (the client
    parses it losslessly), and the job artifact must too."""
    page = bytearray(_noise(PAGE, 21))
    _plant(page, 0x41, SCHEDULE)
    path = _write_msl(tmp_path / "kernel.msl", [(KERNEL_VA, bytes(page), "[kernel]")])
    r = client.post("/api/keyfinders/scan", json={"dump_path": path, "view": "va"})
    assert r.status_code == 200
    expected = KERNEL_VA + 0x41
    assert expected > 2 ** 53
    assert f'"addr":{expected}' in r.text.replace(" ", "")
    assert json.loads(r.text)["rows"][0]["addr"] == expected

    from memdiver.app.pipeline.keyfinders_task_runner import run_keyfinders_job

    class Ctx:
        def emit(self, kind, **kw):
            pass

    out = run_keyfinders_job({"args": {"dump_path": path, "view": "va"},
                              "artifact_dir": str(tmp_path / "art")}, Ctx())
    (artifact,) = out["artifacts"]
    text = (tmp_path / "art" / artifact["relpath"]).read_text()
    assert str(expected) in text


# -- review fixes: absolute stride grid, seams, short reads, hex flags ----------------


@pytest.fixture
def small_windows(monkeypatch):
    """4 KiB windows with a 512 B overlap: seams become testable on tiny dumps."""
    monkeypatch.setattr(tk, "WINDOW_BYTES", 4096)
    monkeypatch.setattr(tk, "WINDOW_OVERLAP", 512)


def test_stride_grid_is_absolute_not_relative_to_the_offset(tmp_path):
    buf = bytearray(_noise(0x2000, 12))
    _plant(buf, 8, SCHEDULE)
    dump = tmp_path / "grid.raw"
    dump.write_bytes(bytes(buf))
    out = _rows(dump_path=str(dump), offset=2, params={"stride": 4})
    assert [r["addr"] for r in out["rows"]] == [8]
    assert out["coverage"]["bytes_scanned"] == 0x2000 - 2


def test_a_hit_before_the_requested_offset_is_never_reported(tmp_path):
    buf = bytearray(_noise(0x2000, 13))
    _plant(buf, 8, SCHEDULE)
    dump = tmp_path / "before.raw"
    dump.write_bytes(bytes(buf))
    assert _rows(dump_path=str(dump), offset=10, params={"stride": 4})["rows"] == []


def test_a_window_seam_reports_a_match_once(tmp_path, small_windows):
    step = 4096 - 512
    buf = bytearray(_noise(3 * step, 14))
    _plant(buf, step - 40, SCHEDULE)          # starts before the seam, ends after it
    dump = tmp_path / "seam.raw"
    dump.write_bytes(bytes(buf))
    out = _rows(dump_path=str(dump), finders=("aes_schedule",))
    assert [r["addr"] for r in out["rows"]] == [step - 40]


def test_a_seam_crossing_entropy_region_is_reported_once_and_whole(tmp_path, small_windows):
    step = 4096 - 512
    buf = bytearray(b"\x01" * (3 * step))
    buf[step - 100:step + 100] = random.Random(5).randbytes(200)
    dump = tmp_path / "entropy.raw"
    dump.write_bytes(bytes(buf))
    kw = dict(dump_path=str(dump), finders=("entropy_window",), params={"window_sizes": [32]})
    small = [(r["addr"], r["length"]) for r in _rows(**kw)["rows"]]
    tk.WINDOW_BYTES = 1 << 20
    whole = [(r["addr"], r["length"]) for r in _rows(**kw)["rows"]]
    assert small == whole and len(small) >= 1


def test_a_short_read_makes_the_scan_incomplete_with_a_reason(tmp_path, monkeypatch):
    from memdiver.core.dump_source import open_dump
    dump = tmp_path / "short.raw"
    dump.write_bytes(_noise(0x2000, 15))
    with open_dump(dump) as source:
        cls, real = type(source), type(source).read_range
    monkeypatch.setattr(cls, "read_range", lambda self, o, n, *a, **k: real(self, o, n, *a, **k)[:-8])
    out = _rows(dump_path=str(dump))
    assert out["coverage"]["short_reads"] == 1
    assert out["complete"] is False and out["incomplete_reason"] == "short_reads"
    monkeypatch.undo()
    clean = _rows(dump_path=str(dump))
    assert clean["complete"] is True and clean["incomplete_reason"] is None


def test_cli_offset_and_length_accept_hex(tmp_path, capsys):
    buf = bytearray(_noise(0x3000, 2))
    _plant(buf, 0x100, SCHEDULE)
    _plant(buf, 0x2000, SCHEDULE2)
    dump = tmp_path / "flat.raw"
    dump.write_bytes(bytes(buf))
    rc, text = _cli(["scan", str(dump), "--offset", "0x1000", "--length", "0x2000"], capsys)
    assert rc == 0 and [r["addr"] for r in json.loads(text)["rows"]] == [0x2000]
