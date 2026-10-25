"""Built-in saved queries over synthetic vol3 tables registered in a real case."""
from __future__ import annotations

import pyarrow as pa
import pytest

from memdiver.analysis.case import Case
from memdiver.analysis.queries import get_saved_query, saved_queries
from memdiver.app.tools_vol3 import vol3_query_result
from memdiver.core.service_errors import CapabilityError

A, B = "a" * 64, "b" * 64


def _register(case, name, capture, rows, **columns):
    case.register_table(name, pa.table(columns), capture_id=capture,
                        image_sha256=capture, producer="test")


def _pslist(case, capture, procs):
    _register(case, "vol3__linux_pslist", capture, procs,
              offset_v=pa.array([0x10 + p[0] for p in procs], pa.uint64()),
              pid=[p[0] for p in procs], tid=[p[0] for p in procs],
              ppid=[0] * len(procs), comm=[p[1] for p in procs])


@pytest.fixture
def case(tmp_path):
    case = Case.init(tmp_path / "case")
    _pslist(case, A, [(1, "init"), (2, "sshd"), (3, "bash")])
    _pslist(case, B, [(1, "init"), (2, "sshd")])
    _register(case, "vol3__linux_psscan", A, None,
              offset_p=pa.array([1, 2, 3, 4], pa.uint64()), pid=[1, 2, 3, 666],
              tid=[1, 2, 3, 666], ppid=[0, 1, 1, 1], comm=["init", "sshd", "bash", "rootkit"],
              exit_state=["", "", "", "EXIT_DEAD"])
    _register(case, "vol3__linux_sockstat", A, None, process_name=["sshd", "sshd"],
              pid=[2, 2], tid=[2, 2], fd=[3, 4], family=["AF_INET"] * 2, type=["STREAM"] * 2,
              proto=["TCP"] * 2, source_addr=["0.0.0.0", "1.1.1.1"], source_port=["22", "22"],
              destination_addr=["0.0.0.0"] * 2, destination_port=["0"] * 2,
              state=["LISTEN", "ESTABLISHED"])
    _register(case, "vol3__linux_proc", A, None, pid=[2, 2, 2, 2, 3, 3],
              process=["sshd"] * 4 + ["bash"] * 2,
              start=pa.array([1, 2, 3, 4, 5, 6], pa.uint64()),
              end=pa.array([2, 3, 4, 5, 6, 7], pa.uint64()),
              flags=["r-x", "rwx", "r-x", "r-x", "r--", "r-x"],
              file_path=["/lib/libc.so", "/lib/libc.so", "Anonymous Mapping", "[stack]",
                         "/bin/bash", "/bin/bash"])
    return case


def _run(case, name):
    out = vol3_query_result(str(case.dir), saved=name).payload
    return [dict(zip(out["columns"], r)) for r in out["rows"]]


def test_all_queries_have_required_tables_and_plugins():
    for query in saved_queries().values():
        assert query.requires and all(p.startswith("linux.") for p in query.requires.values())
        assert query.description and query.sql.lstrip().upper().startswith("SELECT")


def test_hidden_processes_finds_psscan_only_pid(case):
    rows = _run(case, "hidden_processes")
    assert [(r["capture_id"], r["pid"], r["comm"]) for r in rows] == [(A, 666, "rootkit")]


def test_hidden_processes_is_per_capture(case):
    _register(case, "vol3__linux_psscan", B, None, offset_p=pa.array([9], pa.uint64()),
              pid=[3], tid=[3], ppid=[1], comm=["bash"], exit_state=[""])
    got = {(r["capture_id"], r["pid"]) for r in _run(case, "hidden_processes")}
    assert got == {(A, 666), (B, 3)}   # pid 3 is visible in A but hidden in B


def test_processes_with_sockets(case):
    rows = _run(case, "processes_with_sockets")
    assert [(r["pid"], r["comm"], r["fd"], r["state"]) for r in rows] == [
        (2, "sshd", 3, "LISTEN"), (2, "sshd", 4, "ESTABLISHED")]


def test_rwx_and_anonymous_executable_mappings(case):
    rows = _run(case, "rwx_mappings")
    assert [(r["start"], r["flags"], r["file_path"]) for r in rows] == [
        (2, "rwx", "/lib/libc.so"), (3, "r-x", "Anonymous Mapping")]


def test_modules_per_process_are_distinct_file_backed(case):
    rows = _run(case, "modules_per_process")
    assert [(r["pid"], r["file_path"]) for r in rows] == [
        (2, "/lib/libc.so"), (3, "/bin/bash")]


def test_process_diff_across_images(case):
    rows = _run(case, "process_diff")
    assert [(r["comm"], r["images"], r["present_in"]) for r in rows] == [("bash", 1, [A])]


def test_missing_table_is_precondition_naming_plugin(tmp_path):
    empty = Case.init(tmp_path / "empty")
    with pytest.raises(CapabilityError) as err:
        vol3_query_result(str(empty.dir), saved="processes_with_sockets")
    assert "linux.sockstat.Sockstat" in str(err.value) and err.value.code == "vol3.missing_tables"
    assert get_saved_query("process_diff").requires == {
        "vol3__linux_pslist": "linux.pslist.PsList"}
