"""Tests for isf.tryloop: ground-truth parsing, comparison, verdicts, try_isf."""

from __future__ import annotations

import json
import os
from pathlib import Path
from types import SimpleNamespace

import pytest

from memdiver.core.service_errors import CapabilityError
from memdiver.isf import tryloop as tl
from memdiver.isf.tryloop import (
    Comparison, GroundTruth, GroundTruthTask, canonical, compare_pslist,
    implicated_by_comparison, implicated_by_error, parse_ground_truth, try_isf, verdict_of,
)

VOL3_HEADER = "OFFSET (V)\tPID\tTID\tPPID\tCOMM\tUID\tGID\tEUID\tEGID\tCREATION TIME\tFile output"
COLS = ["OFFSET (V)", "PID", "TID", "PPID", "COMM"]


def _vol3_text(rows):
    lines = ["Volatility 3 Framework 2.28.2", "", VOL3_HEADER, ""]
    for off, pid, tid, ppid, comm in rows:
        lines.append(f"{off}\t{pid}\t{tid}\t{ppid}\t{comm}\t0\t0\t0\t0\t2026-09-13 16:12:26 UTC\tDisabled")
    return "\n".join(lines) + "\n"


PS_TEXT = """UID        PID  PPID  C STIME TTY          TIME CMD
root         1     0  2 16:12 ?        00:00:10 /sbin/init splash --flag
root         2     0  0 16:12 ?        00:00:00 [kthreadd]
root         5     2  0 16:12 ?        00:00:00 [kworker/0:0-events]
root       900     1  0 16:12 ?        00:00:00 python3 -c print(1)
"""


def _truth_vol3(tmp_path):
    p = tmp_path / "gt.txt"
    p.write_text(_vol3_text([("0x88800361c440", 1, 1, 0, "systemd"),
                             ("0x8880036196c0", 2, 2, 0, "kthreadd")]))
    return parse_ground_truth(p)


def _truth_ps(tmp_path):
    p = tmp_path / "ps.txt"
    p.write_text(PS_TEXT)
    return parse_ground_truth(p)


def _row(off, pid, tid, ppid, comm):
    return [canonical(off, 48), pid, tid, ppid, comm]


# ---------------------------------------------------------------- parsing
def test_parse_vol3(tmp_path):
    gt = _truth_vol3(tmp_path)
    assert gt.source == "vol3_pslist" and len(gt.tasks) == 2
    assert gt.tasks[0] == GroundTruthTask(1, 0, "systemd", 1, 0x88800361C440)
    assert gt.hard_columns == ("PID", "TID", "PPID", "COMM", "OFFSET (V)")


def test_parse_ps(tmp_path):
    gt = _truth_ps(tmp_path)
    assert gt.source == "ps" and gt.hard_columns == ("PID", "PPID", "COMM")
    by_pid = {t.pid: t for t in gt.tasks}
    assert by_pid[1].comm is None            # command line with spaces: not a comm
    assert by_pid[2].comm == "kthreadd"
    assert by_pid[5].comm == "kworker/0:0-eve"  # truncated to 15
    assert by_pid[900].comm is None and by_pid[900].ppid == 1


def test_parse_unknown_format(tmp_path):
    p = tmp_path / "x.txt"
    p.write_text("hello\nworld\n\n")
    with pytest.raises(CapabilityError):
        parse_ground_truth(p)


def test_parse_vol3_skips_short_and_nonnumeric(tmp_path):
    p = tmp_path / "g.txt"
    p.write_text(VOL3_HEADER + "\nshort\tline\n0x1\tabc\t1\t0\tx\t0\t0\t0\t0\tt\tf\n")
    with pytest.raises(CapabilityError) as e:  # nothing parseable -> empty, never a verdict
        parse_ground_truth(p)
    assert e.value.code == "isf.ground_truth_empty"


@pytest.mark.parametrize("bits", [48, 57])
def test_canonical(bits):
    low = 0x1234
    assert canonical(low, bits) == low
    masked = (1 << (bits - 1)) | 0x10
    expect = ((1 << 64) - 1) ^ ((1 << bits) - 1) | masked
    assert canonical(masked, bits) == expect
    assert canonical(expect, bits) == expect  # idempotent
    assert canonical(1 << 70 | 5, bits) == 5  # masked to 64 bits


# ------------------------------------------------------------- comparison
def test_compare_vol3_perfect(tmp_path):
    gt = _truth_vol3(tmp_path)
    rows = [_row(0x88800361C440, 1, 1, 0, "systemd"), _row(0x8880036196C0, 2, 2, 0, "kthreadd")]
    c = compare_pslist(COLS, rows, gt, 48)
    assert (c.matched, c.expected, c.returned) == (2, 2, 2)
    assert c.recall == c.precision == 1.0 and not c.mismatches
    assert verdict_of(c, min_recall=0.95, min_precision=0.95) == tl.PASS


def test_compare_vol3_wrong_pid_is_mismatch_on_right_task(tmp_path):
    gt = _truth_vol3(tmp_path)
    rows = [_row(0x88800361C440, 77, 1, 0, "systemd"), _row(0x8880036196C0, 2, 2, 0, "kthreadd")]
    c = compare_pslist(COLS, rows, gt, 48)
    assert c.matched == 2 and not c.missing and not c.extra
    assert c.mismatches == [{"pid": 1, "column": "PID", "expected": 1, "got": 77}]
    assert verdict_of(c, min_recall=0.95, min_precision=0.95) == tl.PARTIAL
    assert [i["item"] for i in implicated_by_comparison(c)] == ["task_struct.tgid"]


def test_compare_missing_extra_duplicates(tmp_path):
    gt = _truth_vol3(tmp_path)
    rows = [_row(0x88800361C440, 1, 1, 0, "systemd"), _row(0x88800361C440, 1, 1, 0, "systemd"),
            _row(0x8880DEAD0000, 99, 99, 1, "zzz")]
    c = compare_pslist(COLS, rows, gt, 48)
    assert c.missing == [2] and c.extra == [99] and c.duplicates == [1]
    assert c.returned == 3 and c.matched == 1
    assert verdict_of(c, min_recall=0.95, min_precision=0.95) == tl.PARTIAL


def test_compare_comm_truncated_to_15(tmp_path):
    p = tmp_path / "g.txt"
    p.write_text(_vol3_text([("0x88800361c440", 9, 9, 2, "rcu_tasks_kthread")]))
    gt = parse_ground_truth(p)
    c = compare_pslist(COLS, [_row(0x88800361C440, 9, 9, 2, "rcu_tasks_kthre")], gt, 48)
    assert not c.mismatches


def test_compare_vol3_comm_mismatch_and_offset_column_missing(tmp_path):
    gt = _truth_vol3(tmp_path)
    c = compare_pslist(COLS, [_row(0x88800361C440, 1, 1, 0, "other")], gt, 48)
    assert [m["column"] for m in c.mismatches] == ["COMM"]
    assert [i["item"] for i in implicated_by_comparison(c)] == ["task_struct.comm"] \
        or implicated_by_comparison(c)[0]["item"] == "task_struct.comm"


def test_compare_ps_keyed_by_pid(tmp_path):
    gt = _truth_ps(tmp_path)
    cols = ["PID", "PPID", "COMM"]
    rows = [[1, 0, "init"], [2, 0, "kthreadd"], [5, 2, "kworker/0:0"], [4242, 1, "ps"]]
    c = compare_pslist(cols, rows, gt, 48)
    # kworker prefix rule: ps name 'kworker/0:0-ev' starts with comm + '-'? it is the
    # ps name that is longer, so comm 'kworker/0:0' must match via startswith(got + '-')
    assert c.matched == 3 and c.missing == [900] and c.extra == [4242]
    assert not c.mismatches
    assert c.recall == 0.75 and c.precision == 0.75


def test_compare_ps_kworker_prefix_rule_negative(tmp_path):
    gt = _truth_ps(tmp_path)
    c = compare_pslist(["PID", "PPID", "COMM"], [[5, 2, "kworker/1:0"]], gt, 48)
    assert [m["column"] for m in c.mismatches] == ["COMM"]
    c = compare_pslist(["PID", "PPID", "COMM"], [[5, 2, ""]], gt, 48)
    assert [m["column"] for m in c.mismatches] == ["COMM"]  # empty never matches


def test_compare_ps_ignores_non_int_pid_rows(tmp_path):
    gt = _truth_ps(tmp_path)
    c = compare_pslist(["PID", "PPID", "COMM"], [["x", 0, "a"]], gt, 48)
    assert c.returned == 0 and c.matched == 0


def test_comparison_empty_rates():
    c = Comparison()
    assert c.recall == 0.0 and c.precision == 0.0


def test_to_dict_truncation_flag():
    c = Comparison(expected=100, returned=100, missing=list(range(51)))
    d = c.to_dict()
    assert d["truncated"] is True and len(d["missing"]) == 50
    assert Comparison(missing=list(range(50))).to_dict()["truncated"] is False
    assert c.to_dict(limit=100)["truncated"] is False
    m = Comparison(mismatches=[{"column": "PID"}] * 60).to_dict()
    assert m["mismatch_count"] == 60 and len(m["mismatches"]) == 50 and m["truncated"]


# ---------------------------------------------------------------- verdicts
def test_verdict_thresholds():
    kw = dict(min_recall=0.95, min_precision=0.95)
    assert verdict_of(Comparison(), **kw) == tl.FAIL
    assert verdict_of(Comparison(matched=4, expected=10, returned=4), **kw) == tl.FAIL
    assert verdict_of(Comparison(matched=5, expected=10, returned=5), **kw) == tl.PARTIAL
    assert verdict_of(Comparison(matched=95, expected=100, returned=95), **kw) == tl.PASS
    assert verdict_of(Comparison(matched=94, expected=100, returned=94), **kw) == tl.PARTIAL
    assert verdict_of(Comparison(matched=95, expected=95, returned=101), **kw) == tl.PARTIAL
    assert verdict_of(Comparison(matched=10, expected=10, returned=10, duplicates=[1]), **kw) == tl.PARTIAL
    assert verdict_of(Comparison(matched=10, expected=10, returned=10,
                                 mismatches=[{"column": "PID"}]), **kw) == tl.PARTIAL


# -------------------------------------------------------------- implicated
def test_implicated_by_error_cases():
    got = implicated_by_error("Symbol type not in kernel_isf_probe SymbolTable: file")
    assert [g["item"] for g in got] == ["type:file"]
    got = implicated_by_error(
        "AttributeError: StructType has no attribute: kernel_isf!task_struct.cred")
    assert [g["item"] for g in got] == ["task_struct.cred"]
    got = implicated_by_error("SymbolError: Unknown symbol: init_task")
    assert got[0]["item"] == "symbol:init_task"
    paging = "no paging depth reads the kernel back"
    assert [g["item"] for g in implicated_by_error(paging)] == ["symbol:init_top_pgt"]
    got = implicated_by_error(paging + "; init_task reads b'wapper/'")
    assert [g["item"] for g in got] == ["task_struct.comm"]
    assert implicated_by_error("something unrelated") == []


def test_implicated_by_error_dedupes():
    msg = "Unknown symbol: a.b ... Unknown symbol: a.b"
    assert len(implicated_by_error(msg)) == 1


def test_implicated_by_comparison_zero_rows_and_columns():
    got = implicated_by_comparison(Comparison(expected=5, returned=0))
    assert [g["item"] for g in got] == list(tl.TASK_LIST_FIELDS)
    assert "0 rows" in got[0]["reason"]
    cmp = Comparison(expected=10, returned=10, matched=10, mismatches=[
        {"column": "PPID"}, {"column": "PPID"}, {"column": "UID"}])
    items = [g["item"] for g in implicated_by_comparison(cmp)]
    assert items[:2] == ["task_struct.real_parent", "task_struct.tgid"]  # most frequent first
    assert "cred.uid" in items
    assert implicated_by_comparison(Comparison(expected=1, returned=1, matched=1)) == []


# ---------------------------------------------------------------- try_isf
def _fake_run(rows, truncated=False, columns=COLS):
    return SimpleNamespace(row_count=len(rows), truncated=truncated, stop_reason=None,
                           diagnostics=[], rows=rows,
                           columns=[SimpleNamespace(name=c) for c in columns])


@pytest.fixture
def patched(monkeypatch):
    import memdiver.core.image.context as ctx_mod
    import memdiver.engine.vol3_runner as runner

    state = {"run": _fake_run([]), "build_exc": None, "run_exc": None}
    paging = SimpleNamespace(va_bits=48, to_dict=lambda: {"va_bits": 48})

    def build(image, isf, *a, **k):
        if state["build_exc"]:
            raise state["build_exc"]
        return SimpleNamespace(kernel_paging=paging)

    def run_plugin(ctx, plugin, args, **kw):
        if state["run_exc"]:
            raise state["run_exc"]
        return state["run"]

    monkeypatch.setattr(ctx_mod.ImageContext, "build", staticmethod(build))
    monkeypatch.setattr(runner, "resolve_plugin", lambda name: name)
    monkeypatch.setattr(runner, "run_plugin", run_plugin)
    return state


def _try(tmp_path, gt=None, **kw):
    return try_isf(tmp_path / "img", tmp_path / "isf.json", ground_truth=gt, **kw)


def test_try_build_error(patched, tmp_path):
    patched["build_exc"] = RuntimeError("Symbol type not in kernel_isf_probe SymbolTable: file")
    r = _try(tmp_path)
    assert (r["stage"], r["verdict"]) == ("build", "error")
    assert r["implicated"][0]["item"] == "type:file" and "build" in r["elapsed_s"]


def test_try_run_error(patched, tmp_path):
    patched["run_exc"] = AttributeError("StructType has no attribute: kernel_isf!task_struct.cred")
    r = _try(tmp_path)
    assert (r["stage"], r["verdict"]) == ("run", "error")
    assert r["implicated"][0]["item"] == "task_struct.cred" and r["paging"] == {"va_bits": 48}


def test_try_no_ground_truth_unverified(patched, tmp_path):
    patched["run"] = _fake_run([_row(0x88800361C440, 1, 1, 0, "systemd")])
    r = _try(tmp_path)
    assert (r["stage"], r["verdict"], r["implicated"]) == ("done", "unverified", [])
    assert r["sample"][0]["PID"] == 1


def test_try_zero_rows_fails(patched, tmp_path):
    r = _try(tmp_path)
    assert r["verdict"] == "fail"
    assert [i["item"] for i in r["implicated"]] == list(tl.TASK_LIST_FIELDS)


def test_try_non_pslist_plugin_unverified(patched, tmp_path):
    _truth_vol3(tmp_path)
    patched["run"] = _fake_run([[1]], columns=["X"])
    r = _try(tmp_path, gt=tmp_path / "gt.txt", plugin="linux.lsof")
    assert r["verdict"] == "unverified"


def test_try_pass_and_truncated_never_passes(patched, tmp_path):
    _truth_vol3(tmp_path)
    rows = [_row(0x88800361C440, 1, 1, 0, "systemd"), _row(0x8880036196C0, 2, 2, 0, "kthreadd")]
    patched["run"] = _fake_run(rows)
    r = _try(tmp_path, gt=tmp_path / "gt.txt")
    assert r["verdict"] == "pass" and r["ground_truth"]["tasks"] == 2
    patched["run"] = _fake_run(rows, truncated=True)
    r = _try(tmp_path, gt=tmp_path / "gt.txt")
    assert r["verdict"] == "partial" and r["truncated"] is True


def test_try_zero_rows_with_ground_truth(patched, tmp_path):
    _truth_vol3(tmp_path)
    r = _try(tmp_path, gt=tmp_path / "gt.txt")
    assert r["verdict"] == "fail" and r["comparison"]["returned"] == 0
    assert {i["item"] for i in r["implicated"]} >= {"task_struct.tasks"}


def test_try_never_raises_for_bad_truth_format_is_valueerror(patched, tmp_path):
    bad = tmp_path / "bad.txt"
    bad.write_text("nope\n")
    with pytest.raises(CapabilityError):
        _try(tmp_path, gt=bad)


# ------------------------------------------------------------ real corpus
STEM = "arista-eos-4.36.1F_5.10.165.Ar-48367454.4361F"
_corpus_env = os.environ.get("MEMDIVER_IMAGE_CORPUS")
_corpus = Path(_corpus_env) if _corpus_env else None
_needed = [f"{STEM}{s}" for s in (".lime", ".isf.json", ".vol3_pslist.txt", ".ps_at_dump.txt")]
_have_corpus = bool(_corpus and _corpus.is_dir() and all((_corpus / n).exists() for n in _needed))
real = pytest.mark.skipif(not _have_corpus, reason="MEMDIVER_IMAGE_CORPUS arista files not present")


_KEEP_SYMBOLS = {"init_task", "linux_banner", "init_top_pgt", "init_mm", "init_files"}
_ROOT_TYPES = ["task_struct", "file", "mm_struct", "files_struct", "cred", "list_head",
               "inet_sock", "unix_sock"]  # vol3 linux extensions probe the socket types


def _type_names(node, acc):
    if isinstance(node, dict):
        if node.get("kind") in ("struct", "union", "enum", "typedef") and "name" in node:
            acc.add(node["name"])
        for v in node.values():
            _type_names(v, acc)
    elif isinstance(node, list):
        for v in node:
            _type_names(v, acc)


@pytest.fixture(scope="module")
def shipped_isf():
    """The shipped ISF trimmed to what linux.pslist needs (build 12 s -> ~3 s)."""
    full = json.loads((_corpus / f"{STEM}.isf.json").read_text())
    seen, todo = set(), list(_ROOT_TYPES)
    while todo:
        name = todo.pop()
        if name in seen or name not in full["user_types"]:
            continue
        seen.add(name)
        found = set()
        _type_names(full["user_types"][name], found)
        todo.extend(found - seen)
    trimmed = dict(full)
    trimmed["symbols"] = {k: v for k, v in full["symbols"].items() if k in _KEEP_SYMBOLS}
    trimmed["user_types"] = {k: full["user_types"][k] for k in seen}
    return trimmed


def _paths():
    return (_corpus / f"{STEM}.lime", _corpus / f"{STEM}.isf.json",
            _corpus / f"{STEM}.vol3_pslist.txt", _corpus / f"{STEM}.ps_at_dump.txt")


def _derived(isf, tmp_path, mutate):
    import copy
    d = dict(isf)
    d["user_types"] = copy.deepcopy(isf["user_types"])
    mutate(d)
    out = tmp_path / "draft.isf.json"
    out.write_text(json.dumps(d))
    return out


@real
@pytest.mark.parametrize("which", [2, 3])
def test_real_shipped_isf_passes(which):
    img, isf, *_ = _paths()
    r = try_isf(img, isf, ground_truth=_paths()[which])
    assert r["verdict"] == "pass", r.get("comparison") or r.get("error")
    assert r["rows"] == 123 and r["implicated"] == []


@real
def test_real_tasks_offset_shifted_fails(shipped_isf, tmp_path):
    def mut(d):
        d["user_types"]["task_struct"]["fields"]["tasks"]["offset"] += 8
    r = try_isf(_paths()[0], _derived(shipped_isf, tmp_path, mut), ground_truth=_paths()[2])
    assert r["verdict"] == "fail"
    assert "task_struct.tasks" in {i["item"] for i in r["implicated"]}


@real
def test_real_real_parent_shifted_partial(shipped_isf, tmp_path):
    def mut(d):
        d["user_types"]["task_struct"]["fields"]["real_parent"]["offset"] += 16
    r = try_isf(_paths()[0], _derived(shipped_isf, tmp_path, mut), ground_truth=_paths()[2])
    assert r["verdict"] == "partial"
    assert "task_struct.real_parent" in {i["item"] for i in r["implicated"]}


@real
def test_real_missing_file_type_errors_at_build(shipped_isf, tmp_path):
    def mut(d):
        del d["user_types"]["file"]
    r = try_isf(_paths()[0], _derived(shipped_isf, tmp_path, mut), ground_truth=_paths()[2])
    assert (r["stage"], r["verdict"]) == ("build", "error")
    assert "type:file" in {i["item"] for i in r["implicated"]}


def test_space_aligned_vol3_header_and_skipped_rows(tmp_path):
    p = tmp_path / "sp.txt"
    p.write_text(
        "OFFSET (V)      PID     TID     PPID    COMM    UID\n"
        "0x88800361c440  1       1       0       systemd  0\n"
        "0x8880036196c0  2       2       -       kthreadd  0\n")
    gt = parse_ground_truth(p)
    assert len(gt.tasks) == 1 and gt.tasks[0].pid == 1 and gt.skipped_rows == 1


def test_invalid_ground_truth_is_capability_error(tmp_path):
    p = tmp_path / "bad.txt"
    p.write_text("OFFSET (V)\tPID\tNOPE\n1\t2\t3\n")
    with pytest.raises(CapabilityError) as e:
        parse_ground_truth(p)
    assert e.value.code == "isf.ground_truth_invalid"
    p.write_text("nothing useful\n")
    with pytest.raises(CapabilityError) as e:
        parse_ground_truth(p)
    assert e.value.code == "isf.ground_truth_invalid"
    with pytest.raises(CapabilityError) as e:
        parse_ground_truth(tmp_path / "missing.txt")
    assert e.value.code == "isf.ground_truth_invalid"


def test_empty_ground_truth_is_capability_error(tmp_path):
    p = tmp_path / "empty.txt"
    p.write_text(VOL3_HEADER + "\n")
    with pytest.raises(CapabilityError) as e:
        parse_ground_truth(p)
    assert e.value.code == "isf.ground_truth_empty"


# ------------------------------------------------- vol3-required types

def test_vol3_required_types_come_from_vol3_source():
    pytest.importorskip("volatility3")
    required = tl.vol3_required_types()
    assert required and "file" in required and "task_struct" in required
    assert "module" not in required  # optional_set_type_class
    assert len(set(required)) == len(required)


def test_missing_required_types(tmp_path, monkeypatch):
    monkeypatch.setattr(tl, "vol3_required_types", lambda: ("file", "task_struct", "cred"))
    isf = tmp_path / "x.isf.json"
    isf.write_text(json.dumps({"user_types": {"task_struct": {"size": 0}}}))
    assert [i["item"] for i in tl.missing_required_types(isf)] == ["type:file", "type:cred"]
    assert tl.missing_required_types(tmp_path / "absent.json") == []
    isf.write_text("not json")
    assert tl.missing_required_types(isf) == []


def test_try_build_error_implicates_all_missing_required_types(patched, tmp_path, monkeypatch):
    monkeypatch.setattr(tl, "vol3_required_types", lambda: ("file", "task_struct", "cred"))
    (tmp_path / "isf.json").write_text(json.dumps({"user_types": {"task_struct": {}}}))
    patched["build_exc"] = RuntimeError("Symbol type not in kernel_isf_probe SymbolTable: file")
    r = _try(tmp_path)
    assert r["stage"] == "build" and r["verdict"] == "error"
    items = [i["item"] for i in r["implicated"]]
    assert "type:file" in items and "type:cred" in items and "type:task_struct" not in items
    assert len(items) == len(set(items))


def test_try_other_build_error_does_not_add_required_types(patched, tmp_path, monkeypatch):
    monkeypatch.setattr(tl, "vol3_required_types", lambda: ("file",))
    (tmp_path / "isf.json").write_text(json.dumps({"user_types": {}}))
    patched["build_exc"] = RuntimeError("boom")
    assert _try(tmp_path)["implicated"] == []
