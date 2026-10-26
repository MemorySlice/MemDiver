"""P4 gate on the real arista-eos dump: a draft built from probes + manual claims
(never the shipped ISF) makes vol3 linux.pslist match ground truth.

Replays claims_round1/claims_round2 of the manual gate through the library producers.
The shipped ISF is used ONLY for the final comparison. Gated on MEMDIVER_IMAGE_CORPUS.
Run with ``-s`` to see timings.
"""

from __future__ import annotations

import collections
import json
import os
import time
from pathlib import Path

import pytest

from memdiver.app import tools_isf as T
from memdiver.core.image.context import file_sha256
from memdiver.isf.draft import IsfDraftStore

CORPUS = os.environ.get("MEMDIVER_IMAGE_CORPUS")
ARISTA = "arista-eos-4.36.1F_5.10.165.Ar-48367454.4361F"
_NEEDED = (".lime", ".isf.json", ".vol3_pslist.txt")
pytestmark = pytest.mark.skipif(
    not CORPUS or not all((Path(CORPUS) / f"{ARISTA}{ext}").is_file() for ext in _NEEDED),
    reason="MEMDIVER_IMAGE_CORPUS must hold the arista-eos .lime/.isf.json/.vol3_pslist.txt")

GATE = "gate"
ABI = "x86_64 SysV LP64 ABI"
ptr = lambda sub: {"kind": "pointer", "subtype": sub}  # noqa: E731
st = lambda name: {"kind": "struct", "name": name}  # noqa: E731
base = lambda name: {"kind": "base", "name": name}  # noqa: E731

BASE_TYPES = [  # (name, size, signed, kind)
    ("char", 1, True, "char"), ("unsigned char", 1, False, "char"),
    ("short int", 2, True, "int"), ("short unsigned int", 2, False, "int"),
    ("int", 4, True, "int"), ("unsigned int", 4, False, "int"),
    ("long int", 8, True, "int"), ("long unsigned int", 8, False, "int"),
    ("long long int", 8, True, "int"), ("long long unsigned int", 8, False, "int"),
    ("_Bool", 1, False, "bool"), ("pointer", 8, False, "int"), ("void", 0, False, "void")]
TASK_FIELDS = [  # (struct, field, offset, type, source)
    ("task_struct", "tasks", 864, st("list_head"), "sched.h tasks"),
    ("task_struct", "pid", 1128, base("int"), "sched.h pid"),
    ("task_struct", "tgid", 1132, base("int"), "sched.h tgid"),
    ("task_struct", "comm", 1672, {"kind": "array", "count": 16, "subtype": base("char")}, "comm[16]"),
    ("task_struct", "real_parent", 1144, ptr(st("task_struct")), "sched.h real_parent"),
    ("task_struct", "parent", 1152, ptr(st("task_struct")), "sched.h parent"),
    ("task_struct", "cred", 1656, ptr(st("cred")), "sched.h cred"),
    ("task_struct", "real_cred", 1648, ptr(st("cred")), "sched.h real_cred"),
    ("task_struct", "mm", 944, ptr(st("mm_struct")), "sched.h mm"),
    ("task_struct", "active_mm", 952, ptr(st("mm_struct")), "sched.h active_mm"),
    ("task_struct", "files", 1752, ptr(st("files_struct")), "sched.h files"),
    ("cred", "uid", 4, st("kuid_t"), "cred.h"), ("cred", "gid", 8, st("kgid_t"), "cred.h"),
    ("cred", "euid", 20, st("kuid_t"), "cred.h"), ("cred", "egid", 24, st("kgid_t"), "cred.h")]
SYMBOL_TYPES = [("init_task", "task_struct"), ("init_mm", "mm_struct"),
                ("init_files", "files_struct")]


def _timed(label, fn):
    start = time.perf_counter()
    out = fn()
    print(f"[p4-gate] {label}: {time.perf_counter() - start:.1f}s")
    return out


def _set(case, capture, op, args, tier, source, evidence):
    T.isf_draft_set_result(case, capture, GATE, op, args, source=source, tier=tier,
                           evidence=[evidence], author="agent")


def _round1(case, capture, image, store):
    for name, size, signed, kind in BASE_TYPES:
        _set(case, capture, "base_type", {"name": name, "size": size, "signed": signed,
                                          "kind": kind, "endian": "little"},
             "upstream_constant", "abi", ABI)
    src = "include/linux/types.h"
    _set(case, capture, "struct", {"name": "list_head", "size": 16}, "upstream_constant", "source", src)
    for field, off in (("next", 0), ("prev", 8)):
        _set(case, capture, "field", {"struct": "list_head", "field": field, "offset": off,
                                      "type": ptr(st("list_head"))}, "upstream_constant", "source", src)
    for s, f, off, typ, where in TASK_FIELDS:
        _set(case, capture, "field", {"struct": s, "field": f, "offset": off, "type": typ},
             "upstream_constant", "source", f"offset from layout_legs claim; type from {where}")
    for t in ("kuid_t", "kgid_t"):
        _set(case, capture, "struct", {"name": t, "size": 4}, "upstream_constant", "source", "uidgid.h")
        _set(case, capture, "field", {"struct": t, "field": "val", "offset": 0,
                                      "type": base("unsigned int")}, "upstream_constant", "source", "uidgid.h")
    symbols = store.materialize(capture, GATE).symbols  # addresses came from the kallsyms probe
    for name, struct in SYMBOL_TYPES:
        _set(case, capture, "symbol", {"name": name, "address": hex(symbols[name]["address"]),
                                       "type": st(struct)}, "upstream_constant", "source",
             f"address from kallsyms probe; type from kernel source {name}")


def _round2(case, capture, first_try):
    stubs = [i["item"][5:] for i in first_try["implicated"] if i["item"].startswith("type:")]
    for name in stubs:
        _set(case, capture, "struct", {"name": name, "size": 0}, "manual", "vol3_required",
             "stub: vol3 LinuxKernelIntermedSymbols requires the type; layout not recovered")
    return stubs


@pytest.fixture(scope="module")
def gate(tmp_path_factory):
    pytest.importorskip("pakunoda")
    pytest.importorskip("volatility3")
    root = Path(CORPUS)
    image = str(root / f"{ARISTA}.lime")
    truth = str(root / f"{ARISTA}.vol3_pslist.txt")
    case = str(tmp_path_factory.mktemp("p4case") / "case")
    capture = file_sha256(Path(image))
    store = IsfDraftStore(Path(case))
    out = {"image": image, "case": case, "capture": capture, "store": store, "truth": truth}
    T.isf_draft_create_result(case, capture, GATE, "x86_64", author="agent")
    for probe in ("kallsyms", "layout_legs"):
        res = _timed(f"probe {probe}", lambda p=probe: T.isf_probe_result(
            image, p, case_dir=case, draft=GATE, author="agent")).payload
        out[probe] = res
    _timed("round-1 claims", lambda: _round1(case, capture, image, store))
    out["try1"] = _timed("try 1", lambda: T.isf_try_result(
        image, case_dir=case, draft=GATE, ground_truth=truth)).payload
    out["stubs"] = _timed("round-2 claims", lambda: _round2(case, capture, out["try1"]))
    out["try2"] = _timed("try 2", lambda: T.isf_try_result(
        image, case_dir=case, draft=GATE, ground_truth=truth)).payload
    return out


def test_probes_fed_the_draft_without_the_shipped_isf(gate):
    assert gate["kallsyms"]["imported"]["symbols"] >= 100_000
    assert gate["layout_legs"]["arch"] == "x86_64"


def test_first_try_fails_at_build_and_implicates_missing_types(gate):
    t1 = gate["try1"]
    assert t1["stage"] == "build" and t1["verdict"] == "error"
    types = [i["item"] for i in t1["implicated"] if i["item"].startswith("type:")]
    assert len(types) >= 10, types
    assert "type:file" in types


def test_second_try_passes_against_ground_truth(gate):
    t2 = gate["try2"]
    assert t2["stage"] == "done" and t2["verdict"] == "pass", t2.get("error")
    cmp = t2["comparison"]
    assert t2["rows"] == 123 and cmp["recall"] == 1.0 and cmp["mismatch_count"] == 0
    assert "record_entry" in t2 and gate["stubs"]


def test_draft_agrees_with_shipped_isf(gate):
    """Port of p4_gate/compare.py: every fact in the draft vs the shipped ISF (reference only)."""
    ref = json.loads((Path(CORPUS) / f"{ARISTA}.isf.json").read_text())
    draft = gate["store"].materialize(gate["capture"], GATE)
    out, bad = collections.Counter(), []
    untyped = set(draft.untyped_fields())
    for name, sym in draft.symbols.items():
        r = ref["symbols"].get(name)
        if r is None:
            out["sym_not_in_ref"] += 1
            continue
        ok = r["address"] == sym["address"]
        out["sym_addr_" + ("eq" if ok else "ne")] += 1
        if not ok:
            bad.append(("symbol", name, sym["address"], r["address"]))
        if "type" in sym and r.get("type") != sym["type"]:
            bad.append(("symtype", name, sym["type"], r.get("type")))
    for s, body in draft.user_types.items():
        rs = ref["user_types"].get(s)
        if rs is None:
            out["struct_not_in_ref"] += 1
            continue
        if body.get("size") and body["size"] != rs["size"]:
            bad.append(("size", s, body["size"], rs["size"]))
        for f, fb in (body.get("fields") or {}).items():
            rf = (rs.get("fields") or {}).get(f)
            if rf is None:
                out["field_not_in_ref"] += 1
                continue
            ok = rf["offset"] == fb["offset"]
            out["field_off_" + ("eq" if ok else "ne")] += 1
            if not ok:
                bad.append(("offset", f"{s}.{f}", fb["offset"], rf["offset"]))
            if (s, f) not in untyped and rf["type"] != fb["type"]:
                bad.append(("ftype", f"{s}.{f}", fb["type"], rf["type"]))
    for b, body in draft.base_types.items():
        rb = ref["base_types"].get(b)
        if rb is not None and rb != body:
            bad.append(("base", b, body, rb))
    print(f"[p4-gate] compare: {dict(sorted(out.items()))} disagreements={len(bad)}")
    assert bad == [], bad[:10]
    assert out["sym_addr_eq"] >= 100_000
    assert out["field_off_eq"] >= 80


def test_no_isf_kernel_view_and_banner_found(gate, tmp_path):
    from memdiver.app.tools_image import image_open_view_result
    from memdiver.core.dump_source import open_dump
    out = tmp_path / "kernel.mdview"
    res = _timed("no-profile kernel view", lambda: image_open_view_result(
        gate["image"], "kernel", no_profile=True, out_path=str(out))).payload
    desc = json.loads(out.read_text().split("\n", 1)[1])  # first line: MEMDIVER-VIEW/1 magic
    blob = json.dumps({"res": res, "desc": desc})
    paging = desc.get("paging") or res.get("paging") or {}
    assert paging.get("pgd_phys", paging.get("dtb")) == 0x2A0C000, blob[:600]
    assert paging.get("va_bits") == 48
    src = open_dump(Path(gate["image"]))
    try:
        assert src.find_first(b"Linux version 5.10") is not None
    finally:
        src.close()
