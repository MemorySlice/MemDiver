"""``app.tools_vol3`` producers over a fake image context and a real case lake."""
from __future__ import annotations

import pyarrow.parquet as pq
import pytest

from memdiver.analysis.case import Case
from memdiver.analysis.record_store import AnalysisRecord
from memdiver.app import tools_vol3 as tv
from memdiver.core.image.view_descriptor import ProfileRef, ViewDescriptor, ViewKind
from memdiver.core.service_errors import CapabilityError, ErrorCategory
from memdiver.engine import vol3_runner as vr

SHA = "a" * 64
KVA = 0xFFFF_8880_1234_5000          # > 2**63: must survive as uint64


class ListRequirement:                # type name is what the runner filters on
    def __init__(self, name):
        self.name = name


def _plugin(name, pid_arg=None):
    class Fake:
        @staticmethod
        def get_requirements():
            return [ListRequirement(pid_arg)] if pid_arg else []
    return vr.PluginInfo(name, "", (1, 0, 0), Fake)


def _spec(name, kind, space=None):
    return vr.ColumnSpec(name, kind, space)


def _pslist_result(rows, plugin="linux.pslist.PsList"):
    cols = [_spec("OFFSET (V)", "hex", "kernel_va"), _spec("PID", "int"), _spec("COMM", "str")]
    return vr.PluginRunResult(plugin, cols, rows, [0] * len(rows), [{} for _ in rows],
                              0.5, capture_id=SHA)


def _maps_result():
    cols = [_spec("PID", "int"), _spec("Start", "hex", "process_va"),
            _spec("End", "hex", "process_va"), _spec("File Path", "str")]
    rows = [[10, 0x1000, 0x3000, "/bin/x"], [11, 0x2000, None, None]]
    return vr.PluginRunResult("linux.proc.Maps", cols, rows, [0, 0], [{}, {}], 0.1,
                              capture_id=SHA)


@pytest.fixture
def env(monkeypatch, tmp_path):
    state = {"info": _plugin("linux.pslist.PsList", "pid"), "result": None, "args": None}
    view = tmp_path / "v.mdview"
    view.write_text("x")
    descriptor = {"d": ViewDescriptor("img", SHA, ViewKind.KERNEL,
                                      profile=ProfileRef("p.json"))}

    def fake_run(ctx, info, args, **kw):
        state["args"] = dict(args)
        return state["result"]

    monkeypatch.setattr(tv, "_plugin_info", lambda plugin, source: state["info"])
    monkeypatch.setattr(tv, "_read_descriptor", lambda p: (view, descriptor["d"]))
    monkeypatch.setattr(tv, "_context_for", lambda d, p: object())
    monkeypatch.setattr("memdiver.analysis.capture_id.capture_id_for", lambda p: SHA)
    monkeypatch.setattr(vr, "run_plugin", fake_run)
    state.update(view=str(view), descriptor=descriptor,
                 case=str(Case.init(tmp_path / "case").dir))
    return state


def test_run_registers_table_with_standard_columns(env):
    env["result"] = _pslist_result([[KVA, 1, "init"], [None, 2, "gone"]])
    payload = tv.vol3_run_result(env["view"], "linux.pslist", case_dir=env["case"]).payload
    ref = payload["table"]
    assert ref["name"] == "vol3__linux_pslist" and ref["row_count"] == 2
    assert ref["path"].endswith("linux.pslist.PsList.parquet")
    assert ref["locations"] == {"offset_v": "kernel_va"} and payload["run_id"] == ref["run_id"]
    table = pq.read_table(ref["path"])
    assert str(table.schema.field("addr").type) == "uint64"
    assert table.column("addr").to_pylist() == [KVA, None]
    assert table.column("space").to_pylist() == ["kernel_va", None]
    assert table.column("size").to_pylist() == [None, None]
    assert set(table.column("image_sha256").to_pylist()) == {SHA}
    meta = Case.open(env["case"]).runs("vol3__linux_pslist")[0]
    assert meta.row_count == 2


def test_span_columns_give_addr_and_size(env):
    env["info"] = _plugin("linux.proc.Maps", "pid")
    env["result"] = _maps_result()
    ref = tv.vol3_run_result(env["view"], "linux.proc", case_dir=env["case"]).payload["table"]
    table = pq.read_table(ref["path"])
    assert table.column("addr").to_pylist() == [0x1000, 0x2000]
    assert table.column("size").to_pylist() == [0x2000, None]
    assert table.column("space").to_pylist() == ["process_va", "process_va"]
    assert ref["locations"] == {"start": "process_va", "end": "process_va"}


def test_process_view_defaults_pid(env):
    env["descriptor"]["d"] = ViewDescriptor("img", SHA, ViewKind.PROCESS, pid=77,
                                            profile=ProfileRef("p.json"))
    env["result"] = _pslist_result([[KVA, 77, "x"]])
    payload = tv.vol3_run_result(env["view"], "linux.pslist").payload
    assert env["args"] == {"pid": [77]} and payload["defaults_applied"] == {"pid": [77]}
    assert payload["table"] is None
    tv.vol3_run_result(env["view"], "linux.pslist", {"pid": [5]})
    assert env["args"] == {"pid": [5]}


def test_kernel_view_has_no_default(env):
    env["result"] = _pslist_result([[KVA, 1, "x"]])
    assert tv.vol3_run_result(env["view"], "linux.pslist").payload["defaults_applied"] == {}


@pytest.mark.parametrize("name", ["linux.pslist.PsList", "linux.pstree.PsTree"])
def test_empty_process_listing_is_a_precondition_error(env, name):
    env["info"] = _plugin(name)
    env["result"] = _pslist_result([], plugin=name)
    with pytest.raises(CapabilityError) as err:
        tv.vol3_run_result(env["view"], name, case_dir=env["case"])
    assert err.value.category is ErrorCategory.PRECONDITION
    assert Case.open(env["case"]).tables() == []


def test_empty_result_of_other_plugin_is_registered(env):
    env["info"] = _plugin("linux.sockstat.Sockstat")
    env["result"] = _pslist_result([], plugin="linux.sockstat.Sockstat")
    payload = tv.vol3_run_result(env["view"], "linux.sockstat", case_dir=env["case"]).payload
    assert payload["row_count"] == 0 and payload["table"]["row_count"] == 0


def test_annotate_round_trip_with_process_va_and_kernel_va(env):
    env["result"] = _pslist_result([[KVA, 1, "init"], [None, 2, "gone"]])
    run = tv.vol3_run_result(env["view"], "linux.pslist", case_dir=env["case"]).payload
    out = tv.vol3_annotate_result(env["case"], "vol3__linux_pslist", run["run_id"],
                                  "offset_v", label_column="comm").payload
    assert out["created"] == 1 and out["skipped"] == [1] and out["skipped_count"] == 1
    (entry,) = AnalysisRecord(env["case"]).entries(SHA, "plugin_row")
    assert entry.locations[0].value == KVA and entry.locations[0].space.value == "kernel_va"
    assert entry.label == "init" and entry.support[0].kind == "vol3_run"
    assert entry.support[0].ref == run["run_id"]
    assert entry.payload["plugin"] == "linux.pslist.PsList"

    env["info"] = _plugin("linux.proc.Maps", "pid")
    env["result"] = _maps_result()
    maps = tv.vol3_run_result(env["view"], "linux.proc", case_dir=env["case"]).payload
    tv.vol3_annotate_result(env["case"], "vol3__linux_proc", maps["run_id"], "start",
                            rows=[1], author="human")
    got = [e for e in AnalysisRecord(env["case"]).entries(SHA)
           if e.payload.get("plugin") == "linux.proc.Maps"]
    assert got[0].locations[0].pid == 11 and got[0].author == "human"


def test_annotate_rejects_bad_input(env):
    env["result"] = _pslist_result([[KVA, 1, "init"]])
    run = tv.vol3_run_result(env["view"], "linux.pslist", case_dir=env["case"]).payload
    rid = run["run_id"]
    with pytest.raises(CapabilityError, match="not a location column"):
        tv.vol3_annotate_result(env["case"], "vol3__linux_pslist", rid, "comm")
    with pytest.raises(CapabilityError, match="out of range"):
        tv.vol3_annotate_result(env["case"], "vol3__linux_pslist", rid, "offset_v", rows=[9])
    with pytest.raises(CapabilityError) as err:
        tv.vol3_annotate_result(env["case"], "vol3__linux_pslist", "nope", "offset_v")
    assert err.value.category is ErrorCategory.NOT_FOUND


def test_query_sql_saved_and_errors(env):
    env["result"] = _pslist_result([[KVA, 1, "init"]])
    tv.vol3_run_result(env["view"], "linux.pslist", case_dir=env["case"])
    rows = tv.vol3_query_result(env["case"], sql="SELECT comm FROM vol3__linux_pslist").payload
    assert rows["rows"] == [["init"]]
    with pytest.raises(CapabilityError, match="known: "):
        tv.vol3_query_result(env["case"], saved="nope")
    with pytest.raises(CapabilityError) as err:
        tv.vol3_query_result(env["case"], saved="hidden_processes")
    assert err.value.category is ErrorCategory.PRECONDITION
    assert "vol3__linux_psscan" in str(err.value) and "linux.psscan.PsScan" in str(err.value)
    with pytest.raises(CapabilityError, match="exactly one"):
        tv.vol3_query_result(env["case"], sql="SELECT 1", saved="hidden_processes")
    listing = tv.vol3_query_result(env["case"]).payload
    assert listing["count"] == len(listing["saved_queries"]) >= 1


def test_run_payload_carries_the_active_view(env):
    env["descriptor"]["d"] = ViewDescriptor("img", SHA, ViewKind.PROCESS, pid=77,
                                            profile=ProfileRef("p.json"))
    env["result"] = _pslist_result([[KVA, 77, "x"]])
    view = tv.vol3_run_result(env["view"], "linux.pslist").payload["view"]
    assert view == {"kind": "process", "pid": 77, "capture_id": SHA, "view_path": env["view"]}


def test_run_payload_view_pid_is_null_for_a_kernel_view(env):
    env["result"] = _pslist_result([[KVA, 1, "x"]])
    view = tv.vol3_run_result(env["view"], "linux.pslist").payload["view"]
    assert view["kind"] == "kernel" and view["pid"] is None


def test_run_result_json_keeps_exact_large_ints(env):
    """MCP agents get ``json.dumps`` output: Python ints are exact, no 2**53 rounding."""
    import json
    big = 0xFFFF_8880_1234_5679
    env["result"] = _pslist_result([[big, 1, "x"]])
    payload = tv.vol3_run_result(env["view"], "linux.pslist").payload
    assert str(big) in json.dumps(payload)
