"""Vol3 rows carry the size of the kernel object they point at; scaffold lists all tasks."""
from __future__ import annotations

import threading
from types import SimpleNamespace

import pyarrow.parquet as pq
import pytest

from memdiver.analysis.case import Case
from memdiver.app import tools_vol3 as tv
from memdiver.app.tools_vol3_dev import vol3_scaffold_result
from memdiver.core.image.view_descriptor import ProfileRef, ViewDescriptor, ViewKind
from memdiver.engine import vol3_runner as vr

SHA = "b" * 64
KVA = 0xFF424DB6C9E68000
TASK_SIZE, MODULE_SIZE = 9344, 1088


def _ctx(missing=()):
    types = {"task_struct": TASK_SIZE, "module": MODULE_SIZE}

    def get_type(name):
        if name in missing:
            raise KeyError(name)
        return SimpleNamespace(size=types[name])

    return SimpleNamespace(kernel=SimpleNamespace(get_type=get_type), lock=threading.RLock())


def test_object_sizes_for_known_plugins_only():
    assert tv._object_sizes(_ctx(), "linux.pslist.PsList") == {
        "OFFSET (V)": {"object_type": "task_struct", "object_size": TASK_SIZE}}
    assert tv._object_sizes(_ctx(), "linux.psscan.PsScan")["OFFSET (P)"]["object_size"] == TASK_SIZE
    assert tv._object_sizes(_ctx(), "linux.lsmod.Lsmod") == {
        "Offset": {"object_type": "module", "object_size": MODULE_SIZE}}
    assert tv._object_sizes(_ctx(), "linux.sockstat.Sockstat") == {}
    assert tv._object_sizes(_ctx(missing={"module"}), "linux.lsmod.Lsmod") == {}


@pytest.fixture
def env(monkeypatch, tmp_path):
    view = tmp_path / "v.mdview"
    view.write_text("x")
    desc = ViewDescriptor("img", SHA, ViewKind.KERNEL, profile=ProfileRef("p.json"))
    state = {"result": None}
    monkeypatch.setattr(tv, "_plugin_info",
                        lambda plugin, source: vr.PluginInfo(plugin, "", (1, 0, 0), type("F", (), {
                            "get_requirements": staticmethod(lambda: [])})))
    monkeypatch.setattr(tv, "_read_descriptor", lambda p: (view, desc))
    monkeypatch.setattr(tv, "_context_for", lambda d, p: _ctx())
    monkeypatch.setattr("memdiver.analysis.capture_id.capture_id_for", lambda p: SHA)
    monkeypatch.setattr(vr, "run_plugin", lambda *a, **k: state["result"])
    state.update(view=str(view), case=str(Case.init(tmp_path / "case").dir))
    return state


def _result(plugin, column, rows):
    cols = [vr.ColumnSpec(column, "hex", "kernel_va"), vr.ColumnSpec("PID", "int")]
    return vr.PluginRunResult(plugin, cols, rows, [0] * len(rows), [{} for _ in rows], 0.1,
                              capture_id=SHA)


def test_pslist_rows_get_task_struct_size_and_columns_carry_the_type(env):
    env["result"] = _result("linux.pslist.PsList", "OFFSET (V)", [[KVA, 1], [None, 2]])
    payload = tv.vol3_run_result(env["view"], "linux.pslist", case_dir=env["case"]).payload
    column = payload["columns"][0]
    assert (column["object_type"], column["object_size"]) == ("task_struct", TASK_SIZE)
    assert "object_type" not in payload["columns"][1]
    table = pq.read_table(payload["table"]["path"])
    assert table.column("size").to_pylist() == [TASK_SIZE, None]


def test_unknown_plugin_is_unchanged(env):
    env["result"] = _result("linux.other.Other", "OFFSET (V)", [[KVA, 1]])
    payload = tv.vol3_run_result(env["view"], "linux.other", case_dir=env["case"]).payload
    assert "object_size" not in payload["columns"][0]
    assert pq.read_table(payload["table"]["path"]).column("size").to_pylist() == [None]


def test_scaffold_walks_every_task_with_comm(monkeypatch):
    from volatility3.plugins.linux import pslist

    tasks = [SimpleNamespace(vol=SimpleNamespace(offset=0x1000 * i), tgid=i, comm=f"p{i}")
             for i in (1, 2, 3)]
    seen = {}

    def list_tasks(context, kernel, filter_func=lambda _: False, include_threads=False):
        seen["filter"] = filter_func
        return iter(tasks)

    monkeypatch.setattr(pslist.PsList, "list_tasks", staticmethod(list_tasks))
    monkeypatch.setattr("volatility3.framework.objects.utility.array_to_string", str)
    cls = vr.plugin_from_source(vol3_scaffold_result("Walker").payload["source"]).cls
    plugin = cls.__new__(cls)
    monkeypatch.setattr(cls, "context", None, raising=False)
    monkeypatch.setattr(cls, "config", {"kernel": "k", "pid": None}, raising=False)
    rows = list(plugin._generator())
    assert [r[1] for r in rows] == [(0x1000, 1, "p1"), (0x2000, 2, "p2"), (0x3000, 3, "p3")]
    assert callable(seen["filter"])
