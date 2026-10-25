"""Tests for ``engine/vol3_runner`` using in-test vol3 plugins over a buffer layer.

No real memory image: a vol3 ``Context`` with a ``BufferDataLayer`` stands in for
the physical layer; a small stand-in exposes the ``ImageContext`` attributes the
runner reads for the kernel case.
"""

from __future__ import annotations

import datetime as dt
import json
import threading
import time
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Callable, Dict, List, Optional

import pytest

pytest.importorskip("volatility3")
pa = pytest.importorskip("pyarrow")

from volatility3.framework import contexts, interfaces, renderers  # noqa: E402
from volatility3.framework.configuration import requirements  # noqa: E402
from volatility3.framework.layers import physical  # noqa: E402
from volatility3.framework.renderers import format_hints  # noqa: E402

from memdiver.core.image.context import ImageContext  # noqa: E402
from memdiver.core.location import AddressSpace  # noqa: E402
from memdiver.core.service_errors import CapabilityError  # noqa: E402
from memdiver.engine import vol3_runner as vr  # noqa: E402

LAYER = "memory_layer"


# -- fixtures / plugin factory --------------------------------------------------

def _new_context() -> Any:
    ctx = contexts.Context()
    ctx.add_layer(physical.BufferDataLayer(ctx, "tmp.mem", LAYER, b"\x00" * 4096))
    return ctx


def _sign_extend_48(address: int) -> int:
    return address | (0xFFFF << 48) if address & (1 << 47) else address


@pytest.fixture
def phys_ctx() -> ImageContext:
    return ImageContext(Path("fake.img"), _new_context(), LAYER)


@pytest.fixture
def kernel_ctx() -> Any:
    kernel = SimpleNamespace(layer_name=LAYER, symbol_table_name="fake_table")
    return SimpleNamespace(
        context=_new_context(), physical_layer=LAYER, has_kernel=True, kernel=kernel,
        lock=threading.RLock(), canonical_kernel_va=_sign_extend_48)


class _Component:
    _version = (1, 0, 0)


def _make_plugin(name: str, columns: List[Any], rows: Callable[[Any], Any],
                 extra_reqs: Optional[List[Any]] = None, with_layer: bool = True) -> Any:
    """A plugin class; ``rows(self)`` is a generator of ``(level, values)``."""
    def get_requirements(cls: Any) -> List[Any]:
        reqs: List[Any] = []
        if with_layer:
            reqs.append(requirements.TranslationLayerRequirement(
                name="primary", description="layer", optional=False))
        return reqs + list(extra_reqs or [])

    def run(self: Any) -> Any:
        return renderers.TreeGrid(columns, rows(self))

    return type(name, (interfaces.plugins.PluginInterface,), {
        "_required_framework_version": (2, 0, 0), "_version": (1, 2, 3),
        "__doc__": "Test plugin.\nSecond line.",
        "get_requirements": classmethod(get_requirements), "run": run})


def _info(cls: Any) -> vr.PluginInfo:
    return vr.PluginInfo(f"user.{cls.__name__}", "", (1, 2, 3), cls)


def _simple(rows: List[Any], columns: Optional[List[Any]] = None, **kw: Any) -> vr.PluginInfo:
    cols = columns or [("PID", int), ("Name", str)]

    def gen(self: Any) -> Any:
        for item in rows:
            yield item

    return _info(_make_plugin("Simple", cols, gen, **kw))


H = format_hints.Hex


# -- guess_space ------------------------------------------------------------------

@pytest.mark.parametrize("name,kind,pid,kernel,expected", [
    ("OFFSET (V)", "hex", False, False, "kernel_va"),
    ("Offset(P)", "hex", True, True, "physical"),
    ("Anything (v)", "int", False, False, "kernel_va"),      # suffix wins even for int
    ("Start", "hex", False, True, "kernel_va"),
    ("End", "hex", False, False, "physical"),
    ("Base Address", "hex", True, True, "process_va"),
    ("Start VPN", "hex", True, True, "process_va"),
    ("Offset", "hex", True, True, "kernel_va"),              # offset names never process_va
    ("Offset", "hex", True, False, "physical"),
    ("PgOff", "hex", False, True, None),                     # not an address token
    ("Flags", "hex", False, True, None),
    ("Size", "int", False, True, None),                      # non-hex ints: suffix only
    ("Start", "int", False, True, None),
    ("Start", "str", False, True, None),
    ("Name (V)", "str", False, True, None),
])
def test_guess_space_matrix(name, kind, pid, kernel, expected):
    assert vr.guess_space(name, kind, pid, kernel) == expected


# -- column_specs -----------------------------------------------------------------

def _cols(*pairs: Any) -> List[Any]:
    return [SimpleNamespace(name=n, type=t) for n, t in pairs]


def test_column_specs_types_and_overrides():
    cols = _cols(("PID", int), ("Offset (P)", H), ("Start", H), ("Note", str))
    specs = vr.column_specs(cols, True)
    assert [(s.name, s.type, s.space) for s in specs] == [
        ("PID", "int", None), ("Offset (P)", "hex", "physical"),
        ("Start", "hex", "process_va"), ("Note", "str", None)]
    out = vr.column_specs(cols, True, {"Start": None, "Note": "kernel_va"})
    assert out[2].space is None and out[3].space == "kernel_va"


def test_column_specs_invalid_space():
    with pytest.raises(CapabilityError) as exc:
        vr.column_specs(_cols(("Start", H)), True, {"Start": "bogus"})
    assert exc.value.code == "vol3.bad_location"


def test_column_types_cover_all_kinds():
    kinds = [("a", int), ("b", str), ("c", bytes), ("d", format_hints.HexBytes),
             ("e", format_hints.MultiTypeData), ("f", dt.datetime), ("g", bool),
             ("h", float), ("i", format_hints.Bin), ("j", H)]
    got = [s.type for s in vr.column_specs(_cols(*kinds), False)]
    assert got == ["int", "str", "bytes", "bytes", "multi", "datetime", "bool",
                   "float", "int", "hex"]


# -- coerce_arguments ---------------------------------------------------------------

def _arg_plugin() -> Any:
    reqs = [
        requirements.IntRequirement(name="count", description="d", optional=True),
        requirements.ListRequirement(name="pids", description="d", element_type=int,
                                     optional=True),
        requirements.BooleanRequirement(name="dump", description="d", optional=True),
        requirements.ChoiceRequirement(name="mode", description="d", choices=["a", "b"],
                                       optional=True),
        requirements.StringRequirement(name="label", description="d", optional=True),
        requirements.VersionRequirement(name="ver", component=_Component, version=(1, 0, 0)),
    ]
    return _make_plugin("ArgPlugin", [("X", int)], lambda self: iter(()), extra_reqs=reqs)


def test_user_requirements_hide_context_ones():
    cls = _arg_plugin()
    assert sorted(r.name for r in vr.user_requirements(cls)) == [
        "count", "dump", "label", "mode", "pids"]
    info = vr.describe_plugin(_info(cls))
    assert set(info["satisfied_by_context"]) == {"TranslationLayerRequirement",
                                                 "VersionRequirement"}
    by_name = {r["name"]: r for r in info["requirements"]}
    assert by_name["pids"]["type"] == "array" and by_name["pids"]["items"] == {"type": "integer"}
    assert by_name["mode"]["choices"] == ["a", "b"]
    assert by_name["count"]["type"] == "integer" and by_name["dump"]["type"] == "boolean"
    assert info["version"] == "1.2.3"


def test_coerce_arguments_ok():
    cls = _arg_plugin()
    out = vr.coerce_arguments(cls, {"count": "0x10", "pids": 7, "dump": "yes",
                                    "mode": "a", "label": 5})
    assert out == {"count": 16, "pids": [7], "dump": True, "mode": "a", "label": "5"}
    assert vr.coerce_arguments(cls, {"pids": ["1", "0x2", 3]}) == {"pids": [1, 2, 3]}
    assert vr.coerce_arguments(cls, {"dump": "off"}) == {"dump": False}
    assert vr.coerce_arguments(cls, {"dump": "TRUE"}) == {"dump": True}
    assert vr.coerce_arguments(cls, {"count": None}) == {}
    assert vr.coerce_arguments(cls, None) == {}


@pytest.mark.parametrize("args,code", [
    ({"nope": 1}, "vol3.unknown_argument"),
    ({"kernel": "x"}, "vol3.unknown_argument"),          # hidden requirements not settable
    ({"count": True}, "vol3.bad_argument"),
    ({"count": "abc"}, "vol3.bad_argument"),
    ({"count": None, "mode": "z"}, "vol3.bad_argument"),
    ({"pids": ["x"]}, "vol3.bad_argument"),
])
def test_coerce_arguments_refused(args, code):
    # ``None`` entries are skipped, so the mode=z case still validates the choice.
    with pytest.raises(CapabilityError) as exc:
        vr.coerce_arguments(_arg_plugin(), args)
    assert exc.value.code == code


# -- plugin catalogue ---------------------------------------------------------------

def test_resolve_plugin(monkeypatch):
    cat = [vr.PluginInfo(n, "", (1,), None) for n in
           ("linux.foo.A", "linux.foo.B", "linux.bar.C")]
    monkeypatch.setattr(vr, "list_plugins", lambda os_family="linux": cat)
    assert vr.resolve_plugin("linux.foo.A").name == "linux.foo.A"
    assert vr.resolve_plugin(" linux.bar ").name == "linux.bar.C"
    with pytest.raises(CapabilityError) as exc:
        vr.resolve_plugin("linux.foo")
    assert exc.value.code == "vol3.plugin_ambiguous"
    with pytest.raises(CapabilityError) as exc:
        vr.resolve_plugin("linux.zzz")
    assert exc.value.code == "vol3.plugin_unknown"
    with pytest.raises(CapabilityError) as exc:
        vr.resolve_plugin("  ")
    assert exc.value.code == "vol3.plugin_required"


_PLUGIN_SRC = '''
from volatility3.framework import interfaces, renderers
from volatility3.framework.configuration import requirements

class OnePlugin(interfaces.plugins.PluginInterface):
    """User plugin one."""
    _required_framework_version = (2, 0, 0)
    _version = (1, 0, 0)

    @classmethod
    def get_requirements(cls):
        return [requirements.TranslationLayerRequirement(name="primary", description="l")]

    def run(self):
        return renderers.TreeGrid([("N", int)], iter([(0, (41,)), (0, (42,))]))
'''


def test_plugin_from_source_runs(phys_ctx):
    info = vr.plugin_from_source(_PLUGIN_SRC)
    assert info.name == "user.OnePlugin" and info.description == "User plugin one."
    assert vr.run_plugin(phys_ctx, info).rows == [[41], [42]]


def test_plugin_from_source_two_classes_rejected():
    src = _PLUGIN_SRC + "\nclass Second(OnePlugin):\n    pass\n"
    with pytest.raises(CapabilityError, match="exactly one"):
        vr.plugin_from_source(src)


def test_real_linux_pslist_catalogue():
    names = [p.name for p in vr.list_plugins("linux")]
    assert "linux.pslist.PsList" in names and names == sorted(names)
    info = vr.resolve_plugin("linux.pslist")
    desc = vr.describe_plugin(info)
    reqs = {r["name"]: r for r in desc["requirements"]}
    assert "kernel" not in reqs
    assert reqs["pid"]["type"] == "array" and reqs["pid"]["items"] == {"type": "integer"}
    assert "ModuleRequirement" in desc["satisfied_by_context"]


# -- run ------------------------------------------------------------------------------

def test_run_rows_depths_absent(phys_ctx):
    cols = [("PID", int), ("Name", str), ("Offset (P)", H), ("Blob", bytes),
            ("HB", format_hints.HexBytes), ("Multi", format_hints.MultiTypeData),
            ("MultiInt", format_hints.MultiTypeData), ("T", dt.datetime),
            ("Flag", bool)]
    naive = dt.datetime(2024, 1, 2, 3, 4, 5)
    aware = dt.datetime(2024, 1, 2, 3, 4, 5, tzinfo=dt.timezone.utc)

    def gen(self: Any) -> Any:
        yield 0, (1, "init", H(0x10), b"\x01\x02", format_hints.HexBytes(b"\xaa"),
                  format_hints.MultiTypeData(b"abc\x00zz", encoding="utf-8"),
                  format_hints.MultiTypeData(12), naive, True)
        yield 1, (2, renderers.UnreadableValue(), renderers.NotApplicableValue(),
                  b"", format_hints.HexBytes(b""), format_hints.MultiTypeData("q".encode("utf-16-le")),
                  format_hints.MultiTypeData(7), aware, False)

    res = vr.run_plugin(phys_ctx, _info(_make_plugin("Rows", cols, gen)), capture_id="cap")
    assert res.depths == [0, 1] and res.row_count == 2 and not res.truncated
    assert res.stop_reason is None and res.capture_id == "cap"
    r0, r1 = res.rows
    assert r0[:5] == [1, "init", 0x10, b"\x01\x02", b"\xaa"]
    assert type(r0[2]) is int and r0[5] == "abc" and r0[6] == "12"
    assert r0[7] == naive and r0[8] is True
    assert r1[1] is None and r1[2] is None
    assert res.absent == [{}, {"Name": "UnreadableValue", "Offset (P)": "NotApplicableValue"}]
    assert r1[7] == aware and r1[8] is False and r1[5] == "q"


def test_run_canonicalizes_kernel_va_only(kernel_ctx):
    cols = [("PID", int), ("OFFSET (V)", H), ("Offset (P)", H), ("Plain", int)]
    raw = 0x0000_8000_0000_1000

    def gen(self: Any) -> Any:
        yield 0, (1, H(raw), H(raw), raw)

    res = vr.run_plugin(kernel_ctx, _info(_make_plugin("Kva", cols, gen)))
    assert res.rows[0] == [1, 0xFFFF_8000_0000_1000, raw, raw]
    assert res.location(0, "OFFSET (V)").value == 0xFFFF_8000_0000_1000
    assert res.location(0, "OFFSET (V)").space is AddressSpace.KERNEL_VA


def test_run_does_not_canonicalize_without_kernel(phys_ctx):
    raw = 0x0000_8000_0000_1000
    info = _simple([(0, (H(raw),))], columns=[("OFFSET (V)", H)])
    assert vr.run_plugin(phys_ctx, info).rows == [[raw]]


def test_row_limit_truncates(phys_ctx):
    info = _simple([(0, (i, "n")) for i in range(10)])
    res = vr.run_plugin(phys_ctx, info, limit=4)
    assert res.truncated and res.stop_reason == "row_limit" and res.row_count == 4
    assert [r[0] for r in res.rows] == [0, 1, 2, 3]


def test_row_limit_exact_not_truncated(phys_ctx):
    info = _simple([(0, (i, "n")) for i in range(4)])
    res = vr.run_plugin(phys_ctx, info, limit=4)
    assert res.row_count == 4 and not res.truncated and res.stop_reason is None


def test_timeout_between_rows(phys_ctx):
    def gen(self: Any) -> Any:
        for i in range(50):
            time.sleep(0.03)
            yield 0, (i, "n")

    res = vr.run_plugin(phys_ctx, _info(_make_plugin("Slow", [("PID", int), ("N", str)], gen)),
                        timeout_s=0.1)
    assert res.truncated and res.stop_reason == "timeout" and 0 < res.row_count < 50


def test_timeout_via_progress_callback(phys_ctx):
    seen: List[Any] = []

    def gen(self: Any) -> Any:
        for pct in (10, 20, 30, 40):
            time.sleep(0.05)
            self._progress_callback(pct, "scan")      # raises once past the deadline
            yield 0, (pct, "n")

    info = _info(_make_plugin("Scan", [("PID", int), ("N", str)], gen))
    res = vr.run_plugin(phys_ctx, info, timeout_s=0.07,
                        progress=lambda p, d: seen.append((p, d)))
    assert res.truncated and res.stop_reason == "timeout" and res.row_count < 4
    assert seen and seen[0] == (10.0, "scan")


def test_progress_forwarded_without_timeout(phys_ctx):
    seen: List[Any] = []

    def gen(self: Any) -> Any:
        self._progress_callback(50, None)
        yield 0, (1, "n")

    info = _info(_make_plugin("Prog", [("PID", int), ("N", str)], gen))
    res = vr.run_plugin(phys_ctx, info, progress=lambda p, d: seen.append((p, d)))
    assert not res.truncated and seen == [(50.0, "")]


def _config_keys(ctx: Any) -> List[str]:
    return [k for k in ctx.context.config.data if k.startswith("memdiver_runs")]


def test_config_subtree_removed_between_runs(phys_ctx):
    observed: List[Any] = []

    def gen(self: Any) -> Any:
        observed.append((self.config.get("count"), self.config.get("label")))
        yield 0, (1, "n")

    reqs = [requirements.IntRequirement(name="count", description="d", optional=True),
            requirements.StringRequirement(name="label", description="d", optional=True)]
    info = _info(_make_plugin("Cfg", [("PID", int), ("N", str)], gen, extra_reqs=reqs))
    vr.run_plugin(phys_ctx, info, {"count": 5, "label": "first"})
    assert _config_keys(phys_ctx) == []
    vr.run_plugin(phys_ctx, info, {"count": 9})
    assert observed == [(5, "first"), (9, None)]
    assert _config_keys(phys_ctx) == []


def test_config_removed_after_plugin_failure(phys_ctx):
    def gen(self: Any) -> Any:
        raise RuntimeError("boom")
        yield  # pragma: no cover

    info = _info(_make_plugin("Boom", [("PID", int)], gen))
    with pytest.raises(RuntimeError):
        vr.run_plugin(phys_ctx, info)
    assert _config_keys(phys_ctx) == []


def test_needs_kernel_on_physical_only(phys_ctx):
    reqs = [requirements.ModuleRequirement(name="kernel", description="k",
                                           architectures=["Intel32", "Intel64"])]
    info = _info(_make_plugin("NeedsK", [("PID", int)], lambda s: iter(()), extra_reqs=reqs))
    with pytest.raises(CapabilityError) as exc:
        vr.run_plugin(phys_ctx, info)
    assert exc.value.code == "vol3.needs_kernel"


def test_unsatisfied_requirement(phys_ctx):
    reqs = [requirements.IntRequirement(name="must", description="d", optional=False)]
    info = _info(_make_plugin("Unsat", [("PID", int)], lambda s: iter(()), extra_reqs=reqs))
    with pytest.raises(CapabilityError) as exc:
        vr.run_plugin(phys_ctx, info)
    assert exc.value.code == "vol3.unsatisfied" and "must" in str(exc.value)
    assert _config_keys(phys_ctx) == []


def test_run_passes_args(phys_ctx):
    got: Dict[str, Any] = {}

    def gen(self: Any) -> Any:
        got["pids"] = self.config.get("pids")
        got["dump"] = self.config.get("dump")
        yield 0, (1, "n")

    reqs = [requirements.ListRequirement(name="pids", description="d", element_type=int,
                                         optional=True),
            requirements.BooleanRequirement(name="dump", description="d", optional=True)]
    info = _info(_make_plugin("Args", [("PID", int), ("N", str)], gen, extra_reqs=reqs))
    vr.run_plugin(phys_ctx, info, {"pids": "0x5", "dump": "true"})
    assert got == {"pids": [5], "dump": True}


def test_column_overrides_applied_in_run(phys_ctx):
    info = _simple([(0, (H(0x20), H(0x30)))], columns=[("Start", H), ("End", H)])
    res = vr.run_plugin(phys_ctx, info, column_overrides={"End": None, "Start": "msl_va"})
    assert res.location_columns() == {"Start": "msl_va"}


# -- PluginRunResult ----------------------------------------------------------------------

def _result(cols, rows, capture_id="cap", absent=None) -> vr.PluginRunResult:
    return vr.PluginRunResult(
        "linux.pslist.PsList", cols, rows, [0] * len(rows),
        absent or [{} for _ in rows], 0.12345, capture_id=capture_id)


def test_location_process_va_needs_pid():
    cols = [vr.ColumnSpec("PID", "int"), vr.ColumnSpec("Start", "hex", "process_va"),
            vr.ColumnSpec("Phys", "hex", "physical")]
    res = _result(cols, [[7, 0x4000, 0x10], [None, 0x4000, 0x10], [7, None, None]])
    loc = res.location(0, "Start")
    assert loc.space is AddressSpace.PROCESS_VA and loc.pid == 7 and loc.capture_id == "cap"
    assert res.location(1, "Start") is None          # pid absent
    assert res.location(2, "Start") is None          # value absent
    assert res.location(0, "PID") is None            # not an address column
    assert res.location(1, "Phys").value == 0x10
    no_pid = _result([vr.ColumnSpec("Start", "hex", "process_va")], [[0x4000]])
    assert no_pid.location(0, "Start") is None


def test_to_dict():
    cols = [vr.ColumnSpec("B", "bytes"), vr.ColumnSpec("T", "datetime"),
            vr.ColumnSpec("N", "int")]
    when = dt.datetime(2024, 5, 6, 7, 8, 9)
    res = _result(cols, [[b"\xde\xad", when, 1], [None, None, 2], [b"", when, 3]],
                  absent=[{}, {"B": "UnreadableValue"}, {}])
    d = res.to_dict(max_rows=2)
    assert d["rows_returned"] == 2 and d["row_count"] == 3
    assert d["rows"][0]["values"] == ["dead", when.isoformat(), 1]
    assert d["rows"][1]["absent"] == {"B": "UnreadableValue"}
    assert d["elapsed_s"] == 0.123 and d["columns"][2] == {"name": "N", "type": "int",
                                                           "space": None}
    json.dumps(d)
    assert res.to_dict()["rows_returned"] == 3


def test_to_arrow_schema(phys_ctx):
    cols = [("PID", int), ("Offset (P)", H), ("Name", str), ("Blob", bytes),
            ("T", dt.datetime), ("Flag", bool), ("F", float)]
    naive = dt.datetime(2024, 1, 2, 3, 4, 5)

    def gen(self: Any) -> Any:
        yield 0, (1, H(0x10), "a", b"\x01", naive, True, 1.5)
        yield 1, (2, H(0x20), renderers.UnreadableValue(), b"", naive, False, 2.5)

    res = vr.run_plugin(phys_ctx, _info(_make_plugin("Arrow", cols, gen)))
    table = res.to_arrow()
    schema = {f.name: f.type for f in table.schema}
    assert schema["PID"] == pa.int64() and schema["Offset (P)"] == pa.uint64()
    assert schema["Name"] == pa.string() and schema["Blob"] == pa.binary()
    assert schema["T"] == pa.timestamp("us", tz="UTC")
    assert schema["Flag"] == pa.bool_() and schema["F"] == pa.float64()
    assert schema["depth"] == pa.int32() and schema["absent"] == pa.string()
    assert table.column("depth").to_pylist() == [0, 1]
    assert table.column("Name").to_pylist() == ["a", None]
    assert table.column("T").to_pylist()[0].tzinfo is not None
    absent = table.column("absent").to_pylist()
    assert absent[0] is None and json.loads(absent[1]) == {"Name": "UnreadableValue"}


def test_to_arrow_large_int_is_uint64_and_negative_hex_wraps():
    cols = [vr.ColumnSpec("Big", "int"), vr.ColumnSpec("Neg", "int"),
            vr.ColumnSpec("H", "hex")]
    res = _result(cols, [[2**63 + 5, -1, -1], [3, 4, 5]])
    table = res.to_arrow()
    assert table.schema.field("Big").type == pa.uint64()
    assert table.schema.field("Neg").type == pa.int64()
    assert table.column("Big").to_pylist() == [2**63 + 5, 3]
    assert table.column("H").to_pylist() == [2**64 - 1, 5]


def test_to_arrow_empty_result():
    table = _result([vr.ColumnSpec("N", "int")], []).to_arrow()
    assert table.num_rows == 0 and table.schema.field("N").type == pa.int64()


def test_table_name():
    assert vr.table_name("linux.pslist.PsList") == "vol3__linux_pslist"
    assert vr.table_name("linux.sockstat.Sockstat") == "vol3__linux_sockstat"
    assert vr.table_name("User.My-Plugin") == "vol3__user_my_plugin"


# -- rows_to_annotations ------------------------------------------------------------------

def test_rows_to_annotations():
    cols = [vr.ColumnSpec("PID", "int"), vr.ColumnSpec("Comm", "str"),
            vr.ColumnSpec("Start", "hex", "process_va")]
    res = _result(cols, [[1, "init", 0x10], [2, "bash", None], [None, "x", 0x30], [4, "y", 0x40]])
    entries = vr.rows_to_annotations(res, "Start", label_column="Comm", run_ref="run-1")
    assert [e.locations[0].value for e in entries] == [0x10, 0x40]   # absent + pid-less skipped
    assert [e.label for e in entries] == ["init", "y"]
    assert entries[0].kind == "plugin_row" and entries[0].author == "tool:vol3"
    assert entries[0].capture_id == "cap"
    assert entries[0].payload["row"] == {"PID": 1, "Comm": "init", "Start": 0x10}
    assert [(s.kind, s.ref) for s in entries[0].support] == [("vol3_run", "run-1")]
    only = vr.rows_to_annotations(res, "Start", rows=[3], author="tool:me")
    assert len(only) == 1 and only[0].author == "tool:me" and only[0].support == ()
    assert only[0].label == "linux.pslist.PsList Start"


def test_rows_to_annotations_errors():
    cols = [vr.ColumnSpec("Start", "hex", "physical")]
    with pytest.raises(CapabilityError) as exc:
        vr.rows_to_annotations(_result(cols, [[1]], capture_id=None), "Start")
    assert exc.value.code == "vol3.no_capture"
    with pytest.raises(CapabilityError) as exc:
        vr.rows_to_annotations(_result(cols, [[1]]), "Nope")
    assert exc.value.code == "vol3.bad_column"


# -- output files ---------------------------------------------------------------------------

def _file_plugin(names: List[str]) -> vr.PluginInfo:
    def gen(self: Any) -> Any:
        for name in names:
            with self.open(name) as handle:
                handle.write(name.encode())
        yield 0, (1, "n")

    return _info(_make_plugin("Writer", [("PID", int), ("N", str)], gen))


def test_output_file_written_to_out_dir(phys_ctx, tmp_path):
    res = vr.run_plugin(phys_ctx, _file_plugin(["x.bin"]), out_dir=tmp_path / "sub")
    assert res.files == [str(tmp_path / "sub" / "x.bin")]
    assert (tmp_path / "sub" / "x.bin").read_bytes() == b"x.bin"
    assert res.diagnostics == []


def test_output_file_collision_gets_prefix(phys_ctx, tmp_path):
    res = vr.run_plugin(phys_ctx, _file_plugin(["x.bin", "x.bin"]), out_dir=tmp_path)
    assert sorted(Path(f).name for f in res.files) == ["1_x.bin", "x.bin"]


def test_output_file_discarded_without_out_dir(phys_ctx):
    res = vr.run_plugin(phys_ctx, _file_plugin(["x.bin"]))
    assert res.files == [] and len(res.diagnostics) == 1
    assert "discarded" in res.diagnostics[0] and "x.bin" in res.diagnostics[0]


def test_output_file_name_sanitized(phys_ctx, tmp_path):
    res = vr.run_plugin(phys_ctx, _file_plugin(["a:b?.bin"]), out_dir=tmp_path / "o")
    assert (tmp_path / "o" / "a_b_.bin").read_bytes() == b"a:b?.bin"
    assert all(Path(f).parent == tmp_path / "o" for f in res.files)


@pytest.mark.parametrize("value, expected", [
    (0x01424DB6C9E68000, 0xFF424DB6C9E68000),   # LA57 masked
    (0x0000FFFF81000000, 0xFFFFFFFF81000000),   # 4-level masked
    (0xFF424DB6C9E68000, 0xFF424DB6C9E68000),   # already canonical
    (0x00007FFF00001000, 0x00007FFF00001000),   # user-space VA untouched
    (None, None),
])
def test_canonicalize_masked_kernel_va(value, expected):
    assert vr.canonicalize_masked_kernel_va(value) == expected


def test_forget_config_removes_every_leaf(phys_ctx):
    config = phys_ctx.context.config
    config["memdiver_runs.rX.Plugin.a"] = 1
    config["memdiver_runs.rX.Plugin.b.c"] = 2
    vr.forget_config(phys_ctx, "memdiver_runs.rX")
    assert not [k for k in config if k.startswith("memdiver_runs.rX.")]


def test_timeout_inside_a_vol3_layer_scan_is_reported_not_swallowed(phys_ctx):
    """vol3's layer scan catches the progress callback's exception and just stops
    yielding; the run must still say it timed out (review finding #1)."""
    from volatility3.framework.layers.scanners import BytesScanner

    def gen(self: Any) -> Any:
        layer = self.context.layers[self.config["primary"]]
        for offset in layer.scan(self.context, BytesScanner(b"\x00"),
                                 progress_callback=self._progress_callback):
            yield 0, (offset,)

    cls = _make_plugin("Scanner", [("Offset (P)", format_hints.Hex)], gen)
    res = vr.run_plugin(phys_ctx, _info(cls), timeout_s=-1.0)
    assert res.truncated is True and res.stop_reason == "timeout"


def test_failed_construction_leaves_no_config_behind(phys_ctx):
    cls = _make_plugin("NeedsKernel", [("PID", int)], lambda self: iter(()),
                       extra_reqs=[requirements.ModuleRequirement(name="kernel")])
    with pytest.raises(CapabilityError):
        vr.run_plugin(phys_ctx, _info(cls))
    assert not [k for k in phys_ctx.context.config if k.startswith("memdiver_runs.")]
