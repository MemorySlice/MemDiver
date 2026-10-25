"""Tests for ``app/tools_vol3_dev``: scaffold, check, write-config, import."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import threading
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

pytest.importorskip("volatility3")
pa = pytest.importorskip("pyarrow")
pq = pytest.importorskip("pyarrow.parquet")

from volatility3.framework import contexts  # noqa: E402
from volatility3.framework.layers import physical  # noqa: E402

from memdiver.app import tools_image, tools_vol3_dev as dev  # noqa: E402
from memdiver.core.service_errors import CapabilityError  # noqa: E402
from memdiver.engine.vol3_runner import describe_plugin, plugin_from_source  # noqa: E402

ALMA_VIEW = Path("/private/tmp/claude-501/-Users-danielbaier-research-projects-github-issues-"
                 "2024-fritap-issues-2026-success-memory-slice-git-MemDiver/"
                 "5bdc82f6-3f6f-4afb-b122-28de170adcc9/scratchpad/views/alma9_kernel.mdview")


def _stub_context(has_kernel: bool) -> Any:
    ctx = contexts.Context()
    ctx.add_layer(physical.BufferDataLayer(ctx, "tmp.mem", "memory_layer", b"\x00" * 64))
    kernel = SimpleNamespace(layer_name="memory_layer", symbol_table_name="t")
    return SimpleNamespace(context=ctx, physical_layer="memory_layer", has_kernel=has_kernel,
                           kernel=kernel, lock=threading.RLock())


@pytest.fixture
def fake_view(monkeypatch: pytest.MonkeyPatch):
    def install(has_kernel: bool = True) -> str:
        image_ctx = _stub_context(has_kernel)
        monkeypatch.setattr(tools_image, "_read_descriptor",
                            lambda p: (Path(p), SimpleNamespace()))
        monkeypatch.setattr(tools_image, "_context_for", lambda d, p: image_ctx)
        return "fake.mdview"
    return install


# -- scaffold ---------------------------------------------------------------------

@pytest.mark.parametrize("per_process", [True, False])
def test_scaffold_loads_and_describes(per_process: bool) -> None:
    data = dev.vol3_scaffold_result("pid scan", description="Find things",
                                    per_process=per_process).payload
    info = plugin_from_source(data["source"])
    assert data["class_name"] == "PidScan" == info.cls.__name__
    assert info.cls._required_framework_version == (2, 0, 0)
    assert info.cls._version == (1, 0, 0)
    described = describe_plugin(info)
    names = [r["name"] for r in described["requirements"]]
    assert names == (["pid"] if per_process else [])
    assert described["description"] == "Find things"
    assert "ModuleRequirement" in described["satisfied_by_context"]
    assert ("VersionRequirement" in described["satisfied_by_context"]) is per_process
    assert "OFFSET (V)" in data["source"] and '"PID"' in data["source"]


def test_scaffold_keeps_identifier_case_and_rejects_bad_input() -> None:
    assert dev.vol3_scaffold_result("MyPlugin").payload["class_name"] == "MyPlugin"
    with pytest.raises(CapabilityError) as os_err:
        dev.vol3_scaffold_result("x", os_family="windows")
    assert os_err.value.code == "vol3.scaffold_os_unsupported"
    with pytest.raises(CapabilityError) as name_err:
        dev.vol3_scaffold_result("!!!")
    assert name_err.value.code == "vol3.scaffold_bad_name"


def test_scaffold_description_cannot_break_the_docstring() -> None:
    source = dev.vol3_scaffold_result("p", description='a """ b\nc').payload["source"]
    assert plugin_from_source(source).cls.__name__ == "P"


# -- check ------------------------------------------------------------------------

def test_check_reports_syntax_error_with_line() -> None:
    bad = "import os\n\ndef broken(:\n    pass\n"
    data = dev.vol3_check_result(bad).payload
    assert data["ok"] is False
    assert data["error"]["type"] == "SyntaxError" and data["error"]["line"] == 3


def test_check_reports_runtime_error_line_and_missing_class() -> None:
    boom = "x = 1\ny = missing_name\n"
    err = dev.vol3_check_result(boom).payload["error"]
    assert (err["type"], err["line"]) == ("NameError", 2)
    err = dev.vol3_check_result("x = 1\n").payload["error"]
    assert err["type"] == "PluginError" and "PluginInterface" in err["message"]


def test_check_requires_source() -> None:
    with pytest.raises(CapabilityError):
        dev.vol3_check_result("  ")


def test_check_without_view_describes() -> None:
    source = dev.vol3_scaffold_result("Checked").payload["source"]
    data = dev.vol3_check_result(source).payload
    assert data["ok"] is True and data["plugin"]["name"] == "user.Checked"
    assert "unsatisfied" not in data


def test_check_with_view_reports_unsatisfied_kernel(fake_view) -> None:
    source = dev.vol3_scaffold_result("Checked").payload["source"]
    data = dev.vol3_check_result(source, fake_view(has_kernel=True)).payload
    assert data["ok"] is True and data["satisfied"] is False
    assert "kernel" in {u["name"] for u in data["unsatisfied"]}


def test_check_with_kernelless_view_names_the_cause(fake_view) -> None:
    source = dev.vol3_scaffold_result("Checked").payload["source"]
    data = dev.vol3_check_result(source, fake_view(has_kernel=False)).payload
    assert data["unsatisfied"][0]["code"] == "vol3.needs_kernel"


def test_check_leaves_no_config_behind(fake_view) -> None:
    source = dev.vol3_scaffold_result("Checked").payload["source"]
    view = fake_view(has_kernel=True)
    dev.vol3_check_result(source, view)
    image_ctx = tools_image._context_for(None, None)
    assert "memdiver_check" not in [k.split(".")[0] for k in image_ctx.context.config]


# -- write-config -----------------------------------------------------------------

_LA57_CONFIG = {
    "kernel.offset": 989855744,
    "kernel.layer_name.class": "memdiver.core.image.paging.LinuxIntel5Level",
    "kernel.layer_name.page_map_offset": 10542448640,
    "kernel.layer_name.memory_layer.class": "volatility3.framework.layers.lime.LimeLayer",
}


def _stub_write_config(monkeypatch: pytest.MonkeyPatch, config: dict) -> None:
    descriptor = SimpleNamespace(image_path=lambda p: Path("/data/x.lime"))
    monkeypatch.setattr(tools_image, "_read_descriptor", lambda p: (Path(p), descriptor))
    monkeypatch.setattr(tools_image, "_context_for", lambda d, p: object())
    monkeypatch.setattr(dev, "_built_configuration",
                        lambda ctx, plugin, source=None: (dict(config), SimpleNamespace(name=plugin)))


def test_write_config_writes_valid_json_and_shim(tmp_path: Path,
                                                 monkeypatch: pytest.MonkeyPatch) -> None:
    _stub_write_config(monkeypatch, _LA57_CONFIG)
    out = tmp_path / "out" / "config.json"
    data = dev.vol3_write_config_result("v.mdview", str(out)).payload
    written = json.loads(out.read_text())
    assert written == _LA57_CONFIG
    assert data["kernel_layer_class"].endswith("LinuxIntel5Level")
    assert data["page_map_offset"] == 10542448640
    shim = Path(data["shim_dir"]) / dev.SHIM_FILE
    assert "memdiver.core.image.paging" in shim.read_text()
    assert data["command"][:2] == ["vol", "-q"] and "-c" in data["command"]
    assert str(data["shim_dir"]) in data["command"]
    assert "memdiver" in data["note"]


def test_write_config_skips_shim_for_stock_layers(tmp_path: Path,
                                                  monkeypatch: pytest.MonkeyPatch) -> None:
    stock = {**_LA57_CONFIG,
             "kernel.layer_name.class": "volatility3.framework.layers.intel.LinuxIntel32e"}
    _stub_write_config(monkeypatch, stock)
    data = dev.vol3_write_config_result("v.mdview", str(tmp_path / "c.json")).payload
    assert data["shim_dir"] is None and "-p" not in data["command"]


def test_write_config_requires_out_path(monkeypatch: pytest.MonkeyPatch) -> None:
    _stub_write_config(monkeypatch, _LA57_CONFIG)
    with pytest.raises(CapabilityError):
        dev.vol3_write_config_result("v.mdview", " ")


@pytest.mark.skipif(not ALMA_VIEW.is_file(), reason="alma-9 kernel view not present")
def test_write_config_real_vol_reproduces_122_processes(tmp_path: Path) -> None:
    """Out-of-process stock ``vol -c`` over the LA57 image lists every process."""
    vol = Path(sys.executable).with_name("vol")
    if not vol.is_file():
        pytest.skip("vol launcher not beside the interpreter")
    data = dev.vol3_write_config_result(str(ALMA_VIEW), str(tmp_path / "config.json")).payload
    argv = data["command"]
    command = [str(vol), *argv[1:-1], "-r", "jsonl", argv[-1]]   # -r is a global option
    done = subprocess.run(command, capture_output=True, text=True, timeout=300,
                          env={**os.environ, "PYTHONDONTWRITEBYTECODE": "1"})
    rows = [json.loads(line) for line in done.stdout.splitlines() if line.startswith("{")]
    assert done.returncode == 0, done.stderr[-500:]
    assert len(rows) == 122


# -- import -----------------------------------------------------------------------

def _case(tmp_path: Path) -> str:
    from memdiver.analysis.case import Case
    return str(Case.init(str(tmp_path / "case")).dir)


def _rows(case_dir: str, table: str) -> Any:
    from memdiver.analysis.case import Case
    return Case.open(Path(case_dir)).query(f"SELECT * FROM {table}").table.to_pylist()


def test_import_parquet_guesses_locations(tmp_path: Path) -> None:
    case_dir = _case(tmp_path)
    src = tmp_path / "linux.pslist.PsList.parquet"
    pq.write_table(pa.table({"PID": [1, 2], "COMM": ["a", "b"],
                             "OFFSET (V)": [0x100, 0x200]}), src)
    data = dev.vol3_import_parquet_result(case_dir, str(src), table="vol3__linux_pslist",
                                          capture_id="cap1").payload
    assert data["format"] == "parquet" and data["row_count"] == 2
    assert data["locations"] == {"offset_v": "kernel_va"}
    assert data["locations_guessed"] is True


def test_import_csv_and_explicit_locations(tmp_path: Path) -> None:
    case_dir = _case(tmp_path)
    src = tmp_path / "maps.csv"
    src.write_text("PID,Start,End\n7,4096,8192\n7,8192,12288\n")
    data = dev.vol3_import_parquet_result(
        case_dir, str(src), table="vol3__linux_proc_maps", capture_id="cap1",
        locations={"Start": "process_va"}).payload
    assert data["locations"] == {"start": "process_va"} and data["row_count"] == 2
    guessed = dev.vol3_import_parquet_result(
        case_dir, str(src), table="vol3__linux_proc_maps2", capture_id="cap1").payload
    assert guessed["locations"] == {"start": "process_va", "end": "process_va"}


NESTED = [
    {"PID": 1, "COMM": "init", "OFFSET (V)": 4096, "__children": [
        {"PID": 5, "COMM": "kid", "OFFSET (V)": 8192, "__children": [
            {"PID": 9, "COMM": "grandkid", "OFFSET (V)": 12288, "__children": []}]}]},
    {"PID": 2, "COMM": "other", "OFFSET (V)": 16384, "__children": []},
]


@pytest.mark.parametrize("suffix", [".jsonl", ".json"])
def test_import_jsonl_flattens_children_with_depth(tmp_path: Path, suffix: str) -> None:
    case_dir = _case(tmp_path)
    src = tmp_path / f"pstree{suffix}"
    src.write_text("\n".join(json.dumps(r) for r in NESTED) if suffix == ".jsonl"
                   else json.dumps(NESTED))
    data = dev.vol3_import_parquet_result(case_dir, str(src), table="vol3__linux_pstree",
                                          capture_id="cap1", image_sha256="ab" * 32).payload
    assert data["row_count"] == 4 and "depth" in data["columns"]
    assert data["locations"] == {"offset_v": "kernel_va"}
    rows = _rows(case_dir, "vol3__linux_pstree")
    assert sorted((r["pid"], r["depth"]) for r in rows) == [(1, 0), (2, 0), (5, 1), (9, 2)]
    assert {r["image_sha256"] for r in rows} == {"ab" * 32}


def test_import_rejects_bad_input(tmp_path: Path) -> None:
    case_dir = _case(tmp_path)
    src = tmp_path / "x.csv"
    src.write_text("a\n1\n")
    for kwargs, code in [({"table": "linux_pslist"}, "vol3.bad_table_name"),
                         ({"table": "vol3__x", "capture_id": ""}, "capture_id_required"),
                         ({"table": "vol3__x", "format": "xml"}, "vol3.bad_format")]:
        args = {"capture_id": "c", **kwargs}
        with pytest.raises(CapabilityError) as err:
            dev.vol3_import_parquet_result(case_dir, str(src), **args)
        assert err.value.code == code
    with pytest.raises(CapabilityError) as missing:
        dev.vol3_import_parquet_result(case_dir, str(tmp_path / "nope.csv"),
                                       table="vol3__x", capture_id="c")
    assert missing.value.code == "vol3.file_not_found"
    odd = tmp_path / "x.txt"
    odd.write_text("a")
    with pytest.raises(CapabilityError) as undetected:
        dev.vol3_import_parquet_result(case_dir, str(odd), table="vol3__x", capture_id="c")
    assert undetected.value.code == "vol3.format_undetected"
    broken = tmp_path / "bad.jsonl"
    broken.write_text("{nope")
    with pytest.raises(CapabilityError) as bad:
        dev.vol3_import_parquet_result(case_dir, str(broken), table="vol3__x", capture_id="c")
    assert bad.value.code == "vol3.bad_file"
