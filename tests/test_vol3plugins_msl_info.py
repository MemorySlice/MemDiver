"""``msl.info`` and ``msl.vasmap`` (``vol3plugins/msl/``): rows on a synthetic and a real ``.msl``.

The synthetic slice reuses ``tests/test_vol3plugins_msl_layer.py``'s writer and stacking
helpers; the plugins run in-process through vol3's own construction path. A non-MSL primary
layer must produce one error line and no rows.
"""

import subprocess

import pytest

pytest.importorskip("volatility3")

from memdiver.vol3plugins.msl import info, vasmap  # noqa: E402
from tests.test_vol3plugins_msl_layer import (  # noqa: E402
    PAGE, REGION_A, REGION_B, REGION_C, RUN_0001, _file_context, _stack, _write_slice,
    needs_run_0001, plain_slice,  # noqa: F401  (plain_slice is a fixture)
)
from memdiver.vol3plugins import msl_layer  # noqa: E402

GOCRYPTFS_PID = 65219


@pytest.fixture(autouse=True)
def _fresh_layer_cache():
    yield
    msl_layer.close_slices()


def _run(plugin_cls, ctx, layer_name):
    ctx.config["plugins.P.primary"] = layer_name
    plugin = plugin_cls(ctx, "plugins.P")
    grid = plugin.run()
    rows = []
    grid.populate(lambda node, acc: rows.append(tuple(node.values)) or acc, None)
    return rows


def test_info_rows_synthetic(plain_slice):
    path, data = plain_slice
    ctx, top = _stack(path)
    rows = dict(_run(info.Info, ctx, top.name))
    assert rows["PID"] == "4242"
    assert rows["OS"] == "LINUX" and rows["Architecture"] == "X86_64"
    assert rows["Page size"] == str(PAGE)
    assert rows["Regions"] == "3"
    assert (rows["Pages Captured"], rows["Pages NotResident"]) == ("9", "2")
    assert (rows["Pages Failed"], rows["Pages Unmapped"]) == ("1", "1")
    assert rows["Captured bytes"] == str(9 * PAGE)
    assert rows["VAS size"] == str((8 + 3 + 2) * PAGE)
    assert rows["Encrypted"] == "no" and rows["Compression"] == "NONE"
    assert rows["End of capture"].startswith("present")
    assert rows["Integrity"] == "valid"


def test_info_reports_compression(tmp_path):
    path = tmp_path / "zstd.msl"
    _write_slice(path, compression=msl_layer_compression())
    ctx, top = _stack(path)
    assert "ZSTD" in dict(_run(info.Info, ctx, top.name))["Compression"]


def msl_layer_compression():
    from memdiver.msl.enums import CompAlgo
    return CompAlgo.ZSTD


def test_vasmap_rows_synthetic(plain_slice):
    path, _data = plain_slice
    ctx, top = _stack(path)
    rows = _run(vasmap.VasMap, ctx, top.name)
    assert [int(r[0]) for r in rows] == [REGION_A, REGION_B, REGION_C]
    first = rows[0]
    assert int(first[2]) == 8 * PAGE
    assert first[5] == "C:4 NR:2 F:1 U:1"
    assert first[6] == 4 * PAGE
    assert rows[2][5] == "C:2 NR:0 F:0 U:0"


def test_non_msl_primary_refuses_cleanly(plain_slice, caplog):
    path, _data = plain_slice
    ctx = _file_context(path)  # the raw FileLayer, no MSL stacking
    for plugin_cls in (info.Info, vasmap.VasMap):
        caplog.clear()
        assert _run(plugin_cls, ctx, "FileLayer") == []
        assert "not an MSL capture layer" in caplog.text


@needs_run_0001
def test_info_cli_real_gocryptfs_shows_pid():
    out = subprocess.run(
        ["vol", "-q", "-p", str(info.__file__).rsplit("/msl/", 1)[0], "-f", str(RUN_0001),
         "msl.info"], capture_output=True, text=True, timeout=180)
    assert out.returncode == 0, out.stderr[-500:]
    assert f"PID\t{GOCRYPTFS_PID}" in out.stdout
