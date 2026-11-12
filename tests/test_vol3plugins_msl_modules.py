"""``msl.modules`` (``vol3plugins/msl/modules.py``): MODULE_ENTRY + Module List Index rows."""

import pytest

pytest.importorskip("volatility3")

from memdiver.vol3plugins import msl_layer  # noqa: E402
from memdiver.vol3plugins.msl import modules  # noqa: E402
from tests.test_vol3plugins_msl_layer import _file_context, plain_slice  # noqa: E402,F401
from tests.test_vol3plugins_msl_slim import (  # noqa: E402
    plain_rows, rich_slice, run_plugin, run_with_both_readers, sample_msls)  # noqa: F401


@pytest.fixture(autouse=True)
def _fresh_layer_cache():
    yield
    msl_layer.close_slices()


def test_rows_merge_entries_and_index_and_sort_by_base(rich_slice):
    path, _ = rich_slice
    rows = plain_rows(run_plugin(modules.Modules, path)[0])
    assert rows == [
        (0x400000, 0x1000, "demo", "/usr/bin/demo", "1.0", "blake3:" + "07" * 32,
         "MODULE_ENTRY"),
        (0x7F0000000000, 0x2000, "libx.so", "/lib/libx.so", "N/A", "N/A", "MODULE_ENTRY")]


def test_slim_reader_gives_the_same_rows(rich_slice, monkeypatch):
    full, slim, _, _ = run_with_both_readers(modules.Modules, rich_slice[0], monkeypatch)
    assert full == slim and len(full) == 2


def test_real_sample_lists_the_eleven_gocryptfs_modules(sample_msls):
    rows = plain_rows(run_plugin(modules.Modules, sample_msls["gocryptfs_aes.msl"])[0])
    assert len(rows) == 11
    assert rows[0][:4] == (0x400000, 0x49CAE0, "gocryptfs", "/usr/bin/gocryptfs")
    assert "libcrypto.so.3" in {r[2] for r in rows}
    assert [r[0] for r in rows] == sorted(r[0] for r in rows)


def test_capture_without_modules_gives_no_rows(plain_slice):
    assert run_plugin(modules.Modules, plain_slice[0])[0] == []


def test_index_only_modules_are_listed():
    """A manifest/inline index entry with no MODULE_ENTRY block still produces a row."""
    from types import SimpleNamespace

    from memdiver.vol3plugins import msl_slim

    index = SimpleNamespace(entries=[SimpleNamespace(base_addr=0x1000, module_size=0x10,
                                                     path="/lib/only.so")])
    reader = SimpleNamespace(
        file_header=SimpleNamespace(hash_algo=0), collect_modules=lambda: [],
        collect_module_list_index=lambda: [index])
    assert msl_slim.HashAlgo(0).name == "BLAKE3"
    assert modules.module_rows(reader) == [{
        "base": 0x1000, "size": 0x10, "path": "/lib/only.so", "version": "",
        "source": "MODULE_LIST_INDEX", "hash": ""}]


def test_non_msl_primary_refuses_cleanly(plain_slice, caplog):
    ctx = _file_context(plain_slice[0])
    ctx.config["plugins.P.primary"] = "FileLayer"
    rows = []
    modules.Modules(ctx, "plugins.P").run().populate(
        lambda node, acc: rows.append(node.values) or acc, None)
    assert rows == [] and "not an MSL capture layer" in caplog.text
