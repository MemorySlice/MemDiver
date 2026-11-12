"""``msl.keyhints`` (``vol3plugins/msl/keyhints.py``): KEY_HINT rows and ``--dump``.

A hint's offset indexes the region's PageData (Captured pages only), so the plugin maps it
to virtual addresses through the page-state runs; a key spanning two non-adjacent runs is
read piecewise. The expected bytes come from the writer's own input.
"""

import pytest

pytest.importorskip("volatility3")

from memdiver.vol3plugins import msl_layer  # noqa: E402
from memdiver.vol3plugins.msl import keyhints  # noqa: E402
from tests.test_vol3plugins_msl_layer import PAGE, _file_context, plain_slice  # noqa: E402,F401
from tests.test_vol3plugins_msl_slim import (  # noqa: E402
    RICH_BASE, plain_rows, rich_slice, run_plugin, run_with_both_readers, sample_msls)  # noqa: F401

READABLE, FIRST_PAGE_KEY, OUT_OF_RANGE, NO_LENGTH, ORPHAN = range(5)


@pytest.fixture(autouse=True)
def _fresh_layer_cache():
    yield
    msl_layer.close_slices()


def _rows(rich_slice, **config):
    path, truth = rich_slice
    rows, files = run_plugin(keyhints.KeyHints, path, **config)
    return plain_rows(rows), files, truth


def test_rows_describe_every_hint(rich_slice):
    rows, files, truth = _rows(rich_slice)
    assert files == {}  # nothing is written without --dump
    assert len(rows) == 5
    spans = rows[READABLE]
    assert spans[0] == 0 and spans[1] == str(truth["region"])
    assert spans[2:5] == (PAGE - 4, RICH_BASE + PAGE - 4, 8)
    assert spans[5:10] == ("SESSION_KEY", "SSH", "CONFIRMED", "ACTIVE", "spans two runs")
    assert spans[10] == "yes"
    assert rows[FIRST_PAGE_KEY][3] == RICH_BASE + 16 and rows[FIRST_PAGE_KEY][10] == "yes"


def test_unplaceable_hints_say_why(rich_slice):
    rows, _, _ = _rows(rich_slice)
    assert rows[OUT_OF_RANGE][3] == "N/A"
    assert rows[OUT_OF_RANGE][10] == "no: offset lies outside the region's captured pages"
    assert rows[NO_LENGTH][4] == "N/A" and rows[NO_LENGTH][10] == "no: key length not recorded"
    assert rows[ORPHAN][3] == "N/A"
    assert rows[ORPHAN][10] == "no: region UUID not in this capture"
    assert rows[ORPHAN][5:7] == ("OTHER", "OTHER")


def test_dump_writes_only_readable_keys_across_runs(rich_slice):
    rows, files, truth = _rows(rich_slice, dump=True)
    data = truth["data"]
    assert sorted(files) == ["keyhint_0.bin", "keyhint_1.bin"]
    # PageData is page 0 then page 2 (page 1 is NotResident): the key crosses that seam.
    assert files["keyhint_0.bin"] == data[PAGE - 4:PAGE + 4]
    assert files["keyhint_1.bin"] == data[16:48]
    assert [r[10] for r in rows].count("yes") == 2


def test_slim_reader_gives_the_same_rows_and_files(rich_slice, monkeypatch):
    full, slim, full_files, slim_files = run_with_both_readers(
        keyhints.KeyHints, rich_slice[0], monkeypatch, dump=True)
    assert full == slim and len(full) == 5
    assert full_files == slim_files and len(full_files) == 2


def test_capture_without_hints_has_no_rows(plain_slice):
    assert run_plugin(keyhints.KeyHints, plain_slice[0])[0] == []


def test_real_samples_have_no_hints(sample_msls):
    assert run_plugin(keyhints.KeyHints, sample_msls["ssh_wolfssh_client.msl"])[0] == []


class _Region:
    base_addr, page_size = 0x1000, 0x1000

    class _Iv:
        def __init__(self, start_page, count, state):
            self.start_page, self.count, self.state = start_page, count, state

    page_intervals = [_Iv(0, 2, 0), _Iv(2, 1, 3), _Iv(3, 1, 0)]  # C C NR C


def test_place_hint_maps_pagedata_offsets_to_virtual_addresses():
    place = keyhints.place_hint
    assert place(_Region, 0, 16).pieces == ((0x1000, 16),)
    assert place(_Region, 0x1FF8, 16).pieces == ((0x2FF8, 8), (0x4000, 8))  # run 1 -> run 2
    assert place(_Region, 0x2FF0, 16).pieces == ((0x4FF0, 16),)  # last captured page
    assert place(_Region, 0x3000, 1).problem.startswith("offset lies outside")
    assert place(_Region, 0x2FF8, 16).problem.startswith("offset lies outside")  # runs off the end
    assert place(None, 0, 1).problem == "region UUID not in this capture"


def test_non_msl_primary_refuses_cleanly(plain_slice, caplog):
    ctx = _file_context(plain_slice[0])
    ctx.config["plugins.P.primary"] = "FileLayer"
    rows = []
    keyhints.KeyHints(ctx, "plugins.P").run().populate(
        lambda node, acc: rows.append(node.values) or acc, None)
    assert rows == [] and "not an MSL capture layer" in caplog.text
