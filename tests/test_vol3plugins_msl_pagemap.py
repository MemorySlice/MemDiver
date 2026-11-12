"""``msl.pagemap`` (``vol3plugins/msl/pagemap.py``): page-state runs, spec section 7.

Rows are checked against the writer's known page states (every state, Table 35 content
semantics, the inferred-on-import basis), the ``--region`` filter, and equality of the
MemDiver-reader and slim-reader runs.
"""

import pytest

pytest.importorskip("volatility3")

from memdiver.vol3plugins import msl_layer  # noqa: E402
from memdiver.vol3plugins.msl import pagemap  # noqa: E402
from tests.test_vol3plugins_msl_layer import (  # noqa: E402
    PAGE, REGION_A, REGION_B, REGION_C, _file_context, plain_slice)  # noqa: F401
from tests.test_vol3plugins_msl_slim import (  # noqa: E402
    RICH_BASE, plain_rows, rich_slice, run_plugin, run_with_both_readers, sample_msls)  # noqa: F401

COLUMNS = ("Region", "UUID", "Start", "End", "State", "Pages", "Bytes", "Content", "Basis")


@pytest.fixture(autouse=True)
def _fresh_layer_cache():
    yield
    msl_layer.close_slices()


def _runs(rows):
    return [(r[0], r[2], r[3], r[4], r[5]) for r in rows]


def test_every_page_state_run_is_listed_in_order(plain_slice):
    path, _data = plain_slice
    rows, _ = run_plugin(pagemap.PageMap, path)
    a = [(0, REGION_A + i * PAGE, REGION_A + (i + j) * PAGE, state, j)
         for i, j, state in ((0, 2, "Captured"), (2, 1, "NotResident"), (3, 1, "Failed"),
                             (4, 1, "Captured"), (5, 1, "Unmapped"), (6, 1, "Captured"),
                             (7, 1, "NotResident"))]
    assert _runs(plain_rows(rows))[:7] == a
    assert _runs(plain_rows(rows))[7:] == [(1, REGION_B, REGION_B + 3 * PAGE, "Captured", 3),
                               (2, REGION_C, REGION_C + 2 * PAGE, "Captured", 2)]


def test_content_column_follows_table_35(plain_slice):
    path, _ = plain_slice
    rows, _ = run_plugin(pagemap.PageMap, path)
    content = {r[4]: r[7] for r in rows}
    assert content == {"Captured": "stored", "NotResident": "none (content is zero)",
                       "Failed": "none (unreadable)", "Unmapped": "none (absent at read time)"}
    assert all(r[6] == r[5] * PAGE for r in rows)  # Bytes = Pages * page size
    assert {r[8] for r in rows} == {"observed"}  # no import provenance, states are live


def test_imported_capture_says_page_states_are_inferred(rich_slice):
    path, _ = rich_slice
    rows, _ = run_plugin(pagemap.PageMap, path)
    assert {r[8] for r in rows} == {"inferred on import"}
    assert [(int(r[2]), r[4], r[5]) for r in rows] == [
        (RICH_BASE, "Captured", 1), (RICH_BASE + PAGE, "NotResident", 1),
        (RICH_BASE + 2 * PAGE, "Captured", 1)]


def test_region_filter_by_index_and_uuid_prefix(plain_slice):
    path, _ = plain_slice
    everything, _ = run_plugin(pagemap.PageMap, path)
    by_index, _ = run_plugin(pagemap.PageMap, path, region="1")
    assert {r[0] for r in by_index} == {1}
    uuid = by_index[0][1]
    for wanted in (uuid, uuid[:8], uuid.upper(), uuid.replace("-", "")[:12]):
        rows, _ = run_plugin(pagemap.PageMap, path, region=wanted)
        assert {r[0] for r in rows} == {1}, wanted
    assert len(everything) > len(by_index)


def test_region_filter_without_match_logs_and_is_empty(plain_slice, caplog):
    path, _ = plain_slice
    rows, _ = run_plugin(pagemap.PageMap, path, region="99")
    assert rows == [] and "no region matches '99'" in caplog.text


def test_select_regions_unit():
    class R:  # noqa: D401 - minimal stand-in
        def __init__(self, uuid):
            self.block_header = type("H", (), {"block_uuid": uuid})()

    regions = [R("aaaaaaaa-0000-0000-0000-000000000000"), R("bbbbbbbb-1111-0000-0000-000000000000")]
    assert [i for i, _ in pagemap.select_regions(regions, None)] == [0, 1]
    assert [i for i, _ in pagemap.select_regions(regions, "1")] == [1]
    assert [i for i, _ in pagemap.select_regions(regions, "BBBB")] == [1]
    assert pagemap.select_regions(regions, "7") == []


def test_slim_reader_gives_the_same_rows(plain_slice, rich_slice, monkeypatch):
    for path in (plain_slice[0], rich_slice[0]):
        full, slim, _, _ = run_with_both_readers(pagemap.PageMap, path, monkeypatch)
        assert full == slim and full
        monkeypatch.undo()
        msl_layer.close_slices()


def test_real_sample_is_one_captured_run(sample_msls):
    rows, _ = run_plugin(pagemap.PageMap, sample_msls["gocryptfs_aes.msl"])
    assert len(rows) == 1
    assert (rows[0][4], rows[0][5]) == ("Captured", 17408)
    assert int(rows[0][2]) == 0xC000000000


def test_non_msl_primary_refuses_cleanly(plain_slice, caplog):
    path, _ = plain_slice
    ctx = _file_context(path)
    ctx.config["plugins.P.primary"] = "FileLayer"
    grid = pagemap.PageMap(ctx, "plugins.P").run()
    rows = []
    grid.populate(lambda node, acc: rows.append(node.values) or acc, None)
    assert rows == [] and "not an MSL capture layer" in caplog.text
