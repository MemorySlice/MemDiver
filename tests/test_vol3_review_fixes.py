"""Regression tests for the vol3 review findings (store containment, truncated inputs, ...)."""
from __future__ import annotations

from types import SimpleNamespace

import pyarrow as pa
import pytest

from memdiver.analysis.case import Case
from memdiver.analysis.fixture_store import FixtureStore
from memdiver.analysis.plugin_store import PluginStore, archive_previous
from memdiver.app import tools_vol3, tools_vol3_dev as dev
from memdiver.core.service_errors import CapabilityError, ErrorCategory

PSLIST, PSSCAN = "vol3__linux_pslist", "vol3__linux_psscan"


def _reg(case, name, pids, **meta):
    table = pa.table({"pid": pids, "comm": ["x"] * len(pids), "ppid": [0] * len(pids),
                      "tid": pids, "exit_state": [""] * len(pids),
                      "offset_p": [0] * len(pids)})
    return case.register_table(name, table, capture_id="c1", producer="vol3", meta=meta)


# -- 3 / 4: store containment ----------------------------------------------------

def test_symlinked_history_is_refused(tmp_path):
    case = Case.init(tmp_path / "case")
    store = PluginStore(case.dir)
    store.put("p", "# one\n")
    outside = tmp_path / "outside"
    outside.mkdir()
    (case.dir / "plugins" / "history").symlink_to(outside)
    with pytest.raises(CapabilityError) as exc:
        store.put("p", "# two\n")
    assert exc.value.code == "store.escape"
    assert list(outside.iterdir()) == []


def test_archive_previous_refuses_symlinked_history(tmp_path):
    outside = tmp_path / "outside"
    outside.mkdir()
    history = tmp_path / "dir" / "history"
    history.parent.mkdir()
    history.symlink_to(outside)
    with pytest.raises(CapabilityError) as exc:
        archive_previous(tmp_path / "dir" / "f.json", history, "f", ".json", "x")
    assert exc.value.code == "store.escape"
    assert list(outside.iterdir()) == []


def test_symlinked_fixtures_ancestor_creates_nothing_outside(tmp_path):
    case = Case.init(tmp_path / "case")
    outside = tmp_path / "outside"
    outside.mkdir()
    fixtures = case.dir / "fixtures"
    if fixtures.exists():
        fixtures.rmdir()
    fixtures.symlink_to(outside)
    with pytest.raises(CapabilityError) as exc:
        FixtureStore(case.dir).put("f1", plugin="linux.pslist.PsList",
                                   view_path="v.mdview", expect=[{"min_rows": 1}])
    assert exc.value.code == "store.escape"
    assert list(outside.iterdir()) == []


# -- 5: truncated saved-query input ----------------------------------------------

def test_saved_query_refuses_truncated_input(tmp_path):
    case = Case.init(tmp_path / "case")
    _reg(case, PSLIST, [1], truncated=True, stop_reason="row_limit")
    ref = _reg(case, PSSCAN, [1, 2])
    with pytest.raises(CapabilityError) as exc:
        tools_vol3.vol3_query_result(str(case.dir), saved="hidden_processes")
    err = exc.value
    assert err.category is ErrorCategory.PRECONDITION
    assert err.code == "vol3.query_truncated_input"
    assert PSLIST in str(err) and "row_limit" in str(err)
    assert case.runs(PSLIST)[0].truncated and case.runs(PSLIST)[0].stop_reason == "row_limit"
    assert not case.runs(PSSCAN)[0].truncated and ref.truncated is False


def test_saved_query_runs_on_complete_input(tmp_path):
    case = Case.init(tmp_path / "case")
    _reg(case, PSLIST, [1])
    _reg(case, PSSCAN, [1, 2])
    data = tools_vol3.vol3_query_result(str(case.dir), saved="hidden_processes").payload
    assert [r[data["columns"].index("pid")] for r in data["rows"]] == [2]


def test_raw_sql_warns_about_truncated_runs(tmp_path):
    case = Case.init(tmp_path / "case")
    _reg(case, PSLIST, [1], truncated=True, stop_reason="timeout")
    _reg(case, PSSCAN, [1])
    data = tools_vol3.vol3_query_result(
        str(case.dir), sql=f"SELECT pid FROM {PSLIST}").payload
    assert len(data["warnings"]) == 1 and "timeout" in data["warnings"][0]
    clean = tools_vol3.vol3_query_result(str(case.dir), sql=f"SELECT pid FROM {PSSCAN}")
    assert clean.payload["warnings"] == []
    assert PSLIST in case.schema()["tables"] and \
        case.schema()["tables"][PSLIST]["truncated_runs"][0]["stop_reason"] == "timeout"


# -- 8: empty listing that was cut short -----------------------------------------

def _listing(truncated, stop_reason):
    return SimpleNamespace(row_count=0, plugin="linux.pslist.PsList",
                           truncated=truncated, stop_reason=stop_reason)


def test_empty_timed_out_listing_reports_the_timeout():
    with pytest.raises(CapabilityError) as exc:
        tools_vol3._check_listing_not_empty(_listing(True, "timeout"))
    assert exc.value.code == "vol3.run_stopped_early" and "timeout" in str(exc.value)


def test_empty_complete_listing_still_blames_profile():
    with pytest.raises(CapabilityError) as exc:
        tools_vol3._check_listing_not_empty(_listing(False, None))
    assert exc.value.code == "vol3.empty_process_list"


# -- 10: import_parquet location validation --------------------------------------

def _src(tmp_path, table):
    import pyarrow.parquet as pq
    path = tmp_path / "in.parquet"
    pq.write_table(table, path)
    return path


def test_import_rejects_unknown_address_space(tmp_path):
    case = Case.init(tmp_path / "case")
    src = _src(tmp_path, pa.table({"offset": [1, 2]}))
    with pytest.raises(CapabilityError) as exc:
        dev.vol3_import_parquet_result(str(case.dir), str(src), table=PSLIST, capture_id="c",
                                       locations={"offset": "bogus"})
    assert exc.value.category is ErrorCategory.INVALID_INPUT
    assert "kernel_va" in str(exc.value)


def test_import_rejects_non_integer_located_column(tmp_path):
    case = Case.init(tmp_path / "case")
    src = _src(tmp_path, pa.table({"name": ["a", "b"]}))
    with pytest.raises(CapabilityError) as exc:
        dev.vol3_import_parquet_result(str(case.dir), str(src), table=PSLIST, capture_id="c",
                                       locations={"name": "kernel_va"})
    assert exc.value.category is ErrorCategory.INVALID_INPUT and "name" in str(exc.value)
