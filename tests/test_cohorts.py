"""Experiment cohorts: meta.json parsing, grouping, mixed-cohort refusal."""

import json

import pytest

from memdiver.app.session import ToolSession
from memdiver.app.tools import list_phases, scan_dataset
from memdiver.core.dataset_metadata import load_run_meta
from memdiver.core.service_errors import CapabilityError, ErrorCategory
from memdiver.engine.cohorts import (cohort_of, group_by_cohort,
                                     require_single_cohort)


def _run(parent, name, meta=None):
    run = parent / name
    run.mkdir(parents=True)
    (run / "a.dump").write_bytes(b"\x00" * 16)
    if meta is not None:
        (run / "meta.json").write_text(json.dumps(meta))
    return run


def _dump(run):
    return str(run / "a.dump")


def test_parsing_valid_missing_malformed(tmp_path):
    ok = _run(tmp_path, "r1", {"cohort": "len16", "condition": {"len": "16"}})
    assert load_run_meta(ok).cohort == "len16"
    assert load_run_meta(ok).condition == {"len": "16"}
    bare = _run(tmp_path, "r2", {})
    m = load_run_meta(bare)
    assert m.cohort is None and m.condition == {}
    bad = _run(tmp_path, "r3", {"cohort": 5, "condition": {"a": "x", "b": 3}})
    m = load_run_meta(bad)
    assert m.cohort is None and m.condition == {"a": "x"}
    notobj = _run(tmp_path, "r4", {"condition": ["x"]})
    assert load_run_meta(notobj).condition == {}


def test_cohort_of_without_meta(tmp_path):
    assert cohort_of(_dump(_run(tmp_path, "r1"))) is None


def test_group_by_cohort_preserves_order(tmp_path):
    runs = [
        _run(tmp_path, "r1", {"cohort": "b"}),
        _run(tmp_path, "r2", {"cohort": "a"}),
        _run(tmp_path, "r3", {"cohort": "b"}),
        _run(tmp_path, "r4"),
    ]
    paths = [_dump(r) for r in runs]
    groups = group_by_cohort(paths)
    assert list(groups) == ["b", "a", None]
    assert groups["b"] == [paths[0], paths[2]]


def test_require_single_cohort(tmp_path):
    a1 = _dump(_run(tmp_path, "r1", {"cohort": "a"}))
    a2 = _dump(_run(tmp_path, "r2", {"cohort": "a"}))
    b = _dump(_run(tmp_path, "r3", {"cohort": "b"}))
    none = _dump(_run(tmp_path, "r4"))
    assert require_single_cohort([a1, a2, none]) == "a"
    assert require_single_cohort([none]) is None
    with pytest.raises(CapabilityError) as ei:
        require_single_cohort([a1, a2, b])
    assert ei.value.code == "cohort.mixed"
    assert ei.value.category == ErrorCategory.INVALID_INPUT
    assert "'a': 2" in str(ei.value) and "mixed_ok" in str(ei.value)
    assert require_single_cohort([a1, b], mixed_ok=True) is None


def _library(tmp_path):
    lib = tmp_path / "TLS13" / "scen" / "lib"
    _run(lib, "lib_run_13_1", {"cohort": "len16", "condition": {"len": "16"}})
    _run(lib, "lib_run_13_2", {"cohort": "len16"})
    _run(lib, "lib_run_13_3")
    return lib


def test_list_phases_exposes_cohort_rows(tmp_path):
    lib = _library(tmp_path)
    for r in lib.iterdir():
        (r / "lib_run_13_x_pre_handshake.dump").write_bytes(b"\0" * 8)
    out = list_phases(ToolSession(), str(lib))
    rows = {r["run"]: r for r in out["run_rows"]}
    assert rows["lib_run_13_1"]["cohort"] == "len16"
    assert rows["lib_run_13_1"]["condition"] == {"len": "16"}
    assert rows["lib_run_13_3"]["cohort"] is None


def test_scan_dataset_exposes_cohort_counts(tmp_path):
    _library(tmp_path)
    out = scan_dataset(ToolSession(), str(tmp_path))
    assert out["cohorts"] == {"len16": 2}
