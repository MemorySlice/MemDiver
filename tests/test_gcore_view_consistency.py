"""One view per surface on a gcore core whose ``raw`` and ``vas`` views differ.

gcore (and gdb_raw/lldb_raw) default ``size_for`` / ``read_all`` to ``"vas"``
but ``read_range`` / ``find_all`` to ``"raw"``. A surface leaning on both
defaults sizes one view and reads or searches the other. These tests pin:

* ``run_file`` reports ``offset_view`` (``"vas"`` here, ``"raw"`` for a flat
  dump) and its hit offsets address the planted bytes in that view;
* ``/hex-raw`` reports ``distinct_views`` from the detected format;
* the entropy endpoint sizes and reads the same (flat) view and names it;
* ``locate_key_across_dumps`` sizes the view it searches.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List

import pytest

from memdiver.app.pipeline.analysis_task_runner import run_file
from memdiver.app.session import ToolSession
from memdiver.app.tools_inspect import entropy_result, read_hex_raw_result
from memdiver.core.dump_source import distinct_views, open_dump
from memdiver.engine.key_location import locate_key_across_dumps
from tests.fixtures.synth_gcore_planted import (
    PLANTED_SECRET,
    SECRET_REGEX,
    write_planted_core,
)


@dataclass
class _FakeCtx:
    task_id: str = "test-gcore-view-consistency"
    events: List[Dict[str, Any]] = field(default_factory=list)

    def emit(self, event_type: str, **fields: Any) -> None:
        self.events.append({"type": event_type, **fields})

    def is_cancelled(self) -> bool:
        return False


@pytest.fixture
def core(tmp_path):
    return write_planted_core(tmp_path / "planted.core")


def _run_file(dump: Path, out: Path) -> Dict[str, Any]:
    run_file({"dump_path": str(dump), "algorithms": ["user_regex"],
              "user_regex": SECRET_REGEX, "artifact_dir": str(out)}, _FakeCtx())
    return json.loads((out / "analysis" / "result.json").read_text())


def test_fixture_views_really_differ(core):
    assert core.raw_offset != core.vas_offset
    with open_dump(core.path) as source:
        assert source.format_name == "gcore"
        n = len(PLANTED_SECRET)
        assert source.read_range(core.raw_offset, n, view="raw") == PLANTED_SECRET
        assert source.read_range(core.vas_offset, n, view="vas") == PLANTED_SECRET
        assert source.read_range(core.vas_offset, n, view="raw") != PLANTED_SECRET


def test_run_file_names_vas_offset_view_for_gcore(core, tmp_path):
    report = _run_file(core.path, tmp_path / "out")["libraries"][0]
    assert report["metadata"]["offset_view"] == "vas"
    assert [h["offset"] for h in report["hits"]] == [core.vas_offset]


def test_run_file_keeps_raw_offset_view_for_flat_dump(tmp_path):
    dump = tmp_path / "flat.dump"
    dump.write_bytes(b"\x00" * 300 + PLANTED_SECRET + b"\x00" * 300)
    report = _run_file(dump, tmp_path / "out")["libraries"][0]
    assert report["metadata"]["offset_view"] == "raw"
    assert [h["offset"] for h in report["hits"]] == [300]


def test_distinct_views(core, tmp_path):
    flat = tmp_path / "flat.dump"
    flat.write_bytes(b"\x00" * 64)
    with open_dump(core.path) as source:
        assert distinct_views(source) == ("raw", "vas")
    with open_dump(flat) as source:
        assert distinct_views(source) == ("raw",)


def test_hex_raw_reports_distinct_views(core):
    payload = read_hex_raw_result(ToolSession(), str(core.path), 0, 1).payload
    assert payload["format"] == "gcore"
    assert payload["distinct_views"] == ["raw", "vas"]


def test_entropy_window_reads_the_view_it_sizes(core):
    # A window ending exactly at the vas size: valid in the flat view, and a
    # read of the SAME view returns all of it. Mixing views read the raw
    # file instead (a different byte count and different bytes).
    n = 256
    payload = entropy_result(
        ToolSession(), str(core.path), core.vas_size - n, n, window=32, step=16,
    ).payload
    assert payload["view"] == "vas"
    with open_dump(core.path) as source:
        expected = source.read_range(core.vas_size - n, n, view="vas")
    from memdiver.core.entropy import shannon_entropy
    assert payload["overall_entropy"] == round(shannon_entropy(expected), 4)


def test_entropy_window_over_planted_bytes_uses_vas(core):
    from memdiver.core.entropy import shannon_entropy
    n = len(PLANTED_SECRET)
    payload = entropy_result(
        ToolSession(), str(core.path), core.vas_offset, n).payload
    assert payload["overall_entropy"] == round(shannon_entropy(PLANTED_SECRET), 4)


def test_entropy_whole_dump_is_the_flat_view(core):
    from memdiver.core.entropy import shannon_entropy
    payload = entropy_result(ToolSession(), str(core.path)).payload
    with open_dump(core.path) as source:
        assert payload["overall_entropy"] == round(
            shannon_entropy(source.read_all()), 4)
    assert payload["view"] == "vas"


def test_locate_key_sizes_the_view_it_searches(core):
    result = locate_key_across_dumps([core.path], PLANTED_SECRET)
    row = result.dumps[0]
    assert row.present is True
    # find_all's default for gcore is "raw", so the size must be raw's too.
    assert row.size_for_view == core.raw_size
    assert list(row.offsets) == [core.raw_offset]


def test_locate_key_explicit_vas_view(core):
    row = locate_key_across_dumps(
        [core.path], PLANTED_SECRET, view="vas").dumps[0]
    assert row.size_for_view == core.vas_size
    assert list(row.offsets) == [core.vas_offset]


if __name__ == "__main__":
    raise SystemExit(pytest.main([__file__, "-q"]))
