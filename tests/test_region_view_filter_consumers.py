"""Consumers of a FILTERED consensus read back through the SAME view filter.

A filtered ``vas`` view is a dense concatenation of the included runs, so its
offsets differ from the unfiltered view. Every consumer that re-opens a dump
after a filtered consensus (aligned windows, class-region jump offsets,
pipeline stages reading a reference, n-sweep, hex reads) must therefore open
it with the filter the consensus used. These tests pin that contract, plus the
REST session auto-apply precedence and the CLI flag parsing.
"""

from __future__ import annotations

import argparse
import base64
import json
from pathlib import Path

import pytest

from memdiver.core.dump_source import open_dump
from memdiver.engine.consensus_service import build_consensus
from memdiver.msl.region_select import RegionCategory as C
from memdiver.msl.region_select import RegionSelection
from tests.test_region_view_filter import PAGE, _write_dump

HEAP_RW = RegionSelection(frozenset({C.HEAP}), writable_only=True)
HEAP_RW_NOTE = HEAP_RW.to_note()


@pytest.fixture
def pair(tmp_path):
    a = _write_dump(tmp_path / "a.msl", 0, 0x10, extra_ro_anon=True)
    b = _write_dump(tmp_path / "b.msl", 0x100000, 0x40, extra_ro_anon=False)
    return a, b


def _read_view(path, offset, length, region_filter=None, view="vas"):
    with open_dump(Path(path), region_filter=region_filter) as src:
        src.open()
        return bytes(src.read_range(offset, length, view=view))


# -- the vector records its filter ----------------------------------------------


def test_consensus_vector_records_the_filter(pair):
    paths = [str(p) for p in pair]
    assert build_consensus(paths).region_filter is None
    assert build_consensus(paths, region_filter=HEAP_RW).region_filter == HEAP_RW_NOTE


# -- aligned window -----------------------------------------------------------


def test_filtered_window_reads_the_filtered_bytes(pair):
    from memdiver.app.tools_consensus import aligned_window_from_vector

    paths = [str(p) for p in pair]
    consensus = build_consensus(paths, region_filter=HEAP_RW)
    window = aligned_window_from_vector(
        consensus, anchor_path=paths[0], anchor_view="vas",
        offset=PAGE, length=64,
    )
    assert window["region_filter"] == HEAP_RW_NOTE
    for block, path in zip(window["dumps"], paths):
        expected = _read_view(path, PAGE, 64, region_filter=HEAP_RW)
        assert base64.b64decode(block["bytes"]) == expected
    # The gap this closes: the UNFILTERED view holds other bytes there.
    assert _read_view(paths[0], PAGE, 64) != _read_view(
        paths[0], PAGE, 64, region_filter=HEAP_RW)


def test_window_result_builds_and_reads_with_the_filter(pair):
    from memdiver.app.composition import build_tool_session
    from memdiver.app.tools_consensus import aligned_window_result

    paths = [str(p) for p in pair]
    payload = aligned_window_result(
        build_tool_session(), dump_paths=paths, anchor_path=paths[1],
        anchor_view="vas", offset=0, length=32, region_filter=HEAP_RW_NOTE,
    ).payload
    assert payload["region_filter"] == HEAP_RW_NOTE
    expected = _read_view(paths[1], 0, 32, region_filter=HEAP_RW)
    assert base64.b64decode(payload["dumps"][1]["bytes"]) == expected


def test_vector_without_filter_field_reads_unfiltered(pair):
    """A vector predating the field behaves exactly as before."""
    from memdiver.app.tools_consensus import aligned_window_from_vector

    paths = [str(p) for p in pair]
    consensus = build_consensus(paths)
    del consensus.region_filter  # simulate a pre-field vector
    window = aligned_window_from_vector(
        consensus, anchor_path=paths[0], anchor_view="vas", offset=0, length=16)
    assert window["region_filter"] is None
    assert base64.b64decode(window["dumps"][0]["bytes"]) == _read_view(paths[0], 0, 16)


def test_built_filter_beats_a_conflicting_request(pair):
    from memdiver.app.tools_consensus import aligned_window_from_vector

    paths = [str(p) for p in pair]
    consensus = build_consensus(paths, region_filter=HEAP_RW)
    window = aligned_window_from_vector(
        consensus, anchor_path=paths[0], anchor_view="vas", offset=0,
        length=16, region_filter="stack",
    )
    assert window["region_filter"] == HEAP_RW_NOTE
    assert base64.b64decode(window["dumps"][0]["bytes"]) == _read_view(
        paths[0], 0, 16, region_filter=HEAP_RW)


# -- class regions ------------------------------------------------------------


def test_class_region_jump_offsets_are_filtered_view_offsets(pair):
    from memdiver.app.tools_consensus import class_regions_from_vector

    paths = [str(p) for p in pair]
    consensus = build_consensus(paths, region_filter=HEAP_RW)
    page = class_regions_from_vector(
        consensus, classes=["invariant", "non_invariant"], min_length=1,
        anchor_path=paths[0], anchor_view="vas",
    )
    assert page["region_filter"] == HEAP_RW_NOTE
    assert page["anchor"]["jumpable"]
    assert page["regions"]
    for row in page["regions"]:
        got = _read_view(paths[0], row["anchor_offset"], 1, region_filter=HEAP_RW)
        assert got == consensus.reference_bytes[row["slab_start"]:row["slab_start"] + 1]


# -- n-sweep ------------------------------------------------------------------


def test_nsweep_applies_and_records_the_filter(pair):
    from memdiver.engine.nsweep import run_nsweep

    sources = [open_dump(p) for p in pair]
    for src in sources:
        src.open()
    try:
        result = run_nsweep(
            sources, n_values=[2], reduce_kwargs={}, oracle=lambda _b: False,
            region_filter=HEAP_RW,
        )
        assert all(s.size_for("vas") == 3 * PAGE for s in sources)
    finally:
        for src in sources:
            src.close()
    assert result.region_filter == HEAP_RW_NOTE
    assert result.to_dict()["region_filter"] == HEAP_RW_NOTE


def test_nsweep_without_filter_is_unchanged(pair):
    from memdiver.engine.nsweep import run_nsweep

    sources = [open_dump(p) for p in pair]
    for src in sources:
        src.open()
    try:
        result = run_nsweep(sources, n_values=[2], reduce_kwargs={},
                            oracle=lambda _b: False)
    finally:
        for src in sources:
            src.close()
    assert result.region_filter is None
    assert "region_filter" not in result.to_dict()


# -- pipeline stages read the filter back from the artifacts --------------------


def test_pipeline_stages_reuse_the_recorded_filter(pair, tmp_path):
    from memdiver.app import tools_pipeline

    out = tmp_path / "consensus"
    meta = tools_pipeline.consensus(
        dump_paths=[str(p) for p in pair], output_dir=str(out),
        region_filter=HEAP_RW_NOTE)
    assert json.loads((out / "consensus.json").read_text())["region_filter"] == HEAP_RW_NOTE
    assert tools_pipeline._consensus_region_filter(meta["variance_path"]) == HEAP_RW_NOTE
    # Explicit wins over the recorded one.
    assert tools_pipeline._consensus_region_filter(
        meta["variance_path"], "stack") == "regions=stack"

    reduced = tools_pipeline.search_reduce(
        variance_path=meta["variance_path"], reference_path=str(pair[0]),
        num_dumps=2, output_dir=str(tmp_path / "reduce"), min_variance=0.0)
    assert reduced["region_filter"] == HEAP_RW_NOTE
    candidates = json.loads(Path(reduced["candidates_path"]).read_text())
    assert candidates["region_filter"] == HEAP_RW_NOTE


def test_unfiltered_artifacts_record_nothing(pair, tmp_path):
    from memdiver.app import tools_pipeline

    meta = tools_pipeline.consensus(
        dump_paths=[str(p) for p in pair], output_dir=str(tmp_path / "c"))
    assert tools_pipeline._consensus_region_filter(meta["variance_path"]) is None


def test_incremental_state_records_the_filter(pair, tmp_path):
    from memdiver.app import tools_pipeline

    meta = tools_pipeline.consensus(
        dump_paths=[str(p) for p in pair], output_dir=str(tmp_path / "c"),
        persist_welford=True, region_filter=HEAP_RW_NOTE)
    state = json.loads(Path(meta["state_path"]).read_text())
    assert state["region_filter"] == HEAP_RW_NOTE
    assert meta["size"] == 3 * PAGE


def test_reference_read_uses_the_filter(pair):
    from memdiver.app.tools_pipeline import _read_reference_bytes

    filtered = _read_reference_bytes(str(pair[0]), {}, region_filter=HEAP_RW_NOTE)
    assert len(filtered) == 3 * PAGE
    assert len(_read_reference_bytes(str(pair[0]), {})) > len(filtered)


# -- hex reads ------------------------------------------------------------------


def test_hex_raw_read_honours_the_filter(pair):
    from memdiver.app.composition import build_tool_session
    from memdiver.app.tools_inspect import read_hex_raw_result

    result = read_hex_raw_result(
        build_tool_session(), str(pair[0]), PAGE, 32, view="vas",
        region_filter=HEAP_RW_NOTE)
    assert base64.b64decode(result.payload["bytes"]) == _read_view(
        pair[0], PAGE, 32, region_filter=HEAP_RW)


# -- session auto-apply precedence ---------------------------------------------


def test_effective_region_filter_precedence():
    from memdiver.api.region_filter_resolution import effective_region_filter

    # Request value wins over the session's.
    assert effective_region_filter(
        "regions=stack", explicitly_set=True, session_filter="regions=heap",
    ) == "regions=stack"
    # Explicit "all" (normalised to None by the model) means NO filter.
    assert effective_region_filter(
        None, explicitly_set=True, session_filter="regions=heap") is None
    # Field not sent -> the session's filter.
    assert effective_region_filter(
        None, explicitly_set=False, session_filter="regions=heap") == "regions=heap"
    assert effective_region_filter(
        None, explicitly_set=False, session_filter=None) is None


def test_request_region_filter_reads_the_saved_session(tmp_path):
    from memdiver.api.models import ConsensusRequest
    from memdiver.api.region_filter_resolution import request_region_filter
    from memdiver.engine.session_store import SessionSnapshot, SessionStore

    SessionStore.save(SessionSnapshot(session_name="s", region_filter="regions=heap"),
                      tmp_path / "s.memdiver")
    implicit = ConsensusRequest(dump_paths=["a", "b"], session_name="s")
    explicit_all = ConsensusRequest(dump_paths=["a", "b"], session_name="s",
                                    region_filter="all")
    explicit = ConsensusRequest(dump_paths=["a", "b"], session_name="s",
                                region_filter="stack")
    no_session = ConsensusRequest(dump_paths=["a", "b"])
    assert request_region_filter(implicit, tmp_path) == "regions=heap"
    assert request_region_filter(explicit_all, tmp_path) is None
    assert request_region_filter(explicit, tmp_path) == "regions=stack"
    assert request_region_filter(no_session, tmp_path) is None


@pytest.fixture
def client(tmp_path, monkeypatch):
    from fastapi.testclient import TestClient

    from memdiver.api.config import get_settings
    from memdiver.api.main import create_app

    for sub, env in [("oracles", "MEMDIVER_ORACLE_DIR"),
                     ("tasks", "MEMDIVER_TASK_ROOT"),
                     ("uploads", "MEMDIVER_UPLOAD_DIR"),
                     ("sessions", "MEMDIVER_SESSION_DIR")]:
        (tmp_path / sub).mkdir()
        monkeypatch.setenv(env, str(tmp_path / sub))
    monkeypatch.setenv("MEMDIVER_PIPELINE_MAX_WORKERS", "1")
    get_settings.cache_clear()
    with TestClient(create_app()) as c:
        yield c
    get_settings.cache_clear()


def test_rest_consensus_auto_applies_the_session_filter(client, pair):
    paths = [str(p) for p in pair]
    saved = client.post("/api/sessions/",
                        json={"session_name": "rf", "region_filter": HEAP_RW_NOTE})
    assert saved.status_code == 200, saved.text

    implicit = client.post("/api/analysis/consensus",
                           json={"dump_paths": paths, "session_name": "rf"}).json()
    assert implicit["region_filter"] == HEAP_RW_NOTE
    assert implicit["size"] == 3 * PAGE

    explicit_all = client.post(
        "/api/analysis/consensus",
        json={"dump_paths": paths, "session_name": "rf", "region_filter": "all"},
    ).json()
    assert explicit_all["region_filter"] is None
    assert explicit_all["size"] > 3 * PAGE

    explicit = client.post(
        "/api/analysis/consensus",
        json={"dump_paths": paths, "session_name": "rf", "region_filter": "stack"},
    ).json()
    assert explicit["region_filter"] == "regions=stack"

    missing = client.post("/api/analysis/consensus",
                          json={"dump_paths": paths, "session_name": "nope"})
    assert missing.status_code == 404


def test_rest_window_by_consensus_id_uses_the_build_filter(client, pair):
    paths = [str(p) for p in pair]
    built = client.post("/api/analysis/consensus",
                        json={"dump_paths": paths, "region_filter": HEAP_RW_NOTE}).json()
    window = client.post("/api/analysis/consensus/aligned-window", json={
        "consensus_id": built["consensus_id"], "anchor_path": paths[0],
        "view": "vas", "offset": PAGE, "length": 32,
    })
    assert window.status_code == 200, window.text
    body = window.json()
    assert body["region_filter"] == HEAP_RW_NOTE
    assert base64.b64decode(body["dumps"][0]["bytes"]) == _read_view(
        paths[0], PAGE, 32, region_filter=HEAP_RW)


def test_pipeline_worker_params_auto_apply_the_session_filter(tmp_path):
    from memdiver.api.routers.pipeline import PipelineRunRequest, _build_worker_params
    from memdiver.engine.session_store import SessionSnapshot, SessionStore

    SessionStore.save(SessionSnapshot(session_name="p", region_filter="regions=stack"),
                      tmp_path / "p.memdiver")
    import memdiver.api.region_filter_resolution as resolution

    original = resolution._default_session_dir
    resolution._default_session_dir = lambda: tmp_path
    try:
        implicit = PipelineRunRequest(source_paths=["a.msl"], session_name="p")
        explicit = PipelineRunRequest(source_paths=["a.msl"], session_name="p",
                                      region_filter="all")
        assert _build_worker_params(implicit, None, tmp_path)["region_filter"] == \
            "regions=stack"
        assert _build_worker_params(explicit, None, tmp_path)["region_filter"] is None
    finally:
        resolution._default_session_dir = original


# -- CLI flags ------------------------------------------------------------------


def _consensus_parser():
    from memdiver.cli.consensus import add_region_filter_arguments
    from memdiver.cli.main import build_parser

    parser = build_parser()
    sub = next(a for a in parser._actions
               if isinstance(a, argparse._SubParsersAction))
    consensus = sub.choices["consensus"]
    if not any("--regions" in a.option_strings for a in consensus._actions):
        add_region_filter_arguments(consensus)
    return parser


@pytest.mark.parametrize("argv, expected", [
    ([], None),
    (["--regions", "heap,stack"], "regions=heap,stack"),
    (["--regions", "all"], None),
    (["--regions", "heap", "--exclude-regions", "stack"], "regions=heap"),
])
def test_cli_region_flags_parse(pair, argv, expected):
    from memdiver.cli.consensus import region_filter_from_args

    args = _consensus_parser().parse_args(["consensus", str(pair[0]), str(pair[1]), *argv])
    assert region_filter_from_args(args) == expected


def test_cli_exclude_only_means_everything_but(pair):
    from memdiver.cli.consensus import region_filter_from_args

    args = _consensus_parser().parse_args(
        ["consensus", str(pair[0]), str(pair[1]), "--exclude-regions", "image"])
    note = region_filter_from_args(args)
    assert note is not None and "image" not in note.split("=", 1)[1].split(",")


def test_cli_region_flags_reject_unknown_names(pair):
    from memdiver.cli.consensus import region_filter_from_args

    args = _consensus_parser().parse_args(
        ["consensus", str(pair[0]), str(pair[1]), "--regions", "bogus"])
    with pytest.raises(ValueError):
        region_filter_from_args(args)


def test_cli_missing_flags_mean_unfiltered():
    from memdiver.cli.consensus import region_filter_from_args

    assert region_filter_from_args(argparse.Namespace()) is None


def test_cli_consensus_reports_the_filter(pair, tmp_path):
    from memdiver.cli.consensus import _cmd_consensus

    out = tmp_path / "report.json"
    args = _consensus_parser().parse_args(
        ["consensus", str(pair[0]), str(pair[1]), "--regions", "heap",
         "-o", str(out)])
    assert _cmd_consensus(args) == 0
    report = json.loads(out.read_text())
    assert report["region_filter"] == "regions=heap"
    assert report["size"] == 3 * PAGE
