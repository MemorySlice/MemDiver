"""``classification_basis_mixed`` reaches every consensus surface.

``core.region_align`` knows when a REGION-FILTERED alignment mixes dumps
classified by mapping names (new imports / live captures with a named
VAS_MAP) with dumps classified by stored type only: their ``anon:`` ordinals
can diverge, so filtered regions may not correspond. It used to only log
that. These tests pin the structured ``Diagnostic`` (code
``classification_basis_mixed``) on the library result objects, the REST
``POST /api/analysis/consensus`` body, the CLI JSON + stderr, the producer
payloads the MCP tools serialise, and the incremental builder — and its
ABSENCE when the build is unfiltered or every dump shares one basis.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from memdiver.api.main import create_app  # noqa: E402
from memdiver.app.composition import open_dump  # noqa: E402
from memdiver.app.tools_pipeline import consensus as pipeline_consensus  # noqa: E402
from memdiver.core.region_align import (  # noqa: E402
    CLASSIFICATION_BASIS_MIXED,
    AlignmentCoverage,
    classification_basis_diagnostic,
)
from memdiver.core.region_view_filter import region_filter_note  # noqa: E402
from memdiver.engine.consensus_msl import (  # noqa: E402
    build_msl_consensus_result,
    build_msl_incremental,
)
from memdiver.engine.consensus_service import build_consensus  # noqa: E402

from tests.test_region_align_names import (  # noqa: E402
    DEFAULT,
    _android_import,
    _memslicer_msl,
    _strip_names,
)

HEAP = "heap"


def _codes(diagnostics) -> list:
    return [d["code"] if isinstance(d, dict) else d.code for d in diagnostics]


@pytest.fixture
def memslicer_pair(tmp_path):
    """Native captures: one new-style (named VAS_MAP), one legacy (no names)."""
    named = _memslicer_msl(tmp_path / "named.msl", True)
    legacy = _memslicer_msl(tmp_path / "legacy.msl", False)
    return str(named), str(legacy)


@pytest.fixture
def android_pair(tmp_path, monkeypatch):
    """Imports of one Android app_process: with names, and the pre-W1a way."""
    named = _android_import(tmp_path, "named")
    _strip_names(monkeypatch)
    legacy = _android_import(tmp_path, "legacy")
    return str(named), str(legacy)


# -- core / library ------------------------------------------------------------


def test_diagnostic_shape_names_the_dumps_and_remedy(android_pair):
    from memdiver.core.region_align import build_dump_region_map
    from memdiver.msl.reader import MslReader

    maps = []
    for i, path in enumerate(android_pair):
        with MslReader(Path(path)) as reader:
            maps.append(build_dump_region_map(i, reader, metadata_only=True,
                                              region_filter=DEFAULT))
    diag = classification_basis_diagnostic(maps)
    body = diag.to_dict()
    assert body["code"] == CLASSIFICATION_BASIS_MIXED
    assert body["severity"] == "warning"
    assert body["details"]["named_dumps"] == [0]
    assert body["details"]["stored_type_dumps"] == [1]
    assert body["details"]["total_dumps"] == 2
    assert "re-import" in body["details"]["remedy"]
    assert AlignmentCoverage.from_alignment(maps, []).diagnostics == (diag,)


def test_imported_android_pair_warns_in_one_shot_and_incremental(android_pair):
    """Library result objects: ``MslConsensusResult`` + incremental builder."""
    sources = [open_dump(Path(p), region_filter=region_filter_note(DEFAULT))
               for p in android_pair]
    for src in sources:
        src.open()
    try:
        result = build_msl_consensus_result(sources)
        assert _codes(result.coverage.diagnostics) == [CLASSIFICATION_BASIS_MIXED]
        builder = build_msl_incremental(sources, region_filter=DEFAULT)
        assert _codes(builder.diagnostics) == [CLASSIFICATION_BASIS_MIXED]
        assert _codes(build_msl_consensus_result(sources, region_filter=None)
                      .coverage.diagnostics) == [CLASSIFICATION_BASIS_MIXED]
    finally:
        for src in sources:
            src.close()


def test_imported_android_pair_unfiltered_is_silent(android_pair):
    sources = [open_dump(Path(p)) for p in android_pair]
    for src in sources:
        src.open()
    try:
        assert build_msl_consensus_result(sources).coverage.diagnostics == ()
        assert build_msl_incremental(sources).diagnostics == ()
    finally:
        for src in sources:
            src.close()


def test_consensus_vector_report_carries_the_diagnostic(memslicer_pair):
    cm = build_consensus(list(memslicer_pair), region_filter=HEAP)
    report = cm.alignment_report
    assert _codes(report.diagnostics) == [CLASSIFICATION_BASIS_MIXED]
    assert _codes(report.to_dict()["diagnostics"]) == [CLASSIFICATION_BASIS_MIXED]
    # The string warnings stay exactly what they were (no duplicate prose).
    assert not any("classification bases" in w for w in report.warnings)


@pytest.mark.parametrize("region_filter", [None, "all"])
def test_unfiltered_consensus_is_silent(memslicer_pair, region_filter):
    cm = build_consensus(list(memslicer_pair), region_filter=region_filter)
    assert cm.alignment_report.diagnostics == ()
    assert cm.alignment_report.to_dict()["diagnostics"] == []


def test_same_basis_filtered_consensus_is_silent(memslicer_pair):
    named, _legacy = memslicer_pair
    cm = build_consensus([named, named], region_filter=HEAP)
    assert cm.size > 0
    assert cm.alignment_report.diagnostics == ()


# -- REST ------------------------------------------------------------------------


@pytest.fixture
def client():
    return TestClient(create_app())


def test_rest_consensus_hoists_the_diagnostic(client, memslicer_pair):
    resp = client.post("/api/analysis/consensus", json={
        "dump_paths": list(memslicer_pair), "region_filter": HEAP})
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert _codes(body["diagnostics"]) == [CLASSIFICATION_BASIS_MIXED]
    assert body["diagnostics"] == body["alignment"]["diagnostics"]
    assert set(body["diagnostics"][0]) == {"code", "message", "severity", "details"}


def test_rest_consensus_unfiltered_has_empty_diagnostics(client, memslicer_pair):
    resp = client.post("/api/analysis/consensus",
                       json={"dump_paths": list(memslicer_pair)})
    assert resp.status_code == 200, resp.text
    assert resp.json()["diagnostics"] == []


def test_rest_aligned_window_alignment_carries_it(client, memslicer_pair):
    resp = client.post("/api/analysis/consensus/aligned-window", json={
        "dump_paths": list(memslicer_pair), "region_filter": HEAP,
        "anchor": "slab", "slab_offset": 0, "length": 16})
    assert resp.status_code == 200, resp.text
    assert _codes(resp.json()["alignment"]["diagnostics"]) == [
        CLASSIFICATION_BASIS_MIXED]


# -- CLI -------------------------------------------------------------------------


def _run_cli(monkeypatch, argv):
    from memdiver.cli.main import main

    monkeypatch.setattr(sys, "argv", ["memdiver", *argv])
    with pytest.raises(SystemExit) as exc_info:
        main()
    return exc_info.value.code


def test_cli_consensus_json_and_stderr(monkeypatch, capsys, tmp_path,
                                       memslicer_pair):
    out = tmp_path / "out.json"
    code = _run_cli(monkeypatch, ["consensus", *memslicer_pair,
                                  "--regions", HEAP, "-o", str(out)])
    assert code == 0
    body = json.loads(out.read_text())
    assert _codes(body["diagnostics"]) == [CLASSIFICATION_BASIS_MIXED]
    err = capsys.readouterr().err
    assert f"warning [{CLASSIFICATION_BASIS_MIXED}]" in err
    assert "hint: re-import" in err


def test_cli_consensus_unfiltered_is_quiet(monkeypatch, capsys, tmp_path,
                                           memslicer_pair):
    out = tmp_path / "out.json"
    assert _run_cli(monkeypatch, ["consensus", *memslicer_pair,
                                  "-o", str(out)]) == 0
    assert json.loads(out.read_text())["diagnostics"] == []
    assert CLASSIFICATION_BASIS_MIXED not in capsys.readouterr().err


def test_cli_consensus_window_warns(monkeypatch, capsys, tmp_path, memslicer_pair):
    out = tmp_path / "w.json"
    code = _run_cli(monkeypatch, ["consensus-window", *memslicer_pair,
                                  "--regions", HEAP, "--slab-offset", "0",
                                  "--length", "16", "-o", str(out)])
    assert code == 0
    body = json.loads(out.read_text())
    assert _codes(body["alignment"]["diagnostics"]) == [CLASSIFICATION_BASIS_MIXED]
    assert f"warning [{CLASSIFICATION_BASIS_MIXED}]" in capsys.readouterr().err


# -- producers behind the MCP tools ------------------------------------------------


def test_pipeline_consensus_producer_payload(tmp_path, memslicer_pair):
    """``tools_pipeline.consensus`` is what the MCP ``consensus`` tool dumps."""
    meta = pipeline_consensus(dump_paths=list(memslicer_pair),
                              output_dir=str(tmp_path / "c"), region_filter=HEAP)
    assert _codes(meta["diagnostics"]) == [CLASSIFICATION_BASIS_MIXED]
    stored = json.loads((tmp_path / "c" / "consensus.json").read_text())
    assert stored["diagnostics"] == meta["diagnostics"]


def test_pipeline_incremental_consensus_payload(tmp_path, memslicer_pair):
    meta = pipeline_consensus(dump_paths=list(memslicer_pair),
                              output_dir=str(tmp_path / "i"), region_filter=HEAP,
                              persist_welford=True)
    assert _codes(meta["diagnostics"]) == [CLASSIFICATION_BASIS_MIXED]


def test_analyze_candidates_lists_it_first(memslicer_pair):
    from memdiver.app.tools_pipeline import analyze_candidates

    payload = analyze_candidates(dump_paths=list(memslicer_pair),
                                 region_filter=HEAP)
    assert payload["diagnostics"][0]["code"] == CLASSIFICATION_BASIS_MIXED


def test_aligned_window_result_status_block(memslicer_pair):
    from memdiver.app.composition import build_tool_session
    from memdiver.app.tools_consensus import aligned_window_result

    result = aligned_window_result(build_tool_session(),
                                   dump_paths=list(memslicer_pair),
                                   slab_offset=0, length=16, region_filter=HEAP)
    assert _codes(result.status.diagnostics) == [CLASSIFICATION_BASIS_MIXED]
    assert _codes(result.payload["alignment"]["diagnostics"]) == [
        CLASSIFICATION_BASIS_MIXED]


@pytest.fixture
def mcp_tools():
    pytest.importorskip("mcp")
    from memdiver.mcp_server.server import create_server
    try:
        server = create_server()
    except ImportError as exc:  # mcp 2.x SDK layout missing in this env
        pytest.skip(f"mcp server unavailable: {exc}")
    return {t.name: t.fn for t in server._tool_manager.list_tools()}


def test_mcp_consensus_and_window_tools(mcp_tools, tmp_path, memslicer_pair):
    meta = json.loads(mcp_tools["consensus"](
        dump_paths=list(memslicer_pair), output_dir=str(tmp_path / "m"),
        region_filter=HEAP))
    assert _codes(meta["diagnostics"]) == [CLASSIFICATION_BASIS_MIXED]
    window = json.loads(mcp_tools["aligned_window"](
        dump_paths=list(memslicer_pair), slab_offset=0, length=16,
        region_filter=HEAP))
    assert _codes(window["alignment"]["diagnostics"]) == [
        CLASSIFICATION_BASIS_MIXED]
    unfiltered = json.loads(mcp_tools["consensus"](
        dump_paths=list(memslicer_pair), output_dir=str(tmp_path / "u"),
        region_filter="all"))
    assert unfiltered["diagnostics"] == []


# -- experiment orchestration ------------------------------------------------------


def test_experiment_consensus_progress_carries_it(tmp_path):
    from memdiver.app.experiment_orchestration import _experiment_consensus_phase

    tool_dir = tmp_path / "tool"
    for run, new_style in (("run_a", True), ("run_b", False)):
        (tool_dir / run).mkdir(parents=True)
        _memslicer_msl(tool_dir / run / "capture.msl", new_style)
    events = []
    _experiment_consensus_phase(
        {"tool": tool_dir}, None, None,
        lambda event, **fields: events.append((event, fields)),
        region_filter=HEAP)
    (extra,) = [f["extra"] for e, f in events
                if e == "progress" and "diagnostics" in f.get("extra", {})]
    assert _codes(extra["diagnostics"]) == [CLASSIFICATION_BASIS_MIXED]
