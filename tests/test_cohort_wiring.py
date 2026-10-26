"""Cohort guard wired into consensus + N-sweep producers and their 4 surfaces.

Dumps from different experiment cohorts (``meta.json`` ``cohort``) must never
share one variance accumulator unless ``mixed_ok`` says so.
"""

from __future__ import annotations

import argparse
import io
import json
from contextlib import redirect_stdout

import numpy as np
import pytest

from memdiver.app.session import ToolSession
from memdiver.core.service_errors import CapabilityError

SIZE = 4096


def _run(parent, name, cohort, seed):
    run = parent / name
    run.mkdir(parents=True)
    rng = np.random.default_rng(seed)
    (run / "d.bin").write_bytes(rng.integers(0, 256, SIZE, dtype=np.uint8).tobytes())
    if cohort is not None:
        (run / "meta.json").write_text(json.dumps({"cohort": cohort}))
    return str(run / "d.bin")


@pytest.fixture()
def mixed(tmp_path):
    """Four dumps: two cohort 'a', two cohort 'b'."""
    return [_run(tmp_path, f"r{i}", c, i)
            for i, c in enumerate(["a", "a", "b", "b"])]


@pytest.fixture()
def same(tmp_path):
    return [_run(tmp_path, f"s{i}", "a", 10 + i) for i in range(3)]


@pytest.fixture()
def bare(tmp_path):
    return [_run(tmp_path, f"n{i}", None, 20 + i) for i in range(3)]


def _window(paths, **kw):
    from memdiver.app.tools_consensus import aligned_window_result
    return aligned_window_result(
        ToolSession(), dump_paths=paths, length=16, normalize=False, **kw)


def _regions(paths, **kw):
    from memdiver.app.tools_consensus import class_regions_result
    return class_regions_result(ToolSession(), dump_paths=paths, **kw)


def _anchor(paths, **kw):
    from memdiver.app.tools_consensus import anchor_consensus_result
    anchors = [{"dump_path": p, "offset": 100} for p in paths]
    return anchor_consensus_result(
        ToolSession(), dump_paths=paths, anchors=anchors, delta_start=-8,
        length=16, **kw)


def _refused(fn, paths):
    with pytest.raises(CapabilityError) as ei:
        fn(paths)
    assert ei.value.code == "cohort.mixed"


@pytest.mark.parametrize("fn", [_window, _regions, _anchor])
def test_producers_refuse_mixed(fn, mixed):
    _refused(fn, mixed)


@pytest.mark.parametrize("fn", [_window, _regions, _anchor])
def test_producers_mixed_ok_and_echo(fn, mixed, same, bare):
    assert fn(mixed, mixed_ok=True).payload["cohort"] is None
    assert fn(same).payload["cohort"] == "a"
    assert fn(bare).payload["cohort"] is None


def test_pipeline_consensus_guard(mixed, same, bare, tmp_path):
    from memdiver.app.tools_pipeline import consensus

    with pytest.raises(CapabilityError) as ei:
        consensus(dump_paths=mixed, output_dir=str(tmp_path / "o1"))
    assert ei.value.code == "cohort.mixed"
    assert consensus(dump_paths=mixed, output_dir=str(tmp_path / "o2"),
                     mixed_ok=True)["cohort"] is None
    assert consensus(dump_paths=same, output_dir=str(tmp_path / "o3"))["cohort"] == "a"
    assert consensus(dump_paths=bare, output_dir=str(tmp_path / "o4"))["cohort"] is None


def test_pipeline_consensus_group_by_cohort(mixed, tmp_path):
    from memdiver.app.tools_pipeline import consensus

    out = tmp_path / "grouped"
    result = consensus(dump_paths=mixed, output_dir=str(out), group_by="cohort")
    assert result["group_by"] == "cohort" and result["skipped"] == []
    by = {c["cohort"]: c for c in result["cohorts"]}
    assert set(by) == {"a", "b"}
    assert all(c["num_dumps"] == 2 and c["size"] == SIZE for c in by.values())
    assert (out / "a" / "variance.npy").exists()
    assert (out / "b" / "variance.npy").exists()


def test_group_by_skips_singleton_and_rejects_unknown(mixed, tmp_path):
    from memdiver.app.tools_pipeline import consensus

    extra = _run(tmp_path, "solo", "c", 99)
    result = consensus(dump_paths=mixed + [extra], output_dir=str(tmp_path / "g"),
                       group_by="cohort")
    assert result["skipped"] == [
        {"cohort": "c", "num_dumps": 1, "reason": "fewer than 2 dumps"}]
    with pytest.raises(CapabilityError):
        consensus(dump_paths=mixed, output_dir=str(tmp_path / "h"), group_by="bogus")


def test_n_sweep_guard(mixed, tmp_path):
    from memdiver.app.tools_pipeline import n_sweep

    kw = dict(source_paths=mixed, output_dir=str(tmp_path / "ns"),
              n_values=[1, 2], oracle_path=str(tmp_path / "no_oracle.py"))
    with pytest.raises(CapabilityError) as ei:
        n_sweep(**kw)
    assert ei.value.code == "cohort.mixed"
    # With the override the guard steps aside; any later failure is not ours.
    try:
        n_sweep(**kw, mixed_ok=True)
    except Exception as exc:  # noqa: BLE001
        assert getattr(exc, "code", None) != "cohort.mixed"


# ---------------------------------------------------------------- surfaces

def _post(client, route, body):
    return client.post(f"/api/analysis{route}", json=body)


def test_web_surface(mixed):
    from fastapi.testclient import TestClient
    from memdiver.api.main import create_app

    client = TestClient(create_app())
    for route, body in (
        ("/consensus", {"dump_paths": mixed}),
        ("/consensus/aligned-window", {"dump_paths": mixed, "length": 16,
                                      "anchor_path": mixed[0], "view": "raw"}),
        ("/consensus/regions", {"dump_paths": mixed}),
        ("/consensus/anchor", {"dump_paths": mixed,
                               "anchors": [{"dump_path": p, "offset": 100} for p in mixed],
                               "delta_start": -8, "length": 16}),
    ):
        bad = _post(client, route, body)
        assert bad.status_code == 400, (route, bad.text)
        assert "cohort.mixed" in bad.text, route
        ok = _post(client, route, {**body, "mixed_ok": True})
        assert ok.status_code == 200, (route, ok.text)
        assert ok.json()["cohort"] is None


def test_mcp_surface(mixed, tmp_path):
    pytest.importorskip("mcp")
    from memdiver.mcp_server.server import create_server

    tools = {t.name: t for t in create_server()._tool_manager.list_tools()}
    refused = tools["aligned_window"].fn(dump_paths=mixed, length=16)
    assert "cohort.mixed" in refused
    out = json.loads(tools["aligned_window"].fn(
        dump_paths=mixed, length=16, mixed_ok=True))
    assert out["cohort"] is None
    grouped = json.loads(tools["consensus"].fn(
        dump_paths=mixed, output_dir=str(tmp_path / "m"), group_by="cohort"))
    assert {c["cohort"] for c in grouped["cohorts"]} == {"a", "b"}
    for name in ("consensus", "consensus_regions", "anchor_consensus", "n_sweep"):
        assert "mixed_ok" in tools[name].parameters["properties"], name


def test_cli_surface(mixed, tmp_path):
    from memdiver.cli.consensus import _cmd_consensus_window
    from memdiver.cli.main import build_parser

    parser = build_parser()
    argv = ["consensus-window", *mixed, "--length", "16"]
    with pytest.raises(CapabilityError) as ei, redirect_stdout(io.StringIO()):
        _cmd_consensus_window(parser.parse_args(argv))
    assert ei.value.code == "cohort.mixed"
    out_file = tmp_path / "o.json"
    args = parser.parse_args([*argv, "--mixed-ok", "-o", str(out_file)])
    assert isinstance(args, argparse.Namespace) and args.mixed_ok is True
    with redirect_stdout(io.StringIO()):
        assert _cmd_consensus_window(args) == 0
    assert json.loads(out_file.read_text())["cohort"] is None
    for cmd in ("consensus", "consensus-regions", "consensus-anchor", "n-sweep"):
        help_text = io.StringIO()
        sub = next(a for a in parser._actions
                   if isinstance(a, argparse._SubParsersAction)).choices[cmd]
        sub.print_help(help_text)
        assert "--mixed-ok" in help_text.getvalue(), cmd
