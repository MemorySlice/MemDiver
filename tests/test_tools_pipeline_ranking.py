"""Surface reach of the A3 ranked candidate list.

``tests/test_mcp_tools_pipeline.py`` covers the ``app.tools_pipeline``
producer itself; this module proves the two headless SURFACES actually carry
the new parameters and the inline regions through — the MCP tool (which before
A3 handed an agent a file path it had no tool to read back) and the
``search-reduce`` CLI handler.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path

import numpy as np
import pytest


def _four_region_dumps(tmp_path: Path, count: int = 5) -> list[Path]:
    """``count`` raw dumps whose cross-dump variance plants four regions.

    Same layout as ``tests/test_candidate_pipeline._four_region_dump``: a
    512-byte high-variance blob at 128, a mid-variance 32-byte run at 768, and
    two identical 16-byte high-variance runs at 1024 and 1280.
    """
    size = 2048
    paths: list[Path] = []
    for index in range(count):
        rng = np.random.default_rng(100 + index)
        buf = np.zeros(size, dtype=np.uint8)
        buf[128:640] = np.frombuffer(bytes(range(256)) * 2, dtype=np.uint8)
        buf[768:800] = np.frombuffer(bytes(range(200, 232)), dtype=np.uint8)
        buf[1024:1040] = np.frombuffer(bytes(range(16)), dtype=np.uint8)
        buf[1280:1296] = np.frombuffer(bytes(range(16)), dtype=np.uint8)
        # Perturb the planted runs per dump so they carry real variance. The
        # 768 run gets a narrower spread, which is what puts it in the POINTER
        # band while the other three land in KEY_CANDIDATE.
        for start, end, spread in ((128, 640, 255), (768, 800, 60),
                                   (1024, 1040, 255), (1280, 1296, 255)):
            noise = rng.integers(0, spread + 1, end - start, dtype=np.uint16)
            shifted = (buf[start:end].astype(np.uint16) + noise) % 256
            buf[start:end] = shifted.astype(np.uint8)
        path = tmp_path / f"dump_{index}.bin"
        path.write_bytes(buf.tobytes())
        paths.append(path)
    return paths


@pytest.fixture
def consensus_state(tmp_path: Path) -> dict:
    """A finalized Welford session over ``_four_region_dumps`` + its reference."""
    from memdiver.cli import _cmd_consensus_add, _cmd_consensus_begin

    dumps = _four_region_dumps(tmp_path)
    state_path = tmp_path / "session.json"
    assert _cmd_consensus_begin(
        argparse.Namespace(state=str(state_path), size=2048)) == 0
    for dump in dumps:
        assert _cmd_consensus_add(argparse.Namespace(
            state=str(state_path), dump=str(dump),
            key_file=None, passphrase=None, kem_key_file=None)) == 0
    return {"state": state_path, "reference": dumps[0]}


def _cli_namespace(consensus_state: dict, out_path: Path, **overrides):
    args = dict(
        state=str(consensus_state["state"]),
        reference_dump=str(consensus_state["reference"]),
        alignment=8, block_size=16, density_threshold=0.5,
        min_variance=100.0, entropy_window=16, entropy_threshold=3.5,
        min_region=8, output=str(out_path),
        key_file=None, passphrase=None, kem_key_file=None,
    )
    args.update(overrides)
    return argparse.Namespace(**args)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def test_cli_search_reduce_emits_ranked_rows(tmp_path, consensus_state):
    from memdiver.cli import _cmd_search_reduce

    out = tmp_path / "candidates.json"
    assert _cmd_search_reduce(_cli_namespace(consensus_state, out)) == 0
    payload = json.loads(out.read_text())
    assert payload["regions"]
    ranks = sorted(r["rank"] for r in payload["regions"])
    assert ranks == list(range(1, len(payload["regions"]) + 1))
    weights = payload["thresholds"]["score_weights"]
    for row in payload["regions"]:
        recomputed = sum(weights[k] * v for k, v in row["score_components"].items())
        assert row["score"] == pytest.approx(recomputed, abs=1e-12)


def test_cli_search_reduce_relays_the_full_payload_to_output(tmp_path, consensus_state):
    """``--output`` keeps relaying ``candidates.json`` verbatim — the inline cap
    bounds the RETURN dict, never the file the CLI writes."""
    from memdiver.cli import _cmd_search_reduce

    out = tmp_path / "candidates.json"
    assert _cmd_search_reduce(_cli_namespace(consensus_state, out)) == 0
    payload = json.loads(out.read_text())
    assert set(payload) >= {"N", "stages", "thresholds", "regions",
                            "fallback_entropy_only", "recommended_floor"}
    # Ranks are handed out over the COMPLETE region set, so a contiguous
    # 1..n in the relayed file is proof that nothing was dropped from it.
    assert sorted(r["rank"] for r in payload["regions"]) == list(
        range(1, len(payload["regions"]) + 1))
    assert payload["N"] == 5


def test_cli_search_reduce_threads_classes_order_and_max_region(
    tmp_path, consensus_state
):
    from memdiver.cli import _cmd_search_reduce

    out = tmp_path / "candidates.json"
    assert _cmd_search_reduce(_cli_namespace(
        consensus_state, out, classes="pointer,key_candidate",
        order="rank", max_region=64)) == 0
    payload = json.loads(out.read_text())
    assert payload["thresholds"]["classes"] == ["pointer", "key_candidate"]
    assert payload["thresholds"]["order"] == "rank"
    assert payload["thresholds"]["max_region"] == 64
    assert [r["rank"] for r in payload["regions"]] == list(
        range(1, len(payload["regions"]) + 1))
    assert all(r["length"] <= 64 for r in payload["regions"])


def test_cli_search_reduce_accepts_a_namespace_without_the_new_flags(
    tmp_path, consensus_state
):
    """The handler is also driven by hand-built namespaces; an absent flag must
    behave as the pre-A3 default, not raise."""
    from memdiver.cli import _cmd_search_reduce

    out = tmp_path / "candidates.json"
    args = _cli_namespace(consensus_state, out)
    for absent in ("classes", "order", "max_region"):
        assert not hasattr(args, absent)
    assert _cmd_search_reduce(args) == 0
    payload = json.loads(out.read_text())
    assert payload["thresholds"]["order"] == "offset"
    assert payload["thresholds"]["classes"] is None
    assert payload["thresholds"]["max_region"] == 0


def test_cli_parser_exposes_the_new_search_reduce_flags():
    from memdiver.cli.main import build_parser

    parsed = build_parser().parse_args([
        "search-reduce", "--state", "s.json", "--reference-dump", "d.bin",
        "-o", "out.json", "--classes", "pointer,key_candidate",
        "--order", "rank", "--max-region", "64",
    ])
    assert parsed.classes == "pointer,key_candidate"
    assert parsed.order == "rank"
    assert parsed.max_region == 64


# ---------------------------------------------------------------------------
# MCP
# ---------------------------------------------------------------------------


def _mcp_search_reduce():
    pytest.importorskip("mcp")
    from memdiver.mcp_server.server import create_server

    tools = {t.name: t for t in create_server()._tool_manager.list_tools()}
    assert "search_reduce" in tools
    return tools["search_reduce"].fn


def test_mcp_search_reduce_exposes_the_new_parameters():
    import inspect

    params = inspect.signature(_mcp_search_reduce()).parameters
    assert {"classes", "max_region", "order", "max_returned"} <= set(params)
    assert params["order"].default == "offset"
    assert params["max_region"].default == 0


def test_mcp_search_reduce_returns_regions_not_just_a_path(tmp_path):
    """Before A3 the tool returned ``candidates_path`` and a count, and no MCP
    tool in this server could open that file — the stage was unreachable."""
    tool = _mcp_search_reduce()
    dumps = _four_region_dumps(tmp_path)
    buffers = [p.read_bytes() for p in dumps]

    from memdiver.core.variance import compute_variance

    variance_path = tmp_path / "variance.npy"
    np.save(variance_path, compute_variance(buffers, 2048))

    payload = json.loads(tool(
        variance_path=str(variance_path),
        reference_path=str(dumps[0]),
        num_dumps=len(dumps),
        output_dir=str(tmp_path / "out"),
        min_variance=100.0, entropy_window=16, entropy_threshold=3.5,
        min_region=8, alignment=8, block_size=16, order="rank",
    ))
    assert payload["regions"], "MCP search_reduce returned no inline regions"
    assert [r["rank"] for r in payload["regions"]] == list(
        range(1, len(payload["regions"]) + 1))
    assert payload["regions_truncated"] is False
    assert payload["regions_returned"] == payload["num_regions"]
    assert Path(payload["candidates_path"]).is_file()


def test_mcp_search_reduce_reports_truncation(tmp_path):
    tool = _mcp_search_reduce()
    dumps = _four_region_dumps(tmp_path)

    from memdiver.core.variance import compute_variance

    variance_path = tmp_path / "variance.npy"
    np.save(variance_path, compute_variance([p.read_bytes() for p in dumps], 2048))

    payload = json.loads(tool(
        variance_path=str(variance_path),
        reference_path=str(dumps[0]),
        num_dumps=len(dumps),
        output_dir=str(tmp_path / "out"),
        min_variance=100.0, entropy_window=16, entropy_threshold=3.5,
        min_region=8, alignment=8, block_size=16, max_returned=1,
    ))
    assert payload["regions_truncated"] is True
    assert payload["regions_returned"] == 1
    assert payload["num_regions"] > 1
    assert payload["regions"][0]["rank"] == 1
