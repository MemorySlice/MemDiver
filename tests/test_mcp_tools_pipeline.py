"""Tests for mcp_server.tools_pipeline — pipeline-stage MCP wrappers.

Exercises each tool as a pure function (no MCP server / FastMCP
dependency). The wrappers are thin: search_reduce → candidates.json,
brute_force → hits.json, n_sweep → report.{json,md,html}, emit_plugin
→ plugin.py. Failure at any layer surfaces through the engine call,
so these tests mainly assert the file I/O + dict-return contract.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import List

import numpy as np
import pytest

from mcp_server import tools_pipeline


KEY_BYTES = bytes(range(32))
KEY_OFFSET = 256
DUMP_SIZE = 1024


@pytest.fixture
def oracle_path(tmp_path: Path) -> Path:
    body = (
        "KEY = bytes(range(32))\n"
        "def verify(candidate):\n"
        "    return candidate == KEY\n"
    )
    p = tmp_path / "oracle.py"
    p.write_text(body)
    os.chmod(p, 0o600)
    return p


@pytest.fixture
def consensus_artifacts(tmp_path: Path) -> dict:
    """Build a fake variance.npy + reference.bin pair.

    Variance is 0 everywhere except the 32 bytes at KEY_OFFSET where
    we slam a large value so the reduce filter chain keeps them.
    Reference bytes are the sentinel at KEY_OFFSET, padding elsewhere.
    """
    variance = np.zeros(DUMP_SIZE, dtype=np.float32)
    variance[KEY_OFFSET:KEY_OFFSET + 32] = 20000.0
    rng = np.random.default_rng(7)
    ref = bytearray(rng.integers(0, 256, DUMP_SIZE, dtype=np.uint8).tobytes())
    ref[KEY_OFFSET:KEY_OFFSET + 32] = KEY_BYTES
    variance_path = tmp_path / "variance.npy"
    ref_path = tmp_path / "reference.bin"
    np.save(variance_path, variance)
    ref_path.write_bytes(bytes(ref))
    return {"variance": variance_path, "reference": ref_path}


def _make_raw_dump(tmp_path: Path, index: int, carry_sentinel: bool) -> Path:
    padding_rng = np.random.default_rng(42)
    buf = bytearray(padding_rng.integers(0, 256, DUMP_SIZE, dtype=np.uint8).tobytes())
    for start in (64, 512, 768):
        rng = np.random.default_rng(1000 + index * 17 + start)
        buf[start:start + 32] = rng.integers(0, 256, 32, dtype=np.uint8).tobytes()
    if carry_sentinel:
        buf[KEY_OFFSET:KEY_OFFSET + 32] = KEY_BYTES
    else:
        other = np.random.default_rng(9000 + index).integers(0, 256, 32, dtype=np.uint8).tobytes()
        buf[KEY_OFFSET:KEY_OFFSET + 32] = other
    p = tmp_path / f"dump_{index}.bin"
    p.write_bytes(bytes(buf))
    return p


@pytest.fixture
def source_paths(tmp_path: Path) -> List[str]:
    paths = [_make_raw_dump(tmp_path, 0, carry_sentinel=True)]
    for i in range(1, 4):
        paths.append(_make_raw_dump(tmp_path, i, carry_sentinel=False))
    return [str(p) for p in paths]


# ----------------------------------------------------------------------
# search_reduce
# ----------------------------------------------------------------------


def test_search_reduce_writes_candidates_json(tmp_path, consensus_artifacts):
    out = tmp_path / "out"
    result = tools_pipeline.search_reduce(
        variance_path=str(consensus_artifacts["variance"]),
        reference_path=str(consensus_artifacts["reference"]),
        num_dumps=4,
        output_dir=str(out),
        min_variance=100.0,
        entropy_window=16,
        entropy_threshold=3.5,
        min_region=8,
        alignment=8,
        block_size=16,
    )
    cand_path = Path(result["candidates_path"])
    assert cand_path.is_file()
    assert result["num_regions"] >= 1
    payload = json.loads(cand_path.read_text())
    assert "regions" in payload and payload["regions"]


# ----------------------------------------------------------------------
# brute_force
# ----------------------------------------------------------------------


def test_brute_force_writes_hits_json(tmp_path, consensus_artifacts, oracle_path):
    out = tmp_path / "out"
    # First run search_reduce to get a candidates file.
    reduction = tools_pipeline.search_reduce(
        variance_path=str(consensus_artifacts["variance"]),
        reference_path=str(consensus_artifacts["reference"]),
        num_dumps=4,
        output_dir=str(out),
        min_variance=100.0,
        entropy_window=16,
        entropy_threshold=3.5,
        min_region=8,
        alignment=8,
        block_size=16,
    )
    result = tools_pipeline.brute_force(
        candidates_path=reduction["candidates_path"],
        reference_path=str(consensus_artifacts["reference"]),
        oracle_path=str(oracle_path),
        output_dir=str(out),
        key_sizes=(32,),
        stride=8,
        jobs=1,
        exhaustive=True,
    )
    assert result["verified_count"] >= 1
    hits_path = Path(result["hits_path"])
    assert hits_path.is_file()
    payload = json.loads(hits_path.read_text())
    assert any(h["offset"] == KEY_OFFSET for h in payload["hits"])


# ----------------------------------------------------------------------
# n_sweep
# ----------------------------------------------------------------------


def test_n_sweep_emits_three_reports(tmp_path, source_paths, oracle_path):
    out = tmp_path / "nsweep"
    result = tools_pipeline.n_sweep(
        source_paths=source_paths,
        oracle_path=str(oracle_path),
        output_dir=str(out),
        n_values=[3, 4],
        reduce_kwargs={
            "min_variance": 100.0,
            "entropy_window": 16,
            "entropy_threshold": 3.5,
            "min_region": 8,
            "alignment": 8,
            "block_size": 16,
        },
        key_sizes=(32,),
        stride=8,
    )
    assert Path(result["report_json"]).is_file()
    assert Path(result["report_md"]).is_file()
    assert Path(result["report_html"]).is_file()
    assert result["total_dumps"] == 4


# ----------------------------------------------------------------------
# emit_plugin
# ----------------------------------------------------------------------


def test_emit_plugin_writes_valid_python(tmp_path):
    # Build a synthetic hits.json manually with neighborhood variance so
    # vol3_emit has the static-mask signal it needs.
    reference = bytearray(b"A" * 256)
    reference[100:132] = bytes(range(32))
    variance = [0.0] * 160
    for i in range(32):
        variance[64 + i] = 10000.0
    hit = {
        "offset": 100,
        "length": 32,
        "key_hex": bytes(range(32)).hex(),
        "region_index": 0,
        "neighborhood_start": 36,
        "neighborhood_variance": variance,
    }
    hits_path = tmp_path / "hits.json"
    hits_path.write_text(json.dumps({"hits": [hit]}))
    reference_path = tmp_path / "reference.bin"
    reference_path.write_bytes(bytes(reference))

    out = tmp_path / "plugin_out"
    result = tools_pipeline.emit_plugin(
        hits_path=str(hits_path),
        reference_path=str(reference_path),
        name="mcp_test_plugin",
        output_dir=str(out),
    )
    plugin_path = Path(result["plugin_path"])
    assert plugin_path.is_file()
    source = plugin_path.read_text()
    compile(source, str(plugin_path), "exec")
    assert "mcp_test_plugin" in source
