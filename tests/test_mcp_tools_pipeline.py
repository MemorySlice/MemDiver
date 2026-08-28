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

from memdiver.core.service_errors import (
    CapabilityError,
    ErrorCategory,
    FileNotFoundServiceError,
)
from memdiver.mcp_server import tools_pipeline


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
    # Advisory recommended floor is surfaced (return dict + persisted artifact).
    assert "recommended_floor" in result and result["recommended_floor"] >= 0.0
    assert payload["recommended_floor"] == result["recommended_floor"]


# ----------------------------------------------------------------------
# search_reduce — inline ranked regions (A3)
# ----------------------------------------------------------------------


@pytest.fixture
def multi_region_artifacts(tmp_path: Path) -> dict:
    """A variance/reference pair with FOUR surviving regions of unequal rank.

    Mirrors ``tests/test_candidate_pipeline._four_region_dump`` so the offsets
    and the order they rank in are hand-derivable here too: a 512-byte
    KEY_CANDIDATE blob at 128, a 32-byte POINTER run at 768, and two identical
    16-byte KEY_CANDIDATE runs at 1024 and 1280 which rank first and second.
    """
    size = 2048
    variance = np.zeros(size, dtype=np.float32)
    ref = bytearray(size)
    ref[128:640] = bytes(range(256)) * 2
    variance[128:640] = 15000.0
    ref[768:800] = bytes(range(200, 232))
    variance[768:800] = 1000.0
    ref[1024:1040] = bytes(range(16))
    variance[1024:1040] = 15000.0
    ref[1280:1296] = bytes(range(16))
    variance[1280:1296] = 15000.0
    variance_path = tmp_path / "multi_variance.npy"
    ref_path = tmp_path / "multi_reference.bin"
    np.save(variance_path, variance)
    ref_path.write_bytes(bytes(ref))
    return {"variance": variance_path, "reference": ref_path}


def _reduce_multi(artifacts: dict, out: Path, **overrides) -> dict:
    kwargs = dict(
        variance_path=str(artifacts["variance"]),
        reference_path=str(artifacts["reference"]),
        num_dumps=5,
        output_dir=str(out),
        min_variance=100.0,
        entropy_window=16,
        entropy_threshold=3.5,
        min_region=8,
        alignment=8,
        block_size=16,
    )
    kwargs.update(overrides)
    return tools_pipeline.search_reduce(**kwargs)


def test_search_reduce_returns_the_regions_inline(tmp_path, multi_region_artifacts):
    """The whole point of A3: an MCP client cannot read ``candidates_path``
    back, so the regions have to travel in the result."""
    result = _reduce_multi(multi_region_artifacts, tmp_path / "out")
    assert [r["offset"] for r in result["regions"]] == [128, 768, 1024, 1280]
    assert result["regions_returned"] == result["num_regions"] == 4
    assert result["regions_truncated"] is False
    assert result["order"] == "offset"
    # Identical to what was persisted — one list, two ways to reach it.
    persisted = json.loads(Path(result["candidates_path"]).read_text())
    assert persisted["regions"] == result["regions"]


def test_search_reduce_inline_rows_carry_the_score_breakdown(
    tmp_path, multi_region_artifacts
):
    result = _reduce_multi(multi_region_artifacts, tmp_path / "out")
    weights = json.loads(
        Path(result["candidates_path"]).read_text()
    )["thresholds"]["score_weights"]
    for row in result["regions"]:
        assert row["rank"] >= 1
        assert set(row["score_components"]) == set(weights)
        recomputed = sum(weights[k] * v for k, v in row["score_components"].items())
        assert row["score"] == pytest.approx(recomputed, abs=1e-12)
        assert sum(row["class_counts"].values()) == row["length"]


def test_search_reduce_order_rank_returns_best_first(tmp_path, multi_region_artifacts):
    result = _reduce_multi(multi_region_artifacts, tmp_path / "out", order="rank")
    assert [r["offset"] for r in result["regions"]] == [1024, 1280, 128, 768]
    assert [r["rank"] for r in result["regions"]] == [1, 2, 3, 4]
    assert result["order"] == "rank"


def test_search_reduce_truncation_is_flagged_and_keeps_the_best_ranked(
    tmp_path, multi_region_artifacts
):
    """A cap must never read as 'that is all there is', and must never drop the
    top candidate just because it sits at a high offset."""
    result = _reduce_multi(multi_region_artifacts, tmp_path / "out", max_returned=2)
    assert result["regions_truncated"] is True
    assert result["regions_returned"] == 2
    assert result["num_regions"] == 4          # the TRUE total is still reported
    assert result["max_returned"] == 2
    # Ranks 1 and 2 live at the two HIGHEST offsets; a blind head of the
    # offset-ordered list would have returned 128 and 768 instead.
    assert [r["offset"] for r in result["regions"]] == [1024, 1280]
    assert [r["rank"] for r in result["regions"]] == [1, 2]
    # Nothing is lost from the artifact.
    persisted = json.loads(Path(result["candidates_path"]).read_text())
    assert len(persisted["regions"]) == 4


def test_search_reduce_max_returned_zero_is_uncapped(tmp_path, multi_region_artifacts):
    result = _reduce_multi(multi_region_artifacts, tmp_path / "out", max_returned=0)
    assert result["regions_returned"] == 4
    assert result["regions_truncated"] is False


def test_search_reduce_keeps_every_pre_existing_payload_key(
    tmp_path, multi_region_artifacts
):
    """A3 is additive: the four keys other code already consumes keep their
    exact meaning."""
    result = _reduce_multi(multi_region_artifacts, tmp_path / "out")
    assert set(result) >= {
        "candidates_path", "num_regions", "stages",
        "fallback_entropy_only", "recommended_floor",
    }
    assert Path(result["candidates_path"]).is_file()
    assert result["num_regions"] == 4
    assert result["fallback_entropy_only"] is False
    assert result["recommended_floor"] >= 0.0
    assert set(result["stages"]) == {
        "total_bytes", "variance", "byte_class", "aligned", "high_entropy",
    }


def test_search_reduce_threads_the_class_and_max_region_filters(
    tmp_path, multi_region_artifacts
):
    """``classes`` reaches the engine as names, and composes with min_variance
    exactly as the engine documents."""
    keys_only = _reduce_multi(
        multi_region_artifacts, tmp_path / "k", classes=["key_candidate"],
    )
    assert [r["offset"] for r in keys_only["regions"]] == [128, 1024, 1280]

    short_only = _reduce_multi(
        multi_region_artifacts, tmp_path / "s", max_region=32,
    )
    assert [r["offset"] for r in short_only["regions"]] == [768, 1024, 1280]


def test_search_reduce_rejects_an_unknown_class_name(tmp_path, multi_region_artifacts):
    with pytest.raises(ValueError, match="unknown byte class"):
        _reduce_multi(multi_region_artifacts, tmp_path / "x", classes=["pointerz"])


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


# ----------------------------------------------------------------------
# error funnel: stages raise a structured CapabilityError, not an
# ``{"error": ...}`` magic dict (Phase 5a). The MCP tool bodies are
# wrapped by ``mcp_error_funnel``, which renders the raised error as the
# structured ``{"error", "code", "category"}`` JSON payload.
# ----------------------------------------------------------------------


def test_search_reduce_missing_variance_raises(tmp_path):
    with pytest.raises(FileNotFoundServiceError) as excinfo:
        tools_pipeline.search_reduce(
            variance_path=str(tmp_path / "nope.npy"),
            reference_path=str(tmp_path / "nope.bin"),
            num_dumps=4,
            output_dir=str(tmp_path / "out"),
        )
    assert excinfo.value.category is ErrorCategory.NOT_FOUND
    assert excinfo.value.message.startswith("File not found:")


def test_brute_force_missing_reference_raises(tmp_path):
    with pytest.raises(FileNotFoundServiceError) as excinfo:
        tools_pipeline.brute_force(
            candidates_path=str(tmp_path / "nope.json"),
            reference_path=str(tmp_path / "nope.bin"),
            oracle_path=str(tmp_path / "nope.py"),
            output_dir=str(tmp_path / "out"),
        )
    assert excinfo.value.category is ErrorCategory.NOT_FOUND


def test_emit_plugin_missing_reference_raises(tmp_path):
    with pytest.raises(FileNotFoundServiceError) as excinfo:
        tools_pipeline.emit_plugin(
            hits_path=str(tmp_path / "nope.json"),
            reference_path=str(tmp_path / "nope.bin"),
            name="x",
            output_dir=str(tmp_path / "out"),
        )
    assert excinfo.value.category is ErrorCategory.NOT_FOUND


def test_mcp_error_funnel_renders_structured_payload(tmp_path):
    """The funnel that wraps the MCP pipeline tools renders a raised
    CapabilityError as the ``{"error", "code", "category"}`` JSON shape."""
    from memdiver.mcp_server.presenters import mcp_error_funnel

    @mcp_error_funnel
    def tool() -> str:
        return json.dumps(
            tools_pipeline.search_reduce(
                variance_path=str(tmp_path / "nope.npy"),
                reference_path=str(tmp_path / "nope.bin"),
                num_dumps=4,
                output_dir=str(tmp_path / "out"),
            )
        )

    payload = json.loads(tool())
    assert set(payload) == {"error", "code", "category"}
    assert payload["error"].startswith("File not found:")
    assert payload["category"] == "NOT_FOUND"


def test_capability_error_is_used_for_invalid_input(tmp_path):
    """A corrupt (non-npy) variance file surfaces as an INVALID_INPUT
    CapabilityError rather than a magic error dict."""
    bad = tmp_path / "bad.npy"
    bad.write_bytes(b"not a numpy array")
    with pytest.raises(CapabilityError) as excinfo:
        tools_pipeline.search_reduce(
            variance_path=str(bad),
            reference_path=str(bad),
            num_dumps=4,
            output_dir=str(tmp_path / "out"),
        )
    assert excinfo.value.category is ErrorCategory.INVALID_INPUT
    assert excinfo.value.message.startswith("Invalid input:")


def test_export_pattern_propagates_original_analysis_service_category(tmp_path):
    """``export_pattern`` must let ``AnalysisServiceError`` (already a
    ``CapabilityError`` subclass) propagate with its own accurate category
    instead of catching it and re-raising a blanket ``INVALID_INPUT``.

    ``fmt="xml"`` trips ``UnknownFormatError`` (category ``UNSUPPORTED``,
    status 400) deep inside ``auto_export_pattern`` — before this fix a
    surrounding ``except AnalysisServiceError`` in ``tools_pipeline.py``
    discarded that category and always reported ``INVALID_INPUT``.
    """
    dumps = []
    for i in range(2):
        p = tmp_path / f"dump_{i}.bin"
        p.write_bytes(os.urandom(256))
        dumps.append(str(p))

    with pytest.raises(CapabilityError) as excinfo:
        tools_pipeline.export_pattern(
            dump_paths=dumps, fmt="xml", name="x",
        )
    assert excinfo.value.category is ErrorCategory.UNSUPPORTED
    assert excinfo.value.status == 400
    assert "Unknown format" in excinfo.value.message
