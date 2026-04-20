"""Tests for engine.pipeline_runner.run_pipeline.

Exercises the full Phase 25 chain (consensus → reduce → brute-force →
optional nsweep → optional emit-plugin) end-to-end inside a fake
``WorkerContext`` that captures the progress events the TaskManager
would publish. No ProcessPool here — we call ``run_pipeline`` directly
so failures are trivial to debug.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List

import numpy as np
import pytest

from engine.pipeline_runner import run_pipeline


# ------------------------------------------------------------------
# fake WorkerContext
# ------------------------------------------------------------------


@dataclass
class _FakeCtx:
    task_id: str = "test"
    cancel: bool = False
    events: List[Dict[str, Any]] = field(default_factory=list)

    def emit(self, event_type: str, **fields: Any) -> None:
        self.events.append({"type": event_type, **fields})

    def is_cancelled(self) -> bool:
        return self.cancel


# ------------------------------------------------------------------
# fixtures — synthetic dumps + oracle
# ------------------------------------------------------------------


KEY_BYTES = bytes(range(32))
KEY_OFFSET = 256
DUMP_SIZE = 1024


def _make_raw_dump(seed: int, key_bytes: bytes) -> bytes:
    """One dump: low-variance pseudo-stable padding except at KEY_OFFSET.

    The pipeline selects HIGH-variance bytes as key candidates, so the
    fixture builds N dumps that share the same "padding" everywhere
    except the 32 bytes at KEY_OFFSET, which differ per dump. Source
    index 0 writes the oracle-sentinel there; later sources write
    per-seed random bytes, creating the variance signal the pipeline
    relies on.
    """
    # Deterministic padding shared across dumps so variance outside the
    # key window is exactly zero.
    padding_rng = np.random.default_rng(42)
    buf = bytearray(padding_rng.integers(0, 256, DUMP_SIZE, dtype=np.uint8).tobytes())
    # Sprinkle a little structured high-entropy block elsewhere so the
    # entropy filter has something to look at — windows of high entropy
    # help the filter chain even though we only hit at KEY_OFFSET.
    high_rng = np.random.default_rng(seed)
    for start in (64, 512, 768):
        buf[start:start + 32] = bytes(high_rng.integers(0, 256, 32, dtype=np.uint8))
    buf[KEY_OFFSET:KEY_OFFSET + 32] = key_bytes
    return bytes(buf)


@pytest.fixture
def dumps_dir(tmp_path: Path) -> List[str]:
    """Four raw dumps, only the first carrying the oracle sentinel."""
    paths: List[str] = []
    # First dump carries the sentinel; later dumps get distinct keys.
    p0 = tmp_path / "dump_0.bin"
    p0.write_bytes(_make_raw_dump(seed=0, key_bytes=KEY_BYTES))
    paths.append(str(p0))
    for i in range(1, 4):
        p = tmp_path / f"dump_{i}.bin"
        key_rng = np.random.default_rng(1000 + i)
        other = bytes(key_rng.integers(0, 256, 32, dtype=np.uint8))
        p.write_bytes(_make_raw_dump(seed=1000 + i, key_bytes=other))
        paths.append(str(p))
    return paths


@pytest.fixture
def oracle_path(tmp_path: Path) -> Path:
    """A Shape-1 oracle that only accepts the sentinel KEY_BYTES."""
    body = (
        "KEY = bytes(range(32))\n"
        "def verify(candidate):\n"
        "    return candidate == KEY\n"
    )
    path = tmp_path / "oracle.py"
    path.write_text(body)
    os.chmod(path, 0o600)
    return path


@pytest.fixture
def artifact_dir(tmp_path: Path) -> Path:
    d = tmp_path / "artifacts"
    d.mkdir()
    return d


# ------------------------------------------------------------------
# happy path
# ------------------------------------------------------------------


def test_run_pipeline_consensus_reduce_brute_force(
    dumps_dir, oracle_path, artifact_dir
):
    ctx = _FakeCtx()
    params = {
        "artifact_dir": str(artifact_dir),
        "source_paths": dumps_dir,
        "reduce_kwargs": {
            "min_variance": 100.0,
            "entropy_window": 16,
            "entropy_threshold": 3.5,
            "min_region": 8,
            "alignment": 8,
            "block_size": 16,
        },
        "oracle_path": str(oracle_path),
        "brute_force": {
            "key_sizes": [32],
            "stride": 8,
            "jobs": 1,
            "exhaustive": True,
        },
    }
    result = run_pipeline(params, ctx)

    # Artifacts registered for every stage we ran.
    names = {a["name"] for a in result["artifacts"]}
    assert {"consensus_variance", "consensus_reference",
            "candidates", "hits"} <= names

    # On disk.
    assert (artifact_dir / "consensus" / "variance.npy").is_file()
    assert (artifact_dir / "consensus" / "reference.bin").is_file()
    assert (artifact_dir / "search_reduce" / "candidates.json").is_file()
    assert (artifact_dir / "brute_force" / "hits.json").is_file()

    hits_payload = json.loads(
        (artifact_dir / "brute_force" / "hits.json").read_text()
    )
    assert hits_payload["verified_count"] >= 1
    # The sentinel is at KEY_OFFSET in every dump.
    assert any(h["offset"] == KEY_OFFSET for h in hits_payload["hits"])

    # Stage lifecycle events present.
    stage_starts = [e for e in ctx.events if e["type"] == "stage_start"]
    stage_ends = [e for e in ctx.events if e["type"] == "stage_end"]
    assert {s["stage"] for s in stage_starts} >= {"consensus", "search_reduce", "brute_force"}
    assert {s["stage"] for s in stage_ends} >= {"consensus", "search_reduce", "brute_force"}

    # pct values on stage_start / stage_end are well-formed.
    for ev in stage_ends:
        assert ev["pct"] == 1.0


# ------------------------------------------------------------------
# optional stages
# ------------------------------------------------------------------


def test_run_pipeline_with_emit_plugin(
    dumps_dir, oracle_path, artifact_dir
):
    ctx = _FakeCtx()
    params = {
        "artifact_dir": str(artifact_dir),
        "source_paths": dumps_dir,
        "reduce_kwargs": {
            "min_variance": 100.0,
            "entropy_window": 16,
            "entropy_threshold": 3.5,
            "min_region": 8,
            "alignment": 8,
            "block_size": 16,
        },
        "oracle_path": str(oracle_path),
        "brute_force": {"key_sizes": [32], "stride": 8, "jobs": 1,
                        "exhaustive": True},
    }
    params["emit"] = {"name": "test_plugin", "hit_index": 0}
    result = run_pipeline(params, ctx)
    # Pipeline now saves Welford state and passes state_path to brute-force,
    # so emit-plugin succeeds with neighborhood_variance attached.
    plugin_path = result["summary"].get("plugin_path")
    assert plugin_path is not None
    assert Path(plugin_path).exists()
    # Inferred fields artifact should also be written.
    fields_path = artifact_dir / "emit_plugin" / "test_plugin_fields.json"
    assert fields_path.exists()


def test_run_pipeline_with_nsweep(dumps_dir, oracle_path, artifact_dir):
    ctx = _FakeCtx()
    params = {
        "artifact_dir": str(artifact_dir),
        "source_paths": dumps_dir,
        "reduce_kwargs": {
            "min_variance": 100.0,
            "entropy_window": 16,
            "entropy_threshold": 3.5,
            "min_region": 8,
            "alignment": 8,
            "block_size": 16,
        },
        "oracle_path": str(oracle_path),
        "brute_force": {"key_sizes": [32], "stride": 8, "jobs": 1,
                        "exhaustive": True},
        "nsweep": {
            "n_values": [3, 4],
            "reduce_kwargs": {
                "min_variance": 100.0,
                "entropy_window": 16,
                "entropy_threshold": 3.5,
                "min_region": 8,
                "alignment": 8,
                "block_size": 16,
            },
            "key_sizes": [32],
            "stride": 8,
            "exhaustive": True,
        },
    }
    result = run_pipeline(params, ctx)
    assert (artifact_dir / "nsweep" / "report.json").is_file()
    assert (artifact_dir / "nsweep" / "report.md").is_file()
    assert (artifact_dir / "nsweep" / "report.html").is_file()
    names = {a["name"] for a in result["artifacts"]}
    assert {"nsweep_json", "nsweep_md", "nsweep_html"} <= names
    summary = result["summary"].get("nsweep")
    assert summary is not None
    assert summary["total_dumps"] == len(dumps_dir)


# ------------------------------------------------------------------
# cancellation
# ------------------------------------------------------------------


def test_run_pipeline_respects_cancel(dumps_dir, oracle_path, artifact_dir):
    """If ctx.is_cancelled flips true between stages the pipeline raises."""
    ctx = _FakeCtx(cancel=True)
    params = {
        "artifact_dir": str(artifact_dir),
        "source_paths": dumps_dir,
        "reduce_kwargs": {},
        "oracle_path": str(oracle_path),
        "brute_force": {"key_sizes": [32], "stride": 8, "jobs": 1},
    }
    with pytest.raises(RuntimeError):
        run_pipeline(params, ctx)
