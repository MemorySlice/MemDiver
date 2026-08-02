"""Tests for app.pipeline.pipeline_runner.run_pipeline.

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

from memdiver.app.pipeline.pipeline_runner import run_pipeline


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


def test_run_pipeline_persists_consensus_state_contract(
    dumps_dir, oracle_path, artifact_dir
):
    """The rewritten runner routes the consensus stage through the app producer
    (persist_welford=True). This pins the contract /refine + /neighborhood +
    brute-force state_path depend on: the ``consensus_state`` artifact, the exact
    ``state.json`` key set, and the mean/m2 arrays it points at.
    """
    ctx = _FakeCtx()
    params = {
        "artifact_dir": str(artifact_dir),
        "source_paths": dumps_dir,
        "reduce_kwargs": {
            "min_variance": 100.0, "entropy_window": 16, "entropy_threshold": 3.5,
            "min_region": 8, "alignment": 8, "block_size": 16,
        },
        "oracle_path": str(oracle_path),
        "brute_force": {"key_sizes": [32], "stride": 8, "jobs": 1,
                        "exhaustive": True},
    }
    result = run_pipeline(params, ctx)

    # The consensus_state artifact is registered (alongside the other stages).
    names = {a["name"] for a in result["artifacts"]}
    assert {"consensus_variance", "consensus_reference", "consensus_state",
            "candidates", "hits"} <= names

    # state.json carries exactly the four keys the readers expect, and its
    # mean/m2 pointers resolve to real arrays sized to the variance vector.
    state_path = artifact_dir / "consensus" / "state.json"
    assert state_path.is_file()
    state = json.loads(state_path.read_text())
    assert set(state) == {"size", "num_dumps", "mean_path", "m2_path"}
    assert state["num_dumps"] == len(dumps_dir)
    variance = np.load(artifact_dir / "consensus" / "variance.npy")
    mean = np.load(state["mean_path"])
    m2 = np.load(state["m2_path"])
    assert mean.shape == m2.shape == (state["size"],) == variance.shape


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


class _CountingRawSource:
    """Fake non-MSL DumpSource that counts read_all() invocations."""

    format_name = "raw"

    def __init__(self, data: bytes):
        self._data = data
        self.read_calls = 0

    @property
    def size(self) -> int:
        # Length without reading — the streaming fold probes this to size the
        # accumulator, so it must not count as a read.
        return len(self._data)

    def size_for(self, view: str = "raw") -> int:
        return len(self._data)

    def read_all(self, *args, **kwargs) -> bytes:
        self.read_calls += 1
        return self._data


def test_build_consensus_reads_each_raw_source_once(artifact_dir):
    """Regression: the raw-dump consensus branch must read each source exactly
    once (cached), not 2-3x (min-size probe + per-fold + reference)."""
    from memdiver.app.pipeline.pipeline_runner import _build_consensus

    sources = [
        _CountingRawSource(bytes([i]) * 128 + bytes(range(128)))
        for i in range(3)
    ]
    ctx = _FakeCtx()
    artifacts: List[Dict[str, Any]] = []
    _build_consensus(
        sources,
        ctx=ctx,
        artifact_dir=artifact_dir,
        artifacts=artifacts,
    )
    for idx, src in enumerate(sources):
        assert src.read_calls == 1, (
            f"source {idx} read {src.read_calls} times, expected 1"
        )


# ------------------------------------------------------------------
# Phase 2: opt-in escalation fall-through
# ------------------------------------------------------------------


# Per-byte population variance of the key window across [KEY_BYTES, D, D, D] is
# 3*DELTA**2 / 16. DELTA=113 -> ~2394, in the diluted band [phi0~1911, 3000):
# below the shipped default floor (brute-force misses) but recoverable by the
# floor-free escalation, which then labels it FLOOR_WAS_TOO_HIGH / tier "phi0".
DILUTED_DELTA = 113


def _diluted_reduce_kwargs() -> Dict[str, Any]:
    """Reduce at the shipped default floor so the diluted key is excluded."""
    return {
        "min_variance": 3000.0,
        "entropy_window": 16,
        "entropy_threshold": 3.5,
        "min_region": 8,
        "alignment": 8,
        "block_size": 16,
    }


@pytest.fixture
def diluted_dumps_dir(tmp_path: Path) -> List[str]:
    """Dumps whose key window sits in the diluted band (< default floor).

    Dump 0 carries the oracle sentinel; dumps 1..3 share a constant
    ``KEY_BYTES + DILUTED_DELTA`` key window, so the per-byte variance there is
    a controlled ~2394 (below 3000). The per-seed high-entropy blocks stay
    full-variance (>3000), so a reduce at min_variance=3000 finds only
    oracle-rejected candidates and the diluted key is missed.
    """
    other = bytes((b + DILUTED_DELTA) & 0xFF for b in KEY_BYTES)
    paths: List[str] = []
    p0 = tmp_path / "dump_0.bin"
    p0.write_bytes(_make_raw_dump(seed=0, key_bytes=KEY_BYTES))
    paths.append(str(p0))
    for i in range(1, 4):
        p = tmp_path / f"dump_{i}.bin"
        p.write_bytes(_make_raw_dump(seed=1000 + i, key_bytes=other))
        paths.append(str(p))
    return paths


def test_run_pipeline_escalate_false_is_no_op(dumps_dir, oracle_path, artifact_dir):
    """escalate=False must leave the default path untouched (byte-identical)."""
    ctx = _FakeCtx()
    params = {
        "artifact_dir": str(artifact_dir),
        "source_paths": dumps_dir,
        "reduce_kwargs": {
            "min_variance": 100.0, "entropy_window": 16, "entropy_threshold": 3.5,
            "min_region": 8, "alignment": 8, "block_size": 16,
        },
        "oracle_path": str(oracle_path),
        "brute_force": {"key_sizes": [32], "stride": 8, "jobs": 1, "exhaustive": True},
        "escalate": False,
    }
    result = run_pipeline(params, ctx)

    # No escalation traces anywhere.
    assert "escalation" not in result["summary"]
    assert not any(a["name"].startswith("escalate") for a in result["artifacts"])
    assert not (artifact_dir / "escalate").exists()
    assert not any(
        e.get("stage") == "escalate" for e in ctx.events
        if e["type"] in ("stage_start", "stage_end")
    )
    # The default brute-force hit is unchanged.
    hits = json.loads((artifact_dir / "brute_force" / "hits.json").read_text())
    assert hits["verified_count"] >= 1


def test_run_pipeline_escalate_recovers_diluted_key_reports_phi0(
    diluted_dumps_dir, oracle_path, artifact_dir
):
    """The core cascade: default floor misses, escalation recovers, one fold."""
    ctx = _FakeCtx()
    params = {
        "artifact_dir": str(artifact_dir),
        "source_paths": diluted_dumps_dir,
        "reduce_kwargs": _diluted_reduce_kwargs(),
        "oracle_path": str(oracle_path),
        "brute_force": {"key_sizes": [32], "stride": 8, "jobs": 1, "exhaustive": True},
        "escalate": True,
    }
    result = run_pipeline(params, ctx)

    # The default floor missed (brute-force found no verified hit).
    hits = json.loads((artifact_dir / "brute_force" / "hits.json").read_text())
    assert hits["verified_count"] == 0

    # Escalation recovered the diluted key and labeled the tier.
    esc = result["summary"]["escalation"]
    assert esc["verdict"] == "FLOOR_WAS_TOO_HIGH"
    assert esc["hit_tier"] == "phi0"
    assert esc["offset"] == KEY_OFFSET
    assert (artifact_dir / "escalate" / "verdict.json").is_file()
    assert any(a["name"] == "escalate_verdict" for a in result["artifacts"])

    # The Theta(N*d) consensus fold ran exactly once (escalation reused the
    # cached variance.npy; it never re-folded).
    consensus_starts = [
        e for e in ctx.events
        if e["type"] == "stage_start" and e.get("stage") == "consensus"
    ]
    assert len(consensus_starts) == 1


# ------------------------------------------------------------------
# Phase 2: emit-plugin empty-hits skip + escalate gating
# ------------------------------------------------------------------


def test_run_pipeline_emit_plugin_skipped_when_no_hits(
    diluted_dumps_dir, oracle_path, artifact_dir
):
    """When brute-force verifies nothing, emit_plugin takes the skip branch.

    Reaches ``_run_emit_plugin``'s empty-hits guard: it emits a ``skipped``
    stage_end and returns ``None`` WITHOUT invoking the plugin generator, so no
    plugin artifact is registered and no ``emit_plugin`` directory is written.
    """
    ctx = _FakeCtx()
    params = {
        "artifact_dir": str(artifact_dir),
        "source_paths": diluted_dumps_dir,
        "reduce_kwargs": _diluted_reduce_kwargs(),
        "oracle_path": str(oracle_path),
        "brute_force": {"key_sizes": [32], "stride": 8, "jobs": 1, "exhaustive": True},
        "emit": {"name": "test_plugin", "hit_index": 0},
    }
    result = run_pipeline(params, ctx)

    # No verified hit at the default floor.
    hits = json.loads((artifact_dir / "brute_force" / "hits.json").read_text())
    assert hits["verified_count"] == 0

    # emit_plugin skipped: no plugin path, no plugin dir, no plugin artifact.
    assert result["summary"]["plugin_path"] is None
    assert not (artifact_dir / "emit_plugin").exists()
    assert not any(a["name"] == "vol3_plugin" for a in result["artifacts"])

    # The skip surfaces as a stage_end carrying ``skipped``.
    skip_ends = [
        e for e in ctx.events
        if e["type"] == "stage_end" and e.get("stage") == "emit_plugin"
        and e.get("extra", {}).get("skipped")
    ]
    assert skip_ends


def test_run_pipeline_escalate_skipped_when_default_hits(
    dumps_dir, oracle_path, artifact_dir
):
    """escalate=True is a no-op when brute-force already found a verified hit.

    Exercises ``_escalate_enabled``'s ``verified_count != 0`` short-circuit: the
    escalate stage is gated off, so no escalation summary/artifacts/dir appear
    even though escalation was opted in.
    """
    ctx = _FakeCtx()
    params = {
        "artifact_dir": str(artifact_dir),
        "source_paths": dumps_dir,
        "reduce_kwargs": {
            "min_variance": 100.0, "entropy_window": 16, "entropy_threshold": 3.5,
            "min_region": 8, "alignment": 8, "block_size": 16,
        },
        "oracle_path": str(oracle_path),
        "brute_force": {"key_sizes": [32], "stride": 8, "jobs": 1, "exhaustive": True},
        "escalate": True,
    }
    result = run_pipeline(params, ctx)

    # The default floor found the key, so escalation must not fire.
    hits = json.loads((artifact_dir / "brute_force" / "hits.json").read_text())
    assert hits["verified_count"] >= 1
    assert "escalation" not in result["summary"]
    assert not (artifact_dir / "escalate").exists()
    assert not any(a["name"].startswith("escalate") for a in result["artifacts"])
    assert not any(
        e.get("stage") == "escalate" for e in ctx.events
        if e["type"] in ("stage_start", "stage_end")
    )


# ------------------------------------------------------------------
# _register_artifact: streamed sha256
# ------------------------------------------------------------------


def test_register_artifact_streamed_sha_matches_whole_file(artifact_dir):
    """A multi-chunk artifact hashes byte-identically to a whole-file sha256."""
    import hashlib

    from memdiver.app.pipeline.pipeline_runner import _register_artifact

    # Deterministic payload several MiB long so the incremental hash spans many
    # internal read buffers (not a single-shot read) and any chunk-boundary bug
    # would surface.
    data = bytes((i * 37 + 11) & 0xFF for i in range(2 * 1024 * 1024 + 123))
    (artifact_dir / "big.bin").write_bytes(data)

    artifacts: List[Dict[str, Any]] = []
    spec = _register_artifact(
        artifacts, artifact_dir, name="big", relpath="big.bin"
    )

    assert spec["sha256"] == hashlib.sha256(data).hexdigest()
    assert spec["size"] == len(data)
    assert artifacts == [spec]


def test_register_artifact_missing_relpath_yields_none_sha(artifact_dir):
    """A relpath that is not a file records ``sha256 == None`` and size 0."""
    from memdiver.app.pipeline.pipeline_runner import _register_artifact

    artifacts: List[Dict[str, Any]] = []
    spec = _register_artifact(
        artifacts, artifact_dir, name="ghost", relpath="does_not_exist.bin"
    )

    assert spec["sha256"] is None
    assert spec["size"] == 0

