"""Error/validation-branch tests for ``memdiver.app.tools_pipeline``.

The happy paths for these producers live in ``test_mcp_tools_pipeline.py``
(which imports the same module through the ``mcp_server`` re-export). This
file covers the reachable *error* branches — the input-validation guards and
the ``FileNotFoundError`` / ``OSError`` / ``ValueError`` → service-error
funnels — using only synthetic on-disk artifacts (no markers, no real dumps).
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Dict, List

import numpy as np
import pytest

from memdiver.app import tools_pipeline as tp
from memdiver.core.service_errors import (
    CapabilityError,
    EncryptedDumpLockedError,
    ErrorCategory,
    FileNotFoundServiceError,
)
from memdiver.core.service_result import TagStatus


# ----------------------------------------------------------------------
# _select_hit
# ----------------------------------------------------------------------


def test_select_hit_empty_hits_raises(tmp_path):
    """A hits file with no hits raises the 'no hits to emit' ValueError."""
    hits_path = tmp_path / "hits.json"
    hits_path.write_text(json.dumps({"hits": []}))
    with pytest.raises(ValueError, match="no hits to emit"):
        tp._select_hit(hits_path, 0)


def test_select_hit_index_out_of_range_raises(tmp_path):
    """An out-of-range hit index reports how many hits are present."""
    hits_path = tmp_path / "hits.json"
    hits_path.write_text(json.dumps({"hits": [{"offset": 1}]}))
    with pytest.raises(ValueError, match="requested hit 5 but only 1 present"):
        tp._select_hit(hits_path, 5)


# ----------------------------------------------------------------------
# search_reduce
# ----------------------------------------------------------------------


def test_search_reduce_missing_variance_raises_not_found(tmp_path):
    """A missing variance.npy surfaces as FileNotFoundServiceError."""
    with pytest.raises(FileNotFoundServiceError):
        tp.search_reduce(
            variance_path=str(tmp_path / "missing.npy"),
            reference_path=str(tmp_path / "missing.bin"),
            num_dumps=2,
            output_dir=str(tmp_path / "out"),
        )


def test_search_reduce_invalid_variance_raises_capability_error(tmp_path):
    """A variance path that is not a valid .npy funnels to INVALID_INPUT."""
    bad = tmp_path / "bad.npy"
    bad.write_bytes(b"not a real numpy file")
    ref = tmp_path / "reference.bin"
    ref.write_bytes(b"A" * 256)
    with pytest.raises(CapabilityError) as exc:
        tp.search_reduce(
            variance_path=str(bad),
            reference_path=str(ref),
            num_dumps=2,
            output_dir=str(tmp_path / "out"),
        )
    assert exc.value.category == ErrorCategory.INVALID_INPUT


# ----------------------------------------------------------------------
# emit_plugin
# ----------------------------------------------------------------------


def test_emit_plugin_empty_hits_funnels_to_capability_error(tmp_path):
    """An empty hits file reaches emit_plugin via write_fields and the
    ValueError from _select_hit is funnelled to a CapabilityError."""
    hits_path = tmp_path / "hits.json"
    hits_path.write_text(json.dumps({"hits": []}))
    ref = tmp_path / "reference.bin"
    ref.write_bytes(b"A" * 256)
    with pytest.raises(CapabilityError) as exc:
        tp.emit_plugin(
            hits_path=str(hits_path),
            reference_path=str(ref),
            name="plugin",
            output_dir=str(tmp_path / "out"),
            write_fields=True,
        )
    assert exc.value.category == ErrorCategory.INVALID_INPUT


# ----------------------------------------------------------------------
# consensus
# ----------------------------------------------------------------------


def test_consensus_missing_dumps_raises_not_found(tmp_path):
    """Non-existent dump paths raise FileNotFoundServiceError."""
    with pytest.raises(FileNotFoundServiceError):
        tp.consensus(
            dump_paths=[str(tmp_path / "a.bin"), str(tmp_path / "b.bin")],
            output_dir=str(tmp_path / "out"),
        )


def test_consensus_single_dump_raises_precondition(tmp_path):
    """Fewer than two dumps is a PRECONDITION failure."""
    one = tmp_path / "one.bin"
    one.write_bytes(b"A" * 128)
    with pytest.raises(CapabilityError) as exc:
        tp.consensus(dump_paths=[str(one)], output_dir=str(tmp_path / "out"))
    assert exc.value.category == ErrorCategory.PRECONDITION


def test_consensus_empty_dumps_raises_precondition(tmp_path):
    """Two empty dumps yield an empty variance vector → PRECONDITION."""
    e1 = tmp_path / "e1.bin"
    e1.write_bytes(b"")
    e2 = tmp_path / "e2.bin"
    e2.write_bytes(b"")
    with pytest.raises(CapabilityError) as exc:
        tp.consensus(
            dump_paths=[str(e1), str(e2)], output_dir=str(tmp_path / "out")
        )
    assert exc.value.category == ErrorCategory.PRECONDITION


# ----------------------------------------------------------------------
# n_sweep
# ----------------------------------------------------------------------


def test_n_sweep_missing_source_raises_not_found(tmp_path):
    """A missing source dump surfaces as FileNotFoundServiceError."""
    oracle = tmp_path / "oracle.py"
    oracle.write_text("def verify(candidate):\n    return False\n")
    with pytest.raises(FileNotFoundServiceError):
        tp.n_sweep(
            source_paths=[str(tmp_path / "missing.bin")],
            oracle_path=str(oracle),
            output_dir=str(tmp_path / "out"),
            n_values=[1],
        )


# ======================================================================
# PIECE 6b — happy paths + remaining error/refine branches.
#
# These light up the producer bodies that the error-only tests above never
# reach. Shared synthetic artifacts (variance/reference/dumps/oracle) are
# built on disk; internal collaborators are only monkeypatched where an
# error must be *injected* to prove the funnel (each such test asserts the
# exact CapabilityError category).
# ======================================================================


KEY_BYTES = bytes(range(32))
KEY_OFFSET = 256
DUMP_SIZE = 1024
REDUCE_KW = dict(
    min_variance=100.0, entropy_window=16, entropy_threshold=3.5,
    min_region=8, alignment=8, block_size=16,
)


class _Collector:
    """Records ``on_progress(event, **fields)`` calls for assertion."""

    def __init__(self) -> None:
        self.events: List = []

    def __call__(self, event: str, **fields: Any) -> None:
        self.events.append((event, fields))

    def stages(self, event: str):
        return [f.get("stage") for e, f in self.events if e == event]


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
def never_match_oracle(tmp_path: Path) -> Path:
    p = tmp_path / "never.py"
    p.write_text("def verify(candidate):\n    return False\n")
    os.chmod(p, 0o600)
    return p


@pytest.fixture
def consensus_artifacts(tmp_path: Path) -> Dict[str, Path]:
    """A variance.npy + reference.bin pair with a single high-variance,
    key-carrying 32-byte block at ``KEY_OFFSET`` (everything else static)."""
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


def _make_raw_dump(dir_: Path, index: int, carry_sentinel: bool) -> Path:
    # Identical static base across every dump (same seed), then a few
    # per-dump-varying 32-byte blocks + the sentinel key at KEY_OFFSET.
    padding_rng = np.random.default_rng(42)
    buf = bytearray(padding_rng.integers(0, 256, DUMP_SIZE, dtype=np.uint8).tobytes())
    for start in (64, 512, 768):
        rng = np.random.default_rng(1000 + index * 17 + start)
        buf[start:start + 32] = rng.integers(0, 256, 32, dtype=np.uint8).tobytes()
    if carry_sentinel:
        buf[KEY_OFFSET:KEY_OFFSET + 32] = KEY_BYTES
    else:
        other = np.random.default_rng(9000 + index).integers(
            0, 256, 32, dtype=np.uint8).tobytes()
        buf[KEY_OFFSET:KEY_OFFSET + 32] = other
    p = dir_ / f"dump_{index}.bin"
    p.write_bytes(bytes(buf))
    return p


@pytest.fixture
def source_paths(tmp_path: Path) -> List[str]:
    d = tmp_path / "dumps"
    d.mkdir()
    paths = [_make_raw_dump(d, 0, carry_sentinel=True)]
    for i in range(1, 4):
        paths.append(_make_raw_dump(d, i, carry_sentinel=False))
    return [str(p) for p in paths]


@pytest.fixture
def export_dumps(tmp_path: Path) -> List[str]:
    """Eight dumps sharing a static base with one strong 64-byte volatile
    region at offset 256 — enough signal for auto region detection."""
    d = tmp_path / "exp_dumps"
    d.mkdir()
    base = np.random.default_rng(42).integers(0, 256, DUMP_SIZE, dtype=np.uint8).tobytes()
    paths: List[str] = []
    for i in range(8):
        buf = bytearray(base)
        buf[256:320] = np.random.default_rng(500 + i).integers(
            0, 256, 64, dtype=np.uint8).tobytes()
        p = d / f"e{i}.bin"
        p.write_bytes(bytes(buf))
        paths.append(str(p))
    return paths


def _reduce(out: Path, art: Dict[str, Path], **hooks) -> Dict[str, Any]:
    return tp.search_reduce(
        variance_path=str(art["variance"]), reference_path=str(art["reference"]),
        num_dumps=4, output_dir=str(out), **REDUCE_KW, **hooks,
    )


# ----------------------------------------------------------------------
# _raise_if_locked (the locked-source guard raises before any empty-result
# misattribution)
# ----------------------------------------------------------------------


def test_progress_bridge_prefixes_colonless_stage():
    """The bridge prefixes a leaf stage that has no ``:`` of its own, and
    leaves an already-namespaced stage untouched; a negative pct maps to None."""
    col = _Collector()
    bridge = tp._progress_bridge(col, "search_reduce")
    assert bridge is not None
    bridge(SimpleNamespace(stage="variance", pct=0.5, msg="m", extra={"k": 1}))
    bridge(SimpleNamespace(stage="own:sub", pct=-1.0, msg="n", extra=None))
    stages = [f["stage"] for e, f in col.events if e == "progress"]
    assert stages == ["search_reduce:variance", "own:sub"]
    pcts = [f["pct"] for e, f in col.events if e == "progress"]
    assert pcts == [0.5, None]


def test_progress_bridge_returns_none_without_sink():
    assert tp._progress_bridge(None, "stage") is None


def test_raise_if_locked_raises_for_locked_source():
    locked = SimpleNamespace(tag_status=TagStatus.MISSING_KEY)
    with pytest.raises(EncryptedDumpLockedError) as exc:
        tp._raise_if_locked(locked)
    assert exc.value.category == ErrorCategory.PRECONDITION


def test_raise_if_locked_passes_through_decrypted_source():
    ok = SimpleNamespace(tag_status=TagStatus.NOT_ENCRYPTED)
    assert tp._raise_if_locked(ok) is None


# ----------------------------------------------------------------------
# search_reduce — green path (with all surface hooks active)
# ----------------------------------------------------------------------


def test_search_reduce_green_writes_candidates(tmp_path, consensus_artifacts):
    col = _Collector()
    seen: List = []
    out = tmp_path / "out"
    result = _reduce(
        out, consensus_artifacts,
        on_source=lambda src: seen.append(src),
        on_progress=col, is_cancelled=lambda: False,
    )
    cand_path = Path(result["candidates_path"])
    assert cand_path.is_file()
    assert result["num_regions"] >= 1
    payload = json.loads(cand_path.read_text())
    assert payload["regions"]
    assert payload["recommended_floor"] == result["recommended_floor"]
    # Bracketing stage events streamed through the progress bridge.
    assert "search_reduce" in col.stages("stage_start")
    assert "search_reduce" in col.stages("stage_end")


# ----------------------------------------------------------------------
# brute_force — green path + injected-error funnel
# ----------------------------------------------------------------------


def test_brute_force_green_writes_hits(tmp_path, consensus_artifacts, oracle_path):
    out = tmp_path / "out"
    reduction = _reduce(out, consensus_artifacts)
    col = _Collector()
    result = tp.brute_force(
        candidates_path=reduction["candidates_path"],
        reference_path=str(consensus_artifacts["reference"]),
        oracle_path=str(oracle_path),
        output_dir=str(out),
        key_sizes=(32,), stride=8, jobs=1, exhaustive=True,
        on_progress=col,
    )
    assert result["verified_count"] >= 1
    hits_path = Path(result["hits_path"])
    assert hits_path.is_file()
    payload = json.loads(hits_path.read_text())
    assert any(h["offset"] == KEY_OFFSET for h in payload["hits"])
    assert "brute_force" in col.stages("stage_end")


def test_brute_force_missing_reference_raises_not_found(tmp_path, oracle_path):
    cand = tmp_path / "candidates.json"
    cand.write_text(json.dumps({"regions": []}))
    with pytest.raises(FileNotFoundServiceError):
        tp.brute_force(
            candidates_path=str(cand),
            reference_path=str(tmp_path / "missing.bin"),
            oracle_path=str(oracle_path),
            output_dir=str(tmp_path / "o"),
        )


def test_brute_force_engine_valueerror_funnels(
    tmp_path, consensus_artifacts, oracle_path, monkeypatch
):
    out = tmp_path / "out"
    reduction = _reduce(out, consensus_artifacts)

    def _boom(*a, **k):
        raise ValueError("engine exploded")

    monkeypatch.setattr("memdiver.engine.brute_force.run_brute_force", _boom)
    with pytest.raises(CapabilityError) as exc:
        tp.brute_force(
            candidates_path=reduction["candidates_path"],
            reference_path=str(consensus_artifacts["reference"]),
            oracle_path=str(oracle_path),
            output_dir=str(out),
        )
    assert exc.value.category == ErrorCategory.INVALID_INPUT
    assert "engine exploded" in exc.value.message


# ----------------------------------------------------------------------
# n_sweep — green path, escalation branch, injected-error funnel
# ----------------------------------------------------------------------


def test_n_sweep_green_emits_reports(tmp_path, source_paths, oracle_path):
    out = tmp_path / "nsweep"
    col = _Collector()
    seen: List = []
    result = tp.n_sweep(
        source_paths=source_paths, oracle_path=str(oracle_path),
        output_dir=str(out), n_values=[3, 4], reduce_kwargs=dict(REDUCE_KW),
        key_sizes=(32,), stride=8,
        on_source=lambda src: seen.append(src), on_progress=col,
    )
    assert Path(result["report_json"]).is_file()
    assert Path(result["report_md"]).is_file()
    assert Path(result["report_html"]).is_file()
    assert result["total_dumps"] == 4
    assert seen  # on_source ran per opened source
    assert "nsweep" in col.stages("stage_end")


def test_n_sweep_escalate_populates_escalation(
    tmp_path, source_paths, never_match_oracle
):
    out = tmp_path / "nsweep_esc"
    result = tp.n_sweep(
        source_paths=source_paths, oracle_path=str(never_match_oracle),
        output_dir=str(out), n_values=[3, 4], reduce_kwargs=dict(REDUCE_KW),
        key_sizes=(32,), stride=8, escalate=True,
    )
    assert result["first_hit_n"] is None
    assert "escalation" in result
    esc = result["escalation"]
    # An oracle that never matches exhausts the maximal candidate set without
    # a hit: the escalation verdict is the negative ABSENT terminal, with no
    # tier/offset/key attributed and every sweep point recorded as a miss.
    assert esc["verdict"] == "ABSENT"
    assert esc["hit_tier"] is None
    assert esc["key_hex"] is None
    assert esc["offset"] is None
    assert esc["exit_code"] == 2
    assert esc["tried"] == esc["maximal_candidates"] > 0
    assert esc["sweep"]
    assert all(point["hit"] is False for point in esc["sweep"])


def test_n_sweep_engine_oserror_funnels(
    tmp_path, source_paths, oracle_path, monkeypatch
):
    def _boom(*a, **k):
        raise OSError("bad sweep")

    monkeypatch.setattr("memdiver.engine.nsweep.run_nsweep", _boom)
    with pytest.raises(CapabilityError) as exc:
        tp.n_sweep(
            source_paths=source_paths, oracle_path=str(oracle_path),
            output_dir=str(tmp_path / "o"), n_values=[3],
            reduce_kwargs=dict(REDUCE_KW),
        )
    assert exc.value.category == ErrorCategory.INVALID_INPUT
    # The funnel wraps the injected OSError verbatim, so the message names
    # the failing operation (mirrors test_brute_force_engine_valueerror_funnels).
    assert "bad sweep" in exc.value.message


# ----------------------------------------------------------------------
# emit_plugin — write_fields path, plain path, and FileNotFound funnel
# ----------------------------------------------------------------------


def _synthetic_hits(tmp_path: Path):
    reference = bytearray(b"A" * 256)
    reference[100:132] = bytes(range(32))
    variance = [0.0] * 160
    for i in range(32):
        variance[64 + i] = 10000.0
    hit = {
        "offset": 100, "length": 32, "key_hex": bytes(range(32)).hex(),
        "region_index": 0, "neighborhood_start": 36,
        "neighborhood_variance": variance,
    }
    hits_path = tmp_path / "hits.json"
    hits_path.write_text(json.dumps({"hits": [hit]}))
    ref_path = tmp_path / "emit_ref.bin"
    ref_path.write_bytes(bytes(reference))
    return hits_path, ref_path


def test_emit_plugin_write_fields_writes_artifacts(tmp_path):
    from memdiver.engine.vol3_emit import extract_inferred_fields

    hits_path, ref_path = _synthetic_hits(tmp_path)
    hit = json.loads(hits_path.read_text())["hits"][0]
    out = tmp_path / "o"
    result = tp.emit_plugin(
        hits_path=str(hits_path), reference_path=str(ref_path),
        name="wf_plugin", output_dir=str(out), write_fields=True,
        on_progress=_Collector(),
    )
    plugin_path = Path(result["plugin_path"])
    assert plugin_path.is_file()
    compile(plugin_path.read_text(), str(plugin_path), "exec")
    fields_path = out / "wf_plugin_fields.json"
    assert fields_path.is_file()
    expected = extract_inferred_fields(hit, variance_threshold=None)
    assert result["fields"] == expected
    assert json.loads(fields_path.read_text()) == expected
    assert result["fields_path"] == str(fields_path)


def test_emit_plugin_plain_path_omits_fields(tmp_path):
    hits_path, ref_path = _synthetic_hits(tmp_path)
    out = tmp_path / "o"
    result = tp.emit_plugin(
        hits_path=str(hits_path), reference_path=str(ref_path),
        name="plain_plugin", output_dir=str(out),
    )
    plugin_path = Path(result["plugin_path"])
    assert plugin_path.is_file()
    assert result["size"] == plugin_path.stat().st_size
    assert "fields" not in result
    assert not (out / "plain_plugin_fields.json").exists()


def test_emit_plugin_missing_reference_raises_not_found(tmp_path):
    hits_path, _ = _synthetic_hits(tmp_path)
    with pytest.raises(FileNotFoundServiceError):
        tp.emit_plugin(
            hits_path=str(hits_path),
            reference_path=str(tmp_path / "missing.bin"),
            name="x", output_dir=str(tmp_path / "o"),
        )


# ----------------------------------------------------------------------
# consensus — batch happy, persist_welford (raw + msl), injected funnel
# ----------------------------------------------------------------------


def test_consensus_batch_writes_variance_and_reference(tmp_path, source_paths):
    out = tmp_path / "o"
    meta = tp.consensus(dump_paths=source_paths, output_dir=str(out))
    assert meta["num_dumps"] == 4
    variance_path = Path(meta["variance_path"])
    reference_path = Path(meta["reference_path"])
    assert variance_path.is_file() and reference_path.is_file()
    assert (out / "consensus.json").is_file()
    # reference.bin is the first dump's bytes truncated to consensus size.
    assert reference_path.read_bytes() == Path(source_paths[0]).read_bytes()[: meta["size"]]
    assert "classification_counts" in meta


def test_consensus_persist_welford_raw_writes_state(tmp_path, source_paths):
    from memdiver.core.variance import WelfordVariance

    out = tmp_path / "o"
    result = tp.consensus(
        dump_paths=source_paths, output_dir=str(out), persist_welford=True,
    )
    state = json.loads((out / "state.json").read_text())
    assert set(state) == {"size", "num_dumps", "mean_path", "m2_path"}
    assert (out / "mean.npy").is_file() and (out / "m2.npy").is_file()
    # Byte-identical to a direct Welford computation over the same dumps.
    buffers = [Path(p).read_bytes() for p in source_paths]
    min_size = min(len(b) for b in buffers)
    welford = WelfordVariance(min_size)
    for buf in buffers:
        welford.add_dump(buf[:min_size])
    assert state["num_dumps"] == welford.num_dumps == 4
    assert np.array_equal(np.load(out / "mean.npy"), welford.state_arrays()[0])
    assert np.array_equal(np.load(out / "m2.npy"), welford.state_arrays()[1])
    assert np.array_equal(np.load(out / "variance.npy"), welford.variance())
    assert result["state_path"] == str(out / "state.json")


def _msl_paths(tmp_path: Path, count: int = 3) -> List[str]:
    import sys

    sys.path.insert(0, str(Path(__file__).parent / "fixtures"))
    try:
        from generate_msl_fixtures import write_aslr_fixture
    finally:
        sys.path.pop(0)
    rng = np.random.default_rng(7)
    paths: List[str] = []
    for i in range(count):
        key_bytes = rng.integers(0, 256, 32, dtype=np.uint8).tobytes()
        p = write_aslr_fixture(
            tmp_path / f"d{i + 1}.msl",
            region_base=0x1000_0000 * (i + 1),
            key_bytes=key_bytes,
        )
        paths.append(str(p))
    return paths


def test_consensus_persist_welford_msl_branch(tmp_path):
    from memdiver.core.dump_source import open_dump
    from memdiver.engine.consensus_msl import MslIncrementalBuilder

    paths = _msl_paths(tmp_path, count=3)
    out = tmp_path / "o"
    result = tp.consensus(
        dump_paths=paths, output_dir=str(out), persist_welford=True,
    )
    assert result["num_dumps"] == 3
    state = json.loads((out / "state.json").read_text())
    assert state["num_dumps"] == 3
    assert (out / "variance.npy").is_file()
    assert (out / "mean.npy").is_file()
    assert (out / "m2.npy").is_file()
    # Byte-identical to a direct MslIncrementalBuilder fold over the same
    # sources (mirrors the raw branch's direct-WelfordVariance sibling above).
    sources = []
    for p in paths:
        src = open_dump(Path(p))
        src.open()
        sources.append(src)
    builder = MslIncrementalBuilder.from_sources(sources)
    for i in range(len(sources)):
        builder.fold_next(i)
    for src in sources:
        src.close()
    assert np.array_equal(np.load(out / "mean.npy"), builder.welford_state()[0])
    assert np.array_equal(np.load(out / "m2.npy"), builder.welford_state()[1])
    assert np.array_equal(np.load(out / "variance.npy"), builder.get_live_variance())
    assert Path(result["reference_path"]).read_bytes() == builder.get_reference()


def test_consensus_batch_engine_error_funnels(tmp_path, source_paths, monkeypatch):
    def _boom(*a, **k):
        raise ValueError("consensus blew up")

    monkeypatch.setattr(
        "memdiver.engine.consensus_service.build_consensus", _boom)
    with pytest.raises(CapabilityError) as exc:
        tp.consensus(dump_paths=source_paths, output_dir=str(tmp_path / "o"))
    assert exc.value.category == ErrorCategory.INVALID_INPUT
    assert "consensus blew up" in exc.value.message


def test_consensus_persist_open_error_funnels(tmp_path, source_paths, monkeypatch):
    def _boom(*a, **k):
        raise OSError("cannot open")

    monkeypatch.setattr("memdiver.app.composition.open_dump", _boom)
    with pytest.raises(CapabilityError) as exc:
        tp.consensus(
            dump_paths=source_paths, output_dir=str(tmp_path / "o"),
            persist_welford=True,
        )
    assert exc.value.category == ErrorCategory.INVALID_INPUT


# ----------------------------------------------------------------------
# auto_floor — green verdict + not-found / invalid-input funnels
# ----------------------------------------------------------------------


def test_auto_floor_green_writes_verdict(tmp_path, consensus_artifacts, oracle_path):
    out = tmp_path / "af"
    col = _Collector()
    seen: List = []
    verdict = tp.auto_floor(
        variance_path=str(consensus_artifacts["variance"]),
        reference_path=str(consensus_artifacts["reference"]),
        oracle_path=str(oracle_path), num_dumps=4,
        reduce_kwargs=dict(REDUCE_KW), output_dir=str(out),
        on_source=lambda src: seen.append(src), on_progress=col,
    )
    assert seen  # on_source hook ran on the opened reference
    # The fixture's only high-variance block is the 32-byte key at
    # KEY_OFFSET (phi=20000.0, well above the DEFAULT_FLOOR=3000.0 band), so
    # the oracle recovers it on the first try at the "default" tier.
    assert verdict["verdict"] == "RECOVERED"
    assert verdict["hit_tier"] == "default"
    assert verdict["offset"] == KEY_OFFSET
    assert verdict["key_hex"] == KEY_BYTES.hex()
    assert verdict["phi_star"] == 20000.0
    assert "artifacts" in verdict
    for p in verdict["artifacts"].values():
        assert Path(p).is_file()
    assert "escalate" in col.stages("stage_start")


def test_auto_floor_missing_variance_raises_not_found(
    tmp_path, consensus_artifacts, oracle_path
):
    with pytest.raises(FileNotFoundServiceError):
        tp.auto_floor(
            variance_path=str(tmp_path / "missing.npy"),
            reference_path=str(consensus_artifacts["reference"]),
            oracle_path=str(oracle_path), num_dumps=4,
            output_dir=str(tmp_path / "o"),
        )


def test_auto_floor_invalid_variance_funnels(
    tmp_path, consensus_artifacts, oracle_path
):
    bad = tmp_path / "bad.npy"
    bad.write_bytes(b"not a numpy file")
    with pytest.raises(CapabilityError) as exc:
        tp.auto_floor(
            variance_path=str(bad),
            reference_path=str(consensus_artifacts["reference"]),
            oracle_path=str(oracle_path), num_dumps=4,
            output_dir=str(tmp_path / "o"),
        )
    assert exc.value.category == ErrorCategory.INVALID_INPUT


# ----------------------------------------------------------------------
# export_pattern / manual_export_pattern / _resolve_key_material
# ----------------------------------------------------------------------


def test_export_pattern_auto_writes_pattern_file(tmp_path, export_dumps):
    out = tmp_path / "exp"
    result = tp.export_pattern(
        dump_paths=export_dumps, output_dir=str(out),
        fmt="volatility3", name="auto_pat", min_static_ratio=0.05,
    )
    assert result["format"] == "volatility3"
    assert result["content"]
    pattern_path = Path(result["pattern_path"])
    assert pattern_path.is_file()
    assert pattern_path.suffix == ".py"
    assert pattern_path.read_text() == result["content"]


def test_export_pattern_missing_dump_raises_not_found(tmp_path):
    with pytest.raises(FileNotFoundServiceError):
        tp.export_pattern(dump_paths=[str(tmp_path / "nope.bin"),
                                      str(tmp_path / "nope2.bin")])


def test_export_pattern_single_dump_raises_precondition(tmp_path):
    one = tmp_path / "one.bin"
    one.write_bytes(b"A" * 128)
    with pytest.raises(CapabilityError) as exc:
        tp.export_pattern(dump_paths=[str(one)])
    assert exc.value.category == ErrorCategory.PRECONDITION


def test_manual_export_missing_dump_raises_not_found(tmp_path):
    with pytest.raises(FileNotFoundServiceError):
        tp.manual_export_pattern(
            dump_paths=[str(tmp_path / "nope.bin"), str(tmp_path / "nope2.bin")],
            offset=0, length=32)


def test_manual_export_single_dump_raises_precondition(tmp_path):
    one = tmp_path / "one.bin"
    one.write_bytes(b"A" * 128)
    with pytest.raises(CapabilityError) as exc:
        tp.manual_export_pattern(dump_paths=[str(one)], offset=0, length=32)
    assert exc.value.category == ErrorCategory.PRECONDITION


def test_manual_export_pattern_with_key_material_dict(
    tmp_path, source_paths, monkeypatch
):
    # A static, non-volatile region (offset 0 is identical across dumps).
    # Passing an explicit ``key_material`` dict (even empty) exercises the
    # pre-decoded idiom of ``_resolve_key_material``: "if key_material is not
    # None: return key_material" short-circuits BEFORE the file-path idiom's
    # ``key_material_kwargs(key_file, passphrase, kem_key_file)`` call. Prove
    # that short-circuit by making the file-path helper explode — the dict
    # idiom must still succeed because it never reaches that call.
    def _boom(*a, **k):
        raise AssertionError(
            "key_material_kwargs should not be called when an explicit "
            "key_material dict is supplied"
        )

    monkeypatch.setattr(tp, "key_material_kwargs", _boom)
    result = tp.manual_export_pattern(
        dump_paths=source_paths, offset=0, length=64,
        fmt="json", name="manual_pat", key_material={},
    )
    assert result["format"] == "json"
    assert result["content"]
    assert "pattern_path" not in result  # no output_dir given
    # The region is static across all four dumps, so the exported pattern's
    # hex reflects the first dump's raw bytes at [0:64) exactly.
    expected_hex = " ".join(
        f"{b:02x}" for b in Path(source_paths[0]).read_bytes()[0:64]
    )
    assert result["pattern"]["hex_pattern"] == expected_hex
    assert result["pattern"]["static_ratio"] == 1.0


# ----------------------------------------------------------------------
# verify_key_result — canonical dict + each hard-error branch
# ----------------------------------------------------------------------


def _dump_with_key(tmp_path: Path) -> Path:
    buf = bytearray(b"\x00" * 256)
    buf[0:32] = KEY_BYTES
    p = tmp_path / "verify_dump.bin"
    p.write_bytes(bytes(buf))
    return p


def test_verify_key_returns_canonical_dict(tmp_path):
    dump = _dump_with_key(tmp_path)
    seen: List = []
    result = tp.verify_key_result(
        dump_path=str(dump), offset=0, length=32,
        ciphertext_hex="00" * 32, cipher="AES-256-CBC",
        on_source=lambda src: seen.append(src),
    )
    assert set(result) == {"verified", "offset", "length", "cipher", "key_hex"}
    assert result["offset"] == 0 and result["length"] == 32
    assert result["cipher"] == "AES-256-CBC"
    assert isinstance(result["verified"], bool)
    # key_hex is populated iff the decryption verified.
    assert (result["key_hex"] is None) != bool(result["verified"])
    assert seen  # on_source hook ran


def test_verify_key_missing_dump_raises_not_found(tmp_path):
    with pytest.raises(FileNotFoundServiceError):
        tp.verify_key_result(
            dump_path=str(tmp_path / "nope.bin"), offset=0, length=32,
            ciphertext_hex="00" * 16,
        )


def test_verify_key_unknown_cipher_raises(tmp_path):
    dump = _dump_with_key(tmp_path)
    with pytest.raises(CapabilityError) as exc:
        tp.verify_key_result(
            dump_path=str(dump), offset=0, length=32,
            ciphertext_hex="00" * 16, cipher="ROT13",
        )
    assert exc.value.category == ErrorCategory.INVALID_INPUT
    assert "Unknown cipher" in exc.value.message


def test_verify_key_offset_exceeds_dump_raises(tmp_path):
    dump = _dump_with_key(tmp_path)
    with pytest.raises(CapabilityError) as exc:
        tp.verify_key_result(
            dump_path=str(dump), offset=250, length=64,
            ciphertext_hex="00" * 16,
        )
    assert exc.value.category == ErrorCategory.INVALID_INPUT
    assert "exceeds dump size" in exc.value.message


def test_verify_key_bad_ciphertext_hex_raises(tmp_path):
    dump = _dump_with_key(tmp_path)
    with pytest.raises(CapabilityError) as exc:
        tp.verify_key_result(
            dump_path=str(dump), offset=0, length=32,
            ciphertext_hex="not-hex",
        )
    assert exc.value.category == ErrorCategory.INVALID_INPUT
    assert "Invalid hex input" in exc.value.message
