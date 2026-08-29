"""Tests for the additive progress / cancel / persist hooks on the six
``app.tools_pipeline`` pipeline producers.

These hooks (``on_progress`` / ``is_cancelled`` on every producer, plus the
opt-in ``persist_welford`` on ``consensus`` and ``write_fields`` on
``emit_plugin``) exist so a later step can route the web pipeline THROUGH the
producers without behaviour change. The invariant under test:

* With the hooks unset, every producer is byte-identical to before.
* With an ``on_progress`` collector, each emits ``stage_start`` / ``stage_end``
  (and progress) with the stage names + ``extra`` field names the web relies on.
* ``is_cancelled`` returning True at a stage boundary raises the same cancel
  signal ``experiment_result`` uses (``CapabilityError`` with ``code`` =
  ``"cancelled"``).
* ``consensus(persist_welford=True)`` writes ``state.json`` / ``mean.npy`` /
  ``m2.npy`` whose values match a direct Welford computation.
* ``emit_plugin(write_fields=True)`` writes ``<name>_fields.json`` matching
  ``extract_inferred_fields``.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any, Dict, List, Tuple

import numpy as np
import pytest

from memdiver.app import tools_pipeline
from memdiver.core.service_errors import CapabilityError
from memdiver.engine.vol3_emit import extract_inferred_fields
from tests._emit_pins import strip_timestamp

KEY_BYTES = bytes(range(32))
KEY_OFFSET = 256
DUMP_SIZE = 1024


class Collector:
    """Records ``on_progress(event, **fields)`` calls."""

    def __init__(self) -> None:
        self.events: List[Tuple[str, Dict[str, Any]]] = []

    def __call__(self, event: str, **fields: Any) -> None:
        self.events.append((event, fields))

    def of(self, event: str) -> List[Dict[str, Any]]:
        return [f for e, f in self.events if e == event]

    def stages(self, event: str) -> List[str]:
        return [f.get("stage") for f in self.of(event)]


#: Promoted into ``tests/_emit_pins.py`` so the golden-pin module shares one
#: definition of the vol3 timestamp stripper rather than a third copy.
_strip_timestamp = strip_timestamp


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
def consensus_artifacts(tmp_path: Path) -> Dict[str, Path]:
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


REDUCE_KW = dict(
    min_variance=100.0, entropy_window=16, entropy_threshold=3.5,
    min_region=8, alignment=8, block_size=16,
)


def _candidates(out: Path, art: Dict[str, Path], **hooks) -> Dict[str, Any]:
    return tools_pipeline.search_reduce(
        variance_path=str(art["variance"]), reference_path=str(art["reference"]),
        num_dumps=4, output_dir=str(out), **REDUCE_KW, **hooks,
    )


def _hits(out: Path, art: Dict[str, Path], oracle: Path,
          candidates_path: str, **hooks) -> Dict[str, Any]:
    return tools_pipeline.brute_force(
        candidates_path=candidates_path, reference_path=str(art["reference"]),
        oracle_path=str(oracle), output_dir=str(out),
        key_sizes=(32,), stride=8, jobs=1, exhaustive=True, **hooks,
    )


def _synthetic_hits_json(tmp_path: Path) -> Tuple[Path, Path]:
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
    ref_path = tmp_path / "emit_reference.bin"
    ref_path.write_bytes(bytes(reference))
    return hits_path, ref_path


# ----------------------------------------------------------------------
# (a) byte-identical output when the hooks are unset
# ----------------------------------------------------------------------


def test_search_reduce_byte_identical_without_hooks(tmp_path, consensus_artifacts):
    a = _candidates(tmp_path / "a", consensus_artifacts)
    b = _candidates(tmp_path / "b", consensus_artifacts, on_progress=Collector())
    assert (tmp_path / "a" / "candidates.json").read_bytes() == \
        (tmp_path / "b" / "candidates.json").read_bytes()
    assert a["num_regions"] == b["num_regions"]
    assert a["recommended_floor"] == b["recommended_floor"]


def test_brute_force_byte_identical_without_hooks(tmp_path, consensus_artifacts, oracle_path):
    cand = _candidates(tmp_path / "c", consensus_artifacts)
    a = _hits(tmp_path / "a", consensus_artifacts, oracle_path, cand["candidates_path"])
    b = _hits(tmp_path / "b", consensus_artifacts, oracle_path,
              cand["candidates_path"], on_progress=Collector())
    assert (tmp_path / "a" / "hits.json").read_bytes() == \
        (tmp_path / "b" / "hits.json").read_bytes()
    assert a["verified_count"] == b["verified_count"] >= 1


def test_consensus_batch_byte_identical_without_hooks(tmp_path, source_paths):
    a = tools_pipeline.consensus(dump_paths=source_paths, output_dir=str(tmp_path / "a"))
    b = tools_pipeline.consensus(dump_paths=source_paths, output_dir=str(tmp_path / "b"),
                                 on_progress=Collector())
    assert (tmp_path / "a" / "variance.npy").read_bytes() == \
        (tmp_path / "b" / "variance.npy").read_bytes()
    assert (tmp_path / "a" / "reference.bin").read_bytes() == \
        (tmp_path / "b" / "reference.bin").read_bytes()
    assert a["num_dumps"] == b["num_dumps"] and a["size"] == b["size"]


def test_consensus_default_omits_welford_state(tmp_path, source_paths):
    """The default (batch) path must NOT persist the Welford accumulator state.

    ``mean.npy`` / ``m2.npy`` / ``state.json`` are gated behind the opt-in
    ``persist_welford`` flag (only ``/refine``, ``/neighborhood`` and brute-force
    ``state_path`` need them, and those run off a ``persist_welford=True`` fold).
    A default consensus run still writes ``variance.npy`` (the variance map every
    caller needs) but none of the accumulator state, so plain CLI/MCP runs don't
    pay to materialize + write the two full-size arrays. This locks that
    contract."""
    out = tmp_path / "o"
    result = tools_pipeline.consensus(
        dump_paths=source_paths, output_dir=str(out),
    )
    assert (out / "variance.npy").is_file()
    for gated in ("mean.npy", "m2.npy", "state.json"):
        assert not (out / gated).exists(), gated
    # The result envelope likewise omits the persist-only pointers.
    for gated_key in ("state_path", "mean_path", "m2_path"):
        assert gated_key not in result, gated_key


def test_emit_plugin_byte_identical_without_hooks(tmp_path):
    hits_path, ref_path = _synthetic_hits_json(tmp_path)
    common = dict(hits_path=str(hits_path), reference_path=str(ref_path),
                  name="hooks_plugin")
    tools_pipeline.emit_plugin(output_dir=str(tmp_path / "a"), **common)
    tools_pipeline.emit_plugin(output_dir=str(tmp_path / "b"),
                               on_progress=Collector(), **common)
    a = _strip_timestamp((tmp_path / "a" / "hooks_plugin.py").read_text())
    b = _strip_timestamp((tmp_path / "b" / "hooks_plugin.py").read_text())
    assert a == b


def test_n_sweep_stable_fields_without_hooks(tmp_path, source_paths, oracle_path):
    common = dict(source_paths=source_paths, oracle_path=str(oracle_path),
                  n_values=[3, 4], reduce_kwargs=dict(REDUCE_KW),
                  key_sizes=(32,), stride=8)
    a = tools_pipeline.n_sweep(output_dir=str(tmp_path / "a"), **common)
    b = tools_pipeline.n_sweep(output_dir=str(tmp_path / "b"),
                               on_progress=Collector(), **common)
    for k in ("total_dumps", "first_hit_n", "first_hit_offset", "headline"):
        assert a[k] == b[k]


def test_auto_floor_stable_fields_without_hooks(tmp_path, consensus_artifacts, oracle_path):
    common = dict(variance_path=str(consensus_artifacts["variance"]),
                  reference_path=str(consensus_artifacts["reference"]),
                  oracle_path=str(oracle_path), num_dumps=4,
                  reduce_kwargs=dict(REDUCE_KW))
    a = tools_pipeline.auto_floor(output_dir=str(tmp_path / "a"), **common)
    b = tools_pipeline.auto_floor(output_dir=str(tmp_path / "b"),
                                  on_progress=Collector(), **common)
    assert a["verdict"] == b["verdict"]
    assert a["phi0"] == b["phi0"]


# ----------------------------------------------------------------------
# (b) on_progress emits stage_start / stage_end with expected names + extras
# ----------------------------------------------------------------------


def test_search_reduce_emits_stage_events(tmp_path, consensus_artifacts):
    col = Collector()
    _candidates(tmp_path / "o", consensus_artifacts, on_progress=col)
    assert "search_reduce" in col.stages("stage_start")
    assert "search_reduce" in col.stages("stage_end")
    end = col.of("stage_end")[0]["extra"]
    assert {"num_regions", "stages", "fallback_entropy_only"} <= set(end)


def test_brute_force_emits_stage_events(tmp_path, consensus_artifacts, oracle_path):
    cand = _candidates(tmp_path / "c", consensus_artifacts)
    col = Collector()
    _hits(tmp_path / "o", consensus_artifacts, oracle_path,
          cand["candidates_path"], on_progress=col)
    assert "brute_force" in col.stages("stage_start")
    end = col.of("stage_end")[0]["extra"]
    assert {"verified_count", "total_candidates", "variance_threshold", "hits"} <= set(end)
    # No override supplied -> resolves to the producer default.
    assert end["variance_threshold"] == 2000.0


def test_brute_force_stage_end_carries_override(tmp_path, consensus_artifacts, oracle_path):
    """A user variance_threshold override is surfaced on the brute_force stage_end
    so the web reducer seeds its convergence preview from the exact cutoff the
    emit stage will use (instead of the hardcoded 2000 default)."""
    cand = _candidates(tmp_path / "c", consensus_artifacts)
    col = Collector()
    _hits(tmp_path / "o", consensus_artifacts, oracle_path,
          cand["candidates_path"], on_progress=col, variance_threshold=1500.0)
    end = col.of("stage_end")[0]["extra"]
    assert end["variance_threshold"] == 1500.0


def test_n_sweep_emits_stage_events(tmp_path, source_paths, oracle_path):
    col = Collector()
    tools_pipeline.n_sweep(
        source_paths=source_paths, oracle_path=str(oracle_path),
        output_dir=str(tmp_path / "o"), n_values=[3, 4],
        reduce_kwargs=dict(REDUCE_KW), key_sizes=(32,), stride=8,
        on_progress=col,
    )
    assert "nsweep" in col.stages("stage_start")
    end = col.of("stage_end")[0]["extra"]
    assert {"first_hit_n", "first_hit_offset", "total_dumps"} <= set(end)


def test_emit_plugin_emits_stage_events(tmp_path):
    hits_path, ref_path = _synthetic_hits_json(tmp_path)
    col = Collector()
    tools_pipeline.emit_plugin(
        hits_path=str(hits_path), reference_path=str(ref_path),
        name="evt_plugin", output_dir=str(tmp_path / "o"),
        write_fields=True, on_progress=col,
    )
    assert "emit_plugin" in col.stages("stage_start")
    end = col.of("stage_end")[0]["extra"]
    assert {"plugin_path", "fields", "variance_threshold"} <= set(end)
    assert end["fields"] is not None


def test_consensus_persist_emits_stage_and_fold_events(tmp_path, source_paths):
    col = Collector()
    tools_pipeline.consensus(
        dump_paths=source_paths, output_dir=str(tmp_path / "o"),
        persist_welford=True, on_progress=col,
    )
    assert "consensus" in col.stages("stage_start")
    assert "consensus" in col.stages("stage_end")
    folds = [f for f in col.of("progress") if f.get("stage") == "consensus"]
    assert len(folds) == len(source_paths)
    assert {"dumps_folded", "total_dumps"} <= set(folds[-1]["extra"])
    end = col.of("stage_end")[0]["extra"]
    assert {"total_bytes", "num_dumps"} <= set(end)


def test_auto_floor_emits_escalate_stage_events(tmp_path, consensus_artifacts, oracle_path):
    col = Collector()
    tools_pipeline.auto_floor(
        variance_path=str(consensus_artifacts["variance"]),
        reference_path=str(consensus_artifacts["reference"]),
        oracle_path=str(oracle_path), num_dumps=4,
        reduce_kwargs=dict(REDUCE_KW), output_dir=str(tmp_path / "o"),
        on_progress=col,
    )
    assert "escalate" in col.stages("stage_start")
    end = col.of("stage_end")[0]["extra"]
    assert {"verdict", "hit_tier", "phi_star", "phi0"} <= set(end)


# ----------------------------------------------------------------------
# (c) is_cancelled True at a boundary raises the cancel signal
# ----------------------------------------------------------------------


_CANCEL = lambda: True  # noqa: E731


def _assert_cancelled(fn) -> None:
    with pytest.raises(CapabilityError) as excinfo:
        fn()
    assert excinfo.value.code == "cancelled"


def test_search_reduce_cancel(tmp_path, consensus_artifacts):
    _assert_cancelled(lambda: _candidates(
        tmp_path / "o", consensus_artifacts, is_cancelled=_CANCEL))


def test_brute_force_cancel(tmp_path, consensus_artifacts, oracle_path):
    cand = _candidates(tmp_path / "c", consensus_artifacts)
    _assert_cancelled(lambda: _hits(
        tmp_path / "o", consensus_artifacts, oracle_path,
        cand["candidates_path"], is_cancelled=_CANCEL))


def test_n_sweep_cancel(tmp_path, source_paths, oracle_path):
    _assert_cancelled(lambda: tools_pipeline.n_sweep(
        source_paths=source_paths, oracle_path=str(oracle_path),
        output_dir=str(tmp_path / "o"), n_values=[3, 4],
        reduce_kwargs=dict(REDUCE_KW), key_sizes=(32,), stride=8,
        is_cancelled=_CANCEL))


def test_emit_plugin_cancel(tmp_path):
    hits_path, ref_path = _synthetic_hits_json(tmp_path)
    _assert_cancelled(lambda: tools_pipeline.emit_plugin(
        hits_path=str(hits_path), reference_path=str(ref_path),
        name="x", output_dir=str(tmp_path / "o"), is_cancelled=_CANCEL))


def test_consensus_cancel(tmp_path, source_paths):
    _assert_cancelled(lambda: tools_pipeline.consensus(
        dump_paths=source_paths, output_dir=str(tmp_path / "o"),
        persist_welford=True, is_cancelled=_CANCEL))


def test_auto_floor_cancel(tmp_path, consensus_artifacts, oracle_path):
    _assert_cancelled(lambda: tools_pipeline.auto_floor(
        variance_path=str(consensus_artifacts["variance"]),
        reference_path=str(consensus_artifacts["reference"]),
        oracle_path=str(oracle_path), num_dumps=4,
        reduce_kwargs=dict(REDUCE_KW), output_dir=str(tmp_path / "o"),
        is_cancelled=_CANCEL))


# ----------------------------------------------------------------------
# (d) consensus persist mode reproduces the Welford state contract
# ----------------------------------------------------------------------


def test_consensus_persist_matches_direct_welford(tmp_path, source_paths):
    from memdiver.core.variance import WelfordVariance

    out = tmp_path / "o"
    result = tools_pipeline.consensus(
        dump_paths=source_paths, output_dir=str(out), persist_welford=True,
    )
    # Contract: state.json = {size, num_dumps, mean_path, m2_path}
    state = json.loads((out / "state.json").read_text())
    assert set(state) == {"size", "num_dumps", "mean_path", "m2_path"}

    buffers = [Path(p).read_bytes() for p in source_paths]
    min_size = min(len(b) for b in buffers)
    welford = WelfordVariance(min_size)
    for buf in buffers:
        welford.add_dump(buf[:min_size])
    exp_mean, exp_m2, exp_n = welford.state_arrays()

    assert state["size"] == min_size
    assert state["num_dumps"] == exp_n == len(source_paths)
    mean = np.load(state["mean_path"])
    m2 = np.load(state["m2_path"])
    assert mean.shape == m2.shape == (min_size,)
    assert np.array_equal(mean, exp_mean)
    assert np.array_equal(m2, exp_m2)
    # variance.npy equals the live Welford variance.
    variance = np.load(out / "variance.npy")
    assert np.array_equal(variance, welford.variance())
    # The persisted state round-trips through WelfordVariance.from_state
    # exactly as the /refine reader does.
    rebuilt = WelfordVariance.from_state(mean, m2, int(state["num_dumps"]))
    assert np.array_equal(rebuilt.variance(), welford.variance())


# ----------------------------------------------------------------------
# (e) emit_plugin write_fields mode preserves the inferred-fields artifact
# ----------------------------------------------------------------------


def test_emit_plugin_write_fields_matches_extractor(tmp_path):
    hits_path, ref_path = _synthetic_hits_json(tmp_path)
    hit = json.loads(hits_path.read_text())["hits"][0]
    out = tmp_path / "o"
    result = tools_pipeline.emit_plugin(
        hits_path=str(hits_path), reference_path=str(ref_path),
        name="fields_plugin", output_dir=str(out), write_fields=True,
    )
    fields_path = out / "fields_plugin_fields.json"
    assert fields_path.is_file()
    expected = extract_inferred_fields(hit, variance_threshold=None)
    assert json.loads(fields_path.read_text()) == expected
    assert result["fields"] == expected
    assert result["fields_path"] == str(fields_path)


def test_emit_plugin_default_omits_fields_json(tmp_path):
    hits_path, ref_path = _synthetic_hits_json(tmp_path)
    out = tmp_path / "o"
    result = tools_pipeline.emit_plugin(
        hits_path=str(hits_path), reference_path=str(ref_path),
        name="plain_plugin", output_dir=str(out),
    )
    assert not (out / "plain_plugin_fields.json").exists()
    assert "fields" not in result


# ----------------------------------------------------------------------
# (f) consensus persist mode MSL path mirrors the runner helper byte-for-byte
# ----------------------------------------------------------------------


def _msl_fixture_paths(tmp_path: Path, count: int = 3) -> List[Path]:
    import sys

    sys.path.insert(0, str(Path(__file__).parent / "fixtures"))
    try:
        from generate_msl_fixtures import write_aslr_fixture
    finally:
        sys.path.pop(0)
    rng = np.random.default_rng(7)
    paths: List[Path] = []
    for i in range(count):
        key_bytes = rng.integers(0, 256, 32, dtype=np.uint8).tobytes()
        paths.append(write_aslr_fixture(
            tmp_path / f"d{i + 1}.msl",
            region_base=0x1000_0000 * (i + 1),
            key_bytes=key_bytes,
        ))
    return paths


def test_consensus_persist_msl_matches_runner_helper(tmp_path):
    """The native-MSL fold is a code-mirror of ``pipeline_runner._build_consensus``
    (the web pipeline's consensus stage now routes through the producer). This
    validates that mirror end-to-end: the producer's persist_welford output must
    be byte-identical to the runner helper's on the same MSL sources.
    """
    from dataclasses import dataclass, field
    from typing import Tuple as _Tuple

    from memdiver.core.dump_source import open_dump
    from memdiver.app.pipeline.pipeline_runner import _build_consensus

    paths = _msl_fixture_paths(tmp_path, count=3)

    @dataclass
    class _Ctx:
        events: List[_Tuple[str, Dict[str, Any]]] = field(default_factory=list)

        def emit(self, event: str, **fields: Any) -> None:
            self.events.append((event, fields))

        def is_cancelled(self) -> bool:
            return False

    # Runner helper: fold already-open MSL sources into <helper_dir>/consensus/*.
    helper_dir = tmp_path / "helper"
    helper_dir.mkdir()
    sources = [open_dump(p) for p in paths]
    for s in sources:
        s.open()
    try:
        _build_consensus(sources, ctx=_Ctx(), artifact_dir=helper_dir,
                         artifacts=[])
    finally:
        for s in sources:
            s.close()

    # Producer (the production web path): open the paths itself, persist_welford.
    prod_dir = tmp_path / "producer"
    tools_pipeline.consensus(dump_paths=[str(p) for p in paths],
                             output_dir=str(prod_dir), persist_welford=True)

    hc = helper_dir / "consensus"
    for fname in ("variance.npy", "reference.bin", "mean.npy", "m2.npy"):
        assert (hc / fname).read_bytes() == (prod_dir / fname).read_bytes(), fname
    hstate = json.loads((hc / "state.json").read_text())
    pstate = json.loads((prod_dir / "state.json").read_text())
    assert hstate["size"] == pstate["size"]
    assert hstate["num_dumps"] == pstate["num_dumps"] == 3
