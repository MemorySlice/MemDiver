"""Bounded-RAM single-dump analysis buffer (app/pipeline/analysis_buffer.py).

Covers:
* ``contains_bytes`` and the two ``x in dump_data`` sites it replaced
  (constraint_validator probe, SSH-2 validate_pair) on bytes AND mmap;
* strategy selection (bytes / mmap / spill / guarded read_all for encrypted);
* end-to-end ``run_file`` output identity across bytes, mmap and spill paths,
  and the encrypted-.msl refusal unless ``force_memory``;
* a tracemalloc bound for the mmap path on a 64 MiB raw dump.
"""

from __future__ import annotations

import json
import logging
import mmap
import tracemalloc
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List

import numpy as np
import pytest

from memdiver.algorithms.base import AnalysisContext, Match
from memdiver.algorithms.registry import get_registry
from memdiver.algorithms.unknown_key.constraint_validator import (
    ConstraintValidatorAlgorithm,
)
from memdiver.app.pipeline.analysis_buffer import (
    STRATEGY_BYTES,
    STRATEGY_MMAP,
    STRATEGY_SPILL,
    open_analysis_buffer,
    plan_analysis_buffer,
    spill_flat_view,
)
from memdiver.app.pipeline.analysis_task_runner import run_file
from memdiver.core.buffer_ops import contains_bytes
from memdiver.core.dump_source import open_dump
from memdiver.core.kdf import TLS13HKDF
from memdiver.core.kdf_ssh import SSH2KDF, SSH2KDFPlugin
from memdiver.core.service_errors import CapabilityError
from memdiver.msl.enums import RegionType
from memdiver.msl.writer import MslEncryptionConfig, MslWriter

PAGE = 4096
RAW_KEY = bytes(range(32))
BUFFER_LOGGER = "memdiver.app.pipeline.analysis_buffer"
ALL_ALGORITHMS = sorted(get_registry().names)


@dataclass
class _FakeCtx:
    task_id: str = "test-analysis-buffer"
    events: List[Dict[str, Any]] = field(default_factory=list)

    def emit(self, event_type: str, **fields: Any) -> None:
        self.events.append({"type": event_type, **fields})

    def is_cancelled(self) -> bool:
        return False


# ---------------------------------------------------------------------------
# helpers / fixtures
# ---------------------------------------------------------------------------


def _mapped(path: Path) -> mmap.mmap:
    with open(path, "rb") as fh:
        return mmap.mmap(fh.fileno(), 0, access=mmap.ACCESS_READ)


def _content(size: int, seed: int = 11) -> bytes:
    """Mostly structured bytes with a few random (key-like) islands."""
    rng = np.random.default_rng(seed)
    buf = bytearray(b"\x00" * size)
    buf[0:16] = b"MEMDIVER_HEADER!"
    for start in range(1024, size - 64, 8192):
        buf[start:start + 32] = rng.integers(0, 256, 32, dtype=np.uint8).tobytes()
        buf[start + 64:start + 80] = b"secret=ABCDEF012"
    return bytes(buf)


@pytest.fixture
def raw_dump(tmp_path: Path) -> Path:
    path = tmp_path / "sample.dump"
    path.write_bytes(_content(64 * 1024))
    return path


def _write_msl(path: Path, encryption=None) -> Path:
    writer = MslWriter(path, pid=4242, encryption=encryption)
    writer.add_memory_region(0x10000000, _content(8 * PAGE, seed=1),
                             region_type=RegionType.HEAP)
    writer.add_memory_region(0x7FFF0000, _content(3 * PAGE, seed=2),
                             region_type=RegionType.STACK,
                             page_states=[0, 0, 2, 0])
    writer.add_end_of_capture()
    writer.write()
    return path


@pytest.fixture
def msl_dump(tmp_path: Path) -> Path:
    return _write_msl(tmp_path / "plain.msl")


@pytest.fixture
def encrypted_msl(tmp_path: Path) -> Path:
    return _write_msl(tmp_path / "enc.msl", MslEncryptionConfig(raw_key=RAW_KEY))


def _run(dump: Path, out: Path, **extra: Any) -> Dict[str, Any]:
    params = {"artifact_dir": str(out), "dump_path": str(dump),
              "algorithms": ALL_ALGORITHMS, "user_regex": r"secret=[A-F0-9]{8}",
              **extra}
    ret = run_file(params, _FakeCtx())
    return json.loads((out / ret["artifacts"][0]["relpath"]).read_text())


def _strategy_logged(caplog) -> str:
    for rec in caplog.records:
        if rec.name == BUFFER_LOGGER:
            return rec.getMessage().split(": ", 1)[1].split(" ", 1)[0]
    return ""


# ---------------------------------------------------------------------------
# substring membership on mmap (the silent-False bug)
# ---------------------------------------------------------------------------


def test_in_operator_on_mmap_is_silently_false(raw_dump):
    """Documents WHY contains_bytes exists: ``in`` lies on an mmap."""
    mm = _mapped(raw_dump)
    try:
        assert (b"MEMDIVER" in mm) is False
        assert contains_bytes(mm, b"MEMDIVER") is True
    finally:
        mm.close()


@pytest.mark.parametrize("needle,expected", [
    (b"MEMDIVER_HEADER!", True), (b"secret=ABCDEF012", True),
    (b"\xde\xad\xbe\xef\x99", False), (b"", True),
])
def test_contains_bytes_matches_bytes_semantics(raw_dump, needle, expected):
    data = raw_dump.read_bytes()
    mm = _mapped(raw_dump)
    try:
        assert (needle in data) is expected
        assert contains_bytes(data, needle) is expected
        assert contains_bytes(mm, needle) is expected
        assert contains_bytes(memoryview(data), needle) is expected
    finally:
        mm.close()


def _dump_with(tmp_path: Path, payload: bytes) -> Path:
    path = tmp_path / "probe.dump"
    path.write_bytes(b"\x00" * 1000 + payload + b"\x00" * 1000)
    return path


def test_constraint_validator_probe_finds_derived_value_in_mmap(tmp_path):
    candidate = bytes(range(100, 132))
    derived = TLS13HKDF.hkdf_extract(b"\x00" * 32, candidate)
    path = _dump_with(tmp_path, derived)
    ctx = AnalysisContext(
        library="x", protocol_version="TLS13", phase="file",
        extra={"candidates": [Match(offset=5, length=32, confidence=0.5,
                                    label="c", data=candidate)]})
    algo = ConstraintValidatorAlgorithm()
    from_bytes = algo.run(path.read_bytes(), ctx)
    mm = _mapped(path)
    try:
        from_mmap = algo.run(mm, ctx)
    finally:
        mm.close()
    assert len(from_bytes.matches) == 1
    assert from_mmap.matches == from_bytes.matches


def test_ssh2_validate_pair_finds_derived_value_in_mmap(tmp_path):
    secret, other = bytes(range(32)), bytes(range(50, 82))
    exchange_hash = bytes(range(200, 232))
    derived = SSH2KDF.derive_key(secret, exchange_hash, "A", exchange_hash, 32)
    path = _dump_with(tmp_path, derived)
    plugin = SSH2KDFPlugin()
    kwargs = {"hash_candidates": [exchange_hash]}
    confidence = plugin.validate_pair(secret, other, path.read_bytes(), **kwargs)
    mm = _mapped(path)
    try:
        assert plugin.validate_pair(secret, other, mm, **kwargs) == confidence
    finally:
        mm.close()
    assert confidence > 0.0


# ---------------------------------------------------------------------------
# strategy selection
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("fixture,budget,strategy", [
    ("raw_dump", 1 << 40, STRATEGY_BYTES),
    ("raw_dump", 1024, STRATEGY_MMAP),
    ("msl_dump", 1 << 40, STRATEGY_BYTES),
    ("msl_dump", 1024, STRATEGY_SPILL),
    ("encrypted_msl", 1024, STRATEGY_BYTES),
])
def test_plan_strategy(request, fixture, budget, strategy):
    path = request.getfixturevalue(fixture)
    km = {"key": RAW_KEY} if fixture == "encrypted_msl" else {}
    with open_dump(path, **km) as source:
        assert plan_analysis_buffer(source, budget=budget).strategy == strategy


@pytest.mark.parametrize("fixture", ["raw_dump", "msl_dump"])
@pytest.mark.parametrize("budget", [1 << 40, 1024])
def test_buffer_equals_read_all(request, tmp_path, fixture, budget):
    path = request.getfixturevalue(fixture)
    spill_dir = tmp_path / "spill"
    with open_dump(path) as source:
        expected = source.read_all()
        with open_analysis_buffer(source, budget=budget,
                                  spill_dir=spill_dir) as buf:
            assert len(buf) == len(expected)
            assert buf[:] == expected
    assert not spill_dir.exists()  # spill file (and empty dir) removed


def test_spill_is_chunked_and_exact(msl_dump, tmp_path):
    with open_dump(msl_dump) as source:
        out = spill_flat_view(source, tmp_path, chunk_bytes=1000)
        assert out.read_bytes() == source.read_all()
    out.unlink()


def test_encrypted_over_budget_refused_unless_forced(encrypted_msl):
    with open_dump(encrypted_msl, key=RAW_KEY) as source:
        expected = source.read_all()
        with pytest.raises(CapabilityError) as info:
            with open_analysis_buffer(source, budget=1024):
                pass
        assert info.value.code == "memory_budget_exceeded"
        with open_analysis_buffer(source, budget=1024, force=True) as buf:
            assert isinstance(buf, bytes) and buf == expected


# ---------------------------------------------------------------------------
# end-to-end run_file identity
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("fixture,low_budget_strategy", [
    ("raw_dump", STRATEGY_MMAP), ("msl_dump", STRATEGY_SPILL),
])
def test_run_file_identical_across_paths(request, tmp_path, monkeypatch, caplog,
                                         fixture, low_budget_strategy):
    dump = request.getfixturevalue(fixture)
    caplog.set_level(logging.INFO, logger=BUFFER_LOGGER)
    monkeypatch.setenv("MEMDIVER_MEMORY_BUDGET_MB", "100000")
    baseline = _run(dump, tmp_path / "bytes")
    assert _strategy_logged(caplog) == STRATEGY_BYTES
    caplog.clear()
    monkeypatch.setenv("MEMDIVER_MEMORY_BUDGET_MB", "0.001")
    # force_memory: the algorithms' own working sets (tens of MiB of entropy
    # slabs) exceed a 1 KiB budget; force keeps the mmap/spill strategy.
    bounded = _run(dump, tmp_path / "bounded", force_memory=True)
    assert _strategy_logged(caplog) == low_budget_strategy
    assert bounded == baseline
    assert baseline["libraries"][0]["hits"]  # non-trivial comparison
    assert not (tmp_path / "bounded" / "analysis" / "spill").exists()


def test_run_file_encrypted_refused_then_forced(encrypted_msl, tmp_path,
                                                 monkeypatch):
    km = {"key_hex": RAW_KEY.hex()}
    baseline = _run(encrypted_msl, tmp_path / "bytes", **km)
    monkeypatch.setenv("MEMDIVER_MEMORY_BUDGET_MB", "0.001")
    with pytest.raises(CapabilityError) as info:
        _run(encrypted_msl, tmp_path / "refused", **km)
    assert info.value.code == "memory_budget_exceeded"
    forced = _run(encrypted_msl, tmp_path / "forced", force_memory=True, **km)
    assert forced == baseline
    assert not list((tmp_path / "forced").rglob("memdiver-spill-*"))


# ---------------------------------------------------------------------------
# RAM bound
# ---------------------------------------------------------------------------


def test_mmap_path_heap_peak_is_far_below_dump_size(tmp_path):
    size = 64 * 1024 * 1024
    path = tmp_path / "big.dump"
    with open(path, "wb") as fh:
        fh.truncate(size)
        fh.seek(size // 2)
        fh.write(b"secret=ABCDEF012")
    algo = get_registry().get("user_regex")
    ctx = AnalysisContext(library="big", protocol_version="unknown", phase="file",
                          extra={"user_patterns": [{"name": "r",
                                                    "regex": r"secret=[A-F0-9]{8}"}]})
    tracemalloc.start()
    try:
        with open_dump(path) as source:
            with open_analysis_buffer(source, budget=1024 * 1024) as buf:
                assert isinstance(buf, mmap.mmap)
                result = algo.run(buf, ctx)
                assert contains_bytes(buf, b"secret=")
        _, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    assert [m.offset for m in result.matches] == [size // 2]
    assert peak < 4 * 1024 * 1024, f"heap peak {peak} B"
