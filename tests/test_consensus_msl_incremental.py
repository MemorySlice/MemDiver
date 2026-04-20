"""Tests for MslIncrementalBuilder — parity with batch MSL consensus."""

import sys
from pathlib import Path

import numpy as np
import pytest

from core.dump_source import open_dump
from engine.consensus_msl import build_msl_consensus, build_msl_incremental


def _fixture_paths(tmp_path: Path, count: int = 3) -> list[Path]:
    sys.path.insert(0, str(Path(__file__).parent / "fixtures"))
    try:
        from generate_msl_fixtures import write_aslr_fixture
    finally:
        sys.path.pop(0)
    rng = np.random.default_rng(7)
    paths = []
    for i in range(count):
        key_bytes = rng.integers(0, 256, 32, dtype=np.uint8).tobytes()
        path = write_aslr_fixture(
            tmp_path / f"d{i+1}.msl",
            region_base=0x1000_0000 * (i + 1),
            key_bytes=key_bytes,
        )
        paths.append(path)
    return paths


def test_incremental_matches_batch_parity(tmp_path):
    paths = _fixture_paths(tmp_path, count=3)

    with open_dump(paths[0]) as s1, open_dump(paths[1]) as s2, open_dump(paths[2]) as s3:
        batch_var, batch_total, batch_ref = build_msl_consensus(
            [s1, s2, s3], num_dumps=3,
        )

    with open_dump(paths[0]) as s1, open_dump(paths[1]) as s2, open_dump(paths[2]) as s3:
        builder = build_msl_incremental([s1, s2, s3])
        for i in range(3):
            builder.fold_next(i)
        inc_var = builder.get_live_variance()
        inc_ref = builder.get_reference()

    assert builder.total_bytes == batch_total
    assert np.allclose(batch_var, inc_var, atol=1e-3)
    assert batch_ref == inc_ref
    assert builder.num_dumps == 3


def test_incremental_non_destructive_get_live_variance(tmp_path):
    paths = _fixture_paths(tmp_path, count=3)
    with open_dump(paths[0]) as s1, open_dump(paths[1]) as s2, open_dump(paths[2]) as s3:
        builder = build_msl_incremental([s1, s2, s3])
        builder.fold_next(0)
        v1 = builder.get_live_variance().copy()
        builder.fold_next(1)
        v2 = builder.get_live_variance().copy()
        assert not np.allclose(v1, v2), "second fold should change variance"
        builder.fold_next(2)
        assert builder.num_dumps == 3


def test_empty_sources_returns_zero_layout():
    builder = build_msl_incremental([])
    assert builder.total_bytes == 0
    assert builder.num_dumps == 0
    assert builder.get_reference() == b""


def test_get_live_variance_before_any_fold(tmp_path):
    paths = _fixture_paths(tmp_path, count=2)
    with open_dump(paths[0]) as s1, open_dump(paths[1]) as s2:
        builder = build_msl_incremental([s1, s2])
        v = builder.get_live_variance()
        assert v.shape == (builder.total_bytes,)
        assert np.all(v == 0.0)
