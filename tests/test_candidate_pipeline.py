"""Tests for engine.candidate_pipeline — search-space reduction."""

import numpy as np
import pytest

from memdiver.core.variance import ByteClass, VarianceThresholds
from memdiver.engine.candidate_pipeline import (
    DEFAULT_MIN_VARIANCE,
    MIN_N_FOR_VARIANCE,
    SCORE_WEIGHTS,
    ReductionResult,
    reduce_search_space,
    resolve_byte_classes,
)


def _synth_dump(size: int, key_offset: int, key_length: int, seed: int = 42):
    rng = np.random.default_rng(seed)
    data = bytearray(size)
    key = rng.integers(0, 256, key_length, dtype=np.uint8).tobytes()
    data[key_offset:key_offset + key_length] = key
    variance = np.zeros(size, dtype=np.float32)
    variance[key_offset:key_offset + key_length] = 15000.0
    return bytes(data), variance


def test_finds_planted_key_at_n_threshold():
    data, variance = _synth_dump(1024, 256, 32)
    result = reduce_search_space(variance, data, num_dumps=5)
    assert isinstance(result, ReductionResult)
    assert not result.fallback_entropy_only
    assert len(result.regions) == 1
    assert result.regions[0].offset == 256
    assert result.regions[0].length == 32
    assert result.stages.high_entropy == 32


def test_n_below_threshold_falls_back_to_entropy_only():
    data, variance = _synth_dump(1024, 256, 32)
    result = reduce_search_space(variance, data, num_dumps=1)
    assert result.fallback_entropy_only
    assert result.num_dumps < MIN_N_FOR_VARIANCE
    assert result.stages.variance == len(variance)


def test_unreachable_entropy_threshold_raises():
    data, variance = _synth_dump(1024, 256, 32)
    with pytest.raises(ValueError, match="log2"):
        reduce_search_space(
            variance, data, num_dumps=5,
            entropy_window=32, entropy_threshold=6.0,
        )


def test_variance_size_mismatch_raises():
    data = b"\x00" * 512
    variance = np.zeros(1024, dtype=np.float32)
    with pytest.raises(ValueError, match="reference dump shorter"):
        reduce_search_space(variance, data, num_dumps=5)


def test_serializes_round_trip():
    data, variance = _synth_dump(1024, 256, 32)
    result = reduce_search_space(variance, data, num_dumps=5)
    d = result.to_dict()
    assert d["N"] == 5
    assert d["fallback_entropy_only"] is False
    assert d["stages"]["total_bytes"] == 1024
    assert len(d["regions"]) == 1
    assert d["regions"][0]["offset"] == 256
    assert d["thresholds"]["alignment"] == 8


def test_empty_dump():
    variance = np.array([], dtype=np.float32)
    result = reduce_search_space(variance, b"", num_dumps=5)
    assert result.regions == []
    assert result.stages.total_bytes == 0


# ---------------------------------------------------------------------------
# ByteClass filter + max_region (A2)
# ---------------------------------------------------------------------------


def _two_class_dump(size: int = 1024, key_offset: int = 256,
                    pointer_offset: int = 512, length: int = 32):
    """One KEY_CANDIDATE region and one POINTER region, both high-entropy.

    Each region holds ``length`` distinct byte values, so its window entropy is
    log2(32) = 5.0 and both clear the 4.5 entropy gate; only the variance band
    tells them apart.
    """
    data = bytearray(size)
    data[key_offset:key_offset + length] = bytes(range(length))
    data[pointer_offset:pointer_offset + length] = bytes(
        range(length, 2 * length)
    )
    variance = np.zeros(size, dtype=np.float32)
    variance[key_offset:key_offset + length] = 15000.0    # KEY_CANDIDATE
    variance[pointer_offset:pointer_offset + length] = 1000.0   # POINTER
    return bytes(data), variance


def test_classes_none_is_byte_identical_to_the_pre_filter_behaviour():
    """Pinned to the values this call produced before ``classes`` existed."""
    data, variance = _synth_dump(1024, 256, 32)
    result = reduce_search_space(variance, data, num_dumps=5)
    assert result.stages.total_bytes == 1024
    assert result.stages.variance == 32
    assert result.stages.aligned == 32
    assert result.stages.high_entropy == 32
    assert [(r.offset, r.length, r.mean_variance) for r in result.regions] == [
        (256, 32, 15000.0),
    ]
    assert result.thresholds["min_variance"] == 3000.0
    assert result.thresholds["classes"] is None
    assert result.thresholds["max_region"] == 0
    # The new stage is a pass-through when no class is requested.
    assert result.stages.byte_class == result.stages.variance


def test_class_filter_keeps_only_the_requested_class():
    data, variance = _two_class_dump()
    both = reduce_search_space(variance, data, num_dumps=5, min_variance=100.0)
    assert [r.offset for r in both.regions] == [256, 512]

    keys_only = reduce_search_space(
        variance, data, num_dumps=5, min_variance=100.0,
        classes=[ByteClass.KEY_CANDIDATE],
    )
    assert [r.offset for r in keys_only.regions] == [256]
    assert keys_only.thresholds["classes"] == ["key_candidate"]


def test_class_filter_reports_its_own_stage():
    data, variance = _two_class_dump()
    result = reduce_search_space(
        variance, data, num_dumps=5, min_variance=100.0,
        classes=[ByteClass.KEY_CANDIDATE],
    )
    assert result.stages.variance == 64      # both regions clear the float floor
    assert result.stages.byte_class == 32    # the class gate drops the pointer run
    assert result.stages.high_entropy == 32


def test_class_filter_composes_with_min_variance_instead_of_replacing_it():
    """KEY_CANDIDATE bytes below a raised float floor are still dropped."""
    data, variance = _two_class_dump()
    result = reduce_search_space(
        variance, data, num_dumps=5, min_variance=20000.0,
        classes=[ByteClass.KEY_CANDIDATE],
    )
    assert result.stages.variance == 0
    assert result.stages.byte_class == 0
    assert result.regions == []


def test_multi_class_query_keeps_both_bands():
    data, variance = _two_class_dump()
    result = reduce_search_space(
        variance, data, num_dumps=5, min_variance=100.0,
        classes=[ByteClass.POINTER, ByteClass.KEY_CANDIDATE],
    )
    assert [r.offset for r in result.regions] == [256, 512]
    assert result.thresholds["classes"] == ["pointer", "key_candidate"]


def test_class_filter_honours_custom_thresholds():
    """Raising structural_max above 15000 makes the key run STRUCTURAL."""
    data, variance = _two_class_dump()
    result = reduce_search_space(
        variance, data, num_dumps=5, min_variance=100.0,
        classes=[ByteClass.KEY_CANDIDATE],
        class_thresholds=VarianceThresholds(0.0, 20000.0, 30000.0),
    )
    assert result.regions == []
    assert result.stages.byte_class == 0


def test_class_filter_is_skipped_in_the_entropy_only_fallback():
    data, variance = _two_class_dump()
    result = reduce_search_space(
        variance, data, num_dumps=1, classes=[ByteClass.KEY_CANDIDATE],
    )
    assert result.fallback_entropy_only
    assert result.stages.byte_class == result.stages.variance == len(variance)


def test_max_region_drops_regions_that_are_too_long():
    data, variance = _synth_dump(1024, 256, 32)
    assert reduce_search_space(
        variance, data, num_dumps=5, max_region=31).regions == []
    kept = reduce_search_space(variance, data, num_dumps=5, max_region=32)
    assert [r.offset for r in kept.regions] == [256]


def test_max_region_zero_is_unbounded():
    data, variance = _synth_dump(1024, 256, 32)
    bounded = reduce_search_space(variance, data, num_dumps=5, max_region=0)
    assert [r.offset for r in bounded.regions] == [256]


# ---------------------------------------------------------------------------
# Ranking (A3)
# ---------------------------------------------------------------------------


def _four_region_dump(size: int = 2048):
    """Four surviving regions whose RANK order is not their OFFSET order.

    Planted so the ordering assertions below are hand-derivable rather than
    read back off the implementation:

    * ``128``  — 512 bytes, KEY_CANDIDATE, maximal entropy. Everything about it
      is ideal except its length, which is 8x a plausible key.
    * ``768``  — 32 bytes, POINTER-band variance. Right size, wrong band.
    * ``1024`` — 16 bytes, KEY_CANDIDATE, 16 distinct byte values.
    * ``1280`` — a byte-for-byte duplicate of ``1024``, so the two score
      IDENTICALLY and the tie-break is the only thing separating them.
    """
    data = bytearray(size)
    variance = np.zeros(size, dtype=np.float32)
    data[128:640] = bytes(range(256)) * 2
    variance[128:640] = 15000.0
    data[768:800] = bytes(range(200, 232))
    variance[768:800] = 1000.0
    data[1024:1040] = bytes(range(16))
    variance[1024:1040] = 15000.0
    data[1280:1296] = bytes(range(16))
    variance[1280:1296] = 15000.0
    return bytes(data), variance


#: Filter settings that keep every planted run of ``_four_region_dump`` whole.
_FOUR_REGION_KWARGS = dict(
    num_dumps=5, min_variance=100.0, block_size=16,
    entropy_window=16, entropy_threshold=3.5, min_region=8,
)


def test_order_offset_reproduces_the_pre_ranking_ordering():
    """Pinned to where the runs were PLANTED, not to what the ranker returns."""
    data, variance = _four_region_dump()
    result = reduce_search_space(variance, data, **_FOUR_REGION_KWARGS)
    assert [(r.offset, r.length) for r in result.regions] == [
        (128, 512), (768, 32), (1024, 16), (1280, 16),
    ]
    assert result.thresholds["order"] == "offset"


def test_order_is_offset_by_default():
    """The default must not reorder ``candidates.json`` under existing callers."""
    import inspect
    assert inspect.signature(reduce_search_space).parameters["order"].default == "offset"


def test_order_rank_sorts_by_descending_score():
    data, variance = _four_region_dump()
    result = reduce_search_space(variance, data, order="rank", **_FOUR_REGION_KWARGS)
    assert [r.offset for r in result.regions] == [1024, 1280, 128, 768]
    scores = [r.score for r in result.regions]
    assert scores == sorted(scores, reverse=True)
    assert [r.rank for r in result.regions] == [1, 2, 3, 4]


def test_a_key_sized_region_outranks_a_long_one_that_is_otherwise_identical():
    """The 512-byte blob at 128 matches the 16-byte run at 1024 on class,
    variance and entropy; only length separates them, and length must not be a
    reward for being big."""
    data, variance = _four_region_dump()
    result = reduce_search_space(variance, data, **_FOUR_REGION_KWARGS)
    by_offset = {r.offset: r for r in result.regions}
    assert by_offset[1024].rank < by_offset[128].rank
    assert by_offset[1024].score_components.length == 1.0
    assert by_offset[128].score_components.length < 1.0


def test_ties_are_broken_by_offset():
    data, variance = _four_region_dump()
    result = reduce_search_space(variance, data, **_FOUR_REGION_KWARGS)
    by_offset = {r.offset: r for r in result.regions}
    assert by_offset[1024].score == by_offset[1280].score
    assert by_offset[1024].rank < by_offset[1280].rank


def test_ranking_is_reproducible_across_runs():
    data, variance = _four_region_dump()
    first = reduce_search_space(variance, data, order="rank", **_FOUR_REGION_KWARGS)
    second = reduce_search_space(variance, data, order="rank", **_FOUR_REGION_KWARGS)
    assert ([(r.offset, r.rank, r.score) for r in first.regions]
            == [(r.offset, r.rank, r.score) for r in second.regions])


def test_rank_is_stamped_in_both_orders():
    """An offset-ordered consumer still gets the ranking, and can sort itself."""
    data, variance = _four_region_dump()
    offsets = reduce_search_space(variance, data, **_FOUR_REGION_KWARGS)
    ranked = reduce_search_space(variance, data, order="rank", **_FOUR_REGION_KWARGS)
    assert sorted(r.rank for r in offsets.regions) == [1, 2, 3, 4]
    assert ({(r.offset, r.rank) for r in offsets.regions}
            == {(r.offset, r.rank) for r in ranked.regions})


def test_score_is_the_weighted_sum_of_the_components_on_the_row():
    data, variance = _four_region_dump()
    result = reduce_search_space(variance, data, **_FOUR_REGION_KWARGS)
    assert result.thresholds["score_weights"] == SCORE_WEIGHTS
    for region in result.regions:
        components = region.score_components.to_dict()
        assert set(components) == set(SCORE_WEIGHTS)
        assert all(0.0 <= v <= 1.0 for v in components.values())
        recomputed = sum(SCORE_WEIGHTS[k] * v for k, v in components.items())
        assert region.score == pytest.approx(recomputed, abs=1e-12)


def test_every_serialized_row_carries_its_score_provenance():
    data, variance = _four_region_dump()
    payload = reduce_search_space(variance, data, **_FOUR_REGION_KWARGS).to_dict()
    for row in payload["regions"]:
        assert set(row) >= {
            "offset", "length", "mean_entropy", "mean_variance",
            "region_entropy", "class_counts", "rank", "score",
            "score_components",
        }
        weights = payload["thresholds"]["score_weights"]
        recomputed = sum(weights[k] * v for k, v in row["score_components"].items())
        assert row["score"] == pytest.approx(recomputed, abs=1e-12)


def test_class_counts_report_a_mixed_region_rather_than_one_label():
    """A region straddling two bands must report BOTH — real key material is
    class-mixed, and a single dominant label would hide that."""
    data, variance = _four_region_dump()
    variance[768:784] = 15000.0     # half the POINTER run becomes KEY_CANDIDATE
    result = reduce_search_space(variance, data, **_FOUR_REGION_KWARGS)
    mixed = next(r for r in result.regions if r.offset == 768)
    assert mixed.class_counts == {
        "invariant": 0, "structural": 0, "pointer": 16, "key_candidate": 16,
    }
    assert sum(mixed.class_counts.values()) == mixed.length


def test_class_counts_are_empty_in_the_entropy_only_fallback():
    """At N < 3 the pipeline has already declared variance unusable; it must
    not turn round and report a classification derived from it."""
    data, variance = _four_region_dump()
    result = reduce_search_space(variance, data, num_dumps=1, min_variance=100.0,
                                 block_size=16, entropy_window=16,
                                 entropy_threshold=3.5, min_region=8)
    assert result.fallback_entropy_only
    assert result.regions
    for region in result.regions:
        assert region.class_counts == {}
        assert region.score_components.byte_class == 0.0
        assert region.rank >= 1


def test_invalid_order_raises():
    data, variance = _synth_dump(1024, 256, 32)
    with pytest.raises(ValueError, match="order="):
        reduce_search_space(variance, data, num_dumps=5, order="score")


def test_resolve_byte_classes_accepts_names_codes_and_enums():
    assert resolve_byte_classes("key_candidate") == (ByteClass.KEY_CANDIDATE,)
    assert resolve_byte_classes("KEY_CANDIDATE") == (ByteClass.KEY_CANDIDATE,)
    assert resolve_byte_classes(3) == (ByteClass.KEY_CANDIDATE,)
    assert resolve_byte_classes([ByteClass.POINTER, "key_candidate"]) == (
        ByteClass.POINTER, ByteClass.KEY_CANDIDATE,
    )


def test_resolve_byte_classes_rejects_an_unknown_name():
    with pytest.raises(ValueError, match="unknown byte class"):
        resolve_byte_classes(["key_candidat"])


# ---------------------------------------------------------------------------
# Real corpus: the ranked list must contain the real key, unaided (A3)
# ---------------------------------------------------------------------------

#: The one run this assertion is anchored to: eight 11,223,040-byte dumps of a
#: single OpenSSL TLS 1.2 session, whose ``keylog.csv`` puts a 48-byte
#: CLIENT_RANDOM master secret at this offset in every one of them.
_TLS12_RUN = (
    "TLS12/100_iterations_Abort/openssl/openssl_run_12_1"
)
_TLS12_KEY_OFFSET = 370_672
_TLS12_KEY_LENGTH = 48
#: Measured rank of that region among the 25 candidates the all-non-invariant
#: query yields. Guarded as a ceiling, not pinned to an exact value: the point
#: is that a blind analyst reads the real key off the first page of the list,
#: not that it holds one particular row. Every region above it on this corpus
#: is itself high-entropy secret-looking material (rank 2 CONTAINS the
#: session's client_random), so this is a headroom bound, not slack.
_TLS12_KEY_MAX_RANK = 12


def _tls12_master_secret(run_dir) -> bytes:
    """The run's real 48-byte master secret, read from its ``keylog.csv``.

    Ground truth for the ASSERTION only — the reduction below is handed the
    dumps and nothing else, which is the whole point of the test.
    """
    import csv

    with open(run_dir / "keylog.csv", newline="") as handle:
        for row in csv.DictReader(handle):
            fields = row["line"].split()
            if fields and fields[0] == "CLIENT_RANDOM":
                return bytes.fromhex(fields[2])
    raise AssertionError(f"no CLIENT_RANDOM line in {run_dir / 'keylog.csv'}")


@pytest.mark.requires_dataset
def test_real_tls12_key_is_in_the_ranked_list_without_a_keylog(capsys):
    """End-to-end on real dumps: eight phases of one OpenSSL TLS 1.2 run go in,
    and the ranked candidate list contains the run's real master secret —
    byte-exact, with no keylog, oracle or pcap supplied to the pipeline.

    ``requires_dataset`` but deliberately NOT ``slow``: ``slow`` is deselected
    by the default addopts, so marking it would evict the one assertion that
    proves the differential workflow works on real memory from ``make test``.
    """
    from pathlib import Path

    from memdiver.core.variance import compute_variance
    from tests.fixtures.tls_ground_truth import tls_dumps_dir

    run_dir = Path(tls_dumps_dir()) / _TLS12_RUN
    dumps = sorted(run_dir.glob("*.dump"))
    if len(dumps) < MIN_N_FOR_VARIANCE:
        pytest.skip(f"TLS 1.2 reference run not present under {run_dir}")

    buffers = [p.read_bytes() for p in dumps]
    size = min(len(b) for b in buffers)
    reference = buffers[0]

    # Ground truth, established independently of the reduction.
    secret = _tls12_master_secret(run_dir)
    assert len(secret) == _TLS12_KEY_LENGTH
    assert reference.find(secret) == _TLS12_KEY_OFFSET

    variance = compute_variance(buffers, size)
    result = reduce_search_space(
        variance, reference, len(buffers),
        # All-non-invariant, which is what real key material actually is: these
        # 48 bytes classify as 22 KEY_CANDIDATE + 18 POINTER + 8 STRUCTURAL, so
        # a KEY_CANDIDATE-only query returns fragments INSIDE the key instead
        # of the key. min_variance must drop to 0.0 or its 3000.0 default
        # re-imposes the KEY_CANDIDATE floor the class query just widened.
        classes=[ByteClass.STRUCTURAL, ByteClass.POINTER, ByteClass.KEY_CANDIDATE],
        min_variance=0.0,
        min_region=8,
        order="rank",
    )

    hits = [r for r in result.regions
            if r.offset <= _TLS12_KEY_OFFSET < r.offset + r.length]
    assert hits, (
        f"the real key at {_TLS12_KEY_OFFSET} is in none of "
        f"{len(result.regions)} candidate regions"
    )
    key_region = hits[0]
    # Byte-exact on both ends: the region IS the key, not a run overlapping it.
    assert (key_region.offset, key_region.length) == (
        _TLS12_KEY_OFFSET, _TLS12_KEY_LENGTH,
    )
    assert key_region.class_counts == {
        "invariant": 0, "structural": 8, "pointer": 18, "key_candidate": 22,
    }
    with capsys.disabled():
        print(
            f"\nreal TLS 1.2 master secret at {_TLS12_KEY_OFFSET}: "
            f"rank {key_region.rank} of {len(result.regions)} "
            f"(score {key_region.score:.4f}, "
            f"components {key_region.score_components.to_dict()})"
        )
    assert key_region.rank <= _TLS12_KEY_MAX_RANK, (
        f"the real key ranked {key_region.rank} of {len(result.regions)}; "
        f"the score has stopped surfacing it"
    )
    assert result.regions[key_region.rank - 1] is key_region


class TestMinVarianceResolvesAgainstClasses:
    """The float floor must not silently undo an explicit class query.

    ``DEFAULT_MIN_VARIANCE`` is exactly ``POINTER_MAX``, the KEY_CANDIDATE lower
    bound. Before this resolution existed, widening ``classes`` to all three
    non-invariant bands left that floor standing and returned KEY_CANDIDATE
    bytes anyway -- measured on the real corpus, 7 regions instead of 25, with
    the actual TLS secret absent from both the result and any warning.
    """

    def _variance(self) -> np.ndarray:
        # One byte per band: invariant, structural, pointer, key_candidate.
        return np.array([0.0] * 8 + [100.0] * 8 + [1000.0] * 8 + [9000.0] * 8,
                        dtype=np.float64)

    def _reduce(self, **kwargs):
        return reduce_search_space(
            self._variance(), bytes(32), 4,
            alignment=1, block_size=4, density_threshold=0.0,
            entropy_threshold=0.0, min_region=1, **kwargs,
        )

    def test_no_classes_keeps_the_historical_floor(self) -> None:
        assert self._reduce().thresholds["min_variance"] == DEFAULT_MIN_VARIANCE

    def test_naming_classes_drops_the_floor_to_zero(self) -> None:
        result = self._reduce(classes=[ByteClass.STRUCTURAL, ByteClass.POINTER])
        assert result.thresholds["min_variance"] == 0.0

    def test_an_explicit_floor_still_wins_over_the_class_query(self) -> None:
        """"KEY_CANDIDATE bytes, but only above 5000" stays expressible."""
        result = self._reduce(classes=[ByteClass.KEY_CANDIDATE], min_variance=5000.0)
        assert result.thresholds["min_variance"] == 5000.0

    def test_the_resolved_floor_is_published_never_the_sentinel(self) -> None:
        for kwargs in ({}, {"classes": [ByteClass.POINTER]}):
            assert self._reduce(**kwargs).thresholds["min_variance"] is not None

    def test_the_structural_band_is_reachable_which_the_old_floor_forbade(self) -> None:
        """The regression in one assertion.

        A STRUCTURAL byte has variance 100, far below the 3000 floor, so under
        the old default this query returned nothing at all -- the class filter
        looked broken and said nothing about why.
        """
        result = self._reduce(classes=[ByteClass.STRUCTURAL])
        assert result.regions, "STRUCTURAL bytes unreachable: the floor undid the class query"
        assert all(r.offset >= 8 and r.offset < 16 for r in result.regions)
