"""Tests for engine.consensus module."""
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

import numpy as np
import pytest

from memdiver.core.variance import ByteClass, VarianceThresholds, classify_variance
from memdiver.engine.consensus import ConsensusVector, INVARIANT_MAX, STRUCTURAL_MAX, POINTER_MAX
from memdiver.engine.results import StaticRegion


def _make_dumps(data_list):
    """Create temporary dump files from byte data."""
    paths = []
    for data in data_list:
        f = tempfile.NamedTemporaryFile(suffix=".dump", delete=False)
        f.write(data)
        f.close()
        paths.append(Path(f.name))
    return paths


def test_consensus_identical_dumps():
    """Identical dumps should have zero variance everywhere."""
    data = b"\x42" * 100
    paths = _make_dumps([data, data, data])
    cm = ConsensusVector()
    cm.build(paths)
    assert cm.size == 100
    assert all(v == 0.0 for v in cm.variance)
    assert all(c == ByteClass.INVARIANT for c in cm.classifications)


def test_consensus_different_dumps():
    """Different dumps should show non-zero variance."""
    d1 = b"\x00" * 50 + b"\xFF" * 50
    d2 = b"\x00" * 50 + b"\x00" * 50
    d3 = b"\x00" * 50 + b"\x80" * 50
    paths = _make_dumps([d1, d2, d3])
    cm = ConsensusVector()
    cm.build(paths)
    # First 50 bytes should be invariant
    assert all(cm.classifications[i] == ByteClass.INVARIANT for i in range(50))
    # Last 50 bytes should have non-zero variance
    assert any(cm.variance[i] > 0 for i in range(50, 100))


def test_consensus_static_regions():
    """Should find contiguous static regions."""
    data1 = b"\x00" * 100 + b"\xFF" * 32 + b"\x00" * 100
    data2 = b"\x00" * 100 + b"\x00" * 32 + b"\x00" * 100
    paths = _make_dumps([data1, data2])
    cm = ConsensusVector()
    cm.build(paths)
    static = cm.get_static_regions(min_length=32)
    assert len(static) >= 1
    assert any(r.length >= 32 for r in static)


def test_consensus_classification_counts():
    cm = ConsensusVector()
    cm.classifications = ["invariant"] * 50 + ["key_candidate"] * 10
    cm.size = 60
    counts = cm.classification_counts()
    assert counts["invariant"] == 50
    assert counts["key_candidate"] == 10


def test_consensus_too_few_dumps():
    """Should handle < 2 dumps gracefully."""
    cm = ConsensusVector()
    cm.build([])
    assert cm.size == 0


def test_consensus_incremental_matches_batch():
    """build_incremental + add_source * N + finalize must agree with build()."""
    import numpy as np

    d1 = b"\x00" * 50 + b"\xFF" * 50
    d2 = b"\x00" * 50 + b"\x00" * 50
    d3 = b"\x00" * 50 + b"\x80" * 50

    batch = ConsensusVector()
    batch.build(_make_dumps([d1, d2, d3]))

    incremental = ConsensusVector()
    incremental.build_incremental(100)
    stats = [incremental.add_source(d) for d in (d1, d2, d3)]
    incremental.finalize()

    assert incremental.size == 100
    assert incremental.num_dumps == 3
    assert np.allclose(incremental.variance, batch.variance, rtol=1e-4, atol=1e-3)
    assert list(incremental.classifications) == list(batch.classifications)
    # Live stats after every add must be monotonic in n
    assert [s[0] for s in stats] == [1, 2, 3]


# ---------------------------------------------------------------------------
# get_regions — one getter over all four classes (A2)
# ---------------------------------------------------------------------------

# A synthetic layout with one run of every class, long enough that the two
# legacy getters hit them at their own default min_length (32 / 16).
_LAYOUT = [
    (40, 0.0),        # [0, 40)    invariant
    (20, 150.0),      # [40, 60)   structural
    (20, 2500.0),     # [60, 80)   pointer
    (20, 9000.0),     # [80, 100)  key_candidate
    (40, 0.0),        # [100, 140) invariant
]


def _vector_from_layout(layout=_LAYOUT, thresholds=None):
    """A ConsensusVector carrying a hand-built variance profile."""
    values = []
    for length, variance in layout:
        values.extend([variance] * length)
    cm = ConsensusVector(thresholds=thresholds)
    cm.variance = np.array(values, dtype=np.float32)
    cm.classifications = classify_variance(cm.variance, thresholds)
    cm.size = len(values)
    cm.num_dumps = 3
    return cm


def test_get_regions_reaches_every_class():
    """STRUCTURAL and POINTER were counted but had no getter at all."""
    cm = _vector_from_layout()
    assert [(r.start, r.end) for r in cm.get_regions(ByteClass.INVARIANT)] == [
        (0, 40), (100, 140),
    ]
    assert [(r.start, r.end) for r in cm.get_regions(ByteClass.STRUCTURAL)] == [
        (40, 60),
    ]
    assert [(r.start, r.end) for r in cm.get_regions(ByteClass.POINTER)] == [
        (60, 80),
    ]
    assert [(r.start, r.end) for r in cm.get_regions(ByteClass.KEY_CANDIDATE)] == [
        (80, 100),
    ]


def test_get_regions_carries_label_and_mean_variance():
    cm = _vector_from_layout()
    (structural,) = cm.get_regions(ByteClass.STRUCTURAL)
    assert structural.classification == "structural"
    assert structural.mean_variance == 150.0
    (pointer,) = cm.get_regions(ByteClass.POINTER)
    assert pointer.classification == "pointer"
    assert pointer.mean_variance == 2500.0


def test_get_regions_accepts_a_raw_int_code():
    cm = _vector_from_layout()
    assert cm.get_regions(int(ByteClass.POINTER)) == cm.get_regions(ByteClass.POINTER)


def test_get_regions_multi_class_query_merges_adjacent_runs():
    """A union query keeps a mixed-class secret in one piece."""
    cm = _vector_from_layout()
    regions = cm.get_regions([ByteClass.POINTER, ByteClass.KEY_CANDIDATE])
    assert [(r.start, r.end) for r in regions] == [(60, 100)]
    # Labelled by the most volatile class present.
    assert regions[0].classification == "key_candidate"


def test_get_regions_min_length_filters():
    cm = _vector_from_layout()
    assert [(r.start, r.end) for r in cm.get_regions(
        ByteClass.INVARIANT, min_length=40)] == [(0, 40), (100, 140)]
    assert cm.get_regions(ByteClass.STRUCTURAL, min_length=21) == []


def test_get_regions_max_length_bounds():
    cm = _vector_from_layout()
    # Both invariant runs are 40 bytes; the structural run is 20.
    assert [(r.start, r.end) for r in cm.get_regions(
        ByteClass.INVARIANT, max_length=39)] == []
    assert [(r.start, r.end) for r in cm.get_regions(
        ByteClass.INVARIANT, max_length=40)] == [(0, 40), (100, 140)]


def test_get_regions_max_length_zero_is_unbounded():
    cm = _vector_from_layout()
    assert cm.get_regions(ByteClass.INVARIANT, max_length=0) == cm.get_regions(
        ByteClass.INVARIANT
    )


def test_get_regions_rejects_empty_class_query():
    cm = _vector_from_layout()
    with pytest.raises(ValueError, match="at least one"):
        cm.get_regions([])


def test_get_regions_honours_custom_thresholds():
    """Raising structural_max above 2500 turns the POINTER run STRUCTURAL."""
    wide = VarianceThresholds(0.0, 3000.0, 8000.0)
    cm = _vector_from_layout(thresholds=wide)
    assert [(r.start, r.end) for r in cm.get_regions(ByteClass.STRUCTURAL)] == [
        (40, 80),
    ]
    assert cm.get_regions(ByteClass.POINTER) == []


def test_legacy_getters_return_exactly_what_they_returned_before():
    """Pinned against hand-built rows, not against get_regions."""
    cm = _vector_from_layout()
    assert cm.get_static_regions() == [
        StaticRegion(start=0, end=40, mean_variance=0.0,
                     classification="invariant"),
        StaticRegion(start=100, end=140, mean_variance=0.0,
                     classification="invariant"),
    ]
    assert cm.get_volatile_regions() == [
        StaticRegion(start=80, end=100, mean_variance=9000.0,
                     classification="key_candidate"),
    ]


def test_legacy_getters_keep_their_default_min_lengths():
    """32 for static, 16 for volatile — a 20-byte run passes one, not both."""
    layout = [(20, 0.0), (20, 9000.0), (20, 0.0)]
    cm = _vector_from_layout(layout)
    assert cm.get_static_regions() == []
    assert cm.get_static_regions(min_length=20) == [
        StaticRegion(start=0, end=20, mean_variance=0.0,
                     classification="invariant"),
        StaticRegion(start=40, end=60, mean_variance=0.0,
                     classification="invariant"),
    ]
    assert cm.get_volatile_regions() == [
        StaticRegion(start=20, end=40, mean_variance=9000.0,
                     classification="key_candidate"),
    ]


# ---------------------------------------------------------------------------
# iter_regions / count_regions — the LAZY, paginated retrieval path
# ---------------------------------------------------------------------------
#
# ``get_regions`` computes a region's mean variance BEFORE any caller-side
# limit can apply, so a ``min_length=1`` STRUCTURAL query over an 11 MB slab is
# ~10^5-10^6 numpy reductions for a page the caller truncates to 200 rows.
# These pin the three properties that make the lazy path safe to page with:
# it computes only what it yields, it yields in offset order, and its cursor
# neither repeats nor drops a row.


def test_get_regions_is_exactly_the_lazy_iterator():
    """The eager getter is ``list(iter_regions(...))`` — byte for byte.

    Pinned so the two paths cannot drift into two filter chains, which is how
    a paginated total and the page it sizes stop agreeing.
    """
    cm = _vector_from_layout()
    for query in (ByteClass.INVARIANT, ByteClass.STRUCTURAL,
                  [ByteClass.POINTER, ByteClass.KEY_CANDIDATE]):
        for min_length, max_length in ((1, 0), (20, 0), (1, 20), (40, 40)):
            assert cm.get_regions(
                query, min_length=min_length, max_length=max_length,
            ) == list(cm.iter_regions(
                query, min_length=min_length, max_length=max_length,
            )), (query, min_length, max_length)


def test_iter_regions_computes_mean_variance_only_for_yielded_rows(monkeypatch):
    """THE point of the lazy path: an abandoned iterator costs one reduction.

    Counted on the real reducer, so a future rewrite that hoists the variance
    pass back out of the loop fails here rather than silently reintroducing
    the whole-slab cost.
    """
    cm = _vector_from_layout()
    calls = []
    original = ConsensusVector._region_mean_variance

    def counting(self, start, end):
        calls.append((start, end))
        return original(self, start, end)

    monkeypatch.setattr(ConsensusVector, "_region_mean_variance", counting)

    regions = cm.iter_regions([ByteClass.INVARIANT, ByteClass.STRUCTURAL])
    assert calls == [], "constructing the iterator must reduce nothing"

    first = next(regions)
    assert calls == [(0, 60)], "one reduction for the one row taken"
    assert (first.start, first.end) == (0, 60)

    next(regions)
    assert len(calls) == 2
    # ... and the eager getter over the SAME query reduces every region.
    calls.clear()
    assert len(cm.get_regions([ByteClass.INVARIANT, ByteClass.STRUCTURAL])) == 2
    assert len(calls) == 2


def test_iter_regions_yields_in_offset_order():
    cm = _vector_from_layout()
    starts = [r.start for r in cm.iter_regions(
        [ByteClass.INVARIANT, ByteClass.STRUCTURAL, ByteClass.POINTER,
         ByteClass.KEY_CANDIDATE],
    )]
    assert starts == sorted(starts)
    # One union over every class is one region: the whole slab.
    assert starts == [0]


def test_iter_regions_after_is_an_exclusive_cursor():
    """``after`` skips runs starting AT or before it — so paging by the last
    ``start`` seen can neither repeat nor drop a row."""
    cm = _vector_from_layout()
    query = [ByteClass.STRUCTURAL, ByteClass.POINTER, ByteClass.KEY_CANDIDATE]
    # One contiguous non-invariant run [40, 100) plus nothing else.
    assert [(r.start, r.end) for r in cm.iter_regions(query)] == [(40, 100)]
    assert [(r.start, r.end) for r in cm.iter_regions(query, after=39)] == [(40, 100)]
    assert list(cm.iter_regions(query, after=40)) == [], "AT the cursor is skipped"

    invariant = [(r.start, r.end) for r in cm.iter_regions(ByteClass.INVARIANT)]
    assert invariant == [(0, 40), (100, 140)]
    assert [(r.start, r.end) for r in cm.iter_regions(
        ByteClass.INVARIANT, after=0)] == [(100, 140)]
    # Paging the whole set with the cursor reproduces it exactly once.
    paged = []
    cursor = -1
    while True:
        page = list(cm.iter_regions(ByteClass.INVARIANT, after=cursor))[:1]
        if not page:
            break
        paged.append((page[0].start, page[0].end))
        cursor = page[0].start
    assert paged == invariant


def test_iter_regions_after_default_skips_nothing():
    """``-1`` is before every valid start, including ``0``."""
    cm = _vector_from_layout()
    assert cm.get_regions(ByteClass.INVARIANT) == list(
        cm.iter_regions(ByteClass.INVARIANT, after=-1))


def test_count_regions_agrees_with_the_list_it_sizes():
    """The total a paginated caller states its page against."""
    cm = _vector_from_layout()
    for query in (ByteClass.INVARIANT, ByteClass.STRUCTURAL, ByteClass.POINTER,
                  ByteClass.KEY_CANDIDATE,
                  [ByteClass.POINTER, ByteClass.KEY_CANDIDATE]):
        for min_length, max_length in ((1, 0), (20, 0), (1, 20), (41, 0)):
            assert cm.count_regions(
                query, min_length=min_length, max_length=max_length,
            ) == len(cm.get_regions(
                query, min_length=min_length, max_length=max_length,
            )), (query, min_length, max_length)


def test_count_regions_reduces_no_variance(monkeypatch):
    """A count is run LENGTHS only — paying a per-region ``.mean()`` for it
    would reintroduce exactly the cost the lazy iterator exists to avoid."""
    cm = _vector_from_layout()
    calls = []
    monkeypatch.setattr(
        ConsensusVector, "_region_mean_variance",
        lambda self, start, end: calls.append((start, end)) or 0.0,
    )

    assert cm.count_regions(ByteClass.INVARIANT) == 2
    assert calls == []


def test_count_regions_accepts_names_and_raw_codes_like_get_regions():
    cm = _vector_from_layout()
    assert cm.count_regions(int(ByteClass.POINTER)) == cm.count_regions(
        ByteClass.POINTER)
    with pytest.raises(ValueError, match="at least one"):
        cm.count_regions([])


# ---------------------------------------------------------------------------
# _class_runs memoization
# ---------------------------------------------------------------------------
#
# `count_regions` then `iter_regions` is the SHAPE of every paginated region
# listing, and each used to run its own whole-slab pass (a class mask plus a
# run scan — a measured ~370 ms over 211 M bytes), so page 20 cost exactly
# what page 1 cost. The runs are a pure function of the classification array,
# which is immutable once a build produced it; these tests pin both halves of
# that — the reuse, and the invalidation that makes the reuse safe.


def test_count_then_iter_runs_the_whole_slab_pass_once(monkeypatch):
    """The shape of every paginated region listing, charged once."""
    import memdiver.engine.consensus as consensus_module

    cm = _vector_from_layout()
    passes = []
    real = consensus_module.find_contiguous_runs

    def _counting(*args, **kwargs):
        passes.append(args[1:])
        return real(*args, **kwargs)

    monkeypatch.setattr(consensus_module, "find_contiguous_runs", _counting)
    total = cm.count_regions(ByteClass.INVARIANT)
    rows = list(cm.iter_regions(ByteClass.INVARIANT))
    assert total == len(rows) == 2
    assert len(passes) == 1
    assert len(cm._class_runs_cache) == 1
    # And a later page pays nothing either.
    assert list(cm.iter_regions(ByteClass.INVARIANT, after=0)) != []
    assert len(passes) == 1


def test_class_runs_caches_each_class_tuple_separately():
    cm = _vector_from_layout()
    invariant = cm._class_runs((ByteClass.INVARIANT,))
    pointer = cm._class_runs((ByteClass.POINTER,))
    union = cm._class_runs((ByteClass.INVARIANT, ByteClass.POINTER))
    assert invariant == [(0, 40), (100, 140)]
    assert pointer == [(60, 80)]
    assert union != invariant and union != pointer
    assert len(cm._class_runs_cache) == 3
    assert cm._class_runs((ByteClass.INVARIANT,)) is invariant


def test_reassigning_classifications_drops_the_cached_runs():
    """A stale cache would describe the PREVIOUS array's runs."""
    cm = _vector_from_layout()
    assert cm._class_runs((ByteClass.INVARIANT,)) == [(0, 40), (100, 140)]
    cm.classifications = np.full(140, int(ByteClass.INVARIANT), dtype=np.uint8)
    assert cm._class_runs_cache == {}
    assert cm._class_runs((ByteClass.INVARIANT,)) == [(0, 140)]


def test_finalize_drops_the_cached_runs():
    """The incremental path replaces classifications outside the setter."""
    cm = ConsensusVector()
    cm.build_incremental(8)
    cm.add_source(b"\x00" * 8)
    cm.add_source(b"\x00" * 8)
    cm.finalize()
    before = cm._class_runs((ByteClass.INVARIANT,))
    assert before == [(0, 8)]
    cm.build_incremental(8)
    assert cm._class_runs_cache == {}
    assert cm._class_runs((ByteClass.INVARIANT,)) == []


# ---------------------------------------------------------------------------
# The VA / VAS walks (bisect keys + the defensive sort)
# ---------------------------------------------------------------------------


def _aligned_vector(rows=4, page_size=16):
    """A vector with a hand-built two-dump aligned layout, one row per page."""
    cm = ConsensusVector()
    cm.msl_layout = [
        (row * page_size, page_size,
         [0x1000 + row * page_size, 0x9000 + row * page_size])
        for row in range(rows)
    ]
    cm.size = rows * page_size
    cm.num_dumps = 2
    cm.variance = np.zeros(cm.size, dtype=np.float32)
    cm.classifications = np.zeros(cm.size, dtype=np.uint8)
    return cm


def test_va_starts_is_cached_and_matches_the_va_index():
    cm = _aligned_vector()
    starts = cm._va_starts(0)
    assert starts == [entry[0] for entry in cm._va_index_for(0)]
    assert cm._va_starts(0) is starts
    # Per dump, not shared between dumps.
    assert cm._va_starts(1) == [entry[0] for entry in cm._va_index_for(1)]
    assert cm._va_starts(1) != starts


def test_walk_vas_window_is_order_insensitive():
    """The ascending-vas_offset contract is bisected, but still only a contract.

    A caller that yields the runs in another order must get the same answer,
    which is why the defensive sort survives the fast path that skips it.
    """
    cm = _aligned_vector()
    runs = [(0x1000, 32, 0), (0x9000, 32, 32)]
    ascending = list(cm._walk_vas_window(0, runs, 16, 32))
    shuffled = list(cm._walk_vas_window(0, list(reversed(runs)), 16, 32))
    assert ascending == shuffled
    assert ascending, "the window overlaps both runs and must yield something"


def test_walk_vas_window_finds_a_run_it_has_to_skip_past():
    """The near end is bisected; the run before the target must not be lost."""
    cm = _aligned_vector(rows=8)
    runs = [(0x1000, 64, 0), (0x1040, 64, 64)]
    walked = list(cm._walk_vas_window(0, runs, 80, 16))
    assert walked
    assert all(offset + run <= 16 for offset, run, _slab, _row in walked)
    # Every byte of the window is accounted for exactly once.
    assert sum(run for _offset, run, _slab, _row in walked) == 16
