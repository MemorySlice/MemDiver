"""Tests for engine.correlator module."""
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from memdiver.core.models import TLSSecret
from memdiver.engine.correlator import SearchCorrelator


def _make_dump(data):
    f = tempfile.NamedTemporaryFile(suffix=".dump", delete=False)
    f.write(data)
    f.close()
    return Path(f.name)


def test_search_all_finds_key():
    key = b"\xAB" * 32
    data = b"\x00" * 100 + key + b"\x00" * 100
    path = _make_dump(data)
    secret = TLSSecret("TEST_SECRET", b"\x00" * 32, key)
    corr = SearchCorrelator()
    hits = corr.search_all(path, [secret], library="test", phase="pre_abort", run_id=1)
    assert len(hits) == 1
    assert hits[0].offset == 100
    assert hits[0].secret_type == "TEST_SECRET"


def test_search_all_periodic_needle_no_overlap():
    """Regression: a periodic needle must yield non-overlapping matches.

    Before the fix, ``start = idx + 1`` re-found the same repeating pattern at
    every shifted offset, inflating the hit count. ``\\xAA\\xAA`` inside a run of
    four 0xAA bytes must produce exactly two adjacent (non-overlapping) hits,
    not three overlapping ones.
    """
    needle = b"\xAA\xAA"
    data = b"\x00" * 10 + needle * 2 + b"\x00" * 10  # four contiguous 0xAA bytes
    path = _make_dump(data)
    secret = TLSSecret("PERIODIC", b"\x00" * 2, needle)
    corr = SearchCorrelator()
    hits = corr.search_all(path, [secret])
    assert len(hits) == 2
    assert [h.offset for h in hits] == [10, 12]


def test_search_static_periodic_needle_no_overlap():
    """Regression: unfiltered static search must also advance by needle length."""
    needle = b"\xBB\xBB"
    data = b"\x00" * 5 + needle * 3 + b"\x00" * 5  # six contiguous 0xBB bytes
    secret = TLSSecret("PERIODIC", b"\x00" * 2, needle)
    corr = SearchCorrelator()
    matches = corr.search_static(data, [secret])
    assert len(matches) == 3
    assert [m.offset for m in matches] == [5, 7, 9]


def test_empty_secret_value_does_not_hang():
    """Regression: an empty secret_value must not spin forever.

    ``bytes.find(b"", start)`` returns ``start`` (never -1), so with the
    ``start = idx + len(needle)`` advance an empty needle looped infinitely.
    An empty secret simply has no hits. If this test hangs, the guard is gone.
    """
    data = b"\x00" * 50 + b"\xCD" * 4 + b"\x00" * 50
    path = _make_dump(data)
    empty = TLSSecret("EMPTY", b"\x00" * 32, b"")
    real = TLSSecret("REAL", b"\x00" * 4, b"\xCD" * 4)
    corr = SearchCorrelator()

    # search_all (find-loop + Aho-Corasick paths) must terminate and skip the empty.
    hits = corr.search_all(path, [empty, real], library="test", phase="pre_abort", run_id=1)
    assert [h.secret_type for h in hits] == ["REAL"]

    # search_static unfiltered path must also terminate and skip the empty.
    matches = corr.search_static(data, [empty, real])
    assert [m.label for m in matches] == ["REAL"]


def test_search_all_no_match():
    data = b"\x00" * 200
    path = _make_dump(data)
    secret = TLSSecret("MISS", b"\x00" * 32, b"\xFF" * 32)
    corr = SearchCorrelator()
    hits = corr.search_all(path, [secret])
    assert len(hits) == 0


def test_search_static_unfiltered():
    key = b"\xBB" * 32
    data = b"\x00" * 50 + key + b"\x00" * 50
    secret = TLSSecret("KEY", b"\x00" * 32, key)
    corr = SearchCorrelator()
    matches = corr.search_static(data, [secret])
    assert len(matches) == 1
    assert matches[0].offset == 50


def test_search_static_with_multielement_consensus_no_truthiness_error():
    """Regression: a multi-element classifications ndarray must not trigger
    'truth value of an array is ambiguous'. Emptiness is tested via len()."""
    import numpy as np

    from memdiver.core.variance import ByteClass
    from memdiver.engine.consensus import ConsensusVector

    key = b"\xCC" * 32
    data = b"\x00" * 50 + key + b"\x00" * 50
    secret = TLSSecret("KEY", b"\x00" * 32, key)

    consensus = ConsensusVector()
    # Mark the whole buffer non-key (static) so the match survives filtering.
    consensus.classifications = np.full(
        len(data), int(ByteClass.INVARIANT), dtype=np.uint8
    )
    corr = SearchCorrelator(consensus=consensus)
    # Would raise ValueError before the fix on the `not classifications` check.
    matches = corr.search_static(data, [secret])
    assert len(matches) == 1
    assert matches[0].offset == 50


def test_search_static_empty_consensus_falls_back():
    """An empty classifications array must route to the unfiltered fallback."""
    import numpy as np

    from memdiver.engine.consensus import ConsensusVector

    key = b"\xDD" * 32
    data = b"\x00" * 50 + key + b"\x00" * 50
    secret = TLSSecret("KEY", b"\x00" * 32, key)

    consensus = ConsensusVector()
    consensus.classifications = np.array([], dtype=np.uint8)
    corr = SearchCorrelator(consensus=consensus)
    matches = corr.search_static(data, [secret])
    assert len(matches) == 1
    assert matches[0].offset == 50
