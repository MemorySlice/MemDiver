"""Tests for the presence-only search seam.

``find_first`` is the cheap counterpart of ``find_all``: it answers "is this
secret present in this dump?" with a single ``.find()`` and an early exit
instead of scanning a multi-gigabyte view to completion. Its contract is
agreement: for every source, every view and every needle,
``find_first(...)`` must equal ``find_all(...)[0]`` on a hit and be ``None``
whenever ``find_all`` returns an empty list. These tests pin that agreement
across every source implementation rather than re-asserting hard-coded offsets.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from memdiver.core.dump_io import DumpReader, find_all_offsets, find_first_offset
from memdiver.core.dump_source import (
    DumpSource,
    MslDumpSource,
    RawDumpSource,
    _find_all_in_bytes,
    _find_first_in_bytes,
    find_first_in,
    open_dump,
)
from memdiver.core.dump_sources.gcore import GCoreDumpSource
from memdiver.core.dump_sources.gdb_raw import GdbRawDumpSource
from memdiver.core.dump_sources.lldb_raw import LldbRawDumpSource
from tests.fixtures import synth_elf_core, synth_raw_regions
from tests.fixtures.generate_msl_fixtures import generate_msl_file

# Needle that must not occur in any fixture.
MISSING = b"NO_SUCH_NEEDLE_0123456789_ZZZZ"


# ---------------------------------------------------------------------------
# find_first_offset — the shared primitive
# ---------------------------------------------------------------------------


class TestFindFirstOffset:
    BUF = b"abXXcdXXef"

    def test_agrees_with_find_all_first_hit(self):
        assert find_first_offset(self.BUF, b"XX") == find_all_offsets(self.BUF, b"XX")[0]
        assert find_first_offset(self.BUF, b"XX") == 2

    def test_returns_none_on_miss(self):
        assert find_first_offset(self.BUF, MISSING) is None
        assert find_all_offsets(self.BUF, MISSING) == []

    def test_needle_at_offset_zero(self):
        assert find_first_offset(self.BUF, b"ab") == 0

    def test_needle_at_eof(self):
        assert find_first_offset(self.BUF, b"ef") == len(self.BUF) - 2

    def test_whole_buffer_as_needle(self):
        assert find_first_offset(self.BUF, self.BUF) == 0

    def test_needle_longer_than_buffer(self):
        assert find_first_offset(self.BUF, self.BUF + b"!") is None

    def test_overlapping_needle_reports_only_the_first(self):
        assert find_all_offsets(b"aaaa", b"aa") == [0, 1, 2]
        assert find_first_offset(b"aaaa", b"aa") == 0

    def test_empty_needle_reports_no_match_in_both_primitives(self):
        """An empty needle is a caller error, not a query with a degenerate
        answer, and BOTH primitives report "absent" so they can be swapped
        freely. Reporting offset 0 (what a bare ``b"".find`` returns) would let
        an empty secret masquerade as a hit at the start of every dump in a
        corpus sweep -- a false positive in the place it is most expensive to
        notice. The pair must agree: a caller must never be able to get
        "present" from one and "absent" from the other for the same input."""
        assert find_all_offsets(self.BUF, b"") == []
        assert find_first_offset(self.BUF, b"") is None

    def test_empty_needle_terminates_over_an_mmap(self, tmp_path):
        """REGRESSION GUARD for an unbounded loop.

        ``mmap.find(b"", start)`` CLAMPS an out-of-range ``start`` to the buffer
        length instead of returning -1 (asserted below), so the
        ``start = idx + 1`` cursor in ``find_all_offsets`` could never escape:
        it appended the same offset forever, hanging the process and growing the
        result list without bound. ``bytes`` happens to terminate on the same
        input, so this only ever reproduced on the mmap-backed sources -- which
        are exactly the ones a corpus sweep uses. Both primitives now guard the
        empty needle up front."""
        import mmap

        path = tmp_path / "probe.bin"
        path.write_bytes(self.BUF)
        with open(path, "rb") as fh:
            mm = mmap.mmap(fh.fileno(), 0, access=mmap.ACCESS_READ)
            try:
                # The clamping behaviour that made the loop unbounded.
                assert mm.find(b"", len(self.BUF) + 5) == len(self.BUF)  # never -1
                # Guarded: terminates, and agrees with the bytes path.
                assert find_all_offsets(mm, b"") == []
                assert find_first_offset(mm, b"") is None
                # Real needles are unaffected.
                assert find_first_offset(mm, b"XX") == 2
                assert find_first_offset(mm, MISSING) is None
            finally:
                mm.close()

    def test_empty_buffer(self):
        assert find_first_offset(b"", b"x") is None
        # Empty needle is "absent" regardless of the buffer (see
        # test_empty_needle_reports_no_match_in_both_primitives).
        assert find_first_offset(b"", b"") is None
        assert find_all_offsets(b"", b"") == []

    def test_dump_source_helper_delegates(self):
        assert _find_first_in_bytes(b"aaaa", b"aa") == find_first_offset(b"aaaa", b"aa")
        assert _find_first_in_bytes(b"aaaa", b"aa") == _find_all_in_bytes(b"aaaa", b"aa")[0]
        assert _find_first_in_bytes(b"abc", MISSING) is None


# ---------------------------------------------------------------------------
# DumpReader
# ---------------------------------------------------------------------------


@pytest.fixture
def raw_path(tmp_path: Path) -> Path:
    p = tmp_path / "test.dump"
    p.write_bytes(b"\xAA" * 512 + b"MARKER" + b"\xBB" * 512 + b"TAIL")
    return p


class TestDumpReaderFindFirst:
    def test_agrees_with_find_all(self, raw_path):
        with DumpReader(raw_path) as reader:
            # b"" is deliberately excluded: find_all over an mmap with an empty
            # needle does not terminate (see find_first_offset's docstring).
            for needle in (b"MARKER", b"TAIL", b"\xAA" * 8, MISSING):
                hits = reader.find_all(needle)
                first = reader.find_first(needle)
                assert first == (hits[0] if hits else None), needle

    def test_empty_needle_reports_absent(self, raw_path):
        with DumpReader(raw_path) as reader:
            assert reader.find_first(b"") is None
            assert reader.find_all(b"") == []

    def test_needle_at_offset_zero(self, raw_path):
        with DumpReader(raw_path) as reader:
            assert reader.find_first(b"\xAA") == 0

    def test_needle_at_eof(self, raw_path):
        size = raw_path.stat().st_size
        with DumpReader(raw_path) as reader:
            assert reader.find_first(b"TAIL") == size - 4

    def test_miss_returns_none(self, raw_path):
        with DumpReader(raw_path) as reader:
            assert reader.find_first(MISSING) is None

    def test_unmapped_reader_returns_none(self, raw_path):
        reader = DumpReader(raw_path)
        assert reader.find_first(b"MARKER") is None  # never opened
        assert reader.find_all(b"MARKER") == []

    def test_empty_file_returns_none(self, tmp_path):
        empty = tmp_path / "empty.dump"
        empty.write_bytes(b"")
        with DumpReader(empty) as reader:
            assert reader.find_first(b"x") is None
            assert reader.find_all(b"x") == []


# ---------------------------------------------------------------------------
# DumpSource implementations
# ---------------------------------------------------------------------------


def assert_find_first_agrees(source, needle: bytes, view: str) -> None:
    """``find_first`` must equal ``find_all[0]``, or ``None`` when there is
    no hit, for this source/view/needle triple."""
    hits = source.find_all(needle, view=view)
    first = source.find_first(needle, view=view)
    expected = hits[0] if hits else None
    assert first == expected, (
        f"{type(source).__name__} view={view!r} needle={needle[:16]!r}: "
        f"find_first={first!r} find_all[:2]={hits[:2]!r}"
    )


def sweep_views(source, views, present_needles, empty_needle: bool = False) -> None:
    """Assert agreement for present needles and a miss.

    ``empty_needle=True`` also compares the empty needle. Every source now
    guards ``b""`` in both ``find_all`` and ``find_first`` (they agree on
    "absent"), so this is safe everywhere; it stays opt-in only to keep the
    per-source empty-needle assertions explicit and individually named.
    """
    for view in views:
        for needle in present_needles:
            assert_find_first_agrees(source, needle, view)
        assert_find_first_agrees(source, MISSING, view)
        if empty_needle:
            assert_find_first_agrees(source, b"", view)


class TestRawDumpSourceFindFirst:
    def test_agrees_with_find_all(self, raw_path):
        with RawDumpSource(raw_path) as src:
            sweep_views(src, ["raw"], [b"MARKER", b"TAIL", b"\xAA" * 8])

    def test_empty_needle_reports_absent(self, raw_path):
        with RawDumpSource(raw_path) as src:
            assert src.find_first(b"") is None
            assert src.find_all(b"") == []

    def test_hit_offsets(self, raw_path):
        with RawDumpSource(raw_path) as src:
            assert src.find_first(b"MARKER") == 512
            assert src.find_first(MISSING) is None

    def test_open_dump_dispatch_exposes_find_first(self, raw_path):
        with open_dump(raw_path) as src:
            assert isinstance(src, RawDumpSource)
            assert src.find_first(b"MARKER") == 512


@pytest.fixture
def msl_path(tmp_path: Path) -> Path:
    p = tmp_path / "test.msl"
    p.write_bytes(generate_msl_file())
    return p


class TestMslDumpSourceFindFirst:
    def test_agrees_with_find_all_in_both_views(self, msl_path):
        with MslDumpSource(msl_path) as src:
            vas_head = src.read_range(0, 8, view="vas")
            raw_head = src.read_range(0, 8, view="raw")
            # The VAS projection searches per captured run (plain ``bytes``), so
            # the empty needle terminates there; the raw view is mmap-backed.
            sweep_views(src, ["vas"], [n for n in (vas_head,) if n],
                        empty_needle=True)
            sweep_views(src, ["raw"], [n for n in (raw_head,) if n])

    def test_raw_view_empty_needle_reports_absent(self, msl_path):
        with MslDumpSource(msl_path) as src:
            assert src.find_first(b"", view="raw") is None
            assert src.find_all(b"", view="raw") == []

    def test_vas_hit_is_a_vas_offset_not_a_file_offset(self, msl_path):
        with MslDumpSource(msl_path) as src:
            probe = src.read_range(0, 16, view="vas")
            if not probe:
                pytest.skip("synthetic .msl fixture exposes no captured VAS bytes")
            hit = src.find_first(probe, view="vas")
            assert hit == src.find_all(probe, view="vas")[0]
            assert src.read_range(hit, len(probe), view="vas") == probe

    def test_miss_returns_none_in_both_views(self, msl_path):
        with MslDumpSource(msl_path) as src:
            assert src.find_first(MISSING, view="vas") is None
            assert src.find_first(MISSING, view="raw") is None

    def test_unopened_source_returns_none_for_vas(self, msl_path):
        src = MslDumpSource(msl_path)
        assert src.find_first(b"anything", view="vas") is None
        assert src.find_all(b"anything", view="vas") == []

    def test_bad_view_raises_like_find_all(self, msl_path):
        with MslDumpSource(msl_path) as src:
            with pytest.raises(ValueError):
                src.find_all(b"x", view="garbage")
            with pytest.raises(ValueError):
                src.find_first(b"x", view="garbage")


@pytest.fixture
def gcore_path(tmp_path: Path) -> Path:
    return synth_elf_core.build(tmp_path / "run_0001") / "gcore.core"


class TestGCoreDumpSourceFindFirst:
    def test_agrees_with_find_all_in_both_views(self, gcore_path):
        with GCoreDumpSource(gcore_path) as src:
            vas_head = src.read_range(0, 12, view="vas")
            raw_head = src.read_range(0, 12, view="raw")
            sweep_views(src, ["vas"], [n for n in (vas_head,) if n],
                        empty_needle=True)
            sweep_views(src, ["raw"], [n for n in (raw_head,) if n],
                        empty_needle=True)

    def test_vas_hit_round_trips_through_read_range(self, gcore_path):
        with GCoreDumpSource(gcore_path) as src:
            vas_size = src.size_for("vas")
            probe = src.read_range(max(0, vas_size - 24), 16, view="vas")
            if not probe:
                pytest.skip("synthetic core exposes no captured VAS bytes")
            hit = src.find_first(probe, view="vas")
            assert hit == src.find_all(probe, view="vas")[0]
            assert src.read_range(hit, len(probe), view="vas") == probe

    def test_needle_straddling_two_segments(self, gcore_path):
        """The stitched-boundary path: a needle spanning the seam between two
        VAS segments must be found identically by find_all and find_first."""
        with GCoreDumpSource(gcore_path) as src:
            seams = [end for _start, end, _off in src.iter_ranges("vas")]
            if len(seams) < 2:
                pytest.skip("synthetic core has fewer than two segments")
            # Convert the first segment's VA end into a flat VAS boundary.
            first_len = next(
                end - start for start, end, _off in src.iter_ranges("vas")
            )
            straddle = src.read_range(first_len - 4, 8, view="vas")
            if len(straddle) < 8:
                pytest.skip("cannot build a straddling needle")
            assert_find_first_agrees(src, straddle, "vas")

    def test_miss_and_empty_needle(self, gcore_path):
        with GCoreDumpSource(gcore_path) as src:
            assert src.find_first(MISSING, view="raw") is None
            assert src.find_first(MISSING, view="vas") is None
            # gcore's find_all guards the empty needle (no hits); find_first
            # mirrors that rather than reporting offset 0.
            assert src.find_all(b"", view="raw") == []
            assert src.find_first(b"", view="raw") is None
            assert src.find_all(b"", view="vas") == []
            assert src.find_first(b"", view="vas") is None

    def test_bad_view_raises_like_find_all(self, gcore_path):
        with GCoreDumpSource(gcore_path) as src:
            with pytest.raises(ValueError):
                src.find_all(b"x", view="garbage")
            with pytest.raises(ValueError):
                src.find_first(b"x", view="garbage")


@pytest.fixture
def regions_dir(tmp_path: Path) -> Path:
    return synth_raw_regions.build(tmp_path / "run_0001")


@pytest.mark.parametrize(
    "flavour,cls",
    [("gdb_raw", GdbRawDumpSource), ("lldb_raw", LldbRawDumpSource)],
)
class TestRegionedRawFindFirst:
    def test_agrees_with_find_all_in_both_views(self, regions_dir, flavour, cls):
        with cls(regions_dir / f"{flavour}.bin") as src:
            vas_head = src.read_range(0, 16, view="vas")
            raw_head = src.read_range(0, 16, view="raw")
            sweep_views(src, ["vas"], [n for n in (vas_head,) if n],
                        empty_needle=True)
            sweep_views(src, ["raw"], [n for n in (raw_head,) if n],
                        empty_needle=True)

    def test_vas_hit_round_trips(self, regions_dir, flavour, cls):
        with cls(regions_dir / f"{flavour}.bin") as src:
            probe = src.read_range(0x2000, 16, view="vas")
            if not probe:
                pytest.skip("synthetic region dump too small")
            hit = src.find_first(probe, view="vas")
            assert hit == src.find_all(probe, view="vas")[0]
            assert src.read_range(hit, len(probe), view="vas") == probe

    def test_miss_and_empty_needle(self, regions_dir, flavour, cls):
        with cls(regions_dir / f"{flavour}.bin") as src:
            assert src.find_first(MISSING, view="raw") is None
            assert src.find_first(MISSING, view="vas") is None
            # find_all guards the empty needle (it would match every byte);
            # find_first mirrors that guard.
            assert src.find_all(b"", view="raw") == []
            assert src.find_first(b"", view="raw") is None
            assert src.find_all(b"", view="vas") == []
            assert src.find_first(b"", view="vas") is None

    def test_bad_view_raises_like_find_all(self, regions_dir, flavour, cls):
        with cls(regions_dir / f"{flavour}.bin") as src:
            with pytest.raises(ValueError):
                src.find_all(b"x", view="garbage")
            with pytest.raises(ValueError):
                src.find_first(b"x", view="garbage")

    def test_open_dump_dispatch_exposes_find_first(self, regions_dir, flavour, cls):
        with open_dump(regions_dir / f"{flavour}.bin") as src:
            assert isinstance(src, cls)
            head = src.read_range(0, 16, view="raw")
            assert src.find_first(head, view="raw") == src.find_all(head, view="raw")[0]


# ---------------------------------------------------------------------------
# find_first_in — the backward-compatibility seam
# ---------------------------------------------------------------------------


class _LegacySourceWithoutFindFirst:
    """A minimal duck-typed source that predates ``find_first``.

    It implements exactly the :class:`DumpSource` structural contract and
    nothing more — the shape a third-party source registered through
    ``register_dump_source`` is allowed to have.
    """

    DATA = b"abXXcdXXef"

    def __init__(self, path: Path = Path("legacy.bin")):
        self._path = path

    @property
    def path(self) -> Path:
        return self._path

    @property
    def name(self) -> str:
        return self._path.name

    @property
    def format_name(self) -> str:
        return "legacy"

    @property
    def size(self) -> int:
        return len(self.DATA)

    def size_for(self, view: str = "raw") -> int:
        return len(self.DATA)

    def open(self) -> None:
        pass

    def close(self) -> None:
        pass

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return None

    def read_range(self, offset: int, length: int, view: str = "raw") -> bytes:
        return self.DATA[offset:offset + length]

    def find_all(self, needle: bytes, view: str = "raw"):
        return _find_all_in_bytes(self.DATA, needle)

    def iter_ranges(self, *args, **kwargs):
        yield (0, len(self.DATA), self.DATA)

    def metadata(self):
        return {"format": "legacy"}


class TestFindFirstIn:
    def test_protocol_does_not_require_find_first(self):
        """The compatibility contract: ``find_first`` must stay OUT of the
        runtime_checkable DumpSource Protocol, or every existing duck-typed
        source would stop satisfying ``isinstance``."""
        legacy = _LegacySourceWithoutFindFirst()
        assert not hasattr(legacy, "find_first")
        assert isinstance(legacy, DumpSource)

    def test_falls_back_to_find_all_for_a_legacy_source(self):
        legacy = _LegacySourceWithoutFindFirst()
        assert find_first_in(legacy, b"XX") == legacy.find_all(b"XX")[0] == 2
        assert find_first_in(legacy, MISSING) is None

    def test_forwards_an_explicit_view_to_a_legacy_source(self):
        legacy = _LegacySourceWithoutFindFirst()
        assert find_first_in(legacy, b"cd", view="raw") == 4

    def test_uses_the_native_method_when_available(self, raw_path):
        calls = []

        class _Spy(RawDumpSource):
            def find_first(self, needle, view="raw"):
                calls.append((needle, view))
                return super().find_first(needle, view)

        with _Spy(raw_path) as src:
            assert find_first_in(src, b"MARKER") == 512
        assert calls == [(b"MARKER", "raw")]

    def test_omitted_view_preserves_each_source_default(self, msl_path, raw_path):
        # MslDumpSource defaults to "vas", RawDumpSource to "raw"; find_first_in
        # must not force a view of its own.
        with MslDumpSource(msl_path) as msl:
            assert find_first_in(msl, MISSING) == msl.find_first(MISSING)
            probe = msl.read_range(0, 8, view="vas")
            if probe:
                assert find_first_in(msl, probe) == msl.find_first(probe, view="vas")
        with RawDumpSource(raw_path) as raw:
            assert find_first_in(raw, b"MARKER") == raw.find_first(b"MARKER", view="raw")

    def test_agrees_with_find_all_across_every_builtin_source(
        self, raw_path, msl_path, gcore_path, regions_dir,
    ):
        cases = [
            (RawDumpSource(raw_path), None),
            (MslDumpSource(msl_path), "vas"),
            (MslDumpSource(msl_path), "raw"),
            (GCoreDumpSource(gcore_path), "vas"),
            (GCoreDumpSource(gcore_path), "raw"),
            (GdbRawDumpSource(regions_dir / "gdb_raw.bin"), "vas"),
            (LldbRawDumpSource(regions_dir / "lldb_raw.bin"), "raw"),
        ]
        for source, view in cases:
            with source as src:
                kwargs = {} if view is None else {"view": view}
                head = src.read_range(0, 12, **kwargs)
                for needle in [n for n in (head,) if n] + [MISSING]:
                    hits = src.find_all(needle, **kwargs)
                    expected = hits[0] if hits else None
                    assert find_first_in(src, needle, view=view) == expected, (
                        f"{type(src).__name__} view={view!r}"
                    )


class TestFindFirstIsPositionIndependent:
    """REGRESSION GUARD: ``find_first`` must not depend on the mmap's position.

    ``mmap.find(sub)`` defaults its start to the mapping's CURRENT FILE
    POSITION, not 0 -- unlike ``bytes.find``, which has no position at all. So a
    bare ``buf.find(needle)`` searched only the tail after anything advanced the
    mapping, and reported a PRESENT needle as absent. ``find_all`` was never
    exposed because it always passes an explicit ``start``.

    This class exists because every other assertion in this file opens a FRESH
    source, and the bug is invisible that way -- a 196-case real-corpus
    differential sweep passed while the bug was live. The distinguishing move is
    to advance the position first, which ``read_all()`` does.

    Reproduced on a real corpus dump before the fix: a TLS 1.3 secret at offset
    585148 was found by ``find_all`` and reported missing by ``find_first``.
    """

    NEEDLE = b"MARKER"
    EXPECTED = 512

    def test_dump_reader_after_read_all(self, raw_path):
        with DumpReader(raw_path) as reader:
            assert reader.find_first(self.NEEDLE) == self.EXPECTED
            reader.read_all()  # advances the mmap position to EOF
            assert reader.find_first(self.NEEDLE) == self.EXPECTED
            assert reader.find_all(self.NEEDLE) == [self.EXPECTED]

    def test_raw_dump_source_after_read_all(self, raw_path):
        with RawDumpSource(raw_path) as src:
            src.read_all()
            assert src.find_first(self.NEEDLE) == self.EXPECTED
            assert find_first_in(src, self.NEEDLE) == self.EXPECTED

    def test_msl_raw_view_after_read_all(self, msl_path):
        with MslDumpSource(msl_path) as src:
            probe = src.read_range(0, 8, view="raw")
            src.read_all(view="raw")
            assert src.find_first(probe, view="raw") == 0

    def test_gcore_raw_view_after_read_all(self, gcore_path):
        """The gcore raw view searches the LIVE mmap via ``_reader_raw_bytes``.

        That helper deliberately returns the mapping itself rather than copying a
        multi-GB core, so the ``_find_first_in_bytes`` name is misleading: it
        really can receive an mmap, which is exactly how it inherited the bug.
        """
        with GCoreDumpSource(gcore_path) as src:
            probe = src.read_range(0, 8, view="raw")
            # GCoreDumpSource exposes no ``read_all``, so advance the underlying
            # mapping directly -- that position, however it got there, is the
            # actual precondition under test.
            mm = src._reader._mmap  # noqa: SLF001
            mm.seek(0, 2)  # SEEK_END
            assert mm.tell() > 0
            assert src.find_first(probe, view="raw") == 0
            assert src.find_first(MISSING, view="raw") is None

    def test_find_first_agrees_with_find_all_after_read_all(self, raw_path):
        """The invariant that actually matters: the pair cannot disagree."""
        for needle in (b"MARKER", b"TAIL", b"\xAA" * 8, MISSING):
            with RawDumpSource(raw_path) as src:
                src.read_all()
                allhits = src.find_all(needle)
                expected = allhits[0] if allhits else None
                assert src.find_first(needle) == expected, needle
