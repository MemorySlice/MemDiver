"""Tests for core/dump_source.py — DumpSource implementations."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import pytest
from memdiver.core.dump_io import find_all_offsets
from memdiver.core.dump_source import (
    MslDumpSource,
    RawDumpSource,
    _find_all_in_bytes,
    open_dump,
    read_range_with_validity,
)
from tests.fixtures.generate_msl_aslr_fixtures import (
    _build_memory_region_mixed,
    generate_aslr_msl_pair,
)
from tests.fixtures.generate_msl_fixtures import (
    PAGE_SIZE,
    _build_end_of_capture,
    _build_file_header,
    _build_process_identity,
    generate_msl_file,
)


class TestFindAllOffsets:
    """The shared overlapping-aware byte search used by DumpReader and
    _find_all_in_bytes (see core/dump_io.find_all_offsets)."""

    def test_non_overlapping(self):
        assert find_all_offsets(b"abXXcdXXef", b"XX") == [2, 6]

    def test_overlapping_matches(self):
        # 'aaa' contains 'aa' at offsets 0 and 1 (start advances by 1 byte).
        assert find_all_offsets(b"aaaa", b"aa") == [0, 1, 2]

    def test_no_match(self):
        assert find_all_offsets(b"abc", b"z") == []

    def test_dump_source_helper_delegates(self):
        # _find_all_in_bytes must keep identical (overlapping) semantics.
        assert _find_all_in_bytes(b"aaaa", b"aa") == find_all_offsets(b"aaaa", b"aa")


@pytest.fixture
def raw_path(tmp_path):
    p = tmp_path / "test.dump"
    p.write_bytes(b"\xAA" * 512 + b"\xBB" * 512)
    return p


@pytest.fixture
def msl_path(tmp_path):
    p = tmp_path / "test.msl"
    p.write_bytes(generate_msl_file())
    return p


class TestRawDumpSource:
    def test_format_name(self, raw_path):
        src = RawDumpSource(raw_path)
        assert src.format_name == "raw"
        assert src.path == raw_path

    def test_read_all(self, raw_path):
        with RawDumpSource(raw_path) as src:
            data = src.read_all()
            assert len(data) == 1024
            assert data[:512] == b"\xAA" * 512

    def test_read_range(self, raw_path):
        with RawDumpSource(raw_path) as src:
            chunk = src.read_range(500, 24)
            assert len(chunk) == 24

    def test_read_range_negative_offset_safe(self, raw_path):
        """A negative offset must not return tail bytes via Python slicing.

        Regression: ``DumpReader.read_range`` indexed ``self._mmap[offset:end]``
        with no negative-offset guard, so a negative offset returned the wrong
        region's bytes for adversarial dumps. It must now return b"".
        """
        with RawDumpSource(raw_path) as src:
            assert src.read_range(-1, 16) == b""
            assert src.read_range(-1000, 16) == b""
            # Negative/zero length is also rejected.
            assert src.read_range(0, -5) == b""
            assert src.read_range(0, 0) == b""

    def test_find_all(self, raw_path):
        with RawDumpSource(raw_path) as src:
            offsets = src.find_all(b"\xAA\xAA\xAA\xAA")
            assert len(offsets) > 0
            assert offsets[0] == 0

    def test_iter_ranges(self, raw_path):
        with RawDumpSource(raw_path) as src:
            ranges = list(src.iter_ranges())
            assert len(ranges) == 1
            vaddr, length, data = ranges[0]
            assert vaddr == 0
            assert length == 1024

    def test_metadata(self, raw_path):
        src = RawDumpSource(raw_path)
        meta = src.metadata()
        assert meta["format"] == "raw"

    def test_size(self, raw_path):
        with RawDumpSource(raw_path) as src:
            assert src.size == 1024


class TestMslDumpSource:
    def test_format_name(self, msl_path):
        src = MslDumpSource(msl_path)
        assert src.format_name == "msl"

    def test_read_all(self, msl_path):
        with MslDumpSource(msl_path) as src:
            data = src.read_all()
            assert len(data) > 0

    def test_iter_ranges(self, msl_path):
        with MslDumpSource(msl_path) as src:
            ranges = list(src.iter_ranges())
            assert len(ranges) >= 1
            vaddr, length, data = ranges[0]
            assert vaddr == 0x7FFF00000000
            assert length == 4096

    def test_metadata(self, msl_path):
        with MslDumpSource(msl_path) as src:
            meta = src.metadata()
            assert meta["format"] == "msl"
            assert meta["pid"] == 1234

    def test_find_all(self, msl_path):
        with MslDumpSource(msl_path) as src:
            # Page data starts with b"\xAA" * 32
            offsets = src.find_all(b"\xAA\xAA\xAA\xAA")
            assert len(offsets) > 0


class TestOpenDump:
    def test_auto_detect_raw(self, raw_path):
        src = open_dump(raw_path)
        assert isinstance(src, RawDumpSource)

    def test_auto_detect_msl(self, msl_path):
        src = open_dump(msl_path)
        assert isinstance(src, MslDumpSource)

    def test_auto_detect_big_endian_elf_core(self, tmp_path):
        """A big-endian ELF core (EI_DATA=2) with e_type==ET_CORE must be
        dispatched to GCoreDumpSource. Regression: e_type was read
        little-endian unconditionally, so a big-endian core's e_type
        (0x0004 stored big-endian) was misread as 0x0400 != ET_CORE and the
        file fell through to RawDumpSource."""
        from memdiver.core.dump_sources.gcore import GCoreDumpSource
        # EI_DATA = 2 (ELFDATA2MSB) at magic[5]; e_type stored big-endian.
        e_ident = b"\x7fELF" + bytes([2, 2, 1]) + b"\x00" * 9  # class=2,data=2
        # e_type at offset 16, big-endian ET_CORE (4) -> b"\x00\x04".
        header = e_ident + b"\x00\x04" + b"\x00" * 32
        p = tmp_path / "be_core.elf"
        p.write_bytes(header)
        src = open_dump(p)
        assert isinstance(src, GCoreDumpSource)

    def test_auto_detect_little_endian_elf_core_still_works(self, tmp_path):
        """The little-endian path (EI_DATA=1) must keep dispatching to
        GCoreDumpSource — guards against the byteorder fix regressing LE."""
        from memdiver.core.dump_sources.gcore import GCoreDumpSource
        e_ident = b"\x7fELF" + bytes([2, 1, 1]) + b"\x00" * 9  # data=1 (LSB)
        header = e_ident + b"\x04\x00" + b"\x00" * 32  # e_type LE = 4
        p = tmp_path / "le_core.elf"
        p.write_bytes(header)
        src = open_dump(p)
        assert isinstance(src, GCoreDumpSource)


class TestMslViewModes:
    """Regression tests for the raw-vs-VAS view split.

    Before Phase 25, the hex viewer always read through the VAS
    projection and offset 0 of a .msl file showed the first captured
    page's bytes (often an ELF header from a module) instead of the
    MSL container's ``MEMSLICE`` magic. These tests pin both views.
    """

    def test_raw_view_starts_with_msl_magic(self, msl_path):
        from memdiver.msl.enums import FILE_MAGIC
        with MslDumpSource(msl_path) as src:
            head = src.read_range(0, len(FILE_MAGIC), view="raw")
            assert head == FILE_MAGIC

    def test_vas_view_matches_captured_page(self, msl_path):
        with MslDumpSource(msl_path) as src:
            # The generate_msl_file fixture pads captured pages with
            # 0xAA, so the VAS projection at offset 0 must start that
            # way — not with the MSL magic.
            head = src.read_range(0, 4, view="vas")
            assert head == b"\xAA\xAA\xAA\xAA"

    def test_size_for_raw_and_vas_differ(self, msl_path):
        with MslDumpSource(msl_path) as src:
            raw = src.size_for("raw")
            vas = src.size_for("vas")
            assert raw == msl_path.stat().st_size
            # Header + block headers + hash chain wrap the payload, so
            # the container is strictly larger than the flat projection.
            assert raw > vas > 0

    def test_default_size_stays_vas_for_scanners(self, msl_path):
        """The bare ``.size`` property must keep its historical VAS
        semantics — lots of scanner code reads it directly."""
        with MslDumpSource(msl_path) as src:
            assert src.size == src.size_for("vas")

    def test_unknown_view_raises(self, msl_path):
        with MslDumpSource(msl_path) as src:
            with pytest.raises(ValueError):
                src.read_range(0, 4, view="garbage")

    def test_va_to_vas_offset_first_region(self, msl_path):
        with MslDumpSource(msl_path) as src:
            regions = src.get_reader().collect_regions()
            assert regions, "fixture must have at least one region"
            first = regions[0]
            assert src.va_to_vas_offset(first.base_addr) == 0

    def test_va_to_vas_offset_out_of_range(self, msl_path):
        with MslDumpSource(msl_path) as src:
            assert src.va_to_vas_offset(0xDEADBEEF00000000) is None

    def test_va_to_file_offset_points_to_block_header(self, msl_path):
        """A module's VA should translate to the file offset of a real
        block header — the first 4 bytes there must be the MSLC block
        magic."""
        from memdiver.msl.enums import BLOCK_MAGIC
        with MslDumpSource(msl_path) as src:
            regions = src.get_reader().collect_regions()
            assert regions
            va = regions[0].base_addr
            file_off = src.va_to_file_offset(va)
            assert file_off is not None
            head = src.read_range(file_off, 4, view="raw")
            assert head == BLOCK_MAGIC



# ---------------------------------------------------------------------------
# read_range_valid / read_range_with_validity — the presence-reporting read
# ---------------------------------------------------------------------------


@pytest.fixture
def aslr_msl_path(tmp_path):
    """Run 1 of the ASLR pair: one 2-page region, page 0 CAPTURED, page 1
    FAILED (see tests/fixtures/generate_msl_aslr_fixtures.py). The FAILED page
    is exactly the filler the "va" view pads with."""
    p = tmp_path / "run_1.msl"
    run1, _run2 = generate_aslr_msl_pair()
    p.write_bytes(run1)
    return p


#: Base VA of the first of two deliberately ABUTTING one-page regions.
_ABUT_BASE = 0x7FFF00000000


@pytest.fixture
def abutting_msl_path(tmp_path):
    """An .msl whose two all-CAPTURED regions touch exactly (no VA gap).

    ``iter_ranges`` yields them as two separate runs because they are two
    separate region blocks; ``read_range_valid`` must still report ONE run.
    """
    timestamp_ns = 1_700_000_000_000_000_000
    blob = _build_file_header(b"\x11" * 16, timestamp_ns, pid=1234)
    blob += _build_process_identity()[0]
    for index, pad in ((0, 0xA1), (1, 0xB2)):
        region, _ = _build_memory_region_mixed(
            _ABUT_BASE + index * PAGE_SIZE, 1, b"\x00", bytes([pad]) * PAGE_SIZE,
        )
        blob += region
    blob += _build_end_of_capture(timestamp_ns + 1_000_000_000)[0]
    p = tmp_path / "abutting.msl"
    p.write_bytes(blob)
    return p


def _read_range_va_reference(src, offset, length):
    """The pre-refactor body of ``_read_range_va``, verbatim.

    Kept here as an independent oracle so ``test_read_range_va_is_unchanged``
    proves the collapse onto ``read_range_valid`` is behaviour-neutral rather
    than merely self-consistent.
    """
    if length <= 0 or src._reader is None:
        return b""
    span_start, _span_size = src._va_span()
    req_start = span_start + offset
    req_end = req_start + length
    buf = bytearray(length)
    for vaddr, clen, chunk in src.iter_ranges():
        c_end = vaddr + clen
        if c_end <= req_start:
            continue
        if vaddr >= req_end:
            break
        ov_start = max(vaddr, req_start)
        ov_end = min(c_end, req_end)
        buf[ov_start - req_start:ov_end - req_start] = \
            chunk[ov_start - vaddr:ov_end - vaddr]
    return bytes(buf)


class _SourceWithoutReadRangeValid:
    """A duck-typed source that predates ``read_range_valid``.

    Mirrors ``_LegacySourceWithoutFindFirst`` in tests/test_dump_io_find_first.py:
    it implements the :class:`DumpSource` structural contract and nothing more,
    which is the shape a third-party source registered through
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


class TestReadRangeValid:
    def test_read_range_valid_reports_only_captured_runs(self, aslr_msl_path):
        """A CAPTURED page followed by a FAILED page: the run list must cover
        the captured page ONLY, and the filler must still be inside the bytes
        (so the window keeps its VA alignment) but outside every run."""
        with MslDumpSource(aslr_msl_path) as src:
            data, runs = src.read_range_valid(0, 2 * PAGE_SIZE, view="va")
            assert len(data) == 2 * PAGE_SIZE
            assert runs == [(0, PAGE_SIZE)]
            assert data[PAGE_SIZE:] == b"\x00" * PAGE_SIZE
            # And the run really does point at real bytes.
            assert data[:PAGE_SIZE] != b"\x00" * PAGE_SIZE

    def test_read_range_valid_merges_abutting_captured_runs(
        self, abutting_msl_path,
    ):
        """Two captured regions that touch in VA are ONE run, not two."""
        with MslDumpSource(abutting_msl_path) as src:
            assert len(list(src.iter_ranges())) == 2, "fixture must have 2 runs"
            data, runs = src.read_range_valid(0, 2 * PAGE_SIZE, view="va")
            assert runs == [(0, 2 * PAGE_SIZE)]
            assert data[:PAGE_SIZE] == bytes([0xA1]) * PAGE_SIZE
            assert data[PAGE_SIZE:] == bytes([0xB2]) * PAGE_SIZE

    def test_read_range_valid_never_reports_the_truncated_tail_as_captured(
        self, abutting_msl_path,
    ):
        """A run whose ``avail < length`` must report only the COPIED bytes.

        ``CapturedRun.length`` is the run's NOMINAL size; ``avail`` is how much
        of it the buffer actually holds (a container truncated mid-payload).
        The copy is clamped by ``avail``, so the rest of the run stays
        zero-filled — and reporting the run's full VA overlap would hand that
        filler back as CAPTURED, the exact false presence this method exists to
        prevent.

        The truncation is injected at the index seam rather than by truncating
        the file, because the block-level length checks usually reject a
        short container outright: ``avail`` exists precisely for the case
        where they do not, so that is the case this pins.
        """
        half = PAGE_SIZE // 2
        with MslDumpSource(abutting_msl_path) as src:
            real = src._run_index()
            assert real is not None and len(real.by_va) == 2, "fixture must have 2 runs"
            truncated = real.by_va[0]._replace(avail=half)
            by_va = (truncated,) + real.by_va[1:]
            patched = real._replace(
                runs=by_va,
                by_va=by_va,
                va_starts=tuple(r.va_start for r in by_va),
                vas_starts=tuple(r.vas_offset for r in by_va),
            )
            src._reader.captured_run_index = lambda: patched

            data, runs = src.read_range_valid(0, 2 * PAGE_SIZE, view="va")

        # The run over the truncated region stops at `avail`; it therefore no
        # longer abuts the second region, so the two do NOT merge.
        assert runs == [(0, half), (PAGE_SIZE, PAGE_SIZE)]
        # Every reported byte is a byte that was really copied...
        assert data[:half] == bytes([0xA1]) * half
        assert data[PAGE_SIZE:] == bytes([0xB2]) * PAGE_SIZE
        # ...and the zero-filled tail is outside every run.
        assert data[half:PAGE_SIZE] == b"\x00" * (PAGE_SIZE - half)
        assert all(
            not (start <= pos < start + run_len)
            for pos in range(half, PAGE_SIZE)
            for start, run_len in runs
        )

    def test_read_range_valid_on_vas_and_raw_covers_the_returned_length(
        self, msl_path,
    ):
        """``"vas"``/``"raw"`` return short rather than padding, so every byte
        handed back is real and full coverage is the truth."""
        with MslDumpSource(msl_path) as src:
            for view in ("vas", "raw"):
                data, runs = src.read_range_valid(0, 64, view=view)
                assert data == src.read_range(0, 64, view=view)
                assert runs == [(0, len(data))]
                assert len(data) == 64
            # A read entirely past the end returns nothing, and claims nothing.
            past = src.size_for("vas") + 4096
            assert src.read_range_valid(past, 64, view="vas") == (b"", [])

    def test_read_range_valid_clamps_past_the_end(self, aslr_msl_path):
        """Reading past the last captured VA yields no run covering the tail."""
        with MslDumpSource(aslr_msl_path) as src:
            length = 4 * PAGE_SIZE
            data, runs = src.read_range_valid(0, length, view="va")
            assert len(data) == length
            assert runs == [(0, PAGE_SIZE)]
            assert max(start + run_len for start, run_len in runs) <= PAGE_SIZE
            assert data[PAGE_SIZE:] == b"\x00" * (length - PAGE_SIZE)
            # Starting inside the FAILED page: entirely filler, zero runs.
            tail, tail_runs = src.read_range_valid(PAGE_SIZE, length, view="va")
            assert tail_runs == []
            assert tail == b"\x00" * length

    def test_read_range_valid_rejects_an_unknown_view(self, msl_path):
        with MslDumpSource(msl_path) as src:
            with pytest.raises(ValueError):
                src.read_range_valid(0, 4, view="garbage")

    def test_read_range_valid_empty_and_unopened(self, aslr_msl_path):
        """Degenerate inputs match ``_read_range_va``'s historical handling."""
        closed = MslDumpSource(aslr_msl_path)
        assert closed.read_range_valid(0, 16, view="va") == (b"", [])
        with MslDumpSource(aslr_msl_path) as src:
            assert src.read_range_valid(0, 0, view="va") == (b"", [])
            assert src.read_range_valid(0, -5, view="va") == (b"", [])

    def test_read_range_va_is_unchanged(self, aslr_msl_path):
        """The collapsed ``_read_range_va`` is byte-for-byte what it was."""
        with MslDumpSource(aslr_msl_path) as src:
            cases = [(0, 16), (0, PAGE_SIZE), (0, 2 * PAGE_SIZE),
                     (64, 128), (PAGE_SIZE - 8, 32), (PAGE_SIZE, 64),
                     (0, 4 * PAGE_SIZE), (0, 0), (0, -5)]
            for offset, length in cases:
                assert src._read_range_va(offset, length) == \
                    _read_range_va_reference(src, offset, length), (offset, length)
                # ...and it stays the first element of the new API.
                assert src._read_range_va(offset, length) == \
                    src.read_range_valid(offset, length, view="va")[0]
        closed = MslDumpSource(aslr_msl_path)
        assert closed._read_range_va(0, 16) == b""


class TestReadRangeWithValidity:
    def test_uses_the_native_method_when_available(self, aslr_msl_path):
        calls = []

        class _Spy(MslDumpSource):
            def read_range_valid(self, offset, length, view="vas"):
                calls.append((offset, length, view))
                return super().read_range_valid(offset, length, view)

        with _Spy(aslr_msl_path) as src:
            data, runs = read_range_with_validity(src, 0, 2 * PAGE_SIZE, view="va")
        assert calls == [(0, 2 * PAGE_SIZE, "va")]
        assert runs == [(0, PAGE_SIZE)]
        assert len(data) == 2 * PAGE_SIZE

    def test_read_range_with_validity_falls_back_for_a_source_without_the_method(
        self, raw_path,
    ):
        """RawDumpSource and a duck-typed stub both lack ``read_range_valid``;
        the helper must fall back to ``read_range`` and claim full coverage —
        correct, because neither pads."""
        legacy = _SourceWithoutReadRangeValid()
        assert not hasattr(legacy, "read_range_valid")
        assert read_range_with_validity(legacy, 2, 4) == (b"XXcd", [(0, 4)])
        assert read_range_with_validity(legacy, 2, 4, view="raw") == (b"XXcd", [(0, 4)])
        # A read past the end claims nothing.
        assert read_range_with_validity(legacy, 99, 4) == (b"", [])

        with RawDumpSource(raw_path) as src:
            assert not hasattr(src, "read_range_valid")
            data, runs = read_range_with_validity(src, 500, 24)
            assert data == src.read_range(500, 24)
            assert runs == [(0, 24)]

    def test_omitted_view_preserves_each_source_default(self, msl_path, raw_path):
        """Like ``find_first_in``, the helper must not force a view of its own:
        MslDumpSource defaults to "vas", RawDumpSource to "raw"."""
        with MslDumpSource(msl_path) as msl:
            assert read_range_with_validity(msl, 0, 8) == \
                msl.read_range_valid(0, 8, view="vas")
        with RawDumpSource(raw_path) as raw:
            data, _runs = read_range_with_validity(raw, 0, 8)
            assert data == raw.read_range(0, 8, view="raw")


def _linear_vas_read(src, offset, length):
    """``read_range(..., "vas")`` walked linearly over ``iter_ranges``.

    The pre-index algorithm, verbatim, so the bisecting replacement is proven
    behaviour-neutral against an independent oracle rather than against itself.
    """
    result, flat_pos = bytearray(), 0
    for _va, rng_len, chunk in src.iter_ranges():
        rng_end = flat_pos + rng_len
        if rng_end <= offset:
            flat_pos = rng_end
            continue
        if flat_pos >= offset + length:
            break
        s, e = max(0, offset - flat_pos), min(rng_len, offset + length - flat_pos)
        result.extend(chunk[s:e])
        flat_pos = rng_end
    return bytes(result)


def _linear_va_to_vas(src, va):
    """``va_to_vas_offset`` walked linearly over ``iter_ranges`` — the oracle."""
    flat_pos = 0
    for vaddr, length, _chunk in src.iter_ranges():
        if vaddr <= va < vaddr + length:
            return flat_pos + (va - vaddr)
        flat_pos += length
    return None


class TestCapturedRunIndex:
    """The reader-level run index that replaced the per-read region walk.

    Every read used to restart ``iter_ranges`` from region 0 and copy each
    region's page data on the way past the target — a measured 846 MB copied
    to deliver 16 KiB. These tests pin the two things that makes safe: the
    index describes exactly what the walk described, and it never outlives the
    mapping it was computed against.
    """

    def test_index_describes_exactly_what_iter_ranges_yields(self, aslr_msl_path):
        with MslDumpSource(aslr_msl_path) as src:
            walked = list(src.iter_ranges())
            index = src._run_index()
            assert len(index.runs) == len(walked)
            flat = 0
            for run, (vaddr, length, chunk) in zip(index.runs, walked):
                assert (run.va_start, run.length) == (vaddr, length)
                assert run.vas_offset == flat
                assert bytes(src._reader.read_view(run.buf_offset, run.avail)) == chunk
                flat += length

    def test_reads_match_a_linear_walk(self, aslr_msl_path):
        with MslDumpSource(aslr_msl_path) as src:
            vas_size = src.size_for("vas")
            for offset in (-1, 0, 1, PAGE_SIZE - 1, PAGE_SIZE, vas_size - 1,
                           vas_size, vas_size + 10):
                for length in (0, 1, 7, PAGE_SIZE, 3 * PAGE_SIZE):
                    assert src.read_range(offset, length, "vas") == \
                        _linear_vas_read(src, offset, length), (offset, length)
            span_start, _span = src._va_span()
            for run_va, run_len, _chunk in src.iter_ranges():
                for va in (run_va - 1, run_va, run_va + run_len - 1,
                           run_va + run_len):
                    assert src.va_to_vas_offset(va) == _linear_va_to_vas(src, va)
                    offset = va - span_start
                    assert src.read_range_valid(offset, PAGE_SIZE, view="va") == \
                        (_read_range_va_reference(src, offset, PAGE_SIZE),
                         src.read_range_valid(offset, PAGE_SIZE, view="va")[1])

    def test_captured_runs_matches_the_iter_ranges_run_table(self, aslr_msl_path):
        """``captured_runs`` is the run table WITHOUT copying the bytes."""
        with MslDumpSource(aslr_msl_path) as src:
            flat, expected = 0, []
            for vaddr, length, _chunk in src.iter_ranges():
                expected.append((vaddr, length, flat))
                flat += length
            assert list(src.captured_runs()) == expected

    def test_captured_runs_is_empty_without_a_reader(self, aslr_msl_path):
        assert MslDumpSource(aslr_msl_path).captured_runs() == ()

    def test_va_span_start_agrees_with_metadata(self, aslr_msl_path):
        """The narrow accessor must answer what the dict key answered."""
        with MslDumpSource(aslr_msl_path) as src:
            assert src.va_span_start() == src.metadata()["va_span_start"]
        closed = MslDumpSource(aslr_msl_path)
        # No reader: metadata() omits the key entirely, so the accessor must
        # say None rather than a plausible 0.
        assert closed.va_span_start() is None
        assert "va_span_start" not in closed.metadata()

    def test_size_for_vas_agrees_with_the_bytes_it_describes(self, aslr_msl_path):
        with MslDumpSource(aslr_msl_path) as src:
            assert src.size_for("vas") == len(src.read_all("vas"))

    def test_index_is_cached_on_the_reader_not_the_source_view(self, aslr_msl_path):
        """Two source views over one pooled reader share ONE index.

        Load-bearing placement, not an optimisation detail: ``borrow_reader``
        hands out a fresh view per request, so an index parked on the view
        would be cold on every request and the walk would be back.
        """
        from memdiver.msl.reader import MslReader

        reader = MslReader(aslr_msl_path)
        reader.open()
        try:
            first = MslDumpSource.borrow_reader(aslr_msl_path, reader)
            second = MslDumpSource.borrow_reader(aslr_msl_path, reader)
            assert first is not second
            assert first._run_index() is second._run_index()
        finally:
            reader.close()

    def test_a_reopened_reader_rebuilds_the_index(self, tmp_path):
        """A stale index would serve the PREVIOUS mapping's buffer offsets."""
        from memdiver.msl.reader import MslReader

        path = tmp_path / "swapped.msl"
        run1, run2 = generate_aslr_msl_pair()
        path.write_bytes(run1)
        reader = MslReader(path)
        reader.open()
        before = reader.captured_run_index()
        reader.close()
        assert reader._captured_runs_cache is None

        # Same reader object, different bytes behind the same path.
        path.write_bytes(run2)
        reader.open()
        try:
            after = reader.captured_run_index()
            assert after is not before
            assert [run.va_start for run in after.runs] != \
                [run.va_start for run in before.runs]
            # No `with`: __enter__ would open a SECOND reader over the view
            # and the borrowed one — the thing under test — would go unused.
            src = MslDumpSource.borrow_reader(path, reader)
            assert [run[0] for run in src.captured_runs()] == \
                [va for va, _len, _chunk in src.iter_ranges()]
        finally:
            reader.close()
