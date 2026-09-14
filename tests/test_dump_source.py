"""Tests for core/dump_source.py — DumpSource implementations."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import pytest
from memdiver.core import dump_source as dump_source_module
from memdiver.core.dump_io import find_all_offsets
from memdiver.core.dump_source import (
    MslDumpSource,
    RawDumpSource,
    _find_all_in_bytes,
    open_dump,
    read_range_with_validity,
    supported_views,
)
from tests.fixtures.generate_msl_aslr_fixtures import (
    SECRET_OFFSET_IN_PAGE,
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


# ---------------------------------------------------------------------------
# find_all / find_first over the "va" view — searching the SPARSE projection
# ---------------------------------------------------------------------------


@pytest.fixture
def aslr_run2_msl_path(tmp_path):
    """Run 2 of the ASLR pair, whose CAPTURED page is 0xFE-filled.

    Run 1 cannot be used to prove "padding is never matched": its captured
    page is pad byte 0x00, so a search for a run of zeroes there legitimately
    hits 4050 real captured bytes and the assertion would pass whether or not
    the padding was excluded. Run 2's pad is 0xFE, so the ONLY zeroes in its
    "va" projection are the synthesized filler over the FAILED page — which
    makes a zero needle a direct probe for the bug.
    """
    p = tmp_path / "run_2.msl"
    _run1, run2 = generate_aslr_msl_pair()
    p.write_bytes(run2)
    return p


#: Pages of untouched VA between the two regions of ``gapped_msl_path``.
_GAP_PAGES = 3


@pytest.fixture
def gapped_msl_path(tmp_path):
    """``abutting_msl_path`` with the second region pushed 3 pages away.

    Same two all-CAPTURED one-page regions, same pad bytes, same seam needle —
    the ONLY difference is that the regions no longer touch in VA. It is the
    control for ``abutting_msl_path``: together they pin that adjacency, not
    "two regions in one dump", is what licenses joining captured runs.
    """
    timestamp_ns = 1_700_000_000_000_000_000
    blob = _build_file_header(b"\x22" * 16, timestamp_ns, pid=1234)
    blob += _build_process_identity()[0]
    for index, pad in ((0, 0xA1), (1 + _GAP_PAGES, 0xB2)):
        region, _ = _build_memory_region_mixed(
            _ABUT_BASE + index * PAGE_SIZE, 1, b"\x00", bytes([pad]) * PAGE_SIZE,
        )
        blob += region
    blob += _build_end_of_capture(timestamp_ns + 1_000_000_000)[0]
    p = tmp_path / "gapped.msl"
    p.write_bytes(blob)
    return p


#: The needle that straddles the seam between the two one-page regions of
#: ``abutting_msl_path`` / ``gapped_msl_path``: the last 4 bytes of the first
#: region followed by the first 4 of the second.
_SEAM_NEEDLE = bytes([0xA1]) * 4 + bytes([0xB2]) * 4


class TestFindAllVa:
    """Byte search over ``view="va"`` — the sparse full-VA projection.

    The "va" view is synthesized: gaps, FAILED/UNMAPPED pages and truncated
    run tails are all manufactured ``0x00`` and its span can be terabytes
    wide, so it is neither materialized nor scanned end to end. These tests
    pin the two properties that makes it a usable search surface at all:
    every reported offset addresses bytes the dump really captured, and no
    reported offset is an artefact of how the scan was windowed.
    """

    def test_hits_are_va_span_relative_offsets(self, aslr_run2_msl_path):
        """The one invariant every consumer depends on.

        The viewer renders a hit as ``va_span_start + offset``, so a hit that
        were an absolute VA (or a VAS offset) would scroll it to the wrong
        row — silently, because both are plausible integers. Round-tripping
        through ``read_range(..., view="va")`` is the only check that catches
        that, and it must hold for EVERY hit, not just the first.
        """
        needle = bytes([0xFE]) * 8
        with MslDumpSource(aslr_run2_msl_path) as src:
            hits = src.find_all(needle, view="va")
            assert hits, "fixture must contain the needle"
            for offset in hits:
                assert src.read_range(offset, len(needle), view="va") == needle

    def test_the_secret_is_found_at_its_known_va_offset(self, aslr_run2_msl_path):
        """A real needle at a known place, so the invariant test above cannot
        pass on a vacuously empty hit list. The ASLR fixture plants the run's
        secret at ``SECRET_OFFSET_IN_PAGE`` of the first (captured) page, and
        that page starts the VA span."""
        with MslDumpSource(aslr_run2_msl_path) as src:
            secret = src.read_range(SECRET_OFFSET_IN_PAGE, 32, view="va")
            assert secret != bytes([0xFE]) * 32, "fixture must plant a secret"
            assert src.find_all(secret, view="va") == [SECRET_OFFSET_IN_PAGE]

    def test_synthesized_padding_is_never_matched(self, aslr_run2_msl_path):
        """The finding this whole code path exists to prevent.

        Run 2's captured page is 0xFE-filled, so the only zeroes anywhere in
        its "va" projection are the filler the view manufactures over the
        FAILED page. A search for them must come back empty.

        The two guards below are what stop this from passing vacuously: the
        zeroes ARE readable through ``read_range`` (the view still pads, as it
        must, to keep VA alignment) and they ARE present in the full padded
        projection — so a naive implementation that scanned that projection
        would report them. Without those assertions this test would still pass
        against an implementation that simply failed to find anything.
        """
        zeroes = b"\x00" * 8
        with MslDumpSource(aslr_run2_msl_path) as src:
            # Guard 1: the filler is genuinely readable at the FAILED page.
            assert src.read_range(PAGE_SIZE, 8, view="va") == zeroes
            # Guard 2: and it genuinely occurs in the full padded projection.
            projection = src.read_range(0, src.size_for("va"), view="va")
            assert projection.find(zeroes) == PAGE_SIZE
            # ...and the search still refuses to report it.
            assert src.find_all(zeroes, view="va") == []
            assert src.find_first(zeroes, view="va") is None

    def test_run1_zeroes_are_real_captured_bytes_not_padding(self, aslr_msl_path):
        """The counterexample that pins the fixture choice above.

        Run 1's pad byte IS 0x00, so its captured page really does hold
        thousands of zero runs and the search MUST report them. Keeping this
        beside the run-2 test documents why "zero needle returns []" is only
        meaningful on run 2 — and guards against someone "fixing" a future
        failure by blanket-suppressing zero needles.
        """
        zeroes = b"\x00" * 8
        with MslDumpSource(aslr_msl_path) as src:
            hits = src.find_all(zeroes, view="va")
            # The captured page is the oracle: every zero run inside it is a
            # finding, and the secret planted at SECRET_OFFSET_IN_PAGE is the
            # only thing that interrupts them.
            captured = src.read_range(0, PAGE_SIZE, view="va")
            assert hits == find_all_offsets(captured, zeroes)
            assert len(hits) == PAGE_SIZE - 7 - 32 - 7
            # Every one of them is inside the CAPTURED page, never the FAILED
            # page that follows it.
            assert max(hits) + len(zeroes) <= PAGE_SIZE

    def test_adjacent_captured_runs_are_joined(self, abutting_msl_path):
        """A secret straddling two abutting captured pages is a real secret.

        In VA those bytes are contiguous, so refusing to join the two runs
        would lose the finding outright. ``"vas"`` searches each captured run
        on its own and therefore misses it — asserted here not as a bug to fix
        but as the documented, out-of-scope limitation of that view, and as
        proof that "va" is genuinely doing something "vas" cannot.
        """
        with MslDumpSource(abutting_msl_path) as src:
            assert len(list(src.iter_ranges())) == 2, "fixture must have 2 runs"
            assert src.find_all(_SEAM_NEEDLE, view="va") == [PAGE_SIZE - 4]
            assert src.read_range(PAGE_SIZE - 4, 8, view="va") == _SEAM_NEEDLE
            # Known limitation of the per-chunk "vas" scan, pinned on purpose.
            assert src.find_all(_SEAM_NEEDLE, view="vas") == []

    def test_runs_separated_by_a_gap_are_never_joined(self, gapped_msl_path):
        """The control for the test above: same bytes, no adjacency.

        Splicing two captured runs across a gap would manufacture a match that
        does not exist anywhere in the process — a fabricated finding, which
        is strictly worse than a missed one. Two probes: the seam needle (the
        splice itself) and a zero needle (the gap filler).
        """
        with MslDumpSource(gapped_msl_path) as src:
            assert src._captured_va_segments() == [
                (0, PAGE_SIZE),
                ((1 + _GAP_PAGES) * PAGE_SIZE, PAGE_SIZE),
            ]
            assert src.find_all(_SEAM_NEEDLE, view="va") == []
            assert src.find_first(_SEAM_NEEDLE, view="va") is None
            # The gap's filler is not a finding either.
            assert src.find_all(b"\x00" * 16, view="va") == []
            # Both regions are still searched — the gap suppresses the JOIN,
            # not the scan.
            assert src.find_all(bytes([0xA1]) * 8, view="va")[0] == 0
            assert src.find_all(bytes([0xB2]) * 8, view="va")[0] == \
                (1 + _GAP_PAGES) * PAGE_SIZE

    @pytest.mark.parametrize("chunk", [100, 512, 4096])
    def test_window_size_does_not_change_the_answer(
        self, aslr_run2_msl_path, chunk, monkeypatch,
    ):
        """Windowing is an implementation detail, and must stay one.

        The scan walks each captured segment in ``_VA_SEARCH_CHUNK`` windows
        that overlap by ``len(needle) - 1``. Get that overlap wrong by one and
        you either drop every needle straddling a window boundary or report it
        twice; at the real 8 MiB window neither bug is reachable from any
        fixture small enough to keep in a test suite. Shrinking the constant
        to sizes far below the 4 KiB page puts many boundaries inside the
        data, so both failure modes become observable.
        """
        needle = bytes([0xFE]) * 8
        with MslDumpSource(aslr_run2_msl_path) as src:
            reference = src.find_all(needle, view="va")
            assert len(reference) > 1
            monkeypatch.setattr(dump_source_module, "_VA_SEARCH_CHUNK", chunk)
            windowed = src.find_all(needle, view="va")
            assert windowed == reference
            assert len(set(windowed)) == len(windowed), "duplicate hits"
            assert src.find_first(needle, view="va") == reference[0]

    def test_window_smaller_than_the_needle_still_advances(
        self, aslr_run2_msl_path, monkeypatch,
    ):
        """A window below the needle length would give a non-positive step and
        loop forever. The scan floors the window at ``2 * needle_len`` for
        exactly that reason; this pins it rather than trusting a comment."""
        needle = bytes([0xFE]) * 8
        with MslDumpSource(aslr_run2_msl_path) as src:
            reference = src.find_all(needle, view="va")
            monkeypatch.setattr(dump_source_module, "_VA_SEARCH_CHUNK", 1)
            assert src.find_all(needle, view="va") == reference

    def test_find_first_is_find_all_head(self, aslr_run2_msl_path):
        """The presence query and the enumeration must never disagree: a
        corpus sweep uses ``find_first`` and the viewer uses ``find_all``, so
        a divergence shows up as "the tool says the key is there but will not
        show me where"."""
        with MslDumpSource(aslr_run2_msl_path) as src:
            for needle in (bytes([0xFE]) * 8,
                           src.read_range(SECRET_OFFSET_IN_PAGE, 32, view="va"),
                           b"NO_SUCH_NEEDLE_IN_ANY_FIXTURE"):
                hits = src.find_all(needle, view="va")
                expected = hits[0] if hits else None
                assert src.find_first(needle, view="va") == expected, needle[:8]

    def test_empty_needle_reports_absent(self, aslr_run2_msl_path):
        """``b""`` is a caller error, not a query with a degenerate answer.
        Returning 0 (what ``bytes.find`` gives) would let an empty secret
        masquerade as a hit at the start of every dump in a corpus sweep."""
        with MslDumpSource(aslr_run2_msl_path) as src:
            assert src.find_all(b"", view="va") == []
            assert src.find_first(b"", view="va") is None

    def test_needle_longer_than_the_span_reports_absent(self, aslr_run2_msl_path):
        """No window can hold it, so the walk must end empty rather than
        reading past the segment or dividing by a negative step."""
        with MslDumpSource(aslr_run2_msl_path) as src:
            oversized = bytes([0xFE]) * (10 * PAGE_SIZE)
            assert len(oversized) > src.size_for("va")
            assert src.find_all(oversized, view="va") == []
            assert src.find_first(oversized, view="va") is None

    def test_unopened_source_reports_absent(self, aslr_run2_msl_path):
        """Matches the "vas" contract: no reader means no hits, never a
        crash — the API layer opens sources lazily and a closed one must not
        turn a search into a 500."""
        closed = MslDumpSource(aslr_run2_msl_path)
        assert closed.find_all(bytes([0xFE]) * 4, view="va") == []
        assert closed.find_first(bytes([0xFE]) * 4, view="va") is None
        assert closed._captured_va_segments() == []

    def test_unknown_view_still_raises(self, aslr_run2_msl_path):
        """Adding "va" must not have turned the typo guard into a third
        silent alias: ``view="garbage"`` is a programming error and stays a
        ``ValueError`` (the capability gap is a separate, 400-shaped error —
        see ``app.tools_inspect._require_supported_view``)."""
        with MslDumpSource(aslr_run2_msl_path) as src:
            with pytest.raises(ValueError, match="Unknown view"):
                src.find_all(b"x", view="garbage")
            with pytest.raises(ValueError, match="Unknown view"):
                src.find_first(b"x", view="garbage")


class TestSupportedViews:
    """``supported_views`` — the question the API layer asks BEFORE it hands
    a view to a source (see ``app.tools_inspect._require_supported_view``)."""

    def test_msl_and_raw_serve_all_three_views(self):
        assert supported_views(MslDumpSource) == ("raw", "vas", "va")
        assert supported_views(RawDumpSource) == ("raw", "vas", "va")

    def test_region_backed_sources_do_not_serve_va(self):
        from memdiver.core.dump_sources._regioned_base import _RegionedRawSource
        from memdiver.core.dump_sources.gcore import GCoreDumpSource

        assert supported_views(GCoreDumpSource) == ("raw", "vas")
        assert supported_views(_RegionedRawSource) == ("raw", "vas")

    def test_a_source_that_declares_nothing_keeps_its_historical_views(self):
        """A third-party source registered via ``register_dump_source``
        declares no ``SUPPORTED_VIEWS``. It must not be read as "serves no
        view at all" — that would break every such source the day this helper
        landed. The fallback is the two views every source has always served.
        """
        class _LegacySource:
            format_name = "third_party"

        assert supported_views(_LegacySource()) == ("raw", "vas")
        assert supported_views(object()) == ("raw", "vas")
