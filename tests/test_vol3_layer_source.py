"""Tests for core/image/sources.py: Vol3LayerSource over a fake layer adapter."""

import pytest

import memdiver.core.image.sources as sources
from memdiver.core.dump_source import (
    distinct_views,
    open_dump,
    read_range_with_validity,
    supported_views,
)
from memdiver.core.image.run_index import LayerRun, RunState
from memdiver.core.image.sources import Vol3LayerSource
from memdiver.core.image.view_descriptor import ProfileRef, ViewDescriptor, ViewKind
from memdiver.core.location import AddressSpace, GapReason

C, F, N = RunState.CAPTURED, RunState.FAILED, RunState.NOT_RESIDENT
SHA = "ef" * 32
RUNS = [LayerRun(0x1000, 0x2000, C), LayerRun(0x3000, 0x1000, N),
        LayerRun(0x5000, 0x1000, C), LayerRun(0x6000, 0x1000, F)]
CAPTURED_SPANS = [(0x1000, 0x3000), (0x5000, 0x6000)]
IMAGE_BYTES = bytes(range(256)) * 4


def _memory():
    mem = bytearray(0x7000)
    for lo, hi in CAPTURED_SPANS:
        for i in range(lo, hi):
            mem[i] = (i * 7 + 3) % 251 + 1  # never 0, so padding is distinguishable
    return mem


class FakeAdapter:
    def __init__(self, memory, runs):
        self.memory, self._runs = memory, list(runs)
        self.calls, self.closed = [], False

    def runs(self):
        return self._runs

    def read(self, address, length):
        self.calls.append((address, length))
        inside = any(r.state is C and r.start <= address and address + length <= r.end
                     for r in self._runs)
        assert inside, f"read outside a captured run: {address:#x}+{length:#x}"
        return bytes(self.memory[address:address + length])

    def describe(self):
        return {"layer": "fake"}

    def close(self):
        self.closed = True


def _make(tmp_path, memory=None, runs=RUNS, kind=ViewKind.PROCESS):
    (tmp_path / "img.bin").write_bytes(IMAGE_BYTES)
    kw = dict(pid=42, profile=ProfileRef("p.json")) if kind is ViewKind.PROCESS else {}
    desc = ViewDescriptor("img.bin", SHA, kind, **kw)
    path = desc.write(tmp_path / "v.mdview")
    adapter = FakeAdapter(memory if memory is not None else _memory(), runs)
    return Vol3LayerSource(path, adapter_factory=lambda d, p: adapter), adapter


@pytest.fixture
def opened(tmp_path):
    src, adapter = _make(tmp_path)
    src.open()
    yield src, adapter
    src.close()


def _captured_bytes(mem):
    return b"".join(bytes(mem[lo:hi]) for lo, hi in CAPTURED_SPANS)


# ------------------------------------------------------------------ sizes

def test_sizes_per_view(opened):
    src, _ = opened
    assert src.size_for("vas") == 0x3000
    assert src.size_for("va") == 0x6000
    assert src.size_for("raw") == len(IMAGE_BYTES)
    assert src.size == 0x3000


def test_size_is_zero_before_open_but_raw_works(tmp_path):
    src, _ = _make(tmp_path)
    assert src.size_for("vas") == 0 and src.size_for("va") == 0
    assert src.size_for("raw") == len(IMAGE_BYTES)


def test_identity(opened):
    src, _ = opened
    assert src.format_name == "image_view"
    assert src.name == "v.mdview"


# ------------------------------------------------------------------ vas

def test_vas_is_concatenation_of_captured_runs(opened):
    src, adapter = opened
    assert src.read_all("vas") == _captured_bytes(adapter.memory)
    assert src.read_range(0, 0x3000) == _captured_bytes(adapter.memory)  # default view


def test_vas_read_spanning_two_runs(opened):
    src, adapter = opened
    data = src.read_range(0x1FF8, 0x10, "vas")
    mem = adapter.memory
    assert data == bytes(mem[0x2FF8:0x3000]) + bytes(mem[0x5000:0x5008])
    assert src.read_range_valid(0x1FF8, 0x10, "vas")[1] == [(0, 0x10)]


def test_vas_read_past_end_is_short(opened):
    src, _ = opened
    assert len(src.read_range(0x2FF0, 0x100, "vas")) == 0x10
    assert src.read_range_valid(0x3000, 8, "vas") == (b"", [])


def test_adapter_only_read_inside_captured_runs(opened):
    src, adapter = opened
    src.read_all("va")
    src.read_all("vas")
    src.read_location(0x0, 0x8000)
    list(src.iter_ranges())
    src.find_all(b"zz", "va")
    assert adapter.calls  # FakeAdapter.read itself asserts containment


# ------------------------------------------------------------------ va

def test_va_pads_gaps_and_reports_exact_captured_runs(opened):
    src, adapter = opened
    data, runs = src.read_range_valid(0, 0x6000, "va")
    assert len(data) == 0x6000
    assert runs == [(0, 0x2000), (0x4000, 0x1000)]
    assert data[:0x2000] == bytes(adapter.memory[0x1000:0x3000])
    assert data[0x2000:0x4000] == b"\x00" * 0x2000
    assert data[0x4000:0x5000] == bytes(adapter.memory[0x5000:0x6000])


def test_va_partial_window_runs_are_result_relative(opened):
    src, _ = opened
    data, runs = src.read_range_valid(0x1F00, 0x300, "va")  # va 0x2F00..0x3200
    assert len(data) == 0x300
    assert runs == [(0, 0x100)]


def test_va_read_clamped_to_span(opened):
    src, _ = opened
    assert len(src.read_range(0x5F00, 0x1000, "va")) == 0x100


def test_read_range_with_validity_agrees_with_source(opened):
    src, _ = opened
    for view in ("va", "vas", "raw"):
        assert read_range_with_validity(src, 0x10, 0x2000, view) == \
            src.read_range_valid(0x10, 0x2000, view)


def test_unsupported_view_raises(opened):
    src, _ = opened
    with pytest.raises(ValueError, match="unsupported"):
        src.read_range(0, 4, "bogus")


# ------------------------------------------------------------------ raw

def test_raw_reads_image_file_bytes(opened):
    src, _ = opened
    assert src.read_range(10, 20, "raw") == IMAGE_BYTES[10:30]
    assert src.read_all("raw") == IMAGE_BYTES
    assert src.read_range_valid(0, 4, "raw") == (IMAGE_BYTES[:4], [(0, 4)])


def test_find_in_raw_view(opened):
    src, _ = opened
    assert src.find_first(bytes([5, 6, 7]), "raw") == 5
    assert src.find_all(bytes([5, 6, 7]), "raw") == [5, 261, 517, 773]


# --------------------------------------------------------- read_location

def test_read_location_coverage_gaps_and_reasons(opened):
    src, adapter = opened
    res = src.read_location(0x2000, 0x5000)  # 0x2000..0x7000
    reasons = {(g.start, g.length): g.reason for g in res.coverage.gaps}
    assert reasons == {(0x3000, 0x1000): GapReason.NOT_RESIDENT,
                       (0x4000, 0x1000): GapReason.UNMAPPED,
                       (0x6000, 0x1000): GapReason.FAILED}
    segs = list(res.segments())
    assert segs == [(0x2000, bytes(adapter.memory[0x2000:0x3000])),
                    (0x5000, bytes(adapter.memory[0x5000:0x6000]))]


def test_read_location_carries_process_location(opened):
    src, _ = opened
    loc = src.read_location(0x1000, 4).location
    assert loc.space is AddressSpace.PROCESS_VA
    assert loc.value == 0x1000
    assert loc.pid == 42
    assert loc.capture_id == SHA


@pytest.mark.parametrize("kind, space", [(ViewKind.PHYSICAL, AddressSpace.PHYSICAL)])
def test_location_space_for_physical_view(tmp_path, kind, space):
    src, _ = _make(tmp_path, kind=kind)
    loc = src.location(0x20)
    assert loc.space is space and loc.pid is None and loc.capture_id == SHA


def test_read_location_requires_open(tmp_path):
    src, _ = _make(tmp_path)
    with pytest.raises(RuntimeError, match="not open"):
        src.read_location(0, 4)


# ----------------------------------------------------------------- search

def _plant(mem, offset, needle):
    mem[offset:offset + len(needle)] = needle


def test_find_all_in_vas_and_va_coordinates(tmp_path):
    mem = _memory()
    needle = b"NEEDLE!"
    _plant(mem, 0x1100, needle)
    _plant(mem, 0x5200, needle)
    src, _ = _make(tmp_path, mem)
    with src:
        assert src.find_all(needle, "vas") == [0x100, 0x2200]
        assert src.find_all(needle, "va") == [0x100, 0x4200]
        assert src.find_first(needle, "vas") == 0x100
        assert src.find_first(b"absent-needle", "vas") is None
        assert src.find_all(b"", "vas") == []


def test_needle_straddling_gap_between_runs_is_not_found(tmp_path):
    mem = _memory()
    needle = b"ABCDEFGH"
    _plant(mem, 0x2FFC, needle[:4])   # end of run 1
    _plant(mem, 0x5000, needle[4:])   # start of run 2 (vas-adjacent, va-gapped)
    src, _ = _make(tmp_path, mem)
    with src:
        assert src.find_all(needle, "vas") == []
        assert src.find_all(needle, "va") == []


def test_needle_across_chunk_boundary_in_one_run_found_exactly_once(tmp_path, monkeypatch):
    monkeypatch.setattr(sources, "CHUNK", 16)
    mem = _memory()
    needle = b"0123456789"
    _plant(mem, 0x1000 + 12, needle)  # straddles the 16-byte window edge
    src, _ = _make(tmp_path, mem)
    with src:
        assert src.find_all(needle, "vas") == [12]
        assert src.find_all(needle, "va") == [12]


@pytest.mark.parametrize("offset", range(0, 40))
def test_chunked_search_finds_each_position_exactly_once(tmp_path, monkeypatch, offset):
    monkeypatch.setattr(sources, "CHUNK", 16)
    mem = _memory()
    needle = b"QRSTUVWX"
    _plant(mem, 0x1000 + offset, needle)
    src, _ = _make(tmp_path, mem)
    with src:
        assert src.find_all(needle, "vas") == [offset]


# ------------------------------------------------------- runs / iteration

def test_captured_runs(opened):
    src, _ = opened
    assert src.captured_runs() == ((0x1000, 0x2000, 0), (0x5000, 0x1000, 0x2000))
    assert src.va_span_start() == 0x1000


def test_iter_ranges_chunks_each_captured_run(opened, monkeypatch):
    src, adapter = opened
    monkeypatch.setattr(sources, "CHUNK", 0x800)
    got = list(src.iter_ranges())
    assert [(va, n) for va, n, _ in got] == [
        (0x1000, 0x800), (0x1800, 0x800), (0x2000, 0x800), (0x2800, 0x800),
        (0x5000, 0x800), (0x5800, 0x800)]
    assert b"".join(d for _, _, d in got) == _captured_bytes(adapter.memory)


def test_iter_ranges_requires_open(tmp_path):
    src, _ = _make(tmp_path)
    with pytest.raises(RuntimeError):
        list(src.iter_ranges())


# ---------------------------------------------------------------- metadata

def test_metadata_before_and_after_open(tmp_path):
    src, _ = _make(tmp_path)
    before = src.metadata()
    assert before["format"] == "image_view"
    assert before["capture_id"] == SHA
    assert before["raw_size"] == len(IMAGE_BYTES)
    assert before["pid"] == 42 and before["view"] == "process"
    assert "vas_size" not in before and "layer" not in before
    with src:
        after = src.metadata()
    assert after["vas_size"] == 0x3000
    assert after["va_size"] == 0x6000
    assert after["va_span_start"] == 0x1000
    assert after["layer"] == {"layer": "fake"}


# ---------------------------------------------------------------- lifecycle

def test_close_calls_adapter_close_and_resets(tmp_path):
    src, adapter = _make(tmp_path)
    src.open()
    src.close()
    assert adapter.closed
    assert src.size_for("vas") == 0
    assert src.va_span_start() is None


def test_open_is_idempotent(tmp_path):
    calls = []
    src, adapter = _make(tmp_path)
    factory = src._factory
    src._factory = lambda d, p: calls.append(1) or factory(d, p)
    src.open()
    src.open()
    assert calls == [1]


def test_context_manager_closes(tmp_path):
    src, adapter = _make(tmp_path)
    with src:
        assert not adapter.closed
    assert adapter.closed


def test_empty_view_sizes_are_zero(tmp_path):
    src, _ = _make(tmp_path, runs=[])
    with src:
        assert src.size_for("vas") == 0 and src.size_for("va") == 0
        assert src.read_all("vas") == b""
        assert src.find_all(b"x", "vas") == []


# ------------------------------------------------- dump_source integration

def test_open_dump_returns_layer_source_for_descriptor(tmp_path):
    _make(tmp_path)  # writes img.bin and v.mdview; not opened (no Volatility)
    src = open_dump(tmp_path / "v.mdview")
    assert isinstance(src, Vol3LayerSource)
    assert src.format_name == "image_view"


def test_supported_and_distinct_views(opened):
    src, _ = opened
    assert set(supported_views(src)) == {"raw", "vas", "va"}
    assert distinct_views(src) == ("vas", "va", "raw")
