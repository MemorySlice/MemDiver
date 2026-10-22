"""``vas`` / ``va`` / ``read_range`` / ``find`` on COMPRESSED .msl regions.

The captured-run index used to point compressed runs at their ON-DISK bytes,
so every byte view of a zstd/lz4 region served codec output. Each test below
compares against the plaintext memory the file was written from, for files
written by MemDiver (multi-region, with FAILED/UNMAPPED gaps) and by memslicer.
"""

from __future__ import annotations

import random

import pytest

pytest.importorskip("zstandard")
pytest.importorskip("lz4.block")

from memdiver.core.dump_source import open_dump  # noqa: E402
from memdiver.core.dump_io import find_all_offsets  # noqa: E402
from memdiver.core.msl_helpers import get_region_page_data  # noqa: E402
from memdiver.msl.enums import CompAlgo, PageState  # noqa: E402
from memdiver.msl.reader import MslReader  # noqa: E402
from memdiver.msl.writer import MslWriter  # noqa: E402
from tests.test_msl_compress_framing import _memslicer_file, memslicer  # noqa: E402,F401

PAGE = 4096
CODECS = [CompAlgo.ZSTD, CompAlgo.LZ4]
NEEDLE = b"KEY!SECRET"
C, F, U = int(PageState.CAPTURED), int(PageState.FAILED), int(PageState.UNMAPPED)


def _specs():
    """(base, captured bytes, page_states, compression) per region."""
    rng = random.Random(11)
    out = []
    base = 0x100000
    for i, (states, algo) in enumerate([
        ([C, C, F, C], CompAlgo.ZSTD),
        ([C, U, C, C, C], CompAlgo.LZ4),
        ([C, C], CompAlgo.NONE),          # mixed file: one plain region
        ([F, C, C], CompAlgo.ZSTD),
    ]):
        n = sum(1 for s in states if s == C)
        data = bytearray(rng.randbytes(64) + bytes(n * PAGE - 64))  # compressible
        data[100:110] = NEEDLE
        data[-10:] = NEEDLE
        out.append((base, bytes(data), states, algo))
        base += (len(states) + 2 + i) * PAGE
    return out


def _expected_vas(specs):
    """The flat ``vas`` stream: captured runs in base order."""
    return b"".join(d for _, d, _, _ in sorted(specs, key=lambda s: s[0]))


@pytest.fixture
def mixed_msl(tmp_path):
    specs = _specs()
    path = tmp_path / "mixed.msl"
    w = MslWriter(path)
    for base, data, states, algo in specs:
        w.add_memory_region(base, data, page_states=states, compression=algo)
    w.add_end_of_capture()
    w.write()
    return path, specs


def test_compressed_vas_read_all_is_plaintext(mixed_msl):
    path, specs = mixed_msl
    want = _expected_vas(specs)
    with open_dump(path) as src:
        assert src.size_for("vas") == len(want)
        assert src.read_all("vas") == want
        assert b"".join(c for _, _, c in src.iter_ranges()) == want


def test_compressed_read_range_windows(mixed_msl):
    path, specs = mixed_msl
    want = _expected_vas(specs)
    with open_dump(path) as src:
        for off in (0, 1, PAGE - 3, 3 * PAGE + 5, len(want) - 7, len(want) + 1):
            for length in (1, 16, PAGE + 9, 5 * PAGE):
                assert src.read_range(off, length, view="vas") == want[off:off + length]


def test_compressed_va_view_and_page_data(mixed_msl):
    path, specs = mixed_msl
    with open_dump(path) as src:
        span = src.va_span_start()
        reader = src.get_reader()
        for base, data, states, _algo in specs:
            pos = 0
            for page, state in enumerate(states):
                got = src.read_range(base - span + page * PAGE, PAGE, view="va")
                if state == C:
                    assert got == data[pos:pos + PAGE]
                    pos += PAGE
                else:
                    assert got == bytes(PAGE)
        by_base = {r.base_addr: r for r in reader.collect_regions()}
        for base, data, _states, _algo in specs:
            assert get_region_page_data(reader, by_base[base]) == data


def test_compressed_find_vas_and_va(mixed_msl):
    path, specs = mixed_msl
    with open_dump(path) as src:
        want_vas = []
        flat = 0
        for _base, data, _s, _a in sorted(specs, key=lambda s: s[0]):
            # Per-run semantics: a run is a maximal CAPTURED page run.
            want_vas += [flat + i for i in find_all_offsets(data, NEEDLE)]
            flat += len(data)
        hits = src.find_all(NEEDLE, view="vas")
        assert len(hits) == 8
        assert src.find_first(NEEDLE, view="vas") == hits[0]
        assert src.find_all(NEEDLE, view="vas", limit=3) == hits[:3]
        for off in hits:
            assert src.read_range(off, len(NEEDLE), view="vas") == NEEDLE
        assert set(hits) <= set(want_vas)
        va_hits = src.find_all(NEEDLE, view="va")
        assert len(va_hits) == 8
        for off in va_hits:
            assert src.read_range(off, len(NEEDLE), view="va") == NEEDLE
        assert src.find_all(b"\x28\xb5\x2f\xfd", view="vas") == []  # no zstd magic


def test_compressed_run_index_is_decompressed_relative(mixed_msl):
    path, _specs_ = mixed_msl
    with MslReader(path) as reader:
        index = reader.captured_run_index()
        assert any(run.block is not None for run in index.runs)
        assert any(run.block is None for run in index.runs)
        for run in index.runs:
            assert reader.run_span(run) == run.avail == run.length
            assert len(reader.run_view(run, 0, run.length)) == run.length


def test_decompressed_payload_cache_holds_one_block(mixed_msl):
    path, _specs_ = mixed_msl
    with MslReader(path) as reader:
        blocks = [r.block for r in reader.captured_run_index().runs if r.block]
        first = reader.decompressed_payload(blocks[0])
        assert reader.decompressed_payload(blocks[0]) is first
        reader.decompressed_payload(blocks[-1])
        assert reader._payload_cache[0] == blocks[-1].file_offset
    assert reader._payload_cache is None  # dropped on close


@pytest.mark.parametrize("algo", CODECS, ids=lambda a: a.name)
@pytest.mark.parametrize("pages", [1, 3])
def test_memslicer_compressed_views(memslicer, tmp_path, algo, pages):  # noqa: F811
    path, data = _memslicer_file(memslicer, tmp_path, algo, pages)
    with open_dump(path) as src:
        assert src.read_all("vas") == data
        assert src.read_range(10, 100, view="vas") == data[10:110]
        assert src.read_range(0, len(data), view="va") == data
        assert src.find_all(data[64:80], view="vas") == find_all_offsets(data, data[64:80])
        assert src.find_first(data[:16], view="vas") == 0
        reader = src.get_reader()
        assert get_region_page_data(reader, reader.collect_regions()[0]) == data


if __name__ == "__main__":
    import sys
    sys.exit(pytest.main([__file__, "-q"]))
