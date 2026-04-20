"""Tests for api/services/reader_cache.py — the MslReader LRU cache.

Covers the correctness properties the PR 3 plan calls out:

- Same-path acquire returns the identical reader instance (warm reuse).
- LRU eviction respects refcounts: idle entries are closed immediately,
  in-use entries are marked evicted and closed on last release (deferred
  close). No TOCTOU race where an in-use reader is closed out from under
  an active reader.
- shutdown() closes all idle entries and flags in-use ones for deferred
  close; subsequent acquires reopen cleanly.
- invalidate() drops a specific path, useful for "file was replaced".
- Concurrent acquire/release from multiple threads is safe.
- The cached_dump_source context manager auto-detects MSL vs raw and
  only caches MSL inputs; raw inputs still work end-to-end.
- MCP tool functions see the reuse benefit — integration-level proof
  that the rewired call sites actually share the cache.
"""

from __future__ import annotations

import sys
import threading
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from api.services.reader_cache import (
    DEFAULT_MAX_SIZE,
    MslReaderCache,
    cached_dump_source,
    cached_msl_reader,
    get_default_cache,
    set_default_cache,
    shutdown_default_cache,
)
from tests.fixtures.generate_msl_fixtures import (
    write_aslr_fixture,
    write_msl_fixture,
)


@pytest.fixture(autouse=True)
def _isolated_default_cache():
    """Every test gets a fresh module cache, then cleans up."""
    set_default_cache(MslReaderCache(max_size=4))
    yield
    shutdown_default_cache()


@pytest.fixture
def msl_path(tmp_path):
    return write_msl_fixture(tmp_path / "fixture.msl")


# --- Same-path reuse -----------------------------------------------------


def test_acquire_same_path_returns_same_reader(msl_path):
    """Two context-manager acquires of the same path reuse the reader."""
    with cached_msl_reader(msl_path) as r1:
        id1 = id(r1)
    with cached_msl_reader(msl_path) as r2:
        id2 = id(r2)
    assert id1 == id2


def test_reader_stays_open_after_release(msl_path):
    """After the context manager exits, the reader is still open in the
    cache so a subsequent acquire is an instant hit (not a reopen)."""
    with cached_msl_reader(msl_path) as reader:
        reader.collect_regions()
    # Reader mmap must still be alive post-release.
    cache = get_default_cache()
    stats = cache.stats()
    assert stats["size"] == 1
    assert stats["refcounts"][str(msl_path.resolve())] == 0
    # Internal cache slots populated on first acquire should survive.
    with cached_msl_reader(msl_path) as reader2:
        assert reader2._regions_cache is not None


# --- LRU eviction --------------------------------------------------------


def test_idle_lru_eviction_closes_oldest(tmp_path):
    """Filling past max_size closes the oldest idle entries immediately."""
    cache = MslReaderCache(max_size=2)
    set_default_cache(cache)

    p1 = write_msl_fixture(tmp_path / "a.msl")
    p2 = write_msl_fixture(tmp_path / "b.msl")
    p3 = write_msl_fixture(tmp_path / "c.msl")

    with cached_msl_reader(p1) as r1:
        r1.collect_regions()
    with cached_msl_reader(p2) as r2:
        r2.collect_regions()
    with cached_msl_reader(p3) as r3:
        r3.collect_regions()

    stats = cache.stats()
    assert stats["size"] == 2
    # p1 should have been evicted (it's the oldest idle entry).
    keys = stats["keys"]
    assert str(p1.resolve()) not in keys
    assert str(p2.resolve()) in keys
    assert str(p3.resolve()) in keys


def test_in_use_entry_survives_eviction_with_deferred_close(tmp_path):
    """If the oldest entry is in-use, eviction removes it from the map
    but defers the reader close until the holder releases."""
    cache = MslReaderCache(max_size=2)
    set_default_cache(cache)

    p1 = write_msl_fixture(tmp_path / "a.msl")
    p2 = write_msl_fixture(tmp_path / "b.msl")
    p3 = write_msl_fixture(tmp_path / "c.msl")

    # Acquire p1 and hold the reference.
    with cached_msl_reader(p1) as r1:
        r1.collect_regions()
        # Acquire p2 and p3; p1 is over-capacity and must be deferred-
        # evicted because we still hold r1.
        with cached_msl_reader(p2):
            with cached_msl_reader(p3):
                # While nested, r1 should still be readable — not closed.
                assert r1._mmap is not None
                # And p1 should have been deferred-evicted from the map.
                keys = cache.stats()["keys"]
                assert str(p1.resolve()) not in keys
                # Can still read from r1.
                header = r1.file_header
                assert header is not None

    # After the outermost release, the deferred-evicted reader should be closed.
    assert r1._mmap is None


def test_evicted_entry_reopens_on_next_acquire(tmp_path):
    """Re-acquiring a path after eviction opens a fresh reader instance."""
    cache = MslReaderCache(max_size=1)
    set_default_cache(cache)

    p1 = write_msl_fixture(tmp_path / "a.msl")
    p2 = write_msl_fixture(tmp_path / "b.msl")

    with cached_msl_reader(p1) as r1:
        id1 = id(r1)
    with cached_msl_reader(p2):
        pass  # evicts p1
    with cached_msl_reader(p1) as r1_again:
        id1_again = id(r1_again)

    assert id1 != id1_again  # fresh instance after eviction


# --- invalidate ----------------------------------------------------------


def test_invalidate_drops_idle_entry(msl_path):
    """invalidate() removes the cache entry and closes the idle reader."""
    with cached_msl_reader(msl_path) as reader:
        pass
    assert get_default_cache().stats()["size"] == 1
    assert get_default_cache().invalidate(msl_path) is True
    assert get_default_cache().stats()["size"] == 0
    assert reader._mmap is None


def test_invalidate_nonexistent_is_noop(tmp_path):
    """invalidate() on an uncached path returns False without error."""
    result = get_default_cache().invalidate(tmp_path / "never_cached.msl")
    assert result is False


# --- shutdown ------------------------------------------------------------


def test_shutdown_closes_all_idle(tmp_path):
    p1 = write_msl_fixture(tmp_path / "a.msl")
    p2 = write_msl_fixture(tmp_path / "b.msl")
    with cached_msl_reader(p1) as r1:
        pass
    with cached_msl_reader(p2) as r2:
        pass

    get_default_cache().shutdown()
    assert r1._mmap is None
    assert r2._mmap is None
    assert get_default_cache().stats()["size"] == 0


def test_shutdown_defers_close_for_in_use(msl_path):
    """shutdown() during an active use leaves the reader alive for the
    holder to close on release."""
    with cached_msl_reader(msl_path) as reader:
        get_default_cache().shutdown()
        assert reader._mmap is not None  # still usable
        _ = reader.file_header  # must not raise
    # After context exit, the deferred close should have fired.
    assert reader._mmap is None


# --- concurrent access ---------------------------------------------------


def test_concurrent_acquire_is_safe(msl_path):
    """Four threads acquiring the same path concurrently must not crash
    and must all see the same reader instance."""
    seen_ids: list[int] = []
    errors: list[BaseException] = []
    barrier = threading.Barrier(4)
    lock = threading.Lock()

    def worker():
        try:
            barrier.wait()
            with cached_msl_reader(msl_path) as reader:
                header = reader.file_header
                regions = reader.collect_regions()
                with lock:
                    seen_ids.append(id(reader))
                assert header is not None
                assert len(regions) == 1
        except BaseException as exc:  # noqa: BLE001
            errors.append(exc)

    threads = [threading.Thread(target=worker) for _ in range(4)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert not errors, f"worker errors: {errors}"
    assert len(seen_ids) == 4
    assert len(set(seen_ids)) == 1  # all saw the same instance


# --- cached_dump_source auto-detect -------------------------------------


def test_cached_dump_source_msl_path_uses_cache(msl_path):
    """An MSL path through cached_dump_source borrows from the cache."""
    with cached_dump_source(msl_path) as src:
        assert src.format_name == "msl"
        data = src.read_range(0, 16)
        assert len(data) <= 16

    # After use, the MSL reader should still be in the cache.
    assert get_default_cache().stats()["size"] == 1


def test_cached_dump_source_raw_path_does_not_touch_cache(tmp_path):
    """A raw .dump path should not populate the cache at all."""
    raw = tmp_path / "fake.dump"
    raw.write_bytes(b"\x00" * 128 + b"\x11\x22\x33\x44" + b"\x00" * 128)

    with cached_dump_source(raw) as src:
        assert src.format_name == "raw"
        data = src.read_range(0, 32)
        assert len(data) == 32

    assert get_default_cache().stats()["size"] == 0


def test_cached_dump_source_aslr_fixture_round_trips(tmp_path):
    """The ASLR test fixture is non-default (different key at 0x200);
    make sure cached_dump_source works end-to-end on it."""
    p = write_aslr_fixture(
        tmp_path / "aslr.msl",
        region_base=0x7FFF00000000,
        key_bytes=b"\xFF" * 32,
    )
    with cached_dump_source(p) as src:
        assert src.format_name == "msl"
        # The fixture's region is one 4096-byte page.
        assert src.size == 4096
        # Filler byte 0x42 is visible outside the key region.
        sample = src.read_range(0, 16)
        assert sample == b"\x42" * 16


# --- integration: MCP tool call reuses the cache ------------------------


def test_mcp_tool_get_session_info_uses_cache(msl_path):
    """Two sequential get_session_info calls on the same file must share
    one reader — proving the tools_inspect.py rewire is effective."""
    from mcp_server.session import ToolSession
    from mcp_server.tools_inspect import get_session_info

    session = ToolSession()
    report1 = get_session_info(session, str(msl_path))
    report2 = get_session_info(session, str(msl_path))

    assert "error" not in report1
    assert report1["dump_uuid"] == report2["dump_uuid"]
    # Cache must have exactly one entry for this path after both calls.
    stats = get_default_cache().stats()
    assert stats["size"] == 1
    assert str(msl_path.resolve()) in stats["keys"]


def test_mcp_tool_read_hex_on_msl_caches(msl_path):
    """read_hex on an MSL file must leave the reader warm in the cache."""
    from mcp_server.session import ToolSession
    from mcp_server.tools_inspect import read_hex

    session = ToolSession()
    r1 = read_hex(session, str(msl_path), offset=0, length=32)
    r2 = read_hex(session, str(msl_path), offset=0, length=32)
    assert r1["hex_lines"] == r2["hex_lines"]
    assert get_default_cache().stats()["size"] == 1


def test_mcp_tool_read_hex_on_raw_does_not_cache(tmp_path):
    """read_hex on a raw .dump file must not populate the MSL reader cache."""
    from mcp_server.session import ToolSession
    from mcp_server.tools_inspect import read_hex

    raw = tmp_path / "tiny.dump"
    raw.write_bytes(b"\x42" * 256)
    session = ToolSession()
    result = read_hex(session, str(raw), offset=0, length=16)
    assert "error" not in result
    assert result["format"] == "raw"
    assert get_default_cache().stats()["size"] == 0


# --- misc ---------------------------------------------------------------


def test_default_max_size_is_32():
    """Sanity: the module constant should match the plan spec."""
    assert DEFAULT_MAX_SIZE == 32


def test_invalid_max_size_rejected():
    with pytest.raises(ValueError):
        MslReaderCache(max_size=0)
