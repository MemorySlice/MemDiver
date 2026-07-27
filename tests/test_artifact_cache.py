"""Unit tests for the P1.5 run-scoped artifact cache + variance mmap.

Covers memdiver.app.artifact_cache (mmapped_variance / reference_cache_scope /
cache_reference_bytes) and the two bypass rules in
tools_pipeline._read_reference_bytes (an ``on_source`` hook or key material must
force a real read every call; only plaintext, non-observed reads are cached).
"""

import os
import time

import numpy as np
import pytest

from memdiver.app.artifact_cache import (
    _REFERENCE_CACHE_VAR,
    cache_reference_bytes,
    mmapped_variance,
    reference_cache_scope,
)


def _write_var(tmp_path):
    p = tmp_path / "variance.npy"
    np.save(p, np.arange(16, dtype=np.float32))
    return str(p)


# --- mmapped_variance -------------------------------------------------------
def test_mmapped_variance_reads_and_closes(tmp_path):
    p = _write_var(tmp_path)
    mm_holder = {}
    with mmapped_variance(p) as arr:
        assert arr.dtype == np.float32
        assert np.array_equal(arr, np.arange(16, dtype=np.float32))
        # What consumers actually do — dtype-copy to an owned float64 array.
        copy = np.asarray(arr, dtype=np.float64)
        mm_holder["mm"] = arr._mmap
    # fd released on exit (reading the array now would segfault — do not).
    assert mm_holder["mm"].closed is True
    # The copy taken inside the block survives the close.
    assert np.array_equal(copy, np.arange(16))


def test_mmapped_variance_closes_on_exception(tmp_path):
    p = _write_var(tmp_path)
    mm_holder = {}
    with pytest.raises(RuntimeError):
        with mmapped_variance(p) as arr:
            mm_holder["mm"] = arr._mmap
            raise RuntimeError("boom")
    assert mm_holder["mm"].closed is True


def test_mmapped_variance_missing_file_raises(tmp_path):
    with pytest.raises((FileNotFoundError, OSError, ValueError)):
        with mmapped_variance(str(tmp_path / "nope.npy")):
            pass


# --- reference_cache_scope / cache_reference_bytes --------------------------
def test_no_scope_is_passthrough_no_caching(tmp_path):
    calls = []

    def loader():
        calls.append(1)
        return b"AAA"

    path = str(tmp_path / "r.bin")
    assert cache_reference_bytes(path, loader) == b"AAA"
    assert cache_reference_bytes(path, loader) == b"AAA"
    assert len(calls) == 2  # never cached without a scope


def test_scope_caches_then_drops(tmp_path):
    ref = tmp_path / "reference.bin"
    ref.write_bytes(b"BBBB")
    calls = []

    def loader():
        calls.append(1)
        return ref.read_bytes()

    with reference_cache_scope():
        a = cache_reference_bytes(str(ref), loader)
        b = cache_reference_bytes(str(ref), loader)
        assert a is b and len(calls) == 1  # single read shared within the scope

    # Scope dropped: nothing retained, a fresh scope re-reads.
    assert _REFERENCE_CACHE_VAR.get() is None
    with reference_cache_scope():
        cache_reference_bytes(str(ref), loader)
    assert len(calls) == 2


def test_stat_key_invalidates_on_rewrite(tmp_path):
    ref = tmp_path / "reference.bin"
    ref.write_bytes(b"CCCC")

    def loader():
        return ref.read_bytes()

    with reference_cache_scope():
        first = cache_reference_bytes(str(ref), loader)
        time.sleep(0.01)
        ref.write_bytes(b"DDDDDD")  # different size + mtime
        os.utime(ref)
        second = cache_reference_bytes(str(ref), loader)
    assert first == b"CCCC" and second == b"DDDDDD"


def test_nested_scope_reuses_outer(tmp_path):
    ref = tmp_path / "reference.bin"
    ref.write_bytes(b"E")
    calls = []

    def loader():
        calls.append(1)
        return b"E"

    with reference_cache_scope():
        cache_reference_bytes(str(ref), loader)
        with reference_cache_scope():  # inner reuses the outer dict
            cache_reference_bytes(str(ref), loader)
    assert len(calls) == 1
    assert _REFERENCE_CACHE_VAR.get() is None  # outer reset restored default


# --- integration: _read_reference_bytes bypass rules ------------------------
def test_read_reference_bypasses_on_on_source(tmp_path):
    from memdiver.app.tools_pipeline import _read_reference_bytes

    ref = tmp_path / "reference.bin"
    ref.write_bytes(b"FFFF")
    seen = []
    with reference_cache_scope():
        out1 = _read_reference_bytes(str(ref), {}, lambda s: seen.append(1))
        out2 = _read_reference_bytes(str(ref), {}, lambda s: seen.append(1))
    assert out1 == out2 == b"FFFF"
    assert len(seen) == 2  # on_source observes a real open on every call
    assert _REFERENCE_CACHE_VAR.get() is None


def test_read_reference_caches_plaintext_no_hook(tmp_path):
    from memdiver.app.tools_pipeline import _read_reference_bytes

    ref = tmp_path / "reference.bin"
    ref.write_bytes(b"GGGG")
    with reference_cache_scope():
        a = _read_reference_bytes(str(ref), {}, None)
        b = _read_reference_bytes(str(ref), {}, None)
        assert a is b  # shared cached blob
    assert a == b"GGGG"


def test_read_reference_bypasses_when_keyed(tmp_path):
    from memdiver.app.tools_pipeline import _read_reference_bytes

    ref = tmp_path / "reference.bin"
    ref.write_bytes(b"HHHH")
    # A plaintext .bin opens as a RawDumpSource that ignores key kwargs, so the
    # read still succeeds — but has_key_material() is True, so the shared cache
    # is bypassed and no secret-derived bytes are ever stored.
    keyed = {"key": b"\x00" * 32, "passphrase": None, "kem_private_key": None}
    with reference_cache_scope():
        out = _read_reference_bytes(str(ref), keyed, None)
        assert out == b"HHHH"
        assert _REFERENCE_CACHE_VAR.get() == {}  # nothing cached
