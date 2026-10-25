"""Tests for core/image/context.py: ImageContextCache, ImageContext, file_sha256."""

import builtins
import hashlib
import pickle
import sys
import threading
import time
from pathlib import Path

import pytest

import memdiver.core.image.context as context
from memdiver.core.image.context import (
    ImageContext,
    ImageContextCache,
    file_sha256,
    require_volatility3,
)
from memdiver.core.service_errors import CapabilityError, ErrorCategory


def _ctx(tag="x"):
    return ImageContext(Path(f"/img/{tag}"), context=object(), physical_layer="base")


# ------------------------------------------------------------ ImageContextCache

def test_cache_builds_once_per_key_and_returns_the_same_object():
    cache, calls = ImageContextCache(), []

    def build():
        calls.append(1)
        return _ctx()

    first = cache.get_or_build("k", build)
    assert cache.get_or_build("k", build) is first
    assert len(calls) == 1 and len(cache) == 1


def test_cache_evicts_the_least_recently_used_key():
    cache = ImageContextCache(maxsize=2)
    for key in "abc":
        cache.get_or_build(key, lambda k=key: _ctx(k))
    assert len(cache) == 2
    rebuilt = []
    cache.get_or_build("a", lambda: rebuilt.append("a") or _ctx("a"))   # evicted
    assert rebuilt == ["a"]


def test_cache_hit_refreshes_recency():
    cache = ImageContextCache(maxsize=2)
    cache.get_or_build("a", lambda: _ctx("a"))
    cache.get_or_build("b", lambda: _ctx("b"))
    cache.get_or_build("a", lambda: pytest.fail("a must be cached"))   # a is now newest
    cache.get_or_build("c", lambda: _ctx("c"))                         # evicts b, not a
    rebuilt = []
    cache.get_or_build("a", lambda: rebuilt.append("a") or _ctx("a"))
    cache.get_or_build("b", lambda: rebuilt.append("b") or _ctx("b"))
    assert rebuilt == ["b"]


def test_cache_clear_empties_and_forces_a_rebuild():
    cache, calls = ImageContextCache(), []
    cache.get_or_build("k", lambda: calls.append(1) or _ctx())
    cache.clear()
    assert len(cache) == 0
    cache.get_or_build("k", lambda: calls.append(1) or _ctx())
    assert len(calls) == 2


def test_cache_len_counts_distinct_keys():
    cache = ImageContextCache(maxsize=10)
    for i in range(3):
        cache.get_or_build(i, _ctx)
    assert len(cache) == 3


def test_concurrent_get_or_build_builds_the_same_key_once():
    cache, calls, results = ImageContextCache(), [], []
    barrier = threading.Barrier(8)

    def build():
        calls.append(1)
        time.sleep(0.05)
        return _ctx()

    def worker():
        barrier.wait()
        results.append(cache.get_or_build("same", build))

    threads = [threading.Thread(target=worker) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert len(calls) == 1
    assert len(results) == 8 and all(r is results[0] for r in results)


def test_a_failing_build_is_not_cached():
    cache = ImageContextCache()
    with pytest.raises(RuntimeError):
        cache.get_or_build("k", lambda: (_ for _ in ()).throw(RuntimeError("boom")))
    assert len(cache) == 0
    assert cache.get_or_build("k", _ctx) is not None


# ------------------------------------------------------------ ImageContext

def test_image_context_refuses_pickling():
    with pytest.raises(TypeError, match="never pickled"):
        pickle.dumps(_ctx())


def test_has_kernel_follows_kernel_paging():
    ctx = _ctx()
    assert not ctx.has_kernel
    ctx.kernel_paging = object()
    assert ctx.has_kernel


def test_kernel_without_a_profile_is_a_capability_error():
    with pytest.raises(CapabilityError) as info:
        _ = _ctx().kernel
    assert info.value.category is ErrorCategory.INVALID_INPUT


# ------------------------------------------------------------ file_sha256

@pytest.fixture
def counted_hash(monkeypatch):
    calls = []
    real = context._hash_file
    monkeypatch.setattr(context, "_hash_file", lambda p: calls.append(p) or real(p))
    return calls


def test_file_sha256_matches_hashlib(tmp_path, counted_hash):
    f = tmp_path / "img.bin"
    f.write_bytes(b"memory" * 1000)
    assert file_sha256(f, index_dir=tmp_path) == hashlib.sha256(b"memory" * 1000).hexdigest()


def test_file_sha256_second_call_uses_the_index(tmp_path, counted_hash):
    f = tmp_path / "img.bin"
    f.write_bytes(b"abc")
    first = file_sha256(f, index_dir=tmp_path)
    assert file_sha256(f, index_dir=tmp_path) == first
    assert len(counted_hash) == 1
    assert (tmp_path / "sha256_index.json").is_file()


def test_file_sha256_rehashes_when_the_file_changes(tmp_path, counted_hash):
    f = tmp_path / "img.bin"
    f.write_bytes(b"abc")
    file_sha256(f, index_dir=tmp_path)
    f.write_bytes(b"abcd")   # size differs
    assert file_sha256(f, index_dir=tmp_path) == hashlib.sha256(b"abcd").hexdigest()
    assert len(counted_hash) == 2


def test_file_sha256_rehashes_on_mtime_change_with_same_size(tmp_path, counted_hash):
    import os
    f = tmp_path / "img.bin"
    f.write_bytes(b"abc")
    file_sha256(f, index_dir=tmp_path)
    f.write_bytes(b"xyz")
    os.utime(f, ns=(1, f.stat().st_mtime_ns + 5_000_000_000))
    assert file_sha256(f, index_dir=tmp_path) == hashlib.sha256(b"xyz").hexdigest()
    assert len(counted_hash) == 2


def test_file_sha256_survives_a_corrupt_index(tmp_path, counted_hash):
    f = tmp_path / "img.bin"
    f.write_bytes(b"abc")
    (tmp_path / "sha256_index.json").write_text("{not json")
    assert file_sha256(f, index_dir=tmp_path) == hashlib.sha256(b"abc").hexdigest()


def test_file_sha256_defaults_to_the_memdiver_cache_dir(tmp_path, monkeypatch, counted_hash):
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "home"))
    f = tmp_path / "img.bin"
    f.write_bytes(b"abc")
    file_sha256(f)
    index = context.cache_dir() / "sha256_index.json"
    assert index.is_file() and str(tmp_path / "home") in str(index)


# ------------------------------------------------------------ require_volatility3

def test_require_volatility3_passes_when_installed():
    require_volatility3()


def test_require_volatility3_raises_a_capability_error_when_missing(monkeypatch):
    monkeypatch.setitem(sys.modules, "volatility3.framework", None)
    real_import = builtins.__import__

    def fake(name, *a, **kw):
        if name == "volatility3.framework":
            raise ImportError("no vol3")
        return real_import(name, *a, **kw)

    monkeypatch.setattr(builtins, "__import__", fake)
    with pytest.raises(CapabilityError) as info:
        require_volatility3()
    assert info.value.category is ErrorCategory.UNSUPPORTED
    assert "volatility3" in str(info.value)


def test_image_context_carries_a_reentrant_lock():
    """vol3 contexts are shared across threads by the cache; all vol3 calls hold this."""
    ctx = ImageContext(Path("/x"), object(), "phys")
    with ctx.lock:
        with ctx.lock:   # re-entrant: adapters nest vmas() inside runs()
            pass
