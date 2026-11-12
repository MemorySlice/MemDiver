"""``app.key_material``: the run-scoped ``KeyedSources`` pool and ``probe_dump_key``.

* keyed: one open per path, the SAME source for every use, all closed when the
  block ends (also on an exception); unkeyed: exactly the old paths (the
  shared LRU through ``open_dump_source``, plain ``open_dump`` as opener);
* ``probe_dump_key`` tells the format with ``open_dump``'s detection and only
  probes an ``.msl``; the lock guard refuses a probed key with the same error
  and hint as an opened source (``KeyStatus.from_tag_status``).
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from memdiver.app import key_material as km_mod
from memdiver.app.composition import raise_if_locked
from memdiver.app.key_material import KeyedSources, ProbedKey, probe_dump_key
from memdiver.core import dump_source
from memdiver.core.service_errors import EncryptedDumpLockedError
from memdiver.core.service_result import KeyStatus
from memdiver.msl import reader as reader_mod
from memdiver.msl.enums import TagStatus
from memdiver.msl.writer import MslEncryptionConfig, MslWriter

pytest.importorskip("cryptography")

KEY = bytes(range(32))
KM = {"key": KEY, "passphrase": None, "kem_private_key": None}
UNKEYED = {"key": None, "passphrase": None, "kem_private_key": None}


def _msl(path: Path, key: bytes = None) -> Path:
    cfg = MslEncryptionConfig(raw_key=key) if key else None
    writer = MslWriter(path, pid=7, encryption=cfg)
    writer.add_memory_region(0x1000, b"\xab" * 4096)
    writer.add_end_of_capture()
    writer.write()
    return path


@pytest.fixture
def opens(monkeypatch):
    """Paths of every ``open_dump`` call (the uncached primitive, looked up in core)."""
    seen = []
    real = dump_source.open_dump

    def counting(path, **kwargs):
        seen.append(Path(path).name)
        return real(path, **kwargs)
    monkeypatch.setattr(dump_source, "open_dump", counting)
    return seen


@pytest.fixture
def two(tmp_path):
    return [_msl(tmp_path / f"d{i}.msl", KEY) for i in range(2)]


# -- KeyedSources, keyed --------------------------------------------------------------

def test_keyed_pool_opens_each_path_once_and_hands_out_the_same_source(two, opens):
    with KeyedSources(KM) as pool:
        with pool.source(two[0]) as first:
            assert first.tag_status is TagStatus.VALID
        with pool.opener(two[0], **KM) as again, pool.opener(str(two[0]), **KM) as text:
            assert again is first is text
        with pool.source(two[1]) as other:
            assert other is not first
        assert first.get_reader()._mmap is not None  # still open inside the block
    assert opens == ["d0.msl", "d1.msl"]
    with pytest.raises(RuntimeError, match="not opened"):
        first.get_reader()


def test_keyed_pool_resolves_spellings_of_one_path(two, opens, monkeypatch):
    monkeypatch.chdir(two[0].parent)
    with KeyedSources(KM) as pool:
        with pool.source(two[0]) as a, pool.source("d0.msl") as b:
            with pool.source(Path("./d0.msl")) as c:
                assert a is b is c
    assert opens == ["d0.msl"]


def test_keyed_pool_closes_everything_on_an_exception(two):
    pool = KeyedSources(KM)
    with pytest.raises(ZeroDivisionError):
        with pool:
            with pool.source(two[0]) as source:
                1 / 0  # noqa: B018 - the exception under test
    assert source._reader is None


def test_close_closes_each_source_even_when_one_raises(two):
    pool = KeyedSources(KM)
    with pool.source(two[0]) as broken, pool.source(two[1]) as fine:
        pass

    def boom():
        raise OSError("close failed")
    broken.close = boom
    with pytest.raises(OSError, match="close failed"):
        pool.close()
    assert fine._reader is None


def test_opener_with_other_kwargs_is_a_fresh_open_dump(two, opens):
    with KeyedSources(KM) as pool:
        with pool.source(two[0]) as pooled:
            pass
        other = pool.opener(two[0], key=os.urandom(32), passphrase=None, kem_private_key=None)
        with other as source:
            assert source is not pooled and source.tag_status is TagStatus.CORRUPTED
        assert pooled.tag_status is TagStatus.VALID
    assert opens == ["d0.msl", "d0.msl"]


# -- KeyedSources, unkeyed: the old paths ---------------------------------------------------

def test_unkeyed_source_is_the_cached_open_dump_source(tmp_path, monkeypatch):
    plain = _msl(tmp_path / "plain.msl")
    calls = []
    real = km_mod.open_dump_source

    def spy(path, km, region_filter=None):
        calls.append((path, km))
        return real(path, km, region_filter)
    monkeypatch.setattr(km_mod, "open_dump_source", spy)
    with KeyedSources(UNKEYED) as pool, pool.source(plain) as source:
        assert source.tag_status is TagStatus.NOT_ENCRYPTED
    assert calls == [(str(plain), UNKEYED)]


def test_unkeyed_opener_is_plain_open_dump(tmp_path, opens):
    plain = _msl(tmp_path / "plain.msl")
    with KeyedSources({}) as pool:
        first = pool.opener(plain)
        assert isinstance(first, dump_source.MslDumpSource)
        with first as source:
            assert source._reader is not None
        assert first._reader is None  # closed by its own with, as before
        assert pool.opener(plain) is not first
    assert opens == ["plain.msl", "plain.msl"]


# -- probe_dump_key + the lock guard --------------------------------------------------------

def test_probe_dump_key_probes_only_an_msl(tmp_path, monkeypatch):
    probed = []
    real = reader_mod.probe_key

    def spy(path, **kwargs):
        probed.append(Path(path).name)
        return real(path, **kwargs)
    monkeypatch.setattr(reader_mod, "probe_key", spy)
    raw = tmp_path / "proc.bin"
    raw.write_bytes(os.urandom(256))
    plain = _msl(tmp_path / "plain.msl")
    locked = _msl(tmp_path / "locked.msl", KEY)
    assert probe_dump_key(raw, KM) == ProbedKey(TagStatus.NOT_ENCRYPTED)
    assert probe_dump_key(plain, KM) == ProbedKey(TagStatus.NOT_ENCRYPTED)
    assert probe_dump_key(locked, KM) == ProbedKey(TagStatus.VALID)
    assert probe_dump_key(str(locked), {}) == ProbedKey(TagStatus.MISSING_KEY)
    assert probed == ["plain.msl", "locked.msl", "locked.msl"]


@pytest.mark.parametrize("km", [{}, {"key": os.urandom(32)}], ids=["no-key", "wrong-key"])
def test_a_probed_lock_is_refused_exactly_like_an_opened_one(tmp_path, km):
    locked = _msl(tmp_path / "locked.msl", KEY)
    with pytest.raises(EncryptedDumpLockedError) as probed:
        raise_if_locked(probe_dump_key(locked, km))
    with dump_source.open_dump(locked, **km) as source:
        with pytest.raises(EncryptedDumpLockedError) as opened:
            raise_if_locked(source)
    assert (probed.value.code, probed.value.category, probed.value.message) == (
        opened.value.code, opened.value.category, opened.value.message)
    assert probed.value.code == "encrypted_dump_locked"


# -- KeyStatus.from_tag_status --------------------------------------------------------------

@pytest.mark.parametrize("status", list(TagStatus))
def test_from_source_delegates_to_from_tag_status(status):
    class _Source:
        tag_status = status
    assert KeyStatus.from_source(_Source()) == KeyStatus.from_tag_status(status)


def test_from_tag_status_hints():
    assert KeyStatus.from_tag_status(TagStatus.VALID) == KeyStatus(TagStatus.VALID, True)
    assert KeyStatus.from_tag_status(TagStatus.NOT_ENCRYPTED).hint is None
    missing = KeyStatus.from_tag_status(TagStatus.MISSING_KEY)
    corrupted = KeyStatus.from_tag_status(TagStatus.CORRUPTED)
    assert not missing.decrypted and not corrupted.decrypted
    assert missing.hint == "dump is encrypted; no valid decryption key was supplied"
    assert corrupted.hint == "AEAD verification failed (wrong key or tampered file)"
    assert KeyStatus.from_source(object()) == KeyStatus()  # no tag_status: plaintext
