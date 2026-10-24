"""Argon2id parameter handling (spec §10.5 "Minimum") across producer/consumer.

Consumers derive with exactly the header-stored parameters; producers never
store parameters below the minimum; legacy MemDiver files (weak header,
CEK derived with clamped params) still open via a single retry.
"""

import logging

import pytest

from memdiver.msl import crypto
from memdiver.msl.enums import (ARGON2ID_MIN_LANES, ARGON2ID_MIN_MEMORY_KIB,
                                ARGON2ID_MIN_TIME, KdfType, TagStatus)
from memdiver.msl.reader import MslReader
from memdiver.msl.writer import MslEncryptionConfig, MslWriter

pytestmark = pytest.mark.skipif(not crypto.kdf_is_available(KdfType.ARGON2ID),
                                reason="argon2-cffi not installed")

PASSPHRASE = b"correct horse"
WEAK = (1, 8, 1)
MINIMUM = (ARGON2ID_MIN_TIME, ARGON2ID_MIN_MEMORY_KIB, ARGON2ID_MIN_LANES)


def _write(path, cfg, **kwargs):
    w = MslWriter(path, pid=7, encryption=cfg, **kwargs)
    w.add_memory_region(0x1000, b"\xAB" * 4096)
    w.add_end_of_capture()
    w.write()
    return path


def _weak_header_cfg() -> MslEncryptionConfig:
    """Config whose header will store WEAK params (bypasses __post_init__)."""
    cfg = MslEncryptionConfig(kdf_type=KdfType.ARGON2ID, passphrase=PASSPHRASE)
    cfg.kdf_time, cfg.kdf_memory, cfg.kdf_lanes = WEAK
    return cfg


def _header_params(path):
    with MslReader(path) as reader:
        ep = reader._enc_params
        return ep.kdf_time, ep.kdf_memory, ep.kdf_lanes


def _exact_weak_file(path, monkeypatch):
    """Header says WEAK and the CEK is derived with exactly WEAK (foreign
    producer such as memslicer test fixtures)."""
    with monkeypatch.context() as m:
        m.setattr(crypto, "clamp_argon2id_params", lambda t, mem, lanes: (t, mem, lanes))
        return _write(path, _weak_header_cfg())


# -- derive_key_argon2id --

def test_derive_enforces_minimum_by_default():
    salt = b"s" * 16
    clamped = crypto.derive_key_argon2id(PASSPHRASE, salt, *WEAK)
    assert clamped == crypto.derive_key_argon2id(PASSPHRASE, salt, *MINIMUM)


def test_derive_exact_params_warns(caplog):
    salt = b"s" * 16
    with caplog.at_level(logging.WARNING, logger="memdiver.msl.crypto"):
        exact = crypto.derive_key_argon2id(PASSPHRASE, salt, *WEAK,
                                           enforce_minimum=False)
    assert exact != crypto.derive_key_argon2id(PASSPHRASE, salt, *MINIMUM)
    assert "below the spec minimum" in caplog.text


def test_below_minimum_and_clamp_helpers():
    assert crypto.argon2id_below_minimum(*WEAK)
    assert not crypto.argon2id_below_minimum(*MINIMUM)
    assert crypto.clamp_argon2id_params(*WEAK) == MINIMUM
    assert crypto.clamp_argon2id_params(5, 1 << 17, 8) == (5, 1 << 17, 8)


# -- consumer --

def test_consumer_derives_with_stored_weak_params(tmp_path, monkeypatch, caplog):
    path = _exact_weak_file(tmp_path / "exact.msl", monkeypatch)
    assert _header_params(path) == WEAK
    with caplog.at_level(logging.WARNING):
        with MslReader(path, passphrase=PASSPHRASE) as reader:
            assert reader.tag_status == TagStatus.VALID
            assert len(reader.collect_regions()) == 1
    assert "legacy" not in caplog.text


def test_legacy_clamped_cek_file_reads_via_retry(tmp_path, caplog):
    # Old MemDiver behaviour: weak params in header, CEK from clamped params.
    path = _write(tmp_path / "legacy.msl", _weak_header_cfg())
    assert _header_params(path) == WEAK
    with caplog.at_level(logging.WARNING, logger="memdiver.msl.reader"):
        with MslReader(path, passphrase=PASSPHRASE) as reader:
            assert reader.tag_status == TagStatus.VALID
            assert len(reader.collect_regions()) == 1
    assert "legacy" in caplog.text


def test_wrong_passphrase_on_weak_file_still_corrupted(tmp_path, monkeypatch):
    path = _exact_weak_file(tmp_path / "exact.msl", monkeypatch)
    with MslReader(path, passphrase=b"wrong") as reader:
        assert reader.tag_status == TagStatus.CORRUPTED


def test_memslicer_weak_kdf_file_reads_valid(tmp_path):
    ms = pytest.importorskip("memslicer.msl.writer")
    from memslicer.msl.encryption import EncryptionParams, derive_key
    from memslicer.msl.constants import FLAG_ENCRYPTED
    from memslicer.msl.types import FileHeader, MemoryRegion, ProcessIdentity
    params = EncryptionParams(kdf_time=1, kdf_memory=8, kdf_lanes=1)
    path = tmp_path / "memslicer.msl"
    with open(path, "wb") as f:
        w = ms.MSLWriter(f, FileHeader(pid=4242, flags=FLAG_ENCRYPTED),
                         encryption_key=derive_key(PASSPHRASE.decode(), params),
                         encryption_params=params)
        w.write_process_identity(ProcessIdentity(ppid=1, exe_path="/bin/x"))
        w.write_memory_region(MemoryRegion(
            base_addr=0x10000, region_size=4096, protection=3,
            page_states=[0], page_data_chunks=[bytes(4096)]))
        w.finalize()
    with MslReader(path, passphrase=PASSPHRASE) as reader:
        assert reader.tag_status == TagStatus.VALID


# -- producer --

def test_producer_raises_weak_config_to_minimum(tmp_path):
    cfg = MslEncryptionConfig(kdf_type=KdfType.ARGON2ID, passphrase=PASSPHRASE,
                              kdf_time=1, kdf_memory=8, kdf_lanes=1)
    assert (cfg.kdf_time, cfg.kdf_memory, cfg.kdf_lanes) == MINIMUM
    path = _write(tmp_path / "new.msl", cfg)
    assert _header_params(path) == MINIMUM
    with MslReader(path, passphrase=PASSPHRASE) as reader:
        assert reader.tag_status == TagStatus.VALID


def test_producer_keeps_stronger_params():
    cfg = MslEncryptionConfig(kdf_type=KdfType.ARGON2ID, passphrase=PASSPHRASE,
                              kdf_time=4, kdf_memory=1 << 17, kdf_lanes=8)
    assert (cfg.kdf_time, cfg.kdf_memory, cfg.kdf_lanes) == (4, 1 << 17, 8)


def test_rewrap_keeps_source_weak_params(tmp_path, monkeypatch):
    src = _exact_weak_file(tmp_path / "src.msl", monkeypatch)
    with MslReader(src, passphrase=PASSPHRASE) as reader:
        reuse = MslEncryptionConfig.rewrap(reader._rewrap_material())
        assert (reuse.kdf_time, reuse.kdf_memory, reuse.kdf_lanes) == WEAK
        copy = _write(tmp_path / "copy.msl", reuse,
                      dump_uuid=reader.file_header.dump_uuid)
    assert _header_params(copy) == WEAK
    with MslReader(copy, passphrase=PASSPHRASE) as reader:
        assert reader.tag_status == TagStatus.VALID
