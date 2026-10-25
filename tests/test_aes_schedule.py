"""T3.1: the AES key-schedule finder (``algorithms/keyfinders/aes_schedule.py``)."""

import ctypes
import mmap
import os
import random
from pathlib import Path

import pytest

from memdiver.algorithms.base import AnalysisContext
from memdiver.algorithms.keyfinders.aes_schedule import (
    AesScheduleAlgorithm, find_aes_schedules,
)
from memdiver.algorithms.keyfinders.aes_tables import (
    expand_key, inv_mix_column, inverse_layout, mix_column,
)
from memdiver.algorithms.registry import AlgorithmRegistry

#: FIPS-197 Appendix A: key -> last word of the expanded schedule.
FIPS_197 = {
    "2b7e151628aed2a6abf7158809cf4f3c": "b6630ca6",
    "8e73b0f7da0e6452c810f32b809079e562f8ead2522c6b7b": "01002202",
    "603deb1015ca71be2b73aef0857d77811f352c073b6108d72d9810a30914dff4": "706c631e",
}
LIBCRYPTO = Path("/opt/homebrew/lib/libcrypto.3.dylib")


def _noise(size, seed=7):
    return bytearray(random.Random(seed).randbytes(size))


def _swap32(blob):
    return b"".join(blob[i:i + 4][::-1] for i in range(0, len(blob), 4))


def _plant(buf, offset, blob):
    buf[offset:offset + len(blob)] = blob


def _found(matches):
    return {(m.offset, m.metadata["orientation"], m.metadata["byte_order"]): m.metadata["key_hex"]
            for m in matches}


@pytest.mark.parametrize("key_hex,last_word", FIPS_197.items())
def test_expand_key_matches_fips_197(key_hex, last_word):
    schedule = expand_key(bytes.fromhex(key_hex))
    assert schedule[:len(key_hex) // 2].hex() == key_hex
    assert schedule[-4:].hex() == last_word


def test_mix_columns_round_trip():
    col = bytes.fromhex("db135345")
    assert mix_column(col).hex() == "8e4da1bc"  # FIPS-197 / standard MixColumns vector
    assert inv_mix_column(mix_column(col)) == col


@pytest.mark.parametrize("bits", [128, 192, 256])
@pytest.mark.parametrize("orientation", ["forward", "inverse"])
@pytest.mark.parametrize("byte_order", ["natural", "swapped32"])
def test_finds_each_layout_at_an_odd_offset(bits, orientation, byte_order):
    key = bytes(range(1, bits // 8 + 1))
    blob = expand_key(key)
    if orientation == "inverse":
        blob = inverse_layout(blob)
    if byte_order == "swapped32":
        blob = _swap32(blob)
    buf = _noise(1 << 16)
    _plant(buf, 12_345, blob)
    matches = find_aes_schedules(bytes(buf))
    assert _found(matches) == {(12_345, orientation, byte_order): key.hex()}
    match = matches[0]
    assert match.confidence == 1.0 and match.label == f"aes{bits}_schedule"
    assert match.length == len(blob) and match.data == blob


def test_key_offset_only_when_the_key_bytes_are_verbatim():
    key = bytes(range(16))
    buf = _noise(4096)
    _plant(buf, 101, expand_key(key))
    _plant(buf, 1001, inverse_layout(expand_key(key)))
    _plant(buf, 2001, _swap32(expand_key(key)))
    by_offset = {m.offset: m.metadata for m in find_aes_schedules(bytes(buf))}
    assert by_offset[101]["key_offset"] == 101
    assert by_offset[1001]["key_offset"] == 1001 + 160  # AES-128 key is the last round key
    assert "key_offset" not in by_offset[2001]


def test_stride_skips_unaligned_schedules():
    buf = _noise(8192)
    _plant(buf, 1001, expand_key(bytes(16 * [7]) + b""))
    _plant(buf, 4000, expand_key(bytes(range(16))))
    assert [m.offset for m in find_aes_schedules(bytes(buf), stride=1)] == [1001, 4000]
    assert [m.offset for m in find_aes_schedules(bytes(buf), stride=4)] == [4000]


def test_truncated_schedule_scores_partial_confidence():
    schedule = expand_key(bytes(range(16)))
    buf = _noise(1000)
    data = bytes(buf[:900]) + schedule[:96]  # 24 of 44 words survive, 20 of 40 derived
    [match] = find_aes_schedules(data)
    assert match.offset == 900 and match.length == 96
    assert match.confidence == pytest.approx(20 / 40)
    assert find_aes_schedules(data, min_confidence=0.6) == []


def test_corrupted_round_lowers_confidence():
    schedule = bytearray(expand_key(bytes(range(16))))
    schedule[100] ^= 0xFF
    buf = _noise(2048)
    _plant(buf, 500, bytes(schedule))
    [match] = find_aes_schedules(bytes(buf))
    assert match.metadata["matched_words"] == 39 and match.metadata["derived_words"] == 40


@pytest.mark.parametrize("fill", [0x00, 0xFF, 0x09, 0x52, 0x63])
def test_constant_fill_is_never_a_schedule(fill):
    assert find_aes_schedules(bytes([fill]) * (1 << 18)) == []


def test_random_noise_has_no_false_positives():
    assert find_aes_schedules(bytes(_noise(8 << 20, seed=11))) == []


def test_schedule_across_a_slab_boundary(monkeypatch):
    from memdiver.algorithms.keyfinders import aes_schedule
    monkeypatch.setattr(aes_schedule, "_SLAB", 4096)
    buf = _noise(20_000)
    _plant(buf, 4096 - 50, expand_key(bytes(range(32))))
    _plant(buf, 3 * 4096 - 1, inverse_layout(expand_key(bytes(range(24)))))
    assert [m.offset for m in find_aes_schedules(bytes(buf))] == [4046, 12287]


def test_accepts_an_mmap(tmp_path):
    buf = _noise(1 << 16)
    _plant(buf, 777, expand_key(bytes(range(16))))
    path = tmp_path / "dump.bin"
    path.write_bytes(bytes(buf))
    with open(path, "rb") as fh, mmap.mmap(fh.fileno(), 0, access=mmap.ACCESS_READ) as mm:
        assert [m.offset for m in find_aes_schedules(mm)] == [777]


@pytest.mark.parametrize("kwargs", [{"key_bits": [512]}, {"orientations": ["sideways"]},
                                    {"byte_orders": ["pdp"]}, {"stride": 0},
                                    {"orientations": []}])
def test_rejects_bad_parameters(kwargs):
    with pytest.raises(ValueError):
        find_aes_schedules(b"\0" * 1024, **kwargs)


def test_algorithm_is_registered_and_reads_context_extra():
    registry = AlgorithmRegistry()
    registry.discover()
    algorithm = registry.get("aes_schedule")
    assert isinstance(algorithm, AesScheduleAlgorithm)
    buf = _noise(4096)
    _plant(buf, 64, expand_key(bytes(range(16))))
    _plant(buf, 1024, expand_key(bytes(range(32))))
    context = AnalysisContext("openssl", "13", "pre", extra={"aes_key_bits": [256]})
    result = algorithm.run(bytes(buf), context)
    assert [m.offset for m in result.matches] == [1024]
    assert result.confidence == 1.0 and result.metadata == {"schedules": 1}
    assert algorithm.estimate_working_set(100 << 20) < 100 << 20


@pytest.mark.skipif(not LIBCRYPTO.is_file(), reason="needs Homebrew OpenSSL 3 libcrypto")
@pytest.mark.parametrize("bits", [128, 192, 256])
def test_finds_real_openssl_aes_key_structs(bits):
    """OpenSSL's C ``AES_KEY`` keeps host-endian u32 round keys: swapped32 on LE hosts."""
    lib = ctypes.CDLL(str(LIBCRYPTO))
    key = os.urandom(bits // 8)
    buf = _noise(1 << 15)
    for offset, setter in ((3001, lib.AES_set_encrypt_key), (9003, lib.AES_set_decrypt_key)):
        aes_key = ctypes.create_string_buffer(244)  # rd_key[60] + rounds
        assert setter(key, bits, aes_key) == 0
        _plant(buf, offset, aes_key.raw)
    assert _found(find_aes_schedules(bytes(buf))) == {
        (3001, "forward", "swapped32"): key.hex(), (9003, "inverse", "swapped32"): key.hex()}
