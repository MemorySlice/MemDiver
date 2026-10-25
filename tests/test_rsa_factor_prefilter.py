"""The rsa_factor prefilters (odd, top limb, small-prime sieve) never drop a true factor."""
import math
import os
import random

import numpy as np
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa

from memdiver.algorithms.keyfinders import rsa_factor as rf


@pytest.fixture(autouse=True)
def _always_sieve(monkeypatch):
    monkeypatch.setattr(rf, "_SIEVE_MIN_CANDIDATES", 0)


def _small_prime(bits, rng):
    while True:
        candidate = rng.getrandbits(bits) | (1 << (bits - 1)) | 1
        if rf._probable_prime(candidate):
            return candidate


def _key(bits):
    if bits < 1024:  # cryptography refuses < 1024-bit keys
        rng = random.Random(bits)
        p, q = _small_prime(bits // 2, rng), _small_prime(bits // 2, rng)
        return p * q, p, q
    numbers = rsa.generate_private_key(65537, bits).private_numbers()
    return numbers.public_numbers.n, numbers.p, numbers.q


def _window(x, length, order):
    return x.to_bytes(length, order)


@pytest.mark.parametrize("bits", [512, 1024, 2048, 4096])
@pytest.mark.parametrize("order", ["big", "little"])
def test_prefilters_keep_planted_factor_at_odd_offsets(bits, order):
    n, p, q = _key(bits)
    length = ((n.bit_length() + 7) // 8) // 2
    rng = random.Random(bits)
    for factor in (p, q):
        buf = bytearray(os.urandom(40_000))
        off = rng.randrange(1, len(buf) - length) | 1
        buf[off:off + length] = _window(factor, length, order)
        arr = np.frombuffer(bytes(buf), dtype=np.uint8)
        stop = len(arr) - length + 1
        kept = rf._candidate_offsets(arr, 0, stop, length, 1, order, rf.DEFAULT_MAX_RUN,
                                     rf._sieve_primes([n]))
        assert off in kept.tolist()


@pytest.mark.parametrize("order", ["big", "little"])
def test_end_to_end_finds_factor_at_odd_offset(order):
    n, p, _ = _key(1024)
    buf = bytearray(os.urandom(30_001))
    buf[12_345:12_345 + 64] = _window(p, 64, order)
    stride = {"big": "be_stride", "little": "le_stride"}[order]
    hits = rf.find_rsa_prime_factors(bytes(buf), moduli=[n], scan_public_keys=False,
                                     byte_orders=(order,), **{stride: 1})
    assert [(h.offset, h.metadata["byte_order"]) for h in hits] == [(12_345, order)]


@pytest.mark.parametrize("order", ["big", "little"])
def test_sieve_residues_match_bigint_coprimality(order):
    length = 24
    arr = np.frombuffer(os.urandom(5_000), dtype=np.uint8)
    rel = np.arange(0, len(arr) - length + 1, 3, dtype=np.int64)
    for primes in rf._SIEVE_STAGES:
        kept = rf._coprime_to(arr, rel, length, order, primes)
        modulus = math.prod(primes)
        expected = [math.gcd(int.from_bytes(arr[o:o + length].tobytes(), order), modulus) == 1
                    for o in rel.tolist()]
        assert kept.tolist() == expected


def test_sieve_skips_primes_dividing_the_modulus():
    n = 3 * 5 * 1000003
    stages = rf._sieve_primes([n])
    flat = [p for stage in stages for p in stage]
    assert 3 not in flat and 5 not in flat and 7 in flat


def test_small_prime_modulus_divisor_survives():
    n = 3 * 1000003 * 999983
    length = ((n.bit_length() + 7) // 8) // 2
    buf = bytearray(os.urandom(2_000))
    buf[777:777 + length] = _window(3 * 1000003, length, "big")
    arr = np.frombuffer(bytes(buf), dtype=np.uint8)
    kept = rf._candidate_offsets(arr, 0, len(arr) - length + 1, length, 1, "big",
                                 rf.DEFAULT_MAX_RUN, rf._sieve_primes([n]))
    assert 777 in kept.tolist()


@pytest.mark.parametrize("order", ["big", "little"])
def test_constant_run_gate_flags_only_windows_with_a_run(order):
    length, run = 32, 16
    buf = bytearray(os.urandom(400))
    buf[100:100 + run] = b"\x00" * run
    arr = np.frombuffer(bytes(buf), dtype=np.uint8)
    rel = np.arange(0, len(arr) - length + 1, dtype=np.int64)
    flagged = rf._has_constant_run(arr, rel, length, run)
    for r in rel.tolist():
        window = arr[r:r + length].tobytes()
        has_run = any(len(set(window[i:i + run])) == 1 for i in range(length - run + 1))
        assert flagged[r] == has_run


def test_max_run_zero_disables_gate():
    n, p, _ = _key(1024)
    buf = bytearray(os.urandom(8_000))
    buf[3_001:3_001 + 64] = p.to_bytes(64, "big")
    for max_run in (0, 16):
        hits = rf.find_rsa_prime_factors(bytes(buf), moduli=[n], scan_public_keys=False,
                                         byte_orders=("big",), max_run=max_run)
        assert [h.offset for h in hits] == [3_001]
