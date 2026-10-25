"""T3.2: ``rsa_der``, ``rsa_factor``, ``pem_scan`` and ``entropy_window`` key finders."""

import mmap
import random
from functools import lru_cache

import pytest
from cryptography.hazmat.primitives import serialization as ser
from cryptography.hazmat.primitives.asymmetric import rsa

from memdiver.algorithms.base import AnalysisContext
from memdiver.algorithms.keyfinders.entropy_window import (
    EntropyWindowAlgorithm, find_high_entropy_windows,
)
from memdiver.algorithms.keyfinders.pem_scan import PemScanAlgorithm, find_pem_private_keys
from memdiver.algorithms.keyfinders.rsa_der import RsaDerAlgorithm, find_rsa_private_der
from memdiver.algorithms.keyfinders.rsa_factor import (
    RsaFactorAlgorithm, find_rsa_prime_factors,
)
from memdiver.algorithms.registry import AlgorithmRegistry

PKCS1 = (ser.Encoding.DER, ser.PrivateFormat.TraditionalOpenSSL, ser.NoEncryption())
PKCS8 = (ser.Encoding.DER, ser.PrivateFormat.PKCS8, ser.NoEncryption())
SPKI = (ser.Encoding.DER, ser.PublicFormat.SubjectPublicKeyInfo)
RSA_PUBLIC = (ser.Encoding.DER, ser.PublicFormat.PKCS1)


@lru_cache(maxsize=None)
def _key(bits):
    return rsa.generate_private_key(65537, bits)


def _numbers(bits):
    return _key(bits).private_numbers()


def _noise(size, seed=11):
    return bytearray(random.Random(seed).randbytes(size))


def _embed(blob, at, size=6000, seed=11):
    buf = _noise(size, seed)
    buf[at:at + len(blob)] = blob
    return buf


def _limbs(value, order="little"):
    return value.to_bytes((value.bit_length() + 63) // 64 * 8, order)


def _ssh_blob(e, n):
    def mpint(v):
        raw = v.to_bytes((v.bit_length() + 8) // 8, "big")
        return len(raw).to_bytes(4, "big") + raw
    return b"\x00\x00\x00\x07ssh-rsa" + mpint(e) + mpint(n)


def _ctx(**extra):
    return AnalysisContext("openssl", "13", "pre", extra=extra)


@pytest.mark.parametrize("bits", [1024, 2048])
@pytest.mark.parametrize("fmt,name", [(PKCS1, "pkcs1"), (PKCS8, "pkcs8")])
def test_rsa_der_finds_key_at_odd_offset(bits, fmt, name):
    der = _key(bits).private_bytes(*fmt)
    buf = _embed(der, 1237)
    (match,) = find_rsa_private_der(buf)
    assert (match.offset, match.length) == (1237, len(der))
    assert match.data == der
    meta = match.metadata
    assert meta["format"] == name and meta["modulus_bits"] == bits and meta["e"] == 65537
    assert all(meta["checks"].values())
    assert meta["n_head"] == f"{_numbers(bits).public_numbers.n:x}"[:16]


def test_rsa_der_mmap_and_algorithm(tmp_path):
    der = _key(1024).private_bytes(*PKCS8)
    path = tmp_path / "heap.bin"
    path.write_bytes(bytes(_embed(der, 777)))
    with open(path, "rb") as fh, mmap.mmap(fh.fileno(), 0, access=mmap.ACCESS_READ) as mm:
        result = RsaDerAlgorithm().run(mm, _ctx())
    assert [m.offset for m in result.matches] == [777]
    assert result.confidence == 1.0


def test_rsa_der_rejects_corrupted_and_noise():
    der = bytearray(_key(1024).private_bytes(*PKCS1))
    n_start = der.index(_numbers(1024).public_numbers.n.to_bytes(128, "big"))
    der[n_start + 60] ^= 0x01
    assert find_rsa_private_der(_embed(bytes(der), 500)) == []
    assert find_rsa_private_der(_noise(20000)) == []
    assert find_rsa_private_der(bytes(20000)) == []


def test_rsa_der_min_bits_filters():
    buf = _embed(_key(1024).private_bytes(*PKCS1), 100)
    assert find_rsa_private_der(buf, min_bits=2048) == []


@pytest.mark.parametrize("bits", [1024, 2048])
def test_rsa_factor_le_limbs_with_spki(bits):
    nums = _numbers(bits)
    n = nums.public_numbers.n
    buf = _noise(9000)
    spki = _key(bits).public_key().public_bytes(*SPKI)
    buf[200:200 + len(spki)] = spki
    buf[4096:4096 + bits // 16] = _limbs(nums.p)
    matches = find_rsa_prime_factors(buf, byte_orders=("little",))
    (match,) = [m for m in matches if m.offset == 4096]
    meta = match.metadata
    assert meta["byte_order"] == "little" and meta["modulus_source"] == "spki"
    assert meta["modulus_offset"] == 200 + len(spki) - len(_key(bits).public_key().public_bytes(*RSA_PUBLIC))
    assert meta["modulus_bits"] == bits and meta["probable_prime"] is True
    assert int.from_bytes(match.data, "little") * (n // nums.p) == n


def test_n_sha256_is_sha256_of_minimal_big_endian_modulus_in_both_finders():
    import hashlib
    nums = _numbers(1024)
    n = nums.public_numbers.n
    want = hashlib.sha256(n.to_bytes((n.bit_length() + 7) // 8, "big")).hexdigest()
    der = _key(1024).private_bytes(ser.Encoding.DER, ser.PrivateFormat.TraditionalOpenSSL,
                                   ser.NoEncryption())
    buf = _embed(der, 777)
    (der_match,) = [m for m in find_rsa_private_der(buf) if m.offset == 777]
    assert der_match.metadata["n_sha256"] == want
    buf = _noise(9000)
    spki = _key(1024).public_key().public_bytes(*SPKI)
    buf[200:200 + len(spki)] = spki
    buf[4096:4096 + 64] = _limbs(nums.p)
    (fac,) = [m for m in find_rsa_prime_factors(buf, byte_orders=("little",)) if m.offset == 4096]
    assert fac.metadata["n_sha256"] == want


def test_rsa_factor_reports_d_location_and_q():
    nums = _numbers(1024)
    buf = _noise(6000)
    blob = _ssh_blob(nums.public_numbers.e, nums.public_numbers.n)
    buf[100:100 + len(blob)] = blob
    buf[2048:2048 + 64] = _limbs(nums.q)
    buf[3072:3072 + 128] = _limbs(nums.d)
    (match,) = find_rsa_prime_factors(buf, byte_orders=("little",))
    assert match.offset == 2048 and match.metadata["modulus_source"] == "ssh-rsa"
    assert match.metadata["d_offset"] == 3072 and match.metadata["d_byte_order"] == "little"


def test_rsa_factor_big_endian_unaligned_with_extra_modulus():
    nums = _numbers(1024)
    n = nums.public_numbers.n
    buf = _noise(5000)
    buf[1301:1301 + 64] = _limbs(nums.p, "big")
    matches = find_rsa_prime_factors(buf, moduli=[f"{n:x}"], byte_orders=("big",))
    (match,) = matches
    assert match.offset == 1301 and match.metadata["byte_order"] == "big"
    assert match.metadata["modulus_source"] == "extra"
    # Limb-aligned LE stride cannot see a big-endian unaligned value.
    assert find_rsa_prime_factors(buf, moduli=[n], byte_orders=("little",)) == []


def test_rsa_factor_bare_rsa_public_key_source_and_mmap(tmp_path):
    nums = _numbers(1024)
    pub = _key(1024).public_key().public_bytes(*RSA_PUBLIC)
    buf = _noise(5000)
    buf[64:64 + len(pub)] = pub
    buf[1024:1024 + 64] = _limbs(nums.p)
    path = tmp_path / "heap.bin"
    path.write_bytes(bytes(buf))
    with open(path, "rb") as fh, mmap.mmap(fh.fileno(), 0, access=mmap.ACCESS_READ) as mm:
        result = RsaFactorAlgorithm().run(mm, _ctx())
    (match,) = result.matches
    assert match.offset == 1024 and match.metadata["modulus_source"] == "rsa_public_key"


def test_rsa_factor_negative_controls():
    nums = _numbers(1024)
    n = nums.public_numbers.n
    spki = _key(1024).public_key().public_bytes(*SPKI)
    other = _numbers(2048).p
    wrong = _noise(6000)
    wrong[100:100 + len(spki)] = spki
    wrong[2048:2048 + 64] = _limbs(other >> 512)  # right size, not a divisor
    assert find_rsa_prime_factors(wrong) == []
    corrupted = bytearray(wrong)
    corrupted[2048:2048 + 64] = _limbs(nums.p)
    corrupted[2048 + 10] ^= 0xFF
    assert find_rsa_prime_factors(corrupted) == []
    assert find_rsa_prime_factors(_noise(6000), moduli=[n]) == []
    assert find_rsa_prime_factors(bytes(6000), moduli=[n]) == []
    assert find_rsa_prime_factors(bytes(6000)) == []


def test_rsa_factor_rejects_bad_parameters():
    with pytest.raises(ValueError):
        find_rsa_prime_factors(b"", byte_orders=("middle",))
    with pytest.raises(ValueError):
        find_rsa_prime_factors(b"", le_stride=0)


@pytest.mark.parametrize("bits,kind", [(1024, "RSA PRIVATE KEY"), (2048, "PRIVATE KEY")])
def test_pem_scan_verifies_rsa_bodies(bits, kind):
    fmt = ser.PrivateFormat.TraditionalOpenSSL if kind.startswith("RSA") else ser.PrivateFormat.PKCS8
    pem = _key(bits).private_bytes(ser.Encoding.PEM, fmt, ser.NoEncryption())
    buf = _embed(pem, 999, size=8000)
    (match,) = find_pem_private_keys(buf)
    assert match.offset == 999 and match.data == pem.rstrip(b"\n")[:len(match.data)]
    meta = match.metadata
    assert meta["kind"] == kind and meta["checks"]["rsa_verified"] is True
    assert meta["checks"]["modulus_bits"] == bits and match.confidence == 1.0


def test_pem_scan_other_kinds_and_encrypted():
    ec = ser.Encoding.PEM, ser.PrivateFormat.TraditionalOpenSSL, ser.NoEncryption()
    from cryptography.hazmat.primitives.asymmetric import ec as ec_mod
    ec_pem = ec_mod.generate_private_key(ec_mod.SECP256R1()).private_bytes(*ec)
    enc_pem = _key(1024).private_bytes(
        ser.Encoding.PEM, ser.PrivateFormat.PKCS8, ser.BestAvailableEncryption(b"pw"))
    buf = _noise(9000)
    buf[100:100 + len(ec_pem)] = ec_pem
    buf[3000:3000 + len(enc_pem)] = enc_pem
    kinds = {m.metadata["kind"]: m for m in find_pem_private_keys(buf)}
    assert set(kinds) == {"EC PRIVATE KEY", "ENCRYPTED PRIVATE KEY"}
    assert kinds["ENCRYPTED PRIVATE KEY"].metadata["encrypted"] is True
    assert kinds["EC PRIVATE KEY"].metadata["decoded"] is True


def test_pem_scan_negative_controls():
    pem = bytearray(_key(1024).private_bytes(ser.Encoding.PEM, *PKCS1[1:]))
    pem[120] = ord("!")  # invalid base64 character
    (broken,) = find_pem_private_keys(_embed(bytes(pem), 50))
    assert broken.metadata["decoded"] is False and broken.confidence < 0.5
    good = bytearray(_key(1024).private_bytes(ser.Encoding.PEM, *PKCS1[1:]))
    start = good.index(b"\n") + 5
    good[start] = ord("A") if good[start] != ord("A") else ord("B")
    (flipped,) = find_pem_private_keys(bytes(good))
    assert flipped.metadata["checks"]["rsa_verified"] is False
    assert find_pem_private_keys(_noise(5000)) == [] and find_pem_private_keys(bytes(5000)) == []


def test_pem_scan_mmap_and_algorithm(tmp_path):
    pem = _key(1024).private_bytes(ser.Encoding.PEM, *PKCS8[1:])
    path = tmp_path / "heap.bin"
    path.write_bytes(bytes(_embed(pem, 321)))
    with open(path, "rb") as fh, mmap.mmap(fh.fileno(), 0, access=mmap.ACCESS_READ) as mm:
        result = PemScanAlgorithm().run(mm, _ctx())
    assert [m.offset for m in result.matches] == [321]


def test_entropy_window_finds_key_sized_windows_per_size():
    buf = bytearray(4096)
    key = random.Random(5).randbytes(32)
    buf[1000:1032] = key
    matches = find_high_entropy_windows(buf, window_sizes=(16, 32))
    assert matches and {m.label for m in matches} == {"high_entropy_window"}
    assert any(abs(m.offset - 1000) <= 2 and m.length == 32 for m in matches)
    assert all(m.metadata["threshold"] < 5 for m in matches)
    assert find_high_entropy_windows(bytes(4096)) == []


def test_entropy_window_algorithm_and_validation():
    buf = bytearray(4096)
    buf[512:576] = random.Random(6).randbytes(64)
    result = EntropyWindowAlgorithm().run(buf, _ctx())
    assert result.matches and result.confidence > 0
    assert EntropyWindowAlgorithm().estimate_working_set(len(buf), _ctx()) >= 0
    with pytest.raises(ValueError):
        find_high_entropy_windows(buf, window_sizes=())


def test_registry_discovers_new_finders():
    reg = AlgorithmRegistry()
    reg.discover()
    assert {"rsa_der", "rsa_factor", "pem_scan", "entropy_window"} <= set(reg.names)


def test_rsa_factor_modulus_in_one_captured_run_prime_in_another(tmp_path):
    from memdiver.app import tools_keyfinders as tk
    from tests.test_keyfinders_surfaces import _write_msl
    nums = _numbers(1024)
    spki = _key(1024).public_key().public_bytes(*SPKI)
    run_a, run_b = _noise(0x1000, 21), _noise(0x1000, 22)
    run_a[0x100:0x100 + len(spki)] = spki
    run_b[0x200:0x200 + 64] = _limbs(nums.p)
    path = _write_msl(tmp_path / "two.msl", [(0x400000, bytes(run_a), "a"),
                                             (0x500000, bytes(run_b), "b")])
    out = tk.keyfinders_scan_result(path, finders=("rsa_factor",),
                                    params={"rsa_byte_orders": ["little"]}).payload
    (row,) = [r for r in out["rows"] if r["addr"] == 0x500200]
    assert row["metadata"]["modulus_source"] == "spki"
    assert row["metadata"]["modulus_offset"] is None
