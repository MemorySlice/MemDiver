"""RSA prime-factor finder for live processes (OpenSSL BIGNUM limb arrays).

A running OpenSSL (and sshd, nginx, ...) does not hold its RSA private key as DER:
``RSA`` keeps ``n, e, d, p, q, dmp1, dmq1, iqmp`` as ``BIGNUM`` limb arrays, i.e. each
integer as little-endian 64-bit limbs (the integer's little-endian bytes on x86_64 /
aarch64). The public modulus ``n`` is usually in the same memory (SubjectPublicKeyInfo,
an X.509 certificate, an ``ssh-rsa`` wire blob) or known from outside (``rsa_moduli``),
so the private key is recognised by *dividing*: any window of ``len(n)/2`` bytes ``p``
with ``1 < p < n`` and ``n % p == 0`` is a prime factor of ``n``.

Windows are tried little-endian (default stride 8: limb aligned) and big-endian
(stride 1). A vectorised prefilter drops even candidates, ones whose top limb is zero,
and ones sharing a small prime with the window (exact), plus -- heuristically, disable
with ``max_run=0`` -- ones holding 16 identical consecutive bytes, before big-integer work. ``data`` may be any buffer (``bytes``, ``bytearray``,
``mmap``, ``memoryview``).

Match metadata carries ``n_sha256``: ``sha256(n.to_bytes((n.bit_length() + 7) // 8, "big"))``
(see :func:`~memdiver.algorithms.keyfinders.rsa_der.modulus_summary`, shared with ``rsa_der``).
"""

import math
import re
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple, Union

import numpy as np

from memdiver.algorithms.base import AlgorithmResult, AnalysisContext, BaseAlgorithm, Match
from memdiver.algorithms.keyfinders.rsa_der import (
    BIT_STRING, RSA_ENCRYPTION_OID, SEQUENCE, modulus_summary, read_integers, read_tlv,
)
from memdiver.core.constants import UNKNOWN_KEY

BYTE_ORDERS = ("little", "big")
DEFAULT_LE_STRIDE = 8
DEFAULT_BE_STRIDE = 1
DEFAULT_MIN_BITS = 512
DEFAULT_MAX_BITS = 8192
DEFAULT_MAX_MODULI = 256
_SLAB = 1 << 22
_TOP_LIMB = 8
_MAX_PUBLIC_E_BYTES = 8
_SPKI_ALGORITHM = re.compile(re.escape(RSA_ENCRYPTION_OID) + rb"\x05\x00\x03")
_BARE_PUBLIC = re.compile(
    rb"(?=\x30(?:\x82[\x00-\xff]{2}|\x81[\x00-\xff])\x02(?:\x82[\x00-\xff]{2}|\x81[\x00-\xff]))",
    re.DOTALL)
_SSH_RSA = re.compile(rb"\x00\x00\x00\x07ssh-rsa\x00\x00\x00")
#: Odd primes whose residues sieve candidates, grouped so each product fits int64 maths.
_SIEVE_STAGES = ((3, 5, 7, 11, 13, 17, 19, 23), (29, 31, 37, 41, 43), (47, 53, 59, 61, 67),
                 (71, 73, 79, 83))
_SIEVE_MIN_CANDIDATES = 20_000
DEFAULT_MAX_RUN = 16
_MR_BASES = (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37)

#: modulus -> where it came from, e.g. ``{"source": "spki", "offset": 1234, "e": 65537}``.
Moduli = Dict[int, Dict[str, Any]]


def _probable_prime(n: int) -> bool:
    if n < 2 or any(n % b == 0 for b in _MR_BASES):
        return n in _MR_BASES
    d, r = n - 1, 0
    while d % 2 == 0:
        d, r = d // 2, r + 1
    for base in _MR_BASES:
        x = pow(base, d, n)
        if x in (1, n - 1):
            continue
        if not any((x := x * x % n) == n - 1 for _ in range(r - 1)):
            return False
    return True


def _public_key_ints(data: Any, seq_pos: int) -> Optional[Tuple[int, int]]:
    tlv = read_tlv(data, seq_pos)
    if tlv is None or tlv[0] != SEQUENCE:
        return None
    ints = read_integers(data, tlv[1], tlv[2])
    return (ints[0], ints[1]) if ints is not None and len(ints) == 2 else None


def _spki_moduli(data: Any) -> Iterable[Tuple[int, int, int]]:
    """``(offset, n, e)`` for every SubjectPublicKeyInfo / certificate public key."""
    for m in _SPKI_ALGORITHM.finditer(data):
        bits = read_tlv(data, m.end() - 1)
        if bits is None or bits[0] != BIT_STRING or data[bits[1]] != 0:
            continue
        pair = _public_key_ints(data, bits[1] + 1)
        if pair:
            yield bits[1] + 1, pair[0], pair[1]


def _bare_public_moduli(data: Any) -> Iterable[Tuple[int, int, int]]:
    for m in _BARE_PUBLIC.finditer(data):
        pair = _public_key_ints(data, m.start())
        if pair and pair[1] < (1 << (8 * _MAX_PUBLIC_E_BYTES)):
            yield m.start(), pair[0], pair[1]


def _ssh_mpint(data: Any, pos: int, max_len: int) -> Optional[Tuple[int, int]]:
    if pos + 4 > len(data):
        return None
    size = int.from_bytes(data[pos:pos + 4], "big")
    if not 0 < size <= max_len or pos + 4 + size > len(data):
        return None
    return int.from_bytes(data[pos + 4:pos + 4 + size], "big"), pos + 4 + size


def _ssh_rsa_moduli(data: Any) -> Iterable[Tuple[int, int, int]]:
    """``(offset, n, e)`` for every ``ssh-rsa`` wire blob (string, mpint e, mpint n)."""
    for m in _SSH_RSA.finditer(data):
        e_end = _ssh_mpint(data, m.end() - 3, _MAX_PUBLIC_E_BYTES * 4)
        n_end = _ssh_mpint(data, e_end[1], 2050) if e_end else None
        if e_end and n_end:
            yield m.start(), n_end[0], e_end[0]


def _as_int(value: Union[int, str]) -> int:
    return value if isinstance(value, int) else int(value, 16)


def collect_moduli(data: Any, extra: Sequence[Union[int, str]] = (),
                   scan_public_keys: bool = True, min_bits: int = DEFAULT_MIN_BITS,
                   max_bits: int = DEFAULT_MAX_BITS,
                   max_moduli: int = DEFAULT_MAX_MODULI) -> Moduli:
    """Candidate moduli: caller-supplied first, then public keys found in *data*."""
    found: Moduli = {}
    for value in extra:
        found.setdefault(_as_int(value), {"source": "extra", "offset": None, "e": None})
    if scan_public_keys:
        for source, finder in (("spki", _spki_moduli), ("rsa_public_key", _bare_public_moduli),
                               ("ssh-rsa", _ssh_rsa_moduli)):
            for offset, n, e in finder(data):
                found.setdefault(n, {"source": source, "offset": offset, "e": e})
    sized = {n: info for n, info in found.items()
             if n % 2 and min_bits <= n.bit_length() <= max_bits}
    return dict(list(sized.items())[:max_moduli])


def _candidate_offsets(arr: np.ndarray, start: int, stop: int, length: int,
                       stride: int, order: str, max_run: int = 0,
                       sieve_primes: Sequence[Sequence[int]] = ()) -> np.ndarray:
    """Offsets in ``[start, stop)`` whose window may divide a modulus.

    Exact necessary conditions (never drop a divisor of an odd ``n``): the window is odd,
    its top limb is non-zero, and it is coprime to every sieve prime (``p | x`` and
    ``x | n`` would give ``p | n``). ``max_run`` > 0 adds the heuristic randomness gate
    :func:`_has_constant_run` (see there).
    """
    offs = np.arange(start, stop, stride, dtype=np.int64)
    low, top = (offs, offs + length - 1) if order == "little" else (offs + length - 1, offs)
    keep = (arr[low] & 1) == 1
    sign = -1 if order == "little" else 1
    top_zero = np.ones(len(offs), dtype=bool)
    for k in range(min(_TOP_LIMB, length)):
        top_zero &= arr[top + sign * k] == 0
    offs = offs[keep & ~top_zero]
    span = arr[start:stop - 1 + length]
    if max_run and length >= max_run and len(offs):
        offs = offs[~_has_constant_run(span, offs - start, length, max_run)]
    for primes in sieve_primes:
        if len(offs) < _SIEVE_MIN_CANDIDATES:
            break
        offs = offs[_coprime_to(span, offs - start, length, order, primes)]
    return offs


_POWER_TABLES: Dict[Tuple[int, int], np.ndarray] = {}
_POWER_TABLE_LIMIT = 8


def _powers(modulus: int, base: int, count: int) -> np.ndarray:
    """``base**i % modulus`` for ``i < count`` (modulus < 2**30), memoised per scan shape."""
    table = _POWER_TABLES.get((modulus, base))
    if table is None or len(table) < count:
        table = _build_powers(modulus, base, count)
        if len(_POWER_TABLES) >= _POWER_TABLE_LIMIT:
            _POWER_TABLES.pop(next(iter(_POWER_TABLES)))
        _POWER_TABLES[(modulus, base)] = table
    return table[:count]


def _build_powers(modulus: int, base: int, count: int) -> np.ndarray:
    out = np.empty(count, dtype=np.int32)
    out[0], filled, step = 1, 1, base % modulus
    while filled < count:
        part = min(filled, count - filled)
        out[filled:filled + part] = out[:part].astype(np.int64) * step % modulus
        filled, step = filled + part, step * step % modulus
    return out


def _coprime_to(span: np.ndarray, rel: np.ndarray, length: int, order: str,
                primes: Sequence[int]) -> np.ndarray:
    """Mask: window ``span[r:r+length]`` as an integer is coprime to ``prod(primes)``.

    A prefix sum of ``byte * 256**(+-i)`` gives each window's residue up to a unit
    factor (a power of 256, coprime to the odd modulus), which leaves coprimality intact.
    """
    modulus = math.prod(primes)
    base = 256 if order == "little" else pow(256, -1, modulus)
    weighted = span.astype(np.int64) * _powers(modulus, base, len(span))
    prefix = np.cumsum(weighted)
    prefix = np.concatenate(([0], prefix))
    residue = (prefix[rel + length] - prefix[rel]) % modulus
    return np.gcd(residue, modulus) == 1


def _has_constant_run(span: np.ndarray, rel: np.ndarray, length: int,
                      run: int) -> np.ndarray:
    """Mask: window contains ``run`` identical consecutive bytes (zero pad, 0xff fill...).

    HEURISTIC, not exact: an RSA prime (indistinguishable from random) has such a run
    with probability < ``length * 2**(-8 * (run - 1))`` -- below 2**-100 for run 16 --
    but a hand-crafted divisor could. Disable with ``max_run=0``.
    """
    same = (span[1:] == span[:-1]).astype(np.int32)
    prefix = np.concatenate(([0], np.cumsum(same, dtype=np.int32)))
    starts = (prefix[run - 1:] - prefix[:len(prefix) - run + 1]) == run - 1
    by_start = np.concatenate(([0], np.cumsum(starts, dtype=np.int32)))
    last_start = length - run + 1
    return (by_start[rel + last_start] - by_start[rel]) > 0


def _window_slabs(size: int, length: int) -> Iterable[Tuple[int, int]]:
    last = size - length + 1
    for start in range(0, max(last, 0), _SLAB):
        yield start, min(start + _SLAB, last)


def _divisors_at(data: Any, offsets: np.ndarray, length: int, order: str,
                 group: Sequence[int]) -> Iterable[Tuple[int, int, int]]:
    """``(offset, n, p)`` for windows at *offsets* that divide one modulus of *group*."""
    for off in offsets.tolist():
        x = int.from_bytes(data[off:off + length], order)
        for n in group:
            if 1 < x < n and n % x == 0:
                yield off, n, x


def _private_exponents(p: int, q: int, e: int) -> List[int]:
    """Candidate ``d`` values: ``e^-1`` mod lcm(p-1, q-1) (FIPS 186-4) and mod phi(n)."""
    exponents = []
    for modulus in dict.fromkeys((math.lcm(p - 1, q - 1), (p - 1) * (q - 1))):
        if math.gcd(e, modulus) == 1:
            exponents.append(pow(e, -1, modulus))
    return exponents


def _d_location(data: Any, p: int, q: int, e: Optional[int]) -> Dict[str, Any]:
    """Where ``d`` (derived from p, q, e) is in memory, if the buffer supports ``find``."""
    if not e or not hasattr(data, "find") or p < 3 or q < 3:
        return {}
    for d in _private_exponents(p, q, e):
        for order in BYTE_ORDERS:
            at = data.find(d.to_bytes((d.bit_length() + 7) // 8, order))
            if at >= 0:
                return {"d_offset": at, "d_byte_order": order}
    return {}


def _factor_match(data: Any, off: int, n: int, p: int, order: str, length: int,
                  moduli: Moduli) -> Match:
    info, q = moduli[n], n // p
    meta = {"byte_order": order, "modulus_source": info["source"],
            "modulus_offset": info["offset"], "e": info["e"],
            "factor_bits": p.bit_length(), "cofactor_bits": q.bit_length(),
            "probable_prime": _probable_prime(p),
            **modulus_summary(n), **_d_location(data, p, q, info["e"])}
    return Match(offset=off, length=length, confidence=1.0, label="rsa_prime_factor",
                 data=bytes(data[off:off + length]), metadata=meta)


def _sieve_primes(group: Sequence[int]) -> List[Tuple[int, ...]]:
    """Sieve stages without any prime dividing a modulus of *group*."""
    stages = [tuple(p for p in stage if all(n % p for n in group)) for stage in _SIEVE_STAGES]
    return [stage for stage in stages if stage]


def _scan_order(data: Any, arr: np.ndarray, groups: Dict[int, List[int]], order: str,
                stride: int, moduli: Moduli, max_run: int = DEFAULT_MAX_RUN) -> List[Match]:
    matches: List[Match] = []
    for length, group in groups.items():
        sieve = _sieve_primes(group)
        for start, stop in _window_slabs(len(arr), length):
            offsets = _candidate_offsets(arr, start, stop, length, stride, order,
                                         max_run, sieve)
            matches.extend(_factor_match(data, off, n, p, order, length, moduli)
                           for off, n, p in _divisors_at(data, offsets, length, order, group))
    return matches


def find_rsa_prime_factors(data: Any, moduli: Sequence[Union[int, str]] = (),
                           scan_public_keys: bool = True,
                           byte_orders: Sequence[str] = BYTE_ORDERS,
                           le_stride: int = DEFAULT_LE_STRIDE,
                           be_stride: int = DEFAULT_BE_STRIDE,
                           min_bits: int = DEFAULT_MIN_BITS, max_bits: int = DEFAULT_MAX_BITS,
                           max_moduli: int = DEFAULT_MAX_MODULI,
                           moduli_info: Optional[Moduli] = None,
                           max_run: int = DEFAULT_MAX_RUN) -> List[Match]:
    """Prime factors of known / in-memory RSA moduli, found as raw integer windows.

    ``moduli_info`` (modulus -> provenance, as :func:`collect_moduli` returns) adds
    moduli harvested elsewhere, e.g. from other captured runs of the same dump; the
    ones this buffer holds itself keep their own provenance.

    ``max_run`` drops windows holding that many identical consecutive bytes (a heuristic
    no random prime trips; 0 disables). The odd / top-limb / small-prime-coprime
    prefilters are exact.
    """
    unknown = [o for o in byte_orders if o not in BYTE_ORDERS]
    if unknown or min(le_stride, be_stride) < 1:
        raise ValueError(f"byte orders must be in {BYTE_ORDERS} and strides >= 1")
    found = collect_moduli(data, moduli, scan_public_keys, min_bits, max_bits, max_moduli)
    for n, info in (moduli_info or {}).items():
        found.setdefault(n, info)
    groups: Dict[int, List[int]] = {}
    for n in found:
        groups.setdefault(((n.bit_length() + 7) // 8) // 2, []).append(n)
    arr = np.frombuffer(data, dtype=np.uint8)
    strides = {"little": le_stride, "big": be_stride}
    matches = [m for order in byte_orders
               for m in _scan_order(data, arr, groups, order, strides[order], found, max_run)]
    return sorted(matches, key=lambda m: m.offset)


class RsaFactorAlgorithm(BaseAlgorithm):
    """Find RSA prime factors (BIGNUM limbs) of moduli known from outside or from memory."""

    name = "rsa_factor"
    description = "RSA prime-factor finder: windows dividing public moduli (OpenSSL BIGNUM)"
    mode = UNKNOWN_KEY

    def run(self, dump_data: bytes, context: AnalysisContext) -> AlgorithmResult:
        extra = context.extra
        matches = find_rsa_prime_factors(
            dump_data, moduli=extra.get("rsa_moduli", ()),
            scan_public_keys=extra.get("rsa_scan_public_keys", True),
            byte_orders=extra.get("rsa_byte_orders", BYTE_ORDERS),
            le_stride=extra.get("rsa_le_stride", DEFAULT_LE_STRIDE),
            be_stride=extra.get("rsa_be_stride", DEFAULT_BE_STRIDE),
            min_bits=extra.get("rsa_min_bits", DEFAULT_MIN_BITS),
            max_bits=extra.get("rsa_max_bits", DEFAULT_MAX_BITS),
            max_moduli=extra.get("rsa_max_moduli", DEFAULT_MAX_MODULI),
            moduli_info=extra.get("rsa_moduli_info"),
            max_run=extra.get("rsa_max_run", DEFAULT_MAX_RUN))
        best = max((m.confidence for m in matches), default=0.0)
        return AlgorithmResult(algorithm_name=self.name, confidence=best, matches=matches,
                               metadata={"factors": len(matches)})

    def estimate_working_set(self, size: int, context: Optional[AnalysisContext] = None,
                             sample: Optional[Sequence[bytes]] = None) -> int:
        """Per-slab offset/mask arrays (~48 B per slab byte at stride 1), independent of size."""
        return 48 * min(size, _SLAB)
