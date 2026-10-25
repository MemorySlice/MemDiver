"""DER RSA private-key finder: PKCS#1 ``RSAPrivateKey`` and PKCS#8 ``PrivateKeyInfo``.

A DER key is self-describing, so it is found at any offset (stride 1) by a cheap
byte-regex prefilter on the ``SEQUENCE { INTEGER 0, ...`` prefix and then parsed with
a minimal TLV reader (no ASN.1 dependency). A candidate is accepted only when it parses
completely AND ``n == p * q``; ``e * d == 1 (mod lcm(p-1, q-1))`` and the CRT
parameters are reported as extra ``checks``. ``data`` may be any buffer (``bytes``,
``bytearray``, ``mmap``, ``memoryview``).

:func:`parse_rsa_private_key` and :func:`read_tlv` are shared with the PEM scanner
and the public-key readers of :mod:`.rsa_factor`.
"""

import hashlib
import math
import re
from typing import Any, Dict, List, NamedTuple, Optional, Tuple

from memdiver.algorithms.base import AlgorithmResult, AnalysisContext, BaseAlgorithm, Match
from memdiver.core.constants import UNKNOWN_KEY

SEQUENCE, INTEGER, OCTET_STRING, BIT_STRING, OID = 0x30, 0x02, 0x04, 0x03, 0x06
#: ``06 09 2a864886f70d010101`` -- the rsaEncryption OID (TLV form).
RSA_ENCRYPTION_OID = bytes.fromhex("06092a864886f70d010101")
DEFAULT_MIN_BITS = 512
DEFAULT_MAX_BITS = 16384
_PKCS1_FIELDS = 9
_LEN = rb"(?:\x82[\x00-\xff]{2}|\x81[\x00-\xff])"
#: ``30 <len> 02 01 00 02 <len>`` (PKCS#1) / ``30 <len> 02 01 00 30 0d <oid> 05 00 04 <len>`` (PKCS#8).
_PKCS1_PREFIX = re.compile(rb"(?=(\x30" + _LEN + rb"\x02\x01\x00\x02[\x81\x82]))", re.DOTALL)
_PKCS8_PREFIX = re.compile(
    rb"(?=(\x30" + _LEN + rb"\x02\x01\x00\x30\x0d" + re.escape(RSA_ENCRYPTION_OID)
    + rb"\x05\x00\x04[\x81\x82]))", re.DOTALL)


class RsaPrivateKey(NamedTuple):
    format: str
    length: int
    n: int
    e: int
    d: int
    p: int
    q: int
    dp: int
    dq: int
    qinv: int


def read_tlv(buf: Any, pos: int) -> Optional[Tuple[int, int, int]]:
    """``(tag, content_start, content_end)`` of the DER element at *pos*, else ``None``."""
    if pos < 0 or pos + 2 > len(buf):
        return None
    tag, first = buf[pos], buf[pos + 1]
    start = pos + 2
    if first >= 0x80:
        count = first & 0x7F
        if count == 0 or count > 4 or start + count > len(buf):
            return None
        first = int.from_bytes(buf[start:start + count], "big")
        start += count
    end = start + first
    return (tag, start, end) if end <= len(buf) else None


def read_integers(buf: Any, start: int, end: int) -> Optional[List[int]]:
    """Every INTEGER child of the SEQUENCE body ``[start, end)``; ``None`` if anything else."""
    values, pos = [], start
    while pos < end:
        tlv = read_tlv(buf, pos)
        if tlv is None or tlv[0] != INTEGER or tlv[2] > end or tlv[1] == tlv[2]:
            return None
        raw = buf[tlv[1]:tlv[2]]
        if raw[0] & 0x80:
            return None
        values.append(int.from_bytes(raw, "big"))
        pos = tlv[2]
    return values if pos == end else None


def _pkcs1_body(buf: Any, pos: int) -> Optional[Tuple[List[int], int]]:
    tlv = read_tlv(buf, pos)
    if tlv is None or tlv[0] != SEQUENCE:
        return None
    ints = read_integers(buf, tlv[1], tlv[2])
    if ints is None or len(ints) != _PKCS1_FIELDS or ints[0] != 0:
        return None
    return ints, tlv[2]


def _pkcs8_inner(buf: Any, pos: int) -> Optional[Tuple[int, int]]:
    """``(octet-string start, outer end)`` for ``SEQ{0, SEQ{rsaEncryption, NULL}, OCTET}``."""
    outer = read_tlv(buf, pos)
    if outer is None or outer[0] != SEQUENCE or bytes(buf[outer[1]:outer[1] + 3]) != b"\x02\x01\x00":
        return None
    algo = read_tlv(buf, outer[1] + 3)
    if algo is None or algo[0] != SEQUENCE:
        return None
    if bytes(buf[algo[1]:algo[1] + len(RSA_ENCRYPTION_OID)]) != RSA_ENCRYPTION_OID:
        return None
    octets = read_tlv(buf, algo[2])
    if octets is None or octets[0] != OCTET_STRING or octets[2] != outer[2]:
        return None
    return octets[1], outer[2]


def parse_rsa_private_key(buf: Any, pos: int = 0) -> Optional[RsaPrivateKey]:
    """Parse a PKCS#1 or PKCS#8 RSA private key at *pos*; ``None`` unless ``n == p * q``."""
    parsed = _pkcs1_body(buf, pos)
    fmt, end = "pkcs1", None
    if parsed is None:
        inner = _pkcs8_inner(buf, pos)
        parsed = _pkcs1_body(buf, inner[0]) if inner else None
        fmt = "pkcs8"
        end = inner[1] if inner else None
    if parsed is None:
        return None
    (_, n, e, d, p, q, dp, dq, qinv), body_end = parsed
    if not (p > 1 and q > 1 and n == p * q):
        return None
    return RsaPrivateKey(fmt, (end or body_end) - pos, n, e, d, p, q, dp, dq, qinv)


def key_checks(key: RsaPrivateKey) -> Dict[str, bool]:
    """Consistency checks beyond ``n == p * q`` (which acceptance already requires)."""
    lam = math.lcm(key.p - 1, key.q - 1)
    return {
        "n_eq_pq": key.n == key.p * key.q,
        "ed_ok": key.e * key.d % lam == 1,
        "crt_ok": (key.dp == key.d % (key.p - 1) and key.dq == key.d % (key.q - 1)
                   and key.qinv * key.q % key.p == 1),
    }


def modulus_summary(n: int) -> Dict[str, Any]:
    """Bit length plus a sha256 fingerprint and head/tail hex of the modulus.

    ``n_sha256`` is ``sha256`` of ``n``'s minimal big-endian bytes
    (``n.to_bytes((n.bit_length() + 7) // 8, "big")``), the same in every RSA finder.
    """
    digits = f"{n:x}"
    n_bytes = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return {"modulus_bits": n.bit_length(),
            "n_sha256": hashlib.sha256(n_bytes).hexdigest(),
            "n_head": digits[:16], "n_tail": digits[-16:]}


def _match_for(data: Any, offset: int, key: RsaPrivateKey) -> Match:
    checks = key_checks(key)
    meta = {"format": key.format, "e": key.e, "checks": checks, **modulus_summary(key.n)}
    confidence = 1.0 if checks["ed_ok"] else 0.9
    return Match(offset=offset, length=key.length, confidence=confidence,
                 label="rsa_private_key_der", data=bytes(data[offset:offset + key.length]),
                 metadata=meta)


def find_rsa_private_der(data: Any, min_bits: int = DEFAULT_MIN_BITS,
                         max_bits: int = DEFAULT_MAX_BITS) -> List[Match]:
    """Every parseable PKCS#1 / PKCS#8 RSA private key in *data*, ordered by offset."""
    offsets = sorted({m.start() for rx in (_PKCS1_PREFIX, _PKCS8_PREFIX)
                      for m in rx.finditer(data)})
    matches: List[Match] = []
    covered_until = 0  # a PKCS#8 wrapper hides its own inner PKCS#1 key
    for offset in offsets:
        key = parse_rsa_private_key(data, offset) if offset >= covered_until else None
        if key is not None and min_bits <= key.n.bit_length() <= max_bits:
            matches.append(_match_for(data, offset, key))
            covered_until = offset + key.length
    return matches


class RsaDerAlgorithm(BaseAlgorithm):
    """Find DER-encoded RSA private keys (PKCS#1 and PKCS#8)."""

    name = "rsa_der"
    description = "DER PKCS#1 / PKCS#8 RSA private-key finder (n == p*q verified)"
    mode = UNKNOWN_KEY

    def run(self, dump_data: bytes, context: AnalysisContext) -> AlgorithmResult:
        extra = context.extra
        matches = find_rsa_private_der(
            dump_data, min_bits=extra.get("rsa_min_bits", DEFAULT_MIN_BITS),
            max_bits=extra.get("rsa_max_bits", DEFAULT_MAX_BITS))
        best = max((m.confidence for m in matches), default=0.0)
        return AlgorithmResult(algorithm_name=self.name, confidence=best, matches=matches,
                               metadata={"keys": len(matches)})
