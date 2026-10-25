"""PEM private-key scanner: ``-----BEGIN <X> PRIVATE KEY-----`` ... ``-----END <X> PRIVATE KEY-----``.

Finds RSA / EC / DSA / OPENSSH / ENCRYPTED / plain PKCS#8 ``PRIVATE KEY`` blocks in
any buffer, base64-decodes the body and checks it: RSA (PKCS#1) and plain PKCS#8
bodies go through the :mod:`.rsa_der` parser (``n == p * q``); OpenSSH keys must carry
the ``openssh-key-v1`` magic; other kinds just have to decode. The match covers the PEM text.
"""

import base64
import binascii
import re
from typing import Any, Dict, List, Optional

from memdiver.algorithms.base import AlgorithmResult, AnalysisContext, BaseAlgorithm, Match
from memdiver.algorithms.keyfinders.rsa_der import key_checks, modulus_summary, parse_rsa_private_key
from memdiver.core.constants import UNKNOWN_KEY

MAX_BODY_BYTES = 20000
OPENSSH_MAGIC = b"openssh-key-v1\x00"
_PEM = re.compile(
    rb"-----BEGIN ((?:[A-Z0-9]+ )*PRIVATE KEY)-----([\x09\x0a\x0d\x20-\x7e]{0,%d}?)"
    rb"-----END \1-----" % MAX_BODY_BYTES)


def _decode_body(body: bytes) -> Optional[bytes]:
    """Base64 payload of a PEM body (RFC 1421 header lines dropped), ``None`` if invalid."""
    lines = [ln.strip() for ln in body.splitlines()]
    payload = b"".join(ln for ln in lines if ln and b":" not in ln)
    try:
        return base64.b64decode(payload, validate=True)
    except (binascii.Error, ValueError):
        return None


def _body_checks(kind: str, der: bytes) -> Dict[str, Any]:
    if kind in ("RSA PRIVATE KEY", "PRIVATE KEY"):
        key = parse_rsa_private_key(der)
        if key is not None:
            return {"rsa_verified": True, "format": key.format, **key_checks(key),
                    **modulus_summary(key.n)}
        return {"rsa_verified": False}
    if kind == "OPENSSH PRIVATE KEY":
        return {"openssh_magic": der.startswith(OPENSSH_MAGIC)}
    return {}


def _confidence(kind: str, der: Optional[bytes], checks: Dict[str, Any]) -> float:
    if der is None:
        return 0.4
    verified = checks.get("rsa_verified") or checks.get("openssh_magic")
    if verified:
        return 1.0
    return 0.5 if kind in ("RSA PRIVATE KEY", "OPENSSH PRIVATE KEY") else 0.9


def _pem_match(data: Any, m: "re.Match[bytes]") -> Match:
    kind = m.group(1).decode("ascii")
    der = _decode_body(m.group(2))
    checks = _body_checks(kind, der) if der is not None else {}
    meta = {"kind": kind, "decoded": der is not None, "der_length": len(der or b""),
            "encrypted": kind.startswith("ENCRYPTED") or b"ENCRYPTED" in m.group(2),
            "checks": checks}
    return Match(offset=m.start(), length=m.end() - m.start(),
                 confidence=_confidence(kind, der, checks), label="pem_private_key",
                 data=bytes(data[m.start():m.end()]), metadata=meta)


def find_pem_private_keys(data: Any) -> List[Match]:
    """Every PEM private-key block in *data*, ordered by offset."""
    return [_pem_match(data, m) for m in _PEM.finditer(data)]


class PemScanAlgorithm(BaseAlgorithm):
    """Find PEM-armoured private keys (RSA/EC/DSA/OPENSSH/ENCRYPTED/PKCS#8)."""

    name = "pem_scan"
    description = "PEM private-key block scanner with RSA/OpenSSH body verification"
    mode = UNKNOWN_KEY

    def run(self, dump_data: bytes, context: AnalysisContext) -> AlgorithmResult:
        matches = find_pem_private_keys(dump_data)
        best = max((m.confidence for m in matches), default=0.0)
        return AlgorithmResult(algorithm_name=self.name, confidence=best, matches=matches,
                               metadata={"blocks": len(matches)})
