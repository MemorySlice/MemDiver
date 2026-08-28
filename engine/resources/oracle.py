"""ResourceOracle — verify a candidate key against a VerificationResource.

Implements the engine ``Oracle`` shape (``verify(bytes) -> bool``) so it plugs
straight into the existing brute-force loop, but instead of running
user-supplied Python it runs first-party, data-driven logic: for each challenge
a resource yields, derive the concrete record key from the raw candidate (TLS
1.2 via ``derive_tls12_keys``, TLS 1.3 via ``derive_tls13_record_keys``) and
confirm it against the captured record — an AEAD tag check through the C1
verifiers, or an HMAC+padding check for the older TLS 1.2 CBC suites.

Extensibility: a challenge whose ``derivation`` is ``None`` treats the candidate
as the raw key and judges via its ``success`` strategy (the seam a future
encrypted-file / ransomware resource uses). New protocols attach by adding a
branch that routes through the KDF registry — the verifier protocol is untouched.
"""

from __future__ import annotations

import hmac
import logging
from typing import Dict, List, Optional

from memdiver.core.kdf_tls import (
    Tls12SuiteParams,
    derive_tls12_keys,
    derive_tls13_record_keys,
)
from memdiver.engine.resources.challenge import DecryptionChallenge, SuccessStrategy
from memdiver.engine.verification import HAS_CRYPTO, VERIFIER_REGISTRY

logger = logging.getLogger("memdiver.engine.resources.oracle")

if HAS_CRYPTO:
    from cryptography.hazmat.primitives.ciphers import (
        Cipher as _Cipher,
        algorithms as _algorithms,
        modes as _modes,
    )

_TLS12_MASTER_SECRET_LEN = 48
# A recovered TLS 1.3 traffic secret is one hash length (SHA-256/384).
_TLS13_SECRET_LENS = (32, 48)


def _xor_iv_seq(iv: bytes, seq_num: int) -> bytes:
    """RFC 8446 §5.3 / RFC 7905 nonce: base IV XOR the big-endian sequence number."""
    seq = seq_num.to_bytes(len(iv), "big")
    return bytes(a ^ b for a, b in zip(iv, seq))


class ResourceOracle:
    """Verify candidate keys against the challenges of a VerificationResource."""

    def __init__(self, resource, *, max_challenges: Optional[int] = None) -> None:
        self.protocol = getattr(resource, "protocol", "")
        challenges = list(resource.challenges())
        if max_challenges is not None:
            # The cap silently discards verification work; say so at INFO so a
            # "0 confirmed" result can never be mistaken for full coverage.
            if len(challenges) > max_challenges:
                logger.info(
                    "max_challenges=%d truncated %d challenges to %d",
                    max_challenges, len(challenges), max_challenges,
                )
            challenges = challenges[:max_challenges]
        # Pre-group challenges by derivation signature so ``verify()`` derives the
        # (session-constant) key material ONCE per distinct session/suite per
        # candidate instead of once per record — every record in a TLS session
        # shares the same client/server random + suite; only the per-record nonce
        # varies. Raw (no-derivation) challenges keep their own bucket. Unknown
        # protocols are dropped (no derivation route yet).
        self._raw: List[DecryptionChallenge] = []
        self._tls12_groups: Dict[tuple, List[DecryptionChallenge]] = {}
        self._tls13_groups: Dict[object, List[DecryptionChallenge]] = {}
        for ch in challenges:
            d = ch.derivation
            if d is None:
                self._raw.append(ch)
            elif d.protocol == "TLS" and d.version == "12":
                sig = (d.client_random, d.server_random, d.cipher_suite)
                self._tls12_groups.setdefault(sig, []).append(ch)
            elif d.protocol == "TLS" and d.version == "13":
                self._tls13_groups.setdefault(d.cipher_suite, []).append(ch)
        self._count = len(challenges)
        if not self._count:
            logger.warning("ResourceOracle built with zero challenges — will never confirm")

    def __len__(self) -> int:
        return self._count

    def verify(self, candidate: bytes) -> bool:
        """True if *candidate* decrypts any challenge in the resource.

        Key derivation runs once per group (per candidate); only the per-record
        AEAD/CBC check repeats. Each ``_check_*`` is exception-safe (the verifier
        and CBC paths swallow their own errors), so a single malformed record
        cannot abort the loop.
        """
        if not HAS_CRYPTO:
            return False
        for ch in self._raw:
            if self._verify_raw(candidate, ch):
                return True
        if len(candidate) == _TLS12_MASTER_SECRET_LEN:
            for (cr, sr, suite), records in self._tls12_groups.items():
                keys = self._derive_tls12(candidate, cr, sr, suite)
                if keys is not None and any(self._check_tls12(keys, ch) for ch in records):
                    return True
        if len(candidate) in _TLS13_SECRET_LENS:
            for suite, records in self._tls13_groups.items():
                rk = self._derive_tls13(candidate, suite)
                if rk is not None and any(self._check_tls13(rk, ch) for ch in records):
                    return True
        return False

    @staticmethod
    def _aead_confirms(verifier_name: str, key: bytes, nonce: bytes,
                       ch: DecryptionChallenge) -> bool:
        """A valid AEAD tag under *key*/*nonce* confirms the record (== a match)."""
        verifier = VERIFIER_REGISTRY.get(verifier_name)
        return bool(verifier and verifier.verify(
            key, ch.ciphertext, b"", None,
            nonce=nonce, aad=ch.aad, tag=ch.tag,
        ) is True)

    # -- raw key (no derivation) — the encrypted-file / ransomware seam ----- #

    def _verify_raw(self, key: bytes, ch: DecryptionChallenge) -> bool:
        """Judge a candidate used directly as the cipher key (no KDF)."""
        verifier = VERIFIER_REGISTRY.get(ch.cipher)
        if verifier is None:
            return False
        if ch.success is SuccessStrategy.VALIDATOR:
            plaintext = self._decrypt(verifier, key, ch, ch.nonce)
            if plaintext is None or ch.validator is None:
                return False
            try:
                return bool(ch.validator(plaintext))
            except Exception:
                return False
        expected = ch.expected_plaintext if ch.success is SuccessStrategy.EXPECTED_PLAINTEXT else None
        return verifier.verify(
            key, ch.ciphertext, ch.nonce, expected,
            nonce=ch.nonce, aad=ch.aad, tag=ch.tag,
        ) is True

    @staticmethod
    def _decrypt(verifier, key: bytes, ch: DecryptionChallenge,
                 nonce: bytes) -> Optional[bytes]:
        """Return the recovered plaintext for the VALIDATOR strategy, or None.

        Only AEAD ciphers expose a plaintext-returning ``decrypt`` today; a
        future encrypted-file resource extends this as needed.
        """
        decrypt = getattr(verifier, "decrypt", None)
        if decrypt is None:
            return None
        return decrypt(key, ch.ciphertext, nonce, aad=ch.aad, tag=ch.tag)

    # -- TLS 1.2 ----------------------------------------------------------- #

    @staticmethod
    def _derive_tls12(candidate, cr, sr, suite):
        try:
            return derive_tls12_keys(candidate, cr, sr, suite)
        except Exception:
            return None

    def _check_tls12(self, keys, ch: DecryptionChallenge) -> bool:
        """Confirm one TLS 1.2 record against already-derived *keys* (both directions)."""
        suite = keys.suite
        d = ch.derivation
        for write_key, fixed_iv, mac_key in (
            (keys.client_write_key, keys.client_write_iv, keys.client_mac_key),
            (keys.server_write_key, keys.server_write_iv, keys.server_mac_key),
        ):
            if suite.aead:
                nonce = self._tls12_aead_nonce(suite, fixed_iv, d.record_iv, d.seq_num)
                if self._aead_confirms(suite.verifier, write_key, nonce, ch):
                    return True
            elif self._verify_tls12_cbc(write_key, mac_key, suite, ch):
                return True
        return False

    @staticmethod
    def _tls12_aead_nonce(suite: Tls12SuiteParams, fixed_iv: bytes,
                          record_iv: bytes, seq_num: int) -> bytes:
        """TLS 1.2 AEAD nonce: GCM = salt||explicit (RFC 5288); ChaCha = iv XOR seq (RFC 7905)."""
        if suite.record_iv_len:  # GCM carries an explicit 8-byte nonce on the wire
            return fixed_iv + record_iv
        return _xor_iv_seq(fixed_iv, seq_num)

    def _verify_tls12_cbc(self, write_key: bytes, mac_key: bytes,
                          suite: Tls12SuiteParams, ch: DecryptionChallenge) -> bool:
        """Decrypt a TLS 1.2 CBC record and check its HMAC + padding (RFC 5246 §6.2.3.2).

        ``ch.aad`` carries the 3-byte record header prefix (type || version) that
        the record MAC covers; ``derivation.record_iv`` is the explicit per-record
        IV; ``derivation.seq_num`` is the 64-bit record sequence number.
        """
        d = ch.derivation
        iv = d.record_iv
        if not iv or len(ch.ciphertext) % 16 != 0 or not ch.ciphertext:
            return False
        try:
            cipher = _Cipher(_algorithms.AES(write_key), _modes.CBC(iv))
            dec = cipher.decryptor()
            plain = dec.update(ch.ciphertext) + dec.finalize()
        except Exception:
            return False
        # Strip and validate PKCS7-style TLS padding.
        pad_len = plain[-1] + 1
        if pad_len > len(plain) or any(b != plain[-1] for b in plain[-pad_len:]):
            return False
        body = plain[:-pad_len]
        mac_len = suite.mac_key_len
        if len(body) < mac_len:
            return False
        content, mac = body[:-mac_len], body[-mac_len:]
        # MAC = HMAC(mac_key, seq(8) || type(1) || version(2) || len(2) || content)
        mac_input = (
            d.seq_num.to_bytes(8, "big")
            + ch.aad
            + len(content).to_bytes(2, "big")
            + content
        )
        expected = hmac.new(mac_key, mac_input, suite.mac_hash or suite.prf_hash).digest()
        return hmac.compare_digest(mac, expected)

    # -- TLS 1.3 ----------------------------------------------------------- #

    @staticmethod
    def _derive_tls13(candidate, suite):
        try:
            return derive_tls13_record_keys(candidate, suite)
        except Exception:
            return None

    def _check_tls13(self, rk, ch: DecryptionChallenge) -> bool:
        """Confirm one TLS 1.3 record against already-derived record keys *rk*."""
        nonce = _xor_iv_seq(rk.iv, ch.derivation.seq_num)
        return self._aead_confirms(rk.suite.verifier, rk.key, nonce, ch)
