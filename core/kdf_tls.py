"""TLS KDF plugins wrapping TLS12PRF and TLS13HKDF as BaseKDF subclasses."""

import logging
from typing import List, Optional, Set

from core.kdf import TLS12PRF, TLS13HKDF, _hash_length
from core.kdf_base import BaseKDF, KDFParams
from core.models import CryptoSecret

logger = logging.getLogger("memdiver.kdf_tls")

_KDF_MATCH_CONFIDENCE = 0.95
_TLS12_KEY_SIZE = 48
_TLS13_KEY_SIZE = 32


class TLS12KDF(BaseKDF):
    """TLS 1.2 PRF as a BaseKDF plugin."""

    name = "tls12_prf"
    protocol = "TLS"
    versions = {"12"}

    def derive(self, secret: bytes, params: KDFParams) -> bytes:
        """Derive via TLS 1.2 PRF using first label and context as seed."""
        label = params.labels[0] if params.labels else b"master secret"
        if isinstance(label, str):
            label = label.encode("ascii")
        length = params.key_lengths[0] if params.key_lengths else _TLS12_KEY_SIZE
        return TLS12PRF.prf(secret, label, params.context, length, params.hash_algo)

    def expand_traffic_secret(
        self,
        secret: CryptoSecret,
        key_lengths: Optional[List[int]] = None,
        hash_algo: str = "sha256",
    ) -> List[CryptoSecret]:
        """TLS 1.2 has no traffic secret expansion."""
        return []

    def validate_pair(
        self,
        candidate_a: bytes,
        candidate_b: bytes,
        dump_data: bytes,
        hash_algo: str = "sha256",
    ) -> float:
        """Test TLS 1.2 PRF relationship between two 48-byte candidates."""
        probe_random = b"\x00" * 32

        # Try a as PMS -> does PRF yield b?
        derived = TLS12PRF.derive_master_secret(
            candidate_a, probe_random, probe_random, hash_algo
        )
        if derived == candidate_b:
            return _KDF_MATCH_CONFIDENCE

        # Try b as PMS -> does PRF yield a?
        derived = TLS12PRF.derive_master_secret(
            candidate_b, probe_random, probe_random, hash_algo
        )
        if derived == candidate_a:
            return _KDF_MATCH_CONFIDENCE

        return 0.0

    def supported_secret_types(self) -> Set[str]:
        return set()


class TLS13KDF(BaseKDF):
    """TLS 1.3 HKDF as a BaseKDF plugin."""

    name = "tls13_hkdf"
    protocol = "TLS"
    versions = {"13"}

    TRAFFIC_SECRET_TYPES = {
        "CLIENT_HANDSHAKE_TRAFFIC_SECRET",
        "SERVER_HANDSHAKE_TRAFFIC_SECRET",
        "CLIENT_TRAFFIC_SECRET_0",
        "SERVER_TRAFFIC_SECRET_0",
    }

    def derive(self, secret: bytes, params: KDFParams) -> bytes:
        """Derive via TLS 1.3 HKDF-Expand-Label."""
        label = params.labels[0] if params.labels else "derived"
        if isinstance(label, bytes):
            label = label.decode("ascii")
        length = params.key_lengths[0] if params.key_lengths else _TLS13_KEY_SIZE
        return TLS13HKDF.hkdf_expand_label(
            secret, label, params.context, length, params.hash_algo
        )

    def expand_traffic_secret(
        self,
        secret: CryptoSecret,
        key_lengths: Optional[List[int]] = None,
        hash_algo: str = "sha256",
    ) -> List[CryptoSecret]:
        """Expand a TLS 1.3 traffic secret into key, IV, and finished."""
        if key_lengths is None:
            key_lengths = [16, 32]

        base_type = secret.secret_type
        derived: List[CryptoSecret] = []

        for key_len in key_lengths:
            write_key = TLS13HKDF.hkdf_expand_label(
                secret.secret_value, "key", b"", key_len, hash_algo
            )
            derived.append(CryptoSecret(
                secret_type=f"{base_type}_KEY_{key_len * 8}",
                identifier=secret.identifier,
                secret_value=write_key,
                protocol=secret.protocol,
            ))

        iv = TLS13HKDF.hkdf_expand_label(
            secret.secret_value, "iv", b"", 12, hash_algo
        )
        derived.append(CryptoSecret(
            secret_type=f"{base_type}_IV",
            identifier=secret.identifier,
            secret_value=iv,
            protocol=secret.protocol,
        ))

        hash_len = _hash_length(hash_algo)
        finished = TLS13HKDF.hkdf_expand_label(
            secret.secret_value, "finished", b"", hash_len, hash_algo
        )
        derived.append(CryptoSecret(
            secret_type=f"{base_type}_FINISHED",
            identifier=secret.identifier,
            secret_value=finished,
            protocol=secret.protocol,
        ))

        return derived

    def validate_pair(
        self,
        candidate_a: bytes,
        candidate_b: bytes,
        dump_data: bytes,
        hash_algo: str = "sha256",
    ) -> float:
        """Test TLS 1.3 HKDF relationship between two 32-byte candidates."""
        # Try HKDF-Extract both ways.
        prk = TLS13HKDF.hkdf_extract(salt=candidate_a, ikm=candidate_b, hash_algo=hash_algo)
        if prk == candidate_a or prk == candidate_b:
            return _KDF_MATCH_CONFIDENCE

        prk = TLS13HKDF.hkdf_extract(salt=candidate_b, ikm=candidate_a, hash_algo=hash_algo)
        if prk == candidate_a or prk == candidate_b:
            return _KDF_MATCH_CONFIDENCE

        # Try HKDF-Expand-Label with standard TLS 1.3 labels.
        empty_hash = bytes(_TLS13_KEY_SIZE)
        tls13_labels = [
            "derived", "c hs traffic", "s hs traffic",
            "c ap traffic", "s ap traffic", "exp master", "res master",
        ]
        for label in tls13_labels:
            derived = TLS13HKDF.hkdf_expand_label(
                candidate_a, label, empty_hash, _TLS13_KEY_SIZE, hash_algo
            )
            if derived == candidate_b:
                return _KDF_MATCH_CONFIDENCE

            derived = TLS13HKDF.hkdf_expand_label(
                candidate_b, label, empty_hash, _TLS13_KEY_SIZE, hash_algo
            )
            if derived == candidate_a:
                return _KDF_MATCH_CONFIDENCE

        return 0.0

    def supported_secret_types(self) -> Set[str]:
        return set(self.TRAFFIC_SECRET_TYPES)
