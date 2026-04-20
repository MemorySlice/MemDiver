"""SSH-2 Key Derivation Function (RFC 4253, Section 7.2).

Derives encryption keys, IV, and integrity keys from the shared secret K,
exchange hash H, and session identifier using iterative hashing:

    K1 = HASH(K || H || X || session_id)
    Kn = HASH(K || H || K1 || ... || K(n-1))
    key = K1 || K2 || ... truncated to the required length

where X is a single ASCII character ("A" through "F") selecting the key type,
and K is encoded as an SSH mpint (RFC 4251, Section 5).
"""

import hashlib
import logging
import struct
from typing import List, Optional, Set

from core.kdf_base import BaseKDF, KDFParams
from core.models import CryptoSecret

logger = logging.getLogger("memdiver.kdf_ssh")

# SSH-2 key type characters (RFC 4253 Section 7.2)
KEY_TYPE_CHARS = "ABCDEF"


class SSH2KDF:
    """SSH-2 key derivation per RFC 4253 Section 7.2."""

    @staticmethod
    def _encode_mpint(value: bytes) -> bytes:
        """Encode raw bytes as an SSH mpint (RFC 4251 Section 5).

        Prepends a 4-byte big-endian length. If the high bit of the first
        byte is set, a leading \\x00 is inserted to keep the value positive.
        """
        if value and (value[0] & 0x80):
            value = b"\x00" + value
        return struct.pack(">I", len(value)) + value

    @staticmethod
    def derive_key(
        shared_secret: bytes,
        exchange_hash: bytes,
        key_type_char: str,
        session_id: bytes,
        key_length: int,
        hash_algo: str = "sha256",
    ) -> bytes:
        """Derive a single key of *key_length* bytes for *key_type_char*.

        *key_type_char* must be a single ASCII letter "A" through "F".
        """
        k_encoded = SSH2KDF._encode_mpint(shared_secret)
        x = key_type_char.encode("ascii")

        # K1 = HASH(K || H || X || session_id)
        k1 = hashlib.new(hash_algo, k_encoded + exchange_hash + x + session_id).digest()

        parts = [k1]
        total = len(k1)

        while total < key_length:
            # Kn = HASH(K || H || K1 || ... || K(n-1))
            kn = hashlib.new(
                hash_algo, k_encoded + exchange_hash + b"".join(parts)
            ).digest()
            parts.append(kn)
            total += len(kn)

        return b"".join(parts)[:key_length]

    @staticmethod
    def derive_all_keys(
        shared_secret: bytes,
        exchange_hash: bytes,
        session_id: bytes,
        key_length: int = 32,
        hash_algo: str = "sha256",
    ) -> dict[str, bytes]:
        """Derive all six SSH-2 keys ("A" through "F")."""
        return {
            char: SSH2KDF.derive_key(
                shared_secret, exchange_hash, char, session_id, key_length, hash_algo
            )
            for char in KEY_TYPE_CHARS
        }


# Mapping from key type char to semantic secret type name
_KEY_TYPE_NAMES = {
    "A": "SSH2_IV_CS",
    "B": "SSH2_IV_SC",
    "C": "SSH2_ENCRYPTION_KEY_CS",
    "D": "SSH2_ENCRYPTION_KEY_SC",
    "E": "SSH2_INTEGRITY_KEY_CS",
    "F": "SSH2_INTEGRITY_KEY_SC",
}


class SSH2KDFPlugin(BaseKDF):
    """KDF plugin for SSH-2 key derivation (RFC 4253)."""

    name = "ssh2"
    protocol = "SSH"
    versions: Set[str] = {"2"}

    _KEY_SIZE = 32
    _CONFIDENCE = 0.95

    def derive(self, secret: bytes, params: KDFParams) -> bytes:
        """Derive a single SSH-2 key from shared secret bytes."""
        key_type_char = params.extra.get("key_type_char", "A")
        exchange_hash = params.context or b"\x00" * 32
        session_id = params.extra.get("session_id", exchange_hash)
        key_length = params.key_lengths[0] if params.key_lengths else 32
        return SSH2KDF.derive_key(
            secret, exchange_hash, key_type_char, session_id,
            key_length, params.hash_algo,
        )

    def expand_traffic_secret(
        self,
        secret: CryptoSecret,
        key_lengths: Optional[List[int]] = None,
        hash_algo: str = "sha256",
    ) -> List[CryptoSecret]:
        """Expand an SSH2_SESSION_KEY into all 6 derived keys (A-F).

        In forensic context exchange_hash and session_id are unknown,
        so synthetic zero-filled values are used as probes.
        """
        if secret.secret_type not in self.supported_secret_types():
            return []
        length = (key_lengths or [self._KEY_SIZE])[0]
        probe = b"\x00" * 32
        derived = SSH2KDF.derive_all_keys(
            secret.secret_value, probe, probe, length, hash_algo,
        )
        return [
            CryptoSecret(
                secret_type=_KEY_TYPE_NAMES[char],
                identifier=secret.identifier,
                secret_value=key_bytes,
                protocol="SSH",
            )
            for char, key_bytes in derived.items()
        ]

    def validate_pair(
        self,
        candidate_a: bytes,
        candidate_b: bytes,
        dump_data: bytes,
        hash_algo: str = "sha256",
    ) -> float:
        """Test whether two candidates are related via SSH-2 KDF."""
        for key_char in KEY_TYPE_CHARS:
            derived = SSH2KDF.derive_key(
                candidate_a, candidate_b, key_char,
                candidate_b, self._KEY_SIZE, hash_algo,
            )
            if derived == candidate_a or derived == candidate_b:
                return self._CONFIDENCE
            derived = SSH2KDF.derive_key(
                candidate_b, candidate_a, key_char,
                candidate_a, self._KEY_SIZE, hash_algo,
            )
            if derived == candidate_a or derived == candidate_b:
                return self._CONFIDENCE
        return 0.0

    def supported_secret_types(self) -> Set[str]:
        """Return secret types this KDF can expand."""
        return {"SSH2_SESSION_KEY"}
