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

from memdiver.core.kdf_base import BaseKDF, KDFParams
from memdiver.core.models import CryptoSecret

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

    @staticmethod
    def _ssh_hash_sizes() -> Set[int]:
        """Valid SSH-2 hash output sizes, sourced from the SSH structure library.

        Reads ``size_choices`` off the SSH builtin structure fields (DRY) rather
        than hardcoding (64, 32, 20). These are the lengths an exchange hash H
        or session_id may have (SHA-512 / SHA-256 / SHA-1).
        """
        # Imported lazily to keep this module importable without the structure
        # library and to avoid a heavy import at module load time.
        from memdiver.core.structure_library_ssh import SSH_BUILTINS

        sizes: Set[int] = set()
        for struct_def in SSH_BUILTINS:
            for fld in struct_def.fields:
                sizes.update(fld.size_choices)
        return sizes

    @staticmethod
    def discover_hash_candidates(
        blobs: List[bytes], cap: int = 32,
    ) -> List[bytes]:
        """Filter dump-derived byte-blobs down to plausible SSH-2 hash inputs.

        SSH-2 key validation requires the exchange hash H and session_id, which
        are themselves hash outputs sitting in the dump. Upstream entropy /
        change-point detectors already surface high-entropy blobs; this helper
        keeps only those that could be H / session_id:

        * length must be one of the SSH hash sizes (``size_choices`` from
          ``core.structure_library_ssh.SSH_BUILTINS`` -- SHA-1/256/512);
        * the blob must not be all-zero (the ``not_zero`` constraint);
        * duplicates are removed preserving first-seen order;
        * the result is capped at *cap* to bound downstream loop cost.

        Takes raw bytes (not Match objects) to keep core decoupled from the
        algorithms layer.
        """
        valid_sizes = SSH2KDFPlugin._ssh_hash_sizes()
        seen: Set[bytes] = set()
        result: List[bytes] = []
        for blob in blobs:
            if len(blob) not in valid_sizes:
                continue
            if not any(blob):  # not_zero constraint: drop all-zero blobs
                continue
            if blob in seen:
                continue
            seen.add(blob)
            result.append(blob)
            if len(result) >= cap:
                break
        return result

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
        hash_candidates: Optional[List[bytes]] = None,
    ) -> float:
        """Test whether two candidates are related via the SSH-2 KDF.

        SSH-2 keys A-F are independent outputs of
        ``HASH(K || H || X || session_id)`` (RFC 4253 Section 7.2). It is
        cryptographically impossible to decide whether two byte-strings are an
        SSH-2 key pair without the shared secret K, the exchange hash H, and
        the session_id. There is no self-contained relationship between two
        derived keys to verify; H and session_id must come from outside.

        Therefore, without *hash_candidates* this returns 0.0 honestly. When
        *hash_candidates* (real H / session_id blobs discovered in the dump) is
        supplied, one candidate is treated as the shared secret K and, for each
        (H, session_id) pair drawn from the candidates, all six key-type chars
        are derived at the length of the OTHER candidate. A match against the
        other candidate -- or presence of a derived value in *dump_data* --
        confirms the link. SSH-2 derived outputs are not uniformly 32 bytes
        (IVs A/B are 8/12/16, HMAC keys E/F often 20, encryption keys C/D
        16/24/32), so derivation length follows the peer candidate.

        Loops are bounded by ``discover_hash_candidates``' cap on the supplied
        *hash_candidates* list.
        """
        if not hash_candidates:
            # Cannot validate an SSH-2 pair without discovered H / session_id.
            return 0.0

        directions = (
            (candidate_a, candidate_b),  # candidate_a as K, derive b-length key
            (candidate_b, candidate_a),  # candidate_b as K, derive a-length key
        )
        for shared_secret, other in directions:
            target_len = len(other)
            for exchange_hash in hash_candidates:
                for session_id in hash_candidates:
                    for key_char in KEY_TYPE_CHARS:
                        derived = SSH2KDF.derive_key(
                            shared_secret, exchange_hash, key_char,
                            session_id, target_len, hash_algo,
                        )
                        if derived == other or derived in dump_data:
                            return self._CONFIDENCE
        return 0.0

    def supported_secret_types(self) -> Set[str]:
        """Return secret types this KDF can expand."""
        return {"SSH2_SESSION_KEY"}
