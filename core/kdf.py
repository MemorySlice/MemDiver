"""TLS Key Derivation Function implementations for validation.

Provides pure-stdlib (hmac + hashlib) implementations of:
- TLS 1.2 PRF (RFC 5246, Section 5) based on P_SHA256
- TLS 1.3 HKDF functions (RFC 8446, Section 7) based on HKDF-Extract/Expand

These are used by the constraint validator algorithm to verify that
candidate key bytes found in memory dumps satisfy the expected KDF
relationships (e.g. a candidate master secret actually derives from a
candidate pre-master secret via the TLS 1.2 PRF).
"""

import hashlib
import hmac
import logging

logger = logging.getLogger("memdiver.kdf")


# -- Hash length lookup --------------------------------------------------- #

_HASH_LENGTHS = {
    "sha256": 32,
    "sha384": 48,
    "sha512": 64,
}


def _hash_length(hash_algo: str) -> int:
    """Return the output length in bytes for *hash_algo*."""
    if hash_algo in _HASH_LENGTHS:
        return _HASH_LENGTHS[hash_algo]
    return hashlib.new(hash_algo).digest_size


class TLS12PRF:
    """TLS 1.2 Pseudo-Random Function (RFC 5246).

    TLS 1.2 uses a single PRF based on P_SHA256:

        PRF(secret, label, seed) = P_SHA256(secret, label + seed)

    where P_hash is the iterative HMAC expansion defined in Section 5.
    """

    @staticmethod
    def p_hash(
        secret: bytes,
        seed: bytes,
        length: int,
        hash_algo: str = "sha256",
    ) -> bytes:
        """P_hash expansion (RFC 5246 Section 5).

        Iteratively applies HMAC: A(i) = HMAC(secret, A(i-1)),
        output = HMAC(secret, A(1)+seed) || HMAC(secret, A(2)+seed) || ...
        """
        result = bytearray()
        a_value = seed  # A(0) = seed

        while len(result) < length:
            # A(i) = HMAC(secret, A(i-1))
            a_value = hmac.new(secret, a_value, hash_algo).digest()
            # P_hash chunk = HMAC(secret, A(i) + seed)
            result.extend(hmac.new(secret, a_value + seed, hash_algo).digest())

        return bytes(result[:length])

    @staticmethod
    def prf(
        secret: bytes,
        label: bytes,
        seed: bytes,
        length: int,
        hash_algo: str = "sha256",
    ) -> bytes:
        """PRF(secret, label, seed) = P_SHA256(secret, label + seed)."""
        return TLS12PRF.p_hash(secret, label + seed, length, hash_algo)

    @staticmethod
    def derive_master_secret(
        pre_master_secret: bytes,
        client_random: bytes,
        server_random: bytes,
        hash_algo: str = "sha256",
    ) -> bytes:
        """Derive the 48-byte master secret (RFC 5246 Section 8.1)."""
        return TLS12PRF.prf(
            pre_master_secret,
            b"master secret",
            client_random + server_random,
            48,
            hash_algo,
        )

    @staticmethod
    def derive_key_block(
        master_secret: bytes,
        server_random: bytes,
        client_random: bytes,
        length: int,
        hash_algo: str = "sha256",
    ) -> bytes:
        """Derive the key block (RFC 5246 Section 6.3).

        Note: seed order is server_random + client_random (reversed from
        master secret derivation).
        """
        return TLS12PRF.prf(
            master_secret,
            b"key expansion",
            server_random + client_random,
            length,
            hash_algo,
        )


class TLS13HKDF:
    """TLS 1.3 HKDF functions (RFC 8446, Section 7).

    Implements HKDF-Extract and HKDF-Expand (RFC 5869) plus the TLS 1.3
    specific ``HKDF-Expand-Label`` and ``Derive-Secret`` helpers.
    """

    @staticmethod
    def hkdf_extract(
        salt: bytes,
        ikm: bytes,
        hash_algo: str = "sha256",
    ) -> bytes:
        """HKDF-Extract: PRK = HMAC(salt, IKM) (RFC 5869 Section 2.2)."""
        if not salt:
            salt = b"\x00" * _hash_length(hash_algo)
        return hmac.new(salt, ikm, hash_algo).digest()

    @staticmethod
    def hkdf_expand(
        prk: bytes,
        info: bytes,
        length: int,
        hash_algo: str = "sha256",
    ) -> bytes:
        """HKDF-Expand: iterative HMAC expansion (RFC 5869 Section 2.3)."""
        hash_len = _hash_length(hash_algo)
        n = (length + hash_len - 1) // hash_len
        if n > 255:
            raise ValueError(
                f"HKDF-Expand: requested {length} bytes exceeds maximum "
                f"({255 * hash_len} bytes for {hash_algo})"
            )

        okm = bytearray()
        t_prev = b""

        for i in range(1, n + 1):
            t_prev = hmac.new(
                prk, t_prev + info + bytes([i]), hash_algo
            ).digest()
            okm.extend(t_prev)

        return bytes(okm[:length])

    @staticmethod
    def hkdf_expand_label(
        secret: bytes,
        label: str,
        context: bytes,
        length: int,
        hash_algo: str = "sha256",
    ) -> bytes:
        """HKDF-Expand-Label: builds HkdfLabel struct (RFC 8446 Section 7.1)."""
        full_label = b"tls13 " + label.encode("ascii")
        hkdf_label = (
            length.to_bytes(2, "big")
            + len(full_label).to_bytes(1, "big")
            + full_label
            + len(context).to_bytes(1, "big")
            + context
        )
        return TLS13HKDF.hkdf_expand(secret, hkdf_label, length, hash_algo)

    @staticmethod
    def derive_secret(
        secret: bytes,
        label: str,
        messages_hash: bytes,
        hash_algo: str = "sha256",
    ) -> bytes:
        """Derive-Secret (RFC 8446 Section 7.1)."""
        return TLS13HKDF.hkdf_expand_label(
            secret,
            label,
            messages_hash,
            _hash_length(hash_algo),
            hash_algo,
        )
