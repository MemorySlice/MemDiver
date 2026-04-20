"""Decryption verification for candidate keys found in memory dumps.

Provides cipher-agnostic verification via CipherVerifier protocol.
Ships AesCbcVerifier as the first implementation.
"""

import logging
from dataclasses import dataclass
from typing import Protocol, runtime_checkable

logger = logging.getLogger("memdiver.engine.verification")

try:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.primitives import padding as sym_padding
    HAS_CRYPTO = True
except ImportError:
    HAS_CRYPTO = False


@runtime_checkable
class CipherVerifier(Protocol):
    """Protocol for cipher-specific decryption verification."""

    @property
    def cipher_name(self) -> str: ...

    @property
    def key_length(self) -> int: ...

    def verify(self, candidate: bytes, ciphertext: bytes,
               iv: bytes, expected_plaintext: bytes) -> bool | None: ...

    def create_ciphertext(self, key: bytes, plaintext: bytes,
                          iv: bytes) -> bytes: ...


@dataclass(frozen=True)
class VerificationResult:
    """Result of a key verification attempt."""
    offset: int
    key_hex: str
    cipher_name: str
    verified: bool


class AesCbcVerifier:
    """AES-256-CBC decryption verification."""

    cipher_name = "AES-256-CBC"
    key_length = 32

    def verify(self, candidate: bytes, ciphertext: bytes,
               iv: bytes, expected_plaintext: bytes) -> bool | None:
        """Try decryption. Returns True/False/None (if crypto unavailable)."""
        if not HAS_CRYPTO:
            return None
        if len(candidate) != self.key_length:
            return False
        try:
            cipher = Cipher(algorithms.AES(candidate), modes.CBC(iv))
            decryptor = cipher.decryptor()
            padded = decryptor.update(ciphertext) + decryptor.finalize()
            unpadder = sym_padding.PKCS7(128).unpadder()
            plaintext = unpadder.update(padded) + unpadder.finalize()
            return plaintext == expected_plaintext
        except Exception:
            return False

    def create_ciphertext(self, key: bytes, plaintext: bytes,
                          iv: bytes) -> bytes:
        """Encrypt plaintext with AES-256-CBC + PKCS7 padding."""
        if not HAS_CRYPTO:
            raise ImportError("cryptography package required")
        if len(key) != self.key_length:
            raise ValueError(f"Expected {self.key_length}-byte key, got {len(key)}")
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
        encryptor = cipher.encryptor()
        padder = sym_padding.PKCS7(128).padder()
        padded = padder.update(plaintext) + padder.finalize()
        return encryptor.update(padded) + encryptor.finalize()


# Default verification constants
VERIFICATION_PLAINTEXT = b"AES256_MEMDIVER_VERIFICATION_OK!"
VERIFICATION_IV = bytes(range(16))

# Registry of available verifiers
VERIFIER_REGISTRY: dict[str, CipherVerifier] = {
    "AES-256-CBC": AesCbcVerifier(),
}


def extract_and_verify(
    dump_data: bytes,
    candidate_offsets: list[int],
    ciphertext: bytes,
    verifier: CipherVerifier | None = None,
    iv: bytes = VERIFICATION_IV,
    expected: bytes = VERIFICATION_PLAINTEXT,
) -> VerificationResult | None:
    """Try each candidate offset and return first verified key.

    Args:
        dump_data: Raw dump bytes.
        candidate_offsets: Aligned block start offsets to try.
        ciphertext: Known ciphertext for verification.
        verifier: CipherVerifier to use (default: AesCbcVerifier).
        iv: Initialization vector.
        expected: Expected plaintext.

    Returns:
        VerificationResult for the first verified key, or None.
    """
    if verifier is None:
        verifier = VERIFIER_REGISTRY["AES-256-CBC"]
    key_len = verifier.key_length
    for offset in candidate_offsets:
        if offset + key_len > len(dump_data):
            continue
        candidate = dump_data[offset:offset + key_len]
        result = verifier.verify(candidate, ciphertext, iv, expected)
        if result is True:
            logger.info("Verified key at offset 0x%04x", offset)
            return VerificationResult(
                offset=offset,
                key_hex=candidate.hex(),
                cipher_name=verifier.cipher_name,
                verified=True,
            )
    return None
