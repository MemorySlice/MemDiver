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
    from cryptography.hazmat.primitives.ciphers.aead import (
        AESGCM,
        ChaCha20Poly1305,
    )
    HAS_CRYPTO = True
except ImportError:
    HAS_CRYPTO = False


@runtime_checkable
class CipherVerifier(Protocol):
    """Protocol for cipher-specific decryption verification.

    The core four positional args (candidate/ciphertext/iv/expected_plaintext)
    describe the original block-cipher (CBC) contract. AEAD suites additionally
    need a per-record ``nonce``, optional associated data ``aad``, and the
    authentication ``tag``; these are keyword-only and default to ``None`` so
    every existing CBC call site keeps working unchanged. For an AEAD verifier a
    valid authentication tag *is* the confirmation — ``expected_plaintext`` then
    becomes an optional secondary equality check rather than the sole signal.
    """

    @property
    def cipher_name(self) -> str: ...

    @property
    def key_length(self) -> int: ...

    def verify(self, candidate: bytes, ciphertext: bytes,
               iv: bytes, expected_plaintext: bytes,
               *, nonce: bytes | None = None, aad: bytes | None = None,
               tag: bytes | None = None) -> bool | None: ...

    def create_ciphertext(self, key: bytes, plaintext: bytes,
                          iv: bytes, *, nonce: bytes | None = None,
                          aad: bytes | None = None) -> bytes: ...


@dataclass(frozen=True)
class VerificationResult:
    """Result of a key verification attempt."""
    offset: int
    key_hex: str
    cipher_name: str
    verified: bool


class AesCbcVerifier:
    """AES-CBC decryption verification (AES-256 by default, AES-128 optional)."""

    is_aead = False

    def __init__(self, key_length: int = 32) -> None:
        if key_length not in (16, 32):
            raise ValueError("AES-CBC key length must be 16 or 32 bytes")
        self.key_length = key_length
        self.cipher_name = f"AES-{key_length * 8}-CBC"

    def verify(self, candidate: bytes, ciphertext: bytes,
               iv: bytes, expected_plaintext: bytes,
               *, nonce: bytes | None = None, aad: bytes | None = None,
               tag: bytes | None = None) -> bool | None:
        """Try decryption. Returns True/False/None (if crypto unavailable).

        ``nonce``/``aad``/``tag`` are accepted for protocol compatibility with
        the AEAD verifiers and ignored here — CBC is not authenticated.
        """
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
                          iv: bytes, *, nonce: bytes | None = None,
                          aad: bytes | None = None) -> bytes:
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


class _AeadVerifier:
    """Shared base for AEAD (authenticated) cipher verifiers.

    An AEAD suite decrypts and authenticates in one step: a valid authentication
    tag proves the key/nonce/aad are correct, so tag validation *is* the
    confirmation. Subclasses supply ``cipher_name``, ``key_length`` and an
    ``_aead(key)`` factory returning a one-shot AEAD object exposing
    ``encrypt(nonce, data, aad)`` / ``decrypt(nonce, data, aad)``.

    The nonce is taken from the keyword ``nonce`` when supplied, else falls back
    to ``VERIFICATION_NONCE`` (the ``iv`` positional is a CBC concept and is not
    used, since AEAD nonce sizes differ per suite — ChaCha20-Poly1305 requires
    exactly 12 bytes). The tag may be passed separately via ``tag`` or already
    appended to ``ciphertext`` (the layout ``cryptography`` returns from
    ``encrypt``).
    """

    is_aead = True

    def _aead(self, key: bytes):  # pragma: no cover - overridden
        raise NotImplementedError

    def decrypt(self, key: bytes, ciphertext: bytes, nonce: bytes,
                aad: bytes | None = None, tag: bytes | None = None) -> bytes | None:
        """Return the recovered plaintext, or None if the key/tag is wrong.

        The plaintext-returning counterpart to :meth:`verify` (which returns only
        a bool); used by callers that must inspect the decrypted bytes (e.g. a
        validator predicate). The tag may be passed separately or appended to
        ``ciphertext``.
        """
        if not HAS_CRYPTO:
            return None
        data = ciphertext + tag if tag is not None else ciphertext
        try:
            return self._aead(key).decrypt(nonce, data, aad)
        except Exception:
            return None

    def verify(self, candidate: bytes, ciphertext: bytes,
               iv: bytes, expected_plaintext: bytes,
               *, nonce: bytes | None = None, aad: bytes | None = None,
               tag: bytes | None = None) -> bool | None:
        if not HAS_CRYPTO:
            return None
        if len(candidate) != self.key_length:
            return False
        used_nonce = nonce if nonce is not None else VERIFICATION_NONCE
        data = ciphertext + tag if tag is not None else ciphertext
        try:
            plaintext = self._aead(candidate).decrypt(used_nonce, data, aad)
        except Exception:
            # Any failure — wrong key, bad tag, malformed nonce — is a non-match.
            return False
        # A valid tag already confirms the key; the equality check is an optional
        # extra guard used by the synthetic self-test (expected != None).
        if expected_plaintext is None:
            return True
        return plaintext == expected_plaintext

    def create_ciphertext(self, key: bytes, plaintext: bytes,
                          iv: bytes, *, nonce: bytes | None = None,
                          aad: bytes | None = None) -> bytes:
        """Encrypt plaintext, returning ciphertext||tag (the AEAD layout)."""
        if not HAS_CRYPTO:
            raise ImportError("cryptography package required")
        if len(key) != self.key_length:
            raise ValueError(f"Expected {self.key_length}-byte key, got {len(key)}")
        used_nonce = nonce if nonce is not None else VERIFICATION_NONCE
        return self._aead(key).encrypt(used_nonce, plaintext, aad)


class AesGcmVerifier(_AeadVerifier):
    """AES-GCM (AEAD) decryption verification for AES-128 or AES-256."""

    def __init__(self, key_length: int = 32) -> None:
        if key_length not in (16, 32):
            raise ValueError("AES-GCM key length must be 16 or 32 bytes")
        self.key_length = key_length
        self.cipher_name = f"AES-{key_length * 8}-GCM"

    def _aead(self, key: bytes):
        return AESGCM(key)


class ChaChaPolyVerifier(_AeadVerifier):
    """ChaCha20-Poly1305 (AEAD) decryption verification."""

    cipher_name = "CHACHA20-POLY1305"
    key_length = 32

    def _aead(self, key: bytes):
        return ChaCha20Poly1305(key)


# Default verification constants
VERIFICATION_PLAINTEXT = b"AES256_MEMDIVER_VERIFICATION_OK!"
VERIFICATION_IV = bytes(range(16))
# AEAD nonce default: 12 bytes is the size every TLS AEAD suite uses and the
# only size ChaCha20-Poly1305 accepts.
VERIFICATION_NONCE = bytes(range(12))

# Registry of available verifiers
VERIFIER_REGISTRY: dict[str, CipherVerifier] = {
    "AES-128-CBC": AesCbcVerifier(16),
    "AES-256-CBC": AesCbcVerifier(),
    "AES-128-GCM": AesGcmVerifier(16),
    "AES-256-GCM": AesGcmVerifier(32),
    "CHACHA20-POLY1305": ChaChaPolyVerifier(),
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
