"""AES-256-CBC decryption verification — thin wrapper.

Re-exports from engine.verification for backward compatibility
with existing benchmark scripts.
"""

from engine.verification import (  # noqa: F401
    AesCbcVerifier,
    CipherVerifier,
    VerificationResult,
    extract_and_verify,
    VERIFICATION_IV,
    VERIFICATION_PLAINTEXT,
    VERIFIER_REGISTRY,
    HAS_CRYPTO,
)

# Backward-compatible aliases
create_verification_ciphertext = AesCbcVerifier().create_ciphertext


def verify_candidate_key(candidate, ciphertext, iv=VERIFICATION_IV,
                         expected=VERIFICATION_PLAINTEXT):
    """Backward-compatible wrapper."""
    return AesCbcVerifier().verify(candidate, ciphertext, iv, expected)
