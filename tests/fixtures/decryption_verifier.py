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

# Backward-compatible wrappers — supply the canonical plaintext/IV defaults
# so callers can pass the key alone (matches the original helper contract
# before AesCbcVerifier.create_ciphertext became 3-positional).
def create_verification_ciphertext(key, plaintext=VERIFICATION_PLAINTEXT,
                                   iv=VERIFICATION_IV):
    """Backward-compatible wrapper."""
    return AesCbcVerifier().create_ciphertext(key, plaintext, iv)


def verify_candidate_key(candidate, ciphertext, iv=VERIFICATION_IV,
                         expected=VERIFICATION_PLAINTEXT):
    """Backward-compatible wrapper."""
    return AesCbcVerifier().verify(candidate, ciphertext, iv, expected)
