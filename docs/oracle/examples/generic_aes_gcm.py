"""Stateless AES-GCM oracle boilerplate.

Copy this file, edit the three module-level constants, point
``memdiver brute-force --oracle generic_aes_gcm.py`` at it.

The verification strategy: AEAD-decrypt a known ciphertext with the
candidate as the key. If the tag verifies, we have the right key.
Wrong-length candidates are rejected in O(1).
"""

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

KEY_LENGTH = 32
NONCE = bytes.fromhex("00" * 12)
CIPHERTEXT_WITH_TAG = bytes.fromhex(
    "aabbccddeeff00112233445566778899"
    "aabbccddeeff0011"
)
ASSOCIATED_DATA: bytes | None = None


def verify(candidate: bytes) -> bool:
    if len(candidate) != KEY_LENGTH:
        return False
    try:
        AESGCM(candidate).decrypt(NONCE, CIPHERTEXT_WITH_TAG, ASSOCIATED_DATA)
        return True
    except Exception:
        return False
