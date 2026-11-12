"""WireGuard's Noise_IKpsk2 helpers (BLAKE2s KDF and cookie keys) for memory proofs.

Shared by the kernel plugin ``linux.wireguard`` and the userspace engine
``memdiver.wireguard_go_engine``: both recompute a handshake's chaining key and the
``cookie.c`` precomputed keys from values found in memory, and must do it identically.

Self-contained (see ``__init__``): standard library only, paste-safe, private names carry
the ``_noise_`` prefix.
"""
import hashlib
import hmac

NOISE_CONSTRUCTION = b"Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s"
LABEL_MAC1 = b"mac1----"
LABEL_COOKIE = b"cookie--"


def backend():
    """Which implementation runs (always hashlib/hmac from the standard library)."""
    return "pure-python"


def precompute_key(label, public):
    """``cookie.c precompute_key()``: BLAKE2s-256(label ‖ public)."""
    return hashlib.blake2s(bytes(label) + bytes(public)).digest()


def _noise_hmac_blake2s(key, data):
    return hmac.new(key, data, hashlib.blake2s).digest()


def kdf1(chaining_key, data):
    """Noise ``KDF1`` (noise.c ``kdf(first_dst, ...)``, wireguard-go ``device/kdf``):
    HKDF-BLAKE2s extract + the first expand block."""
    return _noise_hmac_blake2s(_noise_hmac_blake2s(chaining_key, data), b"\x01")


def initiation_chaining_key(ephemeral_public, dh_es, static_static):
    """Chaining key right after the initiation is created or consumed (e, es, ss mixed in)."""
    ck = hashlib.blake2s(NOISE_CONSTRUCTION).digest()
    for data in (ephemeral_public, dh_es, static_static):
        ck = kdf1(ck, data)
    return ck
