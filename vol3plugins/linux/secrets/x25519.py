"""X25519 (RFC 7748) for proving WireGuard static/ephemeral private keys from memory.

Self-contained on purpose: at module level this file imports only the Python standard
library (no MemDiver, no Volatility 3, no sibling module, no relative import) and it never
reads ``__file__``, so it can be pasted verbatim into a generated single-file plugin.
``cryptography`` is an optional accelerator imported lazily on first use; the pure-Python
Montgomery ladder returns byte-identical results.  ``MEMDIVER_PUREPY_CRYPTO=1`` in the
environment forces the pure path (read on every call); ``backend()`` says which is active.

WireGuard stores its static private key already clamped (drivers/net/wireguard/noise.c
``wg_noise_set_static_identity_private_key()`` calls ``curve25519_clamp_secret()``), so
``is_clamped`` is a cheap pre-filter and ``public_key(candidate) == peer-visible public key``
is the proof.
"""

import os
from functools import lru_cache

_X25519_PUREPY_ENV = "MEMDIVER_PUREPY_CRYPTO"
_X25519_P = 2 ** 255 - 19
_X25519_A24 = 121665  # RFC 7748 section 5: (486662 - 2) / 4
_X25519_SIZE = 32
_X25519_BASE_U = (9).to_bytes(_X25519_SIZE, "little")


def _x25519_purepy_forced() -> bool:
    value = os.environ.get(_X25519_PUREPY_ENV, "")
    return value.strip().lower() in ("1", "true", "yes", "on")


@lru_cache(maxsize=1)
def _x25519_probe_cryptography():
    """``(X25519PrivateKey, X25519PublicKey)`` once, or ``None`` if unusable."""
    try:
        from cryptography.hazmat.primitives.asymmetric.x25519 import (
            X25519PrivateKey,
            X25519PublicKey,
        )

        X25519PrivateKey.from_private_bytes(bytes(_X25519_SIZE))  # backend without X25519?
    except Exception:  # ImportError, UnsupportedAlgorithm, partial install
        return None
    return X25519PrivateKey, X25519PublicKey


def _x25519_cryptography():
    if _x25519_purepy_forced():
        return None
    return _x25519_probe_cryptography()


def backend() -> str:
    """``"cryptography"`` when the accelerated path is active, else ``"pure-python"``."""
    return "cryptography" if _x25519_cryptography() is not None else "pure-python"


def _x25519_checked(value, what: str) -> bytes:
    value = bytes(value)
    if len(value) != _X25519_SIZE:
        raise ValueError("X25519 %s must be 32 bytes, got %d" % (what, len(value)))
    return value


def clamp(k) -> bytes:
    """RFC 7748 decodeScalar25519 bit fixing: clear bits 0-2 and 255, set bit 254."""
    scalar = bytearray(_x25519_checked(k, "scalar"))
    scalar[0] &= 248
    scalar[31] &= 127
    scalar[31] |= 64
    return bytes(scalar)


def is_clamped(k) -> bool:
    """True when ``k`` is already in clamped form (``clamp(k) == k``)."""
    return clamp(k) == bytes(k)


def _x25519_ladder(scalar: int, u: int) -> int:
    """RFC 7748 section 5 Montgomery ladder over GF(2^255 - 19) (not constant-time)."""
    p = _X25519_P
    x1, x2, z2, x3, z3 = u, 1, 0, u, 1
    swap = 0
    for t in range(254, -1, -1):
        bit = (scalar >> t) & 1
        if swap ^ bit:
            x2, x3, z2, z3 = x3, x2, z3, z2
        swap = bit
        a, b = x2 + z2, x2 - z2
        aa, bb = a * a % p, b * b % p
        e = aa - bb
        da, cb = (x3 - z3) * a % p, (x3 + z3) * b % p
        x3 = (da + cb) * (da + cb) % p
        z3 = x1 * ((da - cb) * (da - cb) % p) % p
        x2, z2 = aa * bb % p, e * (aa + _X25519_A24 * e) % p
    if swap:
        x2, z2 = x3, z3
    return x2 * pow(z2, p - 2, p) % p


def _x25519_pure(k: bytes, u: bytes) -> bytes:
    scalar = int.from_bytes(clamp(k), "little")
    u_coordinate = (int.from_bytes(u, "little") & ((1 << 255) - 1)) % _X25519_P
    return _x25519_ladder(scalar, u_coordinate).to_bytes(_X25519_SIZE, "little")


def is_small_order_result(out) -> bool:
    """True for the all-zero X25519 output a small-order peer point produces."""
    return bytes(out) == bytes(_X25519_SIZE)


def scalarmult(k, u, strict: bool = False) -> bytes:
    """X25519(k, u): clamps ``k`` and masks bit 255 of ``u`` exactly as RFC 7748 decodes them.

    Non-canonical ``u`` (>= p) is reduced mod p.  A small-order ``u`` gives the all-zero
    output (RFC 7748 returns it; ``cryptography`` raises, so that case runs the pure ladder);
    ``strict=True`` raises ``ValueError`` instead.  DH-consistency ORACLES must reject an
    all-zero shared secret (use ``strict=True`` or ``is_small_order_result``): otherwise a
    zeroed buffer in memory "matches" the shared secret of a small-order peer.
    """
    out = _x25519_scalarmult(_x25519_checked(k, "scalar"), _x25519_checked(u, "u-coordinate"))
    if strict and is_small_order_result(out):
        raise ValueError("X25519 result is all zero: small-order peer point")
    return out


@lru_cache(maxsize=16)
def _x25519_private_object(private_class, k: bytes):
    """The ``cryptography`` private-key object of ``k``, built once: a scan tests one identity
    against many candidate points, and building the object is a third of each exchange."""
    return private_class.from_private_bytes(k)


def _x25519_scalarmult(k: bytes, u: bytes) -> bytes:
    ops = _x25519_cryptography()
    if ops is not None:
        private_class, public_class = ops
        try:
            return _x25519_private_object(private_class, k).exchange(
                public_class.from_public_bytes(u))
        except ValueError:
            pass
    return _x25519_pure(k, u)


def public_key(priv) -> bytes:
    """The X25519 public key ``X25519(priv, 9)`` (WireGuard ``static_public``)."""
    return scalarmult(priv, _X25519_BASE_U)


# --------------------------------------------------------------------------- oracle helpers
# Shared by the ``x25519-pubkey`` / ``x25519-dh-consistency`` format oracles and the
# ``memdiver.wireguard_go`` engine, so every caller applies the same rejection rules.


def is_canonical_u(u) -> bool:
    """RFC 7748 canonical u-coordinate: bit 255 clear and value < p (no aliasing)."""
    return int.from_bytes(bytes(u), "little") < _X25519_P


def proves_public(priv, pub) -> bool:
    """O_id: ``X25519(priv, 9) == pub`` for a non-zero ``priv`` and ``pub``."""
    priv, pub = bytes(priv), bytes(pub)
    if len(priv) != _X25519_SIZE or len(pub) != _X25519_SIZE or not any(priv) or not any(pub):
        return False
    return public_key(priv) == pub


def dh_consistency(priv, remote_public, shared):
    """O_dh: ``X25519(priv, remote_public) == shared``; ``None`` when it cannot decide.

    ``None`` (never a proof, never a rejection): a zero ``priv``/``shared``, a non-canonical
    ``remote_public`` (it aliases another point) or a small-order one (all-zero output, which a
    zeroed buffer would otherwise "match").
    """
    priv, remote_public, shared = bytes(priv), bytes(remote_public), bytes(shared)
    if any(len(v) != _X25519_SIZE for v in (priv, remote_public, shared)):
        return None
    if not any(priv) or not any(shared) or not is_canonical_u(remote_public):
        return None
    try:
        out = scalarmult(priv, remote_public, strict=True)
    except ValueError:
        return None
    return out == shared
