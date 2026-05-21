"""AEAD encryption, key derivation, and key encapsulation for MSL containers.

Implements the cryptographic primitives required by the Memory Slice
Specification v1.0.0 §10 (full-container AEAD encryption):

  * AEAD cipher suites — AES-256-GCM, XChaCha20-Poly1305 (Table 30)
  * Key derivation     — raw key, Argon2id passphrase (Table 31 / §10.5)
  * Key encapsulation   — None, X25519, ML-KEM-768/1024, hybrid (Table 31)
  * HKDF-BLAKE3         — content-encryption-key derivation from KEM secret

Availability model (mirrors msl/compress.py): each algorithm family has an
``*_available`` guard. AES-256-GCM, X25519, Argon2id, XChaCha20-Poly1305 and
HKDF-BLAKE3 are backed by base dependencies (cryptography, PyNaCl,
argon2-cffi, blake3). ML-KEM requires the optional ``[crypto]`` extra
(liboqs-python); when absent, ML-KEM and hybrid mechanisms report
unavailable and raise a clean MslCryptoError rather than crashing.
"""

import hmac
import logging
import os
from typing import Optional, Tuple

from .enums import (ARGON2ID_MIN_LANES, ARGON2ID_MIN_MEMORY_KIB,
                    ARGON2ID_MIN_TIME, CIPHER_NONCE_LEN, KEM_CIPHERTEXT_LEN,
                    MSL_CEK_INFO, EncAlgo, KdfType, KeyEncap)
from .types import MslAuthError, MslCryptoError

logger = logging.getLogger("memdiver.msl.crypto")

CEK_SIZE = 32  # all cipher suites use a 256-bit content-encryption key

_ARGON2_MISSING = "argon2-cffi not installed; install with: pip install memdiver"
_LIBOQS_MISSING = ("liboqs-python not installed; install the post-quantum "
                   "extra: pip install memdiver[crypto]")

# ML-KEM key/ciphertext sizes (FIPS 203). Used to slice hybrid blobs.
_MLKEM_PARAMS = {
    KeyEncap.ML_KEM_768: {"alg": "ML-KEM-768", "pk": 1184, "sk": 2400, "ct": 1088},
    KeyEncap.ML_KEM_1024: {"alg": "ML-KEM-1024", "pk": 1568, "sk": 3168, "ct": 1568},
}
_X25519_KEY_LEN = 32


# ---------------------------------------------------------------- availability

def _have(module: str) -> bool:
    try:
        __import__(module)
        return True
    except ImportError:
        return False


def cipher_is_available(algo: EncAlgo) -> bool:
    if algo == EncAlgo.AES_256_GCM:
        return _have("cryptography")
    if algo == EncAlgo.XCHACHA20_POLY1305:
        return _have("nacl")
    return False


def kdf_is_available(kdf: KdfType) -> bool:
    if kdf == KdfType.NONE:
        return True
    if kdf == KdfType.ARGON2ID:
        return _have("argon2")
    return False


def kem_is_available(mech: KeyEncap) -> bool:
    if mech == KeyEncap.NONE:
        return True
    if mech == KeyEncap.X25519:
        return _have("cryptography")
    if mech in (KeyEncap.ML_KEM_768, KeyEncap.ML_KEM_1024):
        return _have("oqs")
    if mech == KeyEncap.X25519_ML_KEM_768:
        return _have("cryptography") and _have("oqs")
    return False


# ---------------------------------------------------------------------- AEAD

def aead_encrypt(algo: EncAlgo, key: bytes, nonce: bytes, aad: bytes,
                 plaintext: bytes) -> bytes:
    """Encrypt *plaintext*, returning ``ciphertext || 16-byte tag``.

    The 16-byte AEAD tag is appended to the ciphertext (both cipher suites),
    matching the on-disk layout where the tag is the final bytes of the file.
    """
    if algo == EncAlgo.AES_256_GCM:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        return AESGCM(key).encrypt(nonce, plaintext, aad)
    if algo == EncAlgo.XCHACHA20_POLY1305:
        from nacl.bindings import crypto_aead_xchacha20poly1305_ietf_encrypt
        return crypto_aead_xchacha20poly1305_ietf_encrypt(
            plaintext, aad, nonce, key,
        )
    raise MslCryptoError(f"Unsupported cipher suite: {algo}")


def aead_decrypt(algo: EncAlgo, key: bytes, nonce: bytes, aad: bytes,
                 ciphertext_and_tag: bytes) -> bytes:
    """Verify and decrypt ``ciphertext || tag``. Raises MslAuthError on a
    tag mismatch (wrong key, tampered ciphertext, or corrupted AAD)."""
    if algo == EncAlgo.AES_256_GCM:
        from cryptography.exceptions import InvalidTag
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        try:
            return AESGCM(key).decrypt(nonce, ciphertext_and_tag, aad)
        except InvalidTag:
            raise MslAuthError("AEAD tag verification failed (AES-256-GCM)")
    if algo == EncAlgo.XCHACHA20_POLY1305:
        from nacl.bindings import crypto_aead_xchacha20poly1305_ietf_decrypt
        from nacl.exceptions import CryptoError
        try:
            return crypto_aead_xchacha20poly1305_ietf_decrypt(
                ciphertext_and_tag, aad, nonce, key,
            )
        except CryptoError:
            raise MslAuthError("AEAD tag verification failed (XChaCha20-Poly1305)")
    raise MslCryptoError(f"Unsupported cipher suite: {algo}")


def random_nonce(algo: EncAlgo) -> bytes:
    """Generate a CSPRNG nonce sized for *algo*, zero-padded to the 24-byte
    Nonce field. AES-256-GCM uses 12 bytes (rest zero); XChaCha20 uses 24."""
    n = CIPHER_NONCE_LEN[algo]
    return os.urandom(n).ljust(24, b"\x00")


def nonce_for_cipher(algo: EncAlgo, nonce_field: bytes) -> bytes:
    """Extract the cipher-sized nonce from the 24-byte header Nonce field."""
    return nonce_field[:CIPHER_NONCE_LEN[algo]]


# ----------------------------------------------------------- key derivation

def hkdf_blake3(ikm: bytes, salt: bytes, info: bytes,
                length: int = CEK_SIZE) -> bytes:
    """RFC 5869 HKDF using BLAKE3 as the HMAC hash (spec §10.4).

    BLAKE3 produces 32-byte output, so a single expand round covers the
    32-byte CEK. salt defaults to a 32-byte zero block when empty.
    """
    import blake3
    if not salt:
        salt = b"\x00" * 32
    prk = hmac.new(salt, ikm, blake3.blake3).digest()  # extract
    okm = b""
    block = b""
    counter = 1
    while len(okm) < length:  # expand
        block = hmac.new(prk, block + info + bytes([counter]), blake3.blake3).digest()
        okm += block
        counter += 1
    return okm[:length]


def derive_key_argon2id(passphrase: bytes, salt: bytes,
                        time_cost: int = ARGON2ID_MIN_TIME,
                        memory_kib: int = ARGON2ID_MIN_MEMORY_KIB,
                        lanes: int = ARGON2ID_MIN_LANES) -> bytes:
    """Derive a 32-byte CEK from a passphrase via Argon2id (spec §10.5).

    Enforces the spec minimums (time=3, memory=65536 KiB, lanes=4); callers
    requesting weaker parameters are silently raised to the minimum.
    """
    try:
        from argon2.low_level import Type, hash_secret_raw
    except ImportError:
        raise MslCryptoError(_ARGON2_MISSING)
    return hash_secret_raw(
        secret=passphrase,
        salt=salt,
        time_cost=max(time_cost, ARGON2ID_MIN_TIME),
        memory_cost=max(memory_kib, ARGON2ID_MIN_MEMORY_KIB),
        parallelism=max(lanes, ARGON2ID_MIN_LANES),
        hash_len=CEK_SIZE,
        type=Type.ID,
    )


# ------------------------------------------------------- key encapsulation

def _x25519_encapsulate(recipient_public: bytes) -> Tuple[bytes, bytes]:
    """Treat X25519 ECDH as a KEM. Returns (ephemeral_public, shared_secret).
    The ephemeral public key (32 bytes) is the KEM 'ciphertext'."""
    from cryptography.hazmat.primitives.asymmetric.x25519 import (
        X25519PrivateKey, X25519PublicKey)
    ephemeral = X25519PrivateKey.generate()
    shared = ephemeral.exchange(X25519PublicKey.from_public_bytes(recipient_public))
    return ephemeral.public_key().public_bytes_raw(), shared


def _x25519_decapsulate(recipient_private: bytes, kem_ct: bytes) -> bytes:
    from cryptography.hazmat.primitives.asymmetric.x25519 import (
        X25519PrivateKey, X25519PublicKey)
    sk = X25519PrivateKey.from_private_bytes(recipient_private)
    return sk.exchange(X25519PublicKey.from_public_bytes(kem_ct))


def _import_oqs():
    """Import liboqs-python or raise the actionable install hint."""
    try:
        import oqs
    except ImportError:
        raise MslCryptoError(_LIBOQS_MISSING)
    return oqs


def _require_mlkem_alg(oqs, alg: str) -> None:
    """Fail clearly if the installed liboqs lacks the FIPS-203 mechanism name.

    Older / minimally-configured liboqs builds expose only the pre-standard
    "Kyber*" names. Surface that mismatch as an actionable error instead of a
    cryptic failure from ``KeyEncapsulation`` deeper in the stack.
    """
    enabled = oqs.get_enabled_kem_mechanisms()
    if alg not in enabled:
        raise MslCryptoError(
            f"installed liboqs does not enable {alg!r}; available KEM "
            f"mechanisms: {sorted(enabled)}"
        )


def _mlkem_encapsulate(mech: KeyEncap, recipient_public: bytes) -> Tuple[bytes, bytes]:
    oqs = _import_oqs()
    alg = _MLKEM_PARAMS[mech]["alg"]
    _require_mlkem_alg(oqs, alg)
    with oqs.KeyEncapsulation(alg) as kem:
        return kem.encap_secret(recipient_public)  # (ciphertext, shared_secret)


def _mlkem_decapsulate(mech: KeyEncap, recipient_private: bytes, kem_ct: bytes) -> bytes:
    oqs = _import_oqs()
    alg = _MLKEM_PARAMS[mech]["alg"]
    _require_mlkem_alg(oqs, alg)
    with oqs.KeyEncapsulation(alg, recipient_private) as kem:
        return kem.decap_secret(kem_ct)


def kem_encapsulate(mech: KeyEncap, recipient_public: bytes) -> Tuple[bytes, bytes]:
    """Encapsulate to *recipient_public*. Returns (kem_ciphertext, shared_secret).

    For the hybrid mechanism, the ciphertext is X25519_ct || ML-KEM-768_ct and
    the shared secret is x25519_ss || mlkem_ss (concatenate-then-KDF per §10.4).
    """
    if mech == KeyEncap.X25519:
        return _x25519_encapsulate(recipient_public)
    if mech in (KeyEncap.ML_KEM_768, KeyEncap.ML_KEM_1024):
        return _mlkem_encapsulate(mech, recipient_public)
    if mech == KeyEncap.X25519_ML_KEM_768:
        x_pub = recipient_public[:_X25519_KEY_LEN]
        m_pub = recipient_public[_X25519_KEY_LEN:]
        x_ct, x_ss = _x25519_encapsulate(x_pub)
        m_ct, m_ss = _mlkem_encapsulate(KeyEncap.ML_KEM_768, m_pub)
        return x_ct + m_ct, x_ss + m_ss
    raise MslCryptoError(f"Unsupported key encapsulation mechanism: {mech}")


def kem_decapsulate(mech: KeyEncap, recipient_private: bytes, kem_ct: bytes) -> bytes:
    if mech == KeyEncap.X25519:
        return _x25519_decapsulate(recipient_private, kem_ct)
    if mech in (KeyEncap.ML_KEM_768, KeyEncap.ML_KEM_1024):
        return _mlkem_decapsulate(mech, recipient_private, kem_ct)
    if mech == KeyEncap.X25519_ML_KEM_768:
        x_priv = recipient_private[:_X25519_KEY_LEN]
        m_priv = recipient_private[_X25519_KEY_LEN:]
        x_ct = kem_ct[:_X25519_KEY_LEN]
        m_ct = kem_ct[_X25519_KEY_LEN:]
        x_ss = _x25519_decapsulate(x_priv, x_ct)
        m_ss = _mlkem_decapsulate(KeyEncap.ML_KEM_768, m_priv, m_ct)
        return x_ss + m_ss
    raise MslCryptoError(f"Unsupported key encapsulation mechanism: {mech}")


def kem_generate_keypair(mech: KeyEncap) -> Tuple[bytes, bytes]:
    """Generate a (public_key, private_key) pair for *mech*. Helper for key
    management and tests; hybrid keys are the concatenation of both halves."""
    if mech == KeyEncap.X25519:
        from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
        sk = X25519PrivateKey.generate()
        return sk.public_key().public_bytes_raw(), sk.private_bytes_raw()
    if mech in (KeyEncap.ML_KEM_768, KeyEncap.ML_KEM_1024):
        oqs = _import_oqs()
        alg = _MLKEM_PARAMS[mech]["alg"]
        _require_mlkem_alg(oqs, alg)
        with oqs.KeyEncapsulation(alg) as kem:
            pub = kem.generate_keypair()
            return pub, kem.export_secret_key()
    if mech == KeyEncap.X25519_ML_KEM_768:
        x_pub, x_priv = kem_generate_keypair(KeyEncap.X25519)
        m_pub, m_priv = kem_generate_keypair(KeyEncap.ML_KEM_768)
        return x_pub + m_pub, x_priv + m_priv
    raise MslCryptoError(f"Cannot generate keypair for mechanism: {mech}")


# ------------------------------------------------------ CEK orchestration

def _local_cek(kdf_type: KdfType, raw_key: Optional[bytes],
               passphrase: Optional[bytes], kdf_salt: Optional[bytes],
               kdf_time: int, kdf_memory: int, kdf_lanes: int) -> bytes:
    """Derive the CEK for KeyEncap=NONE (raw key or passphrase)."""
    if kdf_type == KdfType.NONE:
        if raw_key is None or len(raw_key) != CEK_SIZE:
            raise MslCryptoError(
                f"KdfType.NONE requires a {CEK_SIZE}-byte raw key"
            )
        return raw_key
    if kdf_type == KdfType.ARGON2ID:
        if not passphrase:
            raise MslCryptoError("KdfType.ARGON2ID requires a passphrase")
        if not kdf_salt:
            raise MslCryptoError("KdfType.ARGON2ID requires a KDF salt")
        return derive_key_argon2id(passphrase, kdf_salt, kdf_time, kdf_memory, kdf_lanes)
    raise MslCryptoError(f"Unsupported KDF type: {kdf_type}")


def derive_cek_producer(
    *,
    key_encap: KeyEncap,
    kdf_type: KdfType,
    dump_uuid_bytes: bytes,
    raw_key: Optional[bytes] = None,
    passphrase: Optional[bytes] = None,
    kdf_salt: Optional[bytes] = None,
    kdf_time: int = ARGON2ID_MIN_TIME,
    kdf_memory: int = ARGON2ID_MIN_MEMORY_KIB,
    kdf_lanes: int = ARGON2ID_MIN_LANES,
    recipient_public: Optional[bytes] = None,
) -> Tuple[bytes, bytes]:
    """Producer-side: return (cek, kem_ciphertext).

    KeyEncap=NONE → kem_ciphertext is empty; CEK from raw key or passphrase.
    KeyEncap≠NONE → encapsulate to recipient_public, derive CEK from the
    shared secret via HKDF-BLAKE3(salt=DumpUUID, info="MSL-CEK-v1").
    """
    if key_encap == KeyEncap.NONE:
        cek = _local_cek(kdf_type, raw_key, passphrase, kdf_salt,
                         kdf_time, kdf_memory, kdf_lanes)
        return cek, b""
    if recipient_public is None:
        raise MslCryptoError(f"{key_encap.name} requires a recipient public key")
    kem_ct, shared = kem_encapsulate(key_encap, recipient_public)
    cek = hkdf_blake3(shared, salt=dump_uuid_bytes, info=MSL_CEK_INFO)
    return cek, kem_ct


def derive_cek_consumer(
    *,
    key_encap: KeyEncap,
    kdf_type: KdfType,
    dump_uuid_bytes: bytes,
    raw_key: Optional[bytes] = None,
    passphrase: Optional[bytes] = None,
    kdf_salt: Optional[bytes] = None,
    kdf_time: int = ARGON2ID_MIN_TIME,
    kdf_memory: int = ARGON2ID_MIN_MEMORY_KIB,
    kdf_lanes: int = ARGON2ID_MIN_LANES,
    recipient_private: Optional[bytes] = None,
    kem_ciphertext: bytes = b"",
) -> bytes:
    """Consumer-side: derive the CEK to decrypt a container."""
    if key_encap == KeyEncap.NONE:
        return _local_cek(kdf_type, raw_key, passphrase, kdf_salt,
                          kdf_time, kdf_memory, kdf_lanes)
    if recipient_private is None:
        raise MslCryptoError(f"{key_encap.name} requires a recipient private key")
    shared = kem_decapsulate(key_encap, recipient_private, kem_ciphertext)
    return hkdf_blake3(shared, salt=dump_uuid_bytes, info=MSL_CEK_INFO)
