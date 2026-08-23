"""TLS KDF plugins wrapping TLS12PRF and TLS13HKDF as BaseKDF subclasses."""

import hashlib
import logging
from dataclasses import dataclass
from typing import Dict, List, Optional, Set, Union

from memdiver.core.kdf import TLS12PRF, TLS13HKDF, _hash_length
from memdiver.core.kdf_base import BaseKDF, KDFParams
from memdiver.core.models import CryptoSecret

logger = logging.getLogger("memdiver.kdf_tls")

_KDF_MATCH_CONFIDENCE = 0.95
_TLS12_KEY_SIZE = 48
_TLS13_KEY_SIZE = 32


class TLS12KDF(BaseKDF):
    """TLS 1.2 PRF as a BaseKDF plugin."""

    name = "tls12_prf"
    protocol = "TLS"
    versions = {"12"}

    def derive(self, secret: bytes, params: KDFParams) -> bytes:
        """Derive via TLS 1.2 PRF using first label and context as seed."""
        label = params.labels[0] if params.labels else b"master secret"
        if isinstance(label, str):
            label = label.encode("ascii")
        length = params.key_lengths[0] if params.key_lengths else _TLS12_KEY_SIZE
        return TLS12PRF.prf(secret, label, params.context, length, params.hash_algo)

    def expand_traffic_secret(
        self,
        secret: CryptoSecret,
        key_lengths: Optional[List[int]] = None,
        hash_algo: str = "sha256",
    ) -> List[CryptoSecret]:
        """TLS 1.2 has no traffic secret expansion."""
        return []

    def validate_pair(
        self,
        candidate_a: bytes,
        candidate_b: bytes,
        dump_data: bytes,
        hash_algo: str = "sha256",
        hash_candidates: Optional[List[bytes]] = None,
    ) -> float:
        """Test TLS 1.2 PRF relationship between two 48-byte candidates.

        *hash_candidates* is accepted for interface compatibility (SSH-2 needs
        it) and ignored here: TLS 1.2 PRF needs no dump-discovered hash inputs.
        """
        probe_random = b"\x00" * 32

        # Try a as PMS -> does PRF yield b?
        derived = TLS12PRF.derive_master_secret(
            candidate_a, probe_random, probe_random, hash_algo
        )
        if derived == candidate_b:
            return _KDF_MATCH_CONFIDENCE

        # Try b as PMS -> does PRF yield a?
        derived = TLS12PRF.derive_master_secret(
            candidate_b, probe_random, probe_random, hash_algo
        )
        if derived == candidate_a:
            return _KDF_MATCH_CONFIDENCE

        return 0.0

    def supported_secret_types(self) -> Set[str]:
        return set()


class TLS13KDF(BaseKDF):
    """TLS 1.3 HKDF as a BaseKDF plugin."""

    name = "tls13_hkdf"
    protocol = "TLS"
    versions = {"13"}

    TRAFFIC_SECRET_TYPES = {
        "CLIENT_HANDSHAKE_TRAFFIC_SECRET",
        "SERVER_HANDSHAKE_TRAFFIC_SECRET",
        "CLIENT_TRAFFIC_SECRET_0",
        "SERVER_TRAFFIC_SECRET_0",
    }

    def derive(self, secret: bytes, params: KDFParams) -> bytes:
        """Derive via TLS 1.3 HKDF-Expand-Label."""
        label = params.labels[0] if params.labels else "derived"
        if isinstance(label, bytes):
            label = label.decode("ascii")
        length = params.key_lengths[0] if params.key_lengths else _TLS13_KEY_SIZE
        return TLS13HKDF.hkdf_expand_label(
            secret, label, params.context, length, params.hash_algo
        )

    def expand_traffic_secret(
        self,
        secret: CryptoSecret,
        key_lengths: Optional[List[int]] = None,
        hash_algo: str = "sha256",
    ) -> List[CryptoSecret]:
        """Expand a TLS 1.3 traffic secret into key, IV, and finished."""
        if key_lengths is None:
            key_lengths = [16, 32]

        base_type = secret.secret_type
        derived: List[CryptoSecret] = []

        for key_len in key_lengths:
            write_key = TLS13HKDF.hkdf_expand_label(
                secret.secret_value, "key", b"", key_len, hash_algo
            )
            derived.append(CryptoSecret(
                secret_type=f"{base_type}_KEY_{key_len * 8}",
                identifier=secret.identifier,
                secret_value=write_key,
                protocol=secret.protocol,
            ))

        iv = TLS13HKDF.hkdf_expand_label(
            secret.secret_value, "iv", b"", 12, hash_algo
        )
        derived.append(CryptoSecret(
            secret_type=f"{base_type}_IV",
            identifier=secret.identifier,
            secret_value=iv,
            protocol=secret.protocol,
        ))

        hash_len = _hash_length(hash_algo)
        finished = TLS13HKDF.hkdf_expand_label(
            secret.secret_value, "finished", b"", hash_len, hash_algo
        )
        derived.append(CryptoSecret(
            secret_type=f"{base_type}_FINISHED",
            identifier=secret.identifier,
            secret_value=finished,
            protocol=secret.protocol,
        ))

        return derived

    def validate_pair(
        self,
        candidate_a: bytes,
        candidate_b: bytes,
        dump_data: bytes,
        hash_algo: str = "sha256",
        hash_candidates: Optional[List[bytes]] = None,
    ) -> float:
        """Test TLS 1.3 HKDF relationship between two 32-byte candidates.

        *hash_candidates* is accepted for interface compatibility (SSH-2 needs
        it) and ignored here: TLS 1.3 HKDF needs no dump-discovered hash inputs.
        """
        # Try HKDF-Extract both ways.
        prk = TLS13HKDF.hkdf_extract(salt=candidate_a, ikm=candidate_b, hash_algo=hash_algo)
        if prk == candidate_a or prk == candidate_b:
            return _KDF_MATCH_CONFIDENCE

        prk = TLS13HKDF.hkdf_extract(salt=candidate_b, ikm=candidate_a, hash_algo=hash_algo)
        if prk == candidate_a or prk == candidate_b:
            return _KDF_MATCH_CONFIDENCE

        # Try HKDF-Expand-Label with standard TLS 1.3 labels.
        # TLS 1.3 Derive-Secret over the empty transcript uses the hash of the
        # empty string as context (RFC 8446 Section 7.1), not zero bytes.
        empty_hash = hashlib.new(hash_algo, b"").digest()
        tls13_labels = [
            "derived", "c hs traffic", "s hs traffic",
            "c ap traffic", "s ap traffic", "exp master", "res master",
        ]
        for label in tls13_labels:
            derived = TLS13HKDF.hkdf_expand_label(
                candidate_a, label, empty_hash, _TLS13_KEY_SIZE, hash_algo
            )
            if derived == candidate_b:
                return _KDF_MATCH_CONFIDENCE

            derived = TLS13HKDF.hkdf_expand_label(
                candidate_b, label, empty_hash, _TLS13_KEY_SIZE, hash_algo
            )
            if derived == candidate_a:
                return _KDF_MATCH_CONFIDENCE

        return 0.0

    def supported_secret_types(self) -> Set[str]:
        return set(self.TRAFFIC_SECRET_TYPES)


# --------------------------------------------------------------------------- #
# TLS 1.2 cipher-suite table + traffic-key derivation (RFC 5246 §6.3)
#
# A recovered TLS 1.2 master secret becomes usable record-decryption keys only
# once expanded through the key block, whose length is fixed by the negotiated
# cipher suite: 2 * (mac_key_len + enc_key_len + fixed_iv_len). The block is
# then sliced in RFC 5246 §6.3 order:
#
#     client_write_MAC_key | server_write_MAC_key
#   | client_write_key     | server_write_key
#   | client_write_IV      | server_write_IV
#
# For AEAD suites mac_key_len is 0 and the "IV" is the implicit nonce salt
# (4 bytes for GCM, 12 for ChaCha20-Poly1305); the per-record explicit nonce
# (record_iv_len) is carried on the wire, not derived. For CBC suites the IV is
# explicit per record (fixed_iv_len 0, record_iv_len = block size).
#
# The server_random needed here is NOT present in an NSS keylog — it is supplied
# by the pcap handshake (Workstream P). This table + derive_tls12_keys() are the
# consumption path that TLS12KDF.expand_traffic_secret (whose registry signature
# cannot carry the randoms) deliberately leaves inert.
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class Tls12SuiteParams:
    """Key-material geometry for one TLS 1.2 cipher suite."""

    name: str
    enc_key_len: int
    fixed_iv_len: int   # implicit nonce salt: GCM 4, ChaCha 12, CBC 0
    mac_key_len: int    # HMAC key: SHA1 20, SHA256 32, SHA384 48, AEAD 0
    record_iv_len: int  # explicit per-record IV/nonce: GCM 8, CBC 16, ChaCha 0
    prf_hash: str       # PRF hash for the key block (sha256 / sha384)
    verifier: str       # matching key in engine.verification.VERIFIER_REGISTRY
    aead: bool
    mac_hash: str = ""  # record-MAC hash for CBC suites (sha1/sha256/sha384); "" for AEAD


# Keyed by IANA cipher-suite code (the uint16 read from a ServerHello). Covers
# the modern AEAD suites C1 verifies plus the common older TLS 1.2 CBC suites.
TLS12_CIPHER_SUITES: Dict[int, Tls12SuiteParams] = {
    # -- AES-GCM (AEAD) --
    0x009C: Tls12SuiteParams("TLS_RSA_WITH_AES_128_GCM_SHA256", 16, 4, 0, 8, "sha256", "AES-128-GCM", True),
    0x009D: Tls12SuiteParams("TLS_RSA_WITH_AES_256_GCM_SHA384", 32, 4, 0, 8, "sha384", "AES-256-GCM", True),
    0xC02B: Tls12SuiteParams("TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256", 16, 4, 0, 8, "sha256", "AES-128-GCM", True),
    0xC02C: Tls12SuiteParams("TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384", 32, 4, 0, 8, "sha384", "AES-256-GCM", True),
    0xC02F: Tls12SuiteParams("TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", 16, 4, 0, 8, "sha256", "AES-128-GCM", True),
    0xC030: Tls12SuiteParams("TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384", 32, 4, 0, 8, "sha384", "AES-256-GCM", True),
    # -- ChaCha20-Poly1305 (AEAD) --
    0xCCA8: Tls12SuiteParams("TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256", 32, 12, 0, 0, "sha256", "CHACHA20-POLY1305", True),
    0xCCA9: Tls12SuiteParams("TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256", 32, 12, 0, 0, "sha256", "CHACHA20-POLY1305", True),
    # -- AES-CBC + HMAC (older, non-AEAD). mac_hash is the record-MAC hash,
    #    distinct from prf_hash: _SHA suites MAC with SHA-1, _SHA256 with SHA-256,
    #    _SHA384 with SHA-384; the MAC key length equals that hash's digest size. --
    0x002F: Tls12SuiteParams("TLS_RSA_WITH_AES_128_CBC_SHA", 16, 0, 20, 16, "sha256", "AES-128-CBC", False, "sha1"),
    0x0035: Tls12SuiteParams("TLS_RSA_WITH_AES_256_CBC_SHA", 32, 0, 20, 16, "sha256", "AES-256-CBC", False, "sha1"),
    0x003C: Tls12SuiteParams("TLS_RSA_WITH_AES_128_CBC_SHA256", 16, 0, 32, 16, "sha256", "AES-128-CBC", False, "sha256"),
    0x003D: Tls12SuiteParams("TLS_RSA_WITH_AES_256_CBC_SHA256", 32, 0, 32, 16, "sha256", "AES-256-CBC", False, "sha256"),
    0xC013: Tls12SuiteParams("TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA", 16, 0, 20, 16, "sha256", "AES-128-CBC", False, "sha1"),
    0xC014: Tls12SuiteParams("TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA", 32, 0, 20, 16, "sha256", "AES-256-CBC", False, "sha1"),
    0xC027: Tls12SuiteParams("TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256", 16, 0, 32, 16, "sha256", "AES-128-CBC", False, "sha256"),
    0xC028: Tls12SuiteParams("TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384", 32, 0, 48, 16, "sha384", "AES-256-CBC", False, "sha384"),
}

# Reverse index so a suite may also be resolved by its IANA name.
_TLS12_SUITES_BY_NAME: Dict[str, Tls12SuiteParams] = {
    p.name: p for p in TLS12_CIPHER_SUITES.values()
}


def resolve_tls12_suite(cipher_suite: Union[int, str, Tls12SuiteParams]) -> Tls12SuiteParams:
    """Resolve a suite given as an IANA code (int), IANA name, or params object.

    Raises KeyError for an unknown/unsupported suite so callers surface a clear
    error rather than deriving keys of the wrong length.
    """
    if isinstance(cipher_suite, Tls12SuiteParams):
        return cipher_suite
    if isinstance(cipher_suite, int):
        return TLS12_CIPHER_SUITES[cipher_suite]
    return _TLS12_SUITES_BY_NAME[cipher_suite]


@dataclass(frozen=True)
class Tls12Keys:
    """Directional write keys/IVs (and MAC keys for CBC) for a TLS 1.2 session."""

    suite: Tls12SuiteParams
    client_write_key: bytes
    server_write_key: bytes
    client_write_iv: bytes
    server_write_iv: bytes
    client_mac_key: bytes = b""
    server_mac_key: bytes = b""


def derive_tls12_keys(
    master_secret: bytes,
    client_random: bytes,
    server_random: bytes,
    cipher_suite: Union[int, str, Tls12SuiteParams],
) -> Tls12Keys:
    """Expand a TLS 1.2 master secret into directional record keys (RFC 5246 §6.3).

    ``cipher_suite`` may be an IANA code, IANA name, or a resolved
    :class:`Tls12SuiteParams`. The server/client randoms come from the handshake
    (a pcap ServerHello/ClientHello); note :func:`TLS12PRF.derive_key_block`
    already applies the reversed ``server_random + client_random`` seed order.
    """
    p = resolve_tls12_suite(cipher_suite)
    block_len = 2 * (p.mac_key_len + p.enc_key_len + p.fixed_iv_len)
    block = TLS12PRF.derive_key_block(
        master_secret, server_random, client_random, block_len, p.prf_hash
    )

    pos = 0

    def _take(n: int) -> bytes:
        nonlocal pos
        chunk = block[pos:pos + n]
        pos += n
        return chunk

    client_mac = _take(p.mac_key_len)
    server_mac = _take(p.mac_key_len)
    client_key = _take(p.enc_key_len)
    server_key = _take(p.enc_key_len)
    client_iv = _take(p.fixed_iv_len)
    server_iv = _take(p.fixed_iv_len)

    return Tls12Keys(
        suite=p,
        client_write_key=client_key,
        server_write_key=server_key,
        client_write_iv=client_iv,
        server_write_iv=server_iv,
        client_mac_key=client_mac,
        server_mac_key=server_mac,
    )


# --------------------------------------------------------------------------- #
# TLS 1.3 cipher-suite table + record-key derivation (RFC 8446 §7.3)
#
# A TLS 1.3 *_traffic_secret_N (the value in an NSS keylog line) expands into a
# record protection key + IV via HKDF-Expand-Label(secret, "key"/"iv", "", len).
# The per-record nonce is write_iv XOR the record sequence number (§5.3); the
# sequence number is a wire fact supplied by the caller (the pcap oracle).
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class Tls13SuiteParams:
    """Key-material geometry for one TLS 1.3 cipher suite."""

    name: str
    key_len: int
    iv_len: int         # always 12 for the defined suites
    hash_algo: str
    verifier: str       # matching key in engine.verification.VERIFIER_REGISTRY


TLS13_CIPHER_SUITES: Dict[int, Tls13SuiteParams] = {
    0x1301: Tls13SuiteParams("TLS_AES_128_GCM_SHA256", 16, 12, "sha256", "AES-128-GCM"),
    0x1302: Tls13SuiteParams("TLS_AES_256_GCM_SHA384", 32, 12, "sha384", "AES-256-GCM"),
    0x1303: Tls13SuiteParams("TLS_CHACHA20_POLY1305_SHA256", 32, 12, "sha256", "CHACHA20-POLY1305"),
}

_TLS13_SUITES_BY_NAME: Dict[str, Tls13SuiteParams] = {
    p.name: p for p in TLS13_CIPHER_SUITES.values()
}


def resolve_tls13_suite(cipher_suite: Union[int, str, Tls13SuiteParams]) -> Tls13SuiteParams:
    """Resolve a TLS 1.3 suite from an IANA code, name, or params object."""
    if isinstance(cipher_suite, Tls13SuiteParams):
        return cipher_suite
    if isinstance(cipher_suite, int):
        return TLS13_CIPHER_SUITES[cipher_suite]
    return _TLS13_SUITES_BY_NAME[cipher_suite]


@dataclass(frozen=True)
class Tls13RecordKeys:
    """Record protection key + base IV expanded from one TLS 1.3 traffic secret."""

    suite: Tls13SuiteParams
    key: bytes
    iv: bytes


def derive_tls13_record_keys(
    traffic_secret: bytes,
    cipher_suite: Union[int, str, Tls13SuiteParams],
) -> Tls13RecordKeys:
    """Expand a TLS 1.3 traffic secret into its record key + base IV (RFC 8446 §7.3)."""
    p = resolve_tls13_suite(cipher_suite)
    key = TLS13HKDF.hkdf_expand_label(traffic_secret, "key", b"", p.key_len, p.hash_algo)
    iv = TLS13HKDF.hkdf_expand_label(traffic_secret, "iv", b"", p.iv_len, p.hash_algo)
    return Tls13RecordKeys(suite=p, key=key, iv=iv)
