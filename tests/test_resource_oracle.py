"""Crux tests for ResourceOracle: derive a record key from a candidate secret and
confirm it against a synthetically-built record — TLS 1.2 GCM, TLS 1.2 CBC,
TLS 1.3, and the raw-key (future encrypted-file) seam. No pcap needed.
"""

import hmac

import pytest

from memdiver.core.kdf_tls import (
    derive_tls12_keys,
    derive_tls13_record_keys,
)
from memdiver.engine.resources.challenge import (
    DecryptionChallenge,
    DerivationContext,
    SuccessStrategy,
)
from memdiver.engine.resources.oracle import ResourceOracle, _xor_iv_seq
from memdiver.engine.verification import HAS_CRYPTO

pytestmark = pytest.mark.skipif(not HAS_CRYPTO, reason="cryptography not installed")

if HAS_CRYPTO:
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305

MS = bytes(range(1, 49))                 # 48-byte master secret
TS = bytes(range(1, 33))                 # 32-byte TLS 1.3 traffic secret (SHA-256 suite)
CR = bytes(range(32))
SR = bytes(range(32, 64))
PLAINTEXT = b"GET /secret HTTP/1.1\r\nHost: x\r\n\r\n"


class _ListResource:
    """Minimal VerificationResource wrapping a fixed challenge list."""

    def __init__(self, protocol, challenges):
        self.protocol = protocol
        self._ch = challenges

    def challenges(self):
        return list(self._ch)


def _aead_for(name, key):
    return ChaCha20Poly1305(key) if name.startswith("CHACHA") else AESGCM(key)


# --------------------------------------------------------------------------- #
# TLS 1.2 AEAD (GCM + ChaCha20)
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("code,record_iv,seq", [
    (0xC02F, bytes(range(8)), 0),        # AES-128-GCM, explicit 8-byte nonce
    (0xC030, bytes(range(8, 16)), 3),    # AES-256-GCM
    (0xCCA8, b"", 5),                    # ChaCha20-Poly1305, nonce = iv XOR seq
])
def test_tls12_aead_record(code, record_iv, seq):
    keys = derive_tls12_keys(MS, CR, SR, code)
    suite = keys.suite
    if suite.record_iv_len:
        nonce = keys.client_write_iv + record_iv
    else:
        nonce = _xor_iv_seq(keys.client_write_iv, seq)
    aad = seq.to_bytes(8, "big") + b"\x17\x03\x03" + len(PLAINTEXT).to_bytes(2, "big")
    blob = _aead_for(suite.verifier, keys.client_write_key).encrypt(nonce, PLAINTEXT, aad)

    ch = DecryptionChallenge(
        cipher=suite.verifier, ciphertext=blob, aad=aad,
        derivation=DerivationContext(
            protocol="TLS", version="12", client_random=CR, server_random=SR,
            cipher_suite=code, record_iv=record_iv, seq_num=seq,
        ),
    )
    oracle = ResourceOracle(_ListResource("TLS", [ch]))
    assert oracle.verify(MS) is True
    assert oracle.verify(bytes(48)) is False          # wrong master secret
    assert oracle.verify(bytes(47)) is False          # wrong length short-circuits


# --------------------------------------------------------------------------- #
# TLS 1.2 CBC + HMAC (older suites)
# --------------------------------------------------------------------------- #

def test_tls12_cbc_record():
    code = 0xC013  # TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA (AES-128, HMAC-SHA1)
    keys = derive_tls12_keys(MS, CR, SR, code)
    suite = keys.suite
    seq = 0
    header = b"\x17\x03\x03"                    # type || version (MAC-covered prefix)
    mac_input = seq.to_bytes(8, "big") + header + len(PLAINTEXT).to_bytes(2, "big") + PLAINTEXT
    mac = hmac.new(keys.client_mac_key, mac_input, suite.mac_hash).digest()
    body = PLAINTEXT + mac
    pad_needed = 16 - (len(body) % 16)
    plain = body + bytes([pad_needed - 1]) * pad_needed
    record_iv = bytes(range(16))
    enc = Cipher(algorithms.AES(keys.client_write_key), modes.CBC(record_iv)).encryptor()
    ciphertext = enc.update(plain) + enc.finalize()

    ch = DecryptionChallenge(
        cipher=suite.verifier, ciphertext=ciphertext, aad=header,
        derivation=DerivationContext(
            protocol="TLS", version="12", client_random=CR, server_random=SR,
            cipher_suite=code, record_iv=record_iv, seq_num=seq,
        ),
    )
    oracle = ResourceOracle(_ListResource("TLS", [ch]))
    assert oracle.verify(MS) is True
    assert oracle.verify(bytes(48)) is False


# --------------------------------------------------------------------------- #
# TLS 1.3
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("code", [0x1301, 0x1303])   # AES-128-GCM, ChaCha20
def test_tls13_record(code):
    rk = derive_tls13_record_keys(TS, code)
    seq = 2
    nonce = _xor_iv_seq(rk.iv, seq)
    aad = b"\x17\x03\x03" + (len(PLAINTEXT) + 16).to_bytes(2, "big")
    blob = _aead_for(rk.suite.verifier, rk.key).encrypt(nonce, PLAINTEXT, aad)

    ch = DecryptionChallenge(
        cipher=rk.suite.verifier, ciphertext=blob, aad=aad,
        derivation=DerivationContext(
            protocol="TLS", version="13", cipher_suite=code, seq_num=seq,
        ),
    )
    oracle = ResourceOracle(_ListResource("TLS", [ch]))
    assert oracle.verify(TS) is True
    assert oracle.verify(bytes(32)) is False


# --------------------------------------------------------------------------- #
# Raw-key seam (future encrypted-file resource): no derivation + validator
# --------------------------------------------------------------------------- #

def test_raw_key_validator_seam():
    key = bytes(range(32))
    nonce = bytes(range(12))
    blob = AESGCM(key).encrypt(nonce, b"%PDF-1.7 ...", None)
    ch = DecryptionChallenge(
        cipher="AES-256-GCM", ciphertext=blob, nonce=nonce,
        success=SuccessStrategy.VALIDATOR,
        validator=lambda pt: pt.startswith(b"%PDF"),
        derivation=None,
    )
    oracle = ResourceOracle(_ListResource("file", [ch]))
    assert oracle.verify(key) is True
    assert oracle.verify(bytes(32)) is False


def test_empty_resource_never_confirms():
    oracle = ResourceOracle(_ListResource("TLS", []))
    assert oracle.verify(MS) is False
