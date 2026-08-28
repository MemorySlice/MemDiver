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


# --------------------------------------------------------------------------- #
# build_oracle cap validation (regression guard)
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("bad_cap", [0, -1])
def test_build_oracle_rejects_a_challenge_cap_below_one(tmp_path, bad_cap):
    """``max_challenges`` below 1 is refused, never reinterpreted.

    Guards the exact regression the fix at ``builtin_oracle.build_oracle``
    closed: the old ``int(raw_cap) if raw_cap else None`` made a cap of ``0``
    *falsy*, so "verify nothing" silently became "uncapped", while ``-1``
    reached ``challenges[:-1]`` and dropped the tail of the challenge list. Both
    produce this codebase's signature failure mode -- a real key reported as
    "0 confirmed" by a run that looks successful -- so both must raise.
    """
    from memdiver.engine.resources.builtin_oracle import build_oracle

    capture = tmp_path / "capture.pcap"
    capture.write_bytes(b"")

    with pytest.raises(ValueError) as excinfo:
        build_oracle({
            "resource_type": "tls-pcap",
            "pcap": str(capture),
            "max_challenges": bad_cap,
        })

    message = str(excinfo.value)
    assert "max_challenges must be >= 1" in message
    assert str(bad_cap) in message


def test_build_oracle_distinguishes_an_absent_cap_from_a_cap_of_zero():
    """Omitting the key -- the one legitimate way to be uncapped -- still works.

    The counterpart to the rejection above, and the half the old truthiness test
    could not tell apart: with no ``max_challenges`` key the whole challenge
    stream survives, while a valid cap truncates to exactly that many. Uses a
    throwaway resource type so the assertion is on the challenge accounting
    itself rather than on a pcap fixture.
    """
    from memdiver.engine.resources import builtin_oracle

    challenges = [
        DecryptionChallenge(
            cipher="AES-256-GCM", ciphertext=b"x", nonce=bytes(12),
            success=SuccessStrategy.VALIDATOR, validator=lambda pt: False,
            derivation=None,
        )
        for _ in range(3)
    ]
    builtin_oracle.register_resource_type(
        "test-list", lambda config: _ListResource("file", challenges)
    )
    try:
        uncapped = builtin_oracle.build_oracle({"resource_type": "test-list"})
        capped = builtin_oracle.build_oracle(
            {"resource_type": "test-list", "max_challenges": 1}
        )
    finally:
        builtin_oracle.RESOURCE_FACTORIES.pop("test-list", None)

    assert len(uncapped) == 3
    assert len(capped) == 1


@pytest.mark.parametrize("bad_cap", [0, -1])
def test_build_oracle_rejects_a_record_cap_below_one(tmp_path, bad_cap):
    """``max_records_per_direction`` below 1 is refused at the same entry point.

    The twin of the ``max_challenges`` guard above, and the half that was
    missing: the record cap was passed straight through ``int(...)`` into
    ``TlsPcapResource``, which did not check it either, so a config-file-driven
    oracle (an ``oracle.toml`` with ``max_records_per_direction = 0``) emitted
    zero records and reported a real key as "0 confirmed". The producer layer
    guards both caps, but a TOML oracle never passes through a producer.
    """
    from memdiver.engine.resources.builtin_oracle import build_oracle

    capture = tmp_path / "capture.pcap"
    capture.write_bytes(b"")

    with pytest.raises(ValueError) as excinfo:
        build_oracle({
            "resource_type": "tls-pcap",
            "pcap": str(capture),
            "max_records_per_direction": bad_cap,
        })

    message = str(excinfo.value)
    assert "max_records_per_direction must be >= 1" in message
    assert str(bad_cap) in message


def test_build_oracle_distinguishes_an_absent_record_cap_from_a_cap_of_zero(tmp_path):
    """Omitting the record cap leaves the resource default in force.

    The non-vacuity companion to the rejection above (mirroring the
    ``max_challenges`` pair): proves the guard rejects a *value*, not the key's
    presence, and that a legitimate cap still reaches the resource. Asserted on
    the resource the factory builds, so no pcap needs to parse.
    """
    from memdiver.engine.resources.builtin_oracle import build_resource

    capture = tmp_path / "capture.pcap"
    capture.write_bytes(b"")
    base = {"resource_type": "tls-pcap", "pcap": str(capture)}

    default = build_resource(dict(base))
    capped = build_resource({**base, "max_records_per_direction": 1})

    assert default.max_records_per_direction == 16
    assert capped.max_records_per_direction == 1


def test_both_cap_layers_agree_on_the_bound_and_the_wording():
    """The oracle-loader guard and the producer guard must not drift apart.

    Two layers reject the same mistake -- ``builtin_oracle`` for a
    config-driven oracle, ``app.tools_pipeline._validate_pcap_caps`` for every
    surface's producer -- and a user who hits one and then the other must read
    the same sentence. Compared for exact equality on the same cap name, so a
    reworded or re-bounded message on either side fails here rather than
    quietly producing two dialects of the same error.
    """
    from memdiver.app.tools_pipeline import _validate_pcap_caps
    from memdiver.core.service_errors import CapabilityError
    from memdiver.engine.resources.builtin_oracle import _require_positive_cap

    with pytest.raises(CapabilityError) as producer:
        _validate_pcap_caps(0, None)
    with pytest.raises(ValueError) as loader:
        _require_positive_cap("pcap_max_records", 0)

    assert str(loader.value) == str(producer.value)


def test_a_valid_cap_passes_through_and_none_means_uncapped():
    """The helper converts, it does not merely check -- and ``None`` survives.

    ``None`` is the only legitimate way to say "no cap supplied"; turning it
    into a number here would silently impose a cap the caller never asked for.
    """
    from memdiver.engine.resources.builtin_oracle import _require_positive_cap

    assert _require_positive_cap("max_challenges", None) is None
    assert _require_positive_cap("max_challenges", 1) == 1
    assert _require_positive_cap("max_challenges", "8") == 8
