"""Tests for vol3plugins/linux/secrets/x25519.py (RFC 7748), on both backends."""

import random

import pytest

from memdiver.vol3plugins.linux.secrets import x25519

PUREPY_ENV = "MEMDIVER_PUREPY_CRYPTO"
BACKENDS = ("cryptography", "pure-python")
P = 2 ** 255 - 19
RNG = random.Random(0x25519)


def _use_backend(monkeypatch, name):
    if name == "pure-python":
        monkeypatch.setenv(PUREPY_ENV, "1")
    else:
        pytest.importorskip("cryptography")
        monkeypatch.delenv(PUREPY_ENV, raising=False)
    assert x25519.backend() == name


@pytest.fixture(params=BACKENDS)
def crypto_backend(request, monkeypatch):
    _use_backend(monkeypatch, request.param)
    return request.param


def _on_both_backends(monkeypatch, function, *args):
    results = []
    for name in BACKENDS:
        _use_backend(monkeypatch, name)
        results.append(function(*args))
    assert results[0] == results[1]
    return results[0]


def _rand(size=32):
    return bytes(RNG.getrandbits(8) for _ in range(size))


RFC7748_5_2 = [
    ("a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4",
     "e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c",
     "c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552"),
    ("4b66e9d4d1b4673c5ad22691957d6af5c11b6421e0ea01d42ca4169e7918ba0d",
     "e5210f12786811d3f4b7959d0538ae2c31dbe7106fc03c3efc4cd549c715a493",
     "95cbde9476e8907d7aade45cb4b873f88b595a68799fa152e6f8f7647aac7957"),
]


@pytest.mark.parametrize("scalar,u,expected", RFC7748_5_2)
def test_rfc7748_section_5_2_vectors(crypto_backend, scalar, u, expected):
    # Both scalars are unclamped and the second u has bit 255 set: decode rules matter.
    assert x25519.scalarmult(bytes.fromhex(scalar), bytes.fromhex(u)).hex() == expected


def _iterate_ladder(iterations):
    """RFC 7748 5.2: k = u = 9; repeatedly (k, u) = (X25519(k, u), k)."""
    k = u = (9).to_bytes(32, "little")
    for _ in range(iterations):
        k, u = x25519.scalarmult(k, u), k
    return k.hex()


def test_rfc7748_one_iteration(crypto_backend):
    assert _iterate_ladder(1) == "422c8e7a6227d7bca1350b3e2bb7279f7897b87bb6854b783c60e80311ae3079"


def test_rfc7748_thousand_iterations(crypto_backend):
    # ~1.4 s on the pure path (measured), well under the 5 s budget, so not marked slow.
    assert _iterate_ladder(1000) == "684cf59ba83309552800ef566f2f4d3c1c3887c49360e3875f2eb94d99532c51"


def test_rfc7748_section_6_1_diffie_hellman(crypto_backend):
    alice = bytes.fromhex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a")
    bob = bytes.fromhex("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb")
    alice_public, bob_public = x25519.public_key(alice), x25519.public_key(bob)
    assert alice_public.hex() == "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a"
    assert bob_public.hex() == "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f"
    shared = "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742"
    assert x25519.scalarmult(alice, bob_public).hex() == shared
    assert x25519.scalarmult(bob, alice_public).hex() == shared


def test_clamp_and_is_clamped():
    raw = bytes([0xFF] * 32)
    clamped = x25519.clamp(raw)
    assert clamped[0] == 0xF8 and clamped[31] == 0x7F and clamped[1:31] == raw[1:31]
    assert x25519.clamp(bytes(32))[31] == 0x40
    assert x25519.is_clamped(clamped) and not x25519.is_clamped(raw)
    assert not x25519.is_clamped(bytes(32))  # bit 254 must be set
    assert x25519.clamp(clamped) == clamped
    for _ in range(20):
        k = _rand()
        assert x25519.is_clamped(x25519.clamp(k))


def test_unclamped_scalar_behaves_like_its_clamped_form(crypto_backend):
    for _ in range(5):
        k, u = _rand(), _rand()
        assert x25519.scalarmult(k, u) == x25519.scalarmult(x25519.clamp(k), u)
        assert x25519.public_key(k) == x25519.public_key(x25519.clamp(k))


def test_u_coordinate_decoding_masks_bit_255_and_reduces_mod_p(crypto_backend):
    k = _rand()
    for small in (2, 9, 18):  # only u < 19 has a non-canonical twin u + p below 2^255
        u = small.to_bytes(32, "little")
        high_bit = (small | 1 << 255).to_bytes(32, "little")
        non_canonical = (small + P).to_bytes(32, "little")
        expected = x25519.scalarmult(k, u)
        assert x25519.scalarmult(k, high_bit) == expected
        assert x25519.scalarmult(k, non_canonical) == expected


def test_small_order_points_give_all_zero_output_on_both_backends(crypto_backend):
    """RFC 7748 returns all zeros; cryptography raises, so the pure ladder answers."""
    k = _rand()
    order_eight = bytes.fromhex("e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800")
    for u in (bytes(32), (1).to_bytes(32, "little"), order_eight):
        assert x25519.scalarmult(k, u) == bytes(32)


def test_random_inputs_identical_on_both_backends(monkeypatch):
    for _ in range(25):
        k, u = _rand(), _rand()  # unclamped scalars, u with random bit 255
        _on_both_backends(monkeypatch, x25519.scalarmult, k, u)
        _on_both_backends(monkeypatch, x25519.public_key, k)


def test_wrong_sizes_raise():
    with pytest.raises(ValueError):
        x25519.scalarmult(bytes(31), bytes(32))
    with pytest.raises(ValueError):
        x25519.scalarmult(bytes(32), bytes(33))
    with pytest.raises(ValueError):
        x25519.clamp(bytes(16))


def test_backend_follows_the_environment_switch(monkeypatch):
    monkeypatch.setenv(PUREPY_ENV, "true")
    assert x25519.backend() == "pure-python"
    monkeypatch.delenv(PUREPY_ENV)
    pytest.importorskip("cryptography")
    assert x25519.backend() == "cryptography"


def test_strict_mode_rejects_small_order_results(crypto_backend):
    """Oracles must not accept an all-zero shared secret (a zeroed buffer would 'match')."""
    k = _rand()
    order_eight = bytes.fromhex("e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800")
    for u in (bytes(32), (1).to_bytes(32, "little"), order_eight):
        out = x25519.scalarmult(k, u)
        assert x25519.is_small_order_result(out)
        with pytest.raises(ValueError):
            x25519.scalarmult(k, u, strict=True)
    good = x25519.scalarmult(k, (9).to_bytes(32, "little"), strict=True)
    assert good == x25519.public_key(k) and not x25519.is_small_order_result(good)


def test_one_identity_against_many_points_matches_the_pure_ladder(monkeypatch):
    """The cached private-key object (one identity, many candidate points) changes nothing."""
    k = _rand()
    points = [x25519.public_key(_rand()) for _ in range(5)]
    _use_backend(monkeypatch, "pure-python")
    pure = [x25519.scalarmult(k, u) for u in points]
    _use_backend(monkeypatch, "cryptography")
    assert [x25519.scalarmult(k, u) for u in points] == pure
    assert [x25519.scalarmult(_rand(), u) for u in points] != pure


# --------------------------------------------------------------------------- noise (WireGuard)


def test_noise_helpers_match_an_independent_hkdf_blake2s():
    import hashlib
    import hmac

    from memdiver.vol3plugins.linux.secrets import noise

    def hkdf1(ck, data):
        prk = hmac.new(ck, data, hashlib.blake2s).digest()
        return hmac.new(prk, b"\x01", hashlib.blake2s).digest()

    e, es, ss, public = _rand(), _rand(), _rand(), _rand()
    ck = hashlib.blake2s(b"Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s").digest()
    for data in (e, es, ss):
        ck = hkdf1(ck, data)
    assert noise.kdf1(e, es) == hkdf1(e, es)
    assert noise.initiation_chaining_key(e, es, ss) == ck
    assert noise.precompute_key(noise.LABEL_MAC1, public) == hashlib.blake2s(
        b"mac1----" + public).digest()
    assert noise.precompute_key(noise.LABEL_COOKIE, public) == hashlib.blake2s(
        b"cookie--" + public).digest()
    assert noise.backend() == "pure-python"
