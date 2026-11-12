"""The gocryptfs oracle's crypto backend chain: cryptography -> pycryptodome -> pure Python.

A stock ``pip install volatility3`` has neither library and ``volatility3[full]`` only
pycryptodome, so a generated plugin must prove keys on every tier. Each test FORCES one
tier in-process (pure Python by ``MEMDIVER_PUREPY_CRYPTO=1``, pycryptodome by poisoning
``cryptography`` in ``sys.modules``) and requires identical verdicts: the same AEAD opens
on every backend, the same tampering is rejected, and the real corpus keys are proven.
Sealing is done with ``cryptography`` by the fixtures BEFORE a tier is forced.
"""

from __future__ import annotations

import os
import random
import struct
import sys
from collections import Counter

import pytest

from memdiver.oracles import get_format
from memdiver.vol3plugins.linux.secrets import aes as aes_primitive
from memdiver.vol3plugins.linux.secrets import chacha as chacha_primitive
from tests._oracle_gocryptfs_fixtures import (
    FEATURE_FLAGS,
    GOCRYPTFS_CORPUS,
    HAVE_CORPUS,
    conf_json,
    content_key_ref,
    corpus_runs,
    encrypt_file,
    run_meta,
    seal_block,
)

pytest.importorskip("cryptography", reason="the fixtures seal with cryptography")
pytest.importorskip("Crypto.Cipher.ChaCha20_Poly1305", reason="pycryptodome tier under test")

g = get_format("gocryptfs-gcm")
BACKENDS = ("cryptography", "pycryptodome", "pure-python")
MASTER = bytes(range(7, 39))
PLAINTEXT = b"memdiver backend chain\n" * 6
RNG = random.Random(0xBAC4E2D)
# (cipher, nonce length, content key length) of every on-disk gocryptfs layout.
LAYOUTS = (("aes-gcm", 12, 32), ("aes-gcm", 16, 32), ("xchacha", 24, 32), ("aes-siv", 16, 64))
needs_corpus = pytest.mark.skipif(not HAVE_CORPUS, reason=f"no gocryptfs corpus at {GOCRYPTFS_CORPUS}")


def force_backend(monkeypatch, name):
    """Make ``name`` the first usable tier of the chain for the rest of the test."""
    if name == "pure-python":
        monkeypatch.setenv(g.PUREPY_ENV, "1")
        return
    monkeypatch.delenv(g.PUREPY_ENV, raising=False)
    if name == "pycryptodome":
        for module in [m for m in sys.modules if m.split(".")[0] == "cryptography"]:
            monkeypatch.setitem(sys.modules, module, None)
        monkeypatch.setitem(sys.modules, "cryptography", None)


@pytest.fixture(params=BACKENDS)
def backend(request, monkeypatch):
    force_backend(monkeypatch, request.param)
    return request.param


def _flip(data, index=0):
    return data[:index] + bytes([data[index] ^ 1]) + data[index + 1:]


def _sample(cipher, flags=None, master=MASTER, nonce_len=None, hkdf=True):
    key = content_key_ref(master, cipher) if hkdf else master
    data = encrypt_file(cipher, key, PLAINTEXT, nonce_len=nonce_len)
    return g.make_sample(data, conf_json(FEATURE_FLAGS[cipher] if flags is None else flags))


@pytest.fixture(scope="module")
def samples():
    """Sealed with cryptography once, before any test poisons it (module scope runs first)."""
    out = {cipher: _sample(cipher) for cipher in ("aes-gcm", "xchacha", "aes-siv")}
    out["legacy-gcm"] = _sample("aes-gcm", flags=["DirIV"], nonce_len=12, hkdf=False)
    out["siv-content-key"] = content_key_ref(MASTER, "aes-siv")
    return out


# --------------------------------------------------------------------------- wiring


def test_registry_binds_the_stdlib_primitives():
    assert g.REQUIRES_PRIMITIVES == ("aes", "chacha")
    assert g.aes is aes_primitive and g.chacha is chacha_primitive
    assert g.BACKENDS == BACKENDS


def test_forced_pure_python_wins_even_with_both_libraries_installed(monkeypatch):
    monkeypatch.setenv(g.PUREPY_ENV, "1")
    assert {g.select_backend(c)[0] for c in ("aes-gcm", "xchacha", "aes-siv")} == {"pure-python"}
    monkeypatch.delenv(g.PUREPY_ENV)
    assert g.select_backend("aes-gcm")[0] == "cryptography"


def test_a_broken_library_falls_through_to_the_next_tier(monkeypatch):
    def broken(_cipher):
        raise OSError("libcrypto.so: cannot open shared object file")

    monkeypatch.setattr(g, "_load_backend", broken)
    assert g.select_backend("xchacha")[0] == "pycryptodome"
    monkeypatch.setattr(g, "_load_pycryptodome", broken)
    assert g.select_backend("xchacha")[0] == "pure-python"
    monkeypatch.setattr(g, "chacha", None)
    with pytest.raises(RuntimeError) as info:
        g.select_backend("xchacha")
    assert "cryptography: OSError" in str(info.value)
    assert "'chacha' is not loaded" in str(info.value)


# --------------------------------------------------------------------------- the oracle per backend


@pytest.mark.parametrize("cipher", ["aes-gcm", "xchacha", "aes-siv"])
def test_every_backend_proves_the_key_and_rejects_a_flipped_one(samples, backend, cipher):
    oracle = g.build_oracle({}, samples[cipher])
    assert oracle.backend == backend and oracle.backend_error is None
    proven = oracle.verify(MASTER, {})
    assert proven["status"] == "proven", proven
    assert proven["detail"] == f"{cipher} block 0 authenticated"
    assert proven["derived"]["backend"] == backend
    assert proven["derived"]["plaintext_len"] == len(PLAINTEXT)
    for bit in (0, 131, 255):
        rejected = oracle.verify(_flip(MASTER, bit // 8), {})
        assert rejected == {"status": "rejected", "kind": g.KIND,
                            "detail": f"{cipher} tag mismatch on block 0", "derived": {}}


def test_every_backend_handles_legacy_gcm_and_content_keys(samples, backend):
    legacy = g.build_oracle({}, samples["legacy-gcm"])
    assert len(legacy.nonce) == 12 and legacy.verify(MASTER, {})["status"] == "proven"
    content = g.build_oracle({"candidate_is": "content"}, samples["aes-siv"])
    assert content.verify(samples["siv-content-key"], {})["status"] == "proven"
    assert content.verify(MASTER * 2, {})["status"] == "rejected"


def _open_cases(cipher, nonce_len, key_len):
    """Blocks sealed by the cryptography-based fixture: plaintext 0..300, random AAD."""
    cases = []
    for length in range(301):
        key, nonce = os.urandom(key_len), os.urandom(32)[:nonce_len]
        aad = struct.pack(">Q", RNG.randrange(1 << 64)) + os.urandom(16)
        block = seal_block(cipher, key, nonce, os.urandom(length), aad)
        cases.append((key, nonce, block[nonce_len:], aad, length))
    return cases


@pytest.mark.parametrize("cipher,nonce_len,key_len", LAYOUTS, ids=lambda v: str(v))
def test_open_block_differential_and_tampering(monkeypatch, cipher, nonce_len, key_len):
    cases = _open_cases(cipher, nonce_len, key_len)
    reference = {}
    for name in BACKENDS:
        force_backend(monkeypatch, name)
        chosen, open_block, mismatch = g.select_backend(cipher)
        assert chosen == name
        for index, (key, nonce, sealed, aad, length) in enumerate(cases):
            plaintext = open_block(key, nonce, sealed, aad)
            assert len(plaintext) == length
            assert reference.setdefault(index, plaintext) == plaintext, (name, index)
            if index % 10 == 0:
                _assert_tampering_rejected(open_block, mismatch, key, nonce, sealed, aad)
        monkeypatch.undo()


def _assert_tampering_rejected(open_block, mismatch, key, nonce, sealed, aad):
    for bad_key, bad_nonce, bad_sealed, bad_aad in (
        (_flip(key), nonce, sealed, aad),
        (_flip(key, len(key) // 2), nonce, sealed, aad),  # second half (AES-SIV: K2, the CTR key)
        (_flip(key, len(key) - 1), nonce, sealed, aad),
        (key, _flip(nonce), sealed, aad),
        (key, _flip(nonce, len(nonce) - 1), sealed, aad),  # XChaCha: the inner-nonce part
        (key, nonce, _flip(sealed, len(sealed) - 1), aad),  # tag (SIV: last ciphertext byte)
        (key, nonce, _flip(sealed, 0), aad),  # first ciphertext byte (or SIV tag byte)
        (key, nonce, sealed, _flip(aad, 3)),  # block number in the AAD
    ):
        if len(key) == 64 and len(sealed) == 16 and bad_key != key and bad_key[:32] == key[:32]:
            continue  # AES-SIV, empty plaintext: K2 is unused (pinned by the guard test below)
        with pytest.raises(mismatch):
            open_block(bad_key, bad_nonce, bad_sealed, bad_aad)


# --------------------------------------------------------------------------- the real corpus


@pytest.fixture(scope="module")
def corpus():
    """(run name, cipher, sample, master key) for every corpus run."""
    if not HAVE_CORPUS:
        pytest.skip("no gocryptfs corpus")
    out = []
    for run in corpus_runs():
        meta = run_meta(run)
        sample = g.sample_from_vault(str(GOCRYPTFS_CORPUS / meta["vault_cipher_dir"]))
        out.append((run.name, meta["cipher"], sample, bytes.fromhex(meta["master_key_hex"])))
    return out


@needs_corpus
def test_whole_corpus_is_proven_identically_on_every_backend(backend, corpus):
    """The 95-run sweep (48 aes-gcm, 47 xchacha): every key proven, every bit-flip rejected."""
    proven, rejected = Counter(), 0
    for name, cipher, sample, key in corpus:
        oracle = g.build_oracle({}, sample)
        assert oracle.backend == backend
        verdict = oracle.verify(key, {})
        assert verdict["status"] == "proven", (name, verdict)
        proven[cipher] += 1
        rejected += oracle.verify(_flip(key, 31), {})["status"] == "rejected"
    assert proven == Counter({"aes": 48, "xchacha": 47})
    assert rejected == len(corpus) == 95


# --------------------------------------------------------------------------- tier self-tests


@pytest.mark.parametrize("cipher,nonce_len", sorted(g.SELFTEST_SEALED), ids=str)
def test_known_answers_open_on_every_backend(monkeypatch, cipher, nonce_len):
    for name in BACKENDS:
        force_backend(monkeypatch, name)
        assert g.select_backend(cipher, nonce_len)[0] == name
        monkeypatch.undo()


def _unsupported(*_args, **_kwargs):
    from cryptography.exceptions import UnsupportedAlgorithm

    raise UnsupportedAlgorithm("not supported by this OpenSSL / in FIPS mode")


@pytest.mark.parametrize("cipher,attribute", [
    ("aes-siv", "AESSIV"), ("xchacha", "ChaCha20Poly1305"), ("aes-gcm", "AESGCM")])
def test_cryptography_refusing_the_algorithm_falls_through(monkeypatch, cipher, attribute):
    """Importable but UnsupportedAlgorithm at construction (FIPS, OpenSSL<3 AES-SIV)."""
    from cryptography.hazmat.primitives.ciphers import aead

    monkeypatch.setattr(aead, attribute, _unsupported)
    if cipher == "xchacha":  # its opener builds the HChaCha20 subkey from ChaCha20 first
        from cryptography.hazmat.primitives.ciphers import algorithms
        monkeypatch.setattr(algorithms, "ChaCha20", _unsupported)
    assert g.select_backend(cipher)[0] == "pycryptodome"


def test_poc_fips_aes_siv_vault_is_proven_on_the_next_tier(monkeypatch, samples):
    """E2review/poc_fips.py: before the self-test every verdict here was ``error``."""
    from cryptography.hazmat.primitives.ciphers import aead

    monkeypatch.setattr(aead, "AESSIV", _unsupported)
    oracle = g.build_oracle({}, samples["aes-siv"])
    assert oracle.backend == "pycryptodome"
    assert oracle.verify(MASTER, {})["status"] == "proven"
    from Crypto.Cipher import AES

    monkeypatch.setattr(AES, "new", _unsupported)  # and pycryptodome refusing too
    oracle = g.build_oracle({}, samples["aes-siv"])
    assert oracle.backend == "pure-python"
    assert oracle.verify(MASTER, {})["status"] == "proven"
    assert "self-test" not in (oracle.backend_error or "")


def test_pycryptodome_construction_failure_falls_through_to_pure(monkeypatch):
    force_backend(monkeypatch, "pycryptodome")
    from Crypto.Cipher import ChaCha20_Poly1305

    monkeypatch.setattr(ChaCha20_Poly1305, "new", _unsupported_value_error)
    assert g.select_backend("xchacha")[0] == "pure-python"


def _unsupported_value_error(*_args, **_kwargs):
    raise ValueError("Nonce must be 8, 12 or 24 bytes long")  # what a too-old build says


def test_a_tier_that_accepts_tampering_or_mis_decrypts_is_refused(monkeypatch):
    class Lenient:
        @staticmethod
        def gcm_decrypt(key, nonce, ct, tag, aad, pure=False):
            return g.SELFTEST_PLAINTEXT  # opens anything: must fail the tamper half

    force_backend(monkeypatch, "pure-python")
    monkeypatch.setattr(g, "aes", Lenient)
    with pytest.raises(RuntimeError, match="tampered known answer was accepted"):
        g.select_backend("aes-gcm")
    Lenient.gcm_decrypt = staticmethod(lambda *a, **k: b"garbage")
    with pytest.raises(RuntimeError, match="wrong plaintext"):
        g.select_backend("aes-gcm")
    assert g.build_oracle({}, _sample_no_crypto()).backend is None


def _sample_no_crypto():
    """A syntactically valid aes-gcm sample that needs no library to build."""
    data = struct.pack(">H", 2) + bytes(16) + bytes(range(1, 16 + 40 + 16 + 1))
    return g.make_sample(data, conf_json(FEATURE_FLAGS["aes-gcm"]))


def test_pure_tier_never_touches_cryptography(monkeypatch):
    """Without the env var aes.py would use cryptography if importable; the tier must not."""
    monkeypatch.delenv(g.PUREPY_ENV, raising=False)

    def refuse(*_args, **_kwargs):
        raise AssertionError("pure tier called into cryptography")

    monkeypatch.setattr(aes_primitive, "_aes_fast", refuse)
    for cipher, nonce_len in sorted(g.SELFTEST_SEALED):
        open_block, mismatch = g._load_pure(cipher)
        g._self_test(cipher, nonce_len, open_block, mismatch)


def test_empty_siv_plaintext_never_reaches_the_oracle(samples):
    """SIV with an empty plaintext never uses K2 -- so block 0 must never be empty."""
    key, nonce = os.urandom(64), os.urandom(16)
    sealed = aes_primitive.siv_encrypt(key, b"", [b"aad", nonce], pure=True)
    assert aes_primitive.siv_decrypt(_flip(key, 32), sealed, [b"aad", nonce], pure=True) == b""
    data = struct.pack(">H", 2) + bytes(16) + nonce + sealed  # block 0 = nonce || tag only
    oracle = g.build_oracle({"candidate_is": "content"},
                            g.make_sample(data, conf_json(FEATURE_FLAGS["aes-siv"])))
    for candidate in (key, _flip(key, 32)):
        verdict = oracle.verify(candidate, {})
        assert verdict["status"] == "error" and "too short for any plaintext" in verdict["detail"]


def test_a_primitive_failing_at_import_leaves_discovery_working(monkeypatch, caplog):
    import types

    import memdiver.oracles as registry

    def boom(name):
        raise ValueError(f"{name} exploded at import")

    module = types.ModuleType("fake_format")
    module.REQUIRES_PRIMITIVES = ("aes",)
    monkeypatch.setattr(registry.importlib, "import_module", boom)
    registry.bind_primitives(module)
    assert getattr(module, "aes", None) is None
    assert "left unbound" in caplog.text and "exploded" in caplog.text
