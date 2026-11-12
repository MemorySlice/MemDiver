"""The gocryptfs format oracle: synthetic vaults for every cipher + the real corpus.

Synthetic files are sealed by ``tests/_oracle_gocryptfs_fixtures.py`` without
any oracle helper, so a pass needs the oracle's own HKDF info strings, AAD,
nonce split and HChaCha20 to be right. The corpus tests then pin the same
code against files real gocryptfs 2.4.0 wrote.
"""

from __future__ import annotations

import os
import struct
import sys

import pytest

from memdiver.oracles import get_format, verdict_from
from memdiver.oracles.formats import gocryptfs_gcm as g
from tests._oracle_gocryptfs_fixtures import (
    CONF_SECRET,
    FEATURE_FLAGS,
    HAVE_CORPUS,
    RUN_0001_MASTER_HEX,
    GOCRYPTFS_CORPUS,
    conf_json,
    content_key_ref,
    corpus_runs,
    encrypt_file,
    hchacha20_ref,
    hkdf_ref,
    run_meta,
)

pytest.importorskip("cryptography", reason="the AEADs need `pip install cryptography`")

MASTER = bytes(range(100, 132))
PLAINTEXT = b"memdiver gocryptfs oracle test\n" * 4
CIPHERS = ("aes-gcm", "xchacha", "aes-siv")
needs_corpus = pytest.mark.skipif(not HAVE_CORPUS, reason=f"no gocryptfs corpus at {GOCRYPTFS_CORPUS}")


def _flip(key: bytes, bit: int = 0) -> bytes:
    flipped = bytearray(key)
    flipped[bit // 8] ^= 1 << (bit % 8)
    return bytes(flipped)


def _sample(cipher: str, master: bytes = MASTER, plaintext: bytes = PLAINTEXT) -> bytes:
    data = encrypt_file(cipher, content_key_ref(master, cipher), plaintext)
    return g.make_sample(data, conf_json(FEATURE_FLAGS[cipher]))


# ---------------------------------------------------------------- synthetic


@pytest.mark.parametrize("cipher", CIPHERS)
def test_synthetic_master_key_proven_and_flipped_bit_rejected(cipher):
    oracle = g.build_oracle({}, _sample(cipher))
    assert oracle.cipher == cipher
    proven = oracle.verify(MASTER, {})
    assert proven["status"] == "proven", proven
    assert proven["kind"] == g.KIND
    assert proven["derived"]["content_key_hex"] == content_key_ref(MASTER, cipher).hex()
    assert proven["derived"]["plaintext_len"] == len(PLAINTEXT)
    for bit in (0, 7, 128, 255):
        assert oracle.verify(_flip(MASTER, bit), {})["status"] == "rejected"


@pytest.mark.parametrize("cipher", CIPHERS)
def test_synthetic_content_key_candidate(cipher):
    oracle = g.build_oracle({"candidate_is": "content"}, _sample(cipher))
    content_key = content_key_ref(MASTER, cipher)
    assert oracle.candidate_lengths == (len(content_key),)
    assert oracle.verify(content_key, {})["status"] == "proven"
    assert oracle.verify(_flip(content_key), {})["status"] == "rejected"
    # The master key is not a content key: wrong length for SIV, wrong key otherwise.
    assert oracle.verify(MASTER, {})["status"] == "rejected"


def test_multi_block_file_verifies_block_zero_only():
    plaintext = os.urandom(4096 + 1000)  # a full block 0 followed by block 1
    data = encrypt_file("aes-gcm", content_key_ref(MASTER, "aes-gcm"), plaintext)
    sample = g.make_sample(data, conf_json(FEATURE_FLAGS["aes-gcm"]))
    assert len(sample) <= g.SAMPLE_MAX_BYTES
    verdict = g.build_oracle({}, sample).verify(MASTER, {})
    assert verdict["status"] == "proven"
    assert verdict["derived"]["plaintext_len"] == 4096


def test_legacy_gcm_without_hkdf_or_gcmiv128_uses_master_and_96_bit_nonce():
    data = encrypt_file("aes-gcm", MASTER, PLAINTEXT, nonce_len=12)
    oracle = g.build_oracle({}, g.make_sample(data, conf_json(["DirIV", "EMENames"])))
    assert (oracle.hkdf, len(oracle.nonce)) == (False, 12)
    assert oracle.verify(MASTER, {})["status"] == "proven"


def test_aes_siv_without_hkdf_uses_sha512_of_master():
    import hashlib

    data = encrypt_file("aes-siv", hashlib.sha512(MASTER).digest(), PLAINTEXT)
    oracle = g.build_oracle({}, g.make_sample(data, conf_json(["AESSIV", "DirIV"])))
    assert oracle.verify(MASTER, {})["status"] == "proven"


def test_hchacha20_matches_draft_vector_and_reference():
    key = bytes(range(32))
    nonce = bytes.fromhex("000000090000004a0000000031415927")
    expected = "82413b4227b27bfed30e42508a877d73a0f9e4d58a74a853c12ec41326d3ecdc"
    assert hchacha20_ref(key, nonce).hex() == expected
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms

    assert g._hchacha20(Cipher, algorithms, key, nonce).hex() == expected


def test_xchacha_cross_checked_against_libsodium():
    bindings = pytest.importorskip("nacl.bindings")
    file_id, nonce = os.urandom(16), os.urandom(24)
    key = content_key_ref(MASTER, "xchacha")
    aad = struct.pack(">Q", 0) + file_id
    sealed = bindings.crypto_aead_xchacha20poly1305_ietf_encrypt(PLAINTEXT, aad, nonce, key)
    data = struct.pack(">H", 2) + file_id + nonce + sealed
    oracle = g.build_oracle({}, g.make_sample(data, conf_json(FEATURE_FLAGS["xchacha"])))
    assert oracle.verify(MASTER, {})["status"] == "proven"


def test_stdlib_hkdf_matches_cryptography():
    for cipher, info in g.HKDF_INFO.items():
        length = g.CONTENT_KEY_LEN[cipher]
        assert g.hkdf_sha256(MASTER, info, length) == hkdf_ref(MASTER, info, length)


def test_wrong_length_candidate_is_rejected_not_error():
    verdict = g.build_oracle({}, _sample("aes-gcm")).verify(MASTER[:31], {})
    assert verdict["status"] == "rejected"
    assert "31 bytes" in verdict["detail"]


def test_missing_backend_is_an_error_verdict(monkeypatch):
    """With no library AND no pure-Python primitive, build still succeeds; verify says why."""
    sample = _sample("aes-gcm")
    # Poison every cached submodule too: an import of "cryptography.exceptions"
    # is served from sys.modules without ever touching the parent package.
    for name in [n for n in sys.modules if n.split(".")[0] in ("cryptography", "Crypto")]:
        monkeypatch.setitem(sys.modules, name, None)
    monkeypatch.setitem(sys.modules, "Crypto", None)
    monkeypatch.setattr(g, "aes", None, raising=False)  # as when the primitive is not inlined
    oracle = g.build_oracle({}, sample)
    assert oracle.backend is None
    verdict = oracle.verify(MASTER, {})
    assert verdict["status"] == "error"
    for missing in ("cryptography", "pycryptodome", "'aes' is not loaded"):
        assert missing in verdict["detail"]


def test_verdict_normalises_through_registry():
    verdict = verdict_from(g.build_oracle({}, _sample("xchacha")).verify(MASTER, {}))
    assert verdict.proven and verdict.kind == "gocryptfs-gcm"
    assert get_format("gocryptfs-gcm") is g


# ------------------------------------------------------- params and sample


def test_explicit_cipher_contradicting_conf_flags_is_refused():
    # The silent-false-negative trap: an AES oracle on an xchacha vault
    # would reject every candidate, indistinguishable from "key not in dump".
    with pytest.raises(ValueError, match="contradicts"):
        g.build_oracle({"cipher": "aes"}, _sample("xchacha"))


def test_sample_without_conf_needs_a_cipher():
    data = encrypt_file("xchacha", content_key_ref(MASTER, "xchacha"), PLAINTEXT)
    bare = g.make_sample(data)
    with pytest.raises(ValueError, match="cipher unknown"):
        g.build_oracle({}, bare)
    assert g.build_oracle({"cipher": "xchacha"}, bare).verify(MASTER, {})["status"] == "proven"
    hinted = g.make_sample(data, cipher="xchacha20-poly1305")
    assert g.build_oracle({}, hinted).verify(MASTER, {})["status"] == "proven"


def test_sample_keeps_feature_flags_but_drops_conf_secrets():
    sample = _sample("aes-gcm")
    assert CONF_SECRET.encode() not in sample and b"Scrypt" not in sample
    assert g.parse_sample(sample)["meta"]["feature_flags"] == FEATURE_FLAGS["aes-gcm"]


@pytest.mark.parametrize(("params", "match"), [
    ({"cipher": "rot13"}, "unknown gocryptfs cipher"),
    ({"candidate_is": "password"}, "candidate_is"),
    ({"hkdf": False}, "without HKDF"),
])
def test_bad_params_raise_value_error(params, match):
    data = encrypt_file("xchacha", content_key_ref(MASTER, "xchacha"), PLAINTEXT)
    with pytest.raises(ValueError, match=match):
        g.build_oracle(params, g.make_sample(data, cipher="xchacha"))


def test_malformed_samples_raise_value_error():
    with pytest.raises(ValueError, match="magic"):
        g.build_oracle({}, b"not a sample")
    with pytest.raises(ValueError, match="version"):
        g.make_sample(b"\x00\x01" + bytes(100))
    hole = struct.pack(">H", 2) + os.urandom(16) + bytes(4096 + 32)
    with pytest.raises(ValueError, match="hole"):
        g.build_oracle({}, g.make_sample(hole, conf_json(FEATURE_FLAGS["aes-gcm"])))


def test_find_content_file_skips_metadata_and_picks_smallest(tmp_path):
    small = encrypt_file("aes-gcm", MASTER, b"x")
    big = encrypt_file("aes-gcm", MASTER, b"y" * 500)
    (tmp_path / "gocryptfs.conf").write_bytes(conf_json(FEATURE_FLAGS["aes-gcm"]))
    (tmp_path / "gocryptfs.diriv").write_bytes(os.urandom(16))
    # Smaller than both content files and header-shaped: only the name excludes it.
    (tmp_path / "gocryptfs.longname.abc.name").write_bytes(b"\x00\x02" + bytes(44))
    (tmp_path / "aaa").write_bytes(big)
    (tmp_path / "sub").mkdir()
    (tmp_path / "sub" / "zzz").write_bytes(small)
    assert g.find_content_file(str(tmp_path)) == str(tmp_path / "sub" / "zzz")


def test_sample_from_vault_round_trip(tmp_path):
    (tmp_path / "gocryptfs.conf").write_bytes(conf_json(FEATURE_FLAGS["xchacha"]))
    (tmp_path / "f1").write_bytes(
        encrypt_file("xchacha", content_key_ref(MASTER, "xchacha"), PLAINTEXT)
    )
    oracle = g.build_oracle({}, g.sample_from_vault(str(tmp_path)))
    assert oracle.verify(MASTER, {})["status"] == "proven"


# ------------------------------------------------- review hardening (fixes 2-8)


@pytest.mark.parametrize("candidate", [None, "a" * 32, 12345, [1] * 32])
def test_verify_never_raises_on_non_bytes_candidates(candidate):
    verdict = g.build_oracle({}, _sample("aes-gcm")).verify(candidate, {})
    assert verdict["status"] == "error" and "bytes" in verdict["detail"]


def test_verify_accepts_bytearray_and_memoryview():
    oracle = g.build_oracle({}, _sample("aes-gcm"))
    assert oracle.verify(bytearray(MASTER), {})["status"] == "proven"
    assert oracle.verify(memoryview(MASTER), {})["status"] == "proven"


def _blob(meta_json: bytes, prefix: bytes = b"") -> bytes:
    return g.SAMPLE_MAGIC + struct.pack(">H", len(meta_json)) + meta_json + prefix


@pytest.mark.parametrize("sample_or_params", [
    ("sample", b"MDGOCFS1\x00"),  # 9 bytes: used to escape as struct.error
    ("sample", "meta []"),
    ("sample", "meta null"),
    ("sample", 'meta {"feature_flags": "XChaCha20Poly1305"}'),
    ("sample", 'meta {"feature_flags": [1, 2]}'),
    ("sample", 'meta {"file_size": "big"}'),
    ("params", ["not", "a", "dict"]),
    ("params", {"hkdf": "false"}),
    ("params", {"hkdf": 0}),
    ("params", {"cipher": 7}),
])
def test_malformed_input_raises_value_error_only(sample_or_params):
    what, value = sample_or_params
    data = encrypt_file("aes-gcm", content_key_ref(MASTER, "aes-gcm"), PLAINTEXT)
    params, sample = {}, g.make_sample(data, conf_json(FEATURE_FLAGS["aes-gcm"]))
    if what == "params":
        params = value
    elif isinstance(value, str):
        sample = _blob(value.split(" ", 1)[1].encode(), data)
    else:
        sample = value
    with pytest.raises(ValueError):
        g.build_oracle(params, sample)


@pytest.mark.parametrize("conf", ["[]", "null", b"\xff\xfe", '{"FeatureFlags": "HKDF"}'])
def test_make_sample_rejects_malformed_conf_with_value_error(conf):
    data = encrypt_file("aes-gcm", content_key_ref(MASTER, "aes-gcm"), PLAINTEXT)
    with pytest.raises(ValueError):
        g.make_sample(data, conf)


def test_flag_membership_is_exact_not_substring():
    # A flag list holding "XChaCha20Poly1305Extra" must not select xchacha.
    assert g.cipher_from_flags(["XChaCha20Poly1305Extra", "GCMIV128"]) == "aes-gcm"


def test_legacy_gcm_without_conf_via_nonce_length_or_hkdf_false():
    data = encrypt_file("aes-gcm", MASTER, PLAINTEXT, nonce_len=12)
    bare = g.make_sample(data, cipher="aes")
    for params in ({"hkdf": False}, {"hkdf": False, "nonce_length": 12}):
        oracle = g.build_oracle(params, bare)
        assert len(oracle.nonce) == 12
        assert oracle.verify(MASTER, {})["status"] == "proven"
        assert oracle.verify(_flip(MASTER), {})["status"] == "rejected"
    with pytest.raises(ValueError, match="nonce_length"):
        g.build_oracle({"nonce_length": 12}, _sample("xchacha"))
    with pytest.raises(ValueError, match="nonce_length"):
        g.build_oracle({"nonce_length": 13, "hkdf": False}, bare)


def test_truncated_sample_is_error_never_rejected():
    data = encrypt_file("aes-gcm", content_key_ref(MASTER, "aes-gcm"), PLAINTEXT)
    sample = g.make_sample(data, conf_json(FEATURE_FLAGS["aes-gcm"]))
    oracle = g.build_oracle({}, sample[:-10])  # recorded file_size > bytes present
    for key in (MASTER, _flip(MASTER)):
        verdict = oracle.verify(key, {})
        assert verdict["status"] == "error" and "sample truncated" in verdict["detail"]
    # A file whose (only) block is cut below nonce + tag + 1 byte.
    cut = data[:g.FILE_HEADER_LEN + 16 + 16]
    stub = g.build_oracle({}, g.make_sample(cut, conf_json(FEATURE_FLAGS["aes-gcm"])))
    assert stub.verify(MASTER, {})["status"] == "error"


@pytest.mark.parametrize(("cipher", "candidate_is", "lengths"), [
    ("aes-gcm", "master", (32,)), ("aes-siv", "master", (32,)),
    ("aes-siv", "content", (64,)), ("xchacha", "content", (32,)),
])
def test_candidate_lengths_exact_per_instance(cipher, candidate_is, lengths):
    oracle = g.build_oracle({"candidate_is": candidate_is}, _sample(cipher))
    assert oracle.candidate_lengths == lengths
    assert set(lengths) <= set(g.CANDIDATE_LENGTHS)


def test_find_content_file_falls_back_past_a_sparse_hole(tmp_path):
    hole = struct.pack(">H", 2) + os.urandom(16) + bytes(100)  # smallest, but unusable
    good = encrypt_file("aes-gcm", MASTER, b"y" * 500)
    (tmp_path / "a_hole").write_bytes(hole)
    (tmp_path / "b_good").write_bytes(good)
    assert g.find_content_file(str(tmp_path)) == str(tmp_path / "b_good")
    (tmp_path / "b_good").unlink()
    with pytest.raises(ValueError, match="no usable"):
        g.find_content_file(str(tmp_path))


# ------------------------------------------------------------- real corpus


@needs_corpus
def test_corpus_run_0001_master_key_proven_and_bit_flip_rejected():
    run = GOCRYPTFS_CORPUS / "run_0001"
    assert run_meta(run)["master_key_hex"] == RUN_0001_MASTER_HEX
    oracle = g.build_oracle({}, g.sample_from_vault(str(run / "cipher")))
    master = bytes.fromhex(RUN_0001_MASTER_HEX)
    verdict = oracle.verify(master, {})
    assert (verdict["status"], oracle.cipher) == ("proven", "aes-gcm"), verdict
    assert verdict["derived"]["content_key_hex"] == content_key_ref(master, "aes-gcm").hex()
    assert oracle.verify(_flip(master, 77), {})["status"] == "rejected"


@needs_corpus
def test_corpus_run_0001_content_key_proven():
    sample = g.sample_from_vault(str(GOCRYPTFS_CORPUS / "run_0001" / "cipher"))
    content_key = content_key_ref(bytes.fromhex(RUN_0001_MASTER_HEX), "aes-gcm")
    oracle = g.build_oracle({"candidate_is": "content"}, sample)
    assert oracle.verify(content_key, {})["status"] == "proven"
    assert oracle.verify(_flip(content_key), {})["status"] == "rejected"


@needs_corpus
def test_corpus_xchacha_run_proven_with_its_key():
    run = corpus_runs("xchacha")[0]
    oracle = g.build_oracle({}, g.sample_from_vault(str(run / "cipher")))
    master = bytes.fromhex(run_meta(run)["master_key_hex"])
    assert oracle.cipher == "xchacha"
    assert oracle.verify(master, {})["status"] == "proven", run
    assert oracle.verify(_flip(master), {})["status"] == "rejected"
