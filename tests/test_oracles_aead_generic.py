"""The ``aead-generic`` format oracle: one sealed message proves an AEAD key.

Includes a differential test against ``gocryptfs-gcm`` on the same sealed block (the in-repo
demo vault samples), the backend chain (cryptography / pycryptodome / pure primitives) and
the inline run the way a generated plugin does it (memdiver and crypto libraries blocked).
"""

import ast
import base64
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from memdiver.oracles import get_format, missing_contract
from memdiver.oracles.embed import BUNDLE_SOURCES_NAME, inline_source, render_bundle
from memdiver.vol3plugins.linux.secrets import aes, chacha

A = get_format("aead-generic")
G = get_format("gocryptfs-gcm")
SAMPLES = Path(__file__).resolve().parents[1] / "samples"
KEY = bytes(range(0x20, 0x40))
POISON_ALL = (
    "import sys\n"
    'for _blocked in ("memdiver", "cryptography", "Crypto"):\n'
    "    sys.modules[_blocked] = None\n"
)


def _seal(alg, key, nonce, plaintext, aad=b"", tag_len=16):
    """ciphertext || tag with the stdlib primitives (independent of the backends under test)."""
    if alg == "aes-gcm":
        ct, tag = aes.gcm_encrypt(key, nonce, plaintext, aad, tag_length=tag_len)
    elif alg == "chacha20-poly1305":
        ct, tag = chacha.chacha20_poly1305_encrypt(key, nonce, plaintext, aad)
    else:
        ct, tag = chacha.xchacha20_poly1305_encrypt(key, nonce, plaintext, aad)
    return ct + tag


CASES = [("aes-gcm", 16, 12), ("aes-gcm", 24, 16), ("aes-gcm", 32, 12),
         ("chacha20-poly1305", 32, 12), ("xchacha20-poly1305", 32, 24)]


def _sample(alg, key_len, nonce_len, tag_len=16, plaintext=b"hello sealed world" * 3):
    key, nonce = KEY[:key_len] if key_len <= 32 else KEY, os.urandom(nonce_len)
    sealed = _seal(alg, key, nonce, plaintext, b"assoc", tag_len)
    return key, A.make_sample(alg, nonce, sealed, aad=b"assoc", tag_len=tag_len)


# ------------------------------------------------------------------ contract


def test_registered_and_complete():
    assert missing_contract(A) == []
    assert A.KIND == "aead-generic"
    assert A.CANDIDATE_LENGTHS == (16, 24, 32)
    assert A.REQUIRES_PRIMITIVES == ("aes", "chacha")


def test_source_is_python38_syntax():
    ast.parse(Path(A.__file__).read_text(encoding="utf-8"), feature_version=(3, 8))


def test_docstring_states_that_aead_tags_are_not_key_committing():
    assert "NOT key-committing" in A.__doc__


# ------------------------------------------------------------------ verify


@pytest.mark.parametrize(("alg", "key_len", "nonce_len"), CASES)
def test_right_key_proven_wrong_key_rejected(alg, key_len, nonce_len):
    key, sample = _sample(alg, key_len, nonce_len)
    o = A.build_oracle({}, sample)
    assert o.unique is True and o.cost_us == A.COST_US_BY_ALG[alg]
    assert A.build_oracle({"kdf": "hkdf-sha256"}, sample).cost_us == A.COST_US_BY_ALG[alg] + A.HKDF_COST_US
    v = o.verify(key, {})
    assert v["status"] == "proven" and v["derived"]["alg"] == alg and "derived_key_hex" not in v["derived"]
    assert o.verify(bytes([key[0] ^ 1]) + key[1:], {})["status"] == "rejected"


def test_truncated_gcm_tag():
    key, sample = _sample("aes-gcm", 32, 12, tag_len=12)
    o = A.build_oracle({}, sample)
    assert o.verify(key, {})["status"] == "proven"
    assert o.verify(bytes(32), {})["status"] == "rejected"


def test_lengths_and_bad_candidates():
    key, sample = _sample("xchacha20-poly1305", 32, 24)
    o = A.build_oracle({}, sample)
    assert o.candidate_lengths == (32,)
    assert o.verify(key[:16], {})["status"] == "rejected"
    assert "takes [32]" in o.prefilter(key[:16])
    assert o.prefilter(key) is None
    assert o.verify(12345, {})["status"] == "error"


def test_hkdf_derivation():
    master = os.urandom(32)
    content = A.hkdf_sha256(master, b"", b"my info", 32)
    nonce = os.urandom(12)
    sample = A.make_sample("chacha20-poly1305", nonce, _seal("chacha20-poly1305", content, nonce, b"x" * 40))
    o = A.build_oracle({"kdf": "hkdf-sha256", "info": "my info"}, sample)
    assert o.candidate_lengths == (16, 24, 32)
    v = o.verify(master, {})
    assert v["status"] == "proven" and v["derived"]["derived_key_hex"] == content.hex()
    hexinfo = A.build_oracle({"kdf": "hkdf-sha256", "info": "hex:" + b"my info".hex()}, sample)
    assert hexinfo.verify(master, {})["status"] == "proven"
    assert A.build_oracle({}, sample).verify(content, {})["status"] == "proven"
    # RFC 5869 test case 1
    okm = A.hkdf_sha256(bytes([0x0B] * 22), bytes(range(13)), bytes(range(0xF0, 0xFA)), 42)
    assert okm.hex().startswith("3cb25f25faacd57a90434f64d0362f2a")


@pytest.mark.parametrize("params", [{"kdf": "pbkdf2"}, {"kdf": "hkdf-sha256", "key_len": 20},
                                    {"info": 5}, "x"])
def test_bad_params_raise(params):
    _, sample = _sample("aes-gcm", 32, 12)
    with pytest.raises(ValueError):
        A.build_oracle(params, sample)


# ------------------------------------------------------------------ sample blob


def test_sample_round_trip_with_separate_tag():
    nonce = os.urandom(12)
    sealed = _seal("aes-gcm", KEY, nonce, b"payload", b"ad")
    sample = A.make_sample("AES-256-GCM", nonce, sealed[:-16], tag=sealed[-16:], aad=b"ad")
    parsed = A.parse_sample(sample)
    assert parsed["alg"] == "aes-gcm" and parsed["tag"] == sealed[-16:] and parsed["aad"] == b"ad"
    assert json.loads(sample[7:7 + int.from_bytes(sample[5:7], "big")])["tag_len"] == 16


@pytest.mark.parametrize("args", [
    ("aes-ccm", bytes(12), bytes(40)),
    ("chacha20-poly1305", bytes(24), bytes(40)),
    ("xchacha20-poly1305", bytes(12), bytes(40)),
    ("aes-gcm", bytes(4), bytes(40)),
    ("aes-gcm", bytes(12), bytes(16)),
    ("aes-gcm", bytes(12), bytes(9000)),
])
def test_make_sample_refuses_bad_messages(args):
    with pytest.raises(ValueError):
        A.make_sample(*args)
    with pytest.raises(ValueError):
        A.make_sample("aes-gcm", bytes(12), bytes(40), tag_len=8)  # too short a tag to prove


@pytest.mark.parametrize("blob", [b"", b"MDAE", b"XXXX\x01\x00\x02{}", b"MDAE\x02\x00\x02{}"])
def test_malformed_samples_raise_valueerror(blob):
    with pytest.raises(ValueError):
        A.build_oracle({}, blob)


# ------------------------------------------------------------------ backends


@pytest.mark.parametrize(("alg", "key_len", "nonce_len"), CASES)
def test_every_backend_tier_gives_the_same_verdicts(alg, key_len, nonce_len, monkeypatch):
    pytest.importorskip("cryptography")
    pytest.importorskip("Crypto.Cipher")
    key, sample = _sample(alg, key_len, nonce_len)
    parsed = A.parse_sample(sample)
    for loader in (A._load_cryptography, A._load_pycryptodome, A._load_pure):
        opener = loader(alg)
        A._self_test(alg, nonce_len, opener)
        assert opener(key, parsed["nonce"], parsed["ciphertext"], parsed["tag"], parsed["aad"]) == \
            b"hello sealed world" * 3
        with pytest.raises(A.TagMismatch):
            opener(bytes(len(key)), parsed["nonce"], parsed["ciphertext"], parsed["tag"], parsed["aad"])


def test_purepy_env_forces_the_pure_tier(monkeypatch):
    monkeypatch.setenv(A.PUREPY_ENV, "1")
    key, sample = _sample("aes-gcm", 32, 12)
    o = A.build_oracle({}, sample)
    assert o.backend == "pure-python" and o.verify(key, {})["status"] == "proven"


def test_no_backend_is_an_error_verdict(monkeypatch):
    monkeypatch.setenv(A.PUREPY_ENV, "1")
    monkeypatch.delattr(A, "chacha")
    key, sample = _sample("xchacha20-poly1305", 32, 24)
    o = A.build_oracle({}, sample)
    v = o.verify(key, {})
    assert o.backend is None and v["status"] == "error" and "chacha" in v["detail"]


def test_a_backend_failing_its_self_test_is_skipped(monkeypatch):
    def broken(alg):
        return lambda key, nonce, ct, tag, aad: b"wrong"
    monkeypatch.setattr(A, "_load_cryptography", broken)
    name, _ = A.select_backend("aes-gcm", 12)
    assert name in ("pycryptodome", "pure-python")


# ------------------------------------------------------------------ differential vs gocryptfs-gcm


@pytest.mark.parametrize("name", ["aes", "xchacha"])
def test_differential_against_gocryptfs_on_the_same_block(name):
    meta = json.loads((SAMPLES / "samples.json").read_text())["slices"][name]
    gsample = (SAMPLES / meta["oracle_sample"]).read_bytes()
    master = bytes.fromhex(meta["master_key_hex"])
    go = G.build_oracle({}, gsample)
    alg = {"aes-gcm": "aes-gcm", "xchacha": "xchacha20-poly1305"}[go.cipher]
    sample = A.make_sample(alg, go.nonce, go.sealed, aad=go.aad)
    hkdf = A.build_oracle({"kdf": "hkdf-sha256", "info": G.HKDF_INFO[go.cipher].decode()}, sample)
    plain = A.build_oracle({}, sample)
    content = go.content_key(master)
    for candidate in (master, bytes([master[0] ^ 1]) + master[1:], os.urandom(32)):
        assert hkdf.verify(candidate, {})["status"] == go.verify(candidate, {})["status"]
    proven = hkdf.verify(master, {})
    assert proven["status"] == "proven"
    assert proven["derived"]["derived_key_hex"] == content.hex()
    assert proven["derived"]["plaintext_sha256"] == go.verify(master, {})["derived"]["plaintext_sha256"]
    assert plain.verify(content, {})["status"] == "proven"
    assert plain.verify(master, {})["status"] == "rejected"


# ------------------------------------------------------------------ inlined, stdlib only


def test_inlined_bundle_proves_with_no_memdiver_and_no_crypto_library(tmp_path):
    lines = ["import base64", f'fmt = load_inlined("aead-generic", {BUNDLE_SOURCES_NAME})']
    for alg, key_len, nonce_len in CASES:
        key, sample = _sample(alg, key_len, nonce_len)
        lines += [f'o = fmt.build_oracle({{}}, base64.b64decode("{base64.b64encode(sample).decode()}"))',
                  f'k = bytes.fromhex("{key.hex()}")',
                  'print(o.backend, o.verify(k, {})["status"], o.verify(bytes([k[0] ^ 1]) + k[1:], {})["status"])']
    script = tmp_path / "plugin_like.py"
    script.write_text(POISON_ALL + render_bundle(["aead-generic"]) + "\n".join(lines) + "\n", encoding="utf-8")
    result = subprocess.run([sys.executable, "-I", script.name], cwd=tmp_path,
                            capture_output=True, text=True, timeout=300)
    assert result.returncode == 0, result.stderr
    assert result.stdout.splitlines() == ["pure-python proven rejected"] * len(CASES)


def test_inline_source_carries_both_primitives():
    assert [p.name for p in inline_source("aead-generic").primitives] == ["aes", "chacha"]


def test_gocryptfs_oracle_now_declares_unique():
    meta = json.loads((SAMPLES / "samples.json").read_text())["slices"]["aes"]
    assert G.build_oracle({}, (SAMPLES / meta["oracle_sample"]).read_bytes()).unique is True


def test_frontend_oracle_kind_list_mirrors_the_registry():
    """frontend/src/api/vol3.ts KNOWN_ORACLE_KINDS must list every registered format KIND."""
    import re

    from memdiver.oracles import list_formats

    source = (Path(__file__).resolve().parents[1] / "frontend" / "src" / "api" / "vol3.ts").read_text()
    block = re.search(r"KNOWN_ORACLE_KINDS = \[(.*?)\] as const", source, re.S)
    assert block, "KNOWN_ORACLE_KINDS not found"
    listed = re.findall(r'"([^"]+)"', block.group(1))
    assert listed[0] == "gocryptfs-gcm"  # the dialog's default
    assert sorted(listed) == list_formats()
