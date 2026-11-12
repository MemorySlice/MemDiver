"""M7: SSH session keys from memory -- the RFC 4253 KDF, the ``ssh-kdf-consistency`` oracle
and the ``memdiver.ssh`` engine (tiers A/B/C) on synthetic memory, plus corpus-gated runs.

Real-data claims under stock ``vol`` live in ``test_vol3plugins_corpus_gate.py`` (C-SSH1).
The corpus tests here skip cleanly without ``MEMDIVER_SSH_CORPUS`` (``.msl`` captures, each
session directory with a ``gt.json``) or ``MEMDIVER_SECRETS_CORPUS``.
"""
import gzip
import hashlib
import json
import os
import random
import struct
from pathlib import Path

import pytest

from memdiver.core.kdf_ssh import SSH2KDF
from memdiver.oracles import get_format, list_formats, missing_contract, verdict_from
from memdiver.vol3plugins.linux.secrets import aes, ssh_kdf, x25519
from memdiver.vol3plugins.memdiver import ssh_engine as E

SSH_CORPUS = Path(os.environ.get("MEMDIVER_SSH_CORPUS", "") or "/nonexistent")
RNG = random.Random(0x55A7)


def rand(n):
    return bytes(RNG.getrandbits(8) for _ in range(n))


def high_bit(n):
    return b"\x9a" + rand(n - 1)


def low_bit(n):
    return b"\x3c" + rand(n - 1)


# --------------------------------------------------------------------------- KDF KATs


def _paramiko_reference(k_int, h, sid, letter, nbytes, hash_fn):
    paramiko = pytest.importorskip("paramiko")

    class Engine(object):
        hash_algo = hash_fn

    class Fake(object):
        K, H, session_id, kex_engine = k_int, h, sid, Engine()
        _logged_hash_selection = True

        def _log(self, *args):
            pass

    return paramiko.Transport._compute_key(Fake(), letter, nbytes)


@pytest.mark.parametrize("hash_name,hash_fn,hlen", [
    ("sha256", hashlib.sha256, 32), ("sha512", hashlib.sha512, 64), ("sha1", hashlib.sha1, 20)])
@pytest.mark.parametrize("k_raw", [low_bit(32), high_bit(32), b"\x00\x00" + low_bit(30)],
                         ids=["no-pad", "high-bit-pad", "leading-zeros"])
def test_rfc4253_derivation_matches_paramiko_reference(hash_name, hash_fn, hlen, k_raw):
    """Independent implementation (Paramiko's Transport._compute_key), all letters, 64 bytes."""
    h, sid = rand(hlen), rand(hlen)
    k_enc = ssh_kdf.encode_mpint(k_raw)
    for letter in "ABCDEF":
        want = _paramiko_reference(int.from_bytes(k_raw, "big"), h, sid, letter, 64, hash_fn)
        assert ssh_kdf.derive_key(k_enc, h, letter, sid, 64, hash_name) == want


@pytest.mark.parametrize("hash_name", ["sha256", "sha512"])
@pytest.mark.parametrize("k_raw", [low_bit(32), high_bit(32)])
def test_derivation_matches_core_kdf_ssh(hash_name, k_raw):
    """``core/kdf_ssh.SSH2KDF`` and the stdlib primitive agree (canonical K)."""
    h, sid = rand(32), rand(32)
    k_enc = ssh_kdf.encode_mpint(k_raw)
    for length in (12, 16, 32, 64):
        core = SSH2KDF.derive_all_keys(k_raw, h, sid, length, hash_name)
        mine = ssh_kdf.derive_all(k_enc, h, sid, length, hash_name)
        assert core == mine


def test_extension_is_k1_then_hash_of_k_h_k1():
    k_enc, h, sid = ssh_kdf.encode_mpint(low_bit(32)), rand(32), rand(32)
    k1 = hashlib.sha256(k_enc + h + b"C" + sid).digest()
    k2 = hashlib.sha256(k_enc + h + k1).digest()
    assert ssh_kdf.derive_key(k_enc, h, "C", sid, 64, "sha256") == k1 + k2
    assert ssh_kdf.derive_key(k_enc, h, "C", sid, 64, "sha512") == hashlib.sha512(
        k_enc + h + b"C" + sid).digest()


def test_curve25519_k_is_the_rfc7748_secret_as_mpint():
    """RFC 7748 section 6.1 shared secret, encoded as RFC 8731 says (mpint, network order)."""
    alice = bytes.fromhex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a")
    bob_pub = bytes.fromhex("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f")
    secret = x25519.scalarmult(alice, bob_pub)
    assert secret.hex() == "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742"
    assert ssh_kdf.encode_mpint(secret) == b"\x00\x00\x00\x20" + secret
    paramiko = pytest.importorskip("paramiko")
    for raw in (secret, b"\xff" + secret[1:], b"\x00" + secret[1:], b"\x00\x80" + secret[2:]):
        m = paramiko.Message()
        m.add_mpint(int.from_bytes(raw, "big"))
        assert ssh_kdf.encode_mpint(raw) == m.asbytes(), raw[:2].hex()
    assert ssh_kdf.encode_mpint(b"\xff" + secret[1:])[:5] == b"\x00\x00\x00\x21\x00"
    # a leading zero byte is dropped (31 bytes) and a 0x00 put back only for a set top bit
    assert ssh_kdf.encode_mpint(b"\x00\x7f" + secret[2:])[:5] == b"\x00\x00\x00\x1f\x7f"
    assert ssh_kdf.encode_mpint(b"\x00\x80" + secret[2:])[:6] == b"\x00\x00\x00\x20\x00\x80"
    assert ssh_kdf.encode_mpint(0) == b"\x00\x00\x00\x00"


def test_hybrid_kex_k_is_a_string_and_kex_names_map():
    k = rand(64)
    assert ssh_kdf.encode_string(k) == b"\x00\x00\x00\x40" + k
    assert ssh_kdf.kex_k_encoding("sntrup761x25519-sha512@openssh.com") == "string"
    assert ssh_kdf.kex_k_encoding("mlkem768x25519-sha256") == "string"
    assert ssh_kdf.kex_k_encoding("curve25519-sha256") == "mpint"
    assert ssh_kdf.kex_hash("sntrup761x25519-sha512@openssh.com") == "sha512"
    assert ssh_kdf.kex_hash("curve25519-sha256@libssh.org") == "sha256"
    assert ssh_kdf.mac_key_length("hmac-sha2-256-etm@openssh.com") == 32


def test_primitive_input_checks():
    with pytest.raises(ValueError):
        ssh_kdf.derive_key(b"k", b"h", "G", b"s", 16)
    with pytest.raises(ValueError):
        ssh_kdf.derive_key(b"k", b"h", "A", b"s", 16, "md17")
    with pytest.raises(ValueError):
        ssh_kdf.encode_mpint(-1)
    assert ssh_kdf.swap_words(b"\x01\x02\x03\x04\x05") == b"\x04\x03\x02\x01\x05"
    assert ssh_kdf.proof_status(2) == "proven"
    assert ssh_kdf.proof_status(1, trusted=True) == "inconclusive"
    assert ssh_kdf.proof_status(0, trusted=True) == "rejected"
    assert ssh_kdf.proof_status(0) == "inconclusive"


# --------------------------------------------------------------------------- the format oracle


def _session(hash_name="sha256", k_raw=None, hlen=32):
    k_raw = k_raw or low_bit(32)
    h = rand(hlen)
    derived = ssh_kdf.derive_all(ssh_kdf.encode_mpint(k_raw), h, h, 64, hash_name)
    return k_raw, h, derived


def test_oracle_is_registered_and_follows_the_contract():
    assert "ssh-kdf-consistency" in list_formats()
    module = get_format("ssh-kdf-consistency")
    assert missing_contract(module) == []
    assert module.REQUIRES_PRIMITIVES == ("ssh_kdf",)
    sample = module.make_sample(hash_name="sha512", kex="sntrup761x25519-sha512@openssh.com")
    assert len(sample) < 200 and module.parse_sample(sample)["hash"] == "sha512"


@pytest.mark.parametrize("hash_name,hlen", [("sha256", 32), ("sha512", 64)])
def test_oracle_proves_the_right_k_and_rejects_a_wrong_one(hash_name, hlen):
    oracle = get_format("ssh-kdf-consistency").build_oracle({}, b"")
    k_raw, h, d = _session(hash_name, hlen=hlen)
    found = [d["C"][:32], d["D"][32:64], rand(32)]          # aes256 C + a chacha half of D
    ok = verdict_from(oracle.verify(k_raw, {"exchange_hash": h, "found": found}))
    assert ok.status == "proven" and ok.derived["letters"] == "CD"
    assert ok.derived["hash"] == hash_name
    wrong = oracle.verify(low_bit(32), {"exchange_hash": h, "found": found, "trusted": True})
    assert wrong["status"] == "rejected"
    untrusted = oracle.verify(low_bit(32), {"exchange_hash": h, "found": found})
    assert untrusted["status"] == "error" and "inconclusive" in untrusted["detail"]


def test_oracle_one_match_is_never_a_proof_and_garbage_is_an_error():
    oracle = get_format("ssh-kdf-consistency").build_oracle({"k_encoding": "mpint"}, None)
    k_raw, h, d = _session()
    one = oracle.verify(k_raw, {"exchange_hash": h, "found": [d["E"][:32]], "trusted": True})
    assert one["status"] == "error" and "only key E" in one["detail"]
    assert oracle.verify("not bytes", {"exchange_hash": h, "found": [b"x" * 16]})["status"] == "error"
    assert oracle.verify(k_raw, {"found": [d["C"]]})["status"] == "error"
    assert oracle.verify(k_raw, {"exchange_hash": rand(17), "found": [d["C"]]})["status"] == "error"


def test_oracle_word_swapped_keys_and_string_k():
    oracle = get_format("ssh-kdf-consistency").build_oracle({"kex": "mlkem768x25519-sha256"}, b"")
    k = rand(32)
    h = rand(32)
    d = ssh_kdf.derive_all(ssh_kdf.encode_string(k), h, h, 64, "sha256")
    found = [ssh_kdf.swap_words(d["C"][:16]), d["A"][:16]]   # an AES round key 0, BE words
    verdict = oracle.verify(k, {"exchange_hash": h, "found": found})
    assert verdict["status"] == "proven", verdict
    assert verdict["derived"]["matches"]["C"]["word_swapped"] is True


# --------------------------------------------------------------------------- synthetic memory


class Heap(object):
    """A fake process: one random-filled segment at ``base``."""

    def __init__(self, size=1 << 16, base=0x7F12_3400_0000):
        self.base = base
        self.data = bytearray(rand(size))

    def put(self, offset, blob):
        self.data[offset:offset + len(blob)] = blob
        return self.base + offset

    def memory(self, extra=()):
        return E.Memory([(self.base, bytes(self.data))] + list(extra))


def _rows(analysis, **want):
    return [r for r in analysis.rows if all(getattr(r, k) == v for k, v in want.items())]


def test_go_kexresult_chacha_is_tier_a_proven():
    heap = Heap()
    k_enc = ssh_kdf.encode_mpint(high_bit(32))
    h = rand(32)
    d = ssh_kdf.derive_all(k_enc, h, h, 64, "sha256")
    h_va, k_va = heap.put(0x1000, h), heap.put(0x2000, k_enc)
    heap.put(0x4000, struct.pack("<16Q", h_va, 32, 32, k_va, len(k_enc), 48, heap.base + 0x3000,
                                 51, 64, heap.base + 0x3100, 83, 96, 5, h_va, 32, 32))
    heap.put(0x5000, d["C"][32:] + d["C"][:32])          # chacha20Poly1305Cipher{lengthKey, contentKey}
    heap.put(0x5200, d["D"][32:] + d["D"][:32])
    analysis = E.analyze(heap.memory(), "client")
    rows = _rows(analysis, tier="A")
    assert {(r.letter, r.direction, r.proven) for r in rows} == {("C", "c2s", E.PROVEN),
                                                                 ("D", "s2c", E.PROVEN)}
    assert all(r.key == d[r.letter] and r.cipher == "chacha20-poly1305@openssh.com" for r in rows)
    assert rows[0].implementation == "go-x/crypto/ssh"


@pytest.mark.parametrize("py312", [False, True])
def test_cpython_paramiko_int_and_bytes_are_tier_a_proven(py312):
    heap = Heap(1 << 15)
    k_int = int.from_bytes(low_bit(32), "big")
    h = rand(32)
    d = ssh_kdf.derive_all(ssh_kdf.encode_mpint(k_int), h, h, 64, "sha256")
    bytes_type, long_type = heap.base + 0x10, heap.base + 0x20
    digits = [(k_int >> (30 * i)) & ((1 << 30) - 1) for i in range(9)]
    size_field = (9 << 3) if py312 else 9
    heap.put(0x1000, struct.pack("<QQQ9I", 1, long_type, size_field, *digits))
    for index, (blob, at) in enumerate([(h, 0x2000), (h, 0x2100), (rand(32), 0x2200),
                                        (d["E"][:32], 0x2300), (d["F"][:32], 0x2400)]):
        heap.put(at, struct.pack("<QQQQ", 2, bytes_type, len(blob), 0xFFFFFFFFFFFFFFFF) + blob + b"\0")
    analysis = E.analyze(heap.memory(), "python3")
    rows = _rows(analysis, tier="A", proven=E.PROVEN)
    assert {r.letter for r in rows} == {"E", "F"}
    assert {r.kind for r in rows} == {"mac"} and rows[0].implementation == "python/paramiko"


def _libssh_heap(k_raw, h, derived, own_keys=True):
    heap = Heap(1 << 15)
    limbs = int.from_bytes(k_raw, "big").to_bytes(32, "little")
    d_va = heap.put(0x800, limbs)
    bn_va = heap.put(0x900, struct.pack("<QiiiI", d_va, 4, 4, 0, 1))
    sid_va, h_va = heap.put(0xA00, h), heap.put(0xA40, h)
    # libssh keeps hash-sized (32-byte) buffers: aes256 keys, 16-byte IVs with 16 more
    # derived bytes after them, 32-byte hmac-sha2-256 keys
    keys = [derived[c][:32] if own_keys else rand(64) for c in ("A", "B", "D", "C", "E", "F")]
    key_vas = [heap.put(0xB00 + 0x80 * i, k) for i, k in enumerate(keys)]
    heap.put(0x1000, struct.pack("<Q", bn_va))                 # shared_secret (struct start)
    heap.put(0x1100, struct.pack("<QQQQ6Q", 32, sid_va, 32, h_va, *key_vas))
    return heap


def test_libssh_crypto_struct_is_tier_a_and_a_wrong_k_is_rejected():
    k_raw, h = low_bit(32), rand(32)
    d = ssh_kdf.derive_all(ssh_kdf.encode_mpint(k_raw), h, h, 64, "sha256")
    analysis = E.analyze(_libssh_heap(k_raw, h, d).memory(), "client")
    proven = _rows(analysis, tier="A", proven=E.PROVEN)
    assert {r.letter: r.key for r in proven} == {
        "A": d["A"][:16], "B": d["B"][:16], "C": d["C"][:32], "D": d["D"][:32],
        "E": d["E"][:32], "F": d["F"][:32]}
    assert {r.cipher for r in proven} == {"aes256-ctr|cbc", "hmac-sha2-256"}
    assert proven[0].implementation == "libssh"
    # the struct's own key buffers belong to a different session: trusted -> rejected
    bad = E.analyze(_libssh_heap(k_raw, h, d, own_keys=False).memory(), "client")
    assert not _rows(bad, proven=E.PROVEN)
    assert [r.proven for r in _rows(bad, tier="A")] == [E.REJECTED]


def test_resident_aes_schedule_fixes_the_key_length():
    """A 32-byte buffer holding an aes128 key: the schedule in memory says 16 bytes."""
    k_raw, h = low_bit(32), rand(32)
    d = ssh_kdf.derive_all(ssh_kdf.encode_mpint(k_raw), h, h, 64, "sha256")
    heap = _libssh_heap(k_raw, h, d)
    heap.put(0x6000, aes.expand_key(d["C"][:16]))
    rows = {r.letter: r for r in _rows(E.analyze(heap.memory(), "client"), proven=E.PROVEN)}
    assert rows["C"].key == d["C"][:16] and rows["C"].cipher == "aes128-ctr|cbc"
    assert rows["D"].key == d["D"][:16] and rows["A"].key == d["A"][:16]


def _libssh_methods(heap, at, names):
    """A libssh ``char *kex_methods[10]`` at ``at`` (strings put after 0x7000)."""
    pointers = [heap.put(0x7000 + 0x80 * i, name.encode() + b"\0") for i, name in enumerate(names)]
    return heap.put(at, struct.pack("<10Q", *pointers))


ELECTED = ["curve25519-sha256@libssh.org", "rsa-sha2-256", "aes256-ctr", "aes256-ctr",
           "hmac-sha2-256", "hmac-sha2-256", "none", "none", "", ""]


def test_libssh_inferred_lengths_are_labelled_inferred():
    k_raw, h = low_bit(32), rand(32)
    d = ssh_kdf.derive_all(ssh_kdf.encode_mpint(k_raw), h, h, 64, "sha256")
    proven = _rows(E.analyze(_libssh_heap(k_raw, h, d).memory(), "client"), proven=E.PROVEN)
    assert proven and all(r.detail.endswith("; lengths: inferred") for r in proven)


def test_libssh_negotiated_kex_methods_name_the_cipher():
    """The elected ``kex_methods`` (after the comma-list offers) give the exact cipher."""
    k_raw, h = low_bit(32), rand(32)
    d = ssh_kdf.derive_all(ssh_kdf.encode_mpint(k_raw), h, h, 64, "sha256")
    heap = _libssh_heap(k_raw, h, d)
    offer = ["curve25519-sha256,ecdh-sha2-nistp256"] + ELECTED[1:2] + ["aes256-ctr,aes128-ctr"] * 2
    _libssh_methods(heap, 0x1100 + 0x148, offer + ELECTED[4:])
    _libssh_methods(heap, 0x1100 + 0x198, ELECTED)
    proven = _rows(E.analyze(heap.memory(), "client"), tier="A", proven=E.PROVEN)
    assert {r.letter: (r.cipher, r.key) for r in proven} == {
        "A": ("aes256-ctr", d["A"][:16]), "B": ("aes256-ctr", d["B"][:16]),
        "C": ("aes256-ctr", d["C"][:32]), "D": ("aes256-ctr", d["D"][:32]),
        "E": ("hmac-sha2-256", d["E"][:32]), "F": ("hmac-sha2-256", d["F"][:32])}
    assert all(r.detail.endswith("; lengths: negotiated(libssh)") for r in proven)


def test_negotiated_cipher_wins_over_the_matched_buffer_length():
    """aes128-ctr negotiated, 32-byte buffers, no schedule resident: keys are 16 bytes."""
    k_raw, h = low_bit(32), rand(32)
    d = ssh_kdf.derive_all(ssh_kdf.encode_mpint(k_raw), h, h, 64, "sha256")
    heap = _libssh_heap(k_raw, h, d)
    _libssh_methods(heap, 0x1100 + 0x198, ELECTED[:2] + ["aes128-ctr", "aes192-ctr"] + ELECTED[4:])
    rows = {r.letter: r for r in _rows(E.analyze(heap.memory(), "client"), proven=E.PROVEN)}
    assert rows["C"].key == d["C"][:16] and rows["C"].cipher == "aes128-ctr"
    assert rows["D"].key == d["D"][:24] and rows["D"].cipher == "aes192-ctr"
    assert rows["A"].key == d["A"][:16] and rows["E"].key == d["E"][:32]


def test_libssh_negotiated_needs_one_consistent_elected_array():
    heap = Heap(1 << 15)
    at = _libssh_methods(heap, 0x100, ELECTED)
    found = E.find_libssh_negotiated(heap.memory(), at - 0x40, window=0x100)
    assert found.source == "libssh" and found.by_direction == {
        "c2s": ("aes256-ctr", "hmac-sha2-256"), "s2c": ("aes256-ctr", "hmac-sha2-256")}
    other = ELECTED[:2] + ["aes128-ctr", "aes128-ctr"] + ELECTED[4:]
    heap.put(0x1A0, struct.pack("<10Q", *[heap.base + 0x2000] * 10))   # not strings: ignored
    pointers = [heap.put(0x3000 + 0x40 * i, n.encode() + b"\0") for i, n in enumerate(other)]
    heap.put(0x150, struct.pack("<10Q", *pointers))   # right after it
    assert E.find_libssh_negotiated(heap.memory(), at - 0x40, window=0x100) is None  # disagree
    assert not E._is_negotiated_methods(["kex", "hk", "aes256-ctr", "rot13", "x", "y"] + [""] * 4)
    assert E._is_negotiated_methods(["kex", "hk"] + ["aes256-gcm@openssh.com"] * 2 +
                                    ["<implicit>"] * 2 + [""] * 4)


@pytest.mark.parametrize("kind, cipher, mac, expected", [
    ("key", "aes192-ctr", "hmac-sha1", ("aes192-ctr", 24)),
    ("iv", "aes256-gcm@openssh.com", None, ("aes256-gcm@openssh.com", 12)),
    ("iv", "chacha20-poly1305@openssh.com", None, None),          # no IV: inference decides
    ("mac", "aes256-gcm@openssh.com", "hmac-sha2-256", None),     # AEAD: no MAC key
    ("mac", "aes128-ctr", "hmac-sha2-512-etm@openssh.com", ("hmac-sha2-512-etm@openssh.com", 64)),
    ("key", "twofish-cbc", "hmac-sha1", None),
])
def test_negotiated_length_per_kind(kind, cipher, mac, expected):
    assert E._negotiated_length(kind, cipher, mac) == expected


def test_wolfssh_inline_arrays_are_tier_a():
    """Layout observed in a wolfSSH 1.4.20 client: h[64] hSz k[1028] kSz sessionId[64] ..."""
    heap = Heap(1 << 15)
    k_raw, h = high_bit(32), rand(32)
    d = ssh_kdf.derive_all(ssh_kdf.encode_mpint(k_raw), h, h, 64, "sha256")
    layout = (h + rand(32) + struct.pack("<I", 32) + k_raw + rand(1028 - 32) + struct.pack("<I", 32)
              + h + rand(32) + struct.pack("<I", 32) + d["A"][:16] + b"\x10" + d["C"][:32] + b"\x20"
              + d["E"][:32])
    heap.put(0x1000, layout)
    rows = _rows(E.analyze(heap.memory(), "client"), tier="A", proven=E.PROVEN)
    assert {r.letter: r.key for r in rows} == {"A": d["A"][:16], "C": d["C"][:32],
                                               "E": d["E"][:32]}
    assert rows[0].implementation == "wolfssh"


def _sshenc(heap, at, name_va, key_va, iv_va, key_len=64, iv_len=0, block=8):
    return heap.put(at, struct.pack("<QQiIIIQQ", name_va, 0x5D00_0000_0000, 1, key_len, iv_len,
                                    block, key_va, iv_va) + b"\0" * 32)


def _openssh_heap(k_resident=False):
    heap = Heap(1 << 15)
    k_enc = ssh_kdf.encode_string(rand(64))                   # sntrup761x25519-sha512
    h = rand(64)
    d = ssh_kdf.derive_all(k_enc, h, h, 64, "sha512")
    name = heap.put(0x100, b"chacha20-poly1305@openssh.com\0")
    key_in, key_out = heap.put(0x200, d["D"]), heap.put(0x300, d["C"])   # client: in = s2c
    enc_in = _sshenc(heap, 0x1000, name, key_in, heap.base + 0x400)
    enc_out = _sshenc(heap, 0x1100, name, key_out, heap.base + 0x400)
    heap.put(0x2000, struct.pack("<QQ", enc_in, enc_out))     # session_state.newkeys[MODE_MAX]
    sid_va = heap.put(0x2100, h)
    heap.put(0x2200, struct.pack("<QQQQQQiIQ", sid_va, sid_va, 0, 64, E.SSHBUF_SIZE_MAX, 256, 0,
                                 1, 0))
    if k_resident:
        heap.put(0x3000, k_enc)
    return heap, d


def test_openssh_structural_only_match_is_unverified_tier_b():
    heap, d = _openssh_heap(k_resident=False)
    analysis = E.analyze(heap.memory(), "ssh")
    rows = _rows(analysis, tier="B")
    assert {(r.direction, r.proven) for r in rows} == {("c2s", E.UNVERIFIED), ("s2c", E.UNVERIFIED)}
    assert {r.direction: r.key for r in rows} == {"c2s": d["C"], "s2c": d["D"]}
    assert not _rows(analysis, proven=E.PROVEN)
    server = E.analyze(heap.memory(), "sshd")              # same struct, server role flips it
    assert {r.direction for r in _rows(server, tier="B")} == {"c2s", "s2c"}


def test_openssh_with_resident_k_becomes_tier_a():
    heap, d = _openssh_heap(k_resident=True)
    analysis = E.analyze(heap.memory(), "ssh")
    assert not _rows(analysis, tier="B")
    proven = _rows(analysis, tier="A", proven=E.PROVEN)
    assert {r.letter for r in proven} == {"C", "D"}
    assert proven[0].locator == "generic:encoded-K+session_id"
    # both sshenc key buffers are the proven keys: their names are the negotiated cipher
    assert {r.cipher for r in proven} == {"chacha20-poly1305@openssh.com"}
    assert all(r.detail.endswith("; lengths: negotiated(openssh)") for r in proven)


def test_openssh_sshenc_bound_for_one_direction_only():
    heap, d = _openssh_heap(k_resident=True)
    heap.put(0x200, rand(64))                                  # in (s2c) sshenc: other bytes
    heap.put(0x500, d["D"])                                    # D still resident elsewhere
    proven = _rows(E.analyze(heap.memory(), "ssh"), tier="A", proven=E.PROVEN)
    assert {r.letter for r in proven} == {"C", "D"}
    assert all(r.detail.endswith("; lengths: negotiated(openssh) for C, inferred for D")
               for r in proven)
    assert {r.letter: r.key for r in proven} == {"C": d["C"], "D": d["D"]}


def _chacha_state(key, rounds=20, ivlen=8):
    words = E.CHACHA_CONSTANTS + key + b"\0" * 16
    return words + b"\0" * 64 + struct.pack("<QQi4x", 0, ivlen, rounds)


def test_dropbear_chacha_pairs_are_tier_c_with_key_context_order():
    heap = Heap(1 << 15)
    recv, trans = rand(64), rand(64)
    for at, key in ((0x1000, recv), (0x2208, trans)):
        heap.put(at, _chacha_state(key[:32]) + _chacha_state(key[32:]))
    rows = _rows(E.analyze(heap.memory(), "dropbear"), tier="C")
    assert {(r.direction, r.key, r.proven) for r in rows} == {("c2s", recv, E.UNVERIFIED),
                                                             ("s2c", trans, E.UNVERIFIED)}
    client = _rows(E.analyze(heap.memory(), "dbclient"), tier="C")
    assert {r.direction: r.key for r in client} == {"s2c": recv, "c2s": trans}
    heap.put(0x1000 + 144, struct.pack("<i", 12))              # rounds != 20: not a state
    assert len(_rows(E.analyze(heap.memory(), "dropbear"), tier="C")) == 1


@pytest.mark.parametrize("key_len", [16, 24, 32])
@pytest.mark.parametrize("byteorder", ["little", "big"])
def test_aes_schedules_re_expand_in_either_word_order(key_len, byteorder):
    heap = Heap(1 << 14)
    key = rand(key_len)
    schedule = aes.expand_key(key)
    heap.put(0x804, schedule if byteorder == "little" else ssh_kdf.swap_words(schedule))
    found = E.find_aes_schedules(heap.memory())
    assert (heap.base + 0x804, key, byteorder) in found
    assert len(found) == 1


def test_one_matching_key_is_not_a_proof():
    heap = Heap()
    k_enc, h = ssh_kdf.encode_mpint(low_bit(32)), rand(32)
    d = ssh_kdf.derive_all(k_enc, h, h, 64, "sha256")
    h_va, k_va = heap.put(0x1000, h), heap.put(0x2000, k_enc)
    heap.put(0x4000, struct.pack("<16Q", h_va, 32, 32, k_va, len(k_enc), 48, heap.base, 1, 1,
                                 heap.base, 1, 1, 5, h_va, 32, 32))
    heap.put(0x5000, d["C"][:32])
    analysis = E.analyze(heap.memory(), "client")
    assert not _rows(analysis, proven=E.PROVEN)
    assert analysis.evidence and analysis.evidence[0].letters == "C"


def test_nothing_in_random_memory():
    analysis = E.analyze(Heap(1 << 17).memory(), "ssh")
    assert analysis.rows == []


def test_newkeys_keylog_lines_and_json_rows():
    heap, d = _openssh_heap(k_resident=True)
    rows = E.analyze(heap.memory(), "ssh").rows
    lines = E.openssh_newkeys_lines(rows, 1700000000)
    assert sorted(lines) == sorted(
        "1700000000 NEWKEYS MODE %s CIPHER chacha20-poly1305@openssh.com KEY %s IV unknown"
        % (mode, d[letter].hex()) for mode, letter in (("OUT", "C"), ("IN", "D")))
    blob = json.dumps([r.as_dict() for r in rows])
    assert "oracle:ssh-kdf-consistency" in blob


def test_memory_reads_never_cross_unmapped_gaps():
    memory = E.Memory([(0x1000, b"a" * 16), (0x1010, b"b" * 16), (0x3000, b"c" * 8)])
    assert len(memory.segments) == 2
    assert memory.read(0x100C, 8) == b"aaaabbbb"
    assert memory.read(0x2FFC, 8) is None and memory.read(0x3000, 9) is None


def test_memory_joins_a_contiguous_run_of_many_pieces_once():
    pieces = [rand(97) for _ in range(40)]
    segments, va = [], 0x10000
    for piece in pieces:
        segments.append((va, piece))
        va += len(piece)
    shuffled = segments[1::2] + segments[::2] + [(0x900000, b"tail")]
    memory = E.Memory(shuffled)
    assert memory.segments == [(0x10000, b"".join(pieces)), (0x900000, b"tail")]
    assert memory.dword(0x10000) == struct.unpack("<I", pieces[0][:4])[0]
    assert memory.dword(0x900002) is None


def test_derive_all_shares_the_k_h_prefix_and_equals_derive_key():
    k_enc, h, sid = ssh_kdf.encode_mpint(high_bit(32)), rand(32), rand(32)
    for hash_name, length in (("sha1", 100), ("sha256", 64), ("sha512", 130), ("sha256", 0)):
        assert ssh_kdf.derive_all(k_enc, h, sid, length, hash_name) == {
            letter: ssh_kdf.derive_key(k_enc, h, letter, sid, length, hash_name)
            for letter in ssh_kdf.LETTERS}
    with pytest.raises(ValueError):
        ssh_kdf.derive_all(k_enc, h, sid, -1)


def test_needles_swap_like_swap_words():
    material = rand(64)
    for probe, offset, swapped in E._needles(material):
        chunk = material[offset:offset + 8]
        assert probe == struct.unpack("<Q", ssh_kdf.swap_words(chunk) if swapped else chunk)[0]


@pytest.mark.parametrize("threshold", [0, 10 ** 9])
def test_near_struct_positional_scan_finds_what_find_does(monkeypatch, threshold):
    """Both window searches (one ``find`` per needle, or one positional pass) are exact."""
    monkeypatch.setattr(E, "WINDOW_SCAN_NEEDLES", threshold)
    test_wolfssh_inline_arrays_are_tier_a()
    test_cpython_paramiko_int_and_bytes_are_tier_a_proven(True)
    window = rand(300) + b"needle-12345" + rand(40) + b"needle-12345" + b"other-needle"
    hits = sorted(E._window_hits(window, {b"needle-12345": [], b"other-needle": [],
                                          b"absent-12345": []}))
    assert hits == [(b"needle-12345", 300), (b"needle-12345", 352), (b"other-needle", 364)]


def test_aes_schedule_windows_are_exact_across_window_edges(monkeypatch):
    """Schedules straddling a window edge (and every nk) are found as in one whole pass."""
    heap = Heap(1 << 15)
    planted = []
    for at, key_len, byteorder in ((0x0FF0, 16, "little"), (0x1F40, 24, "big"),
                                   (0x2FC0, 32, "little"), (0x3FFC, 32, "big"),
                                   (0x5000 - 4, 16, "big")):
        key = rand(key_len)
        schedule = aes.expand_key(key)
        heap.put(at, schedule if byteorder == "little" else ssh_kdf.swap_words(schedule))
        planted.append((heap.base + at, key, byteorder))
    monkeypatch.setattr(E, "AES_WINDOW", 1 << 30)
    whole = E.find_aes_schedules(heap.memory())
    monkeypatch.setattr(E, "AES_WINDOW", 0x1000)
    assert E.find_aes_schedules(heap.memory()) == whole
    assert sorted(whole) == sorted(planted)


# --------------------------------------------------------------------------- real captures (gated)


def _gt_sessions():
    if not SSH_CORPUS.is_dir():
        return []
    return sorted(p.parent for p in SSH_CORPUS.glob("*/gt.json"))


def memory_from_msl(path, writable_only=True):
    """``Memory`` of a ``.msl`` via the stdlib slim reader (plaintext, uncompressed)."""
    from memdiver.vol3plugins import msl_slim

    opened = path
    if str(path).endswith(".gz"):
        raise ValueError("unpack first")
    reader = msl_slim.MslSlimReader(str(opened)).open()
    try:
        regions = reader.collect_regions()
        writable = [(r.base_addr, r.base_addr + r.region_size) for r in regions
                    if r.protection & 0x2]
        segments = []
        for run in reader.captured_run_index().by_va:
            if writable_only and not any(a <= run.va_start < b for a, b in writable):
                continue
            span = reader.run_span(run)
            if span:
                segments.append((run.va_start, reader.read_bytes(run.buf_offset, span)))
        return E.Memory(segments)
    finally:
        reader.close()


@pytest.mark.parametrize("session", _gt_sessions() or [None],
                         ids=lambda p: p.name if p else "no-corpus")
def test_real_msl_captures_prove_ground_truth_keys(session, tmp_path):
    if session is None:
        pytest.skip("MEMDIVER_SSH_CORPUS not set or holds no <session>/gt.json")
    truth = json.loads((session / "gt.json").read_text())
    for proc in truth if isinstance(truth, list) else [truth]:
        msl = session / proc["msl"]
        if not msl.is_file():
            continue
        if msl.suffix == ".gz":
            target = tmp_path / msl.stem
            with gzip.open(msl, "rb") as packed, open(target, "wb") as out:
                out.write(packed.read())
            msl = target
        analysis = E.analyze(memory_from_msl(msl), proc.get("process_name", ""))
        proven = _rows(analysis, tier="A", proven=E.PROVEN)
        if proc["implementation"] == "paramiko":   # _parse_newkeys sets self.K = None
            assert proven == []
            continue
        assert len({r.letter for r in proven}) >= 2, (proc["implementation"], analysis.stats)
        for row in proven:   # exact: same bytes AND the length the implementation used
            assert row.key == bytes.fromhex(proc["keys"][row.letter]), row.letter
