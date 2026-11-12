"""M4 process side: ``memdiver.wireguard_go`` -- wireguard-go keys proven from memory alone.

Synthetic memory built from the Go struct definitions (``device/device.go``,
``noise-protocol.go``, ``keypair.go``; offsets written out independently of the engine's
``GoLayout``) checks every verdict: proven, rejected, the PSK rule (bound / unverified),
transport keys never proven, and the Noise chaining-key proof of ephemerals. The two format
oracles and the X25519 helpers are tested here too, plus the plugin's exports under ``vol``
on a synthetic ``.msl`` (skipped without a ``vol`` beside this interpreter).

Corpus-gated: ``MEMDIVER_WG_GO_CORPUS`` (the rig's ``archive`` directory, see
``tests/_wg_go_corpus.py``): EVERY dump of every wireguard-go run must prove the static key and
the peer key, equal to the in-process keylog; transport keys equal the keylog and are never
proven. Real-data claims under stock ``vol`` live in ``test_vol3plugins_corpus_gate.py``
(C-WGGO1).
"""
import base64
import hashlib
import hmac
import json
import random
import shutil
import struct
import subprocess
import sys
from pathlib import Path

import pytest

from memdiver.oracles import get_format, list_formats, missing_contract, verdict_from
from memdiver.vol3plugins.linux.secrets import x25519
from memdiver.vol3plugins.memdiver import wireguard_go_engine as E
from tests import _wg_go_corpus as corpus

REPO = Path(__file__).resolve().parents[1]
RNG = random.Random(0x3C25519)
ARENA = 0xC000000000
DEVICE = ARENA + 0x1000
PEER = ARENA + 0x2000
KEYPAIR = ARENA + 0x4000
SEND_KEY_VA = ARENA + 0x6000
RECV_KEY_VA = ARENA + 0x6040
CK0 = hashlib.blake2s(b"Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s").digest()


def rand(n):
    return bytes(RNG.getrandbits(8) for _ in range(n))


def private():
    return x25519.clamp(rand(32))


def kdf1(ck, data):
    """HKDF-BLAKE2s, first output (independent of the engine's helper)."""
    prk = hmac.new(ck, data, hashlib.blake2s).digest()
    return hmac.new(prk, b"\x01", hashlib.blake2s).digest()


class Process(object):
    """A wireguard-go heap: Device, one Peer with its Handshake, one Keypair."""

    def __init__(self, psk=None, state=0, device_pointer=True):
        self.mem = bytearray(0x10000)
        self.static = private()
        self.public = x25519.public_key(self.static)
        self.peer_static = private()
        self.peer_public = x25519.public_key(self.peer_static)
        self.ss = x25519.scalarmult(self.static, self.peer_public)
        self.psk = psk
        self.send, self.recv = rand(32), rand(32)
        self.put(DEVICE + 96, struct.pack("<H", 51820))          # Device.net.port
        self.put(DEVICE + 136, self.static + self.public)        # staticIdentity
        self.put(PEER, struct.pack("<I", 1))                      # isRunning
        self.put(PEER + 32, struct.pack("<Q", KEYPAIR))          # keypairs.current
        hs = PEER + 56
        self.put(hs, struct.pack("<Q", state))
        if psk:
            self.put(hs + 96, psk)
        self.put(hs + 160, struct.pack("<II", 0x11223344, 0x55667788))
        self.put(hs + 168, self.peer_public)
        self.put(hs + 232, self.ss)
        if device_pointer:
            self.put(hs + 328, struct.pack("<Q", DEVICE))        # Peer.device
        self.put(PEER + 576, hashlib.blake2s(b"mac1----" + self.peer_public).digest())  # cookieGenerator.mac1.key
        self.put(KEYPAIR + 8, struct.pack("<QQQQ", ARENA + 0x8000, SEND_KEY_VA,
                                          ARENA + 0x8000, RECV_KEY_VA))
        self.put(KEYPAIR + 1072, b"\x01")
        self.put(KEYPAIR + 1104, struct.pack("<II", 0xAABBCCDD, 0x01020304))
        self.put(SEND_KEY_VA, self.send)
        self.put(RECV_KEY_VA, self.recv)

    @property
    def remote_static_va(self):
        return PEER + 56 + 168

    def put(self, va, data):
        self.mem[va - ARENA:va - ARENA + len(data)] = data

    def handshake_put(self, offset, data):
        self.put(PEER + 56 + offset, data)

    def memory(self, extra=()):
        return E.Memory([(ARENA, bytes(self.mem))] + list(extra))

    def initiation_created(self):
        """State 1 with the chaining key ``CreateMessageInitiation`` leaves behind."""
        e = private()
        ck = CK0
        for data in (x25519.public_key(e), x25519.scalarmult(e, self.peer_public), self.ss):
            ck = kdf1(ck, data)
        self.handshake_put(0, struct.pack("<Q", 1))
        self.handshake_put(64, ck)
        self.handshake_put(128, e)
        return e

    def response_created(self):
        """State 3 (responder) with the chaining key of ``CreateMessageResponse``."""
        e, initiator_e = private(), private()
        e_i = x25519.public_key(initiator_e)
        ck = CK0
        for data in (e_i, x25519.scalarmult(self.static, e_i), self.ss, x25519.public_key(e),
                     x25519.scalarmult(e, e_i), x25519.scalarmult(e, self.peer_public),
                     self.psk or bytes(32)):
            ck = kdf1(ck, data)
        self.handshake_put(0, struct.pack("<Q", 3))
        self.handshake_put(64, ck)
        self.handshake_put(128, e)
        self.handshake_put(200, e_i)
        return e


def rows(analysis, kind=None, proven=None):
    return [r for r in analysis.rows
            if (kind is None or r.kind == kind) and (proven is None or r.proven == proven)]


# --------------------------------------------------------------------------- x25519 helpers


def test_x25519_helpers_prove_and_refuse_to_decide():
    a, b = private(), private()
    pub_b = x25519.public_key(b)
    assert x25519.proves_public(a, x25519.public_key(a))
    assert not x25519.proves_public(a, pub_b) and not x25519.proves_public(bytes(32), pub_b)
    shared = x25519.scalarmult(a, pub_b)
    assert x25519.dh_consistency(a, pub_b, shared) is True
    assert x25519.dh_consistency(a, pub_b, rand(32)) is False
    assert x25519.dh_consistency(a, bytes(32), bytes(32)) is None          # small order
    assert x25519.dh_consistency(a, pub_b, bytes(32)) is None              # zeroed shared
    non_canonical = (2 ** 255 - 19 + 1).to_bytes(32, "little")             # aliases u = 1
    assert x25519.dh_consistency(a, non_canonical, shared) is None
    assert x25519.is_canonical_u(pub_b) and not x25519.is_canonical_u(b"\xff" * 32)


# --------------------------------------------------------------------------- format oracles


@pytest.mark.parametrize("kind", ["x25519-pubkey", "x25519-dh-consistency"])
def test_oracles_are_registered_and_follow_the_contract(kind):
    assert kind in list_formats()
    module = get_format(kind)
    assert missing_contract(module) == [] and module.REQUIRES_PRIMITIVES == ("x25519",)
    assert module.CANDIDATE_LENGTHS == (32,)


def test_pubkey_oracle_proves_rejects_and_errors():
    module = get_format("x25519-pubkey")
    key = private()
    oracle = module.build_oracle({}, module.make_sample(x25519.public_key(key)))
    assert verdict_from(oracle.verify(key)).status == "proven"
    assert oracle.verify(private())["status"] == "rejected"
    assert oracle.verify(bytes(32))["status"] == "error"
    assert oracle.verify("text")["status"] == "error"
    in_memory = module.build_oracle({}, b"")
    assert in_memory.verify(key)["status"] == "error"                     # nothing to compare
    assert in_memory.verify(key, {"public": x25519.public_key(key)})["status"] == "proven"
    with pytest.raises(ValueError):
        module.build_oracle({}, b"garbage")


def test_dh_oracle_proves_rejects_and_never_decides_on_degenerate_points():
    module = get_format("x25519-dh-consistency")
    proc = Process()
    ctx = {"remote_public": proc.peer_public, "shared": proc.ss}
    oracle = module.build_oracle({}, b"")
    assert oracle.verify(proc.static, ctx)["status"] == "proven"
    assert oracle.verify(private(), ctx)["status"] == "rejected"
    zeroed = {"remote_public": bytes(32), "shared": bytes(32)}
    assert oracle.verify(proc.static, zeroed)["status"] == "error"
    pinned = module.build_oracle(None, module.make_sample(proc.peer_public, proc.ss))
    assert pinned.verify(proc.static)["status"] == "proven"
    assert module.parse_sample(module.make_sample()) == (None, None)


# --------------------------------------------------------------------------- engine


def test_static_key_and_peer_are_proven_on_trusted_structure():
    proc = Process()
    analysis = E.analyze(proc.memory())
    (identity,) = rows(analysis, "static-private")
    assert identity.proven == E.PROVEN_ID and identity.key == proc.static
    assert identity.addresses == [DEVICE + 136]
    (peer,) = rows(analysis, "peer-public")
    assert peer.proven == E.PROVEN_DH and peer.key == proc.peer_public
    assert peer.locator == "device_backpointer" and peer.addresses == [proc.remote_static_va]
    assert (peer.local_index, peer.remote_index) == (0x11223344, 0x55667788)
    assert list(analysis.identities.values())[0].listen_port == 51820
    assert not rows(analysis, proven=E.REJECTED)


def test_identity_copies_are_one_row():
    proc = Process()
    copy = (ARENA + 0x9000, proc.static + proc.public)
    analysis = E.analyze(proc.memory())
    assert len(rows(analysis, "static-private")) == 1
    with_copy = E.Memory([(ARENA, bytes(proc.mem[:0x9000])), copy,
                          (ARENA + 0x9040, bytes(proc.mem[0x9040:]))])
    (identity,) = rows(E.analyze(with_copy), "static-private")
    assert identity.addresses == [DEVICE + 136, ARENA + 0x9000]


def test_transport_keys_are_reported_but_never_proven():
    proc = Process(psk=rand(32))
    proc.initiation_created()
    analysis = E.analyze(proc.memory())
    transport = rows(analysis, "send") + rows(analysis, "receive")
    assert {(r.kind, r.key) for r in transport} == {("send", proc.send), ("receive", proc.recv)}
    assert all(r.proven == E.UNVERIFIED and E.TRANSPORT_NOTE in r.detail for r in transport)
    assert {r.addresses[0] for r in transport} == {SEND_KEY_VA, RECV_KEY_VA}
    assert all(r.slot == "current" and r.local_index == 0xAABBCCDD for r in transport)


def test_psk_is_bound_only_to_a_proven_peer_of_a_trusted_handshake():
    psk = rand(32)
    analysis = E.analyze(Process(psk=psk).memory())
    (row,) = rows(analysis, "preshared")
    assert row.proven == E.BOUND_PSK and row.key == psk


def test_psk_of_an_untrusted_handshake_is_unverified():
    """No Peer.device back-pointer: the adjacency fallback proves the peer, not the PSK."""
    proc = Process(psk=rand(32), device_pointer=False)
    analysis = E.analyze(proc.memory())
    (peer,) = rows(analysis, "peer-public")
    assert peer.proven == E.PROVEN_DH and peer.locator == "adjacency"
    (row,) = rows(analysis, "preshared")
    assert row.proven == E.UNVERIFIED and "untrusted" in row.detail
    assert not rows(analysis, "send") and not rows(analysis, "ephemeral-private")
    assert not rows(E.analyze(proc.memory(), adjacency_fallback=False), "peer-public")


def test_tampered_precomputed_is_rejected_and_its_psk_unverified():
    proc = Process(psk=rand(32))
    proc.handshake_put(232, rand(32))
    analysis = E.analyze(proc.memory())
    (peer,) = rows(analysis, "peer-public")
    assert peer.proven == E.REJECTED and peer.locator == "device_backpointer"
    (psk,) = rows(analysis, "preshared")
    assert psk.proven == E.UNVERIFIED and not rows(analysis, "send")
    assert rows(analysis, "static-private")[0].proven == E.PROVEN_ID


def test_device_with_a_forged_public_key_is_rejected():
    """The Device copy is tampered; an intact copy elsewhere still proves the key."""
    proc = Process()
    proc.put(ARENA + 0x9000, proc.static + proc.public)     # intact stack/heap copy
    proc.put(DEVICE + 168, rand(32))
    analysis = E.analyze(proc.memory())
    assert rows(analysis, "static-private", E.PROVEN_ID)[0].addresses == [ARENA + 0x9000]
    (rejected,) = rows(analysis, "static-private", E.REJECTED)
    assert rejected.addresses == [DEVICE + 136]
    (peer,) = rows(analysis, "peer-public")
    assert peer.proven == E.PROVEN_DH and peer.locator == "adjacency"


def test_initiation_created_proves_the_local_ephemeral():
    proc = Process()
    ephemeral = proc.initiation_created()
    (row,) = rows(E.analyze(proc.memory()), "ephemeral-private")
    assert row.proven == E.PROVEN_CK and row.key == ephemeral


def test_response_created_proves_ephemeral_and_psk():
    proc = Process(psk=rand(32))
    ephemeral = proc.response_created()
    analysis = E.analyze(proc.memory())
    assert [(r.proven, r.key) for r in rows(analysis, "ephemeral-private")] == [
        (E.PROVEN_CK, ephemeral)]
    assert [(r.proven, r.key) for r in rows(analysis, "preshared")] == [(E.PROVEN_CK, proc.psk)]


def test_wrong_chaining_key_leaves_the_ephemeral_unverified():
    proc = Process()
    proc.initiation_created()
    proc.handshake_put(64, rand(32))
    (row,) = rows(E.analyze(proc.memory()), "ephemeral-private")
    assert row.proven == E.UNVERIFIED


def test_small_order_peer_and_zeroed_precompute_never_prove():
    proc = Process()
    proc.handshake_put(168, bytes(32))
    proc.handshake_put(232, bytes(32))
    analysis = E.analyze(proc.memory())
    assert not rows(analysis, "peer-public") and not rows(analysis, proven=E.REJECTED)


def test_other_device_back_pointers_never_surface_as_rejections():
    """A ``*Device`` qword in a closure with Peer-shaped random bytes around it is not a Peer:
    state/isRunning/keypair slots fit (zeros) and the keys are high entropy, but no mac1 key."""
    proc = Process()
    proc.put(ARENA + 0xA000, rand(0x200))
    proc.put(ARENA + 0xA000 + 0x100, struct.pack("<Q", DEVICE))
    analysis = E.analyze(proc.memory())
    assert len(rows(analysis, "peer-public")) == 1 and not rows(analysis, proven=E.REJECTED)


def test_nothing_in_random_memory():
    analysis = E.analyze(E.Memory([(ARENA, rand(1 << 16))]))
    assert analysis.rows == [] and analysis.handshakes == []


def _adjacency_reference(memory, identity, budget):
    """The per-identity, every-offset scan the single-pass search must equal."""
    found, tried = [], 0
    for start, data in memory.segments:
        for offset in range((-start) % 8, len(data) - 96 + 1, 8):
            remote, shared = data[offset:offset + 32], data[offset + 64:offset + 96]
            if remote[31] & 0x80 or not E.high_entropy(remote) or not E.high_entropy(shared):
                continue
            tried += 1
            if tried > budget:
                return found
            if x25519.dh_consistency(identity.private, remote, shared):
                found.append(start + offset)
    return found


@pytest.mark.parametrize("budget", [10 ** 6, 3])
def test_adjacency_search_tests_every_identity_in_one_exact_pass(budget):
    """Mostly-zero memory (the block skip), handshakes straddling a block edge, two identities,
    random filler, and the candidate budget: equal to a naive per-identity scan."""
    mem = bytearray(0x6000)
    ids = []
    for at in (0x0FC8, 0x2FF0, 0x4800):          # remote/shared straddle 4 KiB block edges
        priv = private()
        identity = E.Identity(priv, x25519.public_key(priv))
        peer = x25519.public_key(private())
        mem[at:at + 32] = peer
        mem[at + 64:at + 96] = x25519.scalarmult(priv, peer)
        ids.append(identity)
    mem[0x5100:0x5900] = rand(0x800)
    memory = E.Memory([(ARENA + 8, bytes(mem))])  # segment start 8-aligned, block edges shifted
    found = E.find_adjacency_handshakes(memory, ids[:2], budget=budget)
    expected = sorted((va, i) for i, identity in enumerate(ids[:2])
                      for va in _adjacency_reference(memory, identity, budget))
    assert [(h.address, ids.index(h.identity)) for h in found] == expected
    if budget > 3:
        assert len(found) == 2 and all(h.dh and not h.trusted for h in found)


def test_process_names():
    assert E.is_wireguard_process("wireguard-go") and E.is_wireguard_process("tailscaled")
    assert E.is_wireguard_process("com.wireguard.a") and not E.is_wireguard_process("sshd")


# --------------------------------------------------------------------------- plugin under vol


def _vol():
    beside = Path(sys.executable).with_name("vol")
    found = str(beside) if beside.is_file() else shutil.which("vol")
    return found


def _synthetic_msl(proc, tmp_path):
    flat = tmp_path / "wg.bin"
    flat.write_bytes(bytes(proc.mem))
    maps = tmp_path / "wg.maps"
    maps.write_text("%x-%x rw-p 00000000 00:00 0 [heap]\n" % (ARENA, ARENA + len(proc.mem)))
    from memdiver.msl.importer import import_regioned_raw
    out = tmp_path / "wg.msl"
    import_regioned_raw(flat, maps, out, pid=4242)
    return out


def _run_vol(msl, tmp_path, *args):
    vol = _vol()
    if vol is None:
        pytest.skip("no vol executable beside this interpreter or on PATH")
    out = tmp_path / ("out-%d" % len(list(tmp_path.glob("out-*"))))
    cache = tmp_path / "cache"
    out.mkdir()
    cache.mkdir(exist_ok=True)
    proc = subprocess.run([vol, "-q", "-r", "json", "--offline", "--cache-path", str(cache),
                           "-p", str(REPO / "vol3plugins"), "-f", str(msl), "-o", str(out),
                           "memdiver.wireguard_go.WireGuardGo", *args],
                          capture_output=True, text=True, timeout=600, cwd=str(out))
    assert proc.returncode == 0, proc.stderr[-3000:]
    return json.loads(proc.stdout[proc.stdout.index("["):]), out


def _b64(data):
    return base64.b64encode(data).decode()


def test_plugin_rows_and_exports_on_a_synthetic_msl(tmp_path):
    proc = Process(psk=rand(32))
    ephemeral = proc.initiation_created()
    msl = _synthetic_msl(proc, tmp_path)
    table, _ = _run_vol(msl, tmp_path)
    proven = {(r["Kind"], r["Proven"]) for r in table}
    assert ("static-private", "oracle:x25519-pubkey") in proven
    assert ("peer-public", "oracle:x25519-dh-consistency") in proven
    assert ("preshared", "bound:peer-handshake") in proven
    assert ("ephemeral-private", "oracle:noise-chaining-key") in proven
    assert {r["Proven"] for r in table if r["Kind"] in ("send", "receive")} == {"unverified"}
    assert {r["Scope"] for r in table} == {"msl:4242"}

    _, out = _run_vol(msl, tmp_path, "--export", "keylog")
    keylog = (out / "wireguard_go.keylog").read_text().splitlines()
    assert "LOCAL_STATIC_PRIVATE_KEY = " + _b64(proc.static) in keylog
    assert "REMOTE_STATIC_PUBLIC_KEY = " + _b64(proc.peer_public) in keylog
    at = keylog.index("LOCAL_EPHEMERAL_PRIVATE_KEY = " + _b64(ephemeral))
    assert keylog[at + 1] == "PRESHARED_KEY = " + _b64(proc.psk)
    transport = json.loads((out / "wireguard_go.wg-transport.json").read_text())
    assert transport["keypairs"] and all(e["send_key"] is None and e["recv_key"] is None
                                         for e in transport["keypairs"])
    assert _b64(proc.send) not in (out / "wireguard_go.wg-transport.json").read_text()

    _, out = _run_vol(msl, tmp_path, "--export", "showconf")
    conf = (out / "wireguard_go.4242.0.conf").read_text()
    assert "PrivateKey = " + _b64(proc.static) in conf and "ListenPort = 51820" in conf
    assert "PresharedKey = " + _b64(proc.psk) in conf

    _, out = _run_vol(msl, tmp_path, "--export", "json")
    document = json.loads((out / "wireguard_go.json").read_text())
    exported = {r["kind"]: r for r in document[0]["rows"]}
    assert exported["static-private"]["key_hex"] == proc.static.hex()
    assert exported["send"]["key_hex"] is None                 # unverified: no key bytes


def test_unbound_psk_stays_out_of_showconf(tmp_path):
    proc = Process(psk=rand(32), device_pointer=False)
    msl = _synthetic_msl(proc, tmp_path)
    _, out = _run_vol(msl, tmp_path, "--export", "showconf")
    conf = (out / "wireguard_go.4242.0.conf").read_text()
    assert "PublicKey = " + _b64(proc.peer_public) in conf
    assert "PresharedKey" not in conf
    _, out = _run_vol(msl, tmp_path, "--export", "showconf", "--export-unverified")
    assert "PresharedKey = " + _b64(proc.psk) in (out / "wireguard_go.4242.0.conf").read_text()


# --------------------------------------------------------------------------- corpus (gated)


@pytest.mark.parametrize("session", corpus.sessions() or [None],
                         ids=lambda s: "%s-%s" % (s[0].name, s[1]) if s else "no-corpus")
def test_every_corpus_dump_proves_the_ground_truth_keys(session):
    if session is None:
        pytest.skip("%s not set or holds no wireguard-go run" % corpus.CORPUS_ENV)
    run, role = session
    truth = corpus.ground_truth(run, role)
    assert x25519.public_key(truth["static_private"]) == truth["static_public"]
    for dump in corpus.dumps(run, role):
        analysis = E.analyze(E.Memory(corpus.load_segments(dump)))
        where = (run.name, role, corpus.phase(dump))
        assert [r.key for r in rows(analysis, "static-private", E.PROVEN_ID)] == [
            truth["static_private"]], where
        assert [(r.key, r.locator) for r in rows(analysis, "peer-public", E.PROVEN_DH)] == [
            (truth["peer_public"], "device_backpointer")], where
        assert not rows(analysis, proven=E.REJECTED), where
        transport = rows(analysis, "send") + rows(analysis, "receive")
        assert all(r.proven == E.UNVERIFIED and r.key in truth["transport"] for r in transport), where
        for row in rows(analysis, "ephemeral-private", E.PROVEN_CK):
            assert row.key in truth["ephemerals"], where
