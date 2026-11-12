"""``linux.wireguard`` (``vol3plugins/linux/wireguard.py``) and ``secrets/wg_offsets.py``.

Unit tests lay out a synthetic kernel in a vol3 ``BufferDataLayer``: ``net_namespace_list`` ->
``struct net`` -> a ``net_device`` with ``rtnl_link_ops->kind == "wireguard"`` -> its
``wg_device`` (static identity, cookie checker) -> ``wg_peer``s with handshake, keypairs,
endpoint and allowed-ips, using the 6.8 table offsets.  The corpus test runs the plugin through
the AArch64-capable volatility3 fork on the real acquired-secrets capture (private
``--cache-path``) and is skipped cleanly when either is absent.
"""

import base64
import hashlib
import json
import os
import logging
import shutil
import struct
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

pytest.importorskip("volatility3")

from volatility3.framework import contexts  # noqa: E402
from volatility3.framework.layers import physical  # noqa: E402

from memdiver.vol3plugins.linux import wireguard as wg  # noqa: E402
from memdiver.vol3plugins.linux.secrets import wg_offsets, x25519  # noqa: E402

REPO = Path(__file__).resolve().parents[1]
OFF = wg_offsets.WG_OFFSETS[("aarch64", "6.8.0-136-generic")]
KL = wg.WgKernelLayout()

PRIV_A = x25519.clamp(hashlib.sha256(b"A").digest())
PRIV_B = x25519.clamp(hashlib.sha256(b"B").digest())
PUB_A, PUB_B = x25519.public_key(PRIV_A), x25519.public_key(PRIV_B)
PSK = hashlib.sha256(b"psk").digest()
EPH = x25519.clamp(hashlib.sha256(b"eph").digest())
SEND, RECV = hashlib.sha256(b"send").digest(), hashlib.sha256(b"recv").digest()


# --------------------------------------------------------------------------- synthetic memory


class Mem:
    """A little-endian LP64 address space in a bytearray (addresses start at BASE)."""

    BASE = 0x10000

    def __init__(self, size: int = 0x40000) -> None:
        self.buf = bytearray(size)
        self.cursor = 0x100

    def alloc(self, size: int, align: int = 64) -> int:
        self.cursor = (self.cursor + align - 1) & ~(align - 1)
        address = self.BASE + self.cursor
        self.cursor += size
        return address

    def put(self, address: int, data: bytes) -> None:
        self.buf[address - self.BASE:address - self.BASE + len(data)] = data

    def ptr(self, address: int, value: int) -> None:
        self.put(address, struct.pack("<Q", value))

    def u32(self, address: int, value: int) -> None:
        self.put(address, struct.pack("<I", value))

    def u16(self, address: int, value: int) -> None:
        self.put(address, struct.pack("<H", value))

    def u8(self, address: int, value: int) -> None:
        self.put(address, bytes([value]))

    def ring(self, head: int, entries) -> None:
        """A ``list_head`` ring through ``head`` and the given list_head addresses."""
        nodes = [head] + list(entries)
        for here, there in zip(nodes, nodes[1:] + nodes[:1]):
            self.ptr(here, there)
            self.ptr(there + 8, here)

    def reader(self) -> wg.SafeReader:
        context = contexts.Context()
        layer = physical.BufferDataLayer(context, "cfg", "mem", bytes(self.BASE) + bytes(self.buf))
        context.add_layer(layer)
        return wg.SafeReader(layer, 8, "little")


def put_identity(mem: Mem, wg_dev: int, priv: bytes, pub: bytes) -> None:
    identity = wg_dev + OFF["wg_device.static_identity"]
    mem.put(identity + OFF["noise_static_identity.static_public"], pub)
    mem.put(identity + OFF["noise_static_identity.static_private"], priv)
    mem.u8(identity + OFF["noise_static_identity.has_identity"], 1)
    checker = wg_dev + OFF["wg_device.cookie_checker"]
    mem.put(checker + OFF["cookie_checker.message_mac1_key"], wg.precompute_key(wg.LABEL_MAC1, pub))
    mem.put(checker + OFF["cookie_checker.cookie_encryption_key"], wg.precompute_key(wg.LABEL_COOKIE, pub))
    mem.ptr(checker + OFF["cookie_checker.device"], wg_dev)


def make_device(mem: Mem, priv: bytes = PRIV_A, pub: bytes = None, name: str = "wg0"):
    """net_namespace_list -> net -> net_device(kind wireguard) -> wg_device; returns addresses."""
    net_list, net = mem.alloc(16), mem.alloc(4672)
    dev = mem.alloc(KL.sizes["net_device"] + OFF["sizeof(wg_device)"], 32)
    wg_dev = dev + KL.sizes["net_device"]
    ops, kind = mem.alloc(208), mem.alloc(16)
    mem.put(kind, b"wireguard\0")
    mem.ptr(ops + KL["rtnl_link_ops.kind"], kind)
    mem.ptr(dev + KL["net_device.rtnl_link_ops"], ops)
    mem.put(dev + KL["net_device.name"], name.encode() + b"\0")
    mem.u32(net + KL["net.ns"] + KL["ns_common.inum"], 4026532233)
    mem.ring(net_list, [net + KL["net.list"]])
    mem.ring(net + KL["net.dev_base_head"], [dev + KL["net_device.dev_list"]])
    mem.ptr(wg_dev + OFF["wg_device.dev"], dev)
    mem.u16(wg_dev + OFF["wg_device.incoming_port"], 51820)
    put_identity(mem, wg_dev, priv, x25519.public_key(priv) if pub is None else pub)
    return SimpleNamespace(net_list=net_list, net=net, dev=dev, wg=wg_dev)


def put_allowedip(mem: Mem, peer: int, raw: bytes, cidr: int) -> int:
    node = mem.alloc(72, 8)
    bitlen, word = len(raw) * 8, 4 if len(raw) == 4 else 8
    stored = b"".join(int.from_bytes(raw[i:i + word], "big").to_bytes(word, "little")
                      for i in range(0, len(raw), word))  # swap_endian() on a LE CPU
    mem.ptr(node + OFF["allowedips_node.peer"], peer)
    mem.u8(node + OFF["allowedips_node.cidr"], cidr)
    mem.u8(node + OFF["allowedips_node.bitlen"], bitlen)
    mem.put(node + OFF["allowedips_node.bits"], stored)
    return node + OFF["allowedips_node.peer_list"]


def put_keypair(mem: Mem, peer: int, slot: str, local: int, remote: int, send: bytes, recv: bytes) -> int:
    kp = mem.alloc(1216)
    mem.ptr(kp + OFF["index_hashtable_entry.peer"], peer)
    mem.u32(kp + OFF["index_hashtable_entry.type"], wg.INDEX_HASHTABLE_KEYPAIR)
    mem.u32(kp + OFF["index_hashtable_entry.index"], local)
    mem.u32(kp + OFF["noise_keypair.remote_index"], remote)
    for member, key in (("sending", send), ("receiving", recv)):
        base = kp + OFF["noise_keypair." + member]
        mem.put(base, key)
        mem.put(base + OFF["noise_symmetric_key.birthdate"], struct.pack("<Q", 5 * 10 ** 9))
        mem.u8(base + OFF["noise_symmetric_key.is_valid"], 1)
    mem.ptr(peer + OFF["wg_peer.keypairs"] + OFF["noise_keypairs.%s_keypair" % slot], kp)
    return kp


def make_peer(mem: Mem, device, remote_pub: bytes, local_priv: bytes = PRIV_A, psk: bytes = PSK,
              precomputed: bytes = None):
    peer = mem.alloc(OFF["sizeof(wg_peer)"])
    hs = peer + OFF["wg_peer.handshake"]
    mem.ptr(peer + OFF["wg_peer.device"], device.wg)
    mem.ptr(hs + OFF["noise_handshake.static_identity"], device.wg + OFF["wg_device.static_identity"])
    mem.put(hs + OFF["noise_handshake.remote_static"], remote_pub)
    if precomputed is None:
        precomputed = wg.x25519_strict(local_priv, remote_pub) or bytes(32)
    mem.put(hs + OFF["noise_handshake.precomputed_static_static"], precomputed)
    mem.put(hs + OFF["noise_handshake.preshared_key"], psk)
    cookie = peer + OFF["wg_peer.latest_cookie"]
    mem.put(cookie + OFF["cookie.message_mac1_key"], wg.precompute_key(wg.LABEL_MAC1, remote_pub))
    mem.put(cookie + OFF["cookie.cookie_decryption_key"], wg.precompute_key(wg.LABEL_COOKIE, remote_pub))
    endpoint = peer + OFF["wg_peer.endpoint"]
    mem.u16(endpoint, 2)
    mem.put(endpoint + 2, struct.pack(">H", 51820) + bytes([10, 199, 0, 2]))
    mem.u16(peer + OFF["wg_peer.persistent_keepalive_interval"], 25)
    mem.ring(peer + OFF["wg_peer.allowedips_list"],
             [put_allowedip(mem, peer, bytes([10, 200, 0, 2]), 32),
              put_allowedip(mem, peer, bytes([10, 0, 0, 255]), 24)])
    return peer


def link_peers(mem: Mem, device, peers) -> None:
    mem.ring(device.wg + OFF["wg_device.peer_list"], [p + OFF["wg_peer.peer_list"] for p in peers])
    mem.u32(device.wg + OFF["wg_device.num_peers"], len(peers))


def walk(mem: Mem, device):
    reader = mem.reader()
    [(net, dev)] = list(wg.iter_wireguard_netdevs(reader, KL, device.net_list))
    wg_dev = wg.wg_device_of(reader, KL, OFF, dev)
    assert (net, dev, wg_dev) == (device.net, device.dev, device.wg)
    return wg.walk_interface(reader, KL, OFF, wg_dev, dev, net, "netns")


# --------------------------------------------------------------------------- oracles


def test_o_id_proves_a_real_identity_and_rejects_a_forged_one():
    assert wg.o_id(PRIV_A, PUB_A) == wg.PASS
    assert wg.o_id(PRIV_A, PUB_B) == wg.FAIL  # forged: pub != f(priv)
    assert wg.o_id(bytes(32), bytes(32)) == wg.NA
    unclamped = bytes([PRIV_A[0] | 7]) + PRIV_A[1:]  # X25519 would clamp it to the same pub
    assert wg.o_id(unclamped, PUB_A) == wg.FAIL


@pytest.mark.parametrize("remote", [bytes(32), (1).to_bytes(32, "little"),
                                    bytes.fromhex("e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800")],
                         ids=["all-zero", "u=1", "order-8"])
def test_small_order_remote_static_never_proves(remote):
    for precomputed in (bytes(32), hashlib.blake2s(b"d", key=b"k").digest()):
        assert wg.o_dh(PRIV_A, remote, precomputed) != wg.PASS
        peer = wg.Peer(0x1000, remote, PSK, precomputed, None, None, None, 0, None, None)
        peer.checks.update(identity=wg.PASS, O_dh=wg.o_dh(PRIV_A, remote, precomputed))
        assert wg.peer_verdict(peer).status != wg.PROVEN


def test_o_dh_and_o_mac1():
    shared = x25519.scalarmult(PRIV_A, PUB_B)
    assert wg.o_dh(PRIV_A, PUB_B, shared) == wg.PASS
    assert wg.o_dh(PRIV_A, PUB_B, bytes(32)) == wg.FAIL
    assert wg.o_dh(None, PUB_B, shared) == wg.NA
    mac1, cookie = wg.precompute_key(wg.LABEL_MAC1, PUB_B), wg.precompute_key(wg.LABEL_COOKIE, PUB_B)
    assert mac1 == hashlib.blake2s(b"mac1----" + PUB_B).digest()
    assert wg.o_mac1(PUB_B, mac1, cookie) == wg.PASS
    assert wg.o_mac1(PUB_A, mac1, cookie) == wg.FAIL
    assert wg.o_mac1(PUB_B, bytes(32), bytes(32)) == wg.NA


def test_verdict_semantics():
    assert wg.decide(False, {}, ("O_id",)).status == wg.NONE
    assert wg.decide(True, {"O_id": wg.PASS, "O_mac1": wg.PASS}, ("O_id",)).label == "O_id+O_mac1"
    assert wg.decide(True, {"O_id": wg.PASS}, ("O_id",), ("noise_handshake.remote_static",)).status == wg.UNVERIFIED
    assert wg.decide(True, {"O_id": wg.PASS, "O_mac1": wg.FAIL}, ("O_id",)).status == wg.CONFLICT
    assert wg.decide(True, {"backptr": wg.PASS}, ()).status == wg.UNVERIFIED  # transport keys


# --------------------------------------------------------------------------- the walk


def test_full_walk_proves_identity_and_peer_and_decodes_config():
    mem = Mem()
    device = make_device(mem)
    peer = make_peer(mem, device, PUB_B)
    link_peers(mem, device, [peer])
    iface = walk(mem, device)
    assert (iface.name, iface.netns, iface.listen_port) == ("wg0", 4026532233, 51820)
    assert wg.identity_verdict(iface.identity).status == wg.PROVEN
    assert iface.identity.checks == {"O_id": "pass", "O_mac1": "pass", "backptr": "pass"}
    [walked] = iface.peers
    assert wg.peer_verdict(walked).status == wg.PROVEN and walked.psk == PSK
    assert walked.endpoint == "10.199.0.2:51820"
    assert walked.allowed_ips == ["10.200.0.2/32", "10.0.0.0/24"]  # host bits masked like wg
    assert walked.checks["O_mac1"] == "pass" and walked.checks["backptr"] == "pass"


def test_forged_static_identity_is_a_conflict_and_proves_no_peer():
    mem = Mem()
    device = make_device(mem, PRIV_A, pub=PUB_B)  # public that is not f(private)
    link_peers(mem, device, [make_peer(mem, device, PUB_B)])
    iface = walk(mem, device)
    assert wg.identity_verdict(iface.identity).status == wg.CONFLICT
    assert wg.peer_verdict(iface.peers[0]).status != wg.PROVEN


def test_identity_is_relocated_when_the_table_offset_drifted():
    mem = Mem()
    device = make_device(mem, bytes(32), pub=bytes(32))
    mem.put(device.wg + OFF["wg_device.static_identity"] + 8, PUB_A + PRIV_A)  # +8 drift
    identity = wg.locate_identity(mem.reader(), OFF, device.wg)
    assert identity.relocated and identity.private == PRIV_A and identity.checks["O_id"] == "pass"


def test_wrong_back_pointers_are_rejected():
    mem = Mem()
    device = make_device(mem)
    stray = make_peer(mem, device, PUB_B)
    mem.ptr(stray + OFF["wg_peer.device"], 0xDEAD0000)
    link_peers(mem, device, [stray])
    assert walk(mem, device).peers == []
    mem.ptr(device.wg + OFF["wg_device.dev"], 0)
    assert wg.wg_device_of(mem.reader(), KL, OFF, device.dev) is None


def test_ipv6_endpoint_and_allowedip():
    mem = Mem()
    device = make_device(mem)
    peer = make_peer(mem, device, PUB_B)
    endpoint = peer + OFF["wg_peer.endpoint"]
    mem.u16(endpoint, 10)
    mem.put(endpoint + 2, struct.pack(">H", 443) + bytes(4) + bytes.fromhex("20010db8" + "00" * 11 + "01"))
    mem.ring(peer + OFF["wg_peer.allowedips_list"],
             [put_allowedip(mem, peer, bytes.fromhex("fd00abcd" + "ff" * 12), 64)])
    link_peers(mem, device, [peer])
    [walked] = walk(mem, device).peers
    assert walked.endpoint == "[2001:db8::1]:443"
    assert walked.allowed_ips == ["fd00:abcd:ffff:ffff::/64"]


def test_in_flight_ephemeral_is_proven_by_the_chaining_key_and_tampering_breaks_it():
    mem = Mem()
    device = make_device(mem)
    peer = make_peer(mem, device, PUB_B, psk=bytes(32))
    hs = peer + OFF["wg_peer.handshake"]
    ss = x25519.scalarmult(PRIV_A, PUB_B)
    ck = wg.initiation_chaining_key(x25519.public_key(EPH), x25519.scalarmult(EPH, PUB_B), ss)
    mem.u32(hs + OFF["noise_handshake.state"], 1)
    mem.put(hs + OFF["noise_handshake.ephemeral_private"], EPH)
    mem.put(hs + OFF["noise_handshake.chaining_key"], ck)
    link_peers(mem, device, [peer])
    [walked] = walk(mem, device).peers
    verdict = wg.peer_verdict(walked)
    assert walked.checks["O_ck"] == "pass" and wg.ephemeral_proven(walked, verdict)
    mem.put(hs + OFF["noise_handshake.ephemeral_private"], x25519.clamp(hashlib.sha256(b"x").digest()))
    [tampered] = walk(mem, device).peers
    assert tampered.checks["O_ck"] == "fail" and wg.peer_verdict(tampered).status == wg.CONFLICT


def test_transport_keys_are_unverified_and_mirrored_across_both_ends():
    mem = Mem()
    dev_a, dev_b = make_device(mem, PRIV_A, name="wgA"), make_device(mem, PRIV_B, name="wgB")
    peer_a, peer_b = make_peer(mem, dev_a, PUB_B, PRIV_A), make_peer(mem, dev_b, PUB_A, PRIV_B)
    put_keypair(mem, peer_a, "current", 0x11, 0x22, SEND, RECV)
    put_keypair(mem, peer_b, "current", 0x22, 0x11, RECV, SEND)
    link_peers(mem, dev_a, [peer_a])
    link_peers(mem, dev_b, [peer_b])
    ifaces = [walk(mem, dev_a), walk(mem, dev_b)]
    wg.check_mirrors(ifaces)
    for iface in ifaces:
        [kp] = iface.peers[0].keypairs
        verdict = wg.keypair_verdict(kp)
        assert kp.checks == {"backptr": "pass", "mirror": "pass"}
        assert verdict.status == wg.UNVERIFIED and "no memory-only oracle" in verdict.label
    mem.put(ifaces[1].peers[0].keypairs[0].address + OFF["noise_keypair.sending"], bytes(range(32)))
    ifaces = [walk(mem, dev_a), walk(mem, dev_b)]
    wg.check_mirrors(ifaces)
    assert wg.keypair_verdict(ifaces[0].peers[0].keypairs[0]).status == wg.CONFLICT


# --------------------------------------------------------------------------- exports


class BarePlugin(wg.WireGuard):
    config = None
    open = None


def _bare(**config):
    plugin = object.__new__(BarePlugin)
    plugin.config, plugin.guessed = config, ()
    plugin.offsets = config.pop("offsets_obj", OFF)
    return plugin


def test_showconf_matches_wg_showconf_layout():
    mem = Mem()
    device = make_device(mem)
    link_peers(mem, device, [make_peer(mem, device, PUB_B)])
    text = wg.showconf(walk(mem, device), lambda kind, record: True)
    assert text == ("[Interface]\nListenPort = 51820\nPrivateKey = %s\n\n[Peer]\nPublicKey = %s\n"
                    "PresharedKey = %s\nAllowedIPs = 10.200.0.2/32, 10.0.0.0/24\n"
                    "Endpoint = 10.199.0.2:51820\nPersistentKeepalive = 25\n"
                    % (wg.b64(PRIV_A), wg.b64(PUB_B), wg.b64(PSK)))


def test_keylog_writes_psk_only_after_an_ephemeral_and_skips_unproven_peers():
    mem = Mem()
    device = make_device(mem)
    good = make_peer(mem, device, PUB_B)
    bad = make_peer(mem, device, PUB_A, precomputed=bytes(range(32)))  # O_dh fails
    link_peers(mem, device, [good, bad])
    iface = walk(mem, device)
    lines = _bare(export_unverified=False)._keylog([iface])
    keys = [line.split(" = ")[0] for line in lines if not line.startswith("#")]
    assert keys == ["LOCAL_STATIC_PRIVATE_KEY", "REMOTE_STATIC_PUBLIC_KEY"]
    assert any("not proven, skipped" in line for line in lines)
    block = wg.keylog_lines(iface, iface.peers[0], True)
    assert [line.split(" = ")[0] for line in block[1:]][-2:] == ["LOCAL_EPHEMERAL_PRIVATE_KEY", "PRESHARED_KEY"]


def test_showconf_omits_unproven_secrets_without_export_unverified():
    mem = Mem()
    device = make_device(mem, PRIV_A, pub=PUB_B)  # forged identity -> conflict
    link_peers(mem, device, [make_peer(mem, device, PUB_B)])
    text = wg.showconf(walk(mem, device), _bare(export_unverified=False)._allowed)
    assert "PrivateKey" not in text and "PresharedKey" not in text


# --------------------------------------------------------------------------- offsets


def test_lookup_exact_is_btf_and_others_are_derived_guesses():
    assert OFF.key_path_guessed() == ()
    x86 = wg_offsets.lookup_offsets("x86_64", "6.8.0-136-generic")
    assert x86.key_path_guessed() == () and x86.untrusted_no_oracle() == () and x86.members == OFF.members
    derived = wg_offsets.lookup_offsets("x86_64", "6.8.0-90-generic")
    assert derived.members == OFF.members and "derived" in derived.source
    assert set(derived.key_path_guessed()) == set(wg_offsets.KEY_PATH_KEYS)


def test_offsets_json_flat_nested_and_errors():
    flat = wg_offsets.load_offsets_json(json.dumps({"wg_peer.handshake": 248, "wg_peer.device": 0}), base=OFF)
    assert flat.sources["wg_peer.handshake"] == "offsets" and flat.sources["wg_device.dev"] == "btf"
    assert flat.sources["wg_peer.device"] == "btf-confirmed"  # equal to the built-in BTF entry
    nested = wg_offsets.load_offsets_json(json.dumps({"btf_offsets": {"wg_device": {
        "size": 1344, "members": {"dev": {"offset": 0}}}}}), base=OFF)
    assert nested.sources["sizeof(wg_device)"] == "btf-confirmed"
    with pytest.raises(ValueError):
        wg_offsets.load_offsets_json(json.dumps({"wg_device": {"dev": 0}}))  # no base: incomplete
    with pytest.raises(ValueError):
        wg_offsets.load_offsets_json("[]")


def test_unusable_offsets_file_is_a_clean_error(tmp_path, caplog):
    bad = tmp_path / "bad.json"
    bad.write_text("{not json")
    plugin = _bare(offsets=str(bad))
    plugin.arch, plugin.kver = "aarch64", "6.8.0-136-generic"
    with caplog.at_level(logging.ERROR):
        assert plugin._collect() == []
    assert "unusable" in caplog.text


# --------------------------------------------------------------------------- real capture (gated)

CAPTURE_DIR = Path(os.environ.get("MEMDIVER_SECRETS_CORPUS", "") or "/nonexistent")
STEM = "ubuntu-24.04-secrets_6.8.0-136-generic"
FORK = Path(os.environ.get("MEMDIVER_VOL3_ARM64_FORK", "") or "/nonexistent")
SIDECAR = CAPTURE_DIR / (STEM + ".secrets.json")


def test_table_entry_equals_the_capture_sidecar_btf_offsets():
    if not SIDECAR.is_file():
        pytest.skip("acquired-secrets sidecar not present")
    loaded = wg_offsets.load_offsets_json(SIDECAR.read_text(), "sidecar", base=OFF)
    from_sidecar = [k for k, source in loaded.sources.items() if source == "btf-confirmed"]
    assert len(from_sidecar) >= 40  # wg_device / wg_peer / noise_handshake / noise_keypair
    assert loaded.members == OFF.members


def _run_and_check(tmp_path, vol_command, stem: str) -> None:
    """Run ``linux.wireguard --export json`` (private --cache-path) and compare with the sidecar."""
    lime, isf, sidecar = (CAPTURE_DIR / (stem + suffix) for suffix in (".lime", ".isf.json", ".secrets.json"))
    symbols = tmp_path / "sym" / "linux"
    symbols.mkdir(parents=True)
    (symbols / (stem + ".json")).symlink_to(isf)
    (tmp_path / "cache").mkdir()  # private identifier cache: the shared one races with other runs
    command = vol_command + ["-q", "-r", "json", "-s", str(tmp_path / "sym"), "-p", str(REPO / "vol3plugins"),
                             "-f", str(lime), "--cache-path", str(tmp_path / "cache"), "-o", str(tmp_path),
                             "linux.wireguard", "--export", "json"]
    result = subprocess.run(command, capture_output=True, text=True, cwd=str(tmp_path), timeout=900)
    assert result.returncode == 0, result.stderr[-2000:]
    assert "guessed WireGuard offsets" not in result.stderr
    rows = json.loads(result.stdout)
    report = json.loads((tmp_path / "wireguard.json").read_text())
    truth = json.loads(sidecar.read_text())["wireguard"]
    assert len(report) == len(truth)
    for interface in truth:
        [got] = [r for r in report if r["public_key"] == interface["public_key_b64"]]
        assert got["private_key"] == interface["private_key_b64"] and got["status"] == "proven"
        assert got["listen_port"] == interface["listen_port"]
        for expected in interface["peers"]:
            [peer] = [p for p in got["peers"] if p["public_key"] == expected["public_key_b64"]]
            assert peer["status"] == "proven" and peer["checks"]["O_dh"] == "pass"
            assert peer["preshared_key"] == expected["preshared_key_b64"]
            assert peer["endpoint"] == expected["endpoint"]
            assert ",".join(peer["allowed_ips"]) == expected["allowed_ips"]
            if expected["latest_handshake_unix"] == 0:  # peer C: handshake in flight
                assert peer["handshake_state"] == "created_initiation" and peer["checks"]["O_ck"] == "pass"
    psk_rows = [r for r in rows if r["Slot"] == "handshake" and r["PSK"] != "(none)"]
    assert psk_rows and all("PSK:bound-to-proven-peer" in r["Verified"] for r in psk_rows)
    transport = [r for r in rows if r["Slot"] in wg.SLOTS]
    assert transport and all(r["Status"] == "unverified" for r in transport)
    c_private = [k for k in json.loads(sidecar.read_text())["keys"] if k["id"] == "wireguard.C.private"]
    if c_private:  # phantom peer: generated, never configured -> must never surface
        assert base64.b64encode(bytes.fromhex(c_private[0]["hex"])).decode() not in result.stdout


def _capture_present(stem: str) -> bool:
    return all((CAPTURE_DIR / (stem + suffix)).is_file() for suffix in (".lime", ".isf.json", ".secrets.json"))


def test_real_capture_through_the_arm64_fork(tmp_path):
    python = FORK / "env" / "bin" / "python"
    if not (_capture_present(STEM) and (FORK / "vol.py").is_file()):
        pytest.skip("aarch64 capture or volatility3-arm64 fork not present")
    _run_and_check(tmp_path, [str(python if python.is_file() else sys.executable), str(FORK / "vol.py")], STEM)


X86_STEM = "ubuntu-24.04-secrets-x86-4level_6.8.0-136-generic"


def test_real_x86_capture_through_stock_vol(tmp_path):
    """Stock volatility3 on the x86_64 capture, no --offsets: the built-in x86 BTF entry suffices."""
    vol = shutil.which("vol") or str(Path(sys.executable).with_name("vol"))
    if not (_capture_present(X86_STEM) and Path(vol).is_file()):
        pytest.skip("x86_64 capture or stock `vol` not present")
    _run_and_check(tmp_path, [vol], X86_STEM)


# --------------------------------------------------------------------------- review fixes


def _consumed_initiation(stale_local: bytes):
    """Responder in CONSUMED_INITIATION: O_ck proves the remote ephemeral, not ``stale_local``."""
    mem = Mem()
    device = make_device(mem)
    peer = make_peer(mem, device, PUB_B)
    hs = peer + OFF["wg_peer.handshake"]
    remote_eph = x25519.public_key(x25519.clamp(hashlib.sha256(b"remote-e").digest()))
    ss = x25519.scalarmult(PRIV_A, PUB_B)
    ck = wg.initiation_chaining_key(remote_eph, x25519.scalarmult(PRIV_A, remote_eph), ss)
    mem.u32(hs + OFF["noise_handshake.state"], 2)
    mem.put(hs + OFF["noise_handshake.remote_ephemeral"], remote_eph)
    mem.put(hs + OFF["noise_handshake.ephemeral_private"], stale_local)
    mem.put(hs + OFF["noise_handshake.chaining_key"], ck)
    link_peers(mem, device, [peer])
    return walk(mem, device)


@pytest.mark.parametrize("stale", [EPH, bytes(range(1, 33))], ids=["stale-clamped", "random"])
def test_1_consumed_initiation_never_proves_the_local_ephemeral(stale):
    iface = _consumed_initiation(stale)
    [peer] = iface.peers
    verdict = wg.peer_verdict(peer)
    assert peer.checks["O_ck"] == "pass" and peer.ck_proves == "remote_ephemeral"
    assert verdict.status == wg.PROVEN and not wg.ephemeral_proven(peer, verdict)
    label = wg.ephemeral_label(peer, verdict)
    assert "remote_ephemeral:proven(O_ck)" in label and "ephemeral:unverified" in label
    lines = _bare(export_unverified=False)._keylog([iface])
    assert not any(line.startswith(("LOCAL_EPHEMERAL_PRIVATE_KEY", "PRESHARED_KEY")) for line in lines)


def test_2_user_offset_on_the_psk_path_is_unverified_unless_it_equals_btf():
    mem = Mem()
    device = make_device(mem)
    link_peers(mem, device, [make_peer(mem, device, PUB_B)])
    [peer] = walk(mem, device).peers
    verdict = wg.peer_verdict(peer)
    moved = wg_offsets.load_offsets_json(json.dumps({"noise_handshake.preshared_key": 216}), base=OFF)
    same = wg_offsets.load_offsets_json(json.dumps({"noise_handshake.preshared_key": 184}), base=OFF)
    assert moved.untrusted_no_oracle() == ("noise_handshake.preshared_key",)
    assert same.untrusted_no_oracle() == () and same.sources["noise_handshake.preshared_key"] == "btf-confirmed"
    untrusted = _bare(export_unverified=False, offsets_obj=moved)
    assert "PSK:unverified" in untrusted._psk_label(peer, verdict) and not untrusted._allowed("psk", peer)
    trusted = _bare(export_unverified=False, offsets_obj=same)
    assert trusted._psk_label(peer, verdict) == "; PSK:bound-to-proven-peer" and trusted._allowed("psk", peer)
    assert "PresharedKey" not in wg.showconf(walk(mem, device), untrusted._allowed)


def test_3_non_canonical_remote_static_cannot_prove():
    aliased = PUB_B[:31] + bytes([PUB_B[31] | 0x80])  # bit 255 set: X25519 masks it to PUB_B
    shared = x25519.scalarmult(PRIV_A, PUB_B)
    assert x25519.scalarmult(PRIV_A, aliased) == shared  # the alias really computes the same DH
    assert wg.o_dh(PRIV_A, aliased, shared) == wg.NA
    above_p = (2 ** 255 - 19 + 1).to_bytes(32, "little")
    assert not x25519.is_canonical_u(above_p) and x25519.is_canonical_u(PUB_B)


def test_4_export_unverified_never_writes_none():
    mem = Mem()
    device = make_device(mem)
    good, empty = make_peer(mem, device, PUB_B), make_peer(mem, device, bytes(32))
    link_peers(mem, device, [good, empty])
    iface = walk(mem, device)
    plugin = _bare(export_unverified=True)
    text = "\n".join(plugin._keylog([iface])) + wg.showconf(iface, plugin._allowed)
    assert "None" not in text and "skipped: public key unreadable or zero" in text
    assert text.count("PublicKey = ") == 1


def test_5_peer_needs_a_proven_identity_and_removed_key_is_no_identity():
    mem = Mem()
    device = make_device(mem)
    link_peers(mem, device, [make_peer(mem, device, PUB_B)])
    checker = device.wg + OFF["wg_device.cookie_checker"]
    mem.put(checker + OFF["cookie_checker.message_mac1_key"], bytes(range(32)))  # identity conflict
    iface = walk(mem, device)
    assert iface.identity.checks["O_id"] == "pass"
    assert wg.identity_verdict(iface.identity).status == wg.CONFLICT
    assert iface.peers[0].checks["O_dh"] == "n/a" and wg.peer_verdict(iface.peers[0]).status != wg.PROVEN
    bare = wg.Peer(0x3000, PUB_B, None, x25519.scalarmult(PRIV_A, PUB_B), None, None, None, 0, None, None)
    bare.checks["O_dh"] = wg.PASS  # O_dh alone, no proven identity recorded: never proven
    assert wg.peer_verdict(bare).status == wg.UNVERIFIED
    assert wg.keylog_lines(iface, wg.Peer(0x4000, None, None, None, None, None, None, 0, None, None),
                           True)[0].endswith("skipped: key unreadable or zero")
    mem2 = Mem()  # removed key: zero private clamped by the kernel, stale public, has_identity=0
    removed = make_device(mem2, x25519.clamp(bytes(32)), pub=PUB_A)
    mem2.u8(removed.wg + OFF["wg_device.static_identity"] + OFF["noise_static_identity.has_identity"], 0)
    identity = wg.locate_identity(mem2.reader(), OFF, removed.wg)
    assert wg.identity_verdict(identity).status == wg.NONE


def test_6_a_full_sidecar_is_sufficient_on_a_kernel_outside_the_table():
    derived = wg_offsets.lookup_offsets("x86_64", "6.8.0-90-generic")
    def sidecar(structs):
        doc = {}
        for name in structs:
            members = {k.split(".", 1)[1]: {"offset": v} for k, v in OFF.members.items()
                       if k.startswith(name + ".")}
            doc[name] = {"members": members}
        return json.dumps({"btf_offsets": doc})
    partial = wg_offsets.load_offsets_json(sidecar(wg_offsets.SIDECAR_STRUCTS[:4]), base=derived)
    assert partial.key_path_guessed() and set(partial.missing_sidecar_structs()) == set(wg_offsets.SIDECAR_STRUCTS[4:])
    full = wg_offsets.load_offsets_json(sidecar(wg_offsets.SIDECAR_STRUCTS), base=derived)
    assert full.key_path_guessed() == () and full.missing_sidecar_structs() == ()
    assert full.untrusted_no_oracle()  # no built-in BTF for x86 yet: PSK/transport stay unverified


# --------------------------------------------------------------------------- net_device fallback sizes


class _NoIsf:
    """A vmlinux module whose ISF has none of the walk types."""

    def get_type(self, name):
        raise KeyError(name)


class _IsfWithNetDevice(_NoIsf):
    def get_type(self, name):
        if name == "net_device":
            return type("T", (), {"size": 1111})()
        raise KeyError(name)


@pytest.mark.parametrize("n, size", [(31, 2512), (41, 2512), (53, 2512), (71, 2512), (100, 2512),
                                     (117, 2512), (136, 2544), (149, 2544)])
def test_x86_ubuntu_6_8_net_device_size_comes_from_the_measured_table(n, size):
    kl = wg.WgKernelLayout.for_kernel(_NoIsf(), "x86_64", "6.8.0-%d-generic" % n)
    assert kl.sizes["net_device"] == size != 2560
    assert kl["net_device.dev_list"] == 360
    assert kl.sources["net_device.name"] == "table"
    assert "net_device.name" not in kl.defaulted()


def test_net_device_member_offsets_follow_the_release():
    first = wg.WgKernelLayout.for_kernel(_NoIsf(), "x86_64", "6.8.0-31-generic")
    later = wg.WgKernelLayout.for_kernel(_NoIsf(), "x86_64", "6.8.0-117-generic")
    last = wg.WgKernelLayout.for_kernel(_NoIsf(), "x86_64", "6.8.0-136-generic")
    assert (first["net_device.name"], first["net_device.nd_net"], first["net.dev_base_head"]) == (296, 272, 144)
    assert (later["net_device.name"], later["net_device.nd_net"], later["net.dev_base_head"]) == (304, 280, 152)
    assert (later["net_device.rtnl_link_ops"], last["net_device.rtnl_link_ops"]) == (2272, 2304)


def test_unknown_kernel_keeps_the_guessed_defaults():
    kl = wg.WgKernelLayout.for_kernel(_NoIsf(), "x86_64", "6.8.0-40-generic")  # not measurable
    assert kl.sizes["net_device"] == 2560 and "net_device.name" in kl.defaulted()
    assert wg.WgKernelLayout.for_kernel(_NoIsf(), "aarch64", "6.8.0-136-generic").sizes["net_device"] == 2560
    assert wg.WgKernelLayout.for_kernel(_NoIsf(), None, None).sizes["net_device"] == 2560


def test_the_isf_size_beats_the_table():
    kl = wg.WgKernelLayout.for_kernel(_IsfWithNetDevice(), "x86_64", "6.8.0-31-generic")
    assert kl.sizes["net_device"] == 1111


def test_the_136_table_entry_equals_the_capture_isf():
    corpus = os.environ.get("MEMDIVER_SECRETS_CORPUS")
    isf = Path(corpus or "/nonexistent") / "ubuntu-24.04-secrets-x86-4level_6.8.0-136-generic.isf.json"
    if not isf.is_file():
        pytest.skip("MEMDIVER_SECRETS_CORPUS x86 4-level ISF not available")
    types = json.loads(isf.read_text())["user_types"]
    entry = wg.NETDEV_LAYOUTS[("x86_64", "6.8.0-136-generic")]
    assert types["net_device"]["size"] == entry["sizeof(net_device)"]
    for key, value in entry.items():
        if key.startswith("sizeof("):
            continue
        type_name, member = key.split(".")
        assert types[type_name]["fields"][member]["offset"] == value, key
