"""``linux.wireguard`` -- WireGuard interfaces, peers and keys, proven from memory alone.

Walk
----
``net_namespace_list`` -> every ``struct net`` -> ``dev_base_head`` -> each ``net_device`` whose
``rtnl_link_ops->kind`` is ``"wireguard"`` -> ``wg_device = netdev_priv(dev)`` =
``dev + ALIGN(sizeof(struct net_device), NETDEV_ALIGN=32)``, accepted only when the back-pointer
``wg_device.dev == dev`` holds.  The ``wireguard`` module's own ``device_list`` (via its kallsyms,
``module.get_symbol``) is walked too and merged, so an interface whose netns list is unreadable
is still found.  ``wg_device.peer_list`` -> ``wg_peer`` (back-pointer ``wg_peer.device``), each
with its ``noise_handshake``, its ``keypairs.{current,previous,next}_keypair``
(``noise_keypair``, back-pointer ``entry.peer``), its endpoint and its ``allowedips_list``
(``allowedips_node``, back-pointer ``node.peer``).  vmlinux offsets come from the ISF; the
module structs come from ``secrets.wg_offsets`` or ``--offsets`` (the capture sidecar is
accepted), each key labelled ``btf`` / ``offsets`` / ``derived`` (a guess).

Proof (memory only -- no traffic, no pcap)
------------------------------------------
* **O_id**  ``X25519(static_private)·G == static_public`` (clamp prefilter first; a forged block
  whose public is not f(private) is a ``conflict``).  If the table offset fails, the 64-byte
  ``{static_public, static_private}`` block is searched inside the ``wg_device`` allocation.
* **O_mac1**  ``BLAKE2s("mac1----" ‖ static_public) == cookie_checker.message_mac1_key`` and the
  ``cookie--`` key likewise (device), and the same over the peer's public in
  ``wg_peer.latest_cookie`` (peer): binds each public key to a second, independent location.
* **O_dh**  ``X25519(static_private, remote_static) == precomputed_static_static`` with the
  small-order rejection of ``x25519.scalarmult(strict=True)``: an all-zero / small-order remote
  static or a zeroed precompute never proves, and neither does a non-canonical ``remote_static``
  (value >= p or bit 255 set, which X25519 would alias to another key).  A proven identity (not
  just O_id) + O_dh => the peer's public key is **proven**.  An identity with
  ``has_identity == 0`` (private key removed) is ``none``, not a conflict.
* **O_ck**  for a handshake in flight the Noise_IKpsk2 chaining key is recomputed from memory:
  ``CREATED_INITIATION``: ``ck = KDF1(KDF1(KDF1(ck0, e_pub), DH(e, S_r)), ss)`` proves the LOCAL
  ``ephemeral_private``; ``CONSUMED_INITIATION``: the same over ``remote_ephemeral`` and
  ``DH(s, E_r)`` proves only the REMOTE ephemeral.  In that state the local
  ``ephemeral_private`` (left stale after a simultaneous initiation, because
  ``consume_initiation`` does not clear it) stays ``unverified`` and is never exported as proven.
* **PSK** has no oracle of its own: it is reported ``proven`` only *indirectly*, as a member of a
  proven peer's handshake (``Verified`` says ``PSK:bound-to-proven-peer``), and only when
  ``noise_handshake.preshared_key`` is BTF-backed.  A user ``--offsets`` value there that differs
  from the built-in BTF entry makes the PSK ``unverified``; the same applies to the transport-key
  offsets (see ``wg_offsets.NO_ORACLE_KEYS``).
* **Transport keys** (``noise_keypair.sending/receiving``) have NO memory-only oracle: the
  chaining key they derive from is zeroed by ``handshake_zero()`` in
  ``wg_noise_handshake_begin_session()``.  They are always ``unverified``, reported with their
  provenance: ``is_valid``, birthdate age (boot clock from ``tk_core``), the index pairing
  (``entry.peer`` back-pointer) and, when both ends of a tunnel live in this image (netns
  setups), the mirror keypair (local/remote index swapped, send == peer's recv).

Zeroing semantics (why material may be absent)
----------------------------------------------
``handshake_zero()`` wipes ``ephemeral_private``, ``remote_ephemeral``, ``hash`` and
``chaining_key`` as soon as a session begins, so an ephemeral private key is resident ONLY while a
handshake is in flight (``CREATED_INITIATION``, e.g. an unreachable peer being retried).
``remote_static``, ``precomputed_static_static`` and ``preshared_key`` persist for the peer's
lifetime; the peer and its keypairs are freed with ``kfree_sensitive()`` (zeroed on free).
``timer_zero_key_material`` wipes all keypairs and the handshake after ``REJECT_AFTER_TIME * 3``
= 540 s without a new handshake; keys expire for sending after 180 s (``REJECT_AFTER_TIME``).

Row shape
---------
One row per (interface, slot): slot ``identity`` (Peer n/a; LocalPrivate/LocalPublic), then per
peer slot ``handshake`` (Peer, PSK, Ephemeral, Endpoint, AllowedIPs, HandshakeState, handshake
indices) and one row per resident keypair slot ``current`` / ``previous`` / ``next`` (indices,
initiator, SendKey, RecvKey, Birthdate, Valid).  ``Ephemeral`` is an extra column (the in-flight
``LOCAL_EPHEMERAL_PRIVATE_KEY``).  Keys are base64 as ``wg`` prints them.

Exports (``--export``; only ``proven`` material unless ``--export-unverified``)
-----------------------------------------------------------------------------
* ``keylog``: ``wireguard.keylog`` in Wireshark's grammar (``<type> = <base64>``; types
  ``LOCAL_STATIC_PRIVATE_KEY``, ``REMOTE_STATIC_PUBLIC_KEY``, ``LOCAL_EPHEMERAL_PRIVATE_KEY``,
  ``PRESHARED_KEY``; Wireshark links a PSK to the LAST ephemeral line, so a PSK line is only
  written right after its ephemeral) plus ``wireguard.wg-transport.json`` (transport keys are
  never proven: their key fields are null without ``--export-unverified``).
* ``showconf``: ``wireguard.<netns>.<ifname>.conf`` in ``wg showconf`` format.
* ``json``: ``wireguard.json``.
"""

import base64
import json
import logging
import socket
import struct
from dataclasses import dataclass, field
from typing import Any, Dict, Iterator, List, Optional, Sequence, Tuple

from volatility3.framework import exceptions, interfaces, renderers
from volatility3.framework.configuration import requirements
from volatility3.framework.renderers import format_hints

from . import btf_layouts, dmcrypt
from .kernel_common import (SafeReader, write_text, align_up, arch_of, find_module, isf_size, iter_list, kernel_reader,
                            kernel_release, module_symbol, nonzero, symbol_address)
from .secrets import wg_offsets, x25519
from .secrets.noise import LABEL_COOKIE, LABEL_MAC1, initiation_chaining_key, precompute_key

vollog = logging.getLogger(__name__)

MAX_NETNS = 4096
MAX_DEVICES_PER_NS = 65536
MAX_PEERS = 1 << 20  # WireGuard's MAX_PEERS_PER_DEVICE
MAX_ALLOWEDIPS = 65536
MAX_MODULES = 4096
NETDEV_ALIGNS = (32, 64)  # NETDEV_ALIGN; 64 also tried (wg_device is __aligned(64))
KEY_LEN = 32
AF_INET_LINUX, AF_INET6_LINUX = 2, 10
INDEX_HASHTABLE_KEYPAIR = 1 << 1
SLOTS = ("current", "previous", "next")
HANDSHAKE_STATES = ("zeroed", "created_initiation", "consumed_initiation",
                    "created_response", "consumed_response")
TRANSPORT_NOTE = "no memory-only oracle for transport keys (chaining key zeroed at session start)"

PROVEN, UNVERIFIED, CONFLICT, NONE = "proven", "unverified", "conflict", "none"
PASS, FAIL, NA = "pass", "fail", "n/a"


# --------------------------------------------------------------------------- kernel layout


_KERNEL_DEFAULTS = {  # aarch64 6.8.0-136 ISF values, used only when an ISF lacks a type
    "net.list": 32, "net.dev_base_head": 152, "net.ns": 128, "ns_common.inum": 16,
    "net_device.dev_list": 360, "net_device.name": 304, "net_device.ifindex": 224,
    "net_device.rtnl_link_ops": 2320, "net_device.nd_net": 280, "rtnl_link_ops.kind": 16,
    "sockaddr.sa_family": 0, "sockaddr_in.sin_port": 2, "sockaddr_in.sin_addr": 4,
    "sockaddr_in6.sin6_port": 2, "sockaddr_in6.sin6_addr": 8, "sockaddr_in6.sin6_scope_id": 24,
    "timespec64.tv_sec": 0,
}
_KERNEL_SIZES = {"net_device": 2560, "net_device.name": 16}

# Measured net/net_device layouts of Ubuntu 24.04 x86_64 6.8.0-N-generic, read from each package's own
# vmlinux ``.BTF`` (linux-image-unsigned-6.8.0-N-generic, zstd bzImage payload; the -136 entry equals the
# capture's dwarf2json ISF).  Used only for keys an ISF lacks.  The aarch64 defaults above are WRONG here:
# sizeof(net_device) is 2512 (6.8.0-31...117) / 2544 (6.8.0-136, -149), not 2560, and net_device.name,
# .ifindex, .nd_net, net.dev_base_head and net.ns move between releases.  6.8.0-40 was not measurable
# (package gone from the archive) and gets no entry.
_NETDEV_6_8_31 = {"sizeof(net_device)": 2512, "net.list": 32, "net.dev_base_head": 144, "net.ns": 120,
                  "ns_common.inum": 16, "net_device.dev_list": 360, "net_device.name": 296,
                  "net_device.ifindex": 216, "net_device.rtnl_link_ops": 2272, "net_device.nd_net": 272,
                  "rtnl_link_ops.kind": 16}
_NETDEV_6_8_41 = dict(_NETDEV_6_8_31, **{"net_device.name": 304, "net_device.ifindex": 224,
                                         "net_device.nd_net": 280})
_NETDEV_6_8_71 = dict(_NETDEV_6_8_41, **{"net.dev_base_head": 152, "net.ns": 128})
_NETDEV_6_8_136 = dict(_NETDEV_6_8_71, **{"sizeof(net_device)": 2544, "net_device.rtnl_link_ops": 2304})
NETDEV_LAYOUTS = {("x86_64", "6.8.0-%s-generic" % n): layout
                  for layout, numbers in ((_NETDEV_6_8_31, (31,)), (_NETDEV_6_8_41, (41, 53)),
                                          (_NETDEV_6_8_71, (71, 100, 117)), (_NETDEV_6_8_136, (136, 149)))
                  for n in numbers}


@dataclass
class WgKernelLayout(dmcrypt.KernelLayout):
    """vmlinux offsets of the netns/netdev walk (same provenance rules as ``linux.dmcrypt``).

    No vmlinux offset is on a key path: every wg_device is accepted through its back-pointer.
    """

    offsets: Dict[str, int] = field(default_factory=lambda: dict(_KERNEL_DEFAULTS))
    sizes: Dict[str, int] = field(default_factory=lambda: dict(_KERNEL_SIZES))

    @classmethod
    def for_kernel(cls, module: Any, arch: Optional[str], kver: Optional[str]) -> "WgKernelLayout":
        """:meth:`from_module`, then every key the ISF lacks taken from :data:`NETDEV_LAYOUTS`.

        An entry only fills what the ISF does not say (the ISF always wins); a filled offset has
        provenance ``table`` and so no longer counts as a guess.  A kernel with no entry keeps the
        aarch64 defaults, exactly as before.
        """
        layout = cls.from_module(module)
        entry = NETDEV_LAYOUTS.get((arch or "", kver or ""))
        if entry is None:
            return layout
        for key in layout.defaulted():
            if key in entry:
                layout.offsets[key], layout.sources[key] = entry[key], "table"
        if isf_size(module, "net_device") is None:
            layout.sizes["net_device"] = entry["sizeof(net_device)"]
        return layout

    def missing_walk(self) -> List[str]:
        return self.defaulted()

    def key_path_defaulted(self) -> List[str]:
        return []


# --------------------------------------------------------------------------- crypto oracles


def b64(data: Optional[bytes]) -> Optional[str]:
    return base64.b64encode(data).decode("ascii") if data else None


def x25519_strict(scalar: bytes, point: bytes) -> Optional[bytes]:
    try:
        return x25519.scalarmult(scalar, point, strict=True)
    except ValueError:
        return None


def o_id(private: Optional[bytes], public: Optional[bytes]) -> str:
    """O_id: ``public == X25519(private, 9)``; clamp prefilter; all-zero never passes."""
    if not nonzero(private) and not nonzero(public):
        return NA
    if not nonzero(private) or not nonzero(public) or not x25519.is_clamped(private):
        return FAIL
    return PASS if x25519.proves_public(private, public) else FAIL


def o_dh(private: Optional[bytes], remote_static: Optional[bytes],
         precomputed: Optional[bytes]) -> str:
    """O_dh: ``X25519(private, remote_static) == precomputed_static_static`` (strict, canonical)."""
    if not nonzero(private) or private is None or remote_static is None or precomputed is None:
        return NA
    if not x25519.is_canonical_u(remote_static):  # aliases another point: can never prove this one
        return NA
    shared = x25519_strict(private, remote_static)
    if shared is None:  # small-order / all-zero remote static: never proves anything
        return FAIL if nonzero(remote_static) or nonzero(precomputed) else NA
    return PASS if shared == precomputed else FAIL


def o_mac1(public: Optional[bytes], mac1_key: Optional[bytes],
           cookie_key: Optional[bytes]) -> str:
    """O_mac1: both cookie.c precomputed keys equal BLAKE2s over ``public``."""
    if not nonzero(public) or not (nonzero(mac1_key) or nonzero(cookie_key)):
        return NA
    ok = (mac1_key == precompute_key(LABEL_MAC1, public)
          and cookie_key == precompute_key(LABEL_COOKIE, public))
    return PASS if ok else FAIL


# --------------------------------------------------------------------------- records


@dataclass
class Identity:
    address: int  # the noise_static_identity
    public: Optional[bytes]
    private: Optional[bytes]
    has_identity: bool
    relocated: bool = False
    checks: Dict[str, str] = field(default_factory=dict)


@dataclass
class Keypair:
    slot: str
    address: int
    local_index: Optional[int]
    remote_index: Optional[int]
    initiator: Optional[bool]
    send_key: Optional[bytes]
    recv_key: Optional[bytes]
    send_birth: Optional[int]
    recv_birth: Optional[int]
    send_valid: bool
    recv_valid: bool
    checks: Dict[str, str] = field(default_factory=dict)


@dataclass
class Peer:
    address: int
    remote_static: Optional[bytes]
    psk: Optional[bytes]
    precomputed: Optional[bytes]
    ephemeral: Optional[bytes]
    remote_ephemeral: Optional[bytes]
    chaining_key: Optional[bytes]
    state: Optional[int]
    local_index: Optional[int]
    remote_index: Optional[int]
    endpoint: str = ""
    allowed_ips: List[str] = field(default_factory=list)
    keepalive: int = 0
    last_handshake: int = 0
    rx_bytes: int = 0
    tx_bytes: int = 0
    attempts: int = 0
    checks: Dict[str, str] = field(default_factory=dict)
    keypairs: List[Keypair] = field(default_factory=list)
    ck_proves: str = ""  # "local_ephemeral" | "remote_ephemeral": the key O_ck was computed over

    @property
    def state_name(self) -> str:
        if self.state is None:
            return "?"
        return HANDSHAKE_STATES[self.state] if self.state < len(HANDSHAKE_STATES) else "state %d" % self.state


@dataclass
class Interface:
    name: str
    netns: Optional[int]
    ifindex: Optional[int]
    net_device: int
    address: int  # wg_device
    listen_port: int
    fwmark: int
    num_peers: int
    origin: str
    identity: Optional[Identity] = None
    peers: List[Peer] = field(default_factory=list)


# --------------------------------------------------------------------------- verdict


@dataclass
class Verdict:
    status: str  # proven | unverified | conflict | none
    label: str


def decide(material: bool, checks: Dict[str, str], required: Sequence[str],
           guessed: Sequence[str] = ()) -> Verdict:
    """The single place a record becomes ``proven``.

    proven = material present, no check failed, every ``required`` check passed and no guessed
    (``derived``) offset on the key path.  A failed check is a ``conflict``.  ``required=()``
    (transport keys) can never be proven.
    """
    if not material:
        return Verdict(NONE, "none")
    failed = [name for name, result in checks.items() if result == FAIL]
    if failed:
        return Verdict(CONFLICT, "conflict:" + "+".join(failed))
    passed = "+".join(name for name, result in checks.items() if result == PASS)
    if required and all(checks.get(name) == PASS for name in required):
        if guessed:
            return Verdict(UNVERIFIED, passed + " (derived offsets)")
        return Verdict(PROVEN, passed)
    return Verdict(UNVERIFIED, passed or "unverified")


def identity_verdict(identity: Optional[Identity], guessed: Sequence[str] = ()) -> Verdict:
    if identity is None:
        return Verdict(NONE, "none")
    if not identity.has_identity:  # private key removed / never set: not a forgery
        return Verdict(NONE, "no identity (has_identity=0)")
    return decide(nonzero(identity.private) or nonzero(identity.public), identity.checks, ("O_id",), guessed)


def peer_verdict(peer: Peer, guessed: Sequence[str] = ()) -> Verdict:
    """Proven needs ``identity`` (the interface identity itself proven, set by ``check_peer``)."""
    return decide(nonzero(peer.remote_static), peer.checks, ("identity", "O_dh"), guessed)


def keypair_verdict(keypair: Keypair) -> Verdict:
    verdict = decide(nonzero(keypair.send_key) or nonzero(keypair.recv_key), keypair.checks, ())
    if verdict.status == UNVERIFIED:
        verdict.label = "unverified: " + TRANSPORT_NOTE + (
            "; " + verdict.label if verdict.label != "unverified" else "")
    return verdict


def ephemeral_proven(peer: Peer, verdict: Verdict) -> bool:
    """The LOCAL ephemeral is proven only where O_ck used DH(e_local, S_r): CREATED_INITIATION."""
    return (verdict.status == PROVEN and peer.state == 1 and peer.ck_proves == "local_ephemeral"
            and peer.checks.get("O_ck") == PASS and nonzero(peer.ephemeral))


def ephemeral_label(peer: Peer, verdict: Verdict) -> str:
    parts = []
    if peer.ck_proves == "remote_ephemeral" and peer.checks.get("O_ck") == PASS:
        parts.append("remote_ephemeral:proven(O_ck)")
    if nonzero(peer.ephemeral):
        parts.append("ephemeral:%s" % ("proven(O_ck)" if ephemeral_proven(peer, verdict) else "unverified"))
    return "".join("; " + part for part in parts)


# --------------------------------------------------------------------------- readers


def _le32(reader: SafeReader, address: int) -> Optional[int]:
    data = reader.read(address, 4)
    return struct.unpack("<I", data)[0] if data else None


def wg_device_of(reader: SafeReader, kl: WgKernelLayout, off: wg_offsets.WgOffsets,
                 dev: int) -> Optional[int]:
    """``netdev_priv(dev)`` if the ``wg_device.dev`` back-pointer confirms it."""
    for alignment in NETDEV_ALIGNS:
        priv = dev + align_up(kl.sizes["net_device"], alignment)
        if reader.ptr(priv + off["wg_device.dev"]) == dev:
            return priv
    return None


def iter_wireguard_netdevs(reader: SafeReader, kl: WgKernelLayout,
                           net_list: int) -> Iterator[Tuple[int, int]]:
    """``(net, net_device)`` for every netdev whose ``rtnl_link_ops->kind`` is wireguard."""
    for net in iter_list(reader, net_list, kl["net.list"], MAX_NETNS):
        for dev in iter_list(reader, net + kl["net.dev_base_head"], kl["net_device.dev_list"],
                             MAX_DEVICES_PER_NS):
            ops = reader.ptr(dev + kl["net_device.rtnl_link_ops"])
            if ops and reader.cstring(reader.ptr(ops + kl["rtnl_link_ops.kind"]), 32) == "wireguard":
                yield net, dev


def read_identity(reader: SafeReader, off: wg_offsets.WgOffsets, address: int) -> Identity:
    public = reader.read(address + off["noise_static_identity.static_public"], KEY_LEN)
    private = reader.read(address + off["noise_static_identity.static_private"], KEY_LEN)
    has = reader.u8(address + off["noise_static_identity.has_identity"])
    identity = Identity(address, public, private, bool(has))
    identity.checks["O_id"] = o_id(private, public)
    return identity


def search_identity(reader: SafeReader, wg: int, size: int) -> Optional[Tuple[int, bytes, bytes]]:
    """Locator fallback: a ``{public, private}`` 64-byte block inside the wg_device allocation."""
    data = reader.read(wg, size) or b""
    for start in range(0, len(data) - 2 * KEY_LEN + 1, 8):
        private = data[start + KEY_LEN:start + 2 * KEY_LEN]
        if nonzero(private) and x25519.is_clamped(private) and \
                x25519.public_key(private) == data[start:start + KEY_LEN]:
            return wg + start, data[start:start + KEY_LEN], private
    return None


def locate_identity(reader: SafeReader, off: wg_offsets.WgOffsets, wg: int) -> Identity:
    """``wg_device.static_identity`` at the table offset, else searched (drift repair)."""
    identity = read_identity(reader, off, wg + off["wg_device.static_identity"])
    if identity.checks["O_id"] != FAIL:
        return identity
    found = search_identity(reader, wg, off["sizeof(wg_device)"])
    if found is None:
        return identity  # stays a conflict: a block whose public is not f(private)
    address, public, private = found
    vollog.info("wg_device @%#x: static_identity found at +%d, table says +%d",
                wg, address - wg, off["wg_device.static_identity"])
    relocated = Identity(address, public, private, True, relocated=True)
    relocated.checks["O_id"] = PASS
    return relocated


def device_cookie_check(reader: SafeReader, off: wg_offsets.WgOffsets, wg: int,
                        identity: Identity) -> None:
    checker = wg + off["wg_device.cookie_checker"]
    identity.checks["O_mac1"] = o_mac1(
        identity.public, reader.read(checker + off["cookie_checker.message_mac1_key"], KEY_LEN),
        reader.read(checker + off["cookie_checker.cookie_encryption_key"], KEY_LEN))
    back = reader.ptr(checker + off["cookie_checker.device"])
    identity.checks["backptr"] = PASS if back == wg else (NA if not back else FAIL)


def decode_endpoint(reader: SafeReader, kl: WgKernelLayout, address: int) -> str:
    """``wg show dump`` endpoint text: ``a.b.c.d:port`` / ``[v6]:port`` / ``""`` (none)."""
    family = reader.u16(address + kl["sockaddr.sa_family"])
    if family == AF_INET_LINUX:
        port, ip = reader.read(address + kl["sockaddr_in.sin_port"], 2), \
            reader.read(address + kl["sockaddr_in.sin_addr"], 4)
        if port and ip:
            return "%s:%d" % (socket.inet_ntop(socket.AF_INET, ip), struct.unpack(">H", port)[0])
    if family == AF_INET6_LINUX:
        port, ip = reader.read(address + kl["sockaddr_in6.sin6_port"], 2), \
            reader.read(address + kl["sockaddr_in6.sin6_addr"], 16)
        scope = reader.u32(address + kl["sockaddr_in6.sin6_scope_id"])
        if port and ip:
            text = socket.inet_ntop(socket.AF_INET6, ip) + ("%%%d" % scope if scope else "")
            return "[%s]:%d" % (text, struct.unpack(">H", port)[0])
    return ""


def decode_allowedip(reader: SafeReader, off: wg_offsets.WgOffsets, node: int) -> Optional[str]:
    """``wg_allowedips_read_node()``: bits are CPU-endian words (``swap_endian``) -> ``ip/cidr``."""
    cidr, bitlen = reader.u8(node + off["allowedips_node.cidr"]), reader.u8(node + off["allowedips_node.bitlen"])
    bits = reader.read(node + off["allowedips_node.bits"], 16)
    if bits is None or bitlen not in (32, 128) or cidr is None or cidr > bitlen:
        return None
    word = 4 if bitlen == 32 else 8
    raw = b"".join(int.from_bytes(bits[i:i + word], reader.byteorder).to_bytes(word, "big")
                   for i in range(0, bitlen // 8, word))
    value = int.from_bytes(raw, "big") & (((1 << cidr) - 1) << (bitlen - cidr))
    family = socket.AF_INET if bitlen == 32 else socket.AF_INET6
    return "%s/%d" % (socket.inet_ntop(family, value.to_bytes(bitlen // 8, "big")), cidr)


def read_allowed_ips(reader: SafeReader, off: wg_offsets.WgOffsets, peer: int) -> List[str]:
    found = []
    for node in iter_list(reader, peer + off["wg_peer.allowedips_list"],
                          off["allowedips_node.peer_list"], MAX_ALLOWEDIPS):
        if reader.ptr(node + off["allowedips_node.peer"]) != peer:
            continue
        text = decode_allowedip(reader, off, node)
        if text:
            found.append(text)
    return found


def read_keypair(reader: SafeReader, off: wg_offsets.WgOffsets, slot: str, address: int,
                 peer: int) -> Keypair:
    sending, receiving = address + off["noise_keypair.sending"], address + off["noise_keypair.receiving"]
    entry = address + off["noise_keypair.entry"]

    def key(base: int) -> Optional[bytes]:
        return reader.read(base + off["noise_symmetric_key.key"], KEY_LEN)

    def birth(base: int) -> Optional[int]:
        return reader.u64(base + off["noise_symmetric_key.birthdate"])

    keypair = Keypair(
        slot, address, _le32(reader, entry + off["index_hashtable_entry.index"]),
        _le32(reader, address + off["noise_keypair.remote_index"]),
        bool(reader.u8(address + off["noise_keypair.i_am_the_initiator"])),
        key(sending), key(receiving), birth(sending), birth(receiving),
        bool(reader.u8(sending + off["noise_symmetric_key.is_valid"])),
        bool(reader.u8(receiving + off["noise_symmetric_key.is_valid"])))
    owner_ok = reader.ptr(entry + off["index_hashtable_entry.peer"]) == peer and \
        reader.u32(entry + off["index_hashtable_entry.type"]) == INDEX_HASHTABLE_KEYPAIR
    keypair.checks["backptr"] = PASS if owner_ok else FAIL
    return keypair


def read_keypairs(reader: SafeReader, off: wg_offsets.WgOffsets, peer: int) -> List[Keypair]:
    keypairs = []
    base = peer + off["wg_peer.keypairs"]
    for slot in SLOTS:
        address = reader.ptr(base + off["noise_keypairs.%s_keypair" % slot])
        if address:
            keypairs.append(read_keypair(reader, off, slot, address, peer))
    return keypairs


def _handshake_fields(reader: SafeReader, off: wg_offsets.WgOffsets, hs: int) -> Dict[str, Any]:
    def key(member: str) -> Optional[bytes]:
        return reader.read(hs + off["noise_handshake." + member], KEY_LEN)

    return dict(
        remote_static=key("remote_static"), psk=key("preshared_key"),
        precomputed=key("precomputed_static_static"), ephemeral=key("ephemeral_private"),
        remote_ephemeral=key("remote_ephemeral"), chaining_key=key("chaining_key"),
        state=reader.u32(hs + off["noise_handshake.state"]),
        local_index=_le32(reader, hs + off["noise_handshake.entry"] + off["index_hashtable_entry.index"]),
        remote_index=_le32(reader, hs + off["noise_handshake.remote_index"]))


def read_peer(reader: SafeReader, kl: WgKernelLayout, off: wg_offsets.WgOffsets, address: int) -> Peer:
    peer = Peer(address, **_handshake_fields(reader, off, address + off["wg_peer.handshake"]))
    peer.endpoint = decode_endpoint(reader, kl, address + off["wg_peer.endpoint"])
    peer.allowed_ips = read_allowed_ips(reader, off, address)
    peer.keepalive = reader.u16(address + off["wg_peer.persistent_keepalive_interval"]) or 0
    peer.last_handshake = reader.u64(address + off["wg_peer.walltime_last_handshake"]
                                     + kl["timespec64.tv_sec"]) or 0
    peer.rx_bytes = reader.u64(address + off["wg_peer.rx_bytes"]) or 0
    peer.tx_bytes = reader.u64(address + off["wg_peer.tx_bytes"]) or 0
    peer.attempts = reader.u32(address + off["wg_peer.timer_handshake_attempts"]) or 0
    peer.keypairs = read_keypairs(reader, off, address)
    return peer


def check_peer(reader: SafeReader, off: wg_offsets.WgOffsets, peer: Peer, identity: Optional[Identity]) -> None:
    """O_dh, O_mac1 (peer cookie), handshake back-pointer and, in flight, O_ck."""
    status = identity_verdict(identity).status if identity is not None else NONE
    proven = status == PROVEN
    peer.checks["identity"] = PASS if proven else (FAIL if status == CONFLICT else NA)
    private = identity.private if proven else None
    peer.checks["O_dh"] = o_dh(private, peer.remote_static, peer.precomputed)
    cookie = peer.address + off["wg_peer.latest_cookie"]
    peer.checks["O_mac1"] = o_mac1(peer.remote_static,
                                   reader.read(cookie + off["cookie.message_mac1_key"], KEY_LEN),
                                   reader.read(cookie + off["cookie.cookie_decryption_key"], KEY_LEN))
    back = reader.ptr(peer.address + off["wg_peer.handshake"] + off["noise_handshake.static_identity"])
    expected = identity.address if identity and not identity.relocated else None
    peer.checks["backptr"] = PASS if expected and back == expected else (NA if expected is None else FAIL)
    peer.checks["O_ck"], peer.ck_proves = o_ck(peer, private)


def o_ck(peer: Peer, private: Optional[bytes]) -> Tuple[str, str]:
    """Recompute the in-flight chaining key; ``(result, which ephemeral it was computed over)``."""
    if not nonzero(peer.chaining_key) or not nonzero(peer.precomputed) or private is None:
        return NA, ""
    if peer.state == 1 and nonzero(peer.ephemeral) and x25519.is_clamped(peer.ephemeral):
        which, e_pub = "local_ephemeral", x25519.public_key(peer.ephemeral)
        dh = x25519_strict(peer.ephemeral, peer.remote_static)
    elif peer.state == 2 and nonzero(peer.remote_ephemeral):
        which, e_pub = "remote_ephemeral", peer.remote_ephemeral
        dh = x25519_strict(private, peer.remote_ephemeral)
    else:
        return NA, ""
    return _ck_matches(peer, e_pub, dh), which


def _ck_matches(peer: Peer, e_pub: bytes, dh: Optional[bytes]) -> str:
    if dh is None:
        return FAIL
    return PASS if initiation_chaining_key(e_pub, dh, peer.precomputed) == peer.chaining_key else FAIL


def check_mirrors(interfaces_: Sequence[Interface]) -> None:
    """Both tunnel ends in one image: local/remote index swapped => keys must mirror."""
    by_index: Dict[Tuple[int, int], Keypair] = {}
    for kp in (k for i in interfaces_ for p in i.peers for k in p.keypairs):
        if kp.local_index is not None and kp.remote_index is not None:
            by_index[(kp.local_index, kp.remote_index)] = kp
    for (local, remote), kp in by_index.items():
        other = by_index.get((remote, local))
        if other is None:
            continue
        same = kp.send_key == other.recv_key and kp.recv_key == other.send_key
        kp.checks["mirror"] = PASS if same and nonzero(kp.send_key) else FAIL


def walk_interface(reader: SafeReader, kl: WgKernelLayout, off: wg_offsets.WgOffsets,
                   wg: int, dev: int, net: Optional[int], origin: str) -> Interface:
    name = reader.inline_string(dev + kl["net_device.name"], kl.sizes.get("net_device.name", 16)) or "?"
    netns = reader.u32(net + kl["net.ns"] + kl["ns_common.inum"]) if net else None
    iface = Interface(name, netns, reader.u32(dev + kl["net_device.ifindex"]), dev, wg,
                      reader.u16(wg + off["wg_device.incoming_port"]) or 0,
                      reader.u32(wg + off["wg_device.fwmark"]) or 0,
                      reader.u32(wg + off["wg_device.num_peers"]) or 0, origin)
    iface.identity = locate_identity(reader, off, wg)
    device_cookie_check(reader, off, wg, iface.identity)
    for address in iter_list(reader, wg + off["wg_device.peer_list"], off["wg_peer.peer_list"], MAX_PEERS):
        if reader.ptr(address + off["wg_peer.device"]) != wg:
            vollog.info("%s: peer @%#x fails the wg_peer.device back-pointer, skipped", name, address)
            continue
        peer = read_peer(reader, kl, off, address)
        check_peer(reader, off, peer, iface.identity)
        iface.peers.append(peer)
    if iface.num_peers != len(iface.peers):
        vollog.warning("%s: num_peers=%d but %d peers walked", name, iface.num_peers, len(iface.peers))
    return iface


# --------------------------------------------------------------------------- showconf / keylog


def showconf(iface: Interface, include: Any) -> str:
    """``wg showconf`` text (src/showconf.c order); ``include(kind, record)`` gates secrets."""
    lines = ["[Interface]"]
    if iface.listen_port:
        lines.append("ListenPort = %u" % iface.listen_port)
    if iface.fwmark:
        lines.append("FwMark = 0x%x" % iface.fwmark)
    identity = iface.identity
    if identity and nonzero(identity.private) and include("identity", identity):
        lines.append("PrivateKey = %s" % b64(identity.private))
    lines.append("")
    peers = [p for p in iface.peers if nonzero(p.remote_static)]
    lines += ["# peer @%#x skipped: public key unreadable or zero" % p.address
              for p in iface.peers if not nonzero(p.remote_static)]
    for index, peer in enumerate(peers):
        lines += ["[Peer]", "PublicKey = %s" % b64(peer.remote_static)]
        if nonzero(peer.psk) and include("psk", peer):
            lines.append("PresharedKey = %s" % b64(peer.psk))
        if peer.allowed_ips:
            lines.append("AllowedIPs = %s" % ", ".join(peer.allowed_ips))
        if peer.endpoint:
            lines.append("Endpoint = %s" % peer.endpoint)
        if peer.keepalive:
            lines.append("PersistentKeepalive = %u" % peer.keepalive)
        if index + 1 < len(peers):
            lines.append("")
    return "\n".join(lines) + "\n"


def keylog_lines(iface: Interface, peer: Peer, with_ephemeral: bool, with_psk: bool = True) -> List[str]:
    """Wireshark WG keylog block for one (interface, peer); PSK only after its ephemeral."""
    if not nonzero(peer.remote_static) or not nonzero(iface.identity.private if iface.identity else None):
        return ["# %s peer @%#x skipped: key unreadable or zero" % (iface.name, peer.address)]
    lines = ["# %s netns %s peer %s handshake %s" % (iface.name, iface.netns, b64(peer.remote_static),
                                                    peer.state_name),
             "LOCAL_STATIC_PRIVATE_KEY = %s" % b64(iface.identity.private),
             "REMOTE_STATIC_PUBLIC_KEY = %s" % b64(peer.remote_static)]
    if with_ephemeral:
        lines.append("LOCAL_EPHEMERAL_PRIVATE_KEY = %s" % b64(peer.ephemeral))
        if nonzero(peer.psk) and with_psk:
            lines.append("PRESHARED_KEY = %s" % b64(peer.psk))
    elif nonzero(peer.psk) and with_psk:
        lines.append("# PRESHARED_KEY not written: Wireshark links a PSK to the preceding "
                     "LOCAL_EPHEMERAL_PRIVATE_KEY and no proven ephemeral is resident "
                     "(the PSK is in the showconf/json exports)")
    return lines


# --------------------------------------------------------------------------- the plugin


class WireGuard(interfaces.plugins.PluginInterface):
    """Lists WireGuard interfaces/peers and recovers their keys, proven from memory alone."""

    _required_framework_version = (2, 0, 0)
    _version = (1, 0, 0)

    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        return [
            requirements.ModuleRequirement(
                name="kernel", description="Linux kernel",
                architectures=["Intel32", "Intel64", "AArch64"]),
            requirements.StringRequirement(
                name="offsets", optional=True,
                description="JSON with WireGuard module struct offsets (a capture sidecar works)"),
            requirements.ChoiceRequirement(
                name="export", choices=["keylog", "showconf", "json"], optional=True,
                description="Write a Wireshark keylog (+ transport JSON), wg showconf files or a JSON report"),
            requirements.BooleanRequirement(
                name="export_unverified", optional=True, default=False,
                description="Also export material that is not proven (transport keys never are)"),
            requirements.BooleanRequirement(
                name="verbose", optional=True, default=False,
                description="Add a Detail column (offset provenance, counters, origin)"),
            btf_layouts.btf_method_requirement(),
        ]

    # ------------------------------------------------------------------ setup

    def _setup(self) -> None:
        self.vmlinux, self.layer, self.reader = kernel_reader(self.context, self.config["kernel"])
        self.byteorder = self.reader.byteorder
        self.arch = arch_of(self.layer)
        self.kver = kernel_release(self.vmlinux, self.reader)
        self.kl = WgKernelLayout.for_kernel(self.vmlinux, self.arch, self.kver)
        if self.kl.defaulted():
            vollog.warning("ISF lacks %d walk offsets, guessed from aarch64 6.8: %s",
                           len(self.kl.defaulted()), ", ".join(self.kl.defaulted()))

    def _load_offsets(self) -> Optional[wg_offsets.WgOffsets]:
        """Trusted memory BTF > table entry (exact, else derived), overlaid by ``--offsets``.

        Raises ``ValueError``/``OSError`` for a bad ``--offsets`` file.
        """
        table, differ = wg_offsets.choose_offsets(self._memory_offsets(),
                                                  wg_offsets.lookup_offsets(self.arch, self.kver))
        if differ:
            vollog.warning("in-memory wireguard BTF differs from the built-in table for %s %s (%d keys; "
                           "using memory): %s", self.arch, self.kver, len(differ), "; ".join(differ))
        path = self.config.get("offsets")
        if not path:
            return table
        with open(path, "r", encoding="utf-8") as handle:
            return wg_offsets.load_offsets_json(handle.read(), "--offsets " + path, table)

    def _memory_offsets(self) -> Optional[wg_offsets.WgOffsets]:
        """Offsets from the image's own ``wireguard`` module BTF when trusted, else None."""
        recovered = btf_layouts.recover_trusted(
            getattr(self, "context", None), self.config.get("kernel"), "wireguard",
            wg_offsets.SIDECAR_STRUCTS, self.config.get("btf_method"))
        if recovered is None:
            return None
        offsets = wg_offsets.from_memory(recovered.members, recovered.source)
        if offsets is None:
            vollog.info("btf-memory wireguard: required members missing: not used")
        return offsets

    def _boot_and_wall_now(self) -> Tuple[Optional[int], Optional[int]]:
        """``(boottime ns, realtime ns)`` at acquisition from ``tk_core.timekeeper`` (last tick)."""
        try:
            tk = self.vmlinux.object_from_symbol("tk_core").timekeeper
            base = int(tk.tkr_mono.base)
            return base + int(tk.offs_boot), base + int(tk.offs_real)
        except (exceptions.SymbolError, exceptions.InvalidAddressException, AttributeError, ValueError):
            return None, None

    # ------------------------------------------------------------------ walk roots

    def _module_device_list(self) -> Optional[int]:
        module = find_module(self.vmlinux, "wireguard", MAX_MODULES)
        return module_symbol(module, "device_list") if module is not None else None

    def _found_devices(self, off: wg_offsets.WgOffsets) -> Dict[int, Tuple[int, Optional[int], str]]:
        """``wg_device -> (net_device, net, origin)`` from the netns walk and the module list."""
        found: Dict[int, Tuple[int, Optional[int], str]] = {}
        net_list = symbol_address(self.vmlinux, "net_namespace_list")
        for net, dev in iter_wireguard_netdevs(self.reader, self.kl, net_list) if net_list else ():
            wg = wg_device_of(self.reader, self.kl, off, dev)
            if wg is not None:
                found[wg] = (dev, net, "netns")
        device_list = self._module_device_list()
        for wg in iter_list(self.reader, device_list, off["wg_device.device_list"], MAX_NETNS) \
                if device_list else ():
            dev = self.reader.ptr(wg + off["wg_device.dev"])
            if not dev or wg_device_of(self.reader, self.kl, off, dev) != wg:
                continue
            if wg in found:
                found[wg] = found[wg][:2] + ("netns+module",)
            else:
                found[wg] = (dev, self.reader.ptr(dev + self.kl["net_device.nd_net"]), "module")
        vollog.info("wireguard walk: netns list %s, module device_list %s, %d devices",
                    "found" if net_list else "absent", "found" if device_list else "absent", len(found))
        return found

    def _collect(self) -> List[Interface]:
        try:
            self.offsets = self._load_offsets()
        except (OSError, ValueError) as error:
            vollog.error("--offsets %s unusable: %s", self.config.get("offsets"), error)
            return []
        if self.offsets is None:
            vollog.warning("no WireGuard offsets for %s %s: pass --offsets", self.arch, self.kver)
            return []
        vollog.info("wireguard offsets: %s", self.offsets.source)
        self.guessed = self.offsets.key_path_guessed()
        if self.guessed:
            vollog.warning("guessed WireGuard offsets on the key path (%s): nothing will be proven; "
                           "pass --offsets (pahole/BTF of wireguard)", ", ".join(self.guessed))
        interfaces_ = [walk_interface(self.reader, self.kl, self.offsets, wg, dev, net, origin)
                       for wg, (dev, net, origin) in sorted(self._found_devices(self.offsets).items())]
        check_mirrors(interfaces_)
        return interfaces_

    # ------------------------------------------------------------------ output

    def _age(self, birth: Optional[int]) -> Any:
        if not birth:
            return renderers.NotApplicableValue()
        if self.boot_now is None:
            return "boot+%.1fs" % (birth / 1e9)
        return "boot+%.1fs (age %.0fs)" % (birth / 1e9, (self.boot_now - birth) / 1e9)

    def _rows(self, iface: Interface) -> Iterator[Tuple[Dict[str, Any], str]]:
        identity, na = iface.identity, renderers.NotApplicableValue()
        verdict = identity_verdict(identity, self.guessed)
        yield {"Slot": "identity", "LocalPrivate": b64(identity.private) if nonzero(identity.private) else na,
               "LocalPublic": b64(identity.public) if nonzero(identity.public) else na,
               "Status": verdict.status, "Verified": verdict.label,
               "Offset(V)": format_hints.Hex(identity.address)}, \
            "origin=%s relocated=%s has_identity=%s num_peers=%d offsets=%s" % (
                iface.origin, identity.relocated, identity.has_identity, iface.num_peers, self.offsets.source)
        for peer in iface.peers:
            yield from self._peer_rows(peer)

    def _peer_rows(self, peer: Peer) -> Iterator[Tuple[Dict[str, Any], str]]:
        na = renderers.NotApplicableValue()
        verdict = peer_verdict(peer, self.guessed)
        label = verdict.label + self._psk_label(peer, verdict) + ephemeral_label(peer, verdict)
        common = {"Peer": b64(peer.remote_static) or na}
        state = peer.state_name + (" (in flight, %d attempts)" % peer.attempts if peer.state == 1 else "")
        yield dict(common, Slot="handshake", PSK=b64(peer.psk) if nonzero(peer.psk) else "(none)",
                   Ephemeral=b64(peer.ephemeral) if nonzero(peer.ephemeral) else na,
                   Endpoint=peer.endpoint or "(none)", AllowedIPs=",".join(peer.allowed_ips) or "(none)",
                   HandshakeState=state, LocalIndex=self._hex(peer.local_index),
                   RemoteIndex=self._hex(peer.remote_index), Status=verdict.status, Verified=label,
                   **{"Offset(V)": format_hints.Hex(peer.address)}), \
            "latest_handshake=%d keepalive=%s rx=%d tx=%d" % (
                peer.last_handshake, peer.keepalive or "off", peer.rx_bytes, peer.tx_bytes)
        for kp in peer.keypairs:
            kp_verdict = keypair_verdict(kp)
            yield dict(common, Slot=kp.slot, LocalIndex=self._hex(kp.local_index),
                       RemoteIndex=self._hex(kp.remote_index), Initiator=kp.initiator,
                       SendKey=b64(kp.send_key) if nonzero(kp.send_key) else na,
                       RecvKey=b64(kp.recv_key) if nonzero(kp.recv_key) else na,
                       Birthdate=self._age(kp.send_birth), Valid=kp.send_valid and kp.recv_valid,
                       Status=kp_verdict.status, Verified=kp_verdict.label + self._transport_note(),
                       **{"Offset(V)": format_hints.Hex(kp.address)}), \
                "send_valid=%s recv_valid=%s recv_birth=%s" % (kp.send_valid, kp.recv_valid, kp.recv_birth)

    def _transport_note(self) -> str:
        untrusted = self.offsets.untrusted_no_oracle("noise_keypair") + \
            self.offsets.untrusted_no_oracle("noise_symmetric_key") + self.offsets.untrusted_no_oracle("wg_peer")
        return "; offsets not BTF-confirmed: " + ",".join(untrusted) if untrusted else ""

    def _psk_trusted(self) -> bool:
        return not self.offsets.untrusted_no_oracle("noise_handshake.")

    def _psk_label(self, peer: Peer, verdict: Verdict) -> str:
        if verdict.status != PROVEN or not nonzero(peer.psk):
            return ""
        if not self._psk_trusted():
            return "; PSK:unverified (user offset, not BTF-confirmed; no PSK oracle)"
        return "; PSK:bound-to-proven-peer"

    @staticmethod
    def _hex(value: Optional[int]) -> Any:
        return format_hints.Hex(value) if value else renderers.NotApplicableValue()

    COLUMNS = [("Interface", str), ("NetNS", int), ("ListenPort", int), ("LocalPrivate", str),
               ("LocalPublic", str), ("Peer", str), ("PSK", str), ("Ephemeral", str), ("Endpoint", str),
               ("AllowedIPs", str), ("HandshakeState", str), ("Slot", str),
               ("LocalIndex", format_hints.Hex), ("RemoteIndex", format_hints.Hex), ("Initiator", bool),
               ("SendKey", str), ("RecvKey", str), ("Birthdate", str), ("Valid", bool), ("Status", str),
               ("Verified", str), ("Offset(V)", format_hints.Hex)]

    def _columns(self) -> List[Tuple[str, Any]]:
        return self.COLUMNS + ([("Detail", str)] if self.config.get("verbose") else [])

    def _generator(self, interfaces_: List[Interface]) -> Iterator[Tuple[int, Tuple]]:
        na = renderers.NotApplicableValue()
        for iface in interfaces_:
            base = {"Interface": iface.name, "NetNS": iface.netns if iface.netns is not None else na,
                    "ListenPort": iface.listen_port}
            for values, detail in self._rows(iface):
                merged = dict(base, **values)
                row = [merged.get(name, na) for name, _ in self.COLUMNS]
                if self.config.get("verbose"):
                    row.append(detail)
                yield 0, tuple(row)

    # ------------------------------------------------------------------ exports

    def _allowed(self, kind: str, record: Any) -> bool:
        if self.config.get("export_unverified"):
            return True
        verdict = identity_verdict(record, self.guessed) if kind == "identity" else peer_verdict(record, self.guessed)
        return verdict.status == PROVEN and (kind != "psk" or self._psk_trusted())

    def _export(self, interfaces_: List[Interface]) -> None:
        mode = self.config.get("export")
        if mode == "keylog":
            self._write("wireguard.keylog", "\n".join(self._keylog(interfaces_)) + "\n")
            self._write("wireguard.wg-transport.json", json.dumps(self._transport(interfaces_), indent=1))
        elif mode == "showconf":
            for iface in interfaces_:
                self._write("wireguard.%s.%s.conf" % (iface.netns, iface.name), showconf(iface, self._allowed))
        elif mode == "json":
            self._write("wireguard.json", json.dumps(self._json(interfaces_), indent=1))

    def _write(self, name: str, text: str) -> None:
        write_text(self, name, text)

    def _keylog(self, interfaces_: List[Interface]) -> List[str]:
        lines = ["# linux.wireguard keylog (Wireshark WireGuard key log format)"]
        for iface in interfaces_:
            if not self._allowed("identity", iface.identity) or not nonzero(iface.identity.private):
                lines.append("# %s netns %s: static identity not proven, skipped" % (iface.name, iface.netns))
                continue
            for peer in iface.peers:
                if not nonzero(peer.remote_static):
                    lines.append("# %s peer @%#x skipped: public key unreadable or zero" % (iface.name, peer.address))
                    continue
                if not self._allowed("peer", peer):
                    lines.append("# %s peer %s not proven, skipped" % (iface.name, b64(peer.remote_static)))
                    continue
                ephemeral = nonzero(peer.ephemeral) and (
                    ephemeral_proven(peer, peer_verdict(peer, self.guessed)) or self.config.get("export_unverified"))
                lines += keylog_lines(iface, peer, bool(ephemeral), self._allowed("psk", peer))
        return lines

    def _transport(self, interfaces_: List[Interface]) -> Dict[str, Any]:
        keys = bool(self.config.get("export_unverified"))
        entries = []
        for iface in interfaces_:
            for peer in iface.peers:
                for kp in peer.keypairs:
                    verdict = keypair_verdict(kp)
                    entries.append({
                        "interface": iface.name, "netns": iface.netns, "peer": b64(peer.remote_static),
                        "slot": kp.slot, "local_index": kp.local_index, "remote_index": kp.remote_index,
                        "initiator": kp.initiator, "send_valid": kp.send_valid, "recv_valid": kp.recv_valid,
                        "send_birthdate_ns": kp.send_birth, "recv_birthdate_ns": kp.recv_birth,
                        "boottime_at_dump_ns": self.boot_now,
                        "send_key": b64(kp.send_key) if keys else None,
                        "recv_key": b64(kp.recv_key) if keys else None,
                        "status": verdict.status, "verified": verdict.label})
        return {"note": TRANSPORT_NOTE + ("" if keys else "; key fields need --export-unverified"),
                "keypairs": entries}

    def _json(self, interfaces_: List[Interface]) -> List[Dict[str, Any]]:
        report = []
        for iface in interfaces_:
            identity = iface.identity
            id_verdict = identity_verdict(identity, self.guessed)
            report.append({
                "interface": iface.name, "netns": iface.netns, "ifindex": iface.ifindex,
                "wg_device": iface.address, "net_device": iface.net_device, "origin": iface.origin,
                "listen_port": iface.listen_port, "fwmark": iface.fwmark,
                "private_key": b64(identity.private) if self._allowed("identity", identity) else None,
                "public_key": b64(identity.public), "status": id_verdict.status,
                "checks": identity.checks, "offsets": self.offsets.source,
                "peers": [self._peer_json(peer) for peer in iface.peers]})
        return report

    def _peer_json(self, peer: Peer) -> Dict[str, Any]:
        verdict = peer_verdict(peer, self.guessed)
        return {
            "public_key": b64(peer.remote_static), "status": verdict.status, "verified": verdict.label,
            "checks": peer.checks, "preshared_key": b64(peer.psk) if self._allowed("psk", peer) and nonzero(peer.psk) else None,
            "ephemeral_private": b64(peer.ephemeral) if nonzero(peer.ephemeral) and (
                ephemeral_proven(peer, verdict) or self.config.get("export_unverified")) else None,
            "endpoint": peer.endpoint, "allowed_ips": peer.allowed_ips,
            "persistent_keepalive": peer.keepalive, "latest_handshake": peer.last_handshake,
            "rx_bytes": peer.rx_bytes, "tx_bytes": peer.tx_bytes, "handshake_state": peer.state_name,
            "handshake_attempts": peer.attempts, "wg_peer": peer.address,
            "keypairs": [{"slot": k.slot, "status": keypair_verdict(k).status, "checks": k.checks,
                          "local_index": k.local_index, "remote_index": k.remote_index}
                         for k in peer.keypairs]}

    def run(self) -> renderers.TreeGrid:
        self._setup()
        self.guessed: Sequence[str] = ()
        self.boot_now, self.wall_now = self._boot_and_wall_now()
        interfaces_ = self._collect()
        peers = [p for i in interfaces_ for p in i.peers]
        vollog.info("linux.wireguard: %d interfaces, %d/%d identities proven, %d/%d peers proven (%s %s)",
                    len(interfaces_), sum(identity_verdict(i.identity, self.guessed).status == PROVEN
                                          for i in interfaces_), len(interfaces_),
                    sum(peer_verdict(p, self.guessed).status == PROVEN for p in peers), len(peers),
                    self.arch, self.kver)
        if self.config.get("export"):
            self._export(interfaces_)
        return renderers.TreeGrid(self._columns(), self._generator(interfaces_))
