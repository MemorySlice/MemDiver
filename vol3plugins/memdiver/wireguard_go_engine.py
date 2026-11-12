"""wireguard-go key recovery from one process's memory, proven from memory alone.

This module is the analysis behind the ``memdiver.wireguard_go.WireGuardGo`` Volatility 3
plugin. It works on plain bytes (a :class:`Memory` of ``(virtual address, bytes)`` segments),
knows nothing about Volatility and imports only the standard library and the stdlib-only
``vol3plugins/linux/secrets/{x25519,noise}`` primitives, so it is unit-tested on synthetic memory and runs
unchanged under stock ``vol``. It covers every program built on the wireguard-go ``device``
package: the ``wireguard-go`` daemon, Tailscale (its fork), wireguard-android's ``libwg-go`` and
wireguard-apple's ``WireGuardKitGo``.

Structures (golang.zx2c4.com/wireguard ``device/``; 64-bit Go, offsets in bytes)
--------------------------------------------------------------------------------
``Device.staticIdentity{sync.RWMutex; privateKey [32]; publicKey [32]}``: the private key is
stored clamped (``NoisePrivateKey.clamp``) and IMMEDIATELY followed by its public key, at
``Device + 136`` (``state`` 32 B + ``net`` 80 B + the 24-byte RWMutex). ``Peer`` = ``isRunning``
@0, ``keypairs{RWMutex; current; previous; next}`` @8 (pointers @32/@40/@48), ``handshake`` @56,
``device *Device`` right after the handshake. ``Handshake`` (stable since 2019) =
``state int`` @0, ``mutex`` @8, ``hash`` @32, ``chainKey`` @64, ``presharedKey`` @96,
``localEphemeral`` @128, ``localIndex``/``remoteIndex`` @160/@164, ``remoteStatic`` @168,
``remoteEphemeral`` @200, ``precomputedStaticStatic`` @232, ``lastTimestamp`` @264,
``lastInitiationConsumption``/``lastSentHandshake`` (``time.Time``) @280/@304; size 328. This
engine anchors everything on ``remoteStatic`` (:class:`GoLayout`). ``Keypair`` = ``sendNonce``
@0, ``send``/``receive`` (``cipher.AEAD`` interfaces; the data word @16/@32 points at
x/crypto's ``chacha20poly1305{key [32]byte}``), ``replayFilter`` (1032 B) @40, ``isInitiator``
@1072, ``created`` @1080, ``localIndex``/``remoteIndex`` @1104/@1108. Checked against the
wireguard-go 0.0.20250522 corpus (Go 1.25, arm64) byte for byte.

Locators
--------
``pubkey_adjacency`` (layout-free): every 8-aligned clamped 32-byte value with 19+ distinct
bytes whose X25519 public key sits in the next 32 bytes. Go copies ``staticIdentity`` by value,
so a process usually holds several copies; they are one identity row with ``Copies``.

``device_backpointer`` (trusted structure): ``Peer.device`` points at ``Device``; a qword equal
to ``copy - 136`` for a proven identity copy marks a ``Peer``, whose ``remoteStatic`` sits 160
bytes before it. The hit is a ``Peer`` only if its shape fits and the peer's own
``cookieGenerator.mac1.key == BLAKE2s("mac1----" ‖ remoteStatic)`` follows within 1 KiB (O_mac1,
as in ``linux.wireguard``). Fields of such a handshake (PSK, indices, ephemerals, keypairs) are
read.

``adjacency`` (fallback, layout-light, NOT trusted): only for a proven identity that no
back-pointer reaches (a fork with another ``Device`` layout): every 8-aligned 32-byte high-
entropy canonical value whose X25519 with the identity sits 64 bytes later. A handshake found
this way proves the peer public key but its PSK is never bound and nothing else is read.

Proof (memory only, no traffic)
-------------------------------
* ``oracle:x25519-pubkey`` -- ``X25519(private)·G == public`` (the ``x25519-pubkey`` format
  oracle). Proves the static private key.
* ``oracle:x25519-dh-consistency`` -- ``X25519(static_private, remoteStatic) ==
  precomputedStaticStatic`` in the same handshake (the ``x25519-dh-consistency`` format
  oracle), with a proven ``static_private``: binds the peer public key to this identity.
  Small-order, all-zero and non-canonical inputs never decide (``x25519.dh_consistency``).
* ``oracle:noise-chaining-key`` -- a handshake caught mid-flight keeps its Noise chaining key;
  recomputing it from memory proves the local ephemeral (Wireshark needs it to decrypt):
  ``initiationCreated``: ``chainKey = KDF1(KDF1(KDF1(ck0, E_pub), DH(e, S_r)), ss)``;
  ``responseCreated``: the responder's chain over the initiator's ``remoteEphemeral``, then its
  own ``E_pub``, ``DH(e, E_i)``, ``DH(e, S_i)`` and the PSK -- so in that state the PSK is
  proven too (see :func:`expected_chaining_key`).
* PSK: otherwise no oracle exists. ``bound:peer-handshake`` only when it sits in a trusted
  (``device_backpointer``) handshake whose peer is proven; otherwise ``unverified``.
* Transport keys (``Keypair.send``/``receive``): NEVER proven -- the chaining key they derive from
  is zeroed by ``Handshake.Clear`` in ``BeginSymmetricSession``. Reported ``unverified`` with
  their provenance (slot, indices, initiator flag). wireguard-go never zeroes old keypairs
  (``device/keypair.go``), so stale epochs may also be in the heap; they are not chased.
* ``rejected`` comes only from a trusted structure: a back-pointer handshake whose precomputed
  value does not match its proven identity, or a ``Device`` whose private key is a proven one
  while its public key slot holds something else.
"""
import base64
import re
import struct

from ..linux.secrets import noise, x25519
from .ssh_engine import MAX_POINTER, MIN_POINTER, Memory, high_entropy

ID_ORACLE = "x25519-pubkey"
DH_ORACLE = "x25519-dh-consistency"
PROVEN_ID = "oracle:" + ID_ORACLE
PROVEN_DH = "oracle:" + DH_ORACLE
PROVEN_CK = "oracle:noise-chaining-key"
BOUND_PSK = "bound:peer-handshake"
UNVERIFIED = "unverified"
REJECTED = "rejected"
KEY_LEN = 32
MAX_ADJACENCY_CANDIDATES = 250000
MAC1_WINDOW = 1024
PROCESS_NAMES = ("wireguard-go", "tailscaled", "wireguard")
PROCESS_PREFIXES = ("com.wireguard",)
HANDSHAKE_STATES = ("zeroed", "initiationCreated", "initiationConsumed", "responseCreated",
                    "responseConsumed")
INITIATION_CREATED = 1
RESPONSE_CREATED = 3
TRANSPORT_NOTE = ("no memory-only oracle for transport keys (their chaining key is zeroed by "
                  "Handshake.Clear when the session begins)")

# A clamped scalar: low 3 bits clear (byte 0), bit 255 clear and bit 254 set (byte 31). The
# regex anchors on byte 31 and looks BEHIND for byte 0: a narrow class first runs at C speed
# (0.24 s on 73 MB, against 17 s for the same test written as a lookahead over ``[\s\S]``).
_CLAMPED_TAIL = re.compile(
    rb"(?s)[\x40-\x7f](?<=[" + b"".join(re.escape(bytes([b])) for b in range(0, 256, 8)) +
    rb"].{30}[\x40-\x7f])")


class GoLayout(object):
    """wireguard-go 64-bit offsets (see the module docstring), anchored on ``remoteStatic``."""

    name = "wireguard-go 0.0.2019+ (64-bit Go)"
    identity_in_device = 136
    device_listen_port = 96      # Device.net.port (uint16)
    device_fwmark = 100          # Device.net.fwmark (uint32)
    hs_state = -168
    hs_chain_key = -104
    hs_psk = -72
    hs_local_ephemeral = -40
    hs_local_index = -8
    hs_remote_index = -4
    hs_remote_ephemeral = 32
    hs_precomputed = 64
    hs_device = 160
    peer_from_remote_static = -224
    peer_keypairs = (("current", 32), ("previous", 40), ("next", 48))
    kp_send_data = 16
    kp_recv_data = 32
    kp_initiator = 1072
    kp_local_index = 1104
    kp_remote_index = 1108


LAYOUT = GoLayout()


def b64(data):
    return base64.b64encode(bytes(data)).decode("ascii") if data else ""


def _pointer(value):
    return value is not None and MIN_POINTER <= value < MAX_POINTER and value % 8 == 0



# --------------------------------------------------------------------------- records


class Identity(object):
    """One static key pair (``Device.staticIdentity``) and every VA where a copy sits."""

    def __init__(self, private, public):
        self.private = bytes(private)
        self.public = bytes(public)
        self.addresses = []
        self.struct_address = None   # the copy a Peer.device back-pointer reaches
        self.listen_port = None      # Device.net, read only for a back-pointer-reached copy
        self.fwmark = None

    @property
    def device(self):
        if self.struct_address is None:
            return None
        return self.struct_address - LAYOUT.identity_in_device

    @property
    def address(self):
        return self.struct_address if self.struct_address is not None else self.addresses[0]


class Keypair(object):
    """One ``Keypair``; ``send``/``recv`` are ``(va, key)`` of the AEADs' key arrays."""

    def __init__(self, slot, address, send, recv, initiator, local_index, remote_index):
        self.slot = slot
        self.address = address
        self.send_va, self.send = send or (None, None)
        self.recv_va, self.recv = recv or (None, None)
        self.initiator = initiator
        self.local_index = local_index
        self.remote_index = remote_index


class Handshake(object):
    """One ``Peer.handshake``: ``address`` is the VA of its ``remoteStatic``."""

    def __init__(self, address, remote_static, precomputed, identity, locator, trusted):
        self.address = address
        self.remote_static = remote_static
        self.precomputed = precomputed
        self.identity = identity
        self.locator = locator
        self.trusted = trusted
        self.dh = None
        self.state = None
        self.local_index = None
        self.remote_index = None
        self.psk = None
        self.local_ephemeral = None
        self.remote_ephemeral = None
        self.ephemeral_proven = False
        self.psk_proven = False      # the PSK is an input of a recomputed chaining key
        self.keypairs = []

    @property
    def state_name(self):
        if self.state is None:
            return "?"
        if self.state < len(HANDSHAKE_STATES):
            return HANDSHAKE_STATES[self.state]
        return "state %d" % self.state


class Row(object):
    """One output row: a key with its verdict and provenance."""

    def __init__(self, kind, key, addresses, proven, detail, peer=b"", slot="", local_index=None,
                 remote_index=None, locator=""):
        self.kind = kind
        self.key = bytes(key or b"")
        self.addresses = sorted(set(addresses))
        self.proven = proven
        self.detail = detail
        self.peer = bytes(peer or b"")
        self.slot = slot
        self.local_index = local_index
        self.remote_index = remote_index
        self.locator = locator

    def as_dict(self, with_key=True):
        return {"kind": self.kind, "key_b64": b64(self.key) if with_key else None,
                "key_hex": self.key.hex() if with_key else None, "length": len(self.key),
                "peer": b64(self.peer) or None, "slot": self.slot or None,
                "local_index": self.local_index, "remote_index": self.remote_index,
                "addresses": ["0x%x" % a for a in self.addresses], "proven": self.proven,
                "locator": self.locator, "detail": self.detail}


class Analysis(object):
    def __init__(self, identities, handshakes, rows, stats):
        self.identities = identities
        self.handshakes = handshakes
        self.rows = rows
        self.stats = stats


# --------------------------------------------------------------------------- locators


def _clamped_candidates(memory):
    """VA of every 8-aligned clamped-looking 32-byte value."""
    for start, data in memory.segments:
        for match in _CLAMPED_TAIL.finditer(data):
            va = start + match.start() - (KEY_LEN - 1)
            if va % 8 == 0:
                yield va


def find_identities(memory, limit=4096):
    """``pubkey_adjacency``: proven ``{private: Identity}`` (clamped priv, then its public)."""
    found, tried = {}, {}
    for va in _clamped_candidates(memory):
        blob = memory.read(va, 2 * KEY_LEN)
        if blob is None:
            continue
        private, public = blob[:KEY_LEN], blob[KEY_LEN:]
        if not high_entropy(private) or not high_entropy(public):
            continue
        key = (private, public)
        if key not in tried:
            if len(tried) >= limit:
                break
            tried[key] = x25519.proves_public(private, public)
        if tried[key]:
            found.setdefault(private, Identity(private, public)).addresses.append(va)
    return found


def _handshake_at(memory, address, identity, locator, trusted, layout=LAYOUT):
    remote = memory.read(address, KEY_LEN)
    precomputed = memory.read(address + layout.hs_precomputed, KEY_LEN)
    if remote is None or precomputed is None or not any(remote):
        return None
    handshake = Handshake(address, remote, precomputed, identity, locator, trusted)
    handshake.dh = x25519.dh_consistency(identity.private, remote, precomputed)
    return handshake


def mac1_key(public):
    """``CookieGenerator.mac1.key`` of a peer: BLAKE2s(``"mac1----"`` ‖ its public key)."""
    return noise.precompute_key(noise.LABEL_MAC1, public)


def plausible_peer(memory, address, layout=LAYOUT):
    """Is the back-pointer hit at ``remoteStatic`` = ``address`` really a ``Peer``?

    A ``*Device`` qword also sits in closures, queues and stacks, so a hit is trusted only
    when the shape fits (state, ``isRunning``, keypair slots, keys) AND the peer's own
    ``cookieGenerator.mac1.key`` == BLAKE2s(``"mac1----"`` ‖ ``remoteStatic``) lies within
    ``MAC1_WINDOW`` bytes after it (+352 in wireguard-go 0.0.20250522; searched, not fixed).
    Random bytes behind another back-pointer therefore never become a ``rejected`` peer.
    """
    peer = address + layout.peer_from_remote_static
    state = memory.qword(address + layout.hs_state)
    running = memory.qword(peer)
    remote = memory.read(address, KEY_LEN)
    precomputed = memory.read(address + layout.hs_precomputed, KEY_LEN)
    if state is None or state >= len(HANDSHAKE_STATES) or running not in (0, 1):
        return False
    if remote is None or precomputed is None or not high_entropy(remote):
        return False
    if not x25519.is_canonical_u(remote) or not high_entropy(precomputed):
        return False
    for _slot, offset in layout.peer_keypairs:
        slot = memory.qword(peer + offset)
        if slot is None or (slot and not _pointer(slot)):
            return False
    window = memory.read(address, MAC1_WINDOW) or b""
    return window.find(mac1_key(remote), KEY_LEN) > 0


def find_backpointer_handshakes(memory, identities, layout=LAYOUT):
    """``device_backpointer``: handshakes whose ``Peer.device`` reaches a proven identity copy."""
    handshakes = {}
    for identity in identities.values():
        for copy in identity.addresses:
            device = copy - layout.identity_in_device
            if not _pointer(device):
                continue
            for hit in memory.find_all(struct.pack("<Q", device), limit=4096):
                if hit % 8:
                    continue
                address = hit - layout.hs_device
                if not plausible_peer(memory, address, layout):
                    continue
                handshake = _handshake_at(memory, address, identity, "device_backpointer", True,
                                          layout)
                if handshake is not None:
                    identity.struct_address = copy
                    handshakes[address] = handshake
    return handshakes


ADJACENCY_BLOCK = 4096
# high_entropy() of a 32-byte value needs 19 distinct byte values, so 18 or more non-zero bytes:
# a block whose candidate bytes hold fewer non-zero bytes cannot start a candidate.
ADJACENCY_MIN_NONZERO = 18


def _adjacency_candidates(memory, layout=LAYOUT):
    """``(va, remote, shared)``: 8-aligned high-entropy canonical-looking ``remote`` values with
    a high-entropy value 64 bytes later. Mostly-zero blocks are skipped at C speed."""
    span = layout.hs_precomputed + KEY_LEN
    for start, data in memory.segments:
        stop = len(data) - span + 1
        for block in range((-start) % 8, stop, ADJACENCY_BLOCK):
            end = min(block + ADJACENCY_BLOCK, stop)
            reach = end - 1 + KEY_LEN      # every remote of the block lies in [block, reach)
            if reach - block - data.count(b"\x00", block, reach) < ADJACENCY_MIN_NONZERO:
                continue
            for offset in range(block, end, 8):
                remote = data[offset:offset + KEY_LEN]
                if remote[31] & 0x80 or not high_entropy(remote):
                    continue
                shared = data[offset + layout.hs_precomputed:offset + span]
                if high_entropy(shared):
                    yield start + offset, remote, shared


def find_adjacency_handshakes(memory, identities, layout=LAYOUT,
                              budget=MAX_ADJACENCY_CANDIDATES):
    """Fallback: ``X25519(identity, R@a) == bytes@a+64`` anywhere (untrusted structure).

    One pass over memory tests every identity in ``identities`` (the candidates do not depend
    on the identity); at most ``budget`` candidates are tried. Returns ``[Handshake]`` in
    address order, identities in the given order at one address.
    """
    found = []
    for tried, (address, remote, shared) in enumerate(_adjacency_candidates(memory, layout), 1):
        if tried > budget:
            break
        for identity in identities:
            if x25519.dh_consistency(identity.private, remote, shared):
                handshake = Handshake(address, remote, shared, identity, "adjacency", False)
                handshake.dh = True
                found.append(handshake)
    return found


def _read_key(memory, pointer_va):
    """``(va, key)`` behind an AEAD interface's data word, or ``None``."""
    pointer = memory.qword(pointer_va)
    if not _pointer(pointer):
        return None
    key = memory.read(pointer, KEY_LEN)
    return (pointer, key) if key and any(key) else None


def read_keypairs(memory, handshake, layout=LAYOUT):
    """The ``current``/``previous``/``next`` keypairs of a trusted handshake's ``Peer``."""
    peer = handshake.address + layout.peer_from_remote_static
    keypairs = []
    for slot, offset in layout.peer_keypairs:
        address = memory.qword(peer + offset)
        if not _pointer(address):
            continue
        initiator = memory.read(address + layout.kp_initiator, 1)
        if initiator is None or initiator[0] > 1:
            continue
        send = _read_key(memory, address + layout.kp_send_data)
        recv = _read_key(memory, address + layout.kp_recv_data)
        if send is None and recv is None:
            continue
        keypairs.append(Keypair(slot, address, send, recv, bool(initiator[0]),
                                memory.dword(address + layout.kp_local_index),
                                memory.dword(address + layout.kp_remote_index)))
    return keypairs


def expected_chaining_key(handshake, static_private):
    """``Handshake.chainKey`` recomputed from memory, or ``None`` for states it cannot be.

    ``initiationCreated`` (initiator, ``CreateMessageInitiation``): ``ck0`` mixed with
    ``E_i = e·G``, ``DH(e, S_r)``, ``ss``. ``responseCreated`` (responder,
    ``CreateMessageResponse``): the ``ConsumeMessageInitiation`` chain over ``E_i =
    remoteEphemeral``, ``DH(s, E_i)``, ``ss``, then ``E_r = e·G``, ``DH(e, E_i)``, ``DH(e, S_i)``
    and the PSK (``KDF3``'s first output is ``KDF1``). ``responseConsumed`` keeps no remote
    ephemeral and ``zeroed`` no chaining key, so neither can be recomputed.
    """
    e = handshake.local_ephemeral
    if not e or not any(e):
        return None
    if handshake.state == INITIATION_CREATED:
        return noise.initiation_chaining_key(x25519.public_key(e),
                                       x25519.scalarmult(e, handshake.remote_static),
                                       handshake.precomputed)
    remote_e = handshake.remote_ephemeral
    if handshake.state != RESPONSE_CREATED or not remote_e or not any(remote_e):
        return None
    ck = noise.initiation_chaining_key(remote_e, x25519.scalarmult(static_private, remote_e),
                                 handshake.precomputed)
    for data in (x25519.public_key(e), x25519.scalarmult(e, remote_e),
                 x25519.scalarmult(e, handshake.remote_static), handshake.psk or bytes(KEY_LEN)):
        ck = noise.kdf1(ck, data)
    return ck


def read_handshake_fields(memory, handshake, layout=LAYOUT):
    """State, indices, PSK and ephemerals of a trusted handshake; O_ck on the ephemeral."""
    base = handshake.address
    state = memory.qword(base + layout.hs_state)
    handshake.state = state if state is not None and state < 16 else None
    handshake.local_index = memory.dword(base + layout.hs_local_index)
    handshake.remote_index = memory.dword(base + layout.hs_remote_index)
    handshake.psk = memory.read(base + layout.hs_psk, KEY_LEN)
    handshake.local_ephemeral = memory.read(base + layout.hs_local_ephemeral, KEY_LEN)
    handshake.remote_ephemeral = memory.read(base + layout.hs_remote_ephemeral, KEY_LEN)
    chain_key = memory.read(base + layout.hs_chain_key, KEY_LEN)
    if handshake.dh and chain_key and any(chain_key):
        expected = expected_chaining_key(handshake, handshake.identity.private)
        handshake.ephemeral_proven = expected is not None and expected == chain_key
        handshake.psk_proven = handshake.ephemeral_proven and handshake.state == RESPONSE_CREATED
    handshake.keypairs = read_keypairs(memory, handshake, layout)


def read_device_fields(memory, identity, layout=LAYOUT):
    """``Device.net.port`` / ``fwmark`` of the ``Device`` a trusted back-pointer reached."""
    if identity.device is None:
        return
    port = memory.read(identity.device + layout.device_listen_port, 2)
    identity.listen_port = struct.unpack("<H", port)[0] if port else None
    identity.fwmark = memory.dword(identity.device + layout.device_fwmark)


def device_conflicts(memory, handshakes, identities, layout=LAYOUT):
    """Trusted ``Device`` structs whose private key is a proven one but whose public is not."""
    conflicts = {}
    for handshake in handshakes:
        device = memory.qword(handshake.address + layout.hs_device)
        if not _pointer(device):
            continue
        blob = memory.read(device + layout.identity_in_device, 2 * KEY_LEN)
        if blob and blob[:KEY_LEN] in identities and not x25519.proves_public(blob[:KEY_LEN],
                                                                               blob[KEY_LEN:]):
            conflicts[device + layout.identity_in_device] = blob[:KEY_LEN]
    return conflicts


# --------------------------------------------------------------------------- analysis


def _identity_rows(identities):
    rows = []
    for identity in identities.values():
        where = ("Device.staticIdentity at 0x%x" % identity.struct_address
                 if identity.struct_address is not None else "no Peer.device back-pointer")
        rows.append(Row("static-private", identity.private, identity.addresses, PROVEN_ID,
                        "X25519(private)*G == the public key stored right after it; public %s; "
                        "%s" % (b64(identity.public), where), peer=b"",
                        locator="pubkey_adjacency"))
    return rows


def _psk_row(handshake, common):
    """The PSK slot: ``bound:peer-handshake`` only on a trusted handshake with a proven peer."""
    psk = handshake.psk
    if not psk or not any(psk):
        return []
    if handshake.psk_proven:
        return [Row("preshared", psk, [handshake.address + LAYOUT.hs_psk], PROVEN_CK,
                    "an input of the recomputed Noise chaining key (responseCreated)", **common)]
    if handshake.trusted and handshake.dh:
        return [Row("preshared", psk, [handshake.address + LAYOUT.hs_psk], BOUND_PSK,
                    "no PSK oracle exists: bound to the proven peer of this trusted handshake",
                    **common)]
    why = ("the peer of this handshake is not proven" if handshake.trusted else
           "untrusted structure (adjacency fallback): the PSK slot is only a layout guess")
    return [Row("preshared", psk, [handshake.address + LAYOUT.hs_psk], UNVERIFIED,
                "no PSK oracle exists; %s" % why, **common)]


def _ephemeral_row(handshake, common):
    ephemeral = handshake.local_ephemeral
    if not handshake.trusted or not ephemeral or not any(ephemeral):
        return []
    if handshake.ephemeral_proven:
        proven = PROVEN_CK
        detail = "Noise chaining key recomputed from it (%s)" % handshake.state_name
    else:
        proven = UNVERIFIED
        detail = "handshake %s: the chaining key does not bind it" % handshake.state_name
    return [Row("ephemeral-private", ephemeral, [handshake.address + LAYOUT.hs_local_ephemeral],
                proven, detail, **common)]


def _transport_rows(handshake):
    rows = []
    for keypair in handshake.keypairs:
        for kind, va, key in (("send", keypair.send_va, keypair.send),
                              ("receive", keypair.recv_va, keypair.recv)):
            if key is None:
                continue
            rows.append(Row(kind, key, [va], UNVERIFIED,
                            "%s; Keypair 0x%x slot %s, initiator %s" % (
                                TRANSPORT_NOTE, keypair.address, keypair.slot,
                                keypair.initiator),
                            peer=handshake.remote_static, slot=keypair.slot,
                            local_index=keypair.local_index,
                            remote_index=keypair.remote_index, locator=handshake.locator))
    return rows


def _peer_rows(handshake):
    hs = handshake
    common = dict(peer=hs.remote_static, local_index=hs.local_index,
                  remote_index=hs.remote_index, locator=hs.locator)
    if hs.dh:
        trust = ("trusted structure (Peer.device -> proven identity, O_mac1)" if hs.trusted
                 else "untrusted structure (adjacency fallback)")
        rows = [Row("peer-public", hs.remote_static, [hs.address], PROVEN_DH,
                    "X25519(static_private, remoteStatic) == precomputedStaticStatic; "
                    "handshake %s; %s" % (hs.state_name, trust), **common)]
    else:
        rows = [Row("peer-public", hs.remote_static, [hs.address], REJECTED,
                    "trusted handshake: X25519(static_private, remoteStatic) != "
                    "precomputedStaticStatic", **common)]
    rows += _psk_row(hs, common)
    if hs.dh:
        rows += _ephemeral_row(hs, common) + _transport_rows(hs)
    return rows


def analyze(memory, adjacency_fallback=True):
    """Analyse one process's memory; returns an :class:`Analysis`."""
    identities = find_identities(memory)
    handshakes = find_backpointer_handshakes(memory, identities)
    stats = {"identities": len(identities), "backpointer-handshakes": len(handshakes)}
    if adjacency_fallback:
        reached = {h.identity.private for h in handshakes.values()}
        unreached = [i for i in identities.values() if i.private not in reached]
        if unreached:
            found = find_adjacency_handshakes(memory, unreached)
            stats["adjacency-handshakes"] = len(found)
            for handshake in found:
                handshakes.setdefault(handshake.address, handshake)
    ordered = [handshakes[a] for a in sorted(handshakes)]
    for handshake in ordered:
        if handshake.trusted and handshake.dh is not None:
            read_handshake_fields(memory, handshake)
        elif handshake.dh:
            handshake.psk = memory.read(handshake.address + LAYOUT.hs_psk, KEY_LEN)
    for identity in identities.values():
        read_device_fields(memory, identity)
    rows = _identity_rows(identities)
    for address, private in sorted(device_conflicts(memory, ordered, identities).items()):
        rows.append(Row("static-private", private, [address], REJECTED,
                        "trusted Device.staticIdentity: its public key slot is not "
                        "X25519(private)*G", locator="device_backpointer"))
    for handshake in dedup(ordered):
        rows += _peer_rows(handshake)
    return Analysis(identities, ordered, rows, stats)


def dedup(handshakes):
    """One handshake per (identity, peer, trusted): trusted copies first, then by address."""
    best = {}
    for handshake in handshakes:
        if handshake.dh is None:
            continue
        key = (handshake.identity.private, handshake.remote_static)
        current = best.get(key)
        if current is None or (handshake.trusted and not current.trusted):
            best[key] = handshake
    return sorted(best.values(), key=lambda h: h.address)


def is_wireguard_process(name):
    name = name or ""
    return name in PROCESS_NAMES or name.startswith(PROCESS_PREFIXES)
