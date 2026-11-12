"""Offset tables for the WireGuard module structures (NOT in a vmlinux ISF).

WireGuard is a loadable module on distribution kernels (Ubuntu ships ``wireguard.ko``), so a
symbol table built from ``vmlinux`` debug info never describes ``struct wg_device``,
``wg_peer``, ``noise_handshake``, ``noise_keypair`` ...  The ``linux.wireguard`` plugin reads
them through this table (or a user-supplied ``--offsets`` JSON) and treats every entry as a
*hypothesis*: back-pointers (``wg_device.dev``, ``wg_peer.device``, ``handshake.static_identity``,
``index_hashtable_entry.peer``, ``cookie_checker.device``, ``allowedips_node.peer``) and the
X25519 relations reject a wrong layout, so a bad entry yields fewer rows, never a wrong key.

Stdlib only (``tests/test_vol3plugins_import_rules.py``).

Entry provenance
----------------
``("aarch64", "6.8.0-136-generic")`` -- the Ubuntu 24.04 arm64 kernel of the MemDiver
acquired-secrets capture.  ``wg_device`` / ``wg_peer`` / ``noise_handshake`` / ``noise_keypair``
equal the capture sidecar's ``btf_offsets`` (pahole over ``/sys/kernel/btf/wireguard``); every
other struct (``noise_static_identity``, ``cookie_checker``, ``cookie``, ``noise_keypairs``,
``noise_symmetric_key``, ``index_hashtable_entry``, ``allowedips_node``, ``endpoint``) was read
member by member from the raw ``btf_wireguard.bin`` in the sidecar tarball.  Provenance of
every key of this entry is ``btf``.

``("x86_64", "6.8.0-136-generic")`` -- the Ubuntu 24.04 amd64 capture of the same setup
(``ubuntu-24.04-secrets-x86-4level``).  It was checked with the same split-BTF parser against
that capture's own ``btf_wireguard.bin``: all 11 ``SIDECAR_STRUCTS`` have the same size and the
same ordered member offsets as on aarch64.  Its sidecar ``btf_offsets`` and the
``pahole_*.txt`` text (41 keys) match by name.  The module layout has no arch-dependent member
on 6.8 (cacheline 64, ``mutex`` 32, ``rw_semaphore`` 40 and ``timer_list`` 40 on both), so both
entries share ``_WG_6_8``.  Provenance ``btf``.

Distribution kernels (x86_64, ``_X86_64_DISTRO_KERNELS``) -- for each listed ``uname -r`` the
official package (archive.ubuntu.com, snapshot.debian.org, dl.rockylinux.org / vault.almalinux.org,
kojipkgs.fedoraproject.org) was unpacked; the ``wireguard.ko`` module BTF was read as split BTF on
top of the ``.BTF`` of the vmlinux extracted from the same package's ``vmlinuz``, and all members
of the 11 ``SIDECAR_STRUCTS`` (offsets and sizes) were compared with ``pahole -C`` (v1.30) on the
same files: every one matched.  Layouts sampled across each series' lifetime were constant per
series, but differ between series: Ubuntu 22.04 GA 5.15, Debian 12 6.1 (generic and cloud),
Ubuntu 24.04 GA 6.8 and 24.04 HWE 6.11 equal ``_WG_6_8``; 6.14 and 6.17 / 6.19 / 7.0 move only
``wg_peer.internal_id`` (``napi_struct`` grew); Fedora 7.2 shrinks ``mutex`` / ``rw_semaphore``;
RHEL 9 pads ``timer_list`` and changes ``wg_peer`` again at 9.4, 9.7 and 9.8.  ``6.8.0-90-generic``
(checked, identical to ``_WG_6_8``) is left out on purpose: tests use it as the kernel without an
exact entry.  RHEL 9.0 (``5.14.0-70.*``) ships ``wireguard.ko`` without module BTF and has no entry.

Any other kernel gets the nearest entry with provenance ``derived`` (a guess): the walk still
runs and every locator still validates, but the plugin never labels key material ``proven``
through a derived key-path offset.  ``--offsets`` members are ``offsets``.

``--offsets`` JSON accepted shapes
----------------------------------
* the MemDiver ground-truth sidecar (``*.secrets.json``): ``{"btf_offsets": {"wg_device":
  {"size": 1344, "members": {"dev": {"offset": 0, ...}, ...}}, "wg_peer": {...}, ...}}``;
* a bare ``btf_offsets`` object (same, without the outer key);
* a flat table: ``{"wg_device.dev": 0, ..., "sizeof(wg_device)": 1344}`` or nested
  ``{"wg_device": {"dev": 0, ...}}``.

Structs a document does not describe are filled from the nearest table entry, keeping that
entry's provenance.  On a kernel that has no exact table entry the filled-in keys are
``derived``, and a derived key-path offset means nothing is labelled proven.  For a capture
sidecar to be sufficient by itself, its ``btf_offsets`` must hold pahole/BTF of every struct in
``SIDECAR_STRUCTS``: the seven key-path structs ``wg_device``, ``wg_peer``, ``noise_handshake``,
``noise_keypair``, ``noise_static_identity``, ``noise_keypairs`` and ``noise_symmetric_key``, plus
``cookie_checker``, ``cookie``, ``index_hashtable_entry`` and ``allowedips_node`` (locators only).
``missing_sidecar_structs()`` names the structs a document lacks.

Offsets without an oracle
-------------------------
The PSK (``noise_handshake.preshared_key``) and the transport keys (``noise_keypairs.*``,
``noise_keypair.sending/receiving``, ``noise_symmetric_key.key``) have no memory-only oracle,
so a wrong offset there would go unnoticed.  A user-supplied value on one of these
``NO_ORACLE_KEYS`` keeps ``btf`` provenance only when it equals the built-in BTF entry.
Otherwise it is ``offsets``, and the plugin reports that material ``unverified``
(``untrusted_no_oracle()``).
"""

import json
import logging
import os
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

__all__ = [
    "REQUIRED_KEYS",
    "KEY_PATH_KEYS",
    "NO_ORACLE_KEYS",
    "SIDECAR_STRUCTS",
    "WgOffsets",
    "WG_OFFSETS",
    "lookup_offsets",
    "load_offsets_json",
]

# "type.member" -> offset (6.8, LP64), plus "sizeof(type)".  Only what the plugin reads.
_WG_6_8 = {
    "wg_device.dev": 0, "wg_device.creating_net": 848, "wg_device.static_identity": 856,
    "wg_device.cookie_checker": 992, "wg_device.device_list": 1248, "wg_device.peer_list": 1264,
    "wg_device.num_peers": 1284, "wg_device.fwmark": 1292, "wg_device.incoming_port": 1296,
    "sizeof(wg_device)": 1344,
    "wg_peer.device": 0, "wg_peer.is_dead": 132, "wg_peer.keypairs": 136, "wg_peer.endpoint": 168,
    "wg_peer.handshake": 240, "wg_peer.latest_cookie": 680, "wg_peer.rx_bytes": 848,
    "wg_peer.tx_bytes": 856, "wg_peer.timer_handshake_attempts": 1064,
    "wg_peer.persistent_keepalive_interval": 1068, "wg_peer.walltime_last_handshake": 1072,
    "wg_peer.peer_list": 1112, "wg_peer.allowedips_list": 1128, "wg_peer.internal_id": 1544,
    "sizeof(wg_peer)": 1552,
    "noise_handshake.entry": 0, "noise_handshake.state": 32, "noise_handshake.static_identity": 48,
    "noise_handshake.ephemeral_private": 56, "noise_handshake.remote_static": 88,
    "noise_handshake.remote_ephemeral": 120, "noise_handshake.precomputed_static_static": 152,
    "noise_handshake.preshared_key": 184, "noise_handshake.hash": 216,
    "noise_handshake.chaining_key": 248, "noise_handshake.remote_index": 292,
    "noise_keypair.entry": 0, "noise_keypair.sending": 32, "noise_keypair.sending_counter": 80,
    "noise_keypair.receiving": 88, "noise_keypair.remote_index": 1176,
    "noise_keypair.i_am_the_initiator": 1180, "noise_keypair.internal_id": 1208,
    "noise_keypairs.current_keypair": 0, "noise_keypairs.previous_keypair": 8,
    "noise_keypairs.next_keypair": 16,
    "noise_symmetric_key.key": 0, "noise_symmetric_key.birthdate": 32,
    "noise_symmetric_key.is_valid": 40,
    "index_hashtable_entry.peer": 0, "index_hashtable_entry.type": 24,
    "index_hashtable_entry.index": 28,
    "noise_static_identity.static_public": 0, "noise_static_identity.static_private": 32,
    "noise_static_identity.has_identity": 104,
    "cookie_checker.cookie_encryption_key": 32, "cookie_checker.message_mac1_key": 64,
    "cookie_checker.device": 144,
    "cookie.birthdate": 0, "cookie.is_valid": 8, "cookie.cookie_decryption_key": 42,
    "cookie.message_mac1_key": 74,
    "allowedips_node.peer": 0, "allowedips_node.cidr": 24, "allowedips_node.bitlen": 27,
    "allowedips_node.bits": 32, "allowedips_node.peer_list": 56,
}

REQUIRED_KEYS = tuple(sorted(_WG_6_8))

# Offsets a key byte is read through: a ``derived`` one here never yields ``proven``.
KEY_PATH_KEYS = frozenset({
    "wg_device.static_identity", "noise_static_identity.static_public",
    "noise_static_identity.static_private", "wg_peer.handshake", "wg_peer.keypairs",
    "noise_handshake.ephemeral_private", "noise_handshake.remote_static",
    "noise_handshake.precomputed_static_static", "noise_handshake.preshared_key",
    "noise_handshake.chaining_key", "noise_keypairs.current_keypair",
    "noise_keypairs.previous_keypair", "noise_keypairs.next_keypair",
    "noise_keypair.sending", "noise_keypair.receiving", "noise_symmetric_key.key",
})


# Key-path offsets no oracle checks: a non-BTF value here is never trusted (see module doc).
NO_ORACLE_KEYS = frozenset({
    "noise_handshake.preshared_key", "wg_peer.keypairs", "noise_keypairs.current_keypair",
    "noise_keypairs.previous_keypair", "noise_keypairs.next_keypair", "noise_keypair.sending",
    "noise_keypair.receiving", "noise_symmetric_key.key",
})

# Provenance values backed by a built-in BTF entry ("btf-confirmed": a user value equal to it)
# or by the kernel's own BTF read from the image ("btf-memory", see ``from_memory``).
MEMORY_SOURCE = "btf-memory"
BTF_SOURCES = frozenset({"btf", "btf-confirmed", MEMORY_SOURCE})

# The pahole/BTF structs a capture sidecar needs so that it alone supplies every offset.
SIDECAR_STRUCTS = ("wg_device", "wg_peer", "noise_handshake", "noise_keypair",
                   "noise_static_identity", "noise_keypairs", "noise_symmetric_key",
                   "cookie_checker", "cookie", "index_hashtable_entry", "allowedips_node")


@dataclass(frozen=True)
class WgOffsets:
    """``"type.member" -> offset`` and, per key, where it came from (btf|offsets|derived)."""

    members: Dict[str, int]
    sources: Dict[str, str] = field(default_factory=dict)
    source: str = "table"

    def __getitem__(self, key: str) -> int:
        return self.members[key]

    def missing(self) -> Tuple[str, ...]:
        return tuple(k for k in REQUIRED_KEYS if k not in self.members)

    def key_path_guessed(self) -> Tuple[str, ...]:
        return tuple(sorted(k for k in KEY_PATH_KEYS if self.sources.get(k, "derived") == "derived"))

    def untrusted_no_oracle(self, prefix: str = "") -> Tuple[str, ...]:
        """``NO_ORACLE_KEYS`` (starting with ``prefix``) whose value is not BTF-confirmed."""
        return tuple(sorted(k for k in NO_ORACLE_KEYS
                            if k.startswith(prefix) and self.sources.get(k, "derived") not in BTF_SOURCES))

    def missing_sidecar_structs(self) -> Tuple[str, ...]:
        """``SIDECAR_STRUCTS`` none of whose members came from ``--offsets``."""
        given = {k.split(".", 1)[0] for k, v in self.sources.items()
                 if v in ("offsets", "btf-confirmed") and "." in k}
        return tuple(s for s in SIDECAR_STRUCTS if s not in given)


def _entry(members: Dict[str, int], provenance: str, source: str) -> WgOffsets:
    return WgOffsets(dict(members), {k: provenance for k in members}, source)


WG_OFFSETS: Dict[Tuple[str, str], WgOffsets] = {
    ("aarch64", "6.8.0-136-generic"): _entry(
        _WG_6_8, "btf", "btf:wireguard aarch64 6.8.0-136-generic (sidecar pahole + raw BTF)"),
    ("x86_64", "6.8.0-136-generic"): _entry(
        _WG_6_8, "btf", "btf:wireguard x86_64 6.8.0-136-generic (raw BTF, all 11 structs; pahole-checked)"),
}

# Distribution x86_64 kernels (see "Distribution kernels" in the module doc).  Only ``wg_peer`` and,
# from 7.2 on, the lock sizes move; every other read offset equals ``_WG_6_8``.
_WG_EL9_PEER = {  # RHEL 9 timer_list is 56 bytes (kABI padding), so wg_peer shifts after the timers
    "wg_peer.timer_handshake_attempts": 1144, "wg_peer.persistent_keepalive_interval": 1148,
    "wg_peer.walltime_last_handshake": 1152, "wg_peer.peer_list": 1192,
    "wg_peer.allowedips_list": 1208,
}
_WG_EL9_1 = dict(_WG_6_8, **_WG_EL9_PEER, **{"wg_peer.internal_id": 1640, "sizeof(wg_peer)": 1648})
_WG_EL9_4 = dict(_WG_6_8, **_WG_EL9_PEER, **{"wg_peer.internal_id": 1672, "sizeof(wg_peer)": 1680})
_WG_EL9_7 = dict(_WG_6_8, **_WG_EL9_PEER, **{"wg_peer.internal_id": 1696, "sizeof(wg_peer)": 1704})
_WG_EL9_8 = dict(_WG_6_8, **_WG_EL9_PEER, **{"wg_peer.internal_id": 1760, "sizeof(wg_peer)": 1768})
_WG_6_14 = dict(_WG_6_8, **{"wg_peer.internal_id": 1576, "sizeof(wg_peer)": 1584})  # napi_struct grew
_WG_6_17 = dict(_WG_6_8, **{"wg_peer.internal_id": 1640, "sizeof(wg_peer)": 1648})
_WG_7_2 = dict(_WG_6_8, **{  # mutex 32 -> 24 and rw_semaphore 40 -> 32 bytes
    "wg_device.cookie_checker": 984, "wg_device.device_list": 1216, "wg_device.peer_list": 1232,
    "wg_device.num_peers": 1252, "wg_device.fwmark": 1260, "wg_device.incoming_port": 1264,
    "sizeof(wg_device)": 1280, "wg_peer.latest_cookie": 672, "wg_peer.rx_bytes": 832,
    "wg_peer.tx_bytes": 840, "wg_peer.timer_handshake_attempts": 1048,
    "wg_peer.persistent_keepalive_interval": 1052, "wg_peer.walltime_last_handshake": 1056,
    "wg_peer.peer_list": 1096, "wg_peer.allowedips_list": 1112, "wg_peer.internal_id": 1640,
    "sizeof(wg_peer)": 1648, "noise_static_identity.has_identity": 96, "cookie_checker.device": 136,
})

# members dict -> the exact ``uname -r`` strings whose official wireguard.ko gave it (pahole-checked).
_X86_64_DISTRO_KERNELS = (
    (_WG_6_8, (  # Ubuntu 22.04 GA, Debian 12 (generic + cloud), Ubuntu 24.04 GA / 22.04 HWE, 24.04 HWE 6.11
        "5.15.0-25-generic", "5.15.0-72-generic", "5.15.0-100-generic", "5.15.0-131-generic",
        "5.15.0-160-generic", "5.15.0-203-generic",
        "6.1.0-9-amd64", "6.1.0-18-amd64", "6.1.0-28-amd64", "6.1.0-37-amd64", "6.1.0-47-amd64",
        "6.1.0-54-amd64", "6.1.0-9-cloud-amd64", "6.1.0-28-cloud-amd64", "6.1.0-54-cloud-amd64",
        "6.8.0-31-generic", "6.8.0-40-generic", "6.8.0-41-generic", "6.8.0-53-generic",
        "6.8.0-71-generic", "6.8.0-100-generic", "6.8.0-117-generic", "6.8.0-149-generic",
        "6.11.0-29-generic")),
    (_WG_6_14, ("6.14.0-37-generic",)),
    (_WG_6_17, (  # Ubuntu 24.04 HWE 6.17 / 7.0, Fedora 41-44 (6.17, 6.19)
        "6.17.0-14-generic", "6.17.0-29-generic", "6.17.0-44-generic",
        "7.0.0-14-generic", "7.0.0-30-generic", "7.0.0-43-generic",
        "6.17.10-100.fc41.x86_64", "6.19.14-108.fc42.x86_64", "6.17.1-300.fc43.x86_64",
        "6.19.10-300.fc44.x86_64")),
    (_WG_7_2, ("7.2.15-100.fc43.x86_64", "7.2.15-200.fc44.x86_64", "7.2.11-300.fc45.x86_64",
               "7.2.15-300.fc45.x86_64")),
    (_WG_EL9_1, ("5.14.0-162.6.1.el9_1.x86_64", "5.14.0-162.23.1.el9_1.x86_64",
                 "5.14.0-284.11.1.el9_2.x86_64", "5.14.0-284.30.1.el9_2.x86_64",
                 "5.14.0-362.8.1.el9_3.x86_64", "5.14.0-362.24.1.el9_3.x86_64")),
    (_WG_EL9_4, ("5.14.0-427.13.1.el9_4.x86_64", "5.14.0-427.16.1.el9_4.x86_64",
                 "5.14.0-427.42.1.el9_4.x86_64", "5.14.0-503.11.1.el9_5.x86_64",
                 "5.14.0-503.14.1.el9_5.x86_64", "5.14.0-503.40.1.el9_5.x86_64",
                 "5.14.0-570.12.1.el9_6.x86_64", "5.14.0-570.18.1.el9_6.x86_64",
                 "5.14.0-570.58.1.el9_6.x86_64")),
    (_WG_EL9_7, ("5.14.0-611.5.1.el9_7.x86_64", "5.14.0-611.55.1.el9_7.x86_64")),
    (_WG_EL9_8, ("5.14.0-687.5.1.el9_8.x86_64", "5.14.0-687.12.1.el9_8.x86_64",
                 "5.14.0-687.66.1.el9_8.x86_64")),
)

for _members, _kvers in _X86_64_DISTRO_KERNELS:
    for _kver in _kvers:
        WG_OFFSETS.setdefault(("x86_64", _kver), _entry(
            _members, "btf", "btf:wireguard x86_64 %s (module BTF; pahole-checked)" % _kver))
del _members, _kvers, _kver


def _version_key(kver: str) -> Tuple[Tuple[int, Any], ...]:
    """Natural sort key: ``6.8.0-100`` after ``6.8.0-99`` (digit runs compare as numbers)."""
    return tuple((0, int(part)) if part.isdigit() else (1, part) for part in re.findall(r"\d+|\D+", kver))


def _nearest_first(entries: List[Tuple[Tuple[str, str], WgOffsets]], kver: str
                   ) -> List[Tuple[Tuple[str, str], WgOffsets]]:
    """Entries by version distance: newest release <= ``kver`` first (descending), then the
    releases above it (ascending); ties keep arch order."""
    ordered = sorted(entries, key=lambda e: (_version_key(e[0][1]), e[0][0]))
    wanted = _version_key(kver)
    below = [e for e in ordered if _version_key(e[0][1]) <= wanted]
    above = [e for e in ordered if _version_key(e[0][1]) > wanted]
    return below[::-1] + above


def _series(kver: str) -> str:
    return ".".join(kver.split("-")[0].split(".")[:2])


def lookup_offsets(arch: str, kver: str) -> Optional[WgOffsets]:
    """Exact ``(arch, kver)`` entry (``btf``), else the nearest entry relabelled ``derived``.

    Nearest = same arch and series, then any arch same series, then any entry: the module's
    structs are LP64-stable across 6.x, and the locators reject a wrong guess.
    """
    hidden = _table_hidden()
    if (arch, kver) in WG_OFFSETS and not hidden:
        return WG_OFFSETS[(arch, kver)]
    entries = _nearest_first([e for e in WG_OFFSETS.items() if not (hidden and e[0][1] == kver)], kver)
    ranked = ([e for e in entries if e[0][0] == arch and _series(e[0][1]) == _series(kver)]
              + [e for e in entries if _series(e[0][1]) == _series(kver)] + entries)
    if not ranked:
        return None
    (entry_arch, entry_kver), entry = ranked[0]
    return _entry(entry.members, "derived",
                  "derived from %s %s for %s %s: %s" % (entry_arch, entry_kver, arch, kver, entry.source))


def _valid_offset(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and 0 <= value < 1 << 16


def _struct_members(type_name: str, table: Any) -> Dict[str, int]:
    """``{"size": n, "members": {m: {"offset": o}}}`` or ``{m: o}`` -> flat ``type.member`` keys."""
    if not isinstance(table, dict):
        return {}
    result = {}
    if _valid_offset(table.get("size")):
        result["sizeof(%s)" % type_name] = table["size"]
    members = table.get("members", table)
    for name, value in members.items() if isinstance(members, dict) else ():
        offset = value.get("offset") if isinstance(value, dict) else value
        if name != "size" and _valid_offset(offset):
            result["%s.%s" % (type_name, name)] = offset
    return result


def _flatten(document: Dict[str, Any]) -> Dict[str, int]:
    flat: Dict[str, int] = {}
    for key, value in document.items():
        if "." in key or key.startswith("sizeof("):
            if _valid_offset(value):
                flat[key] = value
        elif isinstance(value, dict):
            flat.update(_struct_members(key, value))
    return flat


def load_offsets_json(text: str, source: str = "--offsets", base: Optional[WgOffsets] = None) -> WgOffsets:
    """Parse an ``--offsets`` document (see module doc); raises ``ValueError`` when unusable.

    Keys the document lacks come from ``base`` (the table entry for the image) with ``base``'s
    provenance; the document's own keys are labelled ``offsets``.
    """
    document = json.loads(text)
    if not isinstance(document, dict):
        raise ValueError("offsets JSON must be an object")
    document = document.get("btf_offsets", document)
    if not isinstance(document, dict):
        raise ValueError("btf_offsets must be an object")
    given = {k: v for k, v in _flatten(document).items() if k in _WG_6_8}
    if not given:
        raise ValueError("offsets JSON describes no WireGuard struct member the plugin reads")
    members = dict(base.members) if base else {}
    sources = dict(base.sources) if base else {}
    members.update(given)
    for key, value in given.items():  # a value equal to a BTF table entry stays BTF-backed
        confirmed = base is not None and base.sources.get(key) in ("btf", MEMORY_SOURCE) \
            and base.members.get(key) == value
        sources[key] = "btf-confirmed" if confirmed else "offsets"
    offsets = WgOffsets(members, sources, "%s (%d keys; rest: %s)" % (
        source, len(given), base.source if base else "none"))
    if offsets.missing():
        raise ValueError("offsets JSON lacks: %s" % ", ".join(offsets.missing()))
    return offsets


# --------------------------------------------------------------------------- in-memory BTF

# TEST-ONLY switch: ``MEMDIVER_TEST_HIDE_OFFSET_TABLE=1`` makes ``lookup_offsets`` ignore every entry of
# the image's own kernel release (as if it were not in the table).  Read at call time.
HIDE_TABLE_ENV = "MEMDIVER_TEST_HIDE_OFFSET_TABLE"


_TABLE_HIDDEN_WARNED = []


def _table_hidden() -> bool:
    """True when the test-only switch is set; logs one WARNING the first time it is seen."""
    hidden = os.environ.get(HIDE_TABLE_ENV, "") not in ("", "0")
    if hidden and not _TABLE_HIDDEN_WARNED:
        _TABLE_HIDDEN_WARNED.append(True)
        logging.getLogger(__name__).warning(
            "%s is set (TEST ONLY): built-in offset entries of the image's kernel release are ignored", HIDE_TABLE_ENV)
    return hidden


def from_memory(members: Dict[str, int], source: str) -> Optional[WgOffsets]:
    """``WgOffsets`` from layouts read out of the image's own wireguard BTF.

    ``members`` is ``btf_memory.RecoveredLayouts.members`` of a TRUSTED recovery.  Every
    ``REQUIRED_KEYS`` entry must be present, else None (partial coverage is never used).  Each
    key gets provenance ``btf-memory``, which counts like a built-in BTF entry.
    """
    if any(k not in members for k in REQUIRED_KEYS):
        return None
    return _entry({k: members[k] for k in REQUIRED_KEYS}, MEMORY_SOURCE, source)


def differences(memory: WgOffsets, table: Optional[WgOffsets]) -> Tuple[str, ...]:
    """``"key: memory M != table T"`` for every key where the two disagree."""
    if table is None:
        return ()
    return tuple("%s: memory %d != table %d" % (k, memory.members[k], table.members[k])
                 for k in REQUIRED_KEYS
                 if k in memory.members and k in table.members and memory.members[k] != table.members[k])


def choose_offsets(memory: Optional[WgOffsets], table: Optional[WgOffsets]
                   ) -> Tuple[Optional[WgOffsets], Tuple[str, ...]]:
    """Trusted memory BTF > exact table entry > derived: ``(chosen, differences vs the table)``."""
    if memory is None:
        return table, ()
    return memory, differences(memory, table)
