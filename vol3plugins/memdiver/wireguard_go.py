"""``memdiver.wireguard_go.WireGuardGo``: WireGuard keys of userspace wireguard-go, proven.

Usage::

    vol -p <vol3plugins> -f wg.msl memdiver.wireguard_go.WireGuardGo              # a .msl slice
    vol -p <vol3plugins> -f image.lime memdiver.wireguard_go.WireGuardGo --pid 812
    vol -p <vol3plugins> -f image.lime memdiver.wireguard_go.WireGuardGo           # every
                                                    # wireguard-go / tailscaled / com.wireguard*

Covers every program built on wireguard-go's ``device`` package (the ``wireguard-go`` daemon,
Tailscale, wireguard-android's ``libwg-go``, wireguard-apple's ``WireGuardKitGo``).
``wireguard_go_engine`` documents the structures, locators and proofs. Rows:

* ``static-private`` -- ``oracle:x25519-pubkey``: ``X25519(private)·G`` equals the public key
  that wireguard-go stores right after it (``Device.staticIdentity``).
* ``peer-public`` -- ``oracle:x25519-dh-consistency``: ``X25519(static_private, remoteStatic)
  == precomputedStaticStatic`` of the peer's handshake.
* ``ephemeral-private`` -- ``oracle:noise-chaining-key`` for a handshake caught in
  ``initiationCreated`` (chaining key recomputed), else ``unverified``.
* ``preshared`` -- ``bound:peer-handshake`` (no PSK oracle exists: bound to a proven peer of a
  trusted handshake only), else ``unverified``.
* ``send`` / ``receive`` -- transport keys, ALWAYS ``unverified`` (no memory-only oracle).
* ``rejected`` -- only from a trusted structure that contradicts its own proof.

``--export json`` writes ``wireguard_go.json``; ``--export showconf`` one
``wireguard_go.<pid>.<n>.conf`` per identity in ``wg showconf`` format (private key, listen port,
fwmark, peers and bound PSKs; endpoints and allowed IPs are not read); ``--export keylog``
writes ``wireguard_go.keylog`` in the Wireshark grammar of ``linux.wireguard`` (same writer)
plus ``wireguard_go.wg-transport.json`` (transport keys are never proven: their key fields are
null without ``--export-unverified``). Exports hold proven/bound material only unless
``--export-unverified``.

It needs neither MemDiver nor a crypto library (``cryptography`` only speeds X25519 up).
"""
import json
import logging
import time
from typing import Any, Dict, List

from volatility3.framework import interfaces, renderers
from volatility3.framework.configuration import requirements
from volatility3.framework.renderers import format_hints

from . import process_scope
from . import wireguard_go_engine as engine
from ..linux import wireguard as kernel_wg

vollog = logging.getLogger(__name__)

EXPORTABLE = (engine.PROVEN_ID, engine.PROVEN_DH, engine.PROVEN_CK, engine.BOUND_PSK)


class WireGuardGo(interfaces.plugins.PluginInterface):
    """Recovers wireguard-go static, peer, PSK and transport keys and proves them from memory."""

    _required_framework_version = (2, 0, 0)
    _version = (1, 0, 0)

    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        return process_scope.target_requirements(
            "Process IDs (default on an image: wireguard-go, tailscaled, "
            "com.wireguard*)") + process_scope.read_requirements() + [
            requirements.BooleanRequirement(
                name="no_fallback", optional=True, default=False,
                description="Skip the layout-free adjacency search for handshakes that no "
                            "Peer.device back-pointer reaches"),
            requirements.ChoiceRequirement(
                name="export", choices=["json", "showconf", "keylog"], optional=True,
                description="Write wireguard_go.json, wg showconf files or a Wireshark keylog"),
            requirements.BooleanRequirement(
                name="export_unverified", optional=True, default=False,
                description="Also export material that is not proven"),
        ]

    # ------------------------------------------------------------------ analysis

    def _analyse(self):
        results = []
        for target in process_scope.targets(self.context, self.config, "memdiver.wireguard_go",
                                            engine.is_wireguard_process):
            began = time.time()
            memory = engine.Memory(process_scope.target_segments(self.context, self.config,
                                                                 target))
            analysis = engine.analyze(memory, not self.config.get("no_fallback"))
            vollog.info("memdiver.wireguard_go: pid %s (%s) %.1f MiB read, %d rows, %s, %.1f s",
                        target.pid, target.name, memory.size / 1048576.0, len(analysis.rows),
                        analysis.stats, time.time() - began)
            results.append((target, analysis))
        return results

    # ------------------------------------------------------------------ exports

    def _exportable(self, row) -> bool:
        return row.proven in EXPORTABLE or (
            row.proven == engine.UNVERIFIED and bool(self.config.get("export_unverified")))

    def _include(self, kind: str, record: Any) -> bool:
        """The ``linux.wireguard`` writers' gate (``record`` carries the engine verdict)."""
        if self.config.get("export_unverified"):
            return True
        if kind == "psk":  # bound only on a trusted handshake whose peer is proven
            return bool(record.memdiver_handshake.trusted and record.memdiver_handshake.dh)
        return record.memdiver_proven in EXPORTABLE

    def _interfaces(self, target, analysis) -> List[Any]:
        """One ``linux.wireguard`` ``Interface`` per identity, for its showconf/keylog writers."""
        result = []
        for index, identity in enumerate(analysis.identities.values()):
            kid = kernel_wg.Identity(identity.address, identity.public, identity.private, True)
            kid.memdiver_proven = engine.PROVEN_ID
            iface = kernel_wg.Interface(
                name="%s-%d" % (target.name or "wireguard-go", index), netns=target.pid,
                ifindex=None, net_device=0, address=identity.device or 0,
                listen_port=identity.listen_port or 0, fwmark=identity.fwmark or 0,
                num_peers=0, origin="wireguard-go", identity=kid)
            for handshake in engine.dedup(analysis.handshakes):
                if handshake.identity is identity and handshake.dh:
                    iface.peers.append(self._kernel_peer(handshake))
            result.append(iface)
        return result

    @staticmethod
    def _kernel_peer(handshake):
        peer = kernel_wg.Peer(
            address=handshake.address, remote_static=handshake.remote_static,
            psk=handshake.psk, precomputed=handshake.precomputed,
            ephemeral=handshake.local_ephemeral, remote_ephemeral=None, chaining_key=None,
            state=handshake.state, local_index=handshake.local_index,
            remote_index=handshake.remote_index)
        peer.memdiver_proven = engine.PROVEN_DH
        peer.memdiver_ephemeral_proven = handshake.ephemeral_proven
        peer.memdiver_handshake = handshake
        return peer

    def _keylog(self, results) -> List[str]:
        lines = ["# memdiver.wireguard_go keylog (Wireshark WireGuard key log format)"]
        for target, analysis in results:
            for iface in self._interfaces(target, analysis):
                if not iface.peers:
                    lines.append("# pid %s %s: no proven peer, static key in the json/showconf "
                                 "exports" % (target.pid, iface.name))
                for peer in iface.peers:
                    ephemeral = kernel_wg.nonzero(peer.ephemeral) and (
                        peer.memdiver_ephemeral_proven or self.config.get("export_unverified"))
                    lines += kernel_wg.keylog_lines(iface, peer, bool(ephemeral),
                                                    self._include("psk", peer))
        return lines

    def _transport(self, results) -> Dict[str, Any]:
        keys = bool(self.config.get("export_unverified"))
        entries = []
        for target, analysis in results:
            for handshake in engine.dedup(analysis.handshakes):
                for kp in handshake.keypairs:
                    entries.append({
                        "pid": target.pid, "peer": engine.b64(handshake.remote_static),
                        "slot": kp.slot, "keypair": kp.address, "local_index": kp.local_index,
                        "remote_index": kp.remote_index, "initiator": kp.initiator,
                        "send_key": engine.b64(kp.send) if keys and kp.send else None,
                        "recv_key": engine.b64(kp.recv) if keys and kp.recv else None,
                        "status": engine.UNVERIFIED})
        return {"note": engine.TRANSPORT_NOTE + ("" if keys else
                                                 "; key fields need --export-unverified"),
                "keypairs": entries}

    def _json(self, results) -> List[Dict[str, Any]]:
        return [{"pid": t.pid, "process": t.name, "scope": t.scope, "stats": a.stats,
                 "layout": engine.LAYOUT.name,
                 "devices": [{"device": i.device, "listen_port": i.listen_port,
                              "fwmark": i.fwmark, "public_key": engine.b64(i.public)}
                             for i in a.identities.values()],
                 "rows": [r.as_dict(self._exportable(r)) for r in a.rows]}
                for t, a in results]

    def _export(self, results) -> None:
        mode = self.config.get("export")
        if mode == "json":
            process_scope.write_text(self, "wireguard_go.json",
                                     json.dumps(self._json(results), indent=1, sort_keys=True))
        elif mode == "keylog":
            process_scope.write_text(self, "wireguard_go.keylog",
                                     "\n".join(self._keylog(results)) + "\n")
            process_scope.write_text(self, "wireguard_go.wg-transport.json",
                                     json.dumps(self._transport(results), indent=1))
        elif mode == "showconf":
            for target, analysis in results:
                for index, iface in enumerate(self._interfaces(target, analysis)):
                    process_scope.write_text(self, "wireguard_go.%s.%d.conf" % (target.pid, index),
                                             kernel_wg.showconf(iface, self._include))

    # ------------------------------------------------------------------ output

    def _generator(self, results):
        for target, analysis in results:
            for row in analysis.rows:
                yield 0, (
                    int(target.pid) if target.pid is not None else -1,
                    target.name or "-",
                    row.kind,
                    engine.b64(row.key),
                    engine.b64(row.peer) or "-",
                    row.slot or "-",
                    format_hints.Hex(row.local_index if row.local_index is not None else 0),
                    format_hints.Hex(row.remote_index if row.remote_index is not None else 0),
                    format_hints.Hex(row.addresses[0] if row.addresses else 0),
                    len(row.addresses),
                    row.proven,
                    row.locator,
                    target.scope,
                    row.detail,
                )

    def run(self):
        results = self._analyse()
        if self.config.get("export"):
            self._export(results)
        columns = [("PID", int), ("Process", str), ("Kind", str), ("Key", str), ("Peer", str),
                   ("Slot", str), ("LocalIndex", format_hints.Hex),
                   ("RemoteIndex", format_hints.Hex), ("Address", format_hints.Hex),
                   ("Copies", int), ("Proven", str), ("Locator", str), ("Scope", str),
                   ("Detail", str)]
        return renderers.TreeGrid(columns, self._generator(results))
