"""``memdiver.ssh.SSHKeys``: SSH session keys of several implementations, with proof tiers.

Usage::

    vol -p <vol3plugins> -f client.msl memdiver.ssh.SSHKeys            # a .msl process slice
    vol -p <vol3plugins> -f image.lime memdiver.ssh.SSHKeys --pid 9929  # a Linux image
    vol -p <vol3plugins> -f image.lime memdiver.ssh.SSHKeys            # every ssh/sshd/dropbear

Each row is one key, IV or MAC key with its ``Tier`` and ``Proven`` verdict
(``ssh_engine`` documents the tiers):

* Tier ``A`` -- ``oracle:ssh-kdf-consistency``: K/H/session_id found in the process and at
  least two RFC 4253 keys derived from them found in the same memory (Go x/crypto/ssh,
  Paramiko, libssh, wolfSSH, or any implementation whose encoded K is still resident).
* Tier ``B`` -- ``unverified``: OpenSSH ``newkeys``/``sshenc`` structure validated.
* Tier ``C`` -- ``unverified``: a ChaCha20 state pair or an AES schedule (Dropbear, libssh2).
* ``rejected`` -- only from a trusted Tier A struct whose K does not derive its own keys.

The plugin reads only the process's writable mappings unless ``--all-regions`` is given
(keys never live in read-only file mappings), at most ``--max-mb`` MiB per process.
``--export json`` writes ``ssh_keys.json``; ``--export keylog`` writes
``ssh_keys.newkeys.log`` in the OpenSSH keylog-patch format used by the KeyLifespan rigs
(``<ts> NEWKEYS MODE IN|OUT CIPHER <name> KEY <hex> IV <hex|unknown>``), proven keys only
unless ``--export-unverified``.

It needs neither MemDiver nor a crypto library: ``hashlib`` does the KDF.
"""
import json
import logging
import time
from typing import List

from volatility3.framework import interfaces, renderers
from volatility3.framework.configuration import requirements
from volatility3.framework.renderers import format_hints

from . import process_scope
from . import ssh_engine

vollog = logging.getLogger(__name__)

IMPLEMENTATIONS = ["auto", "openssh", "dropbear", "libssh", "wolfssh", "paramiko", "go"]
SSH_PROCESS_NAMES = frozenset(ssh_engine.SERVER_NAMES + ssh_engine.CLIENT_NAMES)


def is_ssh_process(name: str) -> bool:
    """The default ``--pid``-less selection on an image: every ssh/sshd/dropbear task."""
    return name in SSH_PROCESS_NAMES


class SSHKeys(interfaces.plugins.PluginInterface):
    """Recovers SSH session keys from processes and proves them from memory (tiers A/B/C)."""

    _required_framework_version = (2, 0, 0)
    _version = (1, 0, 0)

    @classmethod
    def get_requirements(cls) -> List[interfaces.configuration.RequirementInterface]:
        return process_scope.target_requirements(
            "Process IDs (default on an image: every ssh/sshd/dropbear)") + [
            requirements.ChoiceRequirement(
                name="implementation", choices=IMPLEMENTATIONS, optional=True, default="auto",
                description="Only run the locators of one implementation"),
        ] + process_scope.read_requirements() + [
            requirements.BooleanRequirement(
                name="show_unbound", optional=True, default=False,
                description="Also list AES schedules that no SSH structure binds (tier C)"),
            requirements.ChoiceRequirement(
                name="export", choices=["json", "keylog"], optional=True,
                description="Write ssh_keys.json or an OpenSSH NEWKEYS keylog"),
            requirements.BooleanRequirement(
                name="export_unverified", optional=True, default=False,
                description="Also export keys that are not proven"),
        ]

    # ------------------------------------------------------------------ output

    def _analyse(self):
        results = []
        for target in process_scope.targets(self.context, self.config, "memdiver.ssh",
                                            is_ssh_process):
            began = time.time()
            memory = ssh_engine.Memory(process_scope.target_segments(self.context, self.config,
                                                                     target))
            analysis = ssh_engine.analyze(memory, target.name,
                                          self.config.get("implementation") or "auto",
                                          bool(self.config.get("show_unbound")))
            vollog.info("memdiver.ssh: pid %s (%s) %.1f MiB read, %d rows, %s, %.1f s",
                        target.pid, target.name, memory.size / 1048576.0, len(analysis.rows),
                        analysis.stats, time.time() - began)
            results.append((target, analysis))
        return results

    def _exportable(self, row) -> bool:
        return row.proven == ssh_engine.PROVEN or (
            row.proven == ssh_engine.UNVERIFIED and bool(self.config.get("export_unverified")))

    def _export(self, results) -> None:
        mode = self.config.get("export")
        if mode == "json":
            document = [{"pid": t.pid, "process": t.name, "scope": t.scope, "stats": a.stats,
                         "rows": [r.as_dict() for r in a.rows if self._exportable(r)]}
                        for t, a in results]
            process_scope.write_text(self, "ssh_keys.json",
                                     json.dumps(document, indent=1, sort_keys=True))
        elif mode == "keylog":
            lines = ["# memdiver.ssh NEWKEYS keylog (OpenSSH keylog-patch format)"]
            stamp = int(time.time())
            for target, analysis in results:
                rows = [r for r in analysis.rows if self._exportable(r)]
                body = ssh_engine.openssh_newkeys_lines(rows, stamp)
                lines.append("# pid %s %s: %d line(s)" % (target.pid, target.name, len(body)))
                lines.extend(body)
            process_scope.write_text(self, "ssh_keys.newkeys.log", "\n".join(lines) + "\n")

    def _generator(self, results):
        for target, analysis in results:
            for row in analysis.rows:
                address = row.addresses[0] if row.addresses else 0
                yield 0, (
                    int(target.pid) if target.pid is not None else -1,
                    target.name or "-",
                    row.implementation,
                    row.tier,
                    row.direction,
                    row.kind + (("/" + row.letter) if row.letter else ""),
                    row.cipher,
                    row.key.hex(),
                    len(row.key),
                    format_hints.Hex(address),
                    len(row.addresses),
                    row.proven,
                    target.scope,
                    row.detail,
                )

    def run(self):
        results = self._analyse()
        if self.config.get("export"):
            self._export(results)
        columns = [("PID", int), ("Process", str), ("Implementation", str), ("Tier", str),
                   ("Direction", str), ("Kind", str), ("Cipher", str), ("KeyHex", str),
                   ("Length", int), ("Address", format_hints.Hex), ("Copies", int),
                   ("Proven", str), ("Scope", str), ("Detail", str)]
        return renderers.TreeGrid(columns, self._generator(results))
