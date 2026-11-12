"""Rebuild the in-repo wireguard-go PRESHARED-KEY sample from the WireGuard key-lifecycle corpus.

Judges never need to run this (the output is committed, see ``SHA256SUMS``). It needs MemDiver
and the private corpus (``MEMDIVER_WG_GO_CORPUS`` = the rig's ``archive`` directory); run it from
the repository root::

    MEMDIVER_WG_GO_CORPUS=/abs/WireGuard/archive python samples/build_wireguard_go_psk_sample.py

It takes the responder's ``pre_keys_installed`` dump of ``run_20261112_124707_psk`` (both peers
configured with a ``PresharedKey``; a wireguard-go 0.0.20250522 process on linux/arm64 caught
right after it created the handshake response, so the peer handshake is in ``responseCreated``
and the PSK is an input of its chaining key), converts it with ``msl.importer`` and keeps only the
Go heap arena that holds every key (a region selection; nothing inside the region changes).
Writes ``wireguard_go_psk.msl.gz``, adds the ``wireguard_go_psk`` entry of ``samples.json`` (the
other entries are kept) and rewrites ``SHA256SUMS``.  The PSK ground truth is the
``WG_PRESHARED_KEY`` line of the in-process keylog (also ``psk_ground_truth.json`` of the run).
"""

from __future__ import annotations

import json
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
sys.path.insert(0, str(HERE))

from build_samples import (ALL_CATEGORIES, KeyRegionSelection, gzip_to, region_summary,  # noqa: E402
                           sha256_file, write_sums)
from build_wireguard_go_sample import _proven_rows  # noqa: E402
from memdiver.vol3plugins.memdiver import wireguard_go_engine as engine  # noqa: E402
from tests import _wg_go_corpus as corpus  # noqa: E402

RUN, ROLE, PHASE = "run_20261112_124707_psk", "responder", "pre_keys_installed"
NAME = "wireguard_go_psk.msl"
PSK_TAG = "WG_PRESHARED_KEY"


def keylog_psk(run: Path, role: str) -> bytes:
    """The PSK the traced process wrote to its keylog (``<date> <time> WG_PRESHARED_KEY: <hex>``)."""
    found = set()
    for line in corpus.keylog_path(run, role).read_text().splitlines():
        parts = line.split()
        if len(parts) >= 4 and parts[2] == PSK_TAG + ":":
            found.add(bytes.fromhex(parts[3]))
    if len(found) != 1:
        raise ValueError("expected exactly one %s in the %s keylog, found %d" % (PSK_TAG, role, len(found)))
    return found.pop()


def build(root: Path, work: Path) -> dict:
    run = root / RUN
    (dump,) = [d for d in corpus.dumps(run, ROLE) if corpus.phase(d) == PHASE]
    truth, psk = corpus.ground_truth(run, ROLE), keylog_psk(run, ROLE)
    analysis = engine.analyze(engine.Memory(corpus.load_segments(dump)))
    vas = tuple(sorted({a for r in analysis.rows for a in r.addresses}))
    out = work / NAME
    selection = KeyRegionSelection(ALL_CATEGORIES, vas=vas)
    pid = corpus.pid(run, ROLE)
    corpus.import_dump(dump, out, pid, selection=selection)
    rows = _proven_rows(out)
    assert rows["static-private"][:2] == (truth["static_private"].hex(), engine.PROVEN_ID), rows
    assert rows["peer-public"][:2] == (truth["peer_public"].hex(), engine.PROVEN_DH), rows
    assert rows["ephemeral-private"][1] == engine.PROVEN_CK, rows
    assert rows["ephemeral-private"][0] in {k.hex() for k in truth["ephemerals"]}, rows
    assert rows["preshared"][:2] == (psk.hex(), engine.PROVEN_CK), rows
    gzip_to(out, HERE / (NAME + ".gz"))
    return {
        "file": NAME + ".gz", "msl": NAME, "msl_sha256": sha256_file(out), "pid": pid,
        "implementation": "wireguard-go 0.0.20250522 (f333402), Go 1.25, linux/arm64",
        "role": ROLE, "phase": PHASE, "handshake_state": "responseCreated",
        "keys": {"static_private": truth["static_private"].hex(),
                 "static_public": truth["static_public"].hex(),
                 "peer_public": truth["peer_public"].hex(),
                 "ephemeral_private": rows["ephemeral-private"][0],
                 "preshared": psk.hex()},
        "expected": {kind: {"proven": proven, "addresses": addresses}
                     for kind, (_key, proven, addresses) in sorted(rows.items())},
        "ground_truth": "keylog written from inside the traced wireguard-go process (Delve "
                        "breakpoints), incl. its WG_PRESHARED_KEY line; the PSK was generated with "
                        "openssl rand and configured on both peers",
        "source": {"corpus_run": RUN, "file": "%s/dumps/%s" % (ROLE, dump.name),
                   "bytes": dump.stat().st_size, "sha256": sha256_file(dump),
                   "capture_tool": "Delve-driven flat dump + maps sidecar (rig harness 1.0.0)"},
        "kept_regions": region_summary(out), "selection": selection.to_note(),
    }


def main() -> int:
    root = corpus.corpus()
    if root is None or not (root / RUN).is_dir():
        print("set %s to the WireGuard rig's archive directory (with %s)" % (corpus.CORPUS_ENV, RUN),
              file=sys.stderr)
        return 2
    with tempfile.TemporaryDirectory(prefix="memdiver-wg-psk-sample-") as tmp:
        entry = build(root, Path(tmp))
    manifest_path = HERE / "samples.json"
    manifest = json.loads(manifest_path.read_text())
    manifest["wireguard_go_psk"] = entry
    manifest_path.write_text(json.dumps(manifest, indent=2) + "\n")
    write_sums()
    return 0


if __name__ == "__main__":
    sys.exit(main())
