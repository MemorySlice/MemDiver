"""Rebuild the in-repo wireguard-go sample from the WireGuard key-lifecycle corpus.

Judges never need to run this (the output is committed, see ``SHA256SUMS``). It needs MemDiver
and the private corpus (``MEMDIVER_WG_GO_CORPUS`` = the rig's ``archive`` directory, see
``tests/_wg_go_corpus.py``); run it from the repository root::

    MEMDIVER_WG_GO_CORPUS=/abs/WireGuard/archive python samples/build_wireguard_go_sample.py

It takes the initiator's ``post_rekey_start`` dump of ``run_20260808_125548`` (a wireguard-go
0.0.20250522 process on linux/arm64, caught right after it sent the rekey initiation: static
identity, peer handshake in ``initiationCreated`` with its ephemeral, and the current keypair
all resident), converts it with ``msl.importer.import_regioned_raw`` and keeps only the Go heap
arena that holds every key (a region selection; nothing inside the region changes). Writes
``wireguard_go_initiator.msl.gz``, adds the ``wireguard_go`` entries of ``samples.json``
(the other entries are kept) and rewrites ``SHA256SUMS``.
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
from memdiver.vol3plugins.memdiver import wireguard_go_engine as engine  # noqa: E402
from tests import _wg_go_corpus as corpus  # noqa: E402

RUN, ROLE, PHASE = "run_20260808_125548", "initiator", "post_rekey_start"
NAME = "wireguard_go_initiator.msl"


def _proven_rows(msl: Path) -> dict:
    """Engine verdicts on the written slice, read back through MemDiver's reader."""
    from memdiver.core.dump_source import MslDumpSource

    segments = []
    with MslDumpSource(msl) as source:
        for va, length, vas_offset in source.captured_runs():
            segments.append((va, source.read_range(vas_offset, length, view="vas")))
    analysis = engine.analyze(engine.Memory(segments))
    return {r.kind: (r.key.hex(), r.proven, ["%#x" % a for a in r.addresses])
            for r in analysis.rows}


def build(root: Path, work: Path) -> dict:
    run = root / RUN
    (dump,) = [d for d in corpus.dumps(run, ROLE) if corpus.phase(d) == PHASE]
    truth = corpus.ground_truth(run, ROLE)
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
    assert {rows["send"][0], rows["receive"][0]} <= {k.hex() for k in truth["transport"]}, rows
    gzip_to(out, HERE / (NAME + ".gz"))
    return {
        "file": NAME + ".gz", "msl": NAME, "msl_sha256": sha256_file(out), "pid": pid,
        "implementation": "wireguard-go 0.0.20250522 (f333402), Go 1.25, linux/arm64",
        "role": ROLE, "phase": PHASE, "handshake_state": "initiationCreated",
        "keys": {"static_private": truth["static_private"].hex(),
                 "static_public": truth["static_public"].hex(),
                 "peer_public": truth["peer_public"].hex(),
                 "ephemeral_private": rows["ephemeral-private"][0],
                 "send": rows["send"][0], "receive": rows["receive"][0]},
        "expected": {kind: {"proven": proven, "addresses": addresses}
                     for kind, (_key, proven, addresses) in sorted(rows.items())},
        "ground_truth": "keylog written from inside the traced wireguard-go process (Delve "
                        "breakpoints); ephemeral and transport keys are in the same keylog",
        "source": {"corpus_run": RUN, "file": "%s/dumps/%s" % (ROLE, dump.name),
                   "bytes": dump.stat().st_size, "sha256": sha256_file(dump),
                   "capture_tool": "Delve-driven flat dump + maps sidecar (rig harness 1.0.0)"},
        "kept_regions": region_summary(out), "selection": selection.to_note(),
    }


def main() -> int:
    root = corpus.corpus()
    if root is None or not (root / RUN).is_dir():
        print("set %s to the WireGuard rig's archive directory" % corpus.CORPUS_ENV,
              file=sys.stderr)
        return 2
    with tempfile.TemporaryDirectory(prefix="memdiver-wg-sample-") as tmp:
        entry = build(root, Path(tmp))
    manifest_path = HERE / "samples.json"
    manifest = json.loads(manifest_path.read_text())
    manifest["wireguard_go"] = entry
    manifest["wireguard_go_plugin"] = {
        "vol_plugin": "memdiver.wireguard_go.WireGuardGo", "plugin_dir": "vol3plugins",
        "oracle_kinds": ["x25519-pubkey", "x25519-dh-consistency"]}
    manifest_path.write_text(json.dumps(manifest, indent=2) + "\n")
    write_sums()
    return 0


if __name__ == "__main__":
    sys.exit(main())
