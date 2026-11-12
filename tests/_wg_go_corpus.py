"""The wireguard-go capture corpus: runs, ground truth, dumps (shared by tests + sample build).

``MEMDIVER_WG_GO_CORPUS`` is the absolute ``archive`` directory of the WireGuard key-lifecycle
rig: ``run_*/<role>/{dumps,keylogs,lldb_results}`` with ``role`` in ``initiator``/``responder``.
Every dump is a flat process image ``<stamp>_<pre|post>_<phase>.dump`` with a
``.dump.maps.txt`` sidecar (``file_offset start end perms path``, offsets into the flat file),
captured by Delve from a wireguard-go process; the keylog (one ``<date> <time> NAME: hex`` line
per secret, written from inside the process) is the ground truth. Runs without a wireguard-go
keylog (the kernel-module runs, which hold kcore windows, not process memory) are skipped.
"""
import json
import os
from pathlib import Path

CORPUS_ENV = "MEMDIVER_WG_GO_CORPUS"
ROLES = ("initiator", "responder")
PEER_OF = {"initiator": "WG_STATIC_PUB_RESPONDER", "responder": "WG_STATIC_PUB_INITIATOR"}
SELF_OF = {"initiator": "WG_STATIC_PUB_INITIATOR", "responder": "WG_STATIC_PUB_RESPONDER"}


def corpus():
    value = os.environ.get(CORPUS_ENV, "")
    return Path(value) if value and Path(value).is_dir() else None


def sessions():
    """``[(run_dir, role)]`` that hold a wireguard-go keylog and dumps."""
    root = corpus()
    if root is None:
        return []
    found = []
    for run in sorted(root.glob("run_*")):
        for role in ROLES:
            if keylog_path(run, role).is_file() and dumps(run, role):
                found.append((run, role))
    return found


def keylog_path(run, role):
    return Path(run) / role / "keylogs" / ("keylog_wireguard-go-%s.txt" % role)


def dumps(run, role):
    return sorted(p for p in (Path(run) / role / "dumps").glob("*.dump")
                  if Path(str(p) + ".maps.txt").is_file())


def phase(dump):
    """``post_rekey_start`` of ``20260808_125754_100024_post_rekey_start.dump``."""
    return Path(dump).stem.split("_", 3)[3]


def ground_truth(run, role):
    """Keylog secrets as bytes: static private/publics, peer public, ephemerals, transport."""
    named = {}
    for line in keylog_path(run, role).read_text().splitlines():
        parts = line.split()
        if len(parts) >= 4 and parts[2].endswith(":"):
            named[parts[2][:-1]] = parts[3]
    keys = {name: bytes.fromhex(value) for name, value in named.items() if len(value) == 64}
    return {
        "static_private": keys["WG_STATIC_PRIV_LOCAL"],
        "static_public": keys[SELF_OF[role]],
        "peer_public": keys[PEER_OF[role]],
        "ephemerals": {v for n, v in keys.items() if n.startswith("WG_EPH_PRIV")},
        "transport": {v for n, v in keys.items() if "_SEND_KEY_" in n or "_RECV_KEY_" in n},
    }


def pid(run, role):
    """The traced process's pid (``TARGET_INFO`` event of the rig's event log), else 0."""
    events = Path(run) / role / "lldb_results" / ("events_wireguard-go-%s.jsonl" % role)
    try:
        with open(events) as handle:
            for line in handle:
                event = json.loads(line)
                if event.get("type") == "TARGET_INFO":
                    return int((event.get("metadata") or {}).get("pid") or 0)
    except (OSError, ValueError):
        pass
    return 0


def rig_regions(dump):
    """``[(file_offset, start, end, perms, path)]`` of a ``.dump.maps.txt`` sidecar."""
    regions = []
    for line in Path(str(dump) + ".maps.txt").read_text().splitlines():
        if not line.strip() or line.startswith("#"):
            continue
        offset, start, end, perms, path = line.split(None, 4)
        regions.append((int(offset, 16), int(start, 16), int(end, 16), perms, path.strip()))
    return regions


def load_segments(dump, writable_only=True):
    """``[(va, bytes)]`` of a flat dump (writable mappings only by default)."""
    data = Path(dump).read_bytes()
    return [(start, data[offset:offset + end - start])
            for offset, start, end, perms, _path in rig_regions(dump)
            if not writable_only or "w" in perms]


def proc_maps_text(dump):
    """The sidecar rewritten as ``/proc/<pid>/maps`` (what ``import_regioned_raw`` reads)."""
    return "".join("%x-%x %s 00000000 00:00 0 %s\n" % (start, end, perms,
                                                       "" if path == "[anon]" else path)
                   for _offset, start, end, perms, path in rig_regions(dump))


def import_dump(dump, out, pid_value=0, selection=None):
    """Convert a rig dump to ``.msl`` (one region per mapping at its real VA, arm64)."""
    from memdiver.msl.enums import ArchType
    from memdiver.msl.importer import import_regioned_raw

    out = Path(out)
    maps = out.with_name(out.name + ".maps")
    maps.write_text(proc_maps_text(dump))
    try:
        return import_regioned_raw(Path(dump), maps, out, pid=pid_value, selection=selection,
                                   arch_type=ArchType.ARM64)
    finally:
        maps.unlink()
