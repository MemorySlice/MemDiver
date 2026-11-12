"""S4 real-data run of ``frames="private"`` consensus on capture v2b (plan S4, in-image differential).

``MEMDIVER_SECRETS_CORPUS`` = absolute path of the acquired-secrets capture dir (unset ->
skipped). Stem ``ubuntu-24.04-secrets-x86-4level-v2b_6.8.0-136-generic``; ground truth is
the sidecar's ``siblings[]`` (per member: the VA of every occurrence of a per-session
secret, all 32-byte keys).

Per group (sessions only, listeners/monitors left out) it builds the consensus over the
members' process views with ``frames="all"`` and ``frames="private"`` and prints, with
``-s``: the alignment method, bytes compared, the excluded share-class breakdown, and for
every ground-truth secret occurrence: its share class, whether its bytes are in the
compared slab at all, and how many of them are KEY_CANDIDATE.

Asserted (measured, not assumed):
  * ``frames="all"`` equals the default build;
  * private compares fewer bytes than all, under the expected regime per group;
  * every ground-truth occurrence lies in a private frame (C-SIB1 seen from the consensus).
"""

import collections
import json
import os
from pathlib import Path

import numpy as np
import pytest

from memdiver.core.image.context import file_sha256
from memdiver.core.image.private_frames import (
    PRIVATE_FRAMES_DIAGNOSTIC,
    classify_view_sources,
)
from memdiver.core.image.sources import Vol3LayerSource
from memdiver.core.image.view_descriptor import ProfileRef, ViewDescriptor, ViewKind
from memdiver.core.variance import ByteClass
from memdiver.engine.consensus import (
    ALIGNMENT_MODULE_RELATIVE,
    ALIGNMENT_VIRTUAL_ADDRESS,
    ConsensusVector,
)

_CORPUS = os.environ.get("MEMDIVER_SECRETS_CORPUS", "")
CAPTURE_DIR = Path(_CORPUS) if _CORPUS else Path("/nonexistent")
STEM = "ubuntu-24.04-secrets-x86-4level-v2b_6.8.0-136-generic"
SECRET_LEN = 32  # hmac-sha2-256 / aes256 keys, the gocryptfs master key
PRIVATE = {"private_dirty", "private_clean", "private_file_cow"}

GROUPS = {
    "dropbear": ([11642, 11653, 11664, 11675], ALIGNMENT_VIRTUAL_ADDRESS),
    "openssh": ([11794, 11892, 11848, 11948], ALIGNMENT_MODULE_RELATIVE),
    "gocryptfs": ([11970, 12011, 12056], ALIGNMENT_MODULE_RELATIVE),
}
#: Extra explicit regimes measured per group (Go's heap arenas sit at a fixed VA hint,
#: outside ``[heap]``, so module_relative leaves them unkeyed).
EXTRA_REGIMES = {"gocryptfs": ALIGNMENT_VIRTUAL_ADDRESS}

pytestmark = pytest.mark.skipif(
    not all((CAPTURE_DIR / f"{STEM}{ext}").is_file()
            for ext in (".lime", ".isf.json", ".secrets.json")),
    reason="set MEMDIVER_SECRETS_CORPUS to the capture v2b directory")


@pytest.fixture(scope="module")
def truth():
    records = json.loads((CAPTURE_DIR / f"{STEM}.secrets.json").read_text())["siblings"]
    return {r["pid"]: r for r in records}


@pytest.fixture(scope="module")
def descriptors(tmp_path_factory):
    lime, isf = CAPTURE_DIR / f"{STEM}.lime", CAPTURE_DIR / f"{STEM}.isf.json"
    sha = file_sha256(lime)
    profile = ProfileRef(str(isf), sha256=file_sha256(isf), origin="explicit")
    out = tmp_path_factory.mktemp("views")
    paths = {}
    for pids, _ in GROUPS.values():
        for pid in pids:
            desc = ViewDescriptor(str(lime), sha, ViewKind.PROCESS, pid=pid, profile=profile)
            paths[pid] = desc.write(out / f"{pid}.mdview")
    return paths


def _open(descriptors, pids):
    sources = [Vol3LayerSource(descriptors[pid]) for pid in pids]
    for src in sources:
        src.open()
    return sources


def _build(sources, **kw):
    cm = ConsensusVector()
    cm.build_from_sources(sources, **kw)
    return cm


def _slab_positions(cm, dump, va):
    """Slab offsets of ``va .. va+SECRET_LEN`` of dump ``dump`` (missing bytes are absent)."""
    out = []
    for slab_off, length, vas in cm.msl_layout or []:
        lo, hi = max(va, vas[dump]), min(va + SECRET_LEN, vas[dump] + length)
        out.extend(range(slab_off + lo - vas[dump], slab_off + hi - vas[dump]))
    return out


def _correspondence(cm, pids, truth):
    """{secret: True when some occurrence of it starts at ONE slab offset in every member}."""
    starts = collections.defaultdict(list)
    for dump, pid in enumerate(pids):
        per_member = collections.defaultdict(set)
        for frame in truth[pid]["frames"]:
            pos = _slab_positions(cm, dump, int(frame["va"], 16))
            if len(pos) == SECRET_LEN:
                per_member[frame["secret"]].add(pos[0])
        for name in {f["secret"] for f in truth[pid]["frames"]}:
            starts[name].append(per_member[name])
    return {name: bool(set.intersection(*sets)) for name, sets in starts.items()}


def _secret_rows(cm, pids, truth, spans):
    rows = []
    classes = np.frombuffer(bytes(cm.classifications), dtype=np.uint8) \
        if cm.size else np.zeros(0, np.uint8)
    for dump, pid in enumerate(pids):
        for frame in truth[pid]["frames"]:
            va = int(frame["va"], 16)
            share = next((c for s, n, c in spans[dump] if s <= va < s + n), None)
            pos = _slab_positions(cm, dump, va)
            kc = int(sum(classes[p] == ByteClass.KEY_CANDIDATE for p in pos))
            rows.append((pid, frame["secret"], va, share, len(pos), kc))
    return rows


@pytest.mark.parametrize("group", list(GROUPS))
def test_private_frames_consensus_on_capture_v2b(group, descriptors, truth):
    pids, expected_method = GROUPS[group]
    sources = _open(descriptors, pids)
    try:
        spans = classify_view_sources(sources)
        default, full = _build(sources), _build(sources, frames="all")
        private = _build(sources, frames="private")
        extra = ({EXTRA_REGIMES[group]: _build(sources, frames="private",
                                               alignment=EXTRA_REGIMES[group])}
                 if group in EXTRA_REGIMES else {})
    finally:
        for src in sources:
            src.close()

    assert np.array_equal(default.variance, full.variance)
    assert default.alignment_report == full.alignment_report
    (note,) = [d for d in private.alignment_report.diagnostics
               if d.code == PRIVATE_FRAMES_DIAGNOSTIC]
    a, p = full.alignment_report, private.alignment_report
    print(f"\n[{group}] pids {pids}")
    print(f"  method all={a.method} private={p.method}")
    print(f"  bytes_compared all={a.bytes_compared} private={p.bytes_compared} "
          f"reduction={100 * (1 - p.bytes_compared / max(a.bytes_compared, 1)):.2f}%")
    print(f"  captured={note.details['captured_bytes']} private={note.details['private_bytes']} "
          f"excluded={note.details['excluded_bytes']} classes={note.details['bytes_by_class']}")
    kc_all = len(full.get_volatile_regions(min_length=16))
    kc_priv = len(private.get_volatile_regions(min_length=16))
    print(f"  KEY_CANDIDATE regions(>=16B) all={kc_all} private={kc_priv}")

    shares = collections.Counter()
    for label, cm in (("all", full), ("private", private)):
        for pid, name, va, share, in_slab, kc in _secret_rows(cm, pids, truth, spans):
            shares[share] += label == "all"
            print(f"  {label:7s} pid {pid} {name:10s} va {va:#x} class={share} "
                  f"in_slab={in_slab}/{SECRET_LEN} key_candidate={kc}/{SECRET_LEN}")
    print(f"  ground-truth occurrence classes: {dict(shares)}")
    print(f"  slab-offset correspondence across members (private): "
          f"{_correspondence(private, pids, truth)}")
    for method, cm in extra.items():
        rows = _secret_rows(cm, pids, truth, spans)
        print(f"  private+{method}: bytes_compared={cm.alignment_report.bytes_compared} "
              f"KEY_CANDIDATE regions={len(cm.get_volatile_regions(min_length=16))} "
              f"secret bytes in slab={sum(r[4] for r in rows)}/{SECRET_LEN * len(rows)} "
              f"key_candidate={sum(r[5] for r in rows)} "
              f"correspondence={_correspondence(cm, pids, truth)}")

    assert a.method == p.method == expected_method
    assert 0 < p.bytes_compared < a.bytes_compared
    assert note.details["private_bytes"] < note.details["captured_bytes"]
    assert shares and set(shares) <= PRIVATE
