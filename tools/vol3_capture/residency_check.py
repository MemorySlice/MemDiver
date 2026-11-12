#!/usr/bin/env python3
"""Count raw occurrences of every planted secret in a memory dump (host side).

    residency_check.py DUMP SECRETS_JSON [--json]

For each entry of ``keys[]`` in a ``memdiver-secrets-gt/1`` sidecar, counts
exact byte matches of the full key in DUMP; 64-byte dm-crypt XTS volume keys
are additionally split into their two AES-256 halves (data key, tweak key),
since an expanded or split copy may hold only one half. Plain byte search over
the whole file -- no profile, no address translation -- so it says whether a
secret is resident, not which structure holds it.
"""

from __future__ import annotations

import json
import mmap
import sys


def count_hits(buf: mmap.mmap, needle: bytes) -> tuple[int, list[int]]:
    hits, offsets, pos = 0, [], buf.find(needle)
    while pos != -1:
        hits += 1
        if len(offsets) < 8:
            offsets.append(pos)
        pos = buf.find(needle, pos + 1)
    return hits, offsets


def needles(doc: dict) -> list[tuple[str, bytes]]:
    out: list[tuple[str, bytes]] = []
    xts = {d["name"] for d in doc.get("dmcrypt", []) if "xts" in d.get("cipher", "")}
    for key in doc.get("keys", []):
        raw = bytes.fromhex(key["hex"])
        out.append((key["id"], raw))
        name = key["id"].rsplit(".", 1)[0]
        if name in xts and len(raw) == 64:
            out.append((key["id"] + "[aes256-half0]", raw[:32]))
            out.append((key["id"] + "[aes256-half1]", raw[32:]))
    return out


def main(argv: list[str]) -> int:
    if len(argv) < 3:
        sys.exit(__doc__)
    with open(argv[2], encoding="utf-8") as fh:
        doc = json.load(fh)
    results = []
    with open(argv[1], "rb") as fh, mmap.mmap(fh.fileno(), 0, access=mmap.ACCESS_READ) as buf:
        for label, raw in needles(doc):
            hits, offsets = count_hits(buf, raw)
            results.append({"id": label, "length": len(raw), "hits": hits,
                            "first_offsets": offsets})
    if "--json" in argv:
        print(json.dumps(results, indent=2))
    else:
        for r in results:
            print(f"{r['hits']:6d}  {r['id']:<40} len={r['length']:<3} "
                  f"{','.join(hex(o) for o in r['first_offsets'])}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
