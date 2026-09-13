"""Shared LRU pruning for the API's bounded upload directories.

Both the persisted pcap directory (``upload_dir/pcaps``) and the imported-dump
directory (``upload_dir/imports`` or ``~/.memdiver/imports``) hold files that
nothing else ever garbage-collects: the verification pipeline re-reads a pcap
long after its upload, and a session keeps referring to an imported ``.msl`` by
server path. Without a cap either directory is an unbounded disk-exhaustion
vector, so both are pruned back under a quota after every write.

The logic lives here rather than in one router so the two callers cannot drift.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Optional, Tuple

logger = logging.getLogger("memdiver.api.storage_quota")


def prune_dir_to_quota(
    directory: Path,
    quota_bytes: int,
    *,
    keep: Path,
    label: str = "file",
    suffixes: Optional[Tuple[str, ...]] = None,
) -> None:
    """Best-effort LRU prune of *directory* down to *quota_bytes*.

    Deletes oldest files (by mtime) first until the aggregate size is under the
    quota. ``keep`` (the just-written file) is never removed. ``quota_bytes``
    <= 0 disables pruning. Files vanishing mid-prune (racing request) are
    tolerated — the prune is advisory, not transactional.

    :param suffixes: When given, only files whose suffix (lowercased) is in the
        tuple are counted or evicted. This bounds the blast radius when the
        directory is shared: a caller-supplied ``output_dir`` may legitimately
        be the upload-dir root, and an unfiltered prune there would evict
        unrelated files.
    :param label: Noun used in the eviction log line.
    """
    if quota_bytes <= 0:
        return
    # Snapshot (mtime, size, path) tolerantly: a file vanishing here or below
    # (a concurrent upload/prune) is simply skipped, never fatal.
    stats = []
    for p in directory.iterdir():
        try:
            st = p.stat()
        except FileNotFoundError:
            continue
        if not p.is_file():
            continue
        if suffixes is not None and p.suffix.lower() not in suffixes:
            continue
        stats.append((st.st_mtime, st.st_size, p))
    total = sum(size for _, size, _ in stats)
    for _, size, p in sorted(stats):  # oldest mtime first
        if total <= quota_bytes:
            break
        if p == keep:  # never evict the just-written file
            continue
        try:
            p.unlink()
        except FileNotFoundError:
            continue
        total -= size
        logger.info("pruned oldest %s %s to stay under quota", label, p.name)
