"""Path info router — detect file vs directory and gather metadata."""

from __future__ import annotations

import logging
import os
from collections import deque
from itertools import islice
from pathlib import Path

from fastapi import APIRouter, Query

from memdiver.core.discovery import RunDiscovery

logger = logging.getLogger("memdiver.api.routers.path")

router = APIRouter()

_DUMP_EXTENSIONS = {".dump", ".msl"}
_MAX_CHILDREN = 5000


@router.get("/info")
def path_info(path: str):
    """Detect whether a path is a file or directory and gather metadata."""
    p = Path(path)
    if not p.exists():
        return {
            "exists": False,
            "is_file": False,
            "is_directory": False,
            "file_size": 0,
            "extension": "",
            "has_keylog": False,
            "dump_count": 0,
            "detected_mode": "unknown",
        }

    is_file = p.is_file()
    is_dir = p.is_dir()

    result = {
        "exists": True,
        "is_file": is_file,
        "is_directory": is_dir,
        "file_size": p.stat().st_size if is_file else 0,
        "extension": p.suffix.lower() if is_file else "",
        "has_keylog": False,
        "dump_count": 0,
        "detected_mode": "unknown",
    }

    if is_file:
        result["detected_mode"] = "single_file"
        return result

    if is_dir:
        dump_count = 0
        has_keylog = False
        has_run_dirs = False
        has_nested_run_dirs = False

        # Single pass over children (capped to prevent unbounded scan)
        for child in islice(p.iterdir(), _MAX_CHILDREN):
            if child.is_file():
                if child.suffix.lower() in _DUMP_EXTENSIONS:
                    dump_count += 1
                if child.name == "keylog.csv":
                    has_keylog = True
            elif child.is_dir():
                if "_run_" in child.name:
                    has_run_dirs = True
                for grandchild in islice(child.iterdir(), _MAX_CHILDREN):
                    if grandchild.is_file():
                        if grandchild.suffix.lower() in _DUMP_EXTENSIONS:
                            dump_count += 1
                        if grandchild.name == "keylog.csv":
                            has_keylog = True
                    elif grandchild.is_dir() and "_run_" in grandchild.name:
                        has_nested_run_dirs = True

        result["has_keylog"] = has_keylog
        result["dump_count"] = dump_count

        if has_run_dirs:
            result["detected_mode"] = "run_directory"
        elif has_nested_run_dirs:
            result["detected_mode"] = "dataset"
        elif dump_count > 0:
            result["detected_mode"] = "run_directory"
        else:
            result["detected_mode"] = "dataset"

    return result


_BROWSE_MAX_ENTRIES = 500


@router.get("/browse")
def browse_directory(path: str | None = None, all_files: bool = False):
    """List directory contents for a file browser UI.

    ``all_files`` is opt-in and defaults to today's behaviour (dumps only),
    so every existing caller keeps the exact listing it already gets. It
    exists because a file picked through this browser is not always a dump:
    an oracle's sample ciphertext may carry no extension at all, which the
    ``_DUMP_EXTENSIONS`` filter can never surface.
    """
    p = Path(path) if path else Path.home()

    if not p.exists():
        return {"error": "Path does not exist", "entries": []}

    if not p.is_dir():
        return {"error": "Path is not a directory", "entries": []}

    current = str(p.resolve())
    parent_path = p.resolve().parent
    parent = str(parent_path) if parent_path != p.resolve() else None

    dirs: list[dict] = []
    files: list[dict] = []
    try:
        for child in p.iterdir():
            try:
                if child.is_dir():
                    dirs.append({
                        "name": child.name,
                        "path": str(child.resolve()),
                        "is_dir": True,
                        "size": 0,
                        "extension": "",
                    })
                elif child.is_file() and (all_files or child.suffix.lower() in _DUMP_EXTENSIONS):
                    files.append({
                        "name": child.name,
                        "path": str(child.resolve()),
                        "is_dir": False,
                        "size": child.stat().st_size,
                        "extension": child.suffix.lower(),
                    })
            except PermissionError:
                continue
    except PermissionError:
        return {"error": "Permission denied", "entries": []}

    dirs.sort(key=lambda e: e["name"].lower())
    files.sort(key=lambda e: e["name"].lower())
    entries = (dirs + files)[:_BROWSE_MAX_ENTRIES]

    return {"current": current, "parent": parent, "entries": entries}


# ---------------------------------------------------------------------------
# GET /api/path/discover-dumps
# ---------------------------------------------------------------------------

# Neither sibling endpoint can answer "what dumps live under this corpus root".
# ``/info`` and ``/browse`` are single-level, and ``/api/dataset/runs`` is
# depth <= 1, while a corpus keeps its runs three to four levels down. Hence a
# recursive walk -- which is only safe with hard bounds, because it is pointed
# at research datasets holding multi-GB dumps.

# Results returned in one response. Shares ``_BROWSE_MAX_ENTRIES`` because it
# feeds the same kind of UI list, so the two surfaces stay comparable.
_DISCOVER_MAX_RESULTS = _BROWSE_MAX_ENTRIES

# Files stat'ed, and directories entered, during the walk. Both are multiples of
# the per-directory ``_MAX_CHILDREN`` rather than invented numbers: a recursive
# sweep legitimately crosses many directories, so its budget is that of a single
# directory scaled up. The multipliers are sized so a real corpus (the local one
# is ~19k dumps, each run carrying a handful of sidecars) finishes rather than
# truncates, while a wrong turn into something like ``node_modules`` still stops
# in well under a second. Tripping either budget reports ``truncated`` -- a
# partial answer the analyst can see is partial beats a request that never
# returns.
_DISCOVER_MAX_FILES = _MAX_CHILDREN * 20

_DISCOVER_MAX_DIRS = _MAX_CHILDREN * 10


def _requested_kinds(kinds: list[str] | None) -> set[str]:
    """Normalise the ``kinds`` query parameter into a set of kind strings.

    Accepts both repetition (``kinds=msl&kinds=gcore``) and the comma-separated
    form (``kinds=msl,gcore``), because query-array encoding differs between
    hand-written curl calls and the frontend's URLSearchParams.
    """
    if kinds is None:
        return set()
    out = {
        part.strip().lower()
        for raw in kinds
        for part in raw.split(",")
        if part.strip()
    }
    return out


def _walk_dump_files(root: Path, recursive: bool) -> tuple[list[dict], bool]:
    """Collect dump entries under ``root``, bounded, without following symlinks.

    Returns ``(entries, capped)`` where ``capped`` is True when a budget stopped
    the walk before the tree was exhausted.
    """
    entries: list[dict] = []
    capped = False
    files_seen = 0
    dirs_seen = 0

    # A directory can be reached twice through a bind mount or a directory
    # hardlink even with ``followlinks`` off, which would walk forever. Keying
    # on the real (device, inode) pair makes re-entry impossible.
    visited: set[tuple[int, int]] = set()
    queue: deque[Path] = deque([root])

    while queue:
        current = queue.popleft()
        try:
            key = current.stat()
        except OSError:
            continue
        ident = (key.st_dev, key.st_ino)
        if ident in visited:
            continue
        visited.add(ident)

        dirs_seen += 1
        if dirs_seen > _DISCOVER_MAX_DIRS:
            capped = True
            break

        try:
            with os.scandir(current) as it:
                for entry in it:
                    try:
                        if entry.is_dir(follow_symlinks=False):
                            # Dot-directories hold caches and VCS metadata, never
                            # corpus runs, and are where an unbounded walk goes
                            # to die.
                            if recursive and not entry.name.startswith("."):
                                queue.append(Path(entry.path))
                            continue
                        if not entry.is_file(follow_symlinks=False):
                            # Symlinks to files carry no loop risk, but a dump
                            # reached twice under two names would be counted
                            # twice, which the consensus view reads as two dumps.
                            continue
                    except OSError:
                        continue

                    files_seen += 1
                    if files_seen > _DISCOVER_MAX_FILES:
                        capped = True
                        break

                    candidate = Path(entry.path)
                    # The single admission rule, shared with discovery. It is
                    # pure filename parsing, so no dump contents are read.
                    dump = RunDiscovery.dump_file_for(candidate)
                    if dump is None:
                        continue
                    try:
                        size = entry.stat().st_size
                    except OSError:
                        size = 0
                    entries.append({
                        "path": str(candidate),
                        "kind": dump.kind,
                        "size": size,
                        "run": candidate.parent.name,
                    })
        except (PermissionError, OSError):
            # An unreadable directory is skipped, not fatal: a corpus often
            # sits beside system directories the server cannot enter.
            pass

        if capped:
            break

    return entries, capped


@router.get("/discover-dumps")
def discover_dumps(
    path: str,
    kinds: list[str] | None = Query(default=None),
    recursive: bool = True,
    limit: int = _DISCOVER_MAX_RESULTS,
):
    """Find dump files under a directory, recursively, grouped by kind.

    Mirrors ``browse_directory``'s ``{"error": ...}`` contract rather than
    raising: a directory the analyst has not created yet is an ordinary state of
    the picker UI, not an exceptional one, and the two endpoints are called from
    the same flow -- a 404 here and a 200 there would force the client to handle
    the same user mistake twice.
    """
    empty = {"dumps": [], "total": 0, "truncated": False, "counts_by_kind": {}}

    p = Path(path) if path else Path.home()
    if not p.exists():
        return {"error": "Path does not exist", **empty}
    if not p.is_dir():
        return {"error": "Path is not a directory", **empty}

    discovered, capped = _walk_dump_files(p, recursive)

    # Counted over EVERYTHING discovered, before the kinds filter: the UI paints
    # these as "msl(31) gcore(8) gdb_raw(8)" checkboxes, so filtering first would
    # make the counts of the unselected kinds disappear.
    counts_by_kind: dict[str, int] = {}
    for entry in discovered:
        counts_by_kind[entry["kind"]] = counts_by_kind.get(entry["kind"], 0) + 1

    wanted = _requested_kinds(kinds) or {"msl"}
    selected = [e for e in discovered if e["kind"] in wanted]

    # Sorted BEFORE the limit is applied, so a truncated response is still the
    # deterministic prefix of the same list -- the N-dump consensus alignment
    # downstream pairs dumps positionally and would silently mis-pair otherwise.
    selected.sort(key=lambda e: e["path"])

    capacity = max(1, min(limit, _DISCOVER_MAX_RESULTS))
    truncated = capped or len(selected) > capacity

    return {
        "dumps": selected[:capacity],
        "total": len(selected),
        "truncated": truncated,
        "counts_by_kind": counts_by_kind,
    }
