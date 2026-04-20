"""Path info router — detect file vs directory and gather metadata."""

from __future__ import annotations

import logging
from itertools import islice
from pathlib import Path

from fastapi import APIRouter

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
def browse_directory(path: str | None = None):
    """List directory contents for a file browser UI."""
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
                elif child.is_file() and child.suffix.lower() in _DUMP_EXTENSIONS:
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
