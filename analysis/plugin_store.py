"""Case-scoped store of user Volatility 3 plugin sources (plan T2.5, D7).

Sources live at ``<case>/plugins/<name>.py`` with a sidecar
``<name>.meta.json`` (sha256 / size / created / updated / version). The store
only reads and writes text; EXECUTING a source stays the caller's decision
(``app/tools_vol3`` logs the sha256 first, D7).

Safety posture (copied from the oracle registry, not shared with it, because
that one keeps only a head excerpt of each file):

* a name is an identifier (no separators, no dots), so it cannot name a path;
* a source is size-capped;
* a ``plugins/`` directory that is group/world-writable, or is a symlink that
  leaves the case, is refused; so is a plugin file that is a symlink;
* files are written atomically at ``0o600``.

Nothing is ever deleted: overwriting a name first copies the previous source
to ``plugins/history/<name>-<sha12>.py``.
"""

from __future__ import annotations

import hashlib
import json
import re
import stat
from pathlib import Path
from typing import Any, Dict, Iterator, List, Tuple

from memdiver.analysis.record import utc_now
from memdiver.core.artifact_util import atomic_write_text
from memdiver.core.service_errors import CapabilityError, ErrorCategory

PLUGINS_DIR = "plugins"
HISTORY_DIR = "history"
MAX_SOURCE_BYTES = 256 * 1024
NAME_PATTERN = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,63}$")
META_SUFFIX = ".meta.json"
FILE_MODE = 0o600
_INSECURE_DIR_BITS = stat.S_IWGRP | stat.S_IWOTH


def store_error(message: str, code: str,
           category: ErrorCategory = ErrorCategory.INVALID_INPUT) -> CapabilityError:
    return CapabilityError(message, category=category, code=code)


def validate_name(name: str, what: str = "plugin") -> str:
    """The name when it is an identifier of at most 64 characters, else INVALID_INPUT."""
    if not isinstance(name, str) or not NAME_PATTERN.match(name):
        raise store_error(f"{what} name must be an identifier (letters, digits, underscore; "
                     f"max 64), got {name!r}", f"{what}.bad_name")
    return name


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _check_inside(case_root: Path, candidate: Path, subpath: str) -> Path:
    """``candidate`` resolved, refusing an escape from the case or a symlink."""
    resolved = candidate.resolve()
    if case_root not in resolved.parents and resolved != case_root:
        raise store_error(f"{subpath} resolves outside the case directory", "store.escape",
                     ErrorCategory.PRECONDITION)
    if candidate.is_symlink() or resolved.stat().st_mode & _INSECURE_DIR_BITS:
        raise store_error(f"refusing {resolved}: a symlink or a group/world-writable directory",
                     "store.insecure_dir", ErrorCategory.PRECONDITION)
    return resolved


def safe_directory(case_dir: Path, subpath: str, *, create: bool) -> Path:
    """``<case>/<subpath>`` after the symlink and permission checks; created when asked.

    Every component is checked as it is reached, BEFORE anything is created
    under it, so a symlinked ancestor is refused without side effects.
    """
    case_root = Path(case_dir).resolve()
    current = case_root
    for part in Path(subpath).parts:
        current = current / part
        if current.exists() or current.is_symlink():
            _check_inside(case_root, current, subpath)
        elif create:
            current.mkdir(exist_ok=True)
        else:
            return case_root / subpath
    return _check_inside(case_root, current, subpath) if current.exists() else current


def safe_file(directory: Path, filename: str) -> Path:
    """``directory/filename`` unless it is a symlink (a regular file or absent)."""
    path = directory / filename
    if path.is_symlink():
        raise store_error(f"refusing symlink {path}", "store.symlink", ErrorCategory.PRECONDITION)
    return path


def archive_previous(path: Path, history: Path, stem: str, suffix: str, text: str) -> None:
    """Keep the replaced content of ``path`` under ``history`` (never lose user data)."""
    if history.is_symlink() or (
            history.exists() and history.resolve().parent != history.parent.resolve()):
        raise store_error(f"{history} is a symlink or escapes its directory",
                     "store.escape", ErrorCategory.PRECONDITION)
    history.mkdir(parents=True, exist_ok=True)
    keep = history / f"{stem}-{hashlib.sha256(text.encode('utf-8')).hexdigest()[:12]}{suffix}"
    if not keep.exists():
        atomic_write_text(keep, text, mode=FILE_MODE)


def read_json_dict(path: Path) -> "Dict[str, Any] | None":
    """The JSON object stored at ``path``; ``None`` when absent, unreadable or not an object."""
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    return data if isinstance(data, dict) else None


def json_dicts_in(directory: Path) -> Iterator[Tuple[Path, Dict[str, Any]]]:
    """``(path, object)`` per readable, non-symlink ``*.json`` in ``directory``, by name."""
    if not directory.is_dir():
        return
    for path in sorted(directory.glob("*.json")):
        body = read_json_dict(path) if not path.is_symlink() else None
        if body is not None:
            yield path, body


def put_versioned_json(path: Path, name: str, body: Dict[str, Any]) -> Dict[str, Any]:
    """Write ``body`` to ``path`` stamped with created/updated/version; archive the old one.

    The replaced definition is kept under the sibling ``history/`` directory first.
    Returns the stamped body plus ``sha256`` (of the written text) and ``path``.
    """
    previous = read_json_dict(path)
    stamped = {**body, "created": (previous or {}).get("created") or utc_now(),
               "updated": utc_now(), "version": int((previous or {}).get("version", 0)) + 1}
    if path.is_file():
        archive_previous(path, path.parent / HISTORY_DIR, name, ".json",
                         path.read_text(encoding="utf-8"))
    text = json.dumps(stamped, indent=2, sort_keys=True) + "\n"
    atomic_write_text(path, text, mode=FILE_MODE)
    return {**stamped, "sha256": sha256_text(text), "path": str(path)}


class PluginStore:
    """The ``plugins/`` directory of one case."""

    def __init__(self, case_dir: Path) -> None:
        self._case_dir = Path(case_dir)

    def _dir(self, create: bool) -> Path:
        return safe_directory(self._case_dir, PLUGINS_DIR, create=create)

    def _paths(self, name: str, create: bool) -> "tuple[Path, Path, Path]":
        directory = self._dir(create)
        return (safe_file(directory, f"{name}.py"),
                safe_file(directory, f"{name}{META_SUFFIX}"), directory / HISTORY_DIR)

    def put(self, name: str, source: str) -> Dict[str, Any]:
        """Store ``source`` as ``name``; the previous version, if any, goes to history."""
        validate_name(name)
        if not isinstance(source, str) or not source.strip():
            raise store_error("source is required", "plugin.source_required")
        size = len(source.encode("utf-8"))
        if size > MAX_SOURCE_BYTES:
            raise store_error(f"source is {size} bytes; the cap is {MAX_SOURCE_BYTES}",
                         "plugin.too_large")
        path, meta_path, history = self._paths(name, create=True)
        previous = read_json_dict(meta_path)
        if path.is_file():
            archive_previous(path, history, name, ".py", path.read_text(encoding="utf-8"))
        now = utc_now()
        meta = {"name": name, "sha256": sha256_text(source), "size": size,
                "created": (previous or {}).get("created", now), "updated": now,
                "version": int((previous or {}).get("version", 0)) + 1}
        atomic_write_text(path, source, mode=FILE_MODE)
        atomic_write_text(meta_path, json.dumps(meta, indent=2) + "\n", mode=FILE_MODE)
        return {**meta, "path": str(path)}

    def get(self, name: str) -> Dict[str, Any]:
        """The stored source with its metadata; ``modified_externally`` flags a hand edit."""
        validate_name(name)
        path, meta_path, _ = self._paths(name, create=False)
        if not path.is_file():
            raise store_error(f"no stored plugin {name!r}", "plugin.not_found",
                         ErrorCategory.NOT_FOUND)
        source = path.read_text(encoding="utf-8")
        actual = sha256_text(source)
        recorded = read_json_dict(meta_path) or {}
        meta = {"name": name, "created": recorded.get("created"),
                "updated": recorded.get("updated"), "version": recorded.get("version"),
                "sha256": actual, "size": len(source.encode("utf-8")), "path": str(path),
                "source": source,
                "modified_externally": actual != recorded.get("sha256", actual)}
        return meta

    def list(self) -> List[Dict[str, Any]]:
        """Metadata of every stored plugin, by name (no source text)."""
        directory = self._dir(create=False)
        if not directory.is_dir():
            return []
        out: List[Dict[str, Any]] = []
        for path in sorted(directory.glob("*.py")):
            if not NAME_PATTERN.match(path.stem) or path.is_symlink():
                continue
            meta = self.get(path.stem)
            meta.pop("source", None)
            out.append(meta)
        return out
