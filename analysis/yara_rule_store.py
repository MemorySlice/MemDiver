"""Store of user YARA rule sources: a per-user library and a per-case directory.

A rule lives at ``<root>/yara_rules/<name>.yar`` with a sidecar ``<name>.meta.json``
(sha256 / size / version / created / updated / compiles / errors / rule_names). ``root`` is
the MemDiver home for the LIBRARY scope and the case directory for the CASE scope; the
store itself does not know which. It only reads and writes text, and records the outcome of
a compile check the caller ran (a draft that does not compile is saved and flagged).

The safety posture is :mod:`memdiver.analysis.plugin_store`'s (its helpers are imported,
not copied): a name is an identifier, a source is size-capped, a ``yara_rules/`` directory
that is a symlink leaving the root or is group/world-writable is refused, so is a rule file
that is a symlink, and files are written atomically at ``0o600``.

Nothing is hard-deleted: overwriting a name archives the previous source to
``yara_rules/history/<name>-<sha12>.yar``, and :meth:`YaraRuleStore.delete` archives the
current source there before removing the live file.
"""

from __future__ import annotations

import contextlib
import threading

try:  # POSIX: serialize writers across processes too
    import fcntl
except ImportError:  # pragma: no cover - Windows: in-process lock only
    fcntl = None  # type: ignore[assignment]
import json
from pathlib import Path
from typing import Any, Dict, List, Optional

from memdiver.analysis.plugin_store import (
    FILE_MODE,
    HISTORY_DIR,
    META_SUFFIX,
    NAME_PATTERN,
    archive_previous,
    read_json_dict,
    safe_directory,
    safe_file,
    sha256_text,
    store_error,
    validate_name,
)
from memdiver.analysis.record import utc_now
from memdiver.core.artifact_util import atomic_write_text
from memdiver.core.service_errors import ErrorCategory

RULES_DIR = "yara_rules"
RULE_SUFFIX = ".yar"
MAX_SOURCE_BYTES = 256 * 1024
_WHAT = "yara rule"


#: Serializes writers within this process (flock alone does not, on every platform).
_PROCESS_LOCK = threading.Lock()

class YaraRuleStore:
    """The ``yara_rules/`` directory under one root (the library home or a case)."""

    def __init__(self, root: Path) -> None:
        self._root = Path(root)

    def _dir(self, create: bool) -> Path:
        return safe_directory(self._root, RULES_DIR, create=create)

    def _paths(self, name: str, create: bool) -> "tuple[Path, Path, Path]":
        directory = self._dir(create)
        return (safe_file(directory, f"{name}{RULE_SUFFIX}"),
                safe_file(directory, f"{name}{META_SUFFIX}"), directory / HISTORY_DIR)

    @contextlib.contextmanager
    def _write_lock(self):
        """Serialize writers of this store (flock on a lock file in the rules directory)."""
        directory = self._dir(create=True)
        with _PROCESS_LOCK, open(directory / ".lock", "a") as handle:
            if fcntl is not None:
                fcntl.flock(handle, fcntl.LOCK_EX)
            try:
                yield
            finally:
                if fcntl is not None:
                    fcntl.flock(handle, fcntl.LOCK_UN)

    def put(self, name: str, source: str,
            check: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Store ``source`` as ``name``; ``check`` is a compile-check payload kept in the meta."""
        validate_name(name, _WHAT)
        if not isinstance(source, str) or not source.strip():
            raise store_error("rule source is required", "yara_rule.source_required")
        size = len(source.encode("utf-8"))
        if size > MAX_SOURCE_BYTES:
            raise store_error(f"source is {size} bytes; the cap is {MAX_SOURCE_BYTES}",
                              "yara_rule.too_large")
        with self._write_lock():
            return self._put_locked(name, source, size, check)

    def _put_locked(self, name: str, source: str, size: int,
                    check: Optional[Dict[str, Any]]) -> Dict[str, Any]:
        path, meta_path, history = self._paths(name, create=True)
        previous = read_json_dict(meta_path)
        if path.is_file():
            archive_previous(path, history, name, RULE_SUFFIX, path.read_text(encoding="utf-8"))
        now = utc_now()
        check = check or {}
        meta = {"name": name, "sha256": sha256_text(source), "size": size,
                "created": (previous or {}).get("created", now), "updated": now,
                "version": int((previous or {}).get("version", 0)) + 1,
                "compiles": check.get("valid"), "errors": list(check.get("errors") or []),
                "rule_names": list(check.get("rule_names") or [])}
        atomic_write_text(path, source, mode=FILE_MODE)
        atomic_write_text(meta_path, json.dumps(meta, indent=2) + "\n", mode=FILE_MODE)
        return {**meta, "path": str(path)}

    def get(self, name: str) -> Dict[str, Any]:
        """The stored source with its metadata; ``modified_externally`` flags a hand edit."""
        validate_name(name, _WHAT)
        path, meta_path, _ = self._paths(name, create=False)
        if not path.is_file():
            raise store_error(f"no stored yara rule {name!r}", "yara_rule.not_found",
                              ErrorCategory.NOT_FOUND)
        source = path.read_text(encoding="utf-8")
        actual = sha256_text(source)
        recorded = read_json_dict(meta_path) or {}
        drifted = actual != recorded.get("sha256", actual)
        return {"name": name, "created": recorded.get("created"),
                "updated": recorded.get("updated"), "version": recorded.get("version"),
                "sha256": actual, "size": len(source.encode("utf-8")), "path": str(path),
                "compiles": None if drifted else recorded.get("compiles"),
                "errors": [] if drifted else recorded.get("errors", []),
                "rule_names": [] if drifted else recorded.get("rule_names", []),
                "source": source, "modified_externally": drifted}

    def list(self) -> List[Dict[str, Any]]:
        """Metadata of every stored rule, by name (no source text)."""
        directory = self._dir(create=False)
        if not directory.is_dir():
            return []
        out: List[Dict[str, Any]] = []
        for path in sorted(directory.glob(f"*{RULE_SUFFIX}")):
            if not NAME_PATTERN.match(path.stem) or path.is_symlink():
                continue
            if not path.is_file():
                continue
            try:
                meta = self.get(path.stem)
            except Exception as exc:    # unreadable entry: a row, never a failed list
                out.append({"name": path.stem, "path": str(path), "error": str(exc)})
                continue
            meta.pop("source", None)
            out.append(meta)
        return out

    def delete(self, name: str) -> Dict[str, Any]:
        """Remove ``name`` from the live set; its source is archived to history first."""
        validate_name(name, _WHAT)
        path, meta_path, history = self._paths(name, create=False)
        if not path.is_file():
            raise store_error(f"no stored yara rule {name!r}", "yara_rule.not_found",
                              ErrorCategory.NOT_FOUND)
        with self._write_lock():
            if not path.is_file():
                raise store_error(f"no stored yara rule {name!r}", "yara_rule.not_found",
                                  ErrorCategory.NOT_FOUND)
            source = path.read_text(encoding="utf-8")
            archive_previous(path, history, name, RULE_SUFFIX, source)
            previous = read_json_dict(meta_path) or {}
            version = previous.get("version")
            path.unlink()
            # Tombstone: keeps version/created so a later re-put continues the numbering.
            tombstone = {"name": name, "deleted": True, "version": int(version or 0),
                         "created": previous.get("created"), "updated": utc_now()}
            atomic_write_text(meta_path, json.dumps(tombstone, indent=2) + "\n", mode=FILE_MODE)
        return {"name": name, "deleted": True, "version": version,
                "sha256": sha256_text(source), "history_dir": str(history)}
