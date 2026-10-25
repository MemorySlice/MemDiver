"""Case-scoped store of vol3 plugin fixtures (plan T2.8, D13).

A fixture is ``{name, plugin | source_name, view_path, args, expect}`` stored at
``<case>/fixtures/vol3/<name>.json``. ``plugin`` is a bundled plugin name and
``source_name`` a plugin stored by :mod:`memdiver.analysis.plugin_store`;
exactly one is set. ``expect`` is a non-empty list of declarative predicates
(:mod:`memdiver.analysis.fixture_predicates`). Overwriting a name archives the
previous definition under ``fixtures/vol3/history/``; nothing is deleted.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List, Optional

from memdiver.analysis.fixture_predicates import validate_predicate
from memdiver.analysis.plugin_store import (
    HISTORY_DIR,
    store_error,
    archive_previous,
    safe_directory,
    safe_file,
    sha256_text,
    validate_name,
)
from memdiver.analysis.record import utc_now
from memdiver.core.artifact_util import atomic_write_text
from memdiver.core.service_errors import ErrorCategory

FIXTURES_SUBPATH = "fixtures/vol3"
_FILE_MODE = 0o600


def _validated_expect(expect: Any) -> List[Dict[str, Any]]:
    if not isinstance(expect, list) or not expect:
        raise store_error("expect must be a non-empty list of predicates", "fixture.bad_expect")
    for index, predicate in enumerate(expect):
        try:
            validate_predicate(predicate)
        except ValueError as exc:
            raise store_error(f"expect[{index}]: {exc}", "fixture.bad_predicate") from exc
    return list(expect)


def _validated_target(plugin: str, source_name: Optional[str]) -> None:
    if bool(plugin) == bool(source_name):
        raise store_error("give exactly one of plugin (a bundled plugin) or source_name "
                     "(a stored plugin)", "fixture.bad_target")
    if source_name:
        validate_name(source_name, "plugin")


class FixtureStore:
    """The ``fixtures/vol3/`` directory of one case."""

    def __init__(self, case_dir: Path) -> None:
        self._case_dir = Path(case_dir)

    def _dir(self, create: bool) -> Path:
        return safe_directory(self._case_dir, FIXTURES_SUBPATH, create=create)

    def put(self, name: str, *, plugin: str = "", source_name: Optional[str] = None,
            view_path: str, args: Optional[Dict[str, Any]] = None,
            expect: Any) -> Dict[str, Any]:
        """Store a fixture definition; returns it with ``sha256``/``updated``/``version``."""
        validate_name(name, "fixture")
        _validated_target(plugin, source_name)
        if not view_path or not str(view_path).strip():
            raise store_error("view_path is required", "fixture.view_required")
        if args is not None and not isinstance(args, dict):
            raise store_error("args must be an object", "fixture.bad_args")
        directory = self._dir(create=True)
        path = safe_file(directory, f"{name}.json")
        previous = self._load(path)
        body = {"name": name, "plugin": plugin or "", "source_name": source_name,
                "view_path": str(view_path), "args": dict(args or {}),
                "expect": _validated_expect(expect),
                "created": (previous or {}).get("created") or utc_now(),
                "updated": utc_now(), "version": int((previous or {}).get("version", 0)) + 1}
        if path.is_file():
            archive_previous(path, directory / HISTORY_DIR, name, ".json",
                             path.read_text(encoding="utf-8"))
        text = json.dumps(body, indent=2, sort_keys=True) + "\n"
        atomic_write_text(path, text, mode=_FILE_MODE)
        return {**body, "sha256": sha256_text(text), "path": str(path)}

    def get(self, name: str) -> Dict[str, Any]:
        validate_name(name, "fixture")
        directory = self._dir(create=False)
        path = safe_file(directory, f"{name}.json")
        body = self._load(path)
        if body is None:
            raise store_error(f"no stored fixture {name!r}", "fixture.not_found",
                         ErrorCategory.NOT_FOUND)
        return {**body, "path": str(path)}

    def list(self) -> List[Dict[str, Any]]:
        directory = self._dir(create=False)
        if not directory.is_dir():
            return []
        out: List[Dict[str, Any]] = []
        for path in sorted(directory.glob("*.json")):
            body = self._load(path) if not path.is_symlink() else None
            if body is not None:
                out.append({**body, "path": str(path)})
        return out

    @staticmethod
    def _load(path: Path) -> "Dict[str, Any] | None":
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return None
        return data if isinstance(data, dict) else None
