"""Case-scoped store of vol3 plugin fixtures (plan T2.8, D13).

A fixture is ``{name, plugin | source_name, view_path, args, expect}`` stored at
``<case>/fixtures/vol3/<name>.json``. ``plugin`` is a bundled plugin name and
``source_name`` a plugin stored by :mod:`memdiver.analysis.plugin_store`;
exactly one is set. ``expect`` is a non-empty list of declarative predicates
(:mod:`memdiver.analysis.fixture_predicates`). Overwriting a name archives the
previous definition under ``fixtures/vol3/history/``; nothing is deleted.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List, Optional

from memdiver.analysis.fixture_predicates import validate_predicate
from memdiver.analysis.plugin_store import (
    json_dicts_in,
    put_versioned_json,
    read_json_dict,
    safe_directory,
    safe_file,
    store_error,
    validate_name,
)
from memdiver.core.service_errors import ErrorCategory

FIXTURES_SUBPATH = "fixtures/vol3"


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
        body = {"name": name, "plugin": plugin or "", "source_name": source_name,
                "view_path": str(view_path), "args": dict(args or {}),
                "expect": _validated_expect(expect)}
        return put_versioned_json(safe_file(directory, f"{name}.json"), name, body)

    def get(self, name: str) -> Dict[str, Any]:
        validate_name(name, "fixture")
        directory = self._dir(create=False)
        path = safe_file(directory, f"{name}.json")
        body = read_json_dict(path)
        if body is None:
            raise store_error(f"no stored fixture {name!r}", "fixture.not_found",
                         ErrorCategory.NOT_FOUND)
        return {**body, "path": str(path)}

    def list(self) -> List[Dict[str, Any]]:
        return [{**body, "path": str(path)}
                for path, body in json_dicts_in(self._dir(create=False))]
