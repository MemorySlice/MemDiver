"""Stored user plugin sources: list, get, put (plan T2.5).

The ``vol3.source_*`` capabilities. Sources live in the case directory
(:class:`memdiver.analysis.plugin_store.PluginStore`); ``vol3_run`` /
``vol3_describe`` / ``vol3_check`` accept ``source_name`` + ``case_dir`` in
place of raw ``source`` text, resolved by :func:`_resolve_source`. Running a
stored source is as unsandboxed as running a raw one (D7); its sha256 is logged
by the runner path exactly as for raw text.
"""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from memdiver.core.service_errors import CapabilityError, ErrorCategory
from memdiver.core.service_result import ServiceResult


def _store(case_dir: str) -> Any:
    from memdiver.analysis.plugin_store import PluginStore
    from memdiver.app.tools_case import _open
    return PluginStore(_open(case_dir).dir)


def _resolve_source(source: Optional[str], source_name: Optional[str],
                   case_dir: Optional[str]) -> Optional[str]:
    """The plugin source text: ``source`` as given, or the stored ``source_name``."""
    if not source_name:
        return source
    if source:
        raise CapabilityError("give source or source_name, not both",
                              category=ErrorCategory.INVALID_INPUT, code="vol3.source_ambiguous")
    if not case_dir:
        raise CapabilityError("source_name needs case_dir (the case that stores it)",
                              category=ErrorCategory.INVALID_INPUT,
                              code="vol3.source_case_required")
    # Same lookup as the listing / get: a user source first, else a synthesized plugin.
    return str(vol3_source_get_result(case_dir, source_name).payload["source"])


#: The case layout of synthesized plugins, defined ONCE here (this module is light, so
#: ``app.tools_pipeline`` re-exports them as ``SYNTH_STORE_DIR`` / ``SYNTH_HISTORY_DIR``
#: and ``app.tools_vol3_dev`` refuses the history directory as ``vol -p``). Replaced
#: versions live in the sibling history directory and are never listed or passed to
#: ``vol -p``: vol imports every ``.py`` beneath a ``-p`` directory.
SYNTHESIZED_DIR = "vol3/plugins"
SYNTHESIZED_HISTORY_DIR = "vol3/history"
ORIGIN_USER = "user"
ORIGIN_SYNTHESIZED = "synthesized"
RECIPE_SUFFIX = ".recipe.json"


def _iso_mtime(path: Path) -> str:
    return datetime.fromtimestamp(path.stat().st_mtime, tz=timezone.utc).isoformat()


def _synthesized_entry(path: Path) -> Dict[str, Any]:
    """Listing metadata of one synthesized plugin, with its recipe's name/oracle when present."""
    from memdiver.analysis.plugin_store import read_json_dict, sha256_text
    source = path.read_text(encoding="utf-8")
    recipe_path = path.with_name(path.stem + RECIPE_SUFFIX)
    recipe = read_json_dict(recipe_path) or {}
    oracle = recipe.get("oracle") if isinstance(recipe.get("oracle"), dict) else {}
    stamp = _iso_mtime(path)
    return {"name": path.stem, "sha256": sha256_text(source), "size": len(source.encode("utf-8")),
            "created": stamp, "updated": stamp, "version": None, "path": str(path),
            "origin": ORIGIN_SYNTHESIZED, "kind": ORIGIN_SYNTHESIZED,
            "description": recipe.get("description") or None,
            "oracle_kind": oracle.get("kind") or None,
            "recipe_path": str(recipe_path) if recipe else None}


def _synthesized_dir(case_dir: str) -> Optional[Path]:
    from memdiver.analysis.plugin_store import safe_directory
    from memdiver.app.tools_case import _open
    directory = safe_directory(_open(case_dir).dir, SYNTHESIZED_DIR, create=False)
    return directory if directory.is_dir() else None


def _synthesized_paths(case_dir: str) -> List[Path]:
    """Synthesized ``<name>.py`` files (never symlinks, identifier names only), by name."""
    from memdiver.analysis.plugin_store import NAME_PATTERN
    directory = _synthesized_dir(case_dir)
    if directory is None:
        return []
    return [p for p in sorted(directory.glob("*.py"))
            if NAME_PATTERN.match(p.stem) and not p.is_symlink()]


def _synthesized_plugin_dir(case_dir: str) -> Optional[str]:
    """The ``vol -p`` directory of synthesized plugins, or ``None`` when there is none.

    Only ``<case>/vol3/plugins``: never ``<case>/vol3/history``, whose archived
    versions vol would import as extra plugins.
    """
    directory = _synthesized_dir(case_dir)
    return str(directory) if directory is not None else None


def vol3_source_list_result(case_dir: str) -> "ServiceResult":
    """Metadata (name, sha256, size, updated, version) of every stored plugin source.

    Includes the plugins ``synthesize_vol3_plugin`` wrote (``origin: "synthesized"``,
    plus ``description`` / ``oracle_kind`` / ``recipe_path`` from the recipe beside
    them); a stored user source of the same name is listed first, both are shown.
    """
    sources = [{**s, "origin": ORIGIN_USER} for s in _store(case_dir).list()]
    sources += [_synthesized_entry(p) for p in _synthesized_paths(case_dir)]
    return ServiceResult.ok({"case_dir": str(case_dir), "sources": sources,
                             "count": len(sources)})


def vol3_source_get_result(case_dir: str, name: str,
                           origin: Optional[str] = None) -> "ServiceResult":
    """One stored plugin source with its metadata (a synthesized one when no user source has the name).

    ``origin`` (``"user"`` / ``"synthesized"``) picks one side when a user source and a
    synthesized plugin share ``name`` -- the listing shows both, and without it the
    synthesized one could never be opened. Omitted: user first, synthesized fallback.
    """
    if origin not in (None, ORIGIN_USER, ORIGIN_SYNTHESIZED):
        raise CapabilityError(f"origin must be {ORIGIN_USER!r} or {ORIGIN_SYNTHESIZED!r}",
                              category=ErrorCategory.INVALID_INPUT, code="vol3.source_origin")
    if origin != ORIGIN_SYNTHESIZED:
        try:
            return ServiceResult.ok({**_store(case_dir).get(name), "origin": ORIGIN_USER})
        except CapabilityError as exc:
            if exc.code != "plugin.not_found" or origin == ORIGIN_USER:
                raise
            not_found = exc
    match = [p for p in _synthesized_paths(case_dir) if p.stem == name]
    if not match:
        if origin is None:
            raise not_found
        raise CapabilityError(f"no synthesized plugin {name!r}", category=ErrorCategory.NOT_FOUND,
                              code="plugin.not_found")
    return ServiceResult.ok({**_synthesized_entry(match[0]),
                             "source": match[0].read_text(encoding="utf-8")})


def vol3_source_put_result(case_dir: str, name: str, source: str,
                           view_path: Optional[str] = None) -> "ServiceResult":
    """Store ``source`` as ``name`` and check it; a plugin that does not load is still saved.

    The ``check`` entry is :func:`vol3_check_result`'s payload (``ok: false`` with
    a line number for a broken plugin), so an editor can show it next to the save.
    """
    from memdiver.app.tools_vol3_dev import vol3_check_result
    stored = _store(case_dir).put(name, source)
    check: Dict[str, Any] = vol3_check_result(source, view_path).payload
    return ServiceResult.ok({"stored": stored, "check": check})
