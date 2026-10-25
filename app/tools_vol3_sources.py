"""Stored user plugin sources: list, get, put (plan T2.5).

The ``vol3.source_*`` capabilities. Sources live in the case directory
(:class:`memdiver.analysis.plugin_store.PluginStore`); ``vol3_run`` /
``vol3_describe`` / ``vol3_check`` accept ``source_name`` + ``case_dir`` in
place of raw ``source`` text, resolved by :func:`_resolve_source`. Running a
stored source is as unsandboxed as running a raw one (D7); its sha256 is logged
by the runner path exactly as for raw text.
"""

from __future__ import annotations

from typing import Any, Dict, Optional

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
    return str(_store(case_dir).get(source_name)["source"])


def vol3_source_list_result(case_dir: str) -> "ServiceResult":
    """Metadata (name, sha256, size, updated, version) of every stored plugin source."""
    sources = _store(case_dir).list()
    return ServiceResult.ok({"case_dir": str(case_dir), "sources": sources,
                             "count": len(sources)})


def vol3_source_get_result(case_dir: str, name: str) -> "ServiceResult":
    """One stored plugin source with its metadata."""
    return ServiceResult.ok(_store(case_dir).get(name))


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
