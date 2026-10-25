"""Stored YARA rules: list, get, put, delete in a library and in a case.

The ``yara.rule_*`` capabilities. Rules live in two scopes
(:class:`memdiver.analysis.yara_rule_store.YaraRuleStore`): the per-user LIBRARY
(``<memdiver home>/yara_rules``) and a CASE (``<case>/yara_rules``). A case rule shadows a
library rule of the same name; ``get`` and :func:`resolve_rule_source` look in the case
first. ``yara_check`` / ``yara_scan_dump`` accept ``rule_name`` (+ ``case_dir``) in place of
``rule_source``, resolved here, exactly as the vol3 tools resolve ``source_name``.

Saving a draft that does not compile is allowed and flagged (``compiles: false`` plus the
errors with their lines), so an editor never loses work to a syntax error.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from memdiver.core.service_errors import CapabilityError, ErrorCategory
from memdiver.core.service_result import ServiceResult

LIBRARY = "library"
CASE = "case"
SCOPES = (LIBRARY, CASE)


def _invalid(message: str, code: str) -> CapabilityError:
    return CapabilityError(message, category=ErrorCategory.INVALID_INPUT, code=code)


def _library_store() -> Any:
    from memdiver.analysis.yara_rule_store import YaraRuleStore
    from memdiver.core.constants import memdiver_home
    return YaraRuleStore(memdiver_home())


def _case_store(case_dir: Optional[str]) -> Any:
    from memdiver.analysis.case import case_path
    from memdiver.analysis.yara_rule_store import YaraRuleStore
    if not case_dir or not str(case_dir).strip():
        raise _invalid("scope 'case' needs case_dir (the case that stores the rule)",
                       "yara_rule.case_required")
    root = case_path(case_dir)
    if not root.is_dir():
        raise CapabilityError(f"no case directory {str(root)!r}", category=ErrorCategory.NOT_FOUND,
                              code="yara_rule.case_not_found")
    return YaraRuleStore(root)


def _store(scope: str, case_dir: Optional[str]) -> Any:
    if scope not in SCOPES:
        raise _invalid(f"scope must be one of {list(SCOPES)}, got {scope!r}",
                       "yara_rule.bad_scope")
    return _library_store() if scope == LIBRARY else _case_store(case_dir)


def _with_scope(rows: List[Dict[str, Any]], scope: str) -> List[Dict[str, Any]]:
    return [{**row, "scope": scope} for row in rows]


AUTO = "auto"


def _default_scope(scope: Optional[str], case_dir: Optional[str]) -> str:
    """put/delete: an omitted scope is ``case`` when ``case_dir`` is given, else ``library``."""
    if scope is None or scope == "":
        return CASE if case_dir and str(case_dir).strip() else LIBRARY
    return scope


def _lookup(name: str, case_dir: Optional[str],
            scope: Optional[str] = None) -> Dict[str, Any]:
    """The rule by ``scope``: ``library`` / ``case`` exactly, or ``auto`` (default).

    ``auto`` looks in the case first when ``case_dir`` is given and falls back to the library.
    """
    scope = scope or AUTO
    if scope not in (AUTO, *SCOPES):
        raise _invalid(f"scope must be one of {[AUTO, *SCOPES]}, got {scope!r}",
                       "yara_rule.bad_scope")
    if scope in (CASE, LIBRARY):
        return {**_store(scope, case_dir).get(name), "scope": scope}
    if case_dir:
        try:
            return {**_case_store(case_dir).get(name), "scope": CASE}
        except CapabilityError as exc:
            if exc.code != "yara_rule.not_found":
                raise
    return {**_library_store().get(name), "scope": LIBRARY}


def resolve_rule_source(rule_source: Optional[str], rule_name: Optional[str],
                        case_dir: Optional[str]) -> Tuple[Optional[str], Optional[Dict[str, Any]]]:
    """``(source, origin)``: ``rule_source`` as given, or the stored ``rule_name``'s text.

    Exactly one of the two is accepted. ``origin`` is ``{"rule_name", "scope"}`` when the
    source came from the store, else ``None``.
    """
    if rule_name is None or rule_name == "":
        return rule_source, None
    if rule_source:
        raise _invalid("give rule_source or rule_name, not both", "yara_rule.source_ambiguous")
    found = _lookup(rule_name, case_dir)
    return str(found["source"]), {"rule_name": rule_name, "scope": found["scope"]}


def yara_rule_list_result(case_dir: Optional[str] = None) -> "ServiceResult":
    """Metadata of every stored rule: the library's and, with ``case_dir``, the case's.

    Each row carries ``scope``. A case rule with a library namesake has ``shadows: true``
    and the library row ``shadowed: true`` (``get`` and ``rule_name`` resolve the case one).
    An unreadable rule is a row with an ``error`` field. A ``case_dir`` that does not exist
    does not fail the list: the library rows come back with ``case_error`` set.
    """
    library = _with_scope(_library_store().list(), LIBRARY)
    case: List[Dict[str, Any]] = []
    case_error: Optional[str] = None
    if case_dir:
        try:
            case = _with_scope(_case_store(case_dir).list(), CASE)
        except CapabilityError as exc:
            if exc.code != "yara_rule.case_not_found":
                raise
            case_error = str(exc)
    case_names, library_names = {r["name"] for r in case}, {r["name"] for r in library}
    rules = [{**r, "shadows": r["name"] in library_names, "shadowed": False} for r in case] + \
            [{**r, "shadows": False, "shadowed": r["name"] in case_names} for r in library]
    return ServiceResult.ok({"case_dir": case_dir, "case_error": case_error,
                             "rules": rules, "count": len(rules)})


def yara_rule_get_result(name: str, case_dir: Optional[str] = None,
                         scope: Optional[str] = None) -> "ServiceResult":
    """One stored rule with its source.

    ``scope`` is ``library``, ``case`` or ``auto`` (default: the case wins over the library).
    """
    return ServiceResult.ok(_lookup(name, case_dir, scope))


def yara_rule_put_result(name: str, rule_source: str, scope: Optional[str] = None,
                         case_dir: Optional[str] = None) -> "ServiceResult":
    """Store ``rule_source`` as ``name`` in ``scope`` and compile-check it.

    An omitted ``scope`` is ``case`` when ``case_dir`` is given, else ``library``.
    A rule that does not compile is still saved: ``stored.compiles`` is ``false`` and
    ``stored.errors`` / ``check.errors`` carry ``{line, message}``.
    """
    from memdiver.app.tools_yara import yara_check_result
    scope = _default_scope(scope, case_dir)
    store = _store(scope, case_dir)
    check: Dict[str, Any] = yara_check_result(rule_source).payload
    stored = store.put(name, rule_source, check)
    return ServiceResult.ok({"stored": {**stored, "scope": scope}, "check": check})


def yara_rule_delete_result(name: str, scope: Optional[str] = None,
                            case_dir: Optional[str] = None) -> "ServiceResult":
    """Remove ``name`` from exactly ``scope`` (not found if it is only in the other scope).

    An omitted ``scope`` is ``case`` when ``case_dir`` is given, else ``library``. The last
    source stays in the scope's ``history/``.
    """
    scope = _default_scope(scope, case_dir)
    return ServiceResult.ok({**_store(scope, case_dir).delete(name), "scope": scope})


__all__ = ["AUTO", "CASE", "LIBRARY", "SCOPES", "resolve_rule_source", "yara_rule_delete_result",
           "yara_rule_get_result", "yara_rule_list_result", "yara_rule_put_result"]
