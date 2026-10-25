"""Built-in saved queries over the standard case tables (plan T2.2).

A :class:`SavedQuery` is a plain SQL string plus the case tables it reads and
the vol3 plugin that produces each table, so a missing table yields a message
that names the plugin to run. Queries are read-only SELECTs and go through
``Case.query`` like any other SQL.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List

from memdiver.core.service_errors import CapabilityError, ErrorCategory


@dataclass(frozen=True)
class SavedQuery:
    """One named query: SQL, description, and ``table -> producing plugin``."""

    name: str
    description: str
    sql: str
    requires: Dict[str, str]

    def to_dict(self) -> Dict[str, Any]:
        return {"name": self.name, "description": self.description,
                "sql": self.sql, "requires": dict(self.requires)}


def saved_queries() -> Dict[str, SavedQuery]:
    """Every built-in saved query by name."""
    from memdiver.analysis.queries import linux

    return {q.name: q for q in linux.QUERIES}


def get_saved_query(name: str) -> SavedQuery:
    """The query called ``name``; an unknown name lists the known ones."""
    found = saved_queries()
    if name not in found:
        raise CapabilityError(
            f"unknown saved query {name!r}; known: {', '.join(sorted(found))}",
            category=ErrorCategory.NOT_FOUND, code="vol3.unknown_saved_query")
    return found[name]


def missing_tables(query: SavedQuery, available: List[str]) -> Dict[str, str]:
    """``table -> plugin`` for each required table the case does not have."""
    return {t: p for t, p in query.requires.items() if t not in available}


def require_tables(query: SavedQuery, available: List[str]) -> None:
    """Raise a PRECONDITION error naming missing tables and the plugins to run."""
    missing = missing_tables(query, available)
    if not missing:
        return
    hint = "; ".join(f"{t} (run {p})" for t, p in missing.items())
    raise CapabilityError(
        f"saved query {query.name!r} needs table(s) not in this case: {hint}",
        category=ErrorCategory.PRECONDITION, code="vol3.missing_tables",
        details={"missing": missing})




def truncated_runs(query_tables: List[str], case: Any) -> List[Dict[str, Any]]:
    """Truncated runs of ``query_tables`` in ``case`` (table, run_id, stop_reason)."""
    found: List[Dict[str, Any]] = []
    for table in query_tables:
        if table not in case.tables():
            continue
        found.extend({"table": table, "run_id": r.run_id, "stop_reason": r.stop_reason}
                     for r in case.runs(table) if r.truncated)
    return found


def require_complete_runs(query: SavedQuery, case: Any) -> None:
    """Raise PRECONDITION when a required table has a truncated run in scope.

    A truncated run is a partial listing: set differences over it (e.g. psscan
    rows missing from pslist) would report artefacts of the cut as findings.
    """
    bad = truncated_runs(list(query.requires), case)
    if not bad:
        return
    first = bad[0]
    raise CapabilityError(
        f"saved query {query.name!r} refuses truncated input: table {first['table']} "
        f"run {first['run_id']} stopped early (stop_reason={first['stop_reason']!r}); "
        "re-run the plugin with a higher limit/timeout",
        category=ErrorCategory.PRECONDITION, code="vol3.query_truncated_input",
        details={"truncated_runs": bad})
