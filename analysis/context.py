"""``locate_context``: what is at this address? (plan T1.9, D12)

Every case table carries the standard columns ``capture_id, space, pid, addr,
size`` (D11), so "what contains this address" is ONE range-containment query
over all tables at once — regions, VMAs, modules, heap chunks, page-state runs,
plugin rows — plus a match against the analysis record's annotations. The
result is a :class:`ContextStack`, outermost layer first, each layer naming the
table and run it came from. The overlay, table row popovers, the agent and the
artifact model all use this one primitive instead of re-implementing joins.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Sequence, Tuple

from memdiver.analysis.case import Case
from memdiver.analysis.record_store import AnalysisRecord
from memdiver.core.location import Coverage, Location
from memdiver.core.service_errors import CapabilityError, ErrorCategory

#: Rows returned per call, across all tables (a context stack is a handful of layers).
DEFAULT_LIMIT = 200


@dataclass(frozen=True)
class ContextLayer:
    """One thing that contains the address: a table row or an annotation."""

    source: str              # "table" or "annotation"
    name: str                # table name, or the annotation's kind
    ref: str                 # run_id, or the annotation's entry id
    start: int
    end: int                 # exclusive
    row: Dict[str, Any] = field(default_factory=dict)

    @property
    def size(self) -> int:
        return self.end - self.start

    def to_dict(self) -> Dict[str, Any]:
        return {"source": self.source, "name": self.name, "ref": self.ref,
                "start": self.start, "end": self.end, "row": self.row}


@dataclass(frozen=True)
class ContextStack:
    """Everything containing ``location``, outermost first, plus read coverage."""

    location: Location
    layers: Tuple[ContextLayer, ...]
    coverage: Optional[Coverage] = None
    truncated: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return {"location": self.location.to_dict(),
                "layers": [layer.to_dict() for layer in self.layers],
                "coverage": self.coverage.to_dict() if self.coverage else None,
                "truncated": self.truncated}


def locate_context(case: Case, location: Location, *, source: Any = None,
                   length: int = 1, tables: Optional[Sequence[str]] = None,
                   limit: int = DEFAULT_LIMIT) -> ContextStack:
    """The containing stack of ``location`` in ``case``.

    ``location.capture_id`` is required: an address means nothing without the
    capture it belongs to. ``source`` (an open DumpSource with
    ``read_location``) adds the coverage of ``[value, value+length)``.
    """
    if location.capture_id is None:
        raise CapabilityError("locate_context needs a Location with capture_id",
                              category=ErrorCategory.INVALID_INPUT)
    rows, truncated = _table_layers(case, location, tables, limit)
    layers = rows + _annotation_layers(case, location)
    layers.sort(key=lambda layer: (-layer.size, layer.start, layer.source, layer.name))
    return ContextStack(location, tuple(layers), _coverage(source, location, length),
                        truncated)


def _table_layers(case: Case, location: Location, tables: Optional[Sequence[str]],
                  limit: int) -> Tuple[List[ContextLayer], bool]:
    names = [t for t in case.tables() if tables is None or t in tables]
    if not names:
        return [], False
    selects, params = zip(*(_containment_select(name, location) for name in names))
    sql = " UNION ALL ".join(selects)
    result = case.query(sql, limit=limit, params=[p for group in params for p in group])
    return [_layer_from_row(row) for row in result.table.to_pylist()], result.truncated


def _containment_select(name: str, location: Location) -> Tuple[str, List[Any]]:
    """One SELECT for one table. ``? - addr < size`` cannot overflow uint64."""
    sql = (f"SELECT '{name}' AS table_name, run_id, addr, size, to_json(r) AS row_json "
           f'FROM "{name}" r WHERE capture_id = ? AND space = ? '
           "AND addr <= ? AND ? - addr < size")
    params: List[Any] = [location.capture_id, location.space.value,
                         location.value, location.value]
    if location.pid is not None:
        sql += " AND (pid IS NULL OR pid = ?)"
        params.append(location.pid)
    return sql, params


def _layer_from_row(row: Dict[str, Any]) -> ContextLayer:
    start = int(row["addr"])
    return ContextLayer("table", row["table_name"], row["run_id"] or "",
                        start, start + int(row["size"]), json.loads(row["row_json"]))


def _annotation_layers(case: Case, location: Location) -> List[ContextLayer]:
    assert location.capture_id is not None
    record = AnalysisRecord(case.dir)
    if location.capture_id not in record.captures():
        return []
    layers = []
    for entry in record.latest(location.capture_id):
        for loc in entry.locations:
            span = max(entry.length or 1, 1)
            if _same_space(loc, location) and loc.value <= location.value < loc.value + span:
                layers.append(ContextLayer("annotation", entry.kind, entry.id, loc.value,
                                           loc.value + span, entry.to_dict()))
    return layers


def _same_space(candidate: Location, target: Location) -> bool:
    if candidate.space is not target.space:
        return False
    if candidate.capture_id not in (None, target.capture_id):
        return False
    return candidate.pid is None or target.pid is None or candidate.pid == target.pid


def _coverage(source: Any, location: Location, length: int) -> Optional[Coverage]:
    reader = getattr(source, "read_location", None)
    if not callable(reader):
        return None
    return reader(location.value, length).coverage
