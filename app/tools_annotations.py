"""Analysis-record producers: list, add, supersede, retract annotations.

The ``annotations.*`` capabilities. Each producer is a thin, surface-agnostic
wrapper over :class:`memdiver.analysis.record_store.AnalysisRecord` and returns
a :class:`~memdiver.core.service_result.ServiceResult` whose payload is plain
JSON. Bad input is RAISED as a :class:`CapabilityError`.

``case_dir`` is REQUIRED on every surface for now: the Case abstraction with a
default directory (``~/.memdiver/cases/<name>``) arrives with plan task T1.8.
Locations are dicts as produced by ``Location.to_dict()``.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

from memdiver.analysis.record import (RETRACTION, AnalysisEntry, Support,
                                      retraction_of)
from memdiver.analysis.record_store import AnalysisRecord
from memdiver.core.location import Location
from memdiver.core.service_errors import CapabilityError, ErrorCategory
from memdiver.core.service_result import ServiceResult

#: Fields :func:`annotations_supersede_result` lets a replacement change.
SUPERSEDABLE_FIELDS = ("kind", "locations", "length", "label", "payload", "support")


def _invalid(message: str, code: str = "invalid_annotation") -> CapabilityError:
    return CapabilityError(message, category=ErrorCategory.INVALID_INPUT, code=code)


def _record(case_dir: str) -> AnalysisRecord:
    if not case_dir or not str(case_dir).strip():
        raise _invalid("case_dir is required", "case_dir_required")
    return AnalysisRecord(Path(case_dir).expanduser())


def _parse_locations(locations: Optional[Sequence[Dict[str, Any]]]) -> List[Location]:
    try:
        return [Location.from_dict(dict(item)) for item in locations or ()]
    except (KeyError, TypeError, ValueError) as exc:
        raise _invalid(f"invalid location: {exc!r}", "invalid_location") from exc


def _parse_support(support: Optional[Sequence[Dict[str, Any]]]) -> List[Support]:
    try:
        return [Support.from_dict(dict(item)) for item in support or ()]
    except (KeyError, TypeError, ValueError) as exc:
        raise _invalid(f"invalid support item: {exc!r}", "invalid_support") from exc


def _build_entry(capture_id: str, **fields: Any) -> AnalysisEntry:
    """Construct an entry, turning schema ``ValueError``/``TypeError`` into input errors."""
    try:
        return AnalysisEntry(capture_id=capture_id, **fields)
    except (TypeError, ValueError) as exc:
        raise _invalid(str(exc)) from exc


def _entry_payload(entry: AnalysisEntry, superseded: Optional[bool] = None) -> Dict[str, Any]:
    body = entry.to_dict()
    if superseded is not None:
        body["superseded"] = superseded
    return body


def annotations_list_result(
    case_dir: str, capture_id: str, kind: Optional[str] = None,
    include_superseded: bool = False,
) -> "ServiceResult":
    """Current entries of a capture (or, with ``include_superseded``, every entry).

    Each entry carries a ``superseded`` flag; retractions are listed only when
    ``include_superseded`` is true.
    """
    record = _record(case_dir)
    superseded = {e.supersedes for e in record.entries(capture_id) if e.supersedes}
    shown = (record.entries(capture_id, kind) if include_superseded
             else record.latest(capture_id, kind))
    return ServiceResult.ok({
        "case_dir": str(case_dir), "capture_id": capture_id, "kind": kind,
        "include_superseded": include_superseded, "count": len(shown),
        "entries": [_entry_payload(e, e.id in superseded) for e in shown]})


def annotations_add_result(
    case_dir: str, capture_id: str, kind: str, author: str,
    locations: Optional[Sequence[Dict[str, Any]]] = None, label: str = "",
    payload: Optional[Dict[str, Any]] = None,
    support: Optional[Sequence[Dict[str, Any]]] = None,
    length: Optional[int] = None,
) -> "ServiceResult":
    """Append one new entry to the capture's analysis record."""
    if kind == RETRACTION:
        raise _invalid("use annotations_retract to withdraw an entry", "use_retract")
    entry = _build_entry(
        capture_id, kind=kind, author=author, locations=tuple(_parse_locations(locations)),
        length=length, label=label, payload=dict(payload or {}),
        support=tuple(_parse_support(support)))
    return ServiceResult.ok({"entry": _entry_payload(_record(case_dir).append(entry))})


def annotations_supersede_result(
    case_dir: str, capture_id: str, entry_id: str, author: str, **new_fields: Any,
) -> "ServiceResult":
    """Append an entry that replaces ``entry_id``; unspecified fields are inherited."""
    unknown = sorted(set(new_fields) - set(SUPERSEDABLE_FIELDS))
    if unknown:
        raise _invalid(f"cannot change {unknown}; allowed: {list(SUPERSEDABLE_FIELDS)}",
                       "unsupported_field")
    record = _record(case_dir)
    old = record.get(capture_id, entry_id)
    entry = _build_entry(capture_id, author=author, supersedes=old.id,
                         **_merged_fields(old, new_fields))
    return ServiceResult.ok({"entry": _entry_payload(record.append(entry)),
                             "supersedes": old.id})


def _merged_fields(old: AnalysisEntry, new_fields: Dict[str, Any]) -> Dict[str, Any]:
    merged: Dict[str, Any] = {
        "kind": old.kind, "locations": old.locations, "length": old.length,
        "label": old.label, "payload": old.payload, "support": old.support}
    given = {k: v for k, v in new_fields.items() if v is not None}
    if "locations" in given:
        given["locations"] = tuple(_parse_locations(given["locations"]))
    if "support" in given:
        given["support"] = tuple(_parse_support(given["support"]))
    merged.update(given)
    return merged


def annotations_retract_result(
    case_dir: str, capture_id: str, entry_id: str, author: str, reason: str = "",
) -> "ServiceResult":
    """Withdraw ``entry_id`` by appending a retraction entry (the log is never edited)."""
    record = _record(case_dir)
    target = record.get(capture_id, entry_id)
    try:
        retraction = retraction_of(target, author, reason)
    except ValueError as exc:
        raise _invalid(str(exc)) from exc
    return ServiceResult.ok({"entry": _entry_payload(record.append(retraction)),
                             "retracted": target.id})


__all__ = ["SUPERSEDABLE_FIELDS", "annotations_list_result",
           "annotations_add_result", "annotations_supersede_result",
           "annotations_retract_result"]
