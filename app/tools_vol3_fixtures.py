"""Plugin fixtures: put, list, run (plan T2.8, D13).

The ``vol3.fixture_*`` capabilities. A fixture names a plugin (bundled, or a
stored source), a ``.mdview`` and declarative row predicates
(:mod:`memdiver.analysis.fixture_predicates`). Running one executes the plugin
and records a ``fixture_verdict`` entry in the analysis record.

Verdict vocabulary (the oracle smoke test's, narrowed to what a row check can
prove): ``pass`` — every predicate held on a complete run; ``fail`` — a
predicate was contradicted; ``indeterminate`` — nothing could be proven: the
run was truncated or timed out, the view could not be opened, or the plugin
could not run. ``predicates`` carries the per-predicate outcome either way.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List, Optional

from memdiver.core.service_errors import CapabilityError, ErrorCategory
from memdiver.core.service_result import ServiceResult

PASS, FAIL, INDETERMINATE = "pass", "fail", "indeterminate"
VERDICT_AUTHOR = "tool:vol3"
DEFAULT_FIXTURE_ROWS = 100_000
DEFAULT_FIXTURE_TIMEOUT_S = 300.0
#: Errors that mean "could not evaluate", not "the plugin is wrong".
_UNEVALUABLE = (ErrorCategory.NOT_FOUND, ErrorCategory.UNSUPPORTED,
                ErrorCategory.PRECONDITION, ErrorCategory.INVALID_INPUT)


def _case(case_dir: str) -> Any:
    from memdiver.app.tools_case import _open
    return _open(case_dir)


def vol3_fixture_put_result(case_dir: str, name: str, *, view_path: str, expect: List[Dict[str, Any]],
                            plugin: str = "", source_name: Optional[str] = None,
                            args: Optional[Dict[str, Any]] = None) -> "ServiceResult":
    """Store a fixture at ``<case>/fixtures/vol3/<name>.json`` (validated, versioned)."""
    from memdiver.analysis.fixture_store import FixtureStore
    stored = FixtureStore(_case(case_dir).dir).put(
        name, plugin=plugin, source_name=source_name, view_path=view_path,
        args=args, expect=expect)
    return ServiceResult.ok(stored)


def _last_verdicts(case_dir: Any) -> Dict[str, Dict[str, Any]]:
    """Newest live ``fixture_verdict`` per fixture name, one scan of every capture file."""
    from memdiver.analysis.record import FIXTURE_VERDICT
    from memdiver.analysis.record_store import AnalysisRecord
    record = AnalysisRecord(case_dir)
    newest: Dict[str, Any] = {}
    for capture_id in record.captures():
        for entry in record.latest(capture_id, FIXTURE_VERDICT):
            fixture = entry.payload.get("fixture")
            if fixture is not None and (fixture not in newest
                                        or entry.created >= newest[fixture].created):
                newest[fixture] = entry
    return {name: {"verdict": e.payload.get("verdict"), "created": e.created,
                   "entry_id": e.id, "capture_id": e.capture_id}
            for name, e in newest.items()}


def vol3_fixture_list_result(case_dir: str) -> "ServiceResult":
    """Every stored fixture definition, each with ``last_verdict`` (or ``None``)."""
    from memdiver.analysis.fixture_store import FixtureStore
    case = _case(case_dir)
    verdicts = _last_verdicts(case.dir)
    fixtures = [{**f, "last_verdict": verdicts.get(f.get("name"))}
                for f in FixtureStore(case.dir).list()]
    return ServiceResult.ok({"case_dir": str(case_dir), "fixtures": fixtures,
                             "count": len(fixtures)})


def _row_dicts(payload: Dict[str, Any]) -> List[Dict[str, Any]]:
    names = [column["name"] for column in payload["columns"]]
    return [dict(zip(names, row["values"])) for row in payload["rows"]]


def _verdict(predicates: List[Dict[str, Any]], truncated: bool) -> str:
    if truncated:
        return INDETERMINATE
    return PASS if all(p["ok"] for p in predicates) else FAIL


def _indeterminate(reason: str, code: str) -> Dict[str, Any]:
    return {"verdict": INDETERMINATE, "reason": reason, "reason_code": code,
            "predicates": [], "row_count": None, "truncated": None, "run_id": None}


def _execute(case_dir: str, fixture: Dict[str, Any], view_path: str, limit: int,
             timeout_s: float, register_run: bool) -> Dict[str, Any]:
    from memdiver.analysis.fixture_predicates import evaluate_all
    from memdiver.app.tools_vol3 import vol3_run_result
    from memdiver.app.tools_vol3_sources import _resolve_source
    try:
        source = _resolve_source(None, fixture["source_name"], case_dir)
        run = vol3_run_result(
            view_path, fixture["plugin"], fixture["args"], limit=limit, timeout_s=timeout_s,
            max_rows=limit, case_dir=case_dir if register_run else None, source=source)
    except CapabilityError as exc:
        if exc.category not in _UNEVALUABLE:
            raise
        return _indeterminate(str(exc), exc.code or "vol3.fixture_unevaluable")
    payload = run.payload
    predicates = evaluate_all(fixture["expect"], _row_dicts(payload))
    reason = (f"run stopped early: {payload.get('stop_reason') or 'truncated'}"
              if payload["truncated"] else None)
    return {"verdict": _verdict(predicates, bool(payload["truncated"])), "reason": reason,
            "reason_code": None, "predicates": predicates, "row_count": payload["row_count"],
            "truncated": payload["truncated"], "run_id": payload.get("run_id")}


def _capture_id(view_path: str) -> Optional[str]:
    """The view's capture id, or ``None`` when the view cannot be read."""
    from memdiver.analysis.capture_id import capture_id_for
    from memdiver.app.tools_image import _read_descriptor
    try:
        path, _ = _read_descriptor(view_path)
        return str(capture_id_for(path))
    except (CapabilityError, OSError, ValueError):
        return None


def _record_verdict(case: Any, fixture: Dict[str, Any], outcome: Dict[str, Any],
                    capture_id: str) -> str:
    from memdiver.analysis.record import FIXTURE_VERDICT, AnalysisEntry, Support
    from memdiver.analysis.record_store import AnalysisRecord
    target = fixture["source_name"] or fixture["plugin"]
    support = (Support("vol3_run", outcome["run_id"]),) if outcome["run_id"] else ()
    entry = AnalysisEntry(
        capture_id=capture_id, kind=FIXTURE_VERDICT, author=VERDICT_AUTHOR,
        label=f"fixture {fixture['name']}: {outcome['verdict']}", support=support,
        payload={"fixture": fixture["name"], "fixture_version": fixture.get("version"),
                 "plugin": target, "view_path": fixture["view_path"], **outcome})
    return AnalysisRecord(case.dir).append(entry).id


def vol3_fixture_run_result(case_dir: str, name: str, *, view_path: Optional[str] = None,
                            limit: int = DEFAULT_FIXTURE_ROWS,
                            timeout_s: float = DEFAULT_FIXTURE_TIMEOUT_S,
                            register_run: bool = False) -> "ServiceResult":
    """Run fixture ``name``, evaluate its predicates and file the verdict.

    ``view_path`` overrides the stored view (same fixture, another capture).
    ``register_run`` also files the plugin table in the case and links the
    verdict to that run. The verdict is recorded only when the view's capture id
    is known (``recorded`` says whether it was).
    """
    from memdiver.analysis.fixture_store import FixtureStore
    case = _case(case_dir)
    fixture = FixtureStore(case.dir).get(name)
    view = view_path or fixture["view_path"]
    outcome = _execute(str(case.dir), fixture, view, limit, timeout_s, register_run)
    capture_id = _capture_id(view)
    entry_id = _record_verdict(case, fixture, outcome, capture_id) if capture_id else None
    return ServiceResult.ok({"fixture": name, "view_path": str(Path(view)), "capture_id": capture_id,
                             "recorded": entry_id is not None, "entry_id": entry_id, **outcome})
