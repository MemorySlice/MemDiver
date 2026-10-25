"""Declarative row predicates for plugin fixtures (plan T2.8, D13).

A predicate is a one-key JSON object evaluated over a plugin run's rows
(``list[dict]`` keyed by column name):

* ``{"min_rows": N}`` / ``{"max_rows": N}``
* ``{"row_where": {"COMM": "sshd", "PID": 22176}, "count_at_least": 1,
  "count_at_most": N}`` — rows whose columns ALL equal the given values; the
  count must lie within the bounds (``count_at_least`` defaults to 1)
* ``{"column_all": {"column": "PID", "op": ">=", "value": 0}}`` — every row
* ``{"column_any": {...}}`` — at least one row

``op`` is one of ``== != < <= > >= contains``. Pure and stdlib-only.
"""

from __future__ import annotations

from typing import Any, Callable, Dict, List, Mapping, Optional, Sequence

Row = Mapping[str, Any]
OPERATORS = ("==", "!=", "<", "<=", ">", ">=", "contains")
_ROW_WHERE_BOUNDS = ("count_at_least", "count_at_most")


def _bad(message: str) -> ValueError:
    return ValueError(message)


def _column(row: Row, name: str) -> "tuple[bool, Any]":
    """``(present, value)``; an exact column name first, then case-insensitive."""
    if name in row:
        return True, row[name]
    lowered = name.lower()
    for key, value in row.items():
        if str(key).lower() == lowered:
            return True, value
    return False, None


def _equal(left: Any, right: Any) -> bool:
    return left == right or (left is not None and right is not None
                             and str(left) == str(right))


def _compare(left: Any, op: str, right: Any) -> bool:
    if op == "==":
        return _equal(left, right)
    if op == "!=":
        return not _equal(left, right)
    if left is None:
        return False
    if op == "contains":
        return str(right) in str(left)
    try:
        return {"<": left < right, "<=": left <= right,
                ">": left > right, ">=": left >= right}[op]
    except TypeError:
        return False


def _matches(row: Row, wanted: Mapping[str, Any]) -> bool:
    for name, value in wanted.items():
        present, actual = _column(row, name)
        if not present or not _equal(actual, value):
            return False
    return True


def _int_bound(spec: Mapping[str, Any], key: str) -> Optional[int]:
    value = spec.get(key)
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise _bad(f"{key} must be a non-negative integer, got {value!r}")
    return value


def _check_row_where(spec: Any, bounds: Mapping[str, Any]) -> None:
    if not isinstance(spec, dict) or not spec:
        raise _bad("row_where must be a non-empty object of column: value")
    for key in bounds:
        if key not in _ROW_WHERE_BOUNDS:
            raise _bad(f"row_where takes only {', '.join(_ROW_WHERE_BOUNDS)}, got {key!r}")
    for key in _ROW_WHERE_BOUNDS:
        _int_bound(bounds, key)


def _check_column_spec(spec: Any, name: str) -> None:
    if not isinstance(spec, dict) or not {"column", "op", "value"} <= set(spec):
        raise _bad(f"{name} needs column, op and value")
    if spec["op"] not in OPERATORS:
        raise _bad(f"{name} op must be one of {', '.join(OPERATORS)}, got {spec['op']!r}")


_KINDS = ("min_rows", "max_rows", "row_where", "column_all", "column_any")


def validate_predicate(predicate: Any) -> str:
    """The predicate's kind, or ``ValueError`` naming what is wrong with it."""
    if not isinstance(predicate, dict):
        raise _bad(f"a predicate is an object, got {type(predicate).__name__}")
    kinds = [k for k in predicate if k in _KINDS]
    if len(kinds) != 1:
        raise _bad(f"a predicate has exactly one of {', '.join(_KINDS)}; got "
                   f"{sorted(predicate)}")
    kind = kinds[0]
    extras = {k: v for k, v in predicate.items() if k != kind}
    if kind in ("min_rows", "max_rows"):
        if extras:
            raise _bad(f"{kind} takes no other keys, got {sorted(extras)}")
        _int_bound(predicate, kind)
    elif kind == "row_where":
        _check_row_where(predicate[kind], extras)
    else:
        if extras:
            raise _bad(f"{kind} takes no other keys, got {sorted(extras)}")
        _check_column_spec(predicate[kind], kind)
    return kind


def _eval_row_count(kind: str, predicate: Dict[str, Any], rows: Sequence[Row]) -> Dict[str, Any]:
    count = len(rows)
    bound = int(predicate[kind])
    ok = count >= bound if kind == "min_rows" else count <= bound
    return {"ok": ok, "detail": f"{count} rows, need {kind.split('_')[0]} {bound}"}


def _eval_row_where(predicate: Dict[str, Any], rows: Sequence[Row]) -> Dict[str, Any]:
    count = sum(1 for row in rows if _matches(row, predicate["row_where"]))
    at_least = _int_bound(predicate, "count_at_least")
    low = at_least if at_least is not None else (0 if "count_at_most" in predicate else 1)
    high = _int_bound(predicate, "count_at_most")
    ok = count >= low and (high is None or count <= high)
    bounds = f">= {low}" + (f" and <= {high}" if high is not None else "")
    return {"ok": ok, "detail": f"{count} matching rows, need {bounds}", "matched": count}


def _eval_column(kind: str, predicate: Dict[str, Any], rows: Sequence[Row]) -> Dict[str, Any]:
    spec = predicate[kind]
    seen, hits = 0, 0
    for row in rows:
        present, value = _column(row, spec["column"])
        if present:
            seen += 1
            hits += _compare(value, spec["op"], spec["value"])
    if rows and not seen:
        return {"ok": False, "detail": f"column {spec['column']!r} is not in the result"}
    if kind == "column_all" and not rows:
        # `all()` over nothing is vacuously true; a fixture asserting on a
        # column must see rows, so an empty result fails.
        return {"ok": False, "detail": "no rows"}
    ok = hits == len(rows) if kind == "column_all" else hits >= 1
    return {"ok": ok, "detail": f"{hits} of {len(rows)} rows satisfy "
                                f"{spec['column']} {spec['op']} {spec['value']!r}"}


def evaluate_predicate(predicate: Dict[str, Any], rows: Sequence[Row]) -> Dict[str, Any]:
    """``{"predicate", "ok", "detail"}`` for one predicate over ``rows``."""
    kind = validate_predicate(predicate)
    evaluators: Dict[str, Callable[[], Dict[str, Any]]] = {
        "min_rows": lambda: _eval_row_count(kind, predicate, rows),
        "max_rows": lambda: _eval_row_count(kind, predicate, rows),
        "row_where": lambda: _eval_row_where(predicate, rows),
        "column_all": lambda: _eval_column(kind, predicate, rows),
        "column_any": lambda: _eval_column(kind, predicate, rows),
    }
    return {"predicate": predicate, **evaluators[kind]()}


def evaluate_all(predicates: Sequence[Dict[str, Any]], rows: Sequence[Row]) -> List[Dict[str, Any]]:
    return [evaluate_predicate(p, rows) for p in predicates]
