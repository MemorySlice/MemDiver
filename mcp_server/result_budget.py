"""Opt-in per-call result budget for MCP tool results (default OFF).

``MEMDIVER_MCP_RESULT_BUDGET=<bytes>`` makes :func:`budget_tool` wrap a tool so
a result larger than the budget is deterministically shrunk and ALWAYS carries
a top-level ``_result_budget`` marker (never a silent truncation). Unset / ``0``
-> the tool is returned unwrapped, so behaviour is byte-identical.

Shrink order (JSON results): scalars are kept; every list keeps its first K
items (largest K that fits, min 1) with ``<key>__truncated = {kept, total}``;
nested dicts recurse one level; if K=1 still does not fit, the largest values
become ``{"omitted_bytes": n}``. Structured errors (``error`` + ``code``) that
fit the budget pass through byte-identical; an over-budget one keeps ``error`` /
``code`` / small keys and has its long string fields truncated (``_result_budget``).

Bound: ``returned_bytes <= max(budget, MIN_BUDGET)`` (UTF-8 bytes of the final
string, metadata included). Imports no web framework and not the ``mcp`` SDK.
"""

from __future__ import annotations

import functools
import inspect
import json
import os
from typing import Any, Callable, Optional

ENV_VAR = "MEMDIVER_MCP_RESULT_BUDGET"
#: Smallest honoured budget: below this the marker itself would not fit.
MIN_BUDGET = 1024
_PAGING_PARAMS = ("limit", "offset")
_BASE_HINT = (
    "Result truncated to fit the agent's result budget. Narrow the call "
    "({narrow}) or query the case table with case_query for the full data."
)


def budget_from_env(environ: Optional[dict] = None) -> int:
    """The configured budget in bytes (0 = off; junk / negative = off)."""
    raw = (environ if environ is not None else os.environ).get(ENV_VAR, "")
    try:
        value = int(str(raw).strip() or 0)
    except ValueError:
        return 0
    return max(value, MIN_BUDGET) if value > 0 else 0


def _size(obj: Any) -> int:
    return len(json.dumps(obj, default=str).encode("utf-8"))


def _hint(fn: Callable) -> str:
    try:
        params = set(inspect.signature(fn).parameters)
    except (TypeError, ValueError):
        params = set()
    names = [p for p in _PAGING_PARAMS if p in params]
    narrow = "/".join(names or _PAGING_PARAMS) + "/filters"
    return _BASE_HINT.format(narrow=narrow + ", detail='summary'")


def _cap_lists(node: dict, k: int, depth: int) -> dict:
    out: dict = {}
    for key, value in node.items():
        if isinstance(value, list) and len(value) > k:
            out[key] = value[:k]
            out[f"{key}__truncated"] = {"kept": k, "total": len(value)}
        elif isinstance(value, dict) and depth < 1:
            out[key] = _cap_lists(value, k, depth + 1)
        else:
            out[key] = value
    return out


def _omit_largest(node: dict, target: int) -> dict:
    """Replace the largest top-level / one-level-nested values until it fits."""
    node = {k: (dict(v) if isinstance(v, dict) else v) for k, v in node.items()}
    slots = [(node, k) for k in node]
    slots += [(v, k) for v in node.values() if isinstance(v, dict) for k in v]
    sized = sorted(slots, key=lambda s: -_size(s[0][s[1]]))
    for holder, key in sized:
        if _size(node) <= target:
            break
        if key.endswith("__truncated") or isinstance(holder.get(key), dict) \
                and set(holder[key]) == {"omitted_bytes"}:
            continue
        holder[key] = {"omitted_bytes": _size(holder[key])}
    return node


def _fit(body: dict, target: int) -> dict:
    """The largest-K list cap of ``body`` that fits ``target`` bytes."""
    longest = max([len(v) for v in body.values() if isinstance(v, list)]
                  + [len(x) for d in body.values() if isinstance(d, dict)
                     for x in d.values() if isinstance(x, list)] + [1])
    lo, hi, best = 1, longest, _cap_lists(body, 1, 0)
    while lo <= hi:
        mid = (lo + hi) // 2
        cand = _cap_lists(body, mid, 0)
        if _size(cand) <= target:
            best, lo = cand, mid + 1
        else:
            hi = mid - 1
    if _size(best) > target:
        best = _omit_largest(best, target)
    if _size(best) > target:
        best = {"_omitted_keys": len(body)}
    return best


def _shrink_json(parsed: Any, text: str, budget: int, hint: str) -> str:
    if not isinstance(parsed, dict):
        parsed = {"items": parsed}
    original = len(text.encode("utf-8"))
    meta = {"budget": budget, "original_bytes": original,
            "returned_bytes": 10 ** 9, "hint": hint}
    reserve = _size({"_result_budget": meta}) + 2
    body = _fit(parsed, max(budget - reserve, 2))
    return _finish(body, meta)


def _finish(body: dict, meta: dict) -> str:
    for _ in range(4):  # returned_bytes is its own digit count: iterate to a fixed point
        out = json.dumps({**body, "_result_budget": meta}, default=str)
        actual = len(out.encode("utf-8"))
        if meta["returned_bytes"] == actual:
            break
        meta["returned_bytes"] = actual
    return out


_STR_MARK = "...[truncated]"


def _cap_strings(node: Any, cap: int) -> Any:
    """``node`` with every string longer than ``cap`` UTF-8 bytes cut (marker appended)."""
    if isinstance(node, str):
        if len(node.encode("utf-8")) <= cap:
            return node
        return node.encode("utf-8")[:cap].decode("utf-8", errors="ignore") + _STR_MARK
    if isinstance(node, dict):
        return {k: _cap_strings(v, cap) for k, v in node.items()}
    if isinstance(node, list):
        return [_cap_strings(v, cap) for v in node]
    return node


def _shrink_error(parsed: dict, text: str, budget: int, hint: str) -> str:
    """A structured error over budget: keep ``error``/``code`` and the small keys,
    cut the long string fields (error text can be attacker-influenced)."""
    original = len(text.encode("utf-8"))
    meta = {"budget": budget, "original_bytes": original,
            "returned_bytes": 10 ** 9, "hint": hint}
    target = max(budget - _size({"_result_budget": meta}) - 2, 2)
    lo, hi, best = 0, original, None
    while lo <= hi:
        mid = (lo + hi) // 2
        cand = _cap_strings(parsed, mid)
        if _size(cand) <= target:
            best, lo = cand, mid + 1
        else:
            hi = mid - 1
    if best is None:  # even empty strings do not fit: fall back to the generic shrink
        best = _fit(_cap_strings(parsed, 0), target)
    return _finish(best, meta)


def _shrink_text(text: str, budget: int) -> str:
    original = len(text.encode("utf-8"))
    marker = (f"\n[_result_budget: truncated; original_bytes={original} "
              f"budget={budget}; narrow the call (limit/offset/filters)]")
    room = max(budget - len(marker.encode("utf-8")), 0)
    head = text.encode("utf-8")[:room].decode("utf-8", errors="ignore")
    return head + marker


def apply_budget(result: Any, budget: int, hint: str) -> Any:
    """``result`` unchanged when it fits; else the shrunk form (errors included)."""
    if not budget or not isinstance(result, str):
        return result
    if len(result.encode("utf-8")) <= budget:
        return result
    try:
        parsed = json.loads(result)
    except ValueError:
        return _shrink_text(result, budget)
    if isinstance(parsed, dict) and "error" in parsed and "code" in parsed:
        return _shrink_error(parsed, result, budget, hint)
    return _shrink_json(parsed, result, budget, hint)


def budget_tool(fn: Callable, budget: int) -> Callable:
    """Wrap ``fn`` so its string result obeys ``budget`` (0 -> ``fn`` itself)."""
    if not budget:
        return fn
    hint = _hint(fn)
    if inspect.iscoroutinefunction(fn):
        @functools.wraps(fn)
        async def async_wrapper(*a, **k):
            return apply_budget(await fn(*a, **k), budget, hint)

        return async_wrapper

    @functools.wraps(fn)
    def wrapper(*a, **k):
        return apply_budget(fn(*a, **k), budget, hint)

    return wrapper
