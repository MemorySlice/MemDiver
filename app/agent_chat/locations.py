"""Navigable locations found in a tool result, for the chat panel's "jump to" links.

A tool result is JSON text; any nested dict naming a dump (``dump_path`` or ``path``)
plus an address (``va`` and/or ``offset``; an offset also carries its ``view`` when the
dict names one) becomes one normalised location. At most
:data:`MAX_LOCATIONS` are returned, in document order; non-JSON text yields none.
"""

from __future__ import annotations

import json
from typing import Any, Dict, Iterator, List

MAX_LOCATIONS = 10
_MAX_DEPTH = 8


def _is_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _as_location(node: Dict[str, Any]) -> Dict[str, Any] | None:
    dump = node.get("dump_path") or node.get("path")
    if not isinstance(dump, str) or not dump:
        return None
    found: Dict[str, Any] = {"dump_path": dump}
    for key in ("va", "offset"):
        if _is_int(node.get(key)):
            found[key] = node[key]
    if len(found) == 1:
        return None
    # ``offset`` is relative to ``view`` (span-relative for "va"); the browser needs the
    # view to land on the right bytes, so it travels with the location.
    if "offset" in found and isinstance(node.get("view"), str):
        found["view"] = node["view"]
    return found


def _walk(node: Any, depth: int) -> Iterator[Dict[str, Any]]:
    if depth > _MAX_DEPTH:
        return
    if isinstance(node, dict):
        found = _as_location(node)
        if found is not None:
            yield found
        for value in node.values():
            yield from _walk(value, depth + 1)
    elif isinstance(node, list):
        for item in node:
            yield from _walk(item, depth + 1)


def extract_locations(result_text: str) -> List[Dict[str, Any]]:
    """Up to :data:`MAX_LOCATIONS` ``{dump_path, va|offset}`` dicts from a JSON result."""
    if not result_text or result_text[0] not in "{[":
        return []
    try:
        body = json.loads(result_text)
    except ValueError:
        return []
    found: List[Dict[str, Any]] = []
    for location in _walk(body, 0):
        found.append(location)
        if len(found) >= MAX_LOCATIONS:
            break
    return found
