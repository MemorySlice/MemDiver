"""The MCP playbook prompts, as data for the web chat panel.

``mcp_server.prompts.register_prompts`` only needs an object with a ``prompt(name=,
description=)`` decorator, so a tiny collector captures the renderers without an MCP
server (or the ``mcp`` package) being involved. One source of truth: the web panel
shows exactly the playbooks an MCP client would be offered.
"""

from __future__ import annotations

import functools
import inspect
from typing import Any, Callable, Dict, List, Mapping, Tuple

START_PLAYBOOK = "memdiver_start"

_Entry = Tuple[str, Callable[..., str]]  # (description, renderer)


class _Collector:
    """Stands in for the MCP server's ``prompt`` decorator."""

    def __init__(self) -> None:
        self.entries: Dict[str, _Entry] = {}

    def prompt(self, name: str, description: str = "") -> Callable[[Callable[..., str]], Callable[..., str]]:
        def register(fn: Callable[..., str]) -> Callable[..., str]:
            self.entries[name] = (description, fn)
            return fn

        return register


@functools.lru_cache(maxsize=1)
def _entries() -> Dict[str, _Entry]:
    from memdiver.mcp_server.prompts import register_prompts

    collector = _Collector()
    register_prompts(collector)
    return collector.entries


def _summary(description: str) -> str:
    lines = description.strip().splitlines()
    return lines[0].strip() if lines else ""


def list_playbooks() -> List[Dict[str, Any]]:
    """``[{name, summary, params}]`` for every registered playbook prompt."""
    return [
        {"name": name, "summary": _summary(description),
         "params": list(inspect.signature(fn).parameters)}
        for name, (description, fn) in _entries().items()
    ]


def playbook_index() -> Dict[str, str]:
    """``{name: summary}`` of the playbooks the agent may follow (not the intro)."""
    return {p["name"]: p["summary"] for p in list_playbooks() if p["name"] != START_PLAYBOOK}


def render_playbook(name: str, args: Mapping[str, Any]) -> str:
    """Render one playbook; ``KeyError`` for an unknown name, ``ValueError`` for bad args."""
    entry = _entries().get(name)
    if entry is None:
        raise KeyError(name)
    fn = entry[1]
    allowed = set(inspect.signature(fn).parameters)
    unknown = sorted(set(args) - allowed)
    if unknown:
        raise ValueError(f"unknown argument(s) for {name}: {', '.join(unknown)}")
    for key, value in args.items():
        if value is not None and not isinstance(value, str):
            raise ValueError(f"argument '{key}' must be a string")
    return fn(**dict(args))


def start_text() -> str:
    """The ``memdiver_start`` introduction, embedded in the chat's system prompt."""
    return render_playbook(START_PLAYBOOK, {})
