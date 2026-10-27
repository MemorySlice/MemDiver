"""Central read-sandbox hook for MCP tools (policy-ON only).

When ``MEMDIVER_ALLOWED_ROOTS`` is set the REST API confines every
client-supplied READ path (``api/path_policy.py``). This module gives the MCP
server the same posture with ONE hook rather than per-tool checks:
:func:`guard_tool` wraps a tool function so its arguments are walked with the
shared key logic (``core/path_sandbox.py``) before the tool body runs, and a
denial is returned as the same structured JSON error the error funnel emits.
Policy OFF -> the wrapped tool behaves exactly as before.

Imports no web framework, not the ``mcp`` SDK and nothing from the REST
package: roots come from ``core/sandbox_roots.py``, containment from
``core/path_sandbox.py`` (the same helpers the REST routers use).
"""

from __future__ import annotations

import functools
import inspect
import json
from typing import Any, Callable, Optional

from memdiver.core import path_sandbox
from memdiver.core.sandbox_roots import sandbox_roots, write_roots
from memdiver.core.service_errors import CapabilityError


def _roots(loaded_dataset_root: Any = None):
    return sandbox_roots(loaded_dataset_root)


#: Tools that only READ a case dir: like REST's read routes they need the read
#: roots alone. Every other tool taking ``case_dir`` may write into it, so a
#: path-shaped case dir is also confined to the write roots (a tool missing here
#: is merely stricter, never looser).
CASE_READ_ONLY_TOOLS = frozenset({
    "annotations_list", "case_status", "case_manifest", "case_schema", "case_query",
    "context_at", "yara_rule_list", "yara_rule_get", "isf_draft_list", "isf_draft_get",
    "isf_draft_versions", "isf_draft_diff", "detector_fixtures_list", "vol3_source_list",
    "vol3_source_get", "vol3_fixture_list", "vol3_describe", "vol3_query",
})


def _write_targets(arguments: dict, tool_name: str = ""):
    """Output paths plus a path-shaped ``case_dir`` of a case-WRITING tool.

    REST confines a non-bare case dir to the write roots (``contained_case_dir``);
    a bare case name files under the cases root inside MemDiver home.
    """
    yield from path_sandbox.iter_write_values(arguments)
    if tool_name in CASE_READ_ONLY_TOOLS:
        return
    new_case = arguments.get("case")
    if isinstance(new_case, str) and new_case and path_sandbox.is_path_shaped("case", new_case):
        yield new_case  # case_init: a bare name files under the cases root
    case_dir = arguments.get("case_dir")
    if isinstance(case_dir, str) and case_dir.strip():
        yield str(_resolved_case_dir(case_dir))


def _resolved_case_dir(case_dir: str):
    """The directory ``Case.open`` really uses (a bare name may hit ``<cwd>/<name>``)."""
    from memdiver.analysis.case import resolve_case_dir

    return resolve_case_dir(case_dir)


def _check_read_case_dir(arguments: dict, tool_name: str, roots) -> None:
    """Read-only case tool: a BARE name's resolved dir must lie in a read/write root."""
    case_dir = arguments.get("case_dir")
    if tool_name not in CASE_READ_ONLY_TOOLS or not isinstance(case_dir, str) \
            or not case_dir.strip() or path_sandbox.is_path_shaped("case_dir", case_dir):
        return
    path_sandbox.admit(_resolved_case_dir(case_dir), [*roots, *write_roots()])


def _check_write_roots(arguments: dict, tool_name: str = "") -> None:
    """Raise a 403 ``CapabilityError`` for a write path outside the write roots."""
    roots = write_roots()
    for value in _write_targets(arguments, tool_name):
        path_sandbox.contain_write_target(
            value, roots, field="output path", example_name="out/result",
            where="MemDiver home + upload dir")


def denial_for(fn: Callable, args: tuple, kwargs: dict,
               session: Any = None) -> Optional[CapabilityError]:
    """The sandbox denial for a call's arguments, or ``None`` when admitted."""
    roots = _roots(getattr(session, "dataset_root", None))
    if not roots:
        return None
    try:
        bound = inspect.signature(fn).bind_partial(*args, **kwargs)
    except (TypeError, ValueError):
        bound_args = dict(kwargs)
    else:
        bound_args = dict(bound.arguments)
    try:
        path_sandbox.check_arguments(bound_args, roots)
        _check_read_case_dir(bound_args, getattr(fn, "__name__", ""), roots)
        # Sandbox ON: MCP output paths are confined to the WRITE roots (MemDiver
        # home + upload dir, the same set REST uses), not the broader read roots.
        _check_write_roots(bound_args, getattr(fn, "__name__", ""))
    except CapabilityError as err:
        return err
    return None


def guard_tool(fn: Callable, session: Any = None) -> Callable:
    """Wrap an MCP tool so a sandbox-denied read path returns a JSON error."""
    if inspect.iscoroutinefunction(fn):
        @functools.wraps(fn)
        async def async_wrapper(*a, **k):
            denied = denial_for(fn, a, k, session)
            if denied is not None:
                return json.dumps(denied.to_dict(), default=str)
            return await fn(*a, **k)

        return async_wrapper

    @functools.wraps(fn)
    def wrapper(*a, **k):
        denied = denial_for(fn, a, k, session)
        if denied is not None:
            return json.dumps(denied.to_dict(), default=str)
        return fn(*a, **k)

    return wrapper
