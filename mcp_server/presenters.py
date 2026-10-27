"""MCP-surface presenters for the inspect tools.

This module deliberately imports only the stdlib and ``memdiver.core``
service types — never the optional ``mcp`` SDK — so it can be imported and
unit-tested without the ``mcp`` SDK's MCPServer installed. ``mcp_server/server.py``
wraps every registered tool in :func:`present_mcp_tool`, so JSON encoding and
error presentation happen once, at registration: a ``CapabilityError`` renders
as :func:`mcp_error_payload` (the path-guard denial shape), except for the
original inspect tools (:data:`LEGACY_ERROR_BODY_TOOLS`), whose pinned legacy
``to_error_body()`` shape is kept.

The MCP surface differs from other transports in one respect: an agent needs
the lock signal inlined, so a locked/undecrypted dump is rendered as the same
``{"error": <hint>, "tag_status": <value>}`` dict the legacy tools returned
(via ``_tag_status_error``), rather than being folded into a side channel. The
neutral core hint is augmented with the MCP-specific remedy: the agent-facing
tool PARAMETERS (``key_file`` / ``passphrase`` / ``kem_key_file``), never the
CLI dash-flags. That surface-specific guidance originates here, not in core.
"""

from __future__ import annotations

import functools
import inspect
import json
from typing import Any, Callable

from memdiver.core.service_errors import CapabilityError
from memdiver.core.service_result import ServiceResult

#: The ORIGINAL inspect-family tools (``tools_inspect`` / ``tools_xref``
#: producers). Their hard-error body is the legacy flat
#: ``CapabilityError.to_error_body()`` (message + details merged at top level),
#: pinned by tests and the ``memdiver://`` resources; every OTHER tool renders
#: the structured :func:`mcp_error_payload` shape a path-guard denial also uses.
LEGACY_ERROR_BODY_TOOLS = frozenset({
    "read_hex", "read_hex_raw", "get_entropy", "analyze_region",
    "extract_strings", "detect_format", "get_session_info", "vas_regions",
    "get_processes", "get_modules", "get_handles", "get_connections",
    "get_module_index", "get_import_provenance", "get_blocks", "resolve_va",
    "search_bytes", "get_page_states", "get_cross_references",
    "identify_structure",
})

# MCP-surface remedy for a locked encrypted dump. Agents call the inspect tools
# with these PARAMETER names, so the guidance names the parameters rather than
# the CLI's dash-flags. Kept here in the MCP surface — never in core.
_KEY_PARAMS_HINT = "pass key_file / passphrase / kem_key_file"


def mcp_error_funnel(fn):
    """Backstop decorator translating a propagating ``CapabilityError`` to JSON.

    Wraps an MCP tool body that does NOT already funnel via
    ``present_inspect_mcp_call``. A ``CapabilityError`` escaping the tool is
    rendered as ``json.dumps(err.to_dict())`` — the same structured
    ``{"error", "code", "category"}`` payload the other transports emit — so an
    agent receives a machine-readable error instead of an MCP stack trace. An
    error carrying ``details`` adds them under ``details`` (and hoists
    ``estimate_bytes`` / ``budget_bytes`` for ``memory_budget_exceeded``). The
    success path is untouched: ``fn``'s own ``json.dumps(...)`` return value
    passes straight through.
    """

    @functools.wraps(fn)
    def wrapper(*a, **k):
        try:
            return fn(*a, **k)
        except CapabilityError as e:
            return json.dumps(mcp_error_payload(e), default=str)

    return wrapper


#: Detail keys hoisted to the top level of the funnel payload so an agent can
#: read them without digging (the memory-budget guard's estimate vs budget,
#: mirroring the REST 507 body).
_HOISTED_DETAIL_KEYS = ("estimate_bytes", "budget_bytes")


def mcp_error_payload(err: CapabilityError) -> dict:
    """The MCP error body: ``err.to_dict()`` plus ``details`` when it has any.

    ``{"error", "code", "category"}`` — the same keys a path-guard denial
    returns — so ``"error"`` stays the agent-chat error sniff key.
    """
    payload = err.to_dict()
    if err.details:
        payload["details"] = dict(err.details)
        for key in _HOISTED_DETAIL_KEYS:
            if key in err.details:
                payload[key] = err.details[key]
    return payload


def present_inspect_mcp(result) -> dict:
    """MCP surface: inline the key/tag diagnostic (agents need the lock signal).

    The neutral core hint is augmented with the MCP parameter guidance
    (:data:`_KEY_PARAMS_HINT`) so the agent is told which tool arguments to
    pass — the surface-specific remedy that core no longer carries.
    """
    key = result.status.key
    if not key.decrypted:
        message = f"{key.hint}; {_KEY_PARAMS_HINT}"
        return {"error": message, "tag_status": key.tag_status.value}
    return result.payload


def present_inspect_mcp_call(produce) -> dict:
    """Run a ServiceResult producer and render its result (or hard error).

    ``produce`` is a zero-arg callable invoking one of the ``*_result``
    producers. A raised :class:`CapabilityError` is rendered as the legacy
    ``{"error": <message>}`` dict, merging any ``.details`` (e.g. the
    out-of-range offset/file_size/view/format context) so the observable JSON
    matches the pre-refactor tool output byte-for-byte.
    """
    try:
        return present_inspect_mcp(produce())
    except CapabilityError as e:
        return e.to_error_body()


def _render_tool_result(result: Any) -> str:
    """JSON-encode a tool body's return: ``str`` passes through (already JSON),
    a ``ServiceResult`` goes through :func:`present_inspect_mcp`, a dict as-is."""
    if isinstance(result, str):
        return result
    if isinstance(result, ServiceResult):
        result = present_inspect_mcp(result)
    return json.dumps(result)


def present_mcp_tool(fn: Callable, *, legacy_error_body: bool = False) -> Callable:
    """Registration-layer wrapper: encode + present every tool result ONCE.

    The tool body returns a ``ServiceResult``, a dict or a JSON string, or
    raises :class:`CapabilityError`. The error renders as
    :func:`mcp_error_payload` — or, for a :data:`LEGACY_ERROR_BODY_TOOLS`
    member (``legacy_error_body=True``), as the pinned legacy
    ``to_error_body()``.
    """
    error_body = CapabilityError.to_error_body if legacy_error_body else mcp_error_payload

    if inspect.iscoroutinefunction(fn):
        @functools.wraps(fn)
        async def async_wrapper(*a, **k):
            try:
                result = await fn(*a, **k)
            except CapabilityError as e:
                return json.dumps(error_body(e), default=str)
            return _render_tool_result(result)

        return async_wrapper

    @functools.wraps(fn)
    def wrapper(*a, **k):
        try:
            result = fn(*a, **k)
        except CapabilityError as e:
            return json.dumps(error_body(e), default=str)
        return _render_tool_result(result)

    return wrapper
