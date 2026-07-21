"""MCP-surface presenters for the inspect tools.

This module deliberately imports only the stdlib and ``memdiver.core``
service types — never the optional ``mcp`` SDK — so it can be imported and
unit-tested without FastMCP installed. ``mcp_server/server.py`` imports the
two functions here to render the status-carrying ``ServiceResult`` producers
in :mod:`memdiver.mcp_server.tools_inspect` back to the exact JSON shapes the
MCP tools have always emitted.

The MCP surface differs from other transports in one respect: an agent needs
the lock signal inlined, so a locked/undecrypted dump is rendered as the same
``{"error": <hint>, "tag_status": <value>}`` dict the legacy tools returned
(via ``_tag_status_error``), rather than being folded into a side channel.
"""

from __future__ import annotations

import functools
import json

from memdiver.core.service_errors import CapabilityError


def mcp_error_funnel(fn):
    """Backstop decorator translating a propagating ``CapabilityError`` to JSON.

    Wraps an MCP tool body that does NOT already funnel via
    ``present_inspect_mcp_call``. A ``CapabilityError`` escaping the tool is
    rendered as ``json.dumps(err.to_dict())`` — the same structured
    ``{"error", "code", "category"}`` payload the other transports emit — so an
    agent receives a machine-readable error instead of an MCP stack trace. The
    success path is untouched: ``fn``'s own ``json.dumps(...)`` return value
    passes straight through.
    """

    @functools.wraps(fn)
    def wrapper(*a, **k):
        try:
            return fn(*a, **k)
        except CapabilityError as e:
            return json.dumps(e.to_dict())

    return wrapper


def present_inspect_mcp(result) -> dict:
    """MCP surface: inline the key/tag diagnostic (agents need the lock signal)."""
    key = result.status.key
    if not key.decrypted:
        return key.locked_error_dict()
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
