"""Central read-sandbox hook for MCP tools (policy-ON only).

When ``MEMDIVER_ALLOWED_ROOTS`` is set the REST API confines every
client-supplied READ path (``api/path_policy.py``). This module gives the MCP
server the same posture with ONE hook rather than per-tool checks:
:func:`guard_tool` wraps a tool function so its arguments are walked with the
shared key logic (``core/path_sandbox.py``) before the tool body runs, and a
denial is returned as the same structured JSON error the error funnel emits.
Policy OFF -> the wrapped tool behaves exactly as before.

Imports no web framework and not the ``mcp`` SDK.
"""

from __future__ import annotations

import functools
import inspect
import json
from typing import Any, Callable, Optional

from memdiver.core import path_sandbox
from memdiver.core.service_errors import CapabilityError


def _roots(loaded_dataset_root: Any = None):
    from memdiver.api.read_roots import sandbox_roots

    return sandbox_roots(loaded_dataset_root)


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
        # Sandbox ON: MCP output paths are confined to the same roots.
        path_sandbox.check_write_arguments(bound_args, roots)
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
