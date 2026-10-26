"""Opt-in read-path sandbox for client-supplied filesystem paths.

MemDiver's default trust model (see ``api/main.py::create_app``) lets the
operator point the API at ANY local file: that is the point of a local forensic
workbench. Some deployments want a tighter posture, so this module offers an
OPT-IN policy: set ``MEMDIVER_ALLOWED_ROOTS`` (``os.pathsep``-separated) and
every client-supplied READ path must resolve — symlinks included — inside one of
the admitted roots:

* the configured ``allowed_roots`` themselves,
* the upload directory (where uploaded/imported dumps land),
* the dataset root (configured or currently loaded),
* the MemDiver home (``~/.memdiver``: imports, tasks, sessions),
* the file browser's favourite directories,
* the server's working directory AT STARTUP (captured once at import), and
* the system temp directory (``tempfile.gettempdir()``, ``$TMPDIR``).

A denial's 403 detail names the offending path, lists the admitted roots and
says how to admit it. The MCP server applies the same policy via
``mcp_server/path_guard.py`` (shared logic: ``core/path_sandbox.py``).

When ``allowed_roots`` is unset the policy is DISABLED and every helper here is
a no-op, so the historical unrestricted behaviour is preserved exactly.

The policy is applied in ONE place: :func:`enforce_request_read_paths` is a
FastAPI dependency attached at ``include_router`` time (``api/main.py``) to
every router that accepts read paths. It inspects the query string and the JSON
body for the well-known path-bearing field names in :data:`READ_PATH_KEYS`, so
individual endpoints need no edits. Endpoints with an implicit default path
(``/api/path/browse`` defaulting to ``$HOME``) use :func:`default_browse_root`
and :func:`clamp_parent` so the file browser UX stays inside the sandbox.

Write paths are a separate, always-on concern handled by
``api/path_safety.ensure_within`` against the upload directory.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Any, Iterator

from fastapi import HTTPException, Request

from memdiver.api import read_roots
from memdiver.core import path_sandbox

logger = logging.getLogger("memdiver.api.path_policy")

#: Request field names (query params or JSON keys, at any nesting depth) that
#: carry a filesystem path the server will READ.
#: The key tables and tree walking live in the framework-free
#: :mod:`memdiver.core.path_sandbox` (shared with the MCP server); re-exported
#: here under the historical names. ``model_path``, ``needles`` (``{dump_path:
#: hex}``) and ``related`` (``{name: {dump_path: hex}}``) are covered there.
READ_PATH_KEYS = path_sandbox.READ_PATH_KEYS
_PATH_MAPPING_KEYS = path_sandbox.PATH_MAPPING_KEYS
_NAME_OR_PATH_KEYS = path_sandbox.NAME_OR_PATH_KEYS
_is_path_shaped = path_sandbox.is_path_shaped
_iter_path_values = path_sandbox.iter_path_values
_within = path_sandbox.within


def _configured_roots() -> list[str]:
    return read_roots.configured_roots()


def policy_enabled() -> bool:
    """Return True when the opt-in read-path sandbox is switched on."""
    return bool(_configured_roots())


def _loaded_dataset_root() -> Path | None:
    try:
        from memdiver.api.dependencies import get_tool_session

        return get_tool_session().dataset_root
    except Exception:  # pragma: no cover  # nosec B110 - session not initialised
        return None


def _dynamic_roots() -> Iterator[str]:
    """Yield the roots admitted implicitly alongside the configured ones."""
    yield from read_roots.dynamic_roots(_loaded_dataset_root())


def allowed_roots() -> list[Path]:
    """Return every admitted root, resolved; empty when the policy is off.

    Besides the configured roots: the upload dir, dataset root, MemDiver home,
    favourites, the server's startup working directory and the system temp dir.
    """
    return read_roots.sandbox_roots(_loaded_dataset_root())


def is_admitted(path: str | Path) -> bool:
    """Return True if *path* may be read under the current policy."""
    roots = allowed_roots()
    if not roots:
        return True
    resolved = Path(path).expanduser().resolve(strict=False)
    return _within(resolved, roots)


def admit_read_path(path: str | Path) -> Path:
    """Return *path* resolved, or raise HTTP 403 if the sandbox excludes it.

    A no-op pass-through (beyond ``expanduser``) when the policy is disabled,
    so callers keep their historical relative-path semantics.
    """
    candidate = Path(path).expanduser()
    roots = allowed_roots()
    if not roots:
        return candidate
    resolved = candidate.resolve(strict=False)
    if not _within(resolved, roots):
        raise HTTPException(
            status_code=403, detail=path_sandbox.denial_message(path, roots))
    return resolved


def default_browse_root() -> Path:
    """Where the file browser opens without a path: ``$HOME`` or the 1st root."""
    home = Path.home()
    roots = allowed_roots()
    if not roots or _within(home.resolve(), roots):
        return home
    return roots[0]


def clamp_parent(current: Path) -> str | None:
    """Return the browse ``parent`` for *current*, or None at a sandbox edge."""
    resolved = current.resolve()
    parent = resolved.parent
    if parent == resolved:
        return None
    if not is_admitted(parent):
        return None
    return str(parent)


async def _json_body(request: Request) -> Any:
    content_type = request.headers.get("content-type", "")
    if "json" not in content_type.lower():
        return None
    body = await request.body()
    if not body:
        return None
    try:
        return await request.json()
    except ValueError:
        return None  # malformed JSON: FastAPI's own validation reports it


async def enforce_request_read_paths(request: Request) -> None:
    """FastAPI dependency: 403 any request naming a path outside the sandbox.

    No-op when the policy is disabled. Checks query parameters and the JSON
    body (at any depth) for :data:`READ_PATH_KEYS`. Multipart uploads carry
    file CONTENT, not server paths, so their bodies are not inspected.
    """
    if not policy_enabled():
        return
    for key, value in request.query_params.multi_items():
        if key in READ_PATH_KEYS and value.strip() and _is_path_shaped(key, value):
            admit_read_path(value)
    for value in _iter_path_values(await _json_body(request), False):
        admit_read_path(value)
