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
* the file browser's favourite directories.

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
import os
from pathlib import Path
from typing import Any, Iterable, Iterator

from fastapi import HTTPException, Request

from memdiver.api.config import get_settings, split_list_setting

logger = logging.getLogger("memdiver.api.path_policy")

#: Request field names (query params or JSON keys, at any nesting depth) that
#: carry a filesystem path the server will READ.
READ_PATH_KEYS = frozenset({
    "path", "paths", "dump_path", "dump_paths", "msl_path", "anchor_path",
    "additional_paths", "source_paths", "selected_dump_paths", "pcap_path",
    "root", "library_dir", "library_dirs", "input_path", "dataset_root",
    "variance_path", "plugin_path", "rule_paths", "case_dir",
    "image_path", "view_path", "isf",
})

#: Message returned with every 403 so the operator knows which knob to turn.
_DENIED_DETAIL = (
    "path is outside the allowed roots (MEMDIVER_ALLOWED_ROOTS); add its "
    "directory there, or as a favourite, to admit it"
)


def _configured_roots() -> list[str]:
    return split_list_setting(get_settings().allowed_roots, sep=os.pathsep)


def policy_enabled() -> bool:
    """Return True when the opt-in read-path sandbox is switched on."""
    return bool(_configured_roots())


def _dynamic_roots() -> Iterator[str]:
    """Yield the roots admitted implicitly alongside the configured ones."""
    settings = get_settings()
    if settings.upload_dir is not None:
        yield str(settings.upload_dir)
    if settings.dataset_root:
        yield settings.dataset_root
    try:
        from memdiver.api.dependencies import get_tool_session

        loaded = get_tool_session().dataset_root
        if loaded is not None:
            yield str(loaded)
    except Exception:  # pragma: no cover  # nosec B110 - session not initialised
        pass
    from memdiver.core.constants import memdiver_home

    yield str(memdiver_home())
    from memdiver.api.favourites import read_favourites

    for fav in read_favourites():
        if fav.get("path"):
            yield fav["path"]


def allowed_roots() -> list[Path]:
    """Return every admitted root, resolved; empty when the policy is off."""
    configured = _configured_roots()
    if not configured:
        return []
    roots: list[Path] = []
    for raw in [*configured, *_dynamic_roots()]:
        resolved = Path(raw).expanduser().resolve(strict=False)
        if resolved not in roots:
            roots.append(resolved)
    return roots


def _within(candidate: Path, roots: Iterable[Path]) -> bool:
    return any(candidate == root or candidate.is_relative_to(root) for root in roots)


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
        raise HTTPException(status_code=403, detail=_DENIED_DETAIL)
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


def _iter_path_values(value: Any, key_matches: bool) -> Iterator[str]:
    """Yield every non-blank string under a READ_PATH_KEYS key, recursively."""
    if isinstance(value, dict):
        for key, child in value.items():
            yield from _iter_path_values(child, key in READ_PATH_KEYS)
    elif isinstance(value, list):
        for child in value:
            yield from _iter_path_values(child, key_matches)
    elif key_matches and isinstance(value, str) and value.strip():
        yield value


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
        if key in READ_PATH_KEYS and value.strip():
            admit_read_path(value)
    for value in _iter_path_values(await _json_body(request), False):
        admit_read_path(value)
