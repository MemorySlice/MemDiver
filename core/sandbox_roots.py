"""Assembly of the sandbox READ roots and the WRITE roots (REST and MCP share it).

Admitted when ``MEMDIVER_ALLOWED_ROOTS`` is set: the configured roots, the
upload directory, the dataset root (configured or loaded), the MemDiver home,
the file browser favourites, the server's startup working directory and the
system temp directory. Unset -> :func:`sandbox_roots` is empty (policy OFF).

The write roots (MemDiver home + upload dir) are where the server may WRITE on
behalf of a client; REST always confines writes to them, the MCP guard does so
when the read sandbox is ON.

Imports no web framework. The settings values are read through
:func:`_settings` / :func:`_favourite_paths` (plus ``split_list_setting``), the
ONE remaining edge to the ``memdiver.api`` package: ``Settings``
(pydantic-settings, no FastAPI), its list-splitting helper and the favourites
store still live there. ``api/read_roots.py`` re-exports this module.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any, Iterator, Optional

from memdiver.core import constants, path_sandbox


def _settings() -> Any:
    """The process settings (the single seam to ``memdiver.api.config``)."""
    from memdiver.api.config import get_settings

    return get_settings()


def _favourite_paths() -> Iterator[str]:
    """The file browser favourites (the single seam to ``memdiver.api.favourites``)."""
    from memdiver.api.favourites import read_favourites

    for fav in read_favourites():
        if fav.get("path"):
            yield fav["path"]


def configured_roots() -> list[str]:
    """The ``MEMDIVER_ALLOWED_ROOTS`` entries (``os.pathsep``-separated)."""
    from memdiver.api.config import split_list_setting

    return split_list_setting(_settings().allowed_roots, sep=os.pathsep)


def dynamic_roots(loaded_dataset_root: Optional[Path] = None) -> Iterator[str]:
    """Yield the roots admitted implicitly alongside the configured ones."""
    settings = _settings()
    if settings.upload_dir is not None:
        yield str(settings.upload_dir)
    if settings.dataset_root:
        yield settings.dataset_root
    if loaded_dataset_root is not None:
        yield str(loaded_dataset_root)
    yield str(constants.memdiver_home())
    yield from _favourite_paths()
    yield from path_sandbox.implicit_roots()


def sandbox_roots(loaded_dataset_root: Optional[Path] = None) -> list[Path]:
    """Every admitted read root, resolved; empty when the policy is off."""
    configured = configured_roots()
    if not configured:
        return []
    return path_sandbox.resolve_roots([*configured, *dynamic_roots(loaded_dataset_root)])


def write_roots() -> list[Path]:
    """Where the server may WRITE on behalf of a client: MemDiver home + upload dir."""
    # Looked up on the module (not imported by name) so a patched home applies.
    roots = [str(constants.memdiver_home())]
    upload_dir = _settings().upload_dir
    if upload_dir is not None:
        roots.append(str(upload_dir))
    return path_sandbox.resolve_roots(roots)
