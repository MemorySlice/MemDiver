"""Framework-free assembly of the read-sandbox roots (REST and MCP share it).

Admitted when ``MEMDIVER_ALLOWED_ROOTS`` is set: the configured roots, the
upload directory, the dataset root (configured or loaded), the MemDiver home,
the file browser favourites, the server's startup working directory and the
system temp directory. Unset -> :func:`sandbox_roots` is empty (policy OFF).
This module imports no web framework so the MCP server can use it.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Iterator, Optional

from memdiver.api.config import get_settings, split_list_setting
from memdiver.core import path_sandbox


def configured_roots() -> list[str]:
    return split_list_setting(get_settings().allowed_roots, sep=os.pathsep)


def dynamic_roots(loaded_dataset_root: Optional[Path] = None) -> Iterator[str]:
    """Yield the roots admitted implicitly alongside the configured ones."""
    settings = get_settings()
    if settings.upload_dir is not None:
        yield str(settings.upload_dir)
    if settings.dataset_root:
        yield settings.dataset_root
    if loaded_dataset_root is not None:
        yield str(loaded_dataset_root)
    from memdiver.core.constants import memdiver_home

    yield str(memdiver_home())
    from memdiver.api.favourites import read_favourites

    for fav in read_favourites():
        if fav.get("path"):
            yield fav["path"]
    yield from path_sandbox.implicit_roots()


def sandbox_roots(loaded_dataset_root: Optional[Path] = None) -> list[Path]:
    """Every admitted root, resolved; empty when the policy is off."""
    configured = configured_roots()
    if not configured:
        return []
    return path_sandbox.resolve_roots([*configured, *dynamic_roots(loaded_dataset_root)])
