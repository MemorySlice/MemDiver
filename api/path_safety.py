"""Filesystem path-safety helpers for request-supplied names and paths.

Centralizes containment checks so request handlers cannot be tricked into
reading or writing outside an allowed base directory via ``..`` traversal,
absolute paths, or symlink escapes. All comparisons are done on fully
``resolve()``-d paths.
"""

from __future__ import annotations

from pathlib import Path


def ensure_within(base: Path, candidate: Path) -> Path:
    """Return *candidate* resolved, or raise ``ValueError`` if it escapes *base*.

    *candidate* may be *base* itself or any path nested beneath it. Any value
    that resolves outside *base* — through ``..`` traversal, an absolute path,
    or a symlink pointing elsewhere — is rejected.
    """
    base_resolved = Path(base).resolve()
    cand_resolved = Path(candidate).resolve()
    if cand_resolved != base_resolved and base_resolved not in cand_resolved.parents:
        raise ValueError(f"path {str(candidate)!r} escapes {base_resolved}")
    return cand_resolved


def safe_filename(base: Path, name: str, suffix: str = "") -> Path:
    """Resolve ``name + suffix`` as a direct child *file* of *base*.

    Stricter than :func:`ensure_within`: the result must live *directly* inside
    *base*, so any *name* containing path separators or traversal is rejected.
    Used for request-supplied filenames (e.g. a session name) that must not be
    able to address subdirectories or escape the storage directory.
    """
    base_resolved = Path(base).resolve()
    candidate = ensure_within(base_resolved, base_resolved / f"{name}{suffix}")
    if candidate.parent != base_resolved:
        raise ValueError(f"invalid name {name!r}: must be a bare filename")
    return candidate
