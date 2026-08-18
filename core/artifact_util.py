"""Shared artifact hashing/registration helpers for TaskManager worker runners.

Extracted from :mod:`app.pipeline.pipeline_runner` (P3.2 dedup) so every
worker runner (pipeline, batch, analysis, experiment) and :mod:`engine.oracle`
share one bounded-memory sha256 implementation and one artifact-spec shape,
instead of each maintaining its own (occasionally OOM-risky) copy.
"""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any, Dict, List


def sha256_streamed(path: Path) -> str:
    """Return the hex sha256 of ``path``, read incrementally.

    ``hashlib.file_digest`` (Python 3.11+, the project's floor) streams the file
    through a bounded internal buffer, so peak memory stays bounded and
    full-dump-scale artifacts never load whole into RAM. Byte-identical to
    hashing the whole file at once.
    """
    with path.open("rb") as f:
        return hashlib.file_digest(f, "sha256").hexdigest()


def register_artifact(
    artifacts: List[Dict[str, Any]],
    artifact_dir: Path,
    *,
    name: str,
    relpath: str,
    media_type: str = "application/octet-stream",
) -> Dict[str, Any]:
    """Compute size + sha256 of a written artifact and append a record."""
    full = artifact_dir / relpath
    try:
        size = full.stat().st_size
    except OSError:
        size = 0
    sha = sha256_streamed(full) if full.is_file() else None
    spec = {
        "name": name,
        "relpath": relpath,
        "media_type": media_type,
        "size": size,
        "sha256": sha,
    }
    artifacts.append(spec)
    return spec
