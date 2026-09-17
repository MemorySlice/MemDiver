"""Shared artifact hashing/registration helpers for TaskManager worker runners.

Extracted from :mod:`app.pipeline.pipeline_runner` (P3.2 dedup) so every
worker runner (pipeline, batch, analysis, experiment) and :mod:`engine.oracle`
share one bounded-memory sha256 implementation and one artifact-spec shape,
instead of each maintaining its own (occasionally OOM-risky) copy.
"""

from __future__ import annotations

import hashlib
import logging
import os
import uuid
from pathlib import Path
from typing import Any, Dict, List, Optional, Protocol, runtime_checkable

logger = logging.getLogger("memdiver.core.artifact_util")


@runtime_checkable
class ArtifactRegistrationSink(Protocol):
    """An ``artifacts`` list that also wants to *observe* each registration.

    :func:`register_artifact` is the one place in the codebase where an
    artifact becomes real (written, sized, hashed, and appended). Anything
    that needs to react to that — a live progress stream, an audit log — wants
    to hook exactly there, not at the ~19 scattered call sites.

    Rather than thread a sink argument through every stage helper (or, worse,
    sprinkle an ``emit`` next to every ``register_artifact``), the hook rides
    on the ``artifacts`` container itself: pass a list that implements
    ``artifact_registered`` and it is called once per appended spec. A plain
    ``list`` does not implement it, so the default path is byte-for-byte
    unchanged and ``core`` keeps importing nothing from the layers above it.

    The concrete pipeline-layer implementation is
    ``app.pipeline.artifact_events.EmittingArtifactList``.
    """

    def artifact_registered(self, spec: Dict[str, Any]) -> None:
        ...  # pragma: no cover - structural protocol


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
    """Compute size + sha256 of a written artifact and append a record.

    If ``artifacts`` implements :class:`ArtifactRegistrationSink` (i.e. it
    carries an ``artifact_registered`` attribute) the freshly built spec is
    handed to it after the append, so callers can stream registrations live
    without every call site knowing about it.
    """
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
    # Central artifact-notification point. STRUCTURAL on purpose (the Protocol
    # is ``runtime_checkable``, so this is an attribute check, not a nominal
    # one): ``core`` must not import ``app``/``api``, and the overwhelmingly
    # common caller passes a plain ``list``, which simply does not satisfy it.
    # A sink that raises must never take a run down with it — the artifact IS
    # registered by the time we get here, and a dropped progress event is
    # strictly less bad than a failed pipeline stage.
    if isinstance(artifacts, ArtifactRegistrationSink):
        try:
            artifacts.artifact_registered(spec)
        except Exception:  # pragma: no cover - best effort, never fatal
            logger.debug("artifact_registered sink failed", exc_info=True)
    return spec


def atomic_write_text(
    path: Path,
    text: str,
    *,
    encoding: str = "utf-8",
    mode: Optional[int] = None,
) -> None:
    """Write ``text`` to ``path`` atomically: unique tmp file + ``os.replace``.

    Exists so every surface shares one battle-tested atomic-write primitive.
    It was extracted from ``api.services.task_manager.TaskManager._persist``,
    whose record.json writes are issued off-lock from two threads (the
    event-loop drain and the sync cancel handler dispatched to a worker
    thread). It lives in :mod:`core` because ``app/`` — where the Wave 3
    sweep ledger writes its ``manifest.json`` — must not import ``api/``.

    Three properties are load-bearing and must be preserved by any edit:

    * **Per-write unique tmp name.** A shared ``<name>.tmp`` let concurrent
      writers interleave into torn output, or made the second ``os.replace``
      raise ``FileNotFoundError`` because the tmp had already been moved.
    * **``os.replace`` onto the final path**, which is atomic on POSIX and
      Windows: a reader sees either the old file or the new one, never a
      partial one. Concurrent writers are simply last-writer-wins.
    * **``BaseException`` cleanup** (not ``Exception``): a ``KeyboardInterrupt``
      or worker cancellation mid-write must not leave a stray tmp file behind.

    No ``fsync`` is performed, matching the original: this guards against
    *torn* files, not against power loss, and fsyncing every record write
    would serialise the hot progress-drain path on disk latency.

    The parent directory must already exist — callers own directory creation.

    ``mode``, when given, is applied to the **tmp file before the replace**, so
    the final path never exists with laxer permissions than requested -- not
    even for the instant between ``os.replace`` and a would-be chmod after it.
    Callers writing a file whose *contents* are sensitive (rather than merely
    its existence) should pass it.

    .. warning::
       Do **not** use this for large append-only files. It rewrites the whole
       file every call, so appending to a growing ``results.jsonl`` would be
       O(n^2): a 30,000-line sweep ledger would push roughly 450 GB of writes
       over a full run. That is why the sweep ledger uses this for its small
       ``manifest.json`` only and appends to ``results.jsonl`` directly.
    """
    tmp = path.with_name(f"{path.name}.{uuid.uuid4().hex}.tmp")
    try:
        tmp.write_text(text, encoding=encoding)
        if mode is not None:
            os.chmod(tmp, mode)
        os.replace(tmp, path)
    except BaseException:
        tmp.unlink(missing_ok=True)
        raise
