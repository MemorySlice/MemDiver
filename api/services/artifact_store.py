"""On-disk artifact store for long-running pipeline tasks.

Every task that TaskManager launches gets its own directory under
``settings.task_root``. Stages drop results into that directory (a
candidates.json, a Vol3 plugin.py, an nsweep report.html, etc.) and
:class:`ArtifactStore` handles:

* Creating the per-task dir with a locked-down ``0o700`` permission
  (artifacts can contain oracle code and partial key material).
* Registering artifacts so they're discoverable via a stable name.
* Opening an artifact path with aggressive traversal and symlink
  guards (``resolve(strict=True)`` on both the base and the target
  plus a ``realpath`` cross-check; on macOS ``/tmp`` is a symlink to
  ``/private/tmp`` so the normal ``is_relative_to`` check needs
  resolving both sides before comparing).
* Enforcing a total-store quota by garbage-collecting the oldest
  *terminal* tasks (never touching a RUNNING or PENDING task).

The store itself does not know anything about task status; callers
provide a ``terminal_ids`` / ``running_ids`` view when invoking
:meth:`gc` so the GC policy stays pluggable.
"""

from __future__ import annotations

import logging
import os
import shutil
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Callable, Dict, Iterable, List, Optional

logger = logging.getLogger("memdiver.api.services.artifact_store")

_DEFAULT_QUOTA_BYTES = 5 * 2**30  # 5 GiB


@dataclass
class ArtifactSpec:
    """A single artifact registered under a task directory.

    ``relpath`` is always relative to the task dir so clients can build
    a download URL via ``/api/pipeline/runs/{task_id}/artifacts/{name}``.
    """

    name: str
    relpath: str
    media_type: str = "application/octet-stream"
    size: int = 0
    sha256: Optional[str] = None
    registered_at: float = field(default_factory=time.time)

    def to_dict(self) -> Dict:
        return asdict(self)


class ArtifactStoreError(Exception):
    """Base class for ArtifactStore validation failures."""


class InvalidArtifactName(ArtifactStoreError):
    """Raised when an artifact name would escape its task directory."""


class ArtifactNotFound(ArtifactStoreError):
    """Raised when the requested artifact does not exist."""


class ArtifactStore:
    def __init__(self, root: Path, max_total_bytes: int = _DEFAULT_QUOTA_BYTES) -> None:
        self._root = Path(root).expanduser()
        self._root.mkdir(parents=True, exist_ok=True)
        os.chmod(self._root, 0o700)
        self._root_real = Path(os.path.realpath(self._root))
        self._max_total = int(max_total_bytes)
        self._specs: Dict[str, List[ArtifactSpec]] = {}

    # ------------------------------------------------------------------
    # task directory lifecycle
    # ------------------------------------------------------------------

    @property
    def root(self) -> Path:
        return self._root

    def task_dir(self, task_id: str) -> Path:
        """Return (and create) the per-task directory with locked-down perms."""
        self._assert_safe_task_id(task_id)
        path = self._root / task_id
        if not path.is_dir():
            path.mkdir(parents=True, exist_ok=True)
            os.chmod(path, 0o700)
        return path

    def delete_task(self, task_id: str) -> None:
        """Remove the task dir and forget any registered specs."""
        self._assert_safe_task_id(task_id)
        path = self._root / task_id
        if path.exists():
            shutil.rmtree(path, ignore_errors=True)
        self._specs.pop(task_id, None)

    def exists(self, task_id: str) -> bool:
        self._assert_safe_task_id(task_id)
        return (self._root / task_id).is_dir()

    # ------------------------------------------------------------------
    # artifact registration
    # ------------------------------------------------------------------

    def register(
        self,
        task_id: str,
        name: str,
        relpath: str,
        *,
        media_type: str = "application/octet-stream",
        sha256: Optional[str] = None,
    ) -> ArtifactSpec:
        """Record an artifact that exists inside the task directory.

        Does NOT write bytes — the stage that produced the artifact
        already wrote them via :meth:`resolve_write_path`. This call
        stores the metadata so it can be surfaced in TaskRecord.
        """
        self._validate_relpath(task_id, relpath)
        full = self._resolve(task_id, relpath)
        size = full.stat().st_size if full.is_file() else 0
        spec = ArtifactSpec(
            name=name,
            relpath=str(relpath).replace(os.sep, "/"),
            media_type=media_type,
            size=size,
            sha256=sha256,
        )
        self._specs.setdefault(task_id, []).append(spec)
        return spec

    def list(self, task_id: str) -> List[ArtifactSpec]:
        return list(self._specs.get(task_id, []))

    def resolve_write_path(self, task_id: str, relpath: str) -> Path:
        """Return an absolute path inside the task dir suitable for writing.

        Creates parents as needed; validates that the target cannot
        escape the task dir.
        """
        self._validate_relpath(task_id, relpath)
        target = self._root / task_id / relpath
        target.parent.mkdir(parents=True, exist_ok=True)
        return target

    def open(self, task_id: str, name: str) -> Path:
        """Return an absolute, validated path for the named artifact.

        Used by the download endpoint. Performs every anti-traversal
        check the plan calls out and refuses intermediate symlinks.
        """
        specs = self._specs.get(task_id, [])
        spec = next((s for s in specs if s.name == name), None)
        if spec is None:
            raise ArtifactNotFound(f"task={task_id} name={name}")
        return self._resolve(task_id, spec.relpath, require_file=True)

    # ------------------------------------------------------------------
    # quota-based garbage collection
    # ------------------------------------------------------------------

    def total_bytes(self) -> int:
        total = 0
        for path, _dirs, files in os.walk(self._root):
            for fname in files:
                fp = Path(path) / fname
                try:
                    total += fp.stat().st_size
                except OSError:
                    continue
        return total

    def gc(
        self,
        *,
        terminal_ids: Iterable[str],
        running_ids: Iterable[str],
        atime: Callable[[Path], float] = lambda p: p.stat().st_mtime,
    ) -> List[str]:
        """Delete oldest terminal tasks until under quota.

        ``running_ids`` is never touched. If the store is already under
        quota this is a no-op.
        """
        if self._max_total <= 0:
            return []
        running_set = set(running_ids)
        terminal_set = set(terminal_ids) - running_set
        total = self.total_bytes()
        if total <= self._max_total:
            return []

        # Sort terminals by mtime ascending (oldest first). Missing dirs
        # are treated as infinitely old so they get pruned first.
        def _age(tid: str) -> float:
            p = self._root / tid
            try:
                return atime(p)
            except OSError:
                return 0.0

        candidates = sorted(terminal_set, key=_age)
        removed: List[str] = []
        for tid in candidates:
            if total <= self._max_total:
                break
            task_path = self._root / tid
            if not task_path.exists():
                removed.append(tid)
                self._specs.pop(tid, None)
                continue
            freed = sum(
                f.stat().st_size
                for f in task_path.rglob("*")
                if f.is_file()
            )
            shutil.rmtree(task_path, ignore_errors=True)
            self._specs.pop(tid, None)
            total -= freed
            removed.append(tid)
            logger.info("gc'd task dir %s (freed %d bytes)", tid, freed)
        return removed

    # ------------------------------------------------------------------
    # internals
    # ------------------------------------------------------------------

    def _assert_safe_task_id(self, task_id: str) -> None:
        if not task_id:
            raise InvalidArtifactName("task_id must be non-empty")
        if task_id != Path(task_id).name or os.sep in task_id or "/" in task_id:
            raise InvalidArtifactName(f"unsafe task_id: {task_id!r}")
        if task_id.startswith(".") or task_id in (".", ".."):
            raise InvalidArtifactName(f"unsafe task_id: {task_id!r}")

    def _validate_relpath(self, task_id: str, relpath: str) -> None:
        self._assert_safe_task_id(task_id)
        if not relpath:
            raise InvalidArtifactName("relpath must be non-empty")
        # No absolute paths, no leading separators.
        rel = Path(relpath)
        if rel.is_absolute():
            raise InvalidArtifactName(f"relpath must be relative: {relpath!r}")
        for part in rel.parts:
            if part in ("", ".", ".."):
                raise InvalidArtifactName(f"invalid component in relpath: {relpath!r}")

    def _resolve(self, task_id: str, relpath: str, *, require_file: bool = False) -> Path:
        """Validate a (task_id, relpath) pair and return an absolute path.

        Guards:
        * ``task_id`` and every component of ``relpath`` must not contain
          ``..`` or absolute segments.
        * The resolved target must live under ``root_real`` (compared via
          ``realpath`` so macOS ``/tmp`` → ``/private/tmp`` aliasing does
          not matter).
        * The target itself must not be a symlink, and ``require_file``
          additionally asserts the target is a regular file.
        """
        self._validate_relpath(task_id, relpath)
        base = self._root / task_id
        if not base.exists():
            raise ArtifactNotFound(f"task dir missing: {task_id}")
        target = base / relpath
        if target.is_symlink():
            raise InvalidArtifactName(f"symlinks not allowed: {relpath!r}")
        if require_file:
            resolved = target.resolve(strict=True)
        else:
            resolved = target.resolve(strict=False)
        real_target = Path(os.path.realpath(resolved))
        try:
            real_target.relative_to(self._root_real)
        except ValueError as exc:
            raise InvalidArtifactName(
                f"resolved path {real_target} escapes store root {self._root_real}"
            ) from exc
        if require_file and not real_target.is_file():
            raise ArtifactNotFound(f"not a regular file: {relpath!r}")
        return real_target
