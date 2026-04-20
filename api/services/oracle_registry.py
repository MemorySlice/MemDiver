"""In-process registry for uploaded BYO decryption oracles.

The pipeline's web UI needs a small, stateful place to remember:

* which oracle files have been uploaded
* the sha256 hash observed at upload time (so an ``/arm`` confirmation
  can catch tampering between display and arm)
* whether the oracle has been *armed* (a user-intent confirmation;
  running an unarmed oracle returns 409)
* the detected *shape* (Shape 1 stateless vs Shape 2 stateful factory)

The registry never itself *executes* an oracle. Every endpoint that
runs one loads it via :func:`engine.oracle.load_oracle`, which performs
its own sha256 re-hash + safe-path checks, so the registry is only a
metadata cache — a compromised entry cannot bypass the runtime guard.

Security defaults (see the plan's "Security hardening" section):

* The on-disk oracle file is chmod-ed to ``0o600`` at upload.
* Any co-located ``__pycache__/`` directory is purged before handing
  the path to :func:`load_oracle` so stale bytecode cannot shadow the
  freshly-written source.
* ``sys.dont_write_bytecode = True`` is set at registry construction
  time so the detection probe itself doesn't emit a new cache.
"""

from __future__ import annotations

import hashlib
import logging
import os
import shutil
import stat
import sys
import threading
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional

from engine.oracle import OracleLoadError, load_oracle

logger = logging.getLogger("memdiver.api.services.oracle_registry")

_HEAD_LINES_MAX = 50


class OracleRegistryError(Exception):
    """Base class for registry validation failures."""


class OracleNotFound(OracleRegistryError):
    """The requested oracle id is unknown."""


class OracleNotArmed(OracleRegistryError):
    """The oracle was found but has not been armed for execution."""


class OracleShaMismatch(OracleRegistryError):
    """Arm request supplied a sha256 that no longer matches the file."""


class OracleDisabled(OracleRegistryError):
    """The registry is not configured (no ``MEMDIVER_ORACLE_DIR`` set)."""


@dataclass
class OracleEntry:
    """Metadata about a registered oracle file."""

    oracle_id: str
    filename: str
    path: Path
    sha256: str
    size: int
    shape: int  # 1 or 2
    head_lines: List[str]
    uploaded_at: float = field(default_factory=time.time)
    armed: bool = False
    description: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.oracle_id,
            "filename": self.filename,
            "sha256": self.sha256,
            "size": self.size,
            "shape": self.shape,
            "head_lines": list(self.head_lines),
            "uploaded_at": self.uploaded_at,
            "armed": self.armed,
            "description": self.description,
        }


def _purge_pycache(path: Path) -> None:
    """Delete the ``__pycache__/`` directory next to ``path``.

    Importing from a fresh .py file can still pick up a stale .pyc the
    attacker dropped alongside it; purging proactively avoids that
    hole. Missing or empty dirs are fine.
    """
    cache_dir = path.parent / "__pycache__"
    if cache_dir.is_dir():
        shutil.rmtree(cache_dir, ignore_errors=True)


def _sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _detect_shape(path: Path) -> int:
    """Return 1 or 2 for Shape 1 / Shape 2, or raise OracleLoadError.

    Purely static: imports the user module (no bytecode cache) and
    inspects which top-level symbol is present. Does NOT invoke
    ``build_oracle`` itself, so Shape 2 oracles that need config (e.g.
    the gocryptfs example which requires a ``sample_ciphertext``
    parameter) are still detected correctly.

    Note: import alone runs the top-level of the module, so a user
    oracle that performs expensive work at import time will pay that
    cost here. The example oracles are all cheap.
    """
    import importlib.util

    from engine.oracle import OracleLoadError, _assert_safe_path

    _purge_pycache(path)
    _assert_safe_path(path)
    spec = importlib.util.spec_from_file_location("memdiver_oracle_probe", path)
    if spec is None or spec.loader is None:
        raise OracleLoadError(f"cannot create import spec for {path}")
    module = importlib.util.module_from_spec(spec)
    try:
        spec.loader.exec_module(module)
    except Exception as exc:  # noqa: BLE001
        raise OracleLoadError(f"failed to import oracle {path}: {exc}") from exc
    if callable(getattr(module, "build_oracle", None)):
        return 2
    if callable(getattr(module, "verify", None)):
        return 1
    raise OracleLoadError(
        f"{path}: must export verify(candidate) -> bool or "
        f"build_oracle(config) -> Oracle"
    )


def _read_head(path: Path, max_lines: int = _HEAD_LINES_MAX) -> List[str]:
    """Return the first ``max_lines`` lines of ``path`` as strings."""
    out: List[str] = []
    with path.open("r", encoding="utf-8", errors="replace") as fh:
        for i, line in enumerate(fh):
            if i >= max_lines:
                break
            out.append(line.rstrip("\n"))
    return out


def _assert_safe_id(oracle_id: str) -> None:
    if not oracle_id:
        raise OracleRegistryError("oracle_id must be non-empty")
    if oracle_id != Path(oracle_id).name or "/" in oracle_id or os.sep in oracle_id:
        raise OracleRegistryError(f"unsafe oracle_id: {oracle_id!r}")
    if oracle_id.startswith(".") or oracle_id in (".", ".."):
        raise OracleRegistryError(f"unsafe oracle_id: {oracle_id!r}")


class OracleRegistry:
    """Per-process in-memory oracle catalog backed by a whitelisted dir."""

    def __init__(self, oracle_dir: Optional[Path], examples_dir: Path) -> None:
        self._oracle_dir = Path(oracle_dir).expanduser() if oracle_dir else None
        self._examples_dir = Path(examples_dir).expanduser()
        self._entries: Dict[str, OracleEntry] = {}
        self._lock = threading.RLock()
        # Prevent the detection probe from dropping stale .pyc files
        # into the oracle dir. Global but harmless here — memdiver is a
        # CLI/server with no hot-reload needs.
        sys.dont_write_bytecode = True
        if self._oracle_dir is not None:
            self._oracle_dir.mkdir(parents=True, exist_ok=True)
            try:
                os.chmod(self._oracle_dir, 0o700)
            except OSError:
                pass

    # ------------------------------------------------------------------
    # configuration state
    # ------------------------------------------------------------------

    @property
    def enabled(self) -> bool:
        return self._oracle_dir is not None

    def require_enabled(self) -> Path:
        if self._oracle_dir is None:
            raise OracleDisabled(
                "oracle execution disabled; set MEMDIVER_ORACLE_DIR to "
                "a trusted, non-shared, user-writable-only directory"
            )
        return self._oracle_dir

    # ------------------------------------------------------------------
    # examples
    # ------------------------------------------------------------------

    def list_examples(self) -> List[Dict[str, Any]]:
        """Enumerate bundled example oracles under ``docs/oracle_examples/``."""
        if not self._examples_dir.is_dir():
            return []
        out: List[Dict[str, Any]] = []
        for entry in sorted(self._examples_dir.glob("*.py")):
            if entry.name.startswith("_"):
                continue
            try:
                shape = _detect_shape(entry)
            except OracleLoadError as exc:
                logger.warning("example oracle %s failed to load: %s",
                               entry.name, exc)
                continue
            head_lines = _read_head(entry)
            summary = next(
                (ln.strip('"" \t#') for ln in head_lines if ln.strip()),
                "",
            )
            out.append({
                "filename": entry.name,
                "path": str(entry),
                "sha256": _sha256_file(entry),
                "size": entry.stat().st_size,
                "shape": shape,
                "summary": summary,
                "head_lines": head_lines,
            })
        return out

    # ------------------------------------------------------------------
    # upload / arm / dry-run / delete
    # ------------------------------------------------------------------

    def upload(
        self,
        *,
        filename: str,
        content: bytes,
        description: Optional[str] = None,
    ) -> OracleEntry:
        oracle_dir = self.require_enabled()
        # Accept the user's original filename for display but store
        # under a uuid so a malicious basename cannot escape oracle_dir.
        oracle_id = uuid.uuid4().hex
        safe_filename = Path(filename).name or "oracle.py"
        on_disk = oracle_dir / f"{oracle_id}.py"
        on_disk.write_bytes(content)
        try:
            os.chmod(on_disk, 0o600)
        except OSError:
            pass
        if (on_disk.stat().st_mode & stat.S_IWOTH):  # pragma: no cover
            on_disk.unlink(missing_ok=True)
            raise OracleRegistryError("stored oracle is world-writable; aborting")
        _purge_pycache(on_disk)
        sha = _sha256_file(on_disk)
        try:
            shape = _detect_shape(on_disk)
        except OracleLoadError as exc:
            on_disk.unlink(missing_ok=True)
            raise OracleRegistryError(
                f"oracle failed to load: {exc}"
            ) from exc
        entry = OracleEntry(
            oracle_id=oracle_id,
            filename=safe_filename,
            path=on_disk,
            sha256=sha,
            size=on_disk.stat().st_size,
            shape=shape,
            head_lines=_read_head(on_disk),
            description=description,
        )
        with self._lock:
            self._entries[oracle_id] = entry
        return entry

    def get(self, oracle_id: str) -> OracleEntry:
        _assert_safe_id(oracle_id)
        with self._lock:
            entry = self._entries.get(oracle_id)
        if entry is None:
            raise OracleNotFound(f"unknown oracle: {oracle_id}")
        return entry

    def list_entries(self) -> List[OracleEntry]:
        with self._lock:
            return list(self._entries.values())

    def arm(self, oracle_id: str, client_sha: str) -> OracleEntry:
        entry = self.get(oracle_id)
        _purge_pycache(entry.path)
        current_sha = _sha256_file(entry.path)
        if current_sha != entry.sha256:
            raise OracleShaMismatch(
                f"stored sha256 no longer matches on-disk file "
                f"({entry.sha256[:12]}… vs {current_sha[:12]}…); re-upload"
            )
        if client_sha != entry.sha256:
            raise OracleShaMismatch(
                f"client sha256 mismatch ({client_sha[:12]}… vs "
                f"{entry.sha256[:12]}…); display is stale"
            )
        entry.armed = True
        return entry

    def delete(self, oracle_id: str) -> None:
        entry = self.get(oracle_id)
        with self._lock:
            self._entries.pop(oracle_id, None)
        try:
            entry.path.unlink(missing_ok=True)
        except OSError:  # pragma: no cover
            pass
        _purge_pycache(entry.path)

    def require_armed(self, oracle_id: str) -> OracleEntry:
        entry = self.get(oracle_id)
        if not entry.armed:
            raise OracleNotArmed(f"oracle {oracle_id} not armed")
        return entry

    def dry_run(
        self,
        oracle_id: str,
        *,
        samples: List[bytes],
    ) -> Dict[str, Any]:
        """Run the oracle against ``samples`` and report pass/fail counts.

        Does NOT require the oracle to be armed: the whole point is to
        let a user smoke-test before committing to arming + running.
        """
        entry = self.get(oracle_id)
        _purge_pycache(entry.path)
        verify = load_oracle(entry.path, config={})
        results: List[Dict[str, Any]] = []
        passes = 0
        fails = 0
        errors = 0
        t_total = 0.0
        for idx, sample in enumerate(samples):
            t0 = time.monotonic()
            try:
                ok = bool(verify(sample))
            except Exception as exc:  # noqa: BLE001
                errors += 1
                results.append({
                    "index": idx,
                    "ok": False,
                    "error": repr(exc),
                })
                continue
            dt = (time.monotonic() - t0) * 1_000_000
            t_total += dt
            if ok:
                passes += 1
            else:
                fails += 1
            results.append({
                "index": idx,
                "ok": ok,
                "duration_us": round(dt, 2),
            })
        return {
            "oracle_id": oracle_id,
            "samples": len(samples),
            "passes": passes,
            "fails": fails,
            "errors": errors,
            "per_call_us_avg": round(t_total / max(1, len(samples) - errors), 2),
            "results": results,
        }


# ----------------------------------------------------------------------
# singleton
# ----------------------------------------------------------------------

_default_registry: Optional[OracleRegistry] = None
_default_lock = threading.Lock()


def init_oracle_registry(
    *,
    oracle_dir: Optional[Path],
    examples_dir: Path,
) -> OracleRegistry:
    global _default_registry
    with _default_lock:
        _default_registry = OracleRegistry(
            oracle_dir=oracle_dir,
            examples_dir=examples_dir,
        )
    return _default_registry


def get_oracle_registry() -> OracleRegistry:
    if _default_registry is None:
        raise RuntimeError("OracleRegistry not initialized")
    return _default_registry


def reset_oracle_registry() -> None:
    global _default_registry
    with _default_lock:
        _default_registry = None
