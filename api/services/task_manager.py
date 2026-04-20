"""Lifecycle + execution substrate for long-running pipeline tasks.

``TaskManager`` is the minimal real version of what was formerly a Phase B
stub. It owns:

* An app-lifetime :class:`ProcessPoolExecutor` (spawn) that runs pipeline
  work out-of-process so engine code cannot pickle-poison the FastAPI
  event loop and long runs keep the API responsive.
* A single long-lived :class:`multiprocessing.Manager` used to mint the
  progress queues and cancel events that cross the process boundary.
  The plan explicitly warns against spawning a Manager per task (each
  Manager is its own daemon process, which would leak).
* A dict of :class:`TaskRecord` objects persisted atomically to
  ``<task_root>/<id>/record.json`` via ``tmp + os.replace`` so crashes
  mid-write can never corrupt the index.
* An :class:`asyncio.Semaphore` with capacity 1 so only one outer
  pipeline task runs at a time. This eliminates nested-ProcessPool
  contention between our outer pool and brute-force's inner pool on
  macOS spawn, which is the biggest operational risk the plan calls out.

Progress flows workers → mp.Queue → asyncio drain task →
:class:`ProgressBus` → WebSocket clients. The drain task belongs to the
FastAPI event loop and is spawned from :meth:`TaskManager.startup`.
"""

from __future__ import annotations

import asyncio
import json
import logging
import multiprocessing as mp
import os
import threading
import time
import uuid
from concurrent.futures import Future, ProcessPoolExecutor
from dataclasses import asdict, dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Awaitable, Callable, Dict, List, Optional

from api.services.artifact_store import ArtifactSpec, ArtifactStore
from api.services.progress_bus import Event, ProgressBus

logger = logging.getLogger("memdiver.api.services.task_manager")

SCHEMA_VERSION = 1


class TaskStatus(str, Enum):
    PENDING = "pending"
    RUNNING = "running"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    CANCELLED = "cancelled"


TERMINAL_STATUSES = {
    TaskStatus.SUCCEEDED,
    TaskStatus.FAILED,
    TaskStatus.CANCELLED,
}


@dataclass
class StageRecord:
    name: str
    status: TaskStatus = TaskStatus.PENDING
    pct: float = 0.0
    msg: str = ""
    started_at: Optional[float] = None
    ended_at: Optional[float] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "status": self.status.value,
            "pct": self.pct,
            "msg": self.msg,
            "started_at": self.started_at,
            "ended_at": self.ended_at,
        }


@dataclass
class TaskRecord:
    task_id: str
    kind: str
    status: TaskStatus = TaskStatus.PENDING
    params: Dict[str, Any] = field(default_factory=dict)
    stages: List[StageRecord] = field(default_factory=list)
    artifacts: List[ArtifactSpec] = field(default_factory=list)
    created_at: float = field(default_factory=time.time)
    started_at: Optional[float] = None
    ended_at: Optional[float] = None
    error: Optional[str] = None
    schema_version: int = SCHEMA_VERSION

    def to_dict(self) -> Dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "task_id": self.task_id,
            "kind": self.kind,
            "status": self.status.value,
            "params": self.params,
            "stages": [s.to_dict() for s in self.stages],
            "artifacts": [a.to_dict() for a in self.artifacts],
            "created_at": self.created_at,
            "started_at": self.started_at,
            "ended_at": self.ended_at,
            "error": self.error,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "TaskRecord":
        stages = [
            StageRecord(
                name=s["name"],
                status=TaskStatus(s["status"]),
                pct=s.get("pct", 0.0),
                msg=s.get("msg", ""),
                started_at=s.get("started_at"),
                ended_at=s.get("ended_at"),
            )
            for s in data.get("stages", [])
        ]
        artifacts = [
            ArtifactSpec(
                name=a["name"],
                relpath=a["relpath"],
                media_type=a.get("media_type", "application/octet-stream"),
                size=a.get("size", 0),
                sha256=a.get("sha256"),
                registered_at=a.get("registered_at", time.time()),
            )
            for a in data.get("artifacts", [])
        ]
        return cls(
            task_id=data["task_id"],
            kind=data.get("kind", "pipeline"),
            status=TaskStatus(data.get("status", "pending")),
            params=data.get("params", {}),
            stages=stages,
            artifacts=artifacts,
            created_at=data.get("created_at", time.time()),
            started_at=data.get("started_at"),
            ended_at=data.get("ended_at"),
            error=data.get("error"),
            schema_version=data.get("schema_version", SCHEMA_VERSION),
        )


# The entry point a worker process runs. Declared at module scope so
# spawn can pickle it. ``runner`` must itself be a module-level callable.
def _worker_entry(
    runner_dotted: str,
    params: Dict[str, Any],
    progress_queue: Any,
    cancel_event: Any,
    task_id: str,
) -> Dict[str, Any]:
    """Worker trampoline.

    ``runner_dotted`` is a "module.function" string so the parent process
    doesn't have to pickle a live function object (spawn breaks that for
    functions captured from closures or mutable modules).
    """
    import importlib

    mod_name, _, fn_name = runner_dotted.rpartition(".")
    module = importlib.import_module(mod_name)
    fn = getattr(module, fn_name)
    ctx = WorkerContext(
        task_id=task_id,
        progress_queue=progress_queue,
        cancel_event=cancel_event,
    )
    return fn(params, ctx)


@dataclass
class WorkerContext:
    """Handed to every worker runner so it can emit progress and respect cancel."""

    task_id: str
    progress_queue: Any  # mp.Queue
    cancel_event: Any    # mp.Event

    def emit(self, event_type: str, **fields: Any) -> None:
        try:
            self.progress_queue.put(
                {"task_id": self.task_id, "type": event_type, **fields}
            )
        except Exception:  # pragma: no cover - best effort
            pass

    def is_cancelled(self) -> bool:
        try:
            return bool(self.cancel_event.is_set())
        except Exception:
            return False


class TaskManager:
    """Real, minimal task manager. See module docstring for design."""

    def __init__(
        self,
        *,
        task_root: Path,
        artifact_store: ArtifactStore,
        progress_bus: ProgressBus,
        max_workers: int = 2,
    ) -> None:
        self._task_root = Path(task_root).expanduser()
        self._task_root.mkdir(parents=True, exist_ok=True)
        self._artifact_store = artifact_store
        self._bus = progress_bus
        self._max_workers = max_workers

        self._records: Dict[str, TaskRecord] = {}
        self._futures: Dict[str, Future] = {}
        self._cancel_events: Dict[str, Any] = {}
        self._lock = threading.RLock()

        self._pool: Optional[ProcessPoolExecutor] = None
        self._mp_manager: Optional[Any] = None
        self._drain_task: Optional[asyncio.Task] = None
        self._drain_queue: Optional[Any] = None
        self._loop: Optional[asyncio.AbstractEventLoop] = None
        self._run_lock: Optional[asyncio.Semaphore] = None

    # ------------------------------------------------------------------
    # lifecycle
    # ------------------------------------------------------------------

    async def startup(self, loop: asyncio.AbstractEventLoop) -> None:
        """Allocate the ProcessPool, Manager, and progress-drain task."""
        self._loop = loop
        self._run_lock = asyncio.Semaphore(1)
        ctx = mp.get_context("spawn")
        self._pool = ProcessPoolExecutor(
            max_workers=self._max_workers,
            mp_context=ctx,
        )
        self._mp_manager = ctx.Manager()
        self._drain_queue = self._mp_manager.Queue()
        self._drain_task = loop.create_task(self._drain_progress())
        self.load_from_disk()

    def shutdown(self) -> None:
        """Best-effort graceful shutdown of pool, manager, and drain."""
        if self._drain_task is not None:
            self._drain_task.cancel()
        if self._pool is not None:
            self._pool.shutdown(wait=False, cancel_futures=True)
            self._pool = None
        if self._mp_manager is not None:
            try:
                self._mp_manager.shutdown()
            except Exception:  # pragma: no cover
                pass
            self._mp_manager = None

    # ------------------------------------------------------------------
    # submission
    # ------------------------------------------------------------------

    def submit(
        self,
        *,
        kind: str,
        params: Dict[str, Any],
        runner_dotted: str,
        stage_names: Optional[List[str]] = None,
    ) -> TaskRecord:
        """Create a task record and dispatch it to the pool.

        Returns immediately with the ``TaskRecord`` (status=PENDING).
        Callers should track progress via the WebSocket or :meth:`get`.
        """
        if self._pool is None or self._mp_manager is None or self._loop is None:
            raise RuntimeError("TaskManager not started")

        task_id = uuid.uuid4().hex
        cancel_event = self._mp_manager.Event()
        record = TaskRecord(
            task_id=task_id,
            kind=kind,
            params=dict(params),
            stages=[StageRecord(name=n) for n in (stage_names or [])],
        )
        with self._lock:
            self._records[task_id] = record
            self._cancel_events[task_id] = cancel_event
        self._persist(record)

        # Serialize ACTUAL execution on the Semaphore: we schedule an
        # async coroutine that acquires it then calls pool.submit. The
        # PENDING task record is available immediately; RUNNING kicks in
        # once the semaphore is available.
        asyncio.run_coroutine_threadsafe(
            self._gated_submit(task_id, runner_dotted, params, cancel_event),
            self._loop,
        )
        return record

    async def _gated_submit(
        self,
        task_id: str,
        runner_dotted: str,
        params: Dict[str, Any],
        cancel_event: Any,
    ) -> None:
        assert self._run_lock is not None and self._pool is not None
        async with self._run_lock:
            with self._lock:
                record = self._records.get(task_id)
                if record is None or record.status == TaskStatus.CANCELLED:
                    return
                record.status = TaskStatus.RUNNING
                record.started_at = time.time()
            self._persist(record)
            self._publish(Event(task_id=task_id, type="stage_start",
                                stage=record.kind, msg="task started"))

            future = self._pool.submit(
                _worker_entry,
                runner_dotted,
                params,
                self._drain_queue,
                cancel_event,
                task_id,
            )
            with self._lock:
                self._futures[task_id] = future

            loop = asyncio.get_running_loop()
            try:
                result = await loop.run_in_executor(None, future.result)
                self._on_success(task_id, result or {})
            except asyncio.CancelledError:
                raise
            except Exception as exc:  # noqa: BLE001
                self._on_error(task_id, repr(exc))

    # ------------------------------------------------------------------
    # terminal transitions
    # ------------------------------------------------------------------

    def _finalize(
        self,
        task_id: str,
        *,
        status: TaskStatus,
        publish: Event,
        cancelled_ok: bool = True,
        mutate: Optional[Callable[[TaskRecord], None]] = None,
    ) -> Optional[TaskRecord]:
        """Move ``task_id`` to a terminal state, persist, publish, close.

        ``cancelled_ok=True`` makes the transition a no-op when the record
        has already been moved to CANCELLED (the user-visible cancel wins
        even if the worker coincidentally succeeded). ``mutate`` runs
        under the lock after the status flip for any extra field patches
        the caller needs to apply (e.g., appending artifacts on success).
        """
        with self._lock:
            record = self._records.get(task_id)
            if record is None:
                return None
            if cancelled_ok and record.status == TaskStatus.CANCELLED:
                return None
            record.status = status
            record.ended_at = time.time()
            if mutate is not None:
                mutate(record)
        self._persist(record)
        self._publish(publish)
        self._bus.close_task(task_id)
        return record

    def _on_success(self, task_id: str, result: Dict[str, Any]) -> None:
        def _append_artifacts(record: TaskRecord) -> None:
            for spec_data in result.get("artifacts", []):
                record.artifacts.append(ArtifactSpec(
                    name=spec_data["name"],
                    relpath=spec_data["relpath"],
                    media_type=spec_data.get("media_type", "application/octet-stream"),
                    size=spec_data.get("size", 0),
                    sha256=spec_data.get("sha256"),
                ))

        self._finalize(
            task_id,
            status=TaskStatus.SUCCEEDED,
            publish=Event(
                task_id=task_id, type="done",
                msg="task succeeded", extra=result.get("summary"),
            ),
            mutate=_append_artifacts,
        )

    def _on_error(self, task_id: str, message: str) -> None:
        def _set_error(record: TaskRecord) -> None:
            record.error = message

        self._finalize(
            task_id,
            status=TaskStatus.FAILED,
            publish=Event(task_id=task_id, type="error", error=message),
            mutate=_set_error,
        )

    def cancel(self, task_id: str) -> bool:
        with self._lock:
            record = self._records.get(task_id)
            if record is None or record.status in TERMINAL_STATUSES:
                return False
            future = self._futures.get(task_id)
            event = self._cancel_events.get(task_id)
            if event is not None:
                event.set()
            if future is not None:
                future.cancel()
        self._finalize(
            task_id,
            status=TaskStatus.CANCELLED,
            publish=Event(task_id=task_id, type="error", error="cancelled"),
            cancelled_ok=False,
        )
        return True

    # ------------------------------------------------------------------
    # query
    # ------------------------------------------------------------------

    def get(self, task_id: str) -> Optional[TaskRecord]:
        with self._lock:
            return self._records.get(task_id)

    def list_tasks(self) -> List[TaskRecord]:
        with self._lock:
            return list(self._records.values())

    def terminal_ids(self) -> List[str]:
        with self._lock:
            return [
                tid for tid, rec in self._records.items()
                if rec.status in TERMINAL_STATUSES
            ]

    def running_ids(self) -> List[str]:
        with self._lock:
            return [
                tid for tid, rec in self._records.items()
                if rec.status in (TaskStatus.PENDING, TaskStatus.RUNNING)
            ]

    # ------------------------------------------------------------------
    # persistence
    # ------------------------------------------------------------------

    def _record_path(self, task_id: str) -> Path:
        return self._task_root / task_id / "record.json"

    def _persist(self, record: TaskRecord) -> None:
        """Atomic write via tmp + os.replace."""
        task_dir = self._task_root / record.task_id
        task_dir.mkdir(parents=True, exist_ok=True)
        final = task_dir / "record.json"
        tmp = task_dir / "record.json.tmp"
        tmp.write_text(json.dumps(record.to_dict(), indent=2))
        os.replace(tmp, final)

    def load_from_disk(self) -> None:
        """Rebuild in-memory records and mark orphan RUNNING as FAILED.

        Called from :meth:`startup`. Stray ``record.json.tmp`` files from
        interrupted writes are removed.
        """
        if not self._task_root.is_dir():
            return
        for task_dir in self._task_root.iterdir():
            if not task_dir.is_dir():
                continue
            tmp = task_dir / "record.json.tmp"
            if tmp.exists():
                try:
                    tmp.unlink()
                except OSError:
                    pass
            record_path = task_dir / "record.json"
            if not record_path.is_file():
                continue
            try:
                data = json.loads(record_path.read_text())
                record = TaskRecord.from_dict(data)
            except Exception as exc:
                logger.warning("skipping unreadable task record %s: %s",
                               record_path, exc)
                continue
            if record.status in (TaskStatus.RUNNING, TaskStatus.PENDING):
                record.status = TaskStatus.FAILED
                record.error = "backend restarted"
                record.ended_at = time.time()
                try:
                    self._persist(record)
                except OSError:
                    pass
            with self._lock:
                self._records[record.task_id] = record

    # ------------------------------------------------------------------
    # progress drain
    # ------------------------------------------------------------------

    async def _drain_progress(self) -> None:
        """Pump worker progress events into the bus.

        Runs on the event loop. Uses ``run_in_executor`` to call the
        blocking ``queue.get`` so the loop stays responsive.
        """
        assert self._drain_queue is not None
        loop = asyncio.get_running_loop()
        q = self._drain_queue
        while True:
            try:
                payload = await loop.run_in_executor(None, q.get)
            except asyncio.CancelledError:
                return
            if payload is None:
                continue
            self._handle_worker_event(payload)

    def _handle_worker_event(self, payload: Dict[str, Any]) -> None:
        task_id = payload.get("task_id")
        event_type = payload.get("type", "progress")
        if not task_id:
            return
        stage = payload.get("stage")
        pct = payload.get("pct")
        msg = payload.get("msg")
        with self._lock:
            record = self._records.get(task_id)
            if record is not None and stage and event_type in (
                "stage_start", "progress", "stage_end"
            ):
                persist_needed = self._update_stage(
                    record, stage, pct, msg, event_type,
                )
            else:
                persist_needed = False
        # Persist only when the stage status actually changed — fine-grained
        # progress ticks fire up to 256/s and would hammer the disk.
        if persist_needed and record is not None:
            self._persist(record)
        self._publish(Event(
            task_id=task_id,
            type=event_type,
            stage=stage,
            pct=pct,
            msg=msg,
            extra=payload.get("extra"),
            artifact=payload.get("artifact"),
            error=payload.get("error"),
        ))

    def _update_stage(
        self,
        record: TaskRecord,
        stage: str,
        pct: Optional[float],
        msg: Optional[str],
        event_type: str,
    ) -> bool:
        """Apply a worker event to ``record.stages``. Returns True if a
        status-level transition occurred (``stage_start``/``stage_end`` on
        a declared pipeline stage) so the caller knows it needs to persist.

        Engine sub-stages like ``search_reduce:variance`` are treated as
        fine-grained progress updates on their parent row and never
        create new rows.
        """
        parent_stage = stage.split(":", 1)[0]
        existing = next(
            (s for s in record.stages if s.name == parent_stage), None
        )
        if existing is None:
            return False
        status_changed = False
        if event_type == "stage_start" and parent_stage == stage:
            existing.status = TaskStatus.RUNNING
            existing.started_at = time.time()
            status_changed = True
        elif event_type == "stage_end" and parent_stage == stage:
            existing.status = TaskStatus.SUCCEEDED
            existing.ended_at = time.time()
            existing.pct = 1.0
            status_changed = True
        if pct is not None and pct >= 0:
            existing.pct = float(pct)
        if msg:
            existing.msg = msg
        return status_changed

    def _publish(self, event: Event) -> None:
        try:
            self._bus.publish(event)
        except Exception:  # pragma: no cover - bus must never break a task
            logger.exception("progress bus publish failed")

    @property
    def artifact_store(self) -> ArtifactStore:
        return self._artifact_store

    @property
    def progress_bus(self) -> ProgressBus:
        return self._bus


# ----------------------------------------------------------------------
# module-level singleton (mirrors ConsensusSessionManager pattern)
# ----------------------------------------------------------------------

_default_manager: Optional[TaskManager] = None
_default_lock = threading.Lock()


def get_task_manager() -> TaskManager:
    if _default_manager is None:
        raise RuntimeError("TaskManager not initialized; call init_task_manager")
    return _default_manager


def init_task_manager(
    *,
    task_root: Path,
    artifact_store: ArtifactStore,
    progress_bus: ProgressBus,
    max_workers: int = 2,
) -> TaskManager:
    """Create and install the singleton TaskManager.

    Called once from the FastAPI lifespan startup hook. Idempotent: if
    called twice, returns the existing instance.
    """
    global _default_manager
    with _default_lock:
        if _default_manager is None:
            _default_manager = TaskManager(
                task_root=task_root,
                artifact_store=artifact_store,
                progress_bus=progress_bus,
                max_workers=max_workers,
            )
    return _default_manager


def reset_task_manager() -> None:
    """Test hook: drop the singleton so a fresh one can be installed."""
    global _default_manager
    with _default_lock:
        if _default_manager is not None:
            _default_manager.shutdown()
        _default_manager = None
