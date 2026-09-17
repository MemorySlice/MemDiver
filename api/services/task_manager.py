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

That flow is a SEPARATE channel from the pool's own result channel, which is
what carries a runner's return value home. The terminal ``done`` / ``error``
publish therefore has to wait for the progress channel to catch up, or the
tail of the stream is published after the bus channel closes and no live
client ever sees it. :func:`_worker_entry` posts a flush sentinel as its last
act and :meth:`TaskManager._drain_barrier` waits for it — see those two for
the full story.

Shutdown
--------
Four facts make teardown harder than it looks. They are stated here once;
everything below points back at this section rather than restating them.

1. **Python 3.11 joins the default executor with no timeout.** uvicorn serves
   under :class:`asyncio.Runner`, whose ``close()`` calls
   ``loop.shutdown_default_executor()``; on 3.11 that method has no ``timeout``
   parameter (it arrived in 3.12) and ends in an unconditional ``thread.join()``.
   So a single thread of asyncio's *default* executor parked in an unbounded
   blocking call hangs the whole process, with no traceback. This module
   therefore owns its own drain executor and never borrows the default one.
2. **A running pool worker is joined at interpreter exit.**
   ``pool.shutdown(wait=False)`` does not stop work already in flight, and
   ``concurrent.futures.process._python_exit`` later joins the executor-manager
   thread, which joins every worker — again with no timeout. A worker left alive
   at the end of teardown is not untidy, it is the same hang relocated.
3. **Cancel events are Manager proxies.** They are served by the Manager child,
   and :meth:`WorkerContext.is_cancelled` swallows proxy errors, so an event set
   after the Manager died reaches nobody. Cancel must be signalled *before* the
   Manager is stopped.
4. **uvicorn drains connections before it runs the lifespan shutdown**, and on
   ``force_exit`` it skips the lifespan shutdown entirely. So this class cannot
   assume it will be given a chance to run at all; ``cli/dataset.py`` keeps a
   ``finally`` backstop for that case.

Failing any of these produced the defect this design exists to prevent: a server
that could not be shut down, leaving ``kill -9`` as the only exit — which skips
every ``atexit`` handler and leaks the pool's 5 POSIX semaphores.
"""

from __future__ import annotations

import asyncio
import contextlib
import functools
import json
import logging
import multiprocessing as mp
import queue
import threading
import time
import uuid
from concurrent.futures import Future, ProcessPoolExecutor, ThreadPoolExecutor
from dataclasses import asdict, dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Awaitable, Callable, Dict, List, Optional

from memdiver.api.services.artifact_store import ArtifactSpec, ArtifactStore
from memdiver.api.services.progress_bus import Event, ProgressBus
from memdiver.core.artifact_util import atomic_write_text
from memdiver.core.process_guard import (
    guard_child_process,
    start_guarded_sync_manager,
)

logger = logging.getLogger("memdiver.api.services.task_manager")

SCHEMA_VERSION = 1

# Key of the drain-barrier sentinel a worker puts on the progress queue as its
# very last act (see :func:`_worker_entry` and :meth:`TaskManager._drain_barrier`).
# Namespaced so it can never collide with a real event field.
DRAIN_FLUSH_KEY = "__memdiver_drain_flush__"

# How long the terminal transition waits for that sentinel before giving up and
# publishing anyway. Generous (the queue is already fully written by the time we
# wait; this only covers drain-task scheduling), but bounded: a task must never
# hang because a sentinel went missing.
DRAIN_FLUSH_TIMEOUT_S = 10.0

# Ceiling on one blocking read of the cross-process progress queue. Something
# waits on this: it bounds how long the drain thread stays inside a single
# ``get`` and therefore how quickly teardown can join it (fact 1 above). Keep it
# short — the cost is one ~100-byte proxy round trip per second, and the manager
# blocks server-side for the interval rather than spinning.
DRAIN_POLL_S = 1.0

# How long teardown lets workers stop cooperatively before it signals them.
# Every production runner polls ``WorkerContext.is_cancelled``, so this window
# normally ends with the worker unwinding on its own and posting its sentinel.
SHUTDOWN_GRACE_S = 5.0

# Escalation window applied to ALL workers at once: SIGTERM, wait, SIGKILL,
# wait. Bounded because of fact 2 above.
WORKER_TERM_TIMEOUT_S = 2.0


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
    try:
        return fn(params, ctx)
    finally:
        # Drain barrier. The runner's progress events travel on
        # ``progress_queue``, but the RETURN VALUE travels home on the pool's
        # own result channel — a completely separate pipe. The parent therefore
        # learns the task finished while the tail of the progress stream is
        # still in flight, and ``ProgressBus.subscribe`` stops iterating the
        # instant it yields ``done``/``error``: every event that lands after
        # the terminal publish is invisible to the live client. That is how the
        # final ``stage_end`` (and now every ``artifact`` event registered by
        # the last stage) got silently dropped.
        #
        # Posting the sentinel from HERE — the same process that emitted the
        # events — is what makes the barrier sound. ``mp.Queue`` guarantees
        # ordering only among items enqueued by one process, so a sentinel put
        # by the parent could legally overtake the child's backlog. Posted here
        # it strictly follows every emit the runner made.
        #
        # ``finally`` covers the failure path too: a run that raises has the
        # same right to have its last real events delivered before ``error``.
        try:
            progress_queue.put({DRAIN_FLUSH_KEY: task_id})
        except Exception:  # pragma: no cover - best effort
            logger.debug("drain flush sentinel emit failed", exc_info=True)


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
            logger.debug("progress emit failed", exc_info=True)

    def is_cancelled(self) -> bool:
        try:
            return bool(self.cancel_event.is_set())
        except Exception:
            return False


def _await_exit(workers: List[Any], timeout_s: float) -> None:
    """Block until every worker has exited, or ``timeout_s`` elapses."""
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline and any(p.is_alive() for p in workers):
        time.sleep(0.05)


def _reap_workers(workers: List[Any], grace_s: float) -> None:
    """Wait ``grace_s`` for workers to exit, then SIGTERM, then SIGKILL.

    Each escalation is applied to ALL workers before waiting on any of them, so
    the worst case is ``grace_s + 2 * WORKER_TERM_TIMEOUT_S`` no matter how many
    workers there are. Signalling and then joining one at a time would serialise
    every worker's timeout behind the previous one's.

    Leaving a worker alive would relocate the hang rather than fix it (fact 2 in
    the module docstring). Racing the executor-manager thread's own ``join`` is
    safe: ``popen_fork._send_signal`` guards on ``returncode`` and swallows
    ``ProcessLookupError``.
    """
    _await_exit(workers, grace_s)
    for proc in (p for p in workers if p.is_alive()):
        logger.warning("force-terminating pipeline worker pid=%s", proc.pid)
        proc.terminate()
    _await_exit(workers, WORKER_TERM_TIMEOUT_S)
    for proc in (p for p in workers if p.is_alive()):
        logger.warning("SIGKILLing unresponsive pipeline worker pid=%s", proc.pid)
        proc.kill()
    _await_exit(workers, WORKER_TERM_TIMEOUT_S)


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

        # Set by shutdown/aclose so a submit already queued on ``_run_lock``
        # does not dispatch into a pool that is going away underneath it.
        self._closing = False
        self._pool: Optional[ProcessPoolExecutor] = None
        self._mp_manager: Optional[Any] = None
        self._drain_executor: Optional[ThreadPoolExecutor] = None
        self._drain_task: Optional[asyncio.Task] = None
        self._drain_queue: Optional[Any] = None
        self._loop: Optional[asyncio.AbstractEventLoop] = None
        self._run_lock: Optional[asyncio.Semaphore] = None
        # task_id -> asyncio.Event set when the drain task observes that task's
        # flush sentinel. Touched only from the event loop (the drain task and
        # ``_gated_submit`` both run there), so it needs no lock.
        self._flush_barriers: Dict[str, asyncio.Event] = {}

    # ------------------------------------------------------------------
    # lifecycle
    # ------------------------------------------------------------------

    async def startup(self, loop: asyncio.AbstractEventLoop) -> None:
        """Allocate the ProcessPool, Manager, and progress-drain task."""
        self._loop = loop
        self._closing = False
        self._run_lock = asyncio.Semaphore(1)
        ctx = mp.get_context("spawn")
        # Both children arm a parent-death watchdog. Nothing running in THIS
        # process survives a SIGKILL, so the children have to notice on their
        # own: without it a hard kill orphans the Manager server forever (it is
        # not a daemon process and ``Server.serve_forever`` has no parent
        # check), stranding its unix socket and ``pymp-*`` temp dir. See
        # core/process_guard.py.
        self._pool = ProcessPoolExecutor(
            max_workers=self._max_workers,
            mp_context=ctx,
            initializer=guard_child_process,
        )
        self._mp_manager = start_guarded_sync_manager(ctx)
        self._drain_queue = self._mp_manager.Queue()
        # A drain thread we OWN. Borrowing asyncio's default executor is what
        # made shutdown unjoinable (fact 1 in the module docstring); owning one
        # makes ``loop.shutdown_default_executor()`` a no-op for us by
        # construction rather than by timing.
        self._drain_executor = ThreadPoolExecutor(
            max_workers=1, thread_name_prefix="memdiver-drain",
        )
        self._drain_task = loop.create_task(self._drain_progress())
        self.load_from_disk()

    def shutdown(self, *, grace_s: float = SHUTDOWN_GRACE_S) -> None:
        """Bounded, ordered teardown of cancel events, drain, pool, manager.

        The ORDER is load-bearing and every step has a ceiling:

        1. Cancel events FIRST -- fact 3 in the module docstring.
        2. Drain task next, so nothing new is published mid-teardown.
        3. Bus subscribers released, so nothing is left parked on a channel.
        4. Pool, with the worker handles captured before ``shutdown()`` nulls
           them, then force-reaped -- fact 2.
        5. Manager and drain executor last, in a ``finally`` so a raising pool
           step cannot strand either one.

        Stays SYNCHRONOUS: ``reset_task_manager`` and the test fixtures call it
        from sync context. :meth:`aclose` is the async twin, and delegates here
        so this sequence exists in exactly one place.
        """
        self._closing = True
        self._signal_cancel_all()
        if self._drain_task is not None:
            self._drain_task.cancel()
            self._drain_task = None
        self._bus.close_all()
        try:
            self._stop_pool(grace_s=grace_s)
        finally:
            self._stop_manager()
            self._stop_drain_executor()

    async def aclose(self) -> None:
        """Async twin of :meth:`shutdown`, for the FastAPI lifespan.

        Spends the cooperative window ON the loop -- so an in-flight task can
        still run its drain barrier and publish a real terminal event instead of
        being resurrected as "backend restarted" on the next boot -- then defers
        to :meth:`shutdown` for the ordered teardown itself. The drain task is
        awaited rather than fire-and-forget.
        """
        self._closing = True
        # Signalled here as well as inside ``shutdown`` -- the runners have to
        # see it BEFORE the cooperative window, not after. ``set`` is idempotent
        # and costs one proxy round trip per live task.
        self._signal_cancel_all()
        await self._await_workers_idle(SHUTDOWN_GRACE_S)
        await self._cancel_drain()
        self.shutdown(grace_s=0.0)  # grace already spent, cooperatively

    def _signal_cancel_all(self) -> None:
        """Ask every non-terminal task's worker to stop cooperatively.

        Must run while the Manager is still alive -- fact 3 in the module
        docstring. Sets are issued outside the lock: each one is a blocking
        round trip to the Manager.
        """
        with self._lock:
            events = [
                self._cancel_events[tid]
                for tid, rec in self._records.items()
                if rec.status not in TERMINAL_STATUSES and tid in self._cancel_events
            ]
        for event in events:
            try:
                event.set()
            except Exception:  # pragma: no cover - manager already gone
                logger.debug("cancel event set failed", exc_info=True)

    async def _await_workers_idle(self, grace_s: float) -> None:
        """Let cooperative runners finish, without blocking the event loop.

        Waits on DISPATCHED work only. ``running_ids()`` also counts PENDING,
        and because ``_run_lock`` admits one task at a time a queued task can
        sit PENDING with no worker running at all -- waiting on that would spend
        the entire window on nothing.
        """
        deadline = time.monotonic() + grace_s
        while time.monotonic() < deadline and self._has_live_futures():
            await asyncio.sleep(0.05)

    def _has_live_futures(self) -> bool:
        """True while any submitted worker future is still outstanding."""
        with self._lock:
            return any(not f.done() for f in self._futures.values())

    async def _cancel_drain(self) -> None:
        """Cancel the drain task and actually wait for it to unwind."""
        task, self._drain_task = self._drain_task, None
        if task is None:
            return
        task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await task

    def _stop_pool(self, grace_s: float) -> None:
        """Shut the pool down, then guarantee no worker outlives us.

        ``ProcessPoolExecutor.shutdown()`` sets ``_processes`` to None, so the
        handles are captured first. That attribute is private, hence the
        ``getattr``: a CPython rename degrades to "no force-reap" rather than an
        exception raised in the middle of teardown.
        """
        pool, self._pool = self._pool, None
        if pool is None:
            return
        workers = list((getattr(pool, "_processes", None) or {}).values())
        pool.shutdown(wait=False, cancel_futures=True)
        _reap_workers(workers, grace_s)

    def _stop_drain_executor(self) -> None:
        """Release the private drain thread.

        ``wait=False``: the thread is at worst inside one ``DRAIN_POLL_S`` read,
        and stopping the Manager just above breaks that read immediately.
        """
        executor, self._drain_executor = self._drain_executor, None
        if executor is not None:
            executor.shutdown(wait=False)

    def _stop_manager(self) -> None:
        """Stop the Manager server that mints the queues and cancel events."""
        manager, self._mp_manager = self._mp_manager, None
        if manager is None:
            return
        try:
            manager.shutdown()
        except Exception:  # pragma: no cover
            logger.debug("manager shutdown failed", exc_info=True)

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
            # Re-read the pool INSIDE the lock. The assert above runs before we
            # queue on the gate, so a submit that waited there across a shutdown
            # would otherwise reach ``None.submit`` on a tearing-down loop. A
            # task dropped here stays PENDING and ``load_from_disk`` re-marks it
            # "backend restarted" on the next boot -- the documented behaviour.
            # ``pool is None`` is not redundant with ``_closing``: it is
            # also what narrows the type for ``pool.submit`` below.
            pool = self._pool
            if pool is None or self._closing:
                return
            with self._lock:
                record = self._records.get(task_id)
                if record is None or record.status == TaskStatus.CANCELLED:
                    return
                record.status = TaskStatus.RUNNING
                record.started_at = time.time()
            self._persist(record)
            self._publish(Event(task_id=task_id, type="stage_start",
                                stage=record.kind, msg="task started"))

            # Arm the drain barrier BEFORE the worker can post its sentinel,
            # otherwise a very fast task could flush before we are listening.
            self._flush_barriers[task_id] = asyncio.Event()

            future = pool.submit(
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
                try:
                    # ``wrap_future`` bridges the pool future onto the loop
                    # with NO thread at all, raising the same exceptions in the
                    # same places. It replaced ``run_in_executor(None,
                    # future.result)``, which parked a default-executor thread
                    # for the whole run -- fact 1 in the module docstring.
                    #
                    # It does NOT kill the worker: ``_chain_future`` installs a
                    # cancel callback, but ``Future.cancel()`` returns False for
                    # one already running. Freeing the loop instantly is the
                    # point; ``_stop_pool`` is what ends the process.
                    result = await asyncio.wrap_future(future, loop=loop)
                except asyncio.CancelledError:
                    raise
                except Exception as exc:  # noqa: BLE001
                    await self._drain_barrier(task_id)
                    self._on_error(task_id, repr(exc))
                else:
                    # Let the progress stream catch up first: the terminal
                    # ``done`` closes the bus channel and ends every live
                    # subscriber, so anything still queued would be lost.
                    await self._drain_barrier(task_id)
                    self._on_success(task_id, result or {})
            finally:
                self._flush_barriers.pop(task_id, None)

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
        """Atomic write via a *unique* tmp file + os.replace.

        ``_persist`` runs off the lock from two threads — the event-loop drain
        (``_handle_worker_event``) and the sync ``cancel`` handler that Starlette
        dispatches to a worker thread. A shared ``record.json.tmp`` let their
        writes interleave into torn JSON, or made the second ``os.replace`` raise
        ``FileNotFoundError`` (the tmp already moved) → a 500 out of ``cancel``.
        A per-write tmp makes each write self-contained; ``os.replace`` onto the
        final path is atomic, so concurrent writers are simply last-writer-wins.

        The primitive itself now lives in :func:`core.artifact_util.
        atomic_write_text` so ``app/`` (which may not import ``api/``) can
        share it; this method keeps owning the directory creation and the
        JSON encoding.
        """
        task_dir = self._task_root / record.task_id
        task_dir.mkdir(parents=True, exist_ok=True)
        final = task_dir / "record.json"
        atomic_write_text(final, json.dumps(record.to_dict(), indent=2))

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
            # Matches both the legacy fixed name (record.json.tmp) and the
            # per-write unique name (record.json.<hex>.tmp).
            for stray in task_dir.glob("record.json*.tmp"):
                try:
                    stray.unlink()
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

        Runs on the event loop, calling the blocking ``queue.get`` on this
        manager's OWN drain executor so the loop stays responsive. The read is
        bounded at ``DRAIN_POLL_S``, so the thread is never parked indefinitely
        and teardown can always join it (fact 1 in the module docstring).
        """
        assert self._drain_queue is not None
        loop = asyncio.get_running_loop()
        # ``queue.Empty`` propagates through a ``SyncManager`` proxy because
        # ``BaseProxy._callmethod`` re-raises the remote exception.
        poll = functools.partial(self._drain_queue.get, timeout=DRAIN_POLL_S)
        while True:
            try:
                payload = await loop.run_in_executor(self._drain_executor, poll)
            except asyncio.CancelledError:
                return
            except queue.Empty:
                continue  # bounded read expired; loop round and re-check cancel
            except RuntimeError:
                # Our drain executor is already gone: teardown raced us. Exit
                # quietly rather than raising into a task nobody is awaiting.
                return
            if payload is None:
                continue
            flushed_task = payload.get(DRAIN_FLUSH_KEY)
            if flushed_task:
                # Barrier sentinel, not an event: everything this task's worker
                # emitted has now been handled, so the terminal publish waiting
                # in ``_drain_barrier`` may proceed.
                barrier = self._flush_barriers.get(flushed_task)
                if barrier is not None:
                    barrier.set()
                continue
            self._handle_worker_event(payload)

    async def _drain_barrier(self, task_id: str) -> None:
        """Wait until this task's worker events have all been drained.

        Called on the terminal path, just before ``done``/``error`` is
        published. See the long note in :func:`_worker_entry` for why the
        barrier is needed and why the sentinel is posted by the worker.

        Deliberately forgiving: a missing or late sentinel logs and proceeds.
        Losing the tail of a progress stream is a cosmetic bug; refusing to
        finalise the task would be a hang.
        """
        barrier = self._flush_barriers.get(task_id)
        if barrier is None:
            return
        try:
            await asyncio.wait_for(barrier.wait(), timeout=DRAIN_FLUSH_TIMEOUT_S)
        except asyncio.TimeoutError:
            logger.warning(
                "drain barrier timed out for task %s after %.1fs; "
                "publishing terminal event anyway",
                task_id, DRAIN_FLUSH_TIMEOUT_S,
            )

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
