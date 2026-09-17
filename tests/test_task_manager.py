"""Tests for api.services.task_manager.

Covers B3 of Phase 25's web-UI integration plan: real TaskManager with a
process pool, cancellation, persistence, and restart recovery.

The runners themselves live in ``tests/_task_runners.py`` so spawn can
pickle them by dotted path.
"""

from __future__ import annotations

import asyncio
import json
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Callable

import pytest

from memdiver.api.services.artifact_store import ArtifactStore
from memdiver.api.services.progress_bus import ProgressBus
from memdiver.api.services.task_manager import (
    SHUTDOWN_GRACE_S,
    WORKER_TERM_TIMEOUT_S,
    StageRecord,
    TaskManager,
    TaskRecord,
    TaskStatus,
    reset_task_manager,
)
from tests._pymp import assert_no_new_pymp_dirs, pymp_dirs

TERMINAL_STATUSES = (TaskStatus.SUCCEEDED, TaskStatus.FAILED, TaskStatus.CANCELLED)


@pytest.fixture
def task_manager(tmp_path: Path):
    """Fresh TaskManager per test, started and torn down properly.

    Delegates to :func:`_standalone_manager` so there is exactly one piece of
    start/stop scaffolding in this module; the contextmanager stays separate
    because several tests must drive and TIME the teardown themselves.
    """
    with _standalone_manager(tmp_path) as pair:
        yield pair


def _wait_for_status(
    mgr: TaskManager,
    task_id: str,
    loop,
    predicate: Callable[[TaskRecord], bool],
    timeout: float = 15.0,
    what: str = "the expected state",
) -> TaskRecord:
    """Pump ``loop`` until ``task_id``'s record satisfies ``predicate``.

    The loop has to run: nothing advances a task's status except the drain
    coroutine, so a bare ``time.sleep`` here would wait forever.
    """
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        loop.run_until_complete(asyncio.sleep(0.05))
        record = mgr.get(task_id)
        if record is not None and predicate(record):
            return record
    raise AssertionError(f"task {task_id} never reached {what}")


def _wait_for_terminal(mgr: TaskManager, task_id: str, loop, timeout: float = 15.0):
    return _wait_for_status(
        mgr, task_id, loop, lambda r: r.status in TERMINAL_STATUSES,
        timeout=timeout, what="terminal state",
    )


# ----- basic record lifecycle ---------------------------------------------


def test_submit_returns_pending_record(task_manager):
    mgr, loop = task_manager
    record = mgr.submit(
        kind="echo",
        params={"foo": "bar"},
        runner_dotted="tests._task_runners.echo_runner",
        stage_names=["echo"],
    )
    assert isinstance(record, TaskRecord)
    assert record.status == TaskStatus.PENDING
    assert record.params == {"foo": "bar"}
    # Persisted to disk immediately.
    record_file = (mgr._task_root / record.task_id / "record.json")
    assert record_file.is_file()


def test_echo_runner_round_trip(task_manager):
    mgr, loop = task_manager
    record = mgr.submit(
        kind="echo",
        params={"foo": "bar"},
        runner_dotted="tests._task_runners.echo_runner",
        stage_names=["echo"],
    )
    final = _wait_for_terminal(mgr, record.task_id, loop)
    assert final.status == TaskStatus.SUCCEEDED
    assert final.error is None
    persisted = json.loads((mgr._task_root / record.task_id / "record.json").read_text())
    assert persisted["status"] == "succeeded"


def test_failing_runner_marks_failed(task_manager):
    mgr, loop = task_manager
    record = mgr.submit(
        kind="echo",
        params={"why": "unit-test"},
        runner_dotted="tests._task_runners.failing_runner",
    )
    final = _wait_for_terminal(mgr, record.task_id, loop)
    assert final.status == TaskStatus.FAILED
    assert final.error is not None
    assert "boom" in final.error or "RuntimeError" in final.error


def test_cancel_stops_spin_runner(task_manager):
    mgr, loop = task_manager
    record = mgr.submit(
        kind="spin",
        params={"iterations": 5000},
        runner_dotted="tests._task_runners.cancellable_runner",
    )
    # Give the worker time to start and observe a few iterations.
    _wait_for_running(mgr, record.task_id, loop)
    assert mgr.cancel(record.task_id)
    final = _wait_for_terminal(mgr, record.task_id, loop)
    assert final.status == TaskStatus.CANCELLED


# ----- persistence / restart ----------------------------------------------


def test_load_from_disk_marks_orphan_running_failed(tmp_path):
    tasks_root = tmp_path / "tasks"
    store = ArtifactStore(tmp_path / "artifacts")
    bus = ProgressBus()
    mgr = TaskManager(task_root=tasks_root, artifact_store=store, progress_bus=bus)
    # Hand-craft an orphan RUNNING record on disk.
    task_id = "abcdef"
    task_dir = tasks_root / task_id
    task_dir.mkdir(parents=True)
    (task_dir / "record.json").write_text(json.dumps({
        "schema_version": 1,
        "task_id": task_id,
        "kind": "pipeline",
        "status": "running",
        "params": {},
        "stages": [],
        "artifacts": [],
        "created_at": time.time(),
        "started_at": time.time(),
        "ended_at": None,
        "error": None,
    }))
    mgr.load_from_disk()
    record = mgr.get(task_id)
    assert record is not None
    assert record.status == TaskStatus.FAILED
    assert record.error == "backend restarted"
    persisted = json.loads((task_dir / "record.json").read_text())
    assert persisted["status"] == "failed"


def test_atomic_tmp_cleanup_on_load(tmp_path):
    tasks_root = tmp_path / "tasks"
    store = ArtifactStore(tmp_path / "artifacts")
    bus = ProgressBus()
    mgr = TaskManager(task_root=tasks_root, artifact_store=store, progress_bus=bus)
    # Simulate a crashed write that left a .tmp file behind.
    task_id = "interrupted"
    task_dir = tasks_root / task_id
    task_dir.mkdir(parents=True)
    tmp = task_dir / "record.json.tmp"
    tmp.write_text("partial garbage")
    mgr.load_from_disk()
    assert not tmp.exists()


# ----- query helpers ------------------------------------------------------


def test_list_and_running_terminal_ids(task_manager):
    mgr, loop = task_manager
    r1 = mgr.submit(
        kind="echo",
        params={},
        runner_dotted="tests._task_runners.echo_runner",
    )
    final = _wait_for_terminal(mgr, r1.task_id, loop)
    assert final.status == TaskStatus.SUCCEEDED
    tasks = mgr.list_tasks()
    assert any(t.task_id == r1.task_id for t in tasks)
    assert r1.task_id in mgr.terminal_ids()
    assert r1.task_id not in mgr.running_ids()


def test_to_dict_round_trip():
    rec = TaskRecord(task_id="x", kind="k", params={"a": 1})
    rec.status = TaskStatus.SUCCEEDED
    restored = TaskRecord.from_dict(rec.to_dict())
    assert restored.task_id == "x"
    assert restored.status == TaskStatus.SUCCEEDED
    assert restored.params == {"a": 1}


# ----- _update_stage parent-stage filter regression ----------------------
# Sub-stage events like "search_reduce:variance" must never transition
# the parent row's status — only parent-exact stage_start/stage_end do.


def _mgr_for_unit_tests(tmp_path: Path) -> TaskManager:
    return TaskManager(
        task_root=tmp_path / "tasks",
        artifact_store=ArtifactStore(tmp_path / "artifacts"),
        progress_bus=ProgressBus(),
        max_workers=1,
    )


def _fresh_record() -> TaskRecord:
    return TaskRecord(
        task_id="t",
        kind="pipeline",
        stages=[
            StageRecord(name="consensus"),
            StageRecord(name="search_reduce"),
            StageRecord(name="brute_force"),
        ],
    )


def test_update_stage_parent_exact_start_and_end(tmp_path: Path):
    mgr = _mgr_for_unit_tests(tmp_path)
    record = _fresh_record()

    changed = mgr._update_stage(record, "search_reduce", 0.0, "starting", "stage_start")
    assert changed is True
    sr = next(s for s in record.stages if s.name == "search_reduce")
    assert sr.status == TaskStatus.RUNNING
    assert sr.started_at is not None
    assert sr.msg == "starting"

    changed = mgr._update_stage(record, "search_reduce", 1.0, "done", "stage_end")
    assert changed is True
    assert sr.status == TaskStatus.SUCCEEDED
    assert sr.ended_at is not None
    assert sr.pct == 1.0


def test_update_stage_sub_stage_events_never_transition_parent(tmp_path: Path):
    mgr = _mgr_for_unit_tests(tmp_path)
    record = _fresh_record()
    # Parent must already be running before sub-stage events can arrive.
    mgr._update_stage(record, "search_reduce", 0.0, "", "stage_start")
    sr = next(s for s in record.stages if s.name == "search_reduce")
    assert sr.status == TaskStatus.RUNNING

    # A sub-stage_start must NOT transition parent status and must NOT
    # return status_changed=True (no persistence on sub-stage events).
    changed = mgr._update_stage(
        record, "search_reduce:variance", 0.2, "variance", "stage_start"
    )
    assert changed is False
    assert sr.status == TaskStatus.RUNNING
    assert sr.msg == "variance"
    assert sr.pct == 0.2

    changed = mgr._update_stage(
        record, "search_reduce:aligned", 0.6, "aligned", "progress"
    )
    assert changed is False
    assert sr.status == TaskStatus.RUNNING
    assert sr.pct == 0.6

    # Critically: a sub-stage_end must NOT mark the parent SUCCEEDED.
    changed = mgr._update_stage(
        record, "search_reduce:entropy", 0.9, "entropy", "stage_end"
    )
    assert changed is False
    assert sr.status == TaskStatus.RUNNING
    assert sr.ended_at is None


def test_update_stage_undeclared_stage_is_ignored(tmp_path: Path):
    mgr = _mgr_for_unit_tests(tmp_path)
    record = _fresh_record()
    changed = mgr._update_stage(
        record, "mystery_stage", 0.5, "hi", "stage_start"
    )
    assert changed is False
    assert all(s.status == TaskStatus.PENDING for s in record.stages)


def test_update_stage_progress_updates_pct_and_msg_without_status_change(
    tmp_path: Path,
):
    mgr = _mgr_for_unit_tests(tmp_path)
    record = _fresh_record()
    mgr._update_stage(record, "brute_force", 0.0, "", "stage_start")
    bf = next(s for s in record.stages if s.name == "brute_force")
    assert bf.status == TaskStatus.RUNNING

    changed = mgr._update_stage(record, "brute_force", 0.33, "1/3", "progress")
    assert changed is False
    assert bf.pct == 0.33
    assert bf.msg == "1/3"
    assert bf.status == TaskStatus.RUNNING


# ----- shutdown: the hang that used to force `kill -9` ----------------------
#
# Killing the server printed "resource_tracker: There appear to be 5 leaked
# semaphore objects" -- the fingerprint of exactly one un-finalized
# ProcessPoolExecutor (_call_queue contributes 3 semaphores, _result_queue 2).
# The semaphores were a symptom: SIGKILL skips every atexit handler, and SIGKILL
# was only needed because graceful shutdown could not finish. These tests pin
# each reason it could not.


@contextmanager
def _standalone_manager(
    tmp_path: Path,
    max_workers: int = 2,
    teardown_grace_s: float = SHUTDOWN_GRACE_S,
):
    """A started TaskManager whose teardown the TEST drives and times.

    The module-level ``task_manager`` fixture delegates here; the tests below
    enter it directly because they need to drive and time the teardown
    themselves, which a fixture does after the test body has ended.

    ``teardown_grace_s`` shortens the cooperative window for the tests that
    park a ``stubborn_runner``: that runner exists to ignore cancellation, so
    every one of the real 5 seconds is spent reaching a foregone conclusion.
    """
    mgr = TaskManager(
        task_root=tmp_path / "tasks",
        artifact_store=ArtifactStore(tmp_path / "artifacts"),
        progress_bus=ProgressBus(),
        max_workers=max_workers,
    )
    loop = asyncio.new_event_loop()
    try:
        loop.run_until_complete(mgr.startup(loop))
        yield mgr, loop
    finally:
        mgr.shutdown(grace_s=teardown_grace_s)  # idempotent: already-shut-down is fine
        # Unwind stragglers the way ``asyncio.run`` would, so closing the loop
        # does not print "Task was destroyed but it is pending". ``shutdown``
        # has already set ``_closing``, so a ``_gated_submit`` that only gets
        # scheduled here bails out at the gate instead of starting real work.
        stragglers = asyncio.all_tasks(loop)
        for task in stragglers:
            task.cancel()
        if stragglers:
            loop.run_until_complete(
                asyncio.gather(*stragglers, return_exceptions=True)
            )
        loop.close()
        reset_task_manager()


def _wait_for_running(mgr: TaskManager, task_id: str, loop, timeout: float = 15.0):
    return _wait_for_status(
        mgr, task_id, loop, lambda r: r.status == TaskStatus.RUNNING,
        timeout=timeout, what="RUNNING",
    )


def _submit_stubborn(mgr: TaskManager, loop):
    """Start a worker that will NOT stop when asked, and wait until it runs."""
    record = mgr.submit(
        kind="pipeline",
        params={"seconds": 30.0},
        runner_dotted="tests._task_runners.stubborn_runner",
        stage_names=["spin"],
    )
    _wait_for_running(mgr, record.task_id, loop)
    return record


# Short enough to be free, long enough that a cooperative worker would still
# make it out through the normal path rather than the SIGTERM escalation.
FAST_GRACE_S = 0.2


@pytest.mark.timeout(90)
def test_default_executor_shuts_down_with_task_running(tmp_path: Path):
    """THE reported bug, reduced to one call.

    uvicorn serves under ``asyncio.Runner``, whose ``close()`` calls
    ``loop.shutdown_default_executor()``. On Python 3.11 that joins its threads
    with NO timeout -- the ``timeout`` parameter only arrived in 3.12. The old
    ``await loop.run_in_executor(None, future.result)`` parked one of those
    threads for a task's whole duration, and the old unbounded
    ``run_in_executor(None, q.get)`` parked a second one permanently. So this
    call used to block until the pipeline finished, which is why Ctrl-C did
    nothing and ``kill -9`` was the only way out.

    The ``timeout`` marker matters: a regression makes this HANG (the cancelled
    ``shutdown_default_executor`` still joins its helper thread in a ``finally``),
    so without it a broken build would stall rather than fail.

    The grace window is shortened because it is the CONTEXTMANAGER's teardown
    that pays it here; the assertion under test is only that
    ``shutdown_default_executor()`` returns at all.
    """
    with _standalone_manager(tmp_path, teardown_grace_s=FAST_GRACE_S) as (mgr, loop):
        _submit_stubborn(mgr, loop)
        loop.run_until_complete(
            asyncio.wait_for(loop.shutdown_default_executor(), 20.0)
        )


@pytest.mark.timeout(90)
def test_shutdown_returns_while_stubborn_task_runs(tmp_path: Path):
    """Teardown is bounded even against a worker that ignores cancellation.

    ``pool.shutdown(wait=False)`` does not stop a running worker, and
    ``concurrent.futures.process._python_exit`` later joins it with no timeout
    of its own -- so a worker left alive here is a hang merely relocated to
    interpreter exit.

    The BOUND is the point of this test, so it is computed from the grace
    actually in force rather than slept through at full price. ``_reap_workers``
    applies each escalation to ALL workers before waiting on any of them, so the
    worst case is ``grace + 2 * WORKER_TERM_TIMEOUT_S`` regardless of how many
    workers there are.
    """
    # The window is injected rather than slept through, so pin the production
    # default here -- it is what the server actually ships with.
    assert SHUTDOWN_GRACE_S == 5.0

    with _standalone_manager(tmp_path, teardown_grace_s=FAST_GRACE_S) as (mgr, loop):
        _submit_stubborn(mgr, loop)
        workers = list(mgr._pool._processes.values())
        assert workers, "expected at least one spawned worker"

        started = time.monotonic()
        mgr.shutdown(grace_s=FAST_GRACE_S)
        elapsed = time.monotonic() - started

        assert elapsed < FAST_GRACE_S + 2 * WORKER_TERM_TIMEOUT_S + 10.0
        for proc in workers:
            assert not proc.is_alive(), f"worker {proc.pid} outlived shutdown"
        assert mgr._pool is None and mgr._mp_manager is None


def test_signal_cancel_all_sets_live_events(tmp_path: Path):
    """Cancel events are set while the Manager that serves them is still up.

    They are proxies, and ``WorkerContext.is_cancelled`` swallows proxy errors,
    so setting them after the Manager died would silently reach no worker. That
    ordering is why ``shutdown`` calls this before ``_stop_manager``.
    """
    with _standalone_manager(tmp_path) as (mgr, loop):
        record = mgr.submit(
            kind="spin",
            params={"iterations": 100000},
            runner_dotted="tests._task_runners.cancellable_runner",
        )
        event = mgr._cancel_events[record.task_id]
        assert not event.is_set()

        mgr._signal_cancel_all()
        assert event.is_set()


def test_gated_submit_bails_out_when_closing(tmp_path: Path):
    """A submit queued on the gate must not dispatch across a shutdown.

    The ``assert`` at the top of ``_gated_submit`` runs BEFORE the semaphore is
    acquired, so without the in-lock re-read a coroutine that waited there
    across a teardown reached ``None.submit`` on a dying loop.
    """
    with _standalone_manager(tmp_path) as (mgr, loop):
        task_id = "queued-across-shutdown"
        mgr._records[task_id] = TaskRecord(task_id=task_id, kind="pipeline")
        mgr._closing = True

        loop.run_until_complete(
            mgr._gated_submit(
                task_id, "tests._task_runners.echo_runner", {}, None
            )
        )

        assert task_id not in mgr._futures
        assert mgr._records[task_id].status == TaskStatus.PENDING


@pytest.mark.timeout(90)
def test_aclose_tears_down_pool_manager_and_drain(tmp_path: Path):
    """The async twin the FastAPI lifespan uses leaves nothing behind."""
    with _standalone_manager(tmp_path) as (mgr, loop):
        loop.run_until_complete(mgr.aclose())
        assert mgr._closing is True
        assert mgr._pool is None
        assert mgr._mp_manager is None
        assert mgr._drain_task is None


@pytest.mark.timeout(90)
def test_startup_shutdown_leaves_no_pymp_dir(tmp_path: Path):
    """A full startup/shutdown cycle strands no Manager temp dir.

    See ``tests/_pymp.py`` for why leakage is a set difference and why the
    assertion polls.
    """
    before = pymp_dirs()
    with _standalone_manager(tmp_path):
        pass
    assert_no_new_pymp_dirs(before)
