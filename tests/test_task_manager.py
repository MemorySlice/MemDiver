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
from pathlib import Path

import pytest

from api.services.artifact_store import ArtifactStore
from api.services.progress_bus import ProgressBus
from api.services.task_manager import (
    StageRecord,
    TaskManager,
    TaskRecord,
    TaskStatus,
    reset_task_manager,
)


@pytest.fixture
def task_manager(tmp_path: Path):
    """Fresh TaskManager per test, started and torn down properly."""
    store = ArtifactStore(tmp_path / "artifacts")
    bus = ProgressBus()
    mgr = TaskManager(
        task_root=tmp_path / "tasks",
        artifact_store=store,
        progress_bus=bus,
        max_workers=2,
    )

    async def start():
        await mgr.startup(asyncio.get_running_loop())

    loop = asyncio.new_event_loop()
    try:
        loop.run_until_complete(start())
        yield mgr, loop
    finally:
        mgr.shutdown()
        loop.run_until_complete(asyncio.sleep(0.01))
        loop.close()
        reset_task_manager()


def _wait_for_terminal(mgr: TaskManager, task_id: str, loop, timeout: float = 15.0):
    deadline = time.time() + timeout
    while time.time() < deadline:
        loop.run_until_complete(asyncio.sleep(0.05))
        record = mgr.get(task_id)
        if record is not None and record.status in (
            TaskStatus.SUCCEEDED, TaskStatus.FAILED, TaskStatus.CANCELLED
        ):
            return record
    raise AssertionError(f"task {task_id} never reached terminal state")


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
    deadline = time.time() + 5.0
    while time.time() < deadline:
        loop.run_until_complete(asyncio.sleep(0.05))
        if mgr.get(record.task_id).status == TaskStatus.RUNNING:
            break
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
