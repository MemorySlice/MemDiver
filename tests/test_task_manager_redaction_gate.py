"""TaskManager: secrets never reach a task RECORD; a cancel frees the one-job gate.

* ``redact_secret_params`` walks dicts and lists at any depth and keeps empties;
* ``submit`` persists and serves the redacted copy while the worker gets the
  real params; ``load_from_disk`` rewrites a record written before redaction;
* a cancelled cooperative worker frees the gate as soon as it returns; one that
  ignores its cancel stops blocking the queue after ``CANCEL_GATE_GRACE_S``.

The runners live in ``tests/_task_runners.py`` so spawn can import them.
"""

from __future__ import annotations

import asyncio
import json
import time
from pathlib import Path

import pytest

from memdiver.api.services import task_manager as tm
from memdiver.api.services.artifact_store import ArtifactStore
from memdiver.api.services.progress_bus import ProgressBus
from memdiver.api.services.task_manager import (
    REDACTED,
    TaskManager,
    TaskRecord,
    TaskStatus,
    redact_secret_params,
)

SECRET = "5ec12e7" * 8
RUNNERS = "tests._task_runners"


def test_redaction_walks_every_depth_and_keeps_empties():
    params = {
        "args": {"view_path": "/v", "key_hex": SECRET, "nested": [{"passphrase": "pw"}]},
        "kwargs": {"key_hex": [SECRET, SECRET], "full_image_key_hex": "", "pid": 7},
        "key_material_hex": {"passphrase": "pw", "key_hex": None},
        "secret_hex": SECRET, "keylog_line": "CLIENT_RANDOM a b", "kem_key_hex": None,
        "tuple": ({"secret": {"label": "x"}},),
    }
    got = redact_secret_params(params)
    assert got == {
        "args": {"view_path": "/v", "key_hex": REDACTED, "nested": [{"passphrase": REDACTED}]},
        "kwargs": {"key_hex": REDACTED, "full_image_key_hex": "", "pid": 7},
        "key_material_hex": REDACTED,
        "secret_hex": REDACTED, "keylog_line": REDACTED, "kem_key_hex": None,
        "tuple": [{"secret": REDACTED}],
    }
    assert params["args"]["key_hex"] == SECRET  # the input is not mutated


@pytest.fixture
def manager(tmp_path):
    mgr = TaskManager(task_root=tmp_path / "tasks", artifact_store=ArtifactStore(tmp_path / "art"),
                      progress_bus=ProgressBus(), max_workers=2)
    loop = asyncio.new_event_loop()
    loop.run_until_complete(mgr.startup(loop))
    try:
        yield mgr, loop
    finally:
        mgr.shutdown(grace_s=0.0)
        stragglers = asyncio.all_tasks(loop)
        for task in stragglers:
            task.cancel()
        if stragglers:
            loop.run_until_complete(asyncio.gather(*stragglers, return_exceptions=True))
        loop.close()


def _until(mgr, loop, task_id, status, timeout=30.0):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        loop.run_until_complete(asyncio.sleep(0.05))
        if mgr.get(task_id).status == status:
            return time.monotonic()
    raise AssertionError(f"{task_id} never reached {status}: {mgr.get(task_id).status}")


def _submit(mgr, runner, params, kind="t"):
    return mgr.submit(kind=kind, params=params, runner_dotted=f"{RUNNERS}.{runner}",
                      stage_names=[kind]).task_id


def test_record_is_redacted_but_the_worker_gets_the_secrets(manager, tmp_path):
    mgr, loop = manager
    events = []
    params = {"args": {"key_hex": SECRET, "passphrase": "pw-" + SECRET}, "plain": 1}
    task_id = _submit(mgr, "echo_runner", params)
    mgr.progress_bus.publish = lambda event, _orig=mgr.progress_bus.publish: (
        events.append(event), _orig(event))[1]
    _until(mgr, loop, task_id, TaskStatus.SUCCEEDED)
    record_file = tmp_path / "tasks" / task_id / "record.json"
    assert SECRET not in record_file.read_text()
    assert json.loads(record_file.read_text())["params"] == {
        "args": {"key_hex": REDACTED, "passphrase": REDACTED}, "plain": 1}
    assert mgr.get(task_id).to_dict()["params"]["args"]["key_hex"] == REDACTED
    (done,) = [e for e in events if e.type == "done"]
    assert done.extra["echoed"]["args"]["key_hex"] == SECRET  # echo_runner saw the real value


def test_a_record_written_before_redaction_is_rewritten(tmp_path):
    task_dir = tmp_path / "tasks" / "old"
    task_dir.mkdir(parents=True)
    old = TaskRecord(task_id="old", kind="analysis", status=TaskStatus.SUCCEEDED,
                     params={"dump_path": "/d", "passphrase": "pw", "key_hex": SECRET})
    (task_dir / "record.json").write_text(json.dumps(old.to_dict()))
    mgr = TaskManager(task_root=tmp_path / "tasks", artifact_store=ArtifactStore(tmp_path / "a"),
                      progress_bus=ProgressBus())
    mgr.load_from_disk()
    assert SECRET not in (task_dir / "record.json").read_text()
    assert mgr.get("old").params == {"dump_path": "/d", "passphrase": REDACTED,
                                     "key_hex": REDACTED}
    assert mgr.get("old").status == TaskStatus.SUCCEEDED


def test_cancelled_cooperative_worker_frees_the_gate_when_it_returns(manager, monkeypatch):
    mgr, loop = manager
    monkeypatch.setattr(tm, "CANCEL_GATE_GRACE_S", 60.0)  # the backstop must not be what frees it
    spinning = _submit(mgr, "cancellable_runner", {"iterations": 100_000})
    _until(mgr, loop, spinning, TaskStatus.RUNNING)
    queued = _submit(mgr, "echo_runner", {"x": 1})
    loop.run_until_complete(asyncio.sleep(0.3))
    assert mgr.get(queued).status == TaskStatus.PENDING  # one job at a time
    t0 = time.monotonic()
    assert mgr.cancel(spinning)
    # Far below the 60 s backstop (generous: other agents' scans load the machine).
    assert _until(mgr, loop, queued, TaskStatus.SUCCEEDED) - t0 < 20.0


def test_other_kinds_keep_the_gate_until_their_worker_returns(manager, monkeypatch):
    """Early release is opt-in: a slow-to-unwind pipeline must not overlap the next one."""
    mgr, loop = manager
    monkeypatch.setattr(tm, "CANCEL_GATE_GRACE_S", 0.3)
    stuck = _submit(mgr, "stubborn_runner", {"seconds": 4}, kind="pipeline")
    _until(mgr, loop, stuck, TaskStatus.RUNNING)
    queued = _submit(mgr, "echo_runner", {"x": 1})
    assert mgr.cancel(stuck)
    loop.run_until_complete(asyncio.sleep(2.0))  # well past the 0.3 s grace
    assert mgr.get(queued).status == TaskStatus.PENDING
    _until(mgr, loop, queued, TaskStatus.SUCCEEDED)  # once the worker returns


def test_a_worker_ignoring_cancel_stops_blocking_after_the_grace(manager, monkeypatch):
    mgr, loop = manager
    monkeypatch.setattr(tm, "CANCEL_GATE_GRACE_S", 0.5)
    stuck = _submit(mgr, "stubborn_runner", {"seconds": 30}, kind="vol3_synth")
    _until(mgr, loop, stuck, TaskStatus.RUNNING)
    queued = _submit(mgr, "echo_runner", {"x": 1})
    t0 = time.monotonic()
    assert mgr.cancel(stuck)
    # Long before the stuck worker's 30 s sleep ends.
    assert _until(mgr, loop, queued, TaskStatus.SUCCEEDED) - t0 < 20.0
    assert mgr.get(stuck).status == TaskStatus.CANCELLED


def test_a_worker_interrupted_by_ctrl_c_fails_its_task_and_the_loop_lives_on(manager):
    """Fact 5: a terminal Ctrl-C reaches the workers; their interrupt is a task result."""
    mgr, loop = manager
    interrupted = _submit(mgr, "interrupted_runner", {})
    try:
        _until(mgr, loop, interrupted, TaskStatus.FAILED)
    except KeyboardInterrupt:  # the regression: it escaped the event loop
        pytest.fail("a worker's KeyboardInterrupt escaped the TaskManager event loop")
    assert mgr.get(interrupted).error == "interrupted"
    nxt = _submit(mgr, "echo_runner", {"x": 1})
    _until(mgr, loop, nxt, TaskStatus.SUCCEEDED)


def test_a_keyboard_interrupt_that_is_not_a_job_result_still_propagates():
    from concurrent.futures import Future
    pending, failed, interrupted = Future(), Future(), Future()
    failed.set_exception(RuntimeError("boom"))
    interrupted.set_exception(KeyboardInterrupt())
    assert [tm._interrupted_worker(f) for f in (pending, failed, interrupted)] == [
        False, False, True]


def test_a_worker_killed_mid_job_does_not_break_the_jobs_after_it(manager):
    """SIGKILL / OOM of a worker breaks the whole ProcessPoolExecutor; the next job must
    still run (it used to stay RUNNING forever: every submit raised BrokenProcessPool)."""
    mgr, loop = manager
    killed = _submit(mgr, "killed_runner", {})
    _until(mgr, loop, killed, TaskStatus.FAILED)
    assert "BrokenProcessPool" in mgr.get(killed).error
    nxt = _submit(mgr, "echo_runner", {"x": 1})
    _until(mgr, loop, nxt, TaskStatus.SUCCEEDED)


def test_gate_release_is_idempotent():
    async def scenario():
        lock = asyncio.Semaphore(1)
        gate = tm._ReleasableGate(lock)
        async with gate:
            gate.release()  # early (cancel backstop) ...
            assert not lock.locked()
            await lock.acquire()  # ... someone else takes it
        assert lock.locked()  # the normal exit did not release THEIR hold
    asyncio.run(scenario())


def test_rest_task_listing_serves_the_redacted_record(tmp_path, monkeypatch):
    """``/api/analysis/run-file`` used to persist and list the container key material."""
    from fastapi.testclient import TestClient

    from memdiver.api.config import get_settings
    from memdiver.api.main import create_app
    for sub, env in (("tasks", "MEMDIVER_TASK_ROOT"), ("uploads", "MEMDIVER_UPLOAD_DIR")):
        (tmp_path / sub).mkdir()
        monkeypatch.setenv(env, str(tmp_path / sub))
    dump = tmp_path / "uploads" / "d.bin"
    dump.write_bytes(bytes(4096))
    get_settings.cache_clear()
    try:
        with TestClient(create_app()) as client:
            resp = client.post("/api/analysis/run-file", json={
                "dump_path": str(dump), "algorithms": ["entropy_scan"],
                "passphrase": "pw-" + SECRET, "key_hex": SECRET})
            assert resp.status_code == 200, resp.text
            task_id = resp.json()["task_id"]
            texts = [client.get("/api/tasks/").text, client.get(f"/api/tasks/{task_id}").text]
    finally:
        get_settings.cache_clear()
    texts.append((tmp_path / "tasks" / task_id / "record.json").read_text())
    assert all(SECRET not in text for text in texts)
    assert json.loads(texts[1])["params"]["key_hex"] == REDACTED
    assert Path(tmp_path / "tasks" / task_id).is_dir()
