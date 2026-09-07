"""Tests for live ``artifact`` progress events.

Covers the producer that closed the "results screen shows no artifacts until
you reload" bug: ``app.pipeline.artifact_events.EmittingArtifactList`` +
the duck-typed notification hook in ``core.artifact_util.register_artifact``,
and the ``TaskManager`` drain barrier that stops those events from losing the
race with the terminal ``done`` publish.

Three layers are exercised separately:

1. Registration -> notification (pure, no process pool).
2. The TaskManager's worker-event consumer -> ProgressBus ``Event``.
3. A real spawn-pool round trip proving ORDER: the ``artifact`` events land on
   the bus strictly before ``done``, which is what makes them visible to a
   live WebSocket subscriber (``ProgressBus.subscribe`` stops iterating the
   instant it yields ``done``).
"""

from __future__ import annotations

import asyncio
import pickle
import time
from pathlib import Path

import pytest

from memdiver.api.services.artifact_store import ArtifactStore
from memdiver.api.services.progress_bus import ProgressBus
from memdiver.api.services.task_manager import (
    DRAIN_FLUSH_KEY,
    StageRecord,
    TaskManager,
    TaskRecord,
    TaskStatus,
    reset_task_manager,
)
from memdiver.app.pipeline.artifact_events import EmittingArtifactList
from memdiver.core.artifact_util import register_artifact


class _RecordingCtx:
    """Minimal WorkerContext stand-in: records every emit."""

    def __init__(self) -> None:
        self.events: list[tuple[str, dict]] = []

    def emit(self, event_type: str, **fields) -> None:
        self.events.append((event_type, fields))


@pytest.fixture
def artifact_dir(tmp_path: Path) -> Path:
    d = tmp_path / "artifacts"
    d.mkdir()
    (d / "plugin.py").write_text("# vol3 plugin\n")
    return d


# ---------------------------------------------------------------------------
# 1. registration -> notification
# ---------------------------------------------------------------------------


def test_plain_list_registration_emits_nothing(artifact_dir: Path):
    """The default path is unchanged: a plain list has no notification hook."""
    artifacts: list = []
    spec = register_artifact(
        artifacts, artifact_dir, name="plugin", relpath="plugin.py",
        media_type="text/x-python",
    )
    assert artifacts == [spec]
    assert not hasattr(artifacts, "artifact_registered")


def test_emitting_list_emits_one_artifact_event_per_registration(artifact_dir: Path):
    ctx = _RecordingCtx()
    artifacts = EmittingArtifactList(ctx)

    register_artifact(
        artifacts, artifact_dir, name="plugin", relpath="plugin.py",
        media_type="text/x-python",
    )
    (artifact_dir / "report.md").write_text("# report\n")
    register_artifact(
        artifacts, artifact_dir, name="report", relpath="report.md",
        media_type="text/markdown",
    )

    assert [e[0] for e in ctx.events] == ["artifact", "artifact"]
    assert len(artifacts) == 2


def test_artifact_event_shape_matches_the_consumer_contract(artifact_dir: Path):
    """The payload must ride on ``artifact`` (not ``extra``) with the spec keys.

    ``TaskManager._handle_worker_event`` copies ``payload["artifact"]`` onto
    ``Event.artifact``, and the frontend reducer reads
    ``event.artifact.{name,relpath,media_type,size,sha256}``. Pin all of it.
    """
    ctx = _RecordingCtx()
    artifacts = EmittingArtifactList(ctx)
    spec = register_artifact(
        artifacts, artifact_dir, name="vol3_plugin", relpath="plugin.py",
        media_type="text/x-python",
    )

    (event_type, fields), = ctx.events
    assert event_type == "artifact"
    assert set(fields) == {"artifact"}, "no other event fields may be invented"
    assert fields["artifact"] == spec
    assert fields["artifact"] == {
        "name": "vol3_plugin",
        "relpath": "plugin.py",
        "media_type": "text/x-python",
        "size": len("# vol3 plugin\n"),
        "sha256": spec["sha256"],
    }
    assert isinstance(spec["sha256"], str) and len(spec["sha256"]) == 64


def test_emitted_payload_is_a_copy_not_the_stored_spec(artifact_dir: Path):
    """The emit must not alias the dict that also travels in the return value."""
    ctx = _RecordingCtx()
    artifacts = EmittingArtifactList(ctx)
    spec = register_artifact(
        artifacts, artifact_dir, name="plugin", relpath="plugin.py",
    )
    emitted = ctx.events[0][1]["artifact"]
    assert emitted == spec
    assert emitted is not spec


def test_failing_sink_never_breaks_registration(artifact_dir: Path):
    """A broken emit costs a progress event, never the pipeline stage."""

    class _Exploding(EmittingArtifactList):
        def artifact_registered(self, spec):  # type: ignore[override]
            raise RuntimeError("queue is gone")

    artifacts = _Exploding(_RecordingCtx())
    spec = register_artifact(
        artifacts, artifact_dir, name="plugin", relpath="plugin.py",
    )
    assert list(artifacts) == [spec]


def test_emitting_list_pickles_as_a_plain_list(artifact_dir: Path):
    """``__reduce__`` must strip the ctx: the worker RETURNS this list.

    Without it, pickling the ``{"artifacts": ...}`` result back to the parent
    would try to pickle the WorkerContext's ``mp.Queue`` and turn every
    successful run into a last-moment failure.
    """
    ctx = _RecordingCtx()
    artifacts = EmittingArtifactList(ctx)
    register_artifact(artifacts, artifact_dir, name="plugin", relpath="plugin.py")

    revived = pickle.loads(pickle.dumps(artifacts))
    assert type(revived) is list
    assert revived == list(artifacts)


def test_emitting_list_is_substitutable_for_a_plain_list():
    ctx = _RecordingCtx()
    artifacts = EmittingArtifactList(ctx, [{"name": "seed"}])
    assert isinstance(artifacts, list)
    assert artifacts == [{"name": "seed"}]
    assert ctx.events == [], "seeding must not emit"


# ---------------------------------------------------------------------------
# 2. worker event -> ProgressBus Event
# ---------------------------------------------------------------------------


def _manager(tmp_path: Path) -> tuple[TaskManager, ProgressBus]:
    bus = ProgressBus()
    mgr = TaskManager(
        task_root=tmp_path / "tasks",
        artifact_store=ArtifactStore(tmp_path / "artifacts"),
        progress_bus=bus,
    )
    return mgr, bus


def test_handle_worker_event_publishes_artifact_events(tmp_path: Path):
    mgr, bus = _manager(tmp_path)
    record = TaskRecord(
        task_id="t1", kind="pipeline", params={},
        stages=[StageRecord(name="emit_plugin")],
    )
    record.status = TaskStatus.RUNNING
    mgr._records["t1"] = record

    spec = {
        "name": "vol3_plugin", "relpath": "emit_plugin/x.py",
        "media_type": "text/x-python", "size": 12, "sha256": "ab" * 32,
    }
    mgr._handle_worker_event({"task_id": "t1", "type": "artifact", "artifact": spec})

    published = bus.replay("t1")
    assert len(published) == 1
    assert published[0].type == "artifact"
    assert published[0].artifact == spec
    # An artifact event is not a stage transition: the stage row is untouched.
    assert record.stages[0].status == TaskStatus.PENDING


def test_artifact_event_survives_to_dict_for_the_websocket(tmp_path: Path):
    """``Event.to_dict`` drops Nones — the artifact field must not be dropped."""
    mgr, bus = _manager(tmp_path)
    spec = {"name": "report", "relpath": "nsweep/report.md",
            "media_type": "text/markdown", "size": 3, "sha256": None}
    mgr._handle_worker_event({"task_id": "t2", "type": "artifact", "artifact": spec})

    payload = bus.replay("t2")[0].to_dict()
    assert payload["type"] == "artifact"
    assert payload["artifact"] == spec


# ---------------------------------------------------------------------------
# 3. drain barrier: ordering relative to ``done``
# ---------------------------------------------------------------------------


def test_flush_sentinel_is_not_mistaken_for_an_event(tmp_path: Path):
    """The barrier sentinel must never reach ``_handle_worker_event``."""
    mgr, bus = _manager(tmp_path)
    mgr._handle_worker_event({DRAIN_FLUSH_KEY: "t3"})
    # No task_id key -> ignored outright; nothing published.
    assert bus.replay("t3") == []


@pytest.fixture
def task_manager(tmp_path: Path):
    """Fresh started TaskManager + its loop (mirrors tests/test_task_manager.py)."""
    bus = ProgressBus()
    mgr = TaskManager(
        task_root=tmp_path / "tasks",
        artifact_store=ArtifactStore(tmp_path / "artifacts"),
        progress_bus=bus,
        max_workers=2,
    )
    loop = asyncio.new_event_loop()

    async def _start():
        await mgr.startup(asyncio.get_running_loop())

    try:
        loop.run_until_complete(_start())
        yield mgr, bus, loop
    finally:
        mgr.shutdown()
        loop.run_until_complete(asyncio.sleep(0.01))
        loop.close()
        reset_task_manager()


def _wait_terminal(mgr: TaskManager, task_id: str, loop, timeout: float = 30.0):
    deadline = time.time() + timeout
    while time.time() < deadline:
        loop.run_until_complete(asyncio.sleep(0.05))
        record = mgr.get(task_id)
        if record is not None and record.status in (
            TaskStatus.SUCCEEDED, TaskStatus.FAILED, TaskStatus.CANCELLED,
        ):
            return record
    raise AssertionError(f"task {task_id} never reached a terminal state")


def test_artifact_events_reach_the_bus_before_done(task_manager, tmp_path: Path):
    """End-to-end: the events a runner emits LAST still precede ``done``.

    This is the regression guard for the observed race — a run whose final
    ``stage_end`` never reached the WebSocket because ``done`` (which arrives
    on the pool's result channel, not the progress queue) closed the bus
    channel first. Every ``artifact`` event of the last stage had the same
    exposure, which would have made the fix a flaky UI.
    """
    mgr, bus, loop = task_manager
    out = tmp_path / "run-artifacts"
    record = mgr.submit(
        kind="pipeline",
        params={"artifact_dir": str(out)},
        runner_dotted="tests._task_runners.artifact_registering_runner",
        stage_names=["emit"],
    )
    final = _wait_terminal(mgr, record.task_id, loop)
    assert final.status == TaskStatus.SUCCEEDED, final.error

    events = bus.replay(record.task_id)
    types = [e.type for e in events]
    assert "done" in types, types
    done_at = types.index("done")

    artifact_events = [e for e in events if e.type == "artifact"]
    assert [e.artifact["name"] for e in artifact_events] == [
        "first_artifact", "vol3_plugin",
    ], types
    # THE assertion: every artifact event is ordered before the terminal
    # ``done``, so a live subscriber (which stops at ``done``) has seen them.
    for event in artifact_events:
        assert types.index(event.type) < done_at
        assert event.seq < events[done_at].seq

    # The final stage_end is no longer overtaken either (same root cause).
    assert types.index("stage_end") < done_at

    # And the record still carries the artifacts at completion — the reload
    # path that used to be the ONLY way to see them is untouched.
    assert [a.name for a in final.artifacts] == ["first_artifact", "vol3_plugin"]
