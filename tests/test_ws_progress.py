"""Tests for api.ws.progress — task-progress WebSocket + HTTP events backfill.

Two entry points share the :class:`ProgressBus` installed on the
``TaskManager`` singleton during the FastAPI lifespan:

* ``WebSocket /ws/tasks/{task_id}?since=<seq>`` replays retained events
  then streams live updates until a terminal ``done``/``error``.
* ``GET /api/tasks/{task_id}/events?since=<seq>`` returns the retained
  slice in one shot (HTTP fallback for a reconnecting client).

We reuse the ``isolated_env``/``client`` convention from
``tests/test_api_dataset.py`` (redirect every settings dir into
``tmp_path``). The ``client`` fixture enters the lifespan, so the
singleton TaskManager (and its ProgressBus) is live; we reach into it via
``get_task_manager()`` and publish :class:`Event`s under ``mgr._lock``
exactly like ``tests/test_api_tasks.py``. The manager-uninitialized paths
build a TestClient *without* entering the lifespan so no singleton is
installed.
"""

from __future__ import annotations

import asyncio
from pathlib import Path

import pytest
from fastapi import WebSocketDisconnect
from fastapi.testclient import TestClient

from memdiver.api.config import get_settings
from memdiver.api.main import create_app
from memdiver.api.services.progress_bus import Event
from memdiver.api.services.task_manager import (
    get_task_manager,
    reset_task_manager,
)
from memdiver.api.ws.progress import ws_task_progress


# ---------------------------------------------------------------------------
# Fixtures (mirror tests/test_api_dataset.py + tests/test_api_tasks.py)
# ---------------------------------------------------------------------------


@pytest.fixture
def isolated_env(tmp_path: Path, monkeypatch):
    """Redirect every settings-controlled directory into tmp_path."""
    for sub, env in [
        ("oracles", "MEMDIVER_ORACLE_DIR"),
        ("tasks", "MEMDIVER_TASK_ROOT"),
        ("uploads", "MEMDIVER_UPLOAD_DIR"),
        ("sessions", "MEMDIVER_SESSION_DIR"),
    ]:
        d = tmp_path / sub
        d.mkdir()
        monkeypatch.setenv(env, str(d))
    monkeypatch.setenv("MEMDIVER_PIPELINE_MAX_WORKERS", "1")
    get_settings.cache_clear()
    yield tmp_path
    get_settings.cache_clear()


@pytest.fixture
def client(isolated_env):
    """A TestClient that has entered the lifespan (TaskManager live)."""
    app = create_app()
    with TestClient(app) as c:
        yield c


def _collect_until_close(ws) -> list[dict]:
    """Drain a TestClient websocket until the server closes it."""
    frames: list[dict] = []
    try:
        while True:
            frames.append(ws.receive_json())
    except WebSocketDisconnect:
        pass
    return frames


# ---------------------------------------------------------------------------
# WebSocket /ws/tasks/{task_id}
# ---------------------------------------------------------------------------


def test_ws_manager_not_initialized_sends_error(isolated_env):
    """Connecting before a TaskManager is installed → accept + error frame.

    Building the client *without* the lifespan context manager leaves the
    module singleton uninitialised, so ``get_task_manager()`` raises and
    the handler emits an explicit error frame before closing.
    """
    reset_task_manager()
    c = TestClient(create_app())  # no ``with`` → lifespan never runs
    with c.websocket_connect("/ws/tasks/whatever") as ws:
        frame = ws.receive_json()
    assert frame["type"] == "error"
    assert frame["task_id"] == "whatever"
    assert "not initialized" in frame["error"]
    assert frame["seq"] == 1 and frame["ts"] > 0


def test_ws_unknown_task_sends_error(client):
    """An unknown task id (no record, empty ring) → 'unknown task' error."""
    with client.websocket_connect("/ws/tasks/ws-unknown-task") as ws:
        frame = ws.receive_json()
    assert frame["type"] == "error"
    assert frame["task_id"] == "ws-unknown-task"
    assert frame["error"] == "unknown task"
    assert frame["seq"] == 1 and frame["ts"] > 0  # same shape as every other frame


def test_ws_unknown_task_frame_seq_follows_since(client):
    with client.websocket_connect("/ws/tasks/ws-unknown-task-2?since=7") as ws:
        frame = ws.receive_json()
    assert frame["error"] == "unknown task" and frame["seq"] == 8 and frame["ts"] > 0


def test_ws_replays_backlog_and_closes_on_terminal(client):
    """A populated ring ending in ``done`` is replayed then the socket closes."""
    mgr = get_task_manager()
    task_id = "ws-terminal-task"
    with mgr._lock:  # noqa: SLF001 — test-only direct publish
        bus = mgr.progress_bus
        bus.publish(Event(task_id=task_id, type="stage_start", stage="scan"))
        bus.publish(Event(task_id=task_id, type="progress", pct=50.0))
        bus.publish(Event(task_id=task_id, type="done", msg="complete"))

    with client.websocket_connect(f"/ws/tasks/{task_id}?since=0") as ws:
        frames = _collect_until_close(ws)

    assert [f["type"] for f in frames] == ["stage_start", "progress", "done"]
    assert frames[1]["pct"] == 50.0
    assert frames[-1]["msg"] == "complete"


def test_ws_replays_only_events_after_since(client):
    """``?since=<seq>`` filters the replayed backlog to newer events."""
    mgr = get_task_manager()
    task_id = "ws-since-task"
    with mgr._lock:  # noqa: SLF001 — test-only direct publish
        bus = mgr.progress_bus
        bus.publish(Event(task_id=task_id, type="stage_start", stage="scan"))
        bus.publish(Event(task_id=task_id, type="progress", pct=25.0))
        bus.publish(Event(task_id=task_id, type="done"))

    # Skip the first event (seq == 1); replay should yield seq 2 and 3.
    with client.websocket_connect(f"/ws/tasks/{task_id}?since=1") as ws:
        frames = _collect_until_close(ws)

    assert [f["type"] for f in frames] == ["progress", "done"]


class _FakeWebSocket:
    """Minimal async WebSocket stand-in exposing only what the handler uses."""

    def __init__(self):
        self.sent: list[dict] = []
        self.closed = False

    async def accept(self):
        pass

    async def send_json(self, data):
        self.sent.append(data)

    async def close(self):
        self.closed = True

    async def receive(self):
        """The client never disconnects on its own (the handler races this)."""
        await asyncio.Event().wait()


def test_ws_live_loop_streams_subscribe_event_then_closes(client, monkeypatch):
    """Backlog replay (non-terminal) falls through to the live ``subscribe``
    loop, which streams a live event and closes on its terminal type.

    This exercises the branch the earlier terminal-backlog tests can't
    reach: once the replay ``for`` loop finishes without hitting a
    ``done``/``error`` event, the handler moves on to
    ``async for event in bus.subscribe(task_id)``. We monkeypatch the
    bus's ``subscribe`` to a fake async generator yielding a single
    terminal event so the live loop sends it and closes deterministically,
    instead of racing a real background publisher.
    """
    mgr = get_task_manager()
    task_id = "ws-live-task"
    with mgr._lock:  # noqa: SLF001 — test-only direct publish
        bus = mgr.progress_bus
        # Non-terminal backlog event: the replay loop sends it and falls
        # through to the live subscribe loop instead of returning early.
        bus.publish(Event(task_id=task_id, type="stage_start", stage="scan"))

    live_event = Event(task_id=task_id, type="done", seq=2, msg="live-done")

    async def fake_subscribe(_task_id):
        yield live_event

    monkeypatch.setattr(bus, "subscribe", fake_subscribe)

    fake_ws = _FakeWebSocket()
    asyncio.run(ws_task_progress(fake_ws, task_id, since=0))

    assert [f["type"] for f in fake_ws.sent] == ["stage_start", "done"]
    assert fake_ws.sent[-1]["msg"] == "live-done"
    assert fake_ws.closed is True


def test_ws_subscribe_exhausted_without_terminal_still_closes(client, monkeypatch):
    """``subscribe`` exhausting without a terminal event must still close.

    If the live-subscribe generator is torn down (e.g. bus/task cleanup)
    before ever yielding a ``done``/``error`` event, the ``async for`` loop
    ends on its own and falls off the end of the handler's ``try`` block.
    Without an explicit close on that fall-through, the socket would be
    left open with nothing left to send a terminal frame — a resource
    leak. Assert the handler closes it anyway.
    """
    mgr = get_task_manager()
    task_id = "ws-exhausted-task"
    with mgr._lock:  # noqa: SLF001 — test-only direct publish
        bus = mgr.progress_bus
        bus.publish(Event(task_id=task_id, type="stage_start", stage="scan"))

    async def fake_subscribe(_task_id):
        return
        yield  # pragma: no cover - makes this an async generator

    monkeypatch.setattr(bus, "subscribe", fake_subscribe)

    fake_ws = _FakeWebSocket()
    asyncio.run(ws_task_progress(fake_ws, task_id, since=0))

    assert [f["type"] for f in fake_ws.sent] == ["stage_start"]
    assert fake_ws.closed is True


def test_ws_disconnect_during_live_send_stops_cleanly(client, monkeypatch):
    """A client disconnect while sending a live event returns quietly.

    ``send_json`` raising ``WebSocketDisconnect`` (as it does on Starlette
    when the peer has gone away) must be swallowed by the handler's
    ``except WebSocketDisconnect: return`` rather than propagating — no
    ``close()`` call is expected since the socket is already gone.
    """
    mgr = get_task_manager()
    task_id = "ws-disconnect-task"
    with mgr._lock:  # noqa: SLF001 — test-only direct publish
        bus = mgr.progress_bus
        bus.publish(Event(task_id=task_id, type="stage_start", stage="scan"))

    live_event = Event(task_id=task_id, type="done", seq=2, msg="unreachable")

    async def fake_subscribe(_task_id):
        yield live_event

    monkeypatch.setattr(bus, "subscribe", fake_subscribe)

    class _DisconnectingWebSocket(_FakeWebSocket):
        async def send_json(self, data):
            await super().send_json(data)
            if data["type"] == "done":
                raise WebSocketDisconnect()

    fake_ws = _DisconnectingWebSocket()
    asyncio.run(ws_task_progress(fake_ws, task_id, since=0))

    assert [f["type"] for f in fake_ws.sent] == ["stage_start", "done"]
    assert fake_ws.closed is False


# ---------------------------------------------------------------------------
# GET /api/tasks/{task_id}/events
# ---------------------------------------------------------------------------


def test_http_events_returns_replayed_slice(client):
    """The HTTP backfill returns the full retained slice as dicts."""
    mgr = get_task_manager()
    task_id = "http-events-task"
    with mgr._lock:  # noqa: SLF001 — test-only direct publish
        bus = mgr.progress_bus
        bus.publish(Event(task_id=task_id, type="progress", pct=25.0, msg="quarter"))
        bus.publish(Event(task_id=task_id, type="done"))

    r = client.get(f"/api/tasks/{task_id}/events", params={"since": 0})
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["task_id"] == task_id
    events = body["events"]
    assert [e["type"] for e in events] == ["progress", "done"]
    assert events[0]["pct"] == 25.0
    assert events[0]["msg"] == "quarter"
    # seq is assigned monotonically by the bus.
    assert [e["seq"] for e in events] == [1, 2]


def test_http_events_unknown_task_is_empty(client):
    """An unknown task id yields a 200 with an empty events list."""
    r = client.get("/api/tasks/nope/events", params={"since": 0})
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["task_id"] == "nope"
    assert body["events"] == []


def test_http_events_503_when_manager_uninitialized(isolated_env):
    """Without a live TaskManager the endpoint returns 503, not a hang."""
    reset_task_manager()
    c = TestClient(create_app())  # no ``with`` → lifespan never runs
    r = c.get("/api/tasks/whatever/events", params={"since": 0})
    assert r.status_code == 503


@pytest.mark.timeout(30)
@pytest.mark.parametrize("status, error, frame", [
    ("failed", "backend restarted", {"type": "error", "error": "backend restarted"}),
    ("cancelled", None, {"type": "error", "error": "cancelled"}),
    ("succeeded", None, {"type": "done"}),
])
def test_ws_task_ended_in_an_earlier_server_life_gets_its_terminal_frame(
        client, status, error, frame):
    """A terminal record with no bus history (loaded from disk) must not park the socket.

    It used to wait on ``subscribe`` forever: a UI following the job showed it
    running for good, and the socket held the server's graceful shutdown.
    """
    from memdiver.api.services.task_manager import TaskRecord, TaskStatus
    mgr = get_task_manager()
    task_id = f"ws-earlier-life-{status}"
    with mgr._lock:  # noqa: SLF001 — what load_from_disk installs
        mgr._records[task_id] = TaskRecord(task_id=task_id, kind="vol3_synth",
                                           status=TaskStatus(status), error=error)
    with client.websocket_connect(f"/ws/tasks/{task_id}?since=3") as ws:
        frames = _collect_until_close(ws)
    assert len(frames) == 1 and frames[0]["task_id"] == task_id
    assert {k: frames[0][k] for k in frame} == frame
    # What the client's isTaskProgressEvent requires, or it drops the frame.
    assert frames[0]["seq"] == 4 and isinstance(frames[0]["ts"], float)


@pytest.mark.timeout(30)
def test_ws_client_going_away_ends_a_parked_live_stream(client):
    """A closed socket ends the handler even while its task is still running.

    The handler used to park on ``subscribe`` until the task ended. uvicorn's
    shutdown closes every WebSocket and then waits for the handlers, so one
    open tab held the whole shutdown (and the job's cancel) for the graceful
    timeout. Driven directly: Starlette's TestClient cancels the handler on
    exit, which would hide the difference.
    """
    mgr = get_task_manager()
    task_id = "ws-parked-live-task"
    with mgr._lock:  # noqa: SLF001 — test-only direct publish
        bus = mgr.progress_bus
        bus.publish(Event(task_id=task_id, type="stage_start", stage="scan"))

    class _LeavingWebSocket(_FakeWebSocket):
        async def receive(self):
            await asyncio.sleep(0.2)  # parked on the live stream by now
            return {"type": "websocket.disconnect", "code": 1012}

    fake_ws = _LeavingWebSocket()
    asyncio.run(asyncio.wait_for(ws_task_progress(fake_ws, task_id, since=0), timeout=5))
    assert [f["type"] for f in fake_ws.sent] == ["stage_start"]
    assert fake_ws.closed is False  # gone already: nothing to close
    assert not bus._channels[task_id].subscribers  # noqa: SLF001 — unsubscribed


def test_ws_real_terminal_event_wins_over_the_record_frame(client, monkeypatch):
    """The task ended in THIS life between the replay and the record check: the bus's
    own ``done`` (with the ``extra`` an image job's consumer reads) is what is sent."""
    from memdiver.api.services.task_manager import TaskRecord, TaskStatus
    mgr = get_task_manager()
    task_id = "ws-ended-mid-handshake"
    with mgr._lock:  # noqa: SLF001
        mgr._records[task_id] = TaskRecord(task_id=task_id, kind="image",
                                           status=TaskStatus.SUCCEEDED)
        bus = mgr.progress_bus
        bus.publish(Event(task_id=task_id, type="stage_start", stage="image"))
        bus.publish(Event(task_id=task_id, type="done", extra={"rows": [1, 2]}))
    real_replay, calls = bus.replay, []

    def late_replay(tid, since_seq=0):
        calls.append(since_seq)
        return [] if len(calls) == 1 else real_replay(tid, since_seq=since_seq)
    monkeypatch.setattr(bus, "replay", late_replay)

    fake_ws = _FakeWebSocket()
    asyncio.run(ws_task_progress(fake_ws, task_id, since=0))
    assert [f["type"] for f in fake_ws.sent] == ["stage_start", "done"]
    assert fake_ws.sent[-1]["extra"] == {"rows": [1, 2]} and fake_ws.closed


def test_ws_cancelled_handler_cancels_its_stream_children(client):
    """A handler cancelled from outside (graceful-shutdown timeout) must not leave the
    live stream parked on the bus."""
    mgr = get_task_manager()
    task_id = "ws-cancelled-handler"
    with mgr._lock:  # noqa: SLF001
        bus = mgr.progress_bus
        bus.publish(Event(task_id=task_id, type="stage_start", stage="scan"))

    async def scenario():
        handler = asyncio.ensure_future(ws_task_progress(_FakeWebSocket(), task_id, since=0))
        await asyncio.sleep(0.2)
        assert bus._channels[task_id].subscribers  # noqa: SLF001 — parked live
        handler.cancel()
        await asyncio.gather(handler, return_exceptions=True)
        await asyncio.sleep(0)
        return list(bus._channels[task_id].subscribers)  # noqa: SLF001
    assert asyncio.run(scenario()) == []


def test_ws_event_published_between_snapshot_and_stream_is_sent_once(client, monkeypatch):
    """Events published after the replay snapshot was taken but before the live
    stream starts are delivered -- exactly once, with no replayed duplicate."""
    mgr = get_task_manager()
    task_id = "ws-gap-task"
    with mgr._lock:  # noqa: SLF001
        bus = mgr.progress_bus
        bus.publish(Event(task_id=task_id, type="stage_start", stage="scan"))
    real_replay = bus.replay

    def replay_then_publish(tid, since_seq=0):
        snapshot = real_replay(tid, since_seq=since_seq)
        # The job races ahead right after the snapshot: a progress tick and
        # its terminal ``done`` land in neither this snapshot nor (before the
        # fix) any live queue.
        if since_seq == 0 and snapshot and not any(
                e.type == "done" for e in real_replay(tid)):
            bus.publish(Event(task_id=tid, type="progress", pct=0.5))
            bus.publish(Event(task_id=tid, type="done", msg="fast"))
        return snapshot
    monkeypatch.setattr(bus, "replay", replay_then_publish)

    fake_ws = _FakeWebSocket()
    asyncio.run(asyncio.wait_for(ws_task_progress(fake_ws, task_id, since=0), timeout=5))
    assert [f["seq"] for f in fake_ws.sent] == [1, 2, 3]
    assert [f["type"] for f in fake_ws.sent] == ["stage_start", "progress", "done"]
    assert fake_ws.closed is True
    assert not bus._channels[task_id].subscribers  # noqa: SLF001


def test_ws_terminal_event_during_a_long_replay_arrives(client):
    """A ``done`` published while replayed frames are still being sent arrives."""
    mgr = get_task_manager()
    task_id = "ws-long-replay-task"
    with mgr._lock:  # noqa: SLF001
        bus = mgr.progress_bus
        for i in range(50):
            bus.publish(Event(task_id=task_id, type="progress", pct=i / 50))

    class _SlowWebSocket(_FakeWebSocket):
        async def send_json(self, data):
            await super().send_json(data)
            if data["seq"] == 10:  # mid-replay: the job finishes now
                bus.publish(Event(task_id=task_id, type="done", msg="finished"))
            await asyncio.sleep(0)

    fake_ws = _SlowWebSocket()
    asyncio.run(asyncio.wait_for(ws_task_progress(fake_ws, task_id, since=0), timeout=5))
    seqs = [f["seq"] for f in fake_ws.sent]
    assert seqs == list(range(1, 52))  # 50 replayed + the live done, no dupes
    assert fake_ws.sent[-1]["type"] == "done" and fake_ws.closed is True
