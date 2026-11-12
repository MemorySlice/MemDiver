"""Task progress WebSocket + HTTP events backfill.

Two entry points share the same :class:`ProgressBus`:

* ``WebSocket /ws/tasks/{task_id}?since=<seq>`` — replay retained events
  newer than ``since``, then stream live updates until ``done``/``error``.
* ``GET /api/tasks/{task_id}/events?since=<seq>`` — HTTP fallback used on
  reconnect when the ring buffer has already rolled past the client's
  last seen seq. Returns the full retained slice in one shot.

Both contract with the :class:`TaskManager` singleton installed in the
FastAPI lifespan; if it's not initialized yet (e.g. during tests that
skip startup) the endpoints return an explicit 503 so clients don't hang.
"""

from __future__ import annotations

import asyncio
import logging
import time

from fastapi import APIRouter, WebSocket, WebSocketDisconnect

from memdiver.api.config import get_settings
from memdiver.api.dependencies import task_manager_or_503 as _manager_or_503
from memdiver.api.security import check_ws_token
from memdiver.api.services.progress_bus import Event
from memdiver.api.services.task_manager import (
    TERMINAL_STATUSES,
    TaskRecord,
    TaskStatus,
    get_task_manager,
)

logger = logging.getLogger("memdiver.api.ws.progress")

router = APIRouter(tags=["progress"])


def _record_terminal_frame(record: TaskRecord, since: int) -> dict:
    """The terminal frame of a task that ended with no bus history to replay.

    A task that ended in an EARLIER server life is known from its record only:
    without this frame its socket parked on ``subscribe`` forever -- a UI
    following the job showed it running for good, and the parked socket held
    uvicorn's graceful shutdown for ``web_graceful_timeout_s``. It is a full
    :class:`Event` (``seq`` after the client's ``since``, ``ts``): the client
    drops a frame without them as malformed.
    """
    if record.status is TaskStatus.SUCCEEDED:
        event = Event(task_id=record.task_id, type="done", msg="task succeeded")
    else:
        error = "cancelled" if record.status is TaskStatus.CANCELLED else (
            record.error or record.status.value)
        event = Event(task_id=record.task_id, type="error", error=error,
                      extra=record.error_info or None)
    event.seq, event.ts = since + 1, time.time()
    return event.to_dict()


def _error_frame(task_id: str, error: str, since: int) -> dict:
    """A full :class:`Event` error frame (``seq`` after *since*, ``ts``) for a refusal.

    The client drops a frame without ``seq``/``ts`` as malformed, so the
    refusals sent before any event exists carry them like every other frame.
    """
    event = Event(task_id=task_id, type="error", error=error)
    event.seq, event.ts = since + 1, time.time()
    return event.to_dict()


async def _stream_live(websocket: WebSocket, subscription, since: int) -> None:
    """Forward live events until a terminal one (or until ``subscribe`` ends).

    The subscription was attached before the replay, so it also holds the
    events the replay already sent: skip every ``seq <= since``.
    """
    async for event in subscription:
        if event.seq <= since:
            continue
        await websocket.send_json(event.to_dict())
        if event.type in ("done", "error"):
            return


async def _until_disconnect(websocket: WebSocket) -> None:
    """Return once the client is gone -- which is also how uvicorn's shutdown shows.

    uvicorn closes every open WebSocket (code 1012) when it starts shutting
    down and then WAITS for the handlers (fact 4 of ``api.services.task_manager``).
    A handler parked on ``bus.subscribe`` for a still-running task never saw
    that close, so one open browser tab held the whole graceful shutdown -- and
    the running job, whose cancel only comes from the lifespan teardown after
    it -- for ``web_graceful_timeout_s``. The client sends nothing, so any
    other message is ignored.
    """
    while (await websocket.receive())["type"] != "websocket.disconnect":
        pass


async def _stream_until_disconnect(websocket: WebSocket, subscription, since: int) -> bool:
    """Stream live events, racing a disconnect; True when the stream ended first."""
    stream = asyncio.ensure_future(_stream_live(websocket, subscription, since))
    gone = asyncio.ensure_future(_until_disconnect(websocket))
    try:
        done, _ = await asyncio.wait({stream, gone}, return_when=asyncio.FIRST_COMPLETED)
    finally:
        # Also when THIS handler is cancelled (shutdown timeout): never leave the
        # children running, or the subscriber stays parked on the bus.
        for task in (stream, gone):
            task.cancel()
        await asyncio.gather(stream, gone, return_exceptions=True)
    if stream in done:
        stream.result()  # re-raise e.g. WebSocketDisconnect from a send
        return True
    return False


async def _send_replay(websocket: WebSocket, bus, task_id: str, since: int) -> tuple:
    """Send the retained events after *since*; ``(last seq sent, ended on a terminal event)``."""
    for backlog in bus.replay(task_id, since_seq=since):
        await websocket.send_json(backlog.to_dict())
        since = max(since, backlog.seq)
        if backlog.type in ("done", "error"):
            return since, True
    return since, False


@router.websocket("/ws/tasks/{task_id}")
async def ws_task_progress(
    websocket: WebSocket, task_id: str, since: int = 0, token: str | None = None
):
    """Stream task progress events over a WebSocket.

    Protocol:
    1. Server accepts and immediately replays every event in the ring
       buffer whose ``seq > since``.
    2. Then streams live events until a terminal ``done`` / ``error``.
    3. Closes the socket after the terminal event (client should
       reconnect with the latest ``seq`` if they need to resubscribe).

    Auth: browsers cannot set WebSocket handshake headers, so when
    ``MEMDIVER_API_TOKEN`` is configured this endpoint takes the token via a
    ``?token=`` query param instead of the ``Authorization``/``X-API-Key``
    headers the HTTP routes use. A missing or mismatched token closes the
    socket with code 1008 (policy violation) right after accepting.
    """
    await websocket.accept()
    settings = get_settings()
    if settings.api_token and not check_ws_token(settings.api_token, token):
        await websocket.close(code=1008)
        return
    try:
        manager = get_task_manager()
    except RuntimeError as exc:
        await websocket.send_json(
            _error_frame(task_id, f"task manager not initialized: {exc}", since))
        await websocket.close()
        return

    bus = manager.progress_bus
    if manager.get(task_id) is None and not bus.replay(task_id, since_seq=0):
        await websocket.send_json(_error_frame(task_id, "unknown task", since))
        await websocket.close()
        return

    # Attach BEFORE the replay snapshot: an event published while the replay
    # is being sent (or before a later-attached subscriber would register) is
    # then in the queue; ``_stream_live`` drops the ones the replay covered.
    subscription = bus.subscribe(task_id)
    try:
        since, ended = await _send_replay(websocket, bus, task_id, since)
        record = manager.get(task_id)
        if not ended and record is not None and record.status in TERMINAL_STATUSES:
            # It may have ended (this life) after the replay above: its real
            # terminal event (``done`` with ``extra``) then wins over a frame
            # synthesized from the record.
            since, ended = await _send_replay(websocket, bus, task_id, since)
            if not ended:
                await websocket.send_json(_record_terminal_frame(record, since))
        if ended or (record is not None and record.status in TERMINAL_STATUSES):
            await websocket.close()
            return
        if not await _stream_until_disconnect(websocket, subscription, since):
            return  # the client is gone (or the server is shutting down)
        # Closed after a terminal event -- and also when ``subscribe`` ended
        # without one (e.g. bus/subscriber torn down), so the socket isn't
        # leaked open with no one left to send a terminal frame.
        await websocket.close()
    except WebSocketDisconnect:
        return
    except Exception:  # pragma: no cover - defensive
        logger.exception("websocket streaming error for task %s", task_id)
        try:
            await websocket.close()
        except Exception:
            pass
    finally:
        await subscription.aclose()


@router.get("/api/tasks/{task_id}/events")
def http_task_events(task_id: str, since: int = 0):
    """HTTP backfill for clients whose ``since`` is older than the ring.

    Returns a list of ``Event`` dicts ordered by seq ascending. Empty
    list when the task is unknown or there are no newer events.
    """
    manager = _manager_or_503()
    bus = manager.progress_bus
    events = bus.replay(task_id, since_seq=since)
    return {"task_id": task_id, "events": [e.to_dict() for e in events]}
