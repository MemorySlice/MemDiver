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

import logging

from fastapi import APIRouter, WebSocket, WebSocketDisconnect

from api.dependencies import task_manager_or_503 as _manager_or_503
from api.services.task_manager import get_task_manager

logger = logging.getLogger("memdiver.api.ws.progress")

router = APIRouter(tags=["progress"])


@router.websocket("/ws/tasks/{task_id}")
async def ws_task_progress(websocket: WebSocket, task_id: str, since: int = 0):
    """Stream task progress events over a WebSocket.

    Protocol:
    1. Server accepts and immediately replays every event in the ring
       buffer whose ``seq > since``.
    2. Then streams live events until a terminal ``done`` / ``error``.
    3. Closes the socket after the terminal event (client should
       reconnect with the latest ``seq`` if they need to resubscribe).
    """
    await websocket.accept()
    try:
        manager = get_task_manager()
    except RuntimeError as exc:
        await websocket.send_json({
            "type": "error",
            "task_id": task_id,
            "error": f"task manager not initialized: {exc}",
        })
        await websocket.close()
        return

    bus = manager.progress_bus
    if manager.get(task_id) is None and not bus.replay(task_id, since_seq=0):
        await websocket.send_json({
            "type": "error",
            "task_id": task_id,
            "error": "unknown task",
        })
        await websocket.close()
        return

    try:
        for backlog in bus.replay(task_id, since_seq=since):
            await websocket.send_json(backlog.to_dict())
            if backlog.type in ("done", "error"):
                await websocket.close()
                return
        async for event in bus.subscribe(task_id):
            await websocket.send_json(event.to_dict())
            if event.type in ("done", "error"):
                await websocket.close()
                return
    except WebSocketDisconnect:
        return
    except Exception:  # pragma: no cover - defensive
        logger.exception("websocket streaming error for task %s", task_id)
        try:
            await websocket.close()
        except Exception:
            pass


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
