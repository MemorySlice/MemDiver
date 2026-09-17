"""In-process pub/sub for task progress events.

The :class:`ProgressBus` is a tiny broker between the TaskManager (which
pushes progress events produced by engine workers) and WebSocket clients
(which fan out to one or more subscribers per task). Each task has an
independent ring buffer of the last ``ring_size`` events so a slow or
re-connecting client can replay recent history via ``?since=<seq>``. When
the ring overflows we drop the *oldest* event, which matches the client's
reconnect semantics: a client that sees ``since > first_seq`` knows it
must fall back to an HTTP backfill endpoint rather than trust the live
stream to be complete.

The bus is asyncio-only and lives on the FastAPI event loop. Cross-
process progress (from a ProcessPool worker) is funneled onto the loop
by the TaskManager via ``publish`` in a single drain task.
"""

from __future__ import annotations

import asyncio
import logging
import time
from collections import deque
from dataclasses import asdict, dataclass, field
from typing import Any, AsyncIterator, Deque, Dict, List, Optional

logger = logging.getLogger("memdiver.api.services.progress_bus")

DEFAULT_RING_SIZE = 512


@dataclass
class Event:
    """One progress event broadcast to subscribers of a task.

    Notes on fields:
    * ``seq`` is assigned by the bus at publish time; callers should
      leave it 0 and let the bus number events monotonically per task.
    * ``type`` mirrors the WebSocket event protocol from the plan:
      ``stage_start``, ``progress``, ``stage_end``, ``funnel``,
      ``nsweep_point``, ``oracle_tick``, ``oracle_hit``, ``artifact``,
      ``done``, ``error``.
    * ``ts`` is a monotonic wall-clock at publish time, used only for
      client-side UX (elapsed timers, etc.).
    """

    task_id: str
    type: str
    seq: int = 0
    ts: float = 0.0
    stage: Optional[str] = None
    pct: Optional[float] = None
    msg: Optional[str] = None
    extra: Optional[Dict[str, Any]] = None
    artifact: Optional[Dict[str, Any]] = None
    error: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        # Drop None fields so WebSocket payloads stay compact and
        # schema-friendly for the TypeScript discriminated-union decoder.
        return {k: v for k, v in asdict(self).items() if v is not None}


@dataclass
class _TaskChannel:
    """Per-task state inside the bus."""

    ring: Deque[Event] = field(default_factory=lambda: deque(maxlen=DEFAULT_RING_SIZE))
    # ``None`` is the close sentinel pushed by ``_close_channel``; see there
    # for why a parked subscriber needs one instead of just a ``closed`` flag.
    subscribers: List["asyncio.Queue[Optional[Event]]"] = field(default_factory=list)
    next_seq: int = 1
    first_seq: int = 1  # smallest seq still in ring
    closed: bool = False


class ProgressBus:
    """Per-task ring-buffered progress broker."""

    def __init__(self, ring_size: int = DEFAULT_RING_SIZE) -> None:
        self._ring_size = ring_size
        self._channels: Dict[str, _TaskChannel] = {}

    # ----- publisher side --------------------------------------------------

    def publish(self, event: Event) -> Event:
        """Assign ``seq``/``ts`` and fan out to live subscribers.

        Safe to call from synchronous code on the event loop thread. The
        subscriber queues are ``asyncio.Queue`` instances owned by this
        loop, so ``put_nowait`` works synchronously and does the right
        thing from inside a drain task.
        """

        channel = self._channels.get(event.task_id)
        if channel is None:
            channel = _TaskChannel(
                ring=deque(maxlen=self._ring_size),
            )
            self._channels[event.task_id] = channel

        event.seq = channel.next_seq
        event.ts = time.time()
        channel.next_seq += 1

        # Before appending, if the ring is about to overflow, update
        # first_seq so subscribers know the oldest retained event.
        if len(channel.ring) == self._ring_size:
            channel.first_seq = channel.ring[1].seq if len(channel.ring) > 1 else event.seq
        elif not channel.ring:
            channel.first_seq = event.seq
        channel.ring.append(event)

        self._fanout(event.task_id, channel, event, f"event seq={event.seq}")
        return event

    def _fanout(
        self,
        task_id: str,
        channel: _TaskChannel,
        item: Optional[Event],
        what: str,
    ) -> None:
        """Push *item* onto every live subscriber queue of *channel*.

        One place owns the fan-out policy for both the live events published
        by :meth:`publish` and the ``None`` close sentinel pushed by
        :meth:`_close_channel`, so the two can never drift apart:

        * the ``list(...)`` snapshot — a subscriber removes its own queue in
          the ``finally`` of :meth:`subscribe`, so the live list can be
          mutated while we walk it;
        * the ``QueueFull`` policy — a subscriber that cannot keep up simply
          loses *item* and reconciles via replay on reconnect, because
          blocking here would stall the publisher for every other subscriber.

        ``what`` is a short description of the dropped item, used only to keep
        the warning specific (``event seq=7`` vs ``close sentinel``).
        """

        for q in list(channel.subscribers):
            try:
                q.put_nowait(item)
            except asyncio.QueueFull:
                logger.warning(
                    "progress bus subscriber queue full on task %s; dropping %s",
                    task_id, what,
                )

    # ----- subscriber side -------------------------------------------------

    def replay(self, task_id: str, since_seq: int = 0) -> List[Event]:
        """Return every retained event with ``seq > since_seq``.

        ``since_seq == 0`` returns everything in the ring. If the caller's
        ``since_seq < first_seq`` they have missed events; HTTP backfill
        is the fallback.
        """

        channel = self._channels.get(task_id)
        if channel is None:
            return []
        return [e for e in channel.ring if e.seq > since_seq]

    def first_seq(self, task_id: str) -> int:
        """Smallest seq currently retained for ``task_id`` (1 if empty)."""

        channel = self._channels.get(task_id)
        if channel is None or not channel.ring:
            return 1
        return channel.ring[0].seq

    async def subscribe(self, task_id: str) -> AsyncIterator[Event]:
        """Async iterator yielding *live* events for a task.

        The caller is responsible for first replaying via :meth:`replay`
        to catch up any missed events, then draining this iterator until
        a terminal event (``done`` / ``error``) arrives.
        """

        channel = self._channels.get(task_id)
        if channel is None:
            channel = _TaskChannel(
                ring=deque(maxlen=self._ring_size),
            )
            self._channels[task_id] = channel

        q: "asyncio.Queue[Optional[Event]]" = asyncio.Queue(maxsize=1024)
        channel.subscribers.append(q)
        try:
            while True:
                # Fast path for a channel that was already closed before we
                # attached (or that we have now fully drained): nothing more
                # will ever arrive, so don't park on ``get`` at all.
                if channel.closed and q.empty():
                    return
                event = await q.get()
                # ``None`` is the close sentinel from ``_close_channel``. It
                # means the channel closed with nothing more coming, so the
                # pre-check above can no longer save us — we are already past
                # it, parked in ``get``. Ending here is what lets the
                # WebSocket handler fall out of its ``async for``.
                if event is None:
                    return
                yield event
                if event.type in ("done", "error"):
                    return
        finally:
            try:
                channel.subscribers.remove(q)
            except ValueError:
                pass

    def close_task(self, task_id: str) -> None:
        """Mark a task channel closed; subscribers drain then exit."""

        channel = self._channels.get(task_id)
        if channel is None:
            return
        self._close_channel(task_id, channel)

    def close_all(self) -> None:
        """Close *every* channel — for application shutdown.

        ``close_task`` only fires when a single task reaches a terminal
        event, so a subscriber attached to a task that is still running would
        never be released. At shutdown there is nothing left to wait for, so
        wake all of them at once and let every ``subscribe`` iterator finish.
        """

        for task_id, channel in list(self._channels.items()):
            self._close_channel(task_id, channel)

    def _close_channel(self, task_id: str, channel: _TaskChannel) -> None:
        """Mark one channel closed and wake everyone parked on its queue.

        Setting ``closed`` alone is not enough. A subscriber already
        suspended in ``await q.get()`` never re-evaluates the flag, so it
        parks forever; ``api/ws/progress.py`` is sitting inside that
        ``async for``, which means it also never reaches ``receive()`` and so
        never notices the client going away either. The frontend ships a
        *reconnecting* WebSocket client, so a parked subscriber is the normal
        case rather than an exotic one.

        The wake-up is a ``None`` sentinel pushed through :meth:`_fanout`, the
        same helper :meth:`publish` uses, so it inherits that method's
        event-loop-thread contract and adds no new threading assumption.

        Scope note: this releases subscribers on the per-task terminal path and
        on client disconnect. It does *not* rescue the shutdown case, because
        ``close_all`` runs from the FastAPI lifespan and uvicorn's
        ``Server.shutdown()`` drains open connections *before* it gets there —
        that window is bounded by ``timeout_graceful_shutdown`` instead (see
        ``Settings.web_graceful_timeout_s``). The real fix belongs in
        ``api/ws/progress.py``, which must await ``websocket.receive()``
        concurrently with this subscribe loop so it notices the close frame.
        """

        channel.closed = True
        self._fanout(task_id, channel, None, "close sentinel")

    def drop_task(self, task_id: str) -> None:
        """Remove a task's ring buffer entirely (call once nothing will read it)."""

        self._channels.pop(task_id, None)
