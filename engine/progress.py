"""Shared progress-callback and cancellation primitives for long-running engine work.

These are the types the pipeline orchestrator uses to wire engine functions
into the web-facing TaskManager + ProgressBus. Keeping them in their own
module means engine modules (candidate_pipeline, brute_force, nsweep,
vol3_emit) can import the signature without pulling in any api/ code.

The progress callback is deliberately fire-and-forget: a user oracle that
raises inside a callback should not break the caller, so implementations
should wrap raises with a best-effort try/except. The default ``noop_progress``
is used when callers don't care (CLI, existing tests) so the additive kwarg
never breaks backwards compatibility.
"""

from __future__ import annotations

import threading
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, Optional


@dataclass
class ProgressEvent:
    """One progress update from an engine function.

    Attributes:
        stage: Logical stage name (``"consensus"``, ``"search_reduce"``,
            ``"brute_force"``, ``"nsweep"``, ``"emit_plugin"``, or a
            sub-stage like ``"search_reduce:variance"``).
        pct: Fractional progress in ``[0.0, 1.0]``; ``-1.0`` is used for
            indeterminate events (stage start / one-off log).
        msg: Short human-readable status message.
        extra: Optional stage-specific payload. Stage counts, current N,
            candidate offset, etc. Must be JSON-serializable so a drain
            task can publish the event directly to a WebSocket client.
    """

    stage: str
    pct: float = -1.0
    msg: str = ""
    extra: Optional[Dict[str, Any]] = field(default_factory=dict)


ProgressFn = Callable[[ProgressEvent], None]


def noop_progress(_: ProgressEvent) -> None:
    """Default progress sink: drops every event."""


class CancelEvent:
    """A tiny wrapper around :class:`threading.Event` used as a cooperative
    cancellation signal for long engine loops.

    We don't use :class:`multiprocessing.Event` here because the engine
    functions run inside a single worker process; the TaskManager sets the
    cancel flag via a shared Manager-backed Event when crossing the
    process boundary. This wrapper lets engine code stay stdlib-only and
    makes tests trivial.
    """

    __slots__ = ("_event",)

    def __init__(self) -> None:
        self._event = threading.Event()

    def set(self) -> None:
        self._event.set()

    def is_set(self) -> bool:
        return self._event.is_set()

    def clear(self) -> None:
        self._event.clear()


class Cancelled(Exception):
    """Raised when an engine function observes cooperative cancellation."""


def check_cancel(cancel_event: Optional[Any]) -> None:
    """Raise :class:`Cancelled` if ``cancel_event`` is set.

    Accepts anything that has an ``is_set() -> bool`` method so callers
    can pass :class:`threading.Event`, :class:`multiprocessing.Event`, or
    :class:`CancelEvent` interchangeably.
    """

    if cancel_event is not None and cancel_event.is_set():
        raise Cancelled()


def safe_emit(progress: Optional[ProgressFn], event: ProgressEvent) -> None:
    """Invoke ``progress`` with ``event``, swallowing any exception.

    Engine hot-loops should never blow up because a callback raised.
    """

    if progress is None:
        return
    try:
        progress(event)
    except Exception:  # pragma: no cover - defensive
        pass
