"""Shared progress-streaming helpers for the pipeline tool functions.

Small, state-free adapters that translate an optional ``on_progress`` sink into
the event shapes the surfaces expect. Extracted from ``tools_pipeline`` (P3.1)
so the experiment orchestration module can reuse them without a back-edge
import into ``tools_pipeline``.
"""

from __future__ import annotations

from typing import Any, Callable, Optional

from memdiver.core.service_errors import CapabilityError, ErrorCategory


def _emit(on_progress: Optional[Callable[..., None]], event: str, **fields: Any) -> None:
    """Forward one progress event to the surface's sink, if any.

    ``on_progress`` matches the ``ctx.emit(event, **fields)`` shape the task
    manager already uses, so the API adapter can pass ``ctx.emit`` verbatim; a
    ``None`` sink (the CLI/MCP) is a silent no-op.
    """
    if on_progress is not None:
        on_progress(event, **fields)


def _progress_bridge(
    on_progress: Optional[Callable[..., None]], stage_prefix: str
) -> Optional[Callable[[Any], None]]:
    """Adapt an ``on_progress`` sink into an engine ``progress_callback``.

    Mirrors :func:`app.pipeline.pipeline_runner._bridge`: each
    :class:`engine.progress.ProgressEvent` the leaf emits is translated into an
    ``on_progress("progress", stage=..., pct=..., msg=..., extra=...)`` call,
    prefixing the stage with ``stage_prefix:`` only when it has no ``:`` of its
    own — the exact rule the web runner uses. A later step that routes the web
    pipeline through these producers therefore streams a byte-identical event
    sequence. Returns ``None`` when there is no sink so the leaf keeps its
    ``noop_progress`` default and CLI/MCP behaviour is unchanged.
    """
    if on_progress is None:
        return None

    def _fn(event: Any) -> None:
        stage = event.stage
        if ":" not in stage:
            stage = f"{stage_prefix}:{stage}"
        _emit(
            on_progress, "progress",
            stage=stage,
            pct=event.pct if event.pct >= 0 else None,
            msg=event.msg,
            extra=event.extra or None,
        )

    return _fn


class _CallableCancelEvent:
    """Adapt a surface's ``is_cancelled()`` predicate to the engine's protocol.

    The app layer hands producers a ``Callable[[], bool]``; the engine hot-loops
    call :func:`engine.progress.check_cancel`, which wants anything exposing
    ``is_set() -> bool`` (threading.Event, multiprocessing.Event, CancelEvent).
    This is the one-line shim between the two, so a long sweep can be
    interrupted mid-flight instead of only at stage boundaries.
    """

    __slots__ = ("_predicate",)

    def __init__(self, predicate: Callable[[], bool]) -> None:
        self._predicate = predicate

    def is_set(self) -> bool:
        return bool(self._predicate())


def _cancel_bridge(
    is_cancelled: Optional[Callable[[], bool]],
) -> Optional[_CallableCancelEvent]:
    """Wrap an ``is_cancelled`` predicate for the engine, or ``None`` if unset.

    ``None`` keeps the engine's ``cancel_event=None`` default, so a surface that
    does not support cancellation (CLI, MCP) behaves exactly as before.
    """
    if is_cancelled is None:
        return None
    return _CallableCancelEvent(is_cancelled)


def _raise_cancelled(on_progress: Optional[Callable[..., None]]) -> None:
    """Emit and raise the app layer's canonical cancellation signal.

    Mirrors :func:`_experiment_check_cancelled`'s tail so a cancel observed
    *inside* an engine hot-loop is indistinguishable, to every surface, from one
    observed at a stage boundary: ``app.pipeline.pipeline_runner._run_producer``
    translates the ``code="cancelled"`` CapabilityError into
    ``_CancelledByContext``, and the sink drops the duplicate ``error`` event.
    """
    _emit(on_progress, "error", error="cancelled")
    raise CapabilityError(
        "cancelled",
        category=ErrorCategory.PRECONDITION,
        code="cancelled",
    )


def _experiment_check_cancelled(
    is_cancelled: Optional[Callable[[], bool]],
    on_progress: Optional[Callable[..., None]],
) -> None:
    if is_cancelled is not None and is_cancelled():
        _emit(on_progress, "error", error="cancelled")
        raise CapabilityError(
            "experiment cancelled",
            category=ErrorCategory.PRECONDITION,
            code="cancelled",
        )
