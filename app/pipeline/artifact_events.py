"""Live ``artifact`` progress events for worker-runner artifact registrations.

Why this module exists
----------------------
The web UI's results screen (Plugin / Report tabs and the raw download list)
reads ``pipelineStore.artifacts``. That array had exactly one filler: a
one-shot ``hydrateFromRecord`` fetch of the task record, fired from a
``[taskId]``-keyed effect the instant the run starts — i.e. while the record
still says ``running`` with ``artifacts: []``. The record only grows its
artifacts at *task completion* (``TaskManager._on_success`` →
``_append_artifacts``), long after that single fetch, and nothing re-fetched
it. So the artifact list stayed empty until the user reloaded the page.

Meanwhile the WebSocket protocol has always declared an ``artifact`` event
type (``api.services.progress_bus.Event.artifact``,
``frontend/src/api/progress-events.ts``), the TaskManager has always forwarded
it (``_handle_worker_event``), and the frontend store has always had a
``case "artifact"`` reducer branch that appends to ``artifacts`` — but **no
producer anywhere emitted one**. The consumer chain was complete and the
producer was missing, so the reducer branch was dead code.

:class:`EmittingArtifactList` is that missing producer. It is the ``artifacts``
container the worker runners hand to
:func:`memdiver.core.artifact_util.register_artifact`; the shared registrar
notifies it (see :class:`~memdiver.core.artifact_util.ArtifactRegistrationSink`)
and it turns each registration into one ``ctx.emit("artifact", ...)``. The
artifact list therefore populates *live, during the run*, from the same single
place every artifact is already created.

Why the hook rides on the container
-----------------------------------
``register_artifact`` is called from ~19 sites across four runners, reached
through stage helpers with a dozen different signatures. Threading a sink
parameter down all of them — or writing ``ctx.emit("artifact", ...)`` next to
every call — would put the same three lines in nineteen places and guarantee
the twentieth call site forgets. Attaching the behaviour to the *list* means
the wiring happens once per runner, where the list is constructed, and every
existing and future ``register_artifact`` call is covered for free.
"""

from __future__ import annotations

import logging
from typing import Any, Dict, Iterable, List, Tuple

logger = logging.getLogger("memdiver.app.pipeline.artifact_events")


class EmittingArtifactList(List[Dict[str, Any]]):
    """An ``artifacts`` list that emits an ``artifact`` progress event per append.

    Constructed with a :class:`api.services.task_manager.WorkerContext` (only
    duck-typed on ``emit``, so tests and out-of-tree runners can pass any
    object with that method — this module must not import ``api``).

    Substitutable for the plain ``list`` every runner used before: it *is* a
    list, so ``register_artifact``'s ``artifacts.append(spec)``, the
    ``{"artifacts": artifacts}`` worker return value and ``json.dumps`` all
    behave identically.
    """

    def __init__(self, ctx: Any, initial: Iterable[Dict[str, Any]] = ()) -> None:
        super().__init__(initial)
        self._ctx = ctx

    def artifact_registered(self, spec: Dict[str, Any]) -> None:
        """Emit one ``artifact`` event carrying ``spec``.

        The payload goes on the reserved ``artifact`` field of the worker-event
        dict — NOT ``extra`` — because that is the field
        ``TaskManager._handle_worker_event`` copies onto ``Event.artifact`` and
        the field the frontend reducer reads (``event.artifact?.name`` etc.).
        The spec keys (``name`` / ``relpath`` / ``media_type`` / ``size`` /
        ``sha256``) are already exactly the shape both sides parse, so it is
        forwarded verbatim.

        ``dict(spec)`` copies defensively: the same dict object is also the
        element stored in this list and travels home in the worker's return
        value, and the emit crosses an ``mp.Queue`` (pickled) — a copy keeps
        the two paths from ever aliasing one mutable payload.

        No ``stage`` is attached. ``_handle_worker_event`` only routes
        ``stage_start`` / ``progress`` / ``stage_end`` into the per-stage
        record rows, so a ``stage`` here would be inert, and the registrar has
        no reliable notion of the calling stage anyway.
        """
        self._ctx.emit("artifact", artifact=dict(spec))

    def __reduce__(self) -> Tuple[Any, Tuple[Any, ...]]:
        """Pickle as a PLAIN list.

        Load-bearing, not an optimisation. Every worker runner returns its
        artifacts inside ``{"artifacts": artifacts, ...}``, and that return
        value is pickled back to the parent by the ``ProcessPoolExecutor``.
        The default reduction would try to pickle ``self._ctx`` with it — and
        the WorkerContext holds an ``mp.Queue``, which raises when pickled
        outside of process inheritance. That would turn every successful run
        into a task failure at the very last moment.

        The parent only ever wants the data, so hand it a list.
        """
        return (list, (list(self),))


__all__ = ["EmittingArtifactList"]
