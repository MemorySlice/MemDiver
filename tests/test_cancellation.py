"""Regression tests for the LIVE cooperative-cancellation twin.

The former ``engine/cancellation.py`` (``CancellationToken`` / ``AnalysisCancelled``
/ ``NULL_TOKEN``) was removed in P1.1's follow-up: it was dead on arrival in git
(imported by nothing across the whole history) and had already been superseded by
two live mechanisms that these tests pin:

* ``engine.progress.check_cancel`` + ``progress.Cancelled`` — the primitive an
  engine hot-loop polls to abort. This is the twin of ``CancellationToken.check()``
  / ``AnalysisCancelled``; passing ``None`` is the twin of ``NULL_TOKEN`` (no-op).
* ``api.services.task_manager.WorkerContext.is_cancelled()`` — the non-raising
  "peek" the pipeline/task-runners check at stage boundaries. This is the twin of
  ``CancellationToken.is_cancelled``, and it is what makes cancellation *actually
  honored* (the old ``engine.worker.run_analysis_job`` accepted a ``cancel_event``
  and ignored it).

The engine loops themselves (brute_force, nsweep) already have mid-run cancel
tests in ``test_progress_callbacks.py``; this module pins the primitives directly,
including a genuine mid-run flip driven by a real OS thread — the behaviour the
removed ``_FakeCtx(cancel=True)`` constant could not exercise.
"""

from __future__ import annotations

import threading
import time

import pytest

from memdiver.api.services.task_manager import WorkerContext
from memdiver.engine.progress import Cancelled, check_cancel


def test_check_cancel_contract_across_signal_types():
    """check_cancel raises only when a real signal is set; None/unset are no-ops."""
    ev = threading.Event()
    check_cancel(ev)  # unset -> no-op
    check_cancel(None)  # no signal registered (the old NULL_TOKEN role) -> no-op
    ev.set()
    with pytest.raises(Cancelled):
        check_cancel(ev)  # set -> raise (the old CancellationToken.check twin)


def test_check_cancel_detects_real_event_flipped_midrun():
    """A background thread flips a real threading.Event *during* a polling loop.

    Proves cancellation is observed mid-run (not merely pre-set): work happens
    before the flip, then the next poll raises. This is the real-Event behaviour
    the mocked ``_FakeCtx(cancel=True)`` constant could never test.
    """
    cancel = threading.Event()
    progress = {"iterations": 0}
    flip_at = 100

    def flipper() -> None:
        # Wait until the loop has done genuine work, then request cancellation.
        while progress["iterations"] < flip_at:
            time.sleep(0.001)
        cancel.set()

    worker = threading.Thread(target=flipper)
    worker.start()
    try:
        with pytest.raises(Cancelled):
            # The range is only a safety cap; the loop must exit via Cancelled.
            for i in range(1_000_000):
                check_cancel(cancel)
                progress["iterations"] = i + 1
    finally:
        worker.join(timeout=2.0)

    assert not worker.is_alive()
    assert cancel.is_set()
    # The loop ran real iterations before the mid-run flip landed.
    assert progress["iterations"] >= flip_at


def test_worker_context_is_cancelled_reflects_real_event():
    """WorkerContext.is_cancelled() tracks a real event both ways (peek, no raise).

    This is the stage-boundary check the task-runners poll — the twin of the old
    CancellationToken.is_cancelled, and the reason a cancel actually takes effect.
    """
    ev = threading.Event()
    ctx = WorkerContext(task_id="t", progress_queue=None, cancel_event=ev)
    assert ctx.is_cancelled() is False
    ev.set()
    assert ctx.is_cancelled() is True
    ev.clear()
    assert ctx.is_cancelled() is False


def test_worker_context_is_cancelled_swallows_bad_event():
    """A malformed cancel_event degrades to 'not cancelled', never propagates."""
    ctx = WorkerContext(task_id="t", progress_queue=None, cancel_event=object())
    assert ctx.is_cancelled() is False
