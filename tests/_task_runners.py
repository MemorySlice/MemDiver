"""Module-level runner functions used by test_task_manager.

They must be top-level (picklable) so ``mp.get_context("spawn")`` can
import them in a worker process.
"""

from __future__ import annotations

import time
from typing import Any, Dict


def echo_runner(params: Dict[str, Any], ctx) -> Dict[str, Any]:
    """Emit two progress events then return a result."""
    ctx.emit("stage_start", stage="echo", pct=0.0, msg="started")
    ctx.emit("progress", stage="echo", pct=0.5, msg="halfway")
    ctx.emit("stage_end", stage="echo", pct=1.0, msg="done")
    return {"summary": {"echoed": params}, "artifacts": []}


def failing_runner(params: Dict[str, Any], ctx) -> Dict[str, Any]:
    raise RuntimeError("boom: " + str(params.get("why", "")))


def cancellable_runner(params: Dict[str, Any], ctx) -> Dict[str, Any]:
    """Spin until cancelled, emitting a heartbeat."""
    iterations = int(params.get("iterations", 200))
    for i in range(iterations):
        if ctx.is_cancelled():
            ctx.emit("progress", stage="spin", pct=-1.0, msg="cancelled-ack")
            return {"cancelled": True}
        ctx.emit("progress", stage="spin", pct=i / iterations)
        time.sleep(0.01)
    return {"cancelled": False}


def stubborn_runner(params: Dict[str, Any], ctx) -> Dict[str, Any]:
    """Sleep a long time, deliberately NEVER consulting ``is_cancelled``.

    Models the worst case teardown has to survive: a worker that will not stop
    when asked. Used to prove the shutdown path is bounded (it force-reaps the
    process) and that the loop's default executor can still be shut down while
    such a task is mid-flight -- the exact condition that used to make Ctrl-C
    hang forever and leave ``kill -9`` as the only exit.
    """
    time.sleep(float(params.get("seconds", 30.0)))
    return {"slept": True}


def artifact_registering_runner(params: Dict[str, Any], ctx) -> Dict[str, Any]:
    """Register two artifacts as the runner's very LAST act before returning.

    This is the shape that used to lose the race: the events go on the progress
    mp.Queue microseconds before the pool's result channel resolves the future
    and the parent publishes ``done``, which closes the bus channel and ends
    every live subscriber. Used by ``test_artifact_events`` to prove the drain
    barrier orders the ``artifact`` events strictly before ``done``.
    """
    from pathlib import Path

    from memdiver.app.pipeline.artifact_events import EmittingArtifactList
    from memdiver.core.artifact_util import register_artifact

    artifact_dir = Path(params["artifact_dir"])
    artifact_dir.mkdir(parents=True, exist_ok=True)
    (artifact_dir / "first.txt").write_text("first")
    (artifact_dir / "second.py").write_text("# second\n")

    ctx.emit("stage_start", stage="emit", pct=0.0, msg="started")

    artifacts = EmittingArtifactList(ctx)
    register_artifact(
        artifacts, artifact_dir,
        name="first_artifact", relpath="first.txt", media_type="text/plain",
    )
    register_artifact(
        artifacts, artifact_dir,
        name="vol3_plugin", relpath="second.py", media_type="text/x-python",
    )

    ctx.emit("stage_end", stage="emit", pct=1.0, msg="wrote 2 artifacts")
    return {"summary": {"ok": True}, "artifacts": artifacts}
