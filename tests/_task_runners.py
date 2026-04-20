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
