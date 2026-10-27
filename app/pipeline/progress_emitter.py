"""Shared ``progress``-event adapter for the capability job runners."""

from __future__ import annotations


def progress_emitter(ctx, stage: str, default_msg: str, scale: float = 1.0):
    """Adapt a producer's ``(value, description)`` callback to ``progress`` events.

    ``pct`` is ``value / scale`` clamped to ``[0, 0.99]`` (vol3 reports percent: scale 100).
    """
    def emit(value: float, description: str) -> None:
        pct = max(0.0, min(float(value) / scale, 0.99))
        ctx.emit("progress", stage=stage, pct=pct, msg=description or default_msg)
    return emit
