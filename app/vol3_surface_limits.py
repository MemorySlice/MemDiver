"""Request bounds the REST and MCP surfaces put on ``vol3.exec`` and ``synth.vol3_plugin``.

Both run a ``vol`` subprocess for a remote caller, who must not be able to hold
a server worker for hours. ``vol3.exec`` and MCP's synthesis run inside the
request; REST's synthesis with ``full_image`` (or ``async``) runs as a
cancellable background job (``app.pipeline.vol3_synth_task_runner``), still
bounded here so one job cannot occupy the one-job queue for hours. The CLI and
the library keep the producers' own (unbounded) parameters: an operator at a
shell owns the time.
"""

from __future__ import annotations

from typing import Optional, Sequence

from memdiver.core.service_errors import CapabilityError, ErrorCategory

#: Longest ``vol3_exec`` run a server request may ask for, in seconds.
MAX_EXEC_TIMEOUT_S = 900
#: Most dumps one synthesize request may name.
SYNTH_MAX_DUMPS = 16
#: Worst-case wall time of a synthesize request's full-image ``vol`` attempts.
SYNTH_VOL_BUDGET_S = 3600


def _refuse(message: str, code: str) -> CapabilityError:
    return CapabilityError(message, category=ErrorCategory.INVALID_INPUT, code=code)


def check_exec_timeout(timeout_s: float) -> None:
    """Refuse a ``timeout_s`` outside ``1..MAX_EXEC_TIMEOUT_S``."""
    if not 1 <= timeout_s <= MAX_EXEC_TIMEOUT_S:
        raise _refuse(f"timeout_s must be between 1 and {MAX_EXEC_TIMEOUT_S} seconds "
                      "on this surface (use the CLI for longer runs)", "vol3.exec.timeout_range")


def check_synth_request(dump_paths: Sequence[str], full_image: Optional[str],
                        full_image_sample: Optional[str]) -> None:
    """Refuse more than :data:`SYNTH_MAX_DUMPS` dumps, or a full-image run over budget.

    A full-image verification tries each dump's (key, sample), plus the image's
    own sample, each bounded by ``VOL3_SUBPROC_TIMEOUT_S``; the worst case
    must fit :data:`SYNTH_VOL_BUDGET_S`.
    """
    from memdiver.app.tools_pipeline import VOL3_SUBPROC_TIMEOUT_S

    if len(dump_paths) > SYNTH_MAX_DUMPS:
        raise _refuse(f"{len(dump_paths)} dumps; at most {SYNTH_MAX_DUMPS} per request on "
                      "this surface", "synth.vol3_plugin.too_many_dumps")
    if not full_image:
        return
    attempts = len(dump_paths) + (1 if full_image_sample else 0)
    worst = attempts * VOL3_SUBPROC_TIMEOUT_S
    if worst > SYNTH_VOL_BUDGET_S:
        raise _refuse(f"full-image verification could run {attempts} vol attempts x "
                      f"{VOL3_SUBPROC_TIMEOUT_S} s = {worst} s, over the {SYNTH_VOL_BUDGET_S} s "
                      "budget of this surface; pass fewer dumps or use the CLI",
                      "synth.vol3_plugin.vol_budget")
