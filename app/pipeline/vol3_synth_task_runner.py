"""TaskManager worker entry for ``synth.vol3_plugin`` (``POST /api/vol3/synthesize`` as a job).

A synthesis with ``full_image`` runs stock ``vol`` over a multi-GB image for
minutes (up to the 3600 s budget of ``app.vol3_surface_limits``), which must not
hold a web-server thread and an open request. REST therefore submits it as a
job (kind ``vol3_synth``) for ``async: true`` or a ``full_image``; the MCP tool
and the CLI stay synchronous.

The worker reuses the producer :func:`memdiver.app.tools_pipeline.synthesize_vol3_plugin`
unchanged: its ``on_progress`` reports become ``progress`` events, its
``is_cancelled`` is the task's cancel event (checked between steps, per chunk
of an in-process scan, and every ``CANCEL_POLL_S`` of a ``vol`` run, whose
process group is then killed). The payload -- exactly what the inline endpoint answers -- is
written as the ``vol3_synth_result`` artifact (``vol3_synth/result.json``) and
sent as the terminal ``summary``. A refusal's ``code`` / ``category`` ride on
the ``error`` event's ``extra`` so the UI can show them.

A worker that ends without unwinding (TaskManager teardown SIGTERMs or SIGKILLs
one that did not stop in time, fact 2 of ``api.services.task_manager``) takes
its ``vol`` process group with it through the run's lifeline: see
``engine.vol3_subproc.run_cancellable``.

``params``: ``kwargs`` -- the producer's keyword arguments as the REST surface
resolved them (case directory resolved, request bounds checked) -- plus
``key_material_hex`` (the wire ``passphrase`` / ``key_hex`` / ``kem_key_hex`` of
an encrypted ``.msl``, decoded here so the params stay JSON-friendly), and
``task_root``. The TaskManager redacts every secret in its persisted record;
this function receives the real values.

The function stays top-level and imports lazily so the spawn worker can pickle
it and an import problem surfaces as a reported task failure.
"""

from __future__ import annotations

from typing import Any, Dict

from memdiver.app.pipeline.artifact_paths import task_result_artifact
from memdiver.app.pipeline.progress_emitter import progress_emitter

STAGE = "vol3_synth"


def _producer_kwargs(params: Dict[str, Any]) -> Dict[str, Any]:
    """The producer's kwargs: tuples restored, container key material decoded."""
    from memdiver.core.key_material import from_hex

    kwargs = dict(params.get("kwargs", {}))
    kwargs["verify_on"] = tuple(kwargs.get("verify_on", ()))
    wire = dict(params.get("key_material_hex") or {})
    kwargs["key_material"] = from_hex(
        wire.get("passphrase"), wire.get("key_hex"), wire.get("kem_key_hex")) or {}
    return kwargs


def run_synth_job(params: Dict[str, Any], ctx) -> Dict[str, Any]:
    """Worker entry. Returns ``{"artifacts": [...], "summary": <payload>}``."""
    from memdiver.app.tools_pipeline import synthesize_vol3_plugin
    from memdiver.core.service_errors import CapabilityError
    from memdiver.engine.progress import Cancelled

    kwargs = _producer_kwargs(params)
    ctx.emit("stage_start", stage=STAGE, pct=0.0, msg=f"synthesize {kwargs.get('name', '')}")
    try:
        payload = synthesize_vol3_plugin(
            is_cancelled=ctx.is_cancelled,
            on_progress=progress_emitter(ctx, STAGE, "synthesize"), **kwargs)
    except Cancelled:
        ctx.emit("error", error="cancelled")
        raise RuntimeError("vol3 synthesis cancelled") from None
    except CapabilityError as exc:
        ctx.emit("error", error=exc.message,
                 extra={"code": exc.code, "category": exc.category.name})
        raise ValueError(exc.message) from None
    artifact = task_result_artifact(payload, params, ctx, STAGE)
    ctx.emit("stage_end", stage=STAGE, pct=1.0, msg="synthesis done")
    return {"artifacts": [artifact], "summary": payload}
