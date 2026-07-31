"""MemDiver pipeline orchestration layer.

The TaskManager spawn-worker entry points and the multi-stage pipeline runner.
Relocated here from ``engine/`` in the P1.1 layering fix so the dependency
direction is ``app.pipeline → app.tools_pipeline → engine`` (engine never
imports app). The former ``engine.pipeline_runner`` / ``engine.*_task_runner``
modules now live as ``app.pipeline.*`` submodules.

Worker entry functions (``run_pipeline``, ``run_analysis``, ``run_file``,
``run_batch``, ``run_experiment``) are dispatched by dotted-path string via
``importlib`` in a spawned subprocess, so callers reference the concrete
submodule (e.g. ``memdiver.app.pipeline.pipeline_runner.run_pipeline``), not
this package re-export. The names below are re-exported only for the
convenience of direct importers of the stage-registry API.
"""

from memdiver.app.pipeline.pipeline_runner import (
    STAGE_ENTRY_POINT_GROUP,
    Stage,
    get_pipeline_stages,
    register_stage,
    run_auto_floor_stage,
    run_pipeline,
)

__all__ = [
    "STAGE_ENTRY_POINT_GROUP",
    "Stage",
    "get_pipeline_stages",
    "register_stage",
    "run_auto_floor_stage",
    "run_pipeline",
]
