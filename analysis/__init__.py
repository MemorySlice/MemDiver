"""The interpretation layer: analysis record, case directories, semantic context.

Capture-time facts (``.msl`` blocks, image bytes, page states) are never
mutated. Everything MemDiver, a plugin, an agent or a human *concludes* about a
capture is an append-only, versioned entry in the analysis record
(:mod:`.record`), filed under the capture's identity inside a case directory.
See ``docs/dev/semantic_workbench_plan.md`` (P1, D6, D9).
"""
