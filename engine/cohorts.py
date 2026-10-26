"""Experiment cohorts: group dumps by the ``cohort`` declared in ``meta.json``.

Runs of different experimental conditions (input length, secret reuse,
lifecycle phase, held-out fresh executions) must never be merged into one
variance accumulator. This module is the single place that knows how to tell
which cohort a dump belongs to and to refuse an accidental mix.
"""

from typing import Dict, List, Optional, Sequence

from memdiver.core.discovery import RunDiscovery
from memdiver.core.service_errors import CapabilityError, ErrorCategory


def cohort_of(dump_path: str) -> Optional[str]:
    """Cohort of the run owning ``dump_path``, or ``None`` without a meta/cohort."""
    meta = RunDiscovery.meta_for_dump(dump_path)
    return meta.cohort if meta is not None else None


def group_by_cohort(dump_paths: Sequence[str]) -> Dict[Optional[str], List[str]]:
    """Group dumps by cohort, preserving input order within and across groups."""
    groups: Dict[Optional[str], List[str]] = {}
    for path in dump_paths:
        groups.setdefault(cohort_of(path), []).append(path)
    return groups


def require_single_cohort(
    dump_paths: Sequence[str], *, mixed_ok: bool = False
) -> Optional[str]:
    """Return the single cohort of ``dump_paths`` or refuse a mix.

    Dumps without a cohort never cause a refusal. More than one distinct named
    cohort raises ``cohort.mixed`` unless ``mixed_ok`` is set.
    """
    named = {k: v for k, v in group_by_cohort(dump_paths).items() if k is not None}
    if len(named) > 1 and not mixed_ok:
        raise CapabilityError(
            _mixed_message(named),
            category=ErrorCategory.INVALID_INPUT,
            code="cohort.mixed",
            details={"cohorts": {k: len(v) for k, v in named.items()}},
        )
    return next(iter(named)) if len(named) == 1 else None


def _mixed_message(named: Dict[str, List[str]]) -> str:
    listing = ", ".join(f"{k!r}: {len(v)} dump(s)" for k, v in named.items())
    return (
        f"Dumps span multiple experiment cohorts ({listing}); different "
        "conditions must not be merged into one variance accumulator. "
        "Select one cohort, or pass mixed_ok / --mixed-ok to override."
    )
