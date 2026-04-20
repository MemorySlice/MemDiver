"""PhaseNormalizer - map raw dump phase names to canonical lifecycle stages.

TLS libraries use different naming conventions for lifecycle events (e.g.,
"abort", "shutdown", "cleanup"). This module normalizes those raw names into
a consistent set of canonical phases based on timestamp ordering rather than
name matching.

Canonical phases (in display order):
    pre/post_key_update      - TLS 1.3 key update events
    pre/post_handshake_end   - First lifecycle event after handshake
    pre/post_second_event    - Second lifecycle event (if present)
    pre/post_cleanup         - Final cleanup phase
"""

import logging
from dataclasses import dataclass
from typing import Dict, List, Tuple

from .models import DumpFile, RunDirectory

logger = logging.getLogger("memdiver.phase_normalizer")

CANONICAL_PHASE_ORDER: List[str] = [
    "pre_key_update", "post_key_update",
    "pre_handshake_end", "post_handshake_end",
    "pre_second_event", "post_second_event",
    "pre_cleanup", "post_cleanup",
]

_GENERIC_SUFFIXES: List[str] = ["handshake_end", "second_event"]


@dataclass
class PhaseMapping:
    """Maps a raw dump phase to its canonical lifecycle stage."""

    raw_phase: str
    canonical_phase: str
    timestamp: str
    dump_file: DumpFile


def _group_into_pairs(
    sorted_dumps: List[DumpFile],
) -> List[Tuple[str, List[DumpFile]]]:
    """Group sorted dumps by phase_name, preserving first-appearance order."""
    groups: Dict[str, List[DumpFile]] = {}
    for dump in sorted_dumps:
        groups.setdefault(dump.phase_name, []).append(dump)
    return list(groups.items())


def _generic_suffix(index: int) -> str:
    """Return the canonical suffix for the *index*-th generic pair."""
    if index < len(_GENERIC_SUFFIXES):
        return _GENERIC_SUFFIXES[index]
    return f"event_{index + 1}"


def _emit_mappings(
    dumps: List[DumpFile],
    suffix: str,
    result: Dict[str, PhaseMapping],
) -> None:
    """Write PhaseMapping entries for every dump in *dumps*."""
    for dump in dumps:
        result[dump.full_phase] = PhaseMapping(
            raw_phase=dump.full_phase,
            canonical_phase=f"{dump.phase_prefix}_{suffix}",
            timestamp=dump.timestamp,
            dump_file=dump,
        )


class PhaseNormalizer:
    """Normalize raw dump phase names to canonical lifecycle stages.

    Uses timestamp ordering (not name matching) to assign canonical roles
    to each phase pair.

    Usage::

        normalizer = PhaseNormalizer()
        mappings = normalizer.normalize_run(run_directory)
        for raw, mapping in mappings.items():
            print(f"{raw} -> {mapping.canonical_phase}")
    """

    KEY_UPDATE_NAMES = {"server_key_update", "client_key_update"}
    CLEANUP_NAMES = {"cleanup"}

    def normalize_run(self, run: RunDirectory) -> Dict[str, PhaseMapping]:
        """Normalize all dump phases in a run to canonical lifecycle stages.

        Sorts dumps by timestamp, groups into pre/post pairs by phase_name,
        then classifies: key_update, cleanup (last pair wins), or generic
        (first -> handshake_end, second -> second_event).
        """
        if not run.dumps:
            return {}

        sorted_dumps = sorted(run.dumps, key=lambda d: d.timestamp)
        pairs = _group_into_pairs(sorted_dumps)
        return self._classify_pairs(pairs)

    def available_canonical_phases(self, runs: List[RunDirectory]) -> List[str]:
        """Return canonical phases present across *runs*, in display order."""
        seen: set = set()
        for run in runs:
            for mapping in self.normalize_run(run).values():
                seen.add(mapping.canonical_phase)
        return [phase for phase in CANONICAL_PHASE_ORDER if phase in seen]

    @staticmethod
    def get_canonical_display(canonical: str) -> str:
        """Return a human-readable label (e.g. 'Pre Handshake End')."""
        return canonical.replace("_", " ").title()

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _classify_pairs(
        self,
        pairs: List[Tuple[str, List[DumpFile]]],
    ) -> Dict[str, PhaseMapping]:
        """Classify grouped phase pairs into canonical categories."""
        result: Dict[str, PhaseMapping] = {}

        generic_pairs: List[Tuple[str, List[DumpFile]]] = []
        last_cleanup_dumps = None

        for phase_name, dumps in pairs:
            if phase_name in self.KEY_UPDATE_NAMES:
                _emit_mappings(dumps, "key_update", result)
            elif phase_name in self.CLEANUP_NAMES:
                last_cleanup_dumps = dumps
            else:
                generic_pairs.append((phase_name, dumps))

        for idx, (_phase_name, dumps) in enumerate(generic_pairs):
            _emit_mappings(dumps, _generic_suffix(idx), result)

        if last_cleanup_dumps is not None:
            _emit_mappings(last_cleanup_dumps, "cleanup", result)

        return result
