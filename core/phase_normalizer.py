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

#: Sort key for a dump filename carrying no parseable timestamp (the non-phased
#: dataset dumps: ``gcore.core``, ``gdb_raw.bin`` ...). All-negative so those
#: sort FIRST, which is where the previous plain-string ordering put their
#: empty timestamp too.
UNPARSED_TIMESTAMP: Tuple[int, int, int] = (-1, -1, -1)


def parse_phase_timestamp(timestamp: str) -> Tuple[int, int, int]:
    r"""Parse a dump filename's timestamp prefix into a SORTABLE tuple.

    ``"20251020_171845_606711"`` -> ``(20251020, 171845, 606711)``.

    This lives in ``core`` because it is the ONE definition of "which of these
    two dumps came first", and two consumers need it: :meth:`normalize_run`
    below (which hands out the positional canonical suffixes) and
    ``engine.sweep_plan`` (which emits units in chronological order and
    re-exports this function). A second copy of the rule in ``engine`` would be
    free to drift from the one that assigns the labels - and ``engine`` may
    import ``core`` but never the reverse, so ``core`` is where it belongs.

    Why not just compare the strings
    --------------------------------
    :data:`core.discovery.DUMP_PATTERN` captures the timestamp as
    ``(\d{8}_\d{6}_\d+)``: the trailing microsecond field is VARIABLE WIDTH,
    not zero-padded by the pattern. Every one of the 18,917 measured dumps
    happens to carry six digits, so lexicographic order happens to agree with
    chronological order today - but a single five-digit field breaks it
    silently: ``"...171845_90000"`` (0.090 s) sorts AFTER
    ``"...171845_606711"`` (0.607 s) as text, because ``"9" > "6"``.

    Getting that order wrong is not cosmetic. :meth:`normalize_run` hands out
    the generic canonical suffixes POSITIONALLY by timestamp, so a mis-ordered
    run mislabels which dump is ``handshake_end`` and which is
    ``second_event`` - and ``canonical_phase`` is what consumers filter and
    group by.

    A prefix that does not parse (an empty one, from a non-phased dataset dump)
    yields :data:`UNPARSED_TIMESTAMP` rather than raising - ordering a corpus
    walk must never be fatal.
    """
    parts = timestamp.split("_")
    if len(parts) != 3:
        return UNPARSED_TIMESTAMP
    try:
        return int(parts[0]), int(parts[1]), int(parts[2])
    except ValueError:
        return UNPARSED_TIMESTAMP


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

        Sorts dumps CHRONOLOGICALLY, groups into pre/post pairs by phase_name,
        then classifies: key_update, cleanup (last pair wins), or generic
        (first -> handshake_end, second -> second_event).

        The sort key is :func:`parse_phase_timestamp`, not the raw timestamp
        string. The two agree on every dump in the measured corpus (all six
        microsecond digits), but the generic canonical suffixes are handed out
        POSITIONALLY here, so a single five-digit microsecond field would
        otherwise sort ``..._90000_pre_abort`` (0.090 s) AFTER
        ``..._606711_pre_shutdown`` (0.607 s) and label the two backwards.
        """
        if not run.dumps:
            return {}

        sorted_dumps = sorted(run.dumps, key=lambda d: parse_phase_timestamp(d.timestamp))
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
