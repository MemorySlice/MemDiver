"""Per-dump presence probe: the one worker the corpus survival sweep runs.

WHAT THIS MODULE IS
-------------------
:func:`scan_dump_unit` opens ONE dump, loops the secrets THAT DUMP'S OWN RUN
logged, and records — per ``secret_type`` — whether the verbatim keylog bytes
are present. That is the whole job. It runs no decryption, derives no keys,
scores no detector and writes no database.

Its return value, :class:`DumpScanResult`, has FIVE consumers and exactly one
shape:

1. the worker's return value across a process boundary;
2. one ``results.jsonl`` line in the sweep ledger's sidecar;
3. the ``result_bytes`` the ledger's watermark accounts for;
4. the source of every ``survival`` row (:meth:`engine.project_db.ProjectDB.add_survival_batch`);
5. the ``dumps_searched`` / :attr:`DumpScanResult.secret_types_available` inputs
   of the survival matrix (CONTRACT 5 - it is NOT ``secrets_available``).

A field discovered missing after a full 18,917-unit sweep means RE-RUNNING the
sweep, not patching it. The contracts below are therefore frozen here, each
with the reason it is shaped the way it is.

CONTRACT 1 — ``DumpObservation`` IS the survival row
----------------------------------------------------
:class:`DumpObservation` carries EXACTLY
``engine.project_db._all_columns("survival")`` minus ``{survival_id,
created_at}`` — the two the writer computes itself (a deterministic identity
digest and a timestamp). Nothing is invented and nothing is dropped;
:data:`OBSERVATION_COLUMNS` names them in schema order and
``tests/test_survival_scan.py`` asserts the two against the production constant
so they cannot drift. :meth:`DumpObservation.to_row` is the ONE renderer, and
its output is exactly what ``add_survival_batch`` accepts.

``to_row`` deliberately emits NO ``unit_key``. ``_survival_payload_row`` builds
the primary key from ``unit_key or dump_path or dump_id``, so omitting it pins
``survival_id`` to ``(sweep_id, dump_path, secret_type)`` — the very tuple of
the ``survival_cell_unique`` index. The primary key and the unique index then
agree by construction instead of being two different keys that can disagree,
which is the failure mode ``add_survival_batch`` documents at length. The unit
key still travels, on :attr:`DumpScanResult.unit_key`, for the ledger.

CONTRACT 2 — the record version
-------------------------------
:data:`OBSERVATION_RECORD_VERSION` is :data:`engine.sweep_plan.SWEEP_SCHEMA_VERSION`
*by alias, not by copy* — stated explicitly, because this is the phase's only
on-disk contract that would otherwise carry no version at all. Folding rather
than siblings is the point: ``SWEEP_SCHEMA_VERSION`` is already inside
:func:`engine.sweep_plan.config_digest`, so changing the observation shape
forces a new ``config_digest``, which forces a full re-sweep instead of letting
rows written under two shapes merge into one indistinguishable pile. THE RULE:
**any change to** :data:`OBSERVATION_COLUMNS`, **to the envelope's fields, or
to the meaning of any of them must bump** ``SWEEP_SCHEMA_VERSION``.

That rule has already been exercised once, deliberately: version ``1`` -> ``2``
added :attr:`DumpScanResult.elapsed_s` (CONTRACT 4) and the ``secret_types_*``
counters (CONTRACT 5) BEFORE the first sweep wrote anything. Each was free at
that moment and would have cost a full ~170 GB re-sweep an hour into the first
run. Settle envelope questions HERE, never mid-sweep.

CONTRACT 3 — ``hit_count`` is capped at 1
-----------------------------------------
This is a PRESENCE probe: one :func:`core.dump_source.find_first_in` per
``secret_type``, which is a single ``.find()`` with an early exit. So
``hit_count`` is 0 or 1 — never an occurrence count — and
:data:`MAX_HIT_COUNT` is enforced in :meth:`DumpObservation.__post_init__`.
The column keeps the schema's name (contract 1 admits no renaming), so the cap
is documented and tested instead. DO NOT "fix" it by switching to ``find_all``:
that turns each of 63,481 cells into a full scan to EOF over a 170 GB corpus.

CONTRACT 4 — ``elapsed_s`` lives on the ENVELOPE, not on the row
---------------------------------------------------------------
The sweep's progress UI needs a per-unit duration: ``engine/eta.py`` was cut
because the frontend already smooths its own estimate
(``frontend/src/stores/pipeline-store.ts``, ``nextThroughput``) and there is no
server-side ETA anywhere, so the driver must publish ``elapsed_s`` alongside
``tried``/``total`` in ``engine.progress.ProgressEvent.extra``. That number has
to come from the worker: only the worker knows how long ITS scan took.

It is :attr:`DumpScanResult.elapsed_s`, NOT a ``DumpObservation`` field,
because CONTRACT 1 admits no choice — ``to_row()`` must equal
``project_db._all_columns("survival")`` minus the two writer columns, and
``survival`` has no timing column. A row field would therefore require a
``survival`` schema change, which is not this module's to make. The envelope,
by contrast, is versioned (CONTRACT 2), so adding the field cost exactly one
``SWEEP_SCHEMA_VERSION`` bump taken while nothing had been written.

WHAT IT MEASURES: the scan itself — :func:`core.dump_source.open_dump` plus the
:func:`_probe` loop — and nothing else. Deliberately NOT the whole worker call:
the keylog parse in front of it is per-RUN work amortised over that run's ~7
dumps, and a driver comparing dumps by cost, or a progress ETA extrapolating
from the units done so far, must not see one run's keylog parse attributed to
whichever of its dumps happened to be scanned first. It is a
:func:`time.perf_counter` delta (monotonic; a wall clock can step backwards
mid-sweep and produce a negative duration), rounded to
:data:`ELAPSED_PRECISION` decimals so a ``results.jsonl`` line stays stable.
Paths that never opened the dump — no keylog, and the worker-level ``error``
catch — report ``0.0``: no scan happened, so there is no scan to time.

Note this is NOT the ``sweeps``/``sweep_units`` ledger's ``started_at`` /
``finished_at``: those are driver-side wall clocks that include queueing and
serialisation. Both are useful; they answer different questions.

CONTRACT 5 — the denominator counts SECRET TYPES, not secret entries
--------------------------------------------------------------------
Survival is a fraction, and its denominator must be at the SAME GRAIN as its
numerator. The numerator is rows: one per ``(dump, secret_type)`` cell, because
the unique index is ``(sweep_id, dump_path, secret_type)`` and
:func:`_searchable_groups` collapses two secrets of one type into one group. So
the denominator is a count of DISTINCT SECRET TYPES:

:attr:`DumpScanResult.secret_types_available`
    **THE SURVIVAL DENOMINATOR.** Distinct ``secret_type`` values this unit had
    a searchable needle for — exactly the number of cells the unit could
    contribute. Populated on every outcome that got as far as parsing a keylog,
    including ``unreadable`` and ``unsupported_format``, so the matrix can say
    how many cells a refused or unreadable unit *would* have carried.
:attr:`DumpScanResult.secret_types_searched`
    How many of those were actually probed: equal to
    ``secret_types_available`` on :data:`SCAN_OUTCOME_OK`, and ``0`` on every
    other outcome. "Could have looked" versus "did look".
:attr:`DumpScanResult.secrets_available`
    Raw keylog ENTRIES — ``len(secrets)``, mirroring
    :attr:`core.keylog.KeylogParseResult.secrets_available` and
    :attr:`engine.truth_labels.DumpTruth.secrets_available` value-for-value.
    Provenance, NOT a denominator, despite what the first of those two calls
    itself in its own docstring: at THIS grain "denominator" means cells, and
    an entry is not a cell.

The two diverge whenever a run's keylog declares one secret type twice, and
whenever an entry is dropped for an empty needle
(:attr:`DumpScanResult.secrets_skipped_empty`). On the measured corpus they
never diverge: a TLS1.2 keylog declares exactly ``{CLIENT_RANDOM}`` and a
TLS1.3 keylog exactly five types, with no repeats. That is precisely why this
had to be settled BEFORE the sweep — today's data cannot tell the two apart, so
a matrix wired to ``secrets_available`` would look correct until a corpus that
repeats a type arrived, and would then silently over-state the denominator
(under-stating every published survival fraction) with no symptom.

NOTE FOR THE SWEEP DRIVER (plan item 3f-bis) — two VALUE, not schema, gaps
--------------------------------------------------------------------------
Neither is fixable here; both are the driver's to close, and both are recorded
here because this is the file its author will be reading.

(a) ``run_id`` IS THE DRIVER'S TO MINT, AND MUST BE PASSED TWICE.
    :meth:`engine.project_db.ProjectDB.add_survival_batch` takes ``run_id``
    POSITIONALLY and ``_survival_payload_row`` writes that positional value
    into the column — it never reads ``row["run_id"]``. This module copies the
    ``run_id`` it was given onto every observation, so it reaches
    ``results.jsonl``. If the driver passes one value to ``scan_dump_unit`` and
    a different one (or none) to ``add_survival_batch``, the JSONL and the DB
    disagree about which ``analysis_runs`` row the observations belong to, with
    nothing raising. Pass THE SAME value both ways.

(b) ``dump_id`` IS ALWAYS ``""`` HERE. Nothing in the scan resolves a ``dumps``
    row, so every observation carries the empty default. That is harmless while
    the matrix joins on ``dump_path`` (which is required and validated), but a
    matrix that ever joins on ``dump_id`` gets one bucket for the whole corpus.
    Closing it is a VALUE change — the column already exists — so the driver can
    backfill it without a ``survival`` schema change; it would still be an
    observation-shape change, and therefore still a
    :data:`OBSERVATION_RECORD_VERSION` bump plus a re-sweep, once rows exist.

WHY THESE PARTICULAR CALLS
--------------------------
* :func:`core.dump_source.find_first_in`, never ``source.find_first``.
  ``find_first`` is deliberately NOT on the ``runtime_checkable``
  :class:`core.dump_source.DumpSource` Protocol (widening it would break
  ``isinstance`` for every duck-typed source), and ``find_first_in`` is the
  sanctioned entry point that falls back to ``find_all`` for sources predating
  it.
* Never ``read_all()``. It is NOT part of the ``DumpSource`` contract — gcore
  and the regioned-raw sources omit it on purpose — and it materialises up to
  85 MB per dump.
* Never :class:`core.dump_io.DumpReader` directly. ``mmap.find(sub)`` defaults
  its start to the mapping's CURRENT FILE POSITION, so a bare ``.find()`` after
  anything that advanced the mapping reports a present secret as absent
  (measured on a real corpus dump at offset 585148). That hazard is handled
  only inside :func:`core.dump_io.find_first_offset`.
* Never ``SearchCorrelator.search_all`` (``read_all``-based) and never
  :func:`engine.truth_labels.locate_keylog_truth` (that is ``find_all`` — a
  full scan per secret; presence wants one early-exiting find).
* ``view`` is not forwarded unless a caller deliberately passes one, so every
  source keeps its own default view (``"raw"`` for :class:`RawDumpSource`,
  ``"vas"`` for :class:`MslDumpSource`). Passing ``view="raw"`` blindly would
  silently switch an ``.msl`` unit from its VAS projection to container bytes.
* Secrets resolve PER RUN, from ``<run_dir>/keylog.csv``, by construction —
  there is no "first run" to inherit from, which is what dissolves the
  ``AnalysisPipeline.analyze_library`` run-0-secrets defect here rather than
  reproducing it. The keylog is read through
  :func:`engine.truth_labels.keylog_secrets_for_run`, which returns a TYPED
  parse status: ``core.keylog`` swallows every exception and returns ``[]``, so
  without that status an unreadable keylog is indistinguishable from a run that
  genuinely logged nothing — a silent zero in the denominator.

MAPPING A ``SweepUnit`` ONTO THIS FUNCTION
------------------------------------------
The driver owns this mapping; it is spelled out so it cannot be guessed wrong::

    scan_dump_unit(
        unit.dump_path, unit.run_dir,
        sweep_id=sweep_id,
        unit_key=unit.unit_key,
        run_id=run_id,                      # the analysis_runs row, driver-side
        library=unit.library,
        protocol_version=unit.protocol_version,
        library_version=unit.library_version,
        scenario=unit.scenario,
        run_number=unit.run_number,
        phase=unit.raw_phase,
        canonical_phase=unit.canonical_phase,
    )

Note ``phase=unit.raw_phase``: ``survival.phase`` is the phase as written in
the filename and ``survival.canonical_phase`` is the normalised label; both
columns exist precisely because the corpus's phases are ragged and interleaved.
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple, Union, get_args

from memdiver.core.corpus_axes import KEYLOG_FILENAME, UNKNOWN_LIBRARY_VERSION
from memdiver.core.dump_source import ViewMode, find_first_in, open_dump
from memdiver.core.keylog import (
    KEYLOG_STATUS_MISSING,
    KEYLOG_STATUS_UNREADABLE,
)
from memdiver.core.models import CryptoSecret
from memdiver.engine.project_db import (
    METHOD_KEYLOG_SUBSTRING,
    SURVIVAL_STATUS_ERROR,
    SURVIVAL_STATUS_SEARCHED,
    SURVIVAL_STATUS_UNREADABLE,
    SURVIVAL_STATUSES,
)
from memdiver.engine.sweep_plan import SWEEP_SCHEMA_VERSION
from memdiver.engine.truth_labels import keylog_secrets_for_run

logger = logging.getLogger("memdiver.engine.survival_scan")

PathLike = Union[str, Path]

#: Version of the OBSERVATION RECORD shape. See "CONTRACT 2" in the module
#: docstring: this is an ALIAS of :data:`engine.sweep_plan.SWEEP_SCHEMA_VERSION`,
#: not a copy, so a shape change is forced through ``config_digest`` and
#: therefore through a re-sweep. Bump ``SWEEP_SCHEMA_VERSION`` to bump this.
OBSERVATION_RECORD_VERSION = SWEEP_SCHEMA_VERSION

#: A presence probe can report at most one hit. See "CONTRACT 3".
MAX_HIT_COUNT = 1

#: Decimal places :attr:`DumpScanResult.elapsed_s` is rounded to. Microseconds:
#: fine enough for the fastest unit imaginable, coarse enough that a
#: ``results.jsonl`` line does not carry 17 digits of float noise. See
#: "CONTRACT 4".
ELAPSED_PRECISION = 6

#: Formats whose byte stream a survival ``✗`` may legitimately be claimed from.
#:
#: Every dump in the measured corpus is ELF ``ET_DYN`` — NOT ``ET_CORE`` — so
#: :func:`core.dump_source._detect_elf_core` does not fire and every unit lands
#: on :class:`core.dump_source.RawDumpSource` BY FALLBACK. That is an accident
#: of the corpus, not a guarantee. A future mixed corpus resolving to
#: ``GCoreDumpSource`` (a region view with holes) or ``MslDumpSource`` (a VAS
#: projection) would search a DIFFERENT BYTE STREAM and render ``✗`` for format
#: reasons, indistinguishable from a zeroized key. Anything outside this set is
#: refused as :data:`SCAN_OUTCOME_UNSUPPORTED_FORMAT` unless a caller opts in
#: explicitly via ``allowed_formats``.
SUPPORTED_FORMATS: Tuple[str, ...] = ("raw",)

#: Byte views a caller may name, taken from :data:`core.dump_source.ViewMode`
#: itself so a new view cannot appear there and be rejected here. A typo is
#: raised EAGERLY, before any I/O: a bad view would otherwise fail per-unit
#: inside the read path and quietly turn a whole sweep into 18,917
#: ``unreadable`` rows instead of one loud error.
VIEW_MODES: Tuple[str, ...] = tuple(get_args(ViewMode))

# -- scan outcomes ---------------------------------------------------------
#
# The unit-level verdict, strictly richer than any per-row ``status``. It says
# WHY a unit produced the rows it produced (including none), so "we did not
# look" is never readable as "we looked and it was gone".

#: The dump was opened and every available secret searched. Rows carry
#: :data:`engine.project_db.SURVIVAL_STATUS_SEARCHED`. A unit with a clean but
#: empty keylog is also ``ok`` — with zero rows and
#: ``secret_types_available == 0``.
SCAN_OUTCOME_OK = "ok"

#: The dump was reached but its bytes could not be read (truncated, empty, an
#: I/O error mid-scan). Emits one row per ``secret_type`` with
#: :data:`engine.project_db.SURVIVAL_STATUS_UNREADABLE` and ``present = NULL``:
#: the cell renders "no data WITH A REASON" instead of a false absence, and
#: does not count toward ``runs_attempted``.
SCAN_OUTCOME_UNREADABLE = "unreadable"

#: The dump resolved to a source format outside ``allowed_formats``. Emits NO
#: ROWS AT ALL — "not attempted" (``—``). A row would assert we had a probe
#: against a defined byte stream, and here we never established which stream a
#: search would even have covered. :attr:`DumpScanResult.format_name` and
#: :attr:`DumpScanResult.size_for_view` still travel, so the driver can say
#: exactly what it refused and why.
SCAN_OUTCOME_UNSUPPORTED_FORMAT = "unsupported_format"

#: The run's keylog is absent or unparseable, so there is no truth to search
#: for and NO DENOMINATOR. Emits no rows. This is the outcome that keeps
#: ``core.keylog``'s swallowed-exception ``[]`` from reading as a genuine zero.
SCAN_OUTCOME_NO_KEYLOG = "no_keylog"

#: The attempt itself raised. Emits NO ROWS — an errored attempt is not an
#: observation, and recording one would let a crash masquerade as evidence
#: (the same rule ``add_survival_batch`` applies to
#: :data:`engine.project_db.SURVIVAL_STATUS_ERROR`). Partial results from a
#: half-finished loop are discarded too: a unit is all-or-nothing so the ledger
#: can re-run it cleanly.
SCAN_OUTCOME_ERROR = "error"

#: The closed outcome vocabulary.
SCAN_OUTCOMES: Tuple[str, ...] = (
    SCAN_OUTCOME_OK,
    SCAN_OUTCOME_UNREADABLE,
    SCAN_OUTCOME_UNSUPPORTED_FORMAT,
    SCAN_OUTCOME_NO_KEYLOG,
    SCAN_OUTCOME_ERROR,
)

#: The frozen field list of :class:`DumpObservation`, in ``survival`` schema
#: order. MUST equal ``project_db._all_columns("survival")`` minus
#: ``{"survival_id", "created_at"}``; ``tests/test_survival_scan.py`` asserts
#: that against the production constant in both directions.
OBSERVATION_COLUMNS: Tuple[str, ...] = (
    "run_id",
    "dump_id",
    "library",
    "protocol_version",
    "library_version",
    "scenario",
    "run_number",
    "phase",
    "canonical_phase",
    "secret_type",
    "present",
    "first_offset",
    "hit_count",
    "method",
    "dump_path",
    "sweep_id",
    "status",
    "format_name",
    "size_for_view",
)


@dataclass(frozen=True)
class DumpObservation:
    """One ``(dump, secret_type)`` cell: exactly one ``survival`` row.

    Field order and defaults mirror the ``survival`` table (see "CONTRACT 1").
    Frozen, because an observation is an identity key in the ledger and in the
    result map and must not mutate underneath either.

    Validation raises :class:`ValueError`, not
    :class:`core.service_errors.CapabilityError`: every guard below catches a
    WRITER BUG, not user input, and this object is constructed inside a worker
    process whose exceptions must survive being pickled back to the parent.
    """

    run_id: str = ""
    dump_id: str = ""
    library: str = ""
    protocol_version: str = ""
    library_version: str = UNKNOWN_LIBRARY_VERSION
    scenario: str = ""
    run_number: int = 0
    phase: str = ""
    canonical_phase: str = ""
    secret_type: str = ""
    present: Optional[bool] = None
    first_offset: Optional[int] = None
    hit_count: int = 0
    method: str = METHOD_KEYLOG_SUBSTRING
    dump_path: str = ""
    sweep_id: str = ""
    status: str = SURVIVAL_STATUS_SEARCHED
    format_name: str = ""
    size_for_view: int = 0

    def __post_init__(self) -> None:
        """Enforce the ``status`` / ``present`` / ``hit_count`` invariants.

        * ``status`` comes from the closed
          :data:`engine.project_db.SURVIVAL_STATUSES`.
        * ``present`` is non-NULL if and ONLY IF ``status == 'searched'``. SQL
          NULL is excluded by both ``WHERE present`` and ``WHERE NOT present``,
          so a NULL on a searched row counts as attempted while contributing to
          neither found nor absent; and a non-NULL on an unreadable row is an
          absence claim over bytes that were never read.
        * ``first_offset`` and ``hit_count`` agree with ``present``, so no
          consumer has to decide which of the three to believe.
        * ``hit_count <= MAX_HIT_COUNT``; a larger value means someone replaced
          the presence probe with a full scan (see "CONTRACT 3").
        """
        if self.status not in SURVIVAL_STATUSES:
            raise ValueError(
                "unknown survival status " + repr(self.status)
                + "; expected one of "
                + ", ".join(repr(s) for s in SURVIVAL_STATUSES))
        if self.status == SURVIVAL_STATUS_SEARCHED:
            if self.present is None:
                raise ValueError(
                    "status 'searched' requires a non-NULL present for "
                    + repr(self.secret_type)
                    + "; use status 'unreadable' when the dump could not be"
                    " read")
        elif self.present is not None:
            raise ValueError(
                "status " + repr(self.status) + " must leave present NULL for "
                + repr(self.secret_type) + "; only a searched dump may claim"
                " presence or absence")
        if not 0 <= self.hit_count <= MAX_HIT_COUNT:
            raise ValueError(
                "hit_count " + repr(self.hit_count) + " is outside 0.."
                + str(MAX_HIT_COUNT) + "; this is a presence probe built on"
                " find_first, not an occurrence count")
        if bool(self.present) != (self.first_offset is not None):
            raise ValueError(
                "present " + repr(self.present) + " contradicts first_offset "
                + repr(self.first_offset) + " for " + repr(self.secret_type))
        if bool(self.present) != bool(self.hit_count):
            raise ValueError(
                "present " + repr(self.present) + " contradicts hit_count "
                + repr(self.hit_count) + " for " + repr(self.secret_type))

    @property
    def writes_row(self) -> bool:
        """Whether ``add_survival_batch`` will actually persist this row.

        ``error`` rows are accepted by that writer and dropped: an errored
        attempt is not an observation. This module never EMITS one (an errored
        unit returns zero observations), but the shape admits it because the
        column does.
        """
        return self.status != SURVIVAL_STATUS_ERROR

    def to_row(self) -> Dict[str, Any]:
        """Render this cell as one ``add_survival_batch`` row dict.

        Keys are exactly :data:`OBSERVATION_COLUMNS`, in schema order. No
        ``unit_key`` — see "CONTRACT 1" for why that is load-bearing rather
        than an omission.
        """
        return {name: getattr(self, name) for name in OBSERVATION_COLUMNS}


@dataclass(frozen=True)
class DumpScanResult:
    """One unit's whole verdict: the ``results.jsonl`` line and the row source.

    Carries :attr:`record_version` (CONTRACT 2) and the unit-level facts that
    are NOT per-cell: which format was refused or searched, what the keylog
    parse said, how long the scan took, and how many secret TYPES were
    available versus actually searched. Those counters are what let a reader
    tell "no rows because nothing was logged" from "no rows because we refused
    the format" from "no rows because the worker raised" — three states that
    all look like silence otherwise.

    Fields:
        record_version: CONTRACT 2. Aliased from ``SWEEP_SCHEMA_VERSION``.
        unit_key: The ledger's idempotency key; deliberately not on the rows.
        dump_path: The probed dump, as submitted.
        outcome: One of :data:`SCAN_OUTCOMES`. Read this BEFORE reading
            anything into an empty :attr:`observations`.
        detail: Human-readable reason for a non-``ok`` outcome.
        format_name: ``DumpSource.format_name`` of the source opened, or ``""``
            when no open was reached.
        size_for_view: Bytes the searched view exposed.
        keylog_status: The TYPED parse status from
            :func:`engine.truth_labels.keylog_secrets_for_run`.
        secrets_available: Raw keylog ENTRIES. Provenance, NOT the denominator
            — see CONTRACT 5.
        secret_types_available: **THE SURVIVAL DENOMINATOR** (CONTRACT 5):
            distinct ``secret_type`` values with a searchable needle, i.e. the
            number of cells this unit could contribute. Set on every outcome
            that reached a parsed keylog, ``unreadable`` and
            ``unsupported_format`` included.
        secret_types_searched: How many of those were actually probed. Equals
            :attr:`secret_types_available` on :data:`SCAN_OUTCOME_OK` and is
            ``0`` on every other outcome — "could have looked" vs "did look".
        secrets_skipped_empty: Entries dropped for an empty needle; no absence
            is claimed for them, and they are outside both counts above.
        elapsed_s: Seconds the SCAN took — open plus probe, never the keylog
            parse and never the whole worker call. See CONTRACT 4.
        observations: The cells, one per searched ``secret_type``.
    """

    record_version: int = OBSERVATION_RECORD_VERSION
    unit_key: str = ""
    dump_path: str = ""
    outcome: str = SCAN_OUTCOME_OK
    detail: str = ""
    format_name: str = ""
    size_for_view: int = 0
    keylog_status: str = ""
    secrets_available: int = 0
    secret_types_available: int = 0
    secret_types_searched: int = 0
    secrets_skipped_empty: int = 0
    elapsed_s: float = 0.0
    observations: Tuple[DumpObservation, ...] = ()

    def rows(self) -> List[Dict[str, Any]]:
        """Every persistable row, ready for ``add_survival_batch``."""
        return [o.to_row() for o in self.observations if o.writes_row]

    def to_dict(self) -> Dict[str, Any]:
        """JSON-serialisable view — one ``results.jsonl`` line."""
        return {
            "record_version": self.record_version,
            "unit_key": self.unit_key,
            "dump_path": self.dump_path,
            "outcome": self.outcome,
            "detail": self.detail,
            "format_name": self.format_name,
            "size_for_view": self.size_for_view,
            "keylog_status": self.keylog_status,
            "secrets_available": self.secrets_available,
            "secret_types_available": self.secret_types_available,
            "secret_types_searched": self.secret_types_searched,
            "secrets_skipped_empty": self.secrets_skipped_empty,
            "elapsed_s": self.elapsed_s,
            "observations": [o.to_row() for o in self.observations],
        }


def _searchable_groups(
    secrets: Sequence[CryptoSecret],
) -> Tuple[List[Tuple[str, List[CryptoSecret]]], int]:
    """Group secrets by ``secret_type``, dropping empty needles.

    Grouping is not cosmetic: the ``survival`` grain is
    ``(sweep_id, dump_path, secret_type)``, so two secrets sharing a type must
    produce ONE cell. Emitting two rows would let the unique index silently
    discard one while the writer counted both.

    THE EMPTY-NEEDLE DROP is the guard that matters. ``find_first_offset``
    already returns ``None`` for ``b""`` rather than offset 0, so an empty
    secret cannot fake a hit — but it would then record ``present = FALSE``,
    which is a POSITIVE CLAIM OF ABSENCE for a needle that was never searched.
    Such a secret yields no row at all and is counted out separately.

    Returns the groups in stable ``secret_type`` order (deterministic
    ``results.jsonl`` lines) and the number of secrets dropped as empty.
    """
    grouped: Dict[str, List[CryptoSecret]] = {}
    skipped = 0
    for s in secrets:
        if not s.secret_value:
            skipped += 1
            continue
        grouped.setdefault(s.secret_type, []).append(s)
    return sorted(grouped.items()), skipped


def _elapsed_since(started: float) -> float:
    """Seconds since a :func:`time.perf_counter` reading, rounded and clamped.

    Rounded to :data:`ELAPSED_PRECISION` so a ``results.jsonl`` line does not
    carry float noise, and clamped at ``0.0`` because a duration is never
    negative — the progress ETA that consumes it divides by elapsed time and a
    negative sample would invert the estimate. See "CONTRACT 4".
    """
    return max(0.0, round(time.perf_counter() - started, ELAPSED_PRECISION))


def _probe(
    source: Any,
    groups: Sequence[Tuple[str, List[CryptoSecret]]],
    view: Optional[str],
) -> List[Tuple[str, Optional[int]]]:
    """Return ``(secret_type, first_offset_or_None)`` for every group.

    ONE :func:`core.dump_source.find_first_in` per secret, stopping at the
    first hit within a type: presence, not enumeration. Pure I/O — it builds no
    :class:`DumpObservation`, so the caller's ``except (OSError, ValueError)``
    can mean "the dump could not be read" and nothing else. A validation
    ``ValueError`` from the observation constructor would otherwise be
    laundered into an ``unreadable`` verdict, i.e. a writer bug reported as a
    property of the corpus.
    """
    probed: List[Tuple[str, Optional[int]]] = []
    for secret_type, group in groups:
        offset: Optional[int] = None
        for s in group:
            offset = find_first_in(source, s.secret_value, view=view)
            if offset is not None:
                break
        probed.append((secret_type, offset))
    return probed


def scan_dump_unit(
    dump_path: PathLike,
    run_dir: PathLike,
    *,
    sweep_id: str,
    unit_key: str = "",
    run_id: str = "",
    dump_id: str = "",
    library: str = "",
    protocol_version: str = "",
    library_version: str = UNKNOWN_LIBRARY_VERSION,
    scenario: str = "",
    run_number: int = 0,
    phase: str = "",
    canonical_phase: str = "",
    keylog_filename: str = KEYLOG_FILENAME,
    allowed_formats: Sequence[str] = SUPPORTED_FORMATS,
    view: Optional[str] = None,
) -> DumpScanResult:
    """Probe one dump for its own run's keylog secrets. THE SWEEP WORKER.

    MODULE-LEVEL AND PICKLABLE ON PURPOSE. A ``ProcessPoolExecutor`` pickles
    the callable by reference and its arguments by value, so a bound method
    would drag ``self`` — and, on the sweep driver, an unpicklable DuckDB
    connection — across the process boundary. That is why
    :func:`engine.batch._execute_batch_job` is module-level too. Every
    parameter here is a ``str``/``Path``/``int`` and the return value is a
    frozen dataclass of the same, so both directions pickle.

    Args:
        dump_path: The dump to probe. Opened and closed here.
        run_dir: The run directory supplying *keylog_filename*. Secrets resolve
            PER RUN by construction — there is no cross-run inheritance to get
            wrong.
        sweep_id: Required. One global project DB holds every sweep; rows
            written without it merge a CI slice and a publication run.
        unit_key: The ledger's idempotency key. Travels on the result, not on
            the rows (see "CONTRACT 1").
        run_id, dump_id, library, protocol_version, library_version, scenario,
        run_number, phase, canonical_phase: The corpus axes, copied onto every
            observation. ``phase`` is the RAW filename phase; ``canonical_phase``
            the normalised label.
        keylog_filename: Overridable for a non-default corpus.
        allowed_formats: Source formats a presence claim may be made from; see
            :data:`SUPPORTED_FORMATS`. Widening it is an EXPLICIT OPT-IN.
        view: Byte view. Forwarded only when supplied, so each source keeps its
            own default (``"raw"`` raw, ``"vas"`` MSL).

    Returns:
        A :class:`DumpScanResult`. Read :attr:`DumpScanResult.outcome` before
        reading anything into an empty ``observations``.

    Raises:
        ValueError: If *view* is not a :data:`VIEW_MODES` member. Raised
            EAGERLY, before any I/O, so a typo fails the sweep once instead of
            degrading every unit into an ``unreadable`` row.
    """
    if view is not None and view not in VIEW_MODES:
        raise ValueError(
            "unknown view " + repr(view) + "; expected one of "
            + ", ".join(repr(v) for v in VIEW_MODES))

    dump_str = str(dump_path)
    axes: Dict[str, Any] = {
        "run_id": run_id, "dump_id": dump_id, "library": library,
        "protocol_version": protocol_version,
        "library_version": library_version, "scenario": scenario,
        "run_number": run_number, "phase": phase,
        "canonical_phase": canonical_phase, "dump_path": dump_str,
        "sweep_id": sweep_id, "method": METHOD_KEYLOG_SUBSTRING,
    }

    def result(outcome: str, **kw: Any) -> DumpScanResult:
        return DumpScanResult(unit_key=unit_key, dump_path=dump_str,
                              outcome=outcome, **kw)

    try:
        secrets, keylog_status = keylog_secrets_for_run(
            run_dir, keylog_filename=keylog_filename)
        groups, skipped_empty = _searchable_groups(secrets)
        base: Dict[str, Any] = {
            "keylog_status": keylog_status,
            # Raw ENTRIES vs distinct searchable TYPES: two different grains,
            # named apart so the matrix cannot pick the wrong one. Only the
            # second is the survival denominator (CONTRACT 5).
            "secrets_available": len(secrets),
            "secret_types_available": len(groups),
            "secrets_skipped_empty": skipped_empty,
        }
        if skipped_empty:
            logger.warning(
                "%s: %d keylog secret(s) have empty bytes and were not"
                " searched; no absence is claimed for them.",
                dump_str, skipped_empty)
        if not groups:
            # No dump was opened, so ``elapsed_s`` stays 0.0: there is no scan
            # to time, and reporting the keylog parse here would be exactly the
            # attribution CONTRACT 4 excludes.
            no_truth = keylog_status in (KEYLOG_STATUS_MISSING,
                                         KEYLOG_STATUS_UNREADABLE)
            return result(
                SCAN_OUTCOME_NO_KEYLOG if no_truth else SCAN_OUTCOME_OK,
                detail="keylog status " + keylog_status, **base)

        allowed = tuple(allowed_formats)
        fmt, size = "", 0
        # CONTRACT 4: the clock starts HERE, not at the top of the function.
        # Everything above is the per-RUN keylog parse, amortised over that
        # run's ~7 dumps; charging it to whichever dump happened to be scanned
        # first would skew both a cost comparison and a progress ETA.
        # ``perf_counter`` because a wall clock can step backwards mid-sweep.
        started = time.perf_counter()
        try:
            with open_dump(Path(dump_path)) as source:
                fmt = source.format_name
                if fmt not in allowed:
                    logger.warning(
                        "%s: refusing format %r (allowed: %s); a presence"
                        " claim over a different byte stream is not"
                        " comparable.", dump_str, fmt, allowed)
                    return result(
                        SCAN_OUTCOME_UNSUPPORTED_FORMAT, format_name=fmt,
                        size_for_view=source.size,
                        detail="format " + fmt + " not in " + repr(allowed),
                        elapsed_s=_elapsed_since(started), **base)
                size = (source.size_for(view) if view is not None
                        else source.size_for())
                if size <= 0:
                    # An empty or unmapped view answers every find_first with
                    # None — a FALSE ABSENCE for every secret. That is
                    # unreadable, not "the secrets are gone".
                    raise OSError("view exposes 0 bytes")
                probed = _probe(source, groups, view)
        except (OSError, ValueError) as exc:
            logger.warning("%s: unreadable (%s); no absence is claimed.",
                           dump_str, exc)
            return result(
                SCAN_OUTCOME_UNREADABLE, format_name=fmt, size_for_view=size,
                detail=str(exc), elapsed_s=_elapsed_since(started),
                observations=tuple(
                    DumpObservation(
                        secret_type=secret_type,
                        status=SURVIVAL_STATUS_UNREADABLE, format_name=fmt,
                        size_for_view=size, **axes)
                    for secret_type, _group in groups),
                **base)

        return result(
            SCAN_OUTCOME_OK, format_name=fmt, size_for_view=size,
            secret_types_searched=len(groups),
            elapsed_s=_elapsed_since(started),
            observations=tuple(
                DumpObservation(
                    secret_type=secret_type, status=SURVIVAL_STATUS_SEARCHED,
                    present=offset is not None, first_offset=offset,
                    hit_count=MAX_HIT_COUNT if offset is not None else 0,
                    format_name=fmt, size_for_view=size, **axes)
                for secret_type, offset in probed),
            **base)
    except Exception as exc:  # noqa: BLE001 - one bad unit must not kill a sweep
        # Every counter, ``elapsed_s`` included, stays at its zero default: an
        # errored attempt is not an observation, and a partial duration read
        # off a half-finished scan would be published as if it were a completed
        # unit's cost.
        logger.warning("%s: scan failed (%s: %s); no rows written.",
                       dump_str, type(exc).__name__, exc, exc_info=True)
        return result(SCAN_OUTCOME_ERROR,
                      detail=type(exc).__name__ + ": " + str(exc))


__all__ = [
    "ELAPSED_PRECISION",
    "MAX_HIT_COUNT",
    "OBSERVATION_COLUMNS",
    "OBSERVATION_RECORD_VERSION",
    "SCAN_OUTCOMES",
    "SCAN_OUTCOME_ERROR",
    "SCAN_OUTCOME_NO_KEYLOG",
    "SCAN_OUTCOME_OK",
    "SCAN_OUTCOME_UNREADABLE",
    "SCAN_OUTCOME_UNSUPPORTED_FORMAT",
    "SUPPORTED_FORMATS",
    "VIEW_MODES",
    "DumpObservation",
    "DumpScanResult",
    "scan_dump_unit",
]
