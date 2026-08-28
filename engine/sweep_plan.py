"""Work units and idempotency digests for a resumable full-corpus sweep.

A corpus sweep asks one question of every dump in the TLS corpus: *does this
dump still contain its own run's keylog secrets?* At the measured corpus size
(2,600 runs / 18,917 dumps / ~170 GB) that sweep cannot be a single
non-restartable process, so this module supplies the two things resumability
needs:

1. a LAZY enumeration of the work units (:func:`enumerate_units`) plus a cheap
   separate count for a progress denominator (:func:`count_units`);
2. the digests that make *skip-if-already-done* correct rather than merely
   plausible - a stable per-unit key (:func:`unit_key`), an inputs digest that
   notices the inputs changed (:func:`inputs_digest`) and a config digest that
   notices the *settings* changed (:func:`config_digest`).

The unit is ONE DUMP
--------------------
Not one run, not one library: one dump file. That is the granularity at which
a scan result exists, so it is the granularity at which work can be skipped.

Why ``canonical_phase`` is NOT part of the unit key
--------------------------------------------------
This is the single most important design point in the module.

A unit key must be a function of the unit's *own* identity. ``canonical_phase``
is not: :class:`core.phase_normalizer.PhaseNormalizer` derives it from the set
of **sibling** dumps in the run - it sorts the run's dumps by timestamp and
hands out the generic canonical suffixes *positionally*
(``handshake_end``, then ``second_event``, then ``event_3`` ...; see
``core.phase_normalizer._generic_suffix``). Adding one dump to a run can
therefore re-map the canonical phase of dumps that were never touched.

If ``canonical_phase`` were in the key, the appearance of an unrelated sibling
file would silently change the key of every already-scanned dump in that run:
a resumed sweep would re-scan work it had already completed and, worse, the
ledger would grow orphan rows under keys nothing will ever look up again. A key
that mutates when a *sibling* appears is not an idempotency key.

The ``dump_filename`` used in the key instead carries the RAW phase plus a
microsecond-resolution timestamp (``20251020_171845_606711_pre_server_key_update.dump``),
so it is already unique within a run and depends on nothing but that one file.
``canonical_phase`` is still carried on :class:`SweepUnit` (consumers group and
filter by it) - it just never reaches the key.

Why ``corpus_id`` is a label and not a path
-------------------------------------------
``corpus_id`` defaults to ``Path(root).name`` (e.g. ``tls_dumps``). It is
deliberately NOT the absolute root, and not a hash of the realpath: copying the
corpus to an external drive, or mounting it at a different point, would then
invalidate all 18,917 units for no reason at all - the bytes did not change.
The absolute root is still recorded, as informational data
(:attr:`SweepUnit.corpus_root`), so a ledger row can say where it was scanned
from without that fact leaking into identity.

Why an inputs digest must be recorded WITH its level
---------------------------------------------------
:func:`inputs_digest` folds its own ``level`` into the hashed payload, so the
same unchanged dump digests differently at ``"size"`` and at ``"content"``.
That is deliberate - a digest computed under a weaker rule must never be
mistaken for one computed under a stronger one - but it is also a trap: an
operator who raises ``recheck_inputs`` from ``"size"`` to ``"content"`` changes
all 18,917 digests at once, and a consumer that compares digests alone would
read that as "every input changed" and silently re-sweep ~170 GB.

So a consumer must record the LEVEL alongside the digest and compare
level-aware. :func:`inputs_digest_with_level` returns both as an
:class:`InputsDigest`, whose :meth:`InputsDigest.comparable_with` answers "were
these two computed under the same rule?" before
:meth:`InputsDigest.matches` is allowed to mean anything. A level change is
"not comparable", which is a different fact from "the inputs changed".

That distinction is enforced, not merely documented. A two-valued answer cannot
carry three facts, so :meth:`InputsDigest.compare` returns a tri-state
:class:`DigestComparison` (``MATCH`` / ``CHANGED`` / ``NOT_COMPARABLE``), and
the convenient two-valued :meth:`InputsDigest.matches` RAISES
:class:`IncomparableDigestError` on a level change rather than answering
``False``. A ledger that branches on ``matches()`` alone would otherwise read a
raised ``recheck_inputs`` as "every one of the 18,917 inputs changed" and
re-sweep ~170 GB - the exact failure this class exists to prevent.

Layering: this module is pure compute. ``engine`` may import ``core`` but never
``app`` or ``presentation`` (AST-enforced by
``tests/test_architecture_invariants.py``).
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import (
    Any,
    Dict,
    Iterable,
    Iterator,
    List,
    Optional,
    Sequence,
    Tuple,
)

from memdiver.core.corpus_axes import (
    KEYLOG_FILENAME,
    UNKNOWN_LIBRARY_VERSION,
    VERSION_AXIS_PROTOCOL,
    CorpusAxes,
    axes_from_run_dir,
    resolve_protocol_dir,
    with_canonical_phase,
)
from memdiver.core.discovery import RunDiscovery
from memdiver.core.models import RunDirectory
from memdiver.core.phase_normalizer import (
    UNPARSED_TIMESTAMP,
    PhaseNormalizer,
    parse_phase_timestamp,
)

logger = logging.getLogger("memdiver.engine.sweep_plan")

#: Version of the unit-key *format*. Bumping it invalidates every stored unit
#: key on purpose (that is the escape hatch for a future key-shape change);
#: nothing else in this module may change the key shape silently.
#:
#: ``"u1"`` -> ``"u2"``: ``library_version`` joined the key. On today's corpus
#: every run resolves to :data:`core.corpus_axes.UNKNOWN_LIBRARY_VERSION`, so
#: the collision it prevents (two builds of the same library at the same run
#: number) cannot occur yet - which is exactly why the bump is free NOW and
#: would be a ledger migration once 18,917 rows exist under ``"u1"``.
UNIT_KEY_VERSION = "u2"

#: Version of the sweep's *result* schema. Part of :func:`config_digest`, so a
#: bump forces a re-sweep - which is correct, because rows written under the
#: old schema cannot be compared with rows written under the new one.
#:
#: ``1`` -> ``2``: the observation ENVELOPE
#: (:class:`engine.survival_scan.DumpScanResult`, aliased as
#: :data:`engine.survival_scan.OBSERVATION_RECORD_VERSION`) grew ``elapsed_s``
#: and ``secret_types_available`` / ``secret_types_searched``. Exactly like the
#: ``"u1"`` -> ``"u2"`` unit-key bump above, the bump is FREE NOW - nothing has
#: been swept yet - and would cost a full 18,917-unit / ~170 GB re-sweep once
#: results exist under version ``1``. It is taken deliberately at settle time
#: rather than discovered mid-sweep.
SWEEP_SCHEMA_VERSION = 2

#: Valid ``level`` arguments to :func:`inputs_digest`, cheapest first.
DIGEST_LEVELS: Tuple[str, ...] = ("off", "size", "content")

#: Default :func:`inputs_digest` level: size-only. See that function's docstring
#: for why mtime is excluded.
DEFAULT_DIGEST_LEVEL = "size"

#: Operator-facing NAME of the setting that selects the digest level. The
#: parameter is called ``level`` inside this module for historical reasons;
#: ``recheck_inputs`` is the spelling a driver, a ledger row and a CLI option
#: should use, because "how hard do we re-check the inputs" is what the setting
#: actually means to whoever turns it.
RECHECK_INPUTS_SETTING = "recheck_inputs"

#: Chunk size for the ``"content"`` level's whole-dump hash.
_CONTENT_CHUNK_BYTES = 4 * 1024 * 1024

#: Recorded size for a file that is expected but cannot be stat-ed. Distinct
#: from ``0`` so "the file vanished" and "the file is empty" hash differently.
_MISSING_SIZE = -1

#: Sort key for a dump filename carrying no parseable timestamp. Re-exported
#: from :mod:`core.phase_normalizer`, which owns the parse: the module that
#: ASSIGNS the positional canonical labels and the module that emits units in
#: chronological order must order dumps by the identical rule or the labels and
#: the emission drift apart.
_UNPARSED_TIMESTAMP: Tuple[int, int, int] = UNPARSED_TIMESTAMP

#: The settings that change a sweep's OUTPUT, with their defaults. Anything not
#: on this list cannot enter :func:`config_digest`.
_CONFIG_DEFAULTS: Dict[str, Any] = {
    "expand_keys": False,
    # ``normalize`` re-resolves a run's dumps through the phase normalizer
    # before scanning, so it changes WHICH dump a phase request lands on and
    # therefore what the sweep finds. It is not part of the unit key (the key
    # names a concrete dump file, not a phase request), so if it were absent
    # here too, flipping it would leave a resumed sweep skipping every unit as
    # "already done" against results produced under the other setting.
    "normalize": False,
    "algorithms": (),
    "keylog_filename": KEYLOG_FILENAME,
    "template_name": "",
    "min_secret_len": 0,
    "memdiver_version": "",
    "sweep_schema_version": SWEEP_SCHEMA_VERSION,
}

#: Settings that are deliberately EXCLUDED from :func:`config_digest`: they
#: change how fast the sweep runs, never what it finds. Accepted silently so a
#: caller can pass its whole settings object through.
_CONFIG_IGNORED = frozenset(
    {"workers", "use_processes", "max_inflight", "fsync_policy", "output_dir"}
)


@dataclass(frozen=True)
class SweepUnit:
    """One dump to scan, with the axes it is an instance of.

    Frozen: units are used as identity keys (a ledger row, a result-map entry),
    so they must not mutate underneath a dictionary.

    Fields:
        corpus_id: Stable corpus LABEL (not a path) - see the module docstring.
        protocol_version: ``"12"`` / ``"13"``.
        scenario: Scenario directory name.
        library: Library token from the run directory name.
        library_version: Concrete library build, or ``"unknown"``.
        run_number: Run index from the run directory name.
        dump_path: Absolute path of the dump to scan.
        raw_phase: Phase exactly as written in the filename, prefix included
            (e.g. ``"pre_server_key_update"``).
        canonical_phase: Canonical lifecycle phase from
            :class:`core.phase_normalizer.PhaseNormalizer`, filled in per run.
            Present for filtering/grouping, NEVER part of :attr:`unit_key`.
        phase_timestamp: Timestamp prefix of the dump filename.
        keylog_path: The run's ``keylog.csv``, or ``None`` when absent (2 of the
            2,600 measured runs have none).
        corpus_root: Absolute corpus root. INFORMATIONAL ONLY - recorded for
            provenance, never part of the key.
    """

    corpus_id: str
    protocol_version: str
    scenario: str
    library: str
    library_version: str
    run_number: int
    dump_path: Path
    raw_phase: str
    canonical_phase: str
    phase_timestamp: str
    keylog_path: Optional[Path]
    corpus_root: Optional[Path] = None

    @property
    def run_dir(self) -> Path:
        """The run directory containing :attr:`dump_path`."""
        return self.dump_path.parent

    @property
    def unit_key(self) -> str:
        """This unit's idempotency key; see :func:`unit_key`."""
        return unit_key(self)


# ``parse_phase_timestamp`` is DEFINED in :mod:`core.phase_normalizer`, next to
# the code that hands out the positional canonical labels, and re-exported here
# (see :data:`__all__`). One definition, so this module's emission order and
# those labels are produced by the very same function instead of by two copies
# free to drift; ``core`` owns it because ``engine`` may import ``core`` and
# never the reverse. Callers that import the name from ``sweep_plan`` are
# unaffected.


def unit_key(unit: SweepUnit) -> str:
    """Return the stable idempotency key for ``unit``.

    Shape::

        u2/{corpus_id}/{protocol_version}/{scenario}/{library}/{library_version}/{run_number:04d}/{dump_filename}

    Every component is either a corpus LABEL or a path *component* - never an
    absolute path - so the key survives the corpus being moved or copied to
    another mount. ``canonical_phase`` is deliberately absent (module
    docstring); ``dump_filename`` already identifies the file uniquely within
    its run.

    ``library_version`` sits between ``library`` and ``run_number`` because a
    future multi-build corpus varies the build WITHIN a library: without it,
    ``openssl_run_13_1`` built against two different OpenSSL releases would
    collide on one key and one ledger row. It is
    :data:`core.corpus_axes.UNKNOWN_LIBRARY_VERSION` for every run measured
    today, which is why :data:`UNIT_KEY_VERSION` could absorb it for free.
    """
    return "/".join(
        (
            UNIT_KEY_VERSION,
            unit.corpus_id,
            unit.protocol_version,
            unit.scenario,
            unit.library,
            unit.library_version,
            f"{unit.run_number:04d}",
            unit.dump_path.name,
        )
    )


def _unknown_level_error(level: str) -> ValueError:
    """The one rejection for a digest level outside :data:`DIGEST_LEVELS`.

    Shared by :meth:`InputsDigest.__post_init__` and
    :func:`resolve_digest_level` so both refusals name the same valid levels
    (the tests assert every level in :data:`DIGEST_LEVELS` appears in the
    message) and neither can drift as the list grows.
    """
    return ValueError(
        f"unknown inputs_digest level {level!r}; valid levels are: "
        + ", ".join(repr(name) for name in DIGEST_LEVELS)
    )


class IncomparableDigestError(ValueError):
    """Raised when two :class:`InputsDigest` values answer different questions.

    Carried by :meth:`InputsDigest.matches`, whose two-valued answer has no
    room for the third fact. Use :meth:`InputsDigest.compare` (or check
    :meth:`InputsDigest.comparable_with` first) when a level change is an
    expected input rather than a bug.
    """


class DigestComparison(Enum):
    """The THREE possible outcomes of comparing two inputs digests.

    ``MATCH``
        Same level, same digest: the inputs are unchanged; skip the unit.
    ``CHANGED``
        Same level, different digest: the inputs really changed; re-scan.
    ``NOT_COMPARABLE``
        Different levels: the two digests answer different questions and
        NOTHING follows about the inputs. Re-digest at the recorded level, or
        accept the re-scan as a deliberate cost of raising ``recheck_inputs`` -
        but never record the unit as stale on this basis.

    A boolean cannot carry three facts, which is why this exists: collapsing
    ``NOT_COMPARABLE`` into ``False`` is what turns one operator raising
    ``recheck_inputs`` into 18,917 spurious "changed" verdicts and a ~170 GB
    re-sweep.
    """

    MATCH = "match"
    CHANGED = "changed"
    NOT_COMPARABLE = "not_comparable"


@dataclass(frozen=True)
class InputsDigest:
    """An inputs digest PAIRED with the level that produced it.

    A bare digest is not a comparable value: :func:`inputs_digest` hashes its
    own ``level`` into the payload, so the same untouched dump digests
    differently at ``"size"`` and at ``"content"``. Comparing two digests
    without their levels turns an operator raising ``recheck_inputs`` into
    18,917 false "the inputs changed" verdicts and a full ~170 GB re-sweep.

    So a ledger stores both fields and reads the verdict off
    :meth:`compare`, which is tri-state; :meth:`matches` is the two-valued
    convenience that REFUSES to answer when the levels differ.

    Fields:
        digest: The hex digest, or ``""`` at the ``"off"`` level.
        level: The level that produced ``digest``; one of :data:`DIGEST_LEVELS`.

    ``level`` is validated on construction. An unvalidated typo
    (``InputsDigest("deadbeef", "conten")``) would construct happily and then
    be permanently NOT_COMPARABLE with every digest the sweep computes - a
    permanent full re-sweep from a single mistyped character, and one that
    reports itself as "not comparable" rather than as an error.

    The ``"off"`` level is a deliberate special case: it digests to ``""`` for
    EVERY unit in the corpus, so two ``off`` digests always compare ``MATCH``
    even for different dumps. That is the documented meaning of ``off`` -
    "skip-if-done rests on the unit key plus the config digest alone" (see
    :func:`inputs_digest`) - and it is only correct for an immutable corpus.
    A digest at ``"off"`` therefore proves nothing about the bytes; it is the
    unit key, not the digest, that identifies the unit.
    """

    digest: str
    level: str

    def __post_init__(self) -> None:
        if self.level not in DIGEST_LEVELS:
            raise _unknown_level_error(self.level)

    def comparable_with(self, other: "InputsDigest") -> bool:
        """True when ``other`` was computed under the SAME rule as this one.

        A ``False`` here means "unknown", NOT "changed": the two digests answer
        different questions, so the honest response is to re-digest at the
        recorded level (or accept the re-scan), never to declare the inputs
        stale.
        """
        return self.level == other.level

    def compare(self, other: "InputsDigest") -> DigestComparison:
        """Compare against ``other``, tri-state. THE method to branch on.

        Returns :attr:`DigestComparison.NOT_COMPARABLE` for a level change,
        which is a different fact from :attr:`DigestComparison.CHANGED` - see
        :class:`DigestComparison`.
        """
        if not self.comparable_with(other):
            return DigestComparison.NOT_COMPARABLE
        if self.digest == other.digest:
            return DigestComparison.MATCH
        return DigestComparison.CHANGED

    def matches(self, other: "InputsDigest") -> bool:
        """True when both the level and the digest agree.

        The two-valued convenience over :meth:`compare`, for the common case
        where both digests are known to have been taken at the same level.

        Raises:
            IncomparableDigestError: when the levels differ. It deliberately
                does NOT return ``False`` there: ``False`` reads as "the inputs
                changed", and a ledger branching on it would re-sweep the whole
                corpus because someone raised ``recheck_inputs``. Call
                :meth:`compare` (or :meth:`comparable_with` first) when a level
                change is an expected input.
        """
        verdict = self.compare(other)
        if verdict is DigestComparison.NOT_COMPARABLE:
            raise IncomparableDigestError(
                f"cannot compare an inputs digest taken at {self.level!r} with "
                f"one taken at {other.level!r}: they answer different "
                f"questions. Use compare() for a tri-state verdict."
            )
        return verdict is DigestComparison.MATCH


def resolve_digest_level(
    level: str = DEFAULT_DIGEST_LEVEL, recheck_inputs: Optional[str] = None,
) -> str:
    """Return the effective digest level, validated.

    ``recheck_inputs`` is the named setting (:data:`RECHECK_INPUTS_SETTING`)
    that operators and drivers actually configure; ``level`` is the older
    positional spelling, kept working for every existing caller. When both are
    given the NAMED setting wins, because it is the one a caller passed
    deliberately rather than inherited from a default.

    Raises:
        ValueError: for a level outside :data:`DIGEST_LEVELS`.
    """
    effective = recheck_inputs if recheck_inputs is not None else level
    if effective not in DIGEST_LEVELS:
        raise _unknown_level_error(effective)
    return effective


def inputs_digest(
    unit: SweepUnit,
    level: str = DEFAULT_DIGEST_LEVEL,
    *,
    recheck_inputs: Optional[str] = None,
) -> str:
    """Digest the *inputs* of ``unit`` so a stale result can be detected.

    ``recheck_inputs`` is the named spelling of ``level``
    (:data:`RECHECK_INPUTS_SETTING`) and wins when both are supplied; see
    :func:`resolve_digest_level`. Prefer :func:`inputs_digest_with_level` when
    the value is going to be STORED - a digest without its level is not a
    comparable value (module docstring).

    Levels (see :data:`DIGEST_LEVELS`):

    ``"off"``
        Return ``""``. Skip-if-done then rests on the unit key plus the config
        digest alone. Fastest, and correct for an immutable corpus.
    ``"size"`` (default)
        ``sha256`` over canonical JSON of the sorted ``[(relpath, st_size)]``
        pairs for the dump AND the run's ``keylog.csv`` - both are inputs to the
        scan, so a re-captured keylog must invalidate the result just as a
        re-captured dump does. Paths are relative to the run directory, which is
        what keeps the digest invariant under a corpus move.
    ``"content"``
        Everything ``"size"`` covers, plus a ``sha256`` of the dump's bytes.
        Opt-in only: over the measured corpus that is ~170 GB of reads.

    Why ``"size"`` deliberately EXCLUDES mtime
    ------------------------------------------
    An ``rsync``/``cp``/restore-from-backup of the corpus rewrites every mtime
    while changing not one byte. An mtime-sensitive digest would invalidate all
    18,917 results after such a move and force a full ~170 GB re-sweep for
    nothing. Size still catches the failures that actually matter here - a
    re-capture with different content length, and a truncated or partially
    written dump - and the ``"content"`` level exists for callers that need
    byte-exact certainty. The trade is explicit: a same-size rewrite is
    invisible at ``"size"``.

    Why ``level`` is part of the hashed payload
    ------------------------------------------
    So a ``"size"`` digest can never be mistaken for a ``"content"`` digest of
    the same bytes. The cost is that changing the level changes every digest,
    which a naive consumer would read as "every input changed" - hence
    :class:`InputsDigest` and the level-aware comparison it forces.

    Raises:
        ValueError: for a ``level`` outside :data:`DIGEST_LEVELS`.
    """
    effective = resolve_digest_level(level, recheck_inputs)
    if effective == "off":
        return ""

    run_dir = unit.run_dir
    payload: Dict[str, Any] = {
        "level": effective,
        "sizes": _size_entries(run_dir, _digest_input_paths(unit)),
    }
    if effective == "content":
        payload["content"] = {
            _relpath(run_dir, unit.dump_path): _file_sha256(unit.dump_path),
        }
    return hashlib.sha256(_canonical_json(payload).encode("utf-8")).hexdigest()


def inputs_digest_with_level(
    unit: SweepUnit,
    level: str = DEFAULT_DIGEST_LEVEL,
    *,
    recheck_inputs: Optional[str] = None,
) -> InputsDigest:
    """:func:`inputs_digest`, returning the digest WITH its level.

    The form a ledger should persist: see :class:`InputsDigest` for why a
    digest recorded without its level cannot be compared safely.
    """
    effective = resolve_digest_level(level, recheck_inputs)
    return InputsDigest(digest=inputs_digest(unit, effective), level=effective)


def config_digest(**cfg: Any) -> str:
    """Digest the sweep settings that affect the sweep's OUTPUT.

    Contributing keys (with defaults applied for any not supplied, so the digest
    is stable whether or not a caller spells every setting out):
    ``expand_keys``, ``normalize``, ``algorithms``, ``keylog_filename``,
    ``template_name``, ``min_secret_len``, ``memdiver_version``,
    ``sweep_schema_version``.

    Explicitly IGNORED: ``workers``, ``use_processes``, ``max_inflight``,
    ``fsync_policy``, ``output_dir``. Those change only how fast (and where)
    the sweep runs. Folding them in would mean that an operator who merely
    raises the worker count - the single most likely mid-sweep adjustment -
    invalidates every completed unit and re-reads ~170 GB. They are accepted
    without complaint so a caller can hand over its whole settings mapping.

    Any *other* key is ignored too, with a warning: silently dropping a typo'd
    setting would silently weaken the digest.

    Returns:
        The first 16 hex characters of a ``sha256`` over canonical JSON
        (``sort_keys=True`` and a deterministic separator, so the value is
        stable across processes and Python versions). 64 bits is ample for
        distinguishing a handful of configurations while staying readable in a
        ledger row or a filename.
    """
    for key in cfg:
        if key not in _CONFIG_DEFAULTS and key not in _CONFIG_IGNORED:
            logger.warning(
                "config_digest: ignoring unknown setting %r (it does not "
                "contribute to the digest)", key,
            )

    payload = {
        key: _normalize_config_value(cfg.get(key, default))
        for key, default in _CONFIG_DEFAULTS.items()
    }
    digest = hashlib.sha256(_canonical_json(payload).encode("utf-8")).hexdigest()
    return digest[:16]


def enumerate_units(
    root: Any,
    *,
    corpus_id: Optional[str] = None,
    protocol_versions: Optional[Iterable[str]] = None,
    scenarios: Optional[Iterable[str]] = None,
    libraries: Optional[Iterable[str]] = None,
    canonical_phases: Optional[Iterable[str]] = None,
    max_runs_per_library: int = 0,
    max_units: int = 0,
) -> Iterator[SweepUnit]:
    """Yield one :class:`SweepUnit` per dump, LAZILY.

    A generator, not a list: 18,917 units must never all be resident, and the
    caller must be able to start scanning the first dump before the last
    directory has been walked. Nothing here reads a dump's contents.

    Walk order is ``protocol dir -> scenario -> library -> run dir``, each level
    sorted, so the enumeration is deterministic and resumable position-wise.
    Per run it calls :meth:`core.discovery.RunDiscovery.load_run_directory` with
    ``extract_secrets=False`` (the dump inventory is all that is needed; that
    flag skips the keylog parse and the expensive MSL key-hint fallback) and
    then runs :meth:`core.phase_normalizer.PhaseNormalizer.normalize_run`
    exactly ONCE per run - the normalizer is a whole-run operation, so calling
    it per dump would be both wasteful and, for the positional generic phases,
    no more correct.

    Args:
        root: Corpus root containing the protocol directories.
        corpus_id: Stable corpus label; defaults to ``Path(root).name``.
        protocol_versions: Keep only these versions. Matches either the bare
            version (``"13"``) or the protocol directory name (``"TLS13"``),
            case-insensitively.
        scenarios: Keep only these scenario directory names (case-insensitive).
        libraries: Keep only these library tokens (case-insensitive).
        canonical_phases: Keep only dumps whose canonical phase matches
            (case-insensitive).
        max_runs_per_library: Keep at most this many runs per library directory,
            lowest run number first. ``0`` means no limit.
        max_units: Stop after this many units. ``0`` means no limit.

    A malformed protocol/scenario/library/run directory is skipped with a
    warning and never raises: a partially copied corpus must not abort a sweep.
    """
    root_path = Path(root)
    label = corpus_id or root_path.name
    phase_filter = _normalize_filter(canonical_phases)

    emitted = 0
    for run_dir, axes in _walk_runs(
        root_path,
        protocol_versions=protocol_versions,
        scenarios=scenarios,
        libraries=libraries,
        max_runs_per_library=max_runs_per_library,
    ):
        for unit in _units_for_run(run_dir, axes, label, root_path):
            if phase_filter is not None and unit.canonical_phase.lower() not in phase_filter:
                continue
            yield unit
            emitted += 1
            if max_units > 0 and emitted >= max_units:
                return


def count_units(
    root: Any,
    *,
    corpus_id: Optional[str] = None,
    protocol_versions: Optional[Iterable[str]] = None,
    scenarios: Optional[Iterable[str]] = None,
    libraries: Optional[Iterable[str]] = None,
    canonical_phases: Optional[Iterable[str]] = None,
    max_runs_per_library: int = 0,
    max_units: int = 0,
) -> int:
    """Count the units :func:`enumerate_units` would yield, cheaply.

    A SEPARATE, deliberately cheap pass: a directory listing per run plus one
    :meth:`core.discovery.RunDiscovery.dump_file_for` call per filename (that
    seam reads no file). No ``load_run_directory``, no keylog parse, no
    ``meta.json`` probe, no keylog stat, no capture probe. Its only job is to
    give a progress bar a denominator over 2,600 run directories, so it must
    not cost what the sweep itself costs.

    Cheap, but not a SECOND opinion: admission goes through the same public
    seam ``load_run_directory`` admits its dumps with, so this count and
    :func:`enumerate_units` cannot disagree about which files are dumps. See
    :func:`_dump_filenames` for what a local re-derivation of that rule cost.

    That is enforced by ``resolve_axes=False``: the run axes are resolved from
    DIRECTORY NAMES alone (:func:`_sorted_runs_by_dirname`) rather than through
    :func:`core.corpus_axes.axes_from_run_dir`, which reaches the filesystem
    twice per run - a ``meta.json`` probe and a keylog stat, ~5,200 syscalls
    over the measured corpus - to resolve a ``library_version`` that is
    ``"unknown"`` for every run in it and a ``keylog_path`` a count cannot use.

    ``canonical_phases`` is the one filter that needs more than a filename: the
    canonical phase is a whole-run property. When (and only when) that filter is
    supplied, this function runs :class:`PhaseNormalizer` over the
    already-listed filenames - pure CPU on data it has in hand, still no extra
    I/O.

    ``corpus_id`` is accepted for signature parity with
    :func:`enumerate_units` (it cannot change a count) so callers can pass one
    filter mapping to both.
    """
    del corpus_id  # Accepted for signature parity; cannot affect a count.
    phase_filter = _normalize_filter(canonical_phases)

    total = 0
    for run_dir, _axes in _walk_runs(
        Path(root),
        protocol_versions=protocol_versions,
        scenarios=scenarios,
        libraries=libraries,
        max_runs_per_library=max_runs_per_library,
        resolve_axes=False,
    ):
        filenames = _dump_filenames(run_dir)
        if phase_filter is None:
            total += len(filenames)
        else:
            total += _count_matching_phases(filenames, phase_filter)
        if max_units > 0 and total >= max_units:
            return max_units
    return total


# -- Walking -----------------------------------------------------------------


def _walk_runs(
    root: Path,
    *,
    protocol_versions: Optional[Iterable[str]],
    scenarios: Optional[Iterable[str]],
    libraries: Optional[Iterable[str]],
    max_runs_per_library: int,
    resolve_axes: bool = True,
) -> Iterator[Tuple[Path, CorpusAxes]]:
    """Yield ``(run_dir, axes)`` for every conforming run under ``root``.

    Lazy at every level, and the shared skeleton of both :func:`enumerate_units`
    and :func:`count_units` so the two can never disagree about which runs are
    in scope. Filters that depend only on a path component are applied here, as
    early as possible, so an excluded library's run directories are never even
    listed.

    ``resolve_axes`` selects how a run directory becomes a
    :class:`CorpusAxes`, and nothing else - the walk, the ordering and every
    filter are shared, which is what keeps the count and the enumeration in
    agreement:

    ``True`` (default, :func:`enumerate_units`)
        :func:`_sorted_runs` -> :func:`core.corpus_axes.axes_from_run_dir`,
        which probes ``meta.json`` and stats the keylog. The full record; the
        enumeration genuinely needs ``library_version`` and ``keylog_path``.
    ``False`` (:func:`count_units`)
        :func:`_sorted_runs_by_dirname`, which touches no file at all. Only the
        fields this skeleton filters on are populated; see that function for
        which ones are NOT.
    """
    version_filter = _normalize_filter(protocol_versions)
    scenario_filter = _normalize_filter(scenarios)
    library_filter = _normalize_filter(libraries)

    for protocol_dir in _sorted_subdirs(root):
        protocol_axes: Optional[Tuple[str, str]] = None
        if not resolve_axes:
            protocol_axes = _protocol_dir_axes(protocol_dir.name)
            if protocol_axes is None:
                # ``axes_from_run_dir`` would reject every run under an
                # unrecognised protocol directory one at a time; the cheap path
                # can drop the whole subtree without listing any of it.
                logger.warning(
                    "Skipping unrecognised protocol directory %s", protocol_dir
                )
                continue
        for scenario_dir in _sorted_subdirs(protocol_dir):
            if scenario_filter is not None and scenario_dir.name.lower() not in scenario_filter:
                continue
            for library_dir in _sorted_subdirs(scenario_dir):
                runs = (
                    _sorted_runs(library_dir)
                    if protocol_axes is None
                    else _sorted_runs_by_dirname(library_dir, *protocol_axes)
                )
                yielded = 0
                for run_dir, axes in runs:
                    if version_filter is not None and not _version_matches(
                        axes, protocol_dir.name, version_filter
                    ):
                        continue
                    if library_filter is not None and axes.library.lower() not in library_filter:
                        continue
                    yield run_dir, axes
                    yielded += 1
                    if max_runs_per_library > 0 and yielded >= max_runs_per_library:
                        break


def _sorted_subdirs(parent: Path) -> List[Path]:
    """Immediate subdirectories of ``parent``, name-sorted; ``[]`` on error.

    Never raises: mirroring :func:`core.dataset_metadata.load_run_meta`, a
    corpus scan tolerates an unreadable or vanished directory by logging and
    moving on.
    """
    try:
        with os.scandir(parent) as entries:
            names = sorted(entry.name for entry in entries if entry.is_dir())
    except (FileNotFoundError, NotADirectoryError):
        return []
    except OSError as exc:
        logger.warning("Skipping unreadable directory %s: %s", parent, exc)
        return []
    return [parent / name for name in names]


def _sorted_runs(library_dir: Path) -> List[Tuple[Path, CorpusAxes]]:
    """Conforming run directories under ``library_dir``, by run number.

    A subdirectory whose name does not parse, or whose axes do not resolve
    (unknown protocol directory, version disagreement), is skipped with a
    warning rather than raising - see :func:`core.corpus_axes.axes_from_run_dir`,
    which returns ``None`` for exactly those cases.
    """
    resolved: List[Tuple[Path, CorpusAxes]] = []
    for run_dir in _sorted_subdirs(library_dir):
        try:
            axes = axes_from_run_dir(run_dir)
        except OSError as exc:
            # ``axes_from_run_dir`` probes sidecars (``meta.json``,
            # ``keylog.csv``); an unreadable run directory surfaces here as a
            # PermissionError. Downgrade it: a partial corpus must not abort a
            # sweep (see this module's tolerance contract).
            logger.warning("Skipping unreadable run directory %s: %s", run_dir, exc)
            continue
        if axes is None:
            logger.warning("Skipping non-conforming run directory %s", run_dir)
            continue
        resolved.append((run_dir, axes))
    resolved.sort(key=_run_order)
    return resolved


def _run_order(pair: Tuple[Path, CorpusAxes]) -> Tuple[int, str]:
    """Sort key for a listed run: run number, then directory name.

    Written once and used by BOTH run listers, so "same ordering" is a fact
    about one function rather than a claim two implementations make about each
    other - the same reason the walk itself is shared (:func:`_walk_runs`).
    """
    run_dir, axes = pair
    return axes.run_number, run_dir.name


def _sorted_runs_by_dirname(
    library_dir: Path, protocol: str, protocol_version: str,
) -> List[Tuple[Path, CorpusAxes]]:
    """:func:`_sorted_runs` without touching a single file.

    Resolves each run from its DIRECTORY NAME alone
    (:meth:`core.discovery.RunDiscovery.parse_run_dirname`) plus the already
    resolved protocol directory, and applies the same two admission rules
    :func:`core.corpus_axes.axes_from_run_dir` applies: an unparseable run
    directory name is rejected, and so is a run whose name disagrees with its
    protocol directory about the version. Same ordering, same runs in scope.

    What is deliberately NOT populated, because resolving it costs a syscall
    that :func:`count_units` cannot use the answer for:

    * ``library_version`` is :data:`core.corpus_axes.UNKNOWN_LIBRARY_VERSION` -
      the value ``axes_from_run_dir`` returns for every run in the measured
      corpus anyway, but here it is an assumption rather than a lookup;
    * ``keylog_path`` is ``None``, meaning "not probed", NOT "absent".

    Only :func:`_walk_runs` may call this, and only for the counting pass. A
    caller that needs either field must resolve full axes.
    """
    resolved: List[Tuple[Path, CorpusAxes]] = []
    for run_dir in _sorted_subdirs(library_dir):
        parsed = RunDiscovery.parse_run_dirname(run_dir.name)
        if parsed is None:
            logger.warning("Skipping non-conforming run directory %s", run_dir)
            continue
        library, dirname_version, run_number = parsed
        if dirname_version != protocol_version:
            # The protocol directory and the run directory name disagree about
            # the version; non-conforming, exactly as axes_from_run_dir treats
            # it - neither spelling gets to win.
            logger.warning("Skipping non-conforming run directory %s", run_dir)
            continue
        axes = CorpusAxes(
            protocol=protocol,
            protocol_version=protocol_version,
            library=library,
            library_version=UNKNOWN_LIBRARY_VERSION,
            version_axis=VERSION_AXIS_PROTOCOL,
            scenario=library_dir.parent.name,
            run_number=run_number,
            run_dir=run_dir,
            keylog_path=None,
            phase="",
            canonical_phase="",
            phase_timestamp="",
            dump_path=None,
        )
        resolved.append((run_dir, axes))
    resolved.sort(key=_run_order)
    return resolved


def _protocol_dir_axes(dirname: str) -> Optional[Tuple[str, str]]:
    """Map a protocol DIRECTORY name to ``(protocol_name, version)``, or ``None``.

    ``"TLS13"`` -> ``("TLS", "13")`` - the filesystem-free half of what
    :func:`core.corpus_axes.axes_from_run_dir` does per run, which is all the
    counting pass needs (it must not pay the per-run ``meta.json`` and keylog
    syscalls bundled with the full resolution).

    Delegates to :func:`core.corpus_axes.resolve_protocol_dir`, the public seam
    ``corpus_axes`` exposes for exactly this. A local copy of that resolution
    would leave the cheap counting path one registry edit away from disagreeing
    with the axes path about which protocol directories exist - the same
    duplication class as the dump-admission rule in :func:`_dump_filenames`, and
    the same way a denominator drifts away from its enumeration.

    Called once per protocol DIRECTORY (two calls over the measured corpus),
    never per run.
    """
    return resolve_protocol_dir(dirname)


def _version_matches(
    axes: CorpusAxes, protocol_dirname: str, wanted: frozenset
) -> bool:
    """True when ``axes`` satisfies a protocol-version filter.

    Accepts both spellings a caller is likely to type: the bare version
    (``"13"``) and the protocol directory name (``"TLS13"``).
    """
    return (
        axes.protocol_version.lower() in wanted
        or protocol_dirname.lower() in wanted
    )


def _normalize_filter(values: Optional[Iterable[str]]) -> Optional[frozenset]:
    """Lower-case a filter iterable, or ``None`` for "no filter".

    An empty iterable is also ``None``: "filter by nothing" must mean "keep
    everything", never "keep nothing" - the latter would turn a caller's unset
    default into a silently empty sweep.
    """
    if values is None:
        return None
    normalized = frozenset(str(value).lower() for value in values)
    return normalized or None


# -- Per-run unit construction -----------------------------------------------


def _units_for_run(
    run_dir: Path, axes: CorpusAxes, corpus_id: str, corpus_root: Path
) -> Iterator[SweepUnit]:
    """Yield the units for one run directory.

    Loads the run's dump inventory once (``extract_secrets=False``) and
    normalizes the run's phases once, then emits one unit per dump in
    ``(timestamp, filename)`` order - the timestamp PARSED into
    :func:`parse_phase_timestamp`'s tuple, never compared as text.
    """
    try:
        run = RunDiscovery.load_run_directory(run_dir, extract_secrets=False)
    except OSError as exc:
        logger.warning("Skipping unreadable run directory %s: %s", run_dir, exc)
        return
    if run is None:
        logger.warning("Skipping non-conforming run directory %s", run_dir)
        return

    canonical_by_raw = _canonical_phases_for_run(run)
    for dump in sorted(
        run.dumps,
        key=lambda d: (parse_phase_timestamp(d.timestamp), d.path.name),
    ):
        dump_axes = with_canonical_phase(
            axes, canonical_by_raw.get(dump.full_phase, "")
        )
        yield SweepUnit(
            corpus_id=corpus_id,
            protocol_version=dump_axes.protocol_version,
            scenario=dump_axes.scenario,
            library=dump_axes.library,
            library_version=dump_axes.library_version,
            run_number=dump_axes.run_number,
            dump_path=dump.path,
            raw_phase=dump.full_phase,
            canonical_phase=dump_axes.canonical_phase,
            phase_timestamp=dump.timestamp,
            keylog_path=dump_axes.keylog_path,
            corpus_root=corpus_root,
        )


def _canonical_phases_for_run(run: RunDirectory) -> Dict[str, str]:
    """Map each raw phase in ``run`` to its canonical phase.

    One :meth:`PhaseNormalizer.normalize_run` call per run - the normalizer is a
    whole-run operation (its generic suffixes are positional across siblings),
    so there is no meaningful per-dump call.
    """
    return {
        raw: mapping.canonical_phase
        for raw, mapping in PhaseNormalizer().normalize_run(run).items()
    }


# -- Cheap counting ----------------------------------------------------------


def _dump_filenames(run_dir: Path) -> List[str]:
    """Names of the dump files in ``run_dir``, sorted; ``[]`` on error.

    Admission is decided by CALLING :meth:`RunDiscovery.dump_file_for` on the
    name - the one public seam for "is this filename a dump?" - rather than by
    re-deriving the rule from the patterns it is built out of. That is what
    makes this count agree with :func:`enumerate_units`, which admits its dumps
    through :meth:`RunDiscovery.load_run_directory` and therefore through the
    same seam. It is still filename matching only: ``dump_file_for`` reads no
    file, so the count stays as cheap as a directory listing.

    A second, local copy of the rule is precisely how a denominator drifts. The
    one this replaced tested ``name.endswith(suffix)`` over
    :data:`core.discovery.DATASET_DUMP_SUFFIXES`, whose entries carry a LEADING
    DOT, while discovery's real rule (``core.discovery._infer_dump_kind``)
    matches without it: a bare ``gdb_raw.bin`` / ``lldb_raw.bin`` - the exact
    spelling in ``tests/fixtures/datasets/gocryptfs/run_0001/`` - was enumerated
    but never counted. Unfiltered that under-counts; under a
    ``canonical_phases`` filter the drift INVERTS, because the phase filter
    re-parses the (short) name list and the denominator can promise a unit the
    enumeration never yields.
    """
    try:
        with os.scandir(run_dir) as entries:
            names = sorted(
                entry.name
                for entry in entries
                if entry.is_file()
                and RunDiscovery.dump_file_for(Path(entry.name)) is not None
            )
    except (FileNotFoundError, NotADirectoryError):
        return []
    except OSError as exc:
        logger.warning("Skipping unreadable run directory %s: %s", run_dir, exc)
        return []
    return names


def _count_matching_phases(filenames: Sequence[str], phase_filter: frozenset) -> int:
    """Count ``filenames`` whose canonical phase is in ``phase_filter``.

    Reconstructs just enough of a :class:`RunDirectory` from the names already
    listed to run the normalizer: pure CPU, no additional I/O. Only reached when
    the caller actually asked to filter by canonical phase.
    """
    dumps = [
        dump
        for dump in (RunDiscovery.dump_file_for(Path(name)) for name in filenames)
        if dump is not None
    ]
    if not dumps:
        return 0
    run = RunDirectory(path=Path(), library="", protocol_version="", run_number=0)
    run.dumps = dumps
    canonical_by_raw = _canonical_phases_for_run(run)
    return sum(
        1
        for dump in dumps
        if canonical_by_raw.get(dump.full_phase, "").lower() in phase_filter
    )


# -- Digest internals --------------------------------------------------------


def _digest_input_paths(unit: SweepUnit) -> List[Path]:
    """The files whose state a ``"size"`` digest covers, for ``unit``.

    The dump and the run's keylog: both are inputs to the scan, so a change to
    either must invalidate a cached result. A run with no keylog (2 of the 2,600
    measured runs) contributes only its dump.
    """
    paths = [unit.dump_path]
    if unit.keylog_path is not None:
        paths.append(unit.keylog_path)
    return paths


def _size_entries(run_dir: Path, paths: Sequence[Path]) -> List[Tuple[str, int]]:
    """Sorted ``(relpath, size)`` pairs for ``paths``, relative to ``run_dir``.

    Sorted so the digest never depends on argument order, and relative so it
    never depends on where the corpus is mounted. A file that cannot be stat-ed
    records :data:`_MISSING_SIZE` rather than raising - the digest's job is to
    *notice* that state, not to fail on it.
    """
    entries: List[Tuple[str, int]] = []
    for path in paths:
        try:
            size = path.stat().st_size
        except OSError as exc:
            logger.warning("Cannot stat digest input %s: %s", path, exc)
            size = _MISSING_SIZE
        entries.append((_relpath(run_dir, path), size))
    entries.sort()
    return entries


def _relpath(run_dir: Path, path: Path) -> str:
    """``path`` relative to ``run_dir`` as a POSIX string, or its bare name.

    POSIX separators so a digest computed on Windows matches one computed on
    macOS/Linux for the same tree.
    """
    try:
        return path.relative_to(run_dir).as_posix()
    except ValueError:
        return path.name


def _file_sha256(path: Path) -> str:
    """``sha256`` of a file's bytes, streamed; ``""`` when unreadable."""
    digest = hashlib.sha256()
    try:
        with open(path, "rb") as handle:
            for chunk in iter(lambda: handle.read(_CONTENT_CHUNK_BYTES), b""):
                digest.update(chunk)
    except OSError as exc:
        logger.warning("Cannot read digest input %s: %s", path, exc)
        return ""
    return digest.hexdigest()


def _normalize_config_value(value: Any) -> Any:
    """Coerce a config value into a deterministically JSON-encodable form.

    Collections become SORTED lists of strings: ``algorithms=["aes", "chacha"]``
    and ``algorithms=("chacha", "aes")`` request the same work, so they must
    digest the same. Anything JSON cannot encode falls back to ``repr`` so an
    exotic value degrades to "stable but opaque" rather than raising.
    """
    if isinstance(value, (str, bool, int, float)) or value is None:
        return value
    if isinstance(value, Path):
        return value.as_posix()
    if isinstance(value, (list, tuple, set, frozenset)):
        return sorted(str(item) for item in value)
    if isinstance(value, dict):
        return {str(key): _normalize_config_value(val) for key, val in value.items()}
    return repr(value)


def _canonical_json(payload: Any) -> str:
    """Serialize ``payload`` canonically: sorted keys, no incidental whitespace.

    ``sort_keys=True`` plus a fixed separator makes the encoding - and therefore
    every digest in this module - byte-identical across processes, machines and
    Python versions. ``ensure_ascii=True`` keeps it byte-stable regardless of
    the caller's locale.
    """
    return json.dumps(
        payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    )


__all__ = [
    "DEFAULT_DIGEST_LEVEL",
    "DIGEST_LEVELS",
    "RECHECK_INPUTS_SETTING",
    "SWEEP_SCHEMA_VERSION",
    "UNIT_KEY_VERSION",
    "DigestComparison",
    "IncomparableDigestError",
    "InputsDigest",
    "SweepUnit",
    "config_digest",
    "count_units",
    "enumerate_units",
    "inputs_digest",
    "inputs_digest_with_level",
    "parse_phase_timestamp",
    "resolve_digest_level",
    "unit_key",
]
