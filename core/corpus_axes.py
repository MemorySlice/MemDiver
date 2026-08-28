"""Canonical corpus-axis vocabulary: how one dump path decomposes into axes.

Every corpus-scale workstream (survival matrix, regression detection, corpus
proof) needs to agree on *what a dump is an instance of*: which protocol,
which protocol version, which library, which library build, which scenario,
which run, which lifecycle phase. Historically each consumer re-derived that
from the path with its own regex and its own spelling of the field names.
This module derives it exactly once so nothing invents a second spelling.

The corpus layout this parses::

    <root>/<TLS12|TLS13>/<scenario>/<library>/<library>_run_<ver>_<n>/
        20251020_171845_606711_pre_server_key_update.dump
        keylog.csv
        run_data/traffic.pcap

Resolution walks *up* from the run directory:

* ``run_dir.name`` -> :meth:`core.discovery.RunDiscovery.parse_run_dirname`
  yields ``(library, protocol_version, run_number)``;
* ``run_dir.parent`` is the library grouping directory (positional only: the
  authoritative library token is the one encoded in the run directory name);
* ``run_dir.parent.parent.name`` is the **scenario**;
* ``run_dir.parent.parent.parent.name`` is the protocol directory
  (``TLS12`` / ``TLS13``), matched against the ``dir_prefix`` of the
  descriptors in :data:`core.protocols.REGISTRY` to yield the protocol name
  plus a cross-check of the version encoded in the run directory name.

Both entry points return ``None`` (never raise) for a path that does not
conform to that layout; callers read that as "not a corpus run".

The version axis
----------------
Today the corpus varies the *protocol* version (TLS 1.2 vs TLS 1.3) and holds
each library at a single build, so every real run resolves to
``(version_axis="protocol_version", library_version="unknown")``. A future
multi-build corpus will vary the *library* version instead. Rather than
hard-coding ``protocol_version`` as the only version concept, every axes record
carries both a ``library_version`` and a ``version_axis`` label naming which
dimension is the one being varied. The resolution hook for the future case
already exists (see :func:`_resolve_library_version`), so downstream consumers
group by ``version_axis`` and need no code change when the corpus grows a build
dimension.
"""

from __future__ import annotations

import dataclasses
import logging
from dataclasses import dataclass
from pathlib import Path
from typing import Optional, Tuple

from .dataset_metadata import load_run_meta
from .discovery import DUMP_PATTERN, RunDiscovery
from .protocols import REGISTRY

logger = logging.getLogger("memdiver.core.corpus_axes")

#: Placeholder library version used until the corpus grows a build dimension.
UNKNOWN_LIBRARY_VERSION = "unknown"

#: ``CorpusAxes.version_axis`` value when the varied dimension is the protocol
#: version (the corpus as it exists today).
VERSION_AXIS_PROTOCOL = "protocol_version"

#: ``CorpusAxes.version_axis`` value when a concrete library build was resolved
#: and is therefore the varied dimension.
VERSION_AXIS_LIBRARY = "library_version"

#: Per-run keylog sidecar written by the capture harness.
KEYLOG_FILENAME = "keylog.csv"

#: Attribute consulted on a parsed ``meta.json`` payload for the library build.
#: No corpus run carries it today (there are zero ``meta.json`` files in the
#: TLS corpus); reading it via ``getattr`` keeps the hook forward-compatible
#: without coupling this module to the shape of :class:`DatasetMeta`.
_META_LIBRARY_VERSION_FIELD = "library_version"


@dataclass(frozen=True)
class CorpusAxes:
    """The axes one corpus dump (or run) is an instance of.

    Frozen because these records are used as identity keys: a survival matrix
    cell, a regression comparison pair and a proof ledger row are all keyed by
    some projection of these fields, so they must never mutate underneath a
    dictionary.

    Fields:
        protocol: Protocol name resolved from the protocol directory prefix
            through :data:`core.protocols.REGISTRY` (e.g. ``"TLS"``).
        protocol_version: Version encoded in the protocol directory and
            cross-checked against the run directory name (``"12"`` / ``"13"``).
        library: Library token from the run directory name (e.g. ``"openssl"``).
        library_version: The concrete library build, or
            :data:`UNKNOWN_LIBRARY_VERSION` when the corpus does not record one.
        version_axis: Which version dimension the corpus varies for this run:
            :data:`VERSION_AXIS_PROTOCOL` or :data:`VERSION_AXIS_LIBRARY`.
        scenario: Scenario directory name, e.g.
            ``"100_iterations_Abort_KeyUpdate"``.
        run_number: Run index from the run directory name.
        run_dir: The run directory itself.
        keylog_path: ``run_dir/keylog.csv`` when it exists, else ``None``.
        phase: The RAW phase as written in the dump filename, prefix included,
            e.g. ``"pre_server_key_update"``. Empty when unknown (a run-level
            record, or a dump filename carrying no phase markers).
        canonical_phase: Always ``""`` as produced by
            :func:`axes_from_run_dir` / :func:`axes_from_dump_path` - see the
            note below - and filled in by :func:`with_canonical_phase`.
        phase_timestamp: The dump filename's timestamp prefix, e.g.
            ``"20251020_171845_606711"``. Empty when absent.
        dump_path: The dump this record describes, or ``None`` for a run-level
            record.

    Why ``canonical_phase`` is deliberately left empty here
    -------------------------------------------------------
    A canonical phase is NOT a property of a single path. It is derived by
    :class:`core.phase_normalizer.PhaseNormalizer` from the *set of sibling
    dumps* in a run: the normalizer sorts a run's dumps by timestamp and hands
    out the generic canonical suffixes positionally
    (``handshake_end``, ``second_event``, ``event_3`` ...). Adding one dump to a
    run can therefore re-map the canonical phase of its siblings.

    If these functions guessed a canonical phase from the filename alone, the
    result would be a *mutating identity key*: the same file would key a
    different survival-matrix cell before and after an unrelated sibling
    appeared, silently splitting or merging corpus statistics. So the field
    exists (consumers want it) but only a caller that has already run the
    normalizer over the whole run may set it, via
    :func:`with_canonical_phase`.
    """

    protocol: str
    protocol_version: str
    library: str
    library_version: str
    version_axis: str
    scenario: str
    run_number: int
    run_dir: Path
    keylog_path: Optional[Path]
    phase: str
    canonical_phase: str
    phase_timestamp: str
    dump_path: Optional[Path]


def axes_from_run_dir(
    run_dir, *, library_version: Optional[str] = None,
) -> Optional[CorpusAxes]:
    """Decompose a corpus *run directory* into its axes.

    Returns ``None`` - never raises - when ``run_dir`` does not conform to the
    corpus layout documented at module level (an unparseable run directory
    name, too shallow a path, an unrecognised protocol directory, or a protocol
    version that disagrees with the run directory name).

    ``library_version`` overrides the resolved library build; see
    :func:`_resolve_library_version` for the full order.

    The returned record is run-level: ``phase``, ``canonical_phase`` and
    ``phase_timestamp`` are ``""`` and ``dump_path`` is ``None``.
    """
    run_dir = Path(run_dir)

    parsed = RunDiscovery.parse_run_dirname(run_dir.name)
    if parsed is None:
        return None
    library, dirname_version, run_number = parsed

    library_dir = run_dir.parent
    scenario_dir = library_dir.parent
    protocol_dir = scenario_dir.parent
    if not (library_dir.name and scenario_dir.name and protocol_dir.name):
        return None

    resolved_protocol = _resolve_protocol_dir(protocol_dir.name)
    if resolved_protocol is None:
        return None
    protocol, protocol_version = resolved_protocol
    if protocol_version != dirname_version:
        # The protocol directory and the run directory name disagree about the
        # version; treat the path as non-conforming rather than picking one.
        return None

    effective_library_version = _resolve_library_version(run_dir, library_version)

    keylog_path = run_dir / KEYLOG_FILENAME
    return CorpusAxes(
        protocol=protocol,
        protocol_version=protocol_version,
        library=library,
        library_version=effective_library_version,
        version_axis=_version_axis_for(effective_library_version),
        scenario=scenario_dir.name,
        run_number=run_number,
        run_dir=run_dir,
        keylog_path=keylog_path if _is_readable_file(keylog_path) else None,
        phase="",
        canonical_phase="",
        phase_timestamp="",
        dump_path=None,
    )


def axes_from_dump_path(
    dump_path, *, library_version: Optional[str] = None,
) -> Optional[CorpusAxes]:
    """Decompose a corpus *dump path* into its axes.

    Resolves the run-level axes from ``dump_path.parent`` and adds the RAW
    ``phase`` plus ``phase_timestamp`` read from the dump filename. A filename
    that carries no phase markers still yields a record (with both fields
    empty) as long as the run directory conforms.

    Returns ``None`` - never raises - when the run directory does not conform.
    """
    dump_path = Path(dump_path)
    axes = axes_from_run_dir(dump_path.parent, library_version=library_version)
    if axes is None:
        return None

    phase, phase_timestamp = _parse_phase_from_filename(dump_path.name)
    return dataclasses.replace(
        axes, phase=phase, phase_timestamp=phase_timestamp, dump_path=dump_path,
    )


def with_canonical_phase(axes: CorpusAxes, canonical_phase: str) -> CorpusAxes:
    """Return a copy of ``axes`` carrying ``canonical_phase``.

    Thin :func:`dataclasses.replace` wrapper, and the ONLY sanctioned way to
    populate the field. Call it with a value obtained from
    :class:`core.phase_normalizer.PhaseNormalizer` after normalizing the whole
    run: the canonical phase is positional across a run's sibling dumps, so it
    cannot be inferred from a single path (see :class:`CorpusAxes`).
    """
    return dataclasses.replace(axes, canonical_phase=canonical_phase)


def resolve_protocol_dir(dirname: str) -> Optional[Tuple[str, str]]:
    """Public seam for the protocol-DIRECTORY -> ``(protocol, version)`` rule.

    ``"TLS13"`` -> ``("TLS", "13")``; ``None`` for a directory name this
    registry does not recognise.

    This exists for the same reason
    :meth:`core.discovery.RunDiscovery.dump_file_for` does: the rule is
    genuinely useful outside this module - ``engine.sweep_plan``'s cheap
    counting pass needs the protocol resolution WITHOUT the per-run
    ``meta.json`` and keylog syscalls that :func:`axes_from_run_dir` bundles
    with it - and any second implementation of it would be free to drift out of
    agreement with the axes resolution, which is how a corpus denominator stops
    matching its enumeration. It delegates to the private
    :func:`_resolve_protocol_dir`, which stays in place for the internal call
    site.
    """
    return _resolve_protocol_dir(dirname)


# -- Internals ---------------------------------------------------------------


def _resolve_protocol_dir(dirname: str) -> Optional[Tuple[str, str]]:
    """Map a protocol directory name to ``(protocol_name, version)``.

    ``"TLS13"`` resolves to ``("TLS", "13")`` by matching the registry
    descriptors' ``dir_prefix`` against the directory name and requiring the
    remainder to be one of that descriptor's declared versions. Returns
    ``None`` for an unrecognised directory.
    """
    for name in REGISTRY.list_protocols():
        descriptor = REGISTRY.get(name)
        if descriptor is None or not descriptor.dir_prefix:
            continue
        if not dirname.startswith(descriptor.dir_prefix):
            continue
        version = dirname[len(descriptor.dir_prefix):]
        if version in descriptor.versions:
            # Resolve back through the registry's own prefix index so the
            # returned name is the registry's, not a local guess.
            owner = REGISTRY.get_by_dir_prefix(descriptor.dir_prefix) or descriptor
            return owner.name, version
    return None


def _resolve_library_version(run_dir: Path, override: Optional[str]) -> str:
    """Resolve the library build for ``run_dir``.

    Order: an explicit caller ``override``, then a ``library_version`` field on
    the run's parsed ``meta.json`` if one ever appears, then
    :data:`UNKNOWN_LIBRARY_VERSION`.

    The middle step is the forward-compatibility hook for a multi-build corpus.
    It costs one ``meta.json`` probe per call, which matters on a full-corpus
    sweep; pass ``override`` (or resolve the axes once per run and reuse the
    record) when scanning many dumps in the same run.
    """
    if override:
        return override
    try:
        meta = load_run_meta(run_dir)
    except OSError as exc:
        # load_run_meta tolerates malformed JSON but reaches the filesystem via
        # ``Path.is_file()``, which only swallows ENOENT/ENOTDIR/EBADF/ELOOP --
        # so a mode-000 run directory (EACCES) or an over-long name
        # (ENAMETOOLONG) propagates and would abort a whole corpus sweep on one
        # unreadable directory. These resolvers promise "return None, never
        # raise", so an unreadable probe degrades to "no recorded version".
        # No exc_info: a sweep walks thousands of directories and an unreadable
        # one is an expected, recoverable condition, so a full traceback per
        # occurrence would bury the signal it is meant to report.
        logger.warning("could not read run metadata under %s: %s", run_dir, exc)
        return UNKNOWN_LIBRARY_VERSION
    if meta is not None:
        recorded = getattr(meta, _META_LIBRARY_VERSION_FIELD, "") or ""
        if recorded:
            return str(recorded)
    return UNKNOWN_LIBRARY_VERSION


def _is_readable_file(path: Path) -> bool:
    """``path.is_file()`` that cannot raise.

    ``Path.is_file()`` only swallows ENOENT/ENOTDIR/EBADF/ELOOP, so a parent
    directory the process cannot traverse (EACCES) or a component over the
    platform name limit (ENAMETOOLONG) propagates. Every entry point in this
    module documents "returns None, never raises" because a corpus sweep walks
    thousands of directories it does not control -- one unreadable run must be
    skipped, not fatal.
    """
    try:
        return path.is_file()
    except OSError:
        return False


def _version_axis_for(library_version: str) -> str:
    """Name the version dimension implied by a resolved ``library_version``."""
    if library_version and library_version != UNKNOWN_LIBRARY_VERSION:
        return VERSION_AXIS_LIBRARY
    return VERSION_AXIS_PROTOCOL


def _parse_phase_from_filename(filename: str) -> Tuple[str, str]:
    """Return ``(raw_phase, timestamp)`` for a dump filename.

    ``"20251020_171845_606711_pre_server_key_update.dump"`` yields
    ``("pre_server_key_update", "20251020_171845_606711")``. Non-phased dataset
    dumps (``gcore.core``, ``gdb_raw.bin`` ...) yield ``("", "")``.
    """
    match = DUMP_PATTERN.match(filename)
    if match is None:
        return "", ""
    return f"{match.group(2)}_{match.group(3)}", match.group(1)
