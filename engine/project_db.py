"""ProjectDB - DuckDB + Ibis persistent analysis database.

Schema shape, and why it has the tables it has
----------------------------------------------
``findings`` is an APPEND-ONLY HIT table. In it, "we scanned this dump for
``CLIENT_RANDOM`` and it was gone" and "we never opened this dump" are BOTH
simply the absence of a row, and no number of extra columns can separate them.
A three-state survival cell (found / looked-and-absent / not-applicable) needs a
POSITIVE RECORD OF THE ATTEMPT, which is what ``survival`` is for. Likewise the
denominator — "the keylog says this secret exists" — lives in ``keylog.csv``,
not in any hit; materialising it in ``expected_secrets`` is what keeps the
corpus dashboard a DB read instead of a re-walk of thousands of keylog files.

So the v2 schema is:

``projects`` / ``dumps`` / ``analysis_runs`` / ``findings`` / ``ground_truth``
    The v1 tables, each widened with the corpus axes (library, protocol and
    library version, scenario, run number, phase) that the analysis engine
    already knew but used to discard on the way to disk.
``expected_secrets``
    Denominator ledger: one row per (corpus run, secret_type) the keylog
    declares.
``survival``
    Observation ledger at cell grain: one row per (dump, secret_type) actually
    looked at, with a three-state reading of ``present`` (see
    :meth:`ProjectDB.add_survival_batch`).
``schema_meta``
    Single ``schema_version`` row driving the forward migration in
    :meth:`ProjectDB.open`.

v3 adds the SWEEP CONTROL PLANE and closes three silent-miscount holes:

``sweeps`` / ``sweep_units``
    The resume/watermark ledger for a corpus sweep. ``sweeps`` records WHICH
    slice of the corpus a sweep covered (the filter set), so a bounded CI run
    can never be published as a full-corpus result; ``sweep_units`` records the
    per-unit watermark. Unlike the findings tables these two are MUTABLE — a
    unit row is UPDATEd as it moves through its states.
``survival.status`` / ``survival.present``
    ``status`` separates "searched" from "opened it and could not read it", so a
    missing ``present`` can no longer write SQL NULL — a value that both
    ``WHERE present`` and ``WHERE NOT present`` exclude, i.e. a row that counts
    as attempted but as neither found nor absent.
``survival.format_name`` / ``survival.size_for_view``
    Which byte stream was actually searched, so a ``✗`` caused by a format (a
    VAS projection or a region view) is distinguishable from a real absence.
``expected_secrets.dumps_in_run`` / ``expected_secrets.keylog_status``
    A corpus run with a complete keylog but zero dumps renders as "no data WITH
    A REASON" instead of vanishing from the denominator.

v4 adds the DIFFERENTIAL LEDGER — the tool's core multi-dump workflow, which
until now persisted NOTHING:

``consensus_runs``
    One row per N-dump comparison: which dumps (ordered), how they were put
    into correspondence (``alignment_method`` plus its provenance), the class
    boundaries actually in force, and the resulting four-class byte histogram.
    The thresholds and the alignment method are ON THE ROW because a class
    histogram without them is uninterpretable — the same dumps under a
    different boundary set, or a flat-offset fallback instead of a VA
    alignment, produce a different and non-comparable result.
``candidate_regions``
    One row per ranked candidate under a ``consensus_runs`` row: offset,
    length, ``byte_class``, mean variance, mean entropy, ``rank`` and the score
    components that produced it. Ranked candidates were previously loose
    ``.npy`` / ``.json`` files plus a 30-minute in-process dict that died with
    the server, so a result could not be re-read, compared or cited.
"""

import datetime
import json
import logging
import os
import uuid
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional, Sequence, Tuple

from memdiver.core.install_hints import BASE_INSTALL_HINT
from memdiver.core.service_errors import CapabilityError, ErrorCategory
from memdiver.core.variance import ByteClass
from memdiver.msl.hashing import hash_bytes

logger = logging.getLogger("memdiver.engine.project_db")

try:
    import duckdb
    import ibis
    HAS_DUCKDB = True
except ImportError:
    HAS_DUCKDB = False


def check_deps() -> Dict[str, object]:
    """Check which optional dependencies are available.

    Reuses the module-level :data:`HAS_DUCKDB` probe (both ``duckdb`` and
    ``ibis`` are imported together there) rather than re-importing.

    The return type is ``Dict[str, object]``, not ``Dict[str, bool]``: the
    ``*_version`` entries are VERSION STRINGS. The annotation used to claim
    ``bool`` while the local was already declared ``object`` — a caller reading
    the signature and doing ``if deps["duckdb_version"]:`` on a bool would have
    been type-checked against a lie.
    """
    deps: Dict[str, object] = {"duckdb": HAS_DUCKDB, "ibis": HAS_DUCKDB}
    if HAS_DUCKDB:
        deps["duckdb_version"] = duckdb.__version__
        deps["ibis_version"] = ibis.__version__
    deps["ready"] = bool(deps["duckdb"]) and bool(deps["ibis"])
    return deps

def default_db_path() -> Path:
    """Return default DB path (~/.memdiver/project.duckdb)."""
    from memdiver.core.constants import memdiver_home
    return memdiver_home() / "project.duckdb"

def install_hint() -> str:
    """Return a user-friendly install command string.

    DuckDB + Ibis are base dependencies, so a missing one is a broken
    environment rather than an un-installed extra; point at the repair.
    """
    return BASE_INSTALL_HINT

#: Bump whenever :data:`_ADDED_COLUMNS` or :data:`_TABLE_COLUMNS` changes.
#: Stored in the ``schema_meta`` table so :meth:`ProjectDB.open` can tell a
#: v1 database (no ``schema_meta`` row at all) from an up-to-date one.
_SCHEMA_VERSION = 4

# -- method vocabulary ----------------------------------------------------
#
# ``findings.method``, ``ground_truth.method`` and ``survival.method`` all draw
# from this CLOSED set. It exists so a reader can tell a cheap corpus-wide
# observation apart from an expensive cryptographically-confirmed one without
# string-sniffing, and so precision/recall is never computed over rows that
# were never actually proven.

#: Keylog-truth substring scan: the secret bytes from ``keylog.csv`` were
#: searched for verbatim in the dump. Cheap, corpus-wide, NOT a cryptographic
#: proof. This is what the survival matrix is built from.
METHOD_KEYLOG_SUBSTRING = "keylog_substring"

#: :class:`engine.correlator.SearchCorrelator` running inside
#: :class:`engine.pipeline.AnalysisPipeline` (consensus-aware exact match).
METHOD_CONSENSUS_SEARCH = "consensus_search"

#: Entropy/brute-force candidate search over unlabelled regions.
METHOD_BRUTE_FORCE = "brute_force"

#: An oracle confirmed the candidate actually decrypts real traffic
#: (AEAD verifier or pcap/tshark). Expensive; this is what precision/recall
#: is computed over.
METHOD_ORACLE = "oracle"

#: The closed vocabulary, in increasing order of evidential strength.
METHODS = (
    METHOD_KEYLOG_SUBSTRING,
    METHOD_CONSENSUS_SEARCH,
    METHOD_BRUTE_FORCE,
    METHOD_ORACLE,
)

#: HARD RULE: the corpus survival pass must never write
#: ``confirmed_by='pcap'`` or ``confirmed_by='oracle'``. It only ever proves
#: "these keylog bytes are/are not present in this dump" — it runs no
#: decryption, so labelling its rows as oracle-confirmed would inflate the
#: proof ledger with unproven claims. Those two labels belong exclusively to
#: :meth:`ProjectDB.record_ground_truth_run` and the pcap oracle path.
SURVIVAL_FORBIDDEN_CONFIRMED_BY = ("pcap", "oracle")

# -- survival status vocabulary -------------------------------------------
#
# ``survival.status`` says WHAT HAPPENED when the cell was attempted, which is
# strictly more than ``present`` can express. Without it a writer that could not
# read the dump had exactly two options, both wrong: claim ``present = FALSE``
# (a false absence) or write no row at all (indistinguishable from never having
# tried). A missing ``present`` used to land in the column as SQL NULL, and
# because BOTH ``WHERE present`` and ``WHERE NOT present`` exclude NULL such a
# row counted toward ``runs_attempted`` but toward neither found nor absent —
# a silent deflation of the numerator.

#: The dump was opened and searched. ``present`` MUST be non-NULL. This is the
#: ONLY status that counts toward ``runs_attempted``.
SURVIVAL_STATUS_SEARCHED = "searched"

#: WE OPENED THE RIGHT BYTES AND COULD NOT READ THEM: the dump was reached and
#: the byte stream a search would have covered was established, but reading it
#: failed (truncated file, a view exposing 0 bytes, locked encrypted source, an
#: I/O error mid-scan). ``present`` stays NULL and the row does NOT count as
#: attempted; it exists so the cell renders "no data with a reason" rather than
#: a false absence.
#:
#: An UNSUPPORTED SOURCE FORMAT is deliberately NOT this status, and writes no
#: row at all — it renders as "not attempted" (``—``). The distinction is the
#: strength of the claim: ``unreadable`` asserts we looked at the correct byte
#: stream and it would not yield, whereas a refused format means we never
#: established WHICH stream a search would have covered (a region view with
#: holes and a VAS projection are different streams from the raw container), so
#: "we looked and failed" is more than the evidence supports.
#: :data:`engine.survival_scan.SCAN_OUTCOME_UNSUPPORTED_FORMAT` is that
#: verdict, and it is the unit-level outcome — not a row status — that carries
#: it.
SURVIVAL_STATUS_UNREADABLE = "unreadable"

#: The attempt itself failed (the worker raised). WRITES NO ROW — an errored
#: attempt is not an observation, and recording one would let a crash masquerade
#: as evidence. Accepted as an input so a caller can hand the writer a whole
#: batch and let it drop the failures.
SURVIVAL_STATUS_ERROR = "error"

#: The closed status vocabulary accepted by :meth:`ProjectDB.add_survival_batch`.
SURVIVAL_STATUSES = (
    SURVIVAL_STATUS_SEARCHED,
    SURVIVAL_STATUS_UNREADABLE,
    SURVIVAL_STATUS_ERROR,
)


def _validate_choice(value: str, allowed: Tuple[str, ...], where: str,
                     code: str) -> str:
    """Return *value* if it is in the closed set *allowed*, else raise.

    The shared shape behind every closed-vocabulary guard in this module. Unlike
    :func:`_validate_method` there is NO exempt empty string here: a sweep row
    has a real state from the moment it is written, and ``''`` would be an
    extra, undocumented one.
    """
    if not isinstance(value, str) or value not in allowed:
        raise CapabilityError(
            "unknown " + where + " " + repr(value) + "; expected one of "
            + ", ".join(repr(v) for v in allowed),
            category=ErrorCategory.INVALID_INPUT,
            code=code,
        )
    return value


def _validate_method(method: str, *, allowed: Tuple[str, ...] = METHODS,
                     where: str = "method") -> str:
    """Return *method* if it is in *allowed* (or the EMPTY STRING), else raise.

    An EMPTY STRING method stays legal: it is the column default and means "the
    writer did not classify this row", which is what every pre-v3 row already
    holds. Anything else must come from the closed :data:`METHODS` vocabulary —
    the point of that vocabulary is that a reader can tell a cheap corpus-wide
    observation from a cryptographically-confirmed one without string-sniffing,
    and one typo'd writer is enough to make that untrue forever.

    ONLY ``""`` IS EXEMPT, not every falsy value. The test used to be
    ``if method and ...``, which waved through every other falsy object and let
    two out-of-vocabulary values reach the column:

    * ``method=0`` stored the STRING ``'0'`` — a non-empty method outside the
      vocabulary, so ``WHERE method = ''`` (unclassified) and
      ``WHERE method = 'oracle'`` (proven) both miss it;
    * ``method=None`` stored SQL NULL — excluded by BOTH ``WHERE method = ''``
      AND ``WHERE method <> 'oracle'``, i.e. exactly the NULL trap that
      :data:`SURVIVAL_STATUS_SEARCHED` was introduced to close one table over.

    A non-``str`` is therefore rejected outright rather than silently coerced.
    """
    if not isinstance(method, str):
        raise CapabilityError(
            "invalid " + where + " " + repr(method) + "; expected a string"
            " from " + ", ".join(repr(m) for m in allowed) + " (or '')",
            category=ErrorCategory.INVALID_INPUT,
            code="project_db.unknown_method",
        )
    if method == "":
        return method
    return _validate_choice(method, allowed, where,
                            "project_db.unknown_method")


# -- sweep control-plane vocabularies -------------------------------------
#
# ``sweeps.status`` and ``sweep_units.status`` were documented in the DDL
# comments and nowhere else, so nothing could validate them and every caller
# had to hand-roll the strings. They are closed sets for the same reason
# :data:`METHODS` is: a resume decides what to re-run by comparing against
# them, and one typo'd status makes a finished unit look pending forever.

#: A sweep is planned, then runs, then reaches exactly one terminal state.
SWEEP_STATUSES = ("pending", "running", "completed", "failed", "cancelled")

#: A unit is planned, then runs, then reaches exactly one terminal state.
#: ``skipped`` is terminal too: it means "deliberately not swept" (filtered
#: out, or already covered by a previous sweep), which is NOT the same as
#: ``done`` and must not be counted as coverage.
SWEEP_UNIT_STATUSES = ("pending", "running", "done", "failed", "skipped")

#: Both are validated by :func:`_validate_choice`, defined above with the rest
#: of the closed-vocabulary guards.


# -- v4: differential-analysis vocabularies -------------------------------
#
# ``consensus_runs.alignment_method`` records HOW the N byte streams were put
# into correspondence before they were compared. It is a closed set for the
# same reason :data:`METHODS` is: a variance figure produced by ASLR-aware
# module+offset alignment and one produced by the flat-offset fallback are NOT
# comparable, and a reader that cannot tell them apart will compare them
# anyway. The producer side of this (``AlignmentReport``) is item A1's.

# Imported, never re-spelled: ``core.region_align`` owns this vocabulary and
# the producer side validates against the same tuple, so the column and the
# ``AlignmentReport`` that fills it cannot drift apart.
from memdiver.core.region_align import (  # noqa: E402
    ALIGNMENT_FILE_OFFSET,
    ALIGNMENT_METHODS,
    ALIGNMENT_MODULE_OFFSET,
    ALIGNMENT_VIRTUAL_ADDRESS,
)

#: ``candidate_regions.byte_class`` — the lower-cased names of
#: :class:`core.variance.ByteClass`, DERIVED from the enum rather than
#: re-spelled. The enum is the single source of truth for the four-way
#: classification; a hand-written tuple here would be a second one, and the
#: day a fifth class is added the DB would silently reject it.
BYTE_CLASSES: Tuple[str, ...] = tuple(c.name.lower() for c in ByteClass)

#: Class-boundary defaults for :meth:`ProjectDB.add_consensus_run`, MIRRORING
#: today's ``core.variance`` module constants rather than importing them.
#: Deliberate, and the one duplication in this module: the ``DEFAULT`` clauses
#: in the ``consensus_runs`` DDL below must be SQL literals anyway, so the
#: values already exist twice; and item A2 moves the boundaries out of module
#: constants and into the config path, at which point an import here would
#: break. Every producer is expected to pass the boundaries it actually used —
#: these defaults exist so a caller that has not been updated writes today's
#: real values instead of zeroes.
_DEFAULT_INVARIANT_MAX = 0.0
_DEFAULT_STRUCTURAL_MAX = 200.0
_DEFAULT_POINTER_MAX = 3000.0


def _require_nonempty(value: str, *, where: str, code: str, why: str) -> str:
    """Return *value* when it is a non-empty ``str``, else raise.

    Shared by the two ledger writers' ``sweep_id`` / ``dump_path`` guards, both
    of which fail SILENTLY rather than loudly when the field is empty — the row
    still writes, it just merges with somebody else's.
    """
    if not isinstance(value, str) or value == "":
        raise CapabilityError(
            where + " must be a non-empty string (got " + repr(value) + "). "
            + why,
            category=ErrorCategory.INVALID_INPUT,
            code=code,
        )
    return value

# -- schema ---------------------------------------------------------------
#
# Column definitions are the SINGLE source of truth for this schema: the
# ``CREATE TABLE`` statements, the ``ALTER TABLE ... ADD COLUMN`` migration and
# every ``INSERT`` column list are all generated from them below. That is
# deliberate — a hand-written CREATE plus a hand-written ALTER is exactly how a
# freshly-created database ends up with a different column ORDER than a
# migrated one.
#
# Only identifiers that come from these literal, frozen module-level tuples are
# ever interpolated into SQL text. No caller-supplied value reaches a statement
# string; every value is bound as a ``$n`` parameter.

#: The v1 (pre-migration) columns of each legacy table, in ``CREATE`` order.
_V1_COLUMNS: Dict[str, Tuple[Tuple[str, str], ...]] = {
    "projects": (
        ("project_id", "VARCHAR PRIMARY KEY"),
        ("name", "VARCHAR"),
        ("created_at", "VARCHAR"),
        ("description", "VARCHAR DEFAULT ''"),
    ),
    "dumps": (
        ("dump_id", "VARCHAR PRIMARY KEY"),
        ("project_id", "VARCHAR"),
        ("file_path", "VARCHAR"),
        ("file_type", "VARCHAR"),
        ("file_size", "BIGINT"),
        ("added_at", "VARCHAR"),
        ("metadata_json", "VARCHAR DEFAULT '{}'"),
    ),
    "analysis_runs": (
        ("run_id", "VARCHAR PRIMARY KEY"),
        ("project_id", "VARCHAR"),
        ("dump_id", "VARCHAR"),
        ("started_at", "VARCHAR"),
        ("finished_at", "VARCHAR"),
        ("status", "VARCHAR DEFAULT 'running'"),
        ("config_json", "VARCHAR DEFAULT '{}'"),
    ),
    "findings": (
        ("finding_id", "VARCHAR PRIMARY KEY"),
        ("run_id", "VARCHAR"),
        ("finding_type", "VARCHAR"),
        ("offset", "BIGINT"),
        ("length", "INTEGER"),
        ("value_hex", "VARCHAR"),
        ("value_text", "VARCHAR"),
        ("confidence", "DOUBLE DEFAULT 1.0"),
        ("metadata_json", "VARCHAR DEFAULT '{}'"),
        ("created_at", "VARCHAR"),
    ),
    "ground_truth": (
        ("gt_id", "VARCHAR PRIMARY KEY"),
        ("run_id", "VARCHAR"),
        ("offset", "BIGINT"),
        ("length", "INTEGER"),
        ("key_hex", "VARCHAR"),
        ("secret_type", "VARCHAR"),
        ("cipher", "VARCHAR"),
        ("confirmed_by", "VARCHAR"),
        ("library", "VARCHAR"),
        ("version", "VARCHAR"),
        ("created_at", "VARCHAR"),
    ),
}

#: Columns added by v2, appended to each legacy table in this exact order.
#: Frozen: the tuple order is part of the on-disk contract, because a migrated
#: database gets these appended by ``ALTER TABLE`` while a fresh one gets them
#: from ``CREATE TABLE`` — the two must agree.
#:
#: Every entry carries a ``DEFAULT`` (except ``findings.verified``, which is
#: deliberately three-valued) so the ``ALTER`` back-fills pre-existing rows
#: instead of leaving them NULL.
_ADDED_COLUMNS: Dict[str, Tuple[Tuple[str, str], ...]] = {
    "projects": (
        ("library", "VARCHAR DEFAULT ''"),
        ("protocol_version", "VARCHAR DEFAULT ''"),
        ("library_version", "VARCHAR DEFAULT 'unknown'"),
        ("version_axis", "VARCHAR DEFAULT 'protocol_version'"),
        ("scenario", "VARCHAR DEFAULT ''"),
        ("protocol", "VARCHAR DEFAULT ''"),
    ),
    "dumps": (
        ("phase", "VARCHAR DEFAULT ''"),
        ("canonical_phase", "VARCHAR DEFAULT ''"),
        ("run_number", "INTEGER DEFAULT 0"),
        ("library", "VARCHAR DEFAULT ''"),
        ("run_id", "VARCHAR DEFAULT ''"),
    ),
    "analysis_runs": (
        ("phase", "VARCHAR DEFAULT ''"),
        ("canonical_phase", "VARCHAR DEFAULT ''"),
        ("run_number", "INTEGER DEFAULT 0"),
        ("library", "VARCHAR DEFAULT ''"),
        ("protocol_version", "VARCHAR DEFAULT ''"),
        ("library_version", "VARCHAR DEFAULT 'unknown'"),
        ("scenario", "VARCHAR DEFAULT ''"),
        ("run_dir", "VARCHAR DEFAULT ''"),
        ("keylog_path", "VARCHAR DEFAULT ''"),
        ("pcap_path", "VARCHAR DEFAULT ''"),
    ),
    "findings": (
        ("secret_type", "VARCHAR DEFAULT ''"),
        # secret / string / crypto_key. Lets an aggregator filter on `kind`
        # instead of string-sniffing the free-form `finding_type` (which keeps
        # its historical value verbatim for `finding_counts` /
        # `query_findings(finding_type=)`).
        ("kind", "VARCHAR DEFAULT 'secret'"),
        ("method", "VARCHAR DEFAULT ''"),
        ("dump_path", "VARCHAR DEFAULT ''"),
        ("phase", "VARCHAR DEFAULT ''"),
        ("canonical_phase", "VARCHAR DEFAULT ''"),
        ("library", "VARCHAR DEFAULT ''"),
        # Three-valued on purpose: NULL = never verified, FALSE = verifier ran
        # and rejected, TRUE = verifier confirmed. A DEFAULT of FALSE would
        # turn "not checked" into "checked and wrong".
        ("verified", "BOOLEAN DEFAULT NULL"),
        # v3. `SecretHit.run_id` is the CORPUS RUN NUMBER (`engine/results.py`),
        # and every persistence path serialized it and then dropped it on the
        # floor — there was no column to put it in, so "which of the 2,600 runs
        # produced this finding" was unrecoverable from the DB. Named
        # `run_number` to match the identically-meaning column on `dumps`,
        # `analysis_runs`, `survival` and `expected_secrets`; the bare name
        # `run_id` is already taken here by the FK to `analysis_runs`.
        ("run_number", "INTEGER DEFAULT 0"),
    ),
    "ground_truth": (
        ("phase", "VARCHAR DEFAULT ''"),
        ("canonical_phase", "VARCHAR DEFAULT ''"),
        ("dump_id", "VARCHAR DEFAULT ''"),
        ("dump_path", "VARCHAR DEFAULT ''"),
        ("library_version", "VARCHAR DEFAULT 'unknown'"),
        ("scenario", "VARCHAR DEFAULT ''"),
        ("run_number", "INTEGER DEFAULT 0"),
        ("method", "VARCHAR DEFAULT ''"),
        # Duplicate of `key_hex`, deliberately. `persist_ground_truth` has
        # always written the secret BYTES into the column named `key_hex`, so
        # a consumer reading `key_hex` expecting a key IDENTIFIER gets the
        # secret material instead. Renaming would break `list_ground_truth`
        # consumers and the Phase-1 W5 ledger contract, so both columns are
        # written with the same value: `value_hex` is the correctly-named one,
        # `key_hex` is kept for compatibility.
        ("value_hex", "VARCHAR DEFAULT ''"),
    ),
    # -- v3 additions to the tables v2 introduced whole ---------------------
    #
    # These live here, not in `_V2_TABLES`, for exactly the reason the legacy
    # tables' additions do: `CREATE TABLE IF NOT EXISTS` is a NO-OP against a
    # database that already has the table, so a v2 database would never grow
    # them. Listing them here routes them through `_ensure_columns`' ALTER
    # probe while `_TABLE_COLUMNS` still appends them to the CREATE in the same
    # order, keeping a fresh and a migrated database identical.
    "expected_secrets": (
        # v3. Which sweep wrote the row. `resolve_project_db()` opens a single
        # global `default_db_path()`, so without this two corpora — or two
        # sweep configurations over one corpus — merge into one
        # indistinguishable pile of denominator rows.
        ("sweep_id", "VARCHAR DEFAULT ''"),
        # v3. 33 of the 2,600 corpus run directories contain ZERO `.dump`
        # files, and 31 of those have a complete `keylog.csv` and a non-empty
        # `traffic.pcap`. A denominator written by a per-dump worker loses all
        # of them, which makes `runs_expected == runs_attempted` true BY
        # CONSTRUCTION. Recording the dump count lets such a run render as
        # "no data" WITH A REASON instead of vanishing.
        ("dumps_in_run", "INTEGER DEFAULT 0"),
        # v3. The other half of that reason: '' = not recorded, 'ok' = parsed,
        # 'no_keylog' = the run has no keylog at all, 'unreadable' = there is
        # one but it did not parse. `core/keylog.py` swallows every exception
        # and returns [], which without this column is indistinguishable from a
        # genuinely empty keylog — i.e. from a true zero denominator.
        ("keylog_status", "VARCHAR DEFAULT ''"),
    ),
    "survival": (
        # v3. Same reason as on `expected_secrets`: one global DB file.
        ("sweep_id", "VARCHAR DEFAULT ''"),
        # v3. See :data:`SURVIVAL_STATUSES`. Defaulted to 'searched' so every
        # pre-v3 row — all of which WERE searched — keeps its meaning.
        ("status", "VARCHAR DEFAULT 'searched'"),
        # v3. `DumpSource.format_name` of the source actually opened. Every
        # corpus dump is ET_DYN and falls through to `RawDumpSource`; a future
        # mixed corpus resolving to a region view or a VAS projection would
        # search a DIFFERENT BYTE STREAM and report `✗` for format reasons.
        # Recording the format is what keeps that distinguishable from a real
        # absence.
        ("format_name", "VARCHAR DEFAULT ''"),
        # v3. `DumpSource.size_for(view)` — the number of bytes the searched
        # view actually exposes. Paired with `format_name` it separates "the
        # secret is gone" from "we only looked at a subset of the process".
        ("size_for_view", "BIGINT DEFAULT 0"),
    ),
}

#: Tables introduced WHOLE (nothing to ALTER — ``CREATE TABLE IF NOT EXISTS``
#: is the entire migration for them). Named for v2, when the mechanism was
#: introduced; ``sweeps`` / ``sweep_units`` joined in v3. A column added to one
#: of these tables AFTER its introducing version must go in
#: :data:`_ADDED_COLUMNS`, not here, or a database that already has the table
#: will never grow it.
_V2_TABLES: Dict[str, Tuple[Tuple[str, str], ...]] = {
    "schema_meta": (
        ("key", "VARCHAR PRIMARY KEY"),
        ("value", "VARCHAR"),
    ),
    # The DENOMINATOR ledger: one row per (corpus run, secret_type) that the
    # run's `keylog.csv` says exists. Survival is a fraction, and its
    # denominator lives in the keylogs, not in the hit table. Materialising it
    # here is what makes the corpus dashboard a DB read instead of a re-walk
    # of thousands of keylog files.
    "expected_secrets": (
        ("expected_id", "VARCHAR PRIMARY KEY"),
        ("run_id", "VARCHAR"),
        ("library", "VARCHAR"),
        ("protocol_version", "VARCHAR"),
        ("library_version", "VARCHAR DEFAULT 'unknown'"),
        ("version_axis", "VARCHAR DEFAULT 'protocol_version'"),
        ("protocol", "VARCHAR DEFAULT ''"),
        ("scenario", "VARCHAR DEFAULT ''"),
        ("run_number", "INTEGER DEFAULT 0"),
        ("secret_type", "VARCHAR"),
        ("identifier_hex", "VARCHAR DEFAULT ''"),
        ("secret_len", "INTEGER DEFAULT 0"),
        ("keylog_path", "VARCHAR DEFAULT ''"),
        ("created_at", "VARCHAR"),
    ),
    # The OBSERVATION ledger, at cell grain: one row per (dump, secret_type)
    # that was actually looked at.
    #
    # `present` is the whole point of this table. A row with `present = FALSE`
    # is the POSITIVE RECORD of "we opened this dump, we looked for this
    # secret, and it was gone"; the ABSENCE OF A ROW means "not attempted".
    # `findings` cannot express that distinction: it is an append-only hit
    # table, so "scanned and the secret was zeroized" and "never opened this
    # dump" are both simply the absence of a row.
    #
    # Do NOT "optimise away" this table by inferring absence from missing
    # `findings` rows. Every un-scanned dump would then render as a confirmed
    # absence, i.e. the dashboard would report zeroization where there is none.
    "survival": (
        ("survival_id", "VARCHAR PRIMARY KEY"),
        ("run_id", "VARCHAR"),
        ("dump_id", "VARCHAR DEFAULT ''"),
        ("library", "VARCHAR"),
        ("protocol_version", "VARCHAR"),
        ("library_version", "VARCHAR DEFAULT 'unknown'"),
        ("scenario", "VARCHAR DEFAULT ''"),
        ("run_number", "INTEGER DEFAULT 0"),
        ("phase", "VARCHAR DEFAULT ''"),
        ("canonical_phase", "VARCHAR DEFAULT ''"),
        ("secret_type", "VARCHAR"),
        ("present", "BOOLEAN"),
        ("first_offset", "BIGINT"),
        ("hit_count", "INTEGER DEFAULT 0"),
        ("method", "VARCHAR DEFAULT ''"),
        ("dump_path", "VARCHAR DEFAULT ''"),
        ("created_at", "VARCHAR"),
    ),
    # -- v3: the SWEEP CONTROL PLANE ---------------------------------------
    #
    # `sweeps` answers "what slice of the corpus does this number cover?" and
    # `sweep_units` answers "how far did it get?". They are placed here, in the
    # one item allowed to move the schema, precisely so the ledger that fills
    # them only ever writes ROWS — a schema change discovered after 18,917
    # units have been swept means re-running the sweep, not patching it.
    #
    # These two tables are the DOCUMENTED EXCEPTION to this class's append-only
    # rule (see :class:`ProjectDB`): a unit row is UPDATEd in place as it moves
    # pending -> running -> done/failed. The rule still holds without exception
    # for the findings tables.
    "sweeps": (
        ("sweep_id", "VARCHAR PRIMARY KEY"),
        # WHAT corpus. `corpus_id` is a stable digest/identifier, `corpus_label`
        # the human name; both, because a label alone is not comparable and a
        # digest alone is not readable.
        ("corpus_id", "VARCHAR DEFAULT ''"),
        ("corpus_label", "VARCHAR DEFAULT ''"),
        # WHICH configuration. Digest of the settings that change results, so
        # two sweeps are comparable only when these match.
        ("config_digest", "VARCHAR DEFAULT ''"),
        # THE FILTER SET — the load-bearing part of this table. A 5-run CI
        # slice and a 2,600-run publication run are otherwise the same shape of
        # rows, and nothing downstream could tell them apart. Recording the
        # bounds is what stops a bounded slice being published as a full-corpus
        # result. 0 / '' mean "unbounded", matching an unfiltered sweep.
        ("max_units", "INTEGER DEFAULT 0"),
        ("max_runs_per_library", "INTEGER DEFAULT 0"),
        # JSON arrays (or ''), not comma-joined strings: a library or version
        # token containing the separator would otherwise re-parse wrongly.
        ("library_filter", "VARCHAR DEFAULT ''"),
        ("version_filter", "VARCHAR DEFAULT ''"),
        # pending / running / completed / failed / cancelled.
        ("status", "VARCHAR DEFAULT 'pending'"),
        ("units_planned", "INTEGER DEFAULT 0"),
        ("created_at", "VARCHAR DEFAULT ''"),
        ("started_at", "VARCHAR DEFAULT ''"),
        ("finished_at", "VARCHAR DEFAULT ''"),
    ),
    "sweep_units": (
        ("sweep_unit_id", "VARCHAR PRIMARY KEY"),
        ("sweep_id", "VARCHAR"),
        ("unit_key", "VARCHAR"),
        # pending / running / done / failed / skipped.
        ("status", "VARCHAR DEFAULT 'pending'"),
        ("inputs_digest", "VARCHAR DEFAULT ''"),
        # WHICH digest produced `inputs_digest` ('size' / 'content' / ...).
        # The level is itself part of the hashed payload, so switching it
        # changes every digest at once; a resume that compared digests without
        # comparing levels would read that as "everything changed" and silently
        # re-sweep the whole corpus.
        ("digest_level", "VARCHAR DEFAULT ''"),
        # Watermark into the append-only results stream: where this unit's
        # record starts and how long it is, so a resume can truncate a partial
        # tail instead of re-reading everything.
        ("result_offset", "BIGINT DEFAULT 0"),
        ("result_bytes", "BIGINT DEFAULT 0"),
        ("attempt", "INTEGER DEFAULT 0"),
        ("created_at", "VARCHAR DEFAULT ''"),
        ("started_at", "VARCHAR DEFAULT ''"),
        ("finished_at", "VARCHAR DEFAULT ''"),
    ),
    # -- v4: the DIFFERENTIAL LEDGER --------------------------------------
    #
    # One row per N-dump comparison. The multi-dump variance workflow is the
    # tool's core feature and until v4 it persisted NOTHING: results were
    # loose `.npy` / `.json` files plus a 30-minute in-process dict
    # (`api/services/consensus_session.py`) that died with the server.
    #
    # THE THRESHOLDS AND THE ALIGNMENT METHOD ARE PART OF THE ROW, not
    # incidental metadata. A four-class histogram is meaningless without the
    # boundaries that produced it, and two histograms computed under different
    # boundaries — or one under ASLR-aware module alignment and one under the
    # flat-offset fallback — are not comparable. Storing them next to the
    # counts is what stops them being compared anyway.
    "consensus_runs": (
        ("consensus_id", "VARCHAR PRIMARY KEY"),
        ("project_id", "VARCHAR DEFAULT ''"),
        # The `analysis_runs` row that produced this comparison, when there is
        # one. Optional: the exploratory path (item A4) has no oracle and no
        # pipeline run behind it, so requiring it would make the headless
        # differential workflow unpersistable.
        ("run_id", "VARCHAR DEFAULT ''"),
        # JSON array, IN BUILD ORDER, not a separator join: a dump path can
        # contain any separator, and the order is load-bearing (the first
        # source supplies `ConsensusVector.reference_bytes`).
        ("dump_paths", "VARCHAR DEFAULT '[]'"),
        ("n_dumps", "INTEGER DEFAULT 0"),
        # How many bytes were actually compared — `min(len(b))` on the flat
        # path, the aligned slice length otherwise.
        ("bytes_compared", "BIGINT DEFAULT 0"),
        # -- alignment provenance (item A1 populates these richly) ---------
        #
        # Defaulted to the FALLBACK rather than to '' so a pre-A1 producer
        # that writes nothing states the truth about today's behaviour
        # (`_build_raw` flat offsets) instead of an empty non-answer.
        ("alignment_method", "VARCHAR DEFAULT 'file_offset'"),
        ("bytes_discarded", "BIGINT DEFAULT 0"),
        ("sizes_differed", "BOOLEAN DEFAULT FALSE"),
        # JSON array of the AlignmentReport warnings (item A1's shape).
        ("alignment_warnings", "VARCHAR DEFAULT '[]'"),
        # -- the class boundaries actually in force ------------------------
        ("invariant_max", "DOUBLE DEFAULT 0.0"),
        ("structural_max", "DOUBLE DEFAULT 200.0"),
        ("pointer_max", "DOUBLE DEFAULT 3000.0"),
        # -- the four-class histogram --------------------------------------
        ("invariant_bytes", "BIGINT DEFAULT 0"),
        ("structural_bytes", "BIGINT DEFAULT 0"),
        ("pointer_bytes", "BIGINT DEFAULT 0"),
        ("key_candidate_bytes", "BIGINT DEFAULT 0"),
        ("created_at", "VARCHAR"),
    ),
    # One row per RANKED CANDIDATE under a `consensus_runs` row.
    #
    # `rank` and the four `score_*` columns are ITEM A3's: it defines the
    # score (class weight, then mean variance, then entropy, then length) and
    # owns what each component means. They are carried here now, defaulted to
    # 0.0, so A3 lands as a producer change and not as a second schema bump —
    # a schema bump discovered after results have been written means
    # re-running the analysis, not patching the file.
    #
    # `rank = 0` means UNRANKED (the column default), which is why
    # :meth:`ProjectDB.candidate_regions` sorts unranked rows LAST rather than
    # first: rank 1 is the best candidate, so a naive ascending sort would put
    # every un-scored row above every scored one.
    "candidate_regions": (
        ("candidate_id", "VARCHAR PRIMARY KEY"),
        ("consensus_id", "VARCHAR"),
        ("offset", "BIGINT"),
        ("length", "INTEGER"),
        # One of :data:`BYTE_CLASSES` — the lower-cased
        # :class:`core.variance.ByteClass` names.
        ("byte_class", "VARCHAR DEFAULT ''"),
        ("mean_variance", "DOUBLE DEFAULT 0.0"),
        ("mean_entropy", "DOUBLE DEFAULT 0.0"),
        ("rank", "INTEGER DEFAULT 0"),
        ("score", "DOUBLE DEFAULT 0.0"),
        ("score_class_weight", "DOUBLE DEFAULT 0.0"),
        ("score_variance_component", "DOUBLE DEFAULT 0.0"),
        ("score_entropy_component", "DOUBLE DEFAULT 0.0"),
        ("score_length_component", "DOUBLE DEFAULT 0.0"),
        ("created_at", "VARCHAR"),
    ),
}

#: Full current column layout per table: the introducing version's columns
#: first, then every later addition in :data:`_ADDED_COLUMNS` order. This is
#: what ``CREATE TABLE`` emits, so a fresh database and a migrated one end up
#: byte-identical in column order.
#:
#: Both source dicts are folded the SAME way. A v3 column added to a v2 table
#: (``survival.status``, ``expected_secrets.sweep_id``) must be appended by the
#: same rule as a v2 column added to a v1 table, or the fresh CREATE and the
#: migrating ALTER disagree on order.
_TABLE_COLUMNS: Dict[str, Tuple[Tuple[str, str], ...]] = {
    table: columns + _ADDED_COLUMNS.get(table, ())
    for table, columns in list(_V1_COLUMNS.items()) + list(_V2_TABLES.items())
}


def _quote_ident(name: str) -> str:
    """Double-quote an identifier so reserved words (``offset``, ``key``) work.

    Only ever called with names from the frozen literals above.
    """
    return '"' + name + '"'


def _create_table_sql(table: str) -> str:
    """``CREATE TABLE IF NOT EXISTS`` generated from :data:`_TABLE_COLUMNS`."""
    body = ", ".join(
        _quote_ident(name) + " " + ddl for name, ddl in _TABLE_COLUMNS[table]
    )
    return "CREATE TABLE IF NOT EXISTS " + _quote_ident(table) + "(" + body + ")"


def _insert_sql(table: str, columns: Tuple[str, ...], *,
                ignore_conflicts: bool = False,
                conflict_target: Optional[Tuple[str, ...]] = None,
                update_columns: Tuple[str, ...] = ()) -> str:
    """Parameterised INSERT naming *columns* explicitly.

    Built by string join from frozen literal identifiers; every VALUE is bound
    through a ``$n`` placeholder, so no caller data reaches the SQL text.

    SECURITY NOTE — bandit cannot see this SQL. B608 (hardcoded_sql_expressions)
    only recognises SQL assembled with ``+``, ``%``, ``.format()`` or an
    f-string; this module builds every statement with ``str.join`` over keyword
    tokens, which that check does not model. A CLEAN BANDIT RUN IS THEREFORE NOT
    EVIDENCE OF SAFETY HERE, and a blanket ``# nosec`` would only make the
    silence look deliberate. The actual safety argument, which a reviewer must
    check by hand on every change to this file, is twofold:

    1. every VALUE is bound as a ``$n`` parameter — no caller data is ever
       interpolated into a statement string; and
    2. every IDENTIFIER comes from the frozen module-level literals
       (:data:`_V1_COLUMNS`, :data:`_ADDED_COLUMNS`, :data:`_V2_TABLES`,
       :data:`_SCHEMA_INDEXES`) and passes through :func:`_quote_ident`.

    With *ignore_conflicts*, a row whose PRIMARY KEY or UNIQUE index already
    exists is skipped instead of raising. That is only safe when the key is
    DETERMINISTIC (see :func:`_row_identity`): with a random uuid key the clause
    would never fire and a re-run would duplicate every row.

    With *update_columns*, a conflicting row is UPDATEd from the incoming one
    instead — ``DO NOTHING`` keeps the STALE row, so a resume that CORRECTS an
    earlier observation (``present = FALSE`` re-observed as ``TRUE``) has its
    correction silently discarded. Only the named columns are overwritten; the
    identity columns keep their stored values, so the update can never move a
    row to a different cell. *conflict_target* names the arbiter index —
    DuckDB requires one as soon as a table has more than one UNIQUE/PRIMARY KEY
    constraint (verified: ``Binder Error: Conflict target has to be provided
    for a DO UPDATE operation when the table has multiple UNIQUE/PRIMARY KEY
    constraints``), and a target that does not exist as an index is a bind
    error, not a silent fallback.
    """
    names = ", ".join(_quote_ident(c) for c in columns)
    holes = ", ".join("$" + str(i) for i in range(1, len(columns) + 1))
    parts = [
        "INSERT", "INTO", _quote_ident(table) + "(" + names + ")",
        "VALUES", "(" + holes + ")",
    ]
    if update_columns:
        parts += ["ON", "CONFLICT"]
        if conflict_target:
            parts.append(
                "(" + ", ".join(_quote_ident(c) for c in conflict_target) + ")")
        parts += ["DO", "UPDATE", "SET", ", ".join(
            _quote_ident(c) + " = EXCLUDED." + _quote_ident(c)
            for c in update_columns)]
    elif ignore_conflicts:
        parts += ["ON", "CONFLICT", "DO", "NOTHING"]
    return " ".join(parts)


def _create_index_sql(name: str, table: str, columns: Tuple[str, ...]) -> str:
    """``CREATE UNIQUE INDEX IF NOT EXISTS`` from frozen literal identifiers."""
    cols = ", ".join(_quote_ident(c) for c in columns)
    return " ".join([
        "CREATE", "UNIQUE", "INDEX", "IF", "NOT", "EXISTS", _quote_ident(name),
        "ON", _quote_ident(table) + "(" + cols + ")",
    ])


def _all_columns(table: str) -> Tuple[str, ...]:
    """Every column name of *table*, in schema order."""
    return tuple(name for name, _ddl in _TABLE_COLUMNS[table])


_SCHEMA_SQL = [_create_table_sql(t) for t in _TABLE_COLUMNS]

#: Uniqueness that is NOT expressible as a single-column PRIMARY KEY, declared
#: as an index rather than a ``UNIQUE(...)`` table constraint on purpose: a
#: table constraint can only be written by ``CREATE TABLE``, so a database that
#: already exists could never acquire one, and the fresh and migrated paths
#: would then disagree about what is unique. ``CREATE UNIQUE INDEX IF NOT
#: EXISTS`` runs identically on both, and DuckDB honours it for
#: ``ON CONFLICT DO NOTHING`` exactly as it honours the PRIMARY KEY.
_SCHEMA_INDEXES: Tuple[Tuple[str, str, Tuple[str, ...]], ...] = (
    # The cell grain of the survival ledger. `survival_id` already dedupes by
    # unit key; this catches the other direction — two different unit keys that
    # resolve to the SAME dump — which is what a re-run with a changed unit-key
    # scheme looks like. Scoped by `sweep_id` so two corpora, or a CI slice and
    # a full run, stay independent rather than the second silently losing every
    # row to the first.
    ("survival_cell_unique", "survival",
     ("sweep_id", "dump_path", "secret_type")),
    ("sweep_units_unit_unique", "sweep_units", ("sweep_id", "unit_key")),
    # The candidate grain: one row per (comparison, offset, length). The
    # PRIMARY KEY is derived from exactly these three columns
    # (:meth:`ProjectDB._candidate_identity`), so this index does not catch a
    # case the key misses — it exists so the arbiter of the writer's
    # ``ON CONFLICT`` is the READABLE natural key rather than a hash, which is
    # what makes "a re-run corrects rather than duplicates" checkable in SQL
    # (``COUNT(*) == COUNT(DISTINCT consensus_id, offset, length)``) instead of
    # only by re-deriving the hash.
    ("candidate_region_unique", "candidate_regions",
     ("consensus_id", "offset", "length")),
)

_SCHEMA_INDEX_SQL = [_create_index_sql(n, t, c) for n, t, c in _SCHEMA_INDEXES]

_INSERT_PROJECT = _insert_sql("projects", _all_columns("projects"))
_INSERT_DUMP = _insert_sql("dumps", _all_columns("dumps"))
_INSERT_RUN = _insert_sql("analysis_runs", _all_columns("analysis_runs"))
_INSERT_FINDING = _insert_sql("findings", _all_columns("findings"))
# The W5 proof ledger is DEDUPED, not appended blindly. `gt_id` used to be a
# uuid, which makes `ON CONFLICT` inert, and `persist_ground_truth_labels`
# now defaults to True — so re-running an analysis over the same dumps wrote a
# SECOND label for every already-proven key and inflated the truth denominator
# (and with it every recall figure computed against it). The key is now derived
# from the label's identity (:meth:`ProjectDB._ground_truth_identity`), so a
# re-run is a no-op instead of a duplicate.
#
# DO NOTHING, not DO UPDATE, unlike the two sweep ledgers: every column that is
# not part of the identity is an axis label rather than an observation that a
# later pass could legitimately CORRECT, so keeping the row already on disk
# loses nothing. `ground_truth` also has exactly one constraint (its PRIMARY
# KEY), so no conflict target is required.
_INSERT_GROUND_TRUTH = _insert_sql("ground_truth", _all_columns("ground_truth"),
                                   ignore_conflicts=True)
# Both ledger writers are re-run- and resume-safe: their primary keys are
# derived from the row's identity (:func:`_row_identity`), so re-inserting the
# same cell is an UPDATE of that one row rather than a second row.
#
# LAST WRITE WINS, deliberately, and it is NOT interchangeable with the
# ``DO NOTHING`` this used to be. ``DO NOTHING`` keeps the row already on disk,
# which is only equivalent when the re-submitted row is BYTE-IDENTICAL — and a
# resume cannot guarantee that. A first pass that recorded `present = FALSE`
# (a dump it could not fully read, a stride that missed the needle) and a
# second pass that finds the secret must end with the SECOND reading stored;
# under ``DO NOTHING`` the correction was accepted, counted in the return
# value, and thrown away.

#: The OBSERVATION columns of ``survival``: everything that records WHAT WAS
#: SEEN. Everything else on the row names WHICH CELL was seen (the identity and
#: corpus axes) and is deliberately absent here, so an UPDATE can never move a
#: row to a different cell or restamp its ``created_at``.
_SURVIVAL_UPDATE_COLUMNS = (
    "present", "first_offset", "hit_count", "method", "status",
    "format_name", "size_for_view",
)

#: The OBSERVATION columns of ``expected_secrets``: what the keylog said. The
#: corpus-run axes that compose ``expected_id`` stay fixed.
_EXPECTED_UPDATE_COLUMNS = (
    "identifier_hex", "secret_len", "keylog_path", "dumps_in_run",
    "keylog_status",
)

# `expected_secrets` has exactly one constraint (its PRIMARY KEY), so DuckDB
# accepts an untargeted DO UPDATE.
_INSERT_EXPECTED = _insert_sql("expected_secrets", _all_columns("expected_secrets"),
                               update_columns=_EXPECTED_UPDATE_COLUMNS)
# `survival` has TWO (the PK and `survival_cell_unique`), so the arbiter must be
# named. The cell index is the right one: it subsumes the PK direction whenever
# the unit key and the dump path agree, and it is the ONLY one that catches the
# other direction — two different `unit_key`s resolving to the same dump.
_INSERT_SURVIVAL = _insert_sql(
    "survival", _all_columns("survival"),
    conflict_target=("sweep_id", "dump_path", "secret_type"),
    update_columns=_SURVIVAL_UPDATE_COLUMNS)
# Degraded fallback for a database whose `survival_cell_unique` index could not
# be built (see :meth:`ProjectDB._ensure_indexes`). Naming a non-existent index
# as the arbiter is a BIND ERROR, so without this branch every survival write
# on such a database would fail outright — locking the owner out of their own
# project file, which is exactly what `_ensure_indexes` swallows the error to
# avoid. The PK still dedupes the same-unit-key direction; `degraded_indexes()`
# is how a sweep driver learns the other direction is unguarded.
_INSERT_SURVIVAL_PK_ONLY = _insert_sql(
    "survival", _all_columns("survival"),
    conflict_target=("survival_id",),
    update_columns=_SURVIVAL_UPDATE_COLUMNS)
_INSERT_SCHEMA_META = _insert_sql("schema_meta", ("key", "value"))

# -- sweep control plane: the MUTABLE tables ------------------------------
#
# These upserts are the documented exception to this module's append-only rule.
# A sweep row is re-declared on every resume and a unit row moves
# pending -> running -> done/failed IN PLACE; that in-place move is the entire
# point of a resume watermark, and appending a second row per transition would
# make "how far did this sweep get" a max() over history instead of a lookup.

#: Re-declaring a sweep refreshes its plan and its status, never its
#: ``created_at`` (when it was first planned) or its ``finished_at``
#: (:meth:`ProjectDB.finish_sweep` owns that).
_SWEEP_UPDATE_COLUMNS = (
    "corpus_id", "corpus_label", "config_digest", "max_units",
    "max_runs_per_library", "library_filter", "version_filter", "status",
    "units_planned", "started_at",
)

#: Starting a unit claims it: it owns the attempt counter, the input digest and
#: the start stamp, and CLEARS any ``finished_at`` left by a previous attempt.
#: It must not touch the watermark — a retry that crashes before writing one
#: would otherwise erase the previous attempt's.
_SWEEP_UNIT_START_UPDATE_COLUMNS = (
    "status", "inputs_digest", "digest_level", "attempt", "started_at",
    "finished_at",
)

#: Finishing a unit records the terminal status and the watermark, and leaves
#: ``started_at`` / ``attempt`` alone so the duration and the retry count of the
#: attempt that finished stay readable.
_SWEEP_UNIT_DONE_UPDATE_COLUMNS = (
    "status", "result_offset", "result_bytes", "finished_at",
)

# `sweeps` has one constraint (its PK), so no arbiter is needed.
_UPSERT_SWEEP = _insert_sql("sweeps", _all_columns("sweeps"),
                            update_columns=_SWEEP_UPDATE_COLUMNS)
# `sweep_units` has two (PK + `sweep_units_unit_unique`), so the arbiter must be
# named — and it is the natural key, since the PK is derived from it.
_UPSERT_SWEEP_UNIT_START = _insert_sql(
    "sweep_units", _all_columns("sweep_units"),
    conflict_target=("sweep_id", "unit_key"),
    update_columns=_SWEEP_UNIT_START_UPDATE_COLUMNS)
_UPSERT_SWEEP_UNIT_DONE = _insert_sql(
    "sweep_units", _all_columns("sweep_units"),
    conflict_target=("sweep_id", "unit_key"),
    update_columns=_SWEEP_UNIT_DONE_UPDATE_COLUMNS)

# -- v4: the differential ledger ------------------------------------------
#
# Both writers follow the `survival` pattern rather than `ground_truth`'s: the
# key is DERIVED from the row's identity and a re-submit UPDATES the
# observation columns. `DO NOTHING` would keep the stale row, and re-running a
# comparison is exactly how a result gets CORRECTED here — a second pass with a
# fixed alignment, or A3's ranking applied to a batch first written unranked,
# must end with the second reading stored.

#: The OBSERVATION columns of ``consensus_runs``: everything a re-run of the
#: same comparison is allowed to correct. The identity columns (``project_id``,
#: ``dump_paths``, ``alignment_method`` and the three boundaries) are absent by
#: construction — they compose ``consensus_id``, so an update could never move
#: the row anyway, and listing them would only make that look accidental.
#: ``created_at`` is absent so a re-run does not restamp when the comparison
#: was first recorded. ``run_id`` IS updatable: it names the most recent
#: ``analysis_runs`` row to produce this comparison, which is a fact about the
#: run and not about the comparison's identity.
_CONSENSUS_RUN_UPDATE_COLUMNS = (
    "run_id", "n_dumps", "bytes_compared", "bytes_discarded",
    "sizes_differed", "alignment_warnings",
    "invariant_bytes", "structural_bytes", "pointer_bytes",
    "key_candidate_bytes",
)

#: The OBSERVATION columns of ``candidate_regions``. ``consensus_id`` /
#: ``offset`` / ``length`` are the identity; everything else is a measurement
#: or a score, and item A3 re-writing a batch with real scores must land.
_CANDIDATE_UPDATE_COLUMNS = (
    "byte_class", "mean_variance", "mean_entropy", "rank", "score",
    "score_class_weight", "score_variance_component",
    "score_entropy_component", "score_length_component",
)

# `consensus_runs` has exactly ONE constraint (its PRIMARY KEY), so DuckDB
# accepts an untargeted DO UPDATE and no second unique index is declared. A
# natural-key index over (project_id, dump_paths, alignment_method, thresholds)
# would be a SECOND spelling of the same uniqueness the derived PK already
# enforces — and it would force every write to name an arbiter for no gain.
_INSERT_CONSENSUS_RUN = _insert_sql(
    "consensus_runs", _all_columns("consensus_runs"),
    update_columns=_CONSENSUS_RUN_UPDATE_COLUMNS)

# `candidate_regions` has TWO (the PK and `candidate_region_unique`), so the
# arbiter must be named — DuckDB refuses an untargeted DO UPDATE otherwise.
_INSERT_CANDIDATE = _insert_sql(
    "candidate_regions", _all_columns("candidate_regions"),
    conflict_target=("consensus_id", "offset", "length"),
    update_columns=_CANDIDATE_UPDATE_COLUMNS)
# Degraded fallback, exactly as `_INSERT_SURVIVAL_PK_ONLY` is: naming an index
# that does not exist is a BIND ERROR, so on a database where
# `_ensure_indexes` could not build `candidate_region_unique` every candidate
# write would fail outright and lock the owner out of their own project file.
# The derived PK covers the same key, so nothing is actually unguarded here.
_INSERT_CANDIDATE_PK_ONLY = _insert_sql(
    "candidate_regions", _all_columns("candidate_regions"),
    conflict_target=("candidate_id",),
    update_columns=_CANDIDATE_UPDATE_COLUMNS)

def _json_array(values: Optional[Sequence[object]]) -> str:
    """Render a sequence as a JSON array string (``'[]'`` when empty).

    JSON, not a separator join, for the same reason
    :meth:`ProjectDB._json_filter` uses it: the values stored this way are DUMP
    PATHS and free-text alignment warnings, either of which can contain any
    separator a join might pick, and a re-parse would then silently split one
    entry into two. A ``str`` is passed through verbatim so a caller holding
    pre-rendered JSON is not double-encoded.
    """
    if values is None:
        return "[]"
    if isinstance(values, str):
        return values
    return json.dumps([str(v) for v in values])


def _now_iso() -> str:
    """UTC ISO-8601 stamp — the format every ``*_at`` column on this schema holds."""
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def _new_id() -> str:
    """Random 32-hex id, for rows whose key is NOT derived (see :func:`_row_identity`)."""
    return uuid.uuid4().hex


def _row_identity(*parts: str) -> str:
    """Deterministic 32-hex row id derived from the row's IDENTITY *parts*.

    Why the two ledger tables cannot use :data:`_new_id`
    ---------------------------------------------------
    A uuid primary key makes ``ON CONFLICT DO NOTHING`` inert, so re-running a
    sweep — or resuming one — writes a SECOND row for every cell and every
    denominator entry. The damage is invisible to the obvious check: the
    invariant ``runs_found <= runs_attempted <= runs_expected`` still holds with
    both sides doubled, so the published fractions look untouched while the
    counts behind them are inflated.

    blake3 (via :mod:`msl.hashing`, which the repo already depends on) rather
    than md5: this is a repo-wide convention, and a collision here silently
    OVERWRITES one row with another instead of merely colliding.

    The parts are LENGTH-PREFIXED, not ``"|"``-joined. A plain separator join
    is not injective as soon as a component can contain the separator — and
    these components are dump paths and library names, which certainly can:
    ``("a", "b|c", "t")`` and ``("a|b", "c", "t")`` hashed to the same id, so
    two genuinely different cells became one row. ``len:value`` cannot be
    re-parsed ambiguously whatever the values contain.
    """
    joined = "".join(str(len(p)) + ":" + p for p in parts)
    return hash_bytes(joined.encode("utf-8")).hex()[:32]


def _confirmed_by(hit: dict) -> Optional[str]:
    """Provenance label for a hit: the explicit one, else ``"verifier"`` if verified."""
    return hit.get("confirmed_by") or ("verifier" if hit.get("verified") else None)


def _finding_row_from_hit(hit: dict, *, method: str = METHOD_CONSENSUS_SEARCH,
                          kind: str = "secret") -> dict:
    """Build a ``findings``-table row dict from a serialized hit dict.

    Shared by :meth:`ProjectDB.persist_report` and
    ``pipeline.AnalysisPipeline._persist_report`` so both persistence paths
    carry ``value_hex`` plus confirmed-key metadata identically (rather than
    diverging on whether the key bytes and confirmation marker are kept).

    The ``metadata`` field records whether the hit is a confirmed ground-truth
    key: ``confirmed`` (bool from ``verified``), ``confirmed_by`` (explicit
    label, else ``"verifier"`` when verified), and ``cipher``. ``None`` values
    are dropped.

    Every label a :class:`engine.results.SecretHit` carries — ``secret_type``,
    ``library``, ``phase``, ``dump_path``, ``verified``, and the corpus run
    number it calls ``run_id`` — is forwarded to its own column as well.
    ``finding_type`` keeps the historical ``secret_type`` value verbatim so
    ``finding_counts`` and ``query_findings(finding_type=)`` are unaffected;
    ``secret_type`` is the properly-named duplicate.

    *method* defaults to :data:`METHOD_CONSENSUS_SEARCH` because both callers
    persist hits produced by :class:`engine.correlator.SearchCorrelator`; a hit
    dict carrying its own ``method`` overrides it.
    """
    metadata = {
        "confirmed": bool(hit.get("verified")),
        "confirmed_by": _confirmed_by(hit),
        "cipher": hit.get("cipher"),
    }
    metadata = {k: v for k, v in metadata.items() if v is not None}
    secret_type = hit.get("secret_type", "")
    return {
        "finding_type": secret_type,
        "offset": hit.get("offset"),
        "length": hit.get("length"),
        "value_hex": hit.get("value_hex"),
        "value_text": hit.get("value_text"),
        "confidence": hit.get("confidence", 1.0),
        "metadata": metadata,
        "secret_type": secret_type,
        "kind": hit.get("kind", kind),
        "method": hit.get("method", method),
        "dump_path": str(hit.get("dump_path", "") or ""),
        "phase": hit.get("phase", "") or "",
        "canonical_phase": hit.get("canonical_phase", "") or "",
        "library": hit.get("library", "") or "",
        "verified": hit.get("verified"),
        # `SecretHit.run_id` is an int CORPUS RUN NUMBER, not a foreign key to
        # `analysis_runs` — every serializer emitted it and every writer then
        # discarded it, because there was no column to put it in. It lands in
        # `findings.run_number`, whose name matches its meaning and the four
        # other tables that carry the same axis.
        "run_number": int(hit.get("run_id") or 0),
    }


class ProjectDB:
    """DuckDB-backed project database with Ibis query interface.

    APPEND-ONLY FOR THE FINDINGS TABLES — ``projects``, ``dumps``,
    ``analysis_runs``, ``findings``, ``ground_truth``, ``expected_secrets`` and
    ``survival``. Among those, only ``finish_run`` performs an UPDATE. That rule
    is what makes a persisted result reproducible: nothing rewrites an
    observation after the fact.

    The v3 CONTROL-PLANE tables ``sweeps`` and ``sweep_units`` are the explicit
    and only exception — a unit row is UPDATEd in place as it moves through
    pending -> running -> done/failed, which is the whole point of a resume
    watermark. Do not read that exception as a general loosening; it does not
    extend to any other table.

    If DuckDB is not installed, all operations degrade gracefully to no-ops.
    """

    def __init__(self, db_path: Path):
        self._db_path = Path(db_path)
        self._conn: Any = None
        self._ibis: Any = None
        self._available = False
        #: Names of the :data:`_SCHEMA_INDEXES` entries that could NOT be
        #: built on this database. See :meth:`degraded_indexes`.
        self._degraded_indexes: Tuple[str, ...] = ()

    def open(self) -> None:
        """Connect, create any missing tables, then migrate the schema forward.

        The order matters: ``CREATE TABLE IF NOT EXISTS`` first (so a brand-new
        database is born at :data:`_SCHEMA_VERSION` with the full column set),
        then the recorded version decides whether a pre-existing database still
        needs the later versions' columns appended.
        """
        if not HAS_DUCKDB:
            logger.warning("DuckDB not installed — ProjectDB disabled"); return
        self._conn = duckdb.connect(str(self._db_path))
        for ddl in _SCHEMA_SQL: self._conn.execute(ddl)
        self._migrate()
        self._ensure_indexes()
        self._ibis = ibis.duckdb.from_connection(self._conn)
        self._available = True

    def _ensure_indexes(self) -> None:
        """Create the :data:`_SCHEMA_INDEXES` uniqueness indexes.

        Runs AFTER :meth:`_migrate` because an index may reference a column that
        migration has just added (``survival.sweep_id``).

        A failure is warned about and swallowed rather than raised. The one way
        this fails is a pre-existing database that ALREADY holds the duplicate
        rows this index exists to prevent — precisely the database whose owner
        must not be locked out of their own project file. De-duplicating it here
        would mean deleting the user's rows to satisfy a constraint they never
        asked for; that is their call to make, so the warning names the table.

        BUT the swallow is not free, and a log line is not enough of a signal.
        A database that opened without ``survival_cell_unique`` runs WITHOUT THE
        UNIQUENESS GUARANTEE: every ``ON CONFLICT`` on that arbiter degrades,
        the same (dump, secret_type) can then hold two contradictory rows
        (``present = [TRUE, FALSE]``), and the condition is self-perpetuating —
        once one duplicate pair exists the index can never build again. The one
        WARNING at :meth:`open` is the only trace in the whole process
        lifetime, and nothing downstream can branch on a log record. So the
        names are also recorded in :attr:`_degraded_indexes` (read it via
        :meth:`degraded_indexes`) for a sweep driver to refuse to publish on.
        """
        degraded: List[str] = []
        for sql, (name, table, _cols) in zip(_SCHEMA_INDEX_SQL, _SCHEMA_INDEXES):
            try:
                self._conn.execute(sql)
            except Exception as exc:
                degraded.append(name)
                logger.warning(
                    "project DB %s: could not create unique index %s on %s (%s)"
                    " — the table probably already holds duplicate rows;"
                    " de-duplicate it to get re-run-safe inserts."
                    " degraded_indexes() now reports %s: results written to"
                    " this database are NOT deduplicated and must not be"
                    " published as a corpus result",
                    self._db_path, name, table, exc, name,
                )
        self._degraded_indexes = tuple(degraded)

    def degraded_indexes(self) -> Tuple[str, ...]:
        """Names of the uniqueness indexes this database is running WITHOUT.

        Empty on a healthy database. A NON-EMPTY result means the on-disk
        uniqueness guarantee those indexes provide is absent, so re-running or
        resuming a sweep against this file can write duplicate — and mutually
        contradictory — ledger rows that no ``ON CONFLICT`` will catch.

        A sweep driver should treat a non-empty result as "do not publish": the
        counts behind the fractions are unreliable even though the fractions
        themselves still satisfy ``found <= attempted <= expected``. This is a
        programmatic accessor rather than a log line precisely because the
        failure is silent, one-shot at :meth:`open`, and otherwise invisible for
        the rest of the process lifetime.
        """
        return self._degraded_indexes

    # -- schema migration -------------------------------------------------

    def _migrate(self) -> None:
        """Bring an existing database up to :data:`_SCHEMA_VERSION`.

        A database written by a NEWER MemDiver is left alone with a warning
        rather than refused: the added columns are all nullable/defaulted, so an
        older reader still works, and crashing would lock the user out of their
        own project file.
        """
        stored = self._read_schema_version()
        if stored > _SCHEMA_VERSION:
            logger.warning(
                "project DB %s was written by a newer MemDiver "
                "(schema v%d > v%d); continuing read/write with the older "
                "schema — newer columns are ignored, not dropped",
                self._db_path, stored, _SCHEMA_VERSION,
            )
            return
        if stored < _SCHEMA_VERSION:
            self._ensure_columns()
        self._set_schema_version(_SCHEMA_VERSION)

    def _read_schema_version(self) -> int:
        """Recorded schema version, or ``1`` for a pre-``schema_meta`` database."""
        row = self._conn.execute(
            'SELECT "value" FROM "schema_meta" WHERE "key" = $1',
            ["schema_version"],
        ).fetchone()
        if not row or row[0] is None:
            return 1
        try:
            return int(row[0])
        except (TypeError, ValueError):
            logger.warning("unreadable schema_version %r; assuming v1", row[0])
            return 1

    def _set_schema_version(self, version: int) -> None:
        """Upsert ``schema_meta.schema_version`` (delete + insert, no ON CONFLICT)."""
        self._conn.execute(
            'DELETE FROM "schema_meta" WHERE "key" = $1', ["schema_version"])
        self._conn.execute(_INSERT_SCHEMA_META, ["schema_version", str(version)])

    def _ensure_columns(self) -> None:
        """Append any :data:`_ADDED_COLUMNS` this database is missing.

        Probes ``duckdb_columns()`` and emits ``ALTER TABLE ... ADD COLUMN``
        only for genuinely absent columns, rather than relying on
        ``ADD COLUMN IF NOT EXISTS`` — that clause is not available on every
        DuckDB in our supported range (``duckdb>=1.0.0``), and the probe also
        gives the migration test something to assert against.

        Every identifier interpolated here comes from the frozen literals in
        :data:`_ADDED_COLUMNS`; no caller data is involved, so there is no
        injection surface.
        """
        for table, columns in _ADDED_COLUMNS.items():
            existing = {
                r[0] for r in self._conn.execute(
                    "SELECT column_name FROM duckdb_columns() "
                    "WHERE table_name = $1", [table],
                ).fetchall()
            }
            for name, ddl in columns:
                if name in existing:
                    continue
                self._conn.execute(" ".join([
                    "ALTER", "TABLE", _quote_ident(table),
                    "ADD", "COLUMN", _quote_ident(name), ddl,
                ]))
                logger.info("project DB migration: %s.%s added", table, name)

    @contextmanager
    def _transaction(self) -> Iterator[None]:
        """Run the wrapped writes inside one DuckDB transaction.

        LOAD-BEARING, not defensive. DuckDB's ``executemany`` is NOT atomic on
        its own: measured on duckdb 1.5.2, a batch whose second row fails to
        convert raises and LEAVES THE FIRST ROW COMMITTED. Half a denominator —
        or half an observation ledger — reads downstream as a real one, so the
        rollback is what keeps a failed batch from being published as a result.
        """
        self._conn.execute("BEGIN TRANSACTION")
        try:
            yield
            self._conn.execute("COMMIT")
        except Exception:
            self._conn.execute("ROLLBACK")
            raise

    def close(self) -> None:
        if self._conn is not None: self._conn.close(); self._conn = None
        self._ibis = None; self._available = False

    def __enter__(self): self.open(); return self
    def __exit__(self, *args): self.close()

    # -- write (append-only) ---------------------------------------------

    def create_project(self, name: str, description: str = "", *,
                       library: str = "", protocol_version: str = "",
                       library_version: str = "unknown",
                       version_axis: str = "protocol_version",
                       scenario: str = "", protocol: str = "") -> str:
        """Create a project row.

        *name* is written verbatim. Callers that build it from corpus axes MUST
        keep using the historical ``f"{library}_{protocol_version}"`` format —
        it is a frozen compatibility contract (see :meth:`persist_report`). The
        axes are additionally stored in their own columns so a reader never has
        to parse the name back apart.
        """
        if not self._available: return ""
        pid = _new_id()
        self._conn.execute(_INSERT_PROJECT,
                           [pid, name, _now_iso(), description,
                            library, protocol_version, library_version,
                            version_axis, scenario, protocol])
        return pid

    def add_dump(self, project_id: str, file_path: Path, file_type: str, *,
                 phase: str = "", canonical_phase: str = "",
                 run_number: int = 0, library: str = "",
                 run_id: str = "") -> str:
        """Register one dump file under *project_id* and return its ``dump_id``.

        *run_id* links the dump to the ``analysis_runs`` row that scanned it, so
        a finding's dump is reachable without joining on paths.
        """
        if not self._available: return ""
        did, p = _new_id(), Path(file_path)
        size = p.stat().st_size if p.exists() else 0
        self._conn.execute(_INSERT_DUMP,
                           [did, project_id, str(file_path), file_type, size, _now_iso(), "{}",
                            phase, canonical_phase, int(run_number), library, run_id])
        return did

    def start_run(self, project_id: str, dump_id: Optional[str] = None,
                  config: Optional[dict] = None, *,
                  phase: str = "", canonical_phase: str = "",
                  run_number: int = 0, library: str = "",
                  protocol_version: str = "", library_version: str = "unknown",
                  scenario: str = "", run_dir: str = "",
                  keylog_path: str = "", pcap_path: str = "") -> str:
        """Open an ``analysis_runs`` row.

        Grain: ONE row per analysis invocation, i.e. per (library, phase) — not
        per corpus run. Widening it to per-corpus-run would silently change what
        :meth:`project_timeline` means. Per-corpus-run resolution lives in
        ``dumps`` and ``survival``, both of which carry ``run_number``.

        Because of that grain, ``run_number`` / ``run_dir`` / ``keylog_path`` /
        ``pcap_path`` are only meaningful when the invocation covered exactly
        one corpus run; a caller spanning several runs should leave them empty
        rather than claim one run's sidecars for all of them.

        *phase* is written to its own column AND kept inside ``config_json``
        (callers have always put it there), so the change is purely additive.
        """
        if not self._available: return ""
        rid = _new_id()
        self._conn.execute(_INSERT_RUN,
                           [rid, project_id, dump_id or "", _now_iso(), None, "running",
                            json.dumps(config or {}),
                            phase, canonical_phase, int(run_number), library,
                            protocol_version, library_version, scenario,
                            str(run_dir), str(keylog_path), str(pcap_path)])
        return rid

    def finish_run(self, run_id: str, status: str = "completed") -> None:
        if not self._available: return
        self._conn.execute("UPDATE analysis_runs SET status=$1, finished_at=$2 WHERE run_id=$3",
                           [status, _now_iso(), run_id])

    def add_finding(self, run_id: str, finding_type: str,
                    offset: Optional[int] = None, length: Optional[int] = None,
                    value_hex: Optional[str] = None,
                    value_text: Optional[str] = None,
                    confidence: float = 1.0,
                    metadata: Optional[dict] = None, *,
                    secret_type: str = "", kind: str = "secret",
                    method: str = "", dump_path: str = "",
                    phase: str = "", canonical_phase: str = "",
                    library: str = "", verified: Optional[bool] = None,
                    run_number: int = 0) -> str:
        """Append one finding row.

        *finding_type* keeps its historical free-form value (``finding_counts``
        and ``query_findings(finding_type=)`` group on it). *kind* is the closed
        classifier (``secret`` / ``string`` / ``crypto_key``) an aggregator
        should filter on instead of sniffing *finding_type*. *method* must come
        from :data:`METHODS` — an unknown one raises
        :class:`core.service_errors.CapabilityError`; the empty default stays
        legal and means "unclassified".

        *run_number* is the CORPUS run this finding came from (``SecretHit``
        spells it ``run_id``); it is not the *run_id* parameter, which is the
        ``analysis_runs`` key.
        """
        if not self._available: return ""
        _validate_method(method, where="findings.method")
        fid = _new_id()
        self._conn.execute(_INSERT_FINDING,
                           [fid, run_id, finding_type, offset, length, value_hex,
                            value_text, confidence, json.dumps(metadata or {}), _now_iso(),
                            secret_type, kind, method, str(dump_path),
                            phase, canonical_phase, library, verified,
                            int(run_number or 0)])
        return fid

    def add_findings_batch(self, run_id: str, findings: Sequence[dict]) -> int:
        """Bulk insert findings using executemany.

        Accepts the dicts produced by :func:`_finding_row_from_hit`; any axis
        key a caller omits falls back to the column default. Every ``method``
        must be in :data:`METHODS` (empty = unclassified); the whole batch is
        validated before the first row is written, so one bad row cannot leave a
        half-written batch behind.
        """
        if not self._available or not findings:
            return 0
        for f in findings:
            _validate_method(f.get("method", ""), where="findings.method")
        ts = _now_iso()
        rows = [
            [_new_id(), run_id, f.get("finding_type", ""), f.get("offset"),
             f.get("length"), f.get("value_hex"), f.get("value_text"),
             f.get("confidence", 1.0), json.dumps(f.get("metadata", {})), ts,
             f.get("secret_type", ""), f.get("kind", "secret"),
             f.get("method", ""), str(f.get("dump_path", "") or ""),
             f.get("phase", ""), f.get("canonical_phase", ""),
             f.get("library", ""), f.get("verified"),
             int(f.get("run_number", 0) or 0)]
            for f in findings
        ]
        self._conn.executemany(_INSERT_FINDING, rows)
        return len(rows)

    @staticmethod
    def _expected_identity(sweep_id: str, row: dict) -> str:
        """Deterministic ``expected_id`` at the table's documented grain.

        The grain is ONE ROW PER (corpus run, secret_type), scoped to a sweep —
        so the key is built from the corpus-run axes, NOT from the
        ``analysis_runs`` uuid. Keying on that uuid would defeat the whole
        point: a re-run mints a fresh one, ``ON CONFLICT`` never fires, and the
        denominator doubles.

        A caller with a better corpus-run identity than the axes (the run
        directory, say) may pass ``run_key``; otherwise ALL FIVE axes that name
        a corpus run — library, library version, protocol version, scenario,
        run number — compose it.

        WARNING — a caller that omits the identity fields collapses every
        corpus run into ONE denominator row. The key is built from what the row
        carries, so a batch of rows that all leave ``library`` /
        ``protocol_version`` / ``library_version`` / ``scenario`` /
        ``run_number`` at their defaults resolves to a single ``expected_id``
        per ``secret_type``, and the ``ON CONFLICT`` then folds the whole batch
        into that one row. Pass the axes (or an explicit ``run_key``).

        ``library_version`` and ``scenario`` are in the key even though today's
        corpus makes ``(library, protocol_version, run_number)`` unique on its
        own. Both are COLUMNS ON THIS TABLE, so leaving them out of the key is a
        latent denominator collapse by a factor of #versions x #scenarios the
        day a second library build or a second scenario per protocol lands —
        and ``survival`` keys on the full dump path, so it would NOT collapse
        with it: the numerator and the denominator would then be counting
        different things.
        """
        run_key = str(row.get("run_key") or _row_identity(
            str(row.get("library", "")),
            str(row.get("library_version", "unknown")),
            str(row.get("protocol_version", "")),
            str(row.get("scenario", "")),
            str(int(row.get("run_number", 0) or 0)),
        ))
        return _row_identity(sweep_id, run_key, str(row.get("secret_type", "")))

    def add_expected_secrets_batch(self, run_id: str, rows: Sequence[dict], *,
                                   sweep_id: str = "") -> int:
        """Bulk insert the DENOMINATOR ledger: what the keylogs say should exist.

        One row per (corpus run, secret_type). Survival is a fraction, and its
        denominator is "the keylog declares this secret" — information that
        lives in ``keylog.csv``, not in the hit table. Materialising it here is
        what lets the corpus dashboard be a single DB read instead of a re-walk
        of thousands of keylog files.

        Each dict may carry any ``expected_secrets`` column except
        ``expected_id`` / ``run_id`` / ``created_at``, which are supplied here.
        A row may also carry ``run_key`` (identity only, not a column) and its
        own ``sweep_id``, overriding the batch-wide *sweep_id*.

        *sweep_id* IS REQUIRED (per row, after the batch-wide default is
        applied). It used to default to ``""``, which defeated the column's
        entire purpose: ``resolve_project_db()`` opens ONE global database
        file, so two sweeps over one corpus both wrote ``sweep_id = ''``, their
        denominator rows shared an ``expected_id``, and the SECOND sweep — the
        full-corpus publication run — lost every row to the FIRST, a five-run
        CI slice. An empty value is rejected rather than defaulted.

        RE-RUN SAFE. ``expected_id`` is derived from the row's identity, so
        re-running or resuming a sweep updates the same rows in place rather
        than adding new ones (see :data:`_EXPECTED_UPDATE_COLUMNS` for which
        columns a re-submit is allowed to correct). The whole batch is written
        inside one transaction: a failure part-way leaves the ledger as it was,
        rather than half a denominator that reads as a real one.

        Returns the number of rows SUBMITTED (0 when unavailable or empty). That
        is deliberately not "rows newly inserted" — rows already present are
        updated in place, and counting them as failures would make a correct
        resume look like an error.

        *dumps_in_run* / *keylog_status* on a row are what let a run with a
        complete keylog and zero dumps render as "no data, and here is why"
        instead of dropping out of the denominator entirely.
        """
        if not self._available or not rows:
            return 0
        ts = _now_iso()
        payload = []
        for r in rows:
            row_sweep = _require_nonempty(
                str(r.get("sweep_id", sweep_id) or ""),
                where="expected_secrets.sweep_id",
                code="project_db.sweep_id_required",
                why="One global project DB holds every sweep, so rows written"
                    " without a sweep_id share an expected_id across sweeps and"
                    " the later sweep silently overwrites the earlier one.",
            )
            payload.append(
                [self._expected_identity(row_sweep, r),
                 run_id, r.get("library", ""), r.get("protocol_version", ""),
                 r.get("library_version", "unknown"),
                 r.get("version_axis", "protocol_version"),
                 r.get("protocol", ""), r.get("scenario", ""),
                 int(r.get("run_number", 0) or 0), r.get("secret_type", ""),
                 r.get("identifier_hex", ""), int(r.get("secret_len", 0) or 0),
                 str(r.get("keylog_path", "") or ""), ts,
                 row_sweep,
                 int(r.get("dumps_in_run", 0) or 0),
                 str(r.get("keylog_status", "") or "")])
        with self._transaction():
            self._conn.executemany(_INSERT_EXPECTED, payload)
        return len(payload)

    @staticmethod
    def _survival_payload_row(run_id: str, r: dict, *, sweep_id: str,
                              ts: str) -> Optional[List[Any]]:
        """Validate one submitted survival dict and render it in schema order.

        Returns ``None`` for a :data:`SURVIVAL_STATUS_ERROR` row, which writes
        NO ROW at all — an errored attempt is not an observation, and recording
        one would let a crash masquerade as evidence. Every other rejection
        raises :class:`core.service_errors.CapabilityError`; see
        :meth:`add_survival_batch` for why each guard is there. Validation is
        split out so the batch writer stays a loop over rows plus one
        transaction.
        """
        status = _validate_choice(
            str(r.get("status") or SURVIVAL_STATUS_SEARCHED),
            SURVIVAL_STATUSES, "survival.status",
            "project_db.unknown_survival_status")
        if status == SURVIVAL_STATUS_ERROR:
            return None
        present = r.get("present")
        if status == SURVIVAL_STATUS_SEARCHED and present is None:
            raise CapabilityError(
                "survival row for " + repr(r.get("secret_type", ""))
                + " has status 'searched' but no 'present' value; a NULL"
                " present counts as attempted while matching neither"
                " WHERE present nor WHERE NOT present. Use status"
                " 'unreadable' when the dump could not be read.",
                category=ErrorCategory.INVALID_INPUT,
                code="project_db.survival_present_required",
            )
        method = str(r.get("method") or METHOD_KEYLOG_SUBSTRING)
        _validate_method(method, allowed=(METHOD_KEYLOG_SUBSTRING,),
                         where="survival.method")
        row_sweep = _require_nonempty(
            str(r.get("sweep_id", sweep_id) or ""),
            where="survival.sweep_id",
            code="project_db.sweep_id_required",
            why="One global project DB holds every sweep, so rows written"
                " without a sweep_id merge two sweeps of the same dump and"
                " the later sweep silently overwrites the earlier one.",
        )
        dump_path = _require_nonempty(
            str(r.get("dump_path", "") or ""),
            where="survival.dump_path",
            code="project_db.survival_dump_path_required",
            why="The unique index is (sweep_id, dump_path, secret_type)"
                " while the primary key is built from"
                " unit_key/dump_path/dump_id, so an empty dump_path lets"
                " every cell get a distinct PK and then collapses them all"
                " onto one indexed row — the whole batch is accepted and"
                " counted, and all but the first row is discarded.",
        )
        cell_key = str(r.get("unit_key") or dump_path or r.get("dump_id", ""))
        return [
            _row_identity(row_sweep, cell_key, str(r.get("secret_type", ""))),
            run_id, r.get("dump_id", ""), r.get("library", ""),
            r.get("protocol_version", ""), r.get("library_version", "unknown"),
            r.get("scenario", ""), int(r.get("run_number", 0) or 0),
            r.get("phase", ""), r.get("canonical_phase", ""),
            r.get("secret_type", ""), present,
            r.get("first_offset"), int(r.get("hit_count", 0) or 0),
            method, dump_path, ts,
            row_sweep, status,
            str(r.get("format_name", "") or ""),
            int(r.get("size_for_view", 0) or 0),
        ]

    def add_survival_batch(self, run_id: str, rows: Sequence[dict], *,
                           sweep_id: str = "") -> int:
        """Bulk insert the OBSERVATION ledger at cell grain: (dump, secret_type).

        ``present`` is the whole point of this table:

        * ``present = TRUE``  — we looked and found the secret;
        * ``present = FALSE`` — we opened this dump, searched for this secret,
          and it was gone. This row is the POSITIVE RECORD of that absence;
        * **no row at all** — we never attempted this cell.

        ``findings`` cannot express that third state: it is an append-only hit
        table, so "scanned and the secret was zeroized" and "never opened this
        dump" are both simply the absence of a row. Never infer absence from a
        missing ``findings`` row — every un-scanned dump would then render as a
        confirmed absence, i.e. the dashboard would report zeroization where
        there is none.

        ``status`` says what happened and is the guard on that three-state
        reading (see :data:`SURVIVAL_STATUSES`):

        * ``searched``   — the only status that counts toward ``runs_attempted``.
          ``present`` MUST be non-NULL; a batch that omits it is REJECTED rather
          than written, because SQL NULL is excluded by both ``WHERE present``
          and ``WHERE NOT present`` and such a row would count as attempted
          while contributing to neither found nor absent;
        * ``unreadable`` — reached the dump, could not read it. ``present``
          stays NULL and the cell is NOT attempted;
        * ``error``      — the attempt itself failed. WRITES NO ROW; such rows
          are dropped from the batch and excluded from the return count.

        ``format_name`` / ``size_for_view`` record WHICH BYTE STREAM was
        searched, so an absence caused by a format (a region view or a VAS
        projection exposing a different subset of the process) is
        distinguishable from a secret that is genuinely gone.

        ``method`` may ONLY be :data:`METHOD_KEYLOG_SUBSTRING` — the corpus
        survival pass runs no decryption, so no row it writes may carry an
        evidential claim it did not earn. (That is also why this table has no
        ``confirmed_by`` column at all; :data:`SURVIVAL_FORBIDDEN_CONFIRMED_BY`
        guards ``findings.metadata['confirmed_by']``, which is a different
        thing.) It defaults to :data:`METHOD_KEYLOG_SUBSTRING` rather than to
        the empty string, so an omitted method states the truth instead of
        leaving the row unclassified.

        ``dump_path`` and ``sweep_id`` ARE BOTH REQUIRED on every row that is
        actually written (i.e. every row whose status is not ``error``). They
        used to default to ``""``, and that combination is how this writer could
        destroy a published result without raising or logging anything:

        * the PRIMARY KEY is built from ``unit_key or dump_path or dump_id``
          while the UNIQUE index is ``(sweep_id, dump_path, secret_type)``.
          Those are DIFFERENT KEYS. A caller supplying a distinct ``dump_id``
          (or ``unit_key``) but no ``dump_path`` gets a distinct PK per cell, so
          the PK never fires — and the unique index then collapses every one of
          those cells onto ``(sweep, '', secret_type)``. Measured on the real
          corpus shape (11,141 TLS1.3 dumps x 5 secret types + 7,776 TLS1.2 x 1
          = 63,481 cells): SIX rows survive, 63,475 are dropped, and the writer
          returns 63,481. There are no production callers yet, so tightening is
          free today and impossible once a sweep has run;
        * an empty ``sweep_id`` merges two sweeps over one corpus, and the
          second (the full-corpus publication run) loses to the first (a CI
          slice).

        RE-RUN SAFE, in both directions. ``survival_id`` is derived from the
        cell's identity, and the UNIQUE index on
        ``(sweep_id, dump_path, secret_type)`` catches the other direction —
        two unit keys resolving to the same dump — and is the arbiter this
        writer's ``ON CONFLICT`` names.

        A re-submitted cell UPDATES the stored observation
        (:data:`_SURVIVAL_UPDATE_COLUMNS`); it does not lose to it. Under the
        previous ``DO NOTHING`` a resume that CORRECTED a wrong reading —
        ``present = FALSE`` on the first pass, ``present = TRUE`` with four hits
        on the second — had the correction accepted, counted in the return
        value, and discarded. The identity and axis columns are never touched by
        the update, so a correction can only change WHAT WAS SEEN, never WHICH
        CELL it was seen in.

        The whole batch is written inside one transaction, so a failure part-way
        leaves no partial observation ledger behind. That wrapper is
        load-bearing, not defensive: DuckDB's ``executemany`` is NOT atomic on
        its own, and a batch whose second row fails to convert commits the first
        one. Returns the number of rows SUBMITTED after error rows are dropped —
        not "rows newly inserted", since a correct resume re-submits rows that
        already exist.
        """
        if not self._available or not rows:
            return 0
        ts = _now_iso()
        payload: List[List[Any]] = []
        for r in rows:
            values = self._survival_payload_row(run_id, r, sweep_id=sweep_id,
                                                ts=ts)
            if values is not None:
                payload.append(values)
        if not payload:
            return 0
        stmt = (_INSERT_SURVIVAL_PK_ONLY
                if "survival_cell_unique" in self._degraded_indexes
                else _INSERT_SURVIVAL)
        with self._transaction():
            self._conn.executemany(stmt, payload)
        return len(payload)

    # -- v4: the DIFFERENTIAL ledger (consensus + candidates) -------------

    @staticmethod
    def _consensus_identity(project_id: str, dump_paths: Sequence[str], *,
                            alignment_method: str, invariant_max: float,
                            structural_max: float, pointer_max: float) -> str:
        """Deterministic ``consensus_id`` for one N-dump comparison.

        THE NATURAL KEY IS "what was compared, and under what rules":

        * *project_id* — two projects may hold the same dump paths;
        * the ORDERED *dump_paths* — order is part of the input, not a
          presentation detail: the first source supplies
          ``ConsensusVector.reference_bytes``, so reordering the same files is
          a different comparison with a different reference;
        * *alignment_method* — the same files aligned by module offset and by
          raw file offset produce different, non-comparable variance vectors;
        * the three class boundaries — they decide the histogram outright.

        Re-running the same comparison therefore CORRECTS the stored row
        (:data:`_CONSENSUS_RUN_UPDATE_COLUMNS`); changing any input mints a new
        one, so a re-alignment never overwrites the result it should be
        compared against.

        INJECTIVITY. :func:`_row_identity` length-prefixes every part
        (``len:value``), and a length prefix cannot itself contain the ``:``
        that terminates it — so the concatenation decodes unambiguously
        whatever the values contain, and for a VARIABLE-LENGTH part list too.
        That matters here more than anywhere else in this module: the parts are
        DUMP PATHS, which routinely contain the separators a naive join would
        pick. Under a ``"|"`` join the two comparisons
        ``["/a", "/b|/c"]`` and ``["/a|/b", "/c"]`` — genuinely different dump
        sets — hash to the same id and the second silently overwrites the
        first. The explicit ``len(dump_paths)`` part is belt-and-braces: the
        encoding is already injective without it.

        Floats are rendered with :func:`repr`, which round-trips exactly in
        Python 3, so a threshold of ``200.0`` and one of ``200.0000001`` are
        different ids rather than the same one.
        """
        return _row_identity(
            project_id, alignment_method, str(len(dump_paths)),
            *[str(dp) for dp in dump_paths],
            repr(float(invariant_max)), repr(float(structural_max)),
            repr(float(pointer_max)),
        )

    @staticmethod
    def _candidate_identity(consensus_id: str, offset: int, length: int) -> str:
        """Deterministic ``candidate_id`` at the candidate grain.

        The grain is one row per ``(consensus_id, offset, length)`` — the same
        three columns as the ``candidate_region_unique`` index, deliberately:
        when the PK and the unique index disagree about the key, the PK never
        fires and the index silently collapses whole batches onto one row
        (measured on ``survival``: 63,481 submitted, six stored). Keeping them
        the same key makes that failure mode structurally impossible here.
        """
        return _row_identity(consensus_id, str(int(offset)), str(int(length)))

    def add_consensus_run(self, *, project_id: str = "",
                          dump_paths: Sequence[str] = (),
                          run_id: str = "",
                          alignment_method: str = ALIGNMENT_FILE_OFFSET,
                          bytes_compared: int = 0,
                          bytes_discarded: int = 0,
                          sizes_differed: bool = False,
                          alignment_warnings: Optional[Sequence[str]] = None,
                          invariant_max: float = _DEFAULT_INVARIANT_MAX,
                          structural_max: float = _DEFAULT_STRUCTURAL_MAX,
                          pointer_max: float = _DEFAULT_POINTER_MAX,
                          class_counts: Optional[Dict[str, int]] = None) -> str:
        """Record one N-dump comparison and return its ``consensus_id``.

        RETURNS THE ID, NOT A ROW COUNT, unlike the two batch writers. The
        count is always 1 and carries no information, while the id is the FK
        every :meth:`add_candidate_regions_batch` call needs; the same choice
        :meth:`create_project` and :meth:`start_run` make. ``""`` is the
        degrade-gracefully sentinel — an unavailable database writes nothing
        and says so by returning a falsy id, so a caller that goes on to write
        candidates under it gets an empty ``consensus_id`` and is REJECTED by
        that writer's guard rather than silently filing them under ``''``.

        *dump_paths* IS REQUIRED and must be non-empty. It is the load-bearing
        half of the identity, and an empty one is the same silent collapse
        ``survival.dump_path`` guards against: every comparison in a project
        sharing an alignment method and a boundary set would resolve to ONE
        ``consensus_id``, each run's histogram overwriting the last, with every
        call still returning a plausible-looking id.

        *alignment_method* comes from :data:`ALIGNMENT_METHODS` and defaults to
        the FALLBACK :data:`ALIGNMENT_FILE_OFFSET`, which is what
        ``engine.consensus._build_raw`` actually does today. Defaulting to the
        strongest method instead would have every pre-A1 producer claim an
        ASLR-aware alignment it never performed.

        *class_counts* is keyed by :data:`BYTE_CLASSES` name; unknown keys
        raise rather than being dropped, because a silently-dropped class turns
        a histogram into a smaller histogram that still looks complete.

        RE-RUN SAFE. ``consensus_id`` is derived from the comparison's identity
        (:meth:`_consensus_identity`), so re-running the same comparison
        UPDATES the observation columns (:data:`_CONSENSUS_RUN_UPDATE_COLUMNS`)
        of the one existing row. Wrapped in :meth:`_transaction` for the same
        reason the batch writers are — one statement is atomic on its own, but
        the wrapper is what keeps that true if a later change adds a second.
        """
        if not self._available:
            return ""
        _validate_choice(
            alignment_method, ALIGNMENT_METHODS,
            "consensus_runs.alignment_method",
            "project_db.unknown_alignment_method")
        paths = [str(dp) for dp in dump_paths]
        if not paths:
            raise CapabilityError(
                "add_consensus_run needs a non-empty dump_paths: the ordered"
                " dump set is what makes consensus_id unique, so without it"
                " every comparison in this project sharing an alignment method"
                " and a boundary set collapses onto one row and each run's"
                " histogram silently overwrites the last.",
                category=ErrorCategory.INVALID_INPUT,
                code="project_db.consensus_dump_paths_required",
            )
        counts = {str(k): int(v or 0) for k, v in (class_counts or {}).items()}
        for name in counts:
            _validate_choice(name, BYTE_CLASSES, "consensus_runs.class_counts key",
                             "project_db.unknown_byte_class")
        cid = self._consensus_identity(
            project_id, paths, alignment_method=alignment_method,
            invariant_max=invariant_max, structural_max=structural_max,
            pointer_max=pointer_max)
        values: List[Any] = [
            cid, project_id, run_id, _json_array(paths), len(paths),
            int(bytes_compared or 0), alignment_method,
            int(bytes_discarded or 0), bool(sizes_differed),
            _json_array(alignment_warnings),
            float(invariant_max), float(structural_max), float(pointer_max),
            counts.get("invariant", 0), counts.get("structural", 0),
            counts.get("pointer", 0), counts.get("key_candidate", 0),
            _now_iso(),
        ]
        with self._transaction():
            self._conn.execute(_INSERT_CONSENSUS_RUN, values)
        return cid

    @staticmethod
    def _candidate_payload_row(consensus_id: str, r: dict,
                               *, ts: str) -> List[Any]:
        """Validate one submitted candidate dict and render it in schema order.

        Split out of :meth:`add_candidate_regions_batch` so the writer stays a
        loop plus one transaction, matching :meth:`_survival_payload_row`.
        Unlike that one it never returns ``None``: a candidate has no
        equivalent of ``status = 'error'`` — every submitted region IS an
        observation.
        """
        byte_class = _validate_choice(
            str(r.get("byte_class", "") or ""), BYTE_CLASSES,
            "candidate_regions.byte_class",
            "project_db.unknown_byte_class")
        offset = int(r.get("offset", 0) or 0)
        length = int(r.get("length", 0) or 0)
        return [
            ProjectDB._candidate_identity(consensus_id, offset, length),
            consensus_id, offset, length, byte_class,
            float(r.get("mean_variance", 0.0) or 0.0),
            float(r.get("mean_entropy", 0.0) or 0.0),
            int(r.get("rank", 0) or 0),
            float(r.get("score", 0.0) or 0.0),
            float(r.get("score_class_weight", 0.0) or 0.0),
            float(r.get("score_variance_component", 0.0) or 0.0),
            float(r.get("score_entropy_component", 0.0) or 0.0),
            float(r.get("score_length_component", 0.0) or 0.0),
            ts,
        ]

    def add_candidate_regions_batch(self, consensus_id: str,
                                    rows: Sequence[dict]) -> int:
        """Bulk insert the ranked candidates of one comparison.

        Each dict may carry any ``candidate_regions`` column except
        ``candidate_id`` / ``consensus_id`` / ``created_at``, which are
        supplied here. ``byte_class`` is REQUIRED and validated against
        :data:`BYTE_CLASSES` — the whole point of the differential workflow is
        that a candidate's class is what makes it interesting, and an
        unclassified row is a row no class filter can ever return.

        *consensus_id* IS REQUIRED and non-empty, for the reason
        ``survival.dump_path`` is: it is the scoping half of the candidate key,
        so an empty one merges every comparison's candidates into a single
        ``('', offset, length)`` namespace where the second comparison's rows
        overwrite the first's at every shared offset — accepted, counted in the
        return value, and gone.

        RE-RUN SAFE, and that is what makes A3's ranking landable as a producer
        change: re-writing the same batch with scores filled in UPDATES the
        stored rows (:data:`_CANDIDATE_UPDATE_COLUMNS`) instead of doubling
        them. ``COUNT(*) == COUNT(DISTINCT consensus_id, offset, length)`` holds
        across any number of re-runs.

        The whole batch is written inside one transaction, so a failure
        part-way leaves NO partial candidate list behind. Load-bearing, not
        defensive: DuckDB's ``executemany`` is not atomic on its own, and half
        a ranked list reads downstream as a whole one.

        Returns the number of rows SUBMITTED (0 when unavailable or empty) —
        not "rows newly inserted", since a correct re-run re-submits rows that
        already exist. Every submitted row is written, so the count cannot
        claim more than happened.
        """
        if not self._available or not rows:
            return 0
        cid = _require_nonempty(
            str(consensus_id or ""),
            where="candidate_regions.consensus_id",
            code="project_db.candidate_consensus_id_required",
            why="It is the scoping half of the candidate key, so rows written"
                " without one share a namespace across every comparison in the"
                " database and the later batch silently overwrites the earlier"
                " one at every shared offset.",
        )
        ts = _now_iso()
        payload = [self._candidate_payload_row(cid, r, ts=ts) for r in rows]
        stmt = (_INSERT_CANDIDATE_PK_ONLY
                if "candidate_region_unique" in self._degraded_indexes
                else _INSERT_CANDIDATE)
        with self._transaction():
            self._conn.executemany(stmt, payload)
        return len(payload)

    # -- sweep control plane (the MUTABLE tables) -------------------------

    @staticmethod
    def _json_filter(value: object) -> str:
        """Render a sweep filter as a JSON array string (``''`` when unset).

        JSON, not a comma-joined string, because a library or version token
        containing the separator would otherwise re-parse into two filters — a
        sweep that silently covered a different slice than the one recorded.
        A string is passed through verbatim so a caller holding pre-rendered
        JSON is not double-encoded.
        """
        if value is None or value == "" or value == ():
            return ""
        if isinstance(value, str):
            return value
        return json.dumps(list(value))  # type: ignore[call-overload]

    def start_sweep(self, *, sweep_id: str = "", corpus_id: str = "",
                    corpus_label: str = "", config_digest: str = "",
                    max_units: int = 0, max_runs_per_library: int = 0,
                    library_filter: object = "", version_filter: object = "",
                    units_planned: int = 0,
                    status: str = "running") -> str:
        """Open (or re-declare) a ``sweeps`` row and return its ``sweep_id``.

        THE FILTER SET IS THE LOAD-BEARING PART. A five-run CI slice and a
        2,600-run publication run write the same SHAPE of rows, and nothing
        downstream can tell them apart from the rows alone. *max_units* /
        *max_runs_per_library* / *library_filter* / *version_filter* are what
        stop a bounded slice being published as a full-corpus result; ``0`` and
        ``''`` mean "unbounded", matching an unfiltered sweep.

        The returned id is what every ledger row of this sweep must carry —
        :meth:`add_survival_batch` and :meth:`add_expected_secrets_batch` both
        REQUIRE a non-empty ``sweep_id``, because one global project DB file
        holds every sweep.

        IDEMPOTENT BY DESIGN: passing an existing *sweep_id* re-declares that
        sweep (its plan and status are refreshed, its ``created_at`` is not),
        which is what a resume does on startup. Omit *sweep_id* to mint one.
        """
        if not self._available:
            return ""
        _validate_choice(status, SWEEP_STATUSES, "sweeps.status",
                         "project_db.unknown_sweep_status")
        sid = str(sweep_id or "") or _new_id()
        ts = _now_iso()
        self._conn.execute(_UPSERT_SWEEP, [
            sid, str(corpus_id or ""), str(corpus_label or ""),
            str(config_digest or ""), int(max_units or 0),
            int(max_runs_per_library or 0),
            self._json_filter(library_filter), self._json_filter(version_filter),
            status, int(units_planned or 0), ts, ts, "",
        ])
        return sid

    @staticmethod
    def _sweep_unit_identity(sweep_id: str, unit_key: str) -> Tuple[str, str, str]:
        """Validate a unit's natural key and return ``(sweep_id, unit_key, id)``.

        Shared by :meth:`record_sweep_unit_start` and
        :meth:`record_sweep_unit_done` so both resolve the SAME row: the
        ``sweep_unit_id`` is derived from the natural key, which is what lets a
        driver that crashed between claiming a unit and finishing it still
        record the outcome on the row it claimed.
        """
        sid = _require_nonempty(
            str(sweep_id or ""), where="sweep_units.sweep_id",
            code="project_db.sweep_id_required",
            why="A unit row that names no sweep cannot be resumed against one.")
        key = _require_nonempty(
            str(unit_key or ""), where="sweep_units.unit_key",
            code="project_db.sweep_unit_key_required",
            why="unit_key is the natural key of the watermark; empty ones all"
                " collapse onto a single row per sweep.")
        return sid, key, _row_identity(sid, key)

    def record_sweep_unit_start(self, sweep_id: str, unit_key: str, *,
                                inputs_digest: str = "", digest_level: str = "",
                                attempt: int = 1,
                                status: str = "running") -> str:
        """Claim one unit of *sweep_id* and return its ``sweep_unit_id``.

        Writes the unit's watermark row in the ``running`` state. Re-claiming a
        unit (a retry, or a resume that re-walks the plan) UPDATES that row
        rather than adding a second one — see
        :data:`_SWEEP_UNIT_START_UPDATE_COLUMNS` for what a re-claim is allowed
        to change. The result watermark is deliberately NOT among them: a retry
        that crashes before producing one must not erase the previous attempt's.

        *inputs_digest* / *digest_level* travel together on purpose. The level
        is part of the hashed payload, so switching it changes every digest at
        once; a resume comparing digests without comparing levels would read
        that as "everything changed" and silently re-sweep the whole corpus.
        """
        if not self._available:
            return ""
        _validate_choice(status, SWEEP_UNIT_STATUSES, "sweep_units.status",
                         "project_db.unknown_sweep_unit_status")
        sid, key, uid = self._sweep_unit_identity(sweep_id, unit_key)
        ts = _now_iso()
        self._conn.execute(_UPSERT_SWEEP_UNIT_START, [
            uid, sid, key, status, str(inputs_digest or ""),
            str(digest_level or ""), 0, 0, int(attempt or 0), ts, ts, "",
        ])
        return uid

    def record_sweep_unit_done(self, sweep_id: str, unit_key: str, *,
                               status: str = "done", result_offset: int = 0,
                               result_bytes: int = 0) -> str:
        """Close one unit of *sweep_id* and return its ``sweep_unit_id``.

        *status* must be a terminal :data:`SWEEP_UNIT_STATUSES` member.
        ``skipped`` is terminal too and is NOT coverage: it means "deliberately
        not swept", so a driver counting completed work must not add it to
        ``done``.

        *result_offset* / *result_bytes* are the watermark into the append-only
        results stream — where this unit's record starts and how long it is — so
        a resume can truncate a partial tail instead of re-reading everything.

        Upserts rather than UPDATEs, so a driver that crashed between claiming a
        unit and finishing it can still record the outcome; ``started_at`` and
        ``attempt`` are left to :meth:`record_sweep_unit_start`, keeping the
        finished attempt's duration and retry count readable.
        """
        if not self._available:
            return ""
        _validate_choice(status, SWEEP_UNIT_STATUSES, "sweep_units.status",
                         "project_db.unknown_sweep_unit_status")
        sid, key, uid = self._sweep_unit_identity(sweep_id, unit_key)
        ts = _now_iso()
        self._conn.execute(_UPSERT_SWEEP_UNIT_DONE, [
            uid, sid, key, status, "", "",
            int(result_offset or 0), int(result_bytes or 0), 0, ts, "", ts,
        ])
        return uid

    def finish_sweep(self, sweep_id: str, status: str = "completed") -> None:
        """Close a ``sweeps`` row with a terminal :data:`SWEEP_STATUSES` value.

        ``failed`` / ``cancelled`` are as important as ``completed``: a sweep
        left in ``running`` forever is indistinguishable from one still in
        flight, and a reader would treat its partial ledger as a finished one.
        """
        if not self._available:
            return
        _validate_choice(status, SWEEP_STATUSES, "sweeps.status",
                         "project_db.unknown_sweep_status")
        self._conn.execute(
            'UPDATE "sweeps" SET "status" = $1, "finished_at" = $2'
            ' WHERE "sweep_id" = $3',
            [status, _now_iso(), sweep_id])

    def persist_report(self, result: Optional[dict],
                       persist_ground_truth_labels: bool = True) -> None:
        """Persist a serialized AnalysisResult dict with transaction wrapping.

        When *persist_ground_truth_labels* is True, each confirmed hit (those
        with ``verified``/``confirmed`` set) is additionally recorded in the
        ``ground_truth`` table as a first-class label.

        Why the default is now ``True``
        -------------------------------
        The ``ground_truth`` table is the Phase-1 W5 proof ledger and the
        ``verified`` layer of the survival matrix. Left opt-in with no caller
        ever setting the flag, it is permanently EMPTY in production — the
        ledger exists but never records anything.

        The risk of the flip is near zero because only hits that already carry
        ``verified`` / ``confirmed`` are written, and that is populated solely by
        the ``verify_decryption`` path. On the ordinary analysis path (no
        verifier) the flip therefore adds exactly ZERO rows. The parameter is
        kept so a caller can still opt out explicitly.
        """
        if not self._available or result is None:
            return
        with self._transaction():
            for lib in result.get("libraries", []):
                library = lib.get("library", "unknown")
                protocol_version = lib.get("protocol_version", "")
                # FROZEN name format. `tests/test_project_db.py` pins
                # `projects[0]["name"] == "openssl_13"`, and downstream readers
                # (and existing project files) depend on it. The axes now also
                # live in dedicated columns; do NOT "fix" the name.
                name = f"{library}_{protocol_version}"
                phase = lib.get("phase", "")
                canonical_phase = lib.get("canonical_phase", "") or ""
                library_version = lib.get("library_version", "unknown")
                scenario = lib.get("scenario", "") or ""
                pid = self.create_project(
                    name, library=library, protocol_version=protocol_version,
                    library_version=library_version, scenario=scenario,
                    protocol=lib.get("protocol", "") or "",
                    version_axis=lib.get("version_axis", "protocol_version"),
                )
                rid = self.start_run(
                    pid, config={"phase": phase},
                    phase=phase, canonical_phase=canonical_phase,
                    library=library, protocol_version=protocol_version,
                    library_version=library_version, scenario=scenario,
                )
                hits = lib.get("hits", [])
                self.add_findings_batch(rid, [_finding_row_from_hit(h) for h in hits])
                if persist_ground_truth_labels:
                    confirmed = [h for h in hits if h.get("verified") or h.get("confirmed")]
                    self.persist_ground_truth(
                        rid, confirmed,
                        library=library,
                        version=protocol_version,
                        library_version=library_version,
                        scenario=scenario,
                        phase=phase,
                        canonical_phase=canonical_phase,
                    )
                self.finish_run(rid)

    @staticmethod
    def _ground_truth_identity(hit: dict, *, dump_id: str = "",
                               dump_path: str = "") -> str:
        """Deterministic ``gt_id`` at the table's grain.

        A ground-truth label IS the claim "this secret sits at this offset in
        this dump, confirmed this way". Two rows agreeing on all of that are
        the same label, not two pieces of evidence, so the identity is exactly
        those parts — and re-recording it is a no-op rather than a second row
        in the denominator every recall figure divides by.

        WHAT IS DELIBERATELY EXCLUDED, and why:

        * ``run_id`` — the ``analysis_runs`` uuid. It is freshly minted on
          every re-run, so including it would make ``ON CONFLICT`` inert and
          restore the exact double-count this fixes (the same trap
          :meth:`_expected_identity` documents). The first run's id is the one
          that stays on the row.
        * the corpus axes — ``library`` / ``scenario`` / ``phase`` and friends
          are DESCRIPTIONS of the dump the label already names by path, not
          independent identity. Folding them in would let a caller that
          resolved one axis differently file the same proof twice.

        The dump is keyed by its PATH in preference to ``dump_id``, for the
        same reason ``run_id`` is excluded: ``dumps.dump_id`` is a per-insert
        uuid, and the path is what is stable across re-runs. ``dump_id`` is the
        fallback for a caller that has no path.
        """
        dump_key = (str(hit.get("dump_path", dump_path) or "")
                    or str(hit.get("dump_id", dump_id) or ""))
        return _row_identity(
            dump_key,
            str(hit.get("offset")),
            str(hit.get("length")),
            str(hit.get("value_hex") or ""),
            str(_confirmed_by(hit) or ""),
            str(hit.get("secret_type", "") or ""),
        )

    def persist_ground_truth(self, run_id: str, hits: Sequence[dict],
                             *, library: str = "", version: str = "",
                             library_version: str = "unknown",
                             scenario: str = "", phase: str = "",
                             canonical_phase: str = "", dump_id: str = "",
                             dump_path: str = "", run_number: int = 0,
                             method: str = "") -> None:
        """Record confirmed key locations as first-class ground-truth labels.

        Inserts one ``ground_truth`` row per hit. No-op when DuckDB is absent
        or *hits* is empty. ``confirmed_by`` falls back to ``"verifier"`` when a
        hit is verified but carries no explicit label.

        The axis keyword arguments are per-call defaults; a hit dict carrying
        its own ``phase`` / ``canonical_phase`` / ``dump_id`` / ``dump_path`` /
        ``run_number`` / ``method`` wins, so a caller may mix runs in one batch.
        ``dump_path`` gained its per-call default last, so every axis column can
        now be stamped for a whole batch without rewriting each hit dict.

        ``method`` — the per-call default and any per-hit override — must be in
        :data:`METHODS`. The whole batch is validated before the first row is
        built, and the empty default stays legal (it means "unclassified", which
        is what every pre-v3 row holds).

        The secret bytes are written to BOTH ``key_hex`` and ``value_hex``.
        ``key_hex`` is the historical (mis-named) column and is kept verbatim
        for ``list_ground_truth`` consumers and the Phase-1 W5 ledger contract;
        ``value_hex`` is the correctly-named duplicate to read going forward.
        """
        if not self._available or not hits:
            return
        _validate_method(method, where="ground_truth.method")
        for h in hits:
            _validate_method(h.get("method", "") or "",
                             where="ground_truth.method")
        ts = _now_iso()
        rows = []
        for h in hits:
            value_hex = h.get("value_hex")
            rows.append([
                self._ground_truth_identity(h, dump_id=dump_id,
                                            dump_path=dump_path),
                run_id, h.get("offset"), h.get("length"),
                value_hex, h.get("secret_type", ""), h.get("cipher"),
                _confirmed_by(h), library, version, ts,
                h.get("phase", phase) or "",
                h.get("canonical_phase", canonical_phase) or "",
                h.get("dump_id", dump_id) or "",
                str(h.get("dump_path", dump_path) or ""),
                h.get("library_version", library_version) or "unknown",
                h.get("scenario", scenario) or "",
                int(h.get("run_number", run_number) or 0),
                h.get("method", method) or "",
                value_hex or "",
            ])
        self._conn.executemany(_INSERT_GROUND_TRUTH, rows)

    def record_ground_truth_run(self, hits: Sequence[dict], *, confirmed_by: str,
                                project_name: str = "oracle-run",
                                library: str = "", version: str = "",
                                library_version: str = "unknown",
                                scenario: str = "", run_number: int = 0,
                                phase: str = "", canonical_phase: str = "",
                                dump_id: str = "", dump_path: str = "") -> str:
        """File oracle/pcap-confirmed brute-force hits as ground-truth labels.

        The brute-force path owns confirmed hits but no project/run context, so
        this convenience wrapper creates a fresh project + run, normalizes the
        brute-force hit shape (``key_hex``) onto the ground_truth schema
        (``value_hex``), stamps every row with *confirmed_by*, and closes the
        run. Returns the run_id, or ``""`` when the DB is unavailable or there
        are no hits.

        The corpus axes — *library*, *version* (the PROTOCOL version, keeping
        the historical parameter name the ``ground_truth.version`` column uses),
        *library_version*, *scenario*, *run_number*, *phase*,
        *canonical_phase*, *dump_id*, *dump_path* — say what the analysed dump
        is an instance of. They are stamped on all three rows this writes (the
        project, the analysis run, and every ground_truth label), so the proof
        ledger can be sliced by axis without any reader re-deriving one from a
        path. Each keeps its historical default, so an ad-hoc dump that
        resolves to no axes still writes a usable row.

        ``method`` is deliberately NOT a parameter: it is derived from
        *confirmed_by* below, which is what keeps every row this writes inside
        the closed :data:`METHODS` vocabulary.
        """
        if not self._available or not hits:
            return ""
        pid = self.create_project(
            project_name, library=library, protocol_version=version,
            library_version=library_version, scenario=scenario,
        )
        rid = self.start_run(
            pid, dump_id, config={"source": confirmed_by},
            phase=phase, canonical_phase=canonical_phase,
            run_number=run_number, library=library,
            protocol_version=version, library_version=library_version,
            scenario=scenario,
        )
        rows = [
            {
                "offset": h.get("offset"),
                "length": h.get("length"),
                "value_hex": h.get("value_hex") or h.get("key_hex"),
                "secret_type": h.get("secret_type", ""),
                "cipher": h.get("cipher"),
                "confirmed_by": confirmed_by,
                "verified": True,
            }
            for h in hits
        ]
        # An oracle/pcap label is the strongest evidence class; anything else
        # reaching this wrapper came from the unproven brute-force candidate
        # path. Mapping it here keeps `method` inside the closed vocabulary
        # without the caller having to know about it.
        method = (METHOD_ORACLE if confirmed_by in SURVIVAL_FORBIDDEN_CONFIRMED_BY
                  else METHOD_BRUTE_FORCE)
        self.persist_ground_truth(
            rid, rows, library=library, version=version,
            library_version=library_version, scenario=scenario,
            phase=phase, canonical_phase=canonical_phase,
            dump_id=dump_id, dump_path=dump_path, run_number=run_number,
            method=method,
        )
        self.finish_run(rid)
        return rid

    # -- read (Ibis) -----------------------------------------------------

    def get_project(self, project_id: str) -> Optional[dict]:
        if not self._available:
            return None
        t = self._ibis.table("projects")
        rows = t.filter(t.project_id == project_id).execute().to_dict("records")
        return rows[0] if rows else None

    def list_projects(self) -> List[dict]:
        if not self._available:
            return []
        return self._ibis.table("projects").order_by("created_at").execute().to_dict("records")

    def query_findings(self, run_id: str,
                       finding_type: Optional[str] = None) -> List[dict]:
        if not self._available:
            return []
        t = self._ibis.table("findings")
        expr = t.filter(t.run_id == run_id)
        if finding_type is not None:
            expr = expr.filter(t.finding_type == finding_type)
        return expr.order_by("created_at").execute().to_dict("records")

    def project_timeline(self, project_id: str) -> List[dict]:
        if not self._available:
            return []
        t = self._ibis.table("analysis_runs")
        return t.filter(t.project_id == project_id).order_by("started_at").execute().to_dict("records")

    def list_ground_truth(self, run_id: Optional[str] = None) -> List[dict]:
        """Return ground-truth key labels, optionally filtered by *run_id*."""
        if not self._available:
            return []
        t = self._ibis.table("ground_truth")
        expr = t if run_id is None else t.filter(t.run_id == run_id)
        return expr.order_by("created_at").execute().to_dict("records")

    def finding_counts(self, run_id: str) -> dict:
        if not self._available:
            return {}
        t = self._ibis.table("findings")
        f = t.filter(t.run_id == run_id)
        rows = f.group_by("finding_type").agg(count=f.count()).execute().to_dict("records")
        return {r["finding_type"]: r["count"] for r in rows}

    # -- v4: differential-ledger reads ------------------------------------

    def consensus_runs(self, *, project_id: Optional[str] = None,
                       consensus_id: Optional[str] = None,
                       run_id: Optional[str] = None,
                       alignment_method: Optional[str] = None,
                       limit: Optional[int] = None) -> List[dict]:
        """Recorded N-dump comparisons, newest last, ``[]`` when unavailable.

        Every filter is optional and ANDed. *alignment_method* is validated
        against :data:`ALIGNMENT_METHODS`: a typo would otherwise return an
        empty list, which reads exactly like "this project has no VA-aligned
        comparisons" — the answer a reader is most likely to act on.

        Columns are accessed as ``t["name"]`` rather than ``t.name`` because
        three of them (``rank``, ``offset``, ``length``) collide with Ibis
        ``Table`` members; bracket access is uniform and cannot silently
        resolve to a method.
        """
        if not self._available:
            return []
        if alignment_method is not None:
            _validate_choice(
                alignment_method, ALIGNMENT_METHODS,
                "consensus_runs.alignment_method",
                "project_db.unknown_alignment_method")
        t = self._ibis.table("consensus_runs")
        expr = t
        if project_id is not None:
            expr = expr.filter(t["project_id"] == project_id)
        if consensus_id is not None:
            expr = expr.filter(t["consensus_id"] == consensus_id)
        if run_id is not None:
            expr = expr.filter(t["run_id"] == run_id)
        if alignment_method is not None:
            expr = expr.filter(t["alignment_method"] == alignment_method)
        expr = expr.order_by(["created_at", "consensus_id"])
        if limit is not None:
            expr = expr.limit(int(limit))
        return expr.execute().to_dict("records")

    def candidate_regions(self, consensus_id: Optional[str] = None, *,
                          byte_class: Optional[str] = None,
                          max_rank: Optional[int] = None,
                          min_score: Optional[float] = None,
                          min_length: Optional[int] = None,
                          max_length: Optional[int] = None,
                          limit: Optional[int] = None) -> List[dict]:
        """Ranked candidates, BEST FIRST, ``[]`` when unavailable.

        *max_rank* keeps the top N: **rank 1 is the best candidate**, so the
        useful bound is an upper one. A "minimum rank" filter would keep the
        WORST candidates, which is why this parameter is not spelled that way.
        Use *min_score* for a quality floor. It also excludes the UNRANKED rows
        (``rank = 0``, the column default) — they are not part of any top N,
        and admitting them is the loudest version of the rank-0 trap.

        Ordering is ``(rank == 0, rank, offset)``. Rank 0 is the column default
        and means UNRANKED (item A3 owns the scores that fill it), so a plain
        ascending sort on ``rank`` would put every un-scored row ABOVE the best
        scored one. The leading boolean key sorts the unranked block last; the
        offset tiebreak keeps the order total, so two calls never disagree.
        """
        if not self._available:
            return []
        if byte_class is not None:
            _validate_choice(byte_class, BYTE_CLASSES,
                             "candidate_regions.byte_class",
                             "project_db.unknown_byte_class")
        t = self._ibis.table("candidate_regions")
        expr = t
        if consensus_id is not None:
            expr = expr.filter(t["consensus_id"] == consensus_id)
        if byte_class is not None:
            expr = expr.filter(t["byte_class"] == byte_class)
        if max_rank is not None:
            # `rank >= 1` is NOT redundant: 0 is the column default and means
            # UNRANKED, so a bare `rank <= max_rank` would return the whole
            # un-scored tail as though it were the top N — the same inversion
            # the sort order guards against, and a far quieter one, since the
            # rows it wrongly admits look like perfectly ordinary candidates.
            expr = expr.filter(
                (t["rank"] >= 1) & (t["rank"] <= int(max_rank)))
        if min_score is not None:
            expr = expr.filter(t["score"] >= float(min_score))
        if min_length is not None:
            expr = expr.filter(t["length"] >= int(min_length))
        if max_length is not None:
            expr = expr.filter(t["length"] <= int(max_length))
        expr = expr.order_by([t["rank"] == 0, t["rank"], t["offset"]])
        if limit is not None:
            expr = expr.limit(int(limit))
        return expr.execute().to_dict("records")

    def candidate_class_counts(self, consensus_id: str) -> Dict[str, int]:
        """``{byte_class: n}`` for one comparison, ``{}`` when unavailable.

        The aggregation runs INSIDE DuckDB, as :meth:`finding_counts` does: the
        differential workflow's whole value is a 1,800x reduction of an 11 MB
        dump, and pulling six thousand candidate rows into Python to length()
        them by class would spend the reduction on the way out.
        """
        if not self._available:
            return {}
        t = self._ibis.table("candidate_regions")
        f = t.filter(t["consensus_id"] == consensus_id)
        rows = (f.group_by("byte_class").agg(count=f.count())
                .execute().to_dict("records"))
        return {r["byte_class"]: int(r["count"]) for r in rows}

