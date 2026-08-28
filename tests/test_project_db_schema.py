"""Schema-migration tests for :mod:`engine.project_db` (v1 -> v2 -> v3 -> v4).

The v2 schema adds columns to all five legacy tables plus three new tables; v3
adds ``findings.run_number``, four columns to ``survival``, three to
``expected_secrets``, and the ``sweeps`` / ``sweep_units`` control plane. Two
failure modes make this the riskiest change in the DB layer, and each has a test
here:

1. **CREATE-vs-ALTER divergence.** A fresh database gets its columns from
   ``CREATE TABLE``; a migrated one gets the new ones appended by
   ``ALTER TABLE``. If the two orders disagree, every positional read (and any
   future positional INSERT) silently reads the wrong column. See
   :func:`test_fresh_and_migrated_column_layouts_are_identical`.
2. **Data loss on migration.** Pre-existing rows must survive with the new
   columns back-filled from their ``DEFAULT``. See
   :func:`test_v1_rows_survive_migration_with_defaults`.

There are now THREE upgrade paths to cover, and each exercises something the
others cannot: a v2 database already HAS ``survival`` and ``expected_secrets``,
so ``CREATE TABLE IF NOT EXISTS`` is a no-op against it and the new columns can
only arrive by ``ALTER TABLE`` (a v1 database never sees that path, because it
gets both tables from a fresh ``CREATE``); and a v3 database is the newest
possible starting point, the one a user actually has on disk today, where v4's
two DIFFERENTIAL tables must appear beside a full complement of existing data
without disturbing any of it.

The v1 and v2 DDL and INSERTs below are FROZEN VERBATIM COPIES of the
``engine/project_db.py`` of their day. They must never be "kept in sync" with the
live module — the whole point is to reconstruct a genuinely old database file.
"""

import pytest

from memdiver.engine.project_db import (
    HAS_DUCKDB,
    _ADDED_COLUMNS,
    _SCHEMA_INDEXES,
    _SCHEMA_VERSION,
    _V2_TABLES,
)

if HAS_DUCKDB:
    import duckdb

    from memdiver.engine.project_db import ProjectDB

needs_duckdb = pytest.mark.skipif(not HAS_DUCKDB, reason="duckdb not installed")


# -- frozen v1 schema (verbatim copy — do NOT update) ----------------------

_V1_SCHEMA_SQL = [
    "CREATE TABLE IF NOT EXISTS projects(project_id VARCHAR PRIMARY KEY, name VARCHAR, created_at VARCHAR, description VARCHAR DEFAULT '')",
    "CREATE TABLE IF NOT EXISTS dumps(dump_id VARCHAR PRIMARY KEY, project_id VARCHAR, file_path VARCHAR, file_type VARCHAR, file_size BIGINT, added_at VARCHAR, metadata_json VARCHAR DEFAULT '{}')",
    "CREATE TABLE IF NOT EXISTS analysis_runs(run_id VARCHAR PRIMARY KEY, project_id VARCHAR, dump_id VARCHAR, started_at VARCHAR, finished_at VARCHAR, status VARCHAR DEFAULT 'running', config_json VARCHAR DEFAULT '{}')",
    "CREATE TABLE IF NOT EXISTS findings(finding_id VARCHAR PRIMARY KEY, run_id VARCHAR, finding_type VARCHAR, \"offset\" BIGINT, \"length\" INTEGER, value_hex VARCHAR, value_text VARCHAR, confidence DOUBLE DEFAULT 1.0, metadata_json VARCHAR DEFAULT '{}', created_at VARCHAR)",
    "CREATE TABLE IF NOT EXISTS ground_truth(gt_id VARCHAR PRIMARY KEY, run_id VARCHAR, \"offset\" BIGINT, \"length\" INTEGER, key_hex VARCHAR, secret_type VARCHAR, cipher VARCHAR, confirmed_by VARCHAR, library VARCHAR, version VARCHAR, created_at VARCHAR)",
]

_V1_TS = "2020-01-01T00:00:00+00:00"


# -- frozen v2 schema (verbatim copy — do NOT update) ----------------------
#
# What `_SCHEMA_SQL` emitted at `_SCHEMA_VERSION = 2`. A v2 database is the ONLY
# starting point that exercises `ALTER TABLE` against `survival` /
# `expected_secrets`: from v1 those two tables are created fresh, complete, by
# `CREATE TABLE IF NOT EXISTS`.

_V2_SCHEMA_SQL = [
    "CREATE TABLE IF NOT EXISTS \"projects\"(\"project_id\" VARCHAR PRIMARY KEY, \"name\" VARCHAR, \"created_at\" VARCHAR, \"description\" VARCHAR DEFAULT '', \"library\" VARCHAR DEFAULT '', \"protocol_version\" VARCHAR DEFAULT '', \"library_version\" VARCHAR DEFAULT 'unknown', \"version_axis\" VARCHAR DEFAULT 'protocol_version', \"scenario\" VARCHAR DEFAULT '', \"protocol\" VARCHAR DEFAULT '')",
    "CREATE TABLE IF NOT EXISTS \"dumps\"(\"dump_id\" VARCHAR PRIMARY KEY, \"project_id\" VARCHAR, \"file_path\" VARCHAR, \"file_type\" VARCHAR, \"file_size\" BIGINT, \"added_at\" VARCHAR, \"metadata_json\" VARCHAR DEFAULT '{}', \"phase\" VARCHAR DEFAULT '', \"canonical_phase\" VARCHAR DEFAULT '', \"run_number\" INTEGER DEFAULT 0, \"library\" VARCHAR DEFAULT '', \"run_id\" VARCHAR DEFAULT '')",
    "CREATE TABLE IF NOT EXISTS \"analysis_runs\"(\"run_id\" VARCHAR PRIMARY KEY, \"project_id\" VARCHAR, \"dump_id\" VARCHAR, \"started_at\" VARCHAR, \"finished_at\" VARCHAR, \"status\" VARCHAR DEFAULT 'running', \"config_json\" VARCHAR DEFAULT '{}', \"phase\" VARCHAR DEFAULT '', \"canonical_phase\" VARCHAR DEFAULT '', \"run_number\" INTEGER DEFAULT 0, \"library\" VARCHAR DEFAULT '', \"protocol_version\" VARCHAR DEFAULT '', \"library_version\" VARCHAR DEFAULT 'unknown', \"scenario\" VARCHAR DEFAULT '', \"run_dir\" VARCHAR DEFAULT '', \"keylog_path\" VARCHAR DEFAULT '', \"pcap_path\" VARCHAR DEFAULT '')",
    "CREATE TABLE IF NOT EXISTS \"findings\"(\"finding_id\" VARCHAR PRIMARY KEY, \"run_id\" VARCHAR, \"finding_type\" VARCHAR, \"offset\" BIGINT, \"length\" INTEGER, \"value_hex\" VARCHAR, \"value_text\" VARCHAR, \"confidence\" DOUBLE DEFAULT 1.0, \"metadata_json\" VARCHAR DEFAULT '{}', \"created_at\" VARCHAR, \"secret_type\" VARCHAR DEFAULT '', \"kind\" VARCHAR DEFAULT 'secret', \"method\" VARCHAR DEFAULT '', \"dump_path\" VARCHAR DEFAULT '', \"phase\" VARCHAR DEFAULT '', \"canonical_phase\" VARCHAR DEFAULT '', \"library\" VARCHAR DEFAULT '', \"verified\" BOOLEAN DEFAULT NULL)",
    "CREATE TABLE IF NOT EXISTS \"ground_truth\"(\"gt_id\" VARCHAR PRIMARY KEY, \"run_id\" VARCHAR, \"offset\" BIGINT, \"length\" INTEGER, \"key_hex\" VARCHAR, \"secret_type\" VARCHAR, \"cipher\" VARCHAR, \"confirmed_by\" VARCHAR, \"library\" VARCHAR, \"version\" VARCHAR, \"created_at\" VARCHAR, \"phase\" VARCHAR DEFAULT '', \"canonical_phase\" VARCHAR DEFAULT '', \"dump_id\" VARCHAR DEFAULT '', \"dump_path\" VARCHAR DEFAULT '', \"library_version\" VARCHAR DEFAULT 'unknown', \"scenario\" VARCHAR DEFAULT '', \"run_number\" INTEGER DEFAULT 0, \"method\" VARCHAR DEFAULT '', \"value_hex\" VARCHAR DEFAULT '')",
    "CREATE TABLE IF NOT EXISTS \"schema_meta\"(\"key\" VARCHAR PRIMARY KEY, \"value\" VARCHAR)",
    "CREATE TABLE IF NOT EXISTS \"expected_secrets\"(\"expected_id\" VARCHAR PRIMARY KEY, \"run_id\" VARCHAR, \"library\" VARCHAR, \"protocol_version\" VARCHAR, \"library_version\" VARCHAR DEFAULT 'unknown', \"version_axis\" VARCHAR DEFAULT 'protocol_version', \"protocol\" VARCHAR DEFAULT '', \"scenario\" VARCHAR DEFAULT '', \"run_number\" INTEGER DEFAULT 0, \"secret_type\" VARCHAR, \"identifier_hex\" VARCHAR DEFAULT '', \"secret_len\" INTEGER DEFAULT 0, \"keylog_path\" VARCHAR DEFAULT '', \"created_at\" VARCHAR)",
    "CREATE TABLE IF NOT EXISTS \"survival\"(\"survival_id\" VARCHAR PRIMARY KEY, \"run_id\" VARCHAR, \"dump_id\" VARCHAR DEFAULT '', \"library\" VARCHAR, \"protocol_version\" VARCHAR, \"library_version\" VARCHAR DEFAULT 'unknown', \"scenario\" VARCHAR DEFAULT '', \"run_number\" INTEGER DEFAULT 0, \"phase\" VARCHAR DEFAULT '', \"canonical_phase\" VARCHAR DEFAULT '', \"secret_type\" VARCHAR, \"present\" BOOLEAN, \"first_offset\" BIGINT, \"hit_count\" INTEGER DEFAULT 0, \"method\" VARCHAR DEFAULT '', \"dump_path\" VARCHAR DEFAULT '', \"created_at\" VARCHAR)",
]

_V2_TS = "2021-01-01T00:00:00+00:00"

#: Columns v3 appends to the two tables v2 introduced whole. Frozen here rather
#: than read back from ``_ADDED_COLUMNS`` so the test still fails loudly if a
#: later change quietly drops one.
_V3_COLUMNS_ON_V2_TABLES = {
    "expected_secrets": ("sweep_id", "dumps_in_run", "keylog_status"),
    "survival": ("sweep_id", "status", "format_name", "size_for_view"),
}


def _write_v2_db(db_path):
    """Create a v2 database file with one row in each of the two v2 ledgers."""
    conn = duckdb.connect(str(db_path))
    try:
        for ddl in _V2_SCHEMA_SQL:
            conn.execute(ddl)
        conn.execute(
            'INSERT INTO "schema_meta" VALUES ($1,$2)', ["schema_version", "2"])
        conn.execute(
            "INSERT INTO expected_secrets VALUES "
            "($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)",
            ["e1", "r1", "openssl", "13", "unknown", "protocol_version", "tls",
             "", 7, "CLIENT_RANDOM", "aa" * 32, 32, "/corpus/keylog.csv",
             _V2_TS])
        conn.execute(
            "INSERT INTO survival VALUES "
            "($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17)",
            ["s1", "r1", "d1", "openssl", "13", "unknown", "", 7,
             "pre_abort", "handshake_end", "CLIENT_RANDOM", True, 585148, 1,
             "keylog_substring", "/corpus/run7/pre_abort.dump", _V2_TS])
    finally:
        conn.close()


# -- frozen v3 schema (verbatim copy — do NOT update) ----------------------
#
# What `_SCHEMA_SQL` emitted at `_SCHEMA_VERSION = 3`: everything the live
# module has except v4's `consensus_runs` / `candidate_regions`. This is the
# newest starting point, and the one a real user's file is at today.

_V3_SCHEMA_SQL = [
    'CREATE TABLE IF NOT EXISTS "projects"("project_id" VARCHAR PRIMARY KEY, "name" VARCHAR, "created_at" VARCHAR, "description" VARCHAR DEFAULT \'\', "library" VARCHAR DEFAULT \'\', "protocol_version" VARCHAR DEFAULT \'\', "library_version" VARCHAR DEFAULT \'unknown\', "version_axis" VARCHAR DEFAULT \'protocol_version\', "scenario" VARCHAR DEFAULT \'\', "protocol" VARCHAR DEFAULT \'\')',
    'CREATE TABLE IF NOT EXISTS "dumps"("dump_id" VARCHAR PRIMARY KEY, "project_id" VARCHAR, "file_path" VARCHAR, "file_type" VARCHAR, "file_size" BIGINT, "added_at" VARCHAR, "metadata_json" VARCHAR DEFAULT \'{}\', "phase" VARCHAR DEFAULT \'\', "canonical_phase" VARCHAR DEFAULT \'\', "run_number" INTEGER DEFAULT 0, "library" VARCHAR DEFAULT \'\', "run_id" VARCHAR DEFAULT \'\')',
    'CREATE TABLE IF NOT EXISTS "analysis_runs"("run_id" VARCHAR PRIMARY KEY, "project_id" VARCHAR, "dump_id" VARCHAR, "started_at" VARCHAR, "finished_at" VARCHAR, "status" VARCHAR DEFAULT \'running\', "config_json" VARCHAR DEFAULT \'{}\', "phase" VARCHAR DEFAULT \'\', "canonical_phase" VARCHAR DEFAULT \'\', "run_number" INTEGER DEFAULT 0, "library" VARCHAR DEFAULT \'\', "protocol_version" VARCHAR DEFAULT \'\', "library_version" VARCHAR DEFAULT \'unknown\', "scenario" VARCHAR DEFAULT \'\', "run_dir" VARCHAR DEFAULT \'\', "keylog_path" VARCHAR DEFAULT \'\', "pcap_path" VARCHAR DEFAULT \'\')',
    'CREATE TABLE IF NOT EXISTS "findings"("finding_id" VARCHAR PRIMARY KEY, "run_id" VARCHAR, "finding_type" VARCHAR, "offset" BIGINT, "length" INTEGER, "value_hex" VARCHAR, "value_text" VARCHAR, "confidence" DOUBLE DEFAULT 1.0, "metadata_json" VARCHAR DEFAULT \'{}\', "created_at" VARCHAR, "secret_type" VARCHAR DEFAULT \'\', "kind" VARCHAR DEFAULT \'secret\', "method" VARCHAR DEFAULT \'\', "dump_path" VARCHAR DEFAULT \'\', "phase" VARCHAR DEFAULT \'\', "canonical_phase" VARCHAR DEFAULT \'\', "library" VARCHAR DEFAULT \'\', "verified" BOOLEAN DEFAULT NULL, "run_number" INTEGER DEFAULT 0)',
    'CREATE TABLE IF NOT EXISTS "ground_truth"("gt_id" VARCHAR PRIMARY KEY, "run_id" VARCHAR, "offset" BIGINT, "length" INTEGER, "key_hex" VARCHAR, "secret_type" VARCHAR, "cipher" VARCHAR, "confirmed_by" VARCHAR, "library" VARCHAR, "version" VARCHAR, "created_at" VARCHAR, "phase" VARCHAR DEFAULT \'\', "canonical_phase" VARCHAR DEFAULT \'\', "dump_id" VARCHAR DEFAULT \'\', "dump_path" VARCHAR DEFAULT \'\', "library_version" VARCHAR DEFAULT \'unknown\', "scenario" VARCHAR DEFAULT \'\', "run_number" INTEGER DEFAULT 0, "method" VARCHAR DEFAULT \'\', "value_hex" VARCHAR DEFAULT \'\')',
    'CREATE TABLE IF NOT EXISTS "schema_meta"("key" VARCHAR PRIMARY KEY, "value" VARCHAR)',
    'CREATE TABLE IF NOT EXISTS "expected_secrets"("expected_id" VARCHAR PRIMARY KEY, "run_id" VARCHAR, "library" VARCHAR, "protocol_version" VARCHAR, "library_version" VARCHAR DEFAULT \'unknown\', "version_axis" VARCHAR DEFAULT \'protocol_version\', "protocol" VARCHAR DEFAULT \'\', "scenario" VARCHAR DEFAULT \'\', "run_number" INTEGER DEFAULT 0, "secret_type" VARCHAR, "identifier_hex" VARCHAR DEFAULT \'\', "secret_len" INTEGER DEFAULT 0, "keylog_path" VARCHAR DEFAULT \'\', "created_at" VARCHAR, "sweep_id" VARCHAR DEFAULT \'\', "dumps_in_run" INTEGER DEFAULT 0, "keylog_status" VARCHAR DEFAULT \'\')',
    'CREATE TABLE IF NOT EXISTS "survival"("survival_id" VARCHAR PRIMARY KEY, "run_id" VARCHAR, "dump_id" VARCHAR DEFAULT \'\', "library" VARCHAR, "protocol_version" VARCHAR, "library_version" VARCHAR DEFAULT \'unknown\', "scenario" VARCHAR DEFAULT \'\', "run_number" INTEGER DEFAULT 0, "phase" VARCHAR DEFAULT \'\', "canonical_phase" VARCHAR DEFAULT \'\', "secret_type" VARCHAR, "present" BOOLEAN, "first_offset" BIGINT, "hit_count" INTEGER DEFAULT 0, "method" VARCHAR DEFAULT \'\', "dump_path" VARCHAR DEFAULT \'\', "created_at" VARCHAR, "sweep_id" VARCHAR DEFAULT \'\', "status" VARCHAR DEFAULT \'searched\', "format_name" VARCHAR DEFAULT \'\', "size_for_view" BIGINT DEFAULT 0)',
    'CREATE TABLE IF NOT EXISTS "sweeps"("sweep_id" VARCHAR PRIMARY KEY, "corpus_id" VARCHAR DEFAULT \'\', "corpus_label" VARCHAR DEFAULT \'\', "config_digest" VARCHAR DEFAULT \'\', "max_units" INTEGER DEFAULT 0, "max_runs_per_library" INTEGER DEFAULT 0, "library_filter" VARCHAR DEFAULT \'\', "version_filter" VARCHAR DEFAULT \'\', "status" VARCHAR DEFAULT \'pending\', "units_planned" INTEGER DEFAULT 0, "created_at" VARCHAR DEFAULT \'\', "started_at" VARCHAR DEFAULT \'\', "finished_at" VARCHAR DEFAULT \'\')',
    'CREATE TABLE IF NOT EXISTS "sweep_units"("sweep_unit_id" VARCHAR PRIMARY KEY, "sweep_id" VARCHAR, "unit_key" VARCHAR, "status" VARCHAR DEFAULT \'pending\', "inputs_digest" VARCHAR DEFAULT \'\', "digest_level" VARCHAR DEFAULT \'\', "result_offset" BIGINT DEFAULT 0, "result_bytes" BIGINT DEFAULT 0, "attempt" INTEGER DEFAULT 0, "created_at" VARCHAR DEFAULT \'\', "started_at" VARCHAR DEFAULT \'\', "finished_at" VARCHAR DEFAULT \'\')',
]

_V3_TS = "2022-01-01T00:00:00+00:00"

#: The tables v4 introduces whole. Frozen here rather than read back from
#: ``_V2_TABLES`` so the test still fails loudly if a later change drops one.
_V4_TABLES = ("consensus_runs", "candidate_regions")


def _write_v3_db(db_path):
    """Create a v3 database file with a row in the ledger and control plane."""
    conn = duckdb.connect(str(db_path))
    try:
        for ddl in _V3_SCHEMA_SQL:
            conn.execute(ddl)
        conn.execute(
            'INSERT INTO "schema_meta" VALUES ($1,$2)', ["schema_version", "3"])
        conn.execute(
            "INSERT INTO survival VALUES ("
            + ",".join("$" + str(i) for i in range(1, 22)) + ")",
            ["s1", "r1", "d1", "openssl", "13", "unknown", "", 7,
             "pre_abort", "handshake_end", "CLIENT_RANDOM", True, 585148, 1,
             "keylog_substring", "/corpus/run7/pre_abort.dump", _V3_TS,
             "sweep-1", "searched", "raw", 11223040])
        conn.execute(
            "INSERT INTO sweeps VALUES ("
            + ",".join("$" + str(i) for i in range(1, 14)) + ")",
            ["sweep-1", "corpus-a", "tls_dumps", "digest-1", 0, 0, "", "",
             "completed", 18917, _V3_TS, _V3_TS, _V3_TS])
    finally:
        conn.close()


def _write_v1_db(db_path):
    """Create a v1 database file with one row in every legacy table.

    Uses the historical POSITIONAL inserts on purpose: that is what a database
    written by the old code actually contains.
    """
    conn = duckdb.connect(str(db_path))
    try:
        for ddl in _V1_SCHEMA_SQL:
            conn.execute(ddl)
        conn.execute("INSERT INTO projects VALUES ($1,$2,$3,$4)",
                     ["p1", "openssl_13", _V1_TS, "legacy project"])
        conn.execute("INSERT INTO dumps VALUES ($1,$2,$3,$4,$5,$6,$7)",
                     ["d1", "p1", "/tmp/legacy.dump", "raw", 4096, _V1_TS, "{}"])
        conn.execute("INSERT INTO analysis_runs VALUES ($1,$2,$3,$4,$5,$6,$7)",
                     ["r1", "p1", "d1", _V1_TS, _V1_TS, "completed",
                      '{"phase": "pre_abort"}'])
        conn.execute("INSERT INTO findings VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)",
                     ["f1", "r1", "CLIENT_RANDOM", 1024, 32, "ab" * 32, None,
                      1.0, '{"confirmed": true}', _V1_TS])
        conn.execute(
            "INSERT INTO ground_truth VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)",
            ["g1", "r1", 1024, 32, "ab" * 32, "CLIENT_RANDOM", "AES_256_GCM",
             "verifier", "openssl", "13", _V1_TS])
    finally:
        conn.close()


def _column_layout(db_path):
    """``{table: [column_name, ...]}`` in physical schema order."""
    conn = duckdb.connect(str(db_path))
    try:
        rows = conn.execute(
            "SELECT table_name, column_name FROM duckdb_columns() "
            "ORDER BY table_name, column_index"
        ).fetchall()
    finally:
        conn.close()
    layout = {}
    for table, column in rows:
        layout.setdefault(table, []).append(column)
    return layout


def _one_row(db_path, table):
    """Single row of *table* as a ``{column: value}`` dict."""
    conn = duckdb.connect(str(db_path))
    try:
        cur = conn.execute('SELECT * FROM "' + table + '"')
        names = [d[0] for d in cur.description]
        return dict(zip(names, cur.fetchone()))
    finally:
        conn.close()


# -- (a) v1 -> v2 migration -----------------------------------------------

@needs_duckdb
def test_migration_adds_every_new_column(tmp_path):
    """Opening a v1 database appends every column in ``_ADDED_COLUMNS``."""
    db_path = tmp_path / "legacy.duckdb"
    _write_v1_db(db_path)

    before = _column_layout(db_path)
    for table, columns in _ADDED_COLUMNS.items():
        # `survival` / `expected_secrets` do not exist at all in v1; their v3
        # additions arrive with the fresh CREATE, not by ALTER.
        for name, _ddl in columns:
            assert name not in before.get(table, []), (
                f"{table}.{name} must be absent from the frozen v1 schema"
            )

    with ProjectDB(db_path):
        pass

    after = _column_layout(db_path)
    for table, columns in _ADDED_COLUMNS.items():
        for name, _ddl in columns:
            assert name in after[table], f"migration did not add {table}.{name}"


@needs_duckdb
def test_migration_creates_the_new_tables(tmp_path):
    """``schema_meta``, ``expected_secrets`` and ``survival`` appear."""
    db_path = tmp_path / "legacy.duckdb"
    _write_v1_db(db_path)
    assert "survival" not in _column_layout(db_path)

    with ProjectDB(db_path):
        pass

    layout = _column_layout(db_path)
    assert "schema_meta" in layout
    assert "expected_secrets" in layout
    assert "survival" in layout
    # `present` is the three-state carrier; its absence would break the whole
    # looked-and-absent vs never-attempted distinction.
    assert "present" in layout["survival"]


@needs_duckdb
def test_v1_rows_survive_migration_with_defaults(tmp_path):
    """Pre-existing rows keep their values and get the new columns back-filled."""
    db_path = tmp_path / "legacy.duckdb"
    _write_v1_db(db_path)
    with ProjectDB(db_path):
        pass

    project = _one_row(db_path, "projects")
    assert project["project_id"] == "p1"
    assert project["name"] == "openssl_13"
    assert project["created_at"] == _V1_TS
    assert project["description"] == "legacy project"
    assert project["library"] == ""
    assert project["library_version"] == "unknown"
    assert project["version_axis"] == "protocol_version"

    dump = _one_row(db_path, "dumps")
    assert dump["file_path"] == "/tmp/legacy.dump"
    assert dump["file_size"] == 4096
    assert dump["run_number"] == 0
    assert dump["run_id"] == ""

    run = _one_row(db_path, "analysis_runs")
    assert run["status"] == "completed"
    assert run["config_json"] == '{"phase": "pre_abort"}'
    assert run["phase"] == ""
    assert run["library_version"] == "unknown"

    finding = _one_row(db_path, "findings")
    assert finding["finding_type"] == "CLIENT_RANDOM"
    assert finding["offset"] == 1024
    assert finding["value_hex"] == "ab" * 32
    assert finding["kind"] == "secret"
    assert finding["method"] == ""
    # Three-valued on purpose: a legacy row was never verified, which is not
    # the same as "verified and rejected".
    assert finding["verified"] is None

    gt = _one_row(db_path, "ground_truth")
    assert gt["key_hex"] == "ab" * 32
    assert gt["confirmed_by"] == "verifier"
    # The new correctly-named column defaults empty for legacy rows; only rows
    # written by v2 code carry it.
    assert gt["value_hex"] == ""
    assert gt["library_version"] == "unknown"


@needs_duckdb
def test_migration_records_schema_version(tmp_path):
    db_path = tmp_path / "legacy.duckdb"
    _write_v1_db(db_path)
    with ProjectDB(db_path):
        pass
    conn = duckdb.connect(str(db_path))
    try:
        row = conn.execute(
            'SELECT "value" FROM "schema_meta" WHERE "key" = $1',
            ["schema_version"]).fetchone()
    finally:
        conn.close()
    assert row is not None
    assert row[0] == "4"
    assert row[0] == str(_SCHEMA_VERSION)


# -- (a2) v2 -> v3 migration ----------------------------------------------

@needs_duckdb
def test_v2_migration_alters_the_v2_tables(tmp_path):
    """A v2 database grows the v3 columns on ``survival`` / ``expected_secrets``.

    This is the path ``CREATE TABLE IF NOT EXISTS`` cannot serve: both tables
    already exist, so the statement is a no-op and the only way the new columns
    arrive is ``ALTER TABLE``. A v1 database never exercises it.
    """
    db_path = tmp_path / "v2.duckdb"
    _write_v2_db(db_path)

    before = _column_layout(db_path)
    for table, names in _V3_COLUMNS_ON_V2_TABLES.items():
        assert table in before, f"{table} must already exist in a v2 database"
        for name in names:
            assert name not in before[table], (
                f"{table}.{name} must be absent from the frozen v2 schema"
            )
    assert "run_number" not in before["findings"]

    with ProjectDB(db_path):
        pass

    after = _column_layout(db_path)
    for table, names in _V3_COLUMNS_ON_V2_TABLES.items():
        for name in names:
            assert name in after[table], f"v3 migration did not add {table}.{name}"
    assert "run_number" in after["findings"]


@needs_duckdb
def test_v2_migration_creates_the_sweep_control_plane(tmp_path):
    db_path = tmp_path / "v2.duckdb"
    _write_v2_db(db_path)
    layout = _column_layout(db_path)
    assert "sweeps" not in layout
    assert "sweep_units" not in layout

    with ProjectDB(db_path):
        pass

    layout = _column_layout(db_path)
    # The filter set is the load-bearing part: it is what stops a bounded CI
    # slice being published as a full-corpus result.
    for name in ("max_units", "max_runs_per_library",
                 "library_filter", "version_filter", "config_digest"):
        assert name in layout["sweeps"], f"sweeps.{name} missing"
    for name in ("unit_key", "inputs_digest", "digest_level",
                 "result_offset", "result_bytes", "attempt", "status"):
        assert name in layout["sweep_units"], f"sweep_units.{name} missing"


@needs_duckdb
def test_v2_rows_survive_v3_migration_with_defaults(tmp_path):
    """v2 ledger rows keep their values; the v3 columns back-fill."""
    db_path = tmp_path / "v2.duckdb"
    _write_v2_db(db_path)
    with ProjectDB(db_path):
        pass

    expected = _one_row(db_path, "expected_secrets")
    assert expected["expected_id"] == "e1"
    assert expected["secret_type"] == "CLIENT_RANDOM"
    assert expected["keylog_path"] == "/corpus/keylog.csv"
    assert expected["sweep_id"] == ""
    assert expected["dumps_in_run"] == 0
    assert expected["keylog_status"] == ""

    survival = _one_row(db_path, "survival")
    assert survival["survival_id"] == "s1"
    assert survival["present"] is True
    assert survival["first_offset"] == 585148
    assert survival["sweep_id"] == ""
    # Every pre-v3 row WAS searched, so the back-fill states the truth rather
    # than inventing an "unknown" state.
    assert survival["status"] == "searched"
    assert survival["format_name"] == ""
    assert survival["size_for_view"] == 0


@needs_duckdb
def test_v2_migration_records_schema_version_4(tmp_path):
    db_path = tmp_path / "v2.duckdb"
    _write_v2_db(db_path)
    with ProjectDB(db_path):
        pass
    row = _one_row(db_path, "schema_meta")
    assert row["value"] == "4" == str(_SCHEMA_VERSION)


# -- (a3) v3 -> v4 migration: the DIFFERENTIAL ledger ----------------------

@needs_duckdb
def test_v3_migration_creates_the_differential_ledger(tmp_path):
    """``consensus_runs`` / ``candidate_regions`` appear on a v3 database.

    v4 adds no column to any existing table, so ``CREATE TABLE IF NOT EXISTS``
    IS the whole migration — which is exactly the case that looks safe and
    silently is not if a new table is added to ``_ADDED_COLUMNS`` instead of
    ``_V2_TABLES``, or is added to ``_V2_TABLES`` but never reaches
    ``_TABLE_COLUMNS``.
    """
    db_path = tmp_path / "v3.duckdb"
    _write_v3_db(db_path)
    before = _column_layout(db_path)
    for table in _V4_TABLES:
        assert table not in before, f"{table} must be absent from a v3 database"

    with ProjectDB(db_path):
        pass

    after = _column_layout(db_path)
    # The alignment provenance is the load-bearing part of `consensus_runs`:
    # it is what stops a flat-offset fallback result being compared against a
    # VA-aligned one.
    for name in ("dump_paths", "n_dumps", "bytes_compared", "alignment_method",
                 "bytes_discarded", "sizes_differed", "invariant_max",
                 "structural_max", "pointer_max", "invariant_bytes",
                 "structural_bytes", "pointer_bytes", "key_candidate_bytes"):
        assert name in after["consensus_runs"], f"consensus_runs.{name} missing"
    for name in ("consensus_id", "offset", "length", "byte_class",
                 "mean_variance", "mean_entropy", "rank", "score"):
        assert name in after["candidate_regions"], (
            f"candidate_regions.{name} missing")


@needs_duckdb
def test_v3_rows_survive_v4_migration(tmp_path):
    """A v3 database's existing rows are untouched by the v4 upgrade."""
    db_path = tmp_path / "v3.duckdb"
    _write_v3_db(db_path)
    with ProjectDB(db_path):
        pass

    survival = _one_row(db_path, "survival")
    assert survival["survival_id"] == "s1"
    assert survival["present"] is True
    assert survival["first_offset"] == 585148
    assert survival["sweep_id"] == "sweep-1"
    assert survival["status"] == "searched"
    assert survival["size_for_view"] == 11223040
    assert survival["created_at"] == _V3_TS

    sweep = _one_row(db_path, "sweeps")
    assert sweep["sweep_id"] == "sweep-1"
    assert sweep["units_planned"] == 18917
    assert sweep["status"] == "completed"


@needs_duckdb
def test_v3_migration_records_schema_version_4(tmp_path):
    db_path = tmp_path / "v3.duckdb"
    _write_v3_db(db_path)
    with ProjectDB(db_path):
        pass
    row = _one_row(db_path, "schema_meta")
    assert row["value"] == "4" == str(_SCHEMA_VERSION)


@needs_duckdb
def test_unique_indexes_exist_on_a_fresh_database(tmp_path):
    """The uniqueness that no single-column PRIMARY KEY can express is present.

    Declared as an index rather than a ``UNIQUE(...)`` table constraint because
    only ``CREATE TABLE`` can carry a table constraint — an existing database
    could never acquire one, and fresh vs migrated would then disagree about
    what is unique.
    """
    db_path = tmp_path / "fresh.duckdb"
    with ProjectDB(db_path):
        pass
    conn = duckdb.connect(str(db_path))
    try:
        names = {r[0] for r in conn.execute(
            "SELECT index_name FROM duckdb_indexes()").fetchall()}
    finally:
        conn.close()
    for name, _table, _cols in _SCHEMA_INDEXES:
        assert name in names, f"missing unique index {name}"


@needs_duckdb
def test_unique_indexes_also_reach_a_migrated_database(tmp_path):
    """The v2 upgrade path gets the same indexes as a fresh CREATE."""
    db_path = tmp_path / "v2.duckdb"
    _write_v2_db(db_path)
    with ProjectDB(db_path):
        pass
    conn = duckdb.connect(str(db_path))
    try:
        names = {r[0] for r in conn.execute(
            "SELECT index_name FROM duckdb_indexes()").fetchall()}
    finally:
        conn.close()
    for name, _table, _cols in _SCHEMA_INDEXES:
        assert name in names, f"missing unique index {name} after migration"


@needs_duckdb
def test_duplicate_rows_do_not_lock_the_user_out(tmp_path, caplog):
    """A pre-existing database holding duplicates opens with a warning.

    The one way the unique index can fail to build is a database that already
    contains the duplicate rows the index exists to prevent — precisely the
    database whose owner must not be locked out. De-duplicating it here would
    mean deleting their rows to satisfy a constraint they never asked for.
    """
    db_path = tmp_path / "dupes.duckdb"
    _write_v2_db(db_path)
    conn = duckdb.connect(str(db_path))
    try:
        conn.execute(
            "INSERT INTO survival VALUES "
            "($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,$17)",
            ["s2", "r1", "d1", "openssl", "13", "unknown", "", 7,
             "pre_abort", "handshake_end", "CLIENT_RANDOM", True, 585148, 1,
             "keylog_substring", "/corpus/run7/pre_abort.dump", _V2_TS])
    finally:
        conn.close()

    with caplog.at_level("WARNING", logger="memdiver.engine.project_db"):
        with ProjectDB(db_path) as db:
            assert db._available is True
            assert db.create_project("still works") != ""
    assert any("survival" in r.getMessage() for r in caplog.records)


# -- (b) idempotence -------------------------------------------------------

@needs_duckdb
def test_open_twice_is_idempotent(tmp_path):
    """A second open() changes neither the layout nor the version row."""
    db_path = tmp_path / "legacy.duckdb"
    _write_v1_db(db_path)
    with ProjectDB(db_path):
        pass
    first = _column_layout(db_path)
    with ProjectDB(db_path):
        pass
    assert _column_layout(db_path) == first

    conn = duckdb.connect(str(db_path))
    try:
        rows = conn.execute(
            'SELECT "key", "value" FROM "schema_meta"').fetchall()
    finally:
        conn.close()
    assert rows == [("schema_version", str(_SCHEMA_VERSION))]


@needs_duckdb
def test_open_fresh_twice_is_idempotent(tmp_path):
    db_path = tmp_path / "fresh.duckdb"
    with ProjectDB(db_path):
        pass
    first = _column_layout(db_path)
    with ProjectDB(db_path) as db:
        pid = db.create_project("still works")
        assert pid != ""
    assert _column_layout(db_path) == first


# -- (c) the divergence test ----------------------------------------------

@needs_duckdb
def test_fresh_and_migrated_column_layouts_are_identical(tmp_path):
    """A fresh database and a migrated one have the same columns IN THE SAME ORDER.

    This is the test that catches CREATE-vs-ALTER divergence — the #1 failure
    mode of this migration. ``ALTER TABLE ... ADD COLUMN`` can only append, so
    the ``CREATE TABLE`` statements must list the v1 columns first and the
    ``_ADDED_COLUMNS`` afterwards in exactly that order.
    """
    fresh_path = tmp_path / "fresh.duckdb"
    with ProjectDB(fresh_path):
        pass

    migrated_path = tmp_path / "migrated.duckdb"
    _write_v1_db(migrated_path)
    with ProjectDB(migrated_path):
        pass

    # The v2 starting point is a DISTINCT risk, not a duplicate of the v1 one:
    # it is the only path where `survival` / `expected_secrets` get their new
    # columns appended by ALTER instead of created in order by CREATE.
    from_v2_path = tmp_path / "from_v2.duckdb"
    _write_v2_db(from_v2_path)
    with ProjectDB(from_v2_path):
        pass

    # v3 is the newest starting point and the one users actually hold. It adds
    # no `ALTER` of its own, which is precisely why it is worth checking: a v4
    # table wired up wrongly (declared in `_V2_TABLES` but lost by the
    # `_TABLE_COLUMNS` fold, say) shows up here as a missing table rather than
    # as a column-order difference.
    from_v3_path = tmp_path / "from_v3.duckdb"
    _write_v3_db(from_v3_path)
    with ProjectDB(from_v3_path):
        pass

    fresh = _column_layout(fresh_path)
    for label, path in (("migrated from v1", migrated_path),
                        ("migrated from v2", from_v2_path),
                        ("migrated from v3", from_v3_path)):
        migrated = _column_layout(path)
        assert sorted(fresh) == sorted(migrated), f"table sets differ ({label})"
        for table in sorted(fresh):
            assert fresh[table] == migrated[table], (
                f"column ORDER diverges for {table} ({label}):\n"
                f"  fresh   = {fresh[table]}\n"
                f"  migrated= {migrated[table]}"
            )


@needs_duckdb
def test_every_v2_table_is_reachable_from_table_columns():
    """``_V2_TABLES`` entries must survive the ``_TABLE_COLUMNS`` fold.

    ``_TABLE_COLUMNS`` used to be built from ``_V1_COLUMNS`` and then
    ``.update(_V2_TABLES)``, which OVERWRITES rather than folds: every
    ``_ADDED_COLUMNS`` entry for a v2 table (``survival.status``,
    ``expected_secrets.sweep_id``, …) was silently dropped from
    ``_TABLE_COLUMNS``.

    WHAT THAT ACTUALLY BROKE — and what it did NOT. It did not cause a
    fresh/migrated column-order divergence, and this test is NOT a weaker copy
    of ``test_fresh_and_migrated_layouts_are_identical``: a fresh database has
    no ``schema_meta`` row, so ``_read_schema_version()`` returns 1,
    ``_ensure_columns()`` runs on the fresh path TOO, and both layouts end up
    identical. The real symptom was a LOUD CRASH — ``_all_columns()`` built
    every INSERT four columns short, so the first ledger write died with
    ``Prepared statement needs 17 parameters, 21 given``.

    Keep this test. It is the only structural guard on the fold itself; the
    layout test cannot see the bug, because under the bug the two layouts still
    agreed with each other.
    """
    from memdiver.engine.project_db import _all_columns

    for table, columns in _V2_TABLES.items():
        live = _all_columns(table)
        introduced = tuple(name for name, _ddl in columns)
        assert live[:len(introduced)] == introduced, (
            f"{table} lost or reordered its introducing columns"
        )
        for name, _ddl in _ADDED_COLUMNS.get(table, ()):
            assert name in live, f"{table}.{name} vanished from _TABLE_COLUMNS"


# -- forward compatibility -------------------------------------------------

@needs_duckdb
def test_newer_schema_version_warns_but_opens(tmp_path, caplog):
    """A DB stamped with a newer version opens read/write instead of crashing."""
    db_path = tmp_path / "future.duckdb"
    with ProjectDB(db_path):
        pass
    conn = duckdb.connect(str(db_path))
    try:
        conn.execute('UPDATE "schema_meta" SET "value" = $1 WHERE "key" = $2',
                     ["99", "schema_version"])
    finally:
        conn.close()

    with caplog.at_level("WARNING", logger="memdiver.engine.project_db"):
        with ProjectDB(db_path) as db:
            assert db._available is True
            assert db.create_project("opened anyway") != ""
    assert any("newer MemDiver" in r.getMessage() for r in caplog.records)

    # The newer stamp is preserved, not downgraded.
    conn = duckdb.connect(str(db_path))
    try:
        row = conn.execute(
            'SELECT "value" FROM "schema_meta" WHERE "key" = $1',
            ["schema_version"]).fetchone()
    finally:
        conn.close()
    assert row[0] == "99"


@needs_duckdb
def test_unreadable_schema_version_falls_back_to_v1(tmp_path):
    """Garbage in schema_meta is treated as v1 (re-probe) rather than fatal."""
    db_path = tmp_path / "garbage.duckdb"
    with ProjectDB(db_path):
        pass
    conn = duckdb.connect(str(db_path))
    try:
        conn.execute('UPDATE "schema_meta" SET "value" = $1 WHERE "key" = $2',
                     ["not-a-number", "schema_version"])
    finally:
        conn.close()
    with ProjectDB(db_path) as db:
        assert db._available is True
    row = _one_row(db_path, "schema_meta")
    assert row["value"] == str(_SCHEMA_VERSION)
