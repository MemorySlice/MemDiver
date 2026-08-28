"""Tests for W5 ground-truth enrichment in engine.project_db.

Covers value_hex + confirmed metadata on the default findings path, the
opt-in ground_truth table (persist_ground_truth / list_ground_truth), and
graceful no-op degradation when DuckDB is unavailable.
"""

import json

import pytest

from memdiver.engine.project_db import HAS_DUCKDB, _finding_row_from_hit

if HAS_DUCKDB:
    from memdiver.engine.project_db import ProjectDB

needs_duckdb = pytest.mark.skipif(not HAS_DUCKDB, reason="duckdb not installed")


def _confirmed_hit():
    return {
        "secret_type": "CLIENT_HANDSHAKE_TRAFFIC_SECRET",
        "offset": 4096,
        "length": 32,
        "confidence": 1.0,
        "verified": True,
        "value_hex": "ab" * 32,
        "cipher": "AES_256_GCM",
    }


def _unconfirmed_hit():
    return {
        "secret_type": "SERVER_HANDSHAKE_TRAFFIC_SECRET",
        "offset": 8192,
        "length": 32,
        "confidence": 0.4,
        "verified": False,
        "value_hex": "cd" * 32,
    }


def _report(hits):
    return {"libraries": [{
        "library": "openssl",
        "protocol_version": "13",
        "phase": "pre_abort",
        "hits": hits,
    }]}


# -- helper ---------------------------------------------------------------

def test_finding_row_marks_confirmed():
    row = _finding_row_from_hit(_confirmed_hit())
    assert row["value_hex"] == "ab" * 32
    assert row["metadata"]["confirmed"] is True
    assert row["metadata"]["confirmed_by"] == "verifier"
    assert row["metadata"]["cipher"] == "AES_256_GCM"


def test_finding_row_explicit_confirmed_by_wins():
    hit = _confirmed_hit()
    hit["confirmed_by"] = "manual_review"
    row = _finding_row_from_hit(hit)
    assert row["metadata"]["confirmed_by"] == "manual_review"


def test_finding_row_unconfirmed_drops_none():
    row = _finding_row_from_hit(_unconfirmed_hit())
    assert row["metadata"] == {"confirmed": False}
    assert row["value_hex"] == "cd" * 32


# -- default findings path ------------------------------------------------

@needs_duckdb
def test_persist_report_stores_value_hex_and_metadata(tmp_path):
    with ProjectDB(tmp_path / "t.db") as db:
        db.persist_report(_report([_confirmed_hit()]))
        rid = db.list_projects()[0]["project_id"]
        run_id = db.project_timeline(rid)[0]["run_id"]
        findings = db.query_findings(run_id)
        assert len(findings) == 1
        f = findings[0]
        assert f["value_hex"] == "ab" * 32
        meta = json.loads(f["metadata_json"])
        assert meta["confirmed"] is True
        assert meta["confirmed_by"] == "verifier"
        assert meta["cipher"] == "AES_256_GCM"
        assert db.finding_counts(run_id)["CLIENT_HANDSHAKE_TRAFFIC_SECRET"] == 1


# -- opt-in ground_truth table --------------------------------------------

@needs_duckdb
def test_ground_truth_opt_in_true(tmp_path):
    with ProjectDB(tmp_path / "t.db") as db:
        db.persist_report(
            _report([_confirmed_hit(), _unconfirmed_hit()]),
            persist_ground_truth_labels=True,
        )
        labels = db.list_ground_truth()
        assert len(labels) == 1  # only the confirmed hit
        gt = labels[0]
        assert gt["key_hex"] == "ab" * 32
        assert gt["secret_type"] == "CLIENT_HANDSHAKE_TRAFFIC_SECRET"
        assert gt["cipher"] == "AES_256_GCM"
        assert gt["confirmed_by"] == "verifier"
        assert gt["library"] == "openssl"
        assert gt["version"] == "13"
        # filter by run_id
        run_id = gt["run_id"]
        assert len(db.list_ground_truth(run_id)) == 1
        assert db.list_ground_truth("nonexistent") == []


@needs_duckdb
def test_ground_truth_opt_out(tmp_path):
    """An explicit ``persist_ground_truth_labels=False`` still writes no labels.

    ``persist_report`` now defaults the flag to True (the W5 ledger was
    permanently empty while it was opt-in and nothing set it), so this asserts
    the opt-out rather than the default. The new default is covered by
    ``tests/test_project_db.py::test_persist_report_ground_truth_default_*``.
    """
    with ProjectDB(tmp_path / "t.db") as db:
        db.persist_report(_report([_confirmed_hit()]),
                          persist_ground_truth_labels=False)
        assert db.list_ground_truth() == []


@needs_duckdb
def test_persist_ground_truth_direct(tmp_path):
    with ProjectDB(tmp_path / "t.db") as db:
        pid = db.create_project("proj")
        rid = db.start_run(pid)
        db.persist_ground_truth(
            rid, [_confirmed_hit()], library="boringssl", version="12",
        )
        labels = db.list_ground_truth(rid)
        assert len(labels) == 1
        assert labels[0]["library"] == "boringssl"
        assert labels[0]["version"] == "12"


@needs_duckdb
def test_persist_ground_truth_empty_is_noop(tmp_path):
    with ProjectDB(tmp_path / "t.db") as db:
        pid = db.create_project("proj")
        rid = db.start_run(pid)
        db.persist_ground_truth(rid, [])
        assert db.list_ground_truth(rid) == []


@needs_duckdb
def test_record_ground_truth_run_maps_key_hex(tmp_path):
    """The brute-force wrapper creates a run and maps key_hex -> ground_truth.key_hex."""
    with ProjectDB(tmp_path / "t.db") as db:
        # brute-force Hit shape uses key_hex (not value_hex) and no confirmed_by
        hits = [{"offset": 4096, "length": 48, "key_hex": "aa" * 48, "region_index": 0}]
        rid = db.record_ground_truth_run(hits, confirmed_by="pcap",
                                         project_name="session-x")
        assert rid
        rows = db.list_ground_truth(rid)
        assert len(rows) == 1
        assert rows[0]["key_hex"] == "aa" * 48
        assert rows[0]["confirmed_by"] == "pcap"
        assert rows[0]["offset"] == 4096


def test_record_ground_truth_run_noop_when_unavailable(tmp_path):
    """No DB -> returns '' and never raises."""
    db = ProjectDB(tmp_path / "t.db")  # never opened
    assert db.record_ground_truth_run([{"key_hex": "aa"}], confirmed_by="pcap") == ""


# -- graceful degradation without DuckDB ----------------------------------

@needs_duckdb
def test_ground_truth_noop_when_unavailable(tmp_path):
    """A closed / unavailable DB degrades to no-ops without raising."""
    db = ProjectDB(tmp_path / "t.db")  # never opened -> _available is False
    assert db._available is False
    db.persist_ground_truth("run", [_confirmed_hit()])  # no error
    assert db.list_ground_truth() == []
    assert db.list_ground_truth("run") == []


# -- corpus axes on the brute-force wrapper --------------------------------
#
# The ledger's axis columns exist so the W5 proof ledger can be sliced by
# library / protocol version / scenario / run / phase without any reader
# re-deriving one from a path. `record_ground_truth_run` is the ONLY production
# writer on the oracle path, so if it drops an axis the column is empty forever.

#: One real corpus dump path (see core.corpus_axes for the layout). Used as a
#: STRING only: axis resolution is pure path decomposition, so these tests need
#: no corpus tree on disk.
CORPUS_DUMP = (
    "/Users/danielbaier/Desktop/tls_dumps/TLS13/"
    "100_iterations_Abort_KeyUpdate/openssl/openssl_run_13_1/"
    "20251020_171845_606711_pre_server_key_update.dump"
)


@needs_duckdb
def test_record_ground_truth_run_round_trips_every_axis(tmp_path):
    """Every axis keyword reaches the ground_truth row it describes."""
    with ProjectDB(tmp_path / "t.db") as db:
        rid = db.record_ground_truth_run(
            [{"offset": 585148, "length": 32, "key_hex": "aa" * 32}],
            confirmed_by="pcap",
            project_name="openssl_13",
            library="openssl",
            version="13",
            library_version="3.0.2",
            scenario="100_iterations_Abort_KeyUpdate",
            run_number=1,
            phase="pre_server_key_update",
            canonical_phase="handshake_end",
            dump_id="dump-42",
            dump_path=CORPUS_DUMP,
        )
        row = db.list_ground_truth(rid)[0]

    assert row["library"] == "openssl"
    assert row["version"] == "13"
    assert row["library_version"] == "3.0.2"
    assert row["scenario"] == "100_iterations_Abort_KeyUpdate"
    assert row["run_number"] == 1
    assert row["phase"] == "pre_server_key_update"
    assert row["canonical_phase"] == "handshake_end"
    assert row["dump_id"] == "dump-42"
    assert row["dump_path"] == CORPUS_DUMP
    # Derived, never passed in: a pcap label is the strongest evidence class.
    assert row["method"] == "oracle"


@needs_duckdb
def test_record_ground_truth_run_stamps_axes_on_project_and_run(tmp_path):
    """The axes also land on the project + analysis_runs rows it creates.

    A ledger row is reachable by run_id, so a reader that starts from the run
    (the corpus dashboard does) must see the same axes without joining back.
    """
    with ProjectDB(tmp_path / "t.db") as db:
        rid = db.record_ground_truth_run(
            [{"offset": 0, "length": 32, "key_hex": "bb" * 32}],
            confirmed_by="oracle",
            project_name="openssl_13",
            library="openssl",
            version="13",
            library_version="3.0.2",
            scenario="100_iterations_Abort_KeyUpdate",
            run_number=7,
            phase="pre_abort",
            canonical_phase="second_event",
            dump_id="dump-9",
        )
        project = db.list_projects()[0]
        run = db.project_timeline(project["project_id"])[0]

    assert project["library"] == "openssl"
    assert project["protocol_version"] == "13"
    assert project["library_version"] == "3.0.2"
    assert project["scenario"] == "100_iterations_Abort_KeyUpdate"
    assert run["run_id"] == rid
    assert run["dump_id"] == "dump-9"
    assert run["library"] == "openssl"
    assert run["protocol_version"] == "13"
    assert run["scenario"] == "100_iterations_Abort_KeyUpdate"
    assert run["run_number"] == 7
    assert run["phase"] == "pre_abort"
    assert run["canonical_phase"] == "second_event"


@needs_duckdb
def test_record_ground_truth_run_without_axes_keeps_historical_defaults(tmp_path):
    """An ad-hoc dump (no axes resolvable) still writes a usable row.

    The axes are all optional, so the pre-existing call shape — hits +
    confirmed_by only — must keep working and leave every axis column at its
    documented default rather than NULL.
    """
    with ProjectDB(tmp_path / "t.db") as db:
        rid = db.record_ground_truth_run(
            [{"offset": 16, "length": 48, "key_hex": "cc" * 48}],
            confirmed_by="oracle",
        )
        row = db.list_ground_truth(rid)[0]

    assert row["key_hex"] == "cc" * 48
    assert row["value_hex"] == "cc" * 48
    assert row["confirmed_by"] == "oracle"
    assert row["method"] == "oracle"
    assert row["library"] == ""
    assert row["version"] == ""
    assert row["library_version"] == "unknown"
    assert row["scenario"] == ""
    assert row["run_number"] == 0
    assert row["phase"] == ""
    assert row["canonical_phase"] == ""
    assert row["dump_path"] == ""


@needs_duckdb
def test_persist_ground_truth_hit_dump_path_beats_the_batch_default(tmp_path):
    """A hit carrying its own ``dump_path`` wins over the per-call default.

    ``dump_path`` gained a per-call default alongside the other axes; the
    documented "a hit dict wins" precedence must survive that.
    """
    with ProjectDB(tmp_path / "t.db") as db:
        pid = db.create_project("proj")
        rid = db.start_run(pid)
        db.persist_ground_truth(
            rid,
            [
                {"offset": 0, "length": 32, "value_hex": "aa" * 32},
                {"offset": 32, "length": 32, "value_hex": "bb" * 32,
                 "dump_path": "/other/run/b.dump"},
            ],
            dump_path=CORPUS_DUMP,
        )
        rows = sorted(db.list_ground_truth(rid), key=lambda r: r["offset"])

    assert rows[0]["dump_path"] == CORPUS_DUMP
    assert rows[1]["dump_path"] == "/other/run/b.dump"
