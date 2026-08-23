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
def test_ground_truth_default_false(tmp_path):
    with ProjectDB(tmp_path / "t.db") as db:
        db.persist_report(_report([_confirmed_hit()]))
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
