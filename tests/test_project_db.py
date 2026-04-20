"""Tests for engine.project_db — ProjectDB with DuckDB + Ibis."""

import sys
from pathlib import Path
from unittest.mock import patch

import pytest

from engine.project_db import HAS_DUCKDB

if HAS_DUCKDB:
    from engine.project_db import ProjectDB

needs_duckdb = pytest.mark.skipif(
    not HAS_DUCKDB, reason="duckdb not installed"
)


@needs_duckdb
def test_create_and_get_project(tmp_path):
    """Round-trip create + get project."""
    with ProjectDB(tmp_path / "test.db") as db:
        pid = db.create_project("demo", description="A test project")
        proj = db.get_project(pid)
        assert proj is not None
        assert proj["name"] == "demo"
        assert proj["description"] == "A test project"
        assert proj["project_id"] == pid


@needs_duckdb
def test_list_projects_empty(tmp_path):
    """Empty DB returns empty list."""
    with ProjectDB(tmp_path / "test.db") as db:
        assert db.list_projects() == []


@needs_duckdb
def test_list_projects_multiple(tmp_path):
    """Multiple projects listed in creation order."""
    with ProjectDB(tmp_path / "test.db") as db:
        db.create_project("alpha")
        db.create_project("beta")
        db.create_project("gamma")
        projects = db.list_projects()
        assert len(projects) == 3
        names = [p["name"] for p in projects]
        assert names == ["alpha", "beta", "gamma"]


@needs_duckdb
def test_add_dump(tmp_path):
    """Dump linked to project with correct metadata."""
    dump_file = tmp_path / "sample.dump"
    dump_file.write_bytes(b"\x00" * 256)
    with ProjectDB(tmp_path / "test.db") as db:
        pid = db.create_project("proj")
        did = db.add_dump(pid, dump_file, "raw")
        assert did != ""
        # Verify via Ibis query
        t = db._ibis.table("dumps")
        rows = t.filter(t.dump_id == did).execute().to_dict("records")
        assert len(rows) == 1
        assert rows[0]["project_id"] == pid
        assert rows[0]["file_type"] == "raw"
        assert rows[0]["file_size"] == 256


@needs_duckdb
def test_start_and_finish_run(tmp_path):
    """Analysis run lifecycle: start -> finish updates status."""
    with ProjectDB(tmp_path / "test.db") as db:
        pid = db.create_project("proj")
        rid = db.start_run(pid, config={"algo": "exact_match"})
        # Check initial status
        runs = db.project_timeline(pid)
        assert len(runs) == 1
        assert runs[0]["status"] == "running"
        # DuckDB/pandas may return NaN for NULL VARCHAR columns
        finished = runs[0]["finished_at"]
        assert finished is None or (isinstance(finished, float) and finished != finished)
        # Finish the run
        db.finish_run(rid, status="completed")
        runs = db.project_timeline(pid)
        assert runs[0]["status"] == "completed"
        assert runs[0]["finished_at"] is not None


@needs_duckdb
def test_add_finding_crypto_key(tmp_path):
    """Finding with value_hex stored correctly."""
    with ProjectDB(tmp_path / "test.db") as db:
        pid = db.create_project("proj")
        rid = db.start_run(pid)
        fid = db.add_finding(
            rid, "crypto_key", offset=0x1000, length=32,
            value_hex="aa" * 32, confidence=0.95,
        )
        findings = db.query_findings(rid)
        assert len(findings) == 1
        assert findings[0]["finding_id"] == fid
        assert findings[0]["offset"] == 0x1000
        assert findings[0]["length"] == 32
        assert findings[0]["value_hex"] == "aa" * 32
        assert findings[0]["confidence"] == pytest.approx(0.95)


@needs_duckdb
def test_add_finding_string(tmp_path):
    """Finding with value_text stored correctly."""
    with ProjectDB(tmp_path / "test.db") as db:
        pid = db.create_project("proj")
        rid = db.start_run(pid)
        db.add_finding(rid, "string", value_text="CLIENT_RANDOM")
        findings = db.query_findings(rid)
        assert len(findings) == 1
        assert findings[0]["value_text"] == "CLIENT_RANDOM"


@needs_duckdb
def test_query_findings_by_type(tmp_path):
    """Filter findings by finding_type."""
    with ProjectDB(tmp_path / "test.db") as db:
        pid = db.create_project("proj")
        rid = db.start_run(pid)
        db.add_finding(rid, "crypto_key", value_hex="bb" * 16)
        db.add_finding(rid, "string", value_text="hello")
        db.add_finding(rid, "crypto_key", value_hex="cc" * 16)
        keys = db.query_findings(rid, finding_type="crypto_key")
        assert len(keys) == 2
        strings = db.query_findings(rid, finding_type="string")
        assert len(strings) == 1


@needs_duckdb
def test_query_findings_all(tmp_path):
    """All findings for a run returned."""
    with ProjectDB(tmp_path / "test.db") as db:
        pid = db.create_project("proj")
        rid = db.start_run(pid)
        db.add_finding(rid, "crypto_key", value_hex="aa" * 32)
        db.add_finding(rid, "string", value_text="test")
        db.add_finding(rid, "entropy_region", offset=100, length=64)
        all_findings = db.query_findings(rid)
        assert len(all_findings) == 3


@needs_duckdb
def test_project_timeline(tmp_path):
    """Runs ordered by start time for a project."""
    with ProjectDB(tmp_path / "test.db") as db:
        pid = db.create_project("proj")
        r1 = db.start_run(pid, config={"step": 1})
        db.finish_run(r1)
        r2 = db.start_run(pid, config={"step": 2})
        db.finish_run(r2)
        timeline = db.project_timeline(pid)
        assert len(timeline) == 2
        assert timeline[0]["run_id"] == r1
        assert timeline[1]["run_id"] == r2


@needs_duckdb
def test_finding_counts(tmp_path):
    """Count findings grouped by type."""
    with ProjectDB(tmp_path / "test.db") as db:
        pid = db.create_project("proj")
        rid = db.start_run(pid)
        db.add_finding(rid, "crypto_key", value_hex="aa" * 32)
        db.add_finding(rid, "crypto_key", value_hex="bb" * 32)
        db.add_finding(rid, "string", value_text="test")
        counts = db.finding_counts(rid)
        assert counts["crypto_key"] == 2
        assert counts["string"] == 1


@needs_duckdb
def test_context_manager(tmp_path):
    """Open/close via with statement works correctly."""
    db_path = tmp_path / "test.db"
    with ProjectDB(db_path) as db:
        assert db._available is True
        pid = db.create_project("ctx_test")
        assert pid != ""
    # After exit, DB should be closed
    assert db._available is False
    assert db._conn is None


def test_graceful_without_duckdb(tmp_path):
    """When HAS_DUCKDB is False, all methods degrade to no-ops."""
    with patch("engine.project_db.HAS_DUCKDB", False):
        # Re-import not needed; we just instantiate and call open()
        # which checks HAS_DUCKDB at runtime
        from engine.project_db import ProjectDB as PDB
        db = PDB(tmp_path / "noop.db")
        db.open()
        assert db._available is False
        # Write methods return empty strings
        assert db.create_project("noop") == ""
        assert db.add_dump("x", tmp_path / "f.dump", "raw") == ""
        assert db.start_run("x") == ""
        db.finish_run("x")  # no error
        assert db.add_finding("x", "key") == ""
        # Read methods return empty results
        assert db.get_project("x") is None
        assert db.list_projects() == []
        assert db.query_findings("x") == []
        assert db.project_timeline("x") == []
        assert db.finding_counts("x") == {}
        # New batch methods also degrade
        assert db.add_findings_batch("x", [{"finding_type": "key"}]) == 0
        db.persist_report({"libraries": []})  # no error
        db.close()


@needs_duckdb
def test_add_findings_batch(tmp_path):
    """Bulk insert findings via executemany."""
    with ProjectDB(tmp_path / "test.db") as db:
        pid = db.create_project("batch_proj")
        rid = db.start_run(pid)
        findings = [
            {"finding_type": "crypto_key", "offset": 0x100, "length": 32,
             "value_hex": "aa" * 32, "confidence": 0.9},
            {"finding_type": "string", "offset": 0x200, "length": 10,
             "value_text": "hello"},
        ]
        count = db.add_findings_batch(rid, findings)
        assert count == 2
        all_findings = db.query_findings(rid)
        assert len(all_findings) == 2


@needs_duckdb
def test_add_findings_batch_empty(tmp_path):
    """Empty findings list returns 0."""
    with ProjectDB(tmp_path / "test.db") as db:
        pid = db.create_project("proj")
        rid = db.start_run(pid)
        assert db.add_findings_batch(rid, []) == 0


@needs_duckdb
def test_persist_report(tmp_path):
    """persist_report creates project, run, and findings in a transaction."""
    with ProjectDB(tmp_path / "test.db") as db:
        result = {
            "libraries": [{
                "library": "openssl",
                "protocol_version": "13",
                "phase": "pre_abort",
                "hits": [
                    {"secret_type": "CLIENT_HANDSHAKE_TRAFFIC_SECRET",
                     "offset": 1024, "length": 32, "confidence": 1.0},
                    {"secret_type": "SERVER_HANDSHAKE_TRAFFIC_SECRET",
                     "offset": 2048, "length": 32, "confidence": 0.8},
                ],
            }],
        }
        db.persist_report(result)
        projects = db.list_projects()
        assert len(projects) == 1
        assert projects[0]["name"] == "openssl_13"
        pid = projects[0]["project_id"]
        runs = db.project_timeline(pid)
        assert len(runs) == 1
        assert runs[0]["status"] == "completed"
        findings = db.query_findings(runs[0]["run_id"])
        assert len(findings) == 2


@needs_duckdb
def test_persist_report_none(tmp_path):
    """persist_report with None result is a no-op."""
    with ProjectDB(tmp_path / "test.db") as db:
        db.persist_report(None)  # should not raise
        assert db.list_projects() == []


@needs_duckdb
def test_persist_report_empty_libraries(tmp_path):
    """persist_report with empty libraries list is a no-op."""
    with ProjectDB(tmp_path / "test.db") as db:
        db.persist_report({"libraries": []})
        assert db.list_projects() == []
