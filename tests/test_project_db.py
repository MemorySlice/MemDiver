"""Tests for engine.project_db — ProjectDB with DuckDB + Ibis."""

import sys
from pathlib import Path
from unittest.mock import patch

import pytest

from memdiver.core.service_errors import CapabilityError, ErrorCategory
from memdiver.engine.project_db import HAS_DUCKDB

if HAS_DUCKDB:
    from memdiver.engine.project_db import ProjectDB

needs_duckdb = pytest.mark.skipif(
    not HAS_DUCKDB, reason="duckdb not installed"
)

#: Both ledger writers REQUIRE a non-empty ``sweep_id`` (one global project DB
#: file holds every sweep), so every ledger test names one.
SWEEP = "sweep-1"


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
    with patch("memdiver.engine.project_db.HAS_DUCKDB", False):
        # Re-import not needed; we just instantiate and call open()
        # which checks HAS_DUCKDB at runtime
        from memdiver.engine.project_db import ProjectDB as PDB
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
        # The v4 differential ledger keeps the same discipline. Its sentinel
        # CHAINS: the unavailable consensus writer returns "", which the
        # candidate writer then rejects rather than filing rows under an empty
        # scope. See tests/test_project_db_consensus.py.
        assert db.add_consensus_run(project_id="x", dump_paths=["/a"]) == ""
        assert db.add_candidate_regions_batch("c", [{"offset": 0}]) == 0
        assert db.consensus_runs() == []
        assert db.candidate_regions("c") == []
        assert db.candidate_class_counts("c") == {}
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


# -- v2 axis columns ------------------------------------------------------

def _axis_report(hits=None, **overrides):
    lib = {
        "library": "openssl",
        "protocol_version": "13",
        "phase": "pre_abort",
        "canonical_phase": "handshake_end",
        "library_version": "3.0.2",
        "scenario": "100_iterations_Abort_KeyUpdate",
        "protocol": "TLS",
        "hits": hits if hits is not None else [],
    }
    lib.update(overrides)
    return {"libraries": [lib]}


@needs_duckdb
def test_persist_report_writes_project_and_run_axes(tmp_path):
    """The corpus axes reach their own columns instead of being dropped."""
    with ProjectDB(tmp_path / "test.db") as db:
        db.persist_report(_axis_report())
        project = db.list_projects()[0]
        # FROZEN: the name format is a compatibility contract.
        assert project["name"] == "openssl_13"
        assert project["library"] == "openssl"
        assert project["protocol_version"] == "13"
        assert project["library_version"] == "3.0.2"
        assert project["scenario"] == "100_iterations_Abort_KeyUpdate"
        assert project["protocol"] == "TLS"
        assert project["version_axis"] == "protocol_version"

        run = db.project_timeline(project["project_id"])[0]
        assert run["phase"] == "pre_abort"
        assert run["canonical_phase"] == "handshake_end"
        assert run["library"] == "openssl"
        assert run["library_version"] == "3.0.2"
        assert run["scenario"] == "100_iterations_Abort_KeyUpdate"
        # phase is still mirrored into config_json — the change is additive.
        import json as _json
        assert _json.loads(run["config_json"])["phase"] == "pre_abort"


# `_axis_report` above hand-builds the wide dict. That is deliberate — it pins
# what `persist_report` READS — but it also HID the bug this companion catches:
# `serialize_report` never emitted those keys, so on the only production path
# into this writer (`engine/batch.py` -> `serialize_result` -> `persist_report`)
# every axis column silently wrote its default. Anything asserted here must
# survive the REAL serializer, not a dict written to match the reader.

def _real_serialized_report(**hit_overrides):
    """A real ``LibraryReport`` through the real ``serialize_result``."""
    from memdiver.engine.results import AnalysisResult, LibraryReport, SecretHit
    from memdiver.engine.serializer import serialize_result

    hit_kwargs = {
        "secret_type": "CLIENT_HANDSHAKE_TRAFFIC_SECRET",
        "offset": 585148,
        "length": 32,
        "dump_path": Path("/corpus/openssl_run_13_4/pre_abort.dump"),
        "library": "openssl",
        "phase": "pre_abort",
        "run_id": 4,
        "verified": True,
        "value_hex": "ab" * 32,
        "canonical_phase": "handshake_end",
        "metadata": {"cipher": "AES_256_GCM"},
    }
    hit_kwargs.update(hit_overrides)
    result = AnalysisResult()
    result.libraries.append(LibraryReport(
        library="openssl", protocol_version="13", phase="pre_abort",
        num_runs=1, hits=[SecretHit(**hit_kwargs)],
        canonical_phase="handshake_end", library_version="3.0.2",
        version_axis="protocol_version",
        scenario="100_iterations_Abort_KeyUpdate", protocol="TLS",
    ))
    return serialize_result(result)


# -- a genuinely corpus-shaped tree -----------------------------------------
#
# `core.corpus_axes.axes_from_run_dir` resolves the axes by walking UP from the
# run directory: `<root>/TLS12/<scenario>/<library>/<library>_run_12_1/`. A run
# directory placed anywhere else — as every `tmp_path / "openssl_run_13_4"` in
# this file places one — resolves to `None`, so those tests only ever exercised
# `AnalysisPipeline._resolve_axes`' FALLBACK branch and its success branch had
# no coverage at all. Everything below builds the real shape.

#: 32 bytes so `AesCbcVerifier` (AES-256) accepts it as a key, which is what
#: makes `verify_decryption=True` actually confirm the hit.
_CORPUS_SECRET = bytes(range(32))
_CORPUS_IDENTIFIER = bytes(range(32, 64))
_CORPUS_SCENARIO = "100_iterations_Abort_KeyUpdate"
_CORPUS_SECRET_OFFSET = 64


def _corpus_library(root, *, library="openssl", version="12", run_number=1):
    """Materialise one corpus-shaped run and return its LIBRARY directory.

    Two phased dumps, because a canonical phase is positional across a run's
    sibling dumps: with only one dump `PhaseNormalizer` has nothing to be
    positional about. Both carry the secret at a known offset.
    """
    run_dir = (Path(root) / f"TLS{version}" / _CORPUS_SCENARIO / library
               / f"{library}_run_{version}_{run_number}")
    run_dir.mkdir(parents=True)
    (run_dir / "keylog.csv").write_text(
        f"line\nCLIENT_RANDOM {_CORPUS_IDENTIFIER.hex()} {_CORPUS_SECRET.hex()}\n",
        encoding="utf-8",
    )
    for timestamp, phase in (("20240101_120000_000001", "pre_handshake"),
                             ("20240101_120001_000002", "pre_abort")):
        data = bytearray(512)
        data[_CORPUS_SECRET_OFFSET:_CORPUS_SECRET_OFFSET + len(_CORPUS_SECRET)] = \
            _CORPUS_SECRET
        (run_dir / f"{timestamp}_{phase}.dump").write_bytes(bytes(data))
    return run_dir.parent


def _analyze_corpus_library(library_dir, project_db=None):
    """Run the REAL pipeline over `_corpus_library`, verification on.

    ``normalize=True`` so a canonical phase is actually produced, and
    ``verify_decryption=True`` so the hit is cryptographically confirmed —
    the only path that fills the W5 proof ledger.
    """
    from memdiver.engine.pipeline import AnalysisPipeline
    pipeline = AnalysisPipeline(project_db=project_db)
    return pipeline.analyze_library(
        library_dir, phase="pre_abort", protocol_version="12",
        expand_keys=False, normalize=True, verify_decryption=True, max_runs=1,
    )


@needs_duckdb
def test_persist_report_from_the_real_serializer_lands_every_axis(tmp_path):
    """The end-to-end shape check: real ANALYSIS -> real serializer -> real DB.

    This test used to hand-set every field it asserted (``value_hex``, the
    axes, ``canonical_phase``) on a ``LibraryReport``/``SecretHit`` built for
    the occasion, so all it proved was that the writer READ them. Nothing in
    production WROTE any of them: no constructor of ``LibraryReport`` passed
    an axis, and ``SecretHit.value_hex`` had zero producers. It now drives the
    real :meth:`AnalysisPipeline.analyze_library` over a corpus-shaped tree,
    so every value asserted below had to be produced before it could be
    persisted.
    """
    from memdiver.engine.results import AnalysisResult
    from memdiver.engine.serializer import serialize_result

    library_dir = _corpus_library(tmp_path)
    report = _analyze_corpus_library(library_dir)
    result = AnalysisResult()
    result.libraries.append(report)

    with ProjectDB(tmp_path / "test.db") as db:
        db.persist_report(serialize_result(result))

        project = db.list_projects()[0]
        assert project["name"] == "openssl_12"
        assert project["library_version"] == "unknown"
        assert project["scenario"] == _CORPUS_SCENARIO
        assert project["protocol"] == "TLS"
        assert project["version_axis"] == "protocol_version"

        run = db.project_timeline(project["project_id"])[0]
        # Produced by PhaseNormalizer over the run's sibling dumps, not typed
        # in here — asserted non-empty AND equal to what the report carries.
        assert run["canonical_phase"] == report.canonical_phase != ""
        assert run["library_version"] == "unknown"
        assert run["scenario"] == _CORPUS_SCENARIO

        f = db.query_findings(run["run_id"])[0]
        # The four the reader looked for at the top level and never found.
        assert f["value_hex"] == _CORPUS_SECRET.hex()
        assert f["canonical_phase"] == report.canonical_phase
        assert f["run_number"] == 1
        import json as _json
        meta = _json.loads(f["metadata_json"])
        assert meta["confirmed"] is True
        assert meta["confirmed_by"] == "verifier"
        assert meta["cipher"] == "AES-256-CBC"

        label = db.list_ground_truth()[0]
        assert label["value_hex"] == _CORPUS_SECRET.hex()
        assert label["confirmed_by"] == "verifier"


@needs_duckdb
def test_persist_report_from_the_real_serializer_keeps_an_explicit_label(tmp_path):
    """A pcap/oracle ``confirmed_by`` survives the metadata -> top-level mirror."""
    report = _real_serialized_report(
        metadata={"cipher": "AES_256_GCM", "confirmed_by": "pcap"})
    with ProjectDB(tmp_path / "test.db") as db:
        db.persist_report(report)
        assert db.list_ground_truth()[0]["confirmed_by"] == "pcap"


@needs_duckdb
def test_persist_report_writes_finding_axes(tmp_path):
    """Labels the hit already carried land in the findings columns."""
    hit = {
        "secret_type": "CLIENT_HANDSHAKE_TRAFFIC_SECRET",
        "offset": 585148, "length": 32, "confidence": 1.0,
        "value_hex": "ab" * 32,
        "dump_path": "/corpus/openssl_run_13_0/pre_abort.dump",
        "phase": "pre_abort", "library": "openssl", "verified": True,
    }
    with ProjectDB(tmp_path / "test.db") as db:
        db.persist_report(_axis_report([hit]))
        pid = db.list_projects()[0]["project_id"]
        rid = db.project_timeline(pid)[0]["run_id"]
        f = db.query_findings(rid)[0]
        # finding_type keeps its historical value verbatim.
        assert f["finding_type"] == "CLIENT_HANDSHAKE_TRAFFIC_SECRET"
        assert f["secret_type"] == "CLIENT_HANDSHAKE_TRAFFIC_SECRET"
        assert f["kind"] == "secret"
        assert f["method"] == "consensus_search"
        assert f["dump_path"] == "/corpus/openssl_run_13_0/pre_abort.dump"
        assert f["phase"] == "pre_abort"
        assert f["library"] == "openssl"
        assert f["verified"] is True
        assert db.finding_counts(rid)["CLIENT_HANDSHAKE_TRAFFIC_SECRET"] == 1


@needs_duckdb
def test_persist_report_ground_truth_default_adds_no_rows_for_unverified(tmp_path):
    """The flipped default is a no-op on the ordinary (unverified) path.

    This is the safety argument for defaulting ``persist_ground_truth_labels``
    to True: only hits already carrying ``verified``/``confirmed`` are written,
    and that is populated only when ``verify_decryption`` ran.
    """
    plain = [
        {"secret_type": "CLIENT_HANDSHAKE_TRAFFIC_SECRET",
         "offset": 1024, "length": 32, "confidence": 1.0},
        {"secret_type": "SERVER_HANDSHAKE_TRAFFIC_SECRET",
         "offset": 2048, "length": 32, "confidence": 0.8},
    ]
    with ProjectDB(tmp_path / "test.db") as db:
        db.persist_report(_axis_report(plain))
        pid = db.list_projects()[0]["project_id"]
        rid = db.project_timeline(pid)[0]["run_id"]
        assert len(db.query_findings(rid)) == 2
        assert db.list_ground_truth() == []


@needs_duckdb
def test_persist_report_ground_truth_default_records_confirmed(tmp_path):
    """A verified hit now reaches the W5 ledger without an explicit opt-in."""
    verified = [{"secret_type": "CLIENT_HANDSHAKE_TRAFFIC_SECRET",
                 "offset": 4096, "length": 32, "value_hex": "ef" * 32,
                 "verified": True, "cipher": "AES_256_GCM"}]
    with ProjectDB(tmp_path / "test.db") as db:
        db.persist_report(_axis_report(verified))
        labels = db.list_ground_truth()
        assert len(labels) == 1
        assert labels[0]["confirmed_by"] == "verifier"
        assert labels[0]["phase"] == "pre_abort"
        assert labels[0]["canonical_phase"] == "handshake_end"
        assert labels[0]["library_version"] == "3.0.2"


@needs_duckdb
def test_persist_ground_truth_is_idempotent_across_reruns(tmp_path):
    """Re-recording the same label must NOT inflate the truth denominator.

    ``gt_id`` was a uuid, which makes ``ON CONFLICT`` inert, and
    ``persist_ground_truth_labels`` now defaults to True — so simply analysing
    the same dumps twice doubled the ledger every recall figure divides by.
    The failure is invisible to the obvious check: both sides just get bigger.
    """
    hit = {"secret_type": "CLIENT_RANDOM", "offset": 64, "length": 48,
           "value_hex": "1a" * 48, "verified": True,
           "dump_path": "/corpus/run0/pre_abort.dump"}
    with ProjectDB(tmp_path / "test.db") as db:
        pid = db.create_project("proj")
        # A SECOND analysis run, i.e. a fresh `analysis_runs` uuid — the case a
        # run_id-keyed identity would fail to dedupe.
        for _ in range(2):
            db.persist_ground_truth(db.start_run(pid), [hit],
                                    library="openssl", version="13")
        assert _count(db, "ground_truth") == 1
        # DO NOTHING keeps the FIRST row, axes and all.
        assert db.list_ground_truth()[0]["library"] == "openssl"


@needs_duckdb
def test_persist_ground_truth_still_separates_distinct_labels(tmp_path):
    """Dedupe on identity only: a different offset/dump/key is its own row."""
    base = {"secret_type": "CLIENT_RANDOM", "offset": 64, "length": 48,
            "value_hex": "1a" * 48, "verified": True,
            "dump_path": "/corpus/run0/pre_abort.dump"}
    with ProjectDB(tmp_path / "test.db") as db:
        rid = db.start_run(db.create_project("proj"))
        db.persist_ground_truth(rid, [
            base,
            {**base, "offset": 128},
            {**base, "dump_path": "/corpus/run1/pre_abort.dump"},
            {**base, "value_hex": "2b" * 48},
            {**base, "secret_type": "SERVER_TRAFFIC_SECRET_0"},
        ])
        assert _count(db, "ground_truth") == 5


@needs_duckdb
def test_persist_report_twice_writes_one_ground_truth_label(tmp_path):
    """The same defect on the production path: analysing twice, one label."""
    verified = [{"secret_type": "CLIENT_HANDSHAKE_TRAFFIC_SECRET",
                 "offset": 4096, "length": 32, "value_hex": "ef" * 32,
                 "verified": True, "cipher": "AES_256_GCM"}]
    with ProjectDB(tmp_path / "test.db") as db:
        db.persist_report(_axis_report(verified))
        db.persist_report(_axis_report(verified))
        assert len(db.list_ground_truth()) == 1
        # `findings` is append-only BY DESIGN and is untouched by this: two
        # analyses really are two observations.
        assert _count(db, "findings") == 2


@needs_duckdb
def test_persist_ground_truth_writes_key_hex_and_value_hex(tmp_path):
    """Both columns carry the secret bytes: key_hex (legacy) and value_hex."""
    with ProjectDB(tmp_path / "test.db") as db:
        pid = db.create_project("proj")
        rid = db.start_run(pid)
        db.persist_ground_truth(
            rid,
            [{"secret_type": "CLIENT_RANDOM", "offset": 64, "length": 48,
              "value_hex": "1a" * 48, "verified": True,
              "dump_path": "/corpus/run0/pre_abort.dump", "run_number": 7}],
            library="openssl", version="13", method="oracle",
        )
        row = db.list_ground_truth(rid)[0]
        assert row["key_hex"] == "1a" * 48
        assert row["value_hex"] == "1a" * 48
        assert row["dump_path"] == "/corpus/run0/pre_abort.dump"
        assert row["run_number"] == 7
        assert row["method"] == "oracle"


# -- expected_secrets / survival ------------------------------------------

@needs_duckdb
def test_add_expected_secrets_batch_round_trip(tmp_path):
    """The denominator ledger round-trips through the DB."""
    with ProjectDB(tmp_path / "test.db") as db:
        pid = db.create_project("proj")
        rid = db.start_run(pid)
        written = db.add_expected_secrets_batch(rid, [
            {"library": "openssl", "protocol_version": "13",
             "secret_type": "CLIENT_HANDSHAKE_TRAFFIC_SECRET",
             "identifier_hex": "aa" * 32, "secret_len": 32,
             "keylog_path": "/corpus/run0/keylog.csv", "run_number": 0},
            {"library": "openssl", "protocol_version": "13",
             "secret_type": "SERVER_HANDSHAKE_TRAFFIC_SECRET",
             "secret_len": 32, "run_number": 0},
        ], sweep_id=SWEEP)
        assert written == 2
        t = db._ibis.table("expected_secrets")
        rows = t.filter(t.run_id == rid).order_by("secret_type").execute() \
                .to_dict("records")
        assert [r["secret_type"] for r in rows] == [
            "CLIENT_HANDSHAKE_TRAFFIC_SECRET", "SERVER_HANDSHAKE_TRAFFIC_SECRET"]
        assert rows[0]["identifier_hex"] == "aa" * 32
        assert rows[0]["keylog_path"] == "/corpus/run0/keylog.csv"
        assert rows[0]["library_version"] == "unknown"
        assert rows[0]["version_axis"] == "protocol_version"
        # defaults fill in for the sparser second row
        assert rows[1]["identifier_hex"] == ""
        assert rows[1]["keylog_path"] == ""


@needs_duckdb
def test_add_survival_batch_records_present_and_absent(tmp_path):
    """present=FALSE is a positive record of absence; a missing row is 'not attempted'."""
    with ProjectDB(tmp_path / "test.db") as db:
        pid = db.create_project("proj")
        rid = db.start_run(pid)
        written = db.add_survival_batch(rid, [
            {"library": "openssl", "protocol_version": "13",
             "secret_type": "CLIENT_HANDSHAKE_TRAFFIC_SECRET",
             "present": True, "first_offset": 585148, "hit_count": 2,
             "method": "keylog_substring", "phase": "pre_abort",
             "canonical_phase": "handshake_end", "run_number": 3,
             "dump_path": "/corpus/run3/pre_abort.dump"},
            {"library": "openssl", "protocol_version": "13",
             "secret_type": "SERVER_HANDSHAKE_TRAFFIC_SECRET",
             "present": False, "first_offset": None,
             "method": "keylog_substring", "phase": "post_abort",
             "run_number": 3,
             "dump_path": "/corpus/run3/pre_abort.dump"},
        ], sweep_id=SWEEP)
        assert written == 2
        t = db._ibis.table("survival")
        rows = t.filter(t.run_id == rid).order_by("secret_type").execute() \
                .to_dict("records")
        found, gone = rows
        assert found["present"] is True
        assert found["first_offset"] == 585148
        assert found["hit_count"] == 2
        assert found["run_number"] == 3
        assert found["canonical_phase"] == "handshake_end"
        # The looked-and-absent cell: a real row, not a missing one.
        assert gone["present"] is False
        # NULL BIGINT surfaces as NaN through pandas, as elsewhere in this file.
        absent_offset = gone["first_offset"]
        assert absent_offset is None or absent_offset != absent_offset
        assert gone["hit_count"] == 0
        assert gone["method"] == "keylog_substring"
        # A third secret_type was never attempted -> no row at all.
        assert len(rows) == 2


@needs_duckdb
def test_new_batch_writers_empty_returns_zero(tmp_path):
    with ProjectDB(tmp_path / "test.db") as db:
        pid = db.create_project("proj")
        rid = db.start_run(pid)
        assert db.add_expected_secrets_batch(rid, []) == 0
        assert db.add_survival_batch(rid, []) == 0


def test_new_batch_writers_degrade_without_duckdb(tmp_path):
    """Both new writers no-op on an unopened / unavailable DB."""
    from memdiver.engine.project_db import ProjectDB as PDB
    db = PDB(tmp_path / "noop.db")  # never opened
    assert db._available is False
    assert db.add_expected_secrets_batch("r", [{"secret_type": "x"}]) == 0
    assert db.add_survival_batch("r", [{"secret_type": "x", "present": True}]) == 0


# -- v3: deterministic row identity (re-run / resume safety) --------------

def _survival_row(**over):
    """A minimal VALID survival row: searched, present decided, dump named."""
    row = {"library": "openssl", "protocol_version": "13",
           "secret_type": "CLIENT_RANDOM", "present": True,
           "method": "keylog_substring", "run_number": 3,
           "dump_path": "/corpus/run3/pre_abort.dump"}
    row.update(over)
    return row


def _count(db, table):
    return len(db._ibis.table(table).execute().to_dict("records"))


@needs_duckdb
def test_add_survival_batch_twice_writes_one_row_per_cell(tmp_path):
    """Re-running a sweep must not duplicate the observation ledger.

    With a uuid primary key ``ON CONFLICT`` never fires, so a re-run or a resume
    wrote a SECOND row for every cell. The damage is invisible to the obvious
    check — ``runs_found <= runs_attempted <= runs_expected`` still holds with
    both sides doubled — so the fractions look untouched while the counts behind
    them are inflated.
    """
    with ProjectDB(tmp_path / "test.db") as db:
        rid = db.start_run(db.create_project("proj"))
        batch = [_survival_row(),
                 _survival_row(secret_type="SERVER_HANDSHAKE_TRAFFIC_SECRET",
                               present=False)]
        assert db.add_survival_batch(rid, batch, sweep_id=SWEEP) == 2
        assert _count(db, "survival") == 2
        # Same batch again: same rows, not twice as many.
        assert db.add_survival_batch(rid, batch, sweep_id=SWEEP) == 2
        assert _count(db, "survival") == 2


@needs_duckdb
def test_add_expected_secrets_batch_twice_writes_one_row_per_cell(tmp_path):
    """The DENOMINATOR must not double either — that inflates the whole matrix."""
    with ProjectDB(tmp_path / "test.db") as db:
        rid = db.start_run(db.create_project("proj"))
        batch = [
            {"library": "openssl", "protocol_version": "13", "run_number": 0,
             "secret_type": "CLIENT_HANDSHAKE_TRAFFIC_SECRET"},
            {"library": "openssl", "protocol_version": "13", "run_number": 0,
             "secret_type": "SERVER_HANDSHAKE_TRAFFIC_SECRET"},
        ]
        assert db.add_expected_secrets_batch(rid, batch, sweep_id=SWEEP) == 2
        assert _count(db, "expected_secrets") == 2
        assert db.add_expected_secrets_batch(rid, batch, sweep_id=SWEEP) == 2
        assert _count(db, "expected_secrets") == 2


@needs_duckdb
def test_survival_ids_are_deterministic_not_random(tmp_path):
    """The same cell resolves to the same id across two separate DB files."""
    ids = []
    for name in ("a.db", "b.db"):
        with ProjectDB(tmp_path / name) as db:
            rid = db.start_run(db.create_project("proj"))
            db.add_survival_batch(rid, [_survival_row()], sweep_id="sweep-1")
            ids.append(db._ibis.table("survival").execute()
                       .to_dict("records")[0]["survival_id"])
    assert ids[0] == ids[1]
    assert len(ids[0]) == 32


@needs_duckdb
def test_survival_two_dumps_of_one_run_stay_separate_rows(tmp_path):
    """Dedup is at CELL grain — different dumps are different observations."""
    with ProjectDB(tmp_path / "test.db") as db:
        rid = db.start_run(db.create_project("proj"))
        written = db.add_survival_batch(rid, [
            _survival_row(dump_path="/corpus/run3/pre_abort.dump"),
            _survival_row(dump_path="/corpus/run3/post_abort.dump", present=False),
        ], sweep_id=SWEEP)
        assert written == 2
        assert _count(db, "survival") == 2


# -- v3: sweep_id separates corpora / configurations ----------------------

@needs_duckdb
def test_sweep_id_keeps_two_sweeps_of_one_dump_apart(tmp_path):
    """``resolve_project_db()`` opens ONE global DB file.

    Without ``sweep_id`` two corpora, or two sweep configurations over one
    corpus, merge into a single indistinguishable pile of rows.
    """
    with ProjectDB(tmp_path / "test.db") as db:
        rid = db.start_run(db.create_project("proj"))
        assert db.add_survival_batch(rid, [_survival_row()], sweep_id="ci-slice") == 1
        assert db.add_survival_batch(rid, [_survival_row(present=False)],
                                     sweep_id="full-corpus") == 1
        rows = db._ibis.table("survival").order_by("sweep_id").execute() \
                 .to_dict("records")
        assert [r["sweep_id"] for r in rows] == ["ci-slice", "full-corpus"]
        assert [r["present"] for r in rows] == [True, False]


@needs_duckdb
def test_expected_secrets_sweep_id_separates_denominators(tmp_path):
    with ProjectDB(tmp_path / "test.db") as db:
        rid = db.start_run(db.create_project("proj"))
        row = {"library": "openssl", "protocol_version": "13",
               "run_number": 0, "secret_type": "CLIENT_RANDOM"}
        db.add_expected_secrets_batch(rid, [row], sweep_id="ci-slice")
        db.add_expected_secrets_batch(rid, [row], sweep_id="full-corpus")
        assert _count(db, "expected_secrets") == 2


# -- v3: survival.status, the three-state guard ---------------------------

@needs_duckdb
def test_survival_searched_without_present_is_rejected(tmp_path):
    """A NULL ``present`` is worse than no row: it counts as attempted and as
    neither found nor absent, because both ``WHERE present`` and
    ``WHERE NOT present`` exclude NULL."""

    with ProjectDB(tmp_path / "test.db") as db:
        rid = db.start_run(db.create_project("proj"))
        bad = _survival_row()
        del bad["present"]
        with pytest.raises(CapabilityError) as excinfo:
            db.add_survival_batch(rid, [bad], sweep_id=SWEEP)
        assert excinfo.value.category is ErrorCategory.INVALID_INPUT
        # Nothing written: the whole batch is rejected, not half of it.
        assert _count(db, "survival") == 0


@needs_duckdb
def test_survival_unreadable_keeps_present_null_and_is_not_attempted(tmp_path):
    """"Opened the dump and could not read it" is now expressible.

    Before, a writer had to choose between a false absence claim and no row.
    """
    with ProjectDB(tmp_path / "test.db") as db:
        rid = db.start_run(db.create_project("proj"))
        row = _survival_row(status="unreadable", format_name="gcore")
        del row["present"]
        assert db.add_survival_batch(rid, [row], sweep_id=SWEEP) == 1
        stored = db._ibis.table("survival").execute().to_dict("records")[0]
        assert stored["status"] == "unreadable"
        present = stored["present"]
        assert present is None or present != present  # NULL / NaN via pandas
        # Only 'searched' counts as attempted.
        t = db._ibis.table("survival")
        attempted = t.filter(t.status == "searched").execute().to_dict("records")
        assert attempted == []


@needs_duckdb
def test_survival_status_error_writes_no_row(tmp_path):
    """An errored attempt is not an observation; recording one would let a
    crash masquerade as evidence."""
    with ProjectDB(tmp_path / "test.db") as db:
        rid = db.start_run(db.create_project("proj"))
        rows = [_survival_row(status="error", present=None),
                _survival_row(secret_type="SERVER_HANDSHAKE_TRAFFIC_SECRET")]
        assert db.add_survival_batch(rid, rows, sweep_id=SWEEP) == 1
        stored = db._ibis.table("survival").execute().to_dict("records")
        assert [r["secret_type"] for r in stored] == [
            "SERVER_HANDSHAKE_TRAFFIC_SECRET"]


@needs_duckdb
def test_survival_all_error_rows_write_nothing(tmp_path):
    with ProjectDB(tmp_path / "test.db") as db:
        rid = db.start_run(db.create_project("proj"))
        assert db.add_survival_batch(
            rid, [_survival_row(status="error", present=None)],
            sweep_id=SWEEP) == 0
        assert _count(db, "survival") == 0


@needs_duckdb
def test_survival_rejects_unknown_status(tmp_path):
    with ProjectDB(tmp_path / "test.db") as db:
        rid = db.start_run(db.create_project("proj"))
        with pytest.raises(CapabilityError) as excinfo:
            db.add_survival_batch(rid, [_survival_row(status="maybe")],
                                  sweep_id=SWEEP)
        assert excinfo.value.category is ErrorCategory.INVALID_INPUT


@needs_duckdb
def test_survival_status_defaults_to_searched(tmp_path):
    with ProjectDB(tmp_path / "test.db") as db:
        rid = db.start_run(db.create_project("proj"))
        db.add_survival_batch(rid, [_survival_row()], sweep_id=SWEEP)
        stored = db._ibis.table("survival").execute().to_dict("records")[0]
        assert stored["status"] == "searched"


# -- v3: format-caused absence is distinguishable -------------------------

@needs_duckdb
def test_survival_records_format_and_searched_size(tmp_path):
    """A ``✗`` from a region view / VAS projection searches a DIFFERENT byte
    stream than a raw dump; without these two columns it is indistinguishable
    from a real absence."""
    with ProjectDB(tmp_path / "test.db") as db:
        rid = db.start_run(db.create_project("proj"))
        db.add_survival_batch(rid, [
            _survival_row(present=False, format_name="msl",
                          size_for_view=11223040)], sweep_id=SWEEP)
        stored = db._ibis.table("survival").execute().to_dict("records")[0]
        assert stored["format_name"] == "msl"
        assert stored["size_for_view"] == 11223040


@needs_duckdb
def test_survival_format_columns_default_empty(tmp_path):
    with ProjectDB(tmp_path / "test.db") as db:
        rid = db.start_run(db.create_project("proj"))
        db.add_survival_batch(rid, [_survival_row()], sweep_id=SWEEP)
        stored = db._ibis.table("survival").execute().to_dict("records")[0]
        assert stored["format_name"] == ""
        assert stored["size_for_view"] == 0


# -- v3: a dumpless run keeps a reason ------------------------------------

@needs_duckdb
def test_expected_secrets_records_dumps_in_run_and_keylog_status(tmp_path):
    """33 corpus run directories hold zero ``.dump`` files and 31 of those have
    a complete keylog. They must render as "no data WITH A REASON", not vanish
    from the denominator."""
    with ProjectDB(tmp_path / "test.db") as db:
        rid = db.start_run(db.create_project("proj"))
        db.add_expected_secrets_batch(rid, [
            {"library": "gotls", "protocol_version": "12", "run_number": 5,
             "secret_type": "CLIENT_RANDOM",
             "dumps_in_run": 0, "keylog_status": "ok"},
        ], sweep_id=SWEEP)
        stored = db._ibis.table("expected_secrets").execute().to_dict("records")[0]
        assert stored["dumps_in_run"] == 0
        assert stored["keylog_status"] == "ok"


@needs_duckdb
def test_expected_secrets_dumpless_columns_default(tmp_path):
    with ProjectDB(tmp_path / "test.db") as db:
        rid = db.start_run(db.create_project("proj"))
        db.add_expected_secrets_batch(rid, [
            {"library": "openssl", "protocol_version": "13",
             "secret_type": "CLIENT_RANDOM"}], sweep_id=SWEEP)
        stored = db._ibis.table("expected_secrets").execute().to_dict("records")[0]
        assert stored["dumps_in_run"] == 0
        assert stored["keylog_status"] == ""


# -- v3: transactions ------------------------------------------------------
#
# THE FAILURE HAS TO LAND MID-BATCH. These two tests used to swap in a
# connection proxy whose `executemany` raised on the FIRST call, which meant
# zero rows were ever written and there was nothing to roll back — both tests
# passed with the entire `BEGIN`/`COMMIT`/`ROLLBACK` wrapper deleted, so they
# proved only that an exception propagates.
#
# The wrapper IS load-bearing. DuckDB's `executemany` is not atomic on its own:
# measured on duckdb 1.5.2, `[good_row, bad_row]` raises and LEAVES THE GOOD ROW
# BEHIND without a transaction, and leaves nothing behind with one. That is a
# half-written observation ledger, which reads as a real one.


def _survival_row_that_fails_to_convert(**over):
    """A survival row that passes the writer's own validation and then fails
    inside DuckDB: `present` is a string, and the column is BOOLEAN.

    It has to get past `add_survival_batch` — the writer only rejects a MISSING
    `present` — so that the failure happens during `executemany`, part-way
    through the batch, rather than before a single row is written.
    """
    return _survival_row(present="not-a-bool", **over)


@needs_duckdb
def test_survival_batch_rolls_back_a_mid_batch_failure(tmp_path):
    """A part-written observation ledger reads as a real one; it must not exist."""
    import duckdb

    with ProjectDB(tmp_path / "test.db") as db:
        rid = db.start_run(db.create_project("proj"))
        db.add_survival_batch(rid, [_survival_row()], sweep_id=SWEEP)
        assert _count(db, "survival") == 1

        with pytest.raises(duckdb.Error):
            db.add_survival_batch(rid, [
                # Row 1 is perfectly good and WOULD commit on its own.
                _survival_row(secret_type="SERVER_HANDSHAKE_TRAFFIC_SECRET",
                              dump_path="/corpus/run3/good.dump"),
                # Row 2 blows up inside DuckDB, half-way through the batch.
                _survival_row_that_fails_to_convert(
                    secret_type="EXPORTER_SECRET",
                    dump_path="/corpus/run3/bad.dump"),
            ], sweep_id=SWEEP)

        # ZERO of the two landed — not one of them.
        assert _count(db, "survival") == 1


@needs_duckdb
def test_survival_mid_batch_failure_would_leave_a_row_without_the_transaction(tmp_path):
    """Non-vacuity guard for the test above: prove the reproducer really does
    commit a partial batch when nothing wraps it.

    Without this, deleting the writer's transaction wrapper would still leave
    the rollback test green if DuckDB ever became atomic per-`executemany`.
    """
    import duckdb

    conn = duckdb.connect(str(tmp_path / "raw.duckdb"))
    try:
        conn.execute('CREATE TABLE s("id" VARCHAR PRIMARY KEY, "present" BOOLEAN)')
        with pytest.raises(duckdb.Error):
            conn.executemany('INSERT INTO s("id", "present") VALUES ($1, $2)',
                             [["a", True], ["b", "not-a-bool"]])
        assert conn.execute("SELECT COUNT(*) FROM s").fetchone()[0] == 1
    finally:
        conn.close()


@needs_duckdb
def test_expected_secrets_batch_rolls_back_a_mid_batch_failure(tmp_path):
    """Half a denominator reads as a real one, so it must not survive either."""
    import duckdb

    with ProjectDB(tmp_path / "test.db") as db:
        rid = db.start_run(db.create_project("proj"))
        db.add_expected_secrets_batch(rid, [
            {"library": "openssl", "protocol_version": "13",
             "secret_type": "CLIENT_RANDOM"}], sweep_id=SWEEP)
        assert _count(db, "expected_secrets") == 1

        with pytest.raises((duckdb.Error, duckdb.NotImplementedException)):
            db.add_expected_secrets_batch(rid, [
                # Good row, would commit on its own.
                {"library": "openssl", "protocol_version": "13",
                 "secret_type": "SERVER_HANDSHAKE_TRAFFIC_SECRET"},
                # `identifier_hex` is an UNCOERCED VARCHAR bind (the writer
                # passes it through verbatim), so an untranslatable object is
                # this table's analogue of the survival BOOLEAN case: it gets
                # past the writer and dies inside DuckDB, mid-batch.
                {"library": "openssl", "protocol_version": "13",
                 "secret_type": "EXPORTER_SECRET",
                 "identifier_hex": object()},
            ], sweep_id=SWEEP)

        assert _count(db, "expected_secrets") == 1


# -- v3: the method vocabulary is CLOSED ----------------------------------

def test_methods_vocabulary_is_pinned():
    """``METHODS`` is an on-disk contract, not an implementation detail.

    Precision/recall is computed only over rows that were actually proven, and
    that filter is a membership test against this tuple. Adding a member is a
    deliberate act; renaming one silently reclassifies every stored row.
    """
    from memdiver.engine import project_db as pdb

    assert pdb.METHODS == (
        "keylog_substring",
        "consensus_search",
        "brute_force",
        "oracle",
    )
    assert pdb.METHOD_KEYLOG_SUBSTRING == "keylog_substring"
    assert pdb.METHOD_CONSENSUS_SEARCH == "consensus_search"
    assert pdb.METHOD_BRUTE_FORCE == "brute_force"
    assert pdb.METHOD_ORACLE == "oracle"


def test_survival_statuses_vocabulary_is_pinned():
    from memdiver.engine import project_db as pdb

    assert pdb.SURVIVAL_STATUSES == ("searched", "unreadable", "error")


@needs_duckdb
def test_add_finding_rejects_an_unknown_method(tmp_path):
    with ProjectDB(tmp_path / "test.db") as db:
        rid = db.start_run(db.create_project("proj"))
        with pytest.raises(CapabilityError) as excinfo:
            db.add_finding(rid, "CLIENT_RANDOM", method="vibes")
        assert excinfo.value.category is ErrorCategory.INVALID_INPUT
        # The empty default stays legal: it means "unclassified", which is what
        # every pre-v3 row already holds.
        assert db.add_finding(rid, "CLIENT_RANDOM") != ""


@needs_duckdb
def test_add_findings_batch_rejects_an_unknown_method(tmp_path):
    with ProjectDB(tmp_path / "test.db") as db:
        rid = db.start_run(db.create_project("proj"))
        with pytest.raises(CapabilityError):
            db.add_findings_batch(rid, [
                {"finding_type": "CLIENT_RANDOM", "method": "consensus_search"},
                {"finding_type": "CLIENT_RANDOM", "method": "telepathy"},
            ])
        # Validated before the first write, so no half-written batch survives.
        assert _count(db, "findings") == 0


@needs_duckdb
def test_persist_ground_truth_rejects_an_unknown_method(tmp_path):
    with ProjectDB(tmp_path / "test.db") as db:
        rid = db.start_run(db.create_project("proj"))
        with pytest.raises(CapabilityError):
            db.persist_ground_truth(
                rid, [{"offset": 0, "length": 32, "value_hex": "ab" * 32}],
                method="hearsay")
        with pytest.raises(CapabilityError):
            db.persist_ground_truth(
                rid, [{"offset": 0, "length": 32, "value_hex": "ab" * 32,
                       "method": "hearsay"}])
        assert db.list_ground_truth(rid) == []


# -- v3: the survival pass runs no decryption ------------------------------

def test_survival_table_has_no_confirmed_by_column():
    """The real invariant behind :data:`SURVIVAL_FORBIDDEN_CONFIRMED_BY`.

    That tuple guards ``findings.metadata['confirmed_by']``. ``survival`` has no
    such column AT ALL and must never gain one — the corpus survival pass proves
    only "these keylog bytes are/are not in this dump"; it runs no decryption,
    so it has no provenance to claim.
    """
    from memdiver.engine.project_db import _all_columns

    assert "confirmed_by" not in _all_columns("survival")
    # ...and it does live on the table that earns it.
    assert "confirmed_by" in _all_columns("ground_truth")


@needs_duckdb
def test_add_survival_batch_rejects_any_method_but_keylog_substring(tmp_path):
    """The other half of the same invariant, enforced at the writer."""
    from memdiver.engine.project_db import (
        METHOD_BRUTE_FORCE,
        METHOD_CONSENSUS_SEARCH,
        METHOD_KEYLOG_SUBSTRING,
        METHOD_ORACLE,
    )

    with ProjectDB(tmp_path / "test.db") as db:
        rid = db.start_run(db.create_project("proj"))
        for method in (METHOD_ORACLE, METHOD_BRUTE_FORCE, METHOD_CONSENSUS_SEARCH):
            with pytest.raises(CapabilityError) as excinfo:
                db.add_survival_batch(rid, [_survival_row(method=method)],
                                      sweep_id=SWEEP)
            assert excinfo.value.category is ErrorCategory.INVALID_INPUT
        assert _count(db, "survival") == 0
        assert db.add_survival_batch(
            rid, [_survival_row(method=METHOD_KEYLOG_SUBSTRING)],
            sweep_id=SWEEP) == 1


@needs_duckdb
def test_add_survival_batch_defaults_method_to_keylog_substring(tmp_path):
    """An omitted method states the truth instead of leaving the row blank."""
    with ProjectDB(tmp_path / "test.db") as db:
        rid = db.start_run(db.create_project("proj"))
        row = _survival_row()
        del row["method"]
        db.add_survival_batch(rid, [row], sweep_id=SWEEP)
        stored = db._ibis.table("survival").execute().to_dict("records")[0]
        assert stored["method"] == "keylog_substring"


# -- v3: findings.run_number ----------------------------------------------

def test_finding_row_from_hit_carries_the_corpus_run_number():
    """``SecretHit.run_id`` is the corpus RUN NUMBER and used to be dropped."""
    from memdiver.engine.project_db import _finding_row_from_hit

    row = _finding_row_from_hit({"secret_type": "CLIENT_RANDOM", "run_id": 42})
    assert row["run_number"] == 42
    # An absent one is 0, matching the column default rather than crashing.
    assert _finding_row_from_hit({"secret_type": "CLIENT_RANDOM"})["run_number"] == 0


@needs_duckdb
def test_findings_persist_the_corpus_run_number(tmp_path):
    from memdiver.engine.project_db import _finding_row_from_hit

    with ProjectDB(tmp_path / "test.db") as db:
        rid = db.start_run(db.create_project("proj"))
        db.add_finding(rid, "CLIENT_RANDOM", run_number=7)
        db.add_findings_batch(rid, [
            _finding_row_from_hit({"secret_type": "CLIENT_RANDOM", "run_id": 13})])
        rows = db.query_findings(rid)
        assert sorted(r["run_number"] for r in rows) == [7, 13]


# -- v3: the sweep control plane is schema, not Wave-3 work ---------------

@needs_duckdb
def test_sweep_control_plane_tables_accept_a_row(tmp_path):
    """The ledger that fills these must only ever write ROWS.

    A schema change discovered after 18,917 units have been swept means
    re-running the sweep, not patching it — which is why the DDL lands here, in
    the one item allowed to move the schema.
    """
    from memdiver.engine.project_db import _all_columns, _insert_sql

    with ProjectDB(tmp_path / "test.db") as db:
        db._conn.execute(
            _insert_sql("sweeps", _all_columns("sweeps")),
            ["sw1", "corpus-digest", "tls_dumps", "cfg-digest",
             5, 1, '["openssl"]', '["13"]', "completed", 5,
             "t0", "t0", "t1"])
        db._conn.execute(
            _insert_sql("sweep_units", _all_columns("sweep_units")),
            ["su1", "sw1", "openssl/13/run_1/pre_abort", "done",
             "inputs-digest", "size", 0, 512, 1, "t0", "t0", "t1"])
        sweep = db._ibis.table("sweeps").execute().to_dict("records")[0]
        # The filter set is what stops a 5-run CI slice being published as a
        # 2,600-run result.
        assert sweep["max_units"] == 5
        assert sweep["max_runs_per_library"] == 1
        assert sweep["library_filter"] == '["openssl"]'
        unit = db._ibis.table("sweep_units").execute().to_dict("records")[0]
        assert unit["digest_level"] == "size"
        assert unit["result_bytes"] == 512
        assert unit["attempt"] == 1


@needs_duckdb
def test_sweep_units_are_mutable_unlike_the_findings_tables(tmp_path):
    """``sweeps`` / ``sweep_units`` are the documented exception to append-only:
    a unit row is UPDATEd in place as it moves pending -> running -> done."""
    from memdiver.engine.project_db import _all_columns, _insert_sql

    with ProjectDB(tmp_path / "test.db") as db:
        db._conn.execute(
            _insert_sql("sweep_units", _all_columns("sweep_units")),
            ["su1", "sw1", "unit-1", "pending", "", "size", 0, 0, 0, "t0", "", ""])
        db._conn.execute(
            'UPDATE "sweep_units" SET "status" = $1, "attempt" = $2 '
            'WHERE "sweep_unit_id" = $3', ["done", 1, "su1"])
        unit = db._ibis.table("sweep_units").execute().to_dict("records")[0]
        assert unit["status"] == "done"
        assert unit["attempt"] == 1
        assert _count(db, "sweep_units") == 1


# -- pipeline._persist_report wires the dumps table -----------------------

@needs_duckdb
def test_pipeline_persist_report_writes_dump_rows(tmp_path):
    """``AnalysisPipeline._persist_report`` fills the previously-unused dumps table.

    ``add_dump`` had no production caller at all, so every persisted run used to
    have zero dumps attached. The ``(run, dump)`` pairs the pipeline already
    builds now supply real ``dump_id``s, ``run_number``s and sidecar paths.
    """
    from memdiver.core.models import DumpFile, RunDirectory
    from memdiver.engine.pipeline import AnalysisPipeline
    from memdiver.engine.results import LibraryReport, SecretHit

    run_dir = tmp_path / "openssl_run_13_4"
    run_dir.mkdir()
    dump_path = run_dir / "20251020_171845_606711_pre_abort.dump"
    dump_path.write_bytes(b"\x00" * 512)
    (run_dir / "keylog.csv").write_text("x\n", encoding="utf-8")

    dump = DumpFile(path=dump_path, timestamp="20251020_171845_606711",
                    phase_prefix="pre", phase_name="abort",
                    canonical_phase="handshake_end", kind="gcore")
    run = RunDirectory(path=run_dir, library="openssl", protocol_version="13",
                       run_number=4, dumps=[dump])
    report = LibraryReport(library="openssl", protocol_version="13",
                           phase="pre_abort", num_runs=1)
    hit = SecretHit(secret_type="CLIENT_HANDSHAKE_TRAFFIC_SECRET",
                    offset=585148, length=32, dump_path=dump_path,
                    library="openssl", phase="pre_abort", run_id=4,
                    verified=True)

    with ProjectDB(tmp_path / "test.db") as db:
        pipeline = AnalysisPipeline(project_db=db, auto_persist=False)
        pipeline._persist_report(report, [hit], run_dir.parent, [(run, dump)])

        project = db.list_projects()[0]
        assert project["name"] == "openssl_13"
        assert project["library"] == "openssl"

        run_row = db.project_timeline(project["project_id"])[0]
        assert run_row["phase"] == "pre_abort"
        assert run_row["canonical_phase"] == "handshake_end"
        # single-run invocation -> the per-run sidecars are meaningful
        assert run_row["run_number"] == 4
        assert run_row["run_dir"] == str(run_dir)
        assert run_row["keylog_path"] == str(run_dir / "keylog.csv")

        t = db._ibis.table("dumps")
        dumps = t.execute().to_dict("records")
        assert len(dumps) == 1
        assert dumps[0]["dump_id"] != ""
        assert dumps[0]["file_path"] == str(dump_path)
        assert dumps[0]["file_type"] == "gcore"
        assert dumps[0]["file_size"] == 512
        assert dumps[0]["phase"] == "pre_abort"
        assert dumps[0]["canonical_phase"] == "handshake_end"
        assert dumps[0]["run_number"] == 4
        assert dumps[0]["library"] == "openssl"
        # dumps.run_id is the authoritative dump -> run link.
        assert dumps[0]["run_id"] == run_row["run_id"]

        f = db.query_findings(run_row["run_id"])[0]
        assert f["dump_path"] == str(dump_path)
        assert f["phase"] == "pre_abort"
        assert f["library"] == "openssl"
        assert f["secret_type"] == "CLIENT_HANDSHAKE_TRAFFIC_SECRET"
        assert f["method"] == "consensus_search"
        assert f["verified"] is True
        # The hit is built with `run_id=4`, and this path used to build its hit
        # dict WITHOUT that key: `findings.run_number` landed 0 on every real
        # run even though the column exists and the reader maps it. Same story
        # for `canonical_phase`, which falls back to the analysed dumps'.
        assert f["run_number"] == 4
        assert f["canonical_phase"] == "handshake_end"


@needs_duckdb
def test_pipeline_persist_report_records_verified_hits_as_ground_truth(tmp_path):
    """The ``verify_decryption`` path finally reaches the W5 ledger.

    ``_persist_report`` wrote no ``ground_truth`` row at all, so the ONLY
    pipeline path that produces cryptographically-confirmed key locations never
    recorded one.
    """
    from memdiver.core.models import DumpFile, RunDirectory
    from memdiver.engine.pipeline import AnalysisPipeline
    from memdiver.engine.results import LibraryReport, SecretHit

    run_dir = tmp_path / "openssl_run_13_4"
    run_dir.mkdir()
    dump_path = run_dir / "d.dump"
    dump_path.write_bytes(b"\x00" * 64)
    dump = DumpFile(path=dump_path, timestamp="t", phase_prefix="pre",
                    phase_name="abort", canonical_phase="handshake_end")
    run = RunDirectory(path=run_dir, library="openssl", protocol_version="13",
                       run_number=4, dumps=[dump])
    report = LibraryReport(library="openssl", protocol_version="13",
                           phase="pre_abort", num_runs=1)
    hits = [
        SecretHit(secret_type="CLIENT_HANDSHAKE_TRAFFIC_SECRET", offset=585148,
                  length=32, dump_path=dump_path, library="openssl",
                  phase="pre_abort", run_id=4, verified=True,
                  value_hex="ab" * 32, metadata={"cipher": "AES_256_GCM"}),
        # Unverified: must NOT reach the ledger.
        SecretHit(secret_type="SERVER_HANDSHAKE_TRAFFIC_SECRET", offset=1024,
                  length=32, dump_path=dump_path, library="openssl",
                  phase="pre_abort", run_id=4),
    ]

    with ProjectDB(tmp_path / "test.db") as db:
        pipeline = AnalysisPipeline(project_db=db, auto_persist=False)
        pipeline._persist_report(report, hits, run_dir.parent, [(run, dump)])

        assert len(db.query_findings(
            db.project_timeline(db.list_projects()[0]["project_id"])[0]["run_id"]
        )) == 2
        labels = db.list_ground_truth()
        assert len(labels) == 1
        assert labels[0]["secret_type"] == "CLIENT_HANDSHAKE_TRAFFIC_SECRET"
        assert labels[0]["value_hex"] == "ab" * 32
        assert labels[0]["key_hex"] == "ab" * 32
        assert labels[0]["confirmed_by"] == "verifier"
        assert labels[0]["cipher"] == "AES_256_GCM"
        assert labels[0]["run_number"] == 4
        assert labels[0]["canonical_phase"] == "handshake_end"
        assert labels[0]["method"] == "consensus_search"
        # `add_dump` returns the id it minted, and this path used to discard it,
        # so a label had no way back to its dump row.
        dumps = db._ibis.table("dumps").execute().to_dict("records")
        assert labels[0]["dump_id"] == dumps[0]["dump_id"] != ""
        assert labels[0]["dump_path"] == str(dump_path)

        # Re-running the same analysis must not double the ledger.
        pipeline._persist_report(report, hits, run_dir.parent, [(run, dump)])
        assert len(db.list_ground_truth()) == 1


@needs_duckdb
def test_pipeline_persist_report_honours_a_custom_keylog_filename(tmp_path):
    """``_keylog_path`` used to probe the built-in default and nothing else.

    A corpus whose sidecar is not named ``keylog.csv`` therefore persisted
    ``keylog_path = ""`` even though discovery had just read the real file.
    """
    from memdiver.core.models import DumpFile, RunDirectory
    from memdiver.engine.pipeline import AnalysisPipeline
    from memdiver.engine.results import LibraryReport

    run_dir = tmp_path / "openssl_run_13_0"
    run_dir.mkdir()
    dump_path = run_dir / "d.dump"
    dump_path.write_bytes(b"\x00" * 16)
    (run_dir / "secrets.log").write_text("x\n", encoding="utf-8")
    dump = DumpFile(path=dump_path, timestamp="t", phase_prefix="pre",
                    phase_name="abort")
    run = RunDirectory(path=run_dir, library="openssl", protocol_version="13",
                       run_number=0, dumps=[dump])
    report = LibraryReport(library="openssl", protocol_version="13",
                           phase="pre_abort", num_runs=1)

    with ProjectDB(tmp_path / "test.db") as db:
        pipeline = AnalysisPipeline(project_db=db, auto_persist=False)
        pipeline._persist_report(report, [], run_dir.parent, [(run, dump)],
                                 keylog_filename="secrets.log")
        run_row = db.project_timeline(db.list_projects()[0]["project_id"])[0]
        assert run_row["keylog_path"] == str(run_dir / "secrets.log")

    # ... and the default is unchanged when the caller names nothing.
    (run_dir / "keylog.csv").write_text("x\n", encoding="utf-8")
    with ProjectDB(tmp_path / "default.db") as db:
        pipeline = AnalysisPipeline(project_db=db, auto_persist=False)
        pipeline._persist_report(report, [], run_dir.parent, [(run, dump)])
        run_row = db.project_timeline(db.list_projects()[0]["project_id"])[0]
        assert run_row["keylog_path"] == str(run_dir / "keylog.csv")


@needs_duckdb
def test_pipeline_persist_report_rolls_back_a_failed_write(tmp_path):
    """One transaction: a failure part-way leaves no half-written project.

    ``analyze_library`` swallows this exception, so without the rollback the
    silent outcome was a project + run row carrying only some of their rows.
    """
    from memdiver.core.models import DumpFile, RunDirectory
    from memdiver.engine.pipeline import AnalysisPipeline
    from memdiver.engine.results import LibraryReport

    run_dir = tmp_path / "openssl_run_13_0"
    run_dir.mkdir()
    dump_path = run_dir / "d.dump"
    dump_path.write_bytes(b"\x00" * 16)
    dump = DumpFile(path=dump_path, timestamp="t", phase_prefix="pre",
                    phase_name="abort")
    run = RunDirectory(path=run_dir, library="openssl", protocol_version="13",
                       run_number=0, dumps=[dump])
    report = LibraryReport(library="openssl", protocol_version="13",
                           phase="pre_abort", num_runs=1)

    with ProjectDB(tmp_path / "test.db") as db:
        pipeline = AnalysisPipeline(project_db=db, auto_persist=False)
        with patch.object(ProjectDB, "add_findings_batch",
                          side_effect=RuntimeError("boom")):
            with pytest.raises(RuntimeError):
                pipeline._persist_report(report, [], run_dir.parent,
                                         [(run, dump)])
        assert db.list_projects() == []
        assert _count(db, "dumps") == 0
        assert _count(db, "analysis_runs") == 0


@needs_duckdb
def test_pipeline_persist_report_multi_run_omits_per_run_sidecars(tmp_path):
    """A run row spanning several corpus runs must not claim one run's sidecars."""
    from memdiver.core.models import DumpFile, RunDirectory
    from memdiver.engine.pipeline import AnalysisPipeline
    from memdiver.engine.results import LibraryReport

    pairs = []
    for n in (0, 1):
        run_dir = tmp_path / f"openssl_run_13_{n}"
        run_dir.mkdir()
        dump_path = run_dir / "d.dump"
        dump_path.write_bytes(b"\x00" * 16)
        dump = DumpFile(path=dump_path, timestamp="t", phase_prefix="pre",
                        phase_name="abort")
        pairs.append((RunDirectory(path=run_dir, library="openssl",
                                   protocol_version="13", run_number=n,
                                   dumps=[dump]), dump))

    report = LibraryReport(library="openssl", protocol_version="13",
                           phase="pre_abort", num_runs=2)
    with ProjectDB(tmp_path / "test.db") as db:
        pipeline = AnalysisPipeline(project_db=db, auto_persist=False)
        pipeline._persist_report(report, [], tmp_path, pairs)

        run_row = db.project_timeline(db.list_projects()[0]["project_id"])[0]
        assert run_row["run_number"] == 0
        assert run_row["run_dir"] == ""
        assert run_row["keylog_path"] == ""

        dumps = db._ibis.table("dumps").execute().to_dict("records")
        assert sorted(d["run_number"] for d in dumps) == [0, 1]
        assert all(d["run_id"] == run_row["run_id"] for d in dumps)


# ---------------------------------------------------------------------------
# The producer -> ledger bridge: corpus axes must actually arrive
# ---------------------------------------------------------------------------
#
class _RollbackHostileConn:
    """A connection proxy whose ``ROLLBACK`` raises; everything else passes.

    A DuckDB connection is a C object, so the failure has to be injected from
    outside it rather than by patching a method on it.
    """

    def __init__(self, inner):
        self._inner = inner

    def execute(self, sql, *args, **kwargs):
        if str(sql).strip().upper().startswith("ROLLBACK"):
            raise RuntimeError("rollback failed")
        return self._inner.execute(sql, *args, **kwargs)

    def __getattr__(self, name):
        return getattr(self._inner, name)


@needs_duckdb
def test_pipeline_persist_report_does_not_swallow_a_failed_rollback(tmp_path):
    """A ROLLBACK that itself fails must SURFACE, not vanish.

    ``_persist_report`` used to issue a raw ``BEGIN`` on ``db._conn`` and wrap
    its own ``ROLLBACK`` in ``except Exception: logger.debug(...)``. When that
    rollback threw, the original error was re-raised and the rollback failure
    disappeared — leaving the connection inside an OPEN TRANSACTION. Every
    later ``_persist_report`` then died at ``BEGIN``, ``analyze_library``
    swallowed that too, and the process silently lost all persistence for the
    rest of its life behind one ``logger.warning``.

    Routing through :meth:`ProjectDB._transaction` — the context manager the
    class already uses for its own batch writers — is what makes the failure
    visible. The assertion below is exactly that difference: the error that
    escapes is the ROLLBACK's, not the write's.
    """
    from memdiver.core.discovery import RunDiscovery
    from memdiver.engine.pipeline import AnalysisPipeline
    from memdiver.engine.results import LibraryReport

    library_dir = _corpus_library(tmp_path)
    run = RunDiscovery.discover_library_runs(library_dir)[0]
    dump = run.get_dump_for_phase("pre_abort")
    report = LibraryReport(library="openssl", protocol_version="12",
                           phase="pre_abort", num_runs=1)

    with ProjectDB(tmp_path / "test.db") as db:
        db._conn = _RollbackHostileConn(db._conn)
        pipeline = AnalysisPipeline(project_db=db, auto_persist=False)
        with patch.object(ProjectDB, "add_findings_batch",
                          side_effect=RuntimeError("boom")):
            with pytest.raises(RuntimeError, match="rollback failed"):
                pipeline._persist_report(report, [], library_dir,
                                         [(run, dump)])
        # Restore the real connection so the context manager can close it.
        db._conn = db._conn._inner


# -- the producers actually fill the fields the transport carries ----------


@needs_duckdb
def test_analyze_library_persists_the_verified_key_bytes(tmp_path):
    """The W5 proof ledger records real key bytes, not empty proofs.

    ``SecretHit.value_hex`` had ZERO production writers, so every
    ``ground_truth`` row the verify path wrote landed with ``key_hex = NULL``,
    ``value_hex = ''`` and ``cipher = NULL``: the row count looked healthy and
    the evidence was not in it. ``_verify_hits`` already held the bytes it
    decrypted with — it read them, checked them, and threw them away.
    """
    library_dir = _corpus_library(tmp_path)
    with ProjectDB(tmp_path / "test.db") as db:
        report = _analyze_corpus_library(library_dir, project_db=db)
        assert [h.verified for h in report.hits] == [True]

        run = db.project_timeline(db.list_projects()[0]["project_id"])[0]
        finding = db.query_findings(run["run_id"])[0]
        assert finding["value_hex"] == _CORPUS_SECRET.hex()

        label = db.list_ground_truth()[0]
        # The three columns the live path used to leave empty.
        assert label["key_hex"] == _CORPUS_SECRET.hex()
        assert label["value_hex"] == _CORPUS_SECRET.hex()
        # The verifier's OWN name — what was proven is "decrypts under this
        # verifier", not a claim about the negotiated TLS suite.
        assert label["cipher"] == "AES-256-CBC"
        # Not stamped by the producer: `_confirmed_by` already resolves an
        # unlabelled verified hit to this, and a second spelling could drift.
        assert label["confirmed_by"] == "verifier"
        assert label["offset"] == _CORPUS_SECRET_OFFSET


@needs_duckdb
def test_analyze_library_stamps_the_corpus_axes_on_the_report(tmp_path):
    """The report a caller READS carries the axes, not just the DB row.

    ``LibraryReport`` grew five axis fields and ``serialize_report`` emits
    them, but neither production constructor passed any of them: a normalized
    run whose phase held a canonical value still serialized
    ``canonical_phase=''``, ``scenario=''``, ``protocol=''``,
    ``library_version='unknown'``.
    """
    from memdiver.engine.serializer import serialize_report

    report = _analyze_corpus_library(_corpus_library(tmp_path))
    serialized = serialize_report(report)
    assert serialized["scenario"] == _CORPUS_SCENARIO
    assert serialized["protocol"] == "TLS"
    assert serialized["version_axis"] == "protocol_version"
    assert serialized["library_version"] == "unknown"
    assert serialized["canonical_phase"] != ""
    assert serialized["canonical_phase"] == report.canonical_phase

    # And the hits carry the canonical phase of THEIR OWN dump, stamped by the
    # correlator from the value the pipeline resolved per dump.
    assert [h["canonical_phase"] for h in serialized["hits"]] == \
        [report.canonical_phase]


@needs_duckdb
def test_pipeline_persist_report_resolves_a_corpus_shaped_run(tmp_path):
    """``_resolve_axes``' SUCCESS branch, which nothing else reaches.

    Every other ``_persist_report`` test in this file puts its run directory
    straight under ``tmp_path``, where ``axes_from_run_dir`` returns ``None``
    and only the fallback runs. Here the tree conforms, so the real axes are
    resolved — and a hand-built report carrying only the column defaults must
    still get them, because ``_persisted_axes`` falls back to resolution for a
    report nothing stamped.
    """
    from memdiver.core.discovery import RunDiscovery
    from memdiver.engine.pipeline import AnalysisPipeline
    from memdiver.engine.results import LibraryReport

    library_dir = _corpus_library(tmp_path)
    run = RunDiscovery.discover_library_runs(library_dir)[0]
    dump = run.get_dump_for_phase("pre_abort")
    report = LibraryReport(library="openssl", protocol_version="12",
                           phase="pre_abort", num_runs=1)
    # The un-stamped report really is at the column defaults.
    assert (report.scenario, report.protocol) == ("", "")

    with ProjectDB(tmp_path / "test.db") as db:
        pipeline = AnalysisPipeline(project_db=db, auto_persist=False)
        pipeline._persist_report(report, [], library_dir, [(run, dump)])

        project = db.list_projects()[0]
        assert project["scenario"] == _CORPUS_SCENARIO
        assert project["protocol"] == "TLS"
        assert project["library_version"] == "unknown"
        assert project["version_axis"] == "protocol_version"

        run_row = db.project_timeline(project["project_id"])[0]
        assert run_row["scenario"] == _CORPUS_SCENARIO
        assert run_row["run_number"] == 1


@needs_duckdb
def test_pipeline_persist_report_prefers_the_axes_the_report_carries(tmp_path):
    """A stamped report is written as-is; the DB never re-resolves behind it.

    ``analyze_library`` resolves the axes once and stamps them on the report,
    so the report a caller reads and the row written here cannot disagree.
    """
    from memdiver.core.discovery import RunDiscovery
    from memdiver.engine.pipeline import AnalysisPipeline
    from memdiver.engine.results import LibraryReport

    library_dir = _corpus_library(tmp_path)
    run = RunDiscovery.discover_library_runs(library_dir)[0]
    dump = run.get_dump_for_phase("pre_abort")
    report = LibraryReport(library="openssl", protocol_version="12",
                           phase="pre_abort", num_runs=1,
                           scenario="stamped_scenario", protocol="SSH",
                           library_version="3.0.2",
                           version_axis="library_version")

    with ProjectDB(tmp_path / "test.db") as db:
        pipeline = AnalysisPipeline(project_db=db, auto_persist=False)
        pipeline._persist_report(report, [], library_dir, [(run, dump)])

        project = db.list_projects()[0]
        assert project["scenario"] == "stamped_scenario"
        assert project["protocol"] == "SSH"
        assert project["library_version"] == "3.0.2"
        assert project["version_axis"] == "library_version"


# `app.tools_pipeline._persist_ground_truth_hits` is the ONLY production writer
# on the oracle path. It used to pass hits + confirmed_by and nothing else, so
# every axis column in `ground_truth` landed empty on every real run. These
# tests pin the whole bridge (axis resolution -> record_ground_truth_run -> row)
# rather than either half, because either half alone can silently drop an axis.

#: A real corpus dump path (see core.corpus_axes for the layout). Axis
#: resolution is pure path decomposition, so this is used as a STRING and needs
#: no corpus tree on disk.
_CORPUS_DUMP = (
    "/Users/danielbaier/Desktop/tls_dumps/TLS13/"
    "100_iterations_Abort_KeyUpdate/openssl/openssl_run_13_1/"
    "20251020_171845_606711_pre_server_key_update.dump"
)


def _persist_hits_into(db, dump_path):
    """Run the producer's ledger bridge against an already-open *db*.

    ``_persist_ground_truth_hits`` reaches ProjectDB through the composition
    root and closes the handle it is given, so the test DB is handed over as a
    non-closing stand-in.
    """
    from memdiver.app import tools_pipeline

    class _KeepOpen:
        """Delegate everything to *db* but ignore the producer's ``close()``."""

        def __getattr__(self, name):
            return getattr(db, name)

        def close(self):
            pass

    hits = [{"offset": 585148, "length": 32, "key_hex": "ab" * 32}]
    with patch("memdiver.app.composition.resolve_project_db",
               return_value=_KeepOpen()):
        return tools_pipeline._persist_ground_truth_hits(
            hits,
            confirmed_by="pcap",
            project_name="reference",
            **tools_pipeline._corpus_axes_kwargs(dump_path),
        )


@needs_duckdb
def test_producer_ledger_bridge_populates_the_corpus_axes(tmp_path):
    """A brute-force-shaped call fills the axis columns instead of leaving ''."""
    with ProjectDB(tmp_path / "test.db") as db:
        rid = _persist_hits_into(db, _CORPUS_DUMP)
        assert rid
        row = db.list_ground_truth(rid)[0]

    assert row["library"] == "openssl"
    assert row["version"] == "13"
    assert row["scenario"] == "100_iterations_Abort_KeyUpdate"
    assert row["run_number"] == 1
    assert row["phase"] == "pre_server_key_update"
    assert row["dump_path"] == _CORPUS_DUMP
    assert row["confirmed_by"] == "pcap"
    assert row["method"] == "oracle"
    # Deliberately empty: a canonical phase is positional across a run's
    # SIBLING dumps, so it cannot be derived from one path (core.corpus_axes).
    assert row["canonical_phase"] == ""


@needs_duckdb
def test_producer_ledger_bridge_handles_a_non_corpus_dump(tmp_path):
    """An ad-hoc dump resolves to no axes and still writes a usable row."""
    adhoc = str(tmp_path / "scratch" / "reference.bin")
    with ProjectDB(tmp_path / "test.db") as db:
        rid = _persist_hits_into(db, adhoc)
        assert rid
        row = db.list_ground_truth(rid)[0]

    # The one axis that is always knowable is still recorded...
    assert row["dump_path"] == adhoc
    # ...and the row is complete and readable, just axis-less.
    assert row["value_hex"] == "ab" * 32
    assert row["confirmed_by"] == "pcap"
    assert row["method"] == "oracle"
    assert row["library"] == ""
    assert row["version"] == ""
    assert row["scenario"] == ""
    assert row["run_number"] == 0
    assert row["phase"] == ""


@needs_duckdb
def test_producer_ledger_bridge_on_the_real_corpus_tree(tmp_path):
    """Same bridge, against a dump that really exists on disk.

    The other two cases resolve axes from a path string. This one proves the
    resolution also survives the filesystem probes ``axes_from_dump_path`` makes
    (the run's ``meta.json`` / ``keylog.csv`` sidecars). Skips cleanly when the
    private corpus is not present.
    """
    if not Path(_CORPUS_DUMP).is_file():
        pytest.skip(f"corpus dump not present: {_CORPUS_DUMP}")

    with ProjectDB(tmp_path / "test.db") as db:
        rid = _persist_hits_into(db, _CORPUS_DUMP)
        row = db.list_ground_truth(rid)[0]

    assert (row["library"], row["version"], row["run_number"]) == ("openssl", "13", 1)
    assert row["phase"] == "pre_server_key_update"
    assert row["library_version"] == "unknown"


# =========================================================================
# v3 hardening: the SILENT-LOSS defects
#
# Every test below covers a way this module could accept a batch, return the
# full row count, log nothing, raise nothing -- and store something other than
# what the caller wrote.
# =========================================================================

# -- C1: an empty dump_path silently ate 63,475 of 63,481 cells -----------

@needs_duckdb
def test_survival_without_dump_path_is_rejected_not_silently_collapsed(tmp_path):
    """The defect this replaces would have destroyed the published result.

    The PRIMARY KEY was built from ``unit_key or dump_path or dump_id`` while
    the UNIQUE index is ``(sweep_id, dump_path, secret_type)``. Those are
    DIFFERENT KEYS: a caller supplying a distinct ``dump_id`` but no
    ``dump_path`` got a distinct PK for every cell, so the PK never fired -- and
    the index then collapsed all of them onto ``(sweep, '', secret_type)``.

    On the real corpus shape (11,141 TLS1.3 dumps x 5 secret types + 7,776
    TLS1.2 x 1 = 63,481 cells) SIX rows survived, 63,475 were dropped, and the
    writer returned 63,481. No exception, no log line.
    """

    rows = []
    for i in range(100):
        row = _survival_row(dump_id=f"dump-{i}")
        del row["dump_path"]          # the fatal omission
        rows.append(row)

    with ProjectDB(tmp_path / "test.db") as db:
        rid = db.start_run(db.create_project("proj"))
        with pytest.raises(CapabilityError) as excinfo:
            db.add_survival_batch(rid, rows, sweep_id=SWEEP)
        assert excinfo.value.category is ErrorCategory.INVALID_INPUT
        assert excinfo.value.code == "project_db.survival_dump_path_required"
        # Loudly zero rows, not quietly one.
        assert _count(db, "survival") == 0


@needs_duckdb
def test_survival_error_rows_may_omit_the_dump_path(tmp_path):
    """``status='error'`` writes no row, so it has no cell to identify.

    Rejecting it would make a caller that hands the writer a whole batch and
    lets it drop the failures -- the documented usage -- impossible.
    """
    with ProjectDB(tmp_path / "test.db") as db:
        rid = db.start_run(db.create_project("proj"))
        bad = _survival_row(status="error", present=None)
        del bad["dump_path"]
        assert db.add_survival_batch(rid, [bad, _survival_row()],
                                     sweep_id=SWEEP) == 1
        assert _count(db, "survival") == 1


# -- C2: DO NOTHING kept the STALE row, so a resume lost its correction ---

@needs_duckdb
def test_survival_resume_corrects_a_wrong_observation(tmp_path):
    """A resume that CORRECTS a reading must win, not lose to the stale row.

    ``ON CONFLICT DO NOTHING`` keeps whatever is already on disk. That is only
    equivalent to a re-insert when the re-submitted row is BYTE-IDENTICAL, which
    a resume cannot guarantee: a first pass that recorded ``present = FALSE``
    and a second that finds the secret four times had its correction accepted,
    counted in the return value, and thrown away.
    """
    with ProjectDB(tmp_path / "test.db") as db:
        rid = db.start_run(db.create_project("proj"))
        assert db.add_survival_batch(
            rid, [_survival_row(present=False, hit_count=0, first_offset=None)],
            sweep_id=SWEEP) == 1
        assert db.add_survival_batch(
            rid, [_survival_row(present=True, hit_count=4, first_offset=585148)],
            sweep_id=SWEEP) == 1

        rows = db._ibis.table("survival").execute().to_dict("records")
        assert len(rows) == 1, "the correction must not add a second cell"
        assert rows[0]["present"] is True
        assert rows[0]["hit_count"] == 4
        assert rows[0]["first_offset"] == 585148


@needs_duckdb
def test_survival_identical_resubmit_is_a_no_op(tmp_path):
    """The other half: an unchanged resume changes nothing observable."""
    with ProjectDB(tmp_path / "test.db") as db:
        rid = db.start_run(db.create_project("proj"))
        db.add_survival_batch(rid, [_survival_row()], sweep_id=SWEEP)
        before = db._ibis.table("survival").execute().to_dict("records")
        db.add_survival_batch(rid, [_survival_row()], sweep_id=SWEEP)
        after = db._ibis.table("survival").execute().to_dict("records")
        assert len(after) == 1
        assert before == after


@needs_duckdb
def test_survival_correction_never_moves_the_row_to_another_cell(tmp_path):
    """Only the OBSERVATION columns are updatable; identity stays put."""
    with ProjectDB(tmp_path / "test.db") as db:
        rid = db.start_run(db.create_project("proj"))
        db.add_survival_batch(rid, [_survival_row(library="openssl")],
                              sweep_id=SWEEP)
        created_at = db._ibis.table("survival").execute() \
                       .to_dict("records")[0]["created_at"]
        db.add_survival_batch(
            rid, [_survival_row(library="wolfssl", present=False)],
            sweep_id=SWEEP)
        row = db._ibis.table("survival").execute().to_dict("records")[0]
        assert row["present"] is False          # observation updated
        assert row["library"] == "openssl"      # identity/axis untouched
        assert row["dump_path"] == "/corpus/run3/pre_abort.dump"
        assert row["created_at"] == created_at


@needs_duckdb
def test_expected_secrets_resume_corrects_a_stale_denominator_row(tmp_path):
    """The denominator has the same stale-wins hazard as the numerator."""
    with ProjectDB(tmp_path / "test.db") as db:
        rid = db.start_run(db.create_project("proj"))
        base = {"library": "gotls", "protocol_version": "12", "run_number": 5,
                "secret_type": "CLIENT_RANDOM"}
        db.add_expected_secrets_batch(
            rid, [dict(base, dumps_in_run=0, keylog_status="unreadable")],
            sweep_id=SWEEP)
        db.add_expected_secrets_batch(
            rid, [dict(base, dumps_in_run=6, keylog_status="ok",
                       secret_len=32, identifier_hex="bb" * 32)],
            sweep_id=SWEEP)
        rows = db._ibis.table("expected_secrets").execute().to_dict("records")
        assert len(rows) == 1
        assert rows[0]["keylog_status"] == "ok"
        assert rows[0]["dumps_in_run"] == 6
        assert rows[0]["secret_len"] == 32


# -- C3: an empty sweep_id defeated the column's entire purpose -----------

@needs_duckdb
def test_survival_rejects_an_empty_sweep_id(tmp_path):
    """Two sweeps over one dump merged, and the SECOND lost to the FIRST.

    ``resolve_project_db()`` opens ONE global database file, so a full-corpus
    publication run written with ``sweep_id=''`` collided with a five-run CI
    slice written earlier with ``sweep_id=''``.
    """

    with ProjectDB(tmp_path / "test.db") as db:
        rid = db.start_run(db.create_project("proj"))
        for kwargs in ({}, {"sweep_id": ""}):
            with pytest.raises(CapabilityError) as excinfo:
                db.add_survival_batch(rid, [_survival_row()], **kwargs)
            assert excinfo.value.category is ErrorCategory.INVALID_INPUT
            assert excinfo.value.code == "project_db.sweep_id_required"
        assert _count(db, "survival") == 0


@needs_duckdb
def test_expected_secrets_rejects_an_empty_sweep_id(tmp_path):
    with ProjectDB(tmp_path / "test.db") as db:
        rid = db.start_run(db.create_project("proj"))
        row = {"library": "openssl", "protocol_version": "13",
               "secret_type": "CLIENT_RANDOM"}
        with pytest.raises(CapabilityError) as excinfo:
            db.add_expected_secrets_batch(rid, [row])
        assert excinfo.value.category is ErrorCategory.INVALID_INPUT
        assert excinfo.value.code == "project_db.sweep_id_required"
        assert _count(db, "expected_secrets") == 0


@needs_duckdb
def test_a_per_row_sweep_id_satisfies_the_requirement(tmp_path):
    """The batch-wide default is not the only way to name a sweep."""
    with ProjectDB(tmp_path / "test.db") as db:
        rid = db.start_run(db.create_project("proj"))
        assert db.add_survival_batch(
            rid, [_survival_row(sweep_id="per-row")]) == 1
        assert db._ibis.table("survival").execute() \
                 .to_dict("records")[0]["sweep_id"] == "per-row"


# -- C4: a DB running without its uniqueness index must say so -----------

def _survival_values(**over):
    """A raw 21-value ``survival`` row in schema order, for direct DuckDB use."""
    from memdiver.engine.project_db import _all_columns

    row = {"survival_id": "id-1", "run_id": "r", "dump_id": "", "library": "openssl",
           "protocol_version": "13", "library_version": "unknown", "scenario": "",
           "run_number": 3, "phase": "", "canonical_phase": "",
           "secret_type": "CLIENT_RANDOM", "present": True, "first_offset": None,
           "hit_count": 0, "method": "keylog_substring",
           "dump_path": "/corpus/run3/pre_abort.dump", "created_at": "t0",
           "sweep_id": SWEEP, "status": "searched", "format_name": "",
           "size_for_view": 0}
    row.update(over)
    return [row[c] for c in _all_columns("survival")]


@needs_duckdb
def test_a_healthy_database_reports_no_degraded_indexes(tmp_path):
    with ProjectDB(tmp_path / "test.db") as db:
        assert db.degraded_indexes() == ()


@needs_duckdb
def test_a_database_that_cannot_build_its_unique_index_says_so(tmp_path):
    """``_ensure_indexes`` warns and continues -- correct, but not a signal.

    A database that opened without ``survival_cell_unique`` runs WITHOUT the
    uniqueness guarantee: every ``ON CONFLICT`` on that arbiter degrades, the
    same (dump, secret_type) can hold two CONTRADICTORY rows, and the condition
    is self-perpetuating -- once one duplicate exists the index can never build
    again. One WARNING at ``open()`` is the only trace in the whole process
    lifetime, and nothing downstream can branch on a log record.
    """
    import duckdb

    from memdiver.engine.project_db import _SCHEMA_SQL, _all_columns, _insert_sql

    db_path = tmp_path / "dupes.duckdb"
    conn = duckdb.connect(str(db_path))
    try:
        for ddl in _SCHEMA_SQL:          # tables, but deliberately NO indexes
            conn.execute(ddl)
        conn.executemany(
            _insert_sql("survival", _all_columns("survival")),
            [_survival_values(survival_id="a", present=True),
             _survival_values(survival_id="b", present=False)])
    finally:
        conn.close()

    with ProjectDB(db_path) as db:
        # Still open: the owner is not locked out of their own project file.
        assert db._available is True
        # ...but the loss of the guarantee is now READABLE, not just logged.
        assert "survival_cell_unique" in db.degraded_indexes()
        # And writing still works -- the PK arbiter is used instead of the
        # missing index, so a degraded database is usable but unpublishable.
        assert db.add_survival_batch(
            rid_of := db.start_run(db.create_project("p")),
            [_survival_row(dump_path="/corpus/run9/other.dump")],
            sweep_id=SWEEP) == 1
        assert rid_of


# -- C6: only "" is exempt from the method vocabulary --------------------

@needs_duckdb
@pytest.mark.parametrize("smuggled", [0, None, []])
def test_add_finding_rejects_a_falsy_non_string_method(tmp_path, smuggled):
    """``if method and ...`` waved through every falsy value, not just ``""``.

    ``method=0`` stored the STRING ``'0'`` -- a non-empty method outside the
    closed vocabulary, missed by both ``WHERE method = ''`` and
    ``WHERE method = 'oracle'``. ``method=None`` stored SQL NULL, which is
    excluded by ``WHERE method = ''`` AND by ``WHERE method <> 'oracle'`` --
    the exact NULL trap ``survival.status`` was introduced to close one table
    over.
    """

    with ProjectDB(tmp_path / "test.db") as db:
        rid = db.start_run(db.create_project("proj"))
        with pytest.raises(CapabilityError) as excinfo:
            db.add_finding(rid, "CLIENT_RANDOM", method=smuggled)
        assert excinfo.value.category is ErrorCategory.INVALID_INPUT
        assert _count(db, "findings") == 0


@needs_duckdb
@pytest.mark.parametrize("smuggled", [0, None, []])
def test_add_findings_batch_rejects_a_falsy_non_string_method(tmp_path, smuggled):
    with ProjectDB(tmp_path / "test.db") as db:
        rid = db.start_run(db.create_project("proj"))
        with pytest.raises(CapabilityError):
            db.add_findings_batch(rid, [{"finding_type": "CLIENT_RANDOM",
                                         "method": smuggled}])
        assert _count(db, "findings") == 0


@needs_duckdb
def test_the_empty_string_method_stays_legal(tmp_path):
    """The exemption is for ``""`` alone -- it is the column default and means
    "the writer did not classify this row", which every pre-v3 row holds."""
    with ProjectDB(tmp_path / "test.db") as db:
        rid = db.start_run(db.create_project("proj"))
        assert db.add_finding(rid, "CLIENT_RANDOM", method="") != ""
        assert db._ibis.table("findings").execute() \
                 .to_dict("records")[0]["method"] == ""


# -- C8: the denominator key omitted two of its own columns --------------

@needs_duckdb
def test_expected_identity_separates_library_versions_and_scenarios(tmp_path):
    """``(library, protocol_version, run_number)`` is unique on TODAY's corpus.

    It stops being unique the day a second library build or a second scenario
    per protocol lands -- a silent denominator collapse by a factor of
    #versions x #scenarios (measured: 6 distinct runs folded to 1 row). And
    ``survival`` keys on the full dump path, so it would NOT collapse with it:
    the numerator and the denominator would then count different things.
    """
    with ProjectDB(tmp_path / "test.db") as db:
        rid = db.start_run(db.create_project("proj"))
        base = {"library": "openssl", "protocol_version": "13", "run_number": 0,
                "secret_type": "CLIENT_RANDOM"}
        rows = [
            dict(base, library_version="3.0.2", scenario="server"),
            dict(base, library_version="3.5.0", scenario="server"),
            dict(base, library_version="3.0.2", scenario="client"),
            dict(base, library_version="3.5.0", scenario="client"),
            dict(base, library_version="3.0.2", scenario="mutual_auth"),
            dict(base, library_version="3.5.0", scenario="mutual_auth"),
        ]
        assert db.add_expected_secrets_batch(rid, rows, sweep_id=SWEEP) == 6
        assert _count(db, "expected_secrets") == 6


@needs_duckdb
def test_expected_identity_honours_an_explicit_run_key(tmp_path):
    """A caller with a better corpus-run identity than the axes may pass one,
    and it OVERRIDES them -- two rows whose axes differ but whose ``run_key``
    agrees are the same denominator cell."""
    with ProjectDB(tmp_path / "test.db") as db:
        rid = db.start_run(db.create_project("proj"))
        assert db.add_expected_secrets_batch(rid, [
            {"library": "openssl", "protocol_version": "13", "run_number": 1,
             "secret_type": "CLIENT_RANDOM", "run_key": "/corpus/run_7"},
            {"library": "wolfssl", "protocol_version": "12", "run_number": 9,
             "secret_type": "CLIENT_RANDOM", "run_key": "/corpus/run_7"},
        ], sweep_id=SWEEP) == 2
        assert _count(db, "expected_secrets") == 1


# -- C9: the sweep control plane has a writer API ------------------------

def test_sweep_status_vocabularies_are_pinned():
    """Both are on-disk contracts: a resume decides what to re-run by comparing
    against them, so one typo'd status makes a finished unit look pending."""
    from memdiver.engine.project_db import SWEEP_STATUSES, SWEEP_UNIT_STATUSES

    assert SWEEP_STATUSES == ("pending", "running", "completed", "failed",
                              "cancelled")
    assert SWEEP_UNIT_STATUSES == ("pending", "running", "done", "failed",
                                   "skipped")


@needs_duckdb
def test_start_sweep_records_the_filter_set(tmp_path):
    """The filter set is what stops a five-run CI slice being published as a
    2,600-run full-corpus result: both write the same SHAPE of rows."""
    with ProjectDB(tmp_path / "test.db") as db:
        sid = db.start_sweep(corpus_label="tls_dumps", corpus_id="digest",
                             config_digest="cfg", max_units=5,
                             max_runs_per_library=1,
                             library_filter=["openssl", "wolfssl"],
                             version_filter=["13"], units_planned=5)
        assert len(sid) == 32
        row = db._ibis.table("sweeps").execute().to_dict("records")[0]
        assert row["status"] == "running"
        assert row["max_units"] == 5
        assert row["max_runs_per_library"] == 1
        assert row["library_filter"] == '["openssl", "wolfssl"]'
        assert row["version_filter"] == '["13"]'
        assert row["units_planned"] == 5
        assert row["finished_at"] == ""


@needs_duckdb
def test_sweep_filters_are_json_not_comma_joined(tmp_path):
    """A library or version token containing the separator would otherwise
    re-parse into two filters -- a sweep that covered a different slice than
    the one recorded."""
    import json

    with ProjectDB(tmp_path / "test.db") as db:
        db.start_sweep(sweep_id="sw", library_filter=["open,ssl", "wolfssl"])
        stored = db._ibis.table("sweeps").execute().to_dict("records")[0]
        assert json.loads(stored["library_filter"]) == ["open,ssl", "wolfssl"]


@needs_duckdb
def test_start_sweep_is_idempotent_and_keeps_created_at(tmp_path):
    """A resume re-declares its sweep on startup; that must refresh the plan,
    not mint a second sweep."""
    with ProjectDB(tmp_path / "test.db") as db:
        db.start_sweep(sweep_id="sw", units_planned=5, status="pending")
        created = db._ibis.table("sweeps").execute() \
                    .to_dict("records")[0]["created_at"]
        db.start_sweep(sweep_id="sw", units_planned=2600, status="running")
        rows = db._ibis.table("sweeps").execute().to_dict("records")
        assert len(rows) == 1
        assert rows[0]["units_planned"] == 2600
        assert rows[0]["status"] == "running"
        assert rows[0]["created_at"] == created


@needs_duckdb
def test_sweep_unit_moves_through_its_states_in_place(tmp_path):
    """The documented exception to append-only: a unit row is UPDATEd as it
    moves pending -> running -> done, which is the whole point of a watermark.
    Appending a row per transition would make "how far did this sweep get" a
    max() over history instead of a lookup."""
    with ProjectDB(tmp_path / "test.db") as db:
        sid = db.start_sweep(sweep_id="sw", units_planned=1)
        uid = db.record_sweep_unit_start(
            sid, "openssl/13/run_1/pre_abort",
            inputs_digest="deadbeef", digest_level="size", attempt=1)
        running = db._ibis.table("sweep_units").execute().to_dict("records")[0]
        assert running["status"] == "running"
        assert running["inputs_digest"] == "deadbeef"
        assert running["digest_level"] == "size"
        assert running["attempt"] == 1
        assert running["finished_at"] == ""

        assert db.record_sweep_unit_done(
            sid, "openssl/13/run_1/pre_abort",
            result_offset=4096, result_bytes=512) == uid
        rows = db._ibis.table("sweep_units").execute().to_dict("records")
        assert len(rows) == 1, "a transition must UPDATE, not append"
        assert rows[0]["status"] == "done"
        assert rows[0]["result_offset"] == 4096
        assert rows[0]["result_bytes"] == 512
        # start_at / attempt survive the close, so the finished attempt's
        # duration and retry count stay readable.
        assert rows[0]["started_at"] == running["started_at"]
        assert rows[0]["attempt"] == 1
        assert rows[0]["finished_at"] != ""


@needs_duckdb
def test_a_retry_does_not_erase_the_previous_watermark(tmp_path):
    """A retry that crashes before producing a watermark must not wipe the
    one the previous attempt wrote."""
    with ProjectDB(tmp_path / "test.db") as db:
        sid = db.start_sweep(sweep_id="sw")
        db.record_sweep_unit_start(sid, "u1", attempt=1)
        db.record_sweep_unit_done(sid, "u1", result_offset=10, result_bytes=20)
        db.record_sweep_unit_start(sid, "u1", attempt=2)
        row = db._ibis.table("sweep_units").execute().to_dict("records")[0]
        assert row["status"] == "running"
        assert row["attempt"] == 2
        assert (row["result_offset"], row["result_bytes"]) == (10, 20)


@needs_duckdb
def test_record_sweep_unit_done_works_without_a_prior_start(tmp_path):
    """A driver that crashed between claiming a unit and finishing it can still
    record the outcome."""
    with ProjectDB(tmp_path / "test.db") as db:
        sid = db.start_sweep(sweep_id="sw")
        db.record_sweep_unit_done(sid, "u1", status="failed")
        row = db._ibis.table("sweep_units").execute().to_dict("records")[0]
        assert row["status"] == "failed"


@needs_duckdb
def test_finish_sweep_closes_the_row(tmp_path):
    """A sweep left in ``running`` forever is indistinguishable from one still
    in flight, and its partial ledger reads as a finished one."""
    with ProjectDB(tmp_path / "test.db") as db:
        sid = db.start_sweep(sweep_id="sw")
        db.finish_sweep(sid, status="cancelled")
        row = db._ibis.table("sweeps").execute().to_dict("records")[0]
        assert row["status"] == "cancelled"
        assert row["finished_at"] != ""


@needs_duckdb
def test_sweep_writers_reject_out_of_vocabulary_statuses(tmp_path):
    with ProjectDB(tmp_path / "test.db") as db:
        sid = db.start_sweep(sweep_id="sw")
        for call in (lambda: db.start_sweep(sweep_id="x", status="finished"),
                     lambda: db.finish_sweep(sid, status="done"),
                     lambda: db.record_sweep_unit_start(sid, "u", status="ok"),
                     lambda: db.record_sweep_unit_done(sid, "u", status="completed")):
            with pytest.raises(CapabilityError) as excinfo:
                call()
            assert excinfo.value.category is ErrorCategory.INVALID_INPUT


@needs_duckdb
def test_sweep_unit_writers_reject_empty_keys(tmp_path):
    """Empty unit keys all collapse onto a single watermark row per sweep."""

    with ProjectDB(tmp_path / "test.db") as db:
        sid = db.start_sweep(sweep_id="sw")
        with pytest.raises(CapabilityError):
            db.record_sweep_unit_start(sid, "")
        with pytest.raises(CapabilityError):
            db.record_sweep_unit_done("", "u1")


def test_sweep_writers_degrade_without_duckdb(tmp_path):
    """Every writer no-ops on an unopened DB, like the rest of the class."""
    from memdiver.engine.project_db import ProjectDB as PDB

    db = PDB(tmp_path / "noop.db")  # never opened
    assert db.start_sweep(sweep_id="sw") == ""
    assert db.record_sweep_unit_start("sw", "u") == ""
    assert db.record_sweep_unit_done("sw", "u") == ""
    assert db.finish_sweep("sw") is None
    assert db.degraded_indexes() == ()


# -- C10: "|" is not a safe separator for path components ----------------

def test_row_identity_is_injective_over_separator_containing_parts():
    """``"|".join`` is not injective once a component can contain ``"|"`` --
    and these components are dump paths and library names, which can.
    ``("a", "b|c", "t")`` and ``("a|b", "c", "t")`` hashed to the SAME id, so
    two genuinely different cells silently became one row."""
    from memdiver.engine.project_db import _row_identity

    assert _row_identity("a", "b|c", "t") != _row_identity("a|b", "c", "t")
    assert _row_identity("a", "b\x00c") != _row_identity("a\x00b", "c")
    assert _row_identity("", "ab") != _row_identity("a", "b")
    # ...and it is still deterministic.
    assert _row_identity("a", "b") == _row_identity("a", "b")
    assert len(_row_identity("a", "b")) == 32


# -- C11: the branches nothing exercised ---------------------------------

@needs_duckdb
def test_unit_key_overrides_the_cell_key_of_the_primary_key(tmp_path):
    """``cell_key = unit_key or dump_path or dump_id`` -- the first branch had
    no test, so a change that dropped it would not have been caught."""
    ids = {}
    for name, extra in (("with.db", {"unit_key": "openssl/13/run_3/pre_abort"}),
                        ("without.db", {})):
        with ProjectDB(tmp_path / name) as db:
            rid = db.start_run(db.create_project("proj"))
            db.add_survival_batch(rid, [_survival_row(**extra)], sweep_id=SWEEP)
            ids[name] = db._ibis.table("survival").execute() \
                          .to_dict("records")[0]["survival_id"]
    assert ids["with.db"] != ids["without.db"]


@needs_duckdb
def test_two_unit_keys_resolving_to_one_dump_stay_one_row(tmp_path):
    """The SECONDARY-index conflict path: this is the direction the PK cannot
    catch, and it is what a re-run with a changed unit-key scheme looks like."""
    with ProjectDB(tmp_path / "test.db") as db:
        rid = db.start_run(db.create_project("proj"))
        db.add_survival_batch(
            rid, [_survival_row(unit_key="old-scheme/run3/pre", present=False)],
            sweep_id=SWEEP)
        db.add_survival_batch(
            rid, [_survival_row(unit_key="new-scheme/openssl/13/run_3/pre",
                                present=True, hit_count=2)],
            sweep_id=SWEEP)
        rows = db._ibis.table("survival").execute().to_dict("records")
        assert len(rows) == 1, "same dump + same secret is ONE cell"
        # The later observation wins, and the row keeps its original id.
        assert rows[0]["present"] is True
        assert rows[0]["hit_count"] == 2


def test_msl_hashing_falls_back_to_sha256_without_blake3():
    """``_row_identity`` is built on ``msl.hashing.hash_bytes``, which prefers
    blake3 and falls back to sha256. The fallback is what every ledger id
    depends on in an environment without blake3, so it must be exercised: an
    untested fallback that quietly hashed something else would make the SAME
    cell resolve to DIFFERENT ids on two machines, and the ``ON CONFLICT``
    dedup would stop working across them.
    """
    import builtins
    import hashlib
    import importlib

    import memdiver.msl.hashing as hashing

    real_import = builtins.__import__

    def no_blake3(name, *args, **kwargs):
        if name == "blake3":
            raise ImportError("blake3 disabled for this test")
        return real_import(name, *args, **kwargs)

    try:
        with patch.object(builtins, "__import__", no_blake3):
            fallback = importlib.reload(hashing)
            assert fallback.hash_bytes(b"abc") == hashlib.sha256(b"abc").digest()
            assert fallback.hash_stream([b"a", b"", b"bc"]) == \
                hashlib.sha256(b"abc").digest()
    finally:
        importlib.reload(hashing)   # restore the real (blake3) module

    # And the id derived from it is a 32-hex prefix either way, so the column
    # width is not environment-dependent even though the digest is.
    assert len(hashing.hash_bytes(b"abc").hex()[:32]) == 32
