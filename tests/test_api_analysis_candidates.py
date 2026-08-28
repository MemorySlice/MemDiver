"""The exploratory candidate path (A4) — ``analysis.candidates`` on four surfaces.

The capability under test answers the question the rest of the pipeline could
not: *I have N dumps of one process, I do not know whether there is a key or
where — show me what to look at.* Every other route to a candidate list either
starts from a precomputed ``variance.npy`` or hard-refuses without an oracle or
a capture (``POST /api/pipeline/run``), so before this producer existed the web
UI could not reach a candidate list at all.

What these tests pin, in order:

* the capability is wired on all four surfaces and is NOT a documented gap;
* the HTTP route returns ranked regions INLINE with no oracle and no pcap;
* the error contract — N < 2 is PRECONDITION (matching the three sibling
  producers that make the same check), a bad enum is INVALID_INPUT, a missing dump
  is NOT_FOUND — reaches the transport as 400 / 404 through the app's single
  global ``CapabilityError`` handler, with no ``try/except`` in the route;
* an all-invariant input is a legitimate EMPTY answer plus a diagnostic naming
  the gate that emptied it, never an error;
* an absent project database degrades to "not saved" and says so;
* a persisted ``consensus_id`` round-trips, and a re-run corrects its rows
  rather than duplicating them;
* and, on the real corpus, the ranked list contains the run's real TLS 1.2
  master secret byte-exactly, with no keylog supplied.
"""

from __future__ import annotations

import sys
from pathlib import Path

import numpy as np
import pytest
from fastapi.testclient import TestClient

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from memdiver.api.config import get_settings  # noqa: E402
from memdiver.api.main import create_app  # noqa: E402
from memdiver.app.tools_pipeline import (  # noqa: E402
    CANDIDATES_EMPTY_CODE,
    CANDIDATES_NOT_PERSISTED_CODE,
    analyze_candidates,
)
from memdiver.core.service_errors import CapabilityError, ErrorCategory  # noqa: E402

#: All three non-invariant bands. The default query for a blind analyst, and
#: the only one that returns real key material as ONE region: a measured
#: 48-byte TLS 1.2 secret is 22 KEY_CANDIDATE + 18 POINTER + 8 STRUCTURAL, so a
#: KEY_CANDIDATE-only query returns fragments from inside it instead.
NON_INVARIANT = ["structural", "pointer", "key_candidate"]


@pytest.fixture(autouse=True)
def isolated_project_db(tmp_path, monkeypatch):
    """Point ``memdiver_home()`` at a temp dir for every test in this module.

    The producer PERSISTS by design, so without this each run would write
    consensus/candidate rows into the developer's real ``~/.memdiver``
    database — and the re-run test below, which counts rows, would then be
    counting a shared file.
    """
    monkeypatch.setenv("XDG_DATA_HOME", str(tmp_path / "xdg"))


@pytest.fixture
def planted_dumps(tmp_path):
    """Four equal-sized dumps sharing a low-entropy background plus one
    48-byte window that is different in every dump — a synthetic stand-in for
    the real key region the corpus test below finds for real."""
    rng = np.random.default_rng(11)
    background = rng.integers(0, 4, 8192, dtype=np.uint8)
    paths = []
    for i in range(4):
        body = background.copy()
        body[2048:2096] = rng.integers(0, 256, 48, dtype=np.uint8)
        p = tmp_path / f"phase_{i}.dump"
        p.write_bytes(body.tobytes())
        paths.append(str(p))
    return paths


@pytest.fixture
def multi_window_dumps(tmp_path):
    """Four dumps carrying FIVE separated varying windows, so the reduction
    yields more regions than the cap under test keeps."""
    rng = np.random.default_rng(23)
    background = rng.integers(0, 4, 8192, dtype=np.uint8)
    paths = []
    for i in range(4):
        body = background.copy()
        for window, length in enumerate((48, 32, 64, 24, 40)):
            start = 1024 + window * 1024
            body[start:start + length] = rng.integers(
                0, 256, length, dtype=np.uint8)
        p = tmp_path / f"multi_{i}.dump"
        p.write_bytes(body.tobytes())
        paths.append(str(p))
    return paths


@pytest.fixture
def invariant_dumps(tmp_path):
    """Three byte-identical dumps: every byte position is INVARIANT."""
    paths = []
    for i in range(3):
        p = tmp_path / f"same_{i}.dump"
        p.write_bytes(bytes(4096))
        paths.append(str(p))
    return paths


@pytest.fixture
def client(tmp_path, monkeypatch):
    """A TestClient over the real app, with the task substrate in tmp_path.

    Mirrors the fixture in ``tests/test_api_analysis.py`` so the lifespan +
    TaskManager are exercised exactly as they are for the sibling routes.
    """
    monkeypatch.setenv("MEMDIVER_ORACLE_DIR", str(tmp_path / "oracles"))
    monkeypatch.setenv("MEMDIVER_TASK_ROOT", str(tmp_path / "tasks"))
    monkeypatch.setenv("MEMDIVER_PIPELINE_MAX_WORKERS", "1")
    get_settings.cache_clear()
    with TestClient(create_app()) as c:
        yield c
    get_settings.cache_clear()


# ---------------------------------------------------------------------------
# (a) four-surface parity
# ---------------------------------------------------------------------------


def test_capability_is_wired_on_all_four_surfaces():
    """``analysis.candidates`` claims every in-scope surface and is not a
    documented gap — the ratchet in ``test_architecture_invariants`` then holds
    that claim honest for every future change."""
    from memdiver.app.capabilities import (
        CAPABILITIES,
        IN_SCOPE_SURFACES,
        KNOWN_PARITY_GAPS,
    )

    cap = next(c for c in CAPABILITIES if c.name == "analysis.candidates")
    assert cap.producer == "memdiver.app.tools_pipeline.analyze_candidates"
    assert IN_SCOPE_SURFACES - cap.surfaces == set()
    assert not any(name == "analysis.candidates" for name, _ in KNOWN_PARITY_GAPS)


def test_mcp_tool_returns_the_regions_not_a_file_path(planted_dumps):
    """The MCP surface is the reason the regions come back inline: an agent
    handed a ``candidates_path`` has no way to read it back."""
    import json

    pytest.importorskip("mcp")
    from memdiver.mcp_server.server import create_server

    tools = {t.name: t for t in create_server()._tool_manager.list_tools()}
    assert "analyze_candidates" in tools

    payload = json.loads(tools["analyze_candidates"].fn(
        dump_paths=planted_dumps, classes=NON_INVARIANT, min_region=8))
    assert payload["regions"], payload["diagnostics"]
    assert all("offset" in r and "rank" in r for r in payload["regions"])
    assert not any(key.endswith("_path") for key in payload)


# ---------------------------------------------------------------------------
# (b) the route: a ranked list with no oracle and no capture
# ---------------------------------------------------------------------------


def test_route_returns_ranked_regions_without_an_oracle(client, planted_dumps):
    resp = client.post("/api/analysis/candidates", json={
        "dump_paths": planted_dumps,
        "classes": NON_INVARIANT,
        "min_region": 8,
    })
    assert resp.status_code == 200, resp.text
    body = resp.json()

    assert body["num_dumps"] == 4
    assert body["num_regions"] == body["regions_returned"] >= 1
    assert body["regions_truncated"] is False
    assert body["order"] == "rank"
    assert [r["rank"] for r in body["regions"]] == list(
        range(1, len(body["regions"]) + 1))
    # The planted window is the top-ranked region.
    assert (body["regions"][0]["offset"], body["regions"][0]["length"]) == (2048, 48)
    # Provenance + the resolved floor travel with the result.
    assert body["alignment"]["method"] == "file_offset"
    assert body["thresholds"]["min_variance"] == 0.0
    assert body["thresholds"]["classes"] == NON_INVARIANT
    assert set(body["class_counts"]) <= {
        "invariant", "structural", "pointer", "key_candidate"}


def test_route_caps_the_inline_list_to_the_best_ranked_rows(
    client, multi_window_dumps
):
    resp = client.post("/api/analysis/candidates", json={
        "dump_paths": multi_window_dumps, "classes": NON_INVARIANT,
        "min_region": 8,
        "max_returned": 2,
    })
    body = resp.json()
    assert body["num_regions"] > 2, body
    assert body["regions_returned"] == 2
    assert body["regions_truncated"] is True
    assert {r["rank"] for r in body["regions"]} == {1, 2}


# ---------------------------------------------------------------------------
# (c) the error contract, at the producer and at the transport
# ---------------------------------------------------------------------------


def test_fewer_than_two_dumps_is_a_precondition_failure(planted_dumps, client):
    with pytest.raises(CapabilityError) as excinfo:
        analyze_candidates(dump_paths=planted_dumps[:1])
    # PRECONDITION, matching `consensus` and the two n-sweep producers, which
    # make the identical check. Both categories map to HTTP 400.
    assert excinfo.value.category is ErrorCategory.PRECONDITION
    assert "at least 2" in excinfo.value.message

    resp = client.post("/api/analysis/candidates",
                       json={"dump_paths": planted_dumps[:1]})
    assert resp.status_code == 400, resp.text


def test_a_missing_dump_path_is_not_found(planted_dumps, client, tmp_path):
    absent = str(tmp_path / "nope.dump")
    with pytest.raises(CapabilityError) as excinfo:
        analyze_candidates(dump_paths=[planted_dumps[0], absent])
    assert excinfo.value.category is ErrorCategory.NOT_FOUND
    assert absent in excinfo.value.message

    resp = client.post("/api/analysis/candidates",
                       json={"dump_paths": [planted_dumps[0], absent]})
    assert resp.status_code == 404, resp.text


def test_an_unknown_class_name_is_invalid_input(planted_dumps, client):
    with pytest.raises(CapabilityError) as excinfo:
        analyze_candidates(dump_paths=planted_dumps, classes=["key_candidat"])
    assert excinfo.value.category is ErrorCategory.INVALID_INPUT

    resp = client.post("/api/analysis/candidates", json={
        "dump_paths": planted_dumps, "classes": ["key_candidat"]})
    assert resp.status_code == 400, resp.text


def test_an_unknown_order_is_invalid_input(planted_dumps, client):
    with pytest.raises(CapabilityError) as excinfo:
        analyze_candidates(dump_paths=planted_dumps, order="score")
    assert excinfo.value.category is ErrorCategory.INVALID_INPUT

    resp = client.post("/api/analysis/candidates", json={
        "dump_paths": planted_dumps, "order": "score"})
    assert resp.status_code == 400, resp.text


# ---------------------------------------------------------------------------
# (d) an empty result is an answer, not a failure
# ---------------------------------------------------------------------------


def test_all_invariant_input_returns_zeros_and_a_diagnostic(invariant_dumps, client):
    """Three byte-identical dumps have nothing to differ about. The honest
    answer is zero regions plus a note saying WHY — 0 regions on its own reads
    exactly like a broken filter chain, which is the bug this item exists to
    fix."""
    result = analyze_candidates(dump_paths=invariant_dumps, classes=NON_INVARIANT)

    assert result["num_regions"] == 0
    assert result["regions"] == []
    assert result["class_counts"].get("invariant") == result["size"] == 4096
    codes = [d["code"] for d in result["diagnostics"]]
    assert CANDIDATES_EMPTY_CODE in codes
    empty = next(d for d in result["diagnostics"]
                 if d["code"] == CANDIDATES_EMPTY_CODE)
    assert "class" in empty["message"]
    assert empty["details"]["stages"]["byte_class"] == 0

    resp = client.post("/api/analysis/candidates", json={
        "dump_paths": invariant_dumps, "classes": NON_INVARIANT})
    assert resp.status_code == 200, resp.text
    assert resp.json()["num_regions"] == 0


# ---------------------------------------------------------------------------
# (e) persistence: best-effort, addressable, and re-run safe
# ---------------------------------------------------------------------------


def test_degrades_without_a_project_database(planted_dumps, monkeypatch):
    """``resolve_project_db()`` returning ``None`` is a valid environment (the
    DuckDB/Ibis stack is optional). The analysis must still land, and the
    result must SAY it was not saved rather than implying it was."""
    from memdiver.app import composition

    monkeypatch.setattr(composition, "resolve_project_db", lambda *a, **k: None)
    result = analyze_candidates(
        dump_paths=planted_dumps, classes=NON_INVARIANT, min_region=8)

    assert result["num_regions"] >= 1
    assert result["consensus_id"] == ""
    assert result["persisted"] is False
    assert result["candidates_persisted"] == 0
    not_saved = next(d for d in result["diagnostics"]
                     if d["code"] == CANDIDATES_NOT_PERSISTED_CODE)
    assert not_saved["details"]["reason"] == "project_db_unavailable"
    assert "not saved" in not_saved["message"]


def _project_db_or_skip():
    from memdiver.app.composition import resolve_project_db

    db = resolve_project_db()
    if db is None:
        pytest.skip("project database unavailable in this environment")
    return db


def test_persisted_consensus_id_round_trips(planted_dumps):
    result = analyze_candidates(
        dump_paths=planted_dumps, classes=NON_INVARIANT, min_region=8)
    assert result["persisted"] is True
    assert result["candidates_persisted"] == result["num_regions"]

    db = _project_db_or_skip()
    try:
        runs = db.consensus_runs(consensus_id=result["consensus_id"])
        assert len(runs) == 1
        assert runs[0]["n_dumps"] == 4
        assert runs[0]["alignment_method"] == "file_offset"

        rows = db.candidate_regions(result["consensus_id"])
        assert len(rows) == result["num_regions"]
        assert rows[0]["rank"] == 1
        assert rows[0]["byte_class"] == "key_candidate"
        top = result["regions"][0]
        assert (rows[0]["offset"], rows[0]["length"]) == (top["offset"], top["length"])
    finally:
        db.close()


def test_a_rerun_corrects_rather_than_duplicates(planted_dumps):
    """``consensus_id`` is derived from the comparison's identity, so running
    the same dump set twice must leave ONE run row and ONE row per region."""
    first = analyze_candidates(
        dump_paths=planted_dumps, classes=NON_INVARIANT, min_region=8)
    second = analyze_candidates(
        dump_paths=planted_dumps, classes=NON_INVARIANT, min_region=8)
    assert second["consensus_id"] == first["consensus_id"]

    db = _project_db_or_skip()
    try:
        assert len(db.consensus_runs(consensus_id=first["consensus_id"])) == 1
        rows = db.candidate_regions(first["consensus_id"])
        assert len(rows) == first["num_regions"]
        assert len({(r["offset"], r["length"]) for r in rows}) == len(rows)
    finally:
        db.close()


# ---------------------------------------------------------------------------
# (f) the real corpus — the load-bearing acceptance assertion
# ---------------------------------------------------------------------------

#: The run this assertion is anchored to: eight 11,223,040-byte dumps of one
#: OpenSSL TLS 1.2 session whose ``keylog.csv`` puts a 48-byte CLIENT_RANDOM
#: master secret at offset 370,672 in every one of them.
_TLS12_RUN = "TLS12/100_iterations_Abort/openssl/openssl_run_12_1"
_TLS12_KEY_OFFSET = 370_672
_TLS12_KEY_LENGTH = 48
#: The histogram of that comparison, byte for byte as measured. 6,129
#: non-invariant bytes out of 11.2 MB — a 1,831x reduction.
_TLS12_HISTOGRAM = {
    "invariant": 11_216_911, "structural": 1_652,
    "pointer": 2_566, "key_candidate": 1_911,
}


@pytest.mark.requires_dataset
def test_real_tls12_key_is_in_the_ranked_list_without_a_keylog(capsys):
    """Eight phases of a real OpenSSL TLS 1.2 run go in through the PRODUCER,
    and the ranked list contains the run's real master secret — byte-exact,
    with no keylog, oracle or capture supplied anywhere.

    ``requires_dataset`` but deliberately NOT ``slow``: ``slow`` is deselected
    by the default addopts, so marking it would evict the one assertion that
    proves the exploratory path works on real memory from ``make test`` — the
    only command a developer holding the corpus actually runs.
    """
    import csv

    from tests.fixtures.tls_ground_truth import tls_dumps_dir

    run_dir = Path(tls_dumps_dir()) / _TLS12_RUN
    dumps = sorted(run_dir.glob("*.dump"))
    if len(dumps) != 8:
        pytest.skip(f"TLS 1.2 reference run not present under {run_dir}")

    # Ground truth, read for the ASSERTION only — the producer below is handed
    # the dump paths and nothing else, which is the whole point.
    with open(run_dir / "keylog.csv", newline="") as handle:
        secret = next(
            bytes.fromhex(row["line"].split()[2])
            for row in csv.DictReader(handle)
            if row["line"].split()[:1] == ["CLIENT_RANDOM"]
        )
    assert len(secret) == _TLS12_KEY_LENGTH

    result = analyze_candidates(
        dump_paths=[str(p) for p in dumps],
        classes=NON_INVARIANT,
        min_region=8,
        order="rank",
    )

    assert result["num_dumps"] == 8
    assert result["size"] == 11_223_040
    assert result["class_counts"] == _TLS12_HISTOGRAM
    assert result["alignment"] == {
        "method": "file_offset",
        "bytes_compared": 11_223_040,
        "bytes_discarded": 0,
        "sizes_differed": False,
        "n_sources": 8,
        "warnings": [],
    }
    assert result["warnings"] == []
    assert result["num_regions"] == 25

    hits = [r for r in result["regions"]
            if r["offset"] <= _TLS12_KEY_OFFSET < r["offset"] + r["length"]]
    assert hits, (
        f"the real key at {_TLS12_KEY_OFFSET} is in none of "
        f"{result['num_regions']} candidate regions"
    )
    key_region = hits[0]
    # Byte-exact on both ends: the region IS the key, not a run overlapping it.
    assert (key_region["offset"], key_region["length"]) == (
        _TLS12_KEY_OFFSET, _TLS12_KEY_LENGTH)
    assert dumps[0].read_bytes()[
        _TLS12_KEY_OFFSET:_TLS12_KEY_OFFSET + _TLS12_KEY_LENGTH] == secret
    assert key_region["class_counts"] == {
        "invariant": 0, "structural": 8, "pointer": 18, "key_candidate": 22,
    }

    top_half = (result["num_regions"] + 1) // 2
    with capsys.disabled():
        print(
            f"\nreal TLS 1.2 master secret at {_TLS12_KEY_OFFSET}: rank "
            f"{key_region['rank']} of {result['num_regions']} "
            f"(score {key_region['score']:.4f}); "
            f"{sum(_TLS12_HISTOGRAM.values()) - _TLS12_HISTOGRAM['invariant']:,}"
            f" non-invariant bytes of {result['size']:,}"
        )
    assert key_region["rank"] <= top_half, (
        f"the real key ranked {key_region['rank']} of {result['num_regions']}; "
        f"the score has stopped surfacing it on the first page"
    )


def test_an_unreachable_entropy_threshold_is_invalid_input(planted_dumps, client):
    """No 32-byte window can reach 10 bits/byte. That is a bad argument, not a
    server fault — the route must answer 400, never 500."""
    with pytest.raises(CapabilityError) as excinfo:
        analyze_candidates(dump_paths=planted_dumps,
                           entropy_window=32, entropy_threshold=10.0)
    assert excinfo.value.category is ErrorCategory.INVALID_INPUT

    resp = client.post("/api/analysis/candidates", json={
        "dump_paths": planted_dumps,
        "entropy_window": 32, "entropy_threshold": 10.0})
    assert resp.status_code == 400, resp.text


def test_two_dumps_fall_back_to_entropy_only_and_say_so(planted_dumps):
    """At N=2 the cross-dump variance is not trustworthy, so the reduction
    declines to classify. The regions still come back ranked; they are NOT
    persisted, because ``candidate_regions.byte_class`` is required and there
    is no honest value for a region the pipeline refused to classify."""
    from memdiver.app.tools_pipeline import CANDIDATES_UNCLASSIFIED_CODE

    result = analyze_candidates(dump_paths=planted_dumps[:2], min_region=8)

    assert result["fallback_entropy_only"] is True
    assert result["num_regions"] >= 1
    assert all(r["class_counts"] == {} for r in result["regions"])
    note = next(d for d in result["diagnostics"]
                if d["code"] == CANDIDATES_UNCLASSIFIED_CODE)
    assert note["details"]["num_dumps"] == 2
    # The comparison itself is still recorded; only the unclassifiable
    # candidates are held back.
    assert result["persisted"] is True
    assert result["candidates_persisted"] == 0
