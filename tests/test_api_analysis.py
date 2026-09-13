"""End-to-end tests for ``api.routers.analysis`` — focused on the
Phase B ``POST /api/analysis/batch`` endpoint.

Uses the same TestClient(create_app()) pattern as
``tests/test_api_pipeline.py`` so the lifespan + TaskManager
ProcessPool substrate is exercised by these tests too.
"""

from __future__ import annotations

import time
from pathlib import Path
from typing import Dict

import pytest
from fastapi.testclient import TestClient

from memdiver.api.config import get_settings
from memdiver.api.main import create_app


@pytest.fixture
def tmp_env(tmp_path: Path, monkeypatch):
    """Isolate oracle dir + task root into tmp_path so the test never
    touches the real ``~/.memdiver`` paths.

    Mirrors the fixture in ``tests/test_api_pipeline.py``.
    """
    oracle_dir = tmp_path / "oracles"
    task_root = tmp_path / "tasks"
    oracle_dir.mkdir()
    task_root.mkdir()
    monkeypatch.setenv("MEMDIVER_ORACLE_DIR", str(oracle_dir))
    monkeypatch.setenv("MEMDIVER_TASK_ROOT", str(task_root))
    monkeypatch.setenv("MEMDIVER_TASK_QUOTA_BYTES", "10485760")  # 10 MiB
    monkeypatch.setenv("MEMDIVER_PIPELINE_MAX_WORKERS", "1")
    get_settings.cache_clear()
    yield tmp_path
    get_settings.cache_clear()


@pytest.fixture
def client(tmp_env):
    app = create_app()
    with TestClient(app) as c:
        yield c


@pytest.fixture
def fixture_library_dir() -> str:
    """Return an absolute path to one of the synthetic fixture libraries.

    ``tests/conftest.py`` calls ``generate_dataset()`` at session start,
    so the path is always materialised before tests run. We use a
    library directory that contains a single run subdir so the batch
    job's AnalyzeRequest validation (library_dirs must be a real
    directory) succeeds inside the worker.
    """
    here = Path(__file__).parent
    lib = here / "fixtures" / "dataset" / "TLS12" / "scenario_a" / "openssl"
    assert lib.is_dir(), f"fixture missing: {lib}"
    return str(lib)


def _wait_terminal(client: TestClient, task_id: str, timeout: float = 30.0) -> Dict:
    """Poll ``/api/pipeline/runs/{id}`` until the task lands in a
    terminal state. (Pipeline + analysis endpoints share the
    TaskManager so the read-side path is the same.)"""
    deadline = time.time() + timeout
    while time.time() < deadline:
        r = client.get(f"/api/pipeline/runs/{task_id}")
        assert r.status_code == 200
        rec = r.json()
        if rec["status"] in ("succeeded", "failed", "cancelled"):
            return rec
        time.sleep(0.1)
    raise AssertionError(f"task {task_id} never reached terminal state")


# ------------------------------------------------------------------
# happy path
# ------------------------------------------------------------------


def test_batch_happy_path(client, fixture_library_dir):
    """POST a minimal one-job batch and confirm task_id + early status.

    We do not wait for completion here — running a real
    ``analyze_library`` against a fixture is heavy, and the early
    contract we care about is "submit returns 200 with a task_id and
    a non-terminal status". A separate slow test could be added later
    to assert the artifact lands.
    """
    payload = {
        "jobs": [
            {
                "library_dirs": [fixture_library_dir],
                "phase": "pre_handshake",
                "protocol_version": "12",
                "max_runs": 1,
            },
        ],
        "output_format": "json",
        "workers": 1,
    }
    r = client.post("/api/analysis/batch", json=payload)
    assert r.status_code == 200, r.text
    body = r.json()
    assert isinstance(body["task_id"], str) and body["task_id"]
    # TaskManager submits asynchronously, so the early status is one
    # of pending/running. (Succeeded is theoretically possible too if
    # the inner job somehow finishes before this assertion runs, but
    # in practice the spawn-context startup latency makes that race
    # vanishingly rare.)
    assert body["status"] in {"pending", "running", "succeeded", "failed"}

    # Best-effort: cancel so we don't leave the worker running long
    # enough to fight other tests for the ProcessPool slot.
    client.delete(f"/api/pipeline/runs/{body['task_id']}")


# ------------------------------------------------------------------
# validation errors
# ------------------------------------------------------------------


def test_batch_validation_empty_jobs(client):
    """Empty jobs list must be rejected by Pydantic with 422."""
    r = client.post(
        "/api/analysis/batch",
        json={"jobs": [], "output_format": "json", "workers": 1},
    )
    assert r.status_code == 422


def test_batch_validation_missing_required_field(client, fixture_library_dir):
    """A job missing ``protocol_version`` must trigger 422 (Pydantic)."""
    r = client.post(
        "/api/analysis/batch",
        json={
            "jobs": [
                {
                    "library_dirs": [fixture_library_dir],
                    "phase": "pre_handshake",
                    # protocol_version intentionally omitted
                },
            ],
        },
    )
    assert r.status_code == 422


def test_batch_validation_bad_workers(client, fixture_library_dir):
    """``workers`` outside 1..32 must be rejected by Pydantic."""
    r = client.post(
        "/api/analysis/batch",
        json={
            "jobs": [
                {
                    "library_dirs": [fixture_library_dir],
                    "phase": "pre_handshake",
                    "protocol_version": "12",
                },
            ],
            "workers": 0,
        },
    )
    assert r.status_code == 422


def test_batch_validation_bad_output_format(client, fixture_library_dir):
    """An unknown ``output_format`` must be rejected synchronously at the wire
    (422) rather than deferred to an async worker failure. Guards the shared
    ``OUTPUT_FORMATS`` validation between api.models and core.input_schemas."""
    r = client.post(
        "/api/analysis/batch",
        json={
            "jobs": [
                {
                    "library_dirs": [fixture_library_dir],
                    "phase": "pre_handshake",
                    "protocol_version": "12",
                },
            ],
            "output_format": "xml",
        },
    )
    assert r.status_code == 422


# ------------------------------------------------------------------
# verify-key: malformed hex must be a clean 400, not an unhandled 500
# ------------------------------------------------------------------


@pytest.mark.parametrize(
    "ciphertext_hex, iv_hex",
    [
        ("zz", None),          # non-hex chars
        ("abc", None),         # odd length
        ("00", "zz"),          # malformed iv
        ("00", "abc"),         # odd-length iv
    ],
)
def test_verify_key_malformed_hex_returns_400(client, tmp_path, ciphertext_hex, iv_hex):
    """``bytes.fromhex`` on attacker-controlled ciphertext_hex/iv_hex must
    surface as a 400, never as an unhandled 500 leaking internals."""
    dump = tmp_path / "tiny.bin"
    dump.write_bytes(b"\x00" * 64)
    payload = {
        "dump_path": str(dump),
        "offset": 0,
        "length": 32,
        "ciphertext_hex": ciphertext_hex,
        "cipher": "AES-256-CBC",
    }
    if iv_hex is not None:
        payload["iv_hex"] = iv_hex
    r = client.post("/api/analysis/verify-key", json=payload)
    assert r.status_code == 400, r.text
    assert "hex" in r.json()["detail"].lower()


def test_batch_validation_empty_library_dirs(client):
    """A job with an empty ``library_dirs`` list must be rejected at the
    Pydantic layer (DTO declares ``min_length=1``)."""
    r = client.post(
        "/api/analysis/batch",
        json={
            "jobs": [
                {
                    "library_dirs": [],
                    "phase": "pre_handshake",
                    "protocol_version": "12",
                },
            ],
        },
    )
    assert r.status_code == 422


# ---------------------------------------------------------------------------
# Missing dump paths are 404s, not 500s with an ASGI traceback.
#
# Regression for the import bug: the import endpoint handed the client a
# server-side path that no longer existed, and every consensus call on it
# escaped as a bare FileNotFoundError. Because that is not a CapabilityError it
# bypassed the global error funnel entirely — 500 + full traceback, retried on
# every scroll tick. ``raise_server_exceptions=False`` so a regression shows up
# here as a 500 response rather than an exception.
# ---------------------------------------------------------------------------


@pytest.fixture
def strict_client(tmp_env):
    app = create_app()
    with TestClient(app, raise_server_exceptions=False) as c:
        yield c


def test_run_consensus_missing_dump_is_404(strict_client, tmp_path):
    missing = [str(tmp_path / "gone_a.msl"), str(tmp_path / "gone_b.msl")]
    resp = strict_client.post(
        "/api/analysis/consensus", json={"dump_paths": missing}
    )
    assert resp.status_code == 404, resp.text
    assert "gone_a.msl" in resp.text


def test_consensus_aligned_window_missing_dump_is_404(strict_client, tmp_path):
    """The exact call the hex viewer makes for every visible chunk."""
    missing = [str(tmp_path / "gone_a.msl"), str(tmp_path / "gone_b.msl")]
    resp = strict_client.post(
        "/api/analysis/consensus/aligned-window",
        json={
            "dump_paths": missing,
            "anchor": "dump",
            "anchor_path": missing[0],
            "view": "raw",
            "offset": 0,
            "length": 4096,
            "dumps": missing,
            "include_bytes": True,
            "classify": True,
        },
    )
    assert resp.status_code == 404, resp.text
    body = resp.json()
    # The funnel envelope from core.service_errors.CapabilityError.to_dict().
    assert body.get("category") == "NOT_FOUND", body
    assert "gone" in body.get("error", "")


def test_run_consensus_one_missing_dump_is_404_not_500(strict_client, tmp_path):
    good = tmp_path / "good.dump"
    good.write_bytes(b"\xAA" * 4096)
    resp = strict_client.post(
        "/api/analysis/consensus",
        json={"dump_paths": [str(good), str(tmp_path / "gone.msl")]},
    )
    assert resp.status_code == 404, resp.text


# ---------------------------------------------------------------------------
# A consensus build must SAY which dumps it was built over.
#
# Without the echo a `consensus_id` is unattributable: the client cannot tell
# whether the build in its store describes the dumps currently selected, so it
# keeps projecting a build made over {X, Y} onto a later selection {A, B} —
# wrong slab, wrong classes, bogus cross-dump "Differs" rings, and nothing on
# the wire that could have detected it.
# ---------------------------------------------------------------------------


def test_run_consensus_echoes_dump_paths_and_normalize(strict_client, tmp_path):
    a = tmp_path / "echo_a.dump"
    b = tmp_path / "echo_b.dump"
    a.write_bytes(b"\xAA" * 4096)
    b.write_bytes(b"\xBB" * 4096)

    resp = strict_client.post(
        "/api/analysis/consensus",
        json={"dump_paths": [str(a), str(b)], "normalize": True},
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["dump_paths"] == [str(a), str(b)]
    assert body["normalize"] is True


def test_run_consensus_echoes_normalize_false_by_default(strict_client, tmp_path):
    a = tmp_path / "plain_a.dump"
    b = tmp_path / "plain_b.dump"
    a.write_bytes(b"\x01" * 2048)
    b.write_bytes(b"\x02" * 2048)

    resp = strict_client.post(
        "/api/analysis/consensus",
        json={"dump_paths": [str(a), str(b)]},
    )
    assert resp.status_code == 200, resp.text
    assert resp.json()["normalize"] is False


# ---------------------------------------------------------------------------
# A consensus build must also say WHAT CLASS each region is, and at what BANDS.
#
# Both rows and bands were being thrown away. Without ``classification`` the UI
# legend had to infer a region's class from ``mean_variance``, and without
# ``thresholds`` it had to compare that number against hard-coded 0/200/3000
# literals — a second copy of ``core.variance``'s bands, in TypeScript, free to
# drift the moment a build is run with custom thresholds. The CLI ``consensus``
# command has always emitted ``classification``; this is the web surface
# catching up.
# ---------------------------------------------------------------------------


def _mixed_consensus(client, tmp_path):
    """Two dumps whose first half is identical and whose second half is not.

    Guarantees BOTH region lists are non-empty: the invariant prefix is a
    static region, the differing suffix a volatile one.
    """
    a = tmp_path / "classified_a.dump"
    b = tmp_path / "classified_b.dump"
    a.write_bytes(b"\x00" * 2048 + b"\x00" * 2048)
    b.write_bytes(b"\x00" * 2048 + b"\xFF" * 2048)
    resp = client.post(
        "/api/analysis/consensus", json={"dump_paths": [str(a), str(b)]},
    )
    assert resp.status_code == 200, resp.text
    return resp.json()


def test_run_consensus_carries_classification_on_every_region(
    strict_client, tmp_path,
):
    body = _mixed_consensus(strict_client, tmp_path)

    assert body["static_regions"], body
    assert body["volatile_regions"], body
    for row in body["static_regions"]:
        assert row["classification"] == "invariant"
    for row in body["volatile_regions"]:
        assert row["classification"] == "key_candidate"
    # The pre-existing row fields are untouched.
    assert set(body["static_regions"][0]) == {
        "start", "end", "length", "mean_variance", "classification"}


def test_run_consensus_reports_the_bands_its_classes_were_cut_at(
    strict_client, tmp_path,
):
    """Resolved, never null: "null" reads to a client as "unknown", not as
    "the defaults". The numbers come from ``core.variance``, so a change to
    the bands reaches the legend instead of silently disagreeing with it."""
    from memdiver.core.variance import DEFAULT_THRESHOLDS

    body = _mixed_consensus(strict_client, tmp_path)

    assert body["thresholds"] == {
        "invariant_max": DEFAULT_THRESHOLDS.invariant_max,
        "structural_max": DEFAULT_THRESHOLDS.structural_max,
        "pointer_max": DEFAULT_THRESHOLDS.pointer_max,
    }
    # And they really do bound the rows they were reported with.
    for row in body["volatile_regions"]:
        assert row["mean_variance"] > body["thresholds"]["pointer_max"]
