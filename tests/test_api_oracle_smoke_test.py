"""Tests for ``POST /api/oracles/{id}/smoke-test`` and its registry method.

The endpoint exists because ``/dry-run`` grades whatever the *client* sends,
and the web UI sent sixteen hard-coded synthetic strings -- so a correct
oracle and one wired to ``return False`` both scored 0 pass / 16 fail. Here the
server composes the samples (one positive control the oracle MUST accept, N
negatives it MUST reject) and reports a *verdict* about discrimination rather
than a pass count.

These tests pin the whole verdict table, the tri-state ``positive.ok``, the
"no synthetic fallback" contract on an empty selection, and the rule that the
response must never echo the run's master key back over HTTP.

Fixtures and naming follow ``tests/test_api_oracles.py``; the corpus runs are
synthesised under ``tmp_path`` the way ``tests/test_oracle_autoconfig.py``
builds its own, so nothing here depends on the author's private dataset.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from memdiver.api.services.oracle_registry import (
    OracleNotFound,
    OracleRegistry,
    OracleRegistryError,
    get_oracle_registry,
    init_oracle_registry,
    reset_oracle_registry,
)

#: The run's master key. 32 distinct bytes, so a dump window containing it is
#: never mistaken for low-variety filler by the composer's entropy rule.
KEY = bytes(range(0x40, 0x60))
KEY_HEX = KEY.hex()

# -- Tiny oracles, written inline so the behaviour under test sits next to the
#    assertion that grades it. -------------------------------------------------

ORACLE_ACCEPTS_EVERYTHING = """\
def verify(candidate):
    return True
"""

ORACLE_REJECTS_EVERYTHING = """\
def verify(candidate):
    return False
"""

ORACLE_RAISES = """\
def verify(candidate):
    raise RuntimeError("oracle exploded")
"""

ORACLE_KNOWS_THE_KEY = f"""\
KEY = bytes.fromhex("{KEY_HEX}")


def verify(candidate):
    return candidate == KEY
"""


# -- Fixtures ------------------------------------------------------------------


@pytest.fixture
def examples_dir() -> Path:
    return Path(__file__).parent.parent / "docs" / "oracle" / "examples"


@pytest.fixture
def client(tmp_path: Path, examples_dir: Path):
    """A TestClient over the oracles router, with the singleton always reset.

    ``init_oracle_registry`` installs a PROCESS-wide registry; leaking one
    leaves the next test reading a ``tmp_path`` pytest has already deleted, so
    the teardown is the reason this is a fixture and not three lines inline.
    """
    from fastapi import FastAPI
    from fastapi.testclient import TestClient

    from memdiver.api.routers.oracles import router

    init_oracle_registry(
        oracle_dir=tmp_path / "oracles", examples_dir=examples_dir
    )
    app = FastAPI()
    app.include_router(router, prefix="/api/oracles")
    try:
        yield TestClient(app)
    finally:
        reset_oracle_registry()


def _varied_bytes(length: int) -> bytes:
    """Deterministic filler in which every 32-byte window is high-variety."""
    return bytes((i * 7 + 13) % 251 for i in range(length))


def _make_run(
    tmp_path: Path,
    run_id: str = "run_0001",
    *,
    master_key_hex: str | None = KEY_HEX,
    dump_bytes: bytes | None = None,
    with_meta: bool = True,
) -> Path:
    """One synthetic corpus run; returns the flat dump inside it."""
    run_dir = tmp_path / "dataset" / run_id
    run_dir.mkdir(parents=True, exist_ok=True)
    dump = run_dir / "memslicer.bin"
    dump.write_bytes(_varied_bytes(4096) if dump_bytes is None else dump_bytes)
    if with_meta:
        payload: dict = {
            "run_id": run_id,
            "cipher": "aes",
            "password": "hunter2",
            "aslr_base": 0,
            "pid": 1234,
            "dumps": {},
        }
        if master_key_hex is not None:
            payload["master_key_hex"] = master_key_hex
        (run_dir / "meta.json").write_text(json.dumps(payload))
    return dump


def _upload(source: str, filename: str = "probe.py") -> str:
    """Register an inline oracle through the live registry; returns its id."""
    entry = get_oracle_registry().upload(
        filename=filename, content=source.encode()
    )
    return entry.oracle_id


def _smoke(client, oracle_id: str, dump: Path, **body):
    """POST the smoke-test endpoint with the usual defaults."""
    payload = {"source_paths": [str(dump)], "seed": 1}
    payload.update(body)
    return client.post(f"/api/oracles/{oracle_id}/smoke-test", json=payload)


# -- The verdict table ---------------------------------------------------------


def test_oracle_that_accepts_everything_is_accepts_noise(client, tmp_path):
    """An oracle that says yes to arbitrary memory is a proven non-detector.

    This is the defect ``/dry-run`` could never surface: sixteen synthetic
    strings it accepted looked like sixteen passes, not like a broken oracle.
    """
    dump = _make_run(tmp_path)
    oracle_id = _upload(ORACLE_ACCEPTS_EVERYTHING)

    body = _smoke(client, oracle_id, dump).json()

    assert body["verdict"] == "accepts_noise"
    assert body["negatives"]["accepted"] == body["negatives"]["count"] > 0
    assert body["negatives"]["rejected"] == 0
    assert body["positive"]["present"] is True
    assert body["positive"]["ok"] is True


def test_oracle_that_rejects_everything_is_never_accepts(client, tmp_path):
    """Rejecting the run's own key is the failure a smoke test must name.

    Same raw score as a working oracle under ``/dry-run`` (zero passes on
    synthetic samples); only the positive control tells the two apart.
    """
    dump = _make_run(tmp_path)
    oracle_id = _upload(ORACLE_REJECTS_EVERYTHING)

    body = _smoke(client, oracle_id, dump).json()

    assert body["verdict"] == "never_accepts"
    assert body["positive"]["present"] is True
    assert body["positive"]["ok"] is False
    assert body["negatives"]["accepted"] == 0
    assert body["negatives"]["rejected"] > 0


def test_oracle_that_accepts_only_the_key_discriminates(client, tmp_path):
    """The green path: the key accepted AND real dump bytes rejected.

    ``discriminates`` requires BOTH halves, so this is the only test whose
    oracle is actually correct.
    """
    dump = _make_run(tmp_path)
    oracle_id = _upload(ORACLE_KNOWS_THE_KEY)

    body = _smoke(client, oracle_id, dump).json()

    assert body["verdict"] == "discriminates"
    assert body["positive"]["ok"] is True
    assert body["positive"]["index"] == 0
    assert body["positive"]["source"] == "meta.json"
    assert "run_0001" in body["positive"]["provenance_label"]
    assert body["negatives"]["accepted"] == 0
    assert body["negatives"]["rejected"] == body["negatives"]["count"] > 0


def test_key_accepted_with_no_usable_negatives_is_inconclusive(client, tmp_path):
    """Half the claim proved is not the claim proved.

    A dump too thin to yield one 32-byte window leaves nothing to contradict
    the oracle, so a correct positive alone must not green-light it.
    """
    dump = _make_run(tmp_path, dump_bytes=b"\x01" * 8)
    oracle_id = _upload(ORACLE_KNOWS_THE_KEY)

    body = _smoke(client, oracle_id, dump).json()

    assert body["verdict"] == "inconclusive"
    assert body["positive"]["ok"] is True
    assert body["negatives"]["count"] == 0
    assert body["caveats"], "a zero-negative draw must be disclosed"


def test_oracle_that_raises_is_never_accepts_and_reports_the_error(
    client, tmp_path
):
    """A crashing ``verify`` must reach the analyst as text, not as a 500.

    Every sample errors, so nothing was accepted and nothing was cleanly
    rejected -- and the per-sample ``error`` is the only thing that says why.
    """
    dump = _make_run(tmp_path)
    oracle_id = _upload(ORACLE_RAISES)

    body = _smoke(client, oracle_id, dump).json()

    assert body["verdict"] == "never_accepts"
    assert body["errors"] == body["samples"] > 0
    assert body["positive"]["ok"] is False
    assert "RuntimeError" in body["positive"]["error"]
    assert "oracle exploded" in body["positive"]["error"]
    for index, result in enumerate(body["results"]):
        assert result["index"] == index
        assert "RuntimeError" in result["error"]
        assert "oracle exploded" in result["error"]
    assert body["negatives"]["errors"] == body["negatives"]["count"]
    assert body["negatives"]["accepted"] == 0
    assert body["negatives"]["rejected"] == 0


def test_no_meta_json_reports_no_positive_control_with_ok_null(
    client, tmp_path
):
    """``positive.ok`` is TRI-STATE and ``None`` must not collapse to ``False``.

    "There was no ground truth to test with" is not "the oracle rejected its
    own key", and rendering the two the same way is exactly the confusion this
    endpoint exists to remove.
    """
    dump = _make_run(tmp_path, with_meta=False)
    oracle_id = _upload(ORACLE_REJECTS_EVERYTHING)

    response = _smoke(client, oracle_id, dump)
    body = response.json()

    assert body["verdict"] == "no_positive_control"
    assert body["positive"]["present"] is False
    assert body["positive"]["ok"] is None
    assert body["positive"]["ok"] is not False  # the whole point of tri-state
    assert body["positive"]["index"] is None
    assert body["positive"]["reason"] is not None
    assert "meta.json" in body["positive"]["reason"]
    # The wire form must carry a real null, not an omitted key.
    assert '"ok":null' in response.text.replace(" ", "")


def test_opting_out_of_the_positive_control_is_no_positive_control(
    client, tmp_path
):
    """Declining the ground truth degrades the verdict, it does not fail it.

    The run HAS a usable key here, so the verdict can only come from
    ``include_positive_control=False`` being honoured.
    """
    dump = _make_run(tmp_path)
    oracle_id = _upload(ORACLE_REJECTS_EVERYTHING)

    body = _smoke(client, oracle_id, dump, include_positive_control=False).json()

    assert body["verdict"] == "no_positive_control"
    assert body["positive"]["present"] is False
    assert body["positive"]["ok"] is None
    assert body["positive"]["reason"] is None
    assert body["negatives"]["rejected"] > 0


def test_accepts_noise_outranks_a_missing_positive_control(client, tmp_path):
    """Rule 1 beats rule 2: a proven non-detector stays the headline.

    Without the ordering, an oracle that accepts arbitrary memory would be
    reported as the benign "no ground truth available" whenever the dump
    happened to sit outside the corpus.
    """
    dump = _make_run(tmp_path, with_meta=False)
    oracle_id = _upload(ORACLE_ACCEPTS_EVERYTHING)

    body = _smoke(client, oracle_id, dump).json()

    assert body["positive"]["present"] is False
    assert body["negatives"]["accepted"] > 0
    assert body["verdict"] == "accepts_noise"


# -- Contract: arming, samples, and the dump summary ---------------------------


def test_smoke_test_does_not_require_armed(client, tmp_path):
    """Triage must come BEFORE the arm gate, exactly like ``/dry-run``.

    Mirrors ``test_dry_run_does_not_require_armed``: requiring an arm first
    would force the user to authorise running an oracle they cannot yet tell
    is working.
    """
    dump = _make_run(tmp_path)
    oracle_id = _upload(ORACLE_KNOWS_THE_KEY)
    assert get_oracle_registry().get(oracle_id).armed is False

    response = _smoke(client, oracle_id, dump)

    assert response.status_code == 200
    assert response.json()["verdict"] == "discriminates"
    assert get_oracle_registry().get(oracle_id).armed is False


def test_response_describes_the_dump_it_sampled(client, tmp_path):
    """The analyst has to be able to check WHAT was sampled and from where.

    ``view`` in particular: ``"va"`` would mean the negatives could be
    synthesized zero padding rather than captured bytes.
    """
    dump = _make_run(tmp_path)
    oracle_id = _upload(ORACLE_REJECTS_EVERYTHING)

    body = _smoke(client, oracle_id, dump).json()

    assert body["dump"] == {
        "path": str(dump),
        "format": "raw",
        "view": "vas",
        "size": 4096,
    }
    assert body["negatives"]["key_size"] == 32
    assert len(body["negatives"]["offsets"]) == body["negatives"]["count"]
    assert body["negatives"]["low_entropy_included"] == 0


def test_seed_makes_the_negative_offsets_reproducible(client, tmp_path):
    """Two identical requests must sample identical offsets.

    Without it the UI's "run it again" button produces a result that cannot be
    compared with the previous one.
    """
    dump = _make_run(tmp_path)
    oracle_id = _upload(ORACLE_REJECTS_EVERYTHING)

    first = _smoke(client, oracle_id, dump, seed=99).json()
    second = _smoke(client, oracle_id, dump, seed=99).json()

    assert first["negatives"]["offsets"] == second["negatives"]["offsets"]
    assert first["negatives"]["offsets"]


def test_response_never_echoes_the_master_key(client, tmp_path):
    """The positive control IS the run's key; echoing it hands it to any client.

    The check is made non-vacuous by first proving the run really does declare
    that key, so a typo in ``KEY_HEX`` cannot turn this into an assertion that
    an absent string is absent.
    """
    from memdiver.core.discovery import RunDiscovery

    dump = _make_run(tmp_path)
    meta = RunDiscovery.meta_for_dump(str(dump))
    assert meta is not None
    assert meta.master_key_hex == KEY_HEX  # non-vacuity
    assert meta.master_key == KEY

    oracle_id = _upload(ORACLE_KNOWS_THE_KEY)
    response = _smoke(client, oracle_id, dump)

    assert response.status_code == 200
    assert response.json()["positive"]["ok"] is True  # the key WAS submitted
    assert KEY_HEX not in response.text
    assert KEY_HEX.upper() not in response.text
    import base64

    assert base64.b64encode(KEY).decode() not in response.text


# -- Request validation --------------------------------------------------------


def test_empty_source_paths_is_422_with_no_synthetic_fallback(client, tmp_path):
    """There is deliberately no fallback to made-up bytes.

    Grading an oracle against invented samples is the very defect this
    endpoint replaces, so an empty selection must be refused at the schema
    rather than silently degraded into a meaningless pass.
    """
    _make_run(tmp_path)
    oracle_id = _upload(ORACLE_ACCEPTS_EVERYTHING)

    response = client.post(
        f"/api/oracles/{oracle_id}/smoke-test", json={"source_paths": []}
    )

    assert response.status_code == 422
    body = response.json()
    assert "verdict" not in body
    assert "results" not in body
    assert "negatives" not in body


def test_missing_source_paths_key_is_422(client, tmp_path):
    """``source_paths`` is REQUIRED, not defaulted to an empty list."""
    _make_run(tmp_path)
    oracle_id = _upload(ORACLE_ACCEPTS_EVERYTHING)

    response = client.post(f"/api/oracles/{oracle_id}/smoke-test", json={})

    assert response.status_code == 422


def test_registry_rejects_empty_source_paths_below_the_schema(client, tmp_path):
    """The service layer refuses too, so a non-HTTP caller cannot bypass it.

    The 422 above is a pydantic guard on one surface; this is the invariant
    itself, and it is what keeps the library API honest.
    """
    _make_run(tmp_path)
    oracle_id = _upload(ORACLE_ACCEPTS_EVERYTHING)

    with pytest.raises(OracleRegistryError, match="at least one dump"):
        get_oracle_registry().smoke_test(oracle_id, source_paths=[])


@pytest.mark.parametrize("negatives", [0, 64, 1000])
def test_negatives_outside_the_cap_is_422(client, tmp_path, negatives):
    """``negatives + 1`` must stay inside the 64-sample ceiling ``/dry-run`` sets.

    63 is therefore the maximum, and 0 would ask for a test with no negative
    evidence at all.
    """
    dump = _make_run(tmp_path)
    oracle_id = _upload(ORACLE_ACCEPTS_EVERYTHING)

    response = _smoke(client, oracle_id, dump, negatives=negatives)

    assert response.status_code == 422


def test_negatives_at_the_cap_is_accepted(client, tmp_path):
    """Non-vacuity for the cap: 63 is inside it, so the bound is off-by-one safe."""
    dump = _make_run(tmp_path)
    oracle_id = _upload(ORACLE_REJECTS_EVERYTHING)

    response = _smoke(client, oracle_id, dump, negatives=63)

    assert response.status_code == 200
    assert response.json()["samples"] == 64  # 63 negatives + the positive


def test_unknown_oracle_id_is_404(client, tmp_path):
    """A stale ``oracleId`` from a restarted server must 404, not 500."""
    dump = _make_run(tmp_path)

    response = _smoke(client, "0" * 32, dump)

    assert response.status_code == 404


def test_disabled_registry_cannot_smoke_test_anything(
    tmp_path, examples_dir, monkeypatch
):
    """With no oracle dir there are no oracles, so every id is unknown.

    Pinned because the registry's *disabled* state is reached through a
    different error class (503) elsewhere, and the difference is worth being
    explicit about: ``smoke_test`` resolves the id first, and a disabled
    registry simply holds no entries.
    """
    from fastapi import FastAPI
    from fastapi.testclient import TestClient

    from memdiver.api.routers.oracles import router

    monkeypatch.delenv("MEMDIVER_ORACLE_DIR", raising=False)
    registry = init_oracle_registry(oracle_dir=None, examples_dir=examples_dir)
    app = FastAPI()
    app.include_router(router, prefix="/api/oracles")
    try:
        assert registry.enabled is False
        dump = _make_run(tmp_path)
        response = TestClient(app).post(
            "/api/oracles/abc123/smoke-test",
            json={"source_paths": [str(dump)]},
        )
        assert response.status_code == 404
        with pytest.raises(OracleNotFound):
            registry.smoke_test("abc123", source_paths=[str(dump)])
    finally:
        reset_oracle_registry()


def test_unconfigured_shape2_oracle_is_400_not_500(
    tmp_path, examples_dir
):
    """Smoke-testing before filling in the form is a user mistake, not a crash.

    ``load_oracle`` calls ``build_oracle(config)`` unwrapped, so the user
    oracle's own ``KeyError`` arrives bare; it must be funnelled into a 400
    that names the missing configuration.
    """
    from fastapi import FastAPI
    from fastapi.testclient import TestClient

    from memdiver.api.routers.oracles import router

    init_oracle_registry(
        oracle_dir=tmp_path / "oracles", examples_dir=examples_dir
    )
    try:
        app = FastAPI()
        app.include_router(router, prefix="/api/oracles")
        client = TestClient(app)
        dump = _make_run(tmp_path)
        oracle_id = _upload(
            "def build_oracle(cfg):\n"
            "    raise KeyError('sample_ciphertext')\n",
            filename="needs_config.py",
        )

        response = _smoke(client, oracle_id, dump)

        assert response.status_code == 400
        assert "sample_ciphertext" in response.json()["detail"]
    finally:
        reset_oracle_registry()


# -- The registry method, without FastAPI --------------------------------------


def test_registry_smoke_test_is_usable_without_http(tmp_path, examples_dir):
    """The library API must return the same verdict the router serialises.

    ``OracleRegistry`` is reachable from the CLI and the MCP surface too, so
    the grading cannot live in the router.
    """
    registry = OracleRegistry(
        oracle_dir=tmp_path / "oracles", examples_dir=examples_dir
    )
    try:
        dump = _make_run(tmp_path)
        entry = registry.upload(
            filename="k.py", content=ORACLE_KNOWS_THE_KEY.encode()
        )

        report = registry.smoke_test(
            entry.oracle_id, source_paths=[str(dump)], seed=1
        )

        assert report["oracle_id"] == entry.oracle_id
        assert report["verdict"] == "discriminates"
        assert report["positive"]["ok"] is True
        assert report["negatives"]["accepted"] == 0
    finally:
        reset_oracle_registry()
