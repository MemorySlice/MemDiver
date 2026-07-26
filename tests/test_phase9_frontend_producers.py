"""Phase 9 backend producers for logic formerly duplicated in the frontend.

Covers:
  * ``app.tools_fields.infer_fields_result`` — matches
    ``engine.vol3_emit.extract_inferred_fields`` and emits the exact
    ``{offset, length, type, label, mean_variance}`` field shape.
  * ``POST /api/pipeline/infer-fields`` — same shape + threshold exposure.
  * ``POST /api/pipeline/runs/{id}/refine`` — now embeds ``fields`` per
    neighborhood and surfaces the ``variance_threshold``.
  * ``app.tools_algorithms.algorithm_availability`` — the three gating rules
    with the verbatim reason strings + default-available fall-through.
  * ``GET /api/algorithms/availability`` — the availability map over the wire.
"""

from __future__ import annotations

import json
from pathlib import Path

import numpy as np
import pytest
from fastapi.testclient import TestClient

from memdiver.api.config import get_settings
from memdiver.api.main import create_app
from memdiver.app.tools_algorithms import algorithm_availability
from memdiver.app.tools_fields import infer_fields_result
from memdiver.core.service_errors import CapabilityError
from memdiver.engine.vol3_emit import PLUGIN_STATIC_THRESHOLD, extract_inferred_fields

_FIELD_KEYS = {"offset", "length", "type", "label", "mean_variance"}

# Verbatim reason strings copied from frontend/src/utils/algorithm-availability.ts.
_REASON_DIFFERENTIAL = "Requires 2+ memory dumps for cross-run variance analysis"
_REASON_EXACT_MATCH = "Requires keylog reference data (ground truth)"
_REASON_CONSTRAINT_VALIDATOR = "Requires candidate keys from prior analysis"


# ------------------------------------------------------------------
# fixtures
# ------------------------------------------------------------------


@pytest.fixture
def client(tmp_path, monkeypatch):
    """A TestClient with isolated oracle/task dirs (stateless routes only)."""
    oracle_dir = tmp_path / "oracles"
    task_root = tmp_path / "tasks"
    oracle_dir.mkdir()
    task_root.mkdir()
    monkeypatch.setenv("MEMDIVER_ORACLE_DIR", str(oracle_dir))
    monkeypatch.setenv("MEMDIVER_TASK_ROOT", str(task_root))
    monkeypatch.setenv("MEMDIVER_TASK_QUOTA_BYTES", "10485760")
    monkeypatch.setenv("MEMDIVER_PIPELINE_MAX_WORKERS", "1")
    get_settings.cache_clear()
    app = create_app()
    with TestClient(app) as c:
        yield c
    get_settings.cache_clear()


def _sample_variance() -> list[float]:
    # A profile with a low-variance static run, a volatile key run, and a
    # high-variance dynamic tail, so all three field types appear.
    return (
        [10.0] * 20        # static
        + [50000.0] * 16   # (key region overrides this to key_material)
        + [9000.0] * 12    # dynamic
    )


# ------------------------------------------------------------------
# infer_fields_result producer
# ------------------------------------------------------------------


def test_infer_fields_result_matches_extract_inferred_fields():
    variance = _sample_variance()
    nb_start, offset, length = 1000, 1020, 16  # key at window index 20

    got = infer_fields_result(
        neighborhood_variance=variance,
        neighborhood_start=nb_start,
        offset=offset,
        length=length,
    )
    hit = {
        "offset": offset,
        "length": length,
        "neighborhood_start": nb_start,
        "neighborhood_variance": variance,
    }
    expected = extract_inferred_fields(hit)
    assert got == expected


def test_infer_fields_result_exact_field_shape():
    fields = infer_fields_result(
        neighborhood_variance=_sample_variance(),
        neighborhood_start=1000,
        offset=1020,
        length=16,
    )
    assert fields, "expected at least one field for a non-trivial profile"
    types = set()
    for f in fields:
        assert set(f.keys()) == _FIELD_KEYS
        assert isinstance(f["offset"], int)
        assert isinstance(f["length"], int)
        assert isinstance(f["label"], str)
        assert isinstance(f["mean_variance"], float)
        assert f["type"] in ("static", "key_material", "dynamic")
        types.add(f["type"])
    assert {"static", "key_material", "dynamic"} <= types
    key = next(f for f in fields if f["type"] == "key_material")
    assert key["offset"] == 20 and key["length"] == 16 and key["label"] == "key"


def test_infer_fields_result_empty_variance_returns_empty():
    assert infer_fields_result([], 0, 0, 32) == []


def test_infer_fields_result_custom_threshold_changes_classification():
    # A uniform mid-variance profile: below the default threshold everything is
    # static; drop the threshold and it flips to dynamic.
    variance = [1500.0] * 32
    default = infer_fields_result(variance, 0, 0, 0)
    lowered = infer_fields_result(variance, 0, 0, 0, variance_threshold=100.0)
    assert default[0]["type"] == "static"
    assert lowered[0]["type"] == "dynamic"


@pytest.mark.parametrize(
    "kwargs",
    [
        {"neighborhood_variance": [1.0], "neighborhood_start": 0, "offset": 0, "length": -1},
        {"neighborhood_variance": [1.0], "neighborhood_start": 100, "offset": 50, "length": 8},
        {"neighborhood_variance": [1.0], "neighborhood_start": 0, "offset": 0, "length": 4,
         "variance_threshold": -5.0},
    ],
)
def test_infer_fields_result_raises_on_bad_input(kwargs):
    with pytest.raises(CapabilityError):
        infer_fields_result(**kwargs)


# ------------------------------------------------------------------
# POST /api/pipeline/infer-fields
# ------------------------------------------------------------------


def test_infer_fields_endpoint_returns_fields_and_threshold(client):
    variance = _sample_variance()
    body = {
        "neighborhood_variance": variance,
        "neighborhood_start": 1000,
        "offset": 1020,
        "length": 16,
    }
    r = client.post("/api/pipeline/infer-fields", json=body)
    assert r.status_code == 200, r.text
    payload = r.json()
    assert payload["variance_threshold"] == PLUGIN_STATIC_THRESHOLD
    fields = payload["fields"]
    expected = infer_fields_result(
        neighborhood_variance=variance,
        neighborhood_start=1000,
        offset=1020,
        length=16,
    )
    assert fields == expected
    for f in fields:
        assert set(f.keys()) == _FIELD_KEYS


def test_infer_fields_endpoint_echoes_custom_threshold(client):
    body = {
        "neighborhood_variance": [1500.0] * 8,
        "neighborhood_start": 0,
        "offset": 0,
        "length": 0,
        "variance_threshold": 100.0,
    }
    r = client.post("/api/pipeline/infer-fields", json=body)
    assert r.status_code == 200, r.text
    assert r.json()["variance_threshold"] == 100.0


def test_infer_fields_endpoint_bad_input_is_400(client):
    body = {
        "neighborhood_variance": [1.0],
        "neighborhood_start": 100,
        "offset": 50,
        "length": 8,
    }
    r = client.post("/api/pipeline/infer-fields", json=body)
    assert r.status_code == 400, r.text


# ------------------------------------------------------------------
# refine now includes fields + variance_threshold
# ------------------------------------------------------------------


class _FakeManager:
    def __init__(self, record):
        self._record = record
        self.artifact_store = None

    def get(self, task_id):
        return self._record


def test_refine_includes_fields_and_threshold(tmp_path, monkeypatch):
    import asyncio

    from memdiver.api.routers import pipeline as pipeline_mod
    from memdiver.core.variance import WelfordVariance

    size = 256

    def _make_dump(seed):
        rng = np.random.default_rng(seed)
        return rng.integers(0, 256, size, dtype=np.uint8).tobytes()

    base_dumps = [_make_dump(s) for s in (1, 2)]
    extra_dumps = [_make_dump(s) for s in (3, 4)]

    base = WelfordVariance(size)
    for d in base_dumps:
        base.add_dump(d)
    mean, m2, n = base.state_arrays()

    consensus_dir = tmp_path / "art" / "consensus"
    consensus_dir.mkdir(parents=True)
    mean_path = consensus_dir / "mean.npy"
    m2_path = consensus_dir / "m2.npy"
    np.save(mean_path, mean)
    np.save(m2_path, m2)
    (consensus_dir / "state.json").write_text(
        json.dumps({
            "mean_path": str(mean_path),
            "m2_path": str(m2_path),
            "num_dumps": int(n),
        })
    )

    hit_offset, hit_len = 96, 16
    bf_dir = tmp_path / "art" / "brute_force"
    bf_dir.mkdir(parents=True)
    (bf_dir / "hits.json").write_text(
        json.dumps({"hits": [{"offset": hit_offset, "length": hit_len}]})
    )

    extra_paths = []
    for i, d in enumerate(extra_dumps):
        p = tmp_path / f"extra_{i}.bin"
        p.write_bytes(d)
        extra_paths.append(str(p))

    manager = _FakeManager({"artifact_dir": str(tmp_path / "art")})
    monkeypatch.setattr(pipeline_mod, "_task_manager_or_503", lambda: manager)

    body = pipeline_mod.RefineRequest(additional_paths=extra_paths)
    resp = asyncio.run(pipeline_mod.refine_consensus("t", body))

    assert resp.variance_threshold == PLUGIN_STATIC_THRESHOLD
    assert len(resp.hit_neighborhoods) == 1
    nb = resp.hit_neighborhoods[0]
    assert "fields" in nb
    # Fields match the shared producer over the same neighborhood inputs.
    expected = infer_fields_result(
        neighborhood_variance=nb["neighborhood_variance"],
        neighborhood_start=nb["neighborhood_start"],
        offset=nb["offset"],
        length=hit_len,
    )
    assert nb["fields"] == expected
    for f in nb["fields"]:
        assert set(f.keys()) == _FIELD_KEYS


# ------------------------------------------------------------------
# algorithm_availability producer
# ------------------------------------------------------------------


def test_availability_differential_requires_two_dumps():
    m = algorithm_availability(dump_count=1, has_keylog=True, has_candidate_keys=True)
    assert m["differential"] == {"available": False, "reason": _REASON_DIFFERENTIAL}
    m2 = algorithm_availability(dump_count=2, has_keylog=True, has_candidate_keys=True)
    assert m2["differential"] == {"available": True, "reason": None}


def test_availability_exact_match_requires_keylog():
    m = algorithm_availability(dump_count=5, has_keylog=False, has_candidate_keys=True)
    assert m["exact_match"] == {"available": False, "reason": _REASON_EXACT_MATCH}
    m2 = algorithm_availability(dump_count=5, has_keylog=True, has_candidate_keys=True)
    assert m2["exact_match"] == {"available": True, "reason": None}


def test_availability_constraint_validator_requires_candidates():
    m = algorithm_availability(dump_count=5, has_keylog=True, has_candidate_keys=False)
    assert m["constraint_validator"] == {
        "available": False, "reason": _REASON_CONSTRAINT_VALIDATOR,
    }
    m2 = algorithm_availability(dump_count=5, has_keylog=True, has_candidate_keys=True)
    assert m2["constraint_validator"] == {"available": True, "reason": None}


def test_availability_default_algorithm_is_available():
    m = algorithm_availability(
        dump_count=0, has_keylog=False, has_candidate_keys=False,
        algorithms=["entropy_scan", "pattern_match"],
    )
    assert m == {
        "entropy_scan": {"available": True, "reason": None},
        "pattern_match": {"available": True, "reason": None},
    }


def test_availability_default_names_are_the_gated_ones():
    m = algorithm_availability(dump_count=2, has_keylog=True, has_candidate_keys=True)
    assert set(m.keys()) == {"differential", "exact_match", "constraint_validator"}


def test_availability_mode_is_accepted_and_ignored():
    a = algorithm_availability(dump_count=1, has_keylog=False, has_candidate_keys=False)
    b = algorithm_availability(
        dump_count=1, has_keylog=False, has_candidate_keys=False, mode="research",
    )
    assert a == b


# ------------------------------------------------------------------
# GET /api/algorithms/availability
# ------------------------------------------------------------------


def test_availability_endpoint_returns_gating_map(client):
    r = client.get(
        "/api/algorithms/availability",
        params={"dump_count": 1, "has_keylog": False, "has_candidate_keys": False},
    )
    assert r.status_code == 200, r.text
    avail = r.json()["availability"]
    assert avail["differential"] == {"available": False, "reason": _REASON_DIFFERENTIAL}
    assert avail["exact_match"] == {"available": False, "reason": _REASON_EXACT_MATCH}
    assert avail["constraint_validator"] == {
        "available": False, "reason": _REASON_CONSTRAINT_VALIDATOR,
    }


def test_availability_endpoint_all_available_with_full_context(client):
    r = client.get(
        "/api/algorithms/availability",
        params={"dump_count": 3, "has_keylog": True, "has_candidate_keys": True},
    )
    assert r.status_code == 200, r.text
    avail = r.json()["availability"]
    for entry in avail.values():
        assert entry == {"available": True, "reason": None}


def test_availability_endpoint_explicit_algorithms(client):
    r = client.get(
        "/api/algorithms/availability",
        params=[
            ("dump_count", 1),
            ("has_keylog", False),
            ("has_candidate_keys", False),
            ("algorithms", "differential"),
            ("algorithms", "entropy_scan"),
        ],
    )
    assert r.status_code == 200, r.text
    avail = r.json()["availability"]
    assert set(avail.keys()) == {"differential", "entropy_scan"}
    assert avail["differential"]["available"] is False
    assert avail["entropy_scan"] == {"available": True, "reason": None}
