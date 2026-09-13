"""``POST /api/analysis/consensus/regions`` — the paginated, jumpable region list.

Adapter tests. The compute is covered by ``test_consensus_class_regions.py``;
what a route can get wrong is different, and each of those is asserted here:

* the either/or contract (``consensus_id`` XOR ``dump_paths``) and its two
  error codes — 400 for "neither or both", 404 for an id nobody registered;
* that BOTH branches reach the same producer and return the same shape;
* that the wire caps (``limit``) are enforced at the boundary rather than
  silently clamped after a whole page has been built;
* that the fields the UI cannot re-derive — ``classification``, ``counts``,
  ``anchor.jumpable`` — actually arrive.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from fastapi.testclient import TestClient  # noqa: E402

from memdiver.api.main import create_app  # noqa: E402
from memdiver.api.services.consensus_session import (  # noqa: E402
    ConsensusSessionManager,
)
from memdiver.app.tools_consensus import MAX_REGIONS_PER_PAGE  # noqa: E402
from tests.fixtures.generate_msl_aslr_fixtures import (  # noqa: E402
    generate_aslr_msl_pair,
)

_ROUTE = "/api/analysis/consensus/regions"
_BUILD = "/api/analysis/consensus"


@pytest.fixture(scope="module")
def aslr_pair(tmp_path_factory):
    root = tmp_path_factory.mktemp("api_class_regions")
    run1, run2 = generate_aslr_msl_pair(extra_region=True)
    first, second = root / "run_1.msl", root / "run_2.msl"
    first.write_bytes(run1)
    second.write_bytes(run2)
    return str(first), str(second)


@pytest.fixture
def client():
    return TestClient(create_app())


@pytest.fixture(autouse=True)
def _fresh_manager(monkeypatch):
    """Per-test consensus manager so ids never leak between tests."""
    import memdiver.api.services.consensus_session as mod

    manager = ConsensusSessionManager()
    monkeypatch.setattr(mod, "_default_manager", manager)
    yield manager


@pytest.fixture
def consensus_id(client, aslr_pair):
    resp = client.post(_BUILD, json={"dump_paths": list(aslr_pair)})
    assert resp.status_code == 200, resp.text
    return resp.json()["consensus_id"]


# ---------------------------------------------------------------------------
# The either/or contract
# ---------------------------------------------------------------------------


def test_neither_consensus_id_nor_dump_paths_is_a_400(client):
    resp = client.post(_ROUTE, json={})
    assert resp.status_code == 400, resp.text
    assert "exactly one" in resp.json()["detail"]


def test_both_consensus_id_and_dump_paths_is_a_400(client, aslr_pair, consensus_id):
    resp = client.post(_ROUTE, json={
        "consensus_id": consensus_id, "dump_paths": list(aslr_pair)})
    assert resp.status_code == 400, resp.text


def test_an_unknown_consensus_id_is_a_404(client):
    resp = client.post(_ROUTE, json={"consensus_id": "not-a-real-id"})
    assert resp.status_code == 404, resp.text


# ---------------------------------------------------------------------------
# Both branches
# ---------------------------------------------------------------------------


def test_consensus_id_branch_serves_a_page_and_echoes_the_id(client, consensus_id):
    resp = client.post(_ROUTE, json={"consensus_id": consensus_id,
                                     "min_length": 1})

    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["consensus_id"] == consensus_id
    assert body["coordinate"] == "aligned"
    assert body["classes"] == ["structural", "pointer", "key_candidate"]
    assert body["union"] is True
    assert body["regions"], body


def test_dump_paths_branch_builds_one_and_reports_no_id(client, aslr_pair):
    """The build-one-now branch: there is no registered session to name, so
    ``consensus_id`` is null rather than a fabricated handle."""
    resp = client.post(_ROUTE, json={"dump_paths": list(aslr_pair),
                                     "min_length": 1})

    assert resp.status_code == 200, resp.text
    assert resp.json()["consensus_id"] is None
    assert resp.json()["coordinate"] == "aligned"


def test_both_branches_agree_on_the_page(client, aslr_pair, consensus_id):
    """One producer behind two branches: the only legitimate difference is the
    echoed ``consensus_id``."""
    by_id = client.post(_ROUTE, json={"consensus_id": consensus_id,
                                      "min_length": 1}).json()
    by_paths = client.post(_ROUTE, json={"dump_paths": list(aslr_pair),
                                         "min_length": 1}).json()

    by_id.pop("consensus_id")
    by_paths.pop("consensus_id")
    assert by_id == by_paths


# ---------------------------------------------------------------------------
# The fields the UI cannot re-derive
# ---------------------------------------------------------------------------


def test_every_row_carries_its_classification(client, consensus_id):
    """Without it the legend has to infer a class from ``mean_variance``
    against hard-coded 0/200/3000 literals — a second, drifting copy of
    ``core.variance``'s bands."""
    body = client.post(_ROUTE, json={"consensus_id": consensus_id,
                                     "min_length": 1}).json()

    assert body["regions"]
    for row in body["regions"]:
        assert row["classification"] in {
            "invariant", "structural", "pointer", "key_candidate"}


def test_the_whole_build_histogram_is_echoed_with_the_page(client, consensus_id):
    """``counts`` sizes the CHIPS beside the list, so it must arrive with the
    first page rather than costing a second round trip to POST /consensus."""
    body = client.post(_ROUTE, json={"consensus_id": consensus_id,
                                     "limit": 1, "min_length": 1}).json()

    assert body["counts"], body
    assert sum(body["counts"].values()) == 8192
    assert body["returned"] <= 1


def test_the_page_carries_its_cursor_and_total(client, consensus_id):
    body = client.post(_ROUTE, json={"consensus_id": consensus_id,
                                     "min_length": 1}).json()

    assert set(body) >= {
        "total", "returned", "truncated", "after", "next_after",
        "min_length", "max_length", "anchor", "alignment"}
    assert body["after"] == -1
    assert body["total"] >= body["returned"]


def test_an_anchor_makes_the_page_jumpable(client, consensus_id, aslr_pair):
    body = client.post(_ROUTE, json={
        "consensus_id": consensus_id, "min_length": 1,
        "anchor_path": aslr_pair[0], "anchor_view": "va"}).json()

    assert body["anchor"]["jumpable"] is True
    assert body["anchor"]["dump_index"] == 0
    assert all(row["anchor_offset"] >= 0 for row in body["regions"])


def test_an_anchor_outside_the_build_is_a_409(client, consensus_id, tmp_path):
    """Not a 404: the build exists and the dump exists, they simply do not
    belong together — the state ``_require_dumps_in_build`` names."""
    stranger = tmp_path / "stranger.msl"
    stranger.write_bytes(b"\x00" * 16)
    resp = client.post(_ROUTE, json={
        "consensus_id": consensus_id, "anchor_path": str(stranger)})

    assert resp.status_code == 409, resp.text


# ---------------------------------------------------------------------------
# Wire caps + validation
# ---------------------------------------------------------------------------


def test_limit_above_the_cap_is_refused_at_the_boundary(client, consensus_id):
    """422 at the model, not a silent clamp after a page has been built."""
    resp = client.post(_ROUTE, json={"consensus_id": consensus_id,
                                     "limit": MAX_REGIONS_PER_PAGE + 1})
    assert resp.status_code == 422, resp.text


def test_limit_at_the_cap_is_accepted(client, consensus_id):
    resp = client.post(_ROUTE, json={"consensus_id": consensus_id,
                                     "limit": MAX_REGIONS_PER_PAGE})
    assert resp.status_code == 200, resp.text


def test_a_zero_limit_is_refused(client, consensus_id):
    resp = client.post(_ROUTE, json={"consensus_id": consensus_id, "limit": 0})
    assert resp.status_code == 422, resp.text


def test_an_unknown_class_reaches_the_global_capability_funnel(
    client, consensus_id,
):
    """No ``try/except`` in the route: the producer's CapabilityError is
    rendered by the app's one global handler, like every producer-backed
    route."""
    resp = client.post(_ROUTE, json={"consensus_id": consensus_id,
                                     "classes": ["keycandidate"]})
    assert resp.status_code == 400, resp.text


def test_an_unknown_anchor_view_is_refused_at_the_model(client, consensus_id):
    resp = client.post(_ROUTE, json={"consensus_id": consensus_id,
                                     "anchor_view": "slab"})
    assert resp.status_code == 422, resp.text
