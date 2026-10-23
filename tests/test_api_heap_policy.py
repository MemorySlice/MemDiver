"""HTTP ``allocator`` / ``heap_policy`` fields reach their producer kwargs.

Each producer is replaced by a spy that records its kwargs and stops the
request; the TestClient re-raises the sentinel, so no compute runs. One end-to-
end check on the synthetic heap corpus pins that ``heap_policy: "mask"``
changes ``stages.heap_masked``.
"""

import pytest
from fastapi.testclient import TestClient

from memdiver.api.config import get_settings
from memdiver.api.main import create_app
from memdiver.app import tools_consensus, tools_pipeline
from memdiver.heap import analyze as heap_analyze
from tests.test_candidate_pipeline_heap import write_corpus


class _Stop(Exception):
    """Raised by the spies once the producer kwargs are captured."""


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.delenv("MEMDIVER_ALLOWED_ROOTS", raising=False)
    monkeypatch.setenv("MEMDIVER_TASK_ROOT", str(tmp_path / "tasks"))
    get_settings.cache_clear()
    yield TestClient(create_app())
    get_settings.cache_clear()


@pytest.fixture
def spy(monkeypatch):
    def install(module, name):
        captured = {}

        def fake(*_args, **kwargs):
            captured.update(kwargs)
            raise _Stop

        monkeypatch.setattr(module, name, fake)
        return captured
    return install


@pytest.fixture
def two_dumps(tmp_path):
    paths = []
    for i in range(2):
        path = tmp_path / f"d{i}.dump"
        path.write_bytes(bytes([i]) * 256)
        paths.append(str(path))
    return paths


def _post_until_stop(client, route, body):
    with pytest.raises(_Stop):
        client.post(route, json=body)


def test_consensus_forwards_allocator(client, spy, two_dumps):
    from memdiver.api.routers import analysis

    captured = spy(analysis, "build_consensus")
    _post_until_stop(client, "/api/analysis/consensus",
                     {"dump_paths": two_dumps, "allocator": "mallocng"})
    assert captured["allocator"] == "mallocng"


@pytest.mark.parametrize("route, producer", [
    ("/api/analysis/consensus/aligned-window", "aligned_window_result"),
    ("/api/analysis/consensus/regions", "class_regions_result"),
])
def test_consensus_views_forward_allocator(client, spy, two_dumps, route, producer):
    captured = spy(tools_consensus, producer)
    body = {"dump_paths": two_dumps, "allocator": "off"}
    if producer == "aligned_window_result":
        body.update(anchor="slab", slab_offset=0)
    _post_until_stop(client, route, body)
    assert captured["allocator"] == "off"


def test_candidates_forward_heap_policy_and_allocator(client, spy, two_dumps):
    captured = spy(tools_pipeline, "analyze_candidates")
    _post_until_stop(client, "/api/analysis/candidates", {
        "dump_paths": two_dumps, "heap_policy": "mask", "allocator": "dlmalloc"})
    assert captured["heap_policy"] == "mask"
    assert captured["allocator"] == "dlmalloc"


def test_locate_key_forwards_allocator(client, spy, two_dumps):
    captured = spy(tools_pipeline, "locate_key")
    _post_until_stop(client, "/api/analysis/locate-key", {
        "dump_paths": two_dumps, "secret_hex": "aabb", "allocator": "generic"})
    assert captured["allocator"] == "generic"


def test_defaults_match_the_producers(client, spy, two_dumps):
    captured = spy(tools_pipeline, "analyze_candidates")
    _post_until_stop(client, "/api/analysis/candidates", {"dump_paths": two_dumps})
    assert captured["heap_policy"] == "annotate"
    assert captured["allocator"] == "auto"


def test_unknown_heap_policy_is_a_400(client, two_dumps):
    resp = client.post("/api/analysis/candidates", json={
        "dump_paths": two_dumps, "heap_policy": "drop"})
    assert resp.status_code == 400, resp.text


@pytest.fixture
def corpus(tmp_path, monkeypatch):
    from memdiver.app import composition

    heap_analyze.clear_heap_cache()
    monkeypatch.setattr(composition, "resolve_project_db", lambda *a, **k: None)
    paths, _heap = write_corpus(tmp_path / "dumps")
    yield paths
    heap_analyze.clear_heap_cache()


def test_mask_changes_heap_masked_over_http(client, corpus):
    bodies = {}
    for policy in ("annotate", "mask"):
        resp = client.post("/api/analysis/candidates", json={
            "dump_paths": corpus, "heap_policy": policy, "max_returned": 0})
        assert resp.status_code == 200, resp.text
        bodies[policy] = resp.json()
    assert "heap_masked" not in bodies["annotate"]["stages"]
    assert bodies["mask"]["stages"]["heap_masked"] > 0


def test_consensus_response_carries_heap_block(client, corpus):
    resp = client.post("/api/analysis/consensus", json={"dump_paths": corpus})
    assert resp.status_code == 200, resp.text
    assert resp.json()["heap"]["status"] == "ok"
    resp = client.post("/api/analysis/consensus",
                       json={"dump_paths": corpus, "allocator": "off"})
    assert resp.json()["heap"] is None
