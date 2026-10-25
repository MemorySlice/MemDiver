"""Image views (.mdview) in the hex workspace: page states, views, import preview.

The browser asks the SAME endpoints for an image view as for an ``.msl``; these
tests send the exact requests the frontend sends (``getPageStates``,
``useMslViewSizes`` probe, wizard ``previewImport``) over a TestClient, against
a ``Vol3LayerSource`` driven by a fake layer adapter (no Volatility).
"""

import json
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient

import memdiver.core.image.sources as sources
from memdiver.app.page_state_runs import image_page_states_payload
from memdiver.core.image.run_index import LayerRun, RunState
from memdiver.core.image.view_descriptor import ProfileRef, ViewDescriptor, ViewKind

C, F, N = RunState.CAPTURED, RunState.FAILED, RunState.NOT_RESIDENT
SHA = "ab" * 32
PAGE = 0x1000
USER_BASE = 0x56056590C000


class FakeAdapter:
    def __init__(self, runs, vmas=()):
        self._runs, self._vmas = list(runs), list(vmas)

    def runs(self):
        return self._runs

    def vmas(self):
        return self._vmas

    def read(self, address, length):
        return bytes([0x41]) * length

    def describe(self):
        return {"layer": "fake"}

    def close(self):
        pass


def _vma(start, end, name, prot, heap=False, file_backed=False):
    return SimpleNamespace(start=start, end=end, name=name, protection=prot,
                           is_heap=heap, file_backed=file_backed)


USER_RUNS = [
    LayerRun(USER_BASE, 2 * PAGE, C),
    LayerRun(USER_BASE + 2 * PAGE, PAGE, N),
    LayerRun(USER_BASE + 3 * PAGE, PAGE, C),
    LayerRun(USER_BASE + 4 * PAGE, PAGE, F),
    # a gap of two pages, then more captured memory
    LayerRun(USER_BASE + 7 * PAGE, PAGE, C),
]
USER_VMAS = [
    _vma(USER_BASE, USER_BASE + 3 * PAGE, "[heap]", "rw-", heap=True),
    _vma(USER_BASE + 3 * PAGE, USER_BASE + 5 * PAGE, "/usr/lib/libc.so.6", "r-x",
         file_backed=True),
    _vma(USER_BASE + 7 * PAGE, USER_BASE + 8 * PAGE, "[stack]", "rw-"),
]


@pytest.fixture
def make_view(tmp_path, monkeypatch):
    (tmp_path / "img.bin").write_bytes(b"\0" * 64)

    def make(runs, kind=ViewKind.PROCESS, vmas=()):
        extra = dict(pid=7, profile=ProfileRef("p.json")) if kind is ViewKind.PROCESS else (
            dict(profile=ProfileRef("p.json")) if kind is ViewKind.KERNEL else {})
        path = ViewDescriptor("img.bin", SHA, kind, **extra).write(
            tmp_path / f"{kind.value}.mdview")
        monkeypatch.setattr(sources, "_default_adapter_factory",
                            lambda d, p: FakeAdapter(runs, vmas))
        return str(path)

    return make


@pytest.fixture
def client(monkeypatch, tmp_path):
    from memdiver.api.config import get_settings
    from memdiver.api.main import create_app

    monkeypatch.delenv("MEMDIVER_ALLOWED_ROOTS", raising=False)
    monkeypatch.setenv("MEMDIVER_UPLOAD_DIR", str(tmp_path / "uploads"))
    get_settings.cache_clear()
    yield TestClient(create_app())
    get_settings.cache_clear()


def _intervals(body):
    return [(r["base_addr"], iv["length"], iv["state"])
            for r in body["regions"] for iv in r["intervals"]]


# -- page states ------------------------------------------------------------


def test_page_states_endpoint_answers_for_an_image_view(client, make_view):
    path = make_view(USER_RUNS, vmas=USER_VMAS)
    resp = client.get("/api/inspect/page-states", params={"msl_path": path})
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert _intervals(body) == [
        (USER_BASE, 2 * PAGE, "CAPTURED"),
        (USER_BASE + 2 * PAGE, PAGE, "NOT_RESIDENT"),
        (USER_BASE + 3 * PAGE, PAGE, "CAPTURED"),
        (USER_BASE + 4 * PAGE, PAGE, "FAILED"),
        (USER_BASE + 7 * PAGE, PAGE, "CAPTURED"),
    ]
    # the frontend derives vaSpanStart as the smallest base_addr: the absolute VA
    assert min(r["base_addr"] for r in body["regions"]) == USER_BASE
    assert body["captured_pages"] == 4 and body["total_pages"] == 6
    assert body["vas_size"] == 4 * PAGE


def test_captured_runs_carry_their_vas_offsets_in_stream_order(client, make_view):
    path = make_view(USER_RUNS, vmas=USER_VMAS)
    body = client.get("/api/inspect/page-states", params={"msl_path": path}).json()
    offsets = [iv["vas_offset"] for r in body["regions"] for iv in r["intervals"]
               if iv["state"] == "CAPTURED"]
    assert offsets == [0, 2 * PAGE, 3 * PAGE]


def test_payload_is_empty_but_well_formed_without_runs():
    assert image_page_states_payload([]) == {
        "regions": [], "total_pages": 0, "captured_pages": 0,
        "coverage": 0.0, "vas_size": 0}


def test_page_states_of_a_missing_view_is_an_error_body_not_a_500(client, tmp_path):
    # /api/inspect/* keeps its legacy contract: a CapabilityError is a 200 + error dict.
    resp = client.get("/api/inspect/page-states",
                      params={"msl_path": str(tmp_path / "nope.mdview")})
    assert resp.status_code == 200
    assert "File not found" in resp.json()["error"]


# -- views offered ----------------------------------------------------------


def _probe(client, path, view):
    return client.get("/api/inspect/hex-raw", params={
        "dump_path": path, "offset": 0, "length": 1, "view": view})


def test_process_view_offers_va(client, make_view):
    path = make_view(USER_RUNS, vmas=USER_VMAS)
    body = _probe(client, path, "raw").json()
    assert body["format"] == "image_view"
    assert body["distinct_views"] == ["vas", "va", "raw"]
    served = _probe(client, path, "va").json()
    assert "error" not in served and served["view"] == "va"


def test_va_is_offered_up_to_the_largest_exact_js_integer(client, make_view):
    top = 2 ** 53 - 1
    path = make_view([LayerRun(top - PAGE, PAGE, C)])
    assert "va" in _probe(client, path, "raw").json()["distinct_views"]


def test_va_is_dropped_when_the_span_exceeds_2_pow_53(client, make_view):
    path = make_view([LayerRun(2 ** 53 - PAGE, 2 * PAGE, C)])
    assert _probe(client, path, "raw").json()["distinct_views"] == ["vas", "raw"]


def test_kernel_view_drops_va_and_refuses_it_as_a_capability_error(client, make_view):
    kernel_base = 0xFFFFFFFF81000000
    path = make_view([LayerRun(kernel_base, PAGE, C)], kind=ViewKind.KERNEL)
    assert _probe(client, path, "raw").json()["distinct_views"] == ["vas", "raw"]
    refused = _probe(client, path, "va").json()
    assert "'va' is not available" in refused["error"]
    assert "bytes" not in refused
    states = client.get("/api/inspect/page-states", params={"msl_path": path}).json()
    assert "'va' is not available" in states["error"]


def test_kernel_view_serves_its_vas_navigation_map_on_request(client, make_view):
    """Found in the browser (phase gate): Vol3 row navigation / column highlights in
    a kernel view's ``vas`` need the VA -> packed-offset map, which the default
    (``va``) request refuses. ``view=vas`` serves it; VAs stay exact integers."""
    kernel_base = 0xFF424DB6C0000000
    runs = [LayerRun(kernel_base, PAGE, C), LayerRun(kernel_base + PAGE, PAGE, F),
            LayerRun(kernel_base + 3 * PAGE, 2 * PAGE, C)]
    path = make_view(runs, kind=ViewKind.KERNEL)
    resp = client.get("/api/inspect/page-states", params={"msl_path": path, "view": "vas"})
    body = json.loads(resp.text)
    assert "error" not in body, body
    ivs = [iv for r in body["regions"] for iv in r["intervals"]]
    assert [(iv["va"], iv["state"], iv.get("vas_offset")) for iv in ivs] == [
        (kernel_base, "CAPTURED", 0), (kernel_base + PAGE, "FAILED", None),
        (kernel_base + 3 * PAGE, "CAPTURED", PAGE)]
    assert '"va":%d' % kernel_base in resp.text.replace(" ", "")


def _kernel_vas_view(make_view):
    base = 0xFF424DB6C0000000
    runs = [LayerRun(base, PAGE, C), LayerRun(base + 3 * PAGE, PAGE, C)]
    return base, make_view(runs, kind=ViewKind.KERNEL)


def test_cli_page_states_serves_the_vas_map_of_a_kernel_view(make_view, tmp_path):
    """Parity: ``inspect page-states --view vas`` == the REST ``view=vas``."""
    import argparse

    from memdiver.cli import _cmd_inspect_page_states

    base, path = _kernel_vas_view(make_view)
    out = tmp_path / "vas.json"
    args = argparse.Namespace(msl_path=path, output=str(out), view="vas")
    assert _cmd_inspect_page_states(args) == 0
    ivs = [iv for r in json.loads(out.read_text())["regions"] for iv in r["intervals"]]
    assert [(iv["va"], iv.get("vas_offset")) for iv in ivs] == [(base, 0), (base + 3 * PAGE, PAGE)]
    args.view = "va"
    _cmd_inspect_page_states(args)
    assert "'va' is not available" in json.loads(out.read_text())["error"]


def test_mcp_get_page_states_accepts_view_vas(make_view):
    from memdiver.mcp_server.server import create_server

    base, path = _kernel_vas_view(make_view)
    tool = create_server()._tool_manager._tools["get_page_states"]
    body = json.loads(tool.fn(msl_path=path, view="vas"))
    assert "error" not in body, body
    assert body["regions"][0]["intervals"][0]["va"] == base
    assert "'va' is not available" in json.loads(tool.fn(msl_path=path))["error"]


def test_page_states_refuses_the_raw_view(client, make_view):
    path = make_view(USER_RUNS)
    body = client.get("/api/inspect/page-states", params={"msl_path": path, "view": "raw"})
    assert body.status_code == 422


def test_view_overrides_do_not_outlive_a_reopen(make_view):
    from memdiver.core.dump_source import distinct_views, open_dump

    path = make_view([LayerRun(2 ** 55, PAGE, C)])
    src = open_dump(path)
    src.open()
    assert distinct_views(src) == ("vas", "raw")
    src.close()
    assert distinct_views(src) == ("vas", "va", "raw")


# -- wizard preview ---------------------------------------------------------


def _preview(client, path):
    return client.post("/api/dumps/preview", json={"path": path})


def test_process_view_preview_classifies_vmas(client, make_view):
    path = make_view(USER_RUNS, vmas=USER_VMAS)
    resp = _preview(client, path)
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["format"] == "image_view"
    # Listed by kind, but never applied: nothing filters a Vol3LayerSource.
    assert body["view_kind"] == "process" and body["selection_applicable"] is False
    cats = {r["base_addr"]: r["category"] for r in body["regions"]}
    assert cats == {USER_BASE: "heap", USER_BASE + 3 * PAGE: "image_code",
                    USER_BASE + 7 * PAGE: "stack"}
    captured = {r["base_addr"]: r["captured_bytes"] for r in body["regions"]}
    assert captured == {USER_BASE: 2 * PAGE, USER_BASE + 3 * PAGE: PAGE,
                        USER_BASE + 7 * PAGE: PAGE}
    assert body["totals"]["heap"] == {"count": 1, "bytes": 2 * PAGE}


def test_process_view_preview_honours_the_selection(client, make_view):
    path = make_view(USER_RUNS, vmas=USER_VMAS)
    body = client.post("/api/dumps/preview",
                       json={"path": path, "regions": "heap"}).json()
    assert body["summary"]["included_count"] == 1
    assert body["summary"]["excluded_count"] == 2


@pytest.mark.parametrize("kind", [ViewKind.PHYSICAL, ViewKind.KERNEL])
def test_physical_and_kernel_previews_have_nothing_to_select(client, make_view, kind):
    path = make_view([LayerRun(0, PAGE, C)], kind=kind)
    body = _preview(client, path).json()
    assert body["format"] == "image_view"
    assert body["view_kind"] == kind.value
    assert body["selection_applicable"] is False
    assert body["regions"] == [] and body["totals"] == {}
