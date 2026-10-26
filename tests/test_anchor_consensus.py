"""Anchor-relative consensus: engine (fake sources) + producer + 4 surfaces."""

from __future__ import annotations

import argparse
import io
import json
import sys
from contextlib import redirect_stdout
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from memdiver.engine.anchor_consensus import (  # noqa: E402
    UNDETERMINED, Anchor, anchor_consensus, anchors_from_needles, read_instance,
    search_needles,
)

KEY = bytes(range(0xA0, 0xB0))


class FakeSource:
    """Flat byte buffer; optional ``holes`` [(start, end)) are uncaptured."""

    def __init__(self, data: bytes, base: int = 0, holes=()):
        self.data, self.base, self.holes = data, base, list(holes)

    def va_span_start(self):
        return self.base

    def read_range(self, offset, length, view="va"):
        return self.read_range_valid(offset, length, view)[0]

    def read_range_valid(self, offset, length, view="va"):
        out = bytearray(length)
        runs = []
        for i in range(length):
            pos = offset + i
            if 0 <= pos < len(self.data) and not any(a <= pos < b for a, b in self.holes):
                out[i] = self.data[pos]
                if runs and runs[-1][0] + runs[-1][1] == i:
                    runs[-1] = (runs[-1][0], runs[-1][1] + 1)
                else:
                    runs.append((i, 1))
        return bytes(out), runs

    def find_all(self, needle, view="va", limit=0):
        hits, start = [], 0
        while (i := self.data.find(needle, start)) >= 0:
            hits.append(i)
            start = i + 1
        return hits[:limit] if limit else hits


def _blob(shift: int, noise: int, size: int = 400) -> bytes:
    """Object = 8 noisy bytes + KEY, placed at ``shift``; rest noisy."""
    buf = bytearray((noise * 7 + i * 13) % 251 for i in range(size))
    buf[shift:shift + 8] = bytes([0x11] * 8)
    buf[shift + 8:shift + 24] = KEY
    return bytes(buf)


def _sources():
    return {f"d{i}": FakeSource(_blob(40 + 30 * i, i)) for i in range(3)}


def _windows(sources, **kw):
    needles = {p: KEY for p in sources}
    anchors = anchors_from_needles(sources, needles)
    return [read_instance(sources[p], a[0], kw.get("delta_start", -8),
                          kw.get("length", 40)) for p, a in anchors.items()]


def test_shifted_object_is_invariant_by_delta():
    cons = anchor_consensus(_windows(_sources()), delta_start=-8)
    assert cons.class_at(0) == "invariant"
    assert cons.class_at(15) == "invariant"
    assert cons.class_at(-8) == "invariant"          # the 0x11 prefix
    assert cons.distinct_values[8] == 1
    assert cons.class_at(16) != "invariant"          # past the key: noise


def test_distinct_values_counts_values():
    cons = anchor_consensus(_windows(_sources()), delta_start=-8)
    assert cons.distinct_values[-1] >= 2


def test_hole_is_undetermined_not_zero_then_determined_with_lower_min():
    sources = _sources()
    anchor_off = 40 + 8 + 0                          # d0's key start
    sources["d0"] = FakeSource(_blob(40, 0), holes=[(anchor_off + 4, anchor_off + 6)])
    wins = _windows(sources)
    strict = anchor_consensus(wins, delta_start=-8)
    assert strict.class_at(4) == "undetermined"
    assert strict.classes[12] == UNDETERMINED
    assert strict.captured_count[12] == 2
    assert wins[0].captured_bytes == 38
    relaxed = anchor_consensus(wins, delta_start=-8, min_instances=2)
    assert relaxed.class_at(4) == "invariant"        # the zeros did not leak in


def test_window_clipped_before_view_origin():
    src = FakeSource(KEY + b"\x01" * 40)
    win = read_instance(src, Anchor("p", 0, "va"), -4, 8)
    assert win.captured.tolist() == [False] * 4 + [True] * 4
    assert win.data[:4] == b"\x00" * 4


def test_window_fully_before_origin_is_uncaptured():
    win = read_instance(FakeSource(KEY), Anchor("p", 0, "va"), -50, 8)
    assert win.captured_bytes == 0


def test_anchors_from_needles_returns_all_occurrences_with_basis_and_va():
    src = FakeSource(b"xx" + KEY + b"yy" + KEY, base=0x1000)
    out = anchors_from_needles({"p": src}, {"p": KEY})["p"]
    assert [a.offset for a in out] == [2, 20]
    assert [a.va for a in out] == [0x1002, 0x1014]
    assert "occurrence 1 of 2" in out[1].basis


def test_engine_errors():
    wins = _windows(_sources())
    with pytest.raises(ValueError):
        anchor_consensus(wins[:1], delta_start=0)
    with pytest.raises(ValueError):
        anchor_consensus(wins, delta_start=0, min_instances=1)
    with pytest.raises(ValueError):
        anchor_consensus(wins, delta_start=0, min_instances=9)


def test_regions_are_keyed_by_delta():
    cons = anchor_consensus(_windows(_sources()), delta_start=-8)
    row = next(r for r in cons.regions() if r["class"] == "invariant")
    assert row["delta_start"] == -8 and row["delta_end"] == 16


# ---------------------------------------------------------------------------
# Producer + surfaces (flat files: view "raw")
# ---------------------------------------------------------------------------


@pytest.fixture(scope="module")
def dumps(tmp_path_factory):
    root = tmp_path_factory.mktemp("anchor_consensus")
    paths = []
    for i in range(3):
        p = root / f"run_{i}.bin"
        p.write_bytes(_blob(40 + 30 * i, i))
        paths.append(str(p))
    return paths


def _produce(dumps, **kw):
    import memdiver

    kw.setdefault("needles", {p: KEY.hex() for p in dumps})
    kw.setdefault("delta_start", -8)
    kw.setdefault("length", 40)
    return memdiver.services.anchor_consensus_result(memdiver.ToolSession(), **kw)


def test_producer_payload_shape_and_json(dumps):
    res = _produce(dumps, include_bytes=True)
    payload = json.loads(json.dumps(res.payload))
    assert len(payload["instances"]) == 3
    assert payload["unanchored"] == []
    assert payload["class_counts"]["invariant"] >= 24
    assert payload["alternatives"] == {p: 1 for p in dumps}
    assert payload["reference_hex"][16:48] == KEY.hex()
    assert len(payload["classes"]) == 40


def test_producer_lists_unanchored_and_partial(dumps):
    from memdiver.core.service_result import Resolution

    needles = {p: KEY.hex() for p in dumps[:2]}
    needles[dumps[2]] = "ee" * 16
    res = _produce(dumps, needles=needles)
    assert res.status.resolution is Resolution.PARTIAL
    assert [u["dump_path"] for u in res.payload["unanchored"]] == [dumps[2]]
    assert len(res.payload["instances"]) == 2


def test_producer_explicit_offset_anchors(dumps):
    anchors = [{"dump_path": p, "offset": 48 + 30 * i} for i, p in enumerate(dumps)]
    res = _produce(dumps, needles=None, anchors=anchors)
    assert res.payload["class_counts"]["invariant"] >= 16


def test_producer_errors(dumps):
    from memdiver.core.service_errors import CapabilityError

    for kw in ({"anchors": [], "needles": {}}, {"length": 1 << 21},
               {"min_instances": 1}, {"needles": {dumps[0]: KEY.hex()}},
               {"needles": {p: "zz" for p in dumps}}):
        with pytest.raises(CapabilityError):
            _produce(dumps, **kw)
    with pytest.raises(CapabilityError):
        _produce(dumps, needles=None, anchors=None)


def test_registry_and_library_export():
    import memdiver
    from memdiver.app.capabilities import CAPABILITIES

    assert "anchor_consensus_result" in memdiver.services.__all__
    assert "consensus.anchor" in {c.name for c in CAPABILITIES}


def test_web_route(dumps):
    from fastapi.testclient import TestClient
    from memdiver.api.main import create_app

    client = TestClient(create_app())
    body = {"needles": {p: KEY.hex() for p in dumps}, "delta_start": -8, "length": 40}
    resp = client.post("/api/analysis/consensus/anchor", json=body)
    assert resp.status_code == 200, resp.text
    assert len(resp.json()["instances"]) == 3
    bad = client.post("/api/analysis/consensus/anchor", json={**body, "length": 1 << 21})
    assert bad.status_code == 400
    both = client.post("/api/analysis/consensus/anchor", json={**body, "anchors": []})
    assert both.status_code == 400
    gone = client.post("/api/analysis/consensus/anchor",
                       json={"needles": {"/nonexistent/a": "00", "/nonexistent/b": "00"}})
    assert gone.status_code == 404


def test_mcp_tool(dumps):
    pytest.importorskip("mcp")
    from memdiver.mcp_server.server import create_server

    tools = {t.name: t for t in create_server()._tool_manager.list_tools()}
    out = json.loads(tools["anchor_consensus"].fn(
        needles={p: KEY.hex() for p in dumps}, delta_start=-8, length=40))
    assert len(out["instances"]) == 3


def test_cli(dumps, tmp_path):
    from memdiver.cli.consensus import _cmd_consensus_anchor
    from memdiver.cli.main import build_parser

    out_file = tmp_path / "o.json"
    needle_file = tmp_path / "n.json"
    needle_file.write_text(json.dumps({p: KEY.hex() for p in dumps}))
    args = build_parser().parse_args(
        ["consensus-anchor", *dumps, "--needle-file", str(needle_file),
         "--delta-start", "-8", "--length", "40", "-o", str(out_file)])
    assert isinstance(args, argparse.Namespace)
    with redirect_stdout(io.StringIO()):
        assert _cmd_consensus_anchor(args) == 0
    assert len(json.loads(out_file.read_text())["instances"]) == 3
    args = build_parser().parse_args(
        ["consensus-anchor", *dumps, "--needle", "ee" * 16, "--length", "40"])
    with redirect_stdout(io.StringIO()):
        assert _cmd_consensus_anchor(args) == 1


# ---------------------------------------------------------------------------
# Search cap must never read as "absent"; dump_paths must be honoured
# ---------------------------------------------------------------------------


def _many_keys(n: int) -> bytes:
    return b"".join(KEY + b"\x00\x01" for _ in range(n))


def test_163_hits_are_not_capped_to_16():
    src = FakeSource(_many_keys(163))
    out = search_needles({"p": src}, {"p": KEY})["p"]
    assert len(out.anchors) == 163 and not out.truncated
    assert len(anchors_from_needles({"p": src}, {"p": KEY})["p"]) == 163


def test_capped_search_is_flagged_and_basis_says_so():
    src = FakeSource(_many_keys(10))
    out = search_needles({"p": src}, {"p": KEY}, max_hits=4)["p"]
    assert out.truncated and out.cap == 4 and len(out.anchors) == 4
    assert "\u22654" in out.anchors[1].basis and "search capped" in out.anchors[1].basis
    full = search_needles({"p": src}, {"p": KEY}, max_hits=10)["p"]
    assert not full.truncated and "occurrence 1 of 10" in full.anchors[1].basis


@pytest.fixture
def many_dumps(tmp_path):
    paths = []
    for i in range(2):
        p = tmp_path / f"m{i}.bin"
        p.write_bytes(_many_keys(10))
        paths.append(str(p))
    return paths


def test_producer_occurrence_beyond_cap_is_not_searched_not_absent(many_dumps, monkeypatch):
    from memdiver.core.service_errors import CapabilityError
    from memdiver.engine import anchor_consensus as ac

    monkeypatch.setattr(ac, "DEFAULT_MAX_HITS", 4)
    ok = _produce(many_dumps, needles={p: KEY.hex() for p in many_dumps},
                  occurrence=2, delta_start=0, length=16)
    assert ok.payload["alternatives_truncated"] == {p: True for p in many_dumps}
    assert ok.payload["alternatives"] == {p: 4 for p in many_dumps}
    with pytest.raises(CapabilityError, match="not searched beyond 4 hits"):
        _produce(many_dumps, needles={p: KEY.hex() for p in many_dumps},
                 occurrence=6, delta_start=0, length=16)


def test_producer_reports_untruncated_search(dumps):
    res = _produce(dumps)
    assert res.payload["alternatives_truncated"] == {p: False for p in dumps}


def test_producer_honours_dump_paths_and_reports_dropped(dumps):
    res = _produce(dumps, dump_paths=dumps[:2])
    assert [i["dump_path"] for i in res.payload["instances"]] == dumps[:2]
    assert res.payload["outside_dump_paths"] == [dumps[2]]
    assert _produce(dumps).payload["outside_dump_paths"] == []
