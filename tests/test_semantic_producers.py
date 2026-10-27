"""semantic.propose_layout + artifact_model.build: producers and 4 surfaces over tiny .msl."""

from __future__ import annotations

import argparse
import hashlib
import io
import json
import sys
from contextlib import redirect_stdout
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from memdiver.core.service_errors import CapabilityError, ErrorCategory  # noqa: E402
from memdiver.msl.enums import Protection, RegionType  # noqa: E402
from memdiver.msl.writer import MslWriter  # noqa: E402

PAGE = 0x1000
RW = Protection.READ | Protection.WRITE
ANCHOR_AT = 0x800        # anchor offset inside the page
RANDOM_DELTA = -0x20     # client_random sits 0x20 before the anchor
N = 4


def _rand(tag: str, i: int, n: int) -> bytes:
    return hashlib.sha256(f"{tag}{i}".encode()).digest()[:n]


def _page(i: int) -> tuple[bytes, bytes, bytes]:
    anchor, crand = _rand("key", i, 16), _rand("rnd", i, 8)
    page = bytearray(b"\x11" * PAGE)
    page[0x600:0x7C0] = hashlib.sha256(b"var%d" % i).digest() * 14   # volatile area
    page[ANCHOR_AT:ANCHOR_AT + 16] = anchor
    page[ANCHOR_AT + RANDOM_DELTA:ANCHOR_AT + RANDOM_DELTA + 8] = crand
    return bytes(page), anchor, crand


@pytest.fixture(scope="module")
def corpus(tmp_path_factory):
    root = tmp_path_factory.mktemp("semantic")
    paths, needles, related = [], {}, {}
    for i in range(N):
        page, anchor, crand = _page(i)
        path = str(root / f"d{i}.msl")
        w = MslWriter(path, pid=7, imported=False)
        w.add_memory_region(0x20000000 + i * 0x40000, page, protection=RW,
                            region_type=int(RegionType.ANONYMOUS))
        w.add_end_of_capture()
        w.write()
        paths.append(path)
        needles[path] = anchor.hex()
        related[path] = crand.hex()
    return {"paths": paths, "needles": needles, "related": {"client_random": related}}


def _session():
    from memdiver.app.composition import build_tool_session
    return build_tool_session()


def _propose(corpus, **kw):
    from memdiver.app.tools_semantic import propose_layout_result
    args = dict(needles=corpus["needles"], delta_start=-0x100, length=0x300,
                related=corpus["related"], heap=False, detail="full")
    args.update(kw)
    return propose_layout_result(_session(), **args)


def _field(payload, kind):
    return [f for f in payload["fields"] if f["kind"] == kind]


def test_propose_happy_path_and_anchor_length_default(corpus):
    payload = _propose(corpus).payload
    anchor = _field(payload, "anchor")[0]
    assert anchor["delta"] == 0 and anchor["length"] == 16   # needle length
    assert payload["anchor_length"] == 16
    rnd = _field(payload, "verified_field")[0]
    assert rnd["name"] == "client_random" and rnd["delta"] == RANDOM_DELTA
    assert len(payload["instances"]) == N and payload["unanchored"] == []
    assert sum(payload["class_counts"].values()) == payload["length"]
    assert payload["structure"]["fields"]


def test_explicit_anchors_require_anchor_length(corpus):
    from memdiver.app.tools_semantic import propose_layout_result
    anchors = [{"dump_path": p, "va": 0x20000000 + i * 0x40000 + ANCHOR_AT}
               for i, p in enumerate(corpus["paths"])]
    with pytest.raises(CapabilityError) as exc:
        propose_layout_result(_session(), anchors=anchors, delta_start=-0x100,
                              length=0x300, heap=False)
    assert exc.value.category is ErrorCategory.INVALID_INPUT
    ok = propose_layout_result(_session(), anchors=anchors, anchor_length=16,
                               delta_start=-0x100, length=0x300, heap=False)
    assert _field(ok.payload, "anchor")[0]["length"] == 16


def test_record_entries_written(corpus, tmp_path):
    from memdiver.analysis.record import STRUCTURE_PROPOSAL
    from memdiver.analysis.record_store import AnalysisRecord
    case = tmp_path / "case"
    payload = _propose(corpus, case_dir=str(case)).payload
    assert len(payload["record_entries"]) == N
    entries = [json.loads(line) for f in (case / "annotations").glob("*.jsonl")
               for line in f.read_text().splitlines()]
    assert len(entries) == N
    assert {e["kind"] for e in entries} == {STRUCTURE_PROPOSAL}
    assert entries[0]["payload"]["fields"] and entries[0]["locations"][0]["space"] == "msl_va"
    assert entries[0]["support"][0]["kind"] == "observation"
    assert AnalysisRecord  # the store the entries live in


def _build(corpus, out, **kw):
    from memdiver.app.tools_semantic import artifact_model_build_result
    args = dict(
        needles=corpus["needles"], delta_start=-0x100, length=0x300,
        related=corpus["related"], heap=False, name="demo_obj", out_path=str(out),
        meanings=[{"field": "anchor", "meaning": "demo.key", "label": "KEY",
                   "support": [{"kind": "ground_truth", "ref": "keylog"}]},
                  {"field": "client_random", "meaning": "demo.random"}],
        relationships=[{"kind": "owned_by", "source": "anchor", "target": "client_random"}],
        applicability={"library": "demo", "states": ["post_handshake"]})
    args.update(kw)
    return artifact_model_build_result(_session(), **args)


def test_model_build_writes_clean_model(corpus, tmp_path):
    from memdiver.architect.artifact_model import ArtifactModel
    out = tmp_path / "m.json"
    payload = _build(corpus, out).payload
    assert Path(payload["path"]) == out and payload["problems"] == []
    assert hashlib.sha256(out.read_bytes()).hexdigest() == payload["sha256"]
    model = ArtifactModel.from_dict(json.loads(out.read_text()))
    assert model.check() == [] and model.applicability.states == ("post_handshake",)


def test_builder_refusal_maps_to_invalid_input(corpus, tmp_path):
    out = tmp_path / "bad.json"
    with pytest.raises(CapabilityError) as exc:
        _build(corpus, out, relationships=[
            {"kind": "owned_by", "source": "anchor", "target": "nonexistent"}])
    assert exc.value.category is ErrorCategory.INVALID_INPUT
    assert "unproposed field" in str(exc.value)
    assert not out.exists()


def test_out_path_must_be_new_json(corpus, tmp_path):
    existing = tmp_path / "e.json"
    existing.write_text("{}")
    for bad in (str(existing), str(tmp_path / "m.txt"), ""):
        with pytest.raises(CapabilityError) as exc:
            _build(corpus, bad)
        assert exc.value.category is ErrorCategory.INVALID_INPUT
    assert existing.read_text() == "{}"


# -- surfaces ----------------------------------------------------------------

def test_library_surface_exports():
    import memdiver.services as services
    assert {"propose_layout_result", "artifact_model_build_result"} <= set(services.__all__)


def test_web_routes(corpus, tmp_path):
    from fastapi.testclient import TestClient
    from memdiver.api.main import create_app

    client = TestClient(create_app())
    body = {"needles": corpus["needles"], "delta_start": -0x100, "length": 0x300,
            "related": corpus["related"], "heap": False}
    resp = client.post("/api/semantic/propose-layout", json=body)
    assert resp.status_code == 200, resp.text
    assert _field(resp.json(), "anchor")
    missing = {**body, "needles": {str(tmp_path / "nope.msl"): "aa" * 8,
                                   corpus["paths"][0]: "aa" * 8}}
    assert client.post("/api/semantic/propose-layout", json=missing).status_code == 404
    build = {**body, "name": "demo_obj", "out_path": str(tmp_path / "w.json"),
             "meanings": [{"field": "anchor", "meaning": "demo.key"}]}
    ok = client.post("/api/semantic/model-build", json=build)
    assert ok.status_code in (200, 403), ok.text   # 403 only if a write root is configured


def test_mcp_tools(corpus, tmp_path):
    pytest.importorskip("mcp")
    from memdiver.mcp_server.server import create_server

    tools = {t.name: t for t in create_server()._tool_manager.list_tools()}
    out = json.loads(tools["propose_layout"].fn(
        needles=corpus["needles"], delta_start=-0x100, length=0x300,
        related=corpus["related"], heap=False))
    assert _field(out, "anchor")
    target = tmp_path / "mcp.json"
    built = json.loads(tools["artifact_model_build"].fn(
        name="demo_obj", out_path=str(target), needles=corpus["needles"],
        delta_start=-0x100, length=0x300, related=corpus["related"], heap=False,
        meanings=[{"field": "anchor", "meaning": "demo.key"}]))
    assert built["problems"] == [] and target.is_file()


def test_cli_commands(corpus, tmp_path):
    from memdiver.cli.main import build_parser
    from memdiver.cli.semantic import _cmd_model_build, _cmd_propose_layout

    (tmp_path / "n.json").write_text(json.dumps(corpus["needles"]))
    (tmp_path / "r.json").write_text(json.dumps(corpus["related"]))
    (tmp_path / "s.json").write_text(json.dumps({
        "meanings": [{"field": "anchor", "meaning": "demo.key"}],
        "relationships": [{"kind": "owned_by", "source": "anchor", "target": "client_random"}],
        "applicability": {"library": "demo"}}))
    common = [*corpus["paths"], "--needles-file", str(tmp_path / "n.json"),
              "--related-file", str(tmp_path / "r.json"), "--delta-start", "-256",
              "--length", "768", "--no-heap"]
    out = tmp_path / "p.json"
    args = build_parser().parse_args(["propose-layout", *common, "-o", str(out)])
    assert isinstance(args, argparse.Namespace)
    with redirect_stdout(io.StringIO()):
        assert _cmd_propose_layout(args) == 0
    assert _field(json.loads(out.read_text()), "verified_field")
    model = tmp_path / "cli_model.json"
    args = build_parser().parse_args(
        ["model-build", *common, "--name", "demo_obj", "--spec-file",
         str(tmp_path / "s.json"), "--out-path", str(model)])
    with redirect_stdout(io.StringIO()):
        assert _cmd_model_build(args) == 0
    assert model.is_file()
    with redirect_stdout(io.StringIO()):   # second run: the model exists -> refused
        assert _cmd_model_build(args) == 1


# -- review regressions ----------------------------------------------------------

def test_raw_dump_refused_with_no_va_view(tmp_path):
    from memdiver.app.tools_semantic import artifact_model_build_result, propose_layout_result
    needles = {}
    for i in range(2):
        path = tmp_path / f"r{i}.bin"
        data = bytearray(b"\x11" * 0x400)
        data[0x200:0x210] = _rand("key", i, 16)
        path.write_bytes(bytes(data))
        needles[str(path)] = bytes(data[0x200:0x210]).hex()
    with pytest.raises(CapabilityError) as exc:
        propose_layout_result(_session(), needles=needles, delta_start=-0x100, length=0x200, heap=False)
    assert exc.value.category is ErrorCategory.PRECONDITION and exc.value.code == "semantic.no_va_view"
    with pytest.raises(CapabilityError) as exc:
        artifact_model_build_result(_session(), needles=needles, delta_start=-0x100, length=0x200,
                                    heap=False, name="n", out_path=str(tmp_path / "m.json"))
    assert exc.value.code == "semantic.no_va_view"


def test_window_missing_the_anchor_is_invalid_input_not_500(corpus):
    with pytest.raises(CapabilityError) as exc:
        _propose(corpus, delta_start=16, length=0x300)
    assert exc.value.category is ErrorCategory.INVALID_INPUT
