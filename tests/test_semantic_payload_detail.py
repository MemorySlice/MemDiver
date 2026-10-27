"""detail=summary|full on propose_layout / artifact_model_build across the 4 surfaces."""

from __future__ import annotations

import hashlib
import io
import json
import sys
from contextlib import ExitStack, redirect_stdout
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from memdiver.core.service_errors import CapabilityError, ErrorCategory  # noqa: E402
from memdiver.msl.enums import Protection, RegionType  # noqa: E402
from memdiver.msl.writer import MslWriter  # noqa: E402

PAGE, ANCHOR_AT, N = 0x1000, 0x800, 4
RW = Protection.READ | Protection.WRITE
PROPOSE_OMITTED = ["structure", "alternatives", "fields[].evidence", "fields[].alternatives"]
UI_KEYS = {"instances", "unanchored", "warnings", "class_counts", "base_delta",
           "total_size", "bounds_evidence", "anchor_length", "fields"}


def _rand(tag: str, i: int, n: int) -> bytes:
    return hashlib.sha256(f"{tag}{i}".encode()).digest()[:n]


@pytest.fixture(scope="module")
def corpus(tmp_path_factory):
    root = tmp_path_factory.mktemp("detail")
    paths, needles, related = [], {}, {}
    for i in range(N):
        anchor, crand = _rand("key", i, 16), _rand("rnd", i, 8)
        page = bytearray(b"\x11" * PAGE)
        page[0x600:0x7C0] = hashlib.sha256(b"var%d" % i).digest() * 14
        page[ANCHOR_AT:ANCHOR_AT + 16] = anchor
        page[ANCHOR_AT - 0x20:ANCHOR_AT - 0x18] = crand
        path = str(root / f"d{i}.msl")
        w = MslWriter(path, pid=7, imported=False)
        w.add_memory_region(0x20000000 + i * 0x40000, bytes(page), protection=RW,
                            region_type=int(RegionType.ANONYMOUS))
        w.add_end_of_capture()
        w.write()
        paths.append(path)
        needles[path], related[path] = anchor.hex(), crand.hex()
    return {"paths": paths, "needles": needles, "related": {"client_random": related}}


def _kw(corpus):
    return dict(needles=corpus["needles"], delta_start=-0x100, length=0x300,
                related=corpus["related"], heap=False)


def _session():
    from memdiver.app.composition import build_tool_session
    return build_tool_session()


def _propose(corpus, **kw):
    from memdiver.app.tools_semantic import propose_layout_result
    return propose_layout_result(_session(), **_kw(corpus), **kw).payload


def _build(corpus, out, **kw):
    from memdiver.app.tools_semantic import artifact_model_build_result
    return artifact_model_build_result(
        _session(), **_kw(corpus), name="demo_obj", out_path=str(out),
        meanings=[{"field": "anchor", "meaning": "demo.key"}], **kw).payload


def _internal_full(corpus, name="proposed_layout"):
    from memdiver.app import tools_semantic as S
    kw = _kw(corpus)
    with ExitStack() as stack:
        learned = S._learn(
            stack, dump_paths=None, needles=kw["needles"], anchors=None, occurrence=0,
            delta_start=kw["delta_start"], length=kw["length"], anchor_length=None,
            related=kw["related"], pointer_quorum=None, heap=False, mixed_ok=False)
    return S._proposal_payload(learned, name)


def test_propose_summary_is_default_and_marked(corpus):
    full, summary = _propose(corpus, detail="full"), _propose(corpus)
    assert summary["detail"] == "summary" and summary["omitted"] == PROPOSE_OMITTED
    assert "detail=" in summary["omitted_hint"] or 'detail="full"' in summary["omitted_hint"]
    assert not {"structure", "alternatives"} & set(summary)
    assert UI_KEYS <= set(summary)
    assert summary["alternatives_count"] == len(full["alternatives"])
    assert summary["instances"] == full["instances"]
    for s, f in zip(summary["fields"], full["fields"]):
        assert set(s) == {"name", "kind", "delta", "length", "alternatives_count"}
        assert s["alternatives_count"] == len(f["alternatives"])
        assert (s["name"], s["delta"], s["length"]) == (f["name"], f["delta"], f["length"])
    assert len(json.dumps(summary)) < len(json.dumps(full))


def test_propose_full_is_byte_identical_to_internals(corpus):
    full = _propose(corpus, detail="full")
    assert json.dumps(full) == json.dumps(_internal_full(corpus))
    assert "detail" not in full and "omitted" not in full


def test_build_summary_and_full(corpus, tmp_path):
    summary = _build(corpus, tmp_path / "s.json")
    assert summary["detail"] == "summary" and summary["omitted"] == ["model", "proposal"]
    assert not {"model", "proposal"} & set(summary) and summary["problems"] == []
    ms = summary["model_summary"]
    assert ms["name"] == "demo_obj" and ms["field_count"] > 0 and ms["total_size"]
    assert ms["locator"]["kind"] == "structure" and ms["locator"]["primary"]["key_length"]
    assert Path(summary["path"]).is_file()
    assert hashlib.sha256(Path(summary["path"]).read_bytes()).hexdigest() == summary["sha256"]
    full = _build(corpus, tmp_path / "f.json", detail="full")
    assert {"model", "proposal"} <= set(full) and "detail" not in full
    assert full["proposal"] == _internal_full(corpus, "demo_obj")
    assert ms["field_count"] == len(full["proposal"]["fields"])


@pytest.mark.parametrize("bad", ["", "Summary", "everything", None])
def test_invalid_detail_refused(corpus, tmp_path, bad):
    with pytest.raises(CapabilityError) as exc:
        _propose(corpus, detail=bad)
    assert exc.value.category == ErrorCategory.INVALID_INPUT
    with pytest.raises(CapabilityError):
        _build(corpus, tmp_path / "bad.json", detail=bad)
    assert not (tmp_path / "bad.json").exists()


def test_web_detail(corpus, tmp_path):
    from fastapi.testclient import TestClient
    from memdiver.api.main import create_app

    client = TestClient(create_app())
    body = {"needles": corpus["needles"], "delta_start": -0x100, "length": 0x300,
            "related": corpus["related"], "heap": False}
    default = client.post("/api/semantic/propose-layout", json=body)
    assert default.status_code == 200 and "structure" not in default.json()   # parity: summary
    assert default.json()["detail"] == "summary"
    assert default.json()["omitted"] == PROPOSE_OMITTED
    full = client.post("/api/semantic/propose-layout", json={**body, "detail": "full"})
    assert full.status_code == 200 and "structure" in full.json()
    summary = client.post("/api/semantic/propose-layout", json={**body, "detail": "summary"})
    assert summary.json()["omitted"] == PROPOSE_OMITTED
    bad = client.post("/api/semantic/propose-layout", json={**body, "detail": "x"})
    assert bad.status_code in (400, 422), bad.text
    build = {**body, "name": "demo_obj", "out_path": str(tmp_path / "w.json"),
             "detail": "summary", "meanings": [{"field": "anchor", "meaning": "demo.key"}]}
    ok = client.post("/api/semantic/model-build", json=build)
    assert ok.status_code in (200, 403), ok.text
    if ok.status_code == 200:
        assert ok.json()["omitted"] == ["model", "proposal"]


def test_mcp_detail(corpus, tmp_path):
    pytest.importorskip("mcp")
    from memdiver.mcp_server.server import create_server

    tools = {t.name: t for t in create_server()._tool_manager.list_tools()}
    kw = _kw(corpus)
    out = json.loads(tools["propose_layout"].fn(**kw))
    assert out["detail"] == "summary" and out["omitted"] == PROPOSE_OMITTED
    full = json.loads(tools["propose_layout"].fn(**kw, detail="full"))
    assert "structure" in full and "omitted" not in full
    built = json.loads(tools["artifact_model_build"].fn(
        name="demo_obj", out_path=str(tmp_path / "m.json"), **kw))
    assert built["omitted"] == ["model", "proposal"] and built["model_summary"]
    err = json.loads(tools["propose_layout"].fn(**kw, detail="nope"))
    assert "detail" in json.dumps(err)


def test_cli_detail(corpus, tmp_path):
    from memdiver.cli.main import build_parser
    from memdiver.cli.semantic import _cmd_model_build, _cmd_propose_layout

    (tmp_path / "n.json").write_text(json.dumps(corpus["needles"]))
    (tmp_path / "r.json").write_text(json.dumps(corpus["related"]))
    common = [*corpus["paths"], "--needles-file", str(tmp_path / "n.json"),
              "--related-file", str(tmp_path / "r.json"), "--delta-start", "-256",
              "--length", "768", "--no-heap"]
    parse = build_parser().parse_args
    for extra, expect_full in (([], False), (["--detail", "full"], True)):
        out = tmp_path / f"p{expect_full}.json"
        with redirect_stdout(io.StringIO()):
            assert _cmd_propose_layout(parse(["propose-layout", *common, *extra, "-o", str(out)])) == 0
        assert ("structure" in json.loads(out.read_text())) is expect_full
    out = tmp_path / "b.json"
    with redirect_stdout(io.StringIO()):
        assert _cmd_model_build(parse(["model-build", *common, "--name", "demo_obj",
                                       "--out-path", str(tmp_path / "cm.json"),
                                       "-o", str(out)])) == 0
    assert json.loads(out.read_text())["omitted"] == ["model", "proposal"]
    with pytest.raises(SystemExit):
        with redirect_stdout(io.StringIO()), pytest.MonkeyPatch.context() as mp:
            mp.setattr(sys, "stderr", io.StringIO())
            parse(["propose-layout", *common, "--detail", "bogus"])
