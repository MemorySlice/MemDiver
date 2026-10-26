"""xref.pointers_to: producer + 4 surfaces over a tiny real .msl."""

from __future__ import annotations

import argparse
import io
import json
import struct
import sys
from contextlib import redirect_stdout
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from memdiver.msl.enums import Protection, RegionType  # noqa: E402
from memdiver.msl.writer import MslWriter  # noqa: E402

PAGE = 0x1000
RW = Protection.READ | Protection.WRITE
TARGET = 0x30000100
HOLDER_A = 0x20000040          # word -> TARGET + 8
HOLDER_B = 0x20000800          # word -> TARGET (exact)
HOLDER_SELF = TARGET + 0x10    # inside the target, points into it


@pytest.fixture(scope="module")
def msl(tmp_path_factory):
    path = tmp_path_factory.mktemp("xref") / "d.msl"
    a = bytearray(PAGE)
    a[0x40:0x48] = struct.pack("<Q", TARGET + 8)
    a[0x800:0x808] = struct.pack("<Q", TARGET)
    b = bytearray(PAGE)
    b[0x110:0x118] = struct.pack("<Q", TARGET + 8)
    w = MslWriter(str(path), pid=7, imported=False)
    w.add_memory_region(0x20000000, bytes(a), protection=RW,
                        region_type=int(RegionType.ANONYMOUS))
    w.add_memory_region(0x30000000, bytes(b), protection=RW,
                        region_type=int(RegionType.HEAP))
    w.add_end_of_capture()
    w.write()
    return str(path)


def _produce(msl, **kw):
    import memdiver

    kw.setdefault("target_va", TARGET)
    kw.setdefault("span_after", 0x20)
    return memdiver.services.xref_pointers_result(
        memdiver.ToolSession(), dump_path=msl, **kw)


def test_producer_finds_holders_with_region_and_coverage(msl):
    payload = json.loads(json.dumps(_produce(msl).payload))
    got = {r["holder_va"]: r for r in payload["refs"]}
    assert set(got) == {HOLDER_A, HOLDER_B, HOLDER_SELF}
    assert got[HOLDER_A]["target_delta"] == 8
    assert got[HOLDER_A]["holder_va_hex"] == hex(HOLDER_A)
    assert got[HOLDER_A]["holder_region"] == {
        "va": 0x20000000, "va_hex": hex(0x20000000), "length": PAGE}
    cov = payload["coverage"]
    assert cov["scanned_bytes"] == 2 * PAGE and cov["scanned_runs"] == 2
    assert cov["uncaptured_gap_bytes"] == 0x30000000 - 0x20001000
    assert cov["truncated"] is False
    assert payload["params"]["span_after"] == 0x20


def test_span_before_exclude_and_truncation(msl):
    res = _produce(msl, target_va=TARGET + 8, span_before=8, span_after=1)
    assert len(res.payload["refs"]) == 3
    res = _produce(msl, exclude_target=True)
    assert HOLDER_SELF not in {r["holder_va"] for r in res.payload["refs"]}
    res = _produce(msl, max_refs=1)
    assert len(res.payload["refs"]) == 1 and res.payload["coverage"]["truncated"]


def test_producer_errors(msl, tmp_path):
    from memdiver.core.service_errors import CapabilityError

    raw = tmp_path / "r.bin"
    raw.write_bytes(b"\x00" * 64)
    with pytest.raises(CapabilityError) as ei:
        _produce(str(raw))
    assert ei.value.code == "xref.no_va_view"
    with pytest.raises(CapabilityError):
        _produce(msl, word_size=3)
    with pytest.raises(CapabilityError):
        _produce("/nonexistent/x.msl")


def test_registry_and_library_export():
    import memdiver
    from memdiver.app.capabilities import CAPABILITIES

    assert "xref_pointers_result" in memdiver.services.__all__
    assert "xref.pointers_to" in {c.name for c in CAPABILITIES}


def test_web_route(msl, tmp_path):
    from fastapi.testclient import TestClient
    from memdiver.api.main import create_app

    client = TestClient(create_app())
    body = {"dump_path": msl, "target_va": TARGET, "span_after": 0x20}
    resp = client.post("/api/inspect/xref/pointers", json=body)
    assert resp.status_code == 200, resp.text
    assert len(resp.json()["refs"]) == 3
    raw = tmp_path / "r.bin"
    raw.write_bytes(b"\x00" * 64)
    bad = client.post("/api/inspect/xref/pointers", json={**body, "dump_path": str(raw)})
    assert bad.status_code == 400


def test_mcp_tool(msl):
    pytest.importorskip("mcp")
    from memdiver.mcp_server.server import create_server

    tools = {t.name: t for t in create_server()._tool_manager.list_tools()}
    out = json.loads(tools["xref_pointers"].fn(
        dump_path=msl, target_va=TARGET, span_after=0x20))
    assert len(out["refs"]) == 3


def test_cli(msl, tmp_path):
    from memdiver.cli.inspect import _cmd_xref_pointers
    from memdiver.cli.main import build_parser

    out_file = tmp_path / "o.json"
    args = build_parser().parse_args(
        ["xref-pointers", msl, "--target", hex(TARGET), "--after", "0x20",
         "-o", str(out_file)])
    assert isinstance(args, argparse.Namespace)
    with redirect_stdout(io.StringIO()):
        assert _cmd_xref_pointers(args) == 0
    assert len(json.loads(out_file.read_text())["refs"]) == 3
    raw = tmp_path / "r.bin"
    raw.write_bytes(b"\x00" * 64)
    args = build_parser().parse_args(["xref-pointers", str(raw), "--target", "0x10"])
    with redirect_stdout(io.StringIO()):
        assert _cmd_xref_pointers(args) == 1
