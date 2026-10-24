"""An aligned ``"va"`` window may START on a byte the anchor never captured.

The anchor's ``"va"`` view is the whole VA span; the single-dump view shows an
inter-region gap as UNMAPPED and a FAILED / NOT_RESIDENT / UNMAPPED page as
itself. A window whose first byte sits there is still a window: the
uncaptured stretch is ``gaps`` (zero bytes, outside ``bytes_valid``, class
``-1``), the anchor's ``page_states`` tint it, and the first aligned row inside
the window is a normal segment. Only offsets OUTSIDE the anchor's index space
(negative, at/after the span end) stay a 400.
"""

from __future__ import annotations

import base64
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from fastapi.testclient import TestClient  # noqa: E402

from memdiver.api.main import create_app  # noqa: E402
from memdiver.app.tools_consensus import aligned_window_from_vector  # noqa: E402
from memdiver.core.service_errors import OffsetOutOfRangeError  # noqa: E402
from memdiver.engine.consensus_service import build_consensus  # noqa: E402
from memdiver.msl.enums import PageState  # noqa: E402
from memdiver.msl.writer import MslWriter  # noqa: E402
from tests.fixtures.generate_msl_fixtures import PAGE_SIZE as P  # noqa: E402

C, F, U, N = (PageState.CAPTURED, PageState.FAILED,
              PageState.UNMAPPED, PageState.NOT_RESIDENT)
REGION_A = 0x10000
REGION_B = 0x20000
#: Offset of REGION_B in the anchor's "va" view; the span ends one page later.
B_OFFSET = REGION_B - REGION_A
SPAN = B_OFFSET + P


def _write_msl(path: Path, states, fill: int, pid: int) -> str:
    """Region A with ``states`` (5 pages), then one captured page at B."""
    writer = MslWriter(str(path), pid=pid, imported=False)
    writer.add_process_identity(exe_path="/proc/uncaptured")
    captured = sum(1 for s in states if s == C)
    writer.add_memory_region(
        REGION_A, bytes([fill]) * P * captured, page_states=states)
    writer.add_memory_region(REGION_B, b"\x42" * P, page_states=[C])
    writer.add_end_of_capture()
    writer.write()
    return str(path)


@pytest.fixture
def pair(tmp_path):
    """Anchor: C F U N C | gap | C.   Peer: every page captured."""
    anchor = _write_msl(tmp_path / "anchor.msl", [C, F, U, N, C], 0xA1, 7)
    peer = _write_msl(tmp_path / "peer.msl", [C] * 5, 0xA1, 8)
    return anchor, peer


@pytest.fixture
def consensus(pair):
    return build_consensus(list(pair))


def _window(consensus, pair, offset: int, length: int):
    return aligned_window_from_vector(
        consensus, anchor_path=pair[0], anchor_view="va",
        offset=offset, length=length,
    )


def _assert_uncaptured_head(window, head: int) -> None:
    """``[0, head)`` is a gap in every dump; the rest is one aligned segment."""
    length = window["length"]
    assert window["gaps"] == [[0, head]]
    assert [(s["window_offset"], s["length"]) for s in window["segments"]] == [
        (head, length - head)]
    assert window["classes"][:head] == [-1] * head
    assert -1 not in window["classes"][head:]
    assert window["variants"][:head] == [0] * head
    for block in window["dumps"]:
        assert block["bytes_valid"] == [[head, length - head]]
        assert base64.b64decode(block["bytes"])[:head] == bytes(head)


def test_window_starting_in_a_failed_page(consensus, pair):
    window = _window(consensus, pair, P, 4 * P)
    _assert_uncaptured_head(window, 3 * P)
    anchor, peer = window["dumps"]
    assert anchor["page_states"] == [
        [0, P, "FAILED"], [P, P, "UNMAPPED"], [2 * P, P, "NOT_RESIDENT"]]
    # The peer captured those pages, but they are in no correspondence.
    assert peer["page_states"] == []


def test_window_starting_in_an_unmapped_page(consensus, pair):
    window = _window(consensus, pair, 2 * P, 2 * P + P // 2)
    _assert_uncaptured_head(window, 2 * P)
    assert window["dumps"][0]["page_states"] == [
        [0, P, "UNMAPPED"], [P, P, "NOT_RESIDENT"]]


def test_window_starting_mid_not_resident_page(consensus, pair):
    window = _window(consensus, pair, 3 * P + 16, 2 * P - 16)
    _assert_uncaptured_head(window, P - 16)
    assert window["dumps"][0]["page_states"] == [[0, P - 16, "NOT_RESIDENT"]]
    assert window["anchor"]["slab_offset"] == window["segments"][0]["slab_offset"]


def test_window_starting_exactly_at_the_page_before_a_captured_page(
        consensus, pair):
    window = _window(consensus, pair, 3 * P, 2 * P)
    _assert_uncaptured_head(window, P)
    assert window["dumps"][0]["page_states"] == [[0, P, "NOT_RESIDENT"]]


def test_window_starting_in_an_inter_region_gap(consensus, pair):
    window = _window(consensus, pair, B_OFFSET - P, 2 * P)
    _assert_uncaptured_head(window, P)
    assert window["dumps"][0]["page_states"] == [[0, P, "UNMAPPED"]]
    peer_bytes = base64.b64decode(window["dumps"][1]["bytes"])
    assert peer_bytes[P:] == b"\x42" * P


def test_window_entirely_uncaptured(consensus, pair):
    window = _window(consensus, pair, P, 3 * P)
    assert window["segments"] == []
    assert window["gaps"] == [[0, 3 * P]]
    assert window["anchor"]["slab_offset"] == -1
    assert set(window["classes"]) == {-1}
    assert set(window["variants"]) == {0}
    anchor, peer = window["dumps"]
    assert anchor["bytes_valid"] == [] and peer["bytes_valid"] == []
    assert anchor["page_states"] == [
        [0, P, "FAILED"], [P, P, "UNMAPPED"], [2 * P, P, "NOT_RESIDENT"]]
    assert peer["page_states"] == []


def test_captured_start_is_unchanged(consensus, pair):
    window = _window(consensus, pair, 0, 2 * P)
    assert window["gaps"] == [[P, P]]
    assert window["dumps"][0]["bytes_valid"] == [[0, P]]
    assert window["dumps"][0]["page_states"] == [[P, P, "FAILED"]]


@pytest.mark.parametrize("offset", [SPAN, SPAN + P, -1])
def test_offset_outside_the_va_span_is_still_refused(consensus, pair, offset):
    with pytest.raises(OffsetOutOfRangeError):
        _window(consensus, pair, offset, P)


def test_vas_anchor_past_the_captured_stream_is_still_refused(consensus, pair):
    captured = 3 * P  # pages 0 and 4 of region A, plus region B
    with pytest.raises(OffsetOutOfRangeError):
        aligned_window_from_vector(
            consensus, anchor_path=pair[0], anchor_view="vas",
            offset=captured, length=P,
        )


def _http_window(client, pair, offset: int):
    return client.post("/api/analysis/consensus/aligned-window", json={
        "dump_paths": list(pair), "anchor": "dump", "anchor_path": pair[0],
        "view": "va", "offset": offset, "length": 2 * P,
    })


def test_http_window_starting_uncaptured_is_200(pair):
    response = _http_window(TestClient(create_app()), pair, 2 * P)
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["dumps"][0]["page_states"] == [
        [0, P, "UNMAPPED"], [P, P, "NOT_RESIDENT"]]


def test_http_offset_past_the_span_is_400(pair):
    response = _http_window(TestClient(create_app()), pair, SPAN)
    assert response.status_code == 400, response.text
