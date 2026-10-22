"""Structure apply/identify honour the byte view the offset addresses.

The hex viewer's cursor is an offset in its CURRENT view. On a gcore core the
planted secret sits at raw (container) offset 432 and VAS offset 4352, so a
structure applied at a cursor must read in the cursor's view; ``view=None``
keeps the historical behaviour (the cached dump source's default view, which
for a gcore core is the container file itself).
"""

import json
from pathlib import Path

import pytest

from memdiver.app import tools_xref
from memdiver.app.session import ToolSession
from memdiver.core.service_errors import CapabilityError

FIXTURE = Path(__file__).parent / "e2e" / "fixtures" / "gcore_planted"
CORE = str(FIXTURE / "planted.core")
PLANTED = json.loads((FIXTURE / "planted.json").read_text())
SECRET_HEX_PREFIX = PLANTED["secret"].encode()[:16].hex()


@pytest.fixture
def session():
    return ToolSession()


def _key_field_display(result) -> str:
    fields = result.payload["structure"]["fields"]
    return "".join(str(f["display"]) for f in fields).replace(" ", "").lower()


def test_apply_structure_reads_in_the_requested_view(session):
    vas = tools_xref.apply_structure_result(
        session, CORE, PLANTED["vas_offset"], "aes128_key", view="vas")
    raw = tools_xref.apply_structure_result(
        session, CORE, PLANTED["raw_offset"], "aes128_key", view="raw")
    assert SECRET_HEX_PREFIX[:14] in _key_field_display(vas)
    assert _key_field_display(vas) == _key_field_display(raw)


def test_apply_structure_raw_view_differs_at_the_vas_number(session):
    raw_at_vas_number = tools_xref.apply_structure_result(
        session, CORE, PLANTED["vas_offset"], "aes128_key", view="raw")
    assert SECRET_HEX_PREFIX[:14] not in _key_field_display(raw_at_vas_number)


def test_apply_structure_default_view_is_unchanged(session):
    # No view = the historical read (the container bytes for a gcore core).
    default = tools_xref.apply_structure_result(
        session, CORE, PLANTED["vas_offset"], "aes128_key")
    raw = tools_xref.apply_structure_result(
        session, CORE, PLANTED["vas_offset"], "aes128_key", view="raw")
    assert default.payload == raw.payload


def test_apply_structure_unsupported_view_is_a_capability_error(session):
    with pytest.raises(CapabilityError):
        tools_xref.apply_structure_result(session, CORE, 0, "aes128_key", view="va")


def test_identify_structure_reads_in_the_requested_view(session):
    raw = tools_xref.identify_structure_result(
        session, CORE, PLANTED["raw_offset"], view="raw")
    vas = tools_xref.identify_structure_result(
        session, CORE, PLANTED["vas_offset"], view="vas")
    # Same bytes under the cursor in both views -> the same answer.
    assert _strip_offsets(raw.payload) == _strip_offsets(vas.payload)


def _strip_offsets(payload):
    match = payload.get("match")
    if not match:
        return payload
    return {**match, "fields": [{k: v for k, v in f.items() if k != "offset"}
                                for f in match["fields"]]}


def test_identify_structure_window_matches_the_prefix_read(session):
    # The producer now reads only [offset, offset + max) instead of the whole
    # prefix [0, offset + max); the answer (absolute offsets included) must
    # be exactly what matching on the prefix gave.
    from memdiver.core.structure_library import get_structure_library
    from memdiver.core.structure_overlay import best_match_structure, compute_max_size

    library = get_structure_library()
    max_size = max(compute_max_size(s) for s in library.list_all())
    data = Path(CORE).read_bytes()
    for offset in (0, 100, PLANTED["raw_offset"]):
        expected = best_match_structure(data[:offset + max_size], offset, library)
        got = tools_xref.identify_structure_result(session, CORE, offset).payload["match"]
        if expected is None:
            assert got is None
            continue
        struct_def, overlays, confidence = expected
        assert got["name"] == struct_def.name
        assert got["confidence"] == confidence
        assert [f["offset"] for f in got["fields"]] == [o.offset for o in overlays]


def test_structure_routes_accept_view():
    from fastapi.testclient import TestClient
    from memdiver.api.main import create_app

    client = TestClient(create_app())
    apply = client.get("/api/inspect/structure-apply", params={
        "dump_path": CORE, "offset": PLANTED["raw_offset"],
        "structure_name": "aes128_key", "view": "raw"})
    assert apply.status_code == 200
    assert SECRET_HEX_PREFIX[:14] in "".join(
        str(f["display"]) for f in apply.json()["structure"]["fields"]).replace(" ", "").lower()
    ident = client.get("/api/inspect/structure", params={
        "dump_path": CORE, "offset": PLANTED["vas_offset"], "view": "vas"})
    assert ident.status_code == 200
    assert "match" in ident.json()
    bad = client.get("/api/inspect/structure", params={
        "dump_path": CORE, "offset": 0, "view": "va"})
    assert "error" in bad.json()
