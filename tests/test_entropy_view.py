"""The optional ``view`` of the entropy producer, REST route and MCP tool.

``view=None`` keeps the flat (``read_all``) view; an explicit view drives the
size, the offset bounds and every read, validated like ``read_hex_result``.
"""

import os
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from fastapi.testclient import TestClient  # noqa: E402

from memdiver.api.main import create_app  # noqa: E402
from memdiver.core.entropy import shannon_entropy  # noqa: E402
from memdiver.core.service_errors import (  # noqa: E402
    OffsetOutOfRangeError,
    UnsupportedFormatError,
)
from memdiver.mcp_server import tools_inspect  # noqa: E402
from memdiver.mcp_server.session import ToolSession  # noqa: E402

REGION = bytes(range(256)) * 16  # 4 KiB, entropy exactly 8.0


@pytest.fixture
def session():
    return ToolSession()


@pytest.fixture
def plain_msl(tmp_path):
    from memdiver.msl.writer import MslWriter

    path = tmp_path / "plain.msl"
    writer = MslWriter(path, pid=7)
    writer.add_memory_region(0x1000, REGION)
    writer.add_end_of_capture()
    writer.write()
    return str(path)


@pytest.fixture
def gcore_dump(tmp_path):
    """A synthetic ELF ``gcore.core`` -- a dump format with no "va" view."""
    from tests.fixtures import synth_elf_core

    return str(synth_elf_core.build(tmp_path / "run_0001") / "gcore.core")


@pytest.fixture
def raw_dump(tmp_path):
    path = tmp_path / "plain.dump"
    path.write_bytes(os.urandom(2048))
    return str(path)


def _payload(session, path, **kwargs):
    return tools_inspect.entropy_result(session, path, **kwargs).payload


def test_vas_view_profiles_the_captured_bytes(session, plain_msl):
    payload = _payload(session, plain_msl, view="vas")
    assert payload["view"] == "vas"
    assert payload["overall_entropy"] == round(shannon_entropy(REGION), 4) == 8.0


def test_raw_view_profiles_the_container(session, plain_msl):
    payload = _payload(session, plain_msl, view="raw")
    container = Path(plain_msl).read_bytes()
    assert payload["view"] == "raw"
    assert payload["overall_entropy"] == round(shannon_entropy(container), 4)


def test_no_view_keeps_the_flat_view(session, plain_msl, raw_dump):
    from memdiver.app.pipeline.analysis_buffer import flat_view
    from memdiver.core.dump_source import open_dump

    for path in (plain_msl, raw_dump):
        with open_dump(Path(path)) as source:
            expected_view = flat_view(source) or "raw"
            flat = source.read_all()
        payload = _payload(session, path)
        assert payload["view"] == expected_view
        assert payload["overall_entropy"] == round(shannon_entropy(flat), 4)


def test_explicit_view_bounds_offset_in_that_view(session, plain_msl):
    container_size = Path(plain_msl).stat().st_size
    assert container_size > len(REGION)
    # In range for "raw" but not for "vas".
    offset = len(REGION) + 1
    assert _payload(session, plain_msl, offset=offset, length=64, view="raw")["view"] == "raw"
    with pytest.raises(OffsetOutOfRangeError):
        _payload(session, plain_msl, offset=offset, length=64, view="vas")


def test_windowed_read_uses_the_view(session, plain_msl):
    payload = _payload(session, plain_msl, offset=256, length=256, view="vas")
    assert payload["overall_entropy"] == 8.0


def test_unsupported_view_is_a_capability_error(session, gcore_dump):
    with pytest.raises(UnsupportedFormatError) as info:
        _payload(session, gcore_dump, view="va")
    assert info.value.details["view"] == "va"
    assert info.value.details["supported_views"] == ["raw", "vas"]


def test_gcore_vas_and_raw_views_differ(session, gcore_dump):
    vas = _payload(session, gcore_dump, view="vas")
    raw = _payload(session, gcore_dump, view="raw")
    assert (vas["view"], raw["view"]) == ("vas", "raw")
    assert vas["overall_entropy"] != raw["overall_entropy"]


def test_rest_route_forwards_view(plain_msl, gcore_dump, raw_dump):
    client = TestClient(create_app())
    response = client.get("/api/inspect/entropy",
                          params={"dump_path": plain_msl, "view": "vas"})
    assert response.status_code == 200
    assert response.json()["view"] == "vas"
    assert response.json()["overall_entropy"] == 8.0
    bad = client.get("/api/inspect/entropy", params={"dump_path": gcore_dump, "view": "va"})
    assert bad.status_code == 200, bad.text  # legacy error-body contract
    assert bad.json()["supported_views"] == ["raw", "vas"]
    invalid = client.get("/api/inspect/entropy",
                         params={"dump_path": raw_dump, "view": "bogus"})
    assert invalid.status_code == 422


if __name__ == "__main__":
    import pytest as _pytest

    raise SystemExit(_pytest.main([__file__, "-q"]))
