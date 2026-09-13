"""``consensus.class_regions`` on all four surfaces, in ONE atomic change.

The capability behind "click *Key candidate*, get every occurrence, click a row
to jump there". It is registered on library, CLI, web and MCP from the change
that introduced it — deliberately, and for the same reason
``consensus.aligned_window`` was: the per-row slab -> VA -> navigable-offset
translation is precisely the arithmetic a surface WITHOUT this capability
re-derives, differently and wrongly. A web-only region list would have put a
second copy of ``_translate_va`` in the CLI the first time someone wanted the
same list in a terminal.

These are adapter tests. The compute lives in
``test_consensus_class_regions.py``; here each surface is checked for the two
things an adapter can get wrong — does the payload arrive intact, and does it
arrive from the SAME producer as the other three — plus the registry entry that
makes the parity ratchet hold it there.
"""

from __future__ import annotations

import argparse
import io
import json
import sys
from contextlib import redirect_stdout
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from fastapi.testclient import TestClient  # noqa: E402

import memdiver  # noqa: E402
from memdiver.api.main import create_app  # noqa: E402
from tests.fixtures.generate_msl_aslr_fixtures import (  # noqa: E402
    generate_aslr_msl_pair,
)

_ROUTE = "/api/analysis/consensus/regions"
_MIN_LENGTH = 1


@pytest.fixture(scope="module")
def aslr_pair(tmp_path_factory):
    root = tmp_path_factory.mktemp("regions_surfaces")
    run1, run2 = generate_aslr_msl_pair(extra_region=True)
    first, second = root / "run_1.msl", root / "run_2.msl"
    first.write_bytes(run1)
    second.write_bytes(run2)
    return str(first), str(second)


@pytest.fixture(scope="module")
def client():
    return TestClient(create_app())


@pytest.fixture(scope="module")
def mcp_tool():
    """The registered MCP tool's callable, presenter and all."""
    pytest.importorskip("mcp")
    from memdiver.mcp_server.server import create_server

    tools = {t.name: t for t in create_server()._tool_manager.list_tools()}
    assert "consensus_regions" in tools, sorted(tools)
    return tools["consensus_regions"].fn


def _run_cli(argv: list, expect_json: bool = True) -> tuple:
    """Parse a real argv and dispatch it; return ``(rc, payload)``.

    Goes through ``build_parser()`` rather than a hand-built Namespace so the
    subcommand's REGISTRATION is proven too — a handler wired into the dispatch
    table but missing its parser would still pass otherwise.
    """
    from memdiver.cli.consensus import _cmd_consensus_regions
    from memdiver.cli.main import build_parser

    args = build_parser().parse_args(argv)
    assert isinstance(args, argparse.Namespace)
    buf = io.StringIO()
    with redirect_stdout(buf):
        rc = _cmd_consensus_regions(args)
    return rc, json.loads(buf.getvalue()) if expect_json else buf.getvalue()


# ---------------------------------------------------------------------------
# Library
# ---------------------------------------------------------------------------


def test_library_producers_are_public():
    """BOTH halves of the pair are re-exported: ``class_regions_result``
    builds a consensus, ``class_regions_from_vector`` reuses one the caller
    already holds (the web route's ``consensus_id`` branch)."""
    assert "class_regions_result" in memdiver.services.__all__
    assert "class_regions_from_vector" in memdiver.services.__all__
    from memdiver.app import tools_consensus

    assert memdiver.services.class_regions_result is (
        tools_consensus.class_regions_result)
    assert memdiver.services.class_regions_from_vector is (
        tools_consensus.class_regions_from_vector)


def test_library_surface_returns_a_status_carrying_result(aslr_pair):
    """The library caller gets the whole ``ServiceResult`` — the status block
    the other three surfaces drop."""
    from memdiver.core.service_result import Resolution

    result = memdiver.services.class_regions_result(
        memdiver.ToolSession(), dump_paths=list(aslr_pair),
        min_length=_MIN_LENGTH)

    assert result.status.resolution is Resolution.OK
    assert result.payload["regions"]


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def test_cli_emits_the_payload(aslr_pair):
    rc, payload = _run_cli(
        ["consensus-regions", *aslr_pair, "--min-length", str(_MIN_LENGTH)])

    assert rc == 0
    assert payload["coordinate"] == "aligned"
    assert payload["classes"] == ["structural", "pointer", "key_candidate"]
    assert payload["regions"]


def test_cli_refuses_a_single_dump(aslr_pair):
    """A consensus is a statement about a SET; one dump has nothing to vary
    against."""
    rc, out = _run_cli(["consensus-regions", aslr_pair[0]], expect_json=False)
    assert rc == 1
    assert out == "", "the refusal goes to stderr, never to the JSON stream"


def test_cli_forwards_the_paging_and_anchor_flags(aslr_pair):
    """The flags are not decoration: each must reach the producer, or the
    terminal surface asks a narrower question than the web one."""
    rc, payload = _run_cli([
        "consensus-regions", *aslr_pair, "--min-length", str(_MIN_LENGTH),
        "--classes", "key_candidate", "--limit", "1",
        "--anchor-dump", aslr_pair[0], "--view", "vas"])

    assert rc == 0
    assert payload["classes"] == ["key_candidate"]
    assert payload["union"] is False
    assert payload["returned"] <= 1
    assert payload["anchor"]["view"] == "vas"
    assert payload["anchor"]["jumpable"] is True


def test_cli_no_anchor_offsets_skips_the_open(aslr_pair):
    rc, payload = _run_cli([
        "consensus-regions", *aslr_pair, "--min-length", str(_MIN_LENGTH),
        "--anchor-dump", aslr_pair[0], "--no-anchor-offsets"])

    assert rc == 0
    assert payload["anchor"]["jumpable"] is False


# ---------------------------------------------------------------------------
# MCP
# ---------------------------------------------------------------------------


def test_mcp_tool_returns_json_payload(mcp_tool, aslr_pair):
    """The tool returns a JSON STRING (the MCP transport contract)."""
    raw = mcp_tool(dump_paths=list(aslr_pair), min_length=_MIN_LENGTH)
    assert isinstance(raw, str)

    payload = json.loads(raw)
    assert "error" not in payload, payload
    assert payload["regions"]


def test_mcp_tool_reports_a_capability_error_as_a_body_not_a_traceback(
    mcp_tool, aslr_pair,
):
    payload = json.loads(mcp_tool(dump_paths=[aslr_pair[0]]))
    assert "error" in payload, payload


# ---------------------------------------------------------------------------
# Cross-surface parity
# ---------------------------------------------------------------------------


def test_all_four_surfaces_agree(mcp_tool, client, aslr_pair):
    """The four adapters dispatch through the ONE producer, so identical
    inputs must yield an identical payload. Any future change that inlines the
    compute in one adapter fails here."""
    from_lib = memdiver.services.class_regions_result(
        memdiver.ToolSession(), dump_paths=list(aslr_pair),
        min_length=_MIN_LENGTH, anchor_path=aslr_pair[0]).payload
    from_mcp = json.loads(mcp_tool(
        dump_paths=list(aslr_pair), min_length=_MIN_LENGTH,
        anchor_path=aslr_pair[0]))
    from_web = client.post(_ROUTE, json={
        "dump_paths": list(aslr_pair), "min_length": _MIN_LENGTH,
        "anchor_path": aslr_pair[0]}).json()
    _rc, from_cli = _run_cli([
        "consensus-regions", *aslr_pair, "--min-length", str(_MIN_LENGTH),
        "--anchor-dump", aslr_pair[0]])

    assert from_lib == from_mcp == from_web == from_cli


def test_capability_is_registered_on_all_four_surfaces():
    """The registry entry this change exists to make true. Guards against a
    surface being quietly dropped later while the ``_cap`` still claims it."""
    from memdiver.app.capabilities import CAPABILITIES

    cap = next(c for c in CAPABILITIES if c.name == "consensus.class_regions")
    assert cap.producer == "memdiver.app.tools_consensus.class_regions_result"
    assert cap.surfaces == frozenset({"library", "cli", "web", "mcp"})
