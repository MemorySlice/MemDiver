"""Registration-layer test for the FastMCP server.

Unlike ``test_mcp_tools`` / ``test_mcp_new_tools`` (which call the pure
``tools_*`` functions directly), this exercises ``create_server()`` itself so a
tool that exists but is never ``@mcp.tool()``-registered — the O-2 gap, and the
class of bug that hid the ``FastMCP(description=)`` crash — fails loudly.

Skipped where the optional ``mcp`` SDK is absent (the default dev env); runs in
the CI ``wheel-install`` env and any environment that has ``mcp`` installed.
"""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

pytest.importorskip("mcp")

from memdiver.mcp_server.server import create_server  # noqa: E402

# Every tool the server is expected to register. Kept explicit so a dropped or
# renamed registration is caught, not silently absorbed by a count.
EXPECTED_TOOLS = {
    "scan_dataset", "list_phases", "list_protocols", "analyze_library",
    "read_hex", "get_entropy", "extract_strings", "get_session_info",
    "vas_regions",
    "get_processes", "get_modules", "get_handles", "detect_format",
    "get_cross_references", "identify_structure", "import_raw_dump",
    "search_reduce", "brute_force", "n_sweep", "emit_plugin",
    "read_hex_raw", "resolve_va", "search_bytes", "get_page_states",
    "consensus", "auto_floor", "export_pattern",
    # The N-dump differential view: ONE window, read in EVERY dump at the
    # address the consensus aligned. Wired on all four surfaces in the change
    # that introduced it, so it never needed a KNOWN_PARITY_GAPS entry.
    "aligned_window",
    # P2.3: the manual complement of export_pattern — "I know the offset, I do
    # not have the key bytes". Wired on web + MCP + library in one atomic change
    # so the producer could leave EXEMPT_PRODUCERS and be registered truthfully
    # on all four surfaces.
    "manual_export_pattern",
    # P2.4: the per-offset investigation view ("what is at this offset?"). It
    # was a producer reachable from nowhere; wired on web + MCP + CLI + library
    # in one atomic change so it could leave EXEMPT_PRODUCERS and be registered
    # truthfully on all four surfaces.
    "analyze_region",
    # Phase 4 (G3): capabilities that were previously web-only are now
    # reachable from MCP too.
    "get_connections", "get_module_index", "get_blocks",
    # Phase 5 (G4): verify + experiment lifted into shared producers and
    # exposed on MCP alongside the CLI/API surfaces.
    "verify", "experiment",
    # TLS-key ground-truth: export the recovered keys as an SSLKEYLOGFILE.
    "export_keylog",
    # Phase 1 pcap oracle: parse an uploaded capture and enumerate its TLS
    # sessions (client randoms) so a recovered key can be matched to traffic.
    "inspect_pcap",
    # A4: the exploratory differential path — N dumps in, ranked candidates
    # out, with no oracle and no capture. The MCP surface is the reason it
    # returns its regions inline: an agent handed a file path cannot read it.
    "analyze_candidates",
    # B1/B3: the key-location spine. "I already hold this secret — which dumps
    # still contain it, and where?" plus the signature built on that answer.
    "locate_key", "export_key_pattern",
    # C3: the PAIRED field search — N (dump, capture) pairs, each dump taking
    # its needle from the capture of the run it belongs to, and no key log
    # read. Registered on all four surfaces in the change that added it, so it
    # needs no _MCP_ALLOWED_OMISSIONS / KNOWN_PARITY_GAPS entry.
    "locate_field_across_pairs",
    # D1: RUN a rule MemDiver emitted. ``engine/yara_scan.py`` was fully built
    # and tested and reachable from NO surface, so every emitted detector was
    # unevaluated by construction; this tool is the agent-facing half of the fix
    # (CLI ``scan-yara``, POST /api/scan/yara and the services re-export are the
    # other three, all landed in the same change).
    "scan_yara_rule",
    # D2: SCORE what that rule found. ``engine/detector_metrics.py`` sat in the
    # identical hole -- fully tested, reachable from nowhere -- and without it
    # an agent gets detector firings with no way to judge them, which is how a
    # rule that matches every page gets reported as a success.
    "score_detector_matches",
    # D3: RUN the Volatility3 plugin MemDiver emits, in-process and/or through
    # the operator's own ``vol``. ``engine/vol3_verify.py`` and
    # ``engine/vol3_subproc.py`` sat in the identical hole D1's scanner did --
    # both fully built, both reachable from NO surface -- and the agent surface
    # needs this one most: it is the only place an emitted plugin's claims can
    # be checked without a human reading a TreeGrid.
    "verify_vol3_plugin",
}


def _registered_tool_names(server) -> set:
    """Return the set of registered tool names across mcp SDK versions."""
    mgr = getattr(server, "_tool_manager", None)
    if mgr is not None:
        lister = getattr(mgr, "list_tools", None)
        if callable(lister):
            return {t.name for t in lister()}
        tools = getattr(mgr, "_tools", None)
        if isinstance(tools, dict):
            return set(tools.keys())
    tools = getattr(server, "_tools", None)
    if isinstance(tools, dict):
        return set(tools.keys())
    raise AssertionError(
        "cannot introspect registered tools on this mcp version; "
        f"server attrs: {sorted(vars(server))}"
    )


@pytest.fixture(scope="module")
def registered():
    return _registered_tool_names(create_server())


def test_server_registers_granular_inspect_tools(registered):
    """O-2: the granular structured-inspect tools are reachable via MCP."""
    for name in ("get_processes", "get_modules", "get_handles"):
        assert name in registered, sorted(registered)


def test_server_registers_all_expected_tools(registered):
    missing = EXPECTED_TOOLS - registered
    assert not missing, f"missing registrations: {sorted(missing)}"


def test_server_tool_count(registered):
    assert len(registered) == len(EXPECTED_TOOLS), sorted(registered)
