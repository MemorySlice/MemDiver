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
