"""Every MCP tool is classified READ/WRITE; a new tool forces a review."""

import pytest

pytest.importorskip("mcp")

from memdiver.mcp_server import tool_policy as tp  # noqa: E402

CLS = tp.classify_tools()

# Snapshot of reviewed tool names. A tool added to the server but absent here
# fails test_no_unreviewed_tools: add it here AFTER deciding its class (path
# params derive it; otherwise tool_policy.WRITE_TOOLS_EXTRA / NEVER_AUTO).
REVIEWED = frozenset({
    "aligned_window",
    "analyze_candidates",
    "analyze_library",
    "analyze_region",
    "anchor_consensus",
    "annotations_add",
    "annotations_list",
    "annotations_retract",
    "annotations_supersede",
    "artifact_model_build",
    "artifact_model_export",
    "artifact_model_validate",
    "auto_floor",
    "brute_force",
    "capture_dump",
    "case_export",
    "case_init",
    "case_manifest",
    "case_query",
    "case_schema",
    "case_status",
    "code_evidence",
    "consensus",
    "consensus_regions",
    "context_at",
    "detect_format",
    "detector_fixtures_add",
    "detector_fixtures_list",
    "detector_fixtures_remove",
    "detector_fixtures_run",
    "disasm",
    "emit_plugin",
    "experiment",
    "export_key_pattern",
    "export_keylog",
    "export_pattern",
    "extract_strings",
    "get_blocks",
    "get_connections",
    "get_cross_references",
    "get_entropy",
    "get_handles",
    "get_import_provenance",
    "get_module_index",
    "get_modules",
    "get_page_states",
    "get_processes",
    "get_region_filter",
    "get_session_info",
    "heap_chunk_at",
    "heap_chunks",
    "heap_detect",
    "heap_free_lists",
    "heap_roles",
    "heap_summary",
    "identify_structure",
    "image_extract_process",
    "image_open_view",
    "image_probe",
    "image_processes",
    "image_profile",
    "import_raw_dump",
    "inspect_pcap",
    "isf_draft_create",
    "isf_draft_diff",
    "isf_draft_export",
    "isf_draft_get",
    "isf_draft_import",
    "isf_draft_list",
    "isf_draft_retract",
    "isf_draft_set",
    "isf_draft_validate",
    "isf_draft_versions",
    "isf_probe",
    "isf_try",
    "keyfinders_list",
    "keyfinders_scan",
    "list_phases",
    "list_protocols",
    "locate_field_across_pairs",
    "locate_key",
    "manual_export_pattern",
    "n_sweep",
    "preview_import",
    "propose_layout",
    "read_hex",
    "read_hex_raw",
    "resolve_va",
    "scan_dataset",
    "scan_yara_rule",
    "score_detector_matches",
    "search_bytes",
    "search_reduce",
    "set_region_filter",
    "strings_table",
    "vas_regions",
    "verify",
    "verify_vol3_plugin",
    "vol3_annotate",
    "vol3_check",
    "vol3_describe",
    "vol3_fixture_list",
    "vol3_fixture_put",
    "vol3_fixture_run",
    "vol3_import",
    "vol3_plugins",
    "vol3_query",
    "vol3_run",
    "vol3_scaffold",
    "vol3_source_get",
    "vol3_source_list",
    "vol3_source_put",
    "vol3_write_config",
    "xref_pointers",
    "yara_check",
    "yara_rule_delete",
    "yara_rule_get",
    "yara_rule_list",
    "yara_rule_put",
    "yara_scan_dump",
})


def test_every_tool_classified():
    assert CLS and all(c.access in (tp.READ, tp.WRITE) for c in CLS.values())
    reads = sum(c.access == tp.READ for c in CLS.values())
    print(f"read={reads} write={len(CLS) - reads}")
    assert reads and len(CLS) - reads


def test_no_unreviewed_tools():
    new = sorted(set(CLS) - REVIEWED)
    gone = sorted(REVIEWED - set(CLS))
    assert not new, f"new MCP tools need a READ/WRITE review in tool_policy + REVIEWED: {new}"
    assert not gone, f"REVIEWED lists tools that no longer exist: {gone}"


@pytest.mark.parametrize("name", ["case_query", "case_status", "annotations_list", "read_hex"])
def test_known_reads(name):
    assert CLS[name].access == tp.READ


@pytest.mark.parametrize("name", [
    "annotations_add", "case_init", "isf_draft_set", "export_keylog", "capture_dump",
    "vol3_run", "propose_layout", "artifact_model_build", "yara_rule_put",
])
def test_known_writes(name):
    assert CLS[name].access == tp.WRITE and CLS[name].reasons


@pytest.mark.parametrize("name", [
    "image_profile", "analyze_candidates", "scan_yara_rule", "verify_vol3_plugin", "vol3_run",
    "brute_force", "yara_scan_dump", "yara_check", "yara_rule_put",
])
def test_side_effecting_and_code_exec_tools_are_write(name):
    assert CLS[name].access == tp.WRITE and CLS[name].reasons


def test_set_region_filter_stays_read():
    assert CLS["set_region_filter"].access == tp.READ  # in-memory session state only


def test_exact_read_write_counts():
    reads = sum(c.access == tp.READ for c in CLS.values())
    assert (reads, len(CLS) - reads) == (65, 55)


@pytest.mark.parametrize("name", [
    "verify_vol3_plugin", "vol3_run", "vol3_check", "vol3_source_put", "brute_force",
    "n_sweep", "auto_floor", "scan_yara_rule", "yara_scan_dump", "yara_check", "yara_rule_put",
    "artifact_model_validate", "isf_draft_import",
])
def test_code_exec_tools_are_once_only(name):
    assert CLS[name].scopes == ["once"]
    assert tp.gate_access(CLS[name]) == "write_once"


def test_other_write_tools_offer_chat_scope_and_reads_none():
    assert CLS["case_init"].scopes == ["once", "chat"]
    assert tp.gate_access(CLS["case_init"]) == "write"
    assert CLS["case_query"].scopes == [] and tp.gate_access(CLS["case_query"]) == "read"
    assert tp.gate_access(CLS["capture_dump"]) == "never"


def test_every_code_exec_param_forces_once_only():
    for key in tp.CODE_EXEC_KEYS:
        cls = tp._classify("x", {key})
        assert cls.access == tp.WRITE and cls.scopes == ["once"], key


def test_no_tool_with_a_code_exec_param_offers_chat_scope():
    from memdiver.mcp_server.server import create_server

    for t in create_server()._tool_manager.list_tools():
        if set((t.parameters or {}).get("properties", {})) & tp.CODE_EXEC_KEYS:
            assert "chat" not in CLS[t.name].scopes, t.name


def test_capture_is_never_auto():
    assert CLS["capture_dump"].never_auto
    assert not any(c.never_auto for n, c in CLS.items() if n not in tp.NEVER_AUTO)


def test_unknown_params_fail_closed_to_read_only_when_no_signal():
    # No write/case/code param and not listed -> read; listing in the extras forces write.
    assert tp._classify("x", {"dump_path"}).access == tp.READ
    assert tp._classify("x", {"out_path"}).access == tp.WRITE
    assert tp._classify("x", {"case_dir"}).access == tp.WRITE
    assert tp._classify("case_query", {"case_dir"}).access == tp.READ


def test_allowed_tool_names_are_read_only_and_prefixed():
    names = tp.allowed_tool_names()
    assert names and all(n.startswith("mcp__memdiver__") for n in names)
    assert "mcp__memdiver__case_query" in names
    assert "mcp__memdiver__annotations_add" not in names
    assert len(names) == sum(c.access == tp.READ for c in CLS.values())
