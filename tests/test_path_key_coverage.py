"""Structural guard: every path-bearing parameter name is read-sandboxed or reviewed.

The read sandbox only checks argument names listed in
``core.path_sandbox.READ_PATH_KEYS``; a new path-like parameter that is not
listed silently bypasses it (``reference_path`` / ``reference_dump`` did). This
test enumerates every MCP tool parameter and every REST request field/query
parameter, and fails on any path-LOOKING name that is neither in READ_PATH_KEYS
nor in the reviewed ``NOT_A_PATH`` allow-list below.
"""

from __future__ import annotations

import asyncio
import re

import pytest

from memdiver.core import path_sandbox
from memdiver.core.path_sandbox import READ_PATH_KEYS

PATHISH = re.compile(
    r"path|dump|file|dir|root|isf|keylog|plugin|reference|model|maps|oracle|"
    r"pcap|image|view|library|anchor|source|input|hits|candidates|capture|"
    r"ground_truth|vault|dataset|case", re.I)

#: Reviewed names that look path-ish but are NOT server READ paths. Each group
#: states why. Add here only after checking the handler really never opens it.
NOT_A_PATH = {
    # modes / flags / numbers / enums / hashes
    "view": "view mode (raw|vas|...)", "anchor_view": "view mode",
    "main_view": "UI view mode", "anchor": "anchor mode literal (dump|slab)",
    "all_files": "flag", "include_hits": "flag", "no_profile": "flag",
    "persist_ground_truth": "flag", "has_keylog": "flag",
    "max_hits": "count", "oracle_budget": "number",
    "escalate_oracle_budget": "number", "pcap_max_challenges": "number",
    "pcap_max_records": "number", "orig_file_size": "number",
    "ground_truth_mode": "enum", "input_mode": "enum",
    "single_file_format": "enum", "source_format": "enum",
    "source_format_name": "enum", "resource_type": "enum",
    "oracle_sha256": "hash", "source_hash": "hash",
    "reference_hex": "hex bytes, not a file", "pcap_field": "field id",
    "dump_weights": "{label: float} UI state",
    # inline text / labels (the text itself is supplied, nothing is opened)
    "plugin_source": "plugin TEXT (plugin_path is the READ key)",
    "rule_source": "rule TEXT (rule_paths is the READ key)",
    "keylog_line": "inline keylog line", "keylog_filename": "file NAME in a run dir",
    "dump": "label on a supplied match list (scan.py)",
    "truth_sources": "labels on a supplied truth list",
    "input": "inline input body",
    "source": "inline plugin TEXT / provenance label (vol3, isf, oracles)",
    "source_name": "stored-source name inside a case",
    "plugin": "vol3 plugin NAME", "plugin_name": "name",
    "case": "case name (case_dir is the READ key)",
    "image_sha256": "hash", "oracle_id": "registry id",
    "num_dumps": "count", "dump_count": "count", "dump_labels": "labels",
    # dict-valued containers: the walker recurses, so the INNER path keys
    # (anchor_path, keylog_path, key_file, ...) are the ones checked
    "anchors": "list of dicts (anchor_path inside)", "keylog": "dict (keylog_path inside)",
    "oracle_config": "dict (oracle_path inside)",
    "anchor_label": "label", "anchor_length": "length",
    "include_anchor_offsets": "flag",
    "maps": "multipart upload part (maps file content)",
    # multipart upload part: the body is the content, not a server path
    "file": "multipart upload part",
    # saved-session UI state (api/routers/sessions.py): stored, never opened;
    # reopening goes through endpoints whose own path keys ARE sandboxed
    "active_dump_path": "session UI state", "collapsed_dump_paths": "session UI state",
    "excluded_dump_paths": "session UI state", "origin_dump_path": "session UI state",
    "solo_dump_path": "session UI state",
}


def _looks_pathish(name: str) -> bool:
    return bool(PATHISH.search(name))


def _mcp_names() -> set[str]:
    pytest.importorskip("mcp")
    from memdiver.mcp_server.server import create_server

    tools = asyncio.run(create_server().list_tools())
    names: set[str] = set()
    for tool in tools:
        schema = getattr(tool, "input_schema", None) or getattr(tool, "inputSchema", {})
        names |= set((schema or {}).get("properties", {}))
    return names


def _walk_schema_props(node, out: set[str]) -> None:
    if isinstance(node, dict):
        props = node.get("properties")
        if isinstance(props, dict):
            out.update(props)
        for child in node.values():
            _walk_schema_props(child, out)
    elif isinstance(node, list):
        for child in node:
            _walk_schema_props(child, out)


def _rest_names() -> set[str]:
    from memdiver.api.main import create_app

    spec = create_app().openapi()
    names: set[str] = set()
    for item in spec.get("paths", {}).values():
        for op in item.values():
            for param in op.get("parameters", []) if isinstance(op, dict) else []:
                if param.get("in") == "query":
                    names.add(param["name"])
    _walk_schema_props(spec.get("components", {}).get("schemas", {}), names)
    return names


def _gaps(names: set[str]) -> list[str]:
    return sorted(n for n in names
                  if _looks_pathish(n) and n not in READ_PATH_KEYS and n not in path_sandbox.WRITE_PATH_KEYS
                  and n not in NOT_A_PATH)


def test_mcp_path_like_parameters_are_sandboxed_or_reviewed():
    assert _gaps(_mcp_names()) == []


def test_rest_path_like_fields_are_sandboxed_or_reviewed():
    assert _gaps(_rest_names()) == []


def test_reference_and_dumps_keys_are_read_path_keys():
    for key in ("reference_path", "reference_dump", "dumps"):
        assert key in READ_PATH_KEYS
    assert list(path_sandbox.iter_path_values({"reference_dump": "/x"}, False)) == ["/x"]



def test_mcp_write_paths_confined_when_sandbox_on(tmp_path, monkeypatch):
    root = tmp_path / "ok"
    root.mkdir()
    monkeypatch.setenv("MEMDIVER_ALLOWED_ROOTS", str(root))
    monkeypatch.setattr(path_sandbox, "STARTUP_CWD", str(root))
    from memdiver.api.config import get_settings
    from memdiver.mcp_server.path_guard import guard_tool
    get_settings.cache_clear()
    try:
        def tool(out_path=None):
            return "ran"

        denied = guard_tool(tool)(out_path="/definitely/elsewhere/x.json")
        assert "path.outside_sandbox" in denied
        assert guard_tool(tool)(out_path=str(root / "x.json")) == "ran"
    finally:
        get_settings.cache_clear()
