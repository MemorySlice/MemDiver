"""Code-derived READ/WRITE classification of every registered MCP tool.

Consumed by the in-UI agent chat panel (docs/dev/agent_chat_panel_design.md §4):
READ tools may be auto-allowed; WRITE tools need a per-call human approval;
NEVER_AUTO tools are not offered to the agent at all.

Layering: ``mcp_server`` is a presentation surface, so it may import ``core``
(path sandbox keys) and its own registry; nothing below it imports this module.

The verdict is derived from each tool's JSON-schema parameters, then widened by
two explicit, reviewed sets. Unknown/new tools default to WRITE (fail closed).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from memdiver.core.path_sandbox import WRITE_PATH_KEYS
from memdiver.mcp_server.path_guard import CASE_READ_ONLY_TOOLS

READ = "read"
WRITE = "write"

#: Parameters naming a case that the tool may create or mutate.
CASE_KEYS = frozenset({"case_dir", "case"})

#: Parameters that make the server EXECUTE, COMPILE or LOAD caller-supplied code
#: or rules, or CHOOSE the executable that runs. Never auto-allowable even if
#: nothing is written, and the approval is ONCE-ONLY: a chat-scoped "allow" is
#: keyed by tool name, so it would otherwise let later calls with arbitrary
#: code/binaries through unprompted. Reviewed against every tool's parameters
#: (2026-10): source/plugin_source/plugin_path = vol3 plugin text/file run
#: in-process or by ``vol``; oracle_path = unsandboxed oracle module;
#: source_name = a stored plugin selected for execution; vol_bin/vol_python =
#: the launcher binary; rule_source/rule_paths/rules = YARA rules compiled with
#: ``include`` support (can probe files outside the path sandbox).
CODE_EXEC_KEYS = frozenset({
    "source", "plugin_path", "plugin_source", "oracle_path", "source_name",
    "vol_bin", "vol_python", "rule_source", "rule_paths", "rules",
})

SCOPE_ONCE = "once"
SCOPE_CHAT = "chat"

#: Tools that mutate state or start work WITHOUT a write-path/case parameter.
#: Each entry carries its reason. ``set_region_filter`` deliberately stays READ:
#: it only mutates the in-memory ToolSession filter, nothing on disk or remote.
#: READ tools may also touch the benign ``<memdiver home>/cache/isf`` sha256
#: index (``file_sha256``); that is a fixed-location cache, not analyst data.
WRITE_TOOLS_EXTRA: Dict[str, str] = {
    "image_profile": (
        "may run pakunoda over the image and writes the ISF profile cache "
        "(core/image/profiles.py)"
    ),
    "analyze_candidates": "writes the candidates into the project database",
}

#: Tools too dangerous to hand to an agent even with per-call approval.
NEVER_AUTO: Dict[str, str] = {
    "capture_dump": (
        "attaches to a live process/device (local, usb or remote) and reads its "
        "memory; the target and device are chosen by the model, so a human must "
        "start captures from the UI, not approve them as a chat tool call"
    ),
}


@dataclass(frozen=True)
class ToolClass:
    access: str  # "read" | "write"
    reasons: List[str] = field(default_factory=list)
    never_auto: bool = False
    #: Approval scopes offered for a WRITE tool: ["once"] for code-exec tools.
    scopes: List[str] = field(default_factory=list)


def _classify(name: str, params: set) -> ToolClass:
    reasons: List[str] = []
    for key in sorted(params & WRITE_PATH_KEYS):
        reasons.append(f"write-path parameter '{key}'")
    if name not in CASE_READ_ONLY_TOOLS:
        for key in sorted(params & CASE_KEYS):
            reasons.append(f"case parameter '{key}' on a tool not in CASE_READ_ONLY_TOOLS")
    for key in sorted(params & CODE_EXEC_KEYS):
        reasons.append(f"executes caller-supplied code via '{key}'")
    if name in WRITE_TOOLS_EXTRA:
        reasons.append(WRITE_TOOLS_EXTRA[name])
    if name in NEVER_AUTO:
        reasons.append(NEVER_AUTO[name])
    if not reasons:
        return ToolClass(READ)
    once_only = bool(params & CODE_EXEC_KEYS)
    scopes = [SCOPE_ONCE] if once_only else [SCOPE_ONCE, SCOPE_CHAT]
    return ToolClass(WRITE, reasons, name in NEVER_AUTO, scopes)


def gate_access(cls: ToolClass) -> str:
    """The access-map value the agent-chat gate consumes.

    ``read`` | ``write`` | ``write_once`` (WRITE, no chat-scoped approval) | ``never``.
    """
    if cls.never_auto:
        return "never"
    if cls.access == WRITE and SCOPE_CHAT not in cls.scopes:
        return "write_once"
    return cls.access


def classify_tools(server: Optional[Any] = None) -> Dict[str, ToolClass]:
    """Classify every tool registered on ``server`` (default: a fresh server)."""
    if server is None:
        from memdiver.mcp_server.server import create_server

        server = create_server()
    return {
        t.name: _classify(t.name, set((t.parameters or {}).get("properties", {})))
        for t in server._tool_manager.list_tools()
    }


def allowed_tool_names(prefix: str = "mcp__memdiver__", server: Optional[Any] = None) -> List[str]:
    """READ tools in Agent SDK naming (safe to auto-allow), sorted."""
    return sorted(
        prefix + n for n, c in classify_tools(server).items() if c.access == READ
    )
