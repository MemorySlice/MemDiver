"""Contracts of the in-UI agent chat: settings, the WebSocket event protocol, the backend port.

Design: ``docs/dev/agent_chat_panel_design.md``. The chat is a CLIENT of the MemDiver
MCP server (not a fifth surface): one chat = one backend (the Claude Agent SDK, or the
scripted transport used by tests/demos) talking to a sandboxed ``memdiver mcp`` child.

Every module of the chat depends on this file only; the API layer injects what the
chat needs from outside (tool access map, sandbox roots, settings store), so ``app/``
never imports ``api/`` or ``mcp_server/``.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field, replace
from typing import Any, Awaitable, Callable, Dict, List, Mapping, Optional, Protocol

#: SDK tool-name prefix of the MemDiver MCP server (``mcp__<server>__<tool>``).
MCP_SERVER_NAME = "memdiver"
TOOL_PREFIX = f"mcp__{MCP_SERVER_NAME}__"

DEFAULT_MODEL = "claude-opus-5-5"
MODEL_CHOICES = ("claude-opus-5-5", "claude-sonnet-5-5", "claude-haiku-5-5")
EFFORT_CHOICES = ("low", "medium", "high")

#: Inclusive bounds a user may set; the defaults below are deliberately LOW.
LIMITS: Dict[str, tuple] = {
    "max_turns": (1, 200),
    "max_budget_usd": (0.05, 50.0),
    "result_budget_bytes": (2_000, 500_000),
}


@dataclass(frozen=True)
class AgentSettings:
    """Per-user chat settings (persisted server-side; low by default, user-adjustable)."""

    model: str = DEFAULT_MODEL
    effort: str = "low"
    max_turns: int = 8
    max_budget_usd: float = 0.50
    #: Per-tool-result cap passed to the MCP child (``MEMDIVER_MCP_RESULT_BUDGET``).
    result_budget_bytes: int = 20_000

    def validated(self) -> "AgentSettings":
        """This settings object, or ``ValueError`` naming the first bad field."""
        if self.model not in MODEL_CHOICES:
            raise ValueError(f"model must be one of {', '.join(MODEL_CHOICES)}")
        if self.effort not in EFFORT_CHOICES:
            raise ValueError(f"effort must be one of {', '.join(EFFORT_CHOICES)}")
        for name, (low, high) in LIMITS.items():
            value = getattr(self, name)
            if isinstance(value, bool) or not isinstance(value, (int, float)) \
                    or not low <= value <= high:
                raise ValueError(f"{name} must be between {low} and {high}")
        return self

    def merged(self, changes: Mapping[str, Any]) -> "AgentSettings":
        """A validated copy with ``changes`` applied; unknown keys are refused."""
        unknown = set(changes) - set(asdict(self))
        if unknown:
            raise ValueError(f"unknown setting(s): {', '.join(sorted(unknown))}")
        return replace(self, **dict(changes)).validated()

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


# -- events: server -> browser (the WS protocol) -------------------------------------

#: Every event ``type`` the server may send. The browser ignores unknown types.
EVENT_TYPES = (
    "status",            # {state: "starting"|"ready"|"running"|"closed"}
    "text_delta",        # {text}
    "assistant_message",  # {text}
    "tool_call",         # {id, name, input, access: "read"|"write"}
    "tool_result",       # {id, ok, summary, bytes, truncated, locations? (≤10, omitted if none)}
    "approval_request",  # {id, tool, input, access, scopes: ["once", "chat"]}
    "approval_resolved",  # {id, allowed, message}
    "usage",             # {turns, max_turns, cost_estimate_usd, max_budget_usd}
    "result",            # {session_id, num_turns, cost_estimate_usd, stop_reason, is_error}
    "error",             # {code, message}
)

#: Every message ``type`` the browser may send:
#: ``user_message {text}``, ``approval {id, allow, message?, scope?: "once"|"chat"}``,
#: ``interrupt {}``.
CLIENT_MESSAGE_TYPES = ("user_message", "approval", "interrupt")

#: Values of the tool access map the API layer injects (from ``mcp_server.tool_policy``).
#: ``write_once``: WRITE tools that run caller-supplied code or pick an executable; an
#: approval never covers the rest of the chat (``mcp_server.tool_policy.gate_access``).
TOOL_ACCESS = ("read", "write", "write_once", "never")
APPROVAL_SCOPES = ("once", "chat")


@dataclass(frozen=True)
class ChatEvent:
    """One server -> browser event; ``to_dict`` is the exact WS JSON."""

    type: str
    data: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.type not in EVENT_TYPES:
            raise ValueError(f"unknown chat event type: {self.type}")

    def to_dict(self) -> Dict[str, Any]:
        return {"type": self.type, **self.data}


Emit = Callable[[ChatEvent], Awaitable[None]]


@dataclass(frozen=True)
class Decision:
    """Outcome of :class:`PermissionGate` for one tool call."""

    allow: bool
    message: str = ""


class PermissionGate(Protocol):
    """Decides each tool call: MemDiver READ tools pass, WRITE tools wait for the analyst.

    Anything that is not a ``mcp__memdiver__*`` tool is denied (the chat has no shell,
    file or web tools); a MemDiver tool missing from the access map is treated as WRITE
    (fail closed); ``never`` tools are denied even when approved. Pending approvals are
    denied when the chat closes. ``scope="chat"`` approves that tool for the rest of the
    chat (the analyst's choice, shown in the UI), ``"once"`` only this call.
    """

    async def decide(self, tool_name: str, tool_input: Mapping[str, Any]) -> Decision: ...

    def resolve(self, request_id: str, allow: bool, message: str = "",
                scope: str = "once") -> bool: ...

    async def close(self) -> None: ...


@dataclass(frozen=True)
class McpChild:
    """How the backend starts the sandboxed MemDiver MCP server (stdio)."""

    command: str
    args: List[str]
    env: Dict[str, str]


@dataclass(frozen=True)
class ChatSpec:
    """Everything a backend needs to start one chat."""

    system_prompt: str
    settings: AgentSettings
    mcp: McpChild
    #: SDK tool names auto-approved (MemDiver READ tools); everything else goes to the gate.
    allowed_tools: List[str]
    #: Working directory of the agent process (the case dir, else MemDiver home).
    cwd: str
    #: Private config dir for the agent runtime (keeps the analyst's own config out).
    config_dir: str
    resume_session_id: Optional[str] = None
    #: Bare tool name -> "read"|"write"|"never" (``mcp_server.tool_policy``); labels
    #: tool_call events. Tools missing from it are labelled "write" (fail closed).
    tool_access: Mapping[str, str] = field(default_factory=dict)


class AgentBackend(Protocol):
    """One chat's model loop. ``send`` runs one user turn to completion, emitting events."""

    async def start(self, spec: ChatSpec, gate: PermissionGate, emit: Emit) -> None: ...

    async def send(self, text: str) -> None: ...

    async def interrupt(self) -> None: ...

    async def close(self) -> None: ...
