"""API-side assembly of the in-UI agent chat (the chat is a CLIENT of the MCP server).

``app/agent_chat`` holds the framework-free chat (gate, session, backends); this module
wires it to the web deployment: server-side credentials check, per-user settings, the
sandboxed ``memdiver mcp`` child it spawns, the registry of open chats and the outbound
event queues the WebSocket drains. Design: ``docs/dev/agent_chat_panel_design.md``.
"""

from __future__ import annotations

import asyncio
import functools
import importlib.util
import os
import sys
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from memdiver.analysis.case import MANIFEST
from memdiver.api import path_policy, read_roots
from memdiver.api.config import get_settings
from memdiver.api.services import agent_playbooks
from memdiver.api.user_prefs import read_pref
from memdiver.app.agent_chat import contracts as c
from memdiver.app.agent_chat.gate import ApprovalGate
from memdiver.app.agent_chat.sdk_backend import make_backend
from memdiver.app.agent_chat.session import ChatRegistry, ChatSession
from memdiver.app.agent_chat.settings_store import load_settings
from memdiver.app.agent_chat.system_prompt import build_system_prompt
from memdiver.core.constants import memdiver_home
from memdiver.core import path_sandbox
from memdiver.core.install_hints import missing_package_message
from memdiver.core.service_errors import CapabilityError, ErrorCategory

BACKEND_ENV = "MEMDIVER_AGENT_BACKEND"
SCRIPT_ENV = "MEMDIVER_AGENT_SCRIPT"
SDK_MODULE = "claude_agent_sdk"
#: Server-env variables that count as agent credentials (their VALUES never leave the server).
CREDENTIAL_VARS = ("ANTHROPIC_API_KEY", "ANTHROPIC_AUTH_TOKEN")
CLOUD_PROVIDER_FLAGS = ("CLAUDE_CODE_USE_BEDROCK", "CLAUDE_CODE_USE_VERTEX",
                        "CLAUDE_CODE_USE_FOUNDRY")
#: Secrets the MCP child has no use for; everything else (PATH, ...) is inherited.
_CHILD_ENV_DROPPED = (*CREDENTIAL_VARS, "MEMDIVER_API_TOKEN")
#: Credentials the MCP child must never see; set to "" (not removed) in its env because the
#: CLI merges that env over the inherited one.
CHILD_ENV_BLANKED = (
    "ANTHROPIC_API_KEY", "ANTHROPIC_AUTH_TOKEN", "CLAUDE_CODE_OAUTH_TOKEN",
    "MEMDIVER_API_TOKEN", "AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY",
    "AWS_SESSION_TOKEN", "AWS_BEARER_TOKEN_BEDROCK", "GOOGLE_APPLICATION_CREDENTIALS")
MAX_OPEN_CHATS = 4
#: A chat that no WebSocket attaches to within this long is closed (frees its slot).
UNATTACHED_TTL_SECONDS = 120.0
CLOSE_ALL_TIMEOUT_SECONDS = 15.0
_CLOSE_ONE_TIMEOUT_SECONDS = 10.0


# -- status ----------------------------------------------------------------------------


def _env_flag(name: str) -> bool:
    return os.environ.get(name, "").strip().lower() not in ("", "0", "false", "no")


def has_credentials() -> bool:
    """True when the SERVER env carries something the agent runtime can authenticate with."""
    return any(os.environ.get(v) for v in CREDENTIAL_VARS) or any(
        _env_flag(v) for v in CLOUD_PROVIDER_FLAGS)


def agent_status() -> Dict[str, Any]:
    """``{available, backend, credentials, reason?, install_hint?}`` (never any secret value)."""
    backend = os.environ.get(BACKEND_ENV, "").strip().lower() or "sdk"
    status: Dict[str, Any] = {"available": False, "backend": backend,
                              "credentials": has_credentials()}
    if backend not in ("sdk", "scripted"):
        status["backend"] = "sdk"
        status["reason"] = f"unknown {BACKEND_ENV} '{backend}' (sdk|scripted)"
    elif backend == "scripted" and not os.environ.get(SCRIPT_ENV):
        status["reason"] = f"the scripted backend needs {SCRIPT_ENV}=<script.json>"
    elif importlib.util.find_spec(SDK_MODULE) is None:
        hint = missing_package_message("claude-agent-sdk", "agent")
        status["reason"] = "the Claude Agent SDK is not installed"
        status["install_hint"] = hint
    else:
        status["available"] = True
    return status


# -- tool policy ------------------------------------------------------------------------


@functools.lru_cache(maxsize=1)
def _tool_classes() -> Dict[str, str]:
    from memdiver.mcp_server.tool_policy import classify_tools, gate_access

    return {name: gate_access(cls) for name, cls in classify_tools().items()}


def tool_access_map() -> Dict[str, str]:
    """Bare tool name -> ``read|write|write_once|never`` (``mcp_server.tool_policy``).

    ``write_once``: tools that run caller-supplied code or pick an executable — the
    gate never lets an approval of them cover the rest of the chat.
    """
    return dict(_tool_classes())


def tool_names_by_access(access: Dict[str, str]) -> Tuple[List[str], List[str]]:
    """``(read_tools, write_tools)``; ``never`` tools are offered to nobody."""
    read = sorted(n for n, a in access.items() if a == "read")
    write = sorted(n for n, a in access.items() if a in ("write", "write_once"))
    return read, write


# -- spec assembly ----------------------------------------------------------------------


def _existing(raw: str, what: str, *, want_dir: bool = False) -> Path:
    path = path_policy.admit_read_path(raw).resolve(strict=False)
    if not path.exists() or (want_dir and not path.is_dir()):
        raise ValueError(f"{what} does not exist: {raw}")
    return path


def _too_broad_for_a_root(path: Path) -> bool:
    """``/``, the user's home, or any ancestor of home / of the MemDiver home."""
    for anchor in (Path.home().resolve(), memdiver_home().resolve()):
        if path == anchor or path in anchor.parents:
            return True
    return False


def _validated_case_dir(raw: str) -> Path:
    """An existing case directory (``case.json``) narrow enough to become a read root."""
    case = _existing(raw, "case_dir", want_dir=True)
    if _too_broad_for_a_root(case):
        raise ValueError(f"case_dir {raw!r} is too broad: it contains the home directory "
                         "(or is it); pick the case directory itself")
    if not (case / MANIFEST).is_file():
        raise ValueError(f"case_dir {raw!r} is not a case (no {MANIFEST})")
    return case


def _validated_dump(raw: str) -> Path:
    """An existing regular FILE; only the file itself (never its directory) is admitted."""
    dump = _existing(raw, "dump path")
    if not dump.is_file():
        raise ValueError(f"dump path {raw!r} must be an existing regular file")
    return dump


def write_warnings(case_dir: Optional[Path]) -> List[str]:
    """Writes stay confined to MemDiver home + upload dir (REST parity); a case outside
    them is therefore read-only for the chat."""
    if case_dir is None or path_sandbox.within(case_dir, read_roots.write_roots()):
        return []
    return [f"case_dir {case_dir} is outside the MemDiver data directory and the upload "
            "directory: the chat can read it but cannot write to it"]


def _child_roots(case_dir: Optional[Path], dumps: List[Path]) -> List[str]:
    """Read roots of the MCP child: the case dir plus each dump as an EXACT-FILE root
    (``path_sandbox.within`` admits ``p == root``), never a dump's parent directory."""
    configured = read_roots.configured_roots()
    if configured:
        return configured
    roots: List[str] = [str(memdiver_home())]
    upload_dir = get_settings().upload_dir
    if upload_dir is not None:
        roots.append(str(upload_dir))
    if case_dir is not None:
        roots.append(str(case_dir))
    roots.extend(str(d) for d in dumps)
    return list(dict.fromkeys(roots))


def _child_env(roots: List[str]) -> Dict[str, str]:
    env = {k: v for k, v in os.environ.items() if k not in _CHILD_ENV_DROPPED}
    # The SDK hands the CLI the FULL server environment and the CLI layers the stdio
    # child's env ON TOP of it (bundled CLI: ``{...baseEnv, ...server.env}``, inferred from
    # its source), so dropping a key here would leave the inherited one: blank it instead.
    env.update({name: "" for name in CHILD_ENV_BLANKED})
    env["MEMDIVER_ALLOWED_ROOTS"] = os.pathsep.join(roots)
    upload_dir = get_settings().upload_dir
    if upload_dir is not None:
        env["MEMDIVER_UPLOAD_DIR"] = str(upload_dir)
    return env


def build_spec(case_dir: Optional[str], dump_paths: List[str],
               access: Dict[str, str]) -> c.ChatSpec:
    """The :class:`ChatSpec` of one chat; ``ValueError`` for a missing path."""
    case = _validated_case_dir(case_dir) if case_dir else None
    dumps = [_validated_dump(p) for p in dump_paths]
    settings, _ = load_settings(read_pref)
    env = _child_env(_child_roots(case, dumps))
    env["MEMDIVER_MCP_RESULT_BUDGET"] = str(settings.result_budget_bytes)
    config_dir = memdiver_home() / "agent" / "claude"
    config_dir.mkdir(parents=True, exist_ok=True)
    from memdiver.mcp_server.tool_policy import allowed_tool_names

    return c.ChatSpec(
        system_prompt=build_system_prompt(
            playbook_index=agent_playbooks.playbook_index(),
            start_text=agent_playbooks.start_text()),
        settings=settings,
        mcp=c.McpChild(sys.executable, ["-m", "memdiver.cli", "mcp"], env),
        allowed_tools=allowed_tool_names(),
        cwd=str(case or memdiver_home()),
        config_dir=str(config_dir),
        tool_access=access)


# -- registry of open chats ---------------------------------------------------------------


@dataclass
class ChatHandle:
    """One open chat plus the queue its single WebSocket drains."""

    session: ChatSession
    queue: "asyncio.Queue[c.ChatEvent]" = field(default_factory=asyncio.Queue)
    attached: bool = False


_registry = ChatRegistry(max_chats=MAX_OPEN_CHATS)
_handles: Dict[str, ChatHandle] = {}
_background: "set[asyncio.Task[Any]]" = set()


def reset_chat_registry() -> None:
    """Forget every chat without closing it (tests; the lifespan closes them first)."""
    global _registry
    _registry = ChatRegistry(max_chats=MAX_OPEN_CHATS)
    _handles.clear()


def get_handle(chat_id: str) -> Optional[ChatHandle]:
    """The live handle of ``chat_id``, or None when unknown or already closed."""
    handle = _handles.get(chat_id)
    if handle is not None and (handle.session.closed or _registry.get(chat_id) is None):
        _handles.pop(chat_id, None)
        return None
    return handle


def _expire_if_unattached(chat_id: str) -> None:
    handle = _handles.get(chat_id)
    if handle is not None and not handle.attached:
        task = asyncio.get_running_loop().create_task(close_chat(chat_id))
        _background.add(task)
        task.add_done_callback(_background.discard)


async def create_chat(case_dir: Optional[str], dump_paths: List[str]) -> Dict[str, Any]:
    """Create (not yet start) a chat; the WebSocket attach starts it.

    ``CapabilityError`` (503) when the agent runtime is unavailable, ``ValueError`` for a
    bad path, ``RuntimeError`` when too many chats are open.
    """
    status = agent_status()
    if not status["available"]:
        raise CapabilityError(
            str(status.get("reason") or "agent unavailable"),
            category=ErrorCategory.PRECONDITION, status=503, code="agent.unavailable",
            details={"install_hint": status.get("install_hint")})
    access = tool_access_map()
    spec = build_spec(case_dir, dump_paths, access)
    backend = make_backend(str(status["backend"]), access)
    chat_id = uuid.uuid4().hex
    queue: "asyncio.Queue[c.ChatEvent]" = asyncio.Queue()

    async def emit(event: c.ChatEvent) -> None:
        queue.put_nowait(event)

    session = ChatSession(chat_id, backend, lambda e: ApprovalGate(access, e), spec, emit)
    _registry.create(session)
    _handles[chat_id] = ChatHandle(session=session, queue=queue)
    asyncio.get_running_loop().call_later(
        UNATTACHED_TTL_SECONDS, _expire_if_unattached, chat_id)
    read, write = tool_names_by_access(access)
    return {"chat_id": chat_id, "ws_path": f"/ws/agent/{chat_id}",
            "read_tools": read, "write_tools": write,
            "warnings": write_warnings(Path(spec.cwd) if case_dir else None)}


async def close_chat(chat_id: str) -> bool:
    """Close one chat (pending approvals are denied); False when it is unknown."""
    _handles.pop(chat_id, None)
    try:
        return await asyncio.wait_for(_registry.close(chat_id), _CLOSE_ONE_TIMEOUT_SECONDS)
    except asyncio.TimeoutError:
        return True


async def close_all_chats() -> None:
    """Shutdown hook: close every open chat, bounded so shutdown can never hang."""
    _handles.clear()
    try:
        await asyncio.wait_for(_registry.close_all(), CLOSE_ALL_TIMEOUT_SECONDS)
    except asyncio.TimeoutError:
        pass
